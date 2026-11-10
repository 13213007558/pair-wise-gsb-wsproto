from __future__ import annotations

from typing import List, cast

import h11
import pytest

from wsproto import WSConnection
from wsproto.connection import CLIENT, SERVER
from wsproto.events import AcceptConnection, RejectConnection, Request
from wsproto.handshake import H11Handshake
from wsproto.origin import (
    InvalidHostError,
    InvalidOriginError,
    MissingOriginError,
    MultipleOriginsError,
    NullOriginError,
    OriginPolicy,
    OriginPolicyError,
    ParsedHost,
    ParsedOrigin,
    UntrustedOriginError,
    parse_host,
    parse_origin,
)
from wsproto.typing import Headers
from wsproto.utilities import LocalProtocolError, RemoteProtocolError, generate_nonce

TRUSTED = (
    "https://example.com",
    "https://app.example.com:8443",
)


def _raw_request(extra_headers: Headers) -> bytes:
    client = h11.Connection(h11.CLIENT)
    headers: Headers = [
        (b"Host", b"example.com"),
        (b"Connection", b"Keep-Alive, Upgrade"),
        (b"Upgrade", b"websocket"),
        (b"Sec-WebSocket-Version", b"13"),
        (b"Sec-WebSocket-Key", generate_nonce()),
    ]
    return cast(
        "bytes",
        client.send(
            h11.Request(method="GET", target="/chat", headers=headers + extra_headers),
        ),
    )


def _server(policy: OriginPolicy | None = None) -> WSConnection:
    return WSConnection(SERVER, origin_policy=policy)


def _reject(policy: OriginPolicy, extra_headers: Headers) -> RemoteProtocolError:
    server = _server(policy)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(_raw_request(extra_headers))
    return excinfo.value


# ---------------------------------------------------------------------------
# Strict parsing
# ---------------------------------------------------------------------------


def test_parse_origin_structure_and_default_ports() -> None:
    assert parse_origin(b"https://example.com") == ParsedOrigin(
        "https", "example.com", None,
    )
    assert parse_origin("https://example.com:443") == ParsedOrigin(
        "https", "example.com", None,
    )
    assert parse_origin("http://example.com:80") == ParsedOrigin(
        "http", "example.com", None,
    )
    assert parse_origin("wss://example.com:9000") == ParsedOrigin(
        "wss", "example.com", 9000,
    )
    assert parse_origin("https://[2001:db8::1]:8443") == ParsedOrigin(
        "https", "2001:db8::1", 8443, ipv6=True,
    )
    assert parse_origin("https://[2001:DB8::1]") == ParsedOrigin(
        "https", "2001:db8::1", None, ipv6=True,
    )
    assert parse_origin("http://10.20.30.40:8080") == ParsedOrigin(
        "http", "10.20.30.40", 8080,
    )


def test_parse_origin_schemes_are_lowercased_but_hosts_are_not_rewritten() -> None:
    assert parse_origin(b"HTTPS://example.com") == ParsedOrigin(
        "https", "example.com", None,
    )
    with pytest.raises(InvalidOriginError):
        parse_origin(b"https://EXAMPLE.com")


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"not an origin",
        b"https://",
        b"://example.com",
        b"1scheme://example.com",
        b"https://example.com/path",
        b"https://example.com?q=1",
        b"https://example.com#frag",
        b"https://user@example.com",
        b"https://example.com:",
        b"https://example.com:99999",
        b"https://example.com:abc",
        b"https://example.com.",
        b"https://ex..ample.com",
        b"https://exa mple.com",
        b"https://[::1",
        b"https://[99.99.99.99]",
        b"https://[fe80::1%25eth0]",
        b"https://192.168.000.1",
        b"https://example.com\xff",
    ],
)
def test_parse_origin_rejects_invalid_syntax(value: bytes) -> None:
    with pytest.raises(InvalidOriginError):
        parse_origin(value)


def test_parse_origin_null_is_distinct() -> None:
    with pytest.raises(NullOriginError):
        parse_origin(b"null")
    with pytest.raises(InvalidOriginError):
        parse_origin(b"NULL")


def test_parse_host_canonicalizes() -> None:
    assert parse_host(b"Example.COM:8443") == ParsedHost("example.com", 8443)
    assert parse_host(b"[2001:DB8::1]:443") == ParsedHost(
        "2001:db8::1", 443, ipv6=True,
    )
    assert parse_host(b"fe80::1") == ParsedHost("fe80::1", None, ipv6=True)


@pytest.mark.parametrize(
    "value",
    [b"", b"example.com:", b"example.com:bad", b"[::1", b"a@b.com", b"host/ path", b"192.168.000.1"],
)
def test_parse_host_rejects_garbage(value: bytes) -> None:
    with pytest.raises(InvalidHostError):
        parse_host(value)


# ---------------------------------------------------------------------------
# Policy configuration
# ---------------------------------------------------------------------------


def test_policy_requires_some_trust() -> None:
    with pytest.raises(ValueError, match="at least one origin"):
        OriginPolicy([])


def test_policy_rejects_bad_trusted_origin() -> None:
    with pytest.raises(InvalidOriginError):
        OriginPolicy(["not an origin"])
    with pytest.raises(ValueError, match="null origin"):
        OriginPolicy(["null"])


def test_policy_accepts_preparsed_origins() -> None:
    parsed = parse_origin("https://example.com")
    policy = OriginPolicy([parsed])
    assert policy.admit([b"https://example.com"], b"example.com") == [parsed]


# ---------------------------------------------------------------------------
# Trusted page and lookalike domains
# ---------------------------------------------------------------------------


def test_trusted_page_is_admitted_through_handshake() -> None:
    server = _server(OriginPolicy(TRUSTED))
    server.receive_data(_raw_request([(b"Origin", b"https://example.com")]))
    event = next(server.events())
    assert isinstance(event, Request)
    assert event.host == "example.com"
    accept = server.send(AcceptConnection())
    assert accept.startswith(b"HTTP/1.1 101")
    assert server.connection is not None


@pytest.mark.parametrize(
    "origin",
    [
        b"https://evil-example.com",
        b"https://example.com.evil.com",
        b"https://sub.example.com",
        b"http://example.com",
        b"https://example.com:8443",
        b"wss://example.com",
        b"https://app.example.com",
    ],
)
def test_lookalike_origins_are_denied(origin: bytes) -> None:
    error = _reject(OriginPolicy(TRUSTED), [(b"Origin", origin)])
    assert isinstance(error, RemoteProtocolError)
    assert error.event_hint == RejectConnection(status_code=403)


def test_lookalike_suffix_never_matches() -> None:
    policy = OriginPolicy(["https://example.com"])
    with pytest.raises(UntrustedOriginError):
        policy.admit([b"https://example.com.evil.com"], b"example.com")


def test_rejection_does_not_reflect_origin_and_opens_no_connection() -> None:
    server = _server(OriginPolicy(TRUSTED))
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(
            _raw_request([(b"Origin", b"https://evil-example.com")]),
        )
    response = server.send(excinfo.value.event_hint)
    assert response == b"HTTP/1.1 403 \r\ncontent-length: 0\r\n\r\n"
    assert b"evil-example" not in response
    assert server.connection is None


# ---------------------------------------------------------------------------
# Multi-valued and duplicated Origin headers
# ---------------------------------------------------------------------------


def test_multiple_origin_lines_are_rejected_by_default() -> None:
    error = _reject(
        OriginPolicy(TRUSTED),
        [
            (b"Origin", b"https://example.com"),
            (b"Origin", b"https://app.example.com:8443"),
        ],
    )
    assert isinstance(error.__cause__, MultipleOriginsError)


def test_two_origin_lines_never_merge_into_one_source() -> None:
    policy = OriginPolicy(
        TRUSTED, allow_multiple_origins=True,
    )
    with pytest.raises(MultipleOriginsError):
        policy.admit(
            [b"https://example.com", b"https://example.com"],
            b"example.com",
        )


def test_space_separated_origins_are_individual_values() -> None:
    policy = OriginPolicy(
        TRUSTED, allow_multiple_origins=True,
    )
    admitted = policy.admit(
        [b"https://example.com https://app.example.com:8443"],
        b"example.com",
    )
    assert admitted == [
        parse_origin("https://example.com"),
        parse_origin("https://app.example.com:8443"),
    ]
    with pytest.raises(UntrustedOriginError):
        policy.admit(
            [b"https://example.com https://evil-example.com"],
            b"example.com",
        )


def test_multi_value_with_one_untrusted_value_is_denied() -> None:
    policy = OriginPolicy(
        TRUSTED, allow_multiple_origins=True,
    )
    with pytest.raises(UntrustedOriginError):
        policy.admit(
            [b"https://example.com", b"https://evil-example.com"],
            b"example.com",
        )


# ---------------------------------------------------------------------------
# Missing and null origins
# ---------------------------------------------------------------------------


def test_missing_origin_denied_by_default() -> None:
    error = _reject(OriginPolicy(TRUSTED), [])
    assert isinstance(error.__cause__, MissingOriginError)


def test_missing_origin_allowed_for_non_browser_clients() -> None:
    server = _server(
        OriginPolicy(TRUSTED, allow_missing_origin=True),
    )
    server.receive_data(_raw_request([]))
    event = next(server.events())
    assert isinstance(event, Request)
    server.send(AcceptConnection())


def test_missing_origin_does_not_bypass_other_handshake_rules() -> None:
    server = _server(
        OriginPolicy(TRUSTED, allow_missing_origin=True),
    )
    client = h11.Connection(h11.CLIENT)
    raw = client.send(
        h11.Request(
            method="GET",
            target="/",
            headers=[
                (b"Host", b"example.com"),
                (b"Connection", b"Upgrade"),
                (b"Upgrade", b"websocket"),
                (b"Sec-WebSocket-Version", b"13"),
            ],
        ),
    )
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(raw)
    assert str(excinfo.value) == "Missing header, 'Sec-WebSocket-Key'"


def test_null_origin_denied_by_default_and_allowed_when_configured() -> None:
    error = _reject(OriginPolicy(TRUSTED), [(b"Origin", b"null")])
    assert isinstance(error.__cause__, NullOriginError)

    server = _server(
        OriginPolicy(TRUSTED, allow_null_origin=True),
    )
    server.receive_data(_raw_request([(b"Origin", b"null")]))
    assert isinstance(next(server.events()), Request)


def test_null_cannot_be_combined_with_real_origin() -> None:
    policy = OriginPolicy(
        TRUSTED, allow_null_origin=True, allow_multiple_origins=True,
    )
    with pytest.raises(NullOriginError):
        policy.admit(
            [b"null https://example.com"], b"example.com",
        )


# ---------------------------------------------------------------------------
# IPv6 and default port comparison
# ---------------------------------------------------------------------------


def test_ipv6_origin_equivalence_and_distinction() -> None:
    policy = OriginPolicy(
        ["https://[2001:db8::1]:443", "https://[fe80::1]"],
    )
    assert policy.admit(
        [b"https://[2001:DB8::1]"], b"[2001:db8::1]",
    ) == [ParsedOrigin("https", "2001:db8::1", None, ipv6=True)]
    assert policy.admit([b"https://[fe80::0001]"], b"fe80::1")
    with pytest.raises(UntrustedOriginError):
        policy.admit([b"https://[2001:db8::2]"], b"[2001:db8::2]")
    with pytest.raises(UntrustedOriginError):
        policy.admit(
            [b"https://[2001:db8::1]:8443"], b"[2001:db8::1]:8443",
        )


def test_default_ports_match_but_explicit_ports_stay_distinct() -> None:
    policy = OriginPolicy(["https://example.com"])
    assert policy.admit([b"https://example.com:443"], b"example.com")
    with pytest.raises(UntrustedOriginError):
        policy.admit([b"https://example.com:8443"], b"example.com")


def test_scheme_difference_is_significant() -> None:
    policy = OriginPolicy(["https://example.com"])
    for origin in [b"http://example.com", b"ws://example.com", b"wss://example.com"]:
        with pytest.raises(UntrustedOriginError):
            policy.admit([origin], b"example.com")


def test_malformed_host_is_rejected_even_when_origin_may_be_absent() -> None:
    policy = OriginPolicy(
        ["https://example.com"], allow_missing_origin=True,
    )
    with pytest.raises(InvalidHostError):
        policy.admit([], b"example.com:bad")


def test_bracketed_ipv4_origin_is_invalid() -> None:
    with pytest.raises(InvalidOriginError):
        parse_origin(b"https://[10.0.0.1]")


def test_bare_ipv6_origin_is_invalid() -> None:
    with pytest.raises(InvalidOriginError):
        parse_origin(b"https://fe80::1")


def test_empty_origin_line_is_invalid() -> None:
    policy = OriginPolicy(TRUSTED)
    with pytest.raises(InvalidOriginError):
        policy.admit([b"   "], b"example.com")


def test_admit_rejects_host_with_zone_identifier() -> None:
    policy = OriginPolicy(["https://[fe80::1]"])
    with pytest.raises(InvalidHostError):
        policy.admit([b"https://[fe80::1]"], b"[fe80::1%25eth0]")


def test_str_round_trip_of_parsed_origin() -> None:
    assert str(parse_origin(b"https://[2001:db8::1]:8443")) == (
        "https://[2001:db8::1]:8443"
    )
    assert str(parse_origin(b"https://example.com:443")) == "https://example.com"


@pytest.mark.parametrize(
    "origin",
    [
        b"https://[gggg::1]",
        b"https://[::1]bad",
        b"https://[::1]:",
        b"https://[::1]:99999",
        b"https://",
        b"https://[",
    ],
)
def test_ip_literal_failure_paths(origin: bytes) -> None:
    with pytest.raises(InvalidOriginError):
        parse_origin(origin)


def test_parse_origin_accepts_str_and_non_ascii_inputs() -> None:
    assert parse_origin("https://example.com") == parse_origin(
        b"https://example.com",
    )
    with pytest.raises(InvalidOriginError):
        parse_origin(b"https://example.com\xff")


def test_parse_host_failure_paths() -> None:
    for value in [b"[gggg::1]", b"[::1]:bad", b"[::1]:99999", b"fe80::zzzz", b"a..b"]:
        with pytest.raises(InvalidHostError):
            parse_host(value)
    with pytest.raises(InvalidHostError):
        parse_host(b"example.com\xff")
    assert parse_host("Example.com") == ParsedHost("example.com", None)
    assert parse_host("10.0.0.1:8080") == ParsedHost("10.0.0.1", 8080)
    with pytest.raises(InvalidHostError):
        parse_host("example.com:70000")


def test_policy_accepts_string_and_parsed_origins_equally() -> None:
    from_string = OriginPolicy(["https://example.com"])
    from_parsed = OriginPolicy([parse_origin("https://example.com")])
    raw = ([b"https://example.com"], b"example.com")
    assert from_string.admit(*raw) == from_parsed.admit(*raw)


def test_null_only_policy_is_constructible() -> None:
    policy = OriginPolicy([], allow_null_origin=True)
    assert policy.admit([b"null"], b"example.com") == []
    with pytest.raises(MissingOriginError):
        policy.admit([], b"example.com")


def test_remaining_parse_branches() -> None:
    # Empty authority after scheme.
    with pytest.raises(InvalidOriginError):
        parse_origin(b"https://")
    # Stray brackets outside bracket notation.
    with pytest.raises(InvalidOriginError):
        parse_origin(b"https://ex]ample.com")
    # A bare IPv6-looking authority must demand bracket notation.
    with pytest.raises(InvalidOriginError):
        parse_origin(b"https://fe80:0:0:0:0:0:0:1")
    # String (rather than bytes) inputs exercise the other decode branch.
    assert parse_origin("https://example.com") == ParsedOrigin(
        "https", "example.com", None,
    )
    assert parse_host("example.com") == ParsedHost("example.com", None)


def test_remaining_host_branches() -> None:
    # Bare IPv6-looking value that is not actually an address.
    with pytest.raises(InvalidHostError):
        parse_host(b"fe80::not-an-address")
    # Unparseable bracket content and a bracket IPv6 in the colon path.
    with pytest.raises(InvalidHostError):
        parse_host(b"[fe80::1")
    # Illegal reg-name characters and empty labels.
    with pytest.raises(InvalidHostError):
        parse_host(b"bad^host.example")
    with pytest.raises(InvalidHostError):
        parse_host(b"a..b.example")
    # Bracketed IPv6 with an out-of-range port uses the host error type.
    with pytest.raises(InvalidHostError):
        parse_host(b"[::1]:70000")
    # A bare IPv6-looking value carrying a dotted suffix cannot be IPv6.
    with pytest.raises(InvalidHostError):
        parse_host(b"fe80::1:8080.example")


def test_defensive_origin_branches() -> None:
    # Empty authority cannot be reached via parse_origin; exercise directly.
    from wsproto.origin import _parse_host_and_port

    with pytest.raises(InvalidOriginError):
        _parse_host_and_port("")
    with pytest.raises(InvalidOriginError):
        _parse_host_and_port("fe80:0:0:0:0:0:0:1")
    # Origin-side bracketed literal port parsing (the non-host branch).
    with pytest.raises(InvalidOriginError):
        parse_origin(b"https://[::1]:notaport")
    # A bracketed IPv6 address is not accepted through the plain colon path.
    with pytest.raises(InvalidHostError):
        parse_host(b"[fe80::1]extra:1")


# ---------------------------------------------------------------------------
# Forwarded headers and normal proxy traffic
# ---------------------------------------------------------------------------


def test_forwarded_headers_do_not_change_admission() -> None:
    server = _server(OriginPolicy(TRUSTED))
    server.receive_data(
        _raw_request(
            [
                (b"Origin", b"https://example.com"),
                (b"X-Forwarded-Host", b"internal.lan"),
                (b"X-Forwarded-Proto", b"https"),
                (b"Forwarded", b"for=10.0.0.1;host=internal.lan"),
            ],
        ),
    )
    assert isinstance(next(server.events()), Request)


def test_forwarded_headers_cannot_smuggle_an_origin() -> None:
    error = _reject(
        OriginPolicy(TRUSTED),
        [
            (b"Origin", b"https://evil-example.com"),
            (b"X-Origin", b"https://example.com"),
            (b"X-Forwarded-Host", b"example.com"),
        ],
    )
    assert isinstance(error.__cause__, UntrustedOriginError)


def test_invalid_syntax_is_a_policy_failure() -> None:
    error = _reject(
        OriginPolicy(TRUSTED),
        [(b"Origin", b"https://example.com/path")],
    )
    assert isinstance(error.__cause__, InvalidOriginError)


# ---------------------------------------------------------------------------
# Client mode and default behaviour
# ---------------------------------------------------------------------------


def test_client_connection_rejects_policy() -> None:
    with pytest.raises(LocalProtocolError):
        WSConnection(CLIENT, origin_policy=OriginPolicy(TRUSTED))
    with pytest.raises(LocalProtocolError):
        H11Handshake(CLIENT, origin_policy=OriginPolicy(TRUSTED))


def test_handshake_without_policy_keeps_legacy_behaviour() -> None:
    server = _server()
    server.receive_data(
        _raw_request([(b"Origin", b"https://anything.example")]),
    )
    assert isinstance(next(server.events()), Request)


def test_policy_is_applied_before_request_event() -> None:
    server = _server(OriginPolicy(TRUSTED))
    with pytest.raises(RemoteProtocolError):
        server.receive_data(
            _raw_request([(b"Origin", b"https://evil-example.com")]),
        )
    assert list(server.events()) == []
    assert server.connection is None


def test_policy_runs_for_initiated_upgrade_connections() -> None:
    server = H11Handshake(SERVER, origin_policy=OriginPolicy(TRUSTED))
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.initiate_upgrade_connection(
            [
                (b"Host", b"example.com"),
                (b"Connection", b"Upgrade"),
                (b"Upgrade", b"websocket"),
                (b"Sec-WebSocket-Version", b"13"),
                (b"Sec-WebSocket-Key", generate_nonce()),
                (b"Origin", b"https://evil-example.com"),
            ],
            "/",
        )
    assert excinfo.value.event_hint == RejectConnection(status_code=403)

    allowed = H11Handshake(SERVER, origin_policy=OriginPolicy(TRUSTED))
    allowed.initiate_upgrade_connection(
        [
            (b"Host", b"example.com"),
            (b"Connection", b"Upgrade"),
            (b"Upgrade", b"websocket"),
            (b"Sec-WebSocket-Version", b"13"),
            (b"Sec-WebSocket-Key", generate_nonce()),
            (b"Origin", b"https://example.com"),
        ],
        "/",
    )
    assert isinstance(next(allowed.events()), Request)


def test_policy_callable_matches_admit() -> None:
    policy = OriginPolicy(TRUSTED)
    expected: List[ParsedOrigin] = [parse_origin("https://example.com")]
    assert policy([b"https://example.com"], b"example.com") == expected
    assert policy.admit([b"https://example.com"], b"example.com") == expected
    assert issubclass(MissingOriginError, OriginPolicyError)
    assert issubclass(UntrustedOriginError, OriginPolicyError)


def test_session_resources_are_allocated_only_after_request_event() -> None:
    # Mirrors example/origin_policy_server.py: no session may exist while the
    # policy is still evaluating the handshake.
    policy = OriginPolicy(TRUSTED, allow_missing_origin=True)
    sessions: List[str] = []

    def handle(raw: bytes) -> bytes:
        server = WSConnection(SERVER, origin_policy=policy)
        try:
            server.receive_data(raw)
        except RemoteProtocolError as exc:
            assert sessions == []
            return cast("bytes", server.send(exc.event_hint))
        for event in server.events():
            assert isinstance(event, Request)
            sessions.append(event.target)
            return cast("bytes", server.send(AcceptConnection()))
        msg = "handshake produced no event"
        raise AssertionError(msg)

    rejected = handle(_raw_request([(b"Origin", b"https://evil-example.com")]))
    assert rejected.startswith(b"HTTP/1.1 403")
    assert sessions == []

    accepted = handle(_raw_request([(b"Origin", b"https://example.com")]))
    assert accepted.startswith(b"HTTP/1.1 101")
    assert sessions == ["/chat"]

    accepted_without_origin = handle(_raw_request([]))
    assert accepted_without_origin.startswith(b"HTTP/1.1 101")
    assert sessions == ["/chat", "/chat"]
