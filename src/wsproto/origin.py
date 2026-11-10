"""
wsproto/origin
~~~~~~~~~~~~~~

Strict parsing and admission policy for the WebSocket ``Origin`` header.

Browsers always send an ``Origin`` header with a WebSocket handshake
(RFC 6454, section 7.3).  A server can use it to decide which web pages are
allowed to open a WebSocket, but the decision must be made on *parsed*
origins rather than on raw header strings: a suffix match would happily
admit ``https://evil-example.com`` for a trust list containing
``https://example.com``.

Nothing in this module echoes attacker controlled data back into an error
message or an HTTP response.  Every failure mode raised here is turned into
a plain HTTP rejection by the handshake layer.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .events import RejectConnection
from .utilities import RemoteProtocolError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

# RFC 3986, section 3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
_SCHEME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789+-.")
# RFC 3986, section 2.3 (unreserved) plus section 2.2 (sub-delims).
_REG_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=%")
_DIGITS = set("0123456789")

# Default ports for the schemes that may appear in a web origin.
_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}


class OriginPolicyError(Exception):
    """Base class for every failure raised by the admission policy."""


class MissingOriginError(OriginPolicyError):
    """The request carried no ``Origin`` header at all."""


class NullOriginError(OriginPolicyError):
    """The request carried the literal, opaque ``null`` origin."""


class MultipleOriginsError(OriginPolicyError):
    """More than one origin value, or a repeated value, was present."""


class InvalidOriginError(OriginPolicyError):
    """An ``Origin`` value is not a valid serialized origin."""


class UntrustedOriginError(OriginPolicyError):
    """A syntactically valid origin is not in the trusted set."""


class InvalidHostError(OriginPolicyError):
    """The request ``Host`` header is not a valid host[:port] value."""


@dataclass(frozen=True)
class ParsedOrigin:
    """
    An origin split into its structured triple (RFC 6454, section 6).

    Origins are compared structurally on these fields, never as raw header
    strings.  A default port is normalized away, so ``https://x:443`` and
    ``https://x`` produce identical instances.
    """

    scheme: str
    host: str
    port: int | None
    ipv6: bool = False

    def __str__(self) -> str:
        host = f"[{self.host}]" if self.ipv6 else self.host
        if self.port is None:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{self.port}"


@dataclass(frozen=True)
class ParsedHost:
    """A parsed ``Host`` header value (RFC 7230, section 5.4)."""

    host: str
    port: int | None
    ipv6: bool = False


def _strip_ows(value: bytes) -> bytes:
    return value.strip(b" \t")


def _looks_like_ipv4(host: str) -> bool:
    # Four dot-separated all-digit labels are meant as an IPv4 literal even
    # if Python rejects the spelling (e.g. an ambiguous leading zero).
    labels = host.split(".")
    return len(labels) == 4 and all(
        label and all(char in _DIGITS for char in label) for label in labels
    )


def _parse_port(text: str) -> int:
    if not text or any(char not in _DIGITS for char in text):
        msg = "origin port must be a decimal integer"
        raise InvalidOriginError(msg)
    port = int(text)
    if port > 65535:
        msg = "origin port is out of range"
        raise InvalidOriginError(msg)
    return port


def _parse_ip_literal(
    text: str,
    invalid: type[OriginPolicyError] = InvalidOriginError,
) -> tuple[str, int | None, bool]:
    # ``text`` is the content inside the brackets plus any ":port" suffix.
    bracket = text.find("]")
    if bracket == -1 or text.find("[", 1) != -1:
        msg = "malformed IP literal"
        raise invalid(msg)
    address = text[:bracket]
    remainder = text[bracket + 1 :]
    if "%" in address:
        msg = "zone identifiers are not allowed"
        raise invalid(msg)
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        msg = "invalid IP literal"
        raise invalid(msg) from exc
    if not isinstance(parsed, ipaddress.IPv6Address):
        msg = "only IPv6 addresses may use bracket notation"
        raise invalid(msg)
    port = None
    if remainder:
        if not remainder.startswith(":") or remainder == ":":
            msg = "malformed IP literal"
            raise invalid(msg)
        if invalid is InvalidHostError:
            port = _parse_host_port(remainder[1:])
        else:
            port = _parse_port(remainder[1:])
    return str(parsed), port, True


def _parse_bare_ipv6_host(text: str) -> tuple[str, int | None, bool]:
    # RFC 7230 allows an unbracketed IP-literal in Host, in which case no
    # port can be expressed because the separator is ambiguous.
    if text.count(":") < 2 or "." in text:
        msg = "IPv6 host must use bracket notation to carry a port"
        raise InvalidHostError(msg)
    address = text
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        msg = "invalid IPv6 host"
        raise InvalidHostError(msg) from exc
    if not isinstance(parsed, ipaddress.IPv6Address):
        msg = "invalid IPv6 host"
        raise InvalidHostError(msg)
    return str(parsed), None, True


def _parse_host_and_port(authority: str) -> tuple[str, int | None, bool]:
    if not authority:
        msg = "origin is missing a host"
        raise InvalidOriginError(msg)
    if authority.startswith("["):
        return _parse_ip_literal(authority[1:])
    if "[" in authority or "]" in authority:
        msg = "malformed IP literal in origin"
        raise InvalidOriginError(msg)
    if "@" in authority:
        msg = "userinfo is not allowed in an origin"
        raise InvalidOriginError(msg)

    host, separator, port_text = authority.rpartition(":")
    if not separator:
        host, port_text = authority, ""
    if ":" in host:
        msg = "IPv6 origins must use bracket notation"
        raise InvalidOriginError(msg)
    if separator and not port_text:
        msg = "origin port must be a decimal integer"
        raise InvalidOriginError(msg)
    port = _parse_port(port_text) if port_text else None

    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        parsed_ip = None
    if isinstance(parsed_ip, ipaddress.IPv6Address):
        msg = "IPv6 origins must use bracket notation"
        raise InvalidOriginError(msg)
    if isinstance(parsed_ip, ipaddress.IPv4Address):
        # Re-format so equivalent spellings compare identically. Python
        # already rejects ambiguous leading-zero addresses above.
        return str(ipaddress.IPv4Address(int(parsed_ip))), port, False
    if _looks_like_ipv4(host):
        msg = "invalid IPv4 address in origin"
        raise InvalidOriginError(msg)
    if any(char not in _REG_NAME_CHARS for char in host):
        msg = "origin host contains illegal characters"
        raise InvalidOriginError(msg)
    if host.endswith("."):
        msg = "origin host must not have a trailing dot"
        raise InvalidOriginError(msg)
    if any(label == "" for label in host.split(".")):
        msg = "origin host contains an empty label"
        raise InvalidOriginError(msg)
    return host, port, False


def parse_origin(value: bytes | str) -> ParsedOrigin:
    """
    Strictly parse a single serialized origin.

    :param value: one raw ``Origin`` header value.
    :raises NullOriginError: if the value is the opaque ``null`` origin.
    :raises InvalidOriginError: if the value is not a valid origin.
    """
    if isinstance(value, bytes):
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError as exc:
            msg = "origin is not ASCII"
            raise InvalidOriginError(msg) from exc
    else:
        text = value
    if text == "null":
        msg = "the null origin is not trusted"
        raise NullOriginError(msg)
    if not text:
        msg = "origin header value is empty"
        raise InvalidOriginError(msg)

    scheme_separator = text.find("://")
    if scheme_separator <= 0:
        msg = "origin must be scheme://host[:port]"
        raise InvalidOriginError(msg)
    scheme = text[:scheme_separator].lower()
    if not scheme[0].isalpha() or any(char not in _SCHEME_CHARS for char in scheme):
        msg = "origin scheme is invalid"
        raise InvalidOriginError(msg)

    authority = text[scheme_separator + 3 :]
    if not authority or "/" in authority or "?" in authority or "#" in authority:
        msg = "origin must not contain a path, query or fragment"
        raise InvalidOriginError(msg)

    host, port, ipv6 = _parse_host_and_port(authority)
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    return ParsedOrigin(scheme=scheme, host=host, port=port, ipv6=ipv6)


def _parse_host_port(text: str) -> int:
    if not text or any(char not in _DIGITS for char in text):
        msg = "host port must be a decimal integer"
        raise InvalidHostError(msg)
    port = int(text)
    if port > 65535:
        msg = "host port is out of range"
        raise InvalidHostError(msg)
    return port


def parse_host(value: bytes | str) -> ParsedHost:
    """
    Strictly parse an HTTP ``Host`` header value.

    The host is returned in lowercase canonical ASCII form so it can be
    compared structurally with the host component of a parsed origin.
    """
    if isinstance(value, bytes):
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError as exc:
            msg = "host header is not ASCII"
            raise InvalidHostError(msg) from exc
    else:
        text = value
    text = text.strip()
    if not text:
        msg = "host header value is empty"
        raise InvalidHostError(msg)
    if "@" in text or "/" in text or " " in text:
        msg = "host header contains illegal characters"
        raise InvalidHostError(msg)

    if text.startswith("["):
        host, port, ipv6 = _parse_ip_literal(text[1:], invalid=InvalidHostError)
        return ParsedHost(host=host, port=port, ipv6=ipv6)

    if text.count(":") >= 2:
        host, port, ipv6 = _parse_bare_ipv6_host(text)
        return ParsedHost(host=host, port=port, ipv6=ipv6)

    host, separator, port_text = text.rpartition(":")
    if not separator:
        host, port_text = text, ""
    if separator and not port_text:
        msg = "host port must be a decimal integer"
        raise InvalidHostError(msg)
    port = _parse_host_port(port_text) if port_text else None

    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        parsed_ip = None
    if isinstance(parsed_ip, ipaddress.IPv6Address):
        msg = "IPv6 host must use bracket notation"
        raise InvalidHostError(msg)
    if isinstance(parsed_ip, ipaddress.IPv4Address):
        return ParsedHost(
            host=str(ipaddress.IPv4Address(int(parsed_ip))),
            port=port,
            ipv6=False,
        )
    if _looks_like_ipv4(host):
        msg = "invalid IPv4 address in host header"
        raise InvalidHostError(msg)
    canonical = host.lower()
    if any(char not in _REG_NAME_CHARS for char in canonical):
        msg = "host header contains illegal characters"
        raise InvalidHostError(msg)
    if any(label == "" for label in canonical.split(".")):
        msg = "host header contains an empty label"
        raise InvalidHostError(msg)
    return ParsedHost(host=canonical, port=port, ipv6=False)


def _split_origin_fields(values: Sequence[bytes]) -> list[bytes]:
    tokens: list[bytes] = []
    for value in values:
        stripped = _strip_ows(value)
        if not stripped:
            msg = "origin header value is empty"
            raise InvalidOriginError(msg)
        tokens.extend(stripped.split())
    return tokens


@dataclass(frozen=True)
class OriginPolicy:
    """
    Server-side handshake admission policy based on parsed origins.

    Trust is an explicit set of complete origins.  Matching is structural
    over scheme, host and port, so subdomains, different schemes and
    lookalike sibling domains are never accepted by accident.  The browser
    edge cases can each be configured independently.

    :param allowed_origins: complete trusted origins, each either a
        :class:`ParsedOrigin` or a serialized origin string.
    :param allow_missing_origin: permit requests without any ``Origin``
        header, as sent by some non-browser clients.
    :param allow_null_origin: permit the literal opaque ``null`` origin.
    :param allow_multiple_origins: when several values are present, require
        every one of them to be in the trusted set.  Repeated identical
        values stay distinct header lines and are always rejected.
    """

    allowed_origins: Iterable[ParsedOrigin | str]
    allow_missing_origin: bool = False
    allow_null_origin: bool = False
    allow_multiple_origins: bool = False
    _allowed: frozenset[ParsedOrigin] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        parsed: set[ParsedOrigin] = set()
        for origin in self.allowed_origins:
            if isinstance(origin, ParsedOrigin):
                parsed.add(origin)
            else:
                try:
                    parsed.add(parse_origin(origin))
                except NullOriginError as exc:
                    msg = "the null origin cannot be part of the trusted set"
                    raise ValueError(msg) from exc
        object.__setattr__(self, "_allowed", frozenset(parsed))
        if not parsed and not (
            self.allow_missing_origin
            or self.allow_null_origin
            or self.allow_multiple_origins
        ):
            msg = "an origin policy must trust at least one origin"
            raise ValueError(msg)

    def admit(
        self,
        origin_values: Sequence[bytes],
        host_value: bytes | str,
    ) -> list[ParsedOrigin]:
        """
        Evaluate a handshake and return its parsed, trusted origins.

        :param origin_values: every raw ``Origin`` header line, in wire
            order.  An empty sequence means the header was absent.
        :param host_value: the raw ``Host`` header of the same request.
        :raises OriginPolicyError: on any configured denial or parse error.
        """
        # Validate the Host structurally: a malformed Host must never reach
        # the application as a Request regardless of the missing/null flags.
        parse_host(host_value)

        if not origin_values:
            if self.allow_missing_origin:
                return []
            msg = "request is missing an Origin header"
            raise MissingOriginError(msg)

        tokens = _split_origin_fields(origin_values)
        if len(tokens) > 1:
            if not self.allow_multiple_origins:
                msg = "requests may only carry a single origin"
                raise MultipleOriginsError(msg)
            if len(tokens) != len(set(tokens)):
                # Two header lines must never collapse into one source.
                msg = "duplicate origin values are not allowed"
                raise MultipleOriginsError(msg)
        if len(tokens) > 1 and any(token == b"null" for token in tokens):
            msg = "the null origin cannot be combined with other origins"
            raise NullOriginError(msg)

        origins: list[ParsedOrigin] = []
        for token in tokens:
            if token == b"null":
                if not self.allow_null_origin:
                    msg = "the null origin is not trusted"
                    raise NullOriginError(msg)
                continue
            parsed = parse_origin(token)
            if parsed not in self._allowed:
                msg = "origin is not in the trusted set"
                raise UntrustedOriginError(msg)
            origins.append(parsed)
        return origins

    def __call__(
        self,
        origin_values: Sequence[bytes],
        host_value: bytes | str,
    ) -> list[ParsedOrigin]:
        return self.admit(origin_values, host_value)


def enforce_origin_policy(
    policy: OriginPolicy,
    origin_values: Sequence[bytes],
    host_value: bytes | str,
) -> list[ParsedOrigin]:
    """
    Run a policy and translate a denial into a handshake rejection.

    This is the hook used by the server handshake: a policy failure keeps
    the normal HTTP rejection flow and never establishes a WebSocket
    connection.  The rejection uses a fixed status and no dynamic headers,
    so the untrusted origin value is never reflected back to the peer.
    """
    try:
        return policy.admit(origin_values, host_value)
    except OriginPolicyError as exc:
        raise RemoteProtocolError(
            str(exc),
            event_hint=RejectConnection(status_code=403),
        ) from exc
