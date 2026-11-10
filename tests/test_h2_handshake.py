from __future__ import annotations

import pytest

from wsproto import H2Handshake
from wsproto.connection import CLIENT, SERVER, ConnectionState
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Ping,
    RejectConnection,
    RejectData,
    Request,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.frame_protocol import CloseReason
from wsproto.h2 import (
    ENABLE_CONNECT_PROTOCOL,
    H2Data,
    H2EndStream,
    H2ErrorCode,
    H2Request,
    H2Reset,
    H2ResetStream,
    H2Response,
    H2SendData,
    H2SendHeaders,
)
from wsproto.utilities import LocalProtocolError, RemoteProtocolError

from .helpers import FakeExtension


def _connect_request(
    stream_id: int = 1,
    *,
    method: bytes = b"CONNECT",
    scheme: bytes = b"https",
    authority: bytes = b"example.com",
    path: bytes = b"/chat",
    protocol: bytes | None = b"websocket",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> H2Request:
    return H2Request(
        stream_id=stream_id,
        method=method,
        scheme=scheme,
        authority=authority,
        path=path,
        protocol=protocol,
        headers=headers if headers is not None else [(b"sec-websocket-protocol", b"chat, rpc")],
    )


def _established_pair(
    stream_id: int = 1,
) -> tuple[H2Handshake, H2Handshake]:
    client = H2Handshake(CLIENT, extensions=[PerMessageDeflate()])
    client.send(
        Request(
            host="example.com",
            target="/chat",
            subprotocols=["chat", "rpc"],
            extensions=[PerMessageDeflate()],
        ),
        stream_id=stream_id,
    )
    server = H2Handshake(
        SERVER,
        extensions=[PerMessageDeflate()],
        connect_protocol_enabled=True,
    )
    server.receive_event(_connect_request(stream_id))
    request = next(server.events())
    assert isinstance(request, Request)
    accept = server.send(
        AcceptConnection(subprotocol="chat", extensions=[PerMessageDeflate()]),
    )
    assert isinstance(accept, H2SendHeaders)
    client.receive_event(
        H2Response(stream_id=stream_id, status_code=200, headers=accept.headers[1:]),
    )
    assert isinstance(next(client.events()), AcceptConnection)
    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN
    return client, server


def test_settings_identifier() -> None:
    # RFC 8441, Section 3.
    assert ENABLE_CONNECT_PROTOCOL == 0x8


def test_successful_handshake_emits_structured_events() -> None:
    client = H2Handshake(CLIENT)
    request_event = client.send(
        Request(host="example.com", target="/chat", subprotocols=["chat"]),
        stream_id=3,
    )
    assert isinstance(request_event, H2SendHeaders)
    assert request_event.stream_id == 3
    assert request_event.end_stream is False
    assert (b":method", b"CONNECT") in request_event.headers
    assert (b":protocol", b"websocket") in request_event.headers
    assert (b":scheme", b"https") in request_event.headers
    assert (b":authority", b"example.com") in request_event.headers
    assert (b":path", b"/chat") in request_event.headers
    # No HTTP/1.1 upgrade headers are ever generated.
    assert all(name not in {b"upgrade", b"connection", b"sec-websocket-key"}
               for name, _ in request_event.headers)

    server = H2Handshake(SERVER, connect_protocol_enabled=True)
    server.receive_event(
        H2Request(
            stream_id=3,
            method=b"CONNECT",
            scheme=b"https",
            authority=b"example.com",
            path=b"/chat",
            protocol=b"websocket",
            headers=[(b"sec-websocket-protocol", b"chat")],
        ),
    )
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "example.com"
    assert request.target == "/chat"
    assert request.subprotocols == ["chat"]
    assert request.scheme == "https"

    accept = server.send(AcceptConnection(subprotocol="chat"))
    assert isinstance(accept, H2SendHeaders)
    assert accept.headers[0] == (b":status", b"200")
    assert (b"sec-websocket-protocol", b"chat") in accept.headers
    assert all(name != b"sec-websocket-accept" for name, _ in accept.headers)

    client.receive_event(H2Response(3, 200, accept.headers[1:]))
    accepted = next(client.events())
    assert isinstance(accepted, AcceptConnection)
    assert accepted.subprotocol == "chat"
    assert client.state is ConnectionState.OPEN
    assert client.connection is not None
    assert server.connection is not None


def test_extension_negotiation_roundtrip() -> None:
    client = H2Handshake(CLIENT, extensions=[FakeExtension(offer_response="param=1")])
    outgoing = client.send(
        Request(host="example.com", target="/", extensions=[FakeExtension(offer_response="param=1")]),
        stream_id=1,
    )
    assert (b"sec-websocket-extensions", b"fake; param=1") in outgoing.headers

    server_extension = FakeExtension(accept_response="param=1")
    server = H2Handshake(SERVER, extensions=[server_extension], connect_protocol_enabled=True)
    server.receive_event(
        _connect_request(headers=[(b"sec-websocket-extensions", b"fake; param=1")]),
    )
    next(server.events())
    accept = server.send(AcceptConnection(extensions=[server_extension]))
    assert (b"sec-websocket-extensions", b"fake; param=1") in accept.headers

    client.receive_event(H2Response(1, 200, accept.headers[1:]))
    accepted = next(client.events())
    assert isinstance(accepted, AcceptConnection)
    assert accepted.extensions  # finalized and enabled on the client


def test_server_rejects_when_connect_protocol_not_negotiated() -> None:
    server = H2Handshake(SERVER, connect_protocol_enabled=False)
    server.receive_event(_connect_request())

    rejection = next(server.events())
    assert isinstance(rejection, RejectConnection)
    assert rejection.status_code == 405

    outgoing = server.send(rejection)
    assert isinstance(outgoing, H2SendHeaders)
    assert (b":status", b"405") in outgoing.headers
    assert outgoing.end_stream is True
    assert server.state is ConnectionState.CLOSED
    # No WebSocket connection was ever created.
    assert server.connection is None


def test_bad_pseudo_headers_are_rejected() -> None:
    server = H2Handshake(SERVER, connect_protocol_enabled=True)

    cases = [
        _connect_request(method=b"GET"),
        _connect_request(protocol=None),
        _connect_request(protocol=b"h2c"),
        _connect_request(scheme=b""),
        _connect_request(authority=b""),
        _connect_request(path=b""),
    ]
    for bad_request in cases:
        with pytest.raises(RemoteProtocolError) as exc_info:
            server.receive_event(bad_request)
        assert isinstance(exc_info.value.event_hint, RejectConnection)
        # A failed stream must not expose a WebSocket connection.
        assert server.connection is None
        server = H2Handshake(SERVER, connect_protocol_enabled=True)


@pytest.mark.parametrize(
    "forbidden",
    [
        b"connection",
        b"upgrade",
        b"sec-websocket-key",
        b"sec-websocket-version",
    ],
)
def test_http11_upgrade_headers_are_forbidden_on_request(forbidden: bytes) -> None:
    server = H2Handshake(SERVER, connect_protocol_enabled=True)
    request = _connect_request(headers=[(forbidden, b"something")])
    with pytest.raises(RemoteProtocolError) as exc_info:
        server.receive_event(request)
    assert exc_info.value.event_hint.status_code == 400


@pytest.mark.parametrize(
    "forbidden",
    [b"connection", b"upgrade", b"sec-websocket-accept", b"sec-websocket-version"],
)
def test_http11_success_headers_are_forbidden_on_response(forbidden: bytes) -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="example.com", target="/chat"), stream_id=1)
    response = H2Response(1, 200, [(forbidden, b"something")])
    with pytest.raises(RemoteProtocolError):
        client.receive_event(response)
    assert client.state is ConnectionState.CLOSED


def test_non_200_response_rejects_and_delivers_body() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="example.com", target="/chat"), stream_id=1)

    client.receive_event(H2Response(1, 404, [(b"content-length", b"5")]))
    rejection = next(client.events())
    assert isinstance(rejection, RejectConnection)
    assert rejection.status_code == 404
    assert rejection.has_body is True

    client.receive_event(H2Data(1, b"sorry", end_stream=True))
    body = next(client.events())
    assert isinstance(body, RejectData)
    assert body.data == b"sorry"
    assert body.body_finished is False
    finished = next(client.events())
    assert isinstance(finished, RejectData)
    assert finished.body_finished is True
    assert client.state is ConnectionState.CLOSED
    # DATA belonging to the rejection never reaches the frame parser.
    assert client.connection is None


def test_client_data_before_success_is_not_a_websocket_message() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="example.com", target="/chat"), stream_id=1)

    stray_frame = b"\x81\x02hi"  # A valid-looking TEXT frame.
    with pytest.raises(RemoteProtocolError):
        client.receive_event(H2Data(1, stray_frame))
    assert list(client.events()) == []
    assert client.connection is None
    assert client.state is ConnectionState.CLOSED


def test_data_after_failed_handshake_is_reject_body_not_message() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="example.com", target="/chat"), stream_id=1)
    client.receive_event(H2Response(1, 500, []))
    assert isinstance(next(client.events()), RejectConnection)

    stray_frame = b"\x81\x02hi"  # Would parse as a TEXT frame once established.
    client.receive_event(H2Data(1, stray_frame))
    body = next(client.events())
    assert isinstance(body, RejectData)
    assert body.data == stray_frame
    assert body.body_finished is False
    assert client.connection is None

    client.receive_event(H2EndStream(1))
    finished = next(client.events())
    assert isinstance(finished, RejectData)
    assert finished.body_finished is True
    assert client.state is ConnectionState.CLOSED


def test_server_reject_with_body_emits_headers_then_data() -> None:
    server = H2Handshake(SERVER, connect_protocol_enabled=True)
    server.receive_event(_connect_request(stream_id=2))
    assert isinstance(next(server.events()), Request)

    headers = server.send(
        RejectConnection(status_code=403, has_body=True, headers=[(b"content-length", b"3")]),
    )
    assert isinstance(headers, H2SendHeaders)
    assert (b":status", b"403") in headers.headers
    assert headers.end_stream is False
    assert server.state is ConnectionState.REJECTING

    body = server.send(RejectData(b"bye", body_finished=True))
    assert isinstance(body, H2SendData)
    assert body.data == b"bye"
    assert body.end_stream is True
    assert server.state is ConnectionState.CLOSED
    assert server.connection is None


def test_server_data_before_handshake_is_rejected() -> None:
    server = H2Handshake(SERVER, connect_protocol_enabled=True)
    with pytest.raises(RemoteProtocolError):
        server.receive_event(H2Data(7, b"\x81\x02hi"))
    assert server.connection is None


def test_informational_response_does_not_open_connection() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="example.com", target="/chat"), stream_id=1)
    client.receive_event(H2Response(1, 103, []))
    assert client.state is ConnectionState.CONNECTING
    assert list(client.events()) == []

    client.receive_event(H2Response(1, 200, []))
    assert isinstance(next(client.events()), AcceptConnection)
    assert client.state is ConnectionState.OPEN


def test_unexpected_subprotocol_rejected() -> None:
    client = H2Handshake(CLIENT)
    client.send(
        Request(host="example.com", target="/chat", subprotocols=["chat"]),
        stream_id=1,
    )
    with pytest.raises(RemoteProtocolError):
        client.receive_event(
            H2Response(1, 200, [(b"sec-websocket-protocol", b"not-offered")]),
        )


def test_data_after_handshake_flows_through_connection() -> None:
    client, server = _established_pair()

    outgoing = client.send(TextMessage(data="hello"))
    assert isinstance(outgoing, H2SendData)
    assert outgoing.end_stream is False
    server.receive_event(H2Data(1, outgoing.data))
    message = next(server.events())
    assert isinstance(message, TextMessage)
    assert message.data == "hello"

    ping = server.send(Ping(payload=b"p"))
    client.receive_event(H2Data(1, ping.data))
    received_ping = next(client.events())
    assert isinstance(received_ping, Ping)
    assert received_ping.payload == b"p"


def test_websocket_close_handshake_does_not_end_the_stream() -> None:
    client, server = _established_pair()

    close_frame = client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    assert isinstance(close_frame, H2SendData)
    assert close_frame.end_stream is False

    server.receive_event(H2Data(1, close_frame.data))
    close_event = next(server.events())
    assert isinstance(close_event, CloseConnection)
    assert close_event.code is CloseReason.NORMAL_CLOSURE
    assert server.state is ConnectionState.REMOTE_CLOSING

    response = server.send(close_event.response())
    assert isinstance(response, H2SendData)
    assert response.end_stream is False
    client.receive_event(H2Data(1, response.data))
    assert next(client.events()).code is CloseReason.NORMAL_CLOSURE
    # Both peers completed the WS close but the stream itself is not half-closed.
    assert server.state is ConnectionState.CLOSED


def test_end_stream_without_close_frame_is_abnormal_closure() -> None:
    client, server = _established_pair()

    server.receive_event(H2EndStream(1))
    close_event = next(server.events())
    assert isinstance(close_event, CloseConnection)
    assert close_event.code is CloseReason.ABNORMAL_CLOSURE
    assert server.state is ConnectionState.CLOSED

    # The adapter never fabricates a WebSocket CLOSE frame for END_STREAM.
    with pytest.raises(LocalProtocolError):
        server.send(close_event.response())


def test_data_with_end_stream_after_close_is_normal_completion() -> None:
    client, server = _established_pair()

    close_frame = client.send(CloseConnection(code=1000))
    server.receive_event(H2Data(1, close_frame.data))
    assert isinstance(next(server.events()), CloseConnection)
    # The client then half-closes; this must not report a second closure.
    server.receive_event(H2Data(1, b"", end_stream=True))
    assert list(server.events()) == []
    assert server.state is ConnectionState.CLOSED


def test_remote_reset_is_abnormal_closure() -> None:
    client, server = _established_pair()

    server.receive_event(H2Reset(1, H2ErrorCode.PROTOCOL_ERROR))
    close_event = next(server.events())
    assert isinstance(close_event, CloseConnection)
    assert close_event.code is CloseReason.ABNORMAL_CLOSURE
    assert "1" in (close_event.reason or "")
    assert server.state is ConnectionState.CLOSED


def test_local_reset_only_targets_own_stream() -> None:
    client, server = _established_pair(stream_id=1)
    reset = server.reset_stream(H2ErrorCode.CANCEL)
    assert isinstance(reset, H2ResetStream)
    assert reset.stream_id == 1
    assert reset.error_code is H2ErrorCode.CANCEL
    assert server.state is ConnectionState.CLOSED
    # A second reset is a no-op rather than raising.
    server.receive_event(H2Reset(1))


def test_local_end_stream_event_is_half_close() -> None:
    client, server = _established_pair()
    event = client.end_stream()
    assert isinstance(event, H2SendData)
    assert event.data == b""
    assert event.end_stream is True
    # Half-closing the send side does not stop inbound WebSocket frames.
    server_frame = server.send(BytesMessage(data=b"still coming"))
    client.receive_event(H2Data(1, server_frame.data))
    assert isinstance(next(client.events()), BytesMessage)


def test_streams_are_independent_adapters() -> None:
    client_one, server_one = _established_pair(stream_id=1)
    client_two, server_two = _established_pair(stream_id=3)

    # Reset stream 1 on the server transport only.
    server_one.receive_event(H2Reset(1, H2ErrorCode.CANCEL))
    assert isinstance(next(server_one.events()), CloseConnection)
    assert server_one.state is ConnectionState.CLOSED

    # Stream 3 is untouched and keeps exchanging messages.
    assert server_two.state is ConnectionState.OPEN
    frame = client_two.send(TextMessage(data="stream three"))
    server_two.receive_event(H2Data(3, frame.data))
    assert isinstance(next(server_two.events()), TextMessage)

    # The client side of stream 1 is also independent of stream 3.
    assert client_one.state is ConnectionState.OPEN
    assert client_two.state is ConnectionState.OPEN


def test_stream_id_mismatch_is_rejected() -> None:
    client, _ = _established_pair(stream_id=1)
    with pytest.raises(LocalProtocolError):
        client.receive_event(H2Data(9, b"abc"))


def test_repr_contains_stream_and_state() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="example.com", target="/"), stream_id=5)
    assert repr(client) == "H2Handshake(client=True, stream_id=5, state=ConnectionState.CONNECTING)"


def test_role_checks_and_local_state_guards() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER, connect_protocol_enabled=True)

    # A client cannot receive requests, a server cannot receive responses.
    with pytest.raises(LocalProtocolError):
        client.receive_event(_connect_request())
    with pytest.raises(LocalProtocolError):
        server.receive_event(H2Response(1, 200))

    # A server cannot initiate; a client CONNECT needs a stream id and cannot
    # be sent twice.
    with pytest.raises(LocalProtocolError):
        server.send(Request(host="example.com", target="/"))
    with pytest.raises(LocalProtocolError):
        client.send(Request(host="example.com", target="/"))

    client.send(Request(host="example.com", target="/"), stream_id=1)
    with pytest.raises(LocalProtocolError):
        client.send(Request(host="example.com", target="/"), stream_id=3)

    # No stream operations before a server-side stream is known.
    with pytest.raises(LocalProtocolError):
        server.end_stream()
    with pytest.raises(LocalProtocolError):
        server.reset_stream()

    # Accepting/rejecting is server-only and needs a request first.
    with pytest.raises(LocalProtocolError):
        client.send(AcceptConnection())
    with pytest.raises(LocalProtocolError):
        client.send(RejectConnection())


def test_server_rejects_unexpected_subprotocol() -> None:
    server = H2Handshake(SERVER, connect_protocol_enabled=True)
    server.receive_event(_connect_request())
    assert isinstance(next(server.events()), Request)
    with pytest.raises(LocalProtocolError):
        server.send(AcceptConnection(subprotocol="not-offered"))


def test_boolean_extension_offer_roundtrip() -> None:
    offered = FakeExtension(offer_response=True)
    client = H2Handshake(CLIENT, extensions=[offered])
    outgoing = client.send(
        Request(host="example.com", target="/", extensions=[offered]),
        stream_id=1,
    )
    assert (b"sec-websocket-extensions", b"fake") in outgoing.headers

    accepted = FakeExtension(accept_response=True)
    server = H2Handshake(SERVER, extensions=[accepted], connect_protocol_enabled=True)
    server.receive_event(
        _connect_request(headers=[(b"sec-websocket-extensions", b"fake")]),
    )
    next(server.events())
    accept = server.send(AcceptConnection(extensions=[accepted]))
    assert (b"sec-websocket-extensions", b"fake") in accept.headers

    client.receive_event(H2Response(1, 200, accept.headers[1:]))
    assert isinstance(next(client.events()), AcceptConnection)


def test_sending_frame_before_handshake_fails() -> None:
    client = H2Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(Ping(payload=b"x"))


def test_reject_data_requires_rejecting_state() -> None:
    client = H2Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(RejectData(b"x"))


def test_data_on_closed_stream_raises() -> None:
    client, _ = _established_pair()
    client.receive_event(H2EndStream(1))
    assert isinstance(next(client.events()), CloseConnection)
    with pytest.raises(LocalProtocolError):
        client.receive_event(H2Data(1, b"more"))


def test_end_stream_is_idempotent() -> None:
    client, _ = _established_pair()
    first = client.end_stream()
    second = client.end_stream()
    assert first == second
    assert second.end_stream is True
    assert client.state is ConnectionState.OPEN
