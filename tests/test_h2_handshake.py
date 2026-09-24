from __future__ import annotations

import pytest
from wsproto.connection import CLIENT, SERVER, Connection, ConnectionState
from wsproto.events import (
    AcceptConnection,
    CloseConnection,
    RejectConnection,
    Request,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.frame_protocol import CloseReason
from wsproto.handshake import H2Handshake
from wsproto.utilities import LocalProtocolError, RemoteProtocolError

from .helpers import FakeExtension


def request_headers(**kwargs: bytes) -> list[tuple[bytes, bytes]]:
    headers = [
        (b":method", b"CONNECT"),
        (b":protocol", b"websocket"),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b":authority", b"localhost"),
        (b"sec-websocket-version", b"13"),
    ]
    return [
        (name, kwargs.get(name.decode("ascii"), value)) for name, value in headers
    ]


def test_successful_handshake() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)

    server.receive_headers(client.send(Request(host="localhost", target="/")))
    assert isinstance(next(server.events()), Request)

    client.receive_headers(server.send(AcceptConnection()))
    assert isinstance(next(client.events()), AcceptConnection)

    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN

    assert repr(client) == "H2Handshake(client=True, state=ConnectionState.OPEN)"
    assert repr(server) == "H2Handshake(client=False, state=ConnectionState.OPEN)"


def test_request_headers() -> None:
    client = H2Handshake(CLIENT)
    headers = client.send(
        Request(
            host="localhost",
            target="/chat",
            subprotocols=["chat", "superchat"],
            extra_headers=[(b"origin", b"http://example.com")],
        ),
    )
    # RFC 8441 extended CONNECT pseudo-headers.
    assert (b":method", b"CONNECT") in headers
    assert (b":protocol", b"websocket") in headers
    assert (b":scheme", b"https") in headers
    assert (b":path", b"/chat") in headers
    assert (b":authority", b"localhost") in headers
    assert (b"sec-websocket-version", b"13") in headers
    assert (b"sec-websocket-protocol", b"chat, superchat") in headers
    assert (b"origin", b"http://example.com") in headers
    # The HTTP/1.1 upgrade machinery must not be used.
    names = [name for name, _ in headers]
    assert b"sec-websocket-key" not in names
    assert b"upgrade" not in names
    assert b"connection" not in names


def test_request_headers_scheme_override() -> None:
    client = H2Handshake(CLIENT)
    headers = client.send(
        Request(
            host="localhost",
            target="/",
            extra_headers=[(b":scheme", b"http")],
        ),
    )
    schemes = [value for name, value in headers if name == b":scheme"]
    assert schemes == [b"http"]


def test_server_request_event() -> None:
    server = H2Handshake(SERVER)
    server.receive_headers(
        [
            *request_headers(),
            (b"sec-websocket-protocol", b"chat, superchat"),
            (b"sec-websocket-extensions", b"permessage-deflate"),
            (b"origin", b"http://example.com"),
        ],
    )
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "localhost"
    assert request.target == "/"
    assert request.subprotocols == ["chat", "superchat"]
    assert request.extensions == ["permessage-deflate"]
    assert (b"origin", b"http://example.com") in request.extra_headers
    # Pseudo-headers and negotiated headers are not passed through.
    assert not any(name.startswith(b":") for name, _ in request.extra_headers)


def test_server_request_does_not_require_websocket_key() -> None:
    server = H2Handshake(SERVER)
    # No Sec-WebSocket-Key header: valid for RFC 8441.
    server.receive_headers(request_headers())
    assert isinstance(next(server.events()), Request)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (b":method", b"GET"),
        (b":protocol", b"not-websocket"),
        (b":scheme", None),
        (b":path", None),
        (b":authority", None),
        (b"sec-websocket-version", b"12"),
        (b"sec-websocket-version", None),
    ],
)
def test_server_rejects_bad_requests(name: bytes, value: bytes | None) -> None:
    headers = [
        (header_name, header_value)
        for header_name, header_value in request_headers()
        if header_name != name
    ]
    if value is not None:
        headers.append((name, value))
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_headers(headers)
    assert isinstance(excinfo.value.event_hint, RejectConnection)


def test_server_rejects_old_version_with_426_hint() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_headers(request_headers(**{"sec-websocket-version": b"12"}))
    assert excinfo.value.event_hint.status_code == 426


def test_accept_response_headers() -> None:
    server = H2Handshake(SERVER)
    server.receive_headers(
        [*request_headers(), (b"sec-websocket-protocol", b"chat")],
    )
    next(server.events())
    headers = server.send(
        AcceptConnection(
            subprotocol="chat",
            extra_headers=[(b"x-extra", b"value")],
        ),
    )
    # A 200 response, not a 101.
    assert (b":status", b"200") in headers
    assert (b"sec-websocket-protocol", b"chat") in headers
    assert (b"x-extra", b"value") in headers
    names = [name for name, _ in headers]
    assert b"sec-websocket-accept" not in names
    assert b"upgrade" not in names


def test_accept_unoffered_subprotocol() -> None:
    server = H2Handshake(SERVER)
    server.receive_headers(request_headers())
    next(server.events())
    with pytest.raises(LocalProtocolError):
        server.send(AcceptConnection(subprotocol="chat"))


def test_extension_negotiation() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)

    request_headers_out = client.send(
        Request(host="localhost", target="/", extensions=[FakeExtension(True)]),
    )
    assert (b"sec-websocket-extensions", b"fake") in request_headers_out

    server.receive_headers(request_headers_out)
    next(server.events())
    response_headers = server.send(
        AcceptConnection(extensions=[FakeExtension(True, "offer")]),
    )
    assert (b"sec-websocket-extensions", b"fake; offer") in response_headers

    client.receive_headers(response_headers)
    event = next(client.events())
    assert isinstance(event, AcceptConnection)
    assert len(event.extensions) == 1
    assert event.extensions[0].accepted_offer == "fake; offer"


def test_client_rejects_unoffered_subprotocol() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/", subprotocols=["chat"]))
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_headers(
            [(b":status", b"200"), (b"sec-websocket-protocol", b"other")],
        )
    assert isinstance(excinfo.value.event_hint, RejectConnection)


def test_client_rejects_unoffered_extension() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/"))
    with pytest.raises(RemoteProtocolError):
        client.receive_headers(
            [(b":status", b"200"), (b"sec-websocket-extensions", b"fake")],
        )


@pytest.mark.parametrize("status", [b"400", b"404", b"500"])
def test_client_rejected_handshake(status: bytes) -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/"))
    client.receive_headers([(b":status", status), (b"content-type", b"text/plain")])
    event = next(client.events())
    assert isinstance(event, RejectConnection)
    assert event.status_code == int(status)
    assert (b"content-type", b"text/plain") in event.headers
    assert client.state is ConnectionState.CLOSED
    assert client.connection is None


def test_client_response_missing_status() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/"))
    with pytest.raises(RemoteProtocolError):
        client.receive_headers([(b"sec-websocket-protocol", b"chat")])


def test_client_response_bad_status() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/"))
    with pytest.raises(RemoteProtocolError):
        client.receive_headers([(b":status", b"not-a-number")])


def test_client_response_before_request() -> None:
    client = H2Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.receive_headers([(b":status", b"200")])


def test_send_invalid_events() -> None:
    client = H2Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(TextMessage(data="hi"))
    with pytest.raises(LocalProtocolError):
        client.send(AcceptConnection())

    server = H2Handshake(SERVER)
    with pytest.raises(LocalProtocolError):
        server.send(Request(host="localhost", target="/"))
    with pytest.raises(LocalProtocolError):
        server.send(AcceptConnection())


def test_receive_headers_after_handshake() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)
    server.receive_headers(client.send(Request(host="localhost", target="/")))
    next(server.events())
    client.receive_headers(server.send(AcceptConnection()))
    next(client.events())
    with pytest.raises(LocalProtocolError):
        client.receive_headers([(b":status", b"200")])
    with pytest.raises(LocalProtocolError):
        server.receive_headers(request_headers())


def establish_connections() -> tuple[Connection, Connection]:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)
    server.receive_headers(client.send(Request(host="localhost", target="/")))
    next(server.events())
    client.receive_headers(server.send(AcceptConnection()))
    next(client.events())
    client_connection = client.connection
    server_connection = server.connection
    assert client_connection is not None
    assert server_connection is not None
    return client_connection, server_connection


def test_data_transfer_after_handshake() -> None:
    client_connection, server_connection = establish_connections()

    # A fragmented text message, client to server.
    server_connection.receive_data(
        client_connection.send(TextMessage(data="hello ", message_finished=False)),
    )
    server_connection.receive_data(
        client_connection.send(TextMessage(data="world", message_finished=True)),
    )
    events = list(server_connection.events())
    assert events == [
        TextMessage(data="hello ", frame_finished=True, message_finished=False),
        TextMessage(data="world", frame_finished=True, message_finished=True),
    ]

    # And back, server to client.
    client_connection.receive_data(
        server_connection.send(TextMessage(data="hi")),
    )
    assert list(client_connection.events()) == [TextMessage(data="hi")]


def test_end_stream_is_abnormal_closure_without_close_frame() -> None:
    client_connection, server_connection = establish_connections()
    # An HTTP/2 END_STREAM (fed in as None) without a Close frame is an
    # abnormal closure, never a normal (1000) close.
    server_connection.receive_data(None)
    event = next(server_connection.events())
    assert isinstance(event, CloseConnection)
    assert event.code is CloseReason.ABNORMAL_CLOSURE
    assert server_connection.state is ConnectionState.CLOSED


def test_end_stream_after_close_handshake_is_a_no_op() -> None:
    client_connection, server_connection = establish_connections()
    server_connection.receive_data(
        client_connection.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE)),
    )
    event = next(server_connection.events())
    assert isinstance(event, CloseConnection)
    client_connection.receive_data(server_connection.send(event.response()))
    assert isinstance(next(client_connection.events()), CloseConnection)
    assert client_connection.state is ConnectionState.CLOSED
    assert server_connection.state is ConnectionState.CLOSED

    # The HTTP/2 END_STREAM that terminates the stream afterwards does
    # not fabricate another CloseConnection event.
    server_connection.receive_data(None)
    client_connection.receive_data(None)
    assert list(server_connection.events()) == []
    assert list(client_connection.events()) == []


def test_rst_stream_style_teardown_is_abnormal() -> None:
    # An HTTP/2 RST_STREAM is surfaced by tearing the frame layer down
    # with receive_data(None): the result is an abnormal closure (1006),
    # not a fabricated normal Close frame.
    client_connection, _ = establish_connections()
    client_connection.receive_data(None)
    event = next(client_connection.events())
    assert isinstance(event, CloseConnection)
    assert event.code is CloseReason.ABNORMAL_CLOSURE
    assert event.code is not CloseReason.NORMAL_CLOSURE


def test_permessage_deflate_roundtrip() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)
    server.receive_headers(
        client.send(
            Request(host="localhost", target="/", extensions=[PerMessageDeflate()]),
        ),
    )
    next(server.events())
    client.receive_headers(
        server.send(AcceptConnection(extensions=[PerMessageDeflate()])),
    )
    next(client.events())

    client_connection = client.connection
    server_connection = server.connection
    assert client_connection is not None
    assert server_connection is not None

    payload = "compressible " * 100
    wire_data = client_connection.send(TextMessage(data=payload))
    # The message was actually compressed on the wire.
    assert len(wire_data) < len(payload)
    server_connection.receive_data(wire_data)
    assert list(server_connection.events()) == [TextMessage(data=payload)]
