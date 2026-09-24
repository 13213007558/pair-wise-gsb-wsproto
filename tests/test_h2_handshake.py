from __future__ import annotations

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    DataReceived,
    RequestReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
)
from h2.settings import SettingCodes
from wsproto.connection import CLIENT, SERVER, Connection, ConnectionState
from wsproto.events import AcceptConnection, CloseConnection, Request, TextMessage
from wsproto.extensions import PerMessageDeflate
from wsproto.handshake import H2Handshake
from wsproto.utilities import LocalProtocolError, RemoteProtocolError


def test_h2_handshake_round_trip() -> None:
    client_extension = PerMessageDeflate()
    client = H2Handshake(CLIENT)
    request_headers = client.initiate_connection(
        Request(
            host="example.com",
            target="/chat",
            extensions=[client_extension],
            subprotocols=["chat", "other"],
        ),
    )

    request_header_dict = dict(request_headers)
    assert request_header_dict[b":method"] == b"CONNECT"
    assert request_header_dict[b":protocol"] == b"websocket"
    assert b"sec-websocket-key" not in request_header_dict
    assert b"upgrade" not in request_header_dict

    server = H2Handshake(SERVER)
    request = server.receive_headers(request_headers)
    assert isinstance(request, Request)
    assert request.host == "example.com"
    assert request.target == "/chat"
    assert request.subprotocols == ["chat", "other"]

    server_extension = PerMessageDeflate()
    response_headers = server.accept(
        AcceptConnection(subprotocol="chat", extensions=[server_extension]),
    )
    response_header_dict = dict(response_headers)
    assert b":status" not in response_header_dict
    assert b"sec-websocket-accept" not in response_header_dict
    assert response_header_dict[b"sec-websocket-protocol"] == b"chat"
    assert b"permessage-deflate" in response_header_dict[b"sec-websocket-extensions"]

    accepted = client.receive_headers([(b":status", b"200"), *response_headers])
    assert isinstance(accepted, AcceptConnection)
    assert accepted.subprotocol == "chat"
    assert accepted.extensions == [client_extension]

    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN
    assert isinstance(client.connection, Connection)
    assert isinstance(server.connection, Connection)


def test_h2_server_rejects_unoffered_subprotocol() -> None:
    server = H2Handshake(SERVER)
    server.receive_headers(
        [
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/chat"),
            (b"sec-websocket-version", b"13"),
            (b"sec-websocket-protocol", b"chat"),
        ],
    )

    with pytest.raises(LocalProtocolError, match="unexpected subprotocol"):
        server.accept(AcceptConnection(subprotocol="other"))


def test_h2_server_rejects_unoffered_extension() -> None:
    server = H2Handshake(SERVER)
    server.receive_headers(
        [
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/chat"),
            (b"sec-websocket-version", b"13"),
        ],
    )

    with pytest.raises(LocalProtocolError, match="selected from the request offers"):
        server.accept(AcceptConnection(extensions=[PerMessageDeflate()]))


def test_h2_request_rejects_http1_upgrade_headers() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError, match="cannot be used"):
        server.receive_headers(
            [
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/chat"),
                (b"sec-websocket-version", b"13"),
                (b"sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
            ],
        )


def test_h2_client_rejects_101_response() -> None:
    client = H2Handshake(CLIENT)
    client.initiate_connection(Request(host="example.com", target="/chat"))

    with pytest.raises(RemoteProtocolError, match="must not use 101"):
        client.receive_headers([(b":status", b"101")])


def test_h2_client_rejects_http1_accept_header() -> None:
    client = H2Handshake(CLIENT)
    client.initiate_connection(Request(host="example.com", target="/chat"))

    with pytest.raises(RemoteProtocolError, match="cannot be used"):
        client.receive_headers(
            [
                (b":status", b"200"),
                (b"sec-websocket-accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ],
        )


def test_h2_client_rejects_unoffered_subprotocol() -> None:
    client = H2Handshake(CLIENT)
    client.initiate_connection(
        Request(host="example.com", target="/chat", subprotocols=["chat"]),
    )

    with pytest.raises(RemoteProtocolError, match="unrecognized subprotocol"):
        client.receive_headers(
            [(b":status", b"200"), (b"sec-websocket-protocol", b"other")],
        )


def test_h2_client_rejects_unoffered_extension() -> None:
    client = H2Handshake(CLIENT)
    client.initiate_connection(Request(host="example.com", target="/chat"))

    with pytest.raises(RemoteProtocolError, match="unrecognized extension"):
        client.receive_headers(
            [(b":status", b"200"), (b"sec-websocket-extensions", b"permessage-deflate")],
        )


def _pump(sender: H2Connection, receiver: H2Connection) -> list[object]:
    data = sender.data_to_send()
    if not data:
        return []
    return list(receiver.receive_data(data))


def _h2_pair() -> tuple[H2Connection, H2Connection]:
    client = H2Connection(H2Configuration(client_side=True))
    server = H2Connection(H2Configuration(client_side=False))
    client.initiate_connection()
    server.initiate_connection()
    server.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
    _pump(client, server)
    _pump(server, client)
    _pump(client, server)
    return client, server


def test_h2_two_connect_streams_reset_and_eof() -> None:
    client_h2, server_h2 = _h2_pair()
    client_handshakes: dict[int, H2Handshake] = {}
    server_handshakes: dict[int, H2Handshake] = {}

    client_handshakes[1] = H2Handshake(CLIENT)
    client_h2.send_headers(
        1,
        client_handshakes[1].initiate_connection(
            Request(host="example.com", target="/text", subprotocols=["chat"]),
        ),
    )
    client_handshakes[3] = H2Handshake(CLIENT)
    client_h2.send_headers(
        3,
        client_handshakes[3].initiate_connection(
            Request(
                host="example.com",
                target="/compressed",
                extensions=[PerMessageDeflate()],
            ),
        ),
    )

    for event in _pump(client_h2, server_h2):
        if not isinstance(event, RequestReceived):
            continue
        handshake = H2Handshake(SERVER)
        request = handshake.receive_headers(event.headers)
        assert isinstance(request, Request)
        if event.stream_id == 1:
            response_headers = handshake.accept(AcceptConnection(subprotocol="chat"))
        else:
            response_headers = handshake.accept(
                AcceptConnection(extensions=[PerMessageDeflate()]),
            )
        server_handshakes[event.stream_id] = handshake
        server_h2.send_headers(
            event.stream_id,
            [(b":status", b"200"), *response_headers],
        )

    for event in _pump(server_h2, client_h2):
        if isinstance(event, ResponseReceived):
            accepted = client_handshakes[event.stream_id].receive_headers(event.headers)
            assert isinstance(accepted, AcceptConnection)

    text_client = client_handshakes[1].connection
    text_server = server_handshakes[1].connection
    compressed_client = client_handshakes[3].connection
    compressed_server = server_handshakes[3].connection
    assert text_client is not None
    assert text_server is not None
    assert compressed_client is not None
    assert compressed_server is not None

    client_h2.send_data(
        1,
        text_client.send(TextMessage(data="split ", message_finished=False)),
    )
    client_h2.send_data(
        1,
        text_client.send(TextMessage(data="message", message_finished=True)),
    )
    text_events = []
    for event in _pump(client_h2, server_h2):
        if isinstance(event, DataReceived) and event.stream_id == 1:
            text_server.receive_data(event.data)
            server_h2.acknowledge_received_data(
                event.flow_controlled_length,
                event.stream_id,
            )
            text_events.extend(text_server.events())
    _pump(server_h2, client_h2)
    assert [event.data for event in text_events] == ["split ", "message"]

    client_h2.reset_stream(1, ErrorCodes.CANCEL)
    reset_errors = {}
    for event in _pump(client_h2, server_h2):
        if isinstance(event, StreamReset):
            reset_errors[event.stream_id] = ConnectionResetError(
                f"HTTP/2 stream reset with error code {event.error_code}",
            )
    assert isinstance(reset_errors[1], ConnectionResetError)
    assert list(text_server.events()) == []

    compressed_message = "compressible HTTP/2 WebSocket message " * 4
    client_h2.send_data(
        3,
        compressed_client.send(TextMessage(data=compressed_message)),
    )
    compressed_events = []
    for event in _pump(client_h2, server_h2):
        if isinstance(event, DataReceived) and event.stream_id == 3:
            compressed_server.receive_data(event.data)
            server_h2.acknowledge_received_data(
                event.flow_controlled_length,
                event.stream_id,
            )
            compressed_events.extend(compressed_server.events())
    assert [event.data for event in compressed_events] == [compressed_message]

    reply = "the other stream still works"
    server_h2.send_data(3, compressed_server.send(TextMessage(data=reply)))
    client_events = []
    for event in _pump(server_h2, client_h2):
        if isinstance(event, DataReceived) and event.stream_id == 3:
            compressed_client.receive_data(event.data)
            client_h2.acknowledge_received_data(
                event.flow_controlled_length,
                event.stream_id,
            )
            client_events.extend(compressed_client.events())
    assert [event.data for event in client_events] == [reply]

    client_h2.end_stream(3)
    eof_events = []
    for event in _pump(client_h2, server_h2):
        if isinstance(event, StreamEnded) and event.stream_id == 3:
            compressed_server.receive_data(None)
            eof_events.extend(compressed_server.events())
    assert eof_events == [CloseConnection(code=1006)]
