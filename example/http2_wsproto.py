"""
An offline RFC 8441 example using hyper-h2 and wsproto.

The two HTTP/2 endpoints exchange bytes directly in memory. No sockets are
opened. Run from a checkout with:

    PYTHONPATH=src python example/http2_wsproto.py
"""

from __future__ import annotations

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
from wsproto.connection import CLIENT, SERVER, Connection
from wsproto.events import AcceptConnection, CloseConnection, Request, TextMessage
from wsproto.extensions import PerMessageDeflate
from wsproto.handshake import H2Handshake


def pump(sender: H2Connection, receiver: H2Connection) -> list[object]:
    data = sender.data_to_send()
    if not data:
        return []
    return list(receiver.receive_data(data))


def make_h2_pair() -> tuple[H2Connection, H2Connection]:
    client = H2Connection(H2Configuration(client_side=True))
    server = H2Connection(H2Configuration(client_side=False))
    client.initiate_connection()
    server.initiate_connection()
    server.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
    pump(client, server)
    pump(server, client)
    pump(client, server)
    return client, server


def websocket_events(connection: Connection) -> list[object]:
    return list(connection.events())


def main() -> None:
    client_h2, server_h2 = make_h2_pair()
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

    for event in pump(client_h2, server_h2):
        if not isinstance(event, RequestReceived):
            continue
        handshake = H2Handshake(SERVER)
        request = handshake.receive_headers(event.headers)
        if event.stream_id == 1:
            response_headers = handshake.accept(
                AcceptConnection(subprotocol=request.subprotocols[0]),
            )
        else:
            response_headers = handshake.accept(
                AcceptConnection(extensions=[PerMessageDeflate()]),
            )
        server_handshakes[event.stream_id] = handshake
        server_h2.send_headers(
            event.stream_id,
            [(b":status", b"200"), *response_headers],
        )

    for event in pump(server_h2, client_h2):
        if isinstance(event, ResponseReceived):
            client_handshakes[event.stream_id].receive_headers(event.headers)

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
        text_client.send(TextMessage(data="fragmented ", message_finished=False)),
    )
    client_h2.send_data(
        1,
        text_client.send(TextMessage(data="text", message_finished=True)),
    )
    text_chunks = []
    for event in pump(client_h2, server_h2):
        if isinstance(event, DataReceived) and event.stream_id == 1:
            text_server.receive_data(event.data)
            server_h2.acknowledge_received_data(
                event.flow_controlled_length,
                event.stream_id,
            )
            text_chunks.extend(event.data for event in websocket_events(text_server))
    pump(server_h2, client_h2)

    client_h2.reset_stream(1, ErrorCodes.CANCEL)
    reset_errors = {}
    for event in pump(client_h2, server_h2):
        if isinstance(event, StreamReset):
            reset_errors[event.stream_id] = ConnectionResetError(
                f"stream {event.stream_id} reset with error {event.error_code}",
            )

    compressed_message = "compressed over HTTP/2 " * 4
    client_h2.send_data(
        3,
        compressed_client.send(TextMessage(data=compressed_message)),
    )
    compressed_messages = []
    for event in pump(client_h2, server_h2):
        if isinstance(event, DataReceived) and event.stream_id == 3:
            compressed_server.receive_data(event.data)
            server_h2.acknowledge_received_data(
                event.flow_controlled_length,
                event.stream_id,
            )
            compressed_messages.extend(event.data for event in websocket_events(compressed_server))

    server_h2.send_data(
        3,
        compressed_server.send(TextMessage(data="stream 3 still works")),
    )
    client_messages = []
    for event in pump(server_h2, client_h2):
        if isinstance(event, DataReceived) and event.stream_id == 3:
            compressed_client.receive_data(event.data)
            client_h2.acknowledge_received_data(
                event.flow_controlled_length,
                event.stream_id,
            )
            client_messages.extend(event.data for event in websocket_events(compressed_client))

    client_h2.end_stream(3)
    eof_events = []
    for event in pump(client_h2, server_h2):
        if isinstance(event, StreamEnded) and event.stream_id == 3:
            compressed_server.receive_data(None)
            eof_events.extend(websocket_events(compressed_server))

    assert text_chunks == ["fragmented ", "text"]
    assert isinstance(reset_errors[1], ConnectionResetError)
    assert compressed_messages == [compressed_message]
    assert client_messages == ["stream 3 still works"]
    assert eof_events == [CloseConnection(code=1006)]

    print("stream 1 text chunks:", text_chunks)
    print("stream 1 reset error:", reset_errors[1])
    print("stream 3 compressed message:", compressed_messages[0])
    print("stream 3 reply after reset of stream 1:", client_messages[0])
    print("stream 3 END_STREAM event:", eof_events[0])


if __name__ == "__main__":
    main()
