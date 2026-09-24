"""
WebSockets over HTTP/2 (RFC 8441) with wsproto and h2, entirely in memory.

This example boots a client and a server HTTP/2 connection (using the
``h2`` package) with no sockets involved: bytes are shuttled between the
two peers by hand.  Over that single HTTP/2 connection it then:

* opens two extended CONNECT streams with wsproto's
  :class:`~wsproto.handshake.H2Handshake`,
* sends a fragmented text message on the first stream,
* sends permessage-deflate compressed messages on the second stream,
* resets the first stream (RST_STREAM) and shows that it surfaces as an
  abnormal closure (close code 1006) rather than a fabricated normal
  WebSocket Close frame, while the second stream carries on working,
* cleanly closes the second stream (WebSocket close handshake followed
  by HTTP/2 END_STREAM in both directions).

Requires the ``h2`` package (>= 4.1), which is not a wsproto dependency:

    pip install h2
    python example/h2_extended_connect.py
"""

from __future__ import annotations

import collections

import h2.config
import h2.connection
import h2.events
import h2.settings

from wsproto.connection import CLIENT, SERVER, Connection, ConnectionState
from wsproto.events import (
    AcceptConnection,
    CloseConnection,
    Event,
    Request,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.frame_protocol import CloseReason
from wsproto.handshake import H2Handshake
from wsproto.typing import Headers


def pump(sender: "Peer", receiver: "Peer") -> list[object]:
    """Move all pending bytes from one peer to the other."""
    data = sender.h2.data_to_send()
    if not data:
        return []
    return receiver.h2.receive_data(data)


class Peer:
    """Glues one end of an h2 connection to wsproto handshakes/connections."""

    def __init__(self, client_side: bool) -> None:
        self.h2 = h2.connection.H2Connection(
            config=h2.config.H2Configuration(
                client_side=client_side,
                header_encoding=None,  # wsproto works on bytes headers
            ),
        )
        self.websockets: dict[int, Connection] = {}
        self.received: dict[int, list[Event]] = collections.defaultdict(list)

    def send_event(self, stream_id: int, event: Event) -> None:
        """Send a wsproto event as HTTP/2 DATA on the stream."""
        data = self.websockets[stream_id].send(event)
        if data:
            self.h2.send_data(stream_id, data)

    def _receive_frames(self, stream_id: int, data: bytes | None) -> None:
        websocket = self.websockets[stream_id]
        websocket.receive_data(data)
        self.received[stream_id].extend(websocket.events())


class Client(Peer):
    def __init__(self) -> None:
        super().__init__(client_side=True)
        self.h2.initiate_connection()
        self.handshakes: dict[int, H2Handshake] = {}

    def open_websocket(self, request: Request) -> int:
        """Start an RFC 8441 extended CONNECT for a WebSocket."""
        handshake = H2Handshake(CLIENT)
        headers = handshake.send(request)
        stream_id = self.h2.get_next_available_stream_id()
        self.h2.send_headers(stream_id, headers)
        self.handshakes[stream_id] = handshake
        return stream_id

    def handle(self, events: list[object]) -> None:
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                handshake = self.handshakes[event.stream_id]
                handshake.receive_headers(event.headers)
                accept = next(handshake.events())
                assert isinstance(accept, AcceptConnection), accept
                assert handshake.connection is not None
                self.websockets[event.stream_id] = handshake.connection
            elif isinstance(event, h2.events.DataReceived):
                self.h2.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id,
                )
                self._receive_frames(event.stream_id, event.data)
            elif isinstance(event, h2.events.StreamEnded):
                # END_STREAM is the end of the byte stream: EOF.
                self._receive_frames(event.stream_id, None)
            elif isinstance(event, h2.events.StreamReset):
                # RST_STREAM is an abnormal transport failure, not a
                # WebSocket close.  Tearing the frame layer down yields
                # an abnormal closure (1006) -- wsproto never fabricates
                # a normal Close frame here.
                self._receive_frames(event.stream_id, None)


class Server(Peer):
    def __init__(self) -> None:
        super().__init__(client_side=False)
        self.h2.initiate_connection()
        # RFC 8440: advertise that extended CONNECT is supported.
        self.h2.update_settings(
            {h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 1},
        )

    def handle(self, events: list[object]) -> None:
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self._accept_websocket(event.stream_id, event.headers)
            elif isinstance(event, h2.events.DataReceived):
                self.h2.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id,
                )
                self._receive_frames(event.stream_id, event.data)
            elif isinstance(event, h2.events.StreamEnded):
                # END_STREAM is the end of the byte stream: EOF.
                self._receive_frames(event.stream_id, None)
            elif isinstance(event, h2.events.StreamReset):
                self._receive_frames(event.stream_id, None)

    def _accept_websocket(self, stream_id: int, headers: Headers) -> None:
        handshake = H2Handshake(SERVER)
        handshake.receive_headers(headers)
        request = next(handshake.events())
        assert isinstance(request, Request)
        if request.target == "/compressed":
            accept = AcceptConnection(extensions=[PerMessageDeflate()])
        else:
            subprotocol = "chat" if "chat" in request.subprotocols else None
            accept = AcceptConnection(subprotocol=subprotocol)
        # The 2xx response headers -- no 101, no Sec-WebSocket-Key.
        self.h2.send_headers(stream_id, handshake.send(accept))
        assert handshake.connection is not None
        self.websockets[stream_id] = handshake.connection


def text_messages(events: list[Event]) -> list[TextMessage]:
    return [event for event in events if isinstance(event, TextMessage)]


def main() -> dict[str, object]:
    client = Client()
    server = Server()

    # Exchange the HTTP/2 connection prefaces (no sockets involved).
    server.handle(pump(client, server))
    client.handle(pump(server, client))

    # Open two extended CONNECT streams over the one connection.
    chat = client.open_websocket(
        Request(host="example.com", target="/chat", subprotocols=["chat"]),
    )
    compressed = client.open_websocket(
        Request(
            host="example.com",
            target="/compressed",
            extensions=[PerMessageDeflate()],
        ),
    )
    server.handle(pump(client, server))
    client.handle(pump(server, client))
    print(f"streams open: chat={chat}, compressed={compressed}")

    # Stream 1: a fragmented text message, client to server.
    client.send_event(chat, TextMessage(data="Hello, ", message_finished=False))
    client.send_event(chat, TextMessage(data="fragmented world!", message_finished=True))
    server.handle(pump(client, server))
    fragments = text_messages(server.received[chat])
    assert [event.message_finished for event in fragments] == [False, True]
    fragmented_text = "".join(event.data for event in fragments)
    print(f"stream {chat}: reassembled fragmented text: {fragmented_text!r}")

    # Stream 2: a permessage-deflate compressed message.
    payload = "compressible payload " * 40
    client.send_event(compressed, TextMessage(data=payload))
    server.handle(pump(client, server))
    [compressed_message] = text_messages(server.received[compressed])
    assert compressed_message.data == payload
    print(f"stream {compressed}: compressed message received intact")

    # The server resets stream 1 with RST_STREAM (CANCEL).  The client
    # sees an abnormal closure (1006), not a normal WebSocket Close.
    server.h2.reset_stream(chat, error_code=0x8)
    client.handle(pump(server, client))
    [reset_close] = [
        event
        for event in client.received[chat]
        if isinstance(event, CloseConnection)
    ]
    assert reset_close.code is CloseReason.ABNORMAL_CLOSURE
    assert client.websockets[chat].state is ConnectionState.CLOSED
    print(f"stream {chat}: reset -> abnormal closure (code 1006)")

    # ... while stream 2 carries on working.
    server.send_event(compressed, TextMessage(data="still with me?"))
    client.handle(pump(server, client))
    [reply] = text_messages(client.received[compressed])
    assert reply.data == "still with me?"
    print(f"stream {compressed}: still working after the reset")

    # Cleanly close stream 2: WebSocket close handshake first ...
    client.send_event(compressed, CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    server.handle(pump(client, server))
    [close_event] = [
        event
        for event in server.received[compressed]
        if isinstance(event, CloseConnection)
    ]
    server.send_event(compressed, close_event.response())
    client.handle(pump(server, client))
    assert client.websockets[compressed].state is ConnectionState.CLOSED
    assert server.websockets[compressed].state is ConnectionState.CLOSED

    # ... then END_STREAM in both directions.  Because the WebSocket
    # closing handshake completed, the EOF is a no-op for wsproto.
    client.h2.end_stream(compressed)
    server.handle(pump(client, server))
    server.h2.end_stream(compressed)
    client.handle(pump(server, client))
    assert not [
        event
        for event in server.received[compressed] + client.received[compressed]
        if isinstance(event, CloseConnection)
        and event.code != CloseReason.NORMAL_CLOSURE
    ]
    print(f"stream {compressed}: clean close + END_STREAM, no fake close frames")

    return {
        "fragmented_text": fragmented_text,
        "compressed_payload": payload,
        "reset_close_code": reset_close.code,
        "post_reset_reply": reply.data,
    }


if __name__ == "__main__":
    main()
