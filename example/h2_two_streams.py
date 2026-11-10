"""
RFC 8441 WebSockets over HTTP/2: two concurrent streams on one transport.

This example never opens a socket and depends on no concrete HTTP/2 library.
A tiny in-memory "transport" shuffles the structured H2Event objects produced
by wsproto.H2Handshake between a client side and a server side. It proves that
upgrading or terminating one HTTP/2 stream never affects the other stream, and
that an HTTP/2 stream end/reset is kept separate from the WebSocket close
handshake.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from wsproto import H2Handshake
from wsproto.connection import CLIENT, SERVER, ConnectionState
from wsproto.events import (
    AcceptConnection,
    CloseConnection,
    RejectConnection,
    Request,
    TextMessage,
)
from wsproto.h2 import (
    H2Data,
    H2EndStream,
    H2ErrorCode,
    H2Event,
    H2Request,
    H2Reset,
    H2Response,
    H2SendData,
    H2SendHeaders,
)


@dataclass
class FakeH2Transport:
    """Collects outbound events and delivers them to the peer side."""

    log: list[str] = field(default_factory=list)

    def record(self, label: str, event: H2Event) -> None:
        self.log.append(f"{label}: {event}")


def _peer_headers(event: H2SendHeaders) -> H2Request | H2Response:
    pseudo = {name: value for name, value in event.headers if name.startswith(b":")}
    ordinary = [(name, value) for name, value in event.headers if not name.startswith(b":")]
    if b":method" in pseudo:
        return H2Request(
            stream_id=event.stream_id,
            method=pseudo[b":method"],
            scheme=pseudo[b":scheme"],
            authority=pseudo[b":authority"],
            path=pseudo[b":path"],
            protocol=pseudo.get(b":protocol"),
            headers=ordinary,
        )
    return H2Response(
        stream_id=event.stream_id,
        status_code=int(pseudo[b":status"]),
        headers=ordinary,
    )


def run() -> None:
    transport = FakeH2Transport()

    # The server only enables the extended CONNECT after the transport has
    # exchanged SETTINGS_ENABLE_CONNECT_PROTOCOL with the client.
    servers = {
        1: H2Handshake(SERVER, connect_protocol_enabled=True),
        3: H2Handshake(SERVER, connect_protocol_enabled=True),
    }
    clients = {
        1: H2Handshake(CLIENT),
        3: H2Handshake(CLIENT),
    }

    # --- Both streams send an extended CONNECT and get upgraded -------------
    for stream_id in (1, 3):
        request_headers = clients[stream_id].send(
            Request(host="example.com", target=f"/ws{stream_id}", subprotocols=["chat"]),
            stream_id=stream_id,
        )
        transport.record(f"client stream {stream_id} ->", request_headers)
        servers[stream_id].receive_event(_peer_headers(request_headers))
        request = next(servers[stream_id].events())
        assert isinstance(request, Request)

        accept = servers[stream_id].send(AcceptConnection(subprotocol="chat"))
        transport.record(f"server stream {stream_id} ->", accept)
        clients[stream_id].receive_event(_peer_headers(accept))
        assert isinstance(next(clients[stream_id].events()), AcceptConnection)

    print("both streams upgraded:", all(
        clients[s].state is ConnectionState.OPEN for s in clients
    ))

    # --- A message on stream 3 proves it is fully independent ---------------
    message_frame = clients[3].send(TextMessage(data="hello on stream 3"))
    assert isinstance(message_frame, H2SendData)
    servers[3].receive_event(H2Data(3, message_frame.data))
    message = next(servers[3].events())
    assert isinstance(message, TextMessage) and message.data == "hello on stream 3"
    transport.record("client stream 3 ->", message_frame)

    # --- Terminate stream 1 with RST_STREAM; stream 3 must survive -----------
    reset = servers[1].reset_stream(H2ErrorCode.CANCEL)
    transport.record("server stream 1 ->", reset)
    clients[1].receive_event(H2Reset(1, H2ErrorCode.CANCEL))
    close_event = next(clients[1].events())
    assert isinstance(close_event, CloseConnection)
    assert close_event.code.name == "ABNORMAL_CLOSURE"

    print("stream 1 after reset:   ", clients[1].state)
    print("stream 3 still open:    ", clients[3].state is ConnectionState.OPEN)
    assert clients[1].state is ConnectionState.CLOSED
    assert clients[3].state is ConnectionState.OPEN
    assert servers[3].state is ConnectionState.OPEN

    # --- A WebSocket close on stream 3 does not touch stream 1 --------------
    close_frame = clients[3].send(CloseConnection(code=1000))
    assert isinstance(close_frame, H2SendData) and close_frame.end_stream is False
    servers[3].receive_event(H2Data(3, close_frame.data))
    ws_close = next(servers[3].events())
    assert isinstance(ws_close, CloseConnection)
    servers[3].send(ws_close.response())
    transport.record("client stream 3 ->", close_frame)

    # END_STREAM on the already-closed stream 1 is an idempotent no-op.
    servers[1].receive_event(H2EndStream(1))
    assert list(servers[1].events()) == []

    # --- A server without the negotiated setting rejects the CONNECT --------
    strict_server = H2Handshake(SERVER, connect_protocol_enabled=False)
    strict_server.receive_event(
        H2Request(
            stream_id=5,
            method=b"CONNECT",
            scheme=b"https",
            authority=b"example.com",
            path=b"/ws5",
            protocol=b"websocket",
        ),
    )
    rejection = next(strict_server.events())
    assert isinstance(rejection, RejectConnection) and rejection.status_code == 405
    reject_headers = strict_server.send(rejection)
    transport.record("server stream 5 ->", reject_headers)
    print("unnegotiated CONNECT:   rejected with", rejection.status_code)

    print("\ntransport activity ({} events):".format(len(transport.log)))
    for line in transport.log:
        print(" ", line)


if __name__ == "__main__":
    run()
