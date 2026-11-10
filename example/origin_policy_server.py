"""
This server accepts WebSocket handshakes from exactly two trusted web pages.

It demonstrates :class:`wsproto.origin.OriginPolicy`: the policy runs inside
wsproto while the opening handshake is being parsed, before the
:class:`~wsproto.events.Request` event is ever emitted.  Session resources are
therefore allocated *after* a Request is observed, which is only possible once
the origin has already been admitted.

Like synchronous_server.py this handles one connection at a time and exists
only to show the API; do not use it as production code.
"""
from __future__ import annotations

import socket
import sys

from wsproto import ConnectionType, WSConnection
from wsproto.events import (
    AcceptConnection,
    CloseConnection,
    Message,
    Ping,
    Request,
    TextMessage,
)
from wsproto.origin import OriginPolicy
from wsproto.utilities import RemoteProtocolError

RECEIVE_BYTES = 4096

# Trust is a fixed list of complete, parsed origins. Scheme, host and port all
# have to match. "https://example.com.evil.com" or "http://example.com" do not
# match, and a subdomain such as "https://www.example.com" is not admitted
# either. Non-browser clients without an Origin header may still connect.
ORIGIN_POLICY = OriginPolicy(
    allowed_origins=[
        "https://example.com",
        "https://app.example.com:8443",
    ],
    allow_missing_origin=True,
)


def main() -> None:
    """Run the server."""
    try:
        ip = sys.argv[1]
        port = int(sys.argv[2])
    except (IndexError, ValueError):
        print(f"Usage: {sys.argv[0]} <BIND_IP> <PORT>")
        sys.exit(1)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(0)

    try:
        while True:
            print("Waiting for connection...")
            stream, addr = server.accept()
            print(f"Client connected: {addr[0]}:{addr[1]}")
            handle_connection(stream)
            stream.shutdown(socket.SHUT_WR)
            stream.close()
    except KeyboardInterrupt:
        print("Received SIGINT: shutting down…")


def handle_connection(stream: socket.socket) -> None:
    """
    Handle one connection with the shared admission policy attached.
    """
    ws = WSConnection(ConnectionType.SERVER, origin_policy=ORIGIN_POLICY)
    running = True

    while running:
        in_data = stream.recv(RECEIVE_BYTES)
        try:
            ws.receive_data(in_data)
        except RemoteProtocolError as exc:
            # Policy denials and malformed handshakes share the existing
            # rejection flow. The response body and headers are fixed, so the
            # untrusted Origin is never echoed back.
            print(f"Rejecting handshake: {exc}")
            stream.send(ws.send(exc.event_hint))
            return

        out_data = b""
        for event in ws.events():
            if isinstance(event, Request):
                # The Origin policy has already passed at this point, so only
                # now is it safe to allocate per-session state.
                session = create_session(event)
                out_data += ws.send(AcceptConnection())
            elif isinstance(event, CloseConnection):
                print(
                    f"Connection closed: code={event.code} reason={event.reason}",
                )
                destroy_session(session)
                out_data += ws.send(event.response())
                running = False
            elif isinstance(event, TextMessage):
                out_data += ws.send(Message(data=event.data[::-1]))
            elif isinstance(event, Ping):
                out_data += ws.send(event.response())
            else:
                print(f"Unknown event: {event!r}")

        stream.send(out_data)


def create_session(request: Request) -> dict[str, object]:
    """Allocate the resources that belong to one accepted WebSocket."""
    session = {"target": request.target, "host": request.host}
    print(f"Allocating session for {session}")
    return session


def destroy_session(session: dict[str, object]) -> None:
    """Release the resources allocated in :func:`create_session`."""
    print(f"Destroying session for {session}")


if __name__ == "__main__":
    main()
