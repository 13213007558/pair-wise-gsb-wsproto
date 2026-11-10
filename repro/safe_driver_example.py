"""
Upper-layer driver for wsproto that never loses a close event and never emits
business messages while the connection is closing.

Key rules demonstrated here (the library itself is sans-I/O and only enforces
the state machine; the glue code must follow these rules):

1. Always *fully drain* ``connection.events()`` after every ``receive_data``.
   State transitions (REMOTE_CLOSING / CLOSED) happen as CloseConnection events
   are *yielded*, not when the bytes are fed in. Taking only ``next(events)``
   and then sending leaves the connection looking OPEN even though a close
   frame is already buffered.
2. Gate every business send on ``connection.state is OPEN``. During
   REMOTE_CLOSING / LOCAL_CLOSING / CLOSED only a CloseConnection reply is
   legal; a business send raises LocalProtocolError.
3. A remote CloseConnection always needs a reply (unless we already sent one).
4. ``receive_data(None)`` (socket EOF) synthesises an abnormal CloseConnection
   and moves straight to CLOSED; drain it exactly like a framed close.
5. A protocol-error CloseConnection (ParseFailed) moves straight to CLOSED and
   must not be answered with business data.

This is pure in-memory code: a fake transport records the bytes that a real
socket would send.
"""
from __future__ import annotations

from collections import deque

from wsproto.connection import CLIENT, Connection, ConnectionState
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Event,
    Ping,
    TextMessage,
)
from wsproto.utilities import LocalProtocolError


class SafeDriver:
    """Drain-first driver with a send gate keyed on the connection state."""

    def __init__(self) -> None:
        self.conn = Connection(CLIENT)
        self.wire: list[bytes] = []          # bytes a real socket would send
        self.messages: list[object] = []     # business events for the app
        self.closed: CloseConnection | None = None

    def feed(self, data: bytes | None) -> None:
        """Hand network bytes (or None for EOF) and drain every event."""
        self.conn.receive_data(data)
        # One iterator, exhausted completely: never peek just the first event.
        for event in self.conn.events():
            self._handle(event)

    def _handle(self, event: Event) -> None:
        if isinstance(event, (TextMessage, BytesMessage)):
            self.messages.append(event)
        elif isinstance(event, Ping):
            # Control replies remain legal while OPEN.
            self._emit(self.conn.send(event.response()))
        elif isinstance(event, CloseConnection):
            # Record first close only; the generator guarantees no duplicates,
            # but guarding here makes the driver's own contract explicit.
            if self.closed is None:
                self.closed = event
            self._reply_to_close(event)

    def _reply_to_close(self, event: CloseConnection) -> None:
        # A normal remote close while OPEN/REMOTE_CLOSING needs our close frame;
        # that send also flips REMOTE_CLOSING -> CLOSED. In LOCAL_CLOSING it
        # completes the handshake. In CLOSED (e.g. parse error / EOF) no frame
        # can be sent, which is correct.
        if self.conn.state is ConnectionState.CLOSED:
            return
        try:
            self._emit(self.conn.send(event.response()))
        except LocalProtocolError:
            pass

    def send_business(self, data: bytes) -> bool:
        """Return False (and send nothing) unless the connection is OPEN."""
        if self.conn.state is not ConnectionState.OPEN:
            return False
        self._emit(self.conn.send(BytesMessage(data=data)))
        return True

    def initiate_close(self, code: int = 1000, reason: str = "") -> None:
        if self.conn.state in (
            ConnectionState.OPEN,
            ConnectionState.REMOTE_CLOSING,
        ):
            self._emit(
                self.conn.send(CloseConnection(code=code, reason=reason)),
            )

    def _emit(self, data: bytes) -> None:
        self.wire.append(bytes(data))


def _text_frame(payload: str) -> bytes:
    raw = payload.encode("utf-8")
    return b"\x81" + bytes([len(raw)]) + raw


def _close_frame(code: int = 1000, reason: str = "bye") -> bytes:
    payload = code.to_bytes(2, "big") + reason.encode("utf-8")
    return b"\x88" + bytes([len(payload)]) + payload


def main() -> None:
    # 1) data + close arrive together: queued business send must be suppressed.
    driver = SafeDriver()
    assert driver.send_business(b"queued before feed") is True
    driver.feed(_text_frame("hello") + _close_frame())
    assert [type(m).__name__ for m in driver.messages] == ["TextMessage"]
    assert isinstance(driver.closed, CloseConnection)
    assert driver.conn.state is ConnectionState.CLOSED
    # The close reply is on the wire; no business frame went out after it.
    assert driver.send_business(b"must be dropped") is False
    close_reply = driver.wire[-1]
    assert close_reply[0] & 0x0F == 0x8, close_reply.hex()
    print("1) data+close -> state:", driver.conn.state.name,
          "| wire frames:", [b.hex()[:8] + "..." for b in driver.wire])

    # 2) local close first, then remote close: handshake completes cleanly.
    driver = SafeDriver()
    driver.initiate_close()
    assert driver.conn.state is ConnectionState.LOCAL_CLOSING
    assert driver.send_business(b"blocked locally") is False
    driver.feed(_close_frame())
    assert driver.conn.state is ConnectionState.CLOSED
    print("2) local then remote close -> state:", driver.conn.state.name)

    # 3) EOF with unread data: data delivered, then one abnormal close.
    driver = SafeDriver()
    driver.feed(_text_frame("buffered"))
    driver.feed(None)
    assert driver.closed is not None
    assert driver.closed.code.value == 1006
    assert driver.conn.state is ConnectionState.CLOSED
    print("3) EOF -> state:", driver.conn.state.name,
          "| close code:", driver.closed.code)

    # 4) remote protocol error: immediate CLOSED, no business frame accepted.
    driver = SafeDriver()
    driver.feed(_text_frame("ok") + b"\x8f\x00")  # invalid opcode 0xF
    assert driver.conn.state is ConnectionState.CLOSED
    assert driver.closed is not None and driver.closed.code.value == 1002
    assert driver.send_business(b"never") is False
    print("4) protocol error -> state:", driver.conn.state.name,
          "| close code:", driver.closed.code)

    print("\nAll driver invariants held.")


if __name__ == "__main__":
    main()
