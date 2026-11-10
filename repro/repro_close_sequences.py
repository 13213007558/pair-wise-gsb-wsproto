"""
Minimal in-memory reproductions for wsproto close/event-drain semantics.

Every step records: the call order (receive_data / next(events) / send),
Connection.state, the event delivered, and the actual bytes emitted by send().
No network is used. Frames are hand-built so the observed Connection does not
need masking (it is a client-side Connection receiving server frames).

Run:  .venv/bin/python repro/repro_close_sequences.py
"""
from __future__ import annotations

from dataclasses import dataclass

from wsproto.connection import CLIENT, Connection, ConnectionState
from wsproto.events import BytesMessage, CloseConnection, TextMessage
from wsproto.frame_protocol import CloseReason
from wsproto.utilities import LocalProtocolError

STATE = {s.name for s in ConnectionState}


def frame(opcode: int, payload: bytes = b"", fin: bool = True) -> bytes:
    """Build an unmasked frame as a server would send to a client."""
    first = (0x80 if fin else 0x00) | opcode
    assert len(payload) <= 125
    return bytes([first, len(payload)]) + payload


TEXT = frame(0x1, b"hi")          # single complete text frame
BINARY = frame(0x2, b"\x01\x02")  # single complete binary frame
CLOSE = frame(0x8, (1000).to_bytes(2, "big") + b"bye")
# A frame the parser must reject (invalid opcode 0xF).
GARBAGE = bytes([0x8F, 0x00])


@dataclass
class Step:
    action: str
    state: str
    detail: str
    out_bytes: bytes = b""


class TracedConnection:
    """Wraps Connection and logs every receive/next/send with state snapshots."""

    def __init__(self) -> None:
        self.conn = Connection(CLIENT)
        self.log: list[Step] = []

    def _snap(self, action: str, detail: str, out: bytes = b"") -> None:
        self.log.append(Step(action, self.conn.state.name, detail, out))

    def receive(self, data: bytes | None, label: str) -> None:
        self.conn.receive_data(data)
        self._snap("receive_data", f"{label} -> state does NOT move yet")

    def next_event(self, label: str) -> object | None:
        gen = self.conn.events()
        try:
            event = next(gen)
        except StopIteration:
            self._snap("next(events)", f"{label}: generator exhausted")
            return None
        self._snap("next(events)", f"{label}: delivered {event!r}")
        return event

    def drain(self, label: str) -> list[object]:
        out: list[object] = []
        for event in self.conn.events():
            self._snap("for-in events", f"{label}: delivered {event!r}")
            out.append(event)
        if not out:
            self._snap("for-in events", f"{label}: generator exhausted")
        return out

    def try_send(self, event: object, label: str) -> None:
        try:
            data = self.conn.send(event)
        except LocalProtocolError as exc:
            self._snap("send", f"{label}: LocalProtocolError: {exc}")
            return
        self._snap("send", f"{label}: accepted {event!r}", data)


def show(title: str, traced: TracedConnection) -> None:
    print(f"\n=== {title} ===")
    print(f"{'step':<4}{'action':<16}{'state':<16}detail / emitted bytes")
    for i, step in enumerate(traced.log, 1):
        extra = f" | wire={step.out_bytes.hex()}" if step.out_bytes else ""
        print(f"{i:<4}{step.action:<16}{step.state:<16}{step.detail}{extra}")


# ---------------------------------------------------------------------------
# Scenario 1: data frame followed by a close frame arrive in one receive_data.
# The application only takes the FIRST event, then calls send() before draining
# the rest of the generator.
# ---------------------------------------------------------------------------
def scenario_1_data_then_close_partial_drain() -> None:
    traced = TracedConnection()
    traced.receive(TEXT + CLOSE, "TEXT then CLOSE in one buffer")

    # Buggy application pattern: peek only the first event.
    first = traced.next_event("first event only")
    assert isinstance(first, TextMessage)

    # State is still OPEN because the CloseConnection has not been yielded.
    traced.try_send(BytesMessage(data=b"biz"), "send while close not yet drained")

    # Now drain the remainder: the close event and the REMOTE_CLOSING transition.
    rest = traced.drain("remaining events")
    assert any(isinstance(e, CloseConnection) for e in rest)

    traced.try_send(BytesMessage(data=b"more"), "send after close drained")
    show("1) data then close; only first event consumed before send()", traced)


# Same input, but the generator is fully drained before any send(): this shows
# the intended contract and the state the application should rely on.
def scenario_1b_full_drain_reference() -> None:
    traced = TracedConnection()
    traced.receive(TEXT + CLOSE, "TEXT then CLOSE in one buffer")
    events = traced.drain("full drain before send")
    assert [type(e).__name__ for e in events] == ["TextMessage", "CloseConnection"]
    traced.try_send(BytesMessage(data=b"biz"), "send after full drain")
    show("1b) same input, full drain before send() (reference behavior)", traced)


# ---------------------------------------------------------------------------
# Scenario 2: close frame first, then a data frame. RFC 6455 says data after a
# close frame is illegal; record what the parser delivers and when state moves.
# ---------------------------------------------------------------------------
def scenario_2_close_then_data() -> None:
    traced = TracedConnection()
    traced.receive(CLOSE + TEXT, "CLOSE then TEXT in one buffer")
    events = traced.drain("full drain")
    print("\n=== 2) close then data ===")
    print("delivered event types:", [type(e).__name__ for e in events])
    for i, step in enumerate(traced.log, 1):
        print(f"{i:<4}{step.action:<16}{step.state:<16}{step.detail}")
    print("note: FrameProcessor stops at CLOSE (closed=True); trailing TEXT is"
          " never decoded or exposed.")


# ---------------------------------------------------------------------------
# Scenario 3: local close first, then the remote close frame arrives.
# ---------------------------------------------------------------------------
def scenario_3_local_close_then_remote_close() -> None:
    traced = TracedConnection()
    traced.try_send(CloseConnection(code=1000, reason="me"), "local close")
    assert traced.conn.state is ConnectionState.LOCAL_CLOSING

    traced.receive(CLOSE, "remote CLOSE while LOCAL_CLOSING")
    # Still LOCAL_CLOSING until the event is actually yielded.
    events = traced.drain("drain remote close")
    assert isinstance(events[0], CloseConnection)
    assert traced.conn.state is ConnectionState.CLOSED

    traced.try_send(BytesMessage(data=b"late"), "business send after CLOSED")
    show("3) local close, then remote close", traced)


# ---------------------------------------------------------------------------
# Scenario 4: EOF (receive_data(None)) while events are only half read.
# ---------------------------------------------------------------------------
def scenario_4_eof_mid_iteration() -> None:
    traced = TracedConnection()
    traced.receive(TEXT, "buffered TEXT, not read yet")
    half = traced.next_event("read one event, then EOF arrives")
    assert isinstance(half, TextMessage)

    # Transport drops: socket.recv() == b"" -> receive_data(None).
    traced.receive(None, "EOF")
    assert traced.conn.state is ConnectionState.CLOSED
    events = traced.drain("events after EOF")
    assert isinstance(events[0], CloseConnection)
    assert events[0].code is CloseReason.ABNORMAL_CLOSURE

    traced.try_send(BytesMessage(data=b"orphan"), "send after EOF")
    show("4) EOF while events half consumed", traced)


# ---------------------------------------------------------------------------
# Extra probes requested by the investigation:
#  * un-exhausted generator + a second events() iterator
#  * ParseFailed mid-iteration: is close delivered twice? what is the state?
# ---------------------------------------------------------------------------
def probe_recreated_iterator() -> None:
    print("\n=== 5a) un-exhausted generator, then a fresh events() iterator ===")
    conn = Connection(CLIENT)
    conn.receive_data(TEXT + CLOSE)
    gen1 = conn.events()
    first = next(gen1)
    print("first from gen1:", type(first).__name__, "| state:", conn.state.name)
    del gen1  # application drops the generator without exhausting it
    gen2 = conn.events()
    rest = list(gen2)
    print("fresh iterator delivers:", [type(e).__name__ for e in rest],
          "| state:", conn.state.name)
    third = list(conn.events())
    print("third iterator delivers:", third, "(no duplicate close)")


def probe_parse_failed() -> None:
    print("\n=== 5b) ParseFailed mid-iteration (remote protocol violation) ===")
    conn = Connection(CLIENT)
    conn.receive_data(TEXT + GARBAGE)
    delivered: list[object] = []
    for event in conn.events():
        delivered.append(event)
        print("yielded:", type(event).__name__,
              getattr(event, "code", ""), "| state now:", conn.state.name)
    print("all delivered types:", [type(e).__name__ for e in delivered])
    print("state AFTER consuming the error CloseConnection:", conn.state.name)
    try:
        wire = conn.send(BytesMessage(data=b"should this be allowed?"))
    except LocalProtocolError as exc:
        print("send() -> LocalProtocolError:", exc)
    else:
        print("send() -> ACCEPTED, wire:", wire.hex(),
              " <-- business data still serialisable after remote protocol error")
    again = list(conn.events())
    print("re-iterating events() yields:", again, "(no duplicate close)")


if __name__ == "__main__":
    scenario_1_data_then_close_partial_drain()
    scenario_1b_full_drain_reference()
    scenario_2_close_then_data()
    scenario_3_local_close_then_remote_close()
    scenario_4_eof_mid_iteration()
    probe_recreated_iterator()
    probe_parse_failed()
