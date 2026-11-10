from __future__ import annotations

import pytest

from wsproto.connection import CLIENT, SERVER, Connection, ConnectionState
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    Request,
    TextMessage,
)
from wsproto.frame_protocol import CloseReason
from wsproto.utilities import LocalProtocolError


@pytest.mark.parametrize("client_sends", [True, False])
@pytest.mark.parametrize("final", [True, False])
def test_send_message(client_sends: bool, final: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    data = b"x" * 23
    remote.receive_data(local.send(BytesMessage(data=data, message_finished=final)))
    event = next(remote.events())
    assert isinstance(event, BytesMessage)
    assert event.data == data
    assert event.message_finished is final


@pytest.mark.parametrize("client_sends", [True, False])
@pytest.mark.parametrize(
    "code, reason",
    [(CloseReason.NORMAL_CLOSURE, "bye"), (CloseReason.GOING_AWAY, "👋👋")],
)
def test_closure(client_sends: bool, code: CloseReason, reason: str) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    remote.receive_data(local.send(CloseConnection(code=code, reason=reason)))
    event = next(remote.events())
    assert isinstance(event, CloseConnection)
    assert event.code is code
    assert event.reason == reason

    assert remote.state is ConnectionState.REMOTE_CLOSING
    assert local.state is ConnectionState.LOCAL_CLOSING

    local.receive_data(remote.send(event.response()))
    event = next(local.events())
    assert isinstance(event, CloseConnection)
    assert event.code is code
    assert event.reason == reason

    assert remote.state is ConnectionState.CLOSED  # type: ignore[comparison-overlap]
    assert local.state is ConnectionState.CLOSED

    with pytest.raises(LocalProtocolError):
        local.receive_data(b"foobar")


def test_abnormal_closure() -> None:
    client = Connection(CLIENT)
    client.receive_data(None)
    event = next(client.events())
    assert isinstance(event, CloseConnection)
    assert event.code is CloseReason.ABNORMAL_CLOSURE
    assert client.state is ConnectionState.CLOSED


def test_close_whilst_closing() -> None:
    client = Connection(CLIENT)
    client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    with pytest.raises(LocalProtocolError):
        client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))


def test_send_after_close() -> None:
    client = Connection(CLIENT)
    client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    with pytest.raises(LocalProtocolError):
        client.send(TextMessage(data="", message_finished=True))


@pytest.mark.parametrize("client_sends", [True, False])
def test_ping_pong(client_sends: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    payload = b"x" * 23
    remote.receive_data(local.send(Ping(payload=payload)))
    event = next(remote.events())
    assert isinstance(event, Ping)
    assert event.payload == payload

    local.receive_data(remote.send(event.response()))
    event = next(local.events())
    assert isinstance(event, Pong)
    assert event.payload == payload


def test_unsolicited_pong() -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    payload = b"x" * 23
    server.receive_data(client.send(Pong(payload=payload)))
    event = next(server.events())
    assert isinstance(event, Pong)
    assert event.payload == payload


@pytest.mark.parametrize("split_message", [True, False])
def test_data(split_message: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    data = "ƒñö®∂😎"
    server.receive_data(
        client.send(TextMessage(data=data, message_finished=not split_message)),
    )
    event = next(server.events())
    assert isinstance(event, TextMessage)
    assert event.message_finished is not split_message


def test_frame_protocol_gets_fed_garbage() -> None:
    client = Connection(CLIENT)

    payload = b"x" * 23
    frame = b"\x09" + bytearray([len(payload)]) + payload

    client.receive_data(frame)
    event = next(client.events())
    assert isinstance(event, CloseConnection)
    assert event.code == CloseReason.PROTOCOL_ERROR
    # RFC 6455 section 7.2: a protocol error fails the connection immediately.
    assert client.state is ConnectionState.CLOSED


def test_send_invalid_event() -> None:
    client = Connection(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(Request(target="/", host="wsproto"))


def test_receive_data_when_closed() -> None:
    client = Connection(CLIENT)
    client._state = ConnectionState.CLOSED
    with pytest.raises(LocalProtocolError):
        client.receive_data(b"something")


# ---------------------------------------------------------------------------
# Event draining and lazy state transitions.
#
# These tests deliberately keep using the *same* Connection object: rebuilding
# a Connection after every receive_data() would hide the state carried by the
# un-exhausted events() generator and the internal frame parser.
# ---------------------------------------------------------------------------


def _text_frame(payload: str) -> bytes:
    raw = payload.encode("utf-8")
    return b"\x81" + bytes([len(raw)]) + raw


def _close_frame(code: int = 1000, reason: str = "bye") -> bytes:
    payload = code.to_bytes(2, "big") + reason.encode("utf-8")
    return b"\x88" + bytes([len(payload)]) + payload


def test_remote_close_state_moves_when_event_is_yielded() -> None:
    # Documented lazy semantics: receive_data() alone must not change state.
    client = Connection(CLIENT)
    client.receive_data(_close_frame())
    assert client.state is ConnectionState.OPEN

    event = next(client.events())
    assert isinstance(event, CloseConnection)
    assert client.state is ConnectionState.REMOTE_CLOSING


def test_partial_drain_keeps_state_open_until_close_is_consumed() -> None:
    # Reproduces the reported trap: a data frame followed by a close frame in
    # one buffer. Reading only the first event leaves the connection OPEN, so a
    # business send is still accepted; draining the close then closes the door.
    client = Connection(CLIENT)
    client.receive_data(_text_frame("hi") + _close_frame())

    first = next(client.events())
    assert isinstance(first, TextMessage)
    assert client.state is ConnectionState.OPEN
    # The library cannot know the close frame is pending until its event is
    # consumed, so this send succeeds by design.
    client.send(BytesMessage(data=b"while-open"))

    second = next(client.events())
    assert isinstance(second, CloseConnection)
    assert client.state is ConnectionState.REMOTE_CLOSING
    with pytest.raises(LocalProtocolError):
        client.send(BytesMessage(data=b"after-close"))


def test_full_drain_blocks_business_send() -> None:
    # The same input, correctly drained, exposes REMOTE_CLOSING before send().
    client = Connection(CLIENT)
    client.receive_data(_text_frame("hi") + _close_frame())

    events = list(client.events())
    assert [type(event).__name__ for event in events] == [
        "TextMessage",
        "CloseConnection",
    ]
    assert client.state is ConnectionState.REMOTE_CLOSING
    with pytest.raises(LocalProtocolError):
        client.send(BytesMessage(data=b"nope"))


def test_recreated_event_iterator_does_not_duplicate_close() -> None:
    # Dropping an un-exhausted generator and creating a new one must resume
    # rather than replay: the close is delivered exactly once.
    client = Connection(CLIENT)
    client.receive_data(_text_frame("hi") + _close_frame())

    first = next(client.events())
    assert isinstance(first, TextMessage)

    rest = list(client.events())
    assert len(rest) == 1
    assert isinstance(rest[0], CloseConnection)
    assert client.state is ConnectionState.REMOTE_CLOSING
    assert list(client.events()) == []


def test_data_after_close_frame_is_never_exposed() -> None:
    # RFC 6455 section 5.5.1: data frames after a close frame are ignored. The
    # frame processor stops at CLOSE, so no business data leaks out.
    client = Connection(CLIENT)
    client.receive_data(_close_frame() + _text_frame("late"))

    events = list(client.events())
    assert [type(event).__name__ for event in events] == ["CloseConnection"]
    assert client.state is ConnectionState.REMOTE_CLOSING
    assert list(client.events()) == []


def test_remote_close_after_local_close_reaches_closed() -> None:
    client = Connection(CLIENT)
    client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    assert client.state is ConnectionState.LOCAL_CLOSING

    # State only advances when the remote close event is actually consumed.
    client.receive_data(_close_frame())
    assert client.state is ConnectionState.LOCAL_CLOSING

    event = next(client.events())
    assert isinstance(event, CloseConnection)
    assert client.state is ConnectionState.CLOSED
    with pytest.raises(LocalProtocolError):
        client.send(BytesMessage(data=b"late"))


def test_eof_with_buffered_events_delivers_data_then_close_once() -> None:
    # EOF (receive_data(None)) while events are only half read. Buffered
    # business data is delivered first, then a single abnormal CloseConnection.
    client = Connection(CLIENT)
    client.receive_data(_text_frame("hi"))
    first = next(client.events())
    assert isinstance(first, TextMessage)

    client.receive_data(None)
    assert client.state is ConnectionState.CLOSED

    events = list(client.events())
    assert len(events) == 1
    assert isinstance(events[0], CloseConnection)
    assert events[0].code is CloseReason.ABNORMAL_CLOSURE
    # Re-iterating must not redeliver the synthetic close.
    assert list(client.events()) == []
    with pytest.raises(LocalProtocolError):
        client.send(BytesMessage(data=b"orphan"))


def test_parse_failure_closes_connection_and_blocks_business_send() -> None:
    # A remote protocol violation yields a CloseConnection and must fail the
    # connection immediately (RFC 6455 section 7.2), not leave it OPEN.
    client = Connection(CLIENT)
    client.receive_data(_text_frame("hi") + b"\x8f\x00")  # invalid opcode 0xF

    events = list(client.events())
    assert [type(event).__name__ for event in events] == [
        "TextMessage",
        "CloseConnection",
    ]
    assert events[1].code is CloseReason.PROTOCOL_ERROR
    assert client.state is ConnectionState.CLOSED
    assert list(client.events()) == []
    with pytest.raises(LocalProtocolError):
        client.send(BytesMessage(data=b"blocked"))
    with pytest.raises(LocalProtocolError):
        client.receive_data(b"more bytes")
