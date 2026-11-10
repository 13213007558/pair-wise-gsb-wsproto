# Close-handshake event-draining reproductions

Pure in-memory scripts (no sockets, no network). Run from the repository root
with the project virtualenv:

```sh
.venv/bin/python repro/repro_close_sequences.py
.venv/bin/python repro/safe_driver_example.py
```

## `repro_close_sequences.py`

Each step logs the call order (`receive_data` / `next(events)` / `send`), the
`Connection.state` at that instant, the event delivered, and the actual bytes
`send()` emits — so conclusions are based on the whole sequence, not the final
state.

| # | Scenario | Observed contract |
|---|----------|-------------------|
| 1 | data frame then close in one buffer, only `next()` taken before `send()` | State stays `OPEN` until the `CloseConnection` event is yielded; the early business `send()` is accepted. Fully draining first yields `REMOTE_CLOSING` and the same `send()` raises `LocalProtocolError`. |
| 2 | close then data | Frame processor stops at CLOSE; trailing data is never decoded or exposed; one `CloseConnection` only. |
| 3 | local close then remote close | `LOCAL_CLOSING` after local `send`; moves to `CLOSED` only when the remote close event is consumed. |
| 4 | EOF (`receive_data(None)`) while events half read | Buffered data delivered first, then one abnormal (`1006`) `CloseConnection`; state `CLOSED`; no replay on a new iterator. |
| 5a | un-exhausted generator, fresh `events()` iterator | Resumes instead of replaying; close delivered exactly once. |
| 5b | `ParseFailed` mid-iteration | Yields one error `CloseConnection`. Before the fix the state stayed `OPEN` and a business `send()` was accepted; after the fix the state is `CLOSED` and the `send()` raises. |

## `safe_driver_example.py`

An upper-layer driver that:

1. fully drains `events()` after every `receive_data()` (single iterator);
2. gates every business send on `state is OPEN`;
3. replies to a remote close when the handshake still requires it;
4. treats EOF and protocol-error closes as terminal without sending data.

## Where state actually changes

- `Connection.receive_data` only buffers; normal close state transitions happen
  inside `Connection.events` when the CLOSE frame is yielded
  (`src/wsproto/connection.py`).
- `FrameProtocol._parse_more_gen` sets `closed = True` on CLOSE, so frames
  after it are never produced; the generator is one-shot, which prevents
  duplicate close delivery.
- `receive_data(None)` (EOF) appends an abnormal `CloseConnection` and sets
  `CLOSED` immediately because there is no frame left to lazily yield.
- A `ParseFailed` is caught in `events()` and converted into a
  `CloseConnection`; the fix sets `CLOSED` at the same yield point.
