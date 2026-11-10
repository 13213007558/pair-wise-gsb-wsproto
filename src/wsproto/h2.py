"""
wsproto/h2
~~~~~~~~~~

An RFC 8441 (Bootstrapping WebSockets with HTTP/2) handshake adapter.

Unlike :class:`~wsproto.handshake.H11Handshake`, this module never touches
raw HTTP bytes or sockets. The owning HTTP/2 transport feeds structured
:class:`H2Event` instances into :class:`H2Handshake` and receives the same
kind of structured events back. Once the extended CONNECT handshake has
completed, an ordinary :class:`~wsproto.connection.Connection` performs the
WebSocket framing, so every stream gets its own independent state machine.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, cast

from .connection import Connection, ConnectionState, ConnectionType
from .events import (
    AcceptConnection,
    CloseConnection,
    Event,
    RejectConnection,
    RejectData,
    Request,
)
from .extensions import Extension
from .frame_protocol import CloseReason
from .handshake import client_extensions_handshake, server_extensions_handshake
from .utilities import (
    LocalProtocolError,
    RemoteProtocolError,
    split_comma_header,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

    from .typing import Headers

#: RFC 8441, Section 3 - SETTINGS_ENABLE_CONNECT_PROTOCOL identifier.
ENABLE_CONNECT_PROTOCOL = 0x8

#: The value of the ``:protocol`` pseudo-header that selects WebSocket.
WEBSOCKET_PROTOCOL = b"websocket"


class H2ErrorCode(IntEnum):
    """RFC 7540, Section 7 - error codes used on RST_STREAM."""

    NO_ERROR = 0
    PROTOCOL_ERROR = 1
    INTERNAL_ERROR = 2
    FLOW_CONTROL_ERROR = 3
    SETTINGS_TIMEOUT = 4
    STREAM_CLOSED = 5
    FRAME_SIZE_ERROR = 6
    REFUSED_STREAM = 7
    CANCEL = 8
    COMPRESSION_ERROR = 9
    CONNECT_ERROR = 10
    ENHANCE_YOUR_CALM = 11
    INADEQUATE_SECURITY = 12
    HTTP_1_1_REQUIRED = 13


# Header fields that belong to the HTTP/1.1 upgrade handshake and therefore
# must never appear on an RFC 8441 extended CONNECT request.
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {b"connection", b"upgrade", b"sec-websocket-key", b"sec-websocket-version"},
)

# The HTTP/1.1 success headers must never be used to accept an RFC 8441
# request; success is signalled by a ``:status`` of 200 alone.
_FORBIDDEN_RESPONSE_HEADERS = frozenset(
    {b"connection", b"upgrade", b"sec-websocket-accept", b"sec-websocket-version"},
)


@dataclass(frozen=True)
class H2Event:
    """Base class for the structured HTTP/2 transport events."""


@dataclass(frozen=True)
class H2Request(H2Event):
    """
    An HTTP/2 request HEADERS frame delivered to the adapter.

    The five pseudo-headers of an extended CONNECT request are exposed as
    structured fields while the ordinary header fields remain in ``headers``.

    :param stream_id: The HTTP/2 stream identifier.
    :param method: The ``:method`` pseudo-header value.
    :param scheme: The ``:scheme`` pseudo-header value.
    :param authority: The ``:authority`` pseudo-header value.
    :param path: The ``:path`` pseudo-header value.
    :param protocol: The ``:protocol`` pseudo-header value, or ``None``.
    :param headers: The ordinary (non pseudo-header) header fields.
    """

    stream_id: int
    method: bytes
    scheme: bytes
    authority: bytes
    path: bytes
    protocol: bytes | None
    headers: Headers = field(default_factory=list)


@dataclass(frozen=True)
class H2Response(H2Event):
    """
    An HTTP/2 response HEADERS frame delivered to the adapter.

    :param stream_id: The HTTP/2 stream identifier.
    :param status_code: The ``:status`` pseudo-header value.
    :param headers: The ordinary (non pseudo-header) header fields.
    """

    stream_id: int
    status_code: int
    headers: Headers = field(default_factory=list)


@dataclass(frozen=True)
class H2Data(H2Event):
    """
    An HTTP/2 DATA frame delivered to the adapter.

    :param stream_id: The HTTP/2 stream identifier.
    :param data: The DATA frame payload.
    :param end_stream: Whether the frame carried the END_STREAM flag.
    """

    stream_id: int
    data: bytes
    end_stream: bool = False


@dataclass(frozen=True)
class H2EndStream(H2Event):
    """
    Signals that the peer ended the stream (END_STREAM without DATA).

    :param stream_id: The HTTP/2 stream identifier.
    """

    stream_id: int


@dataclass(frozen=True)
class H2Reset(H2Event):
    """
    Signals that the peer reset the stream with RST_STREAM.

    :param stream_id: The HTTP/2 stream identifier.
    :param error_code: The RFC 7540 error code carried by RST_STREAM.
    """

    stream_id: int
    error_code: H2ErrorCode = H2ErrorCode.CANCEL


@dataclass(frozen=True)
class H2SendHeaders(H2Event):
    """
    Instructs the transport to send a HEADERS frame on ``stream_id``.

    :param stream_id: The HTTP/2 stream identifier.
    :param headers: Pseudo- and ordinary header fields, already lower-cased.
    :param end_stream: Whether END_STREAM should be set on the frame.
    """

    stream_id: int
    headers: Headers
    end_stream: bool = False


@dataclass(frozen=True)
class H2SendData(H2Event):
    """
    Instructs the transport to send a DATA frame on ``stream_id``.

    :param stream_id: The HTTP/2 stream identifier.
    :param data: The DATA frame payload (a WebSocket frame or empty for half-close).
    :param end_stream: Whether END_STREAM should be set on the frame.
    """

    stream_id: int
    data: bytes = b""
    end_stream: bool = False


@dataclass(frozen=True)
class H2ResetStream(H2Event):
    """
    Instructs the transport to send RST_STREAM on ``stream_id``.

    :param stream_id: The HTTP/2 stream identifier.
    :param error_code: The RFC 7540 error code to carry.
    """

    stream_id: int
    error_code: H2ErrorCode = H2ErrorCode.CANCEL


class H2Handshake:
    """
    A library-independent RFC 8441 extended CONNECT handshake adapter.

    The adapter owns no sockets and performs no HTTP/2 framing. The calling
    transport converts its HTTP/2 frames into the structured :class:`H2Event`
    subclasses and feeds them through :meth:`receive_event`; outbound activity
    is returned from :meth:`send`, :meth:`end_stream` and :meth:`reset_stream`
    as structured events for the transport to encode. HTTP/2 flow control
    remains entirely the caller's responsibility.

    A server-side adapter only accepts a ``:protocol=websocket`` CONNECT once
    the upper layer has declared that ``SETTINGS_ENABLE_CONNECT_PROTOCOL`` was
    negotiated, via ``connect_protocol_enabled=True``. The HTTP/1.1
    ``Sec-WebSocket-Key``/``Sec-WebSocket-Accept`` machinery is never used.
    """

    def __init__(
        self,
        connection_type: ConnectionType,
        extensions: list[Extension] | None = None,
        connect_protocol_enabled: bool = False,
    ) -> None:
        """
        :param wsproto.connection.ConnectionType connection_type: Whether this
            adapter acts as a client or a server.
        :param list extensions: The proposed/supported WebSocket extensions.
        :param bool connect_protocol_enabled: Server side only. Set this once
            the transport has negotiated ``SETTINGS_ENABLE_CONNECT_PROTOCOL``;
            until then extended CONNECT requests are rejected with 405.
        """
        self.client = connection_type is ConnectionType.CLIENT
        self._extensions = extensions or []
        self._connect_protocol_enabled = connect_protocol_enabled
        self._state = ConnectionState.CONNECTING
        self._connection: Connection | None = None
        self._events: deque[Event] = deque()
        self._stream_id: int | None = None
        self._initiating_request: Request | None = None
        self._local_half_closed = False

    @property
    def state(self) -> ConnectionState:
        if self._connection is not None:
            return self._connection.state
        return self._state

    @property
    def connection(self) -> Connection | None:
        """The established WebSocket connection, or ``None`` before success."""
        return self._connection

    @property
    def stream_id(self) -> int | None:
        """The HTTP/2 stream this adapter is bound to."""
        return self._stream_id

    def send(self, event: Event, stream_id: int | None = None) -> H2Event:
        """
        Produce the structured HTTP/2 transport event for a wsproto event.

        A client must pass its allocated ``stream_id`` when sending the initial
        :class:`~wsproto.events.Request`; afterwards the remembered stream id
        is reused.

        :param event: The WebSocket handshake or frame event to emit.
        :param stream_id: Required for the client's opening CONNECT request.
        :returns: A structured event for the HTTP/2 transport to encode.
        """
        if isinstance(event, Request):
            return self._send_request(event, stream_id)
        if isinstance(event, AcceptConnection):
            return self._accept(event)
        if isinstance(event, RejectConnection):
            return self._reject(event)
        if isinstance(event, RejectData):
            return self._send_reject_data(event)
        return self._send_websocket_event(event)

    def end_stream(self) -> H2SendData:
        """
        Half-close the HTTP/2 stream (send END_STREAM, no WebSocket close frame).

        Ending a stream without a WebSocket CLOSE frame is distinct from the
        WebSocket closing handshake; the peer will treat it as an abnormal
        closure. Only this one stream is affected.
        """
        if self._connection is None or self._stream_id is None:
            msg = "Cannot end the stream before the handshake completed"
            raise LocalProtocolError(msg)
        if self.state is ConnectionState.CLOSED:
            msg = "Stream already closed."
            raise LocalProtocolError(msg)
        if self._local_half_closed:
            # END_STREAM is idempotent: the transport may retransmit it.
            return H2SendData(stream_id=self._stream_id, data=b"", end_stream=True)
        event = H2SendData(stream_id=self._stream_id, data=b"", end_stream=True)
        self._local_half_closed = True
        return event

    def reset_stream(
        self, error_code: H2ErrorCode = H2ErrorCode.CANCEL,
    ) -> H2ResetStream:
        """
        Reset the HTTP/2 stream with RST_STREAM and mark it closed.

        No WebSocket CLOSE frame is produced and other streams on the same
        transport are untouched.
        """
        if self._stream_id is None:
            msg = "Cannot reset a stream that has not been established"
            raise LocalProtocolError(msg)
        event = H2ResetStream(stream_id=self._stream_id, error_code=error_code)
        self._mark_closed()
        return event

    def receive_event(self, event: H2Event) -> None:
        """
        Hand a structured HTTP/2 transport event to the adapter.

        WebSocket-level events resulting from it are collected and later
        yielded by :meth:`events`.
        """
        if isinstance(event, H2Request):
            self._receive_request(event)
        elif isinstance(event, H2Response):
            self._receive_response(event)
        elif isinstance(event, H2Data):
            self._receive_data(event)
        elif isinstance(event, H2EndStream):
            self._receive_end_stream(event)
        elif isinstance(event, H2Reset):
            self._receive_reset(event)
        else:  # pragma: no cover
            msg = f"Unknown HTTP/2 event {event}"
            raise LocalProtocolError(msg)

    def events(self) -> Generator[Event, None, None]:
        """Yield pending WebSocket :class:`~wsproto.events.Event` objects."""
        while self._events:
            yield self._events.popleft()
        if self._connection is not None:
            yield from self._connection.events()

    # Outbound handshake handling

    def _send_request(self, request: Request, stream_id: int | None) -> H2SendHeaders:
        if not self.client:
            msg = "Cannot initiate a CONNECT request when acting as the server"
            raise LocalProtocolError(msg)
        if self.state is not ConnectionState.CONNECTING:
            msg = f"Request cannot be sent in state {self.state}"
            raise LocalProtocolError(msg)
        if self._initiating_request is not None:
            msg = "A CONNECT request was already initiated on this stream"
            raise LocalProtocolError(msg)
        if stream_id is None:
            msg = "A client CONNECT request needs an allocated stream id"
            raise LocalProtocolError(msg)

        self._initiating_request = request
        self._stream_id = stream_id

        headers: Headers = [
            (b":method", b"CONNECT"),
            (b":protocol", WEBSOCKET_PROTOCOL),
            (b":scheme", request.scheme.encode("ascii")),
            (b":authority", request.host.encode("idna")),
            (b":path", request.target.encode("ascii")),
        ]
        if request.subprotocols:
            headers.append(
                (b"sec-websocket-protocol", ", ".join(request.subprotocols).encode("ascii")),
            )
        if request.extensions:
            offers: dict[str, str | bool] = {}
            for extension in request.extensions:
                assert isinstance(extension, Extension)
                offers[extension.name] = extension.offer()
            extension_headers = []
            for name, params in offers.items():
                name_bytes = name.encode("ascii")
                if isinstance(params, bool):
                    if params:
                        extension_headers.append(name_bytes)
                else:
                    extension_headers.append(b"%s; %s" % (name_bytes, params.encode("ascii")))
            if extension_headers:
                headers.append((b"sec-websocket-extensions", b", ".join(extension_headers)))

        return H2SendHeaders(
            stream_id=stream_id,
            headers=headers + request.extra_headers,
        )

    def _accept(self, event: AcceptConnection) -> H2SendHeaders:
        if self.client:
            msg = "Cannot accept a CONNECT request when acting as the client"
            raise LocalProtocolError(msg)
        if self.state is not ConnectionState.CONNECTING:
            msg = f"Connection cannot be accepted in state {self.state}"
            raise LocalProtocolError(msg)
        assert self._initiating_request is not None
        assert self._stream_id is not None

        headers: Headers = [(b":status", b"200")]
        if event.subprotocol is not None:
            if event.subprotocol not in self._initiating_request.subprotocols:
                msg = f"unexpected subprotocol {event.subprotocol}"
                raise LocalProtocolError(msg)
            headers.append(
                (b"sec-websocket-protocol", event.subprotocol.encode("ascii")),
            )
        if event.extensions:
            accepted = server_extensions_handshake(
                cast("Sequence[str]", self._initiating_request.extensions),
                event.extensions,
            )
            if accepted:
                headers.append((b"sec-websocket-extensions", accepted))

        transport_event = H2SendHeaders(
            stream_id=self._stream_id,
            headers=headers + event.extra_headers,
        )
        self._connection = Connection(ConnectionType.SERVER, event.extensions)
        self._state = ConnectionState.OPEN
        return transport_event

    def _reject(self, event: RejectConnection) -> H2SendHeaders:
        if self.client:
            msg = "Cannot reject a CONNECT request when acting as the client"
            raise LocalProtocolError(msg)
        if self.state is not ConnectionState.CONNECTING and (
            self.state is not ConnectionState.REJECTING
        ):
            msg = f"Connection cannot be rejected in state {self.state}"
            raise LocalProtocolError(msg)
        assert self._stream_id is not None

        headers = [(b":status", str(event.status_code).encode("ascii")), *event.headers]
        transport_event = H2SendHeaders(
            stream_id=self._stream_id,
            headers=headers,
            end_stream=not event.has_body,
        )
        if event.has_body:
            self._state = ConnectionState.REJECTING
        else:
            self._state = ConnectionState.CLOSED
        return transport_event

    def _send_reject_data(self, event: RejectData) -> H2SendData:
        if self.state is not ConnectionState.REJECTING:
            msg = f"Cannot send rejection data in state {self.state}"
            raise LocalProtocolError(msg)
        assert self._stream_id is not None
        if event.body_finished:
            self._state = ConnectionState.CLOSED
        return H2SendData(
            stream_id=self._stream_id,
            data=event.data,
            end_stream=event.body_finished,
        )

    def _send_websocket_event(self, event: Event) -> H2SendData:
        if self._connection is None or self._stream_id is None:
            msg = f"Event {event} cannot be sent before the handshake completed"
            raise LocalProtocolError(msg)
        data = self._connection.send(event)
        return H2SendData(stream_id=self._stream_id, data=data)

    # Inbound handshake handling

    def _receive_request(self, event: H2Request) -> None:
        if self.client:
            msg = "A client adapter cannot receive CONNECT requests"
            raise LocalProtocolError(msg)
        if self.state is not ConnectionState.CONNECTING:
            msg = f"CONNECT request cannot be handled in state {self.state}"
            raise LocalProtocolError(msg)

        self._stream_id = event.stream_id

        if not self._connect_protocol_enabled:
            # RFC 8441, Section 5.2: reject an extended CONNECT when the
            # SETTINGS extension was not negotiated.
            self._events.append(RejectConnection(status_code=405))
            return

        if event.method != b"CONNECT":
            msg = "RFC 8441 request method must be CONNECT"
            raise RemoteProtocolError(msg, event_hint=RejectConnection(status_code=405))
        if event.protocol != WEBSOCKET_PROTOCOL:
            msg = "Missing or bad ':protocol' pseudo-header, expected 'websocket'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(status_code=400),
            )
        if not event.scheme or not event.authority or not event.path:
            msg = "Extended CONNECT requires ':scheme', ':authority' and ':path'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(status_code=400),
            )

        subprotocols: list[str] = []
        extensions: list[str] = []
        headers: Headers = []
        for name, value in event.headers:
            name = name.lower()
            if name in _FORBIDDEN_REQUEST_HEADERS:
                msg = f"HTTP/1.1 upgrade header {name.decode()!r} is forbidden on RFC 8441"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(status_code=400),
                )
            if name == b"sec-websocket-protocol":
                subprotocols.extend(split_comma_header(value))
            elif name == b"sec-websocket-extensions":
                extensions.extend(split_comma_header(value))
            else:
                headers.append((name, value))

        self._initiating_request = Request(
            host=event.authority.decode("idna"),
            target=event.path.decode("ascii"),
            extensions=extensions,
            subprotocols=subprotocols,
            extra_headers=headers,
            scheme=event.scheme.decode("ascii"),
        )
        self._events.append(self._initiating_request)

    def _receive_response(self, event: H2Response) -> None:
        if not self.client:
            msg = "A server adapter cannot receive CONNECT responses"
            raise LocalProtocolError(msg)
        if self.state is not ConnectionState.CONNECTING:
            msg = f"CONNECT response cannot be handled in state {self.state}"
            raise LocalProtocolError(msg)
        if self._stream_id is not None and event.stream_id != self._stream_id:
            msg = f"Response for stream {event.stream_id} does not match {self._stream_id}"
            raise LocalProtocolError(msg)
        self._stream_id = event.stream_id

        if 100 <= event.status_code < 200:
            # Informational responses carry no meaning for this handshake.
            return
        if event.status_code != 200:
            self._state = ConnectionState.REJECTING
            self._events.append(
                RejectConnection(
                    status_code=event.status_code,
                    headers=list(event.headers),
                    has_body=True,
                ),
            )
            return

        subprotocol = None
        accepted_extensions: list[str] = []
        headers: Headers = []
        for name, value in event.headers:
            name = name.lower()
            if name in _FORBIDDEN_RESPONSE_HEADERS:
                msg = f"HTTP/1.1 upgrade header {name.decode()!r} is forbidden on RFC 8441"
                self._mark_closed()
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(status_code=400),
                )
            if name == b"sec-websocket-protocol":
                subprotocol = value.decode("ascii")
            elif name == b"sec-websocket-extensions":
                accepted_extensions = split_comma_header(value)
            else:
                headers.append((name, value))

        assert self._initiating_request is not None
        if subprotocol is not None and (
            subprotocol not in self._initiating_request.subprotocols
        ):
            self._mark_closed()
            msg = f"unrecognized subprotocol {subprotocol}"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        extensions = client_extensions_handshake(
            accepted_extensions,
            self._extensions,
        )

        self._connection = Connection(ConnectionType.CLIENT, extensions)
        self._state = ConnectionState.OPEN
        self._events.append(
            AcceptConnection(
                subprotocol=subprotocol,
                extensions=extensions,
                extra_headers=headers,
            ),
        )

    def _receive_data(self, event: H2Data) -> None:
        if self._stream_id is not None and event.stream_id != self._stream_id:
            msg = f"Data for stream {event.stream_id} does not match {self._stream_id}"
            raise LocalProtocolError(msg)

        if self._connection is not None:
            if self.state is ConnectionState.CLOSED:
                msg = "Stream already closed."
                raise LocalProtocolError(msg)
            self._connection.receive_data(event.data)
            if event.end_stream:
                self._receive_remote_end_stream()
            return

        if self.state is ConnectionState.REJECTING:
            self._events.append(RejectData(data=event.data, body_finished=False))
            if event.end_stream:
                self._events.append(RejectData(data=b"", body_finished=True))
                self._state = ConnectionState.CLOSED
            return

        # DATA before a valid 200 response must never become a WebSocket
        # message; treat it as a protocol violation.
        self._mark_closed()
        msg = "DATA received before the extended CONNECT succeeded"
        raise RemoteProtocolError(msg, event_hint=RejectConnection())

    def _receive_end_stream(self, event: H2EndStream) -> None:
        if self._stream_id is not None and event.stream_id != self._stream_id:
            msg = f"End of stream {event.stream_id} does not match {self._stream_id}"
            raise LocalProtocolError(msg)

        if self.state is ConnectionState.CLOSED:
            return
        if self.state is ConnectionState.REJECTING:
            self._events.append(RejectData(data=b"", body_finished=True))
            self._state = ConnectionState.CLOSED
            return
        if self._connection is None:
            self._mark_closed()
            msg = "Stream ended before the extended CONNECT succeeded"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        self._receive_remote_end_stream()

    def _receive_remote_end_stream(self) -> None:
        # RFC 8441, Section 5.5: END_STREAM without a CLOSE frame is an
        # abnormal WebSocket closure, but it only affects this stream.
        if self.state is ConnectionState.REMOTE_CLOSING:
            self._mark_closed()
            return
        self._events.append(CloseConnection(code=CloseReason.ABNORMAL_CLOSURE))
        self._mark_closed()

    def _receive_reset(self, event: H2Reset) -> None:
        if self._stream_id is not None and event.stream_id != self._stream_id:
            msg = f"Reset of stream {event.stream_id} does not match {self._stream_id}"
            raise LocalProtocolError(msg)
        if self.state is ConnectionState.CLOSED:
            return
        # A RST_STREAM is an abnormal closure with no CLOSE frame exchanged.
        self._events.append(
            CloseConnection(
                code=CloseReason.ABNORMAL_CLOSURE,
                reason=f"HTTP/2 stream reset (error code {int(event.error_code)})",
            ),
        )
        self._mark_closed()

    def _mark_closed(self) -> None:
        self._state = ConnectionState.CLOSED
        if self._connection is not None:
            self._connection._state = ConnectionState.CLOSED

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(client={self.client}, "
            f"stream_id={self._stream_id}, state={self.state})"
        )


__all__ = (
    "ENABLE_CONNECT_PROTOCOL",
    "H2Data",
    "H2EndStream",
    "H2ErrorCode",
    "H2Event",
    "H2Handshake",
    "H2Request",
    "H2Reset",
    "H2ResetStream",
    "H2Response",
    "H2SendData",
    "H2SendHeaders",
    "WEBSOCKET_PROTOCOL",
)
