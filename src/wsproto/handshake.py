"""
wsproto/handshake
~~~~~~~~~~~~~~~~~~

An implementation of WebSocket handshakes.
"""
from __future__ import annotations

from collections import deque
from typing import (
    TYPE_CHECKING,
    cast,
)

import h11

from .connection import Connection, ConnectionState, ConnectionType
from .events import AcceptConnection, Event, RejectConnection, RejectData, Request
from .extensions import Extension
from .utilities import (
    LocalProtocolError,
    RemoteProtocolError,
    generate_accept_token,
    generate_nonce,
    normed_header_dict,
    split_comma_header,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Sequence

    from .typing import Headers

# RFC6455, Section 4.2.1/6 - Reading the Client's Opening Handshake
WEBSOCKET_VERSION = b"13"

# RFC6455, Section 4.2.1/3 - Value of the Upgrade header
WEBSOCKET_UPGRADE = b"websocket"


class H11Handshake:
    """A Handshake implementation for HTTP/1.1 connections."""

    def __init__(self, connection_type: ConnectionType) -> None:
        self.client = connection_type is ConnectionType.CLIENT
        self._state = ConnectionState.CONNECTING

        if self.client:
            self._h11_connection = h11.Connection(h11.CLIENT)
        else:
            self._h11_connection = h11.Connection(h11.SERVER)

        self._connection: Connection | None = None
        self._events: deque[Event] = deque()
        self._initiating_request: Request | None = None
        self._nonce: bytes | None = None

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def connection(self) -> Connection | None:
        """
        Return the established connection.

        This will either return the connection or raise a
        LocalProtocolError if the connection has not yet been
        established.

        :rtype: h11.Connection
        """
        return self._connection

    def initiate_upgrade_connection(
        self, headers: Headers, path: bytes | str,
    ) -> None:
        """
        Initiate an upgrade connection.

        This should be used if the request has already be received and
        parsed.

        :param list headers: HTTP headers represented as a list of 2-tuples.
        :param str path: A URL path.
        """
        if self.client:
            msg = "Cannot initiate an upgrade connection when acting as the client"
            raise LocalProtocolError(
                msg,
            )
        upgrade_request = h11.Request(method=b"GET", target=path, headers=headers)
        h11_client = h11.Connection(h11.CLIENT)
        self.receive_data(h11_client.send(upgrade_request))

    def send(self, event: Event) -> bytes:
        """
        Send an event to the remote.

        This will return the bytes to send based on the event or raise
        a LocalProtocolError if the event is not valid given the
        state.

        :returns: Data to send to the WebSocket peer.
        :rtype: bytes
        """
        data = b""
        if isinstance(event, Request):
            data += self._initiate_connection(event)
        elif isinstance(event, AcceptConnection):
            data += self._accept(event)
        elif isinstance(event, RejectConnection):
            data += self._reject(event)
        elif isinstance(event, RejectData):
            data += self._send_reject_data(event)
        else:
            msg = f"Event {event} cannot be sent during the handshake"
            raise LocalProtocolError(
                msg,
            )
        return data

    def receive_data(self, data: bytes | None) -> None:
        """
        Receive data from the remote.

        A list of events that the remote peer triggered by sending
        this data can be retrieved with :meth:`events`.

        :param bytes data: Data received from the WebSocket peer.
        """
        self._h11_connection.receive_data(data or b"")
        while True:
            try:
                event = self._h11_connection.next_event()
            except h11.RemoteProtocolError:
                msg = "Bad HTTP message"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                )
            if (
                isinstance(event, h11.ConnectionClosed)
                or event is h11.NEED_DATA
                or event is h11.PAUSED
            ):
                break

            if self.client:
                if isinstance(event, h11.InformationalResponse):
                    if event.status_code == 101:
                        self._events.append(self._establish_client_connection(event))
                    else:
                        self._events.append(
                            RejectConnection(
                                headers=list(event.headers),
                                status_code=event.status_code,
                                has_body=False,
                            ),
                        )
                        self._state = ConnectionState.CLOSED
                elif isinstance(event, h11.Response):
                    self._state = ConnectionState.REJECTING
                    self._events.append(
                        RejectConnection(
                            headers=list(event.headers),
                            status_code=event.status_code,
                            has_body=True,
                        ),
                    )
                elif isinstance(event, h11.Data):
                    self._events.append(
                        RejectData(data=event.data, body_finished=False),
                    )
                elif isinstance(event, h11.EndOfMessage):
                    self._events.append(RejectData(data=b"", body_finished=True))
                    self._state = ConnectionState.CLOSED
            elif isinstance(event, h11.Request):
                self._events.append(self._process_connection_request(event))

    def events(self) -> Generator[Event, None, None]:
        """
        Return a generator that provides any events that have been generated
        by protocol activity.

        :returns: a generator that yields H11 events.
        """
        while self._events:
            yield self._events.popleft()

    # Server mode methods

    def _process_connection_request(
        self, event: h11.Request,
    ) -> Request:
        if event.method != b"GET":
            msg = "Request method must be GET"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        connection_tokens = None
        extensions: list[str] = []
        host = None
        key = None
        subprotocols: list[str] = []
        upgrade = b""
        version = None
        headers: Headers = []
        for name, value in event.headers:
            name = name.lower()
            if name == b"connection":
                connection_tokens = split_comma_header(value)
            elif name == b"host":
                host = value.decode("idna")
                continue  # Skip appending to headers
            elif name == b"sec-websocket-extensions":
                extensions.extend(split_comma_header(value))
                continue  # Skip appending to headers
            elif name == b"sec-websocket-key":
                key = value
            elif name == b"sec-websocket-protocol":
                subprotocols.extend(split_comma_header(value))
                continue  # Skip appending to headers
            elif name == b"sec-websocket-version":
                version = value
            elif name == b"upgrade":
                upgrade = value
            headers.append((name, value))
        if connection_tokens is None or not any(
            token.lower() == "upgrade" for token in connection_tokens
        ):
            msg = "Missing header, 'Connection: Upgrade'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if version != WEBSOCKET_VERSION:
            msg = "Missing header, 'Sec-WebSocket-Version'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(
                    headers=[(b"Sec-WebSocket-Version", WEBSOCKET_VERSION)],
                    status_code=426 if version else 400,
                ),
            )
        if key is None:
            msg = "Missing header, 'Sec-WebSocket-Key'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if upgrade.lower() != WEBSOCKET_UPGRADE:
            msg = f"Missing header, 'Upgrade: {WEBSOCKET_UPGRADE.decode()}'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        if host is None:
            msg = "Missing header, 'Host'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )

        self._initiating_request = Request(
            extensions=extensions,
            extra_headers=headers,
            host=host,
            subprotocols=subprotocols,
            target=event.target.decode("ascii"),
        )
        return self._initiating_request

    def _accept(self, event: AcceptConnection) -> bytes:
        # _accept is always called after _process_connection_request.
        assert self._initiating_request is not None
        request_headers = normed_header_dict(self._initiating_request.extra_headers)

        nonce = request_headers[b"sec-websocket-key"]
        accept_token = generate_accept_token(nonce)

        headers = [
            (b"Upgrade", WEBSOCKET_UPGRADE),
            (b"Connection", b"Upgrade"),
            (b"Sec-WebSocket-Accept", accept_token),
        ]

        if event.subprotocol is not None:
            if event.subprotocol not in self._initiating_request.subprotocols:
                msg = f"unexpected subprotocol {event.subprotocol}"
                raise LocalProtocolError(msg)
            headers.append(
                (b"Sec-WebSocket-Protocol", event.subprotocol.encode("ascii")),
            )

        if event.extensions:
            accepts = server_extensions_handshake(
                cast("Sequence[str]", self._initiating_request.extensions),
                event.extensions,
            )
            if accepts:
                headers.append((b"Sec-WebSocket-Extensions", accepts))

        response = h11.InformationalResponse(
            status_code=101,
            headers=headers + event.extra_headers,
            reason=b"Switching Protocols",
        )
        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            event.extensions,
        )
        self._state = ConnectionState.OPEN
        return self._h11_connection.send(response) or b""

    def _reject(self, event: RejectConnection) -> bytes:
        if self.state != ConnectionState.CONNECTING:
            msg = f"Connection cannot be rejected in state {self.state}"
            raise LocalProtocolError(
                msg,
            )

        headers = list(event.headers)
        if not event.has_body:
            headers.append((b"content-length", b"0"))
        response = h11.Response(status_code=event.status_code, headers=headers)
        data = self._h11_connection.send(response) or b""
        self._state = ConnectionState.REJECTING
        if not event.has_body:
            data += self._h11_connection.send(h11.EndOfMessage()) or b""
            self._state = ConnectionState.CLOSED
        return data

    def _send_reject_data(self, event: RejectData) -> bytes:
        if self.state != ConnectionState.REJECTING:
            msg = f"Cannot send rejection data in state {self.state}"
            raise LocalProtocolError(
                msg,
            )

        data = self._h11_connection.send(h11.Data(data=event.data)) or b""
        if event.body_finished:
            data += self._h11_connection.send(h11.EndOfMessage()) or b""
            self._state = ConnectionState.CLOSED
        return data

    # Client mode methods

    def _initiate_connection(self, request: Request) -> bytes:
        self._initiating_request = request
        self._nonce = generate_nonce()

        headers = [
            (b"Host", request.host.encode("idna")),
            (b"Upgrade", WEBSOCKET_UPGRADE),
            (b"Connection", b"Upgrade"),
            (b"Sec-WebSocket-Key", self._nonce),
            (b"Sec-WebSocket-Version", WEBSOCKET_VERSION),
        ]

        if request.subprotocols:
            headers.append(
                (
                    b"Sec-WebSocket-Protocol",
                    (", ".join(request.subprotocols)).encode("ascii"),
                ),
            )

        if request.extensions:
            offers = _extension_offers(
                cast("Sequence[Extension]", request.extensions),
            )
            if offers:
                headers.append((b"Sec-WebSocket-Extensions", offers))

        upgrade = h11.Request(
            method=b"GET",
            target=request.target.encode("ascii"),
            headers=headers + request.extra_headers,
        )
        return self._h11_connection.send(upgrade) or b""

    def _establish_client_connection(
        self, event: h11.InformationalResponse,
    ) -> AcceptConnection:
        # _establish_client_connection is always called after _initiate_connection.
        assert self._initiating_request is not None
        assert self._nonce is not None

        accept = None
        connection_tokens = None
        accepts: list[str] = []
        subprotocol = None
        upgrade = b""
        headers: Headers = []
        for name, value in event.headers:
            name = name.lower()
            if name == b"connection":
                connection_tokens = split_comma_header(value)
                continue  # Skip appending to headers
            if name == b"sec-websocket-extensions":
                accepts = split_comma_header(value)
                continue  # Skip appending to headers
            if name == b"sec-websocket-accept":
                accept = value
                continue  # Skip appending to headers
            if name == b"sec-websocket-protocol":
                subprotocol = value.decode("ascii")
                continue  # Skip appending to headers
            if name == b"upgrade":
                upgrade = value
                continue  # Skip appending to headers
            headers.append((name, value))

        if connection_tokens is None or not any(
            token.lower() == "upgrade" for token in connection_tokens
        ):
            msg = "Missing header, 'Connection: Upgrade'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if upgrade.lower() != WEBSOCKET_UPGRADE:
            msg = f"Missing header, 'Upgrade: {WEBSOCKET_UPGRADE.decode()}'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        accept_token = generate_accept_token(self._nonce)
        if accept != accept_token:
            msg = "Bad accept token"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if subprotocol is not None and subprotocol not in self._initiating_request.subprotocols:
            msg = f"unrecognized subprotocol {subprotocol}"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        extensions = client_extensions_handshake(
            accepts, cast("Sequence[Extension]", self._initiating_request.extensions),
        )

        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            extensions,
            self._h11_connection.trailing_data[0],
        )
        self._state = ConnectionState.OPEN
        return AcceptConnection(
            extensions=extensions, extra_headers=headers, subprotocol=subprotocol,
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(client={self.client}, state={self.state})"


class H2Handshake:
    """
    A Handshake implementation for RFC 8441 WebSockets (over HTTP/2).

    This handshake performs no I/O of its own: the HTTP/2 layer (for
    example the `h2` package) owns the connection and the streams.
    This class validates the extended CONNECT exchange, produces the
    header blocks the HTTP/2 layer should send, and then hands off to a
    frame-layer :class:`~wsproto.connection.Connection` available via
    :attr:`connection`.

    Unlike :class:`H11Handshake` there is no 101 (Switching Protocols)
    response and no `Sec-WebSocket-Key`/`Sec-WebSocket-Accept`
    exchange: the extended CONNECT request and a 2xx response are
    sufficient to establish the connection, so those headers are neither
    generated nor required (RFC 8441, Section 4).

    The flow is:

    *Client*: call :meth:`send` with a :class:`~wsproto.events.Request`
    and pass the returned headers to the HTTP/2 layer (e.g.
    `h2.send_headers`). When the response headers arrive, pass them to
    :meth:`receive_headers`; an
    :class:`~wsproto.events.AcceptConnection` (or
    :class:`~wsproto.events.RejectConnection`) event is emitted.

    *Server*: pass the CONNECT request headers to
    :meth:`receive_headers`; a :class:`~wsproto.events.Request` event is
    emitted. Call :meth:`send` with an
    :class:`~wsproto.events.AcceptConnection` and pass the returned
    headers (including `:status: 200`) to the HTTP/2 layer.

    When each side may send data (RFC 8441, Section 5):

    * The client may send WebSocket frames (as HTTP/2 DATA frames) as
      soon as it has sent the CONNECT request headers; it does not have
      to wait for the response. Note that wsproto only exposes the
      frame-layer :attr:`connection` once the 2xx response has been
      processed, because extension negotiation is not final before
      then.
    * The server may send WebSocket frames once it has passed the 2xx
      response headers to the HTTP/2 layer, and must be prepared to
      receive client DATA frames that were sent before the response
      arrived (the HTTP/2 layer buffers them on the stream).

    Stream termination:

    * An HTTP/2 `END_STREAM` flag is the end of the byte stream: feed
      it to the frame layer as `connection.receive_data(None)`. If the
      WebSocket closing handshake already completed this is a no-op;
      otherwise the connection closes abnormally and a
      :class:`~wsproto.events.CloseConnection` event with code 1006
      (abnormal closure) is emitted.
    * An HTTP/2 `RST_STREAM` is an abnormal transport failure, not a
      WebSocket close. It should be surfaced to the application as an
      error (and the frame layer torn down with
      `connection.receive_data(None)`, again yielding close code
      1006). wsproto never fabricates a normal WebSocket Close frame
      (code 1000) for either signal.
    """

    def __init__(self, connection_type: ConnectionType) -> None:
        self.client = connection_type is ConnectionType.CLIENT
        self._state = ConnectionState.CONNECTING
        self._connection: Connection | None = None
        self._events: deque[Event] = deque()
        self._initiating_request: Request | None = None

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def connection(self) -> Connection | None:
        """
        Return the established frame-layer connection.

        This returns None if the handshake has not yet completed.

        :rtype: wsproto.connection.Connection or None
        """
        return self._connection

    def send(self, event: Event) -> Headers:
        """
        Generate a header block for the HTTP/2 layer to send.

        As a client, send a :class:`~wsproto.events.Request` to generate
        the extended CONNECT request headers. As a server, send an
        :class:`~wsproto.events.AcceptConnection` to generate the 2xx
        response headers.

        Unlike :meth:`H11Handshake.send` this returns a list of headers,
        not bytes: the HTTP/2 layer is responsible for encoding and
        sending them (e.g. with `h2.send_headers`).

        :returns: Headers to send via the HTTP/2 layer.
        :rtype: list of (name, value) tuples
        """
        if isinstance(event, Request):
            return self._initiate_connection(event)
        if isinstance(event, AcceptConnection):
            return self._accept(event)
        msg = f"Event {event} cannot be sent during the handshake"
        raise LocalProtocolError(
            msg,
        )

    def receive_headers(self, headers: Headers) -> None:
        """
        Process a header block received from the HTTP/2 layer.

        As a server, pass the extended CONNECT request headers here; as
        a client, pass the response headers. Any resulting events (a
        :class:`~wsproto.events.Request`,
        :class:`~wsproto.events.AcceptConnection`, or
        :class:`~wsproto.events.RejectConnection`) can be retrieved with
        :meth:`events`.

        :param list headers: HTTP/2 headers as a list of 2-tuples,
            including the pseudo-headers (`:method`, `:protocol`,
            ... for requests, `:status` for responses).
        """
        if self._state is not ConnectionState.CONNECTING:
            msg = f"Cannot receive headers in state {self._state}"
            raise LocalProtocolError(
                msg,
            )
        normed = [(name.lower(), value) for name, value in headers]
        if self.client:
            self._process_response_headers(normed)
        else:
            self._events.append(self._process_request_headers(normed))

    def events(self) -> Generator[Event, None, None]:
        """
        Return a generator that provides any events that have been
        generated by protocol activity.

        :returns: a generator that yields events.
        """
        while self._events:
            yield self._events.popleft()

    # Server mode methods

    def _process_request_headers(self, headers: Headers) -> Request:
        # RFC 8441, Section 4 - the extended CONNECT request. Note that
        # no Sec-WebSocket-Key is required (or used) here.
        normed = normed_header_dict(headers)

        if normed.get(b":method") != b"CONNECT":
            msg = "Request method must be CONNECT"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if normed.get(b":protocol") != WEBSOCKET_UPGRADE:
            msg = f"Missing pseudo-header, ':protocol: {WEBSOCKET_UPGRADE.decode()}'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if normed.get(b":scheme") is None:
            msg = "Missing pseudo-header, ':scheme'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        target = normed.get(b":path")
        if target is None:
            msg = "Missing pseudo-header, ':path'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        authority = normed.get(b":authority")
        if authority is None:
            msg = "Missing pseudo-header, ':authority'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        version = normed.get(b"sec-websocket-version")
        if version != WEBSOCKET_VERSION:
            msg = "Missing header, 'Sec-WebSocket-Version'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(
                    headers=[(b"Sec-WebSocket-Version", WEBSOCKET_VERSION)],
                    status_code=426 if version else 400,
                ),
            )

        subprotocols: list[str] = []
        if b"sec-websocket-protocol" in normed:
            subprotocols = split_comma_header(normed[b"sec-websocket-protocol"])
        extensions: list[str] = []
        if b"sec-websocket-extensions" in normed:
            extensions = split_comma_header(normed[b"sec-websocket-extensions"])

        extra_headers = [
            (name, value)
            for name, value in headers
            if not name.startswith(b":")
            and name not in (b"sec-websocket-extensions", b"sec-websocket-protocol")
        ]

        self._initiating_request = Request(
            extensions=extensions,
            extra_headers=extra_headers,
            host=authority.decode("idna"),
            subprotocols=subprotocols,
            target=target.decode("ascii"),
        )
        return self._initiating_request

    def _accept(self, event: AcceptConnection) -> Headers:
        if self.client:
            msg = "Cannot accept a connection when acting as the client"
            raise LocalProtocolError(
                msg,
            )
        if self._initiating_request is None:
            msg = "Cannot accept a connection before a request has been received"
            raise LocalProtocolError(
                msg,
            )

        headers: Headers = [(b":status", b"200")]

        if event.subprotocol is not None:
            if event.subprotocol not in self._initiating_request.subprotocols:
                msg = f"unexpected subprotocol {event.subprotocol}"
                raise LocalProtocolError(msg)
            headers.append(
                (b"sec-websocket-protocol", event.subprotocol.encode("ascii")),
            )

        if event.extensions:
            accepts = server_extensions_handshake(
                cast("Sequence[str]", self._initiating_request.extensions),
                event.extensions,
            )
            if accepts:
                headers.append((b"sec-websocket-extensions", accepts))

        self._connection = Connection(ConnectionType.SERVER, event.extensions)
        self._state = ConnectionState.OPEN
        return headers + event.extra_headers

    # Client mode methods

    def _initiate_connection(self, request: Request) -> Headers:
        if not self.client:
            msg = "Cannot initiate a connection when acting as the server"
            raise LocalProtocolError(
                msg,
            )
        if self._initiating_request is not None:
            msg = "A connection has already been initiated"
            raise LocalProtocolError(
                msg,
            )
        self._initiating_request = request

        scheme = b"https"
        extra_headers = []
        for name, value in request.extra_headers:
            if name.lower() == b":scheme":
                scheme = value
            else:
                extra_headers.append((name, value))

        headers: Headers = [
            (b":method", b"CONNECT"),
            (b":protocol", WEBSOCKET_UPGRADE),
            (b":scheme", scheme),
            (b":path", request.target.encode("ascii")),
            (b":authority", request.host.encode("idna")),
            (b"sec-websocket-version", WEBSOCKET_VERSION),
        ]

        if request.subprotocols:
            headers.append(
                (
                    b"sec-websocket-protocol",
                    (", ".join(request.subprotocols)).encode("ascii"),
                ),
            )

        if request.extensions:
            offers = _extension_offers(
                cast("Sequence[Extension]", request.extensions),
            )
            if offers:
                headers.append((b"sec-websocket-extensions", offers))

        return headers + extra_headers

    def _process_response_headers(self, headers: Headers) -> None:
        if self._initiating_request is None:
            msg = "Received response headers before a request was sent"
            raise LocalProtocolError(
                msg,
            )
        normed = normed_header_dict(headers)

        status = normed.get(b":status")
        if status is None:
            msg = "Missing pseudo-header, ':status'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        try:
            status_code = int(status)
        except ValueError:
            msg = f"Bad status code {status!r}"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            ) from None

        extra_headers = [
            (name, value)
            for name, value in headers
            if not name.startswith(b":")
            and name not in (b"sec-websocket-extensions", b"sec-websocket-protocol")
        ]

        if not 200 <= status_code < 300:
            # The handshake was rejected. Any response body is delivered
            # by the HTTP/2 layer as DATA frames on this stream; wsproto
            # does not model it.
            self._events.append(
                RejectConnection(
                    headers=extra_headers,
                    status_code=status_code,
                    has_body=True,
                ),
            )
            self._state = ConnectionState.CLOSED
            return

        subprotocol = normed.get(b"sec-websocket-protocol")
        accepted_subprotocol = (
            subprotocol.decode("ascii") if subprotocol is not None else None
        )
        if (
            accepted_subprotocol is not None
            and accepted_subprotocol not in self._initiating_request.subprotocols
        ):
            msg = f"unrecognized subprotocol {accepted_subprotocol}"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )

        accepts: list[str] = []
        if b"sec-websocket-extensions" in normed:
            accepts = split_comma_header(normed[b"sec-websocket-extensions"])
        extensions = client_extensions_handshake(
            accepts, cast("Sequence[Extension]", self._initiating_request.extensions),
        )

        self._connection = Connection(ConnectionType.CLIENT, extensions)
        self._state = ConnectionState.OPEN
        self._events.append(
            AcceptConnection(
                extensions=extensions,
                extra_headers=extra_headers,
                subprotocol=accepted_subprotocol,
            ),
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(client={self.client}, state={self.state})"


def _extension_offers(extensions: Sequence[Extension]) -> bytes | None:
    """
    Build a Sec-WebSocket-Extensions header value offering the extensions.

    This returns None if there are no extensions to offer.
    """
    offers: dict[str, str | bool] = {}
    for extension in extensions:
        assert isinstance(extension, Extension)
        offers[extension.name] = extension.offer()
    if not offers:
        return None
    values = []
    for name, params in offers.items():
        name_bytes = name.encode("ascii")
        if isinstance(params, bool):
            if params:
                values.append(name_bytes)
        else:
            values.append(b"%s; %s" % (name_bytes, params.encode("ascii")))
    return b", ".join(values) if values else None


def server_extensions_handshake(
    requested: Iterable[str], supported: list[Extension],
) -> bytes | None:
    """
    Agree on the extensions to use returning an appropriate header value.

    This returns None if there are no agreed extensions
    """
    accepts: dict[str, bool | bytes] = {}
    for offer in requested:
        name = offer.split(";", 1)[0].strip()
        for extension in supported:
            if extension.name == name:
                accept = extension.accept(offer)
                if isinstance(accept, bool):
                    if accept:
                        accepts[extension.name] = True
                elif accept is not None:
                    accepts[extension.name] = accept.encode("ascii")

    if accepts:
        extensions: list[bytes] = []
        for name, params in accepts.items():
            name_bytes = name.encode("ascii")
            if isinstance(params, bool):
                assert params
                extensions.append(name_bytes)
            elif params == b"":
                extensions.append(b"%s" % (name_bytes))
            else:
                extensions.append(b"%s; %s" % (name_bytes, params))
        return b", ".join(extensions)

    return None


def client_extensions_handshake(
    accepted: Iterable[str], supported: Sequence[Extension],
) -> list[Extension]:
    # This raises RemoteProtocolError is the accepted extension is not
    # supported.
    extensions = []
    for accept in accepted:
        name = accept.split(";", 1)[0].strip()
        for extension in supported:
            if extension.name == name:
                extension.finalize(accept)
                extensions.append(extension)
                break
        else:
            msg = f"unrecognized extension {name}"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
    return extensions
