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

# RFC 8441 extends CONNECT with a protocol. WebSocket data is only carried on
# the HTTP/2 stream after a 2xx response has been sent or received.
H2_WEBSOCKET_PROTOCOL = WEBSOCKET_UPGRADE

# These headers belong to the HTTP/1.1 Upgrade handshake. RFC 8441 replaces
# them with the extended CONNECT pseudo-headers and a 2xx response.
_H2_FORBIDDEN_HEADERS = {
    b"connection",
    b"sec-websocket-accept",
    b"sec-websocket-key",
    b"upgrade",
}


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
            offers: dict[str, str | bool] = {}
            for e in request.extensions:
                assert isinstance(e, Extension)
                offers[e.name] = e.offer()
            extensions = []
            for name, params in offers.items():
                bname = name.encode("ascii")
                if isinstance(params, bool):
                    if params:
                        extensions.append(bname)
                else:
                    extensions.append(b"%s; %s" % (bname, params.encode("ascii")))
            if extensions:
                headers.append((b"Sec-WebSocket-Extensions", b", ".join(extensions)))

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
    A handshake implementation for WebSockets over HTTP/2 (RFC 8441).

    This class is HTTP/2-parser agnostic: callers are responsible for using a
    library such as hyper-h2 to send and receive the HTTP/2 frames. The header
    blocks passed to and returned by this class contain only HTTP headers, not
    serialized HTTP/2 frames.

    A client starts with :meth:`initiate_connection`, then passes the response
    headers to :meth:`receive_headers`. A server passes the request headers to
    :meth:`receive_headers`, then calls :meth:`accept` with the subprotocol and
    extensions actually selected during negotiation. The accepted values are
    checked against the values offered in the request.

    RFC 8441 uses a 2xx response, not 101 Switching Protocols, and does not
    use Sec-WebSocket-Key or Sec-WebSocket-Accept.
    """

    def __init__(self, connection_type: ConnectionType) -> None:
        self.client = connection_type is ConnectionType.CLIENT
        self._state = ConnectionState.CONNECTING
        self._connection: Connection | None = None
        self._initiating_request: Request | None = None

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def connection(self) -> Connection | None:
        """Return the established WebSocket frame connection, if any."""
        return self._connection

    def initiate_connection(
        self,
        request: Request,
        scheme: str = "https",
    ) -> Headers:
        """
        Return the headers for an extended CONNECT request.

        The returned headers must be sent on a new HTTP/2 stream without
        END_STREAM. WebSocket DATA may be sent by the client after a 2xx
        response has been received and processed by :meth:receive_headers.

        :param request: The WebSocket request to negotiate.
        :param scheme: The HTTP scheme to place in the :scheme pseudo-header.
        :returns: HTTP/2 request headers, including pseudo-headers.
        """
        if not self.client:
            msg = "Cannot initiate an extended CONNECT when acting as the server"
            raise LocalProtocolError(msg)
        if self._state is not ConnectionState.CONNECTING:
            msg = f"Cannot initiate a connection in state {self._state}"
            raise LocalProtocolError(msg)

        headers: Headers = [
            (b":method", b"CONNECT"),
            (b":protocol", H2_WEBSOCKET_PROTOCOL),
            (b":scheme", scheme.encode("ascii")),
            (b":authority", request.host.encode("idna")),
            (b":path", request.target.encode("ascii")),
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
            offers: dict[str, str | bool] = {}
            for extension in request.extensions:
                if not isinstance(extension, Extension):
                    msg = "Client extension offers must be Extension instances"
                    raise LocalProtocolError(msg)
                offers[extension.name] = extension.offer()
            extensions = []
            for extension_name, params in offers.items():
                name_bytes = extension_name.encode("ascii")
                if isinstance(params, bool):
                    if params:
                        extensions.append(name_bytes)
                else:
                    extensions.append(b"%s; %s" % (name_bytes, params.encode("ascii")))
            if extensions:
                headers.append((b"sec-websocket-extensions", b", ".join(extensions)))

        for name, value in request.extra_headers:
            normalized_name = name.lower()
            if normalized_name.startswith(b":") or normalized_name in _H2_FORBIDDEN_HEADERS:
                msg = f"Header {name!r} cannot be used in an extended CONNECT request"
                raise LocalProtocolError(msg)
            headers.append((normalized_name, value))

        self._initiating_request = request
        return headers

    def receive_headers(self, headers: Headers) -> Request | AcceptConnection:
        """
        Process an HTTP/2 header block received from the peer.

        On a server this processes the extended CONNECT request and returns a
        :class:`~wsproto.events.Request`. On a client this processes the 2xx
        response and returns an :class:`~wsproto.events.AcceptConnection`.
        """
        if self.client:
            return self._process_connection_response(headers)
        return self._process_connection_request(headers)

    def accept(self, event: AcceptConnection) -> Headers:
        """
        Accept a received extended CONNECT request.

        The returned headers contain the negotiated WebSocket parameters and
        any extra headers from event. The caller must prepend an appropriate
        :status pseudo-header with a 2xx value and send the headers without
        END_STREAM. The server may send WebSocket DATA once those response
        headers have been sent.

        :param event: The subprotocol and extensions actually selected for the
            connection.
        :returns: HTTP/2 response headers, excluding :status.
        """
        if self.client:
            msg = "Cannot accept an extended CONNECT when acting as the client"
            raise LocalProtocolError(msg)
        if self._state is not ConnectionState.CONNECTING:
            msg = f"Connection cannot be accepted in state {self._state}"
            raise LocalProtocolError(msg)
        if self._initiating_request is None:
            msg = "Cannot accept before receiving an extended CONNECT request"
            raise LocalProtocolError(msg)

        request = self._initiating_request
        if event.subprotocol is not None and event.subprotocol not in request.subprotocols:
            msg = f"unexpected subprotocol {event.subprotocol}"
            raise LocalProtocolError(msg)

        headers: Headers = []
        if event.subprotocol is not None:
            headers.append(
                (b"sec-websocket-protocol", event.subprotocol.encode("ascii")),
            )

        if event.extensions:
            if not all(isinstance(offer, str) for offer in request.extensions):
                msg = "Server extension offers must be header strings"
                raise LocalProtocolError(msg)
            accepts = server_extensions_handshake(
                cast("Sequence[str]", request.extensions),
                event.extensions,
            )
            accepted_names = set()
            if accepts is not None:
                accepted_names = {accept.split(";", 1)[0].strip() for accept in split_comma_header(accepts)}
            expected_names = {extension.name for extension in event.extensions}
            if accepted_names != expected_names:
                msg = "accepted extensions must be selected from the request offers"
                raise LocalProtocolError(msg)
            assert accepts is not None
            headers.append((b"sec-websocket-extensions", accepts))

        headers.extend(event.extra_headers)
        self._connection = Connection(ConnectionType.SERVER, event.extensions)
        self._state = ConnectionState.OPEN
        return headers

    def _process_connection_request(self, headers: Headers) -> Request:
        if self._state is not ConnectionState.CONNECTING:
            msg = f"Cannot receive a request in state {self._state}"
            raise LocalProtocolError(msg)

        authority = None
        extensions: list[str] = []
        host = None
        method = None
        path = None
        protocol = None
        scheme = None
        subprotocols: list[str] = []
        version = None
        extra_headers: Headers = []

        for name, value in headers:
            name = name.lower()
            if name == b":authority":
                authority = value.decode("idna")
            elif name == b":method":
                method = value
            elif name == b":path":
                path = value
            elif name == b":protocol":
                protocol = value
            elif name == b":scheme":
                scheme = value
            elif name == b"host":
                host = value.decode("idna")
            elif name == b"sec-websocket-extensions":
                extensions.extend(split_comma_header(value))
            elif name == b"sec-websocket-protocol":
                subprotocols.extend(split_comma_header(value))
            elif name == b"sec-websocket-version":
                version = value
            elif name in _H2_FORBIDDEN_HEADERS:
                msg = f"Header {name!r} cannot be used with RFC 8441 WebSockets"
                raise RemoteProtocolError(msg, event_hint=RejectConnection())
            else:
                extra_headers.append((name, value))

        if method != b"CONNECT":
            msg = "Request method must be CONNECT"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if protocol != H2_WEBSOCKET_PROTOCOL:
            msg = "Missing pseudo-header, ':protocol: websocket'"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if scheme is None:
            msg = "Missing pseudo-header, ':scheme'"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if path is None:
            msg = "Missing pseudo-header, ':path'"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if version != WEBSOCKET_VERSION:
            msg = "Missing header, 'Sec-WebSocket-Version'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(
                    headers=[(b"Sec-WebSocket-Version", WEBSOCKET_VERSION)],
                    status_code=426 if version else 400,
                ),
            )

        request_host = authority if authority is not None else host
        if request_host is None:
            msg = "Missing pseudo-header, ':authority'"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())

        self._initiating_request = Request(
            extensions=extensions,
            extra_headers=extra_headers,
            host=request_host,
            subprotocols=subprotocols,
            target=path.decode("ascii"),
        )
        return self._initiating_request

    def _process_connection_response(self, headers: Headers) -> AcceptConnection:
        if self._state is not ConnectionState.CONNECTING:
            msg = f"Cannot receive a response in state {self._state}"
            raise LocalProtocolError(msg)
        if self._initiating_request is None:
            msg = "Cannot receive a response before initiating a connection"
            raise LocalProtocolError(msg)

        accepts: list[str] = []
        status_code = None
        subprotocol = None
        extra_headers: Headers = []

        for name, value in headers:
            name = name.lower()
            if name == b":status":
                status_code = int(value)
            elif name == b"sec-websocket-extensions":
                accepts.extend(split_comma_header(value))
            elif name == b"sec-websocket-protocol":
                subprotocol = value.decode("ascii")
            elif name in _H2_FORBIDDEN_HEADERS:
                msg = f"Header {name!r} cannot be used with RFC 8441 WebSockets"
                raise RemoteProtocolError(msg, event_hint=RejectConnection())
            else:
                extra_headers.append((name, value))

        if status_code is None:
            msg = "Missing pseudo-header, ':status'"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if status_code == 101:
            msg = "HTTP/2 WebSockets must not use 101 Switching Protocols"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if not 200 <= status_code < 300:
            msg = f"Extended CONNECT rejected with status {status_code}"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(
                    headers=extra_headers,
                    status_code=status_code,
                    has_body=True,
                ),
            )
        if subprotocol is not None and subprotocol not in self._initiating_request.subprotocols:
            msg = f"unrecognized subprotocol {subprotocol}"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())

        extensions = client_extensions_handshake(
            accepts,
            cast("Sequence[Extension]", self._initiating_request.extensions),
        )
        self._connection = Connection(ConnectionType.CLIENT, extensions)
        self._state = ConnectionState.OPEN
        return AcceptConnection(
            extensions=extensions,
            extra_headers=extra_headers,
            subprotocol=subprotocol,
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(client={self.client}, state={self.state})"


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
