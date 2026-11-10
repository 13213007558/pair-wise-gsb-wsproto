wsproto API
============

This document details the API of wsproto.

Semantic Versioning
-------------------

wsproto follows semantic versioning for its public API. Please note that the
guarantees of semantic versioning apply only to the API that is *documented
here*. Simply because a method or data field is not prefaced by an underscore
does not make it part of wsproto's public API. Anything not documented here is
subject to change at any time.

Connection
----------

.. autoclass:: wsproto.WSConnection
   :special-members: __init__
   :members:

.. autoclass:: wsproto.Connection
   :special-members: __init__
   :members:

Incoming bytes are parsed by ``receive_data()``, but state changes caused by
received events are applied while ``events()`` is consumed. For example, when
the remote peer sends a close frame, the connection enters
``REMOTE_CLOSING`` when the corresponding ``CloseConnection`` event is yielded,
not when the bytes are first passed to ``receive_data()``.

.. autoclass:: wsproto.ConnectionType
   :members:

.. autoclass:: wsproto.connection.ConnectionState
   :members:

Handshake
---------

.. autoclass:: wsproto.handshake.H11Handshake
   :members:

.. autofunction:: wsproto.handshake.client_extensions_handshake

.. autofunction:: wsproto.handshake.server_extensions_handshake

HTTP/2 (RFC 8441)
-----------------

:class:`~wsproto.h2.H2Handshake` bootstraps WebSockets over HTTP/2 using the
RFC 8441 extended CONNECT exchange. It is independent of any concrete HTTP/2
library and never opens a socket: the owning transport converts its frames
into the structured :class:`~wsproto.h2.H2Event` subclasses and feeds them in
through :meth:`~wsproto.h2.H2Handshake.receive_event`, while outbound
instructions (HEADERS, DATA, RST_STREAM) are returned as the same kind of
structured events. HTTP/2 flow control stays the caller's responsibility.
Once the handshake succeeds a regular
:class:`~wsproto.connection.Connection` performs the WebSocket framing, and
each stream owns an independent adapter, so ending or resetting one stream
never affects the others.

.. autoclass:: wsproto.h2.H2Handshake
   :members:

.. autoclass:: wsproto.h2.H2Event
   :members:

.. autoclass:: wsproto.h2.H2Request
   :members:

.. autoclass:: wsproto.h2.H2Response
   :members:

.. autoclass:: wsproto.h2.H2Data
   :members:

.. autoclass:: wsproto.h2.H2EndStream
   :members:

.. autoclass:: wsproto.h2.H2Reset
   :members:

.. autoclass:: wsproto.h2.H2SendHeaders
   :members:

.. autoclass:: wsproto.h2.H2SendData
   :members:

.. autoclass:: wsproto.h2.H2ResetStream
   :members:

.. autoclass:: wsproto.h2.H2ErrorCode
   :members:

.. autodata:: wsproto.h2.ENABLE_CONNECT_PROTOCOL

Events
------

Event constructors accept any field as a keyword argument. Some fields are
required, while others have default values.

.. autoclass:: wsproto.events.Event
   :members:

.. autoclass:: wsproto.events.Request
   :members:

.. autoclass:: wsproto.events.AcceptConnection
   :members:

.. autoclass:: wsproto.events.RejectConnection
   :members:

.. autoclass:: wsproto.events.RejectData
   :members:

.. autoclass:: wsproto.events.CloseConnection
   :members:

.. autoclass:: wsproto.events.Message
   :members:

.. autoclass:: wsproto.events.TextMessage
   :members:

.. autoclass:: wsproto.events.BytesMessage
   :members:

.. autoclass:: wsproto.events.Ping
   :members:

.. autoclass:: wsproto.events.Pong
   :members:

Frame Protocol
--------------

.. autoclass:: wsproto.frame_protocol.Opcode
   :members:

.. autoclass:: wsproto.frame_protocol.CloseReason
   :members:

Extensions
----------

.. autoclass:: wsproto.extensions.Extension
   :members:

.. autodata:: wsproto.extensions.SUPPORTED_EXTENSIONS

Exceptions
----------

.. autoclass:: wsproto.utilities.LocalProtocolError
   :members:

.. autoclass:: wsproto.utilities.RemoteProtocolError
   :members:
