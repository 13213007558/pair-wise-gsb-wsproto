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

Origin admission
----------------

A server can attach an :class:`~wsproto.origin.OriginPolicy` to its
connection. The policy parses the incoming ``Origin`` and ``Host`` headers
strictly and runs before the :class:`~wsproto.events.Request` event is
emitted, so a denied handshake keeps the normal HTTP rejection flow and never
opens a WebSocket. Matching is structural over scheme, host and port; raw
string suffix matching is never used.

.. autoclass:: wsproto.origin.OriginPolicy
   :members:

.. autoclass:: wsproto.origin.ParsedOrigin
   :members:

.. autoclass:: wsproto.origin.ParsedHost
   :members:

.. autofunction:: wsproto.origin.parse_origin

.. autofunction:: wsproto.origin.parse_host

.. autofunction:: wsproto.origin.enforce_origin_policy

.. autoclass:: wsproto.origin.OriginPolicyError
    :members:

.. autoclass:: wsproto.origin.MissingOriginError
.. autoclass:: wsproto.origin.NullOriginError
.. autoclass:: wsproto.origin.MultipleOriginsError
.. autoclass:: wsproto.origin.InvalidOriginError
.. autoclass:: wsproto.origin.UntrustedOriginError
.. autoclass:: wsproto.origin.InvalidHostError

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
