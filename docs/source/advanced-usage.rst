Advanced Usage
==============

This document explains some of the more advanced usage concepts with
`wsproto`. This is assume you are familiar with `wsproto` and I/O in
Python.

Back-pressure
-------------

Back-pressure is an important concept to understand when implementing a
client/server protocol. This section briefly explains the issue and then
explains how to handle back-pressure when using `wsproto`.

Imagine that you have a WebSocket server that reads messages from the
client, does some processing, and then sends a response. What happens
if the client sends messages faster than the server can process them?
If the incoming messages are buffered in memory, then the server will
slowly use more and more memory, until the OS eventually kills
it. This scenario is directly applicable to `wsproto`, because every
time you call ``receive_data(some_byte_string_of_data)``, it appends
that data to an internal buffer.

The slow endpoint needs a way to signal the fast endpoint to stop sending
messages until the slow endpoint can catch up. This signaling is called
"back-pressure". As a Sans-IO library, `wsproto` is not responsible for
network concerns like back-pressure, so that responsibility belongs to your
network glue code.

Fortunately, TCP has the ability to signal backpressure, and the
operating system will do that for you automatically—if you follow a
few rules! The OS buffers all incoming and outgoing network
data. Standard Python socket methods, such as ``send(...)`` and
``recv()``, copy data to and from those OS buffers. For example, if
the peer is sending data too quickly, then the OS receive buffer will
start to get full, and the OS will signal the peer to stop
transmitting.  When ``recv()`` is called, the OS will copy data from
its internal buffer into your process, free up space in its own
buffer, and then signal to the peer to start transmitting again.

Therefore, you need to follow these two rules to implement back-pressure over
TCP:

#. Do not receive from the socket faster than your code can process the
   messages. Your processing code may need to signal the receiving code when its
   ready to receive more data.
#. Do not store out-going messages in an unbounded collection. Ideally,
   out-going messages should be sent to the OS as soon as possible. If you need
   to buffer messages in memory, the buffer should be bounded so that it can not
   grow indefinitely.

Post handshake connection
-------------------------

A WebSocket connection starts with a handshake, which is an agreement
to use the WebSocket protocol, and on which sub-protocol and
extensions to use. It can be advantageous to perform this handshake
outside of `wsproto`, for example in a dual stack setup whereby the
HTTP handling is completed separately. In this case the
:class:`Connection <wsproto.connection.Connection>` class can be used
directly.

.. code-block:: python

    connection = Connection(extensions)  # Agreed extensions
    sock.send(connection.send(Message(data=b"Hi")))

    connection.receive_data(sock.recv(4096))

    for event in connection.events():
        # As with WSConnection, only without any handshake events

HTTP/2
------

WebSockets over HTTP/2 have a distinct difference to HTTP/1 in that
only a single HTTP/2 stream is dedicated to the WebSocket rather than
the entire connection (as in HTTP/1). This requires the HTTP/2
connection to be managed before the WebSocket connection with
`Hyper-h2 <https://python-hyper.org/h2>`_ being recommended for
HTTP/2.

Although `wsproto` doesn't manage the HTTP/2 connection it provides an
RFC 8441 handshake entry point and the WebSocket frame layer. The HTTP/2
implementation remains responsible for HTTP/2 frames, stream state, flow
control, and the ``SETTINGS_ENABLE_CONNECT_PROTOCOL`` setting.

For a server, pass the parsed extended CONNECT headers to
:class:`H2Handshake <wsproto.handshake.H2Handshake>`. Then select the
subprotocol and extensions from the request and call ``accept``. The
returned headers do not include ``:status``; prepend a 2xx status and
send them with hyper-h2. RFC 8441 does not use a 101 response,
``Sec-WebSocket-Key``, or ``Sec-WebSocket-Accept``.

.. code-block:: python

    from wsproto.connection import ConnectionType
    from wsproto.events import AcceptConnection
    from wsproto.extensions import PerMessageDeflate
    from wsproto.handshake import H2Handshake

    handshake = H2Handshake(ConnectionType.SERVER)
    request = handshake.receive_headers(request_headers)
    extension = PerMessageDeflate()
    response_headers = handshake.accept(
        AcceptConnection(subprotocol="chat", extensions=[extension]),
    )
    h2_connection.send_headers(
        stream_id,
        [(b":status", b"200")] + response_headers,
    )
    websocket = handshake.connection

For a client, build the extended CONNECT headers with
``initiate_connection``. The client may send WebSocket DATA after a 2xx
response has been received and passed to ``receive_headers``. The server
may send WebSocket DATA after it has sent the 2xx response headers. The
request and response HEADERS must not carry ``END_STREAM`` when the
WebSocket is expected to remain open.

.. code-block:: python

    from wsproto.connection import ConnectionType
    from wsproto.events import Request
    from wsproto.extensions import PerMessageDeflate
    from wsproto.handshake import H2Handshake

    handshake = H2Handshake(ConnectionType.CLIENT)
    request_headers = handshake.initiate_connection(
        Request(
            host="example.com",
            target="/chat",
            subprotocols=["chat"],
            extensions=[PerMessageDeflate()],
        ),
    )
    h2_connection.send_headers(stream_id, request_headers)
    # After h2 emits ResponseReceived:
    accepted = handshake.receive_headers(response_headers)
    websocket = handshake.connection

Any DATA received on the HTTP/2 stream should be passed to
``websocket.receive_data``, and bytes returned by ``websocket.send``
should be wrapped in HTTP/2 DATA frames.

HTTP/2 stream termination is transport termination, not a WebSocket
Close frame. When hyper-h2 emits ``StreamEnded`` (the peer's
``END_STREAM``), pass ``None`` to ``websocket.receive_data``. If no
WebSocket Close frame was received first, wsproto reports the underlying
EOF as ``CloseConnection`` with code 1006 (abnormal closure). When
hyper-h2 emits ``StreamReset`` (``RST_STREAM``), surface an exception
such as ``ConnectionResetError`` in the application glue and discard the
stream. Do not synthesize a normal WebSocket Close frame, and in
particular do not invent close code 1000, for either ``END_STREAM`` or
``RST_STREAM``.
