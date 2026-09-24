from __future__ import annotations

import pytest

from wsproto.connection import CLIENT, SERVER, ConnectionState
from wsproto.events import AcceptConnection, BytesMessage, Ping, Request
from wsproto.extensions import PerMessageDeflate
from wsproto.handshake import H11Handshake
from wsproto.utilities import LocalProtocolError, RemoteProtocolError


def test_successful_handshake() -> None:
    client = H11Handshake(CLIENT)
    server = H11Handshake(SERVER)

    server.receive_data(client.send(Request(host="localhost", target="/")))
    assert isinstance(next(server.events()), Request)

    client.receive_data(server.send(AcceptConnection()))
    assert isinstance(next(client.events()), AcceptConnection)

    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN

    assert repr(client) == "H11Handshake(client=True, state=ConnectionState.OPEN)"
    assert repr(server) == "H11Handshake(client=False, state=ConnectionState.OPEN)"


def test_host_encoding() -> None:
    client = H11Handshake(CLIENT)
    server = H11Handshake(SERVER)
    data = client.send(Request(host="芝士汉堡", target="/"))
    assert b"Host: xn--7ks3rz39bh7u" in data
    server.receive_data(data)
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "芝士汉堡"


@pytest.mark.parametrize("http", [b"HTTP/1.0", b"HTTP/1.1"])
def test_rejected_handshake(http: bytes) -> None:
    server = H11Handshake(SERVER)
    with pytest.raises(RemoteProtocolError):
        server.receive_data(
            b"GET / " + http + b"\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: VQr8cvwwZ1fEk62PDq8J3A==\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"\r\n",
        )


def test_initiate_upgrade_as_client() -> None:
    client = H11Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.initiate_upgrade_connection([], "/")


def test_send_invalid_event() -> None:
    client = H11Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(Ping())


def test_h11_multiple_headers_handshake() -> None:
    server = H11Handshake(SERVER)
    data = (
        b"GET wss://api.website.xyz/ws HTTP/1.1\r\n"
        b"Host: api.website.xyz\r\n"
        b"Connection: Upgrade\r\n"
        b"Pragma: no-cache\r\n"
        b"Cache-Control: no-cache\r\n"
        b"User-Agent: Mozilla/5.0 (X11; Linux x86_64) "
        b"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36\r\n"
        b"Upgrade: websocket\r\n"
        b"Origin: https://website.xyz\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n"
        b"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
        b"Sec-WebSocket-Key: tOzeAzi9xK7ADxxEdTzmaA==\r\n"
        b"Sec-WebSocket-Extensions: this-extension; isnt-seen, even-tho, it-should-be\r\n"
        b"Sec-WebSocket-Protocol: there-protocols\r\n"
        b"Sec-WebSocket-Protocol: arent-seen\r\n"
        b"Sec-WebSocket-Extensions: this-extension; were-gonna-see, and-another-extension; were-also; gonna-see=100; percent\r\n"
        b"Sec-WebSocket-Protocol: only-these-protocols, are-seen, from-the-request-object\r\n"
        b"\r\n"
    )
    server.receive_data(data)
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.subprotocols == [
        "there-protocols",
        "arent-seen",
        "only-these-protocols",
        "are-seen",
        "from-the-request-object",
    ]
    assert request.extensions == [
        "this-extension; isnt-seen",
        "even-tho",
        "it-should-be",
        "this-extension; were-gonna-see",
        "and-another-extension; were-also; gonna-see=100; percent",
    ]


def test_handshake_with_multiple_extension_offers() -> None:
    client = H11Handshake(CLIENT)
    server = H11Handshake(SERVER)

    client_extension = PerMessageDeflate(
        server_no_context_takeover=True, server_max_window_bits=10,
    )
    request = client.send(
        Request(host="localhost", target="/", extensions=[client_extension]),
    )
    # Prepend an invalid candidate (a window of 8 is not supported) to the
    # valid one.
    request = request.replace(
        b"Sec-WebSocket-Extensions: permessage-deflate",
        b"Sec-WebSocket-Extensions: permessage-deflate;"
        b" client_no_context_takeover; client_max_window_bits=8,"
        b" permessage-deflate",
        1,
    )
    server.receive_data(request)
    assert isinstance(next(server.events()), Request)

    server_extension = PerMessageDeflate()
    response = server.send(AcceptConnection(extensions=[server_extension]))
    # The declined candidate's parameters must not leak into the response.
    assert b"client_no_context_takeover" not in response
    assert b"client_max_window_bits=8" not in response
    assert b"server_no_context_takeover" in response
    assert b"server_max_window_bits=10" in response

    client.receive_data(response)
    assert isinstance(next(client.events()), AcceptConnection)

    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN

    # The negotiated parameters belong to the successful candidate.
    assert not server_extension.client_no_context_takeover
    assert server_extension.server_no_context_takeover
    assert server_extension.server_max_window_bits == 10
    assert client_extension.server_no_context_takeover
    assert client_extension.server_max_window_bits == 10

    client_connection = client.connection
    server_connection = server.connection
    assert client_connection is not None
    assert server_connection is not None

    # Exchange two messages in each direction to prove that compression and
    # decompression work with the negotiated parameters.
    for _ in range(2):
        data = b"Compress me! " * 10
        server_connection.receive_data(
            client_connection.send(BytesMessage(data=data, message_finished=True)),
        )
        event = next(server_connection.events())
        assert isinstance(event, BytesMessage)
        assert event.data == data

        client_connection.receive_data(
            server_connection.send(BytesMessage(data=data, message_finished=True)),
        )
        event = next(client_connection.events())
        assert isinstance(event, BytesMessage)
        assert event.data == data


@pytest.mark.parametrize(
    "bad_parameters",
    [
        # Unsupported window size (must not silently enable a wrong window)
        b"server_max_window_bits=8",
        # Not a number (must not leak an int() exception)
        b"client_max_window_bits=abc",
        # The client did not offer this parameter
        b"server_no_context_takeover",
        # Parameters may not be repeated
        b"client_no_context_takeover; client_no_context_takeover",
        # Unknown parameters are not allowed
        b"made_up_parameter",
    ],
)
def test_handshake_rejects_invalid_extension_response(bad_parameters: bytes) -> None:
    client = H11Handshake(CLIENT)
    server = H11Handshake(SERVER)

    client_extension = PerMessageDeflate()
    server.receive_data(
        client.send(Request(host="localhost", target="/", extensions=[client_extension])),
    )
    assert isinstance(next(server.events()), Request)

    server_extension = PerMessageDeflate()
    response = server.send(AcceptConnection(extensions=[server_extension]))
    response = response.replace(
        b"client_max_window_bits=15; server_max_window_bits=15",
        bad_parameters,
    )

    with pytest.raises(RemoteProtocolError):
        client.receive_data(response)

    assert not client_extension.enabled()
    assert client.connection is None
