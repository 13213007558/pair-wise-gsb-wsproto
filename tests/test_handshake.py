from __future__ import annotations

import pytest

from wsproto import WSConnection
from wsproto import extensions as wpext
from wsproto.connection import CLIENT, SERVER, ConnectionState
from wsproto.events import AcceptConnection, Ping, Request, TextMessage
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


def test_permessage_deflate_handshake_multiple_offers() -> None:
    client = WSConnection(CLIENT)
    server = WSConnection(SERVER)

    client_ext = wpext.PerMessageDeflate()
    server_ext = wpext.PerMessageDeflate()

    # The client initiates the handshake, recording its own offer so that
    # the response can later be validated against it.
    request_bytes = client.send(
        Request(host="localhost", target="/", extensions=[client_ext]),
    )
    key_line = next(
        line
        for line in request_bytes.split(b"\r\n")
        if line.lower().startswith(b"sec-websocket-key")
    )

    # The server receives two offers: the first is unacceptable (a window
    # of 8 is too small), so the second one must be negotiated afresh.
    server.receive_data(
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        + key_line + b"\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover;"
        b" client_max_window_bits=8, permessage-deflate; server_max_window_bits=10;"
        b" client_max_window_bits=12\r\n"
        b"\r\n",
    )
    request = next(server.events())
    assert isinstance(request, Request)

    response = server.send(AcceptConnection(extensions=[server_ext]))
    assert (
        b"Sec-WebSocket-Extensions: permessage-deflate;"
        b" client_max_window_bits=12; server_max_window_bits=10" in response
    )
    assert b"client_no_context_takeover" not in response

    client.receive_data(response)
    event = next(client.events())
    assert isinstance(event, AcceptConnection)

    # The negotiated parameters belong to the second (valid) offer, with no
    # state leaking in from the rejected first offer.
    assert server_ext.enabled()
    assert client_ext.enabled()
    assert not server_ext.client_no_context_takeover
    assert not client_ext.client_no_context_takeover
    assert server_ext.client_max_window_bits == 12
    assert server_ext.server_max_window_bits == 10
    assert client_ext.client_max_window_bits == 12
    assert client_ext.server_max_window_bits == 10

    # Messages can be compressed and decompressed in both directions.
    for _ in range(2):
        server.receive_data(client.send(TextMessage(data="hello server")))
        event = next(server.events())
        assert isinstance(event, TextMessage)
        assert event.data == "hello server"

        client.receive_data(server.send(TextMessage(data="hello client")))
        event = next(client.events())
        assert isinstance(event, TextMessage)
        assert event.data == "hello client"


@pytest.mark.parametrize(
    "bad_params",
    [
        "client_max_window_bits=8",
        "client_max_window_bits=abc",
        "server_max_window_bits",
        "client_no_context_takeoverXXX",
        "server_max_window_bits=10; server_max_window_bits=11",
    ],
)
def test_permessage_deflate_invalid_server_response(bad_params: str) -> None:
    client = WSConnection(CLIENT)
    server = WSConnection(SERVER)

    client_ext = wpext.PerMessageDeflate()

    class RogueExtension(wpext.PerMessageDeflate):
        def accept(self, offer: str) -> str:
            # Respond with parameters that violate RFC 7692.
            return bad_params

    server.receive_data(
        client.send(Request(host="localhost", target="/", extensions=[client_ext])),
    )
    request = next(server.events())
    assert isinstance(request, Request)

    response = server.send(AcceptConnection(extensions=[RogueExtension()]))
    assert bad_params.encode("ascii") in response

    # The illegal response fails the handshake with an explainable error
    # rather than leaking an int() exception or silently enabling a wrong
    # window size.
    with pytest.raises(RemoteProtocolError, match="permessage-deflate"):
        client.receive_data(response)
    assert not client_ext.enabled()
