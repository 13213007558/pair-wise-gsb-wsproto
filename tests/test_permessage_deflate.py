from __future__ import annotations

import zlib
from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional, cast

import pytest

from wsproto import extensions as wpext
from wsproto import frame_protocol as fp
from wsproto.connection import CLIENT, SERVER, Connection
from wsproto.events import BytesMessage, CloseConnection, Ping, Pong, TextMessage

if TYPE_CHECKING:
    from typing import TypedDict

    class Params(TypedDict, total=False):
        client_no_context_takeover: bool
        client_max_window_bits: Optional[int]
        server_no_context_takeover: bool
        server_max_window_bits: Optional[int]

else:
    Params = dict


class TestPerMessageDeflate:
    parameter_sets: Sequence[Params] = [
        {
            "client_no_context_takeover": False,
            "client_max_window_bits": 15,
            "server_no_context_takeover": False,
            "server_max_window_bits": 15,
        },
        {
            "client_no_context_takeover": True,
            "client_max_window_bits": 9,
            "server_no_context_takeover": False,
            "server_max_window_bits": 15,
        },
        {
            "client_no_context_takeover": False,
            "client_max_window_bits": 15,
            "server_no_context_takeover": True,
            "server_max_window_bits": 9,
        },
        {
            "client_no_context_takeover": True,
            "client_max_window_bits": 9,
            "server_no_context_takeover": True,
            "server_max_window_bits": 9,
        },
        {"client_no_context_takeover": True, "server_max_window_bits": 9},
        {"server_no_context_takeover": True, "client_max_window_bits": 9},
        {"client_max_window_bits": None, "server_max_window_bits": None},
        {},
    ]

    def make_offer_string(self, params: Params) -> str:
        offer = ["permessage-deflate"]

        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                offer.append("client_max_window_bits")
            else:
                offer.append(
                    "client_max_window_bits=%d" % params["client_max_window_bits"],
                )
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                offer.append("server_max_window_bits")
            else:
                offer.append(
                    "server_max_window_bits=%d" % params["server_max_window_bits"],
                )
        if params.get("client_no_context_takeover", False):
            offer.append("client_no_context_takeover")
        if params.get("server_no_context_takeover", False):
            offer.append("server_no_context_takeover")

        return "; ".join(offer)

    def compare_params_to_string(
        self, params: Params, ext: wpext.PerMessageDeflate, param_string: str,
    ) -> None:
        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                bits = ext.client_max_window_bits
            else:
                bits = params["client_max_window_bits"]
            assert "client_max_window_bits=%d" % bits in param_string
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                bits = ext.server_max_window_bits
            else:
                bits = params["server_max_window_bits"]
            assert "server_max_window_bits=%d" % bits in param_string
        if params.get("client_no_context_takeover", False):
            assert "client_no_context_takeover" in param_string
        if params.get("server_no_context_takeover", False):
            assert "server_no_context_takeover" in param_string

    @pytest.mark.parametrize("params", parameter_sets)
    def test_offer(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate(**params)
        offer = ext.offer()
        offer = cast("str", offer)

        self.compare_params_to_string(params, ext, offer)

    @pytest.mark.parametrize("params", parameter_sets)
    def test_finalize(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                del params["client_max_window_bits"]
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                del params["server_max_window_bits"]
        offer = self.make_offer_string(params)
        ext.finalize(offer)

        if params.get("client_max_window_bits", None):
            assert ext.client_max_window_bits == params["client_max_window_bits"]
        if params.get("server_max_window_bits", None):
            assert ext.server_max_window_bits == params["server_max_window_bits"]
        assert ext.client_no_context_takeover is params.get(
            "client_no_context_takeover", False,
        )
        assert ext.server_no_context_takeover is params.get(
            "server_no_context_takeover", False,
        )

        assert ext.enabled()

    def test_finalize_ignores_rubbish(self) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        ext.finalize("i am the lizard queen; worship me")

        assert ext.enabled()

    @pytest.mark.parametrize("params", parameter_sets)
    def test_accept(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        offer = self.make_offer_string(params)
        response = ext.accept(offer)
        response = cast("str", response)

        if ext.client_no_context_takeover:
            assert "client_no_context_takeover" in response
        if ext.server_no_context_takeover:
            assert "server_no_context_takeover" in response
        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                bits = ext.client_max_window_bits
            else:
                bits = params["client_max_window_bits"]
            assert ext.client_max_window_bits == bits
            assert "client_max_window_bits=%d" % bits in response
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                bits = ext.server_max_window_bits
            else:
                bits = params["server_max_window_bits"]
            assert ext.server_max_window_bits == bits
            assert "server_max_window_bits=%d" % bits in response

    def test_accept_ignores_rubbish(self) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        ext.accept("i am the lizard queen; worship me")

        assert ext.enabled()

    def test_inbound_uncompressed_control_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(False, False, False), len(payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, payload)
        assert data == payload

        assert ext.frame_inbound_complete(proto, True) is None

    def test_inbound_compressed_control_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(True, False, False), len(payload),
        )
        assert result == fp.CloseReason.PROTOCOL_ERROR

    def test_inbound_compressed_continuation_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.CONTINUATION, fp.RsvBits(True, False, False), len(payload),
        )
        assert result == fp.CloseReason.PROTOCOL_ERROR

    def test_inbound_uncompressed_data_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(False, False, False), len(payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, payload)
        assert data == payload

        assert ext.frame_inbound_complete(proto, True) is None

    @pytest.mark.parametrize("client", [True, False])
    def test_client_inbound_compressed_single_data_frame(self, client: bool) -> None:
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert isinstance(data, bytes)
        data2 = ext.frame_inbound_complete(proto, True)
        assert isinstance(data2, bytes)
        assert data + data2 == payload

    @pytest.mark.parametrize("client", [True, False])
    def test_client_inbound_compressed_multiple_data_frames(self, client: bool) -> None:
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"
        split = 3
        data = b""

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), split,
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1
        result2 = ext.frame_inbound_payload_data(proto, compressed_payload[:split])
        assert not isinstance(result2, fp.CloseReason)
        data += result2
        assert ext.frame_inbound_complete(proto, False) is None

        result3 = ext.frame_inbound_header(
            proto,
            fp.Opcode.CONTINUATION,
            fp.RsvBits(False, False, False),
            len(compressed_payload) - split,
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1
        result4 = ext.frame_inbound_payload_data(proto, compressed_payload[split:])
        assert not isinstance(result4, fp.CloseReason)
        data += result4

        result5 = ext.frame_inbound_complete(proto, True)
        assert isinstance(result5, bytes)
        data += result5

        assert data == payload

    @pytest.mark.parametrize("client", [True, False])
    def test_client_decompress_after_uncompressible_frame(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        # A PING frame
        ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(False, False, False), 0,
        )
        result2 = ext.frame_inbound_payload_data(proto, b"")
        assert not isinstance(result2, fp.CloseReason)
        assert ext.frame_inbound_complete(proto, True) is None

        # A compressed TEXT frame
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        result3 = ext.frame_inbound_header(
            proto,
            fp.Opcode.TEXT,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1
        result4 = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert result4 == payload

        result5 = ext.frame_inbound_complete(proto, True)
        assert not isinstance(result5, fp.CloseReason)

    def test_inbound_bad_zlib_payload(self) -> None:
        compressed_payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1
        result2 = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert result2 is fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA

    def test_inbound_bad_zlib_decoder_end_state(self) -> None:
        compressed_payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        class FailDecompressor:
            def decompress(self, data: bytes) -> bytes:
                return b""

            def flush(self) -> None:
                raise zlib.error()

        ext._decompressor = cast("zlib._Decompress", FailDecompressor())
        result2 = ext.frame_inbound_complete(proto, True)

        assert result2 is fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA

    @pytest.mark.parametrize(
        "client,no_context_takeover",
        [(True, True), (True, False), (False, True), (False, False)],
    )
    def test_decompressor_reset(self, client: bool, no_context_takeover: bool) -> None:
        if client:
            args = {"server_no_context_takeover": no_context_takeover}
        else:
            args = {"client_no_context_takeover": no_context_takeover}
        ext = wpext.PerMessageDeflate(**args)
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 0,
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        assert ext._decompressor is not None

        result2 = ext.frame_inbound_complete(proto, True)
        assert not isinstance(result2, fp.CloseReason)

        if no_context_takeover:
            assert ext._decompressor is None
        else:
            assert ext._decompressor is not None

        result3 = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 0,
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1

        assert ext._decompressor is not None

    def test_outbound_uncompressible_opcode(self) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23

        rsv, data = ext.frame_outbound(proto, fp.Opcode.PING, rsv, payload, True)

        assert rsv.rsv1 is False
        assert data == payload

    @pytest.mark.parametrize("client", [True, False])
    def test_outbound_compress_single_frame(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, payload, True)

        assert rsv.rsv1 is True
        assert data == compressed_payload

    @pytest.mark.parametrize("client", [True, False])
    def test_outbound_compress_multiple_frames(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23
        split = 12
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        rsv, data = ext.frame_outbound(
            proto, fp.Opcode.BINARY, rsv, payload[:split], False,
        )
        assert rsv.rsv1 is True

        rsv = fp.RsvBits(False, False, False)
        rsv, more_data = ext.frame_outbound(
            proto, fp.Opcode.CONTINUATION, rsv, payload[split:], True,
        )
        assert rsv.rsv1 is False
        assert data + more_data == compressed_payload

    @pytest.mark.parametrize(
        "client,no_context_takeover",
        [(True, True), (True, False), (False, True), (False, False)],
    )
    def test_compressor_reset(self, client: bool, no_context_takeover: bool) -> None:
        if client:
            args = {"client_no_context_takeover": no_context_takeover}
        else:
            args = {"server_no_context_takeover": no_context_takeover}
        ext = wpext.PerMessageDeflate(**args)
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])
        rsv = fp.RsvBits(False, False, False)

        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, b"", False)
        assert rsv.rsv1 is True
        assert ext._compressor is not None

        rsv = fp.RsvBits(False, False, False)
        rsv, data = ext.frame_outbound(proto, fp.Opcode.CONTINUATION, rsv, b"", True)
        assert rsv.rsv1 is False
        if no_context_takeover:
            assert ext._compressor is None
        else:
            assert ext._compressor is not None

        rsv = fp.RsvBits(False, False, False)
        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, b"", False)
        assert rsv.rsv1 is True
        assert ext._compressor is not None

    @pytest.mark.parametrize("params", parameter_sets)
    def test_repr(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate(**params)
        self.compare_params_to_string(params, ext, repr(ext))


class TestPerMessageDeflateMessageSizeLimit:
    def make_connections(
        self, max_message_size: int | None, no_context_takeover: bool,
    ) -> tuple[Connection, Connection, wpext.PerMessageDeflate]:
        server_ext = wpext.PerMessageDeflate(
            client_no_context_takeover=no_context_takeover,
            max_message_size=max_message_size,
        )
        server_ext._enabled = True
        server = Connection(SERVER, extensions=[server_ext])

        client_ext = wpext.PerMessageDeflate(
            client_no_context_takeover=no_context_takeover,
        )
        client_ext._enabled = True
        client = Connection(CLIENT, extensions=[client_ext])

        return client, server, server_ext

    @staticmethod
    def feed_in_slices(
        server: Connection, wire: bytes | bytearray, slice_size: int = 3,
    ) -> list:
        events = []
        for i in range(0, len(wire), slice_size):
            server.receive_data(bytes(wire[i : i + slice_size]))
            events.extend(server.events())
        return events

    @pytest.mark.parametrize("no_context_takeover", [True, False])
    def test_message_exactly_at_limit_is_accepted(
        self, no_context_takeover: bool,
    ) -> None:
        limit = 50
        client, server, _ = self.make_connections(limit, no_context_takeover)

        wire = client.send(TextMessage("a" * 30, message_finished=False))
        wire += client.send(TextMessage("b" * 20))
        events = self.feed_in_slices(server, wire)

        assert not [e for e in events if isinstance(e, CloseConnection)]
        messages = [e for e in events if isinstance(e, TextMessage)]
        assert "".join(e.data for e in messages) == "a" * 30 + "b" * 20
        assert messages[-1].message_finished

    @pytest.mark.parametrize("no_context_takeover", [True, False])
    def test_limit_exceeded_at_deflate_tail_with_tiny_slices(
        self, no_context_takeover: bool,
    ) -> None:
        limit = 64
        client, server, server_ext = self.make_connections(
            limit, no_context_takeover,
        )

        # A normal small message first, to establish compression context
        # when context takeover is enabled.
        wire = client.send(TextMessage("hello"))
        events = self.feed_in_slices(server, wire)
        texts = [e for e in events if isinstance(e, TextMessage)]
        assert "".join(e.data for e in texts) == "hello"

        # The decompressed message only exceeds the limit with the very
        # last byte of the deflate stream.
        payload = b"y" * limit + b"z"
        wire = client.send(BytesMessage(payload))
        events = self.feed_in_slices(server, wire, slice_size=1)

        closes = [e for e in events if isinstance(e, CloseConnection)]
        assert len(closes) == 1
        assert closes[0].code == fp.CloseReason.MESSAGE_TOO_BIG

        # The application received at most a prefix of the message no
        # longer than the limit, and never a finished message.
        messages = [e for e in events if isinstance(e, BytesMessage)]
        received = b"".join(bytes(e.data) for e in messages)
        assert len(received) <= limit
        assert payload.startswith(received)
        assert not any(e.message_finished for e in messages)

        # The tainted decompression state must not be reused.
        assert server_ext._decompressor is None

    @pytest.mark.parametrize("no_context_takeover", [True, False])
    def test_interleaved_ping_pong_does_not_count_or_reset(
        self, no_context_takeover: bool,
    ) -> None:
        limit = 50
        client, server, _ = self.make_connections(limit, no_context_takeover)

        wire = client.send(TextMessage("a" * 30, message_finished=False))
        wire += client.send(Ping(payload=b"12345"))
        wire += client.send(Pong(payload=b"12345"))
        wire += client.send(TextMessage("b" * 20))
        events = self.feed_in_slices(server, wire)

        # The message is exactly at the 50 byte limit; the interleaved
        # control frames must not count towards it nor reset the count.
        assert not [e for e in events if isinstance(e, CloseConnection)]
        pings = [e for e in events if isinstance(e, Ping)]
        pongs = [e for e in events if isinstance(e, Pong)]
        assert len(pings) == 1
        assert pings[0].payload == b"12345"
        assert len(pongs) == 1
        messages = [e for e in events if isinstance(e, TextMessage)]
        assert "".join(e.data for e in messages) == "a" * 30 + "b" * 20
        assert messages[-1].message_finished

    @pytest.mark.parametrize("no_context_takeover", [True, False])
    def test_utf8_multibyte_counts_decompressed_bytes(
        self, no_context_takeover: bool,
    ) -> None:
        limit = 10

        # 5 characters, 10 decompressed bytes: exactly at the limit.
        client, server, _ = self.make_connections(limit, no_context_takeover)
        wire = client.send(TextMessage("\u00e9" * 5))
        events = self.feed_in_slices(server, wire)
        assert not [e for e in events if isinstance(e, CloseConnection)]
        texts = [e for e in events if isinstance(e, TextMessage)]
        assert "".join(e.data for e in texts) == "\u00e9" * 5

        # 6 characters, 12 decompressed bytes: over the limit.
        client, server, _ = self.make_connections(limit, no_context_takeover)
        wire = client.send(TextMessage("\u00e9" * 6))
        events = self.feed_in_slices(server, wire)
        closes = [e for e in events if isinstance(e, CloseConnection)]
        assert len(closes) == 1
        assert closes[0].code == fp.CloseReason.MESSAGE_TOO_BIG

    def test_small_message_delivered_incrementally(self) -> None:
        client, server, _ = self.make_connections(1000, False)

        text = "hello world, " * 5
        wire = client.send(TextMessage(text, message_finished=False))
        wire += client.send(TextMessage("the end"))

        events = []
        for i in range(len(wire)):
            server.receive_data(bytes(wire[i : i + 1]))
            events.extend(server.events())

        assert not [e for e in events if isinstance(e, CloseConnection)]
        messages = [e for e in events if isinstance(e, TextMessage)]
        assert "".join(e.data for e in messages) == text + "the end"
        assert messages[-1].message_finished
        # Delivery was incremental: more than one non-empty fragment.
        assert len([e for e in messages if e.data]) > 1

    @pytest.mark.parametrize("no_context_takeover", [True, False])
    def test_zip_bomb_rejected_without_full_decompression(
        self, no_context_takeover: bool,
    ) -> None:
        limit = 1024
        client, server, _ = self.make_connections(limit, no_context_takeover)

        payload = b"z" * 1_000_000
        wire = client.send(BytesMessage(payload))
        assert len(wire) < 2000

        server.receive_data(bytes(wire))
        events = list(server.events())

        closes = [e for e in events if isinstance(e, CloseConnection)]
        assert len(closes) == 1
        assert closes[0].code == fp.CloseReason.MESSAGE_TOO_BIG
        # Nowhere near the full 1MB was decompressed into the application.
        messages = [e for e in events if isinstance(e, BytesMessage)]
        assert sum(len(e.data) for e in messages) <= limit

    @pytest.mark.parametrize("client", [True, False])
    @pytest.mark.parametrize("no_context_takeover", [True, False])
    def test_decompressor_dropped_after_limit_error(
        self, client: bool, no_context_takeover: bool,
    ) -> None:
        if client:
            args = {"server_no_context_takeover": no_context_takeover}
        else:
            args = {"client_no_context_takeover": no_context_takeover}
        ext = wpext.PerMessageDeflate(max_message_size=10, **args)
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 7,
        )
        assert isinstance(result, fp.RsvBits)
        assert ext._decompressor is not None

        # 23 decompressed bytes, over the limit of 10.
        result2 = ext.frame_inbound_payload_data(proto, b"\xaa\xa8\xc0\n\x00\x00")
        assert result2 is fp.CloseReason.MESSAGE_TOO_BIG
        assert ext._decompressor is None

        # A subsequent message starts with a fresh decompressor rather
        # than reusing the tainted state.
        result3 = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 0,
        )
        assert isinstance(result3, fp.RsvBits)
        assert ext._decompressor is not None

        compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        small = compressor.compress(b"ok") + compressor.flush(zlib.Z_SYNC_FLUSH)
        result4 = ext.frame_inbound_payload_data(proto, small[:-4])
        assert result4 == b"ok"

    @pytest.mark.parametrize(
        "limit,expected_ok",
        [(23, True), (22, False)],
    )
    def test_inbound_message_size_limit(self, limit: int, expected_ok: bool) -> None:
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        ext = wpext.PerMessageDeflate(max_message_size=limit)
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)

        data = ext.frame_inbound_payload_data(proto, compressed_payload)
        if expected_ok:
            assert data == payload
            assert not isinstance(
                ext.frame_inbound_complete(proto, True), fp.CloseReason,
            )
        else:
            assert data is fp.CloseReason.MESSAGE_TOO_BIG
