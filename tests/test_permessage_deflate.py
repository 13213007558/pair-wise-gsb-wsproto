from __future__ import annotations

import zlib
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Optional, cast

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


def _enabled_ext(**kwargs: Any) -> wpext.PerMessageDeflate:
    ext = wpext.PerMessageDeflate(**kwargs)
    ext._enabled = True
    return ext


def _receiver_ext(
    client: bool, no_context_takeover: bool, limit: int,
 ) -> wpext.PerMessageDeflate:
    if client:
        args = {"server_no_context_takeover": no_context_takeover}
    else:
        args = {"client_no_context_takeover": no_context_takeover}
    return _enabled_ext(max_decompressed_message_size=limit, **args)


def _compress(payload: bytes) -> bytes:
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    return compressor.compress(payload) + compressor.flush(zlib.Z_SYNC_FLUSH)[:-4]


def _frame(fin: bool, rsv1: bool, opcode: fp.Opcode, payload: bytes) -> bytes:
    assert len(payload) <= 125
    first = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | int(opcode)
    return bytes([first, len(payload)]) + payload


# A stored (uncompressed) deflate block header declaring four literal
# bytes. The literal data itself is withheld, so it is only emitted once
# the sync-flush tail appended at message end is processed.
STORED_BLOCK_HEADER = bytes([0x00, 0x04, 0x00, 0xFB, 0xFF])
TAIL_DATA = bytes([0x00, 0x00, 0xFF, 0xFF])


class TestPerMessageDeflateMaxDecompressedMessageSize:
    @pytest.mark.parametrize(
        "client,no_context_takeover",
        [(True, True), (True, False), (False, True), (False, False)],
    )
    def test_limit_exceeded_in_payload_data(
        self, client: bool, no_context_takeover: bool,
    ) -> None:
        ext = _receiver_ext(client, no_context_takeover, limit=10)
        proto = fp.FrameProtocol(client=client, extensions=[ext])
        compressed_payload = _compress(b"x" * 23)

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)

        result = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert result is fp.CloseReason.MESSAGE_TOO_BIG
        # The compression state must not be reused after the error.
        assert ext._decompressor is None
        assert ext._inbound_compressed is None

    @pytest.mark.parametrize("client", [True, False])
    @pytest.mark.parametrize("limit,ok", [(22, False), (23, True)])
    def test_limit_boundary(self, client: bool, limit: int, ok: bool) -> None:
        payload = b"x" * 23
        compressed_payload = _compress(payload)
        ext = _receiver_ext(client, False, limit)
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        result = ext.frame_inbound_payload_data(proto, compressed_payload)
        if not ok:
            assert result is fp.CloseReason.MESSAGE_TOO_BIG
            return
        # A message exactly as large as the limit is allowed.
        assert result == payload
        assert ext.frame_inbound_complete(proto, True) == b""

    @pytest.mark.parametrize(
        "client,no_context_takeover",
        [(True, True), (True, False), (False, True), (False, False)],
    )
    def test_limit_exceeded_in_deflate_tail(
        self, client: bool, no_context_takeover: bool,
    ) -> None:
        # The four literal bytes of the stored block are only emitted
        # when the sync-flush tail is fed at message end, so the limit
        # is exceeded while completing the final frame.
        ext = _receiver_ext(client, no_context_takeover, limit=3)
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(STORED_BLOCK_HEADER),
        )
        assert isinstance(result, fp.RsvBits)
        assert ext.frame_inbound_payload_data(proto, STORED_BLOCK_HEADER) == b""

        result = ext.frame_inbound_complete(proto, True)
        assert result is fp.CloseReason.MESSAGE_TOO_BIG
        # The compression state must not be reused after the error.
        assert ext._decompressor is None
        assert ext._inbound_compressed is None

    @pytest.mark.parametrize("client", [True, False])
    def test_limit_met_exactly_in_deflate_tail(self, client: bool) -> None:
        ext = _receiver_ext(client, False, limit=4)
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(STORED_BLOCK_HEADER),
        )
        assert ext.frame_inbound_payload_data(proto, STORED_BLOCK_HEADER) == b""
        # The message is exactly as large as the limit, so it is allowed.
        assert ext.frame_inbound_complete(proto, True) == TAIL_DATA

    @pytest.mark.parametrize("no_context_takeover", [True, False])
    def test_compression_state_not_reused_after_error(
        self, no_context_takeover: bool,
    ) -> None:
        ext = _receiver_ext(True, no_context_takeover, limit=10)
        proto = fp.FrameProtocol(client=True, extensions=[ext])
        compressed_payload = _compress(b"x" * 23)

        ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        result = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert result is fp.CloseReason.MESSAGE_TOO_BIG

        # A subsequent message must be decompressed with fresh state.
        payload = b"abc"
        compressed_payload = _compress(payload)
        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        data = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert not isinstance(data, fp.CloseReason)
        rest = ext.frame_inbound_complete(proto, True)
        assert not isinstance(rest, fp.CloseReason)
        assert data + rest == payload

    def test_invalid_limit(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            wpext.PerMessageDeflate(max_decompressed_message_size=-1)


@pytest.mark.parametrize("no_context_takeover", [True, False])
def test_connection_tiny_frame_huge_message(no_context_takeover: bool) -> None:
    limit = 100
    receiving_ext = _enabled_ext(
        server_no_context_takeover=no_context_takeover,
        max_decompressed_message_size=limit,
    )
    sending_ext = _enabled_ext(server_no_context_takeover=no_context_takeover)
    receiver = Connection(CLIENT, extensions=[receiving_ext])
    sender = Connection(SERVER, extensions=[sending_ext])

    payload = b"x" * 1000
    wire = bytes(sender.send(BytesMessage(data=payload, message_finished=True)))
    # The compressed message is tiny compared to its decompressed size.
    assert len(wire) < limit

    events = []
    for index in range(0, len(wire), 2):
        receiver.receive_data(wire[index : index + 2])
        events.extend(receiver.events())

    messages = [event for event in events if isinstance(event, BytesMessage)]
    closes = [event for event in events if isinstance(event, CloseConnection)]
    assert len(closes) == 1
    assert closes[0].code is fp.CloseReason.MESSAGE_TOO_BIG
    assert events[-1] is closes[0]
    # The application only received fragments that fit within the limit.
    delivered = b"".join(bytes(event.data) for event in messages)
    assert 0 < len(delivered) <= limit
    assert delivered == payload[: len(delivered)]
    assert all(not event.message_finished for event in messages)
    # The compression state must not be reused after the error.
    assert receiving_ext._decompressor is None
    assert receiving_ext._inbound_compressed is None


@pytest.mark.parametrize("no_context_takeover", [True, False])
@pytest.mark.parametrize("limit,ok", [(99, False), (100, True)])
def test_connection_deflate_tail_and_interleaved_ping_pong(
    no_context_takeover: bool, limit: int, ok: bool,
 ) -> None:
    receiving_ext = _enabled_ext(
        server_no_context_takeover=no_context_takeover,
        max_decompressed_message_size=limit,
    )
    receiver = Connection(CLIENT, extensions=[receiving_ext])

    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    prefix = compressor.compress(b"x" * 96) + compressor.flush(zlib.Z_SYNC_FLUSH)

    # A fragmented message whose final four bytes are only emitted when
    # the sync-flush tail is processed, with control frames interleaved.
    wire = b"".join(
        [
            _frame(False, True, fp.Opcode.BINARY, prefix),
            _frame(True, False, fp.Opcode.PING, b"interleaved ping"),
            _frame(True, False, fp.Opcode.PONG, b"interleaved pong"),
            _frame(True, False, fp.Opcode.CONTINUATION, STORED_BLOCK_HEADER),
        ]
    )

    events = []
    for index in range(len(wire)):
        receiver.receive_data(wire[index : index + 1])
        events.extend(receiver.events())

    messages = [event for event in events if isinstance(event, BytesMessage)]
    pings = [event for event in events if isinstance(event, Ping)]
    pongs = [event for event in events if isinstance(event, Pong)]
    closes = [event for event in events if isinstance(event, CloseConnection)]
    assert len(pings) == 1
    assert len(pongs) == 1
    delivered = b"".join(bytes(event.data) for event in messages)
    if ok:
        # The interleaved ping/pong payloads neither counted towards the
        # limit nor disturbed the message, which is delivered in full.
        assert not closes
        assert delivered == b"x" * 96 + TAIL_DATA
        assert messages[-1].message_finished
    else:
        assert len(closes) == 1
        assert closes[0].code is fp.CloseReason.MESSAGE_TOO_BIG
        assert events[-1] is closes[0]
        # Only the fragments preceding the deflate tail were delivered.
        assert delivered == b"x" * 96
        assert all(not event.message_finished for event in messages)
        # The compression state must not be reused after the error.
        assert receiving_ext._decompressor is None
        assert receiving_ext._inbound_compressed is None


@pytest.mark.parametrize("limit,ok", [(119, False), (120, True)])
def test_connection_utf8_counted_as_decompressed_bytes(
    limit: int, ok: bool,
 ) -> None:
    receiving_ext = _enabled_ext(max_decompressed_message_size=limit)
    sending_ext = _enabled_ext()
    receiver = Connection(CLIENT, extensions=[receiving_ext])
    sender = Connection(SERVER, extensions=[sending_ext])

    text = "é" * 60
    assert len(text.encode("utf-8")) == 120
    wire = bytes(sender.send(TextMessage(data=text, message_finished=True)))

    events = []
    for index in range(0, len(wire), 3):
        receiver.receive_data(wire[index : index + 3])
        events.extend(receiver.events())

    texts = [event for event in events if isinstance(event, TextMessage)]
    closes = [event for event in events if isinstance(event, CloseConnection)]
    if ok:
        assert not closes
        assert "".join(event.data for event in texts) == text
        assert texts[-1].message_finished
    else:
        # 60 characters would fit within the limit; 120 bytes do not.
        assert len(closes) == 1
        assert closes[0].code is fp.CloseReason.MESSAGE_TOO_BIG


def test_connection_small_message_delivered_incrementally() -> None:
    receiving_ext = _enabled_ext(max_decompressed_message_size=1024)
    sending_ext = _enabled_ext()
    receiver = Connection(CLIENT, extensions=[receiving_ext])
    sender = Connection(SERVER, extensions=[sending_ext])

    payload = b"a small message that is delivered in pieces"
    wire = bytes(sender.send(BytesMessage(data=payload, message_finished=True)))

    events = []
    for index in range(0, len(wire), 2):
        receiver.receive_data(wire[index : index + 2])
        events.extend(receiver.events())

    messages = [event for event in events if isinstance(event, BytesMessage)]
    closes = [event for event in events if isinstance(event, CloseConnection)]
    assert not closes
    assert len(messages) > 1
    assert b"".join(bytes(event.data) for event in messages) == payload
    assert all(not event.message_finished for event in messages[:-1])
    assert messages[-1].message_finished
