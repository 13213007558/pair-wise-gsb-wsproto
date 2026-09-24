"""
wsproto/extensions
~~~~~~~~~~~~~~~~~~

WebSocket extensions.
"""
from __future__ import annotations

import zlib
from abc import ABC, abstractmethod
from typing import Optional

from .events import RejectConnection
from .frame_protocol import CloseReason, FrameDecoder, FrameProtocol, Opcode, RsvBits
from .utilities import RemoteProtocolError


class Extension(ABC):
    name: str

    def enabled(self) -> bool:
        return False

    @abstractmethod
    def offer(self) -> bool | str:
        pass

    def accept(self, offer: str) -> bool | str | None:
        pass

    def finalize(self, offer: str) -> None:
        pass

    def frame_inbound_header(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        payload_length: int,
    ) -> CloseReason | RsvBits:
        return RsvBits(False, False, False)

    def frame_inbound_payload_data(
        self, proto: FrameDecoder | FrameProtocol, data: bytes,
    ) -> bytes | CloseReason:
        return data

    def frame_inbound_complete(
        self, proto: FrameDecoder | FrameProtocol, fin: bool,
    ) -> bytes | CloseReason | None:
        pass

    def frame_outbound(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        data: bytes,
        fin: bool,
    ) -> tuple[RsvBits, bytes]:
        return (rsv, data)


class PerMessageDeflate(Extension):
    name = "permessage-deflate"

    DEFAULT_CLIENT_MAX_WINDOW_BITS = 15
    DEFAULT_SERVER_MAX_WINDOW_BITS = 15

    def __init__(
        self,
        client_no_context_takeover: bool = False,
        client_max_window_bits: int | None = None,
        server_no_context_takeover: bool = False,
        server_max_window_bits: int | None = None,
    ) -> None:
        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
        self._client_max_window_bits = self.DEFAULT_CLIENT_MAX_WINDOW_BITS
        self._server_max_window_bits = self.DEFAULT_SERVER_MAX_WINDOW_BITS
        if client_max_window_bits is not None:
            self.client_max_window_bits = client_max_window_bits
        if server_max_window_bits is not None:
            self.server_max_window_bits = server_max_window_bits

        self._compressor: Optional[zlib._Compress] = None  # noqa
        self._decompressor: Optional[zlib._Decompress] = None  # noqa
        # This refers to the current frame
        self._inbound_is_compressible: bool | None = None
        # This refers to the ongoing message (which might span multiple
        # frames). Only the first frame in a fragmented message is flagged for
        # compression, so this carries that bit forward.
        self._inbound_compressed: bool | None = None

        self._enabled = False

        # Snapshot of the original local configuration. Every candidate
        # offer is negotiated afresh from these values so that a rejected
        # (or previously accepted) candidate cannot leak state into the
        # negotiation of a subsequent candidate.
        self._local_config = (
            self.client_no_context_takeover,
            self._client_max_window_bits,
            self.server_no_context_takeover,
            self._server_max_window_bits,
        )

    @property
    def client_max_window_bits(self) -> int:
        return self._client_max_window_bits

    @client_max_window_bits.setter
    def client_max_window_bits(self, value: int) -> None:
        if value < 9 or value > 15:
            msg = "Window size must be between 9 and 15 inclusive"
            raise ValueError(msg)
        self._client_max_window_bits = value

    @property
    def server_max_window_bits(self) -> int:
        return self._server_max_window_bits

    @server_max_window_bits.setter
    def server_max_window_bits(self, value: int) -> None:
        if value < 9 or value > 15:
            msg = "Window size must be between 9 and 15 inclusive"
            raise ValueError(msg)
        self._server_max_window_bits = value

    def _compressible_opcode(self, opcode: Opcode) -> bool:
        return opcode in (Opcode.TEXT, Opcode.BINARY, Opcode.CONTINUATION)

    def enabled(self) -> bool:
        return self._enabled

    def offer(self) -> bool | str:
        parameters = [
            f"client_max_window_bits={self.client_max_window_bits}",
            f"server_max_window_bits={self.server_max_window_bits}",
        ]

        if self.client_no_context_takeover:
            parameters.append("client_no_context_takeover")
        if self.server_no_context_takeover:
            parameters.append("server_no_context_takeover")

        return "; ".join(parameters)

    def finalize(self, offer: str) -> None:
        # `offer` is the server's response to the offer we made; it must be
        # validated against the parameters we originally offered (RFC 7692,
        # Section 7.1) before it is applied.
        client_no_context_takeover = False
        server_no_context_takeover = False
        client_max_window_bits = self.client_max_window_bits
        server_max_window_bits = self.server_max_window_bits

        try:
            for name, value in self._parse_params(offer).items():
                if name == "client_no_context_takeover":
                    if value is not None:
                        msg = f"Extension parameter {name} must not have a value"
                        raise ValueError(msg)
                    # A server may always request this, even if the offer did
                    # not include it (RFC 7692, Section 7.1.1.2).
                    client_no_context_takeover = True
                elif name == "server_no_context_takeover":
                    if value is not None:
                        msg = f"Extension parameter {name} must not have a value"
                        raise ValueError(msg)
                    if not self.server_no_context_takeover:
                        msg = f"Response includes {name} but it was not offered"
                        raise ValueError(msg)
                    server_no_context_takeover = True
                elif name == "client_max_window_bits":
                    bits = self._parse_window_bits(name, value)
                    if bits > self.client_max_window_bits:
                        msg = (
                            f"Response {name}={bits} exceeds the offered"
                            f" {self.client_max_window_bits}"
                        )
                        raise ValueError(msg)
                    client_max_window_bits = bits
                elif name == "server_max_window_bits":
                    bits = self._parse_window_bits(name, value)
                    if bits > self.server_max_window_bits:
                        msg = (
                            f"Response {name}={bits} exceeds the offered"
                            f" {self.server_max_window_bits}"
                        )
                        raise ValueError(msg)
                    server_max_window_bits = bits
                else:
                    msg = f"Unknown extension parameter: {name}"
                    raise ValueError(msg)
        except ValueError as error:
            msg = f"Invalid permessage-deflate response: {error}"
            raise RemoteProtocolError(msg, event_hint=RejectConnection()) from error

        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
        self._client_max_window_bits = client_max_window_bits
        self._server_max_window_bits = server_max_window_bits
        self._enabled = True

    def _parse_params(self, params: str) -> dict[str, str | None]:
        """
        Split an extension parameter string into name/value pairs.

        Parameter names must match exactly, and each parameter may appear at
        most once. Raises ValueError otherwise.
        """
        parsed: dict[str, str | None] = {}
        bits = [b.strip() for b in params.split(";")]
        for bit in bits[1:]:
            name, separator, value = bit.partition("=")
            name = name.strip()
            if not name or name in parsed:
                msg = f"Invalid or duplicate extension parameter: {bit!r}"
                raise ValueError(msg)
            parsed[name] = value.strip() if separator else None
        return parsed

    @staticmethod
    def _parse_window_bits(name: str, value: str | None) -> int:
        if value is None:
            msg = f"Extension parameter {name} requires a value"
            raise ValueError(msg)
        try:
            bits = int(value)
        except ValueError:
            msg = f"Invalid value for extension parameter {name}: {value!r}"
            raise ValueError(msg) from None
        if bits < 9 or bits > 15:
            msg = f"Invalid value for extension parameter {name}: {value!r}"
            raise ValueError(msg)
        return bits

    def _parse_offer(self, offer: str) -> dict[str, int | bool | None]:
        """
        Parse and validate an offer's parameters per RFC 7692.

        Raises ValueError if the offer is invalid and must be declined.
        """
        parsed: dict[str, int | bool | None] = {}
        for name, value in self._parse_params(offer).items():
            if name in ("client_no_context_takeover", "server_no_context_takeover"):
                if value is not None:
                    msg = f"Extension parameter {name} must not have a value"
                    raise ValueError(msg)
                parsed[name] = True
            elif name == "client_max_window_bits":
                # A valueless client_max_window_bits in an offer means the
                # client supports any window size (RFC 7692, Section 7.1.2.2).
                parsed[name] = (
                    None if value is None else self._parse_window_bits(name, value)
                )
            elif name == "server_max_window_bits":
                # A server_max_window_bits offer must include a value
                # (RFC 7692, Section 7.1.2.1).
                parsed[name] = self._parse_window_bits(name, value)
            else:
                msg = f"Unknown extension parameter: {name}"
                raise ValueError(msg)
        return parsed

    def accept(self, offer: str) -> bool | None | str:
        try:
            params = self._parse_offer(offer)
        except ValueError:
            # Decline invalid offers (RFC 7692, Section 7.1).
            return None

        # Negotiate each candidate afresh from the original local
        # configuration so that state from other candidates cannot leak
        # into this negotiation.
        (
            client_no_context_takeover,
            client_max_window_bits,
            server_no_context_takeover,
            server_max_window_bits,
        ) = self._local_config

        # A server may always request client_no_context_takeover, even if
        # the offer did not include it (RFC 7692, Section 7.1.1.2).
        client_no_context_takeover = (
            client_no_context_takeover or "client_no_context_takeover" in params
        )
        # A response must not include server_no_context_takeover unless the
        # offer included it (RFC 7692, Section 7.1.1.1).
        server_no_context_takeover = "server_no_context_takeover" in params

        parameters = []
        if client_no_context_takeover:
            parameters.append("client_no_context_takeover")
        if server_no_context_takeover:
            parameters.append("server_no_context_takeover")

        if "client_max_window_bits" in params:
            offered = params["client_max_window_bits"]
            if offered is not None:
                client_max_window_bits = min(offered, client_max_window_bits)
            parameters.append(f"client_max_window_bits={client_max_window_bits}")
        if "server_max_window_bits" in params:
            offered = params["server_max_window_bits"]
            assert offered is not None
            server_max_window_bits = min(offered, server_max_window_bits)
            parameters.append(f"server_max_window_bits={server_max_window_bits}")

        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
        self._client_max_window_bits = client_max_window_bits
        self._server_max_window_bits = server_max_window_bits
        self._enabled = True
        return "; ".join(parameters)

    def frame_inbound_header(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        payload_length: int,
    ) -> CloseReason | RsvBits:
        if rsv.rsv1 and opcode.iscontrol():
            return CloseReason.PROTOCOL_ERROR
        if rsv.rsv1 and opcode is Opcode.CONTINUATION:
            return CloseReason.PROTOCOL_ERROR

        self._inbound_is_compressible = self._compressible_opcode(opcode)

        if self._inbound_compressed is None:
            self._inbound_compressed = rsv.rsv1
            if self._inbound_compressed:
                assert self._inbound_is_compressible
                if proto.client:
                    bits = self.server_max_window_bits
                else:
                    bits = self.client_max_window_bits
                if self._decompressor is None:
                    self._decompressor = zlib.decompressobj(-int(bits))

        return RsvBits(True, False, False)

    def frame_inbound_payload_data(
        self, proto: FrameDecoder | FrameProtocol, data: bytes,
    ) -> bytes | CloseReason:
        if not self._inbound_compressed or not self._inbound_is_compressible:
            return data
        assert self._decompressor is not None

        try:
            return self._decompressor.decompress(bytes(data))
        except zlib.error:
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA

    def frame_inbound_complete(
        self, proto: FrameDecoder | FrameProtocol, fin: bool,
    ) -> bytes | CloseReason | None:
        if not fin:
            return None
        if not self._inbound_is_compressible:
            self._inbound_compressed = None
            return None
        if not self._inbound_compressed:
            self._inbound_compressed = None
            return None
        assert self._decompressor is not None

        try:
            data = self._decompressor.decompress(b"\x00\x00\xff\xff")
            data += self._decompressor.flush()
        except zlib.error:
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA

        if proto.client:
            no_context_takeover = self.server_no_context_takeover
        else:
            no_context_takeover = self.client_no_context_takeover

        if no_context_takeover:
            self._decompressor = None

        self._inbound_compressed = None

        return data

    def frame_outbound(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        data: bytes,
        fin: bool,
    ) -> tuple[RsvBits, bytes]:
        if not self._compressible_opcode(opcode):
            return (rsv, data)

        if opcode is not Opcode.CONTINUATION:
            rsv = RsvBits(True, rsv[1], rsv[2])

        if self._compressor is None:
            assert opcode is not Opcode.CONTINUATION
            if proto.client:
                bits = self.client_max_window_bits
            else:
                bits = self.server_max_window_bits
            self._compressor = zlib.compressobj(
                zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -int(bits),
            )

        data = self._compressor.compress(bytes(data))

        if fin:
            data += self._compressor.flush(zlib.Z_SYNC_FLUSH)
            data = data[:-4]

            if proto.client:
                no_context_takeover = self.client_no_context_takeover
            else:
                no_context_takeover = self.server_no_context_takeover

            if no_context_takeover:
                self._compressor = None

        return (rsv, data)

    def __repr__(self) -> str:
        descr = [f"client_max_window_bits={self.client_max_window_bits}"]
        if self.client_no_context_takeover:
            descr.append("client_no_context_takeover")
        descr.append(f"server_max_window_bits={self.server_max_window_bits}")
        if self.server_no_context_takeover:
            descr.append("server_no_context_takeover")

        return "<{} {}>".format(self.__class__.__name__, "; ".join(descr))


#: SUPPORTED_EXTENSIONS maps all supported extension names to their class.
#: This can be used to iterate all supported extensions of wsproto, instantiate
#: new extensions based on their name, or check if a given extension is
#: supported or not.
SUPPORTED_EXTENSIONS = {PerMessageDeflate.name: PerMessageDeflate}
