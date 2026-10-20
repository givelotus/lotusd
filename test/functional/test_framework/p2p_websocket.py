#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A minimal synchronous P2P peer speaking over WebSocket (/p2p/ws).

It implements the p2p-zstd-v1 / p2p-zstd sub-protocols independently of the
node (with python-zstandard), so tests exercise interoperability rather than
the node talking to itself.

Both zstd sub-protocols also carry independent (compress-once) frames:
binary messages with RSV2 set whose payload is
[format 1][dictionary version LE32][one zstd frame with its content size],
compressed with the P2P dictionary only (see doc/p2p-websocket.md).
"""

import os
import re
import ssl
import struct
import unittest
from io import BytesIO

from .messages import msg_sendaddrv2, msg_verack, msg_version, sha256
from .p2p import MESSAGEMAP, NET_MAGIC_BYTES


def load_p2p_zstd_dict(srcdir):
    """Read P2P_ZSTD_DICT_V1 from the generated C++ header."""
    path = os.path.join(srcdir, "src", "net_zstd_dict_data.h")
    with open(path, encoding="utf8") as f:
        text = f.read()
    body = text[text.index("P2P_ZSTD_DICT_V1[") :]
    body = body[body.index("{") + 1 : body.index("};")]
    return bytes(int(b, 16) for b in re.findall(r"0x([0-9a-f]{2})", body))


ZSTD_SUBPROTOCOLS = ("p2p-zstd-v1", "p2p-zstd")
INDEPENDENT_FORMAT = 1
INDEPENDENT_DICT_VERSION = 1
MAX_WINDOW = 1 << 20


def decode_independent(body, zdict, max_size):
    """Decode an independent frame as strictly as the node does."""
    import zstandard

    if (
        len(body) < 5
        or body[0] != INDEPENDENT_FORMAT
        or struct.unpack("<I", body[1:5])[0] != INDEPENDENT_DICT_VERSION
    ):
        raise ValueError("unsupported independent frame format/dictionary")
    frame = body[5:]
    if len(frame) < 6 or frame[:4] != b"\x28\xb5\x2f\xfd":
        raise ValueError("independent payload is not a zstd frame")
    params = zstandard.get_frame_parameters(frame)
    if params.content_size in (zstandard.CONTENTSIZE_UNKNOWN, None):
        raise ValueError("independent frame without content size")
    if params.content_size > max_size or params.window_size > MAX_WINDOW:
        raise ValueError("independent frame resource bound exceeded")
    if zstandard.frame_content_size(frame) != params.content_size:
        raise ValueError("inconsistent content size")
    out = zstandard.ZstdDecompressor(dict_data=zdict).decompressobj()
    data = out.decompress(frame)
    if not out.eof or out.unused_data or len(data) != params.content_size:
        raise ValueError("truncated, trailing or mismatched independent frame")
    return data


def encode_independent(raw, zdict):
    """An independent frame of P2P bytes (as the node makes them)."""
    import zstandard

    frame = zstandard.ZstdCompressor(
        level=1, dict_data=zdict, write_content_size=True, write_checksum=False
    ).compress(raw)
    return (
        bytes([INDEPENDENT_FORMAT])
        + struct.pack("<I", INDEPENDENT_DICT_VERSION)
        + frame
    )


def _frames_frame_buffer(ws, allow_rsv2):
    """websocket-client refuses every RSV bit: accept RSV2 on complete binary
    frames of a zstd connection, and nothing else."""
    from websocket import _abnf

    class Frame(_abnf.ABNF):
        def validate(self, skip_utf8_validation=False):
            if (
                allow_rsv2
                and self.rsv2
                and not self.rsv1
                and not self.rsv3
                and self.fin
                and self.opcode == _abnf.ABNF.OPCODE_BINARY
            ):
                self.rsv2 = 0
                try:
                    super().validate(skip_utf8_validation)
                finally:
                    self.rsv2 = 1
                return
            super().validate(skip_utf8_validation)

    class Buffer(_abnf.frame_buffer):
        def recv_frame(self):
            with self.lock:
                if self.needs_header():
                    self.recv_header()
                fin, rsv1, rsv2, rsv3, opcode, has_mask, _ = self.header
                if self.needs_length():
                    self.recv_length()
                length = self.length
                if self.needs_mask():
                    self.recv_mask()
                mask_value = self.mask_value
                payload = self.recv_strict(length)
                if has_mask:
                    payload = _abnf.ABNF.mask(mask_value, payload)
                self.clear()
                frame = Frame(fin, rsv1, rsv2, rsv3, opcode, has_mask, payload)
                frame.validate(self.skip_utf8_validation)
            return frame

    return Buffer(ws.frame_buffer.recv, ws.frame_buffer.skip_utf8_validation)


class P2PWebSocketClient:
    def __init__(
        self,
        url,
        *,
        subprotocols=None,
        srcdir=None,
        net="regtest",
        timeout=30,
        header=None,
        ws=None,
    ):
        """Connect to `url`, or use `ws`, an already open WebSocket with the
        same methods (e.g. test_framework.http2.H2WebSocket)."""
        import zstandard

        if ws is not None:
            self.ws = ws
        else:
            import websocket

            sslopt = {"cert_reqs": ssl.CERT_NONE} if url.startswith("wss") else None
            self.ws = websocket.create_connection(
                url, subprotocols=subprotocols, sslopt=sslopt, timeout=timeout, header=header
            )
        self.subprotocol = self.ws.getsubprotocol()
        self.frames = self.subprotocol in ZSTD_SUBPROTOCOLS
        self.ws.frame_buffer = _frames_frame_buffer(self.ws, self.frames)
        self.magic = NET_MAGIC_BYTES[net]
        self.recvbuf = b""
        self.wire_bytes_sent = 0
        self.payload_bytes_sent = 0
        self.independent_frames_recv = 0
        self.max_message_size = 64 * 1024 * 1024
        self.compressor = self.decompressor = self.zdict = None
        if self.frames:
            # Independent frames always use the dictionary; the stream only
            # with p2p-zstd-v1.
            self.zdict = zstandard.ZstdCompressionDict(
                load_p2p_zstd_dict(srcdir),
                dict_type=zstandard.DICT_TYPE_RAWCONTENT,
            )
            dict_data = self.zdict if self.subprotocol == "p2p-zstd-v1" else None
            self.compressor = zstandard.ZstdCompressor(
                level=1,
                dict_data=dict_data,
                write_checksum=False,
                write_content_size=False,
            ).compressobj()
            self.decompressor = zstandard.ZstdDecompressor(
                dict_data=dict_data
            ).decompressobj()
            self.flush_mode = zstandard.COMPRESSOBJ_FLUSH_BLOCK

    def build_message(self, message):
        data = message.serialize()
        msgtype = message.msgtype
        return (
            self.magic
            + msgtype
            + b"\x00" * (12 - len(msgtype))
            + len(data).to_bytes(4, "little")
            + sha256(sha256(data))[:4]
            + data
        )

    def send_raw(self, raw):
        payload = raw
        if self.compressor:
            payload = self.compressor.compress(raw) + self.compressor.flush(
                self.flush_mode
            )
        self.ws.send_binary(payload)
        self.payload_bytes_sent += len(raw)
        self.wire_bytes_sent += len(payload)

    def send_message(self, message):
        self.send_raw(self.build_message(message))

    def send_independent(self, raw):
        """Send P2P bytes as one independent (RSV2) frame (zstd modes)."""
        from websocket import ABNF

        payload = encode_independent(raw, self.zdict)
        self.ws.send_frame(ABNF(1, 0, 1, 0, ABNF.OPCODE_BINARY, 1, payload))
        self.payload_bytes_sent += len(raw)
        self.wire_bytes_sent += len(payload)

    def recv_wire(self):
        """The next data message's P2P bytes (decompressed)."""
        from websocket import ABNF

        opcode, frame = self.ws.recv_data_frame(True)
        if opcode == ABNF.OPCODE_CLOSE or opcode not in (
            ABNF.OPCODE_BINARY,
            ABNF.OPCODE_CONT,
        ):
            raise ConnectionError("WebSocket closed by the node")
        data = frame.data
        if frame.rsv2:
            self.independent_frames_recv += 1
            return decode_independent(data, self.zdict, self.max_message_size)
        if self.decompressor:
            data = self.decompressor.decompress(data)
        return data

    def recv_raw_message(self):
        """The next complete P2P message: (msgtype, its exact bytes)."""
        while True:
            if len(self.recvbuf) >= 24:
                length = int.from_bytes(self.recvbuf[16:20], "little")
                if len(self.recvbuf) >= 24 + length:
                    raw = self.recvbuf[: 24 + length]
                    self.recvbuf = self.recvbuf[24 + length :]
                    return raw[4:16].rstrip(b"\x00"), raw
            self.recvbuf += self.recv_wire()

    def recv_message(self):
        """Return the next complete P2P message (deserialized)."""
        while True:
            if len(self.recvbuf) >= 24:
                assert self.recvbuf[:4] == self.magic, self.recvbuf[:4]
                msgtype = self.recvbuf[4:16].rstrip(b"\x00")
                length = int.from_bytes(self.recvbuf[16:20], "little")
                if len(self.recvbuf) >= 24 + length:
                    payload = self.recvbuf[24 : 24 + length]
                    assert self.recvbuf[20:24] == sha256(sha256(payload))[:4]
                    self.recvbuf = self.recvbuf[24 + length :]
                    cls = MESSAGEMAP.get(msgtype)
                    if cls is None:
                        return msgtype, payload
                    obj = cls()
                    obj.deserialize(BytesIO(payload))
                    return msgtype, obj
            self.recvbuf += self.recv_wire()

    def wait_for(self, msgtype):
        while True:
            t, msg = self.recv_message()
            if t == msgtype:
                return msg

    def handshake(self, version=70016, *, addr_recv=None, sendaddrv2=False):
        """P2P handshake. `addr_recv` (ip, port) is the node's address as we
        claim to see it; with `sendaddrv2` we ask for ADDRv2 (BIP155)."""
        ver = msg_version()
        ver.nVersion = version
        ver.strSubVer = "/p2p_websocket.py/"
        ver.relay = 1
        if addr_recv is not None:
            ver.addrTo.ip, ver.addrTo.port = addr_recv
        self.send_message(ver)
        their_version = self.wait_for(b"version")
        self.wait_for(b"verack")
        self.send_message(msg_verack())
        if sendaddrv2:
            # This node accepts it after the handshake (BIP155 places it
            # before verack, which it treats as misbehaving).
            self.send_message(msg_sendaddrv2())
        return their_version

    def close(self):
        self.ws.close()


# Codec-only tests; they start no node.
class TestIndependentFrames(unittest.TestCase):
    def setUp(self):
        try:
            import zstandard
        except ImportError:
            self.skipTest("zstandard needed for independent-frame tests")
        self.zstd = zstandard
        srcdir = os.path.join(os.path.dirname(__file__), "..", "..", "..")
        self.zdict = zstandard.ZstdCompressionDict(
            load_p2p_zstd_dict(srcdir), dict_type=zstandard.DICT_TYPE_RAWCONTENT
        )
        self.raw = b"\xfa\xbf\xb5\xdablock" + bytes(range(256)) * 400

    def test_roundtrip(self):
        frame = encode_independent(self.raw, self.zdict)
        self.assertEqual(decode_independent(frame, self.zdict, 1 << 20), self.raw)

    def test_rejects(self):
        good = encode_independent(self.raw, self.zdict)
        no_size = good[:5] + self.zstd.ZstdCompressor(
            dict_data=self.zdict, write_content_size=False
        ).compress(self.raw)
        window = good[:5] + self.zstd.ZstdCompressor(level=3).compress(
            b"x" * (2 * 1024 * 1024)
        )
        for bad in [
            b"",
            good[:4],
            bytes([2]) + good[1:],
            good[:1] + struct.pack("<I", 2) + good[5:],
            good[:-1],
            good + b"x",
            good + good[5:],
            no_size,
            window,
        ]:
            with self.subTest(size=len(bad)):
                with self.assertRaises(Exception):
                    decode_independent(bad, self.zdict, 4 * 1024 * 1024)
        with self.assertRaises(ValueError):
            decode_independent(good, self.zdict, len(self.raw) - 1)
