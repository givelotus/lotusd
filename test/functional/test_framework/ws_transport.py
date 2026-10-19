#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""P2P over WebSocket for the test framework's P2PConnection.

The node's P2P WebSocket endpoint (/p2p/ws) carries the usual P2P byte
stream inside binary WebSocket messages. This module does the RFC 6455
opening handshake (as client or server, without compression: no
subprotocol) and framing, so P2PConnection can keep treating the payload as
a byte stream.
"""

import base64
import hashlib
import os
import re
import struct
import unittest

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
P2P_WS_PATH = "/p2p/ws"

# Lotus v2 framing ("p2p-v2", see src/net_websocket.h): one P2P message per
# WebSocket message, as a 1-byte id (or 0, a length and the name) and the
# payload; RSV1 marks a message compressed with the connection's zstd stream.
P2P_V2_PROTOCOL = "p2p-v2"
# Ids are 1-based indexes; append only, as in src/protocol.cpp.
P2P_V2_MESSAGE_TYPES = [
    "version",
    "verack",
    "addr",
    "addrv2",
    "sendaddrv2",
    "inv",
    "getdata",
    "merkleblock",
    "getblocks",
    "getheaders",
    "tx",
    "headers",
    "block",
    "getaddr",
    "mempool",
    "ping",
    "pong",
    "notfound",
    "filterload",
    "filteradd",
    "filterclear",
    "sendheaders",
    "feefilter",
    "sendcmpct",
    "cmpctblock",
    "getblocktxn",
    "blocktxn",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "avahello",
    "avapoll",
    "avaresponse",
    "avaproof",
    "getavaaddr",
    "getavaproofs",
    "avaproofs",
    "avaproofsreq",
    "avatreasury",
    "avabatch",
    "minedheader",
    "sealedheader",
    "sealedblock",
    "merklixsync",
    "getmerklixbuck",
    "merklixbuck",
    "getshorttx",
    "shorttx",
    "getutxoroots",
    "utxoroots",
    "getutxoshard",
    "utxoshard",
    "getblockundo",
    "blockundo",
    "sendinvshort",
    "invshort",
]
P2P_V2_IDS = {name.encode(): i + 1 for i, name in enumerate(P2P_V2_MESSAGE_TYPES)}
P2P_ZSTD_DICT_VERSION = 2
RSV1 = 0x40
RSV2 = 0x20

_P2P_DICT = None


def p2p_zstd_dict():
    """The node's P2P zstd dictionary, read from src/net_zstd_dict_v2_data.h."""
    global _P2P_DICT
    if _P2P_DICT is None:
        here = os.path.dirname(os.path.realpath(__file__))
        header = os.path.join(here, "..", "..", "..", "src", "net_zstd_dict_v2_data.h")
        with open(header, encoding="utf8") as f:
            text = f.read()
        body = text[text.index("{", text.index("P2P_ZSTD_DICT_V2[")) :].split("}", 1)[0]
        _P2P_DICT = bytes(int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]{2})", body))
    return _P2P_DICT


class P2PV2Converter:
    """Between the framework's v1 messages and p2p-v2 WebSocket messages."""

    def __init__(self, magic, max_message_size=256 * 1024 * 1024):
        self.max_message_size = max_message_size
        self.magic = magic
        self.pending = b""
        self.decompressor = None

    def to_wire(self, v1_bytes):
        """Complete v1 messages in `v1_bytes` (buffered) as p2p-v2 bodies."""
        self.pending += v1_bytes
        bodies = []
        while len(self.pending) >= 24:
            if self.pending[:4] != self.magic:
                raise ValueError("p2p-v2: framework sent a message with bad magic")
            length = struct.unpack("<I", self.pending[16:20])[0]
            if len(self.pending) < 24 + length:
                break
            name = self.pending[4:16].rstrip(b"\x00")
            payload = self.pending[24 : 24 + length]
            self.pending = self.pending[24 + length :]
            msg_id = P2P_V2_IDS.get(name)
            prefix = bytes([msg_id]) if msg_id else b"\x00" + bytes([len(name)]) + name
            bodies.append(prefix + payload)
        return bodies

    def from_wire(self, body, compressed, independent=False):
        """A received p2p-v2 message as a v1 message for the framework."""
        if independent:
            import zstandard

            if (
                len(body) < 6
                or body[0] != 1
                or struct.unpack("<I", body[1:5])[0] != P2P_ZSTD_DICT_VERSION
            ):
                raise ValueError("independent frame/dictionary version mismatch")
            frame = body[5:]
            params = zstandard.get_frame_parameters(frame)
            if (
                params.content_size > self.max_message_size
                or params.window_size > 1024 * 1024
            ):
                raise ValueError("independent frame resource bound exceeded")
            zdict = zstandard.ZstdCompressionDict(
                p2p_zstd_dict(), dict_type=zstandard.DICT_TYPE_RAWCONTENT
            )
            body = zstandard.ZstdDecompressor(dict_data=zdict).decompress(
                frame, max_output_size=self.max_message_size, allow_extra_data=False
            )
        elif compressed:
            if self.decompressor is None:
                import zstandard

                zdict = zstandard.ZstdCompressionDict(
                    p2p_zstd_dict(), dict_type=zstandard.DICT_TYPE_RAWCONTENT
                )
                self.decompressor = zstandard.ZstdDecompressor(
                    dict_data=zdict
                ).decompressobj()
            body = self.decompressor.decompress(body)
        msg_id = body[0]
        if msg_id == 0:
            name = body[2 : 2 + body[1]]
            payload = body[2 + body[1] :]
        else:
            name = P2P_V2_MESSAGE_TYPES[msg_id - 1].encode()
            payload = body[1:]
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return (
            self.magic
            + name.ljust(12, b"\x00")
            + struct.pack("<I", len(payload))
            + checksum
            + payload
        )


OP_CONTINUATION = 0x0
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


def apply_mask(mask, payload):
    """XOR `payload` with the repeated 4-byte `mask` (fast for large data)."""
    n = len(payload)
    if n == 0:
        return payload
    m = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(payload, "little") ^ int.from_bytes(m, "little")).to_bytes(
        n, "little"
    )


def accept_key(key):
    return base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()


class WebSocketLayer:
    """WebSocket state for one connection (client or server role)."""

    def __init__(
        self,
        client,
        host="127.0.0.1",
        port=0,
        path=P2P_WS_PATH,
        v2_magic=None,
        max_message_size=256 * 1024 * 1024,
    ):
        self.client = client
        self.host = host
        self.port = port
        self.path = path
        # With the network magic: speak p2p-v2 (convert v1 messages).
        self.v2 = (
            P2PV2Converter(v2_magic, max_message_size) if v2_magic is not None else None
        )
        self.message_compressed = False
        self.message_independent = False
        self.independent_frames_recv = 0
        self.open = False
        self.closed = False
        self.buf = b""
        self.fragments = b""
        self.key = base64.b64encode(os.urandom(16)).decode()

    # Opening handshake

    def request(self):
        """The client's upgrade request."""
        assert self.client
        return (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self.key}\r\nSec-WebSocket-Version: 13\r\n"
            + (f"Sec-WebSocket-Protocol: {P2P_V2_PROTOCOL}\r\n" if self.v2 else "")
            + "\r\n"
        ).encode()

    def feed_handshake(self, data):
        """Consume handshake bytes. Returns (done, bytes_to_send)."""
        self.buf += data
        end = self.buf.find(b"\r\n\r\n")
        if end < 0:
            if len(self.buf) > 16384:
                raise ValueError("WebSocket handshake too long")
            return False, b""
        head, self.buf = self.buf[:end].decode("latin-1"), self.buf[end + 4 :]
        lines = head.split("\r\n")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        if self.client:
            if lines[0].split(" ")[1:2] != ["101"]:
                raise ValueError(f"WebSocket upgrade refused: {lines[0]}")
            if headers.get("sec-websocket-accept") != accept_key(self.key):
                raise ValueError("bad Sec-WebSocket-Accept")
            if self.v2 and headers.get("sec-websocket-protocol") != P2P_V2_PROTOCOL:
                raise ValueError("server did not select p2p-v2")
            reply = b""
        else:
            method = lines[0].split(" ")[0]
            if method != "GET" or headers.get("upgrade", "").lower() != "websocket":
                raise ValueError(f"not a WebSocket upgrade: {lines[0]}")
            offered = [
                p.strip() for p in headers.get("sec-websocket-protocol", "").split(",")
            ]
            if self.v2 and P2P_V2_PROTOCOL not in offered:
                raise ValueError("client did not offer p2p-v2")
            reply = (
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_key(headers['sec-websocket-key'])}"
                "\r\n"
                + (f"Sec-WebSocket-Protocol: {P2P_V2_PROTOCOL}\r\n" if self.v2 else "")
                + "\r\n"
            ).encode()
        self.open = True
        return True, reply

    # Framing

    def _frame(self, opcode, payload, rsv=0):
        header = bytes([0x80 | rsv | opcode])
        mask_bit = 0x80 if self.client else 0
        n = len(payload)
        if n < 126:
            header += bytes([mask_bit | n])
        elif n < 65536:
            header += bytes([mask_bit | 126]) + struct.pack(">H", n)
        else:
            header += bytes([mask_bit | 127]) + struct.pack(">Q", n)
        if not self.client:
            return header + payload
        mask = os.urandom(4)
        return header + mask + apply_mask(mask, payload)

    def encode(self, payload):
        """Binary message(s) carrying `payload` (with p2p-v2: one per complete
        v1 message in it, uncompressed)."""
        if self.v2:
            return b"".join(
                self._frame(OP_BINARY, body) for body in self.v2.to_wire(payload)
            )
        return self._frame(OP_BINARY, payload)

    def close_frame(self, code=1000):
        return self._frame(OP_CLOSE, struct.pack(">H", code))

    def decode(self, data):
        """Consume frame bytes. Returns (payload bytes, bytes to send back)."""
        self.buf += data
        out = b""
        reply = b""
        while not self.closed:
            if len(self.buf) < 2:
                break
            b0, b1 = self.buf[0], self.buf[1]
            fin, opcode, rsv = b0 & 0x80, b0 & 0x0F, b0 & 0x70
            masked, n = b1 & 0x80, b1 & 0x7F
            pos = 2
            if n == 126:
                if len(self.buf) < 4:
                    break
                n = struct.unpack(">H", self.buf[2:4])[0]
                pos = 4
            elif n == 127:
                if len(self.buf) < 10:
                    break
                n = struct.unpack(">Q", self.buf[2:10])[0]
                pos = 10
            if bool(masked) == self.client:
                raise ValueError("WebSocket frame masking is wrong for its direction")
            mask = b""
            if masked:
                if len(self.buf) < pos + 4:
                    break
                mask = self.buf[pos : pos + 4]
                pos += 4
            if len(self.buf) < pos + n:
                break
            payload = self.buf[pos : pos + n]
            self.buf = self.buf[pos + n :]
            if mask:
                payload = apply_mask(mask, payload)
            if rsv and not (
                self.v2
                and opcode == OP_BINARY
                and (rsv == RSV1 or (rsv == RSV2 and fin))
            ):
                raise ValueError(f"unexpected WebSocket RSV bits {rsv:#x}")
            if opcode in (OP_BINARY, OP_CONTINUATION):
                if opcode == OP_BINARY:
                    self.message_compressed = rsv == RSV1
                    self.message_independent = rsv == RSV2
                self.fragments += payload
                if fin:
                    if self.v2:
                        out += self.v2.from_wire(
                            self.fragments,
                            self.message_compressed,
                            self.message_independent,
                        )
                        if self.message_independent:
                            self.independent_frames_recv += 1
                    else:
                        out += self.fragments
                    self.fragments = b""
            elif opcode == OP_PING:
                reply += self._frame(OP_PONG, payload)
            elif opcode == OP_CLOSE:
                reply += self._frame(OP_CLOSE, payload[:2])
                self.closed = True
            elif opcode == OP_PONG:
                pass
            else:
                raise ValueError(f"unexpected WebSocket opcode {opcode}")
        return out, reply


# Codec-only tests; they do not start nodes or claim consensus validity.


class TestIndependentFrames(unittest.TestCase):
    def setUp(self):
        try:
            import zstandard
        except ImportError:
            self.skipTest("zstandard needed for independent-frame tests")
        self.zstd = zstandard
        self.dictionary = zstandard.ZstdCompressionDict(
            p2p_zstd_dict(), dict_type=zstandard.DICT_TYPE_RAWCONTENT
        )
        self.body = bytes([P2P_V2_IDS[b"tx"]]) + bytes(range(256)) * 400

    def independent(self, body=None, content_size=True):
        body = self.body if body is None else body
        frame = self.zstd.ZstdCompressor(
            dict_data=self.dictionary, write_content_size=content_size
        ).compress(body)
        return b"\x01" + struct.pack("<I", P2P_ZSTD_DICT_VERSION) + frame

    def test_stream_independent_stream(self):
        converter = P2PV2Converter(b"test")
        compressor = self.zstd.ZstdCompressor(dict_data=self.dictionary).compressobj()

        def streamed(body):
            return compressor.compress(body) + compressor.flush(
                self.zstd.COMPRESSOBJ_FLUSH_BLOCK
            )

        first = converter.from_wire(streamed(self.body), True)
        independent = converter.from_wire(self.independent(), False, True)
        last = converter.from_wire(streamed(self.body), True)
        self.assertEqual(first, independent)
        self.assertEqual(first, last)
        self.assertEqual(
            first, P2PV2Converter(b"test").from_wire(self.independent(), False, True)
        )

    def test_wire_independent_frame(self):
        server = WebSocketLayer(False, v2_magic=b"test")
        client = WebSocketLayer(True, v2_magic=b"test")
        wire = server._frame(OP_BINARY, self.independent(), rsv=RSV2)
        decoded, reply = client.decode(wire)
        self.assertFalse(reply)
        self.assertEqual(decoded, P2PV2Converter(b"test").from_wire(self.body, False))

    def test_invalid_envelope_and_limits(self):
        converter = P2PV2Converter(b"test")
        original = self.independent()
        malformed = [
            b"",
            original[:4],
            bytes([2]) + original[1:],
            original[:1] + struct.pack("<I", P2P_ZSTD_DICT_VERSION + 1) + original[5:],
            original[:-1],
            original + b"trailing",
            self.independent(content_size=False),
        ]
        for frame in malformed:
            with self.subTest(size=len(frame)):
                with self.assertRaises(Exception):
                    converter.from_wire(frame, False, True)
        with self.assertRaises(ValueError):
            P2PV2Converter(b"test", max_message_size=100).from_wire(
                original, False, True
            )

        window_frame = self.zstd.ZstdCompressor(level=3).compress(
            b"x" * (2 * 1024 * 1024)
        )
        self.assertGreater(
            self.zstd.get_frame_parameters(window_frame).window_size, 1024 * 1024
        )
        with self.assertRaises(ValueError):
            converter.from_wire(
                b"\x01" + struct.pack("<I", P2P_ZSTD_DICT_VERSION) + window_frame,
                False,
                True,
            )

    def test_invalid_reserved_combinations(self):
        for first in [0xE2, 0x92, 0x22, 0xA0, 0xA9]:
            with self.subTest(first=first):
                with self.assertRaises(ValueError):
                    WebSocketLayer(True, v2_magic=b"test").decode(bytes([first, 1, 0]))
