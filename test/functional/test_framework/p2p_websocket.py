#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A minimal synchronous P2P peer speaking over WebSocket (/p2p/ws).

It speaks the Lotus v2 framing (p2p-v2, see src/net_websocket.h) over a plain
socket (ws://) or TLS (wss://), with test_framework.ws_transport doing the
handshake, framing and conversion (and python-zstandard the decompression),
independently of the node and without P2PConnection's event loop, so tests
can drive a peer step by step.
"""

import os
import socket
import ssl
import struct
import unittest
from io import BytesIO
from urllib.parse import urlparse

from .messages import msg_verack, msg_version, sha256
from .p2p import MESSAGEMAP, NET_MAGIC_BYTES
from .ws_transport import P2P_V2_PROTOCOL, WebSocketLayer, p2p_zstd_dict


def load_p2p_zstd_dict(_srcdir=None):
    return p2p_zstd_dict()


class WebSocketRefused(ConnectionError):
    """The node answered the upgrade with an HTTP error."""

    def __init__(self, status_line):
        super().__init__(status_line)
        self.status_line = status_line


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
        subprotocols=(P2P_V2_PROTOCOL,),
        srcdir=None,
        net="regtest",
        timeout=30,
        header=None,
        ws=None,
    ):
        del srcdir  # (the dictionary is found next to the framework)
        parsed = urlparse(url)
        tls = parsed.scheme == "wss"
        port = parsed.port or (443 if tls else 80)
        self.magic = NET_MAGIC_BYTES[net]
        if ws is None:
            sock = socket.create_connection((parsed.hostname, port), timeout=timeout)
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=parsed.hostname)
        else:
            sock = ws.as_byte_stream()
        self.sock = sock
        v2 = (subprotocols is not None and P2P_V2_PROTOCOL in subprotocols) or (ws is not None and ws.getsubprotocol() == P2P_V2_PROTOCOL)
        self.layer = WebSocketLayer(
            client=True,
            host=parsed.hostname,
            port=port,
            path=parsed.path or "/p2p/ws",
            v2_magic=self.magic if v2 else None,
        )
        if ws is None:
            request = self.layer.request()
            if subprotocols and (not v2 or len(subprotocols) > 1):
                # Offer the protocols as given (the node picks p2p-v2 or refuses).
                head = request.decode().split("\r\n")
                head = [
                    h for h in head if h and not h.startswith("Sec-WebSocket-Protocol")
                ]
                head.append("Sec-WebSocket-Protocol: " + ", ".join(subprotocols))
                request = ("\r\n".join(head) + "\r\n\r\n").encode()
            if header:
                if isinstance(header, dict):
                    header = [f"{name}: {value}" for name, value in header.items()]
                request = request[:-2] + "\r\n".join(header).encode() + b"\r\n\r\n"
            self.sock.sendall(request)
            reply = b""
            while b"\r\n\r\n" not in reply:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise WebSocketRefused("connection closed during the upgrade")
                reply += chunk
            status = reply.split(b"\r\n", 1)[0].decode()
            if status.split()[1] != "101":
                self.sock.close()
                raise WebSocketRefused(status)
            done, _ = self.layer.feed_handshake(reply)
            assert done
        else:
            if ws.status != 200 or (v2 and ws.getsubprotocol() != P2P_V2_PROTOCOL):
                raise WebSocketRefused(f"HTTP/2 {ws.status}")
            self.layer.open = True
        self.subprotocol = P2P_V2_PROTOCOL if v2 else None
        self.payload_bytes_sent = 0
        # Bytes that arrived with the upgrade response
        leftover, self.layer.buf = self.layer.buf, b""
        self.recvbuf = self._decode(leftover)

    def _decode(self, data):
        payload, reply = self.layer.decode(data)
        if reply:
            self.sock.sendall(reply)
        return payload

    def build_message(self, message):
        data = message.serialize()
        msgtype = message.msgtype
        return (
            self.magic
            + msgtype
            + b"\x00" * (12 - len(msgtype))
            + struct.pack("<I", len(data))
            + sha256(sha256(data))[:4]
            + data
        )

    def send_raw(self, raw):
        self.sock.sendall(self.layer.encode(raw))
        self.payload_bytes_sent += len(raw)

    def send_message(self, message):
        self.send_raw(self.build_message(message))

    def recv_raw_message(self):
        """Return a complete native message as the framework's header+body."""
        while True:
            if len(self.recvbuf) >= 24:
                msgtype = self.recvbuf[4:16].rstrip(b"\x00")
                length = struct.unpack("<I", self.recvbuf[16:20])[0]
                if len(self.recvbuf) >= 24 + length:
                    raw = self.recvbuf[: 24 + length]
                    self.recvbuf = self.recvbuf[24 + length :]
                    return msgtype, raw
            if self.layer.closed:
                raise ConnectionError("WebSocket closed by the node")
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("connection closed by the node")
            self.recvbuf += self._decode(data)

    def recv_message(self):
        msgtype, raw = self.recv_raw_message()
        cls = MESSAGEMAP.get(msgtype)
        if cls is None:
            return msgtype, raw[24:]
        obj = cls()
        obj.deserialize(BytesIO(raw[24:]))
        return msgtype, obj

    def wait_for(self, msgtype):
        while True:
            t, msg = self.recv_message()
            if t == msgtype:
                return msg

    def handshake(self, version=70016):
        ver = msg_version()
        ver.nVersion = version
        ver.strSubVer = "/p2p_websocket.py/"
        ver.relay = 1
        self.send_message(ver)
        their_version = self.wait_for(b"version")
        self.wait_for(b"verack")
        self.send_message(msg_verack())
        return their_version

    def close(self):
        try:
            self.sock.sendall(self.layer.close_frame())
        except OSError:
            pass
        self.sock.close()


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
