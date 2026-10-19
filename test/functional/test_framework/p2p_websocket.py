#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A minimal synchronous P2P peer speaking over WebSocket (/p2p/ws).

It implements the p2p-zstd-v1 / p2p-zstd sub-protocols independently of the
node (with python-zstandard), so tests exercise interoperability rather than
the node talking to itself.
"""

import os
import re
import ssl
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
    ):
        import websocket
        import zstandard

        sslopt = {"cert_reqs": ssl.CERT_NONE} if url.startswith("wss") else None
        self.ws = websocket.create_connection(
            url,
            subprotocols=subprotocols,
            sslopt=sslopt,
            timeout=timeout,
            header=header,
        )
        self.subprotocol = self.ws.getsubprotocol()
        self.magic = NET_MAGIC_BYTES[net]
        self.recvbuf = b""
        self.wire_bytes_sent = 0
        self.payload_bytes_sent = 0
        self.compressor = self.decompressor = None
        if self.subprotocol in ("p2p-zstd-v1", "p2p-zstd"):
            dict_data = None
            if self.subprotocol == "p2p-zstd-v1":
                dict_data = zstandard.ZstdCompressionDict(
                    load_p2p_zstd_dict(srcdir),
                    dict_type=zstandard.DICT_TYPE_RAWCONTENT,
                )
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
            data = self.ws.recv()
            if isinstance(data, str) or not data:
                # websocket-client returns a Close frame as an empty string.
                raise ConnectionError("WebSocket closed by the node")
            if self.decompressor:
                data = self.decompressor.decompress(data)
            self.recvbuf += data

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
