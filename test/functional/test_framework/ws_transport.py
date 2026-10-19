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
import struct

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
P2P_WS_PATH = "/p2p/ws"

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

    def __init__(self, client, host="127.0.0.1", port=0, path=P2P_WS_PATH):
        self.client = client
        self.host = host
        self.port = port
        self.path = path
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
            f"Sec-WebSocket-Key: {self.key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
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
            reply = b""
        else:
            method = lines[0].split(" ")[0]
            if method != "GET" or headers.get("upgrade", "").lower() != "websocket":
                raise ValueError(f"not a WebSocket upgrade: {lines[0]}")
            reply = (
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_key(headers['sec-websocket-key'])}"
                "\r\n\r\n"
            ).encode()
        self.open = True
        return True, reply

    # Framing

    def _frame(self, opcode, payload):
        header = bytes([0x80 | opcode])
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
        """A binary message carrying `payload`."""
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
            fin, opcode = b0 & 0x80, b0 & 0x0F
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
            if opcode in (OP_BINARY, OP_CONTINUATION):
                self.fragments += payload
                if fin:
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
