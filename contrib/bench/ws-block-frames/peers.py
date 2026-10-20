# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Load client: many P2P peers that each download one block.

Peers connect over WebSocket (/p2p/ws on the RPC port, with a chosen
Sec-WebSocket-Protocol offer) or raw TCP, complete the version handshake,
wait for a common start signal, send `getdata` for one block and stop when
the whole `block` message has arrived and matches the expected SHA256.
WebSocket peers decode what they receive exactly as a real peer would
(zstd stream with the P2P dictionary, and independent RSV2 frames on zstd
connections), so every side does the same work.

Peers run in asyncio event loops inside several worker processes (see
serve_ab.py); this module has no dependency on the node's source tree
beyond the dictionary header it is given.
"""

import asyncio
import base64
import hashlib
import os
import re
import resource
import struct
import time

MAGIC_REGTEST = bytes.fromhex("dab5bffa")
MSG_BLOCK = 2
PROTOCOL_VERSION = 70016


def load_dictionary(header_path):
    """P2P_ZSTD_DICT_V1 from src/net_zstd_dict_data.h"""
    with open(header_path, encoding="utf8") as f:
        text = f.read()
    body = text[text.index("P2P_ZSTD_DICT_V1[") :]
    body = body[body.index("{") + 1 : body.index("};")]
    return bytes(int(b, 16) for b in re.findall(r"0x([0-9a-f]{2})", body))


def dsha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def p2p_message(command, payload):
    return (
        MAGIC_REGTEST
        + command.encode().ljust(12, b"\0")
        + struct.pack("<I", len(payload))
        + dsha256(payload)[:4]
        + payload
    )


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def version_payload(nonce):
    addr = struct.pack("<Q", 0) + b"\0" * 10 + b"\xff\xff" + b"\x7f\0\0\x01" + b"\0\0"
    user_agent = b"/ws-block-frames-bench/"
    return (
        struct.pack("<iQq", PROTOCOL_VERSION, 0, int(time.time()))
        + addr
        + addr
        + struct.pack("<Q", nonce)
        + compact_size(len(user_agent))
        + user_agent
        + struct.pack("<i", 0)
        + b"\x00"  # relay = false: no transaction announcements
        + struct.pack("<Q", 0)  # extra entropy (eCash)
    )


def getdata_payload(block_hash_hex):
    return (
        compact_size(1)
        + struct.pack("<I", MSG_BLOCK)
        + bytes.fromhex(block_hash_hex)[::-1]
    )


def decode_independent(body, dictionary, max_size=64 << 20):
    """An independent frame: [1][dictionary version LE32 = 1][zstd frame]"""
    import zstandard

    if len(body) < 11 or body[0] != 1 or struct.unpack_from("<I", body, 1)[0] != 1:
        raise ValueError("unsupported independent frame")
    frame = body[5:]
    params = zstandard.get_frame_parameters(frame)
    if params.content_size > max_size or params.window_size > 1 << 20:
        raise ValueError("independent frame resource bound exceeded")
    out = zstandard.ZstdDecompressor(dict_data=dictionary).decompressobj()
    data = out.decompress(frame)
    if not out.eof or out.unused_data or len(data) != params.content_size:
        raise ValueError("malformed independent frame")
    return data


class Codec:
    """The P2P byte stream over one transport (raw TCP or WebSocket)."""

    def __init__(self, subprotocol, dictionary):
        self.subprotocol = subprotocol
        self.encoder = self.decoder = None
        self.dictionary = None
        self.frames = subprotocol in ("p2p-zstd", "p2p-zstd-v1")
        if self.frames:
            import zstandard

            # Independent frames always use the dictionary, the stream only
            # with p2p-zstd-v1.
            self.dictionary = zstandard.ZstdCompressionDict(
                dictionary, dict_type=zstandard.DICT_TYPE_RAWCONTENT
            )
            stream_dict = self.dictionary if subprotocol == "p2p-zstd-v1" else None
            self.encoder = zstandard.ZstdCompressor(
                level=1,
                dict_data=stream_dict,
                write_checksum=False,
                write_content_size=False,
            ).compressobj()
            self.decoder = zstandard.ZstdDecompressor(
                dict_data=stream_dict
            ).decompressobj()
            self.flush = zstandard.COMPRESSOBJ_FLUSH_BLOCK

    def encode(self, raw):
        if self.encoder is None:
            return raw
        return self.encoder.compress(raw) + self.encoder.flush(self.flush)

    def decode(self, payload, rsv):
        if rsv == 0x20 and self.frames:
            return decode_independent(payload, self.dictionary)
        if rsv:
            raise ValueError(f"unexpected RSV bits {rsv:#x}")
        return self.decoder.decompress(payload) if self.decoder else payload


class Peer:
    def __init__(self, host, port, transport, offer, dictionary):
        self.host, self.port = host, port
        self.transport = transport
        self.offer = offer
        self.dictionary = dictionary
        self.buf = bytearray()
        self.wire_recv = 0

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, limit=1 << 20
        )
        self.codec = Codec(None, self.dictionary)
        if self.transport == "ws":
            key = base64.b64encode(os.urandom(16)).decode()
            request = (
                "GET /p2p/ws HTTP/1.1\r\n"
                f"Host: {self.host}:{self.port}\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            )
            if self.offer:
                request += f"Sec-WebSocket-Protocol: {self.offer}\r\n"
            self.writer.write((request + "\r\n").encode())
            head = await self.reader.readuntil(b"\r\n\r\n")
            lines = head.decode().split("\r\n")
            if not lines[0].startswith("HTTP/1.1 101"):
                raise RuntimeError(f"upgrade refused: {lines[0]}")
            selected = ""
            for line in lines[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == "sec-websocket-protocol":
                    selected = value.strip()
            self.codec = self.make_codec(selected)
        self.send(
            p2p_message(
                "version", version_payload(int.from_bytes(os.urandom(8), "little"))
            )
        )
        await self.wait_for(b"verack")
        self.send(p2p_message("verack", b""))
        return self.codec.subprotocol

    def make_codec(self, selected):
        return Codec(selected or None, self.dictionary)

    def send(self, raw):
        if self.transport == "tcp":
            self.writer.write(raw)
            return
        payload = self.codec.encode(raw)
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            head = bytes([0x82, 0x80 | n])
        elif n < 65536:
            head = bytes([0x82, 0xFE]) + struct.pack(">H", n)
        else:
            head = bytes([0x82, 0xFF]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        self.writer.write(head + mask + masked)

    async def fill(self):
        """Append the next chunk of P2P bytes to self.buf"""
        if self.transport == "tcp":
            data = await self.reader.read(1 << 20)
            if not data:
                raise ConnectionError("closed")
            self.wire_recv += len(data)
            self.buf += data
            return
        while True:
            b0, b1 = await self.reader.readexactly(2)
            n = b1 & 0x7F
            extra = 0
            if n == 126:
                n = struct.unpack(">H", await self.reader.readexactly(2))[0]
                extra = 2
            elif n == 127:
                n = struct.unpack(">Q", await self.reader.readexactly(8))[0]
                extra = 8
            payload = await self.reader.readexactly(n)
            self.wire_recv += 2 + extra + n
            opcode = b0 & 0x0F
            if opcode == 0x8:
                raise ConnectionError("closed by the node")
            if opcode in (0x9, 0xA):
                continue  # The node does not ping at the WebSocket layer.
            if not b0 & 0x80 or opcode != 0x2:
                raise ValueError(f"unexpected frame {b0:#x}")
            self.buf += self.codec.decode(payload, b0 & 0x70)
            return

    async def next_message(self):
        while True:
            if len(self.buf) >= 24:
                length = struct.unpack_from("<I", self.buf, 16)[0]
                if len(self.buf) >= 24 + length:
                    command = bytes(self.buf[4:16]).rstrip(b"\0")
                    payload = bytes(self.buf[24 : 24 + length])
                    del self.buf[: 24 + length]
                    return command, payload
            await self.fill()

    async def wait_for(self, command):
        while True:
            got, payload = await self.next_message()
            if got == command:
                return payload


async def run_worker(conf, peers_here, ready, go, results):
    """Connect peers_here peers, signal ready, wait for go, download."""
    dictionary = load_dictionary(conf["dictionary"])
    make_peer = conf.get("make_peer", Peer)
    peers = [
        make_peer(
            conf["host"], conf["port"], conf["transport"], conf["offer"], dictionary
        )
        for _ in range(peers_here)
    ]
    selected = await asyncio.gather(*(p.connect() for p in peers))
    ready.put([s or "none" for s in selected])
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, go.wait)

    async def download(peer):
        start = time.monotonic()
        peer.send(p2p_message("getdata", getdata_payload(conf["block_hash"])))
        payload = await peer.wait_for(b"block")
        done = time.monotonic()
        return {
            "start": start,
            "done": done,
            "ok": hashlib.sha256(payload).hexdigest() == conf["block_sha256"],
            "wire_recv": peer.wire_recv,
        }

    rows = await asyncio.gather(*(download(p) for p in peers))
    usage = resource.getrusage(resource.RUSAGE_SELF)
    results.put({"peers": rows, "client_cpu": usage.ru_utime + usage.ru_stime})
    for p in peers:
        p.writer.close()


def worker_main(conf, peers_here, ready, go, results):
    try:
        asyncio.run(run_worker(conf, peers_here, ready, go, results))
    except BaseException as e:  # Report, so the coordinator never hangs.
        ready.put({"error": repr(e)})
        results.put({"error": repr(e)})
