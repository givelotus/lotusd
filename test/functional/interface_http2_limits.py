#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the HTTP/2 denial-of-service limits against a running node.

Rapid Reset, CONTINUATION floods, oversized header lists, the stream limit,
slow requests and idle connections are each cut off, and the node keeps
serving other clients afterwards.
"""

import json
import socket
import ssl
import struct
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, rpc_port

TIMEOUT = 3  # -rpcservertimeout


def frame(ftype, flags, stream, payload=b""):
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes([ftype, flags])
        + struct.pack(">I", stream & 0x7FFFFFFF)
        + payload
    )


def read_frames(sock, deadline):
    """Read frames until EOF or the deadline; returns [(type, flags, stream, payload)]"""
    buf = b""
    frames = []
    while time.time() < deadline:
        sock.settimeout(max(0.05, deadline - time.time()))
        try:
            data = sock.recv(65536)
        except (socket.timeout, ssl.SSLWantReadError):
            continue
        except (ConnectionError, ssl.SSLError, OSError):
            break
        if not data:
            break
        buf += data
        while len(buf) >= 9:
            length = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + length:
                break
            frames.append(
                (
                    buf[3],
                    buf[4],
                    int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF,
                    buf[9 : 9 + length],
                )
            )
            buf = buf[9 + length :]
    return frames


def goaway_code(frames):
    for ftype, _, _, payload in frames:
        if ftype == 7:
            return int.from_bytes(payload[4:8], "big")
    return None


class HTTP2LimitsTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    topology = "none"
    requires = {"http2"}
    extra_args = [
        [
            f"-rpcservertimeout={TIMEOUT}",
            "-http2resetburst=20",
            "-http2resetrate=1",
            "-http2maxstreams=5",
            "-http2maxheaderlistsize=2048",
            "-http2maxcontinuations=4",
            "-rest",
        ]
    ]

    def raw_tls(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        s = ctx.wrap_socket(
            socket.create_connection(("127.0.0.1", rpc_port(0)), timeout=30),
            server_hostname="localhost",
        )
        assert_equal(s.selected_alpn_protocol(), "h2")
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
        return s

    def still_serves(self):
        from test_framework.http2 import H2Client, basic_auth

        c = H2Client("127.0.0.1", rpc_port(0))
        body = json.dumps({"method": "getblockcount", "id": 1}).encode()
        r = c.request(
            "POST", "/", [("authorization", basic_auth(self.nodes[0].url))], body
        )
        c.close()
        assert_equal(r.status, 200)

    def run_test(self):
        import h2.errors
        from test_framework.http2 import H2Client

        self.log.info("Out-of-range limits are refused at startup")
        self.stop_node(0)
        for arg in (
            "-http2maxframesize=100",
            "-http2maxstreams=0",
            "-http2streamwindow=1",
            "-http2maxheaderlistsize=10",
        ):
            self.nodes[0].assert_start_raises_init_error([arg])
        self.start_node(0)

        self.log.info("Limits are advertised in SETTINGS")
        c = H2Client("127.0.0.1", rpc_port(0))
        while not c.remote_settings_received:
            assert c.pump()
        settings = c.conn.remote_settings
        assert_equal(settings.max_concurrent_streams, 5)
        assert_equal(settings.max_header_list_size, 2048)
        assert_equal(settings.max_frame_size, 16384)
        assert_equal(settings.initial_window_size, 1 << 20)

        self.log.info("An oversized header list gets 431, the connection lives")
        r = c.request("GET", "/rest/chaininfo.json", [("x-big", "a" * 3000)])
        assert_equal(r.status, 431)
        assert_equal(c.request("GET", "/rest/chaininfo.json").status, 200)
        c.close()

        self.log.info("Rapid Reset: opening and resetting streams is cut off")
        c = H2Client("127.0.0.1", rpc_port(0))
        sent = 0
        for _ in range(500):
            if c.terminated is not None:
                break
            try:
                sid = c.conn.get_next_available_stream_id()
                c.conn.send_headers(
                    sid,
                    [
                        (":method", "GET"),
                        (":scheme", "https"),
                        (":authority", "localhost"),
                        (":path", "/rest/chaininfo.json"),
                    ],
                    end_stream=True,
                )
                c.conn.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
                c.flush()
                sent += 1
            except Exception:
                break
            c.pump(timeout=0.01)
        deadline = time.time() + 10
        while c.terminated is None and time.time() < deadline:
            if not c.pump(timeout=1):
                break
        self.log.info(f"  connection ended after {sent} resets: {c.terminated}")
        assert c.terminated is not None
        assert sent < 100, sent
        c.close()
        self.still_serves()

        self.log.info("CONTINUATION flood: the connection is closed")
        s = self.raw_tls()
        # :method GET, :scheme https, :path /, :authority n
        block = b"\x82\x87\x84\x01\x01n"
        data = frame(1, 0, 1, block)  # HEADERS without END_HEADERS
        for i in range(50):
            data += frame(9, 0, 1, b"\x40\x01a\x01b")
        try:
            s.sendall(data)
        except OSError:
            pass
        frames = read_frames(s, time.time() + 10)
        s.close()
        assert goaway_code(frames) is not None, frames
        assert not any(f[0] == 1 for f in frames)  # no response HEADERS
        self.still_serves()

        self.log.info("Exceeding the acknowledged stream limit closes the connection")
        s = self.raw_tls()
        s.sendall(frame(4, 1, 0))  # ACK the server's SETTINGS
        time.sleep(0.2)
        data = b""
        for sid in range(1, 20, 2):
            # Requests without END_STREAM stay open
            data += frame(1, 4, sid, b"\x83\x87\x84\x01\x01n")
        s.sendall(data)
        frames = read_frames(s, time.time() + 10)
        s.close()
        assert_equal(goaway_code(frames), 1)  # PROTOCOL_ERROR
        self.still_serves()

        self.log.info("A request still arriving after -rpcservertimeout is reset")
        c = H2Client("127.0.0.1", rpc_port(0))
        sid = c.conn.get_next_available_stream_id()
        c.conn.send_headers(
            sid,
            [
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/"),
            ],
            end_stream=False,
        )
        c.flush()
        start = time.time()
        while time.time() - start < 4 * TIMEOUT:
            if sid in c.responses and c.responses[sid].reset is not None:
                break
            c.pump(timeout=0.5)
        assert_equal(c.responses[sid].reset, h2.errors.ErrorCodes.CANCEL)
        assert_greater_than(time.time() - start, TIMEOUT - 0.5)

        self.log.info("An idle connection gets GOAWAY, then is closed")
        start = time.time()
        while c.terminated is None and time.time() - start < 4 * TIMEOUT:
            if not c.pump(timeout=0.5):
                break
        assert_equal(c.terminated, h2.errors.ErrorCodes.NO_ERROR)
        c.close()
        self.still_serves()
        # The framework's own keep-alive RPC connection (HTTP/1.1) idled past
        # -rpcservertimeout meanwhile: give it a new one to stop the node.
        self.nodes[0].rpc._set_conn()


if __name__ == "__main__":
    HTTP2LimitsTest().main()
