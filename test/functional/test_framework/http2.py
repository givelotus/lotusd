#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A small HTTP/2 client over TLS for the functional tests (needs `h2`).

It speaks HTTP/2 with the `h2` package (hyper-h2), a sans-I/O implementation
independent of the node's nghttp2, over a blocking TLS socket. Besides plain
requests it can run several streams at once, open RFC 8441 WebSockets
(extended CONNECT) and misbehave on purpose (raw frames, stream resets).
"""

import base64
import socket
import ssl
import time

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings


class Response:
    def __init__(self):
        self.headers = {}
        self.body = b""
        self.ended = False
        self.reset = None

    @property
    def status(self):
        return int(self.headers.get(":status", 0))


class H2Client:
    """One HTTP/2 connection to host:port over TLS."""

    def __init__(
        self,
        host,
        port,
        *,
        alpn=("h2", "http/1.1"),
        timeout=30,
        window=1 << 24,
        server_hostname="localhost",
    ):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(list(alpn))
        raw = socket.create_connection((host, port), timeout=timeout)
        self.sock = ctx.wrap_socket(raw, server_hostname=server_hostname)
        self.alpn = self.sock.selected_alpn_protocol()
        self.timeout = timeout
        self.responses = {}
        self.terminated = None
        self.remote_settings_received = False
        if self.alpn != "h2":
            self.conn = None
            return
        config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        self.conn = h2.connection.H2Connection(config=config)
        self.conn.initiate_connection()
        self.conn.update_settings(
            {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: window}
        )
        self.conn.increment_flow_control_window(window - 65535)
        self.flush()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def flush(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def pump(self, timeout=None):
        """Read once (or time out) and process the events."""
        self.sock.settimeout(self.timeout if timeout is None else timeout)
        try:
            data = self.sock.recv(1 << 16)
        except socket.timeout:
            return True
        except (ConnectionError, ssl.SSLError, OSError):
            data = b""
        if not data:
            if self.terminated is None:
                self.terminated = "eof"
            return False
        try:
            events = self.conn.receive_data(data)
        except h2.exceptions.ProtocolError as e:
            self.terminated = f"protocol error: {e}"
            return False
        for ev in events:
            self.handle(ev)
        self.flush()
        return True

    def handle(self, ev):
        if isinstance(ev, h2.events.ResponseReceived) or isinstance(
            ev, h2.events.InformationalResponseReceived
        ):
            r = self.responses.setdefault(ev.stream_id, Response())
            r.headers.update(dict(ev.headers))
        elif isinstance(ev, h2.events.DataReceived):
            r = self.responses.setdefault(ev.stream_id, Response())
            r.body += ev.data
            self.conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
        elif isinstance(ev, h2.events.StreamEnded):
            self.responses.setdefault(ev.stream_id, Response()).ended = True
        elif isinstance(ev, h2.events.StreamReset):
            self.responses.setdefault(ev.stream_id, Response()).reset = ev.error_code
        elif isinstance(ev, h2.events.ConnectionTerminated):
            self.terminated = ev.error_code
        elif isinstance(ev, h2.events.RemoteSettingsChanged):
            self.remote_settings_received = True

    def start(self, method, path, headers=(), body=None, authority="localhost"):
        """Send a request; returns its stream id."""
        sid = self.conn.get_next_available_stream_id()
        hdrs = [
            (":method", method),
            (":scheme", "https"),
            (":authority", authority),
            (":path", path),
        ] + list(headers)
        self.conn.send_headers(sid, hdrs, end_stream=body is None)
        self.flush()
        if body is not None:
            self.send_body(sid, body, end_stream=True)
        return sid

    def send_body(self, sid, body, end_stream):
        view = memoryview(body)
        while True:
            window = self.conn.local_flow_control_window(sid)
            chunk = min(len(view), window, self.conn.max_outbound_frame_size)
            if chunk > 0 or len(view) == 0:
                last = chunk == len(view)
                self.conn.send_data(
                    sid, bytes(view[:chunk]), end_stream=end_stream and last
                )
                self.flush()
                view = view[chunk:]
                if last:
                    return
            else:
                if not self.pump():
                    raise ConnectionError("connection closed while sending")

    def wait(self, sids, deadline=None):
        deadline = deadline or time.time() + self.timeout
        while time.time() < deadline:
            if all(
                s in self.responses
                and (self.responses[s].ended or self.responses[s].reset is not None)
                for s in sids
            ):
                return [self.responses[s] for s in sids]
            if not self.pump(timeout=max(0.05, deadline - time.time())):
                break
        return [self.responses.get(s, Response()) for s in sids]

    def request(self, method, path, headers=(), body=None, authority="localhost"):
        sid = self.start(method, path, headers, body, authority)
        return self.wait([sid])[0]


def basic_auth(url):
    """The Authorization header value for a node's RPC url"""
    import urllib.parse

    u = urllib.parse.urlparse(url)
    token = base64.b64encode(f"{u.username}:{u.password}".encode()).decode()
    return f"Basic {token}"


class H2WebSocket:
    """A WebSocket over an HTTP/2 stream (RFC 8441 extended CONNECT).

    Offers what test_framework.p2p_websocket.P2PWebSocketClient and the
    Chronik tests use from websocket-client: send_binary(), recv(),
    getsubprotocol(), close().
    """

    def __init__(self, client, path, *, subprotocols=None, headers=()):
        import os

        self.client = client
        self.os = os
        # RFC 8441 3: the server must have advertised the protocol first.
        while not client.remote_settings_received:
            if not client.pump():
                raise ConnectionError("no SETTINGS from the server")
        hdrs = [
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "https"),
            (":authority", "localhost"),
            (":path", path),
            ("sec-websocket-version", "13"),
        ]
        if subprotocols:
            hdrs.append(("sec-websocket-protocol", ", ".join(subprotocols)))
        hdrs += list(headers)
        self.sid = client.conn.get_next_available_stream_id()
        client.conn.send_headers(self.sid, hdrs, end_stream=False)
        client.flush()
        while True:
            r = client.responses.get(self.sid)
            if r is not None and (":status" in r.headers or r.reset is not None):
                break
            if not client.pump():
                break
        self.response = client.responses.get(self.sid, Response())
        self.status = self.response.status
        self.buf = b""
        self.message = b""
        self.closed = False

    def as_byte_stream(self):
        """Raw RFC6455 bytes over DATA, for the native P2P frame converter."""
        parent = self

        class Stream:
            def sendall(self, data):
                parent.client.send_body(parent.sid, data, end_stream=False)

            def recv(self, size):
                while True:
                    response = parent.client.responses.get(parent.sid)
                    if response is not None and response.body:
                        data, response.body = response.body[:size], response.body[size:]
                        return data
                    if parent.closed or (
                        response is not None and (response.ended or response.reset)
                    ):
                        return b""
                    if not parent.client.pump():
                        return b""

            def close(self):
                # The native layer already emitted its close frame.
                parent.closed = True

        return Stream()

    def getsubprotocol(self):
        return self.response.headers.get("sec-websocket-protocol")

    def _send_frame(self, opcode, payload):
        mask = self.os.urandom(4)
        head = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            head += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.client.send_body(self.sid, head + mask + masked, end_stream=False)

    def send_binary(self, data):
        self._send_frame(0x2, bytes(data))

    def _frame(self):
        """Parse one frame from the buffer, or None"""
        b = self.buf
        if len(b) < 2:
            return None
        fin, opcode = b[0] & 0x80, b[0] & 0x0F
        assert not b[1] & 0x80, "the server must not mask"
        n, pos = b[1] & 0x7F, 2
        if n == 126:
            if len(b) < 4:
                return None
            n, pos = int.from_bytes(b[2:4], "big"), 4
        elif n == 127:
            if len(b) < 10:
                return None
            n, pos = int.from_bytes(b[2:10], "big"), 10
        if len(b) < pos + n:
            return None
        self.buf = b[pos + n :]
        return fin, opcode, b[pos : pos + n]

    def recv(self):
        """The next binary message; b"" once the server closed."""
        while True:
            frame = self._frame()
            if frame is None:
                r = self.client.responses.get(self.sid)
                if r is not None and r.body:
                    self.buf += r.body
                    r.body = b""
                    continue
                if self.closed or (r is not None and (r.ended or r.reset)):
                    return b""
                if not self.client.pump():
                    return b""
                continue
            fin, opcode, payload = frame
            if opcode == 0x9:  # ping
                self._send_frame(0xA, payload)
            elif opcode == 0x8:  # close
                self.closed = True
                return b""
            elif opcode in (0x0, 0x1, 0x2):
                self.message += payload
                if fin:
                    msg, self.message = self.message, b""
                    return msg

    def close(self):
        if not self.closed:
            try:
                self._send_frame(0x8, (1000).to_bytes(2, "big"))
            except Exception:
                pass
        self.closed = True
