#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Characterize the HTTP client of the RPC command line tool.

A raw-socket HTTP server in this process records the exact request bytes the
CLI sends and answers with scripted responses: chunked and close-delimited
bodies, error statuses, slow and silent servers, and refused connections. The
expected values were recorded with the original libevent client, so any
transport replacement must reproduce them.
"""

import base64
import os
import re
import socket
import subprocess
import threading
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

AUTH = "Basic " + base64.b64encode(b"u:p").decode()
OK_BODY = b'{"result":5,"error":null,"id":1}'


def read_request(conn):
    """Read one HTTP request (headers and Content-Length body)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def response(status, reason, body, headers=None):
    lines = [f"HTTP/1.1 {status} {reason}"]
    if headers is None:
        headers = [
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
        ]
    lines += headers
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


class ScriptedServer:
    """Accept one connection, record the request, run a scripted reply."""

    def __init__(self, handler):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.request = None
        self.closing = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.sock.settimeout(60)
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            if not self.closing:
                self.handler(self, conn)

    def close(self):
        # The client has exited; wake an accept() that never got a connection.
        self.closing = True
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=5).close()
        except OSError:
            pass
        self.thread.join(timeout=60)
        self.sock.close()


def reply_with(data):
    def handler(server, conn):
        server.request = read_request(conn)
        conn.sendall(data)
        conn.shutdown(socket.SHUT_WR)
        # Let the client finish reading before the socket is closed.
        conn.settimeout(10)
        try:
            while conn.recv(65536):
                pass
        except OSError:
            pass

    return handler


class CliHttpClientTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()

    def setup_network(self):
        # The CLI talks to scripted servers only; no node is needed.
        pass

    def cli_datadir(self):
        # An empty data directory: no configuration file, no cookie.
        path = os.path.join(self.options.tmpdir, "cli")
        os.makedirs(path, exist_ok=True)
        return path

    def run_cli(self, port, *args, credentials=True, connect="127.0.0.1"):
        cmd = [
            self.options.bitcoincli,
            f"-datadir={self.cli_datadir()}",
            "-regtest",
            f"-rpcconnect={connect}",
            f"-rpcport={port}",
        ]
        if credentials:
            cmd += ["-rpcuser=u", "-rpcpassword=p"]
        cmd += list(args)
        start = time.time()
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
        return (
            proc.returncode,
            proc.stdout.decode(errors="replace"),
            proc.stderr.decode(errors="replace"),
            time.time() - start,
        )

    def serve(self, handler, *args, **kwargs):
        server = ScriptedServer(handler)
        result = self.run_cli(server.port, *args, **kwargs)
        server.close()
        return server, result

    def assert_connect_failed(self, rc, err, port, detail, host="127.0.0.1"):
        assert_equal(rc, 1)
        # The daemon name in the hint depends on the build's branding.
        pattern = (
            re.escape(f"error: Could not connect to the server {host}:{port}{detail}")
            + r"\n\nMake sure the \S+ server is running and that you are"
            r" connecting to the correct RPC port\.\n"
        )
        assert re.fullmatch(pattern, err), err

    def run_test(self):
        self.log.info("Default request: request line, headers and body")
        server, (rc, out, err, _) = self.serve(
            reply_with(response(200, "OK", OK_BODY)), "getblockcount"
        )
        assert_equal((rc, out, err), (0, "5\n", ""))
        head, _, body = server.request.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        assert_equal(lines[0], "POST / HTTP/1.1")
        assert_equal(
            lines[1:],
            [
                "Host: 127.0.0.1",
                "Connection: close",
                "Content-Type: application/json",
                f"Authorization: {AUTH}",
                f"Content-Length: {len(body)}",
            ],
        )
        assert_equal(body, b'{"method":"getblockcount","params":[],"id":1}\n')

        self.log.info("Wallet endpoint is percent-encoded")
        server, (rc, out, err, _) = self.serve(
            reply_with(response(200, "OK", OK_BODY)),
            "-rpcwallet=a b/é%~-._",
            "getbalance",
        )
        assert_equal(rc, 0)
        assert_equal(
            server.request.split(b"\r\n")[0],
            b"POST /wallet/a%20b%2F%C3%A9%25~-._ HTTP/1.1",
        )

        self.log.info("Chunked response body")
        chunked = b"7\r\n" + OK_BODY[:7] + b"\r\n"
        rest = OK_BODY[7:]
        chunked += f"{len(rest):x}".encode() + b"\r\n" + rest + b"\r\n0\r\n\r\n"
        _, (rc, out, err, _) = self.serve(
            reply_with(
                response(
                    200,
                    "OK",
                    chunked,
                    ["Content-Type: application/json", "Transfer-Encoding: chunked"],
                )
            ),
            "getblockcount",
        )
        assert_equal((rc, out, err), (0, "5\n", ""))

        self.log.info("Body delimited by connection close")
        _, (rc, out, err, _) = self.serve(
            reply_with(
                response(
                    200,
                    "OK",
                    OK_BODY,
                    ["Content-Type: application/json", "Connection: close"],
                )
            ),
            "getblockcount",
        )
        assert_equal((rc, out, err), (0, "5\n", ""))

        self.log.info("401 with and without credentials")
        _, (rc, out, err, _) = self.serve(
            reply_with(response(401, "Unauthorized", b"")), "getblockcount"
        )
        assert_equal(
            (rc, err),
            (1, "error: Authorization failed: Incorrect rpcuser or rpcpassword\n"),
        )
        _, (rc, out, err, _) = self.serve(
            reply_with(response(401, "Unauthorized", b"")),
            "getblockcount",
            credentials=False,
        )
        assert_equal(rc, 1)
        assert err.startswith(
            "error: Could not locate RPC credentials. No authentication cookie"
            " could be found, and RPC password is not set."
        ), err

        self.log.info("503 and 403 statuses")
        _, (rc, out, err, _) = self.serve(
            reply_with(response(503, "Service Unavailable", b"busy")),
            "getblockcount",
        )
        assert_equal((rc, err), (1, "error: Server response: busy\n"))
        _, (rc, out, err, _) = self.serve(
            reply_with(response(403, "Forbidden", b"")), "getblockcount"
        )
        assert_equal((rc, err), (1, "error: server returned HTTP error 403\n"))

        self.log.info("404 and 500 JSON bodies are passed through")
        for status, reason in ((404, "Not Found"), (500, "Internal Server Error")):
            body = b'{"result":null,"error":{"code":-32601,"message":"Method not found"},"id":1}'
            _, (rc, out, err, _) = self.serve(
                reply_with(response(status, reason, body)), "nosuchmethod"
            )
            assert_equal(
                (rc, out, err),
                # The exit status is the error code modulo 256.
                (
                    32601 % 256,
                    "",
                    "error code: -32601\nerror message:\nMethod not found\n",
                ),
            )

        self.log.info("Empty and unparsable replies")
        _, (rc, out, err, _) = self.serve(
            reply_with(response(200, "OK", b"")), "getblockcount"
        )
        assert_equal((rc, err), (1, "error: no response from server\n"))
        _, (rc, out, err, _) = self.serve(
            reply_with(response(200, "OK", b"not json")), "getblockcount"
        )
        assert_equal((rc, err), (1, "error: couldn't parse reply from server\n"))

        self.log.info("A 50 MB body is accepted")
        big = b"a" * (50 * 1000 * 1000)
        _, (rc, out, err, _) = self.serve(
            reply_with(
                response(200, "OK", b'{"result":"' + big + b'","error":null,"id":1}')
            ),
            "getblockcount",
        )
        assert_equal((rc, len(out), err), (0, len(big) + 1, ""))

        self.log.info("A silent server hits the client timeout")

        def silent(server, conn):
            server.request = read_request(conn)
            time.sleep(4)

        server, (rc, out, err, elapsed) = self.serve(
            silent, "-rpcclienttimeout=1", "getblockcount"
        )
        self.assert_connect_failed(
            rc, err, server.port, ' (error code 0 - "timeout reached")'
        )
        assert elapsed < 4, elapsed

        self.log.info("The timeout measures inactivity, not the whole request")

        def trickle(server, conn):
            server.request = read_request(conn)
            data = response(200, "OK", OK_BODY)
            for i in range(5):
                conn.sendall(data[i : i + 1])
                time.sleep(0.6)
            conn.sendall(data[5:])
            conn.shutdown(socket.SHUT_WR)
            time.sleep(1)

        _, (rc, out, err, _) = self.serve(
            trickle, "-rpcclienttimeout=1", "getblockcount"
        )
        assert_equal((rc, out, err), (0, "5\n", ""))

        self.log.info("A refused connection")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        rc, out, err, _ = self.run_cli(port, "getblockcount")
        # libevent reports a refused connection without an error code.
        self.assert_connect_failed(rc, err, port, "")

        self.log.info("The server closes the connection after accepting it")

        def close_now(server, conn):
            server.request = read_request(conn)

        server, (rc, out, err, _) = self.serve(close_now, "getblockcount")
        self.assert_connect_failed(
            rc, err, server.port, ' (error code 1 - "EOF reached")'
        )

        self.log.info("-rpcconnect with a host name uses only the first address")
        # The server listens on IPv4 only. libevent connects to the first
        # resolved address of "localhost" (::1 on this host) and gives up.
        server, (rc, out, err, _) = self.serve(
            reply_with(response(200, "OK", OK_BODY)),
            "getblockcount",
            connect="localhost",
        )
        if server.request is None:
            assert_equal(out, "")
            self.assert_connect_failed(rc, err, server.port, "", host="localhost")
        else:
            assert_equal((rc, out, err), (0, "5\n", ""))
            assert_equal(server.request.split(b"\r\n")[1], b"Host: localhost")


if __name__ == "__main__":
    CliHttpClientTest().main()
