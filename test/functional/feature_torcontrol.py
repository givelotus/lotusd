#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Tor control client against a scripted control port.

The mock speaks the Tor control protocol as the node uses it: PROTOCOLINFO,
NULL/SAFECOOKIE/HASHEDPASSWORD authentication and ADD_ONION. It checks the
onion service the node advertises, the cached private key, reconnection with
exponential backoff, line framing and the line-length limit.
"""

import base64
import hashlib
import hmac
import os
import re
import socket
import threading
import time
from datetime import datetime

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal

SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"


def onion_v3_service_id(seed):
    """A syntactically valid v3 onion service id (56 base32 characters)."""
    pubkey = hashlib.sha256(seed).digest()
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()[:2]
    return base64.b32encode(pubkey + checksum + version).decode().lower()


class ControlConnection:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def readline(self, timeout=60):
        self.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            data = self.sock.recv(65536)
            if not data:
                raise EOFError
            self.buf += data
        line, _, self.buf = self.buf.partition(b"\n")
        return line.rstrip(b"\r").decode()

    def send(self, data):
        self.sock.sendall(data.encode() if isinstance(data, str) else data)


class MockTorControl:
    """Listens on a fixed port and runs ``handler`` for each connection."""

    def __init__(self, handler, port=0):
        self.handler = handler
        self.commands = []
        self.connections = 0
        self.lock = threading.Lock()
        self.active = None
        self.stopped = False
        self.listener = None
        self.port = port
        self.listen()

    def listen(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", self.port))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(5)
        self.thread = threading.Thread(
            target=self._accept_loop, args=(self.listener,), daemon=True
        )
        self.thread.start()

    def _accept_loop(self, listener):
        listener.settimeout(0.1)
        while self.listener is listener:
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            sock.settimeout(None)
            with self.lock:
                self.connections += 1
            conn = ControlConnection(sock)
            self.active = conn
            try:
                self.handler(self, conn)
            except (EOFError, OSError):
                pass
            finally:
                sock.close()

    def record(self, line):
        with self.lock:
            self.commands.append(line)

    def unlisten(self):
        """Stop accepting connections (new attempts are refused)."""
        listener = self.listener
        self.listener = None
        listener.close()

    def drop_active(self):
        if self.active is not None:
            try:
                self.active.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        if self.listener is not None:
            self.unlisten()
        self.drop_active()
        self.thread.join(timeout=10)


def serve_onion(
    methods="NULL",
    cookiefile=None,
    service_id=None,
    add_onion_reply=None,
    bad_server_hash=False,
    line_end="\r\n",
    trickle=False,
):
    """Build a handler that authenticates and creates an onion service."""

    def handler(mock, conn):
        cookie = None
        client_nonce = server_nonce = None

        def send(lines):
            data = "".join(line + line_end for line in lines).encode()
            if trickle:
                for i in range(len(data)):
                    conn.send(data[i : i + 1])
                    time.sleep(0.002)
            else:
                conn.send(data)

        while True:
            line = conn.readline(timeout=None)
            mock.record(line)
            if line == "PROTOCOLINFO 1":
                auth = f"250-AUTH METHODS={methods}"
                if cookiefile is not None:
                    auth += f' COOKIEFILE="{cookiefile}"'
                send(
                    [
                        "250-PROTOCOLINFO 1",
                        auth,
                        '250-VERSION Tor="0.4.8.10"',
                        "250 OK",
                    ]
                )
            elif line.startswith("AUTHCHALLENGE SAFECOOKIE "):
                with open(cookiefile, "rb") as f:
                    cookie = f.read()
                client_nonce = bytes.fromhex(line.split(" ")[2])
                server_nonce = os.urandom(32)
                server_hash = hmac.new(
                    SERVER_KEY, cookie + client_nonce + server_nonce, hashlib.sha256
                ).digest()
                if bad_server_hash:
                    server_hash = bytes(32)
                send(
                    [
                        f"250 AUTHCHALLENGE SERVERHASH={server_hash.hex()}"
                        f" SERVERNONCE={server_nonce.hex()}"
                    ]
                )
            elif line.startswith("AUTHENTICATE"):
                if cookie is not None:
                    expected = hmac.new(
                        CLIENT_KEY,
                        cookie + client_nonce + server_nonce,
                        hashlib.sha256,
                    ).hexdigest()
                    if line != f"AUTHENTICATE {expected}":
                        send(["515 Authentication failed"])
                        continue
                send(["250 OK"])
            elif line.startswith("ADD_ONION "):
                if add_onion_reply is not None:
                    send(add_onion_reply)
                else:
                    send(
                        [
                            f"250-ServiceID={service_id}",
                            "250-PrivateKey=ED25519-V3:k",
                            "250 OK",
                        ]
                    )
            else:
                send(["510 Unrecognized command"])

    return handler


def log_times(log, pattern):
    """Timestamps (seconds) of the debug log lines matching ``pattern``."""
    times = []
    for line in log.splitlines():
        if pattern in line:
            stamp = line.split(" ", 1)[0]
            times.append(datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp())
    return times


class TorControlTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.add_nodes(self.num_nodes)

    def node_args(self, mock, *extra):
        return [
            "-listen=1",
            "-listenonion=1",
            f"-torcontrol=127.0.0.1:{mock.port}",
            "-debug=tor",
            "-logtimemicros=1",
        ] + list(extra)

    def onion_addresses(self, node):
        return [
            a
            for a in node.getnetworkinfo()["localaddresses"]
            if a["address"].endswith(".onion")
        ]

    def wait_for_command(self, mock, prefix, count=1):
        def found():
            with mock.lock:
                return sum(1 for c in mock.commands if c.startswith(prefix)) >= count

        self.wait_until(found)
        with mock.lock:
            return [c for c in mock.commands if c.startswith(prefix)][count - 1]

    def read_log(self, node, start):
        with open(node.debug_log_path, encoding="utf-8", errors="replace") as f:
            f.seek(start)
            return f.read()

    def run_test(self):
        node = self.nodes[0]
        service_id = onion_v3_service_id(b"lotus")
        key_file = os.path.join(node.chain_path, "onion_v3_private_key")

        self.log.info("NULL authentication creates a new onion service")
        mock = MockTorControl(serve_onion(service_id=service_id))
        self.start_node(0, self.node_args(mock))
        add_onion = self.wait_for_command(mock, "ADD_ONION ")
        m = re.fullmatch(
            r"ADD_ONION NEW:ED25519-V3 Port=(\d+),127\.0\.0\.1:(\d+)", add_onion
        )
        assert m, add_onion
        virtual_port = int(m.group(1))
        with mock.lock:
            assert_equal(
                mock.commands[:3], ["PROTOCOLINFO 1", "AUTHENTICATE", add_onion]
            )
        self.wait_until(lambda: len(self.onion_addresses(node)) == 1)
        address = self.onion_addresses(node)[0]
        assert_equal(address["address"], f"{service_id}.onion")
        assert_equal(address["port"], virtual_port)
        onion = [n for n in node.getnetworkinfo()["networks"] if n["name"] == "onion"]
        assert_equal(onion[0]["proxy"], "127.0.0.1:9050")
        assert_equal(onion[0]["reachable"], True)
        self.wait_until(lambda: os.path.exists(key_file))
        with open(key_file, encoding="utf8") as f:
            assert_equal(f.read(), "ED25519-V3:k")

        self.log.info("Losing the control connection removes the onion address")
        start = node.debug_log_size()
        mock.unlisten()
        mock.drop_active()
        self.wait_until(lambda: len(self.onion_addresses(node)) == 0)

        self.log.info("Reconnection uses exponential backoff")
        self.wait_until(
            lambda: (
                len(log_times(self.read_log(node, start), "trying to reconnect")) >= 3
            )
        )
        times = log_times(self.read_log(node, start), "trying to reconnect")
        assert_greater_than_or_equal(times[1] - times[0], 0.9)
        assert_greater_than_or_equal(times[2] - times[1], 1.35)
        self.log.info("A restarted control port is reconnected to")
        mock.listen()
        self.wait_until(lambda: len(self.onion_addresses(node)) == 1, timeout=30)
        self.stop_node(0)
        mock.close()

        self.log.info("Restart reuses the cached private key")
        mock = MockTorControl(serve_onion(service_id=service_id))
        self.start_node(0, self.node_args(mock))
        add_onion = self.wait_for_command(mock, "ADD_ONION ")
        assert add_onion.startswith("ADD_ONION ED25519-V3:k Port="), add_onion
        self.stop_node(0)
        mock.close()

        self.log.info("SAFECOOKIE authentication")
        cookiefile = os.path.join(self.options.tmpdir, "control_auth_cookie")
        with open(cookiefile, "wb") as f:
            f.write(os.urandom(32))
        mock = MockTorControl(
            serve_onion(
                methods="COOKIE,SAFECOOKIE",
                cookiefile=cookiefile,
                service_id=service_id,
            )
        )
        self.start_node(0, self.node_args(mock))
        self.wait_for_command(mock, "ADD_ONION ")
        with mock.lock:
            assert mock.commands[1].startswith("AUTHCHALLENGE SAFECOOKIE ")
            assert re.fullmatch(r"AUTHENTICATE [0-9a-f]{64}", mock.commands[2])
        self.wait_until(lambda: len(self.onion_addresses(node)) == 1)
        self.stop_node(0)
        mock.close()

        self.log.info("A wrong ServerHash stops SAFECOOKIE authentication")
        mock = MockTorControl(
            serve_onion(
                methods="SAFECOOKIE",
                cookiefile=cookiefile,
                service_id=service_id,
                bad_server_hash=True,
            )
        )
        with node.assert_debug_log(["does not match expected ServerHash"], timeout=30):
            self.start_node(0, self.node_args(mock))
        time.sleep(0.5)
        with mock.lock:
            assert not any(c.startswith("AUTHENTICATE") for c in mock.commands)
        self.stop_node(0)
        mock.close()

        self.log.info("HASHEDPASSWORD authentication escapes quotes")
        mock = MockTorControl(
            serve_onion(methods="HASHEDPASSWORD", service_id=service_id)
        )
        self.start_node(0, self.node_args(mock, '-torpassword=pa"ss'))
        self.wait_for_command(mock, "ADD_ONION ")
        with mock.lock:
            assert_equal(mock.commands[1], 'AUTHENTICATE "pa\\"ss"')
        self.stop_node(0)
        mock.close()

        self.log.info("A password without HASHEDPASSWORD support")
        mock = MockTorControl(serve_onion(methods="NULL", service_id=service_id))
        with node.assert_debug_log(
            [
                "Password provided with -torpassword, but HASHEDPASSWORD"
                " authentication is not available"
            ],
            timeout=30,
        ):
            self.start_node(0, self.node_args(mock, "-torpassword=x"))
        self.stop_node(0)
        mock.close()

        self.log.info("ADD_ONION answered with 510")
        mock = MockTorControl(serve_onion(add_onion_reply=["510 Unrecognized command"]))
        with node.assert_debug_log(["You probably need to upgrade Tor"], timeout=30):
            self.start_node(0, self.node_args(mock))
        self.stop_node(0)
        mock.close()

        self.log.info("LF-only line endings and replies split across segments")
        mock = MockTorControl(
            serve_onion(service_id=service_id, line_end="\n", trickle=True)
        )
        self.start_node(0, self.node_args(mock))
        self.wait_for_command(mock, "ADD_ONION ")
        self.wait_until(lambda: len(self.onion_addresses(node)) == 1)
        self.stop_node(0)
        mock.close()

        self.log.info("A host name is not a valid control address")
        with node.assert_debug_log(
            ["tor: Error parsing socket address localhost:9051"], timeout=30
        ):
            self.start_node(
                0,
                [
                    "-listen=1",
                    "-listenonion=1",
                    "-torcontrol=localhost:9051",
                    "-debug=tor",
                ],
            )
        self.stop_node(0)

        self.log.info("An overlong line disconnects without reconnecting")

        def overlong(mock, conn):
            mock.record(conn.readline())
            conn.send(b"x" * 100001)
            try:
                conn.readline(timeout=10)
            except (EOFError, OSError):
                pass

        mock = MockTorControl(overlong)
        with node.assert_debug_log(
            ["tor: Disconnecting because MAX_LINE_LENGTH exceeded"], timeout=30
        ):
            self.start_node(0, self.node_args(mock))
        time.sleep(3)
        with mock.lock:
            assert_equal(mock.connections, 1)
        self.stop_node(0)
        mock.close()


if __name__ == "__main__":
    TorControlTest().main()
