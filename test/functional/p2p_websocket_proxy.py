#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that ws:// and wss:// P2P dials go through -proxy and never bypass it.

A small forwarding SOCKS5 proxy records each CONNECT request: the node must
hand it the host *name* (so the proxy resolves it, no local DNS lookup) and
must not fall back to a direct connection when the proxy is gone.
"""

import socket
import threading
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port

PUBLIC_PORT_INDEX = 40
PROXY_PORT_INDEX = 41


class ForwardingSocks5Proxy:
    """Minimal SOCKS5 (no auth, CONNECT) that forwards traffic."""

    def __init__(self, port):
        self.requests = []  # (atyp, addr, port)
        self.lock = threading.Lock()
        self.server = socket.create_server(("127.0.0.1", port))
        self.running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self):
        while self.running:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    @staticmethod
    def recvall(conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data += chunk
        return data

    def handle(self, conn):
        try:
            ver, nmethods = self.recvall(conn, 2)
            self.recvall(conn, nmethods)
            conn.sendall(b"\x05\x00")
            ver, cmd, _, atyp = self.recvall(conn, 4)
            if atyp == 3:
                addr = self.recvall(conn, self.recvall(conn, 1)[0]).decode()
            elif atyp == 1:
                addr = socket.inet_ntoa(self.recvall(conn, 4))
            else:
                addr = socket.inet_ntop(socket.AF_INET6, self.recvall(conn, 16))
            port = int.from_bytes(self.recvall(conn, 2), "big")
            with self.lock:
                self.requests.append((atyp, addr, port))
            target = socket.create_connection(
                ("127.0.0.1" if addr == "localhost" else addr, port)
            )
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        except Exception:
            conn.close()
            return

        def pump(src, dst):
            try:
                while data := src.recv(65536):
                    dst.sendall(data)
            except OSError:
                pass
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        threading.Thread(target=pump, args=(conn, target), daemon=True).start()
        threading.Thread(target=pump, args=(target, conn), daemon=True).start()

    def stop(self):
        self.running = False
        self.server.close()


class P2PWebSocketProxyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.proxy_port = p2p_port(PROXY_PORT_INDEX)
        self.proxy = ForwardingSocks5Proxy(self.proxy_port)
        self.extra_args = [
            [f"-publicbind=127.0.0.1:{self.public_port}"],
            [f"-proxy=127.0.0.1:{self.proxy_port}"],
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def run_test(self):
        node0, node1 = self.nodes
        self.generate(node0, 3, sync_fun=self.no_op)

        for scheme, host in (("wss", "localhost"), ("ws", "localhost")):
            url = f"{scheme}://{host}:{self.public_port}/p2p/ws"
            self.log.info(f"{scheme}:// through -proxy, name resolved by the proxy")
            with self.proxy.lock:
                self.proxy.requests.clear()
            node1.addnode(node=url, command="onetry")
            self.wait_until(lambda: len(self.ws_peers(1)) == 1)
            peer = self.ws_peers(1)[0]
            assert_equal(peer["transport"], scheme)
            assert_equal(peer["websocket"]["compression"], "p2p-zstd-v1")
            with self.proxy.lock:
                # SOCKS5 address type 3: a domain name, not an address
                assert_equal(self.proxy.requests, [(3, host, self.public_port)])
            self.sync_blocks()
            node1.disconnectnode(nodeid=peer["id"])
            self.wait_until(lambda: len(self.ws_peers(1)) == 0)
            self.wait_until(lambda: len(self.ws_peers(0)) == 0)

        self.log.info("A dead proxy fails closed: no direct connection")
        self.proxy.stop()
        url = f"wss://localhost:{self.public_port}/p2p/ws"
        node1.addnode(node=url, command="onetry")
        time.sleep(2)
        assert_equal(self.ws_peers(1), [])
        assert_equal(self.ws_peers(0), [])

        self.log.info("-onlynet without wss refuses WebSocket dials")
        self.restart_node(1, ["-onlynet=ipv4"])
        with node1.assert_debug_log(["network wss is not reachable"]):
            node1.addnode(node=url, command="onetry")
        assert_equal(self.ws_peers(1), [])

        self.log.info("Without a proxy the dial is direct")
        self.restart_node(1, [])
        node1.addnode(node=url, command="onetry")
        self.wait_until(lambda: len(self.ws_peers(1)) == 1)


if __name__ == "__main__":
    P2PWebSocketProxyTest().main()
