#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Lotus v2 P2P: WebSocket only, on the P2P port.

- Nodes dial each other's addresses over WebSocket; the P2P port speaks
  HTTP/WebSocket and refuses the raw P2P protocol.
- One port can serve P2P to anyone and RPC to -rpcallowip clients.
- -whitebind permissions apply to WebSocket peers of that listener.
- A listening node without -server still accepts peers.
- A peer that never completes its handshake does not stall other dials.
"""

import os
import socket
import subprocess
import threading
import time
import urllib.parse

from test_framework.authproxy import AuthServiceProxy
from test_framework.messages import NODE_NETWORK, msg_version
from test_framework.p2p import NET_MAGIC_BYTES, P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_port


class P2PWebSocketOnlyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def run_test(self):
        node0, node1, node2 = self.nodes

        self.log.info("Nodes peer over WebSocket on their P2P ports")
        # (The framework connects the nodes in a chain.)
        for node in self.nodes:
            transports = {p["transport"] for p in node.getpeerinfo()}
            assert_equal(transports, {"ws"})
        self.generate(node0, 3)  # syncs through the WebSocket peers
        assert_equal(node1.getblockcount(), 3)

        self.log.info("A peer that never answers does not stall other dials")
        # It accepts TCP, then stays silent through the WebSocket handshake.
        silent = socket.create_server(("127.0.0.1", p2p_port(33)))
        held = []
        threading.Thread(
            target=lambda: held.append(silent.accept()), daemon=True
        ).start()
        self.disconnect_nodes(1, 2)
        start = time.time()
        node1.addnode(node=f"127.0.0.1:{p2p_port(33)}", command="onetry")
        node1.addnode(node=f"127.0.0.1:{p2p_port(2)}", command="onetry")
        self.wait_until(
            lambda: any(
                p["addr"] == f"127.0.0.1:{p2p_port(2)}" for p in node1.getpeerinfo()
            ),
            timeout=10,
        )
        assert time.time() - start < 10
        silent.close()

        self.log.info("The P2P port refuses the raw P2P protocol")
        raw = msg_version()
        raw.nServices = NODE_NETWORK
        payload = raw.serialize()
        header = (
            NET_MAGIC_BYTES[self.chain]
            + b"version".ljust(12, b"\x00")
            + len(payload).to_bytes(4, "little")
        )
        with node0.assert_debug_log(["raw P2P is not accepted (-p2prawlisten=0)"]):
            with socket.create_connection(("127.0.0.1", p2p_port(0)), timeout=10) as s:
                s.sendall(header + b"\x00" * 4 + payload)
                try:
                    reply = s.recv(64)
                except ConnectionResetError:
                    # The shared port classifier closes raw P2P before HTTP.
                    reply = b""
        assert_equal(reply, b"")
        assert all(p["transport"] == "ws" for p in node0.getpeerinfo())

        self.log.info("-whitebind permissions apply to WebSocket peers")
        white = p2p_port(30)
        self.restart_node(0, [f"-whitebind=noban@127.0.0.1:{white}"])
        peer = node0.add_p2p_connection(P2PInterface(), dstport=white)
        info = [p for p in node0.getpeerinfo() if p["inbound"]][-1]
        assert_equal(info["transport"], "ws")
        assert "noban" in info["permissions"], info["permissions"]
        peer.peer_disconnect()
        node0.add_p2p_connection(P2PInterface())  # the normal port: none
        info = [p for p in node0.getpeerinfo() if p["inbound"]][-1]
        assert_equal(info["permissions"], [])
        node0.disconnect_p2ps()

        self.log.info("One port for P2P (anyone) and RPC (-rpcallowip)")
        port = p2p_port(31)
        with node2.assert_debug_log(
            [f"P2P on 127.0.0.1:{port} shares the RPC listener"]
        ):
            # (RPC also stays on the framework's own port.)
            self.restart_node(
                2,
                [
                    f"-port={port}",
                    f"-bind=127.0.0.1:{port}",
                    f"-rpcbind=127.0.0.1:{port}",
                    f"-rpcbind=127.0.0.1:{rpc_port(2)}",
                    "-rpcallowip=127.0.0.1",
                ],
            )
        url = urllib.parse.urlparse(node2.url)
        shared = AuthServiceProxy(
            f"http://{url.username}:{url.password}@127.0.0.1:{port}"
        )
        assert_equal(shared.getblockcount(), node2.getblockcount())
        node0.addnode(node=f"127.0.0.1:{port}", command="onetry")
        self.wait_until(lambda: len(node2.getpeerinfo()) >= 1)
        assert_equal(node2.getpeerinfo()[0]["transport"], "ws")

        self.log.info("A listening node without -server still accepts peers")
        datadir = os.path.join(self.options.tmpdir, "noserver")
        os.makedirs(datadir)
        noserver = p2p_port(32)
        proc = subprocess.Popen(
            [
                self.options.bitcoind,
                f"-datadir={datadir}",
                "-regtest",
                "-server=0",
                "-listen=1",
                f"-bind=127.0.0.1:{noserver}",
                f"-port={noserver}",
                "-discover=0",
                "-dnsseed=0",
                "-fixedseeds=0",
                "-printtoconsole=0",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 60
            connected = False
            while time.time() < deadline and not connected:
                node1.addnode(node=f"127.0.0.1:{noserver}", command="onetry")
                time.sleep(1)
                connected = any(
                    p["addr"] == f"127.0.0.1:{noserver}"
                    and "version" in p
                    and p["version"] > 0
                    for p in node1.getpeerinfo()
                )
            assert connected, "could not peer with the node without -server"
        finally:
            proc.terminate()
            proc.wait(timeout=60)


if __name__ == "__main__":
    P2PWebSocketOnlyTest().main()
