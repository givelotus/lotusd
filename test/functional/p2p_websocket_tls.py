#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end hybrid TCP + WebSocket (wss://, p2p-zstd-v1) P2P test.

- node0 serves JSON-RPC (http/https/zstd) and /p2p/ws on its RPC port and
  advertises -externaldomain=localhost:<rpcport>.
- node1 connects to node0 over wss://localhost:<rpcport>/p2p/ws.
- node2 connects to node0 over ordinary TCP P2P.
"""

import base64
import http.client
import json
import ssl
import time
import urllib.parse

from test_framework.messages import CAddress, msg_getaddr
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, rpc_port
from test_framework.wallet import MiniWallet


class AddrReceiver(P2PInterface):
    def __init__(self, support_addrv2):
        super().__init__(support_addrv2=support_addrv2)
        self.addrs = []

    def on_addr(self, message):
        self.addrs.extend(message.addrs)

    def on_addrv2(self, message):
        self.addrs.extend(message.addrs)

    def wss_addrs(self):
        with p2p_lock:
            return [a for a in self.addrs if a.net == CAddress.NET_WSS]


class P2PWebSocketTLSTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [[], [], []]

    def setup_network(self):
        port0 = rpc_port(0)
        self.extra_args[0] = [f"-externaldomain=localhost:{port0}"]
        self.extra_args[1] = [f"-addnode=wss://localhost:{port0}/p2p/ws"]
        self.setup_nodes()
        # node2 <-> node0 over plain TCP P2P
        self.connect_nodes(2, 0)

    def rpc(self, body, *, tls=False, headers=None):
        url = urllib.parse.urlparse(self.nodes[0].url)
        auth = base64.b64encode(f"{url.username}:{url.password}".encode()).decode()
        h = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
        h.update(headers or {})
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection("127.0.0.1", rpc_port(0), context=ctx)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", rpc_port(0))
        conn.request("POST", "/", json.dumps(body), h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def run_test(self):
        node0, node1, node2 = self.nodes

        self.log.info("node1 reaches node0 over wss:// with p2p-zstd-v1")
        self.wait_until(lambda: len(self.ws_peers(1)) == 1)
        out = self.ws_peers(1)[0]
        assert_equal(out["transport"], "wss")
        assert_equal(out["inbound"], False)
        assert_equal(out["addr"], f"wss://localhost:{rpc_port(0)}/p2p/ws")
        assert_equal(out["websocket"]["compression"], "p2p-zstd-v1")
        assert_equal(out["websocket"]["tls"], True)
        self.wait_until(lambda: len(self.ws_peers(0)) == 1)
        inbound = self.ws_peers(0)[0]
        assert_equal(inbound["transport"], "wss")
        assert_equal(inbound["inbound"], True)
        # node0's TCP peer is node2
        tcp_peers = [p for p in node0.getpeerinfo() if p["transport"] == "tcp"]
        assert_equal(len(tcp_peers), 1)

        self.log.info("JSON-RPC over http:// and https:// on the same port")
        resp, data = self.rpc({"method": "getblockchaininfo", "id": 1})
        assert_equal(resp.status, 200)
        assert_equal(json.loads(data)["result"]["chain"], "regtest")
        resp, data = self.rpc({"method": "getblockchaininfo", "id": 1}, tls=True)
        assert_equal(resp.status, 200)
        assert_equal(json.loads(data)["result"]["chain"], "regtest")

        self.log.info("Mine on node2 (TCP), relay through node0 to node1 (wss)")
        wallet = MiniWallet(node2)
        self.generate(wallet, 101, sync_fun=self.no_op)
        self.sync_blocks()
        assert_equal(node1.getblockcount(), 101)

        self.log.info("Accept-Encoding: zstd on getblock verbosity 2")
        tip = node0.getbestblockhash()
        resp, data = self.rpc(
            {"method": "getblock", "params": [tip, 2], "id": 1},
            headers={"Accept-Encoding": "zstd"},
        )
        assert_equal(resp.getheader("Content-Encoding"), "zstd")
        try:
            import zstandard
        except ImportError:
            self.log.info("zstandard not installed: skipping decompression")
        else:
            block = json.loads(
                zstandard.ZstdDecompressor().decompress(
                    data, max_output_size=1 << 26
                )
            )
            assert_equal(block["result"]["hash"], tip)

        self.log.info("Transactions from node1 (wss) reach node2 (TCP)")
        self.generate(wallet, 1)
        wallet1 = MiniWallet(node1)
        self.generate(wallet1, 101)
        txids = [wallet1.send_self_transfer(from_node=node1)["txid"] for _ in range(5)]
        self.wait_until(lambda: set(txids) <= set(node2.getrawmempool()))
        self.log.info("Blocks mined on node2 (TCP) reach node1 (wss)")
        tip = self.generate(node2, 1, sync_fun=self.no_op)[0]
        self.wait_until(lambda: node1.getbestblockhash() == tip)
        assert_equal(node1.getrawmempool(), [])

        ws = self.ws_peers(1)[0]["websocket"]
        self.log.info(
            f"node1 WebSocket bytes: payload sent/recv "
            f"{ws['payload_bytes_sent']}/{ws['payload_bytes_recv']}, wire "
            f"{ws['wire_bytes_sent']}/{ws['wire_bytes_recv']}"
        )
        assert ws["wire_bytes_recv"] < ws["payload_bytes_recv"]

        self.log.info("node0 advertises localhost:<rpcport> only via ADDRv2")
        v2 = node0.add_p2p_connection(AddrReceiver(support_addrv2=True))
        v1 = node0.add_p2p_connection(AddrReceiver(support_addrv2=False))
        for peer in (v1, v2):
            peer.send_and_ping(msg_getaddr())
        now = int(time.time())
        for i in range(1, 6):
            node0.setmocktime(now + i * 60 * 60)
            v2.sync_with_ping()
            if v2.wss_addrs():
                break
        self.wait_until(lambda: len(v2.wss_addrs()) > 0)
        addr = v2.wss_addrs()[0]
        assert_equal(addr.ip, "localhost")
        assert_equal(addr.port, rpc_port(0))
        v1.sync_with_ping()
        assert_equal(v1.wss_addrs(), [])
        # ADDRv1 has no encoding for names: nothing (e.g. 0.0.0.0) was sent
        assert all(a.ip != "0.0.0.0" for a in v1.addrs)
        node0.setmocktime(0)

        self.log.info("node2 learns the NET_WSS address over TCP ADDRv2")
        # node0 relays node0's own address to node2 (an ADDRv2 bitcoind)
        self.wait_until(
            lambda: any(
                a["network"] == "wss" and a["address"] == "localhost"
                for a in node2.getnodeaddresses(0)
            ),
            timeout=120,
        )

        totals = node0.getnettotals()
        self.log.info(f"node0 getnettotals: {totals}")
        assert totals["websocket"]["wire_bytes_sent"] > 0


if __name__ == "__main__":
    P2PWebSocketTLSTest().main()
