#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test compress-once block frames with mixed peers.

One node serves the same block to zstd WebSocket peers (p2p-zstd-v1 and
p2p-zstd), an uncompressed WebSocket peer and a raw TCP peer. Every peer
receives the identical block, zstd peers get it as an independent frame
compressed once for all of them (metrics), and a zstd peer may send
independent frames too.
"""

import http.client
import time

from test_framework.messages import MSG_BLOCK, CInv, msg_getdata, msg_ping
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, rpc_port
from test_framework.wallet import MiniWallet


class BlockCollector(P2PInterface):
    def __init__(self):
        super().__init__()
        self.blocks = {}

    def on_block(self, message):
        self.blocks[message.block.hash_hex] = message.block.serialize().hex()


class P2PWebSocketCompressOnceTest(BitcoinTestFramework):
    num_nodes = 1
    extra_args = [["-metrics"]]

    def skip_test_if_missing_module(self):
        try:
            import websocket  # noqa: F401
            import zstandard  # noqa: F401
        except ImportError:
            raise SkipTest("websocket-client and zstandard are required")

    def scrape(self):
        # Repeated scrapes within a second return the previous rendering.
        time.sleep(1.1)
        conn = http.client.HTTPConnection("127.0.0.1", rpc_port(0), timeout=30)
        conn.request("GET", "/metrics")
        res = conn.getresponse()
        assert_equal(res.status, 200)
        values = {}
        for line in res.read().decode().splitlines():
            if line.startswith("fullnode_p2p_compress_once") or line.startswith(
                "fullnode_p2p_websocket_independent"
            ):
                name, value = line.rsplit(" ", 1)
                values[name] = float(value)
        conn.close()
        return values

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def connect(self, subprotocols):
        from test_framework.p2p_websocket import P2PWebSocketClient

        peer = P2PWebSocketClient(
            f"ws://127.0.0.1:{rpc_port(0)}/p2p/ws",
            subprotocols=subprotocols,
            srcdir=self.config["environment"]["SRCDIR"],
        )
        peer.handshake()
        return peer

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mine a block larger than -p2pcompressoncethreshold")
        wallet = MiniWallet(node)
        for _ in range(40):
            wallet.send_self_transfer_multi(from_node=node, num_outputs=100)
        blockhash = self.generate(node, 1, sync_fun=self.no_op)[0]
        raw_block = bytes.fromhex(node.getblock(blockhash, 0))
        assert len(raw_block) > 100000, len(raw_block)

        self.log.info("Peers: p2p-zstd-v1 (two), p2p-zstd, none and raw TCP")
        dict_a = self.connect(["p2p-zstd-v1", "p2p-zstd"])
        dict_b = self.connect(["p2p-zstd-v1"])
        zstd = self.connect(["p2p-zstd"])
        uncompressed = self.connect(None)
        assert_equal(dict_a.subprotocol, "p2p-zstd-v1")
        assert_equal(dict_b.subprotocol, "p2p-zstd-v1")
        assert_equal(zstd.subprotocol, "p2p-zstd")
        assert_equal(uncompressed.subprotocol, None)
        tcp = node.add_p2p_connection(BlockCollector())
        self.wait_until(lambda: len(self.ws_peers(0)) == 4)
        before = self.scrape()

        ws_peers = [dict_a, dict_b, zstd, uncompressed]
        getdata = msg_getdata([CInv(MSG_BLOCK, int(blockhash, 16))])
        for peer in ws_peers:
            peer.send_message(getdata)
        tcp.send_without_ping(getdata)

        received = []
        for peer in ws_peers:
            while True:
                msgtype, raw = peer.recv_raw_message()
                if msgtype == b"block":
                    received.append(raw)
                    break
        self.log.info("Every peer received the identical block")
        for raw in received:
            assert_equal(raw[24:], raw_block)
            assert_equal(raw, received[0])
        tcp.wait_until(lambda: blockhash in tcp.blocks)
        assert_equal(tcp.blocks[blockhash], raw_block.hex())

        self.log.info("zstd peers got it as an independent frame")
        assert_equal(dict_a.independent_frames_recv, 1)
        assert_equal(dict_b.independent_frames_recv, 1)
        assert_equal(zstd.independent_frames_recv, 1)
        assert_equal(uncompressed.independent_frames_recv, 0)
        sent = sorted(
            p["websocket"]["independent_frames_sent"] for p in self.ws_peers(0)
        )
        assert_equal(sent, [0, 1, 1, 1])

        self.log.info("The block was compressed once for the three zstd peers")
        after = self.scrape()

        def delta(name):
            return after.get(name, 0) - before.get(name, 0)

        assert_equal(delta("fullnode_p2p_compress_once_encodes_total"), 1)
        assert_equal(delta("fullnode_p2p_compress_once_cache_misses_total"), 1)
        assert_equal(delta("fullnode_p2p_compress_once_cache_hits_total"), 2)
        assert_equal(
            delta('fullnode_p2p_websocket_independent_frames_total{direction="sent"}'),
            3,
        )
        assert_equal(after["fullnode_p2p_compress_once_cache_entries"], 1)
        assert after["fullnode_p2p_compress_once_cache_bytes"] > 0

        self.log.info("Serving it again is a cache hit")
        dict_a.send_message(getdata)
        while dict_a.recv_raw_message()[0] != b"block":
            pass
        again = self.scrape()
        assert_equal(
            again["fullnode_p2p_compress_once_encodes_total"],
            after["fullnode_p2p_compress_once_encodes_total"],
        )
        assert_equal(
            again["fullnode_p2p_compress_once_cache_hits_total"],
            after["fullnode_p2p_compress_once_cache_hits_total"] + 1,
        )

        self.log.info("A zstd peer may send independent frames")
        for peer, nonce in [(dict_a, 42), (zstd, 43)]:
            peer.send_independent(peer.build_message(msg_ping(nonce=nonce)))
            assert_equal(peer.wait_for(b"pong").nonce, nonce)
        self.wait_until(
            lambda: (
                sum(p["websocket"]["independent_frames_recv"] for p in self.ws_peers(0))
                == 2
            )
        )
        for peer in ws_peers:
            peer.close()


if __name__ == "__main__":
    P2PWebSocketCompressOnceTest().main()
