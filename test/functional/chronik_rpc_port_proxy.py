#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test serving Chronik on the RPC port under /chronik (HTTP, TLS, zstd, ws)."""

import http.client
import ssl

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    chronik_sub_to_blocks,
    chronik_port,
    p2p_port,
    rpc_port,
)


def raw_get(port, path, *, tls=False, headers=None):
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=30)
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp, body


class ChronikRpcPortProxyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-chronik"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_chronik()

    def check_per_ip_limit(self, node, pb):
        import socket

        import websocket

        limit_error = pb.WsMsg(
            error=pb.Error(msg="503: Subscription limit of 1 exceeded for this client")
        )

        def connect(host, port, path, headers=None):
            return websocket.create_connection(
                f"ws://{host}:{port}{path}", header=headers or [], timeout=30
            )

        def sub(ws, txid):
            ws.send_binary(pb.WsSub(txid=pb.WsSubTxId(txid=txid)).SerializeToString())

        def sub_ok(ws, txid):
            # The subscription is logged before the limit is checked: also
            # check that no limit error follows.
            with node.assert_debug_log(
                [f"WS subscribe to txid {txid}"],
                unexpected_msgs=["Subscription limit"],
            ):
                sub(ws, txid)
            ws.settimeout(1)
            try:
                raise AssertionError(f"Unexpected WS message {ws.recv()!r}")
            except websocket.WebSocketTimeoutException:
                pass
            ws.settimeout(30)

        def sub_rejected(ws, txid):
            sub(ws, txid)
            msg = pb.WsMsg()
            msg.ParseFromString(ws.recv())
            assert_equal(msg, limit_error)

        port = rpc_port(node.index)
        ws_v4 = connect("127.0.0.1", port, "/chronik/ws")
        sub_ok(ws_v4, "00" * 32)
        # The limit is reached for 127.0.0.1
        sub_rejected(ws_v4, "11" * 32)

        # Clients claiming another address are still 127.0.0.1: the address
        # is the one of the socket, never X-Forwarded-For.
        headers = ["X-Forwarded-For: 198.51.100.9"]
        forged = connect("127.0.0.1", port, "/chronik/ws", headers)
        sub_rejected(forged, "22" * 32)
        forged.close()
        # A direct client of the Chronik listener shares the same budget: each
        # client is counted once, by its address, whichever way it connects.
        direct = connect("127.0.0.1", chronik_port(node.index), "/ws", headers)
        sub_rejected(direct, "22" * 32)
        direct.close()

        # Another client (::1) on the RPC port has its own budget, instead of
        # sharing one address with every other client.
        try:
            ws_v6 = connect("[::1]", port, "/chronik/ws")
        except (OSError, websocket.WebSocketException) as e:
            if not socket.has_ipv6:
                self.log.info(f"No IPv6 ({e}), skipping the ::1 client")
                ws_v4.close()
                return
            raise
        sub_ok(ws_v6, "33" * 32)
        sub_rejected(ws_v6, "44" * 32)
        ws_v6.close()
        ws_v4.close()

    def run_test(self):
        from test_framework.chronik.client import ChronikClient, pb

        node = self.nodes[0]
        self.generate(node, 120)
        direct = ChronikClient("127.0.0.1", chronik_port(node.index))
        proxied = ChronikClient("127.0.0.1/chronik", rpc_port(node.index))

        self.log.info("Chronik requests on the RPC port match the Chronik port")
        assert_equal(proxied.blockchain_info().ok(), direct.blockchain_info().ok())
        assert_equal(
            proxied.blocks(0, 100).ok().blocks, direct.blocks(0, 100).ok().blocks
        )
        assert_equal(proxied.block(5).ok(), direct.block(5).ok())

        self.log.info("Chronik errors pass through with their status")
        direct_resp, direct_body = raw_get(
            chronik_port(node.index), "/block/doesnotexist"
        )
        resp, body = raw_get(rpc_port(node.index), "/chronik/block/doesnotexist")
        assert_equal(resp.status, direct_resp.status)
        assert_equal(body, direct_body)
        assert_equal(resp.getheader("Content-Type"), "application/x-protobuf")

        self.log.info("Chronik is served over TLS on the RPC port")
        resp, body = raw_get(rpc_port(node.index), "/chronik/blockchain-info", tls=True)
        assert_equal(resp.status, 200)
        info = pb.BlockchainInfo()
        info.ParseFromString(body)
        assert_equal(info.tip_height, 120)

        self.log.info("Chronik replies are zstd-encoded when accepted")
        _, plain = raw_get(chronik_port(node.index), "/blocks/0/100")
        resp, body = raw_get(
            rpc_port(node.index),
            "/chronik/blocks/0/100",
            headers={"Accept-Encoding": "gzip, zstd"},
        )
        assert_equal(resp.getheader("Content-Encoding"), "zstd")
        try:
            import zstandard
        except ImportError:
            self.log.info("zstandard module missing, not decompressing")
        else:
            assert_equal(
                zstandard.ZstdDecompressor().decompress(body, max_output_size=1 << 24),
                plain,
            )
            assert len(body) < len(plain)

        self.log.info("Chronik WebSocket works through /chronik/ws")
        ws = proxied.ws()
        chronik_sub_to_blocks(ws, node)
        tip = self.generate(node, 1)[0]
        msg = ws.recv()
        assert_equal(msg.block.msg_type, pb.BLK_CONNECTED)
        assert_equal(msg.block.block_hash[::-1].hex(), tip)
        ws.close()

        self.log.info("Over TLS too (wss://)")
        import websocket

        tls_ws = websocket.create_connection(
            f"wss://127.0.0.1:{rpc_port(node.index)}/chronik/ws",
            sslopt={"cert_reqs": ssl.CERT_NONE},
            timeout=30,
        )
        with node.assert_debug_log(["WS subscribe to blocks"]):
            tls_ws.send_binary(
                pb.WsSub(is_unsub=False, blocks=pb.WsSubBlocks()).SerializeToString()
            )
        tip = self.generate(node, 1)[0]
        while True:
            msg = pb.WsMsg()
            msg.ParseFromString(tls_ws.recv())
            if msg.HasField("block") and msg.block.msg_type == pb.BLK_CONNECTED:
                break
        assert_equal(msg.block.block_hash[::-1].hex(), tip)
        tls_ws.close()

        self.log.info("Per-IP WebSocket limits see the real client address")
        self.restart_node(0, ["-chronik", "-chronikmaxsubsperip=1"])
        self.check_per_ip_limit(node, pb)

        self.log.info("RPC on the same port still requires credentials")
        conn = http.client.HTTPConnection("127.0.0.1", rpc_port(node.index))
        conn.request("POST", "/", '{"method": "getblockcount"}')
        assert_equal(conn.getresponse().status, 401)
        conn.close()

        self.log.info("Chronik is served on -publicbind listeners, RPC is not")
        public_port = p2p_port(40)
        self.restart_node(0, ["-chronik", f"-publicbind=127.0.0.1:{public_port}"])
        public = ChronikClient("127.0.0.1/chronik", public_port)
        assert_equal(public.blockchain_info().ok().tip_height, 122)
        conn = http.client.HTTPConnection("127.0.0.1", public_port)
        conn.request("POST", "/", '{"method": "getblockcount"}')
        assert_equal(conn.getresponse().status, 404)
        conn.close()
        ws = public.ws()
        chronik_sub_to_blocks(ws, node)
        tip = self.generate(node, 1)[0]
        assert_equal(ws.recv().block.block_hash[::-1].hex(), tip)
        ws.close()

        self.log.info("-chronikpubliconrpcport=0 disables /chronik on the RPC port")
        self.restart_node(0, ["-chronik", "-chronikpubliconrpcport=0"])
        resp, _ = raw_get(rpc_port(node.index), "/chronik/blockchain-info")
        assert_equal(resp.status, 404)


if __name__ == "__main__":
    ChronikRpcPortProxyTest().main()
