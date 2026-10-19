#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -publicbind: a listener serving only /p2p/ws (and /chronik).

JSON-RPC, wallet and REST must never be reachable on it, even with valid
credentials and from an address the RPC ACL would allow, while the RPC port
keeps serving everything to -rpcallowip clients.
"""

import base64
import http.client
import json
import ssl
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_port

# Ports of node indexes this test doesn't start, so they are free.
PUBLIC_PORT_INDEX = 40


def public_port():
    return p2p_port(PUBLIC_PORT_INDEX)


class HTTPPublicBindTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def setup_network(self):
        self.extra_args = [
            [f"-publicbind=127.0.0.1:{public_port()}", "-rest"],
            [f"-addnode=wss://localhost:{public_port()}/p2p/ws"],
            # Plain ws:// (no TLS), node to node
            [f"-addnode=ws://127.0.0.1:{public_port()}/p2p/ws"],
        ]
        # Start node0 first so its listeners are up before the others dial
        # it with -addnode (a failed attempt is only retried much later).
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(0)
        for i in range(1, self.num_nodes):
            self.start_node(i)

    def request(
        self, port, method, path, body=None, *, tls=False, auth=True, headers=None
    ):
        url = urllib.parse.urlparse(self.nodes[0].url)
        h = dict(headers or {})
        if auth:
            token = base64.b64encode(f"{url.username}:{url.password}".encode())
            h["Authorization"] = f"Basic {token.decode()}"
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request(method, path, body, h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 5, sync_fun=self.no_op)
        rpc_body = json.dumps({"method": "getblockcount", "id": 1})

        self.log.info("The RPC port still serves RPC and REST to allowed IPs")
        status, data = self.request(rpc_port(0), "POST", "/", rpc_body)
        assert_equal(status, 200)
        assert_equal(json.loads(data)["result"], 5)
        status, _ = self.request(rpc_port(0), "GET", "/rest/chaininfo.json")
        assert_equal(status, 200)

        for tls in (False, True):
            scheme = "https" if tls else "http"
            self.log.info(f"The public port refuses RPC/wallet/REST ({scheme})")
            status, _ = self.request(public_port(), "POST", "/", rpc_body, tls=tls)
            assert_equal(status, 404)
            status, _ = self.request(
                public_port(), "POST", "/wallet/", rpc_body, tls=tls
            )
            assert_equal(status, 404)
            status, _ = self.request(
                public_port(), "GET", "/rest/chaininfo.json", tls=tls
            )
            assert_equal(status, 404)
            # A plain GET of the WebSocket path is not an upgrade: 404 too
            status, _ = self.request(public_port(), "GET", "/p2p/ws", tls=tls)
            assert_equal(status, 404)

        self.log.info("Prefix matching is exact: /p2p/wsx is not public")
        status, _ = self.request(
            public_port(),
            "GET",
            "/p2p/wsx",
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            },
        )
        assert_equal(status, 404)

        self.log.info("node1 peers with node0 over wss:// on the public port")
        self.wait_until(
            lambda: any(p["transport"] == "wss" for p in self.nodes[1].getpeerinfo())
        )
        peer = [p for p in node.getpeerinfo() if p["transport"] == "wss"][0]
        assert_equal(peer["websocket"]["compression"], "p2p-v2")
        assert_equal(peer["addrbind"], f"127.0.0.1:{public_port()}")
        self.log.info("node2 peers with node0 over plain ws:// on the public port")
        self.wait_until(
            lambda: any(p["transport"] == "ws" for p in self.nodes[2].getpeerinfo())
        )
        out = [p for p in self.nodes[2].getpeerinfo() if p["transport"] == "ws"][0]
        assert_equal(out["websocket"]["tls"], False)
        assert_equal(out["websocket"]["compression"], "p2p-v2")
        self.sync_blocks()
        tip = self.generate(self.nodes[2], 1)[0]
        assert_equal(self.nodes[1].getbestblockhash(), tip)

        try:
            import websocket  # noqa: F401
            import zstandard  # noqa: F401
        except ImportError:
            self.log.info("websocket-client/zstandard missing: skipping ws:// client")
        else:
            from test_framework.p2p_websocket import P2PWebSocketClient

            self.log.info("An independent peer handshakes on the public port")
            client = P2PWebSocketClient(
                f"ws://127.0.0.1:{public_port()}/p2p/ws",
                subprotocols=["p2p-v2"],
                srcdir=self.config["environment"]["SRCDIR"],
            )
            assert_equal(client.handshake().nStartingHeight, node.getblockcount())
            client.close()

        self.log.info("-publicbind needs an explicit port")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            ["-publicbind=127.0.0.1"],
            expected_msg="Error: Unable to start HTTP server. See debug log for details.",
        )


if __name__ == "__main__":
    HTTPPublicBindTest().main()
