#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test HTTP/2 (ALPN h2) on the TLS listeners.

A client independent of the node's nghttp2 (the Python h2 package) checks
that HTTP/2 streams are served like HTTP/1.1 requests: same authentication,
-rpcallowip and -trustedproxy handling, public listener rules, Chronik,
zstd and response semantics; that HTTP/1.1 is unchanged; and that
plain-text listeners and -http2=0 never speak HTTP/2.
"""

import http.client
import json
import socket
import ssl

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, p2p_port, rpc_port

PUBLIC_PORT_INDEX = 40


def public_port():
    return p2p_port(PUBLIC_PORT_INDEX)


def h1_tls(port, method, path, body=None, headers=None):
    """An HTTP/1.1 request over TLS, offering only http/1.1"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=30)
    conn.request(method, path, body, headers or {})
    resp = conn.getresponse()
    data = resp.read()
    alpn = conn.sock.selected_alpn_protocol()
    conn.close()
    return resp, data, alpn


class HTTP2Test(BitcoinTestFramework):
    num_nodes = 2
    setup_clean_chain = True
    topology = "none"
    requires = {"http2"}

    def set_test_params(self):
        self.extra_args = [
            [
                "-rest",
                f"-publicbind=127.0.0.1:{public_port()}",
                # Stands in for a load balancer: X-Forwarded-For is believed
                "-trustedproxy=127.0.0.1",
                # 32 multiplexed RPCs, as many as over 32 HTTP/1.1
                # connections, must fit the work queue (else 503)
                "-rpcworkqueue=64",
            ],
            ["-http2=0"],
        ]

    def setup_network(self):
        if self.is_chronik_compiled():
            self.extra_args[0].append("-chronik")
        self.setup_nodes()

    def run_test(self):
        from test_framework.http2 import H2Client, basic_auth

        node = self.nodes[0]
        self.generate(node, 3, sync_fun=self.no_op)
        auth = basic_auth(node.url)
        rpc_body = json.dumps({"method": "getblockcount", "id": 1}).encode()
        port = rpc_port(0)

        self.log.info("ALPN: h2 is preferred when offered, on the RPC port")
        c = H2Client("127.0.0.1", port)
        assert_equal(c.alpn, "h2")

        self.log.info("RPC over HTTP/2 with authentication")
        r = c.request("POST", "/", [("authorization", auth)], rpc_body)
        assert_equal(r.status, 200)
        assert_equal(json.loads(r.body)["result"], 3)
        assert_equal(r.headers["content-type"], "application/json")
        r = c.request("POST", "/", [("authorization", "Basic Zm9vOmJhcg==")], rpc_body)
        assert_equal(r.status, 401)
        r = c.request("POST", "/", [], rpc_body)
        assert_equal(r.status, 401)

        self.log.info("A request reset in the same TLS record is never dispatched")
        # Keep the complete request and reset in one write: the adapter sees
        # both before it dispatches completed requests to the worker queue.
        sid = c.conn.get_next_available_stream_id()
        c.conn.send_headers(
            sid,
            [
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/"),
                ("authorization", auth),
            ],
        )
        c.conn.send_data(
            sid,
            json.dumps(
                {"method": "setnetworkactive", "params": [False], "id": 99}
            ).encode(),
            end_stream=True,
        )
        c.conn.reset_stream(sid)
        c.flush()
        # A reply on this connection also establishes that its preceding
        # reset has been processed. The reset RPC must have no side effect.
        assert_equal(c.request("GET", "/livez").status, 200)
        assert_equal(node.getnetworkinfo()["networkactive"], True)

        self.log.info("Many RPCs multiplexed on one connection")
        sids = []
        for i in range(32):
            body = json.dumps({"method": "getblockhash", "params": [i % 4], "id": i})
            sids.append(c.start("POST", "/", [("authorization", auth)], body.encode()))
        for i, r in enumerate(c.wait(sids)):
            assert_equal(r.status, 200)
            reply = json.loads(r.body)
            assert_equal(reply["id"], i)
            assert_equal(reply["result"], node.getblockhash(i % 4))

        self.log.info("REST, HEAD, 404 and 405 like HTTP/1.1")
        r = c.request("GET", "/rest/chaininfo.json")
        assert_equal(r.status, 200)
        assert_equal(json.loads(r.body)["blocks"], 3)
        h = c.request("HEAD", "/rest/chaininfo.json")
        assert_equal(h.status, 200)
        assert_equal(h.body, b"")
        assert_equal(int(h.headers["content-length"]), len(r.body))
        assert_equal(c.request("GET", "/nonexistent").status, 404)
        assert_equal(c.request("PATCH", "/", [("authorization", auth)]).status, 405)

        self.log.info("Health endpoints")
        r = c.request("GET", "/livez")
        assert_equal(r.status, 200)
        assert_equal(json.loads(r.body)["status"], "ok")

        self.log.info("zstd replies, as over HTTP/1.1")
        tip = node.getbestblockhash()
        plain = c.request("GET", f"/rest/block/{tip}.json")
        assert_equal(plain.status, 200)
        assert "content-encoding" not in plain.headers
        assert_greater_than(len(plain.body), 512)
        z = c.request("GET", f"/rest/block/{tip}.json", [("accept-encoding", "zstd")])
        assert_equal(z.status, 200)
        assert_equal(z.headers["content-encoding"], "zstd")
        try:
            import zstandard
        except ImportError:
            self.log.info("zstandard missing: not decoding the reply")
        else:
            out = zstandard.ZstdDecompressor().decompressobj().decompress(z.body)
            assert_equal(out, plain.body)

        self.log.info("-rpcallowip and -trustedproxy apply per stream")
        r = c.request(
            "POST",
            "/",
            [("authorization", auth), ("x-forwarded-for", "192.0.2.1")],
            rpc_body,
        )
        assert_equal(r.status, 403)
        r = c.request(
            "POST",
            "/",
            [("authorization", auth), ("x-forwarded-for", "127.0.0.5")],
            rpc_body,
        )
        assert_equal(r.status, 200)

        if self.is_chronik_compiled():
            self.log.info("Chronik over HTTP/2 matches Chronik over HTTP/1.1")
            r = c.request("GET", "/chronik/blockchain-info")
            assert_equal(r.status, 200)
            resp, h1_body, _ = h1_tls(port, "GET", "/chronik/blockchain-info")
            assert_equal(resp.status, 200)
            assert_equal(r.body, h1_body)
            assert_equal(r.headers["content-type"], resp.getheader("Content-Type"))
        c.close()

        self.log.info("The public listener refuses RPC, wallet and REST over HTTP/2")
        p = H2Client("127.0.0.1", public_port())
        assert_equal(p.alpn, "h2")
        assert_equal(
            p.request("POST", "/", [("authorization", auth)], rpc_body).status, 404
        )
        assert_equal(
            p.request("POST", "/wallet/", [("authorization", auth)], rpc_body).status,
            404,
        )
        assert_equal(p.request("GET", "/rest/chaininfo.json").status, 404)
        assert_equal(p.request("GET", "/p2p/ws").status, 404)
        if self.is_chronik_compiled():
            assert_equal(p.request("GET", "/chronik/blockchain-info").status, 200)
        p.close()

        self.log.info("HTTP/1.1 is unchanged for clients offering only http/1.1")
        resp, data, alpn = h1_tls(port, "POST", "/", rpc_body, {"Authorization": auth})
        assert_equal(alpn, "http/1.1")
        assert_equal(resp.status, 200)
        assert_equal(json.loads(data)["result"], 3)
        assert_equal(resp.version, 11)

        self.log.info("Plain-text listeners never speak HTTP/2 (no h2c)")
        with socket.create_connection(("127.0.0.1", port), timeout=30) as s:
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            reply = s.recv(4096)
        assert reply.startswith(b"HTTP/1.1 400"), reply
        with socket.create_connection(("127.0.0.1", port), timeout=30) as s:
            s.sendall(
                b"GET /livez HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings"
                b"\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n"
            )
            reply = s.recv(4096)
        # Answered over HTTP/1.1, the h2c upgrade ignored
        assert reply.startswith(b"HTTP/1.1 200"), reply

        self.log.info("-http2=0: h2 is never selected")
        c = H2Client("127.0.0.1", rpc_port(1))
        assert_equal(c.alpn, "http/1.1")
        c.close()
        c = H2Client("127.0.0.1", rpc_port(1), alpn=("h2",))
        assert_equal(c.alpn, None)
        c.close()


if __name__ == "__main__":
    HTTP2Test().main()
