#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Long-poll requests yield a single HTTP worker and wake on tip/shutdown."""

from concurrent.futures import ThreadPoolExecutor

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy


class CoroutineLongpollTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [["-rpcthreads=1", "-rpcworkqueue=64"], []]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 1)
        tip = node.getbestblockhash()
        height = node.getblockcount()
        longpollid = node.getblocktemplate()["longpollid"]

        def call(method, args):
            proxy = get_rpc_proxy(node.url, 0, timeout=15)
            return getattr(proxy, method)(*args)

        quick = get_rpc_proxy(node.url, 0, timeout=3)
        with ThreadPoolExecutor(max_workers=8) as workers:
            requests = [("waitfornewblock", [10000])] * 4 + [
                ("waitforblockheight", [height + 1, 10000]),
                ("getblocktemplate", [{"longpollid": longpollid}]),
                ("getblocktemplate", [{"longpollid": longpollid}]),
            ]
            futures = [workers.submit(call, method, args) for method, args in requests]
            self.wait_until(
                lambda: (
                    sum(
                        c["method"]
                        in {"waitfornewblock", "waitforblockheight", "getblocktemplate"}
                        for c in quick.getrpcinfo()["active_commands"]
                    )
                    == len(requests)
                ),
                timeout=5,
            )
            assert all(not f.done() for f in futures)
            assert_equal(quick.getblockcount(), height)
            new_tip = self.generate(self.nodes[1], 1)[0]
            for (method, _), future in zip(requests, futures):
                result = future.result(timeout=5)
                if method == "getblocktemplate":
                    assert_equal(result["previousblockhash"], new_tip)
                else:
                    assert_equal(result, {"hash": new_tip, "height": height + 1})
            # ABC treats negative nonzero wait timeouts as already expired.
            assert_equal(quick.waitforblock(tip, -1)["hash"], new_tip)
            shutdown_waiters = [
                workers.submit(call, "waitfornewblock", [0]) for _ in range(3)
            ]
            self.wait_until(
                lambda: (
                    sum(
                        c["method"] == "waitfornewblock"
                        for c in quick.getrpcinfo()["active_commands"]
                    )
                    == 3
                ),
                timeout=5,
            )
            self.stop_node(0)
            for future in shutdown_waiters:
                assert_equal(
                    future.result(timeout=5), {"hash": new_tip, "height": height + 1}
                )


if __name__ == "__main__":
    CoroutineLongpollTest().main()
