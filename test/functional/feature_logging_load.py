#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded debug=all IBD and transaction-relay load for logger capacity checks.

This is a correctness workload, not a TPS benchmark or a mainnet replay.
The framework requires zero dropped records for every graceful process exit.
"""

from concurrent.futures import ThreadPoolExecutor

from test_framework.log_messages import assert_no_drops, read_records
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy
from test_framework.wallet import MiniWallet


class LoggingLoadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-debug=all", "-loglevel=trace"] for _ in range(3)]

    def setup_network(self):
        # Keep the two targets at genesis until the source has a real backlog.
        self.setup_nodes()

    def run_test(self):
        source = self.nodes[0]
        wallet = MiniWallet(source)
        self.log.info("Build a 2,000-block backlog with debug=all enabled")
        self.generate(wallet, 2000, sync_fun=self.no_op)
        funding = [
            wallet.send_self_transfer_multi(from_node=source, num_outputs=250)
            for _ in range(20)
        ]
        self.generate(wallet, 1, sync_fun=self.no_op)
        # Select all funding transactions, excluding all coinbases.
        selected = {item["txid"] for item in funding}
        utxos = [
            u for u in wallet.get_utxos(mark_as_spent=False) if u["txid"] in selected
        ]
        assert_equal(len(utxos), 5000)
        raw = [wallet.create_self_transfer(utxo_to_spend=u)["hex"] for u in utxos]
        self.log.info("Mine 4,000 transactions into the IBD backlog")
        for start in range(0, 4000, 1000):
            for tx in raw[start : start + 1000]:
                source.sendrawtransaction(tx)
            self.generate(source, 1, sync_fun=self.no_op)

        work = source.getblockchaininfo()["chainwork"]
        for index in (1, 2):
            self.restart_node(
                index, self.extra_args[index] + [f"-minimumchainwork={work}"]
            )
            assert self.nodes[index].getblockchaininfo()["initialblockdownload"]
            self.connect_nodes(index, 0)
        self.sync_blocks(timeout=180)
        self.wait_until(
            lambda: all(
                not node.getblockchaininfo()["initialblockdownload"]
                for node in self.nodes
            ),
            timeout=60,
        )
        self.log.info("Relay 1,000 independent transactions from eight RPC workers")

        def send_chunk(worker):
            # A JSON-RPC connection is not shared between worker threads.
            rpc = get_rpc_proxy(source.url, source.index, timeout=90)
            for tx in raw[4000 + worker :: 8]:
                rpc.sendrawtransaction(tx)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(send_chunk, range(8)))
        self.sync_mempools(timeout=180)
        for node in self.nodes:
            assert_equal(node.getmempoolinfo()["size"], 1000)
        self.generate(source, 1)
        for node in self.nodes:
            assert_equal(node.getmempoolinfo()["size"], 0)
        self.stop_nodes()
        for node in self.nodes:
            records = read_records(node.debug_log_json_path, node.debug_log_json_start)
            assert_no_drops(records, require_summary=True)
            self.log.info(
                "node%d: %d JSON records, zero dropped lines", node.index, len(records)
            )


if __name__ == "__main__":
    LoggingLoadTest().main()
