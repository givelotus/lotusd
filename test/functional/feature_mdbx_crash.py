#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""SIGKILL a node during transaction-heavy block submission, recover without reindex.

This is process-crash coverage. It does not simulate power loss or torn sectors.
"""

import json
import threading
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class MdbxCrashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [
            [
                "-avalanche=0",
                "-acceptnonstdtxn=1",
                "-dbcache=64",
                "-dbbatchsize=200000",
                "-debug=bench",
            ]
        ] * 3
        self.rpc_timeout = 240
        self.supports_cli = False

    def add_options(self, parser):
        parser.add_argument("--result-json")
        parser.add_argument("--crash-cycles", type=int, default=5)
        parser.add_argument("--transactions", type=int, default=2000)

    def setup_network(self):
        self.setup_nodes()
        # Deliver raw blocks explicitly: recovery must not silently fetch
        # missing history from a peer while its result is being inspected.

    def run_test(self):
        source, target, control = self.nodes
        wallet = MiniWallet(source)
        initial = self.generate(wallet, 110, sync_fun=self.no_op)
        funding = wallet.send_self_transfer_multi(
            from_node=source,
            num_outputs=self.options.transactions * self.options.crash_cycles,
        )["new_utxos"]
        initial += self.generate(wallet, 1, sync_fun=self.no_op)
        for blockhash in initial:
            raw_initial = source.getblock(blockhash, False)
            assert_equal(target.submitblock(raw_initial), None)
            assert_equal(control.submitblock(raw_initial), None)
        assert target.verifychain(4, 0)
        assert_equal(
            target.gettxoutsetinfo()["hash_serialized"],
            source.gettxoutsetinfo()["hash_serialized"],
        )
        control.gettxoutsetinfo()
        results = []
        for cycle in range(self.options.crash_cycles):
            start = time.monotonic()
            txs = []
            for _ in range(self.options.transactions):
                txs.append(wallet.create_self_transfer(utxo_to_spend=funding.pop()))
            submitted = source.rpc.batch(
                [
                    {
                        "jsonrpc": "2.0",
                        "id": i,
                        "method": "sendrawtransaction",
                        "params": [tx["hex"], 0],
                    }
                    for i, tx in enumerate(txs)
                ]
            )
            assert_equal(len(submitted), len(txs))
            assert all(item.get("error") is None for item in submitted), submitted
            # A partially accepted batch would invalidate the heavy-connect claim.
            assert_equal(source.getmempoolinfo()["size"], len(txs))
            blockhash = self.generate(wallet, 1, sync_fun=self.no_op)[0]
            raw = source.getblock(blockhash, False)
            producer_seconds = time.monotonic() - start
            connect_start = time.monotonic()
            assert_equal(control.submitblock(raw), None)
            connect_seconds = time.monotonic() - connect_start
            # Pause at an exact future height inside ConnectBlock. A log
            # marker alone is otherwise racy with the asynchronous logger.
            crash_height = source.getblockcount()
            self.restart_node(
                1,
                extra_args=[
                    *self.extra_args[1],
                    f"-testblockconnectpauseheight={crash_height}",
                ],
            )
            started = threading.Event()
            errors = []

            def connect():
                started.set()
                try:
                    target.submitblock(raw)
                except Exception as err:
                    errors.append(type(err).__name__)

            log_offset = target.debug_log_size()
            worker = threading.Thread(target=connect)
            worker.start()
            assert started.wait(10)
            deadline = time.monotonic() + 10
            connect_phase_seen = False
            while worker.is_alive() and time.monotonic() < deadline:
                with open(target.debug_log_path, "rb") as log:
                    log.seek(log_offset)
                    connect_phase_seen = (
                        f"Pausing block connection at test height {crash_height}".encode()
                        in log.read()
                    )
                if connect_phase_seen:
                    break
                time.sleep(0.0005)
            delay = 0
            connect_in_flight = worker.is_alive()
            assert connect_phase_seen and connect_in_flight
            target.process.kill()
            target.process.wait(timeout=30)
            worker.join(timeout=30)
            assert not worker.is_alive()
            target.running = False
            target.rpc_connected = False
            target.process = None
            self.start_node(1)
            recovered_height = target.getblockcount()
            assert target.verifychain(4, 0)
            # Recover/continue by submitting the same already-known valid block;
            # no -reindex, alternate datadir, or copy of the producer DB is used.
            response = target.submitblock(raw)
            assert response in (None, "duplicate"), response
            assert_equal(target.getbestblockhash(), source.getbestblockhash())
            assert target.verifychain(4, 0)
            assert_equal(
                target.gettxoutsetinfo()["hash_serialized"],
                source.gettxoutsetinfo()["hash_serialized"],
            )
            results.append(
                {
                    "cycle": cycle,
                    "tx_count": len(txs),
                    "raw_bytes": len(raw) // 2,
                    "kill_delay_s": delay,
                    "connect_in_flight": connect_in_flight,
                    "connect_phase_seen": connect_phase_seen,
                    "recovered_height": recovered_height,
                    "rpc_errors": errors,
                    "producer_ingest_and_mine_s": producer_seconds,
                    "control_connect_s": connect_seconds,
                    "control_connect_tps": len(txs) / connect_seconds,
                    "verifychain": True,
                    "continued": True,
                }
            )
        result_path = (
            Path(self.options.result_json)
            if self.options.result_json
            else (Path(self.options.tmpdir) / "mdbx-crash-results.json")
        )
        result_path.write_text(json.dumps(results, indent=2) + "\n")
        assert all(
            item["connect_in_flight"] and item["connect_phase_seen"] for item in results
        )


if __name__ == "__main__":
    MdbxCrashTest().main()
