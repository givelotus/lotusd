#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the validation and UTXO metrics at /metrics: block validation stages,
script checks, validation caches, the UTXO cache and its flushes, reorgs,
invalid and parked blocks."""

import time

from test_framework.blocktools import create_block, create_coinbase
from test_framework.metrics import m, scrape
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode

STAGES = (
    "check",
    "forks",
    "connect",
    "verify",
    "index",
    "load",
    "flush",
    "chainstate",
    "post_connect",
)


class ValidationMetricsTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    extra_args = [["-metrics"]]

    def fresh_scrape(self):
        """A scrape past the one-second rendering cache"""
        time.sleep(1.05)
        return scrape(self.nodes[0])

    def submit_block_with(self, node, txs, coinbase_value=None):
        """Mine a block with txs on the tip and submit it; return the result"""
        tip = node.getbestblockhash()
        height = node.getblockcount()
        coinbase = (
            create_coinbase(height + 1)
            if coinbase_value is None
            else create_coinbase(height + 1, nValue=coinbase_value)
        )
        block = create_block(
            int(tip, 16),
            coinbase,
            node.getblock(tip)["time"] + 1,
            txlist=txs,
        )
        block.solve()
        return node.submitblock(block.serialize().hex())

    def delta(self, after, before, name, **labels):
        return after.total(name, **labels) - before.total(name, **labels)

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)

        before = self.fresh_scrape()
        assert_equal(
            before.label_values(m("block_validation_stage_seconds_count"), "stage"),
            set(STAGES),
        )

        self.log.info("Every stage of each connected block is timed")
        self.generate(wallet, 110)
        s = self.fresh_scrape()
        for stage in STAGES:
            assert_equal(
                self.delta(
                    s, before, m("block_validation_stage_seconds_count"), stage=stage
                ),
                110,
            )
        assert s.total(m("block_validation_stage_seconds_sum")) > 0

        self.log.info("UTXO cache size and entries")
        assert s.value(m("utxo_cache_entries")) > 0
        assert s.value(m("utxo_cache_bytes")) > 0

        self.log.info("Scripts of a block's unseen transaction are checked")
        before = s
        # In the mempool: its scripts are cached when the block connects
        seen = wallet.send_self_transfer(from_node=node)
        # Not in the mempool: checked by the block
        unseen = wallet.create_self_transfer()
        # Submitted directly: generateblock's validity check would cache
        # its scripts first.
        assert_equal(self.submit_block_with(node, [seen["tx"], unseen["tx"]]), None)
        s = self.fresh_scrape()
        assert self.delta(s, before, m("script_check_transactions_count")) >= 1
        assert self.delta(s, before, m("script_check_transactions_sum")) >= 1
        assert self.delta(s, before, m("script_check_workers_count")) >= 1
        name = m("validation_cache_lookups_total")
        assert self.delta(s, before, name, cache="signature", result="miss") >= 1
        assert self.delta(s, before, name, cache="script_execution", result="hit") >= 1
        assert self.delta(s, before, name, cache="script_execution", result="miss") >= 1

        self.log.info("A full flush empties the UTXO cache; lookups then miss")
        before = s
        node.gettxoutsetinfo()  # flushes the chainstate
        s = self.fresh_scrape()
        assert (
            self.delta(s, before, m("utxo_cache_flush_seconds_count"), mode="flush")
            >= 1
        )
        utxo = wallet.get_utxo(mark_as_spent=False)
        assert node.gettxout(utxo["txid"], utxo["vout"]) is not None
        assert node.gettxout("00" * 32, 0) is None
        s2 = self.fresh_scrape()
        name = m("utxo_cache_lookups_total")
        assert self.delta(s2, s, name, result="miss") >= 1
        assert self.delta(s2, s, name, result="absent") >= 1
        assert s2.total(name, result="hit") > 0

        self.log.info("A reorg of depth 1")
        before = s2
        tip = node.getbestblockhash()
        tip_height = node.getblockcount()
        self.generate(node, 1)
        node.invalidateblock(tip)
        self.generate(node, 1)  # a competing block at tip's height
        node.reconsiderblock(tip)  # tip's branch is longer: reorg
        self.wait_until(lambda: node.getblockcount() == tip_height + 1)
        s = self.fresh_scrape()
        assert_equal(self.delta(s, before, m("chain_reorgs_total")), 1)
        assert_equal(self.delta(s, before, m("chain_reorg_depth_blocks_count")), 1)
        assert_equal(
            self.delta(s, before, m("chain_reorg_depth_blocks_bucket"), le="1"), 1
        )
        assert_equal(
            self.delta(s, before, m("blocks_invalid_total"), source="invalidateblock"),
            1,
        )

        self.log.info("A block invalid by consensus, and a parked block")
        before = s
        assert_equal(
            self.submit_block_with(node, [], coinbase_value=10**12), "bad-cb-amount"
        )
        node.parkblock(node.getbestblockhash())
        s = self.fresh_scrape()
        assert_equal(
            self.delta(s, before, m("blocks_invalid_total"), source="validation"), 1
        )
        assert_equal(
            self.delta(s, before, m("blocks_parked_total"), reason="requested"), 1
        )
        assert_equal(
            s.label_values(m("blocks_parked_total"), "reason"),
            {"policy", "finalization_conflict", "deep_reorg", "requested"},
        )


if __name__ == "__main__":
    ValidationMetricsTest().main()
