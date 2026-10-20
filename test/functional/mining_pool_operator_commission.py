#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact operator commission conserves rewards and pays spendable native coins."""

from mining_pool_native_payouts import native_identity, signed_spend, solve_pool_job
from test_framework.messages import CTransaction, FromHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


class MiningPoolOperatorCommissionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.operator = native_identity(1)
        self.worker = native_identity(2)
        self.extra_args = [
            [
                f"-pooladdress={self.operator[0]}",
                "-poolfeepercent=1.25",
                "-gbtwithoutpeers=1",
            ]
        ]

    def run_test(self):
        node = self.nodes[0]
        info = node.getpoolinfo()
        assert_equal(info["operator_fee_bps"], 125)
        assert_equal(info["operator_address"], self.operator[0])
        job = node.getminingjob(self.worker[0])
        assert_equal(job["operator_fee_bps"], 125)
        assert_equal(job["operator_address"], self.operator[0])
        coinbase = FromHex(CTransaction(), job["coinbase_tx_hex"])
        assert_equal(len(coinbase.vout), 2)
        total = sum(output.nValue for output in coinbase.vout)
        assert_equal(job["operator_commission_sats"], total * 125 // 10000)
        assert_equal(job["worker_reward_sats"], total - job["operator_commission_sats"])
        assert_equal(coinbase.vout[0].nValue, job["worker_reward_sats"])
        assert_equal(coinbase.vout[1].nValue, job["operator_commission_sats"])
        for output, advertised in zip(coinbase.vout, job["coinbase_outputs"]):
            assert_equal(advertised["value_sats"], output.nValue)
        block = solve_pool_job(node, job, self.worker[0])
        assert_equal(node.getblock(block)["tx"][0], coinbase.txid_hex)
        spends = [
            signed_spend(coinbase, 0, self.worker),
            signed_spend(coinbase, 1, self.operator),
        ]
        for tx in spends:
            assert not node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]
        node.rpc.generatetoaddress(100, self.operator[0], 1_000_000, 7)
        wrong = signed_spend(coinbase, 0, self.operator)
        assert not node.testmempoolaccept([wrong.serialize().hex()])[0]["allowed"]
        for tx in spends:
            assert_equal(node.sendrawtransaction(tx.serialize().hex()), tx.txid_hex)
        mined = node.rpc.generatetoaddress(1, self.operator[0], 1_000_000, 7)[0]
        for tx in spends:
            assert tx.txid_hex in node.getblock(mined)["tx"]

        self.log.info("Stock network-section configuration and CLI precedence")
        self.stop_node(0)
        with open(node.bitcoinconf, "a", encoding="utf-8") as config:
            config.write(
                f"\n[regtest]\npooladdress={self.operator[0]}\npoolfeepercent=2.50\n"
            )
        self.start_node(0, ["-poolfeepercent=0"])
        assert_equal(node.getpoolinfo()["operator_fee_bps"], 0)
        zero = node.getminingjob(self.worker[0])
        assert_equal(zero["operator_commission_sats"], 0)
        assert_equal(zero["operator_address"], "")
        assert_equal(len(FromHex(CTransaction(), zero["coinbase_tx_hex"]).vout), 1)
        self.restart_node(0, [])
        assert_equal(node.getpoolinfo()["operator_fee_bps"], 250)
        self.restart_node(0, ["-poolfeepercent=100"])
        all_fee = node.getminingjob(self.worker[0])
        assert_equal(all_fee["worker_reward_sats"], 0)
        assert_equal(len(FromHex(CTransaction(), all_fee["coinbase_tx_hex"]).vout), 1)
        self.stop_node(0)
        for invalid in ["-1", "100.01", "1.234", "NaN"]:
            node.assert_start_raises_init_error(
                extra_args=[f"-poolfeepercent={invalid}"],
                expected_msg="Pool fee percent must be 0..100 with at most two decimal places",
                match=ErrorMatch.PARTIAL_REGEX,
            )
        self.start_node(0, [])
        assert node.verifychain(3, 10)


if __name__ == "__main__":
    MiningPoolOperatorCommissionTest().main()
