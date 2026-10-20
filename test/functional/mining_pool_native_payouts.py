#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Pool jobs require explicit native recipients, whose rewards actually spend."""

from test_framework.address import ADDRESS_ECREG_UNSPENDABLE
from test_framework.key import ECKey
from test_framework.messages import (
    CBlockHeader,
    COutPoint,
    CTransaction,
    FromHex,
    blake3_single_chunk,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.v7tx import (
    V2_OP_TRUE,
    bip340_sign,
    coin_of,
    new_v7_tx,
    signing_message,
    v2_op_true_txout,
    v7_input,
)
from test_framework.xpiaddr import encode


def native_identity(number):
    secret = number.to_bytes(32, "big")
    key = ECKey()
    key.set(secret, True)
    xonly = key.get_pubkey().get_bytes()[1:]
    keyhash = blake3_single_chunk(xonly)
    program = bytes.fromhex("7aba20") + keyhash + bytes.fromhex("92bb")
    return encode("rxpi", keyhash, 1), secret, xonly, program


def solve_pool_job(node, job, worker):
    header = FromHex(CBlockHeader(), job["header_hex"])
    target = int(job["network_target"], 16)
    for local_nonce in range(1, 10_000):
        header.nNonce = (job["nonce_prefix"] << 40) | local_nonce
        if header.hash_int <= target:
            result = node.submitminingshare(job["job_id"], worker, header.nNonce)
            assert result["accepted"] and result["block_found"], result
            return result["block_hash"]
    raise AssertionError("No network solution found")


def signed_spend(coinbase, index, identity):
    _, secret, xonly, program = identity
    coin = coinbase.vout[index]
    tx = new_v7_tx()
    tx.vin = [v7_input(COutPoint(coinbase.txid_int, index), program, [b"", xonly])]
    tx.vout = [v2_op_true_txout(coin.nValue - 10_000)]
    digest = signing_message(tx, [coin_of(coin)], 0, 0)
    tx.vin[0].vWitnesses = [(program, [], [bip340_sign(secret, digest), xonly])]
    return tx


class MiningPoolNativePayoutTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.identity = native_identity(1)
        self.extra_args = [[f"-pooladdress={self.identity[0]}", "-gbtwithoutpeers=1"]]

    def run_test(self):
        node = self.nodes[0]
        # Before-control: inherited pool instead constructs a legacy CTxOut,
        # and the native-output guard rejects this actual public job request.
        job = node.getminingjob(self.identity[0])
        assert node.getpoolinfo()["payout_ready"]
        coinbase = FromHex(CTransaction(), job["coinbase_tx_hex"])
        assert_equal(coinbase.nVersion, 7)
        block = solve_pool_job(node, job, self.identity[0])
        assert_equal(node.getblock(block)["tx"][0], coinbase.txid_hex)
        spend = signed_spend(coinbase, 0, self.identity)
        assert not node.testmempoolaccept([spend.serialize().hex()])[0]["allowed"]
        node.rpc.generatetoaddress(100, self.identity[0], 1_000_000, 7)
        assert_equal(node.sendrawtransaction(spend.serialize().hex()), spend.txid_hex)
        mined = node.rpc.generatetoaddress(1, self.identity[0], 1_000_000, 7)[0]
        assert spend.txid_hex in node.getblock(mined)["tx"]

        self.log.info("First pool job materializes a deferred nonempty snapshot")
        # Funding is confirmed before the pending set exists. Nothing calls GBT
        # between admitting these independent children and requesting the job.
        count, fee = 65, 10_000
        value = (spend.vout[0].nValue - fee) // count
        funding = new_v7_tx()
        funding.vin = [v7_input(COutPoint(spend.txid_int, 0), V2_OP_TRUE)]
        funding.vout = [v2_op_true_txout(value) for _ in range(count)]
        node.sendrawtransaction(funding.serialize().hex())
        node.rpc.generatetoaddress(1, self.identity[0], 1_000_000, 7)
        empty_job = node.getminingjob(self.identity[0])
        empty_reward = sum(
            output.nValue
            for output in FromHex(CTransaction(), empty_job["coinbase_tx_hex"]).vout
        )
        pending = []
        for index in range(count):
            child = new_v7_tx()
            child.vin = [v7_input(COutPoint(funding.txid_int, index), V2_OP_TRUE)]
            child.vout = [v2_op_true_txout(value - fee)]
            pending.append(node.sendrawtransaction(child.serialize().hex()))
        assert_equal(len(node.getrawmempool()), count)
        first_job = node.getminingjob(self.identity[0])
        first_coinbase = FromHex(CTransaction(), first_job["coinbase_tx_hex"])
        assert_equal(sum(out.nValue for out in first_coinbase.vout),
                     empty_reward + count * fee)
        # Acceptance verifies the job's transaction/state commitments; its saved
        # transaction list must contain the pending set without a GBT warm-up.
        first_block = solve_pool_job(node, first_job, self.identity[0])
        assert_equal(set(node.getblock(first_block)["tx"][1:]), set(pending))
        assert_equal(node.getrawmempool(), [])

        for address in [
            None,
            "invalid",
            ADDRESS_ECREG_UNSPENDABLE,
            encode("xpi", bytes(32), 1),
        ]:
            args = [] if address is None else [f"-pooladdress={address}"]
            self.restart_node(0, args)
            assert node.getpoolinfo()["enabled"]
            assert not node.getpoolinfo()["payout_ready"]
            assert_raises_rpc_error(
                None, "Native pool requires an explicit", node.getminingjob
            )
            assert_equal(node.getpoolinfo()["active_workers"], 0)
        # Explicit legacy mining retains its own semantics.
        legacy = node.rpc.generatetoaddress(1, ADDRESS_ECREG_UNSPENDABLE, 1_000_000, 2)[
            0
        ]
        assert_equal(node.getblock(legacy, 2)["tx"][0]["version"], 2)


if __name__ == "__main__":
    MiningPoolNativePayoutTest().main()
