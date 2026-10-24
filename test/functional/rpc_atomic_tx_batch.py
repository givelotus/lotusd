#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Atomic raw batches preserve ABC validation and relay dependency chains."""

import copy
import time
from decimal import Decimal

from test_framework.currency import RpcCurrency
from test_framework.key import ECKey
from test_framework.script import CScript
from test_framework.signature_hash import (
    SIGHASH_ALL,
    SIGHASH_FORKID,
    SignatureHashForkId,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode


class AtomicTxBatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        # This test explicitly verifies shorttx; override the framework's
        # compatibility default that disables that path for legacy fixtures.
        self.extra_args = [
            [
                "-avalanche=0",
                "-highbandwidthtx=1",
                "-txrelaypushhb=1",
                "-testdisablehighbandwidthshorttx=0",
            ],
            [
                "-avalanche=0",
                "-highbandwidthtx=1",
                "-txrelaypushhb=1",
                "-testdisablehighbandwidthshorttx=0",
            ],
        ]

    def run_test(self):
        node, peer = self.nodes
        currency = RpcCurrency.from_node(node)
        wallet = MiniWallet(node)
        self.generate(wallet, 102)
        chain = wallet.create_self_transfer_chain(chain_length=40)
        raw = [tx["hex"] for tx in chain]
        ids = [tx["txid"] for tx in chain]
        tested = node.testrawtxbatch(raw, 0)
        assert tested["allowed"]
        assert_equal(len(tested["results"]), len(raw))
        assert all(result["allowed"] for result in tested["results"])
        assert_equal(node.getrawmempool(), [])

        bad = copy.deepcopy(chain[-1]["tx"])
        bad.vin[0].prevout.txid = 42
        for batch in (
            [raw[0], bad.serialize().hex()],
            list(reversed(raw)),
            [raw[0], raw[0]],
        ):
            assert not node.submitrawtxbatch(batch, 0)["accepted"]
            assert_equal(node.getrawmempool(), [])
        assert not node.submitrawtxbatch(raw, Decimal("0.01"))["accepted"]
        assert_equal(node.getrawmempool(), [])
        malformed = raw.copy()
        malformed[7] = "badhex-at-seven"
        malformed[35] = "badhex-at-thirtyfive"
        assert_raises_rpc_error(
            -22,
            "TX decode failed: badhex-at-seven",
            node.submitrawtxbatch,
            malformed,
            0,
        )
        assert_equal(node.getrawmempool(), [])
        now = int(time.time())
        for relay_node in self.nodes:
            relay_node.setmocktime(now)
        with node.assert_debug_log(["sending shorttx"]):
            submitted = node.submitrawtxbatch(raw, 0)
            # Give local-origin transactions a real relay opportunity without
            # bypassing the normal privacy-preserving inventory timer.
            for relay_node in self.nodes:
                relay_node.bumpmocktime(60)
        assert submitted["accepted"]
        assert_equal(submitted["txids"], ids)
        self.sync_mempools()
        assert_equal(sorted(node.getrawmempool()), sorted(ids))
        assert_equal(sorted(peer.getrawmempool()), sorted(ids))
        template = node.getblocktemplate()
        assert_equal(sorted(tx["txid"] for tx in template["transactions"]), sorted(ids))
        self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])
        assert_equal(peer.getrawmempool(), [])

        # Exercise the deferred Schnorr path with enough transactions to run
        # multiple script workers. A bad final signature must publish nothing.
        signing_wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        self.generate(signing_wallet, 101)
        key = ECKey()
        key.set((1).to_bytes(32, "big"), True)
        utxo = signing_wallet.get_utxo()
        signed = []
        signed_ids = []
        signed_txs = []
        sighash_type = SIGHASH_ALL | SIGHASH_FORKID
        for _ in range(40):
            transfer = signing_wallet.create_self_transfer(utxo_to_spend=utxo)
            tx = transfer["tx"]
            digest = SignatureHashForkId(
                signing_wallet.get_scriptPubKey(),
                tx,
                0,
                sighash_type,
                currency.to_atoms(utxo["value"]),
            )
            signature = key.sign_schnorr(digest) + bytes([sighash_type])
            tx.vin[0].scriptSig = CScript([signature])
            signed.append(tx.serialize().hex())
            signed_ids.append(tx.txid_hex)
            signed_txs.append(tx)
            utxo = dict(transfer["new_utxo"], txid=tx.txid_hex)
        bad_signature = copy.deepcopy(signed_txs[-1])
        corrupt = bytearray(bad_signature.vin[0].scriptSig)
        corrupt[10] ^= 1
        bad_signature.vin[0].scriptSig = bytes(corrupt)
        rejected = node.submitrawtxbatch(
            signed[:-1] + [bad_signature.serialize().hex()], 0
        )
        assert not rejected["accepted"]
        assert_equal(node.getrawmempool(), [])
        assert_equal(peer.getrawmempool(), [])
        assert node.testrawtxbatch(signed, 0)["allowed"]
        assert_equal(node.getrawmempool(), [])
        assert node.submitrawtxbatch(signed, 0)["accepted"]
        for relay_node in self.nodes:
            relay_node.bumpmocktime(60)
        self.sync_mempools()
        assert_equal(sorted(node.getrawmempool()), sorted(signed_ids))
        assert_equal(sorted(peer.getrawmempool()), sorted(signed_ids))
        self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])
        assert_equal(peer.getrawmempool(), [])


if __name__ == "__main__":
    AtomicTxBatchTest().main()
