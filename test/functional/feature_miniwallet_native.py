#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise actual native MiniWallet outputs, witnesses, signatures and rescans."""

from copy import deepcopy
from decimal import Decimal
from io import BytesIO

from test_framework.messages import CTransaction
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.wallet import MiniWalletMode, NativeMiniWallet


class NativeMiniWalletTest(BitcoinTestFramework):
    variants = {"default": {}, "cached_chain": {"cached_chain": True}}

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-avalanche=0"]]

    def add_options(self, parser):
        parser.add_argument("--cached-chain", action="store_true")

    def setup_chain(self):
        self.setup_clean_chain = not self.options.cached_chain
        super().setup_chain()

    def check_native(self, tx):
        raw = tx.serialize()
        assert_equal(raw[:4], b"\x07\x00\x00\x00")
        assert all(i.nFlags == 1 for i in tx.vin)
        assert all(o.vBranches for o in tx.vout)
        decoded = CTransaction()
        decoded.deserialize(BytesIO(raw))
        assert_equal(decoded.serialize(), raw)
        assert_equal(decoded.txid_hex, tx.txid_hex)
        assert self.nodes[0].testrawtxbatch([raw.hex()])["allowed"]

    def run_test(self):
        node = self.nodes[0]
        wallet = NativeMiniWallet(node)
        if self.options.cached_chain:
            assert_greater_than(len(wallet.get_utxos(mark_as_spent=False)), 0)
        wallet.generate(140)
        assert_greater_than(len(wallet.get_utxos(mark_as_spent=False)), 0)
        transfer = wallet.create_self_transfer(sequence=0xFFFFFFFF)
        self.check_native(transfer["tx"])
        locked = wallet.create_self_transfer(locktime=node.getblockcount() - 1)
        self.check_native(locked["tx"])
        assert_equal(locked["tx"].nLockTime, node.getblockcount() - 1)
        assert_equal(transfer["tx"].vin[0].nSequence, 0xFFFFFFFF)
        assert_equal(transfer["fee"], Decimal(len(transfer["tx"].serialize())) * 3)
        wallet.sendrawtransaction(from_node=node, tx_hex=transfer["hex"])
        chain = wallet.send_self_transfer_chain(
            from_node=node, chain_length=3, utxo_to_spend=transfer["new_utxo"]
        )
        wallet.rescan_utxos()
        assert wallet.get_utxo(txid=chain[-1]["txid"], mark_as_spent=False)
        block = wallet.generate(1)[0]
        wallet.rescan_utxos()
        assert (
            wallet.get_utxo(txid=chain[-1]["txid"], mark_as_spent=False)[
                "confirmations"
            ]
            == 1
        )
        padded = wallet.create_self_transfer(target_size=1000)
        assert len(padded["tx"].serialize()) >= 1000
        self.check_native(padded["tx"])
        node.invalidateblock(block)
        wallet.rescan_utxos()
        assert (
            wallet.get_utxo(txid=chain[-1]["txid"], mark_as_spent=False)[
                "confirmations"
            ]
            == 0
        )
        node.reconsiderblock(block)

        signed = NativeMiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        signed.generate(102)
        inputs = signed.get_utxos(mark_as_spent=False)[:2]
        assert_equal(len(inputs), 2)
        result = signed.create_self_transfer_multi(utxos_to_spend=inputs, num_outputs=2)
        self.check_native(result["tx"])
        for index in range(2):
            broken = deepcopy(result["tx"])
            script, proof, args = broken.vin[index].vWitnesses[0]
            corrupt = bytes([args[0][0] ^ 1]) + args[0][1:]
            broken.vin[index].vWitnesses = [(script, proof, [corrupt])]
            assert not node.testrawtxbatch([broken.serialize().hex()])["allowed"]
        altered_output = deepcopy(result["tx"])
        altered_output.vout[0].nValue -= 1
        assert not node.testrawtxbatch([altered_output.serialize().hex()])["allowed"]
        signed.sendrawtransaction(from_node=node, tx_hex=result["hex"])
        signed.generate(1)
        assert_equal(node.getmempoolinfo()["size"], 0)
        unequal = signed.create_self_transfer_multi(num_outputs=2)
        unequal["tx"].vout[0].nValue -= 123
        unequal["tx"].vout[1].nValue += 123
        signed.sign_tx(unequal["tx"])
        self.check_native(unequal["tx"])
        unequal_id = signed.sendrawtransaction(
            from_node=node, tx_hex=unequal["tx"].serialize().hex()
        )
        coins = [signed.get_utxo(txid=unequal_id, vout=i) for i in range(2)]
        assert coins[0]["value"] != coins[1]["value"]
        distinct_inputs = signed.create_self_transfer_multi(
            utxos_to_spend=coins, num_outputs=2
        )
        self.check_native(distinct_inputs["tx"])
        signed.sendrawtransaction(from_node=node, tx_hex=distinct_inputs["hex"])
        signed.generate(1)
        # send_to mutates both outputs: the signed change must be re-signed.
        txid, vout = signed.send_to(
            from_node=node,
            scriptPubKey=wallet.get_scriptPubKey(),
            amount=100000,
            fee=10000,
        )
        wallet.rescan_utxos()
        received = wallet.get_utxo(txid=txid, vout=vout, mark_as_spent=False)
        assert_equal(received["value"], Decimal(1000))
        signed.generate(1)
        self.restart_node(0)
        wallet.rescan_utxos()
        assert_equal(
            wallet.get_utxo(txid=txid, vout=vout, mark_as_spent=False)["confirmations"],
            1,
        )


if __name__ == "__main__":
    NativeMiniWalletTest().main()
