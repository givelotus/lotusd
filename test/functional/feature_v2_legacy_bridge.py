#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A full migration of legacy coins to V2 through the legacy bridge.

1. Legacy coinbases (regtest only) fund a P2PKH coin, a 2-of-3 P2SH coin, a
   P2PK coin and a 25-deep chain of legacy transactions, relayed and mined.
2. Version 7 transactions spend the P2PKH coin (P2PKH bridge, modes 0 and
   1), the P2SH coin (P2SH bridge) and legacy MiniWallet coins
   (P2SH(OP_TRUE) bridge), creating V2 outputs.
3. Those V2 outputs are spent natively.

Also: a legacy transaction cannot spend a V2 coin; a non-template legacy
coin (P2PK) is unspendable by v7 but spendable by a legacy transaction; a
reorg across the bridge block restores the legacy coins; a restart keeps
the coins and the UTXO set hash.
"""

from test_framework.hash import hash160
from test_framework.key import ECKey
from test_framework.messages import XEC, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import (
    OP_2,
    OP_3,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_EQUAL,
    OP_HASH160,
    CScript,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx, sign_input
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.v7tx import (
    V2_OP_TRUE,
    LegacyCoin,
    LegacyMiniWallet,
    MiniWalletV7,
    coin_of,
    new_v7_tx,
    p2pkh_bridge_input,
    p2pkh_script,
    p2sh_bridge_input,
    p2sh_bridge_signature,
    sign_p2pkh_bridge,
    v2_op_true_txout,
    v7_input,
)

FEE = 10000


def key(n):
    k = ECKey()
    k.set(n.to_bytes(32, "big"), True)
    return k


def p2sh_script(redeem):
    return CScript([OP_HASH160, hash160(bytes(redeem)), OP_EQUAL])


class V2LegacyBridgeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Node 1 mines version 7 coinbases (the framework default is legacy).
        self.extra_args = [[], ["-coinbaseversion=7"]]

    def send(self, tx):
        txid = self.nodes[0].sendrawtransaction(tx.serialize().hex())
        assert_equal(txid, tx.txid_hex)
        return txid

    def run_test(self):
        node = self.nodes[0]
        # The framework's MiniWallet is a V2 wallet; the legacy coins come
        # from the legacy MiniWallet of v7tx.
        wallet = LegacyMiniWallet(node)
        self.generate(wallet, 120)

        self.log.info("Fund P2PKH, 2-of-3 P2SH and P2PK legacy coins")
        k1, k2, k3, k4 = key(11), key(12), key(13), key(14)
        p2pkh = p2pkh_script(k1.get_pubkey().get_bytes())
        redeem = CScript(
            [
                OP_2,
                k2.get_pubkey().get_bytes(),
                k3.get_pubkey().get_bytes(),
                k4.get_pubkey().get_bytes(),
                OP_3,
                OP_CHECKMULTISIG,
            ]
        )
        p2sh = p2sh_script(redeem)
        p2pk = CScript([k1.get_pubkey().get_bytes(), OP_CHECKSIG])
        amount = 1_000_000 * XEC
        p2pkh_op = wallet.send_to(from_node=node, scriptPubKey=p2pkh, amount=amount)
        p2pkh_op2 = wallet.send_to(from_node=node, scriptPubKey=p2pkh, amount=amount)
        p2sh_op = wallet.send_to(from_node=node, scriptPubKey=p2sh, amount=amount)
        p2pk_op = wallet.send_to(from_node=node, scriptPubKey=p2pk, amount=amount)

        self.log.info("A 25-deep chain of legacy transactions is relayed and mined")
        chain = wallet.create_self_transfer_chain(chain_length=25)
        for t in chain:
            wallet.sendrawtransaction(from_node=node, tx_hex=t["hex"])
        self.sync_mempools()
        assert all(t["txid"] in self.nodes[1].getrawmempool() for t in chain)
        self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])

        self.log.info("P2PKH bridge spends in modes 0 and 1")
        bridged = []
        for op, mode in ((p2pkh_op, 0), (p2pkh_op2, 1)):
            tx = new_v7_tx()
            tx.vin = [
                p2pkh_bridge_input(
                    COutPoint(int(op[0], 16), op[1]), k1.get_pubkey().get_bytes()
                )
            ]
            tx.vout = [v2_op_true_txout(amount - FEE)]
            sign_p2pkh_bridge(tx, [LegacyCoin(amount, p2pkh)], 0, k1, mode)
            bridged.append(self.send(tx))

        self.log.info("P2SH 2-of-3 bridge spend")
        tx = new_v7_tx()
        tx.vin = [
            p2sh_bridge_input(
                COutPoint(int(p2sh_op[0], 16), p2sh_op[1]), bytes(redeem), []
            )
        ]
        tx.vout = [v2_op_true_txout(amount - FEE)]
        coins = [LegacyCoin(amount, p2sh)]
        sigs = [p2sh_bridge_signature(tx, coins, 0, k, 0x41) for k in (k2, k4)]
        script, siblings, _ = tx.vin[0].vWitnesses[0]
        tx.vin[0].vWitnesses[0] = (script, siblings, [b""] + sigs)
        bridged.append(self.send(tx))

        self.log.info("Legacy MiniWallet coins bridge into MiniWalletV7")
        wallet_v7 = MiniWalletV7(node)
        bridged += wallet_v7.fund_from(wallet, 3)
        self.sync_mempools()
        bridge_block = self.generate(node, 1)[0]
        block_txids = node.getblock(bridge_block)["tx"]
        assert all(txid in block_txids for txid in bridged)
        assert node.gettxout(p2pkh_op[0], p2pkh_op[1]) is None

        self.log.info("V2 outputs are spent natively")
        for _ in range(3):
            wallet_v7.send_self_transfer()
        v2_coin_op = (bridged[0], 0)
        tx = new_v7_tx()
        tx.vin = [v7_input(COutPoint(int(v2_coin_op[0], 16), 0), V2_OP_TRUE)]
        tx.vout = [v2_op_true_txout(amount - 2 * FEE)]
        self.send(tx)
        self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])

        self.log.info("A legacy transaction cannot spend a V2 coin")
        v2_utxo = wallet_v7.get_utxo()
        legacy = CTransaction()
        legacy.nVersion = 2
        legacy.vin = [CTxIn(COutPoint(int(v2_utxo["txid"], 16), v2_utxo["vout"]), b"")]
        legacy.vout = [CTxOut(v2_utxo["value"] - FEE, p2pkh)]
        pad_tx(legacy)
        assert_raises_rpc_error(
            -26,
            "bad-txns-legacy-spends-v2-coin",
            node.sendrawtransaction,
            legacy.serialize().hex(),
        )

        self.log.info("A P2PK coin is unspendable by v7 but spendable by v2")
        tx = new_v7_tx()
        tx.vin = [
            p2pkh_bridge_input(
                COutPoint(int(p2pk_op[0], 16), p2pk_op[1]), k1.get_pubkey().get_bytes()
            )
        ]
        tx.vout = [v2_op_true_txout(amount - FEE)]
        sign_p2pkh_bridge(tx, [LegacyCoin(amount, p2pk)], 0, k1, 0)
        assert_raises_rpc_error(
            -26,
            "bad-txns-v2-legacy-coin-template",
            node.sendrawtransaction,
            tx.serialize().hex(),
        )
        legacy = CTransaction()
        legacy.nVersion = 2
        legacy.vin = [CTxIn(COutPoint(int(p2pk_op[0], 16), p2pk_op[1]), b"")]
        legacy.vout = [CTxOut(amount - FEE, p2pkh)]
        pad_tx(legacy)
        sign_input(legacy, 0, p2pk, k1, amount)
        p2pk_spend = self.send(legacy)
        block = self.generate(node, 1)[0]
        assert p2pk_spend in node.getblock(block)["tx"]

        self.log.info("A reorg across the bridge block restores legacy coins")
        tip = node.getbestblockhash()
        node.invalidateblock(bridge_block)
        # The bridge transactions return to the mempool, which spends the
        # coin again; the chain state has it back.
        coin = node.gettxout(p2pkh_op[0], p2pkh_op[1], False)
        assert_equal(coin["scriptPubKey"]["hex"], bytes(p2pkh).hex())
        assert_equal(int(coin["value"] * XEC), amount)
        node.reconsiderblock(bridge_block)
        assert_equal(node.getbestblockhash(), tip)
        assert node.gettxout(p2pkh_op[0], p2pkh_op[1]) is None
        self.sync_blocks()

        self.log.info("A restart keeps the coins and the UTXO set hash")
        p2pkh_left = wallet.send_to(from_node=node, scriptPubKey=p2pkh, amount=amount)
        self.generate(node, 1)
        before = node.gettxoutsetinfo("hash_serialized")["hash_serialized"]
        self.restart_node(0)
        self.connect_nodes(0, 1)
        assert_equal(node.gettxoutsetinfo("hash_serialized")["hash_serialized"], before)
        coin = node.gettxout(p2pkh_left[0], p2pkh_left[1])
        assert_equal(coin["scriptPubKey"]["hex"], bytes(p2pkh).hex())
        # The legacy coin is still bridgeable after the reload.
        tx = new_v7_tx()
        tx.vin = [
            p2pkh_bridge_input(
                COutPoint(int(p2pkh_left[0], 16), p2pkh_left[1]),
                k1.get_pubkey().get_bytes(),
            )
        ]
        tx.vout = [v2_op_true_txout(amount - FEE)]
        sign_p2pkh_bridge(tx, [coin_of(CTxOut(amount, p2pkh))], 0, k1, 1)
        self.send(tx)
        self.sync_all()

        self.log.info("MiniWalletV7 spends version 7 coinbases")
        coinbase_wallet = MiniWalletV7(self.nodes[1])
        self.generate(coinbase_wallet, 101)
        spend = coinbase_wallet.send_self_transfer()
        self.sync_mempools()
        assert spend.txid_hex in node.getrawmempool()
        block = self.generate(self.nodes[1], 1)[0]
        assert spend.txid_hex in node.getblock(block)["tx"]


if __name__ == "__main__":
    V2LegacyBridgeTest().main()
