#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native mining must never reinterpret a legacy address as native bytecode."""

from pathlib import Path

from test_framework.address import ADDRESS_ECREG_UNSPENDABLE
from test_framework.key import ECKey
from test_framework.messages import (
    COutPoint,
    CTransaction,
    FromHex,
    blake3_single_chunk,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.v7tx import (
    bip340_sign,
    coin_of,
    new_v7_tx,
    signing_message,
    v2_op_true_txout,
    v7_input,
)
from test_framework.xpiaddr import encode


class NativePayoutTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-gbtwithoutpeers=1"]]

    def setup_nodes(self):
        # Exercise the product default, not the inherited legacy fixture default.
        config = Path(self.options.tmpdir) / "node0" / "lotusd.conf"
        text = config.read_text(encoding="utf-8")
        assert "coinbaseversion=2\n" in text
        config.write_text(text.replace("coinbaseversion=2\n", ""), encoding="utf-8")
        super().setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        legacy = ADDRESS_ECREG_UNSPENDABLE  # No wallet/private-key lookup.
        height = node.getblockcount()
        assert_raises_rpc_error(
            -5,
            "Native coinbase requires a native address",
            node.rpc.generatetoaddress,
            1,
            legacy,
        )
        assert_equal(node.getblockcount(), height)
        assert_raises_rpc_error(
            -5,
            "Native coinbase requires a native address",
            node.rpc.generatetoaddress,
            1,
            legacy,
            1_000_000,
            7,
        )
        assert_raises_rpc_error(
            -5,
            "Legacy descriptors are unsupported",
            node.rpc.generatetodescriptor,
            1,
            f"addr({legacy})",
        )
        assert_raises_rpc_error(
            -5,
            "Native coinbase requires a native address",
            node.rpc.generateblock,
            legacy,
            [],
            7,
        )
        assert_raises_rpc_error(
            -5,
            "Native coinbase requires a native address",
            node.getblocktemplate,
            {"mineraddress": legacy, "coinbase_version": 7},
        )
        assert_raises_rpc_error(
            -5,
            "Native coinbase requires a native address",
            node.getrawunsolvedblock,
            legacy,
        )
        assert_equal(node.getblockcount(), height)

        self.log.info("Explicit legacy coinbase2 keeps legacy address semantics")
        block = node.rpc.generatetoaddress(1, legacy, 1_000_000, 2)[0]
        assert_equal(node.getblock(block, 2)["tx"][0]["version"], 2)

        self.restart_node(0, extra_args=["-coinbaseversion=2", "-gbtwithoutpeers=1"])
        block = node.rpc.generatetoaddress(1, legacy)[0]
        assert_equal(node.getblock(block, 2)["tx"][0]["version"], 2)
        assert_raises_rpc_error(
            -5,
            "Native coinbase requires a native address",
            node.rpc.generatetoaddress,
            1,
            legacy,
            1_000_000,
            7,
        )
        self.restart_node(0)

        self.log.info("A typed native keyhash payout matures and spends natively")
        secret = (1).to_bytes(32, "big")
        key = ECKey()
        key.set(secret, True)
        xonly = key.get_pubkey().get_bytes()[1:]
        keyhash = blake3_single_chunk(xonly)
        program = bytes.fromhex("7aba20") + keyhash + bytes.fromhex("92bb")
        native = encode("rxpi", keyhash, 1)
        assert_raises_rpc_error(
            -5,
            "Native coinbase requires a native address",
            node.rpc.generatetoaddress,
            1,
            encode("xpi", keyhash, 1),
        )
        blocks = node.rpc.generatetoaddress(101, native)
        cbid = node.getblock(blocks[0])["tx"][0]
        coinbase = FromHex(
            CTransaction(), node.getrawtransaction(cbid, False, blocks[0])
        )
        assert_equal(coinbase.nVersion, 7)
        coin = coinbase.vout[0]
        tx = new_v7_tx()
        tx.vin = [v7_input(COutPoint(int(cbid, 16), 0), program, [b"", xonly])]
        tx.vout = [v2_op_true_txout(coin.nValue - 10_000)]
        digest = signing_message(tx, [coin_of(coin)], 0, 0)
        signature = bip340_sign(secret, digest)
        wrong = bip340_sign((2).to_bytes(32, "big"), digest)
        tx.vin[0].vWitnesses = [(program, [], [wrong, xonly])]
        assert not node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]
        tx.vin[0].vWitnesses = [(program, [], [signature, xonly])]
        txid = node.sendrawtransaction(tx.serialize().hex())
        assert_equal(txid, tx.txid_hex)
        block = node.rpc.generatetoaddress(1, native)[0]
        assert txid in node.getblock(block)["tx"]
        self.restart_node(0)
        assert_equal(node.getblockhash(node.getblockcount()), block)
        assert node.verifychain(3, 10)


if __name__ == "__main__":
    NativePayoutTest().main()
