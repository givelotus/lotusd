# Copyright (c) 2023 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test Chronik's /raw-tx/:txid endpoint.
"""

from test_framework.address import (
    ADDRESS_ECREG_UNSPENDABLE,
    SCRIPTSIG_OP_TRUE,
)
from test_framework.blocktools import GENESIS_CB_TXID
from test_framework.hash import hash160
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import OP_EQUAL, OP_HASH160, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ChronikRawTxTest(BitcoinTestFramework):
    setup_clean_chain = True
    num_nodes = 1
    extra_args = [["-chronik"]]
    rpc_timeout = 240

    requires = {"chronik"}

    def run_test(self):
        node = self.nodes[0]
        chronik = node.get_chronik_client()

        assert_equal(chronik.tx("0").err(400).msg, "400: Not a txid: 0")
        assert_equal(chronik.tx("123").err(400).msg, "400: Not a txid: 123")
        assert_equal(chronik.tx("1234f").err(400).msg, "400: Not a txid: 1234f")
        assert_equal(
            chronik.tx("00" * 31).err(400).msg, f"400: Not a txid: {'00' * 31}"
        )
        assert_equal(chronik.tx("01").err(400).msg, "400: Not a txid: 01")
        assert_equal(
            chronik.tx("12345678901").err(400).msg, "400: Not a txid: 12345678901"
        )

        assert_equal(
            chronik.tx("00" * 32).err(404).msg,
            f"404: Transaction {'00' * 32} not found in the index",
        )

        from test_framework.chronik.client import pb

        # Verify queried genesis tx matches
        # Note: unlike getrawtransaction, this also works on the Genesis coinbase
        assert_equal(
            chronik.raw_tx(GENESIS_CB_TXID).ok(),
            pb.RawTx(
                raw_tx=bytes.fromhex(
                    "070000000000000000000000010001000000000000000000000000000000000000000000"
                    "000000000000000000000000ffffffffffffffff02014d04ffff001d0104455468652054"
                    "696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b"
                    "206f66207365636f6e64206261696c6f757420666f722062616e6b730000f2052a010000"
                    "0001561d9ddd71993c64a52f315a49d86f0eb2c584c0797be784cd69e4c2494d454b0101"
                    "00"
                )
            ),
        )

        cointx, coinvalue = self.mine_mature_coin(node)

        send_values = [coinvalue - 10000, 1000, 2000, 3000]
        send_redeem_scripts = [bytes([i + 0x52]) for i in range(len(send_values))]
        send_scripts = [
            CScript([OP_HASH160, hash160(redeem_script), OP_EQUAL])
            for redeem_script in send_redeem_scripts
        ]
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [
            CTxIn(
                outpoint=COutPoint(int(cointx, 16), 0),
                scriptSig=SCRIPTSIG_OP_TRUE,
                nSequence=0xFFFFFFFE,
            )
        ]
        tx.vout = [
            CTxOut(value, script) for (value, script) in zip(send_values, send_scripts)
        ]
        tx.nLockTime = 1234567890

        # Submit tx to mempool
        raw_tx = tx.serialize()
        txid = node.sendrawtransaction(raw_tx.hex())
        assert_equal(chronik.raw_tx(txid).ok(), pb.RawTx(raw_tx=raw_tx))

        # Mined block still works
        self.generatetoaddress(node, 1, ADDRESS_ECREG_UNSPENDABLE)
        assert_equal(chronik.raw_tx(txid).ok(), pb.RawTx(raw_tx=raw_tx))


if __name__ == "__main__":
    ChronikRawTxTest().main()
