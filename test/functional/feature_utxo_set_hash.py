# Copyright (c) 2020-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test UTXO set hash value calculation in gettxoutsetinfo."""

from test_framework.blocktools import COINBASE_MATURITY, create_transaction
from test_framework.messages import CBlock, COutPoint, FromHex, ser_string
from test_framework.muhash import MuHash3072
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class UTXOSetHashTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True

    requires = {"wallet"}

    def test_deterministic_hash_results(self):
        self.log.info("Test deterministic UTXO set hash results")

        # These depend on the setup_clean_chain option, the chain loaded from
        # the cache
        assert_equal(
            self.nodes[0].gettxoutsetinfo()["hash_serialized"],
            "0160d9861236344c05c01f240be8378c59c981de2c4a318b54b3b194f643f27a",
        )
        assert_equal(
            self.nodes[0].gettxoutsetinfo("muhash")["muhash"],
            "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8",
        )

    def test_muhash_implementation(self):
        self.log.info("Test MuHash implementation consistency")

        node = self.nodes[0]

        # Generate 100 blocks and remove the first since we plan to spend its
        # coinbase
        block_hashes = self.generate(node, COINBASE_MATURITY, coinbase_version=2)
        blocks = [
            FromHex(CBlock(), node.getblock(block, False)) for block in block_hashes
        ]
        spending = blocks.pop(0)

        # Create a spending transaction and mine a block which includes it
        tx = create_transaction(
            node, spending.vtx[0].txid_hex, node.getnewaddress(), amount=49_000_000
        )
        txid = node.sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0)

        tx_block = self.generateblock(
            node, output=node.getnewaddress(), transactions=[txid], coinbase_version=2
        )
        blocks.append(FromHex(CBlock(), node.getblock(tx_block["hash"], False)))

        # Serialize the outputs that should be in the UTXO set and add them to
        # a MuHash object
        muhash = MuHash3072()

        for height, block in enumerate(blocks):
            # The Genesis block coinbase is not part of the UTXO set and we
            # spent the first mined block
            height += 2

            for tx in block.vtx:
                for n, tx_out in enumerate(tx.vout):
                    coinbase = (
                        1
                        if (
                            not tx.vin[0].prevout.txid
                            or getattr(tx.vin[0], "nFlags", 0) == 2
                        )
                        else 0
                    )

                    data = COutPoint(tx.txid_int, n).serialize()
                    data += (height * 2 + coinbase).to_bytes(4, "little", signed=True)
                    # Canonical LegacyCoinWire and C17a lifetime metadata,
                    # calculated from this fixture's real input/output values.
                    assert tx.nVersion in (1, 2)
                    coin_wire = b"\x80" + tx_out.serialize()
                    data += ser_string(coin_wire)
                    if coinbase:
                        fee_per_output = 0
                        lifespan = 21_024_000
                    else:
                        assert_equal(tx.txid_hex, txid)
                        assert_equal(tx.vin[0].prevout.txid, spending.vtx[0].txid_int)
                        assert_equal(tx.vin[0].prevout.n, 0)
                        fee = spending.vtx[0].vout[0].nValue - sum(
                            out.nValue for out in tx.vout
                        )
                        fee_per_output = fee // len(tx.vout)
                        lifespan = min(21_024_000, 131_400 + fee_per_output)
                    data += fee_per_output.to_bytes(8, "little")
                    data += (height + lifespan).to_bytes(8, "little")

                    muhash.insert(data)

        finalized = muhash.digest()
        node_muhash = node.gettxoutsetinfo("muhash")["muhash"]

        assert_equal(finalized[::-1].hex(), node_muhash)

    def run_test(self):
        self.test_deterministic_hash_results()
        self.test_muhash_implementation()


if __name__ == "__main__":
    UTXOSetHashTest().main()
