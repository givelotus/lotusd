#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the name of a transaction that is not a well-formed V2 structure.

Such a transaction is named by the fallback tag over the chain ID and its
complete serialization. The node and the test framework must agree on that
name, and transactions differing in any serialized field must get different
names, so rejecting one cannot poison a reject-cache entry for another.
"""

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import OP_TRUE, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def duplicate_input_tx(script_sig: bytes) -> CTransaction:
    """A version-7 legacy-framed transaction spending one outpoint twice."""
    tx = CTransaction()
    tx.nVersion = 7
    tx.vin = [
        CTxIn(COutPoint(0x11, 0), nSequence=0xFFFFFFFF),
        CTxIn(COutPoint(0x11, 0), script_sig, nSequence=0xFFFFFFFF),
    ]
    tx.vout = [CTxOut(1000, CScript([OP_TRUE]))]
    return tx


class V2FallbackIdentityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        names = set()
        for script_sig in (b"", b"\x51", b"\x51\x51", b"\x52"):
            tx = duplicate_input_tx(script_sig)
            result = node.testmempoolaccept([tx.serialize().hex()])[0]
            self.log.info(f"scriptSig {script_sig.hex() or '-'}: {result}")
            assert_equal(result["allowed"], False)
            # Node and framework name it identically.
            assert_equal(result["txid"], tx.txid_hex)
            names.add(result["txid"])
            # It never decodes into the structural identity of the node.
            assert_equal(
                node.decoderawtransaction(tx.serialize().hex())["txid"], tx.txid_hex
            )
        assert_equal(len(names), 4)


if __name__ == "__main__":
    V2FallbackIdentityTest().main()
