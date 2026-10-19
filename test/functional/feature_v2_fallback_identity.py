#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a version 7 transaction without a V2 structure does not exist.

Such a transaction has no structural identity, so the node refuses to decode
it (bad-txns-v2-identity): it is never named, and so it can never poison a
reject-cache entry for another transaction. (Before T1 it was named by a
fallback hash of its complete serialization.)
"""

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import OP_TRUE, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


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
        for script_sig in (b"", b"\x51", b"\x51\x51", b"\x52"):
            raw = duplicate_input_tx(script_sig).serialize().hex()
            self.log.info(f"witness script {script_sig.hex() or '-'} is refused")
            assert_raises_rpc_error(
                -22, "TX decode failed", node.testmempoolaccept, [raw]
            )
            assert_raises_rpc_error(
                -22, "TX decode failed", node.decoderawtransaction, raw
            )
            assert_raises_rpc_error(
                -22, "TX decode failed", node.sendrawtransaction, raw
            )


if __name__ == "__main__":
    V2FallbackIdentityTest().main()
