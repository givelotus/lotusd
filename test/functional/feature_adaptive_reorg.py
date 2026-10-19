#!/usr/bin/env python3
"""Chain-equivalent nodes must recover identical adaptive capacity after reorg."""

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CTxOut, ToHex
from test_framework.script import OP_RETURN, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class AdaptiveReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-avalanche=0", "-snapsync=0", "-adaptiveblocksize=1"]] * 2

    def run_test(self):
        a, b = self.nodes
        wallet = MiniWallet(a)
        self.generate(wallet, 131)
        self.disconnect_nodes(0, 1)
        parent = a.getbestblockhash()
        now = a.getblockheader(parent)["time"] + 1
        txs = []
        for _ in range(31):
            tx = wallet.create_self_transfer(fee_rate=0)["tx"]
            tx.vout.extend(
                CTxOut(0, CScript([OP_RETURN, b"x" * 9990])) for _ in range(90)
            )
            txs.append(tx)
        orphan = create_block(int(parent, 16), create_coinbase(132), now, txlist=txs)
        orphan.solve()
        assert_equal(a.submitblock(ToHex(orphan)), None)
        grown = a.getfeerateinfo()["ema_block_size_bytes"]
        assert grown > b.getfeerateinfo()["ema_block_size_bytes"]
        a.invalidateblock(orphan.hash_hex)
        for height in (132, 133):
            block = create_block(int(parent, 16), create_coinbase(height), now + height)
            block.solve()
            raw = ToHex(block)
            assert_equal(a.submitblock(raw), None)
            assert_equal(b.submitblock(raw), None)
            parent = block.hash_hex
        assert_equal(a.getbestblockhash(), b.getbestblockhash())
        keys = (
            "ema_block_size_bytes",
            "adaptive_target_block_size",
            "adaptive_max_block_size",
        )
        for key in keys:
            assert_equal(a.getfeerateinfo()[key], b.getfeerateinfo()[key])
        expected = {key: a.getfeerateinfo()[key] for key in keys}
        self.restart_node(0)
        for key in keys:
            assert_equal(a.getfeerateinfo()[key], expected[key])


if __name__ == "__main__":
    AdaptiveReorgTest().main()
