#!/usr/bin/env python3
# Copyright (c) 2021 The Logos developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test int63+1 bit integers."""

import re

from test_framework.txtools import pad_tx
from test_framework.script import hash160
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    prepare_block,
    SUBSIDY,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.mininode import (
    P2PDataStore,
)
from test_framework.script import (
    CScript,
    OP_1ADD,
    OP_1SUB,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,
    OP_ADD,
    OP_SUB,
    OP_DIV,
    OP_MOD,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_HASH160,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from decimal import Decimal
import random

MAX_SCRIPT_INT = 0x7fff_ffff_ffff_ffff
MIN_SCRIPT_INT = -0x7fff_ffff_ffff_ffff


class Int63Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=noban@127.0.0.1"]]

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())
        # OP_TRUE in P2SH
        address = node.decodescript('51')['p2sh']
        num_mature_coins = 30
        node.generatetoaddress(num_mature_coins, address)
        node.generatetoaddress(100, address)

        value = int(SUBSIDY * 1_000_000)
        p2sh_script = CScript([OP_HASH160, bytes(20), OP_EQUAL])

        def make_tx(coin_height):
            assert coin_height <= num_mature_coins
            block_hash = node.getblockhash(coin_height)
            coin = int(node.getblock(block_hash)['tx'][0], 16)
            tx = CTransaction()
            tx.vin.append(
                CTxIn(COutPoint(coin, 1), CScript([b'\x51'])))
            return tx

        def make_block():
            parent_block_header = node.getblockheader(node.getbestblockhash())
            height = parent_block_header['height'] + 1
            coinbase = create_coinbase(height)
            coinbase.vout[1].scriptPubKey = p2sh_script
            coinbase.rehash()
            block = create_block(
                int(parent_block_header['hash'], 16), coinbase, height, parent_block_header['time'] + 1)
            return block

        interesting_numbers = [
            0,
            1,
            -1,
            2,
            -2,
            4,
            -4,
            10,
            -10,
            127,
            -127,
            256,
            -256,
            0x7fffffff,
            -0x7fffffff,
            0x100000000,
            -0x100000000,
            0x7fffffffff,
            -0x7fffffffff,
            0x10000000000,
            -0x10000000000,
            0x7fffffffffffff,
            -0x7fffffffffffff,
            0x100000000000000,
            -0x100000000000000,
            0x7fffffffffffffff,
            -0x7fffffffffffffff,
            0x10000000000000000,
            -0x10000000000000000,
        ]

        # make integer scripts
        valid_scripts = []
        invalid_scripts = []
        def make_script(a, b = None, *, result, opcode):
            if (MIN_SCRIPT_INT <= a <= MAX_SCRIPT_INT and
                    (b is None or MIN_SCRIPT_INT <= b <= MAX_SCRIPT_INT) and
                    (MIN_SCRIPT_INT <= result <= MAX_SCRIPT_INT)):
                if b is None:
                    valid_scripts.append(CScript([a, opcode, result, OP_EQUALVERIFY, OP_TRUE]))
                else:
                    valid_scripts.append(CScript([a, b, opcode, result, OP_EQUALVERIFY, OP_TRUE]))
            else:
                if b is None:
                    invalid_scripts.append(CScript([a, opcode, OP_TRUE]))
                else:
                    invalid_scripts.append(CScript([a, b, opcode, OP_TRUE]))
        for a in interesting_numbers:
            make_script(a, result=a + 1, opcode=OP_1ADD)
            make_script(a, result=a - 1, opcode=OP_1SUB)
            make_script(a, result=-a, opcode=OP_NEGATE)
            make_script(a, result=abs(a), opcode=OP_ABS)
            make_script(a, result=not a, opcode=OP_NOT)
            make_script(a, result=a != 0, opcode=OP_0NOTEQUAL)
            for b in interesting_numbers:
                make_script(a, b, result=a + b, opcode=OP_ADD)
                make_script(a, b, result=a - b, opcode=OP_SUB)
                if b != 0:
                    # Note: We have to use Decimal here, as Python's integers behave differently
                    # for division and modulo for negative numbers.
                    make_script(a, b, result=int(Decimal(a) // Decimal(b)), opcode=OP_DIV)
                    make_script(a, b, result=int(Decimal(a) % Decimal(b)), opcode=OP_MOD)
                else:
                    invalid_scripts.append(CScript([a, b, OP_DIV, OP_TRUE]))
                    invalid_scripts.append(CScript([a, b, OP_MOD, OP_TRUE]))
                make_script(a, b, result=a < b, opcode=OP_LESSTHAN)
                make_script(a, b, result=a > b, opcode=OP_GREATERTHAN)
                make_script(a, b, result=a <= b, opcode=OP_LESSTHANOREQUAL)
                make_script(a, b, result=a >= b, opcode=OP_GREATERTHANOREQUAL)

        txs = []
        num_txs = 10
        scripts_per_tx = len(valid_scripts) // num_txs
        for i in range(1, num_txs + 1):
            fund_tx = make_tx(i * 2)
            spend_tx = make_tx(i * 2 + 1)
            scripts = valid_scripts[(i - 1) * scripts_per_tx:][:scripts_per_tx]
            for script in scripts:
                fund_tx.vout.append(CTxOut(value // len(scripts),
                    CScript([OP_HASH160, hash160(script), OP_EQUAL])))
            fund_tx.rehash()
            for i, script in enumerate(scripts):
                spend_tx.vin.append(CTxIn(COutPoint(fund_tx.txid, i), CScript([script])))
            spend_tx.vout.append(CTxOut(value // len(scripts), p2sh_script))
            txs.append(fund_tx)
            txs.append(spend_tx)
        block = make_block()
        block.vtx.extend(txs)
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node)
        
        fund_txs = []
        invalid_spend_txs = []
        num_txs = 5
        scripts_per_tx = len(invalid_scripts) // num_txs
        for i in range(1, num_txs + 1):
            fund_tx = make_tx(21 + i)
            scripts = invalid_scripts[(i - 1) * scripts_per_tx:][:scripts_per_tx]
            for script in scripts:
                fund_tx.vout.append(CTxOut(value // len(scripts),
                    CScript([OP_HASH160, hash160(script), OP_EQUAL])))
            fund_tx.rehash()
            fund_txs.append(fund_tx)

            for vout, script in enumerate(scripts):
                spend_tx = CTransaction()
                spend_tx.vin.append(CTxIn(COutPoint(fund_tx.txid, vout), CScript([script])))
                spend_tx.vout.append(CTxOut(value // len(scripts), p2sh_script))
                pad_tx(spend_tx)
                invalid_spend_txs.append(spend_tx)

        block = make_block()
        block.vtx.extend(fund_txs)
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node)

        invalid_block = make_block()
        invalid_block.vtx.append(None)
        for invalid_spend_tx in random.sample(invalid_spend_txs, 100):
            invalid_block.vtx[1] = invalid_spend_tx
            prepare_block(invalid_block)
            node.p2p.send_blocks_and_test(
                [invalid_block], node,
                success=False,
                reject_reason='state=blk-bad-inputs, parallel script check failed')


if __name__ == '__main__':
    Int63Test().main()
