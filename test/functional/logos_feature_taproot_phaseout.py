#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test that we successfully phased out taproot during the Numbers update
"""

from test_framework.key import ECKey
from test_framework.blocktools import (
    SUBSIDY,
    create_coinbase,
    create_block,
    prepare_block,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.p2p import (
    P2PDataStore,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_EQUAL,
    OP_HASH160,
    OP_SCRIPTTYPE,
    SIGHASH_ALL,
    SIGHASH_LOTUS,
    SignatureHashLotus,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx


NUMBERS_ACTIVATION_TIME = 2000000000
REPLAY_ACTIVATION_TIME = 2010000000

class TaprootKeySpendTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-whitelist=noban@127.0.0.1',
                            f'-numbersactivationtime={NUMBERS_ACTIVATION_TIME}',
                            f'-replayprotectionactivationtime={REPLAY_ACTIVATION_TIME}']]

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())

        value = int(SUBSIDY * 1_000_000)
        fee = 10_000

        private_key = ECKey()
        private_key.generate()
        public_key = private_key.get_pubkey()

        taproot_script = CScript([OP_SCRIPTTYPE, OP_1, public_key.get_bytes()])

        anyonecanspend_address = node.decodescript('51')['p2sh']
        burn_address = node.decodescript('00')['p2sh']
        node.generatetoaddress(1, anyonecanspend_address)
        node.generatetoaddress(100, burn_address)

        # Build taproot funding transaction
        block_hash = node.getblockhash(1)
        coin = int(node.getblock(block_hash)['tx'][0], 16)
        tx_fund_taproot = CTransaction()
        tx_fund_taproot.vin.append(CTxIn(COutPoint(coin, 1), CScript([b'\x51'])))
        tx_fund_taproot.vout.append(CTxOut(value - fee, taproot_script))
        pad_tx(tx_fund_taproot)

        # Can't add taproot to mempool: They're henceforth non-standard
        peer.send_txs_and_test([tx_fund_taproot], node, success=False, reject_reason='bad-taproot-phased-out')

        # However, before Numbers, we can still mine txs with taproot output
        template = node.getblocktemplate()
        coinbase = create_coinbase(template['height'], pubkey=b'\x03'*33)
        block1 = create_block(coinbase=coinbase, tmpl=template)
        block1.vtx.append(tx_fund_taproot)
        prepare_block(block1)
        peer.send_blocks_and_test([block1], node, timeout=5)

        # Make tx spending taproot
        tx_spend_taproot = CTransaction()
        tx_spend_taproot.vin.append(CTxIn(COutPoint(tx_fund_taproot.txid, 0), CScript()))
        tx_spend_taproot.vout.append(CTxOut(value - fee * 2, CScript([OP_HASH160, bytes(20), OP_EQUAL])))
        sighash_type = SIGHASH_ALL | SIGHASH_LOTUS
        sighash = SignatureHashLotus(
            tx_to=tx_spend_taproot,
            spent_utxos=[tx_fund_taproot.vout[0]],
            sig_hash_type=sighash_type,
            input_index=0,
        )
        signature = private_key.sign_schnorr(sighash)
        signature += bytes([sighash_type])
        tx_spend_taproot.vin[0].scriptSig = CScript([signature])

        # We can't add a taproot spend to mempool either
        peer.send_txs_and_test([tx_spend_taproot], node, success=False, reject_reason='non-mandatory-script-verify-flag (Taproot is being phased out)')

        # However, before Numbers, we can still mine taproot spend txs
        template = node.getblocktemplate()
        coinbase = create_coinbase(template['height'], pubkey=b'\x03'*33)
        block2 = create_block(coinbase=coinbase, tmpl=template)
        block2.vtx.append(tx_spend_taproot)
        prepare_block(block2)
        peer.send_blocks_and_test([block2], node, timeout=5)

        # Undo blocks with the 2 taproot txs
        node.invalidateblock(block2.hash)
        node.invalidateblock(block1.hash)

        # Activate Numbers upgrade
        node.setmocktime(NUMBERS_ACTIVATION_TIME)
        node.generatetoaddress(6, burn_address)

        # Adding taproot output to mempool still fails
        peer.send_txs_and_test([tx_fund_taproot], node, success=False, reject_reason='bad-taproot-phased-out')

        # But now taproot outputs can't even be mined in blocks anymore
        template = node.getblocktemplate()
        coinbase = create_coinbase(template['height'], pubkey=b'\x03'*33)
        block3 = create_block(coinbase=coinbase, tmpl=template)
        block3.vtx.append(tx_fund_taproot)
        prepare_block(block3)
        peer.send_blocks_and_test([block3], node, success=False, reject_reason='bad-taproot-phased-out')

        # Now we roll back Numbers
        node.invalidateblock(node.getbestblockhash())

        # Adding taproot output to mempool still fails
        peer.send_txs_and_test([tx_fund_taproot], node, success=False, reject_reason='bad-taproot-phased-out')

        # Since we rolled back Numbers, we can mine the taproot output again
        template = node.getblocktemplate()
        coinbase = create_coinbase(template['height'], pubkey=b'\x03'*33)
        block4 = create_block(coinbase=coinbase, tmpl=template)
        block4.vtx.append(tx_fund_taproot)
        prepare_block(block4)
        peer.send_blocks_and_test([block4], node, timeout=5)

        # Adding taproot spend to mempool still fails
        peer.send_txs_and_test([tx_spend_taproot], node, success=False, reject_reason='non-mandatory-script-verify-flag (Taproot is being phased out)')

        # Numbers is now activated again, so we can't spend the taproot output even in blocks
        template = node.getblocktemplate()
        coinbase = create_coinbase(template['height'], pubkey=b'\x03'*33)
        block5 = create_block(coinbase=coinbase, tmpl=template)
        block5.vtx.append(tx_spend_taproot)
        prepare_block(block5)
        peer.send_blocks_and_test([block5], node, success=False, reject_reason='blk-bad-inputs')


if __name__ == '__main__':
    TaprootKeySpendTest().main()
