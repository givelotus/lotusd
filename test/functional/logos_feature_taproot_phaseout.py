#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test that we successfully phased out taproot during the Numbers update.

Taproot outputs are rejected in blocks until Second Samuel, also before
Numbers, as on the network run by LotusiaStewardship/lotusd. After Second
Samuel, Taproot outputs and spends are accepted.
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
SECOND_SAMUEL_ACTIVATION_TIME = 2010000000
REPLAY_ACTIVATION_TIME = 2020000000

class TaprootKeySpendTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-whitelist=noban@127.0.0.1',
                            f'-numbersactivationtime={NUMBERS_ACTIVATION_TIME}',
                            f'-secondsamuelactivationtime={SECOND_SAMUEL_ACTIVATION_TIME}',
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
        self.generatetoaddress(node, 1, anyonecanspend_address)
        self.generatetoaddress(node, 100, burn_address)

        # Build taproot funding transaction
        block_hash = node.getblockhash(1)
        coin = int(node.getblock(block_hash)['tx'][0], 16)
        tx_fund_taproot = CTransaction()
        tx_fund_taproot.vin.append(CTxIn(COutPoint(coin, 1), CScript([b'\x51'])))
        tx_fund_taproot.vout.append(CTxOut(value - fee, taproot_script))
        pad_tx(tx_fund_taproot)

        # Can't add taproot to mempool: They're henceforth non-standard
        peer.send_txs_and_test([tx_fund_taproot], node, success=False, reject_reason='bad-taproot-phased-out')

        # Taproot outputs can't be mined before Second Samuel, even before
        # Numbers
        self.check_taproot_output_rejected(node, peer, tx_fund_taproot)

        # Activate Numbers upgrade
        node.setmocktime(NUMBERS_ACTIVATION_TIME)
        self.generatetoaddress(node, 6, burn_address)

        # Adding taproot output to mempool still fails, and so does mining it
        peer.send_txs_and_test([tx_fund_taproot], node, success=False, reject_reason='bad-taproot-phased-out')
        self.check_taproot_output_rejected(node, peer, tx_fund_taproot)

        # Now we roll back Numbers
        node.invalidateblock(node.getbestblockhash())

        # Taproot outputs are still rejected in the mempool and in blocks
        peer.send_txs_and_test([tx_fund_taproot], node, success=False, reject_reason='bad-taproot-phased-out')
        self.check_taproot_output_rejected(node, peer, tx_fund_taproot)

        # Activate Second Samuel
        node.setmocktime(SECOND_SAMUEL_ACTIVATION_TIME)
        self.generatetoaddress(node, 6, burn_address)

        # Taproot outputs are now accepted in the mempool and in blocks
        peer.send_txs_and_test([tx_fund_taproot], node)
        self.generatetoaddress(node, 1, burn_address)
        assert tx_fund_taproot.txid_hex in node.getblock(node.getbestblockhash())['tx']

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

        # And so are Taproot spends
        peer.send_txs_and_test([tx_spend_taproot], node)
        self.generatetoaddress(node, 1, burn_address)
        assert tx_spend_taproot.txid_hex in node.getblock(node.getbestblockhash())['tx']

    def check_taproot_output_rejected(self, node, peer, tx_fund_taproot):
        template = node.getblocktemplate()
        coinbase = create_coinbase(template['height'], pubkey=b'\x03'*33)
        block = create_block(coinbase=coinbase, tmpl=template)
        block.vtx.append(tx_fund_taproot)
        prepare_block(block)
        peer.send_blocks_and_test([block], node, success=False, reject_reason='bad-taproot-phased-out')

if __name__ == '__main__':
    TaprootKeySpendTest().main()
