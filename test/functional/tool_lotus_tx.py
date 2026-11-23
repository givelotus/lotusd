#!/usr/bin/env python3
# Copyright (c) 2026 The Lotusia Stewardship
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test lotus-tx fork-id signing.

lotus-tx is offline and has no median time past, so the fork id it commits is
selected explicitly with -forkid. This test signs the same transaction with
fork id 0 and with CHAIN_FORK_ID and checks a replay-protected node accepts
only the chain-id form, while a node with replay protection off accepts only
the fork-id-0 form.
"""

import json
import os
import subprocess
from decimal import Decimal

from test_framework.address import key_to_p2pkh
from test_framework.key import ECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import bytes_to_wif

CHAIN_FORK_ID = 0x4c4f54
CHAIN_FORK_ID_DEC = str(CHAIN_FORK_ID)
CHAIN_FORK_ID_HEX = "0x{:x}".format(CHAIN_FORK_ID)
REPLAY_OFF_ACTIVATION_TIME = 9999999999
FEE = Decimal("0.001")


class LotusTxForkIdTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            # Replay protection active, Second Samuel active so SIGHASH_LOTUS
            # is accepted.
            ["-replayprotectionactivationtime=0",
             "-secondsamuelactivationtime=0"],
            # Replay protection inactive, SIGHASH_LOTUS still accepted.
            ["-replayprotectionactivationtime={}".format(
                REPLAY_OFF_ACTIVATION_TIME),
             "-secondsamuelactivationtime=0"],
        ]

    def run_test(self):
        binary = os.path.join(
            self.config["environment"]["BUILDDIR"], "src", "lotus-tx")
        assert os.path.isfile(binary), "lotus-tx binary not built: " + binary

        # Each node mines its own chain so its own coinbase can be spent.
        self.disconnect_nodes(0, 1)

        self.log.info("Reject invalid fork ids")
        for invalid in ["0x1000000", "16777216", "not-a-number"]:
            result = subprocess.run(
                [binary, "-regtest", "-forkid={}".format(invalid),
                 "-create", "nversion=2"],
                capture_output=True, text=True)
            assert_equal(result.returncode, 1)
            self.log.info("  -forkid=%s -> %s", invalid, result.stderr.strip())
            assert "invalid fork id" in result.stderr

        self.log.info(
            "Test the replay-protected node accepts only %s", CHAIN_FORK_ID_HEX)
        self.test_node(self.nodes[0], binary, replay_active=True)

        self.log.info(
            "Test the pre-activation node accepts only fork id 0")
        self.test_node(self.nodes[1], binary, replay_active=False)

    def test_node(self, node, binary, replay_active):
        miner_key = ECKey()
        miner_key.generate()
        miner_address = key_to_p2pkh(miner_key.get_pubkey().get_bytes())
        wif = bytes_to_wif(miner_key.get_bytes(), miner_key.is_compressed)

        # The nodes are disconnected and mine separate chains, so there is
        # nothing to sync.
        self.generatetoaddress(node, 101, miner_address, sync_fun=self.no_op)

        # The first block's coinbase is mature and pays the miner key.
        coinbase = node.getblock(node.getblockhash(1), 2)["tx"][0]
        vout = coinbase["vout"][1]
        amount = vout["value"]
        if not isinstance(amount, Decimal):
            amount = Decimal(str(amount))

        dest_key = ECKey()
        dest_key.generate()
        dest = key_to_p2pkh(dest_key.get_pubkey().get_bytes())

        unsigned = self.run_lotus_tx(binary, [
            "-regtest",
            "-create",
            "in={}:{}".format(coinbase["txid"], vout["n"]),
            "outaddr={}:{}".format(amount - FEE, dest),
        ])

        prevtxs = json.dumps([{
            "txid": coinbase["txid"],
            "vout": vout["n"],
            "scriptPubKey": vout["scriptPubKey"]["hex"],
            "amount": float(amount),
        }])
        registers = [
            "set=privatekeys:{}".format(json.dumps([wif])),
            "set=prevtxs:{}".format(prevtxs),
        ]

        # (sighash, fork id argument, accepted?)
        cases = [
            ("ALL|FORKID", None, not replay_active),
            ("ALL|FORKID", "0", not replay_active),
            ("ALL|FORKID", CHAIN_FORK_ID_HEX, replay_active),
            ("ALL|FORKID", CHAIN_FORK_ID_DEC, replay_active),
            ("ALL|LOTUS", None, not replay_active),
            ("ALL|LOTUS", CHAIN_FORK_ID_HEX, replay_active),
        ]

        for sighash, forkid, accepted in cases:
            args = ["-regtest"]
            if forkid is not None:
                args.append("-forkid={}".format(forkid))
            args += [unsigned] + registers + ["sign={}".format(sighash)]
            signed = self.run_lotus_tx(binary, args)

            result = node.testmempoolaccept([signed])[0]
            label = "-forkid={} sign={}".format(forkid, sighash)
            if accepted:
                self.log.info("  %s accepted", label)
                assert_equal(result["allowed"], True)
            else:
                self.log.info("  %s rejected: %s", label,
                              result.get("reject-reason"))
                assert_equal(result["allowed"], False)
                assert "mandatory-script-verify-flag-failed" in \
                    result["reject-reason"]

    def run_lotus_tx(self, binary, args):
        result = subprocess.run([binary] + args, capture_output=True,
                                text=True)
        assert_equal(result.returncode, 0)
        return result.stdout.strip()


if __name__ == '__main__':
    LotusTxForkIdTest().main()
