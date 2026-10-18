# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that we reject low difficulty headers to prevent our block tree from filling up with useless bloat"""

import os

from test_framework.messages import CBlockHeader, FromHex
from test_framework.p2p import P2PInterface, msg_headers
from test_framework.test_framework import BitcoinTestFramework


class RejectLowDifficultyHeadersTest(BitcoinTestFramework):
    setup_clean_chain = True
    chain = "testnet3"  # Use testnet chain because it has an early checkpoint
    num_nodes = 2
    extra_args = [["-minimumchainwork=0x0"], ["-minimumchainwork=0x0"]]

    def add_options(self, parser):
        parser.add_argument(
            "--datafile",
            default="data/blockheader_testnet3.hex",
            help="Test data file (default: %(default)s)",
        )

    def run_test(self):
        self.log.info("Read headers data")
        self.headers_file_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), self.options.datafile
        )
        with open(self.headers_file_path, encoding="utf-8") as headers_data:
            h_lines = [line.strip() for line in headers_data.readlines()]

        # The headers data is taken from testnet3 for early blocks from genesis until the first checkpoint. There are
        # two headers with valid POW at height 1 and 2, forking off from
        # genesis. They are indicated by the FORK_PREFIX.
        FORK_PREFIX = "fork:"
        self.headers = [line for line in h_lines if not line.startswith(FORK_PREFIX)]
        self.headers_fork = [
            line[len(FORK_PREFIX) :] for line in h_lines if line.startswith(FORK_PREFIX)
        ]

        self.headers = [FromHex(CBlockHeader(), h) for h in self.headers]
        self.headers_fork = [FromHex(CBlockHeader(), h) for h in self.headers_fork]

        self.log.info(
            "Feed historical non-ASERT headers (heights 1..4 accepted, height 5 rejected with bad-diffbits under Lotus V2 genesis-active ASERT)"
        )
        peer_checkpoint = self.nodes[0].add_p2p_connection(P2PInterface())
        with self.nodes[0].assert_debug_log(["bad-diffbits"]):
            peer_checkpoint.send_without_ping(msg_headers(self.headers))
            peer_checkpoint.wait_for_disconnect()
        assert {
            "height": 4,
            "hash": self.headers[3].hash_hex,
            "branchlen": 4,
            "status": "headers-only",
        } in self.nodes[0].getchaintips()

        self.log.info("Feed fork headers on node 1 (succeeds under 120s ASERT)")
        peer_before_checkpoint = self.nodes[1].add_p2p_connection(P2PInterface())
        peer_before_checkpoint.send_and_ping(msg_headers(self.headers_fork))
        assert {
            "height": 2,
            "hash": self.headers_fork[1].hash_hex,
            "branchlen": 2,
            "status": "headers-only",
        } in self.nodes[1].getchaintips()


if __name__ == "__main__":
    RejectLowDifficultyHeadersTest().main()
