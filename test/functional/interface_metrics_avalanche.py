#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Avalanche metrics at /metrics: quorum, proof pools, polls sent
and received, votes, finalized items and finalization latency."""

from test_framework.avatools import can_find_inv_in_poll, get_ava_p2p_interface
from test_framework.messages import AvalancheVoteError
from test_framework.metrics import m, scrape
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, uint256_hex

QUORUM_NODE_COUNT = 16
COOLDOWN_MS = 2000


class AvalancheMetricsTest(BitcoinTestFramework):
    setup_clean_chain = True
    num_nodes = 1
    extra_args = [
        [
            "-metrics",
            "-avaproofstakeutxodustthreshold=1000000",
            "-avaproofstakeutxoconfirmations=1",
            f"-avacooldown={COOLDOWN_MS}",
            "-avaminquorumstake=0",
            "-avaminavaproofsnodecount=0",
            "-persistavapeers=0",
            "-avalanchestakingpreconsensus=0",
        ],
    ]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Before any peer: no quorum, every series present")
        s = scrape(node)
        assert_equal(s.value(m("avalanche_quorum_established")), 0)
        assert_equal(s.value(m("avalanche_quorum_nodes")), 0)
        assert_equal(
            s.label_values(m("avalanche_quorum_score"), "scope"),
            {"total", "connected"},
        )
        assert_equal(
            s.label_values(m("avalanche_proofs"), "pool"),
            {"valid", "conflicting", "immature", "dangling"},
        )
        types = {"proof", "block", "contender", "transaction", "batch", "state_anchor"}
        assert_equal(s.label_values(m("avalanche_items_total"), "type"), types)
        assert_equal(
            s.label_values(m("avalanche_items_total"), "outcome"),
            {"finalized", "invalidated", "stale"},
        )
        assert_equal(len(s.series(m("avalanche_items_total"))), 18)
        assert_equal(
            s.label_values(m("avalanche_votes_received_total"), "vote"),
            {"yes", "no", "neutral"},
        )
        assert_equal(s.total(m("avalanche_polls_sent_total")), 0)

        self.log.info("A quorum of 16 peers establishes the quorum")
        quorum = [get_ava_p2p_interface(self, node) for _ in range(QUORUM_NODE_COUNT)]
        assert node.getavalancheinfo()["ready_to_poll"] is True
        self.wait_until(
            lambda: scrape(node).value(m("avalanche_quorum_established")) == 1
        )
        s = scrape(node)
        assert_equal(s.value(m("avalanche_quorum_nodes")), QUORUM_NODE_COUNT)
        assert s.value(m("avalanche_quorum_score"), scope="total") > 0
        assert_equal(
            s.value(m("avalanche_quorum_score"), scope="connected"),
            s.value(m("avalanche_quorum_score"), scope="total"),
        )
        assert_equal(
            s.value(m("avalanche_proofs"), pool="valid"),
            node.getavalancheinfo()["network"]["proof_count"],
        )

        self.log.info("Polling finalizes the peers' proofs")

        def has_finalized_proof(proofid):
            can_find_inv_in_poll(quorum, proofid)
            return node.getrawavalancheproof(uint256_hex(proofid))["finalized"]

        for peer in quorum:
            self.wait_until(lambda: has_finalized_proof(peer.proof.proofid))
        self.wait_until(
            lambda: (
                scrape(node).value(
                    m("avalanche_items_total"), type="proof", outcome="finalized"
                )
                >= QUORUM_NODE_COUNT
            )
        )
        s = scrape(node)
        finalized = s.value(
            m("avalanche_items_total"), type="proof", outcome="finalized"
        )
        # Every finalization is timed (metrics were on when they were added)
        assert_equal(
            s.value(m("avalanche_finalization_seconds_count"), type="proof"),
            finalized,
        )
        assert s.value(m("avalanche_finalization_seconds_sum"), type="proof") > 0
        polls = s.value(m("avalanche_polls_sent_total"))
        assert polls > 0
        assert s.value(m("avalanche_poll_items_sent_total")) >= polls
        assert s.value(m("avalanche_votes_received_total"), vote="yes") > 0

        self.log.info("A block is finalized; 'no' votes are counted")
        tip = int(self.generate(node, 1, sync_fun=self.no_op)[0], 16)
        no_before = s.value(m("avalanche_votes_received_total"), vote="no")
        # One round of 'no' on the tip, then 'yes' until finalized
        self.wait_until(
            lambda: can_find_inv_in_poll(
                quorum, tip, response=AvalancheVoteError.UNKNOWN
            )
        )
        self.wait_until(
            lambda: can_find_inv_in_poll(
                quorum, tip, response=AvalancheVoteError.PARKED
            )
        )

        def block_finalized():
            can_find_inv_in_poll(quorum, tip)
            return node.isfinalblock(uint256_hex(tip))

        self.wait_until(block_finalized)
        self.wait_until(
            lambda: (
                scrape(node).value(
                    m("avalanche_items_total"), type="block", outcome="finalized"
                )
                >= 1
            )
        )
        s = scrape(node)
        assert s.value(m("avalanche_finalization_seconds_count"), type="block") >= 1
        assert s.value(m("avalanche_votes_received_total"), vote="no") > no_before
        assert s.value(m("avalanche_votes_received_total"), vote="neutral") > 0

        self.log.info("Polls from a peer: answered, or ignored within the cooldown")
        poll_node = quorum[0]
        before = scrape(node)
        poll_node.send_poll([tip])
        poll_node.wait_for_avaresponse()
        poll_node.send_poll([tip])
        poll_node.sync_with_ping()

        def polls_received(outcome):
            return scrape(node).value(
                m("avalanche_polls_received_total"), outcome=outcome
            ) - before.value(m("avalanche_polls_received_total"), outcome=outcome)

        self.wait_until(lambda: polls_received("answered") >= 1)
        self.wait_until(lambda: polls_received("ignored") >= 1)


if __name__ == "__main__":
    AvalancheMetricsTest().main()
