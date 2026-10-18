# Copyright (c) 2024-2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Avalanche V2 bulk pre-consensus batch voting (AVABATCH) and treasury voting + 50/25/25 coinbase split (AVATREASURY)."""

import time

from test_framework.address import P2SH_OP_TRUE, SCRIPT_UNSPENDABLE
from test_framework.avatools import (
    assert_response,
    can_find_inv_in_poll,
    get_ava_p2p_interface,
)
from test_framework.blocktools import create_block, create_coinbase
from test_framework.key import ECPubKey
from test_framework.messages import (
    MSG_AVA_MEMPOOL_BATCH,
    MSG_AVA_TREASURY_CONTENDER,
    NODE_AVALANCHE,
    NODE_MERKLIX_EPOCH,
    NODE_NETWORK,
    XEC,
    AvalancheProofVoteResponse,
    AvalancheVote,
    AvalancheVoteError,
    CTxOut,
    ToHex,
    msg_avabatch,
    msg_avatreasury,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx
from test_framework.util import assert_equal, uint256_hex

QUORUM_NODE_COUNT = 16
STAKING_REWARDS_RATIO_PERCENT = 25
TREASURY_REWARDS_RATIO_PERCENT = 25


class AvalancheBatchAndTreasuryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.extra_args = [
            [
                "-avaproofstakeutxodustthreshold=1000000",
                "-avaproofstakeutxoconfirmations=1",
                "-avacooldown=0",
                "-avaminquorumstake=0",
                "-avaminavaproofsnodecount=0",
                "-avalanchestakingrewards=1",
                "-avalanchetreasury=1",
            ],
        ]

    def run_test(self):
        node = self.nodes[0]

        now = int(time.time())
        node.setmocktime(now)

        quorum = [
            get_ava_p2p_interface(
                self,
                node,
                services=NODE_NETWORK | NODE_AVALANCHE | NODE_MERKLIX_EPOCH,
            )
            for _ in range(QUORUM_NODE_COUNT)
        ]

        def wait_for_finalized_proof(proofid):
            def finalize_proof():
                can_find_inv_in_poll(
                    quorum, proofid, response=AvalancheProofVoteResponse.ACTIVE
                )
                return node.getrawavalancheproof(uint256_hex(proofid)).get(
                    "finalized", False
                )

            self.wait_until(finalize_proof)

        for peer in quorum:
            wait_for_finalized_proof(peer.proof.proofid)

        poll_node = quorum[0]
        assert node.getavalancheinfo()["ready_to_poll"] is True

        now += 60 * 60 + 1
        node.setmocktime(now)
        self.generate(node, 1)

        avakey = ECPubKey()
        avakey.set(bytes.fromhex(node.getavalanchekey()))

        tip_hex = node.getbestblockhash()
        tip_int = int(tip_hex, 16)

        coinbase = node.getblock(tip_hex, 2)["tx"][0]
        block_reward_sats = int(
            round(sum(vout["value"] for vout in coinbase["vout"]) * XEC)
        )
        expected_staker_sats = block_reward_sats * STAKING_REWARDS_RATIO_PERCENT // 100
        expected_treasury_sats = (
            block_reward_sats * TREASURY_REWARDS_RATIO_PERCENT // 100
        )
        expected_miner_sats = (
            block_reward_sats - expected_staker_sats - expected_treasury_sats
        )

        self.log.info(
            "1. Test progressive MempoolBatchAnnouncement (AVABATCH / MSG_AVA_MEMPOOL_BATCH) polling and finalization"
        )
        batch1 = msg_avabatch(
            prev_block_hash=tip_int,
            epoch_seq=1,
            parent_batch_id=0,
            subtree_a_root=0x1111,
            utxo_root=0x2222,
            tx_count=32,
            short_ids_hash=0x3333,
        )
        batch1_id = batch1.batch_id()

        # Unknown batch before announcement responds with UNKNOWN (-1)
        poll_node.send_poll([batch1_id], inv_type=MSG_AVA_MEMPOOL_BATCH)
        assert_response(
            poll_node,
            avakey,
            [AvalancheVote(AvalancheVoteError.UNKNOWN, batch1_id)],
        )

        # Send AVABATCH announcement over P2P
        poll_node.send_and_ping(batch1)

        # Before quorum votes it accepted, locally unaccepted remote batch votes 1 (INVALID/REJECTED)
        poll_node.send_poll([batch1_id], inv_type=MSG_AVA_MEMPOOL_BATCH)
        assert_response(
            poll_node,
            avakey,
            [AvalancheVote(AvalancheVoteError.INVALID, batch1_id)],
        )

        # Vote ACCEPTED (0) on batch1 in node's outgoing AVAPOLLs until node accepts and finalizes batch1
        def batch_accepted_by_node(batch_id):
            can_find_inv_in_poll(quorum, batch_id, response=AvalancheVoteError.ACCEPTED)
            poll_node.send_poll([batch_id], inv_type=MSG_AVA_MEMPOOL_BATCH)
            resp = poll_node.wait_for_avaresponse()
            return resp.response.votes[0].error == AvalancheVoteError.ACCEPTED

        self.wait_until(lambda: batch_accepted_by_node(batch1_id))

        # Announce progressive epoch_seq=2 chained on parent_batch_id=batch1_id
        batch2 = msg_avabatch(
            prev_block_hash=tip_int,
            epoch_seq=2,
            parent_batch_id=batch1_id,
            subtree_a_root=0x4444,
            utxo_root=0x5555,
            tx_count=64,
            short_ids_hash=0x6666,
        )
        batch2_id = batch2.batch_id()
        poll_node.send_and_ping(batch2)
        self.wait_until(lambda: batch_accepted_by_node(batch2_id))

        self.log.info(
            "2. Test TreasuryContender (AVATREASURY / MSG_AVA_TREASURY_CONTENDER) polling and 50/25/25 coinbase split"
        )
        treasury_script = P2SH_OP_TRUE
        treasury_msg = msg_avatreasury(
            prevblockhash=tip_int,
            outputs=[
                CTxOut(nValue=expected_treasury_sats, scriptPubKey=treasury_script)
            ],
            total_reward=expected_treasury_sats,
        )
        treasury_cid = treasury_msg.contender_id()

        # Unknown treasury contender before announcement responds with UNKNOWN (-1)
        poll_node.send_poll([treasury_cid], inv_type=MSG_AVA_TREASURY_CONTENDER)
        assert_response(
            poll_node,
            avakey,
            [AvalancheVote(AvalancheVoteError.UNKNOWN, treasury_cid)],
        )

        # Announce treasury contender via AVATREASURY
        poll_node.send_and_ping(treasury_msg)

        # Vote ACCEPTED (0) in node's outgoing AVAPOLLs until treasury_cid is accepted and finalized
        def treasury_finalized(cid):
            # Keep polling until node stops polling cid (meaning it finalized) and votes ACCEPTED
            found = can_find_inv_in_poll(
                quorum, cid, response=AvalancheVoteError.ACCEPTED
            )
            poll_node.send_poll([cid], inv_type=MSG_AVA_TREASURY_CONTENDER)
            resp = poll_node.wait_for_avaresponse()
            return (
                not found
                and resp.response.votes[0].error == AvalancheVoteError.ACCEPTED
            )

        self.wait_until(lambda: treasury_finalized(treasury_cid))

        # Verify getblocktemplate reports total coinbasevalue and 25% staker reward
        gbt = node.getblocktemplate()
        assert_equal(gbt["coinbasevalue"], block_reward_sats)
        assert_equal(
            gbt["coinbasetxn"]["stakingrewards"]["minimumvalue"], expected_staker_sats
        )

        # Mine a block via generate() and verify the 50/25/25 coinbase outputs
        mined_hash = self.generate(node, 1)[0]
        mined_block = node.getblock(mined_hash, 2)
        cb_vouts = mined_block["tx"][0]["vout"]
        assert_equal(len(cb_vouts), 3)
        assert_equal(int(round(cb_vouts[0]["value"] * XEC)), expected_miner_sats)
        assert_equal(int(round(cb_vouts[1]["value"] * XEC)), expected_staker_sats)
        assert_equal(cb_vouts[1]["scriptPubKey"]["hex"], SCRIPT_UNSPENDABLE.hex())
        assert_equal(int(round(cb_vouts[2]["value"] * XEC)), expected_treasury_sats)
        assert_equal(cb_vouts[2]["scriptPubKey"]["hex"], treasury_script.hex())

        self.log.info(
            "3. Verify TreasuryPolicy parks a block missing the finalized 25% treasury output"
        )
        tip2_hex = mined_hash
        tip2_int = int(tip2_hex, 16)
        treasury_msg2 = msg_avatreasury(
            prevblockhash=tip2_int,
            outputs=[
                CTxOut(nValue=expected_treasury_sats, scriptPubKey=treasury_script)
            ],
            total_reward=expected_treasury_sats,
        )
        treasury_cid2 = treasury_msg2.contender_id()
        poll_node.send_and_ping(treasury_msg2)
        self.wait_until(lambda: treasury_finalized(treasury_cid2))

        # Create a block that pays the 25% staker reward but omits the 25% treasury reward
        height = node.getblockcount() + 1
        cb_missing_treasury = create_coinbase(height)
        cb_missing_treasury.vout = [
            CTxOut(
                nValue=block_reward_sats - expected_staker_sats,
                scriptPubKey=cb_missing_treasury.vout[0].scriptPubKey,
            ),
            CTxOut(nValue=expected_staker_sats, scriptPubKey=SCRIPT_UNSPENDABLE),
        ]
        pad_tx(cb_missing_treasury)
        bad_block = create_block(
            tip2_int,
            cb_missing_treasury,
            node.getblock(tip2_hex)["time"] + 1,
            version=4,
        )
        bad_block.solve()
        node.submitblock(ToHex(bad_block))

        # Node parks bad_block because it violates TreasuryPolicy
        assert_equal(node.getbestblockhash(), tip2_hex)
        poll_node.send_poll([bad_block.hash_int])
        assert_response(
            poll_node,
            avakey,
            [AvalancheVote(AvalancheVoteError.PARKED, bad_block.hash_int)],
        )


if __name__ == "__main__":
    AvalancheBatchAndTreasuryTest().main()
