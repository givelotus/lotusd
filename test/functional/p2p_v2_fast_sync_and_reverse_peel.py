#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Lotus v2 Fast UTXO Shard Sync (GETUTXOROOTS/UTXOROOTS, GETUTXOSHARD/UTXOSHARD),
Autonomous Multi-Peer Swarm Coordinator with Fault Injection, Live Pivot Activation,
Forward Block Mining on a Fast-Synced Node, and Bijective Reverse Block Peeling
(GETBLOCKUNDO/BLOCKUNDO), including Holes 11-16.
"""

from test_framework.currency import RpcCurrency
from test_framework.messages import (
    NODE_UTXO_SHARD,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    _lotus_v2_encode_output,
    lotus_v2_branch_leaf,
    msg_getblockundo,
    msg_getutxoroots,
    msg_getutxoshard,
    msg_utxoroots,
    msg_utxoshard,
)
from test_framework.p2p import P2P_SERVICES, P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.xpiaddr import encode

V2_OP_TRUE_SCRIPT = b"\x4e"
V2_OP_TRUE_BRANCH_LEAF = lotus_v2_branch_leaf(V2_OP_TRUE_SCRIPT)


V2_OP_TRUE_ADDRESS = encode("rxpi", V2_OP_TRUE_BRANCH_LEAF)


def make_v2_txout(
    value_sats: int, branch_leaf: bytes = V2_OP_TRUE_BRANCH_LEAF
) -> CTxOut:
    txout = CTxOut()
    txout.nFlags = 0
    txout.nValue = value_sats
    txout.tokenId = b"\x00" * 32
    txout.vBranches = [branch_leaf]
    txout.vPaths = [[0]]
    txout.scriptPubKey = _lotus_v2_encode_output(
        (0, value_sats, b"\x00" * 32, [branch_leaf], [[0]])
    )
    return txout


def build_v2_op_true_tx(
    prev_txid_int: int,
    prev_vout: int,
    output_values_sats: list[int],
) -> CTransaction:
    tx = CTransaction()
    tx.nVersion = 7
    tx.fHasV2Lock = True
    tx.nV2Lock = 0
    tx.nLockTime = 0
    txin = CTxIn(COutPoint(prev_txid_int, prev_vout), V2_OP_TRUE_SCRIPT, 0xFFFFFFFF)
    txin.nFlags = 1
    txin.nPathIndex = 0
    txin.vWitnesses = [(V2_OP_TRUE_SCRIPT, [], [])]
    tx.vin = [txin]
    tx.vout = [make_v2_txout(val, V2_OP_TRUE_BRANCH_LEAF) for val in output_values_sats]
    return tx


def block_hash_to_v2_id(blockhash_hex: str) -> bytes:
    return bytes.fromhex(blockhash_hex)[::-1]


class FastSyncPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.last_utxoroots = None
        self.utxoshards = {}
        self.blockundos = {}

    def on_utxoroots(self, message):
        self.last_utxoroots = message

    def on_utxoshard(self, message):
        self.utxoshards[(message.prefix_depth, message.prefix_bits)] = message

    def on_blockundo(self, message):
        self.blockundos[message.block_id] = message


# The node only asks peers that advertise NODE_UTXO_SHARD for shards.
SWARM_PEER_SERVICES = P2P_SERVICES | NODE_UTXO_SHARD


class SwarmServerPeer(P2PInterface):
    """P2P peer that serves UTXOROOTS and UTXOSHARD messages to a syncing node,
    with optional adversarial corruption of a target shard (e.g. shard 0x3F).
    """

    def __init__(self, roots_raw: bytes, shards_by_key: dict, corrupt_shard_bits=None):
        super().__init__()
        self.roots_raw = roots_raw
        self.shards_by_key = shards_by_key
        self.corrupt_shard_bits = corrupt_shard_bits
        self.getutxoroots_count = 0
        self.getutxoshard_keys = []
        self.deferred_keys = []
        self.hold_responses = False

    def on_getutxoroots(self, message):
        self.getutxoroots_count += 1
        m = msg_utxoroots()
        m.raw_payload = self.roots_raw
        self.send_without_ping(m)

    def on_getutxoshard(self, message):
        key = (message.prefix_depth, message.prefix_bits)
        self.getutxoshard_keys.append(key)
        if self.hold_responses:
            self.deferred_keys.append(key)
            return
        self._serve_shard(key)

    def _serve_shard(self, key):
        raw = self.shards_by_key.get(key)
        if raw is None:
            return
        if self.corrupt_shard_bits is not None and key == (8, self.corrupt_shard_bits):
            tampered = bytearray(raw)
            tampered[-1] ^= 0x01
            self.send_without_ping(msg_utxoshard(bytes(tampered)))
        else:
            self.send_without_ping(msg_utxoshard(raw))

    def flush_deferred_shards(self):
        with p2p_lock:
            self.hold_responses = False
            pending = list(self.deferred_keys)
            self.deferred_keys.clear()
        for key in pending:
            self._serve_shard(key)


class FastSyncAndReversePeelTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        self.setup_nodes()
        # Connect node0 and node1; keep node2 isolated for header-only fast-sync swarm test
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[0:2])

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]
        currency = RpcCurrency.from_node(node0)

        def get_cb_utxo(height: int):
            bh = node0.getblockhash(height)
            blk = node0.getblock(bh, 2)
            cb_tx = blk["tx"][0]
            val_sats = currency.to_atoms(cb_tx["vout"][0]["value"])
            return int(cb_tx["txid"], 16), 0, val_sats

        self.log.info("Mine 101 blocks on node0 to mature coinbase outputs")
        self.generatetoaddress(
            node0,
            101,
            V2_OP_TRUE_ADDRESS,
            coinbase_version=7,
            sync_fun=lambda: self.sync_all(self.nodes[0:2]),
        )

        self.log.info(
            "Create transaction in block 102 whose txid prefix byte is 0x3F so shard 0x3F is populated"
        )
        cb1_txid, cb1_vout, cb1_sats = get_cb_utxo(1)
        tx_3f = None
        for fee_bump in range(1, 5000):
            cand = build_v2_op_true_tx(
                cb1_txid, cb1_vout, [cb1_sats - 5_000 - fee_bump]
            )
            if (cand.txid_int & 0xFF) == 0x3F:
                tx_3f = cand
                break
        assert tx_3f is not None
        node0.sendrawtransaction(tx_3f.serialize().hex())
        self.generatetoaddress(
            node0,
            1,
            V2_OP_TRUE_ADDRESS,
            coinbase_version=7,
            sync_fun=lambda: self.sync_all(self.nodes[0:2]),
        )
        assert_equal(node0.getblockcount(), 102)

        self.log.info(
            "Create intra-block parent-child spend chain in block 103 (Hole 12 test)"
        )
        cb2_txid, cb2_vout, cb2_sats = get_cb_utxo(2)
        parent_val = cb2_sats - 5_000
        parent_tx = build_v2_op_true_tx(cb2_txid, cb2_vout, [parent_val])
        child_val = parent_val - 5_000
        child_tx = build_v2_op_true_tx(parent_tx.txid_int, 0, [child_val])
        node0.sendrawtransaction(parent_tx.serialize().hex())
        node0.sendrawtransaction(child_tx.serialize().hex())
        self.generatetoaddress(
            node0,
            1,
            V2_OP_TRUE_ADDRESS,
            coinbase_version=7,
            sync_fun=lambda: self.sync_all(self.nodes[0:2]),
        )
        assert_equal(node0.getblockcount(), 103)

        self.log.info("Mine pivot block 104 and sync headers/blocks to node1")
        self.generatetoaddress(
            node0,
            1,
            V2_OP_TRUE_ADDRESS,
            coinbase_version=7,
            sync_fun=lambda: self.sync_all(self.nodes[0:2]),
        )
        assert_equal(node0.getblockcount(), 104)

        # Verify initial fast-sync state on nodes
        info0 = node0.getblockchaininfo()
        info1 = node1.getblockchaininfo()
        assert_equal(info0["fast_sync_active"], False)
        assert_equal(info0["earliest_verified_height"], 0)
        assert_equal(info1["fast_sync_active"], False)
        assert_equal(info1["earliest_verified_height"], 0)

        peer = node0.add_p2p_connection(FastSyncPeer())

        pivot_height = 104
        pivot_hash_hex = node0.getblockhash(pivot_height)
        pivot_id = block_hash_to_v2_id(pivot_hash_hex)

        self.log.info("Request UTXOROOTS at pivot height 104 over P2P")
        peer.send_and_ping(msg_getutxoroots(pivot_id))
        with p2p_lock:
            roots_msg = peer.last_utxoroots
        assert roots_msg is not None
        assert_equal(roots_msg.pivot_block_id, pivot_id)
        assert_equal(roots_msg.height, pivot_height)
        assert_equal(len(roots_msg.shards), 256)

        non_empty_shards = [
            idx for idx, (tag, _root) in enumerate(roots_msg.shards) if tag != 0
        ]
        assert len(non_empty_shards) > 0
        assert 0x3F in non_empty_shards, (
            "Shard 0x3F must be non-empty for fault injection test"
        )
        self.log.info(
            f"Pivot height {pivot_height} has {len(non_empty_shards)} non-empty depth-8 shards (including 0x3F)"
        )

        # Fetch all non-empty depth-8 shards over P2P (pipelined)
        for s in non_empty_shards:
            peer.send_without_ping(msg_getutxoshard(pivot_id, 8, s))
        peer.sync_with_ping()

        shard_hex_list = []
        shards_by_key = {}
        for s in non_empty_shards:
            with p2p_lock:
                shard_msg = peer.utxoshards.get((8, s))
            assert shard_msg is not None
            assert_equal(shard_msg.pivot_block_id, pivot_id)
            assert_equal(shard_msg.prefix_depth, 8)
            assert_equal(shard_msg.prefix_bits, s)
            shard_hex_list.append(shard_msg.raw_payload.hex())
            shards_by_key[(8, s)] = shard_msg.raw_payload

        self.log.info(
            "Verify depth-9 adaptive sub-shard P2P requests include boundary sibling proof"
        )
        first_shard = non_empty_shards[0]
        peer.send_without_ping(msg_getutxoshard(pivot_id, 9, first_shard))
        peer.send_and_ping(msg_getutxoshard(pivot_id, 9, first_shard | (1 << 8)))
        with p2p_lock:
            sub0 = peer.utxoshards.get((9, first_shard))
            sub1 = peer.utxoshards.get((9, first_shard | (1 << 8)))
        assert sub0 is not None and sub1 is not None

        self.log.info(
            "Test adversarial fast-sync pivot rejections on node1 (Hole 11 defenses)"
        )
        # 1. Missing non-empty shard must fail verification
        assert_raises_rpc_error(
            -25,
            "missing utxoshard for non-empty depth-8 shard",
            node1.setfastsyncpivot,
            pivot_hash_hex,
            roots_msg.raw_payload.hex(),
            shard_hex_list[:-1],
        )

        # 2. Tampering cardinality_tag in UTXOROOTS must fail header state_root verification
        tampered_roots = bytearray(roots_msg.raw_payload)
        tampered_offset = 96 + first_shard * 33
        tampered_roots[tampered_offset] = (
            2 if tampered_roots[tampered_offset] == 1 else 1
        )
        assert_raises_rpc_error(
            -25,
            None,
            node1.setfastsyncpivot,
            pivot_hash_hex,
            bytes(tampered_roots).hex(),
            shard_hex_list,
        )

        # 3. Tampering coin bytes inside a UTXOSHARD must fail shard root verification
        tampered_shard = bytearray(bytes.fromhex(shard_hex_list[0]))
        tampered_shard[-1] ^= 0x01
        assert_raises_rpc_error(
            -25,
            None,
            node1.setfastsyncpivot,
            pivot_hash_hex,
            roots_msg.raw_payload.hex(),
            [bytes(tampered_shard).hex()] + shard_hex_list[1:],
        )

        self.log.info("Import verified fast-sync pivot at height 104 on node1")
        pivot_res = node1.setfastsyncpivot(
            pivot_hash_hex, roots_msg.raw_payload.hex(), shard_hex_list
        )
        assert_equal(pivot_res["earliest_verified_height"], 104)
        assert_equal(pivot_res["fast_sync_active"], True)
        assert pivot_res["coins_imported"] > 0

        # Verify live CoinsTip() on node1 via gettxout
        tip_txid = child_tx.txid_hex
        txout_info = node1.gettxout(tip_txid, 0)
        assert txout_info is not None
        assert_equal(txout_info["confirmations"], 2)

        info1 = node1.getblockchaininfo()
        assert_equal(info1["fast_sync_active"], True)
        assert_equal(info1["earliest_verified_height"], 104)

        self.log.info(
            "Test autonomous multi-peer P2P swarm on header-only node2 with corrupted shard 0x3F fault injection"
        )
        for h in range(1, pivot_height + 1):
            hdr_hex = node0.getblockheader(node0.getblockhash(h), False)
            node2.submitheader(hdr_hex)
        assert_equal(node2.getblockcount(), 0)

        peer_bad = node2.add_p2p_connection(
            SwarmServerPeer(
                roots_msg.raw_payload, shards_by_key, corrupt_shard_bits=0x3F
            ),
            services=SWARM_PEER_SERVICES,
        )
        peer_good = node2.add_p2p_connection(
            SwarmServerPeer(
                roots_msg.raw_payload, shards_by_key, corrupt_shard_bits=None
            ),
            services=SWARM_PEER_SERVICES,
        )
        # Hold peer_good's responses briefly so peer_bad can inject corrupted shard 0x3F
        # while (8, 0x3F) is in flight in the swarm coordinator.
        with p2p_lock:
            peer_good.hold_responses = True

        swarm_start = node2.syncutxoshardswarm(pivot_hash_hex)
        assert_equal(swarm_start["pivot_height"], 104)
        assert_equal(swarm_start["active_peers"], 2)

        # Wait until peer_bad has received GETUTXOSHARD requests
        self.wait_until(lambda: len(peer_bad.getutxoshard_keys) > 0, timeout=10)
        # If shard 0x3F was assigned to peer_good on the initial round-robin pass,
        # also have peer_bad inject the corrupted shard 0x3F while in flight
        # so the swarm coordinator exercises shard 0x3F rejection from peer_bad.
        if (8, 0x3F) not in peer_bad.getutxoshard_keys and peer_bad.is_connected:
            peer_bad._serve_shard((8, 0x3F))

        self.wait_until(
            lambda: node2.getfastsyncinfo()["corrupted_shards_rejected"] >= 1,
            timeout=10,
        )
        fs_mid = node2.getfastsyncinfo()
        assert_equal(fs_mid["banned_swarm_peers"], 1)
        assert_equal(fs_mid["active_peers"], 1)

        # Now release peer_good's shard responses (including re-requested shard 0x3F)
        peer_good.flush_deferred_shards()
        peer_good.sync_with_ping()

        self.wait_until(
            lambda: node2.getfastsyncinfo()["swarm_state"] == "completed",
            timeout=15,
        )
        fs_done = node2.getfastsyncinfo()
        assert_equal(fs_done["fast_sync_active"], True)
        assert_equal(fs_done["earliest_verified_height"], 104)
        assert_equal(fs_done["verified_shards"], len(non_empty_shards))
        assert_equal(fs_done["coins_imported"], pivot_res["coins_imported"])
        assert_equal(node2.getblockcount(), 104)

        # Verify node2 has live UTXO coins at pivot 104 via gettxout
        txout_node2 = node2.gettxout(tip_txid, 0)
        assert txout_node2 is not None
        assert_equal(txout_node2["confirmations"], 2)

        self.log.info(
            "Mine and connect Block 105 on fast-synced node2 (which has only headers 1..104) and verify on node0"
        )
        spend_tx = build_v2_op_true_tx(child_tx.txid_int, 0, [child_val - 5_000])
        node2.sendrawtransaction(spend_tx.serialize().hex())
        self.generatetoaddress(
            node2, 1, V2_OP_TRUE_ADDRESS, coinbase_version=7, sync_fun=self.no_op
        )
        assert_equal(node2.getblockcount(), 105)
        hash_105 = node2.getblockhash(105)
        block_105_hex = node2.getblock(hash_105, 0)
        assert_equal(node0.submitblock(block_105_hex), None)
        assert_equal(node0.getbestblockhash(), hash_105)

        self.log.info("Peel block 104 -> 103 on node1 via GETBLOCKUNDO / BLOCKUNDO")
        peer.send_and_ping(msg_getblockundo(pivot_id))
        with p2p_lock:
            undo_104 = peer.blockundos.get(pivot_id)
        assert undo_104 is not None

        peel_104 = node1.peelfastsyncblock(pivot_hash_hex, undo_104.raw_payload.hex())
        assert_equal(peel_104["parent_height"], 103)
        assert_equal(peel_104["earliest_verified_height"], 103)
        assert_equal(peel_104["fast_sync_active"], True)
        assert_equal(peel_104["intra_block_spends"], 0)
        assert_equal(peel_104["prior_spends_restored"], 0)

        self.log.info(
            "Reverse-verify a missing historical block without rolling back the live tip"
        )
        historical_block = node0.getblock(pivot_hash_hex, 0)
        live_tip = node2.getbestblockhash()
        live_coin = node2.gettxout(spend_tx.txid_hex, 0)
        assert live_coin is not None
        # Node2 joined from headers and shards, so exercise the optional block
        # body rather than relying on history already downloaded from genesis.
        assert_raises_rpc_error(
            -25,
            "Failed to read block",
            node2.peelfastsyncblock,
            pivot_hash_hex,
            undo_104.raw_payload.hex(),
        )
        supplied = node2.peelfastsyncblock(
            pivot_hash_hex, undo_104.raw_payload.hex(), historical_block
        )
        assert_equal(supplied["earliest_verified_height"], 103)
        assert_equal(node2.getbestblockhash(), live_tip)
        assert_equal(node2.gettxout(spend_tx.txid_hex, 0), live_coin)

        self.log.info(
            "Restart with partial backwards verification and preserve both frontiers"
        )
        node2.kill_process()
        self.start_node(2)
        assert_equal(node2.getbestblockhash(), live_tip)
        assert_equal(node2.gettxout(spend_tx.txid_hex, 0), live_coin)
        assert_equal(node2.getblockchaininfo()["earliest_verified_height"], 103)
        assert_equal(node2.getblockchaininfo()["fast_sync_active"], True)
        self.generatetoaddress(
            node2, 1, V2_OP_TRUE_ADDRESS, coinbase_version=7, sync_fun=self.no_op
        )
        assert_equal(node2.getblockcount(), 106)
        live_tip = node2.getbestblockhash()
        live_coin = node2.gettxout(spend_tx.txid_hex, 0)
        assert live_coin is not None

        self.log.info(
            "Peel block 103 -> 102 with intra-block parent-child spend (Hole 12 test)"
        )
        hash_103_hex = node0.getblockhash(103)
        id_103 = block_hash_to_v2_id(hash_103_hex)
        peer.send_and_ping(msg_getblockundo(id_103))
        with p2p_lock:
            undo_103 = peer.blockundos.get(id_103)
        assert undo_103 is not None

        # Tampering with BLOCKUNDO payload for block 103 must be rejected
        bad_undo_103 = bytearray(undo_103.raw_payload)
        bad_undo_103[40] ^= 0xFF  # Corrupt parent_monetary_state
        assert_raises_rpc_error(
            -25,
            None,
            node1.peelfastsyncblock,
            hash_103_hex,
            bytes(bad_undo_103).hex(),
        )

        self.log.info("Reject malformed history without changing either frontier")
        for undo_hex, block_hex, code, message in [
            (bytes(bad_undo_103).hex(), node0.getblock(hash_103_hex, 0), -25, None),
            (undo_103.raw_payload.hex(), historical_block, -25, "Provided block hash"),
            ("00", node0.getblock(hash_103_hex, 0), -22, "Invalid BLOCKUNDO"),
        ]:
            assert_raises_rpc_error(
                code,
                message,
                node2.peelfastsyncblock,
                hash_103_hex,
                undo_hex,
                block_hex,
            )
            assert_equal(node2.getblockchaininfo()["earliest_verified_height"], 103)
            assert_equal(node2.getbestblockhash(), live_tip)
            assert_equal(node2.gettxout(spend_tx.txid_hex, 0), live_coin)
        supplied_103 = node2.peelfastsyncblock(
            hash_103_hex, undo_103.raw_payload.hex(), node0.getblock(hash_103_hex, 0)
        )
        assert_equal(supplied_103["earliest_verified_height"], 102)
        assert_equal(supplied_103["intra_block_spends"], 1)
        assert_equal(node2.getbestblockhash(), live_tip)
        assert_equal(node2.gettxout(spend_tx.txid_hex, 0), live_coin)
        self.restart_node(2)
        assert_equal(node2.getblockchaininfo()["earliest_verified_height"], 102)
        assert_equal(node2.getbestblockhash(), live_tip)
        assert_equal(node2.gettxout(spend_tx.txid_hex, 0), live_coin)

        peel_103 = node1.peelfastsyncblock(hash_103_hex, undo_103.raw_payload.hex())
        assert_equal(peel_103["parent_height"], 102)
        assert_equal(peel_103["earliest_verified_height"], 102)
        assert_equal(peel_103["fast_sync_active"], True)
        assert_equal(peel_103["intra_block_spends"], 1)
        assert_equal(peel_103["prior_spends_restored"], 1)

        self.log.info(
            "Peel remaining blocks 102 -> 0 backwards to genesis and verify Hole 16 completion"
        )
        block_hashes = {}
        block_ids = {}
        for h in range(102, 0, -1):
            bh_hex = node0.getblockhash(h)
            bid = block_hash_to_v2_id(bh_hex)
            block_hashes[h] = bh_hex
            block_ids[h] = bid
            peer.send_without_ping(msg_getblockundo(bid))
        peer.sync_with_ping()

        for h in range(102, 0, -1):
            with p2p_lock:
                undo_h = peer.blockundos.get(block_ids[h])
            assert undo_h is not None
            res = node1.peelfastsyncblock(block_hashes[h], undo_h.raw_payload.hex())
            assert_equal(res["parent_height"], h - 1)
            assert_equal(res["earliest_verified_height"], h - 1)
            assert_equal(res["fast_sync_active"], (h - 1) > 0)

        info1_final = node1.getblockchaininfo()
        assert_equal(info1_final["earliest_verified_height"], 0)
        assert_equal(info1_final["fast_sync_active"], False)
        completed_tip = node1.getbestblockhash()
        self.restart_node(1)
        assert_equal(node1.getbestblockhash(), completed_tip)
        assert_equal(node1.getblockchaininfo()["earliest_verified_height"], 0)
        assert_equal(node1.getblockchaininfo()["fast_sync_active"], False)


if __name__ == "__main__":
    FastSyncAndReversePeelTest().main()
