#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Legacy chains, v7 bridge spends and both Chronik projections retain coin kind."""

import json
import urllib.request

from test_framework.hash import hash160
from test_framework.messages import XEC, COutPoint
from test_framework.script import OP_TRUE, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, chronik_port
from test_framework.v7tx import (
    LegacyMiniWallet,
    new_v7_tx,
    p2sh_bridge_input,
    v2_op_true_txout,
)


class ChronikV2BridgeTest(BitcoinTestFramework):
    setup_clean_chain = True
    num_nodes = 1
    extra_args = [["-chronik", "-coinbaseversion=2", "-acceptnonstdtxn=1"]]
    requires = {"chronik"}

    def json_get(self, path):
        with urllib.request.urlopen(
            f"http://127.0.0.1:{chronik_port(0)}/v2/explorer/v1/{path}", timeout=10
        ) as response:
            return json.load(response)

    def run_test(self):
        node = self.nodes[0]
        chronik = node.get_chronik_client()
        wallet = LegacyMiniWallet(node)
        self.generate(wallet, 105)
        chain = wallet.create_self_transfer_chain(chain_length=2)
        legacy_script = wallet._scriptPubKey
        script_client = chronik.script("p2sh", hash160(bytes(CScript([OP_TRUE]))).hex())
        for item in chain:
            raw = bytes.fromhex(item["hex"])
            tx = chronik.validate_tx(raw).ok()
            assert_equal(tx.txid, bytes.fromhex(item["txid"])[::-1])
            assert_equal(tx.version, 2)
            assert_equal(tx.inputs[0].is_legacy, True)
            assert_equal(tx.inputs[0].output_script, legacy_script)
            assert_equal(tx.outputs[0].is_legacy, True)
            result = chronik.broadcast_tx(raw).ok()
            assert_equal(result.txid, tx.txid)
        tip = chain[-1]
        assert any(
            u.outpoint.txid == bytes.fromhex(tip["txid"])[::-1] and u.is_legacy
            for u in script_client.utxos().ok().utxos
        )
        # A legacy script can be byte-identical to a HAS_STATE native output.
        # Its creating grammar, rather than byte inference, determines kind.
        framed = wallet.create_self_transfer()["tx"]
        plain = v2_op_true_txout(framed.vout[0].nValue).scriptPubKey
        framed.vout[0].scriptPubKey = (
            bytes([4]) + bytes(plain[1:9]) + bytes([9]) * 32 + bytes(plain[9:])
        )
        framed_id = framed.txid_hex
        framed_proto = chronik.validate_tx(framed.serialize()).ok()
        assert_equal(framed_proto.outputs[0].is_legacy, True)
        assert_equal(framed_proto.outputs[0].state_root, b"")
        chronik.broadcast_tx(framed.serialize()).ok()
        self.generate(node, 1)
        assert any(
            u.outpoint.txid == bytes.fromhex(tip["txid"])[::-1]
            and u.is_legacy
            and u.block_height > 0
            for u in script_client.utxos().ok().utxos
        )

        bridge = new_v7_tx()
        # A height lock gives the native frame a nonzero first byte after
        # version. The legacy parser cannot decode this as an empty v7 tx.
        bridge.nV2Lock = (100 << 8) | 1
        bridge.nLockTime = 100
        bridge.vin = [
            p2sh_bridge_input(
                COutPoint(int(tip["txid"], 16), 0), bytes(CScript([OP_TRUE])), []
            )
        ]
        value = int(tip["new_utxo"]["value"] * XEC) - 10000
        bridge.vout = [v2_op_true_txout(value)]
        raw = bridge.serialize()
        txid = bridge.txid_hex
        validated = chronik.validate_tx(raw).ok()
        assert_equal(validated.txid, bytes.fromhex(txid)[::-1])
        assert_equal(validated.version, 7)
        assert_equal(validated.inputs[0].is_legacy, True)
        assert_equal(validated.inputs[0].output_script, legacy_script)
        assert_equal(validated.outputs[0].is_legacy, False)
        malformed = chronik.validate_tx(raw[:20])
        assert_equal(malformed.status, 500)
        self.log.info("malformed native decode error: %s", malformed.err(500).msg)
        assert_equal(chronik.broadcast_tx(raw).ok().txid, validated.txid)
        assert_equal(
            chronik.tx(tip["txid"]).ok().outputs[0].spent_by.txid, validated.txid
        )
        assert not any(
            u.outpoint.txid == bytes.fromhex(tip["txid"])[::-1]
            for u in script_client.utxos().ok().utxos
        )
        assert txid in [t.txid[::-1].hex() for t in script_client.history().ok().txs]
        self.generate(node, 1)
        wire_id = bytes.fromhex(txid)[::-1].hex()
        self.wait_until(
            lambda: (
                (self.json_get("status").get("indexed_anchor") or {}).get("block_id")
                == bytes.fromhex(node.getbestblockhash())[::-1].hex()
            )
        )
        legacy_id = bytes.fromhex(tip["txid"])[::-1].hex()
        framed_record = self.json_get(
            f"outputs/{bytes.fromhex(framed_id)[::-1].hex()}/0"
        )["data"]
        assert_equal(framed_record["is_legacy"], True)
        assert_equal(framed_record["branches"], [])
        assert_equal(framed_record["has_state"], False)
        output = self.json_get(f"outputs/{legacy_id}/0")["data"]
        assert_equal(output["is_legacy"], True)
        assert_equal(output["legacy_script"], legacy_script.hex())
        assert_equal(output["branches"], [])
        inputs = self.json_get(f"transactions/by-id/{legacy_id}/inputs")["data"][
            "items"
        ]
        assert_equal(inputs[0]["kind"], "legacy_spend")
        assert_equal(inputs[0]["witness_count"], "0")
        inputs = self.json_get(f"transactions/by-id/{wire_id}/inputs")["data"]["items"]
        assert_equal(inputs[0]["kind"], "spend")
        assert_equal(inputs[0]["resolved_coin"]["output"]["is_legacy"], True)
        assert_equal(chronik.raw_tx(txid).ok().raw_tx, raw)
        self.restart_node(0)
        assert all(u.is_legacy for u in script_client.utxos().ok().utxos)
        assert_equal(chronik.tx(txid).ok().inputs[0].is_legacy, True)
        assert_equal(chronik.tx(tip["txid"]).ok().outputs[0].is_legacy, True)


if __name__ == "__main__":
    ChronikV2BridgeTest().main()
