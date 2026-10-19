#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test V2 stateful outputs, ENFORCEOUTPUT and the V2 VM RPCs.

A counter vault holds HAS_STATE root STATEHASH(n). Spending it proves n with
STATEVERIFY, and ENFORCEOUTPUT requires an exact continuation of the vault
(INHERIT paths, same branches) holding STATEHASH(n + 1) and the vault's value
minus a fixed fee. The test creates, spends and continues the vault; checks
rejected transitions, unauthorized state, legacy EMITLOG; exercises
getv2vmprofile, testv2transaction and simulatev2transaction (which builds the
continuation from a zero-output draft); and checks that a reorg restores the
spent state root and its continuation.
"""

import struct

from test_framework.messages import (
    lotus_v2_branch_leaf,
    lotus_v2_tagged_hash,
    ser_compact_size,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

OP_TRUE = b"\x4e"
OP_TRUE_DESCRIPTOR = "raw(4e)"
FEE = 10_000

# Opcodes (P03 registry).
N0, N1 = b"\x00", b"\x4e"
DROP, DUP, ADD, SUB, EQUALVERIFY = b"\x79", b"\x7a", b"\x9e", b"\x9f", b"\x92"
STATEHASH, INPUTINDEX, UTXOVALUE = b"\xc3", b"\xd0", b"\xd6"
ENFORCEOUTPUT, STATEVERIFY, EMITLOG = b"\xeb", b"\xed", b"\x6c"


def num(n: int) -> bytes:
    return n.to_bytes(16, "little", signed=True)


def push(data: bytes) -> bytes:
    if not data:
        return b"\x4c\x00"
    if len(data) <= 75:
        return bytes([len(data)]) + data
    assert len(data) <= 255
    return b"\x4c" + bytes([len(data)]) + data


def statehash(items: list) -> bytes:
    payload = ser_compact_size(len(items))
    for item in items:
        payload += ser_compact_size(len(item)) + item
    return lotus_v2_tagged_hash("Lotus/v2/contractstate", payload)


def template(
    *,
    value_mode=0,
    token_mode=0,
    paths_mode=0,
    burn=False,
    wildcard=False,
    value=0,
    branch_count=0,
    mask=0,
    stack_mask=0,
    state_mode=0,
    output_mode=0,
    branches=(),
) -> bytes:
    flags = (
        value_mode
        | token_mode << 2
        | paths_mode << 4
        | int(burn) << 6
        | int(wildcard) << 7
    )
    out = bytes([flags])
    if value_mode in (1, 2):
        out += struct.pack("<Q", value)
    out += struct.pack(
        "<BHHBB", branch_count, mask, stack_mask, state_mode, output_mode
    )
    for branch in branches:
        out += branch
    return out


# Counter vault: args [n].
#   n DUP N(1) STATEHASH STATEVERIFY       -- the coin holds STATEHASH(n)
#   N(1) ADD N(1) STATEHASH                -- next state STATEHASH(n + 1)
#   INPUTINDEX UTXOVALUE <FEE> SUB         -- next value
#   <template> N(0) ENFORCEOUTPUT DROP TRUE
VAULT_TEMPLATE = template(value_mode=3, paths_mode=2, state_mode=2)
VAULT = (
    DUP
    + N1
    + STATEHASH
    + STATEVERIFY
    + N1
    + ADD
    + N1
    + STATEHASH
    + INPUTINDEX
    + UTXOVALUE
    + push(num(FEE))
    + SUB
    + push(VAULT_TEMPLATE)
    + N0
    + ENFORCEOUTPUT
    + DROP
    + N1
)
VAULT_ROOT = lotus_v2_branch_leaf(VAULT)

# Creator: args [state, branch root, value]; authorizes one stateful output
# with that single branch. (Anyone may spend it: state authorization alone
# does not authenticate state, see plan I-10.)
CREATOR_TEMPLATE = template(value_mode=3, branch_count=1, stack_mask=1, state_mode=2)
CREATOR = push(CREATOR_TEMPLATE) + N0 + ENFORCEOUTPUT + DROP + N1
CREATOR_ROOT = lotus_v2_branch_leaf(CREATOR)


def ser_bytes(b: bytes) -> bytes:
    return ser_compact_size(len(b)) + b


def spend_input(txid_hex: str, vout: int, script: bytes, args=()) -> bytes:
    out = bytes.fromhex(txid_hex)[::-1] + struct.pack("<IIB", vout, 0xFFFFFFFF, 1)
    out += ser_compact_size(0) + ser_compact_size(1)  # path 0, one witness
    out += ser_bytes(script) + ser_compact_size(0)  # no siblings
    out += ser_compact_size(len(args)) + b"".join(ser_bytes(a) for a in args)
    return out


def output(value: int, root: bytes, state: bytes = None) -> bytes:
    flags = 4 if state is not None else 0
    out = struct.pack("<BQ", flags, value)
    if state is not None:
        out += state
    out += ser_compact_size(1) + root
    out += ser_compact_size(1) + ser_compact_size(1) + ser_compact_size(0)
    return out


def v7(inputs: list, outputs: list) -> str:
    raw = struct.pack("<IQHH", 7, 0, len(inputs), len(outputs))
    return (raw + b"".join(inputs) + b"".join(outputs)).hex()


class V2VmOpcodesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def coinbase(self, height: int):
        block = self.node.getblock(self.node.getblockhash(height), 2)
        cb = block["tx"][0]
        return cb["txid"], 0, int(round(float(cb["vout"][0]["value"]) * 100))

    def mine(self, n=1):
        return self.generatetodescriptor(self.node, n, OP_TRUE_DESCRIPTOR)

    def run_test(self):
        self.node = self.nodes[0]
        self.mine(110)

        self.test_profile()
        vault = self.test_create_vault()
        vault = self.test_continue_vault(vault)
        self.test_rejections(vault)
        self.test_simulation_and_reorg(vault)

    def test_profile(self):
        self.log.info("getv2vmprofile reports the allocation and costs")
        profile = self.node.getv2vmprofile()
        classes = {e["byte"]: e["class"] for e in profile["opcodes"]}
        assert_equal(len(classes), 256)
        assert_equal(classes["eb"], "assigned")
        assert_equal(classes["c3"], "assigned")
        assert_equal(classes["6c"], "simulation-only")
        assert_equal(classes["ff"], "ext2-prefix")
        assert_equal(classes["67"], "success")
        assert_equal(profile["ext2_assigned"], [])
        assert_equal(len(profile["profile_digest"]), 64)
        assert_equal(profile["limits"]["max_inputs"], 256)
        assert_equal(profile["limits"]["max_outputs"], 256)
        assert_equal(profile["simulation_rpc"], True)
        eb = [c for c in profile["cost_profile"]["opcodes"] if c["byte"] == "eb"]
        assert_equal(eb[0]["per_scanned_output"], 1)

    def test_create_vault(self):
        self.log.info("Fund a creator coin, then create a stateful vault")
        txid, vout, value = self.coinbase(1)
        creator_value = value - FEE
        fund = v7(
            [spend_input(txid, vout, OP_TRUE)], [output(creator_value, CREATOR_ROOT)]
        )
        fund_txid = self.node.sendrawtransaction(fund)
        self.mine()

        vault_value = creator_value - FEE
        state0 = statehash([num(0)])
        args = [state0, VAULT_ROOT, num(vault_value)]
        create = v7(
            [spend_input(fund_txid, 0, CREATOR, args)],
            [output(vault_value, VAULT_ROOT, state0)],
        )
        result = self.node.testv2transaction(create)
        assert_equal(result["valid"], True)
        effects = result["invocations"][0]["effects"]
        assert_equal(effects["claims"], [{"output": 0, "amount": 0}])
        assert_equal(effects["state_authorized"], [0])
        assert_equal(result["post_check"]["ok"], True)
        create_txid = self.node.sendrawtransaction(create)
        self.mine()
        coin = self.node.gettxout(create_txid, 0)
        assert_equal(coin["stateRoot"], state0.hex())
        return create_txid, vault_value, 0

    def continuation(self, vault, n_args=None, state=None, value=None):
        txid, value_in, n = vault
        return v7(
            [spend_input(txid, 0, VAULT, [num(n if n_args is None else n_args)])],
            [
                output(
                    value_in - FEE if value is None else value,
                    VAULT_ROOT,
                    statehash([num(n + 1)]) if state is None else state,
                )
            ],
        )

    def test_continue_vault(self, vault):
        self.log.info("Spend the vault into its continuation")
        txid, value, n = vault
        tx = self.continuation(vault)
        result = self.node.testv2transaction(tx)
        assert_equal(result["valid"], True)
        assert result["invocations"][0]["accounting_cost"] > 0
        next_txid = self.node.sendrawtransaction(tx)
        self.mine()
        assert_equal(self.node.gettxout(txid, 0), None)
        coin = self.node.gettxout(next_txid, 0)
        assert_equal(coin["stateRoot"], statehash([num(n + 1)]).hex())
        return next_txid, value - FEE, n + 1

    def test_rejections(self, vault):
        self.log.info("Reject a wrong proof, wrong next state and wrong value")
        # Proving the wrong current counter fails STATEVERIFY.
        wrong_proof = self.continuation(
            vault, n_args=vault[2] + 1, state=statehash([num(vault[2] + 2)])
        )
        result = self.node.testv2transaction(wrong_proof)
        assert_equal(result["valid"], False)
        assert_equal(result["invocations"][0]["error"], "STATEVERIFY mismatch")
        assert_raises_rpc_error(-26, None, self.node.sendrawtransaction, wrong_proof)
        # A different next state, or value, matches no output.
        for bad in (
            self.continuation(vault, state=statehash([num(99)])),
            self.continuation(vault, value=vault[1] - FEE - 1),
        ):
            result = self.node.testv2transaction(bad)
            assert_equal(
                result["invocations"][0]["error"], "ENFORCEOUTPUT no matching output"
            )
            assert_raises_rpc_error(-26, None, self.node.sendrawtransaction, bad)

        self.log.info("Reject an unauthorized state output")
        txid, vout, value = self.coinbase(2)
        forged = v7(
            [spend_input(txid, vout, OP_TRUE)],
            [output(value - FEE, VAULT_ROOT, statehash([num(7)]))],
        )
        result = self.node.testv2transaction(forged)
        assert_equal(result["invocations"][0]["status"], "success")
        assert_equal(result["post_check"]["ok"], False)
        assert_equal(result["post_check"]["error"], "state-output-unauthorized")
        assert_raises_rpc_error(
            -26, "state-output-unauthorized", self.node.sendrawtransaction, forged
        )

        self.log.info("EMITLOG is invalid on-chain")
        emit_script = push(b"topic") + N1 + EMITLOG + N1
        txid, vout, value = self.coinbase(3)
        emit_coin = v7(
            [spend_input(txid, vout, OP_TRUE)],
            [output(value - FEE, lotus_v2_branch_leaf(emit_script))],
        )
        emit_txid = self.node.sendrawtransaction(emit_coin)
        self.mine()
        emit = v7(
            [spend_input(emit_txid, 0, emit_script)],
            [output(value - 2 * FEE, lotus_v2_branch_leaf(OP_TRUE))],
        )
        result = self.node.testv2transaction(emit)
        assert_equal(result["invocations"][0]["error"], "EMITLOG is invalid on-chain")
        assert_raises_rpc_error(-26, None, self.node.sendrawtransaction, emit)
        sim = self.node.simulatev2transaction(emit)
        assert_equal(sim["invocations"][0]["status"], "success")
        assert_equal(sim["events"][0]["topic"], b"topic".hex())

    def test_simulation_and_reorg(self, vault):
        self.log.info("Simulate the continuation from a zero-output draft")
        txid, value, n = vault
        draft = v7([spend_input(txid, 0, VAULT, [num(n)])], [])
        sim = self.node.simulatev2transaction(draft)
        assert_equal(sim["invocations"][0]["status"], "success")
        assert_equal(sim["provisional"], True)
        assert_equal(len(sim["drafts"]), 1)
        assert_equal(sim["drafts"][0]["template"], VAULT_TEMPLATE.hex())
        assert_equal(sim["drafts"][0]["wallet_fill_required"], False)
        assert_equal(sim["post_check"]["ok"], True)
        assert_equal(sim["hex"], self.continuation(vault))
        # The completed draft is a valid transaction.
        assert_equal(self.node.testv2transaction(sim["hex"])["valid"], True)
        next_txid = self.node.sendrawtransaction(sim["hex"])
        [block] = self.mine()
        state_next = statehash([num(n + 1)]).hex()
        assert_equal(self.node.gettxout(next_txid, 0)["stateRoot"], state_next)

        self.log.info("A reorg restores the spent state root")
        self.node.invalidateblock(block)
        assert_equal(
            self.node.gettxout(txid, 0, False)["stateRoot"], statehash([num(n)]).hex()
        )
        assert next_txid in self.node.getrawmempool()
        assert_equal(self.node.gettxout(next_txid, 0)["stateRoot"], state_next)
        self.node.reconsiderblock(block)
        assert_equal(self.node.getbestblockhash(), block)
        assert_equal(self.node.gettxout(txid, 0), None)
        assert_equal(self.node.gettxout(next_txid, 0)["stateRoot"], state_next)

        self.log.info("simulatev2transaction can be disabled")
        self.restart_node(0, ["-acceptnonstdtxn=1", "-v2simulationrpc=0"])
        assert_raises_rpc_error(
            -1,
            "simulatev2transaction is disabled",
            self.node.simulatev2transaction,
            draft,
        )
        assert_equal(self.node.getv2vmprofile()["simulation_rpc"], False)


if __name__ == "__main__":
    V2VmOpcodesTest().main()
