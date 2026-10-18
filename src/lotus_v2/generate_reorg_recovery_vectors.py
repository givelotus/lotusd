#!/usr/bin/env python3
"""Regenerate reorg fixture after authenticated Coin-v2 provenance changes.

Requires blake3==1.0.11 and the frozen Python reference at c2a222f1ed04857139c6ade9f6d57adff1f20bb8.
Export tools/lotus-v2-reference from that Git revision to a separate directory;
pass the exported tools/lotus-v2-reference directory with --reference. Every
module hash is checked against the immutable input manifest. The adapter below
adds only Coin encoding/version/fee-lifetime provenance; it never calls C++.
All valid bodies pass the independent VM, monetary, ASERT, PoW, and full-connect
engine. The invalid spend remains unresolved; its child retains a bad ancestor.
"""

import argparse
import dataclasses
import hashlib
import json
import pathlib
import re
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--reference", type=pathlib.Path, required=True)
parser.add_argument(
    "--input",
    type=pathlib.Path,
    default=pathlib.Path(__file__).with_name("testdata")
    / "reorg_recovery_coin_v2_input.json",
)
parser.add_argument("--output", type=pathlib.Path, required=True)
parser.add_argument("--check-cpp", type=pathlib.Path)
args = parser.parse_args()
assert (
    hashlib.sha256(args.input.read_bytes()).hexdigest()
    == "3e734e04f7a139c52325f95dbafa14ef5afe1a4cc0a5ba1daf1260ca336e514d"
)
manifest = json.loads(args.input.read_text())
for name, expected in manifest["reference_files"].items():
    assert (
        hashlib.sha256((args.reference / name).read_bytes()).hexdigest() == expected
    ), name
sys.path.insert(0, str(args.reference.resolve()))
import blake3

assert blake3.__version__ == "1.0.11"
from lotus_v2_reference import block as b, block_cost as bc
from lotus_v2_reference.signing import TxProfile, identity_digests, encode_transaction
from lotus_v2_reference.block_wire import (
    decode_block_wire,
    encode_block_wire,
    complete_transaction_root,
)
from lotus_v2_reference.block_seal import parse_header, block_id
from lotus_v2_reference.header_context import HeaderChainProfile, parent_median_time
from lotus_v2_reference.asert import compact_decode
from lotus_v2_reference.monetary import Profile, MonetaryState, advance, block_cost
from lotus_v2_reference.encoding import encode_compact_size
from lotus_v2_reference.vm import VMProfile, ASSIGNED

pat = r'\{"([a-z0-9-]+)",\s*"([0-9a-f]*)",\s*"([0-9a-f]*)",\s*"([0-9a-f]*)",\s*"([0-9a-f]*)",\s*\{([^}]*)\}\}'
rows = manifest["original_vectors"]
genesis = parse_header(bytes.fromhex(manifest["genesis_wire"])[:134])
initial_money = MonetaryState.from_bytes(bytes.fromhex(manifest["initial_monetary"]))
chain = bytes.fromhex(manifest["chain_id"])
TX = TxProfile(*manifest["transaction_profile"])
MP = Profile(*manifest["monetary_profile"])
COST = bc.BlockCostProfile(*manifest["cost_profile"])
HP = HeaderChainProfile(chain, *manifest["header_profile"])
coeff = manifest["opcode_costs"]
VM = VMProfile(
    8192,
    64,
    8192,
    256,
    256,
    1048576,
    64,
    100000000,
    1,
    {
        op: (
            lambda operands, results, c=coeff[op]: c[0]
            + c[1] * sum(operands)
            + c[2] * sum(results)
        )
        for op in ASSIGNED
    },
)
fees = {}
BaseCoin = b.Coin


@dataclasses.dataclass(frozen=True)
class CoinV2(BaseCoin):
    fee_per_output: int = 0

    def encode(self):
        raw = super().encode()
        lifespan = (
            21024000 if self.coinbase else min(21024000, 131400 + self.fee_per_output)
        )
        expiry = min((1 << 64) - 1, self.creation_height + lifespan)
        return (
            raw
            + bytes([2])
            + self.fee_per_output.to_bytes(8, "little")
            + expiry.to_bytes(8, "little")
        )


def make_coin(*args, **kw):
    c = CoinV2(*args, **kw)
    return dataclasses.replace(c, fee_per_output=fees.get(c.tx_id, 0))


b.Coin = bc.Coin = make_coin
start = (genesis, initial_money, {}, [genesis])
states = {block_id(chain, genesis): start}
ids = {block_id(chain, genesis): block_id(chain, genesis)}
txids = {}
stateroots = {}
result = []
for row in rows:
    old = decode_block_wire(bytes.fromhex(row["wire"]), TX, chain)
    oldparent = old.header.prev_id
    newparent = ids[oldparent]
    valid = bool(row["coins"])
    parent, money, coins, history = (
        states[oldparent] if oldparent in states else (None, None, None, None)
    )
    txs = []
    oldtxs = old.transactions
    for tx in oldtxs:
        nt = dataclasses.replace(
            tx,
            inputs=tuple(
                dataclasses.replace(
                    i,
                    prev_txid=ids.get(i.prev_txid, txids.get(i.prev_txid, i.prev_txid)),
                )
                for i in tx.inputs
            ),
        )
        txs.append(nt)
        txids[identity_digests(tx, TX, chain).txid] = identity_digests(
            nt, TX, chain
        ).txid
    header = dataclasses.replace(
        old.header,
        prev_id=newparent,
        tx_root=complete_transaction_root(tuple(txs), TX, chain),
        nonce=0,
    )
    if valid:
        ctx = b.Parent(
            chain, parent.height, parent.time, parent.state_root, money, parent
        )
        height = header.height
        mtp = parent_median_time(HP, parent, history)
        staged = dict(coins)
        accounted = []
        linear = []
        for n, tx in enumerate(txs):
            spent = []
            invocation = 0
            fee = 0
            if n:
                rec, invocation, spent = b._complete_ordinary(
                    tx,
                    ctx,
                    staged,
                    MP,
                    height=height,
                    mtp=mtp,
                    maturity=2,
                    vm_profile=VM,
                    tx_profile=TX,
                    block_cap=(1 << 128) - 1,
                )
                accounted.append(rec)
                fee = sum(c.value for c in spent) - sum(o.value for o in tx.outputs)
            tid = identity_digests(tx, TX, chain).txid
            fees[tid] = fee // sum(not o.flags & 2 for o in tx.outputs)
            linear.append(
                bc.authenticated_transaction_costs(
                    tx, TX, staged, height, mtp, invocation, COST
                ).account_linear
            )
            for c in spent:
                del staged[c.key()]
            for j, out in enumerate(tx.outputs):
                if not out.flags & 2:
                    c = make_coin(
                        tid, j, out.value, out.branches[0], height, mtp, n == 0, out
                    )
                    staged[c.key()] = c
        frames = sum(
            len(encode_compact_size(len(encode_transaction(t, TX)))) for t in txs
        )
        envelope = bc.authenticated_envelope_cost(frames, len(txs), COST)
        cost = block_cost(envelope, tuple(linear), MP)
        transition = advance(
            MP,
            money,
            work=(1 << 256) // (compact_decode(header.bits, HP.pow_limit) + 1),
            transactions=tuple(accounted),
            coinbase_native_outputs=sum(o.value for o in txs[0].outputs),
            coinbase_native_burn=0,
            coinbase_bytes=len(encode_transaction(txs[0], TX)),
            tx_frame_prefix_bytes=frames,
            account_block_cost=cost,
            enforce_block_cost=cost,
        )
        root = b.utxo_root(staged)
        state = b.state_root(chain, height, root, transition.state)
        header = dataclasses.replace(header, state_root=state)
        stateroots[old.header.state_root] = state
    else:
        header = dataclasses.replace(
            header, state_root=stateroots[old.header.state_root]
        )
    for nonce in range(1000000):
        header = dataclasses.replace(header, nonce=nonce)
        if int.from_bytes(block_id(chain, header), "little") <= compact_decode(
            header.bits, HP.pow_limit
        ):
            break
    else:
        raise ValueError("nonce exhausted")
    wire = encode_block_wire(header, tuple(txs), TX)
    bid = block_id(chain, header)
    ids[bytes.fromhex(row["id"])] = bid
    if valid:
        actual = dict(coins)
        connected = b.connect_complete_block(
            wire,
            ctx,
            history,
            HP,
            actual,
            money,
            MP,
            COST,
            tx_profile=TX,
            vm_profile=VM,
            block_cap=(1 << 128) - 1,
            coinbase_maturity=2,
        )
        assert connected.utxo_root == root
        nm = MonetaryState.from_bytes(connected.monetary_bytes)
        states[bytes.fromhex(row["id"])] = (header, nm, actual, [header, *history][:11])
        out = dict(
            name=row["name"],
            wire=wire.hex(),
            id=bid.hex(),
            root=root.hex(),
            monetary=nm.to_bytes().hex(),
            coins=[c.encode().hex() for c in actual.values()],
        )
    else:
        if parent is not None:
            before = dict(coins)
            try:
                b.connect_complete_block(
                    wire,
                    b.Parent(
                        chain,
                        parent.height,
                        parent.time,
                        parent.state_root,
                        money,
                        parent,
                    ),
                    history,
                    HP,
                    before,
                    money,
                    MP,
                    COST,
                    tx_profile=TX,
                    vm_profile=VM,
                    block_cap=(1 << 128) - 1,
                    coinbase_maturity=2,
                )
            except ValueError as exc:
                assert str(exc) == "unresolved spend", str(exc)
            else:
                raise AssertionError("invalid spend accepted by reference")
            assert before == coins, "invalid connect mutated parent coins"
        out = dict(
            name=row["name"],
            wire=wire.hex(),
            id=bid.hex(),
            root="",
            monetary="",
            coins=[],
        )
    result.append(out)
    print(
        row["name"],
        "reference_validated" if valid else "negative_body_preserved",
        file=sys.stderr,
    )
args.output.write_text(json.dumps(result, indent=2) + "\n")
if args.check_cpp:
    actual = [
        dict(
            name=n,
            wire=w,
            id=i,
            root=r,
            monetary=m,
            coins=re.findall(r"\"([0-9a-f]+)\"", cs),
        )
        for n, w, i, r, m, cs in re.findall(pat, args.check_cpp.read_text())
    ]
    assert actual == result, "C++ pinned vectors differ from independent reference"
    print("all 16 C++ vectors exactly match independent generation", file=sys.stderr)
