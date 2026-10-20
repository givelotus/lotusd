#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Build a reusable signed-transaction flood fixture.

1. Start an isolated regtest node from the given binary.
2. Mine coinbases to deterministic P2PKH keys, mature them, and fan them
   out into many confirmed P2PKH outputs (signed, one block).
3. Stop the node. The stopped datadir is the fixture; every benchmark run
   clones it, so each run starts from identical chain state and an empty
   mempool and signature cache.
4. Write flood.jsonl: real P2PKH transactions spending those outputs, signed
   with ECDSA and with Schnorr, some with several inputs and some as
   dependent chains. Signing runs in worker processes.

Usage:
  make_fixture.py --bitcoind BUILD/src/bitcoind --out DIR [--txs 60000]
"""

import argparse
import hashlib
import json
import multiprocessing
import random
import sys
import time
from pathlib import Path

import admission_common as ac

NUM_KEYS = 64
FANOUT = 500
FEE_PER_BYTE = 2
DUST = 1000


def est_size(n_in, n_out):
    return 10 + 148 * n_in + 34 * n_out


_KEYS = None


def _keys(seed):
    global _KEYS
    if _KEYS is None:
        _KEYS = []
        for i in range(NUM_KEYS):
            k = ac.derive_key(seed, i)
            pub = k.get_pubkey().get_bytes()
            _KEYS.append((k, pub, bytes(ac.p2pkh_script(pub))))
    return _KEYS


def sign_unit(task):
    """task = (seed, kind, inputs, sig_schnorr, out_keys).

    inputs: list of (txid_hex, n, amount, key_index).
    Returns (kind, [tx_hex...]).
    """
    seed, kind, inputs, schnorr, out_keys = task
    keys = _keys(seed)
    txs = []
    if kind == "chain":
        txid, n, amount, kidx = inputs[0]
        for depth, (use_schnorr, okidx) in enumerate(zip(schnorr, out_keys)):
            fee = FEE_PER_BYTE * est_size(1, 1)
            out_amount = amount - fee
            tx = ac.build_tx([(txid, n)], [(keys[okidx][2], out_amount)])
            ac.sign_p2pkh_inputs(
                tx,
                [(keys[kidx][2], amount)],
                [(keys[kidx][0], keys[kidx][1])],
                [use_schnorr],
            )
            txs.append(tx.serialize().hex())
            txid, n, amount, kidx = tx.txid_hex, 0, out_amount, okidx
        return kind, txs
    total = sum(a for _, _, a, _ in inputs)
    n_out = len(out_keys)
    fee = FEE_PER_BYTE * est_size(len(inputs), n_out)
    per_out = (total - fee) // n_out
    tx = ac.build_tx(
        [(t, n) for t, n, _, _ in inputs],
        [(keys[k][2], per_out) for k in out_keys],
    )
    ac.sign_p2pkh_inputs(
        tx,
        [(keys[k][2], a) for _, _, a, k in inputs],
        [(keys[k][0], keys[k][1]) for _, _, _, k in inputs],
        schnorr,
    )
    txs.append(tx.serialize().hex())
    return kind, txs


def plan_units(rng, n_txs, mix):
    """Return a list of (kind, n_inputs, n_txs) until n_txs transactions."""
    kinds = list(mix)
    # Weights are shares of transactions; a chain unit holds 5 on average.
    weights = [mix[k] / (5.0 if k == "chain" else 1.0) for k in kinds]
    units = []
    count = 0
    while count < n_txs:
        kind = rng.choices(kinds, weights)[0]
        if kind == "multi":
            units.append((kind, rng.randint(2, 5), 1))
            count += 1
        elif kind == "chain":
            d = rng.randint(2, 8)
            units.append((kind, 1, d))
            count += d
        else:
            units.append((kind, 1, 1))
            count += 1
    return units


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bitcoind", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--txs", type=int, default=60000)
    ap.add_argument("--seed", default="admission-bench-1")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--portseed", type=int, default=601)
    ap.add_argument(
        "--mix",
        default="ecdsa1=35,schnorr1=35,multi=15,chain=15",
        help="relative transaction shares (chain units hold 2-8 dependent txs)",
    )
    args = ap.parse_args()

    mix = {}
    for part in args.mix.split(","):
        k, v = part.split("=")
        if k not in ("ecdsa1", "schnorr1", "multi", "chain"):
            sys.exit(f"unknown kind {k}")
        mix[k] = float(v)

    rng = random.Random(args.seed)
    units = plan_units(rng, args.txs, mix)
    needed = sum(u[1] for u in units)
    n_fanouts = (needed + FANOUT - 1) // FANOUT
    print(
        f"{len(units)} units, {sum(u[2] for u in units)} txs, "
        f"{needed} funding outputs, {n_fanouts} fanout txs"
    )

    if args.out.exists():
        sys.exit(f"{args.out} exists; choose a new directory")
    args.out.mkdir(parents=True)
    datadir = args.out / "datadir"
    ports = ac.ports_for(args.portseed)
    keys = _keys(args.seed)
    proc, rpc, _ = ac.start_node(
        args.bitcoind, datadir, ports, log_path=args.out / "fixture-node.log"
    )
    try:
        spk0 = keys[0][2].hex()
        desc = rpc.call("getdescriptorinfo", f"raw({spk0})")["descriptor"]
        rpc.call("generatetodescriptor", n_fanouts, desc)
        rpc.call("generatetodescriptor", 101, desc)
        coinbases = []
        for h in range(1, n_fanouts + 1):
            blk = rpc.call("getblock", rpc.call("getblockhash", h), 2)
            cb = blk["tx"][0]
            vout = next(v for v in cb["vout"] if v["scriptPubKey"]["hex"] == spk0)
            coinbases.append((cb["txid"], vout["n"], round(vout["value"] * 100)))

        funding = []
        for i, (txid, n, amount) in enumerate(coinbases):
            fee = FEE_PER_BYTE * est_size(1, FANOUT)
            per_out = (amount - fee) // FANOUT
            if per_out < 50 * DUST:
                sys.exit(f"coinbase {amount} too small for fanout")
            out_keys = [(i * FANOUT + j) % NUM_KEYS for j in range(FANOUT)]
            tx = ac.build_tx([(txid, n)], [(keys[k][2], per_out) for k in out_keys])
            ac.sign_p2pkh_inputs(
                tx, [(keys[0][2], amount)], [(keys[0][0], keys[0][1])], [False]
            )
            got = rpc.call("sendrawtransaction", tx.serialize().hex())
            assert got == tx.txid_hex, (got, tx.txid_hex)
            funding.extend((tx.txid_hex, j, per_out, k) for j, k in enumerate(out_keys))
        rpc.call("generatetodescriptor", 1, desc)
        assert rpc.call("getmempoolinfo")["size"] == 0
        tip = rpc.call("getbestblockhash")
        height = rpc.call("getblockcount")
    finally:
        ac.stop_node(proc, rpc)

    rng.shuffle(funding)
    tasks = []
    pos = 0
    for kind, n_in, n_tx in units:
        inputs = funding[pos : pos + n_in]
        pos += n_in
        if kind == "ecdsa1":
            schnorr = [False]
        elif kind == "schnorr1":
            schnorr = [True]
        else:
            schnorr = [rng.random() < 0.5 for _ in range(max(n_in, n_tx))]
        if kind == "chain":
            out_keys = [rng.randrange(NUM_KEYS) for _ in range(n_tx)]
        elif kind == "multi":
            out_keys = [rng.randrange(NUM_KEYS)]
        else:
            out_keys = [rng.randrange(NUM_KEYS) for _ in range(2)]
        tasks.append((args.seed, kind, inputs, schnorr, out_keys))

    t0 = time.time()
    flood_path = args.out / "flood.jsonl"
    stats = {"ecdsa1": 0, "schnorr1": 0, "multi": 0, "chain": 0}
    n_written = 0
    sigs = 0
    h = hashlib.sha256()
    with multiprocessing.Pool(args.jobs) as pool, open(flood_path, "w") as f:
        for i, (kind, txs) in enumerate(pool.imap(sign_unit, tasks, chunksize=8)):
            line = json.dumps({"unit": i, "kind": kind, "txs": txs}) + "\n"
            h.update(line.encode())
            f.write(line)
            stats[kind] += len(txs)
            n_written += len(txs)
            sigs += len(tasks[i][2]) if kind != "chain" else len(txs)
            if i % 2000 == 0:
                print(f"  signed {n_written} txs ({time.time() - t0:.0f}s)")
    manifest = {
        "seed": args.seed,
        "units": len(tasks),
        "txs": n_written,
        "signatures": sigs,
        "txs_by_kind": stats,
        "funding_outputs": needed,
        "fixture_height": height,
        "fixture_tip": tip,
        "flood_sha256": h.hexdigest(),
        "bitcoind": str(args.bitcoind),
        "sign_seconds": round(time.time() - t0, 1),
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
