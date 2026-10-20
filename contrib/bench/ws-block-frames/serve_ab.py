#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Interleaved A/B benchmark: one node serves one block to many peers.

    serve_ab.py --base BUILD_A --patched BUILD_B --output DIR [options]

BUILD_A and BUILD_B are build directories (containing src/bitcoind), or
bitcoind binaries. For every cell (block size x peer count) and round, a
fresh copy of the same regtest fixture is served by each binary, the order
alternating between rounds. All peers ask for the same block at once.
Measured per serve:

- node CPU time (user + system of the whole bitcoind process, from
  proc_pid_rusage on macOS or /proc on Linux) between the start signal and
  the last peer having the block;
- wall time from the start signal until every peer has the whole block;
- WebSocket wire bytes the node sent (getnettotals), or TCP bytes.

Results go to DIR/results.jsonl (one line per serve) and DIR/SUMMARY.md
(medians with min/max and the B/A ratio of medians). The fixture (built
once in DIR/fixture with the B binary, then cloned) holds one fresh block
per cell, about 225-byte P2PKH-shaped transactions with random keys,
signatures and hashes; it is not a mainnet sample.
"""

import argparse
import ctypes
import hashlib
import json
import multiprocessing
import os
import platform
import random
import shutil
import statistics
import struct
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import peers  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
DICTIONARY = os.path.join(ROOT, "src", "net_zstd_dict_data.h")
RPC_AUTH = "Basic " + __import__("base64").b64encode(b"bench:bench").decode()
COIN = 100  # satoshis per XEC
SUBSIDY = 50_000_000 * COIN
MATURITY_BLOCKS = 130
GENESIS_TIME = 1296688602  # regtest


# ---------------------------------------------------------------- fixture


def ser_compact(n):
    return peers.compact_size(n)


def dsha(data):
    return peers.dsha256(data)


def push(data):
    assert len(data) < 76
    return bytes([len(data)]) + data


def tx_bytes(inputs, outputs, version=2, locktime=0):
    """inputs: [(prev txid bytes LE, n, scriptSig)]; outputs: [(sats, spk)]"""
    out = struct.pack("<i", version) + ser_compact(len(inputs))
    for txid, n, script in inputs:
        out += txid + struct.pack("<I", n) + ser_compact(len(script)) + script
        out += b"\xff\xff\xff\xff"
    out += ser_compact(len(outputs))
    for value, spk in outputs:
        out += struct.pack("<q", value) + ser_compact(len(spk)) + spk
    return out + struct.pack("<I", locktime)


def coinbase_tx(height):
    """Coinbase paying the subsidy to OP_TRUE (as test_framework does)"""
    if height <= 16:
        height_push = bytes([0x50 + height]) if height else b"\x00"
    else:
        h = height.to_bytes((height.bit_length() + 8) // 8, "little")
        height_push = push(h)
    script = height_push + push(b"\x00" * 40)  # transactions are >= 100 bytes
    return tx_bytes([(b"\0" * 32, 0xFFFFFFFF, script)], [(SUBSIDY, b"\x51")], 1)


def merkle_root(hashes):
    while len(hashes) > 1:
        if len(hashes) % 2:
            hashes.append(hashes[-1])
        hashes = [dsha(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return hashes[0]


def make_block(prev_hash, height, ntime, txs):
    """txs: raw transactions after the coinbase, put in CTOR order"""
    coinbase = coinbase_tx(height)
    # CTOR: by txid as a number (its little-endian bytes reversed)
    ids = sorted(((dsha(tx), tx) for tx in txs), key=lambda e: e[0][::-1])
    all_txs = [coinbase] + [tx for _, tx in ids]
    root = merkle_root([dsha(coinbase)] + [i for i, _ in ids])
    nonce = 0
    while True:
        header = (
            struct.pack("<i", 1)
            + prev_hash
            + root
            + struct.pack("<III", ntime, 0x207FFFFF, nonce)
        )
        block_hash = dsha(header)
        if block_hash[31] < 0x80:  # regtest target 0x7fffff << 232
            break
        nonce += 1
    raw = header + ser_compact(len(all_txs)) + b"".join(all_txs)
    return raw, block_hash


FANOUT_SPK = b"\x6d\x51"  # OP_2DROP OP_TRUE: spent by <sig> <key>
FANOUT_MAX = 25000


def large_block_txs(coinbases, target, rng):
    """Fanouts of mature coinbases, then ~225-byte P2PKH-shaped spends"""
    # Each spend is ~226 bytes plus its 11-byte fan-out output.
    count = max(1, (target - 300) // 237)
    fanouts, children = [], []
    remaining = count
    while remaining:
        n = min(FANOUT_MAX, remaining)
        remaining -= n
        cb_txid, cb_value = coinbases.pop()
        value = cb_value // n
        fan = tx_bytes([(cb_txid, 0, b"")], [(value, FANOUT_SPK)] * n)
        fanouts.append(fan)
        fan_id = dsha(fan)
        for i in range(n):
            script = push(rng.randbytes(71)) + push(rng.randbytes(33))
            outs = [
                (
                    value // 2 - 1000,
                    b"\x76\xa9\x14" + rng.randbytes(20) + b"\x88\xac",
                )
                for _ in range(2)
            ]
            children.append(tx_bytes([(fan_id, i, script)], outs))
    return fanouts + children


# ---------------------------------------------------------------- nodes


def binary(path):
    if os.path.isdir(path):
        path = os.path.join(path, "src", "bitcoind")
    if not os.access(path, os.X_OK):
        raise SystemExit(f"not an executable bitcoind: {path}")
    return os.path.abspath(path)


class Node:
    def __init__(self, bitcoind, datadir, args, extra):
        self.bitcoind, self.datadir = bitcoind, datadir
        self.rpcport, self.port = args.rpcport, args.port
        self.cmd = [
            bitcoind,
            f"-datadir={datadir}",
            "-regtest",
            "-server",
            "-listen=1",
            "-bind=127.0.0.1",
            f"-port={self.port}",
            f"-rpcport={self.rpcport}",
            "-rpcuser=bench",
            "-rpcpassword=bench",
            "-connect=0",
            "-dnsseed=0",
            "-discover=0",
            "-fixedseeds=0",
            "-maxconnections=400",
            "-printtoconsole=0",
            "-persistmempool=0",
            "-whitelist=noban,download@127.0.0.1",
        ] + extra

    def __enter__(self):
        os.makedirs(self.datadir, exist_ok=True)
        self.log = open(os.path.join(self.datadir, "process.log"), "w")
        self.proc = subprocess.Popen(
            self.cmd, stdout=self.log, stderr=subprocess.STDOUT
        )
        for _ in range(1200):
            if self.proc.poll() is not None:
                raise RuntimeError(f"bitcoind exited; see {self.datadir}/process.log")
            try:
                self.rpc("getblockcount")
                return self
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("bitcoind RPC did not come up")

    def __exit__(self, *exc):
        try:
            self.rpc("stop")
        except Exception:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()

    def rpc(self, method, *params):
        body = json.dumps({"id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.rpcport}/",
            body,
            {"Authorization": RPC_AUTH, "Content-Type": "application/json"},
        )
        try:
            response = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as e:
            response = e
        data = json.load(response)
        if data.get("error"):
            raise RuntimeError(data["error"])
        return data["result"]

    def cpu_seconds(self):
        return process_cpu_seconds(self.proc.pid)


def process_cpu_seconds(pid):
    """User + system CPU time of a process, in seconds"""
    if sys.platform == "darwin":

        class RUsageInfoV2(ctypes.Structure):
            _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
                (name, ctypes.c_uint64)
                for name in (
                    "user_time system_time pkg_idle_wkups interrupt_wkups "
                    "pageins wired_size resident_size phys_footprint "
                    "proc_start_abstime proc_exit_abstime child_user_time "
                    "child_system_time child_pkg_idle_wkups "
                    "child_interrupt_wkups child_pageins child_elapsed_abstime "
                    "diskio_bytesread diskio_byteswritten"
                ).split()
            ]

        class Timebase(ctypes.Structure):
            _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]

        libc = ctypes.CDLL("/usr/lib/libSystem.dylib")
        info = RUsageInfoV2()
        if libc.proc_pid_rusage(pid, 2, ctypes.byref(info)) != 0:
            raise OSError("proc_pid_rusage failed")
        tb = Timebase()
        libc.mach_timebase_info(ctypes.byref(tb))
        return (info.user_time + info.system_time) * tb.numer / tb.denom / 1e9
    with open(f"/proc/{pid}/stat", encoding="utf8") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def clone_tree(src, dst):
    if os.path.exists(dst):
        shutil.rmtree(dst)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if sys.platform == "darwin":
        subprocess.run(["cp", "-cR", src, dst], check=True)  # APFS clone
    else:
        shutil.copytree(src, dst)


def build_fixture(args, bitcoind):
    directory = os.path.join(args.output, "fixture")
    marker = os.path.join(directory, "fixture.json")
    if os.path.exists(marker):
        with open(marker, encoding="utf8") as f:
            return json.load(f)
    if os.path.exists(directory):
        shutil.rmtree(directory)
    rng = random.Random(20261019)
    cells = [(size, n) for size in args.sizes for n in args.peers]
    datadir = os.path.join(directory, "datadir")
    blocks = {}
    with Node(bitcoind, datadir, args, []) as node:
        prev = bytes.fromhex(node.rpc("getblockhash", 0))[::-1]
        ntime = GENESIS_TIME + 1
        coinbases = []
        for height in range(1, MATURITY_BLOCKS + 1):
            raw, block_hash = make_block(prev, height, ntime, [])
            result = node.rpc("submitblock", raw.hex())
            if result is not None:
                raise RuntimeError(f"maturity block {height}: {result}")
            coinbases.append((dsha(coinbase_tx(height)), SUBSIDY))
            prev, ntime = block_hash, ntime + 1
        coinbases = coinbases[: MATURITY_BLOCKS - 100]
        coinbases.reverse()
        height = MATURITY_BLOCKS
        for size, n in cells:
            height += 1
            txs = large_block_txs(
                coinbases, int(size * 1_000_000) - 100_000 * (size >= 32), rng
            )
            raw, block_hash = make_block(prev, height, ntime, txs)
            result = node.rpc("submitblock", raw.hex())
            if result is not None:
                raise RuntimeError(f"block {size}MB: {result}")
            key = f"{size}MB-{n}"
            blocks[key] = {
                "hash": block_hash[::-1].hex(),
                "bytes": len(raw),
                "transactions": len(txs) + 1,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "height": height,
            }
            print(f"fixture {key}: {len(raw)} bytes, {len(txs) + 1} txs", flush=True)
            prev, ntime = block_hash, ntime + 1
        assert node.rpc("getbestblockhash") == prev[::-1].hex()
    fixture = {"blocks": blocks, "bitcoind": bitcoind}
    with open(marker, "w", encoding="utf8") as f:
        json.dump(fixture, f, indent=2)
    return fixture


# ---------------------------------------------------------------- serving


def serve(args, node, block, n_peers):
    """All peers download one block at once; returns the measurements"""
    workers = min(args.workers, n_peers)
    shares = [n_peers // workers + (i < n_peers % workers) for i in range(workers)]
    ctx = multiprocessing.get_context("spawn")
    ready, results, go = ctx.Queue(), ctx.Queue(), ctx.Event()
    conf = {
        "host": "127.0.0.1",
        "port": node.rpcport if args.transport == "ws" else node.port,
        "transport": args.transport,
        "offer": args.offer,
        "dictionary": DICTIONARY,
        "block_hash": block["hash"],
        "block_sha256": block["sha256"],
    }
    procs = [
        ctx.Process(target=peers.worker_main, args=(conf, share, ready, go, results))
        for share in shares
    ]
    for p in procs:
        p.start()
    selected = []
    try:
        for _ in procs:
            got = ready.get(timeout=300)
            if isinstance(got, dict):
                raise RuntimeError(f"peer setup failed: {got['error']}")
            selected += got
        # Let the node finish the handshakes' follow-up messages.
        time.sleep(args.settle)
        totals_before = node.rpc("getnettotals")
        cpu_before = node.cpu_seconds()
        start = time.monotonic()
        go.set()
        rows, client_cpu = [], 0.0
        for _ in procs:
            got = results.get(timeout=args.timeout)
            if "error" in got:
                raise RuntimeError(f"peer failed: {got['error']}")
            rows += got["peers"]
            client_cpu += got["client_cpu"]
        end = max(r["done"] for r in rows)
        cpu_after = node.cpu_seconds()
        totals_after = node.rpc("getnettotals")
    finally:
        go.set()
        for p in procs:
            p.join(timeout=60)
            if p.is_alive():
                p.terminate()
    if args.transport == "ws":
        wire = (
            totals_after["websocket"]["wire_bytes_sent"]
            - totals_before["websocket"]["wire_bytes_sent"]
        )
    else:
        wire = totals_after["totalbytessent"] - totals_before["totalbytessent"]
    return {
        "ok": all(r["ok"] for r in rows) and len(rows) == n_peers,
        "selected": sorted(set(selected)),
        "node_cpu_s": cpu_after - cpu_before,
        "wall_s": end - start,
        "first_s": min(r["done"] for r in rows) - start,
        "wire_bytes_sent": wire,
        "client_cpu_s": client_cpu,
    }


def warm_block_files(datadir):
    blocks = os.path.join(datadir, "regtest", "blocks")
    for name in os.listdir(blocks):
        if name.startswith("blk"):
            with open(os.path.join(blocks, name), "rb") as f:
                while f.read(1 << 24):
                    pass


def scrape_metrics(node):
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{node.rpcport}/metrics", timeout=10
        ) as r:
            text = r.read().decode()
    except Exception:
        return {}
    values = {}
    for line in text.splitlines():
        if line.startswith("lotus_p2p_compress_once") or line.startswith(
            "lotus_p2p_websocket_independent"
        ):
            name, value = line.rsplit(" ", 1)
            values[name] = float(value)
    return values


def run(args):
    sides = {"A": binary(args.base), "B": binary(args.patched)}
    os.makedirs(args.output, exist_ok=True)
    fixture = build_fixture(args, sides["B"])
    results_path = os.path.join(args.output, "results.jsonl")
    machine = {
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "binaries": {
            k: {"path": v, "sha256": hashlib.sha256(open(v, "rb").read()).hexdigest()}
            for k, v in sides.items()
        },
    }
    with open(os.path.join(args.output, "machine.json"), "w", encoding="utf8") as f:
        json.dump(machine, f, indent=2)
    cells = [(size, n) for size in args.sizes for n in args.peers]
    for round_number in range(args.rounds):
        order = ["A", "B"] if round_number % 2 == 0 else ["B", "A"]
        for side in order:
            datadir = os.path.join(args.output, "run", side)
            clone_tree(os.path.join(args.output, "fixture", "datadir"), datadir)
            with Node(sides[side], datadir, args, args.node_arg) as node:
                # Blocks are read from the page cache, as for a recent tip.
                warm_block_files(datadir)
                for size, n in cells:
                    key = f"{size}MB-{n}"
                    block = fixture["blocks"][key]
                    metrics_before = scrape_metrics(node)
                    row = serve(args, node, block, n)
                    metrics_after = scrape_metrics(node)
                    row.update(
                        {
                            "round": round_number,
                            "side": side,
                            "size_mb": size,
                            "peers": n,
                            "block_bytes": block["bytes"],
                            "transport": args.transport,
                            "offer": args.offer,
                            "load_average": os.getloadavg(),
                            "metrics_delta": {
                                k: v - metrics_before.get(k, 0)
                                for k, v in metrics_after.items()
                                if v != metrics_before.get(k, 0)
                            },
                        }
                    )
                    with open(results_path, "a", encoding="utf8") as f:
                        f.write(json.dumps(row) + "\n")
                    print(
                        f"round {round_number} {side} {key}: cpu {row['node_cpu_s']:.3f}s "
                        f"wall {row['wall_s']:.3f}s wire {row['wire_bytes_sent']} "
                        f"ok={row['ok']} {row['selected']}",
                        flush=True,
                    )
                    if not row["ok"]:
                        raise RuntimeError("a peer did not receive the block intact")
            shutil.rmtree(datadir)
    summarize(args.output)


def summarize(output):
    rows = [
        json.loads(line)
        for line in open(os.path.join(output, "results.jsonl"), encoding="utf8")
    ]
    lines = [
        "| Block | Peers | Metric | A median (min-max) | B median (min-max) | B/A | n |",
        "|---|---:|---|---:|---:|---:|---:|",
    ]
    cells = sorted({(r["size_mb"], r["peers"]) for r in rows})
    for size, n in cells:
        for metric, scale, unit, label in [
            ("node_cpu_s", 1000, "ms", "node CPU"),
            ("wall_s", 1000, "ms", "wall, all peers"),
            ("wire_bytes_sent", 1e-6, "MB", "bytes on the wire"),
        ]:
            got = {}
            for side in "AB":
                vals = [
                    r[metric] * scale
                    for r in rows
                    if r["side"] == side and r["size_mb"] == size and r["peers"] == n
                ]
                got[side] = vals
            if not got["A"] or not got["B"]:
                continue
            ma, mb = statistics.median(got["A"]), statistics.median(got["B"])
            ratio = mb / ma if ma else float("nan")
            fmt = "{:.1f}" if unit != "MB" else "{:.2f}"
            lines.append(
                f"| {size} MB | {n} | {label} ({unit}) | "
                f"{fmt.format(ma)} ({fmt.format(min(got['A']))}-{fmt.format(max(got['A']))}) | "
                f"{fmt.format(mb)} ({fmt.format(min(got['B']))}-{fmt.format(max(got['B']))}) | "
                f"{ratio:.2f} | {len(got['A'])}/{len(got['B'])} |"
            )
    loads = [r["load_average"][0] for r in rows]
    lines += [
        "",
        f"Serves: {len(rows)}. 1-minute load average during the runs: "
        f"median {statistics.median(loads):.1f}, range {min(loads):.1f}-{max(loads):.1f} "
        f"on {os.cpu_count()} CPUs.",
        "",
        "node cpu: user+system CPU of the whole node process from the start signal "
        "until the last peer had the block. wall: start signal to last peer done. "
        "wire: WebSocket frame bytes (or TCP bytes) the node sent in that interval.",
    ]
    with open(os.path.join(output, "SUMMARY.md"), "w", encoding="utf8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base", required=True, help="side A: build dir or bitcoind")
    parser.add_argument(
        "--patched", required=True, help="side B: build dir or bitcoind"
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--sizes", default="1,8,32", help="block sizes, MB (32 means 31.9)"
    )
    parser.add_argument("--peers", default="8,32,64")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--transport", choices=["ws", "tcp"], default="ws")
    parser.add_argument(
        "--offer",
        default="p2p-zstd-v1,p2p-zstd",
        help="Sec-WebSocket-Protocol offered by every peer",
    )
    parser.add_argument("--workers", type=int, default=8, help="client processes")
    parser.add_argument("--rpcport", type=int, default=41604)
    parser.add_argument("--port", type=int, default=41605)
    parser.add_argument("--settle", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument(
        "--node-arg",
        action="append",
        default=["-metrics"],
        help="extra bitcoind argument (repeatable)",
    )
    parser.add_argument("--summarize-only", action="store_true")
    args = parser.parse_args()
    args.sizes = [int(s) for s in args.sizes.split(",")]
    args.peers = [int(n) for n in args.peers.split(",")]
    args.output = os.path.abspath(args.output)
    if args.summarize_only:
        summarize(args.output)
        return
    run(args)


if __name__ == "__main__":
    main()
