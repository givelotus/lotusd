#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Block connection with a cold UTXO database page cache, base vs patched.

Two steps:

  fixture  Build a regtest datadir whose UTXO set holds many coins
           (default 2,000,000 anyone-can-spend outputs), and a file of test
           blocks that each spend random coins from it (default 6 blocks of
           10,000 two-input transactions). Any bitcoind of the tier can
           build it; it is reused by every arm and round.

  run      For each round and each arm, in order (A B A B ...): clone the
           fixture datadir (APFS copy-on-write where available), start that
           arm's bitcoind with a 4 MiB coins cache, and submit the test
           blocks one at a time with submitblock. Before each block the UTXO
           database file is evicted from the OS page cache (see below), so
           every block reads its coins from disk. Records, per block, the
           submitblock wall time and the node's own -debug=bench "Connect
           total" (ConnectBlock) and "Connect block" (ConnectTip) times.

Page cache eviction: `purge` needs root on macOS, so this maps the database
file and calls msync(MS_SYNC | MS_INVALIDATE), which writes back and then
drops that file's cached pages (as vmtouch -e does); Linux uses
posix_fadvise(POSIX_FADV_DONTNEED) after fdatasync. The script checks with
mincore() that the pages were dropped and reports the resident fraction. It
evicts only files in its own cloned datadirs.

The blocks arrive by RPC, which enters ProcessNewBlock; the P2P BLOCK and
compact-block paths are not exercised by this driver.

Example:
  ab_block_connect.py fixture --bitcoind build/src/bitcoind --dir /tmp/fx
  ab_block_connect.py run --fixture /tmp/fx --rounds 5 \\
      --arm base=../base/build --arm patched=build \\
      --arm 'patched-off=build -blockprefetch=0' --out connect.json
"""

import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import http.client
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import abstats  # noqa: E402

BITCOIND_CANDIDATES = ["src/bitcoind", "bin/bitcoind", "src/ecashd", "bin/ecashd"]
COIN_SATS = 100  # 1 XEC = 100 sats
REGTEST_SUBSIDY = 50_000_000 * COIN_SATS
REGTEST_HALVING = 150
REGTEST_BITS = 0x207FFFFF
OP_TRUE = b"\x51"
OP_RETURN = b"\x6a"
MIN_TX_SIZE = 100


# --- Minimal transaction and block serialization -------------------------


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def push(data):
    assert len(data) < 76
    return bytes([len(data)]) + data


def ser_tx(vin, vout, version=2, locktime=0):
    """vin: [(txid_bytes_le, n, script_sig)], vout: [(value, spk)]"""
    out = [struct.pack("<I", version), compact_size(len(vin))]
    for txid, n, sig in vin:
        out += [
            txid,
            struct.pack("<I", n),
            compact_size(len(sig)),
            sig,
            b"\xff\xff\xff\xff",
        ]
    out.append(compact_size(len(vout)))
    for value, spk in vout:
        out += [struct.pack("<q", value), compact_size(len(spk)), spk]
    out.append(struct.pack("<I", locktime))
    return b"".join(out)


def make_tx(vin, vout):
    raw = ser_tx(vin, vout)
    if len(raw) < MIN_TX_SIZE:
        pad = MIN_TX_SIZE - len(raw) - 11
        vout = vout + [(0, OP_RETURN + push(b"\x00" * max(pad, 1)))]
        raw = ser_tx(vin, vout)
    assert len(raw) >= MIN_TX_SIZE
    return raw, sha256d(raw)


def bip34_height(height):
    if height == 0:
        return b"\x00"
    n = height.to_bytes((height.bit_length() + 8) // 8, "little")
    return push(n)


def coinbase(height):
    value = REGTEST_SUBSIDY >> (height // REGTEST_HALVING)
    sig = bip34_height(height) + push(b"\x00" * 40)
    return make_tx([(b"\x00" * 32, 0xFFFFFFFF, sig)], [(value, OP_TRUE)])


def merkle_root(txids):
    level = list(txids)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def make_block(prev_hash_le, height, ntime, txs):
    """txs: [(raw, txid)] excluding the coinbase; sorted for CTOR here."""
    cb = coinbase(height)
    body = [cb] + sorted(txs, key=lambda t: t[1][::-1])
    root = merkle_root([t[1] for t in body])
    target = (REGTEST_BITS & 0xFFFFFF) << (8 * ((REGTEST_BITS >> 24) - 3))
    nonce = 0
    while True:
        header = (
            struct.pack("<i", 1)
            + prev_hash_le
            + root
            + struct.pack("<III", ntime, REGTEST_BITS, nonce)
        )
        h = sha256d(header)
        if int.from_bytes(h, "little") <= target:
            break
        nonce += 1
    raw = header + compact_size(len(body)) + b"".join(t[0] for t in body)
    return raw, h, cb


# --- Node control --------------------------------------------------------


class Node:
    def __init__(self, binary, datadir, rpcport, extra, log):
        self.binary, self.datadir, self.rpcport = binary, datadir, rpcport
        self.extra, self.log = extra, log
        self.proc = None

    def start(self):
        args = [
            self.binary,
            "-regtest",
            f"-datadir={self.datadir}",
            "-listen=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-connect=0",
            f"-rpcport={self.rpcport}",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-server=1",
            "-printtoconsole=0",
            "-txindex=0",
            "-chronik=0",
            "-rpcservertimeout=6000",
        ] + self.extra
        self.proc = subprocess.Popen(
            args, stdout=self.log, stderr=self.log, start_new_session=True
        )
        deadline = time.time() + 300
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit(
                    f"bitcoind exited early ({self.proc.returncode}); "
                    f"see {self.datadir}/regtest/debug.log"
                )
            try:
                self.rpc("getblockcount")
                return
            except (OSError, RuntimeError, http.client.HTTPException):
                time.sleep(0.2)
        raise SystemExit("bitcoind RPC did not come up")

    def rpc(self, method, *params, timeout=3600):
        cookie = os.path.join(self.datadir, "regtest", ".cookie")
        with open(cookie, encoding="utf8") as f:
            auth = base64.b64encode(f.read().strip().encode()).decode()
        conn = http.client.HTTPConnection("127.0.0.1", self.rpcport, timeout=timeout)
        body = json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}
        )
        conn.request(
            "POST",
            "/",
            body,
            {"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        )
        resp = json.loads(conn.getresponse().read())
        conn.close()
        if resp.get("error"):
            raise RuntimeError(f"{method}: {resp['error']}")
        return resp["result"]

    def stop(self):
        if self.proc is None:
            return
        try:
            self.rpc("stop")
        except Exception:  # noqa: BLE001
            pass
        try:
            self.proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None


# --- Page cache eviction -------------------------------------------------

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.mmap.restype = ctypes.c_void_p
_libc.mmap.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_longlong,
]
_libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_libc.msync.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
PROT_READ, MAP_SHARED = 1, 1
if sys.platform == "darwin":
    MS_INVALIDATE, MS_SYNC = 0x2, 0x10
else:
    MS_INVALIDATE, MS_SYNC = 0x2, 0x4


def _mapped(path):
    size = os.path.getsize(path)
    fd = os.open(path, os.O_RDONLY)
    addr = _libc.mmap(None, size, PROT_READ, MAP_SHARED, fd, 0)
    if addr in (None, ctypes.c_void_p(-1).value):
        os.close(fd)
        raise OSError(ctypes.get_errno(), f"mmap {path}")
    return fd, addr, size


def resident_fraction(path):
    fd, addr, size = _mapped(path)
    try:
        page = os.sysconf("SC_PAGE_SIZE")
        n = (size + page - 1) // page
        buf = ctypes.create_string_buffer(n)
        if _libc.mincore(addr, size, buf) != 0:
            return float("nan")
        return sum(1 for b in buf.raw if b & 1) / max(n, 1)
    finally:
        _libc.munmap(addr, size)
        os.close(fd)


def evict(path):
    if sys.platform != "darwin" and hasattr(os, "posix_fadvise"):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fdatasync(fd)
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
        return
    fd, addr, size = _mapped(path)
    try:
        if _libc.msync(addr, size, MS_SYNC | MS_INVALIDATE) != 0:
            raise OSError(ctypes.get_errno(), f"msync {path}")
    finally:
        _libc.munmap(addr, size)
        os.close(fd)


# --- fixture -------------------------------------------------------------


def cmd_fixture(args):
    binary = abstats.find_binary(args.bitcoind, BITCOIND_CANDIDATES)
    if os.path.exists(args.dir):
        raise SystemExit(f"{args.dir} exists; give a new directory")
    datadir = os.path.join(args.dir, "datadir")
    os.makedirs(datadir)
    rng = random.Random(args.seed)
    with open(os.path.join(args.dir, "fixture.log"), "w", encoding="utf8") as log:
        node = Node(
            binary,
            datadir,
            args.rpcport,
            ["-dbcache=1024", "-maxtipage=2000000000"],
            log,
        )
        node.start()
        try:
            build_fixture(node, args, rng)
        finally:
            node.stop()
    print(f"fixture ready in {args.dir}")


def build_fixture(node, args, rng):
    prev = bytes.fromhex(node.rpc("getblockhash", 0))[::-1]
    height = 0
    n_test = args.blocks
    n_fanout_blocks = (
        args.fanout_txs + args.fanout_txs_per_block - 1
    ) // args.fanout_txs_per_block
    n_total = 101 + 1 + n_fanout_blocks + n_test
    t0 = int(time.time()) - 600 * n_total

    def submit(raw):
        res = node.rpc("submitblock", raw.hex())
        if res is not None:
            raise SystemExit(f"fixture block rejected: {res}")

    first_cb = None
    for _ in range(101):
        height += 1
        raw, prev, cb = make_block(prev, height, t0 + 600 * height, [])
        first_cb = first_cb or cb
        submit(raw)

    # Split the first coinbase into fanout_txs coins, then each of those
    # into outputs_per_tx coins.
    cb_value = REGTEST_SUBSIDY
    split_value = cb_value // args.fanout_txs
    split = make_tx([(first_cb[1], 0, b"")], [(split_value, OP_TRUE)] * args.fanout_txs)
    height += 1
    raw, prev, _ = make_block(prev, height, t0 + 600 * height, [split])
    submit(raw)

    coin_value = split_value // args.outputs_per_tx
    coins = []
    fan = []
    for i in range(args.fanout_txs):
        tx = make_tx(
            [(split[1], i, b"")], [(coin_value, OP_TRUE)] * args.outputs_per_tx
        )
        fan.append(tx)
        coins.extend((tx[1], n) for n in range(args.outputs_per_tx))
    for i in range(0, len(fan), args.fanout_txs_per_block):
        height += 1
        raw, prev, _ = make_block(
            prev, height, t0 + 600 * height, fan[i : i + args.fanout_txs_per_block]
        )
        submit(raw)
    print(f"fixture: {len(coins)} coins at height {height}", file=sys.stderr)

    # Test blocks: each spends distinct random coins.
    rng.shuffle(coins)
    need = n_test * args.txs_per_block * args.inputs_per_tx
    if need > len(coins):
        raise SystemExit("not enough fixture coins for the test blocks")
    pos = 0
    with open(os.path.join(args.dir, "blocks.hex"), "w", encoding="utf8") as f:
        for b in range(n_test):
            txs = []
            for _ in range(args.txs_per_block):
                vin = [
                    (coins[pos + k][0], coins[pos + k][1], b"")
                    for k in range(args.inputs_per_tx)
                ]
                pos += args.inputs_per_tx
                txs.append(make_tx(vin, [(coin_value * args.inputs_per_tx, OP_TRUE)]))
            height += 1
            raw, prev, _ = make_block(prev, height, t0 + 600 * height, txs)
            f.write(raw.hex() + "\n")
    meta = {k: v for k, v in vars(args).items() if k != "func"}
    meta["coins"] = len(coins)
    meta["fixture_height"] = height - n_test
    with open(os.path.join(args.dir, "fixture.json"), "w", encoding="utf8") as f:
        json.dump(meta, f, indent=1, sort_keys=True)


# --- run -----------------------------------------------------------------

CONNECT_TOTAL = re.compile(r"- Connect total: ([0-9.]+)ms")
CONNECT_BLOCK = re.compile(r"- Connect block: ([0-9.]+)ms")


def clone_tree(src, dst):
    if sys.platform == "darwin":
        r = subprocess.run(
            ["cp", "-c", "-R", src, dst], check=False, stderr=subprocess.DEVNULL
        )
        if r.returncode == 0:
            return
    shutil.copytree(src, dst)


def run_arm(fixture, binary, extra, rpcport, blocks, workdir, log, warm=False):
    datadir = os.path.join(workdir, "datadir")
    clone_tree(os.path.join(fixture, "datadir"), datadir)
    db = os.path.join(datadir, "regtest", "chainstate", "mdbx.dat")
    node = Node(
        binary,
        datadir,
        rpcport,
        ["-dbcache=4", "-debug=bench", "-maxtipage=2000000000"] + extra,
        log,
    )
    node.start()
    walls, resident = [], []
    try:
        if warm:
            # Read the whole database once so every page is cached.
            with open(db, "rb") as f:
                while f.read(1 << 24):
                    pass
        for raw in blocks:
            if not warm:
                evict(db)
            resident.append(resident_fraction(db))
            t = time.perf_counter()
            res = node.rpc("submitblock", raw)
            walls.append((time.perf_counter() - t) * 1e3)
            if res is not None:
                raise SystemExit(f"test block rejected: {res}")
    finally:
        node.stop()
    with open(
        os.path.join(datadir, "regtest", "debug.log"), encoding="utf8", errors="replace"
    ) as f:
        text = f.read()
    connect = [float(x) for x in CONNECT_TOTAL.findall(text)]
    tip = [float(x) for x in CONNECT_BLOCK.findall(text)]
    shutil.rmtree(datadir)
    return walls, connect[-len(blocks) :], tip[-len(blocks) :], resident


def cmd_run(args):
    with open(os.path.join(args.fixture, "blocks.hex"), encoding="utf8") as f:
        blocks = [line.strip() for line in f if line.strip()]
    if args.max_blocks:
        blocks = blocks[: args.max_blocks]
    arms = []
    for spec in args.arm:
        name, path, extra = abstats.parse_arm(spec)
        arms.append((name, abstats.find_binary(path, BITCOIND_CANDIDATES), extra))
    samples = {}
    raw_rounds = []
    workroot = tempfile.mkdtemp(prefix="ab-block-connect-", dir=args.workdir)
    try:
        with open(os.path.join(workroot, "nodes.log"), "w", encoding="utf8") as log:
            for rnd in range(args.rounds):
                order = (
                    arms
                    if not args.alternate_order or rnd % 2 == 0
                    else list(reversed(arms))
                )
                for name, binary, extra in order:
                    wd = os.path.join(workroot, f"r{rnd}-{name}")
                    os.makedirs(wd)
                    walls, connect, tip, resident = run_arm(
                        args.fixture,
                        binary,
                        extra,
                        args.rpcport,
                        blocks,
                        wd,
                        log,
                        warm=args.warm,
                    )
                    os.rmdir(wd)
                    rec = {
                        "submitblock_total_ms": sum(walls),
                        "connectblock_total_ms": sum(connect),
                        "connecttip_total_ms": sum(tip),
                        "submitblock_median_ms": sorted(walls)[len(walls) // 2],
                        "connectblock_median_ms": sorted(connect)[len(connect) // 2]
                        if connect
                        else 0,
                    }
                    for k, v in rec.items():
                        samples.setdefault(k, {a[0]: [] for a in arms})[name].append(v)
                    raw_rounds.append(
                        {
                            "round": rnd,
                            "arm": name,
                            "submitblock_ms": walls,
                            "connectblock_ms": connect,
                            "connecttip_ms": tip,
                            "resident_before_block": resident,
                        }
                    )
                    print(
                        f"round {rnd + 1}/{args.rounds} {name}: "
                        f"submit {sum(walls):.1f} ms, connect "
                        f"{sum(connect):.1f} ms, resident before blocks "
                        f"max {max(resident):.3f}",
                        file=sys.stderr,
                    )
    finally:
        if not args.keep:
            shutil.rmtree(workroot, ignore_errors=True)
    rows = abstats.summarize(samples)
    names = [a[0] for a in arms]
    print(abstats.render_table(rows, names, "ms"))
    if args.out:
        abstats.write_results(
            args.out,
            {
                "arms": [{"name": n, "binary": b, "args": e} for n, b, e in arms],
                "fixture": os.path.abspath(args.fixture),
                "blocks": len(blocks),
                "rounds": args.rounds,
                "rows": rows,
                "raw": raw_rounds,
            },
        )


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(required=True)
    f = sub.add_parser("fixture", help="build the datadir and test blocks")
    f.add_argument("--bitcoind", required=True, help="binary or build dir")
    f.add_argument("--dir", required=True, help="new output directory")
    f.add_argument("--fanout-txs", type=int, default=200)
    f.add_argument("--outputs-per-tx", type=int, default=10000)
    f.add_argument("--fanout-txs-per-block", type=int, default=50)
    f.add_argument("--blocks", type=int, default=6)
    f.add_argument("--txs-per-block", type=int, default=10000)
    f.add_argument("--inputs-per-tx", type=int, default=2)
    f.add_argument("--seed", type=int, default=20261019)
    f.add_argument("--rpcport", type=int, default=41731)
    f.set_defaults(func=cmd_fixture)
    r = sub.add_parser("run", help="interleaved A/B block connection")
    r.add_argument("--fixture", required=True)
    r.add_argument(
        "--arm",
        action="append",
        required=True,
        help="NAME=BUILD_DIR_OR_BITCOIND [extra bitcoind args]; "
        "the first arm is the baseline",
    )
    r.add_argument("--rounds", type=int, default=5)
    r.add_argument("--max-blocks", type=int, default=0)
    r.add_argument("--rpcport", type=int, default=41733)
    r.add_argument(
        "--workdir", default=None, help="where to clone datadirs (default: system temp)"
    )
    r.add_argument(
        "--alternate-order",
        action="store_true",
        help="reverse the arm order on odd rounds (ABBA)",
    )
    r.add_argument(
        "--warm",
        action="store_true",
        help="read the UTXO database into the page cache instead of evicting it",
    )
    r.add_argument("--keep", action="store_true")
    r.add_argument("--out", help="write raw samples and summary as JSON")
    r.set_defaults(func=cmd_run)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
