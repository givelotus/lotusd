#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Timed Chronik tx-read benchmark: script history pages and /tx lookups.

Builds one deterministic eCash-tier regtest chain (legacy txs) with a plain
node (or reuses --chain-cache), then starts the --build (NAME=BUILD_DIR, with
Chronik) on an APFS/reflink copy of that chain, waits for Chronik to index
it and times, with a warm page cache:

  * GET /script/p2sh/<hash>/history?page=P&page_size=200 for every page of
    every target script (each response loads 200 txs and their spent coins);
  * GET /tx/<txid> for a fixed random sample of txids.

Each block carries --filler-bytes of OP_RETURN data, so the chain spans more
than one blk?????.dat file: older txs live in files the node no longer
appends to, recent ones in the current write file.

Every response body is hashed; the digests in the results JSON of runs of
different builds on the same chain must be equal. Run one build per
invocation (the framework gives every node of a run the same index-0 ports),
alternating builds to spread machine noise.

With --iocount LIB (a DYLD_INSERT_LIBRARIES interposer that counts
open/close/read/pread/lseek/fstat/mmap calls on blocks/blk*.dat and
blocks/rev*.dat, dumped to $IOCOUNT_OUT on SIGUSR2), each build is
restarted once more under the interposer to count those calls per phase.

Example:
  for b in rust=build/ecash-rust native=build/ecash-native; do
      venv/bin/python bench_tx_reads.py --build $b --chain-cache chain \\
          --blocks 3000 --out results-${b%%=*}.json
  done
"""

import argparse
import configparser
import hashlib
import http.client
import json
import os
import random
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _bootstrap():
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--build", action="append", default=[])
    pre.add_argument("--tmpdir")
    pre.add_argument("--configfile")
    pre.add_argument("--portseed")
    ns, _ = pre.parse_known_args()
    if not ns.build:
        raise SystemExit("at least one --build NAME=DIR is required")
    first = os.path.abspath(ns.build[0].split("=", 1)[1])
    cfg_path = os.path.join(first, "test", "config.ini")
    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)
    srcdir = cfg["environment"]["SRCDIR"]
    sys.path.insert(0, os.path.join(srcdir, "test", "functional"))
    if not ns.configfile:
        sys.argv.append(f"--configfile={cfg_path}")
    if not ns.tmpdir:
        base = os.path.join(tempfile.gettempdir(), "chronik-bench-runs")
        os.makedirs(base, exist_ok=True)
        sys.argv.append(f"--tmpdir={base}/run-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}")
    if not ns.portseed:
        sys.argv.append(f"--portseed={4000 + os.getpid() % 2000}")
    if "--nocleanup" not in sys.argv:
        sys.argv.append("--nocleanup")


_bootstrap()

from test_framework.address import (  # noqa: E402
    ADDRESS_ECREG_P2SH_OP_TRUE,
    P2SH_OP_TRUE,
    SCRIPTSIG_OP_TRUE,
)
from test_framework.hash import hash160  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
)
from test_framework.script import OP_EQUAL, OP_HASH160, OP_RETURN, CScript  # noqa: E402
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework import util as _fw_util  # noqa: E402
from test_framework.util import initialize_datadir  # noqa: E402

# Keep every framework port (p2p, rpc, chronik, electrum, tor) inside
# [PORT_MIN, PORT_MIN + 5000): 5 ranges of 1000 ports.
_fw_util.PORT_RANGE = 1000
for _k in list(_fw_util.PORT_START_MAP):
    _fw_util.PORT_START_MAP[_k] = list(_fw_util.PORT_START_MAP).index(_k) * 1000

COINBASE_MATURITY = 100
PAGE_SIZE = 200


def _find_binary(build):
    for name in ("bitcoind", "lotusd"):
        path = os.path.join(build, "src", name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise SystemExit(f"no src/bitcoind or src/lotusd in {build}")


def _copy_tree(src, dst):
    """Copy-on-write clone when the filesystem supports it (APFS)."""
    if subprocess.call(["cp", "-cR", src, dst], stderr=subprocess.DEVNULL) != 0:
        shutil.copytree(src, dst)


class Client:
    def __init__(self, port):
        self.port = port
        self.conn = None

    def get(self, path):
        for attempt in range(3):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
                self.conn.request("GET", path)
                resp = self.conn.getresponse()
                body = resp.read()
                return resp.status, body
            except (http.client.HTTPException, ConnectionError, OSError):
                if self.conn is not None:
                    self.conn.close()
                self.conn = None
                if attempt == 2:
                    raise
        raise AssertionError("unreachable")


class BenchTxReads(BitcoinTestFramework):
    def add_options(self, parser):
        g = parser.add_argument_group("bench")
        g.add_argument("--build", action="append", default=[],
                       help="NAME=BUILD_DIR of the build to measure (also builds the chain)")
        g.add_argument("--blocks", type=int, default=3000)
        g.add_argument("--txs-per-block", type=int, default=8)
        g.add_argument("--scripts", type=int, default=10)
        g.add_argument("--filler-bytes", type=int, default=45000)
        g.add_argument("--tx-queries", type=int, default=3000)
        g.add_argument("--passes", type=int, default=5)
        g.add_argument("--concurrency", default="1,8")
        g.add_argument("--chain-cache", help="dir holding (or receiving) the generated chain")
        g.add_argument("--iocount", help="path of the DYLD interposer dylib")
        g.add_argument("--extra-arg", action="append", default=[],
                       help="NAME=ARG extra node argument")
        g.add_argument("--out", help="write the results JSON here")
        g.add_argument("--chain-only", action="store_true")

    def set_test_params(self):
        self.num_nodes = 0
        self.setup_clean_chain = True

    def setup_network(self):
        pass

    def skip_test_if_missing_module(self):
        pass

    # ---------------------------------------------------------------- chain
    def _base_args(self, binary):
        out = subprocess.run([binary, "-help-debug"], capture_output=True, text=True).stdout
        args = ["-acceptnonstdtxn=1", "-maxtxfee=10000000"]
        if "-avalanche=" in out:
            args.append("-avalanche=0")
        return args

    def target_scripts(self):
        out = []
        for k in range(self.options.scripts):
            redeem = CScript([b"bench-target-%d" % k, b"\x75"])  # <data> OP_DROP
            h = hash160(bytes(redeem))
            out.append((h, CScript([OP_HASH160, h, OP_EQUAL])))
        return out

    def build_chain(self, binary, cache):
        o = self.options
        idx = self.new_node(binary, self._base_args(binary) + ["-chronik=0", "-txindex=0"])
        self.start_node(idx)
        node = self.nodes[idx]
        spk_true = bytes(P2SH_OP_TRUE)
        addr = ADDRESS_ECREG_P2SH_OP_TRUE
        self.generatetoaddress(node, COINBASE_MATURITY + 20, addr, sync_fun=self.no_op)
        # Pool chains: one per history tx slot plus one filler chain, each
        # funded by its own mature coinbase.
        slots = o.txs_per_block + 1
        pool = []
        for h in range(1, slots + 1):
            blk = node.getblock(node.getblockhash(h), 2)
            cb = blk["tx"][0]
            for i, vout in enumerate(cb["vout"]):
                if vout["scriptPubKey"]["hex"] == spk_true.hex():
                    pool.append((cb["txid"], i, int(round(vout["value"] * 100))))
                    break
        assert len(pool) == slots, pool
        targets = self.target_scripts()
        filler = CScript([OP_RETURN, b"\x00" * o.filler_bytes])
        rot = 0
        t0 = time.time()
        for b in range(o.blocks):
            new_pool = []
            for s, (txid, n, value) in enumerate(pool):
                tx = CTransaction()
                tx.vin = [CTxIn(COutPoint(int(txid, 16), n), SCRIPTSIG_OP_TRUE, 0xFFFFFFFF)]
                if s < o.txs_per_block:
                    _, spk = targets[rot % len(targets)]
                    rot += 1
                    tx.vout = [CTxOut(1000, spk), CTxOut(0, P2SH_OP_TRUE)]
                else:
                    tx.vout = [CTxOut(0, filler), CTxOut(0, P2SH_OP_TRUE)]
                fee = 2 * (len(tx.serialize()) + 10)
                change = value - sum(x.nValue for x in tx.vout) - fee
                assert change > 10_000, (value, fee)
                tx.vout[1].nValue = change
                new_txid = node.sendrawtransaction(tx.serialize().hex(), 0)
                new_pool.append((new_txid, 1, change))
            pool = new_pool
            self.generatetoaddress(node, 1, addr, sync_fun=self.no_op)
            if b % 500 == 499:
                self.log.info(f"chain: {b + 1}/{o.blocks} blocks ({time.time() - t0:.0f}s)")
        height = node.getblockcount()
        self.stop_node(idx)
        regtest = os.path.join(node.datadir, "regtest")
        os.makedirs(cache, exist_ok=True)
        for sub in ("blocks", "chainstate"):
            _copy_tree(os.path.join(regtest, sub), os.path.join(cache, sub))
        meta = {"height": height, "blocks": o.blocks, "txs_per_block": o.txs_per_block,
                "scripts": o.scripts, "filler_bytes": o.filler_bytes}
        with open(os.path.join(cache, "meta.json"), "w") as f:
            json.dump(meta, f)
        return meta

    def new_node(self, binary, args):
        # add_nodes() numbers nodes from 0 on every call: one node at a time.
        self.nodes = []
        initialize_datadir(self.options.tmpdir, 0, self.chain)
        self.add_nodes(1, [args], binary=[binary])
        return 0

    # ---------------------------------------------------------------- bench
    def wait_chronik(self, client, height, timeout=1800):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                status, body = client.get("/blockchain-info")
                if status == 200:
                    # BlockchainInfo: field 1 tip_hash (bytes), field 2 tip_height (int32)
                    if self._tip_height(body) == height:
                        return
            except OSError:
                pass
            time.sleep(0.5)
        raise AssertionError("Chronik did not reach the tip")

    @staticmethod
    def _tip_height(body):
        pos = 0
        while pos < len(body):
            key = body[pos]
            pos += 1
            field, wt = key >> 3, key & 7
            if wt == 2:
                ln = body[pos]
                pos += 1 + ln
            elif wt == 0:
                val = 0
                shift = 0
                while True:
                    b = body[pos]
                    pos += 1
                    val |= (b & 0x7F) << shift
                    shift += 7
                    if not b & 0x80:
                        break
                if field == 2:
                    return val
            else:
                return None
        return 0

    def requests(self, node, meta):
        targets = self.target_scripts()
        hist = []
        per_script = meta["blocks"] * meta["txs_per_block"] // meta["scripts"]
        pages = (per_script + PAGE_SIZE - 1) // PAGE_SIZE
        for h, _ in targets:
            for p in range(pages):
                hist.append(f"/script/p2sh/{h.hex()}/history?page={p}&page_size={PAGE_SIZE}")
        # txids: from the first page of every script (most recent txs) and
        # the last (oldest), then a fixed random sample over all heights.
        rng = random.Random(42)
        heights = list(range(COINBASE_MATURITY + 21, meta["height"] + 1))
        sample = [rng.choice(heights) for _ in range(self.options.tx_queries)]
        txq = []
        blockcache = {}
        for hgt in sample:
            if hgt not in blockcache:
                blockcache[hgt] = node.getblock(node.getblockhash(hgt), 1)["tx"]
            txs = blockcache[hgt]
            txq.append(f"/tx/{txs[rng.randrange(len(txs))]}")
        return hist, txq

    def run_list(self, port, paths, conc):
        """Returns (wall seconds, per-request latencies, sha256 of bodies in order)."""
        lat = [0.0] * len(paths)
        bodies = [None] * len(paths)
        errors = []

        def worker(idxs):
            c = Client(port)
            for i in idxs:
                t = time.perf_counter()
                status, body = c.get(paths[i])
                lat[i] = time.perf_counter() - t
                if status != 200:
                    errors.append((paths[i], status, body[:200]))
                bodies[i] = hashlib.sha256(body).digest()

        chunks = [list(range(k, len(paths), conc)) for k in range(conc)]
        t0 = time.perf_counter()
        threads = [threading.Thread(target=worker, args=(ch,)) for ch in chunks]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall = time.perf_counter() - t0
        assert not errors, errors[:3]
        digest = hashlib.sha256(b"".join(bodies)).hexdigest()
        return wall, lat, digest

    def bench_build(self, name, build, meta, cache, idx):
        o = self.options
        binary = _find_binary(build)
        extra = [a.split("=", 1)[1] for a in o.extra_arg if a.split("=", 1)[0] == name]
        args = self._base_args(binary) + ["-chronik=1"] + extra
        idx = self.new_node(binary, args)
        node = self.nodes[idx]
        regtest = os.path.join(node.datadir, "regtest")
        shutil.rmtree(regtest, ignore_errors=True)
        os.makedirs(regtest)
        for sub in ("blocks", "chainstate"):
            _copy_tree(os.path.join(cache, sub), os.path.join(regtest, sub))
        self.start_node(idx)
        client = Client(node.chronik_port)
        t0 = time.time()
        self.wait_chronik(client, meta["height"])
        sync_s = time.time() - t0
        hist, txq = self.requests(node, meta)
        res = {"binary": binary, "sync_seconds": sync_s, "history_requests": len(hist),
               "tx_requests": len(txq), "phases": {}}
        # Warm-up: page cache, Chronik caches.
        self.run_list(node.chronik_port, hist, 1)
        self.run_list(node.chronik_port, txq, 1)
        for conc in [int(c) for c in o.concurrency.split(",")]:
            for label, paths in (("history", hist), ("tx", txq)):
                walls, lats, digests = [], [], set()
                for _ in range(o.passes):
                    wall, lat, digest = self.run_list(node.chronik_port, paths, conc)
                    walls.append(wall)
                    lats.extend(lat)
                    digests.add(digest)
                assert len(digests) == 1, f"{name}: responses differ between passes"
                lats.sort()
                res["phases"][f"{label}_c{conc}"] = {
                    "walls": walls,
                    "median_wall": statistics.median(walls),
                    "min_wall": min(walls),
                    "p50_ms": 1000 * lats[len(lats) // 2],
                    "p99_ms": 1000 * lats[int(len(lats) * 0.99)],
                    "digest": digests.pop(),
                    "txs_loaded_per_pass": (len(paths) * PAGE_SIZE if label == "history"
                                            else len(paths)),
                }
                self.log.info(f"{name} {label} c{conc}: median {statistics.median(walls):.3f}s "
                              f"min {min(walls):.3f}s")
        self.stop_node(idx)
        if o.iocount:
            out = os.path.join(self.options.tmpdir, f"iocount-{name}.jsonl")
            if os.path.exists(out):
                os.remove(out)
            env = {"DYLD_INSERT_LIBRARIES": os.path.abspath(o.iocount), "IOCOUNT_OUT": out}
            self.start_node(idx, env=env)
            pid = node.process.pid
            self.wait_chronik(client, meta["height"])
            self.run_list(node.chronik_port, hist, 1)  # warm
            self.run_list(node.chronik_port, txq, 1)
            os.kill(pid, signal.SIGUSR2)  # reset (discard warm-up counts)
            time.sleep(0.3)
            self.run_list(node.chronik_port, hist, 1)
            time.sleep(0.3)
            os.kill(pid, signal.SIGUSR2)
            time.sleep(0.3)
            self.run_list(node.chronik_port, txq, 1)
            time.sleep(0.3)
            os.kill(pid, signal.SIGUSR2)
            time.sleep(0.5)
            self.stop_node(idx)
            with open(out) as f:
                lines = [json.loads(line) for line in f if line.strip()]
            res["iocount"] = {"history_pass": lines[1], "tx_pass": lines[2]}
            self.log.info(f"{name} iocount: {res['iocount']}")
        return res

    def run_test(self):
        o = self.options
        builds = [b.split("=", 1) for b in o.build]
        assert len(builds) == 1, "one --build per run (see the module docstring)"
        cache = o.chain_cache or os.path.join(o.tmpdir, "chain")
        if os.path.exists(os.path.join(cache, "meta.json")):
            with open(os.path.join(cache, "meta.json")) as f:
                meta = json.load(f)
            self.log.info(f"reusing chain {cache}: {meta}")
        else:
            meta = self.build_chain(_find_binary(os.path.abspath(builds[0][1])), cache)
        files = sorted(os.listdir(os.path.join(cache, "blocks")))
        meta["block_files"] = [f for f in files if f.startswith("blk")]
        if o.chain_only:
            return
        results = {"meta": meta, "builds": {}}
        for i, (name, build) in enumerate(builds):
            results["builds"][name] = self.bench_build(name, os.path.abspath(build), meta,
                                                       cache, i)
        digests = {}
        for name, r in results["builds"].items():
            for ph, v in r["phases"].items():
                digests.setdefault(ph, set()).add(v["digest"])
        results["digests"] = {ph: s.pop() for ph, s in digests.items()}
        self.log.info(json.dumps(results, indent=1))
        if o.out:
            with open(o.out, "w") as f:
                json.dump(results, f, indent=1)


if __name__ == "__main__":
    BenchTxReads().main()
