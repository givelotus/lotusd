#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""HTTP/1.1 versus HTTP/2 on the node's TLS port: an interleaved A/B run.

For each bitcoind given (e.g. a base build and an HTTP/2 build), start a
regtest node in a fresh datadir, prepare a large block, then run every
workload in round-robin rounds (so that load from the rest of the machine
hits all variants alike) and report the median of the rounds, with the load
average around each run.

Workloads (httpload.c is the client):
  small-h1     getblockcount over 64 HTTP/1.1 connections
  small-h2     getblockcount, 64 streams over 4 HTTP/2 connections
  small-h2x1   getblockcount, 64 streams over 1 HTTP/2 connection
  block-h1     getblock <large> 2, over 4 HTTP/1.1 connections
  block-h2     getblock <large> 2, 4 streams over 1 HTTP/2 connection
HTTP/2 workloads are skipped for a node that does not select h2 (e.g. a
build without HTTP/2), so the same command measures the base too.

Usage:
  run.py --bitcoind BUILD_A/src/bitcoind [--bitcoind BUILD_B/src/bitcoind]
         [--rounds 3] [--seconds 10] [--port-base 36500] [--workdir DIR]
         [--json results.json] [--only small-h1,small-h2]
"""

import argparse
import base64
import http.client
import json
import os
import shutil
import ssl
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))

WORKLOADS = {
    "small-h1": {"proto": "h1", "connections": 64, "streams": 1, "rpc": "small"},
    "small-h2": {"proto": "h2", "connections": 4, "streams": 16, "rpc": "small"},
    "small-h2x1": {"proto": "h2", "connections": 1, "streams": 64, "rpc": "small"},
    "block-h1": {"proto": "h1", "connections": 4, "streams": 1, "rpc": "block"},
    "block-h2": {"proto": "h2", "connections": 1, "streams": 4, "rpc": "block"},
}


def build_client(workdir):
    """Compile httpload.c, with HTTP/2 if pkg-config finds libnghttp2."""
    out = os.path.join(workdir, "httpload")
    src = os.path.join(HERE, "httpload.c")
    cc = os.environ.get("CC", "cc")

    def flags(pkgs):
        try:
            return subprocess.check_output(
                ["pkg-config", "--cflags", "--libs", *pkgs], text=True
            ).split()
        except (OSError, subprocess.CalledProcessError):
            return None

    with_h2 = flags(["openssl", "libnghttp2"])
    if with_h2 is not None:
        cmd = [cc, "-O2", "-o", out, src, *with_h2, "-lpthread"]
    else:
        ssl_flags = flags(["openssl"]) or ["-lssl", "-lcrypto"]
        cmd = [cc, "-O2", "-DNO_HTTP2", "-o", out, src, *ssl_flags, "-lpthread"]
    subprocess.check_call(cmd)
    return out


class Node:
    def __init__(self, bitcoind, datadir, rpc_port, p2p_port):
        self.bitcoind = bitcoind
        self.datadir = datadir
        self.rpc_port = rpc_port
        self.user, self.password = "bench", "bench"
        os.makedirs(datadir, exist_ok=True)
        self.proc = subprocess.Popen(
            [
                bitcoind,
                f"-datadir={datadir}",
                "-regtest",
                "-server",
                "-listen=0",
                f"-port={p2p_port}",
                f"-rpcport={rpc_port}",
                f"-rpcuser={self.user}",
                f"-rpcpassword={self.password}",
                # Enough workers and queue for 64 concurrent requests
                "-rpcthreads=16",
                "-rpcworkqueue=256",
                "-debug=0",
                "-printtoconsole=0",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.auth = (
            "Basic "
            + base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        )
        for _ in range(600):
            try:
                self.rpc("getblockcount")
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError(f"{bitcoind} did not start")

    def rpc(self, method, *params):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(
            "127.0.0.1", self.rpc_port, context=ctx, timeout=600
        )
        body = json.dumps({"method": method, "params": list(params), "id": 1})
        conn.request("POST", "/", body, {"Authorization": self.auth})
        reply = json.loads(conn.getresponse().read())
        conn.close()
        if reply.get("error"):
            raise RuntimeError(reply["error"])
        return reply["result"]

    def alpn(self, offer):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(offer)
        import socket

        with socket.create_connection(("127.0.0.1", self.rpc_port)) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                return tls.selected_alpn_protocol()

    def prepare_large_block(self, outputs, txs):
        """A block with `txs` transactions of `outputs` outputs each."""
        self.rpc("createwallet", "bench")
        addr = self.rpc("getnewaddress")
        self.rpc("generatetoaddress", 101 + txs, addr)
        for _ in range(txs):
            dests = {self.rpc("getnewaddress"): 1000 for _ in range(outputs)}
            self.rpc("sendmany", "", dests)
        return self.rpc("generatetoaddress", 1, addr)[0]

    def stop(self):
        try:
            self.rpc("stop")
            self.proc.wait(timeout=120)
        except Exception:
            self.proc.kill()
            self.proc.wait()


def run_workload(client, node, spec, seconds, block_hash):
    if spec["rpc"] == "small":
        body = json.dumps({"method": "getblockcount", "params": [], "id": 1})
    else:
        body = json.dumps({"method": "getblock", "params": [block_hash, 2], "id": 1})
    cmd = [
        client,
        "--port",
        str(node.rpc_port),
        "--proto",
        spec["proto"],
        "--connections",
        str(spec["connections"]),
        "--streams",
        str(spec["streams"]),
        "--seconds",
        str(seconds),
        "--body",
        body,
        "--header",
        f"Authorization: {node.auth}",
        "--header",
        "Content-Type: application/json",
    ]
    load_before = os.getloadavg()
    result = json.loads(subprocess.check_output(cmd, text=True))
    result["loadavg_before"] = load_before
    result["loadavg_after"] = os.getloadavg()
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bitcoind", action="append", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--port-base", type=int, default=36500)
    ap.add_argument("--workdir")
    ap.add_argument("--json")
    ap.add_argument("--only", help="comma separated workload names")
    ap.add_argument("--block-outputs", type=int, default=1000)
    ap.add_argument("--block-txs", type=int, default=10)
    args = ap.parse_args()

    workdir = args.workdir or tempfile.mkdtemp(prefix="http2-bench-")
    os.makedirs(workdir, exist_ok=True)
    client = build_client(workdir)
    names = args.only.split(",") if args.only else list(WORKLOADS)

    nodes = []
    try:
        for i, bitcoind in enumerate(args.bitcoind):
            node = Node(
                os.path.abspath(bitcoind),
                os.path.join(workdir, f"node{i}"),
                args.port_base + 2 * i,
                args.port_base + 2 * i + 1,
            )
            nodes.append(node)
            node.h2 = node.alpn(["h2", "http/1.1"]) == "h2"
            node.block = node.prepare_large_block(args.block_outputs, args.block_txs)
            size = len(json.dumps(node.rpc("getblock", node.block, 2)))
            print(
                f"node{i}: {bitcoind} (h2: {'yes' if node.h2 else 'no'}), "
                f"getblock reply about {size} bytes",
                flush=True,
            )

        results = {}  # (node, workload) -> [runs]
        for r in range(args.rounds):
            for name in names:
                for i, node in enumerate(nodes):
                    spec = WORKLOADS[name]
                    if spec["proto"] == "h2" and not node.h2:
                        continue
                    res = run_workload(client, node, spec, args.seconds, node.block)
                    results.setdefault((i, name), []).append(res)
                    print(
                        f"round {r + 1} node{i} {name}: {res['rps']:.0f} req/s, "
                        f"p50 {res['p50_ms']:.2f} ms, p99 {res['p99_ms']:.2f} ms, "
                        f"errors {res['errors']}, load "
                        f"{res['loadavg_before'][0]:.1f}->{res['loadavg_after'][0]:.1f}",
                        flush=True,
                    )
    finally:
        for node in nodes:
            node.stop()

    print()
    print(
        "| node | workload | median req/s | median p50 ms | median p99 ms "
        "| MB/s | errors | load avg (1 min) |"
    )
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    summary = []
    for (i, name), runs in sorted(results.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        med = {
            k: statistics.median(run[k] for run in runs)
            for k in ("rps", "p50_ms", "p99_ms")
        }
        mbps = statistics.median(
            run["body_bytes"] / run["seconds"] / 1e6 for run in runs
        )
        loads = [run["loadavg_before"][0] for run in runs]
        errors = sum(run["errors"] for run in runs)
        print(
            f"| node{i} | {name} | {med['rps']:.0f} | {med['p50_ms']:.2f} | "
            f"{med['p99_ms']:.2f} | {mbps:.1f} | {errors} | "
            f"{min(loads):.0f}-{max(loads):.0f} |"
        )
        summary.append(
            {
                "node": i,
                "bitcoind": args.bitcoind[i],
                "workload": name,
                "median": med,
                "mb_per_s": mbps,
                "runs": runs,
            }
        )
    if args.json:
        with open(args.json, "w", encoding="utf8") as f:
            json.dump(summary, f, indent=1)
    if not args.workdir:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
