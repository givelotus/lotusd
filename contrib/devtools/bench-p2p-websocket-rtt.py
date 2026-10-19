#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Measure P2P ping round-trip time over TCP and WebSocket transports.

Starts pairs of regtest nodes (in a temporary directory, on ports from
--base-port), connects each client to its server over one transport, sends
pings through the `ping` RPC and reports the peer's `pingtime` statistics.

Usage: bench-p2p-websocket-rtt.py --bitcoind build/src/bitcoind [--pings 300]
"""

import argparse
import base64
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

USER, PASSWORD = "bench", "bench"
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


def rpc(port, method, params=None, timeout=60):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/",
        data=json.dumps({"method": method, "params": params or [], "id": 1}).encode(),
        headers={"Authorization": AUTH, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        out = json.loads(resp.read())
    if out.get("error"):
        raise RuntimeError(out["error"])
    return out["result"]


def start(bitcoind, datadir, rpc_port, p2p_port, extra):
    os.makedirs(datadir, exist_ok=True)
    proc = subprocess.Popen(
        [bitcoind, "-regtest", f"-datadir={datadir}", f"-rpcport={rpc_port}",
         f"-port={p2p_port}", f"-bind=127.0.0.1:{p2p_port}",
         f"-rpcuser={USER}", f"-rpcpassword={PASSWORD}", "-server=1",
         "-listen=1", "-discover=0", "-dnsseed=0", "-fixedseeds=0",
         "-printtoconsole=0", *extra],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 60
    while True:
        try:
            rpc(rpc_port, "getblockcount", timeout=5)
            return proc
        except Exception:
            if proc.poll() is not None or time.time() > deadline:
                raise RuntimeError(f"node on port {rpc_port} did not start")
            time.sleep(0.2)


def main():
    parser = argparse.ArgumentParser(description="P2P ping RTT per transport")
    parser.add_argument("--bitcoind", required=True)
    parser.add_argument("--pings", type=int, default=300)
    parser.add_argument("--base-port", type=int, default=33400)
    args = parser.parse_args()

    # name, client -connect target (from the server's rpc/p2p ports), extras
    transports = [
        ("tcp", "127.0.0.1:{p2p}", [], []),
        ("ws none", "ws://127.0.0.1:{rpc}/p2p/ws", [], ["-p2pwebsocketoffer=none"]),
        ("ws p2p-zstd-v1", "ws://127.0.0.1:{rpc}/p2p/ws", [], []),
        ("wss p2p-zstd-v1", "wss://127.0.0.1:{rpc}/p2p/ws", [], []),
    ]
    tmp = tempfile.mkdtemp(prefix="p2p-ws-rtt-")
    nodes = []
    try:
        pairs = []
        for i, (name, target, server_extra, client_extra) in enumerate(transports):
            port = args.base_port + 10 * i
            srv_rpc, srv_p2p, cli_rpc, cli_p2p = port, port + 1, port + 2, port + 3
            nodes.append((srv_rpc, start(args.bitcoind, f"{tmp}/{i}s", srv_rpc,
                                         srv_p2p, server_extra)))
            nodes.append((cli_rpc, start(
                args.bitcoind, f"{tmp}/{i}c", cli_rpc, cli_p2p,
                ["-tlsephemeral=0",
                 "-connect=" + target.format(rpc=srv_rpc, p2p=srv_p2p),
                 *client_extra])))
            pairs.append((name, cli_rpc))
        for name, cli_rpc in pairs:
            deadline = time.time() + 60
            while not rpc(cli_rpc, "getpeerinfo"):
                if time.time() > deadline:
                    sys.exit(f"{name}: peer did not connect")
                time.sleep(0.2)
        samples = {name: [] for name, _ in pairs}
        for _ in range(args.pings):
            for name, cli_rpc in pairs:
                rpc(cli_rpc, "ping")
            time.sleep(0.02)
            for name, cli_rpc in pairs:
                info = rpc(cli_rpc, "getpeerinfo")[0]
                if "pingtime" in info:
                    samples[name].append(info["pingtime"] * 1e6)
        print(f"{'transport':<18} {'min':>8} {'median':>8} {'p90':>8}  (us, n)")
        for name, cli_rpc in pairs:
            s = sorted(samples[name])
            info = rpc(cli_rpc, "getpeerinfo")[0]
            print(f"{name:<18} {info['minping'] * 1e6:8.1f} "
                  f"{statistics.median(s):8.1f} {s[int(len(s) * 0.9)]:8.1f}"
                  f"  ({len(s)})")
    finally:
        for port, proc in nodes:
            try:
                rpc(port, "stop")
            except Exception:
                pass
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
