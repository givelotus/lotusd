#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""One explicit regtest loss-experiment case; --plan never launches processes.

Use a stopped, artificial regtest prefix fixture and a raw next-block file. A
case copies the prefix into fresh owned server/client datadirs, transfers that
block over WT or WSS, and records fresh ping samples plus validated Avalanche
poll RTT debug events. It never configures system impairment or enables a
release default. See README.md before running; a case is not the full gate.
"""

import argparse
import base64
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "test" / "functional"))
from test_framework import udp_impair  # noqa: E402

AUTH = "Basic " + base64.b64encode(b"wt-experiment:local-regtest-only").decode()
POLL = re.compile(r"poll_rtt peer=(-?\d+) round=(\d+) rtt_ms=(\d+)")


def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def distribution(samples):
    ordered = sorted(samples)
    if not ordered:
        return {"n": 0, "p50_ms": None, "p99_ms": None}
    return {
        "n": len(ordered),
        "p50_ms": ordered[math.ceil(0.5 * len(ordered)) - 1],
        "p99_ms": ordered[math.ceil(0.99 * len(ordered)) - 1],
    }


def poll_samples(path, begin, end, peer_id):
    samples = []
    for line in path.read_text(errors="replace").splitlines():
        match = POLL.search(line)
        if match and int(match[1]) == peer_id:
            timestamp = datetime.fromisoformat(
                line.split()[0].replace("Z", "+00:00")
            ).timestamp()
            if begin <= timestamp <= end:
                samples.append(
                    {
                        "round": int(match[2]),
                        "rtt_ms": int(match[3]),
                        "timestamp": timestamp,
                    }
                )
    return samples


class Deadline:
    """One shared work budget across startup, connection and transfer phases."""

    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def limit(self, seconds):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("case work budget expired")
        return min(seconds, remaining)


class Node:
    def __init__(
        self, binary, datadir, rpc_port, p2p_port, public_port, extra, console, deadline
    ):
        self.port = rpc_port
        self.deadline = deadline
        self.handle = console.open("wb")
        self.process = None
        config = datadir / "experiment.conf"
        config.write_text("")  # Do not load a fixture's inherited configuration.
        command = [
            str(binary),
            "-regtest",
            f"-datadir={datadir}",
            f"-conf={config}",
            "-server=1",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            f"-rpcport={rpc_port}",
            "-rpcuser=wt-experiment",
            "-rpcpassword=local-regtest-only",
            f"-port={p2p_port}",
            f"-bind=127.0.0.1:{p2p_port}",
            f"-publicbind=127.0.0.1:{public_port}",
            "-p2pwebtransport=1",
            f"-p2pwebtransportbind=127.0.0.1:{public_port}",
            "-connect=0",
            "-discover=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-listen=1",
            "-maxconnections=32",
            "-maxavalancheoutbound=0",
            "-excessiveblocksize=40000000",
            "-debug=avalanche",
            "-debug=net",
            "-logtimemicros=1",
            "-printtoconsole=0",
            *extra,
        ]
        try:
            self.process = subprocess.Popen(
                command, stdout=self.handle, stderr=subprocess.STDOUT
            )
            self.wait(lambda: self.rpc("getblockchaininfo"), timeout=60)
        except BaseException:
            self.close()
            raise

    def rpc(self, method, params=None, timeout=10, use_deadline=True):
        if use_deadline:
            timeout = self.deadline.limit(timeout)
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/",
            data=json.dumps(
                {"method": method, "params": params or [], "id": 1}
            ).encode(),
            headers={"Authorization": AUTH, "Content-Type": "application/json"},
        )
        # Encoding a large submitblock JSON body also consumes work budget.
        if use_deadline:
            timeout = self.deadline.limit(timeout)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
        if value["error"]:
            raise RuntimeError(value["error"])
        return value["result"]

    def wait(self, predicate, timeout):
        deadline = min(time.monotonic() + timeout, self.deadline.end)
        last_error = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"owned node exited {self.process.returncode}")
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, RuntimeError) as error:
                last_error = error
            time.sleep(0.02)
        raise TimeoutError(f"node condition timed out: {last_error}")

    def peer(self, peer_id):
        return next(peer for peer in self.rpc("getpeerinfo") if peer["id"] == peer_id)

    def close(self):
        if self.process is not None and self.process.poll() is None:
            try:
                self.rpc("stop", timeout=1, use_deadline=False)
            except Exception:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=1)
        self.handle.close()


def collect_pings(node, peer_id, stop, samples, errors):
    try:
        while not stop.is_set():
            previous = node.peer(peer_id).get("bytesrecv_per_msg", {}).get("pong", 0)
            node.rpc("ping")
            deadline = time.monotonic() + 10
            while not stop.is_set() and time.monotonic() < deadline:
                peer = node.peer(peer_id)
                if peer.get("bytesrecv_per_msg", {}).get("pong", 0) > previous:
                    samples.append(
                        {"timestamp": time.time(), "rtt_ms": peer["pingtime"] * 1000}
                    )
                    break
                stop.wait(0.01)
            else:
                if not stop.is_set():
                    errors.append("ping timeout")
            stop.wait(0.02)
    except Exception as error:
        errors.append(str(error))


def fixture_copy(source, target):
    # A caller-created marker prevents accidentally treating production data as
    # a fixture. Source files are read only; no node ever opens this directory.
    marker = json.loads((source / "wt-experiment-fixture.json").read_text())
    if marker.get("network") != "regtest" or marker.get("stopped") is not True:
        raise ValueError(
            "fixture marker must identify a stopped artificial regtest snapshot"
        )
    if not (source / "regtest" / "blocks").is_dir():
        raise ValueError("fixture must be a regtest datadir root")
    if any(
        (source / item).exists()
        for item in ("blocks", "chainstate", "mainnet", "testnet3")
    ):
        raise ValueError("fixture contains non-regtest chain data")
    if list(source.glob("*.pid")) or list((source / "regtest").glob("*.pid")):
        raise ValueError("remove stale PID files from the stopped fixture copy first")
    if target.resolve().is_relative_to(source.resolve()):
        raise ValueError("output must be outside the fixture")
    if any(path.is_symlink() for path in source.rglob("*")):
        raise ValueError("fixture must contain no symlinks to external data")
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns(
            "*.conf",
            "*.pid",
            ".cookie",
            ".lock",
            "peers.dat",
            "anchors.dat",
            "debug.log",
            "mempool.dat",
        ),
    )


def run_case(args):
    deadline = Deadline(args.timeout)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {
        "status": "incomplete",
        "gate_pass": False,
        "platform": platform.platform(),
        "load_start": os.getloadavg(),
        "transport": args.transport,
        "loss": args.loss,
        "delay_ms": args.delay_ms,
        "rate_mbps": args.rate_mbps,
        "queue_pkts": args.queue_pkts,
        "seed": args.seed,
        "impairment": args.impairment,
        "block_bytes": args.block.stat().st_size,
        "binary_sha256": sha(args.bitcoind),
        "block_sha256": sha(args.block),
        "driver_sha256": sha(Path(__file__)),
        "udp_model_sha256": sha(Path(udp_impair.__file__)),
        "notes": [
            "One case does not establish the multi-run Linux gate or enable defaults."
        ],
    }
    write_json(output / "result.json", result)
    server = client = proxy = collector = None
    proxy_log = None
    stop = threading.Event()
    ping, errors = [], []
    try:
        if args.impairment == "external":
            receipt = json.loads(args.impairment_receipt.read_text())
            for key in ("loss", "delay_ms", "rate_mbps", "queue_pkts"):
                if receipt.get(key) != getattr(args, key):
                    raise ValueError(f"external impairment receipt mismatch: {key}")
            if receipt.get("model") != "packet-level" or not receipt.get(
                "both_directions"
            ):
                raise ValueError(
                    "receipt must describe bidirectional packet-level impairment"
                )
            shutil.copy2(args.impairment_receipt, output / "impairment-receipt.json")
            result["impairment_receipt_sha256"] = sha(args.impairment_receipt)
            result["notes"].append(
                "External impairment receipt is recorded, not independently verified by the driver."
            )
        node_args = (
            json.loads(args.node_args.read_text()) if args.node_args else [[], []]
        )
        if len(node_args) != 2 or any(
            not isinstance(part, list) or any(not isinstance(arg, str) for arg in part)
            for part in node_args
        ):
            raise ValueError("node-args must be a JSON array of two argument arrays")
        # Restrict optional fixture arguments to Avalanche identity/quorum knobs;
        # callers cannot override isolation, paths, binds or transport selection.
        allowed = ("-ava", "-avalanche")
        if any(
            not arg.startswith(allowed) or "\n" in arg
            for part in node_args
            for arg in part
        ):
            raise ValueError("node-args permits Avalanche fixture arguments only")
        if args.node_args:
            result["node_args_sha256"] = sha(args.node_args)
        for name in ("server", "client"):
            fixture_copy(args.fixture, output / name)
        base = args.base_port
        server = Node(
            args.bitcoind,
            output / "server",
            base,
            base + 2,
            base + 4,
            node_args[0],
            output / "server-console.log",
            deadline,
        )
        client = Node(
            args.bitcoind,
            output / "client",
            base + 1,
            base + 3,
            base + 6,
            node_args[1],
            output / "client-console.log",
            deadline,
        )
        prefix = server.rpc("getbestblockhash")
        if client.rpc("getbestblockhash") != prefix:
            raise ValueError("fixture copies started on different chain tips")
        result["prefix_hash"] = prefix
        public_port = base + 4
        if args.impairment == "udp":
            proxy_log = (output / "udp-proxy.log").open("wb")
            proxy = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(udp_impair.__file__)),
                    "--listen",
                    f"127.0.0.1:{base + 5}",
                    "--server",
                    f"127.0.0.1:{public_port}",
                    "--loss",
                    str(args.loss),
                    "--delay-ms",
                    str(args.delay_ms),
                    "--rate-mbps",
                    str(args.rate_mbps),
                    "--queue-pkts",
                    str(args.queue_pkts),
                    "--seed",
                    str(args.seed),
                    "--duration",
                    str(args.timeout + 60),
                    "--stats",
                    str(output / "udp-stats.json"),
                ],
                stdout=proxy_log,
                stderr=subprocess.STDOUT,
            )
            proxy_deadline = min(time.monotonic() + 5, deadline.end)
            while '"proxy": "ready"' not in (output / "udp-proxy.log").read_text():
                if proxy.poll() is not None or time.monotonic() > proxy_deadline:
                    raise RuntimeError("UDP proxy did not start")
                time.sleep(0.02)
            public_port = base + 5
        if args.transport == "wt":
            cert = output / "server" / "regtest" / "node_tls_cert.pem"
            fingerprint = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(cert.read_text())
            ).hexdigest()
            url = f"wt://127.0.0.1:{public_port}/p2p/wt#cert={fingerprint}"
        else:
            url = f"wss://127.0.0.1:{public_port}/p2p/ws"
        client.rpc("addnode", [url, "onetry"])
        peers = client.wait(
            lambda: [
                p
                for p in client.rpc("getpeerinfo")
                if not p["inbound"] and p["version"]
            ],
            timeout=30,
        )
        if (
            len(peers) != 1
            or peers[0]["transport"]
            != {"wt": "webtransport", "wss": "wss"}[args.transport]
        ):
            raise RuntimeError("unexpected transport or extra outbound connection")
        peer_id = peers[0]["id"]
        result["peer_before"] = peers[0]
        collector = threading.Thread(
            target=collect_pings,
            args=(client, peer_id, stop, ping, errors),
            daemon=True,
        )
        collector.start()
        begin = time.time()
        accepted = server.rpc(
            "submitblock", [args.block.read_bytes().hex()], timeout=args.timeout
        )
        if accepted is not None:
            raise RuntimeError(f"fixture next block rejected: {accepted}")
        target = server.rpc("getbestblockhash")
        if target == prefix:
            raise RuntimeError("provided block did not advance fixture tip")
        client.wait(
            lambda: client.rpc("getbestblockhash") == target, timeout=args.timeout
        )
        end = time.time()
        stop.set()
        collector.join(timeout=12)
        if collector.is_alive():
            raise RuntimeError("ping collector did not terminate")
        result["target_hash"] = target
        result["transfer_seconds"] = end - begin
        result["window_unix"] = [begin, end]
        result["peer_after"] = client.peer(peer_id)
        before_bytes = result["peer_before"].get("bytesrecv_per_msg", {})
        after_bytes = result["peer_after"].get("bytesrecv_per_msg", {})
        result["block_body_message_bytes"] = sum(
            after_bytes.get(name, 0) - before_bytes.get(name, 0)
            for name in ("block", "blocktxn")
        )
        result["full_body_transferred"] = (
            result["block_body_message_bytes"] >= 0.9 * result["block_bytes"]
        )
        result["ping_errors"] = errors
        write_json(output / "ping-samples.json", ping)
        selected_ping = [
            sample["rtt_ms"] for sample in ping if begin <= sample["timestamp"] <= end
        ]
        result["ping"] = distribution(selected_ping)
        # close() flushes buffered logs before parsing the valid-response events.
        client.close()
        polls = poll_samples(
            output / "client" / "regtest" / "debug.log", begin, end, peer_id
        )
        write_json(output / "avalanche-poll-samples.json", polls)
        result["avalanche"] = distribution([sample["rtt_ms"] for sample in polls])
        result["load_end"] = os.getloadavg()
        if (
            not selected_ping
            or errors
            or not polls
            or not result["full_body_transferred"]
        ):
            result["status"] = (
                "smoke-only-incomplete-latency"
                if args.allow_incomplete_smoke
                else "failed-latency-samples"
            )
        else:
            result["status"] = "case-complete"
        result["case_eligible_for_gate_review"] = (
            result["status"] == "case-complete"
            and platform.system() == "Linux"
            and args.impairment == "external"
            and args.block.stat().st_size >= 32_000_000
        )
        write_json(output / "result.json", result)
        return (
            0
            if result["status"] == "case-complete" or args.allow_incomplete_smoke
            else 1
        )
    except BaseException as error:
        result["error"] = str(error)
        write_json(output / "result.json", result)
        raise
    finally:
        stop.set()
        if collector:
            collector.join(timeout=12)
        for node in (client, server):
            if node:
                node.close()
        if proxy and proxy.poll() is None:
            proxy.terminate()
            try:
                proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=3)
        if proxy_log:
            proxy_log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan",
        action="store_true",
        help="print interleaved case matrix without launching anything",
    )
    parser.add_argument("--bitcoind", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--block", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--transport", choices=("wt", "wss"))
    parser.add_argument(
        "--impairment", choices=("external", "udp", "none"), default="external"
    )
    parser.add_argument("--impairment-receipt", type=Path)
    parser.add_argument(
        "--node-args",
        type=Path,
        help="two Avalanche fixture argument arrays; hash recorded, contents not copied",
    )
    parser.add_argument("--loss", type=float, default=0)
    parser.add_argument("--delay-ms", type=float, default=25)
    parser.add_argument("--rate-mbps", type=float, default=50)
    parser.add_argument("--queue-pkts", type=int, default=4096)
    parser.add_argument("--seed", type=int, default=8703)
    parser.add_argument("--base-port", type=int, default=41000)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--allow-incomplete-smoke", action="store_true")
    args = parser.parse_args()
    if args.plan:
        print(
            json.dumps(
                {
                    "gate_pass": False,
                    "launches": 0,
                    "cases": [
                        {
                            "loss": loss,
                            "repetition": repeat,
                            "transport": transport,
                            "delay_ms": 25,
                            "rate_mbps": 50,
                        }
                        for loss in (0, 0.005, 0.01, 0.02)
                        for repeat in range(3)
                        for transport in (
                            ("wt", "wss") if repeat % 2 == 0 else ("wss", "wt")
                        )
                    ],
                },
                indent=2,
            )
        )
        return 0
    if any(
        getattr(args, name) is None
        for name in ("bitcoind", "fixture", "block", "output", "transport")
    ):
        parser.error("a case requires bitcoind, fixture, block, output and transport")
    if not 35000 <= args.base_port <= 49992:
        parser.error("base-port must leave all seven ports inside 35000..49998")
    if (
        not all(
            math.isfinite(value)
            for value in (args.loss, args.delay_ms, args.rate_mbps, args.timeout)
        )
        or not 0 <= args.loss <= 1
        or args.delay_ms < 0
        or args.rate_mbps < 0
        or not 0 < args.timeout <= 600
        or not 0 < args.queue_pkts <= 65536
    ):
        parser.error("invalid bounded impairment settings")
    if args.block.stat().st_size > 40_000_000:
        parser.error("target block must be at most 40 MB")
    if args.impairment == "external" and not args.impairment_receipt:
        parser.error("external mode requires the controlled-VM impairment receipt")
    if args.impairment == "udp" and args.transport != "wt":
        parser.error(
            "UDP impairment is WT-only; TCP stream dropping cannot model packet loss"
        )
    if args.impairment == "none" and (args.loss or args.delay_ms or args.rate_mbps):
        parser.error(
            "unimpaired smoke must explicitly set loss, delay-ms and rate-mbps to zero"
        )
    args.bitcoind = args.bitcoind.resolve()

    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        return run_case(args)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    sys.exit(main())
