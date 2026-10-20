#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run one signed-transaction flood against a fresh clone of a fixture.

Transactions from flood.jsonl are split by unit (a dependent chain is one
unit and always goes to one sender, in order) across --peers senders. Each
sender is a separate process: either a raw P2P peer sending TX messages, or
an RPC client calling sendrawtransaction. A ZMQ `sequence` subscriber
timestamps every mempool addition, so admission latency is measured from the
moment a sender starts the socket write (P2P) or issues the
RPC, to the node's mempool-add notification. Clocks are the host's monotonic
clock in every process.

Prints one JSON object (and writes it to --result if given).

Usage:
  flood.py --bitcoind BUILD/src/bitcoind --fixture FIXTURE_DIR \
      --workdir SCRATCH [--peers 8] [--mode p2p|rpc] [--rate 0] \
      [--node-arg=-parallelmempool=0 ...]
"""

import argparse
import hashlib
import json
import multiprocessing
import os
import select
import struct
import subprocess
import threading
import time
from pathlib import Path

import admission_common as ac


def load_units(fixture, peers, peer_index, limit=None):
    units = []
    with open(Path(fixture) / "flood.jsonl") as f:
        for line in f:
            u = json.loads(line)
            if limit is not None and u["unit"] >= limit:
                break
            if u["unit"] % peers == peer_index:
                units.append(u)
    return units


def _drain(sock, stop):
    # The socket stays blocking (a timeout would make it non-blocking for
    # the sender as well, which blocks while the node applies backpressure);
    # wait for readability with select instead.
    buf = b""
    while not stop.is_set():
        try:
            readable, _, _ = select.select([sock], [], [], 0.2)
            if not readable:
                continue
            chunk = sock.recv(1 << 16)
        except OSError:
            return
        if not chunk:
            return
        buf += chunk
        while len(buf) >= 24:
            length = struct.unpack("<I", buf[16:20])[0]
            if len(buf) < 24 + length:
                break
            # Discard everything. Pings go unanswered: the node only drops a
            # peer after a 20 minute ping timeout, and a second writer would
            # interleave frames with the sender.
            buf = buf[24 + length :]


def sender(cfg, peer_index, ready_q, start_ev, stop_ev):
    units = load_units(cfg["fixture"], cfg["peers"], peer_index, cfg["unit_limit"])
    items = []
    for u in units:
        for hx in u["txs"]:
            raw = bytes.fromhex(hx)
            txid = ac.hash256(raw)[::-1].hex()
            items.append((txid, hx, ac.p2p_frame(b"tx", raw)))
    per_peer_rate = cfg["rate"] / cfg["peers"] if cfg["rate"] else 0.0
    sends = []
    errors = 0
    rejected = {}
    if cfg["mode"] == "p2p":
        sock = ac.p2p_connect(cfg["p2p_port"], relay=cfg["peer_relay"])
        sock.settimeout(None)
        drain_stop = threading.Event()
        drainer = threading.Thread(target=_drain, args=(sock, drain_stop), daemon=True)
        drainer.start()
        ready_q.put(peer_index)
        start_ev.wait()
        t0 = time.monotonic()
        for i, (txid, _, frame) in enumerate(items):
            if per_peer_rate:
                due = t0 + i / per_peer_rate
                now = time.monotonic()
                if due > now:
                    time.sleep(due - now)
            t_send = time.monotonic()
            sock.sendall(frame)
            sends.append((txid, t_send))
        stop_ev.wait()
        drain_stop.set()
        sock.close()
    else:
        rpc = ac.RPC(cfg["rpc_port"])
        rpc.call("getblockcount")
        ready_q.put(peer_index)
        start_ev.wait()
        t0 = time.monotonic()
        for i, (txid, hx, _) in enumerate(items):
            if per_peer_rate:
                due = t0 + i / per_peer_rate
                now = time.monotonic()
                if due > now:
                    time.sleep(due - now)
            t_send = time.monotonic()
            try:
                rpc.call("sendrawtransaction", hx)
            except RuntimeError as e:
                errors += 1
                reason = str(e)[:120]
                rejected[reason] = rejected.get(reason, 0) + 1
            t_done = time.monotonic()
            sends.append((txid, t_send, t_done))
    out = Path(cfg["workdir"]) / f"sender-{peer_index}.json"
    out.write_text(json.dumps({"sends": sends, "errors": errors, "rejected": rejected}))


def zmq_listener(cfg, ready_q, stop_ev):
    sub = ac.ZmqSub(cfg["libzmq"], f"tcp://127.0.0.1:{cfg['zmq_port']}")
    adds = {}
    removes = 0
    duplicate_adds = 0
    sequence_gaps = 0
    previous_sequence = None
    ready_q.put("zmq")
    while not stop_ev.is_set():
        frames = sub.recv_multipart()
        if frames is None or len(frames) < 2:
            continue
        if len(frames) >= 3 and len(frames[2]) == 4:
            sequence = struct.unpack("<I", frames[2])[0]
            if previous_sequence is not None:
                sequence_gaps += (sequence - previous_sequence - 1) & 0xFFFFFFFF
            previous_sequence = sequence
        body = frames[1]
        if len(body) < 33:
            continue
        label = body[32:33]
        if label == b"A":
            txid = body[:32].hex()
            duplicate_adds += txid in adds
            adds[txid] = time.monotonic()
        elif label == b"R":
            removes += 1
    sub.close()
    out = Path(cfg["workdir"]) / "zmq.json"
    out.write_text(
        json.dumps(
            {
                "adds": adds,
                "removes": removes,
                "duplicate_adds": duplicate_adds,
                "sequence_gaps": sequence_gaps,
            }
        )
    )


def cpu_seconds(pid):
    r = subprocess.run(
        ["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True
    )
    t = r.stdout.strip()
    if not t:
        return None
    parts = t.replace("-", ":").split(":")
    secs = 0.0
    for p in parts:
        secs = secs * 60 + float(p)
    return secs


def summarize_latency(values):
    if not values:
        return {}
    ms = [v * 1000 for v in values]
    return {
        "n": len(ms),
        "p50_ms": round(ac.percentile(ms, 0.50), 3),
        "p90_ms": round(ac.percentile(ms, 0.90), 3),
        "p99_ms": round(ac.percentile(ms, 0.99), 3),
        "max_ms": round(max(ms), 3),
    }


def run(args):
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    datadir = workdir / "datadir"
    ac.clone_tree(Path(args.fixture) / "datadir", datadir)
    for stale in ("debug.log", "mempool.dat"):
        p = datadir / "regtest" / stale
        if p.exists():
            p.unlink()
    manifest = json.loads((Path(args.fixture) / "manifest.json").read_text())
    fixture_hash = hashlib.sha256(
        (Path(args.fixture) / "flood.jsonl").read_bytes()
    ).hexdigest()
    if fixture_hash != manifest["flood_sha256"]:
        raise ValueError("fixture flood.jsonl differs from manifest")
    ports = ac.ports_for(args.portseed)
    node_args = [
        f"-zmqpubsequence=tcp://127.0.0.1:{ports['zmq']}",
        "-zmqpubsequencehwm=0",
        "-metrics=1",
        "-persistmempool=0",
        # regtest defaults to a full mempool consistency check per admission
        # (quadratic in pool size) and block-index checks; neither is what a
        # production node runs.
        "-checkmempool=0",
        "-checkblockindex=0",
    ] + list(args.node_arg)
    proc, rpc, argv = ac.start_node(
        args.bitcoind, datadir, ports, node_args, log_path=workdir / "node.out"
    )
    cfg = {
        "fixture": str(args.fixture),
        "peers": args.peers,
        "mode": args.mode,
        "rate": args.rate,
        "p2p_port": ports["p2p"],
        "rpc_port": ports["rpc"],
        "zmq_port": ports["zmq"],
        "workdir": str(workdir),
        "libzmq": ac.find_libzmq(args.libzmq),
        "unit_limit": args.unit_limit,
        "peer_relay": not args.no_relay,
    }
    expected = 0
    expected_ids = set()
    with open(Path(args.fixture) / "flood.jsonl") as f:
        for line in f:
            u = json.loads(line)
            if args.unit_limit is not None and u["unit"] >= args.unit_limit:
                break
            expected += len(u["txs"])
            expected_ids.update(
                ac.hash256(bytes.fromhex(hx))[::-1].hex() for hx in u["txs"]
            )
    if len(expected_ids) != expected:
        raise ValueError("fixture contains duplicate transactions")
    result = {
        "mode": args.mode,
        "peers": args.peers,
        "rate": args.rate,
        "peer_relay": not args.no_relay,
        "node_args": node_args,
        "label": args.label,
        "fixture_txs": expected,
        "fixture_sha256": manifest.get("flood_sha256"),
        "host_cpus": os.cpu_count(),
        "loadavg_start": list(os.getloadavg()),
    }
    ctx = multiprocessing.get_context("spawn")
    ready_q = ctx.Queue()
    start_ev = ctx.Event()
    stop_ev = ctx.Event()
    zmq_stop = ctx.Event()
    procs = []
    sampler = None
    zp = None
    try:
        zp = ctx.Process(target=zmq_listener, args=(cfg, ready_q, zmq_stop))
        zp.start()
        assert ready_q.get(timeout=60) == "zmq"
        time.sleep(0.5)  # ZMQ slow-joiner: let the subscription propagate
        for i in range(args.peers):
            p = ctx.Process(target=sender, args=(cfg, i, ready_q, start_ev, stop_ev))
            p.start()
            procs.append(p)
        for _ in range(args.peers):
            ready_q.get(timeout=300)
        time.sleep(0.5)
        cpu0 = cpu_seconds(proc.pid)
        t0 = time.monotonic()
        start_ev.set()
        last_size, last_change = -1, time.monotonic()
        timeline = []
        size = 0
        while True:
            if args.sample_seconds and sampler is None and size >= args.sample_at_size:
                sampler = subprocess.Popen(
                    [
                        "sample",
                        str(proc.pid),
                        str(args.sample_seconds),
                        "-file",
                        str(workdir / "sample.txt"),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                result["sample_started_at_size"] = size
            time.sleep(0.25)
            size = rpc.call("getmempoolinfo")["size"]
            now = time.monotonic()
            timeline.append((round(now - t0, 3), size))
            if size != last_size:
                last_size, last_change = size, now
            if size >= expected:
                break
            if now - last_change > args.stall_seconds:
                break
            if now - t0 > args.timeout:
                break
        t_end = time.monotonic()
        cpu1 = cpu_seconds(proc.pid)
        if args.mode == "rpc":
            for p in procs:
                p.join(timeout=60)
        stop_ev.set()
        for p in procs:
            p.join(timeout=60)
        time.sleep(1.0)  # let trailing notifications arrive
        zmq_stop.set()
        zp.join(timeout=30)
        metrics = ac.scrape_metrics(ports["rpc"])
        if sampler:
            sampler.wait(timeout=args.sample_seconds + 60)
        final_ids = set(rpc.call("getrawmempool"))
        final_size = len(final_ids)
    finally:
        stop_ev.set()
        zmq_stop.set()
        for p in procs + ([zp] if zp is not None else []):
            if p.is_alive():
                p.terminate()
            p.join(timeout=5)
        if sampler and sampler.poll() is None:
            sampler.terminate()
            sampler.wait(timeout=5)
        ac.stop_node(proc, rpc)

    zmq = json.loads((workdir / "zmq.json").read_text())
    adds = zmq["adds"]
    lat = []
    rpc_lat = []
    sent = 0
    sent_ids = set()
    negative_latencies = 0
    errors = 0
    rejected = {}
    for i in range(args.peers):
        s = json.loads((workdir / f"sender-{i}.json").read_text())
        errors += s["errors"]
        for reason, n in s["rejected"].items():
            rejected[reason] = rejected.get(reason, 0) + n
        for item in s["sends"]:
            sent += 1
            txid, t_send = item[0], item[1]
            sent_ids.add(txid)
            t_add = adds.get(txid)
            if t_add is None:
                t_add = adds.get(bytes.fromhex(txid)[::-1].hex())
            if t_add is not None:
                if t_add < t_send:
                    negative_latencies += 1
                else:
                    lat.append(t_add - t_send)
            if len(item) > 2:
                rpc_lat.append(item[2] - t_send)
    add_times = sorted(t - t0 for t in adds.values())
    accepted = len(add_times)
    result.update(
        {
            "sent": sent,
            "accepted_mempool": final_size,
            "accepted_zmq": accepted,
            "rpc_errors": errors,
            "rpc_rejects": rejected,
            "complete": (
                final_ids == expected_ids
                and sent_ids == expected_ids
                and sent == expected
                and accepted == expected
                and len(lat) == expected
                and errors == 0
                and metrics.get("fullnode_mempool_admission_dropped_total", 0) == 0
                and zmq["removes"] == 0
                and zmq["duplicate_adds"] == 0
                and zmq["sequence_gaps"] == 0
                and all(p.exitcode == 0 for p in procs)
                and zp.exitcode == 0
            ),
            "missing_mempool": len(expected_ids - final_ids),
            "unexpected_mempool": len(final_ids - expected_ids),
            "missing_notifications": expected - len(lat),
            "negative_latency_samples": negative_latencies,
            "zmq_removes": zmq["removes"],
            "zmq_duplicate_adds": zmq["duplicate_adds"],
            "zmq_sequence_gaps": zmq["sequence_gaps"],
            "sender_exitcodes": [p.exitcode for p in procs],
            "elapsed_s": round(t_end - t0, 3),
            "node_cpu_s": round(cpu1 - cpu0, 2)
            if cpu0 is not None and cpu1 is not None
            else None,
            "loadavg_end": list(os.getloadavg()),
        }
    )
    if accepted:
        t_last = add_times[-1]
        result["tps_total"] = round(accepted / t_last, 1) if t_last > 0 else None
        lo = add_times[int(accepted * 0.1)]
        hi = add_times[min(accepted - 1, int(accepted * 0.9))]
        if hi > lo:
            result["tps_10_90"] = round(
                (int(accepted * 0.9) - int(accepted * 0.1)) / (hi - lo), 1
            )
        result["first_add_s"] = round(add_times[0], 4)
        result["last_add_s"] = round(t_last, 4)
    result["latency"] = summarize_latency(lat)
    if rpc_lat:
        result["rpc_roundtrip"] = summarize_latency(rpc_lat)
    result["metrics_complete"] = (
        bool(metrics) and metrics.get("fullnode_metrics_dropped_samples_total", 0) == 0
    )
    result["metrics"] = {
        k: v
        for k, v in metrics.items()
        if "mempool_admission" in k
        or k.startswith("fullnode_mempool")
        or k == "fullnode_metrics_dropped_samples_total"
    }
    result["timeline"] = timeline[:: max(1, len(timeline) // 200)]
    if not args.keep_datadir:
        import shutil

        shutil.rmtree(datadir, ignore_errors=True)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bitcoind", required=True, type=Path)
    ap.add_argument("--fixture", required=True, type=Path)
    ap.add_argument("--workdir", required=True, type=Path)
    ap.add_argument("--peers", type=int, default=8)
    ap.add_argument("--mode", choices=("p2p", "rpc"), default="p2p")
    ap.add_argument(
        "--rate",
        type=float,
        default=0.0,
        help="total offered tx/s (0: send as fast as accepted)",
    )
    ap.add_argument("--node-arg", action="append", default=[])
    ap.add_argument("--portseed", type=int, default=611)
    ap.add_argument("--libzmq")
    ap.add_argument("--label", default="")
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--stall-seconds", type=float, default=20)
    ap.add_argument("--unit-limit", type=int, default=None)
    ap.add_argument(
        "--sample-seconds",
        type=int,
        default=0,
        help="macOS: run `sample` on the node for N seconds",
    )
    ap.add_argument(
        "--sample-at-size",
        type=int,
        default=0,
        help="start sampling once the mempool holds N transactions",
    )
    ap.add_argument(
        "--no-relay",
        action="store_true",
        help="P2P senders ask not to be sent transactions (version relay=0), "
        "so the node announces nothing: admission without relay work",
    )
    ap.add_argument("--keep-datadir", action="store_true")
    ap.add_argument("--result", type=Path)
    args = ap.parse_args()
    result = run(args)
    text = json.dumps(result, indent=1)
    if args.result:
        args.result.write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
