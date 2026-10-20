#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Measure transaction propagation on a local regtest cluster.

Starts --nodes nodes in a random graph (each makes --outbound connections),
optionally through a proxy that delays every byte by a per-link one-way
latency, funds a wallet, submits --txs transactions at --rate per second to
random nodes over RPC (sendrawtransaction), waits until every node has every
transaction, and prints one JSON object:

- time from submission until 50/90/99/100% of the nodes accepted each
  transaction (median and worst over transactions; from the nodes' debug
  logs, microsecond timestamps, one machine so one clock);
- bytes sent per node per transaction, by kind: announcements (inv,
  invshort), requests (getdata, getshorttx, notfound), bodies (tx, shorttx),
  reconciliation (merklixsync, getmerklixbuck, merklixbuck), other;
- duplicate bodies (bodies received for a transaction the node already had);
- node CPU seconds per transaction (all bitcoind processes).

It works with any build of the node, old relay or new: new options go in
--extra-args. Nodes started with --silent-args (a fraction --silent of
them) stand for peers that do not relay.

Example (from the source tree, after building into ./build):
  contrib/bench/tx-relay/relay_cluster.py --build-dir build --nodes 24 \
      --outbound 8 --txs 300 --rate 20 --latency 10-80
"""

import argparse
import asyncio
import configparser
import json
import os
import random
import re
import statistics
import subprocess
import sys
import threading
import time

# Small regtest quorum: every node stakes a coinbase, no minimum stake
AVALANCHE_ARGS = [
    "-avacooldown=0",
    "-avaproofstakeutxoconfirmations=1",
    "-avaproofstakeutxodustthreshold=1000000",
    "-avaminquorumstake=0",
    "-avaminquorumconnectedstakeratio=0",
    "-avaminavaproofsnodecount=0",
    "-avalanchestakingpreconsensus=0",
    "-persistavapeers=0",
]

KINDS = {
    "announce": ("inv", "invshort"),
    "request": ("getdata", "getshorttx", "notfound"),
    "body": ("tx", "shorttx"),
    "recon": ("merklixsync", "getmerklixbuck", "merklixbuck"),
}


class DelayProxy:
    """TCP proxies that delay each direction of a link by a fixed latency"""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.tasks = set()
        self.servers = []
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def add(self, target_port, delay):
        """A listening port forwarding to target_port, delay seconds each way"""
        fut = asyncio.run_coroutine_threadsafe(
            self._listen(target_port, delay), self.loop
        )
        return fut.result(timeout=10)

    async def _listen(self, target_port, delay):
        async def handle(reader, writer):
            try:
                treader, twriter = await asyncio.open_connection(
                    "127.0.0.1", target_port
                )
            except OSError:
                writer.close()
                return
            # Keep references: the loop holds tasks only weakly.
            for pipe in (
                self._pipe(reader, twriter, delay),
                self._pipe(treader, writer, delay),
            ):
                task = asyncio.ensure_future(pipe)
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def _pipe(self, reader, writer, delay):
        # Deliveries are timer callbacks: with one delay per direction the
        # due times only grow, so bytes keep their order.
        def write(data):
            if not writer.is_closing():
                writer.write(data)

        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                self.loop.call_at(self.loop.time() + delay, write, data)
        except (ConnectionError, OSError):
            pass
        self.loop.call_at(self.loop.time() + delay, writer.close)


def cpu_seconds(pid):
    out = subprocess.run(
        ["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True
    ).stdout.strip()
    if not out:
        return 0.0
    days = 0
    if "-" in out:
        d, out = out.split("-", 1)
        days = int(d)
    parts = [float(p) for p in out.split(":")]
    secs = 0.0
    for p in parts:
        secs = secs * 60 + p
    return days * 86400 + secs


ACCEPT = re.compile(
    r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z .*AcceptToMemoryPool: "
    r"peer=\d+: accepted ([0-9a-f]{64})"
)
RECV_TX = re.compile(r"received: tx \(\d+ bytes\) peer=")
FINAL = re.compile(
    r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z .*Avalanche finalized tx "
    r"([0-9a-f]{64})"
)


def log_times(path):
    """{txid: unix time accepted from a peer} and tx messages received"""
    from datetime import datetime, timezone

    accepted = {}
    finalized = {}
    tx_msgs = 0
    with open(path, encoding="utf8", errors="replace") as f:
        for line in f:
            for regex, out in ((ACCEPT, accepted), (FINAL, finalized)):
                m = regex.match(line)
                if m:
                    t = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f")
                    out.setdefault(
                        m.group(2), t.replace(tzinfo=timezone.utc).timestamp()
                    )
                    break
            else:
                if RECV_TX.search(line):
                    tx_msgs += 1
    return accepted, tx_msgs, finalized


def pct(sorted_values, f):
    """The value at fraction f of a sorted list (nearest rank)"""
    import math

    rank = math.ceil(f * len(sorted_values) - 1e-9)
    return sorted_values[min(len(sorted_values) - 1, max(0, rank - 1))]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--build-dir", required=True, help="build dir (test/config.ini)")
    ap.add_argument("--bitcoind", help="node binary (default: the build dir's)")
    ap.add_argument("--nodes", type=int, default=24)
    ap.add_argument("--outbound", type=int, default=8)
    ap.add_argument("--txs", type=int, default=300)
    ap.add_argument("--rate", type=float, default=20.0, help="transactions/s")
    ap.add_argument("--latency", default="0", help="one-way ms, N or MIN-MAX")
    ap.add_argument("--silent", type=float, default=0.0)
    ap.add_argument("--silent-args", default="", help="args of silent nodes")
    ap.add_argument("--extra-args", default="", help="args of every node")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--tmpdir", help="datadir root (default: a new temp dir)")
    ap.add_argument("--portseed", type=int, default=os.getpid() % 1000)
    ap.add_argument("--json", help="also write the result here")
    ap.add_argument(
        "--avalanche",
        action="store_true",
        help="give every node a proof and also report Avalanche finalization",
    )
    args = ap.parse_args()

    build = os.path.abspath(args.build_dir)
    config = configparser.ConfigParser()
    config.read(os.path.join(build, "test", "config.ini"))
    srcdir = config["environment"]["SRCDIR"]
    sys.path.insert(0, os.path.join(srcdir, "test", "functional"))
    os.environ.setdefault("SRCDIR", srcdir)
    if args.bitcoind:
        os.environ["BITCOIND"] = os.path.abspath(args.bitcoind)

    from test_framework.test_framework import BitcoinTestFramework
    from test_framework.wallet import MiniWallet

    rng = random.Random(args.seed)
    lo, _, hi = args.latency.partition("-")
    lat_lo, lat_hi = float(lo) / 1000, float(hi or lo) / 1000
    result = {}

    class Cluster(BitcoinTestFramework):
        def set_test_params(self):
            self.num_nodes = args.nodes
            self.setup_clean_chain = False
            n_silent = int(round(args.silent * args.nodes))
            self.silent = set(rng.sample(range(1, args.nodes), n_silent))
            self.extra_args = [
                args.extra_args.split()
                + ["-maxconnections=200", "-metrics"]
                + (AVALANCHE_ARGS if args.avalanche else [])
                + (args.silent_args.split() if i in self.silent else [])
                for i in range(args.nodes)
            ]

        def setup_network(self):
            self.setup_nodes()
            proxy = DelayProxy() if lat_hi > 0 else None
            edges = set()
            for a in range(self.num_nodes):
                targets = [b for b in range(self.num_nodes) if b != a]
                rng.shuffle(targets)
                for b in targets[: args.outbound]:
                    if (a, b) in edges or (b, a) in edges:
                        continue
                    edges.add((a, b))
            self.edges = sorted(edges)
            self.link_ports = {}
            for a, b in self.edges:
                port = self.nodes[b].p2p_port
                if proxy:
                    port = proxy.add(port, rng.uniform(lat_lo, lat_hi))
                self.link_ports[(a, b)] = port
            self.connect_graph()
            if args.avalanche:
                self.start_avalanche()

        def connect_graph(self):
            for (a, b), port in self.link_ports.items():
                self.nodes[a].addnode(f"127.0.0.1:{port}", "onetry")
            want = 2 * len(self.edges)
            try:
                self.wait_until(
                    lambda: sum(len(n.getpeerinfo()) for n in self.nodes) >= want,
                    timeout=60,
                )
            except AssertionError:
                # A onetry connection can fail (loaded machine); go on with
                # what connected if that is nearly all, and report it.
                have = sum(len(n.getpeerinfo()) for n in self.nodes)
                self.log.warning(f"{have} of {want} peer connections up")
                if have < 0.95 * want:
                    raise
            self.sync_blocks(timeout=120)

        def start_avalanche(self):
            """Give every node a proof, restart them with it, reconnect"""
            from test_framework.avatools import gen_proof
            from test_framework.wallet_util import bytes_to_wif

            proofs = [gen_proof(self, self.nodes[0]) for _ in self.nodes]
            self.sync_blocks(timeout=120)
            for i, (privkey, proof) in enumerate(proofs):
                self.restart_node(
                    i,
                    self.extra_args[i]
                    + [
                        f"-avaproof={proof.serialize().hex()}",
                        f"-avamasterkey={bytes_to_wif(privkey.get_bytes())}",
                    ],
                )
            self.connect_graph()
            # Local proofs are verified at the next block.
            self.generate(
                self.nodes[0], 1, sync_fun=lambda: self.sync_blocks(timeout=120)
            )
            try:
                self.wait_until(
                    lambda: all(
                        n.getavalancheinfo()["ready_to_poll"] for n in self.nodes
                    ),
                    timeout=180,
                )
            except AssertionError:
                self.log.error(f"avalanche: {self.nodes[0].getavalancheinfo()}")
                raise

        def run_test(self):
            nodes = self.nodes
            wallet = MiniWallet(nodes[0])
            wallet.rescan_utxos()
            left = args.txs
            while left > 0:
                n = min(left, 500)
                wallet.send_self_transfer_multi(from_node=nodes[0], num_outputs=n)
                left -= n
            self.generate(nodes[0], 1, sync_fun=lambda: self.sync_blocks(timeout=120))
            wallet.rescan_utxos()
            txs = [
                wallet.create_self_transfer(confirmed_only=True)["tx"]
                for _ in range(args.txs)
            ]

            def snapshot():
                bytes_by_kind = dict.fromkeys(list(KINDS) + ["other"], 0)
                by_msg = {}
                for n in nodes:
                    for p in n.getpeerinfo():
                        for msg, b in p["bytessent_per_msg"].items():
                            by_msg[msg] = by_msg.get(msg, 0) + b
                            kind = next(
                                (k for k, v in KINDS.items() if msg in v), "other"
                            )
                            bytes_by_kind[kind] += b
                cpu = sum(cpu_seconds(n.process.pid) for n in nodes)
                return bytes_by_kind, cpu, by_msg

            def metric(name):
                total = 0.0
                found = False
                for i in range(len(nodes)):
                    try:
                        import http.client

                        from test_framework.util import rpc_port

                        conn = http.client.HTTPConnection(
                            "127.0.0.1", rpc_port(i), timeout=10
                        )
                        conn.request("GET", "/metrics")
                        res = conn.getresponse()
                        body = res.read().decode()
                        if res.status != 200:
                            return None
                    except OSError:
                        return None
                    for line in body.splitlines():
                        if line.startswith(name + " ") or line.startswith(name + "{"):
                            total += float(line.rsplit(" ", 1)[1])
                            found = True
                return total if found else None

            bytes0, cpu0, msg0 = snapshot()
            body_recv0 = metric("fullnode_txrelay_body_recv_total")
            body_dup0 = metric("fullnode_txrelay_body_dup_total")
            submit = {}
            origin = {}
            t_start = time.time()
            for i, tx in enumerate(txs):
                due = t_start + i / args.rate
                wait = due - time.time()
                if wait > 0:
                    time.sleep(wait)
                k = rng.randrange(len(nodes))
                submit[tx.txid_hex] = time.time()
                origin[tx.txid_hex] = k
                nodes[k].sendrawtransaction(tx.serialize().hex())
            want = set(submit)

            def done():
                return all(
                    want <= set(n.getrawmempool())
                    for i, n in enumerate(nodes)
                    if i not in self.silent
                )

            complete = True
            try:
                self.wait_until(done, timeout=args.timeout)
            except AssertionError:
                complete = False
            t_end = time.time()
            finalized_all = None
            if args.avalanche:
                finalized_all = True
                try:
                    self.wait_until(
                        lambda: all(
                            n.getmempoolinfo()["finalized_txs_size"] >= len(want)
                            for i, n in enumerate(nodes)
                            if i not in self.silent
                        ),
                        timeout=args.timeout,
                    )
                except AssertionError:
                    finalized_all = False
            time.sleep(1.2)  # metrics endpoint caches scrapes for 1 s
            bytes1, cpu1, msg1 = snapshot()
            body_recv1 = metric("fullnode_txrelay_body_recv_total")
            body_dup1 = metric("fullnode_txrelay_body_dup_total")

            accept = []
            final = []
            tx_msgs = 0
            for n in nodes:
                acc, msgs, fin = log_times(
                    os.path.join(n.datadir, "regtest", "debug.log")
                )
                accept.append(acc)
                final.append(fin)
                tx_msgs += msgs
            relaying = [i for i in range(len(nodes)) if i not in self.silent]
            fin_ts = {50: [], 100: []}
            if args.avalanche:
                for txid, t0 in submit.items():
                    lat = sorted(
                        final[i][txid] - t0 if txid in final[i] else float("inf")
                        for i in relaying
                    )
                    for p in fin_ts:
                        fin_ts[p].append(pct(lat, p / 100))
            ts = {50: [], 90: [], 99: [], 100: []}
            missing = 0
            # Coverage counts the relaying nodes, as in the simulator: a
            # silent node only gets what its peers happen to pick it for.
            silent_missing = sum(
                txid not in accept[i] and i != origin[txid]
                for txid in submit
                for i in self.silent
            )
            for txid, t0 in submit.items():
                lat = []
                for i in relaying:
                    if i == origin[txid]:
                        lat.append(0.0)
                    elif txid in accept[i]:
                        lat.append(max(0.0, accept[i][txid] - t0))
                    else:
                        lat.append(float("inf"))
                        missing += 1
                lat.sort()
                for p in ts:
                    ts[p].append(pct(lat, p / 100))
            relayed = len(submit) * (len(relaying) - 1) - missing
            n_nodes = len(nodes)
            per_node_tx = {
                k: (bytes1[k] - bytes0[k]) / (n_nodes * len(submit)) for k in bytes1
            }
            sizes = [len(tx.serialize()) for tx in txs]
            result.update(
                nodes=n_nodes,
                edges=len(self.edges),
                mean_degree=sum(len(n.getpeerinfo()) for n in nodes) / n_nodes,
                silent=sorted(self.silent),
                txs=len(submit),
                rate=args.rate,
                latency_ms=args.latency,
                extra_args=args.extra_args,
                complete=complete,
                missing_node_txs=missing,
                silent_node_txs_missing=silent_missing,
                submit_seconds=t_end - t_start,
                finalization_seconds=(
                    {
                        f"t{p}": {
                            "median": statistics.median(v),
                            "worst": max(v),
                        }
                        for p, v in fin_ts.items()
                    }
                    if args.avalanche
                    else None
                ),
                finalized_all=finalized_all,
                propagation_seconds={
                    f"t{p}": {
                        "median": statistics.median(v),
                        "p90": sorted(v)[int(0.9 * (len(v) - 1))],
                        "worst": max(v),
                    }
                    for p, v in ts.items()
                },
                bytes_per_node_per_tx=per_node_tx,
                bytes_per_node_per_tx_by_msg={
                    m: (msg1[m] - msg0.get(m, 0)) / (n_nodes * len(submit))
                    for m in msg1
                    if msg1[m] != msg0.get(m, 0)
                },
                bytes_per_node_per_tx_total=sum(
                    v for k, v in per_node_tx.items() if k != "other"
                ),
                tx_size_mean=statistics.mean(sizes),
                floor_bytes=statistics.mean(sizes) + 36,
                tx_messages_received=tx_msgs,
                relayed_acceptances=relayed,
                bodies_received_metric=(
                    None if body_recv1 is None else body_recv1 - body_recv0
                ),
                duplicate_bodies_metric=(
                    None if body_dup1 is None else body_dup1 - body_dup0
                ),
                cpu_seconds_per_tx=(cpu1 - cpu0) / len(submit),
                load_average=os.getloadavg(),
            )

    framework_args = [
        f"--configfile={os.path.join(build, 'test', 'config.ini')}",
        f"--portseed={args.portseed}",
    ]
    if args.tmpdir:
        framework_args.append(f"--tmpdir={args.tmpdir}")
    sys.argv = [sys.argv[0]] + framework_args
    Cluster().main(exit_process=False)
    out = json.dumps(result, indent=1, sort_keys=True)
    print(out)
    if args.json:
        with open(args.json, "w", encoding="utf8") as f:
            f.write(out + "\n")
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(main())
