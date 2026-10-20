#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Measure the one-hop announcement delay of a node.

One node, a P2P sender and a P2P observer (both inbound). The sender gives
the node --txs transactions one at a time; the observer times the
announcement (inv or invshort) of each. Prints one JSON object with the
delays in milliseconds (median, p90, max, mean): end to end as the Python
peers see it (*_ms, includes the test framework's own delays), and inside
the node from its debug log (node_*_ms: from accepting the transaction to
queueing the announcement to the observer).

Example (from the source tree, after building into ./build):
  contrib/bench/tx-relay/relay_onehop.py --build-dir build --txs 150
"""

import argparse
import configparser
import json
import os
import statistics
import sys
import threading
import time


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--build-dir", required=True, help="build dir (test/config.ini)")
    ap.add_argument("--bitcoind", help="node binary (default: the build dir's)")
    ap.add_argument("--txs", type=int, default=100)
    ap.add_argument("--extra-args", default="", help="node args")
    ap.add_argument("--portseed", type=int, default=os.getpid() % 1000)
    ap.add_argument("--json", help="also write the result here")
    args = ap.parse_args()

    build = os.path.abspath(args.build_dir)
    config = configparser.ConfigParser()
    config.read(os.path.join(build, "test", "config.ini"))
    srcdir = config["environment"]["SRCDIR"]
    sys.path.insert(0, os.path.join(srcdir, "test", "functional"))
    os.environ.setdefault("SRCDIR", srcdir)
    if args.bitcoind:
        os.environ["BITCOIND"] = os.path.abspath(args.bitcoind)

    from test_framework.messages import msg_tx
    from test_framework.p2p import P2PInterface
    from test_framework.test_framework import BitcoinTestFramework
    from test_framework.wallet import MiniWallet

    class Observer(P2PInterface):
        def __init__(self):
            super().__init__()
            self.seen = []
            self.lock = threading.Lock()

        def on_inv(self, message):
            now = time.monotonic()
            with self.lock:
                self.seen += [now for inv in message.inv if inv.type == 1]

        def on_invshort(self, message):
            now = time.monotonic()
            with self.lock:
                self.seen += [now] * len(message.short_ids)

    result = {}

    def node_side_delays(node, txids):
        """From each accept to the next inv/invshort sent to peer=1"""
        import re
        from datetime import datetime

        stamp = re.compile(r"^(\S+)Z ")
        accepted = {}
        sends = []
        path = os.path.join(node.datadir, "regtest", "debug.log")
        with open(path, encoding="utf8", errors="replace") as f:
            for line in f:
                m = stamp.match(line)
                if not m:
                    continue
                if "AcceptToMemoryPool: peer=" in line:
                    for t in txids:
                        if t in line:
                            accepted[t] = m.group(1)
                elif re.search(r"sending (inv|invshort) \(\d+ bytes\) peer=1\b", line):
                    sends.append(m.group(1))

        def ts(x):
            return datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%f").timestamp()

        out = []
        send_times = [ts(x) for x in sends]
        for t in txids:
            if t not in accepted:
                continue
            a = ts(accepted[t])
            later = [x for x in send_times if x >= a]
            if later:
                out.append((later[0] - a) * 1000)
        return out

    class OneHop(BitcoinTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.extra_args = [args.extra_args.split()]

        def run_test(self):
            node = self.nodes[0]
            wallet = MiniWallet(node)
            wallet.rescan_utxos()
            sender = node.add_p2p_connection(P2PInterface())
            obs = node.add_p2p_connection(Observer())
            delays = []
            txids = []
            for _ in range(args.txs):
                tx = wallet.create_self_transfer()["tx"]
                before = len(obs.seen)
                t0 = time.monotonic()
                sender.send_without_ping(msg_tx(tx))
                obs.wait_until(lambda: len(obs.seen) > before, timeout=60)
                delays.append((obs.seen[before] - t0) * 1000)
                txids.append(tx.txid_hex)
                wallet.scan_tx(node.decoderawtransaction(tx.serialize().hex()))
            delays.sort()
            node_delays = sorted(node_side_delays(node, txids))
            result.update(
                node_median_ms=statistics.median(node_delays) if node_delays else None,
                node_p90_ms=(
                    node_delays[int(0.9 * (len(node_delays) - 1))]
                    if node_delays
                    else None
                ),
                node_max_ms=node_delays[-1] if node_delays else None,
                txs=len(delays),
                median_ms=statistics.median(delays),
                p90_ms=delays[int(0.9 * (len(delays) - 1))],
                max_ms=delays[-1],
                mean_ms=statistics.mean(delays),
                load_average=os.getloadavg(),
            )

    sys.argv = [
        sys.argv[0],
        f"--configfile={os.path.join(build, 'test', 'config.ini')}",
        f"--portseed={args.portseed}",
    ]
    OneHop().main(exit_process=False)
    out = json.dumps(result, sort_keys=True)
    print(out)
    if args.json:
        with open(args.json, "w", encoding="utf8") as f:
            f.write(out + "\n")
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(main())
