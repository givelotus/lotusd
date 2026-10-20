#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded single-client loopback UDP impairment relay, requiring no privileges.

Ported from the original WebTransport prototype's proto/udp_proxy.py. Loss is
independent per datagram and direction. Delay is one-way; rates are per direction
and include 28 bytes of IPv4/UDP overhead. This is a userspace model, not netem or
a model of TCP loss. Pending packets (including propagation delay) are bounded.
"""

import argparse
import heapq
import ipaddress
import json
import math
import random
import select
import signal
import socket
import sys
import time
from collections import deque


def parse_addr(value):
    host, port = value.rsplit(":", 1)
    if not ipaddress.ip_address(host).is_loopback or not 0 < int(port) < 65536:
        raise ValueError(
            "relay endpoints must be numeric IPv4 loopback addresses and valid ports"
        )
    if ipaddress.ip_address(host).version != 4:
        raise ValueError("the impairment model currently accounts for IPv4 only")
    return host, int(port)


MAX_PENDING_BYTES = 16 << 20


class Direction:
    def __init__(self, name, rate_bps, queue_pkts, delay_s, loss, rng):
        if (
            not all(math.isfinite(v) for v in (rate_bps, delay_s, loss))
            or rate_bps < 0
            or queue_pkts < 1
            or delay_s < 0
            or not 0 <= loss <= 1
        ):
            raise ValueError("invalid impairment settings")
        self.name, self.rate_bps, self.queue_pkts = name, rate_bps, queue_pkts
        self.delay_s, self.loss, self.rng = delay_s, loss, rng
        self.next_free = 0.0
        self.departures = deque()
        self.pending = 0
        self.pending_bytes = 0
        self.stats = {
            "pkts": 0,
            "bytes": 0,
            "lost": 0,
            "dropped_queue": 0,
            "forwarded": 0,
            "send_errors": 0,
            "peak_pending": 0,
            "peak_pending_bytes": 0,
        }

    def schedule(self, now, data, heap, sequence, destination):
        self.stats["pkts"] += 1
        self.stats["bytes"] += len(data)
        if self.rng.random() < self.loss:
            self.stats["lost"] += 1
            return
        while self.departures and self.departures[0] <= now:
            self.departures.popleft()
        # Bound both bottleneck occupancy and all retained payload copies. The
        # latter also applies to an unlimited-rate link with a large delay.
        if (
            self.pending >= self.queue_pkts
            or len(self.departures) >= self.queue_pkts
            or self.pending_bytes + len(data) > MAX_PENDING_BYTES
        ):
            self.stats["dropped_queue"] += 1
            return
        departure = now
        if self.rate_bps:
            departure = max(now, self.next_free) + (len(data) + 28) * 8 / self.rate_bps
            self.next_free = departure
            self.departures.append(departure)
        self.pending += 1
        self.pending_bytes += len(data)
        self.stats["peak_pending_bytes"] = max(
            self.stats["peak_pending_bytes"], self.pending_bytes
        )
        self.stats["peak_pending"] = max(self.stats["peak_pending"], self.pending)
        heapq.heappush(
            heap, (departure + self.delay_s, sequence, self.name, data, destination)
        )

    def sent(self, data, success):
        self.pending -= 1
        self.pending_bytes -= len(data)
        self.stats["forwarded" if success else "send_errors"] += 1


def run(args):
    listen, server = parse_addr(args.listen), parse_addr(args.server)
    directions = {
        name: Direction(
            name,
            args.rate_mbps * 1e6,
            args.queue_pkts,
            args.delay_ms / 1000,
            args.loss,
            random.Random(args.seed + index),
        )
        for index, name in enumerate(("c2s", "s2c"))
    }
    running = True

    def stop(*_):
        nonlocal running
        running = False

    old_handlers = {
        sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)
    }
    heap, sequence, client = [], 0, None
    started = time.monotonic()
    ignored_clients = 0
    try:
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as front,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as back,
        ):
            front.bind(listen)
            back.bind(("127.0.0.1", 0))
            back.connect(server)  # Accept replies from the configured server only.
            for sock in (front, back):
                sock.setblocking(False)
            print(
                json.dumps({"proxy": "ready", "listen": args.listen}),
                file=sys.stderr,
                flush=True,
            )
            while running and (
                not args.duration or time.monotonic() - started < args.duration
            ):
                now = time.monotonic()
                while heap and heap[0][0] <= now:
                    _, _, name, data, destination = heapq.heappop(heap)
                    try:
                        sent = (
                            back.send(data)
                            if name == "c2s"
                            else front.sendto(data, destination)
                        )
                        success = sent == len(data)
                    except OSError:
                        success = False
                    directions[name].sent(data, success)
                timeout = min(0.1, max(0, heap[0][0] - now)) if heap else 0.1
                try:
                    ready, _, _ = select.select([front, back], [], [], timeout)
                except InterruptedError:
                    continue
                for sock in ready:
                    for _ in range(256):
                        try:
                            data, source = sock.recvfrom(65535)
                        except (BlockingIOError, ConnectionRefusedError):
                            break
                        if sock is front:
                            if client is None:
                                client = source
                            if source != client:
                                ignored_clients += 1
                                continue
                            name, destination = "c2s", server
                        else:
                            if client is None:
                                continue
                            name, destination = "s2c", client
                        sequence += 1
                        directions[name].schedule(
                            time.monotonic(), data, heap, sequence, destination
                        )
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
        result = {
            name: dict(
                direction.stats,
                pending_at_stop=direction.pending,
                pending_bytes_at_stop=direction.pending_bytes,
            )
            for name, direction in directions.items()
        }
        result.update(
            loss=args.loss,
            delay_ms=args.delay_ms,
            rate_mbps=args.rate_mbps,
            queue_pkts=args.queue_pkts,
            seed=args.seed,
            ignored_clients=ignored_clients,
            seconds=time.monotonic() - started,
        )
        encoded = json.dumps(result, sort_keys=True) + "\n"
        if args.stats:
            with open(args.stats, "x", encoding="utf8") as output:
                output.write(encoded)
        print(encoded, file=sys.stderr, flush=True, end="")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--loss", type=float, default=0)
    parser.add_argument("--delay-ms", type=float, default=0)
    parser.add_argument("--rate-mbps", type=float, default=0)
    parser.add_argument("--queue-pkts", type=int, default=4096)
    parser.add_argument("--duration", type=float, default=0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--stats")
    args = parser.parse_args()
    if not math.isfinite(args.duration) or args.duration < 0 or args.queue_pkts > 65536:
        parser.error("duration must be nonnegative and queue-pkts at most 65536")
    run(args)


if __name__ == "__main__":
    main()
