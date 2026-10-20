#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Unprivileged bounded UDP-flow relay, preserving payloads in RAW-IP PCAP.

The PCAP uses synthesized IPv4/UDP headers and a normalized client/server
5-tuple. Datagrams and receive timestamps are observed; this is not a kernel
capture of NIC packet timing, offload segments or original network headers.
"""

import argparse
import hashlib
import json
import selectors
import signal
import socket
import struct
import time
from contextlib import ExitStack
from pathlib import Path


def address(text):
    host, port = text.rsplit(":", 1)
    socket.inet_aton(host)
    port = int(port)
    if not 0 < port < 65536:
        raise ValueError("invalid UDP port")
    return host, port


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return ~value & 65535


def packet(payload, source, target):
    total = 28 + len(payload)
    if total > 65535:
        raise ValueError("datagram too large for IPv4 PCAP")
    src, dst = socket.inet_aton(source[0]), socket.inet_aton(target[0])
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    udp = struct.pack("!HHHH", source[1], target[1], len(payload) + 8, 0)
    # A zero IPv4 UDP checksum is valid; payload is never rewritten.
    return ip + udp + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True, type=address)
    parser.add_argument("--server", required=True, type=address)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--max-clients", type=int, default=16)
    args = parser.parse_args()
    if args.seconds <= 0 or not 1 <= args.max_clients <= 64:
        parser.error("positive --seconds and --max-clients in 1..64 required")
    stop = False

    def interrupt(_signal, _frame):
        nonlocal stop
        stop = True

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as front,
        ExitStack() as sockets,
        selectors.DefaultSelector() as selector,
        args.pcap.open("xb") as pcap,
        args.metadata.open("x") as metadata,
    ):
        front.bind(args.listen)
        selector.register(front, selectors.EVENT_READ, None)
        clients = {}
        pcap.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        metadata.write(
            json.dumps(
                {
                    "type": "capture",
                    "listen": args.listen,
                    "server": args.server,
                    "synthetic_headers": True,
                    "max_clients": args.max_clients,
                    "utc_start_ns": time.time_ns(),
                }
            )
            + "\n"
        )
        deadline = time.monotonic() + args.seconds
        while not stop and time.monotonic() < deadline:
            for key, _ in selector.select(
                min(0.1, max(0, deadline - time.monotonic()))
            ):
                payload, peer = key.fileobj.recvfrom(65535)
                now = time.time_ns()
                if key.data is None:
                    direction = "client"
                    if peer not in clients:
                        if len(clients) >= args.max_clients:
                            metadata.write(
                                json.dumps(
                                    {
                                        "type": "flow_cap_drop",
                                        "peer": peer,
                                        "time_ns": now,
                                        "payload_bytes": len(payload),
                                    }
                                )
                                + "\n"
                            )
                            continue
                        back = sockets.enter_context(
                            socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        )
                        back.connect(args.server)
                        clients[peer] = back
                        selector.register(back, selectors.EVENT_READ, peer)
                    source, target = peer, args.server
                    clients[peer].send(payload)
                else:
                    direction = "server"
                    source, target = args.server, key.data
                    front.sendto(payload, key.data)
                raw = packet(payload, source, target)
                pcap.write(
                    struct.pack(
                        "<IIII", now // 10**9, (now % 10**9) // 1000, len(raw), len(raw)
                    )
                )
                pcap.write(raw)
                metadata.write(
                    json.dumps(
                        {
                            "type": "datagram",
                            "direction": direction,
                            "source": source,
                            "target": target,
                            "time_ns": now,
                            "payload_bytes": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                        }
                    )
                    + "\n"
                )
        pcap.flush()
        metadata.flush()


if __name__ == "__main__":
    main()
