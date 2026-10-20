# Mempool admission benchmark

Measures how fast a node admits a flood of **really signed** transactions
arriving from several P2P peers (or from RPC clients), and how long each
transaction takes from leaving the sender to entering the mempool.

Script verification is a large part of admission cost, so the transactions
are ordinary P2PKH spends with real signatures:

| kind | share | inputs | signatures |
|---|---|---|---|
| `ecdsa1` | 35% | 1 | DER ECDSA |
| `schnorr1` | 35% | 1 | 64-byte Schnorr |
| `multi` | 15% | 2-5 | mixed ECDSA/Schnorr |
| `chain` | 15% | 1 each | mixed; chains of 2-8 dependent transactions |

(`--mix` changes the shares.) A chain always goes to one sender, in order, so
children arrive after their parents from the same peer, as from a wallet.

## Files

- `make_fixture.py` starts an isolated regtest node, mines and fans out
  confirmed P2PKH outputs, stops the node, and signs the flood in worker
  processes. The stopped datadir plus `flood.jsonl` and `manifest.json` is
  the fixture.
- `flood.py` runs one flood against a fresh clone (APFS `cp -c` on macOS) of
  the fixture datadir and prints a JSON result.
- `ab.py` runs configurations interleaved over several rounds and prints a
  table of medians with min-max spread.
- `sample_summary.py` summarizes a macOS `sample` profile of one node thread
  (`flood.py --sample-seconds N [--sample-at-size M]` records one).
- `admission_common.py` holds the shared node/RPC/P2P/ZMQ helpers.

Only the Python standard library and `test/functional/test_framework` are
used. The ZMQ subscriber uses `libzmq` through `ctypes` (no pyzmq); pass
`--libzmq PATH` if it is not in a standard location.

## How it measures

- Each sender is its own process. P2P senders complete version/verack, then
  write `tx` messages as fast as the node reads them (`--rate 0`, a flood) or
  at a fixed total rate (`--rate N` tx/s). Received messages are drained and
  discarded. RPC senders call `sendrawtransaction` on persistent connections.
- A ZMQ `sequence` subscriber timestamps every mempool addition. Latency is
  the time from a sender starting the socket write (P2P) or issuing
  the RPC, to its mempool-add notification, on the host's monotonic clock.
  In flood mode latency is dominated by queueing in socket buffers; use
  `--rate` below capacity for service latency.
- Throughput `tps_10_90` is accepted transactions per second between the 10%
  and 90% points of the acceptance timeline (ramp-up and tail excluded);
  `tps_total` is accepted / time of last acceptance.
- `node_cpu_s` is process CPU time (`ps`) until mempool completion/stall.
  Relay work still pending after that point is outside this interval; it is
  not a measurement of total CPU cost to finish propagating the flood.
- The node runs with `-checkmempool=0 -checkblockindex=0` (regtest otherwise
  runs a full mempool consistency check on every admission, which is
  quadratic and not what a production node does), `-whitelist=noban@127.0.0.1`,
  `-persistmempool=0` and `-metrics=1`; the `fullnode_mempool*` metrics are
  scraped at the end of the run.
- Ports are `47000 + 4 * portseed` onwards (outside 20000-34999).

## How to reproduce

Build (any build directory; the scripts take binaries as arguments):

    cmake -GNinja -S . -B build -DCMAKE_BUILD_TYPE=Release
    ninja -C build bitcoind bitcoin-bench

Create a fixture once (about 3 minutes of signing on 8 processes for 200k
transactions):

    contrib/bench/mempool-admission/make_fixture.py \
        --bitcoind build/src/bitcoind --out /path/to/fx-200k --txs 200000

One run:

    contrib/bench/mempool-admission/flood.py --bitcoind build/src/bitcoind \
        --fixture /path/to/fx-200k --workdir /path/to/run --peers 8

prints JSON such as

    {"mode": "p2p", "peers": 8, "accepted_zmq": 200000, "complete": true,
     "tps_10_90": 3648.3, "latency": {"p50_ms": ..., "p99_ms": ...},
     "node_cpu_s": 26.9, "metrics": {...}, ...}

Interleaved A/B (5 rounds):

    contrib/bench/mempool-admission/ab.py \
        --bitcoind old=/old/build/src/bitcoind --bitcoind new=build/src/bitcoind \
        --config old=old --config new=new \
        --fixture /path/to/fx-200k --workdir /path/to/ab --rounds 5 --peers 8

prints a Markdown table (also written to `SUMMARY.md`):

    | config | runs | complete | accepted tx/s (10-90%) | ... |
    | old | 5 | 5/5 | 3650 (3401-3812) | ... |

Profile the message handler late in a flood:

    flood.py ... --sample-seconds 10 --sample-at-size 150000
    sample_summary.py /path/to/run/sample.txt --thread b-msghand

In-process microbenchmark (no networking or relay):

    build/src/bench/bitcoin-bench -filter='MempoolAdmission.*'

## Limits

- Regtest on loopback, one host: no WAN latency, no real peer mix.
- The flood peers never request anything; relay work is the node announcing
  accepted transactions to the other flood peers.
- On a shared host other processes compete for cores; record the load
  average (`loadavg_start` is in every result) and rerun on a quiet machine
  before drawing small-difference conclusions.

A run is complete only when every fixture transaction was sent exactly once,
its mempool-add notification was observed, and the final mempool contains
exactly the fixture set, with no RPC rejects, removals or failed sender
processes. Incomplete runs remain in attempt/completion counts and are excluded
from performance statistics. Inspect every incomplete run before comparing
configurations. The runner pins binary and fixture SHA256 plus run settings;
resuming with changed inputs requires a new work directory.

Verify reporting with:

    python3 contrib/bench/mempool-admission/test_accounting.py

The subscriber rejects duplicate add notifications and gaps in ZMQ's publisher
sequence. Notification delivery time includes validation-queue and subscriber
scheduling delay; it is not a timestamp taken inside the mempool commit.
Negative latency samples are reported and invalidate a run. Histogram timing
statistics are omitted when the metrics subsystem reports dropped event
samples; transaction throughput remains independently checked against ZMQ and
the exact final mempool set. Host filesystem/page caches are not flushed
between fresh datadir clones.
