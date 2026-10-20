# WebTransport loss experiment

This tool runs **one explicitly requested case**, using two fresh regtest nodes.
`run.py --plan` prints the 24-case interleaved WT/WSS matrix without launching
anything. It does not run a sweep, change a firewall, install a queue discipline,
raise privileges, touch a running node, or change defaults. Review and separately
schedule the Linux loss/CPU/Guix/soak work before running it on a test VM.

Use a **stopped artificial regtest datadir snapshot** containing a prefix chain
and a separate raw next-block file. The intended gate uses the original Lane-2
~40-large-block fixture and a 32 MB next block with real transactions, not a
compressible padding-only substitute. This tool consumes that fixture; it does
not claim to generate or validate the full workload. Create
`wt-experiment-fixture.json` in the snapshot root with
`{"network":"regtest","stopped":true}`. Symlinks, PID files and non-regtest chain
data are rejected. Copies omit inherited configurations, peer/anchor caches,
mempool snapshots and log files. Nodes only open the new copies. The output
folder must not exist and must be outside the fixture. It retains logs and data
for review. Only processes spawned by this invocation are stopped. `--timeout` is one
shared work budget for startup, connection and transfer, including RPC socket
waits; later phases cannot restart it. Fixture copying is checked at phase
boundaries. Cleanup has a separate bounded allowance (up to five seconds per
node plus collector/relay joins); normal smoke cleanup takes a fraction of a
second. SIGINT/SIGTERM enter that owned cleanup path.

A case starts from the same prefix in both nodes, establishes the selected
transport, submits the next block on the server and waits for the client tip.
The peer's decoded `block`/`blocktxn` counters must cover at least 90% of the raw
block length; a cached body or a mempool-only compact reconstruction cannot
silently satisfy the transfer check. Message byte counters are not wire-byte or
CPU measurements. Certificate pinning authenticates WT; WSS uses its existing
peer authentication path. Both peers use the existing compression negotiation. The fixture node flags
reserve 32 connections with zero automatic Avalanche outbound slots, leaving
an actual inbound budget; manual connections can still establish Avalanche
identities/quorum. This does not disable the Avalanche processor.

The client samples **fresh** completed pings, detected from its incrementing
`pong` byte counter, rather than repeatedly sampling the last `pingtime` value.
Poll samples come from opt-in `-debug=avalanche` `poll_rtt` events for the exact
peer and transfer interval. The event is emitted only after a pending query and
its response contents match; normal callers verify signatures first. Its
steady-clock milliseconds measure query dispatch to validated processing,
including local queues and signature verification, not pure wire latency.
Only the peer ID, round and elapsed milliseconds are logged, with no secrets.
Neither ordinary log output nor Avalanche policy changes.

A real Avalanche fixture needs distinct valid staked identities and quorum
configuration for the two nodes. `--node-args` accepts a JSON array of two arrays
of `-ava...` fixture arguments (including proof/key arguments); protect this
artificial fixture file with mode 0600. Its hash, not contents, is recorded.
Normal startup/authentication/quorum checks still apply. Missing polls, missing
pings, ping failures or insufficient block-body transfer leave the case
incomplete. `--allow-incomplete-smoke` permits a small transport/tool smoke to
exit successfully while retaining that incomplete status; it never turns it
into a measurement or gate pass.

## Equal impairment requires a packet-level TCP baseline

Do **not** drop bytes from a userspace TCP stream: it corrupts TLS/P2P instead of
simulating TCP packet loss. In a separately controlled Linux test VM, apply the
same bidirectional packet-level delay/loss/rate/queue model to the WT UDP and WSS
TCP public endpoint. Keep RPC and unrelated traffic outside the filters. Record
the VM/kernel, interface/filter/qdisc commands and `tc -s` before/after output
in an operator-reviewed receipt, for example:

```json
{
  "model": "packet-level",
  "both_directions": true,
  "loss": 0.01,
  "delay_ms": 25,
  "rate_mbps": 50,
  "queue_pkts": 4096,
  "machine": "isolated Linux VM identifier and kernel",
  "configuration_and_counters": "paths/hashes of exact filters, qdiscs and counters"
}
```

The driver checks the scalar settings and retains the receipt and its hash. It
**does not independently verify** external qdiscs, equality of the paths, queue
behavior or host load isolation; those require reviewing the recorded evidence.
`delay_ms` is one-way and rates are per direction. The queue and its measured
bottleneck delay must be reported, not tuned after seeing the results.

Example single case (future controlled VM work, not a default command to run):

```sh
python3 contrib/devtools/wt-loss-experiment/run.py \
  --bitcoind /path/to/bitcoind --fixture /path/to/stopped-regtest-prefix \
  --block /path/to/next-32MB-block.raw --output /new/path/loss1-wt-r1 \
  --transport wt --impairment external --impairment-receipt /path/to/receipt.json \
  --node-args /path/to/artificial-ava-identities.json \
  --loss .01 --delay-ms 25 --rate-mbps 50 --base-port 41000
```

Run WSS with the same settings in a different output directory. Ports are
`base+0/+1` RPC, `+2/+3` raw listeners, `+4/+6` public WT/WSS, and optional `+5`
UDP relay. All seven must be reserved; RPC is loopback-only. Defaults fall inside
35000..49998 and must still be coordinated with other jobs.

`--impairment udp` is a WT-only development diagnostic. It launches the bounded
prototype-derived `test_framework/udp_impair.py`: independent seeded per-datagram
loss in each direction, fixed one-way delay, per-direction serialized rate
including 28-byte IPv4/UDP overhead, bounded pending packets including delayed
packets and at most 16 MiB retained payload per direction, drop-tail and explicit forwarding/error/stop counters. It accepts one
client and replies only from its configured loopback server. The pending bound
is a deliberate safety difference from the prototype's unlimited delayed heap.
This userspace model is not interchangeable with TCP netem for a claimed speedup.
Use `--impairment none --loss 0 --delay-ms 0 --rate-mbps 0` for an unimpaired smoke.

## Results and acceptance

Artifacts include exact binary/block/tool hashes, platform/load, before/after
peer counters, raw ping/poll samples, nearest-rank p50/p99, time window, server
and client logs, transport identity, receipt and optional UDP counters. Node
startup configuration and the fixture's provenance must also be retained by the
operator. JSON-RPC submission and server block validation are included in the
reported transfer window; this is not a pure network-throughput measurement.

`gate_pass` always remains false: one case cannot establish the complete gate.
A case is eligible for later review only with the actual >=32 MB body, both
latency sample sets, the Linux host and recorded external packet impairment.
The matrix requires loss 0/0.5/1/2%, three interleaved pairs each, RTT 50 ms/rate
50 Mbit/s, run counts/spread/load and an audited interleaved baseline. At 1% loss,
WT poll p99 must be at most twice RTT plus measured bottleneck queue delay and
beat WSS by at least 3x. Separately require the <=4x Linux CPU-per-byte ceiling at
16 peers, real browser hash and stock/public-CA checks, fallback/firewall check
on a test VM, two-builder Guix equality and the 24-hour 50-peer churn soak.
None of these follows from unit tests or a tiny smoke. Keep both overall
WebTransport defaults off unless the complete gate is reviewed and passes.

Run the bounded pure-Python checks with `python3 contrib/devtools/wt-loss-experiment/test_tools.py`.
