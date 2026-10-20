# Nucleation relay: measurements on regtest clusters

Old relay (`old`): the eCash tier before Nucleation relay (`c59dce9cd6`).
New relay (`new`): the same tier with Nucleation relay, default settings
(fan-out (8, 0.25, 32), 10 ms tick, 8-byte short ids, reconciliation every
250 ms over 30 s), unless the variant says otherwise. Both built the same
way (Release, Chronik on), measured with `relay_cluster.py` from this
directory, interleaved by `run_interleaved.py`: every round runs every
variant once, three rounds.

Setup: one machine (Apple M5 Max, 18 cores, 48 GB, macOS 26.6), shared with
other work; the load average at the end of each run is in the tables (17-84).
Nodes form a random graph (each makes `--outbound` connections; mean degree
13 with 24 nodes and 8 outbound, ~20 with 32 and 12, ~13 with 16 and 8);
every link goes through a proxy that delays each direction by a one-way
latency drawn per link from 10-80 ms, except where noted. Transactions
(~100 bytes, one input, one output) are submitted over RPC to random nodes,
so each enters the network at one node (an originated transaction, sent to
all of that node's peers). Times are from submission to the nodes'
`AcceptToMemoryPool` log lines (one clock). Bytes are all bytes sent, per
node per transaction, by message type. The floor is one body plus one
36-byte request: 136 bytes.

Figures are the median over runs, with the range in brackets. "t50" and
"t100 (median tx)" are the medians over transactions of the time to reach
50% / 100% of the (relaying) nodes; "t100 (worst tx)" is the slowest
transaction of a run.

How to reproduce (after building both trees; see README.md):

    contrib/bench/tx-relay/run_interleaved.py --build-dir build --rounds 3 \
        --variant old=OLD/bitcoind --variant new=build/src/bitcoind \
        --out e1.jsonl -- --nodes 24 --outbound 8 --txs 300 --rate 20 \
        --latency 10-80

The other tables change `--txs/--rate`, `--nodes/--outbound`,
`--latency 0`, add `--silent 0.3 --silent-args "-txrelayfanoutmin=0
-txrelayfanoutpct=0 -txrelayfanoutmax=0 -txreconinterval=0"` (silent
nodes: they receive but never forward or reconcile), `--avalanche`, or use
variants with `@-txrelaytick=50`, `@-txreconinterval=0`, `@-txrelaypushhb=1
-highbandwidthtx=1 -testdisablehighbandwidthshorttx=0`.

## Against the plan's targets

| Target | Result |
|---|---|
| Bytes per node per tx <= 1.3 x floor | **Not met.** New relay 4.0-5.9 x floor in the principal 20-200 tx/s comparisons (549-800 bytes), rising to 7.3 x in the 10 tx/s Avalanche runs; the old relay 2.7-3.7 x. At these rates each 10 ms tick carries about one transaction per peer, so every `invshort`, `getshorttx` and `shorttx` pays a message header and a 32-byte epoch/context (and 16 bytes of key in `getshorttx`) for one 8-byte id; the old relay's 2-5 s timers batch many 36-byte entries per `inv`. A 100 ms tick brings the new relay to 2.5 x floor (below the old relay) at +0.09 s to every node. Higher-rate batching is an unmeasured hypothesis; these runs do not establish the target at any higher rate. |
| Duplicate bodies < 1% of bodies | **Met**: 0 duplicates in every new-relay run (metric `fullnode_txrelay_body_dup_total`), after the commit that fetches reconciliation misses through the request tracker (before it: 9%). The old binary has no such metric. |
| 100% within 1 s, 0% silent, 16-48 peers | **Not met as a strict deadline.** For the median transaction (0.36-0.56 s per run with link latency, 0.03 s without; old relay 2.2-3.1 s). The slowest transaction of a run reached every node within 1 s in 30 of 33 new-relay runs; 1.13, 1.41 and 1.45 s in the other three (single stragglers; one in a run without link latency, where the median was 0.03 s). |
| 100% within 2 s at 30% silent | **Met**: median transaction 0.50 s, slowest 0.78-1.30 s, all three runs complete. Without reconciliation one of three runs never delivered two node-transactions (after 30 s). |
| No Avalanche finalization regression | **No regression observed in these runs.** 50% of nodes finalize a transaction after 2.9-3.1 s (old: 5.0-5.1 s); all nodes after 6.9 s at 10 tx/s (old 8.6 s) and 8.6 s at ~170 tx/s (old 8.5 s, at the ~80-100 tx/s its RPC accepted). |
| -txrelaypushhb (R5) | **The push path was not exercised sufficiently to decide its effect.** The default stays off. Pushes need 16 transactions for one peer in one tick (about 1,600 tx/s here); at 10-170 tx/s the body bytes and propagation are the same with and without, and finalization by all nodes was 7.7 s vs 8.6 s at ~170 tx/s (t50 the same). |

Also measured: node CPU per transaction (all nodes, all threads) is 2-3 x
the old relay's at 20-100 tx/s (tick wake-ups, per-tick messages,
reconciliation rounds every 250 ms), and about equal with Avalanche at
10 tx/s, where polling dominates. One-hop delay inside a node (accept to
announcement queued, `relay_onehop.py`): median 3.1 ms, p90 9.7 ms (old:
4.4 s median).

Not measured: rates above ~200 tx/s (one RPC client), links with loss or
bandwidth limits, real (non-random) topologies, Linux.

#### 24 nodes, 20 tx/s, 300 tx

| variant | runs | t50 s | t100 s (median tx) | t100 s (worst tx) | bytes/node/tx (announce / request / body / recon) | × floor | dup bodies | CPU ms/tx | load | incomplete |
|---|---|---|---|---|---|---|---|---|---|---|
| old | 3 | 1.72 (1.64–1.76) | 2.90 (2.72–2.94) | 5.71 (5.53–6.76) | 399 (396–400) (241 / 39 / 119 / 0) | 2.93 (2.91–2.94) | n/a | 13.8 (13.0–14.5) | 44 (29–70) | 0 |
| new | 3 | 0.24 (0.24–0.25) | 0.42 (0.41–0.43) | 0.67 (0.62–0.67) | 800 (792–800) (507 / 78 / 151 / 63) | 5.88 (5.82–5.88) | 0 | 39.6 (38.7–40.1) | 58 (37–68) | 0 |

#### 24 nodes, 100 tx/s, 1000 tx

| variant | runs | t50 s | t100 s (median tx) | t100 s (worst tx) | bytes/node/tx (announce / request / body / recon) | × floor | dup bodies | CPU ms/tx | load | incomplete |
|---|---|---|---|---|---|---|---|---|---|---|
| old | 3 | 1.80 (1.75–1.83) | 2.95 (2.93–3.14) | 5.37 (4.88–6.13) | 390 (387–392) (235 / 36 / 119 / 0) | 2.87 (2.84–2.88) | n/a | 15.0 (14.6–15.7) | 70 (68–72) | 0 |
| new | 3 | 0.30 (0.26–0.33) | 0.52 (0.45–0.56) | 0.88 (0.73–1.13) | 597 (573–637) (357 / 74 / 147 / 20) | 4.39 (4.21–4.69) | 0 | 28.7 (28.6–33.1) | 77 (64–84) | 0 |

#### 32 nodes (mean degree ~20), 100 tx/s, 1000 tx

| variant | runs | t50 s | t100 s (median tx) | t100 s (worst tx) | bytes/node/tx (announce / request / body / recon) | × floor | dup bodies | CPU ms/tx | load | incomplete |
|---|---|---|---|---|---|---|---|---|---|---|
| old | 3 | 1.54 (1.53–1.59) | 2.50 (2.41–2.50) | 4.47 (4.05–4.90) | 497 (495–499) (341 / 37 / 120 / 0) | 3.66 (3.64–3.67) | n/a | 19.6 (15.1–19.9) | 22 (20–23) | 0 |
| new | 3 | 0.27 (0.24–0.27) | 0.47 (0.45–0.48) | 0.83 (0.80–1.41) | 697 (692–699) (449 / 77 / 151 / 20) | 5.12 (5.09–5.14) | 0 | 48.4 (48.2–49.0) | 24 (18–24) | 0 |

#### 24 nodes, 20 tx/s, no link latency

| variant | runs | t50 s | t100 s (median tx) | t100 s (worst tx) | bytes/node/tx (announce / request / body / recon) | × floor | dup bodies | CPU ms/tx | load | incomplete |
|---|---|---|---|---|---|---|---|---|---|---|
| old | 3 | 1.40 (1.34–1.53) | 2.33 (2.17–2.54) | 4.54 (4.35–4.85) | 395 (390–398) (237 / 39 / 119 / 0) | 2.91 (2.87–2.92) | n/a | 11.2 (11.1–11.4) | 18 (17–18) | 0 |
| new | 3 | 0.02 (0.02–0.02) | 0.03 (0.03–0.03) | 0.27 (0.23–1.45) | 773 (773–781) (483 / 79 / 151 / 60) | 5.69 (5.68–5.74) | 0 | 29.5 (29.5–31.0) | 19 (17–23) | 0 |

#### 24 nodes, 20 tx/s, 30% silent (7 nodes)

| variant | runs | t50 s | t100 s (median tx) | t100 s (worst tx) | bytes/node/tx (announce / request / body / recon) | × floor | dup bodies | CPU ms/tx | load | incomplete |
|---|---|---|---|---|---|---|---|---|---|---|
| new | 3 | 0.26 (0.26–0.27) | 0.50 (0.50–0.51) | 0.82 (0.78–1.30) | 646 (644–646) (371 / 78 / 151 / 46) | 4.75 (4.74–4.75) | 0 | 31.3 (31.0–31.5) | 21 (20–23) | 0 |
| new-norecon | 3 | 0.26 (0.26–0.27) | 0.50 (0.50–0.52) | 0.85 (max: never) | 599 (598–599) (370 / 78 / 151 / 0) | 4.41 (4.40–4.41) | 0 | 29.0 (26.3–35.7) | 21 (20–25) | 1 |

#### 24 nodes, 100 tx/s: relay tick

| variant | runs | t50 s | t100 s (median tx) | t100 s (worst tx) | bytes/node/tx (announce / request / body / recon) | × floor | dup bodies | CPU ms/tx | load | incomplete |
|---|---|---|---|---|---|---|---|---|---|---|
| new | 3 | 0.24 (0.24–0.24) | 0.42 (0.41–0.43) | 0.74 (0.64–0.87) | 652 (650–655) (412 / 75 / 148 / 18) | 4.80 (4.78–4.82) | 0 | 33.7 (32.6–34.1) | 29 (23–34) | 0 |
| new-tick50 | 3 | 0.27 (0.27–0.27) | 0.46 (0.45–0.46) | 0.76 (0.73–0.80) | 428 (428–428) (210 / 61 / 138 / 19) | 3.15 (3.14–3.15) | 0 | 24.9 (24.6–25.3) | 26 (25–33) | 0 |
| new-tick100 | 3 | 0.30 (0.30–0.31) | 0.51 (0.51–0.51) | 0.84 (0.84–0.85) | 342 (342–343) (142 / 51 / 129 / 20) | 2.52 (2.52–2.52) | 0 | 22.0 (22.0–22.1) | 25 (24–29) | 0 |

#### 16 nodes, Avalanche, 10 tx/s, 60 tx

| variant | runs | t50 s | t100 s (median tx) | t100 s (worst tx) | bytes/node/tx (announce / request / body / recon) | × floor | dup bodies | CPU ms/tx | load | incomplete |
|---|---|---|---|---|---|---|---|---|---|---|
| old | 3 | 1.46 (1.44–1.68) | 2.46 (2.36–2.65) | 4.98 (4.09–5.81) | 400 (399–403) (242 / 42 / 116 / 0) | 2.94 (2.93–2.96) | n/a | 96.7 (87.7–97.7) | 26 (22–39) | 0 |
| new | 3 | 0.20 (0.20–0.20) | 0.36 (0.36–0.37) | 0.52 (0.50–0.53) | 997 (992–998) (536 / 76 / 148 / 237) | 7.33 (7.30–7.34) | 0 | 93.2 (91.7–94.7) | 24 (23–52) | 0 |
| new-pushhb | 3 | 0.20 (0.20–0.20) | 0.36 (0.36–0.38) | 0.48 (0.47–0.52) | 1002 (995–1008) (540 / 76 / 148 / 238) | 7.37 (7.32–7.41) | 0 | 91.8 (91.3–97.0) | 28 (26–42) | 0 |

| variant | finalized at 50% of nodes, s | at 100%, s (median tx) | at 100%, s (worst tx) | submit time, s |
|---|---|---|---|---|
| old | 5.04 (4.99–5.17) | 8.63 (8.31–9.14) | 10.66 (10.35–12.32) | 9.17 (8.68–10.27) |
| new | 2.94 (2.92–3.01) | 6.91 (6.52–7.20) | 9.86 (9.47–10.15) | 6.23 (6.21–6.26) |
| new-pushhb | 2.98 (2.91–2.99) | 6.89 (6.83–6.94) | 9.84 (9.78–9.90) | 6.26 (6.21–6.31) |

#### 16 nodes, Avalanche, 600 tx submitted as fast as RPC allows (target 200 tx/s)

| variant | runs | t50 s | t100 s (median tx) | t100 s (worst tx) | bytes/node/tx (announce / request / body / recon) | × floor | dup bodies | CPU ms/tx | load | incomplete |
|---|---|---|---|---|---|---|---|---|---|---|
| new | 3 | 0.22 (0.21–0.23) | 0.39 (0.36–0.40) | 0.58 (0.58–0.62) | 549 (549–560) (313 / 68 / 140 / 28) | 4.04 (4.03–4.12) | 0 | 27.5 (26.7–27.8) | 39 (27–39) | 0 |
| new-pushhb | 3 | 0.22 (0.21–0.23) | 0.39 (0.36–0.41) | 0.59 (0.53–0.62) | 552 (543–560) (317 / 67 / 140 / 27) | 4.06 (3.99–4.11) | 0 | 27.5 (26.8–28.0) | 35 (23–36) | 0 |
| old | 3 | 1.50 (1.41–1.53) | 2.64 (2.56–2.81) | 6.77 (5.28–6.94) | 366 (365–366) (215 / 35 / 116 / 0) | 2.69 (2.68–2.69) | n/a | 21.3 (17.8–22.9) | 32 (22–42) | 0 |

| variant | finalized at 50% of nodes, s | at 100%, s (median tx) | at 100%, s (worst tx) | submit time, s |
|---|---|---|---|---|
| new | 3.10 (2.97–3.20) | 8.56 (8.40–8.71) | 10.06 (9.90–10.21) | 3.48 (3.48–3.49) |
| new-pushhb | 3.04 (3.01–3.13) | 7.67 (7.53–8.21) | 9.17 (9.03–9.71) | 3.49 (3.47–3.54) |
| old | 5.11 (5.10–5.21) | 8.51 (8.41–9.96) | 12.36 (10.48–13.52) | 7.49 (5.99–7.97) |

## Evidence and limits of recovery

These tables were recovered from completed October 19 runs; no benchmark
was rerun during session recovery. The durable handoff contains the raw
`e1`, `e2`, `e3b`, `e5` through `e9` JSONL files and exact batch commands.
The earlier `e3` counted silent nodes in coverage and is superseded by
`e3b`; `e4` has only two rounds per variant after a failed third run and
is excluded from the tables above.

The original binary build paths and hashes need to be retained with the
handoff. These recovered measurements describe the pre-recovery source,
not any later correctness repair or combined canonical stack. CPU is all
node process CPU per submitted transaction, not isolated relay CPU. The
16-node and 24-node graphs have mean degree about 13, below the plan's
16-peer lower bound, so the full requested topology range is unvalidated.
No extended suite, production-node run, or full benchmark sweep was run.
