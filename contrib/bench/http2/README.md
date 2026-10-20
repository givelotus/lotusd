HTTP/1.1 and HTTP/2 benchmark
=============================

An A/B driver comparing the node's HTTP server over HTTP/1.1 and HTTP/2 on
its TLS port, and comparing builds (e.g. a base build without HTTP/2 against
one with it):

- `httpload.c`: a closed-loop load generator in C over OpenSSL (and nghttp2
  for HTTP/2). HTTP/1.1 runs N keep-alive connections with one request in
  flight each; HTTP/2 runs N connections with S concurrent streams each. One
  thread per connection; only 200 responses count. Prints one JSON object.
- `run.py`: builds `httpload` (with HTTP/2 if `pkg-config` finds
  `libnghttp2`, else HTTP/1.1 only), starts a regtest node per `--bitcoind`
  in a fresh datadir (`-rpcthreads=16 -rpcworkqueue=256`, the TLS
  certificate the node generates), prepares a large block with the wallet,
  then runs every workload of every node in interleaved rounds and prints
  the median of the rounds.

| Workload | Client | Request |
| --- | --- | --- |
| `small-h1` | 64 HTTP/1.1 connections | `getblockcount` |
| `small-h2` | 4 HTTP/2 connections x 16 streams | `getblockcount` |
| `small-h2x1` | 1 HTTP/2 connection x 64 streams | `getblockcount` |
| `block-h1` | 4 HTTP/1.1 connections | `getblock <hash> 2` (large JSON reply) |
| `block-h2` | 1 HTTP/2 connection x 4 streams | `getblock <hash> 2` |

A node whose TLS port does not select ALPN h2 (a build without HTTP/2, or
`-http2=0`) only runs the HTTP/1.1 workloads, so the same command measures a
base build.

Requirements: a C compiler, OpenSSL and (for HTTP/2) nghttp2 development
files found by `pkg-config`, Python 3, and node builds with the wallet.

Usage
-----

```sh
contrib/bench/http2/run.py \
    --bitcoind <base build>/src/bitcoind \
    --bitcoind <http2 build>/src/bitcoind \
    [--rounds 3] [--seconds 10] [--port-base 36500] \
    [--block-txs 10] [--block-outputs 1000] \
    [--only small-h1,small-h2] [--workdir DIR] [--json results.json]
```

Each node uses two ports from `--port-base` up. `--workdir` keeps the
datadirs and the built client; without it a temporary directory is removed
afterwards.

Output: one line per run as it completes, e.g.

```
round 1 node1 small-h2: 39061 req/s, p50 1.44 ms, p99 5.30 ms, errors 0, load 22.8->22.8
```

then a Markdown table of medians over the rounds:

```
| node | workload | median req/s | median p50 ms | median p99 ms | MB/s | errors | load avg (1 min) |
```

`MB/s` counts response bodies; `load avg` is the machine's 1-minute load
average before each run (min-max over the rounds). `--json` also writes every
run's raw numbers.

Reading the results
-------------------

Runs are interleaved round by round so background load affects all variants
alike, but on a shared machine the spread between rounds can exceed the
difference between variants: look at the per-run lines and the load
average before drawing conclusions. The client and the node share the
machine's cores; both sides pay for TLS.
