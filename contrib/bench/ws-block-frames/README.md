# Serving one block to many P2P WebSocket peers

Tools to measure what a node spends to serve the same block to many peers
at once, comparing two builds (A and B) on the same fixture, over P2P
WebSocket (see [doc/p2p-websocket.md](../../../doc/p2p-websocket.md)) or raw
TCP. They work for any two builds of the node; they were written for
compress-once block frames.

## What is measured

`serve_ab.py` builds a regtest fixture once, then for each round and each
cell (block size x number of peers) starts each build on a fresh clone of
the fixture, alternating which build goes first. All peers connect, finish
the version handshake, then ask for the same block at the same moment. Per
serve it records:

- **node CPU**: user + system CPU time of the whole node process from the
  start signal until the last peer has the block (macOS `proc_pid_rusage`,
  Linux `/proc/<pid>/stat`);
- **wall time** until every peer has the whole block (each peer checks its
  SHA256);
- **bytes on the wire**: WebSocket frame bytes the node sent
  (`getnettotals`), or TCP bytes with `--transport=tcp`;
- with `-metrics`, the change of the `fullnode_p2p_compress_once_*`,
  `fullnode_p2p_websocket_independent_*` and `fullnode_p2p_block_message_cache_*`
  metrics where they exist.

The peers (`peers.py`) are asyncio connections in several client processes
(`--workers`, default 8). They decode what they receive as real peers would
(the zstd stream with the P2P dictionary), so both builds' peers do the same
work. They send no `sendcmpct`, never relay transactions and request only
the block.

The fixture has one block per cell: about 1, 8 and 31.9 MB (the default
32 MB block size limit) of ~225-byte P2PKH-shaped transactions with random
signatures, keys and hashes, plus fan-out transactions from mature
coinbases. It is a deliberately ordinary byte mix, not a mainnet sample.
Every cell serves a block the node has not served before in that process,
so caches start cold for each cell, and the block files are read once
beforehand so they come from the page cache, as a fresh tip would.

`src/bench/ws_block_serve.cpp` (`bitcoin-bench -filter='WsServe.*'`)
measures the per-peer pieces in isolation: block serialization, the P2P
checksum, stream compression and decompression, and (with compress-once)
independent compression, cache hits and decompression.

## How to reproduce

Build both trees (Release), for example:

```
cmake -GNinja -S <base-tree> -B <base-build> -DCMAKE_BUILD_TYPE=Release -DBUILD_BITCOIN_QT=OFF
ninja -C <base-build> bitcoind bitcoin-bench
cmake -GNinja -S <patched-tree> -B <patched-build> -DCMAKE_BUILD_TYPE=Release -DBUILD_BITCOIN_QT=OFF
ninja -C <patched-build> bitcoind bitcoin-bench
```

Run the driver from the newer tree (its client decodes independent
frames), with Python 3.10+ and `zstandard`:

```
python3 contrib/bench/ws-block-frames/serve_ab.py \
    --base <base-build> --patched <patched-build> \
    --output /path/to/results --sizes 1,8,32 --peers 8,32,64 --rounds 5
```

`--base`/`--patched` take a build directory or a `bitcoind` binary. `--offer` selects the compression subprotocol offered by every peer. `--transport=tcp` measures raw TCP peers instead. `--rpcport`/`--port`
(default 41604/41605) choose the node's ports. Building the fixture takes a
few minutes; it is kept in `<output>/fixture` and reused. A full run of the
default matrix (9 cells, 5 rounds, two builds) takes 20-40 minutes.

Output:

- one line per serve in `<output>/results.jsonl`: `round`, `side` (A/B),
  `size_mb`, `peers`, `node_cpu_s`, `wall_s`, `first_s`, `wire_bytes_sent`,
  `client_cpu_s`, `selected` (subprotocols the node chose), `load_average`
  and `metrics_delta`;
- `<output>/SUMMARY.md`, a table per cell and metric:

```
| Block | Peers | Metric | A median (min-max) | B median (min-max) | B/A | n |
|---|---:|---|---:|---:|---:|---:|
| 8 MB | 32 | node CPU (ms) | ... | ... | 0.xx | 5/5 |
```

`--summarize-only` rewrites the summary from existing results.

For the microbenchmarks:

```
<build>/src/bench/bitcoin-bench -filter='WsServe.*'
```

## Noise

Medians and the full min-max range are reported, never single runs. On a
shared machine, record the load average (it is in every result line) and
rerun on a quiet host before drawing fine conclusions. Peers and node share
the machine: wall times include the peers' own decoding and scheduling.
These are loopback measurements, not WAN bandwidth results.
