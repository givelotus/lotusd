# Transaction relay measurements

Tools to measure how fast and at what cost transactions spread between
nodes, on one machine. They work with any build of the node (old relay or
new), so two relays can be compared with the same tool: pass the binary
with `--bitcoind`, and node options that only one build knows with
`--extra-args` or a variant's `@ARGS`.

All tools use the functional test framework of the build directory given
with `--build-dir` (its `test/config.ini` names the source tree). Use the
newest source tree's framework even when measuring an older binary: it
understands every message either sends. Ports come from the framework
(`TEST_RUNNER_PORT_MIN`, `--portseed`).

## relay_onehop.py

One node, a P2P sender and a P2P observer. Times from giving the node a
transaction to the observer receiving its announcement.

```
contrib/bench/tx-relay/relay_onehop.py --build-dir build --txs 150
```

Output: one JSON object, e.g.
`{"load_average": [...], "max_ms": 20.8, "mean_ms": 4.1, "median_ms": 2.1, "p90_ms": 10.2, "txs": 150}`.

## relay_cluster.py

A regtest cluster of `--nodes` nodes, each making `--outbound` connections
to random others (mean degree about twice that), optionally through a
proxy that delays each direction of each link by a one-way latency drawn
from `--latency MIN-MAX` (milliseconds). It funds a wallet, submits
`--txs` transactions at `--rate` per second to random nodes over RPC, waits
until every node has every transaction (or `--timeout`), and prints one
JSON object:

- `propagation_seconds`: for each transaction, the time from submission
  until 50/90/99/100% of the nodes accepted it (from the nodes' debug logs:
  `AcceptToMemoryPool: peer=N: accepted TXID`, microsecond timestamps);
  median, p90 and worst over transactions;
- `bytes_per_node_per_tx`: bytes sent, divided by nodes and transactions,
  by kind: `announce` (inv, invshort), `request` (getdata, getshorttx,
  notfound), `body` (tx, shorttx), `recon` (merklixsync, getmerklixbuck,
  merklixbuck), `other` (pings, blocks...); `floor_bytes` is the mean
  transaction size plus a 36-byte request;
- `duplicate_bodies_metric` / `bodies_received_metric`: from the nodes'
  `fullnode_txrelay_body_*` metrics (null for builds without them), and
  `tx_messages_received` vs `relayed_acceptances` from the logs;
- `cpu_seconds_per_tx`: CPU time of all node processes during the run,
  per transaction;
- `load_average` at the end, `complete`, `missing_node_txs`.

`--silent F --silent-args "..."`: a fraction F of the nodes (never node 0)
get extra arguments, e.g. a zero fan-out and no reconciliation, to stand
for peers that receive but do not relay. Coverage (`propagation_seconds`,
`complete`, `missing_node_txs`) counts the other nodes, as the simulator
does; `silent_node_txs_missing` reports the silent ones.

`--avalanche`: every node stakes a coinbase in its own proof and is
restarted with it (a small regtest quorum: `-avaminquorumstake=0`,
`-avaminquorumconnectedstakeratio=0` and friends; a node needs 8
Avalanche peers, so use enough nodes and connections). The run also waits
for Avalanche finalization and reports `finalization_seconds` (time from
submission until 50% / 100% of the nodes logged `Avalanche finalized tx`,
median and worst over transactions) and `finalized_all`.

```
contrib/bench/tx-relay/relay_cluster.py --build-dir build --nodes 24 \
    --outbound 8 --txs 300 --rate 20 --latency 10-80
```

## run_interleaved.py

Runs `relay_cluster.py` for several variants (`NAME=BINARY[@ARGS]`), one
round at a time, so changes in machine load affect every variant alike.
Appends each run to `--out` (JSON lines) and prints a table of medians with
the range over rounds. `--summary-only` reprints the table.

```
contrib/bench/tx-relay/run_interleaved.py --build-dir build --rounds 3 \
    --variant old=/path/to/old/bitcoind \
    --variant new=build/src/bitcoind \
    --out runs.jsonl -- --nodes 24 --outbound 8 --txs 300 --rate 20 \
    --latency 10-80
```

Limits: one machine, so nodes share CPU and the proxy (one Python thread)
adds its own delay under load; loopback has no bandwidth limit or loss;
the graph is random, not the real network's.
