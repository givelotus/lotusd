# Operator metrics

With `-metrics`, the node serves its metrics at `/metrics` on the RPC
listeners, in the Prometheus text exposition format (version 0.0.4). Only
`-rpcallowip` clients may scrape it, without authentication; public
(`-publicbind`) listeners never serve it. Renderings are cached for one
second, so scrapes cost little however often they come.

Recording is lock-free (sharded counters, relaxed atomics, and per-thread
event rings drained in the background for histograms); see
`src/metrics/metrics.h`. A disabled node pays one load and a branch at each
recording site.

## Naming

Every metric name starts with one fixed, neutral namespace, `fullnode_`
(`METRICS_NAMESPACE` in `src/node/metrics.h`; change it there and nowhere
else). Metrics whose name a Prometheus convention defines keep that name
without the namespace: `process_start_time_seconds` and the other
`process_*` metrics.

Names follow the Prometheus conventions: counters end in `_total`; quantities
use base units with the unit as suffix (`_seconds`, `_bytes`); histograms
are named for the quantity they observe and render `_bucket`, `_sum` and
`_count`.

## Labels

### Constant labels

Every series carries these labels, so that one Prometheus can scrape nodes
of several daemons and networks without relabelling:

| Label | Value | Source |
|---|---|---|
| `client` | the daemon, e.g. `ecashd` | the build: `FULLNODE_CLIENT` in `src/config/CMakeLists.txt` |
| `network` | `<chain>-<network>`, e.g. `ecash-mainnet`, `ecash-testnet`, `ecash-regtest` | chain part from the build (`FULLNODE_CHAIN`), network from the chain parameters (`mainnet`, `testnet`, `regtest`) |

Each daemon sets its own `FULLNODE_CLIENT` and `FULLNODE_CHAIN` in one place
(`src/config/CMakeLists.txt`, overridable with `-DFULLNODE_CLIENT=...`), so
that other tiers report e.g. `client="lotusd",network="lotus-mainnet"`.

### Operator labels

`-metricslabel=<name>=<value>` adds a constant label to every series. It can
be given up to 16 times. Startup fails if:

- the name is not a valid Prometheus label name (`[a-zA-Z_][a-zA-Z0-9_]*`),
  starts with `__`, or is `le` or `quantile`;
- the name is `client` or `network` (set by the node);
- the name is repeated, or is the name of one of the metrics' own labels
  (e.g. `type`, `direction`);
- the value is empty, longer than 128 bytes, or has control characters.

Values are escaped as the exposition format requires.

### Metric labels

Metric labels only take values from small fixed sets, listed below with
each metric's maximum number of series. Transaction ids, addresses, peer
ids and free text never become label values: per-peer and per-item detail
belongs in RPC (`getpeerinfo`, `getavalancheinfo`, ...), not metrics.

## Catalogue

The maximum cardinality is the number of series a metric can have, before
the constant labels (which do not multiply it: they are the same on every
series of a node). For histograms it counts label combinations; each has
one `_bucket` per bound plus `+Inf`, a `_sum` and a `_count`.

### Build and process

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_build_info` | gauge | `version`, `commit` | 1 | Always 1; the build's version (`major.minor.revision`) and commit (empty if unknown). |
| `process_start_time_seconds` | gauge | | 1 | Start time of the process (Unix time). |
| `fullnode_metrics_dropped_samples_total` | counter | | 1 | Event samples dropped because a recording thread's ring was full. |
| `fullnode_log_dropped_lines_total` | counter | | 1 | Debug and info log lines dropped because the logging thread could not keep up. |
| `fullnode_log_journal_failures_total` | counter | | 1 | Journal sends that failed and fell back to stderr. |

### HTTP and RPC

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_http_requests_total` | counter | `endpoint` (7), `code` (6) | 42 | HTTP requests answered, by endpoint (`rpc`, `wallet`, `rest`, `chronik`, `health`, `metrics`, `other`) and status class (`1xx`..`5xx`, `other`). |
| `fullnode_http_request_duration_seconds` | histogram | `endpoint` (7) | 7 | Time from a request's header to its response. |
| `fullnode_http_tls_handshakes_total` | counter | `result` (2) | 2 | TLS handshakes on the HTTP listeners (`ok`, `failed`). |
| `fullnode_rpc_request_duration_seconds` | histogram | `method` | registered RPC commands + 1 | RPC execution time by method; a method's series appears once it is called. |

### P2P

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_peers` | gauge | `direction` (2), `transport` (2), `peer_network` (8) | 32 | Connected peers. |
| `fullnode_p2p_connections_total` | counter | `direction` (2), `transport` (2) | 4 | Connections established. |
| `fullnode_p2p_websocket_peers` | gauge | `compression` (4), `tls` (2) | 8 | Connected P2P WebSocket peers. |
| `fullnode_p2p_received_bytes_total` | counter | `type` (55 message types + `other`) | 56 | Bytes received (header and payload). |
| `fullnode_p2p_sent_bytes_total` | counter | `type` | 56 | Bytes queued for sending. |
| `fullnode_p2p_received_messages_total` | counter | `type` | 56 | Messages received. |
| `fullnode_p2p_sent_messages_total` | counter | `type` | 56 | Messages queued for sending. |
| `fullnode_p2p_message_handling_seconds` | histogram | `type` | 56 | Time to process a received message (1 in 16 sampled; `_count` is a sample). |

### Chain

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_chain_tip_height` | gauge | | 1 | Height of the active chain tip. |
| `fullnode_chain_tip_timestamp_seconds` | gauge | | 1 | Block timestamp of the tip (Unix time). |
| `fullnode_chain_tip_age_seconds` | gauge | | 1 | Seconds since the tip's timestamp, at scrape time. |
| `fullnode_initial_block_download` | gauge | | 1 | 1 while in initial block download. |
| `fullnode_block_connect_seconds` | histogram | | 1 | Time to connect a block to the tip (ConnectBlock). |

### Mempool

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_mempool_transactions` | gauge | | 1 | Transactions in the mempool. |
| `fullnode_mempool_bytes` | gauge | | 1 | Total size of the mempool's transactions. |

## Tests

`test/functional/test_framework/metrics.py` scrapes and checks an
exposition (format, histogram consistency, duplicate series) and looks up
series by name and labels, ignoring the constant labels unless asked.
