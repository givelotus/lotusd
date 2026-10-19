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
| `process_resident_memory_bytes` | gauge | | 1 | Resident memory size (Linux: /proc/self/statm; macOS: task_info). |
| `process_virtual_memory_bytes` | gauge | | 1 | Virtual memory size. |
| `process_open_fds` | gauge | | 1 | Open file descriptors (Linux: /proc/self/fd; macOS: proc_pidinfo). |
| `process_max_fds` | gauge | | 1 | Soft limit on open file descriptors. |
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
| `fullnode_rpc_work_queue_depth` | gauge | | 1 | HTTP requests (RPC, REST, ...) queued for a worker. |
| `fullnode_rpc_work_queue_capacity` | gauge | | 1 | Requests the queue holds before refusing more (`-rpcworkqueue`). |
| `fullnode_rpc_work_in_flight` | gauge | | 1 | Requests queued or being handled (suspended long polls included). |
| `fullnode_rpc_work_suspended` | gauge | | 1 | Requests suspended without a worker (long polls such as `waitforblockheight`). |
| `fullnode_rpc_work_queue_rejected_total` | counter | | 1 | Requests refused (503) because the queue was full. |

### P2P

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_peers` | gauge | `direction` (2), `transport` (`tcp`, `ws`, `wss`), `peer_network` (8) | 48 | Connected peers. |
| `fullnode_p2p_connections_total` | counter | `direction` (2), `transport` (3) | 6 | Connections established. |
| `fullnode_p2p_websocket_peers` | gauge | `compression` (4), `tls` (2) | 8 | Connected P2P WebSocket peers. |
| `fullnode_p2p_received_bytes_total` | counter | `type` (55 message types + `other`) | 56 | Bytes received (header and payload). |
| `fullnode_p2p_sent_bytes_total` | counter | `type` | 56 | Bytes queued for sending. |
| `fullnode_p2p_received_messages_total` | counter | `type` | 56 | Messages received. |
| `fullnode_p2p_sent_messages_total` | counter | `type` | 56 | Messages queued for sending. |
| `fullnode_p2p_message_handling_seconds` | histogram | `type` | 56 | Time to process a received message (1 in 16 sampled; `_count` is a sample). |

### P2P health

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_p2p_handshake_seconds` | histogram | `direction` (2), `transport` (3) | 6 | Time from a connection's creation to its verack. For outbound WebSocket peers, the TCP, TLS and upgrade happen before and are not included. |
| `fullnode_p2p_ping_seconds` | histogram | `transport` (3) | 3 | Ping round trips (ping to matching pong). |
| `fullnode_addrman_addresses` | gauge | `table` (`new`, `tried`) | 2 | Addresses in the address manager's tables. |
| `fullnode_p2p_bans_total` | counter | | 1 | Subnets banned. |
| `fullnode_p2p_banned_subnets` | gauge | | 1 | Subnets on the ban list. |
| `fullnode_p2p_discouragements_total` | counter | `outcome` (`discouraged`, `disconnected_local`, `exempt_noban`, `exempt_manual`) | 4 | Peers punished for misbehaving, by what happened. |
| `fullnode_p2p_misbehavior_total` | counter | `reason` (10) | 10 | Misbehavior events by class: `handshake`, `oversized_message`, `invalid_header`, `invalid_block`, `invalid_compact_block`, `invalid_tx`, `bloom_filter`, `avalanche`, `avalanche_proof`, `other`. |

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

### Avalanche

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_avalanche_quorum_established` | gauge | | 1 | 1 once the quorum is established (latched, while at least 8 nodes are connected). |
| `fullnode_avalanche_quorum_nodes` | gauge | | 1 | Avalanche nodes counted for the quorum. |
| `fullnode_avalanche_quorum_score` | gauge | `scope` (`total`, `connected`) | 2 | Stake score of the known peers, and of those with a connected node (the local proof not included). |
| `fullnode_avalanche_proofs` | gauge | `pool` (`valid`, `conflicting`, `immature`, `dangling`) | 4 | Proofs in each proof pool. |
| `fullnode_avalanche_polls_sent_total` | counter | | 1 | Polls sent to peers. |
| `fullnode_avalanche_poll_items_sent_total` | counter | | 1 | Items asked for in the polls sent. |
| `fullnode_avalanche_polls_received_total` | counter | `outcome` (`answered`, `ignored`) | 2 | Polls received; ignored when the peer's cooldown had not elapsed. |
| `fullnode_avalanche_votes_received_total` | counter | `vote` (`yes`, `no`, `neutral`) | 3 | Votes in responses to our polls: yes (0), no (positive error, e.g. invalid or parked), neutral (negative error, e.g. unknown). |
| `fullnode_avalanche_items_total` | counter | `type` (6), `outcome` (`finalized`, `invalidated`, `stale`) | 18 | Items whose vote ended. Types: `proof`, `block`, `contender`, `transaction`, `batch`, `state_anchor`. |
| `fullnode_avalanche_finalization_seconds` | histogram | `type` (6) | 6 | Time from an item's registration for polling to its finalization. Items registered while metrics were off are not timed. |

### Mempool admission

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_mempool_accepted_total` | counter | | 1 | Transactions accepted (from peers, RPC, raw batches, packages, reorgs and the mempool file; test acceptances excluded). |
| `fullnode_mempool_rejected_total` | counter | `reason` (13) | 13 | Transactions refused, by validation result: `consensus`, `inputs_not_standard`, `not_standard`, `missing_inputs`, `premature_spend`, `duplicate` (incl. already in the mempool), `conflict`, `child_before_parent`, `mempool_policy`, `no_mempool`, `package_reconsiderable` (e.g. fee below the floor), `avalanche_reconsiderable`, `unknown`. |
| `fullnode_mempool_accepted_fee_rate_sats_per_byte` | histogram | | 1 | Accepted transactions' own fee rate (base fee over sigcheck-adjusted virtual size, without prioritisetransaction deltas). Buckets 0 to 10000 sat/byte, dense around the 1 sat/byte floor. |
| `fullnode_mempool_removed_total` | counter | `reason` (7) | 7 | Transactions removed: `expiry`, `sizelimit` (evictions), `reorg`, `block`, `conflict`, `avalanche`, `manual`. |
| `fullnode_mempool_min_fee_rate_sats_per_byte` | gauge | `kind` (`rolling`, `effective`) | 2 | Rolling minimum (raised when the mempool is full; 0 otherwise) and the effective admission floor (highest of the minimum relay fee, the rolling minimum and the fee hysteresis rate, as `estimatefee`). |
| `fullnode_tx_pool_transactions` | gauge | `pool` (`orphan`, `conflicting`) | 2 | Transactions held outside the mempool: orphans, and conflicting ones awaiting a vote. |
| `fullnode_tx_pool_removed_total` | counter | `pool` (2), `reason` (`expired`, `evicted`) | 4 | Transactions dropped from those pools on expiry, or evicted at random when full. |

### Validation and UTXO

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_block_validation_stage_seconds` | histogram | `stage` (9) | 9 | Time per stage of connecting a block. ConnectBlock: `check`, `forks`, `connect` (spending inputs), `verify` (scripts and signatures), `index` (undo and index); ConnectTip: `load` (reading the block), `flush` (into the UTXO cache), `chainstate` (writing it if needed), `post_connect`. Failed blocks and block template checks are not counted. 10 µs to 60 s. |
| `fullnode_script_check_transactions` | histogram | | 1 | Per block, transactions whose scripts had to be checked (not in the script cache): the parallel script check queue's depth. |
| `fullnode_script_check_workers` | histogram | | 1 | Per block, script check workers used (parallelism). |
| `fullnode_validation_cache_lookups_total` | counter | `cache` (`signature`, `script_execution`), `result` (`hit`, `miss`) | 4 | Lookups in the signature and script execution caches. |
| `fullnode_utxo_cache_bytes` | gauge | | 1 | Memory used by the chainstate's UTXO cache, as of its last flush check (each block and periodically). |
| `fullnode_utxo_cache_entries` | gauge | | 1 | Coins in that cache, as of its last flush check. |
| `fullnode_utxo_cache_lookups_total` | counter | `result` (`hit`, `miss`, `absent`) | 3 | Coin lookups in that cache: found, read from the database, or in neither. Hit rate: `hit / sum`. |
| `fullnode_utxo_cache_flush_seconds` | histogram | `mode` (`flush`, `sync`) | 2 | Time to write the cache to the database: emptying it (`flush`) or keeping it (`sync`). `_count` counts flushes. |
| `fullnode_chain_reorgs_total` | counter | | 1 | Chain reorganizations (tip changes that disconnected blocks). |
| `fullnode_chain_reorg_depth_blocks` | histogram | | 1 | Blocks disconnected per reorganization. |
| `fullnode_blocks_invalid_total` | counter | `source` (`validation`, `invalidateblock`) | 2 | Blocks marked invalid. |
| `fullnode_blocks_parked_total` | counter | `reason` (`policy`, `finalization_conflict`, `deep_reorg`, `requested`) | 4 | Blocks parked: a block policy failed, forks below the Avalanche-finalized tip, `-parkdeepreorg`, or `parkblock`/an Avalanche rejection. |

### Storage

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_db_size_bytes` | gauge | `db` (6) | 6 | Size of each MDBX database (the data file's current geometry), as of its last commit. Databases: `chainstate`, `block_index`, `txindex`, `blockfilterindex`, `coinstatsindex`, `other`. Two databases of one kind (e.g. a snapshot chainstate and the background one) share a series: the last commit sets it. |
| `fullnode_db_commit_seconds` | histogram | `db` (6) | 6 | Time to write and commit a batch (and sync it when asked). `_count` counts commits. 50 µs to 120 s. |

### This tier's features

Transaction-relay announcement metrics are added by the Nucleation relay
work, under this naming scheme; they are not listed here.

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_sealed_headers_total` | counter | `outcome` (`rebuilt`, `already_have`, `fallback`, `invalid`, `rejected`) | 5 | Sealed headers received: block rebuilt from the mempool overlay, already had its data, fell back to requesting the compact block, malformed, or header/coinbase refused. |
| `fullnode_merklix_rounds_total` | counter | `round` (`summary`, `bucket`), `result` (`matched`, `differences`) | 4 | Merklix reconciliation rounds received (merklixsync, merklixbuck). |
| `fullnode_merklix_difference_size` | histogram | `round` (2) | 2 | Short ids found missing per round that decoded some. |
| `fullnode_merklix_overflows_total` | counter | | 1 | Sub-buckets with more differences than their sketch decodes. |
| `fullnode_snapshot_publications_total` | counter | `kind` (`chain_tip`, `best_header`, `mempool`) | 3 | Chain/mempool snapshots published for lock-free RPC reads. |
| `fullnode_snapshot_publish_seconds` | histogram | `kind` (3) | 3 | Time to build and publish a snapshot. 5 µs to 10 s. |
| `fullnode_snapshot_sync_state` | gauge | `state` (`idle`, `fetching_roots`, `fetching_shards`, `pivot_active_peeling`, `completed`, `failed`) | 6 | UTXO snapshot (fast) sync swarm state, one-hot. |
| `fullnode_snapshot_sync_pivot_height` | gauge | | 1 | Height of the fast sync pivot (0 if none). |
| `fullnode_snapshot_sync_shards` | gauge | `status` (`total`, `verified`, `pending`, `in_flight`) | 4 | Fast sync UTXO shards. |
| `fullnode_snapshot_sync_coins_imported` | gauge | | 1 | Coins imported by the current session. |
| `fullnode_snapshot_sync_blocks_peeled` | gauge | | 1 | Blocks peeled back from the pivot. |
| `fullnode_snapshot_sync_peers` | gauge | `status` (`active`, `banned`) | 2 | Fast sync swarm peers. |
| `fullnode_block_template_build_seconds` | histogram | `stage` (`select`, `validity`, `total`) | 3 | Time to build a block template (CreateNewBlock). |
| `fullnode_adaptive_block_size_bytes` | gauge | `limit` (`max`, `target`, `max_generated`, `ema`) | 4 | Adaptive block capacity: the consensus limit it allows, its target, the mining limit with `-adaptiveblocksize`, and the moving average of block sizes. |
| `fullnode_adaptive_block_size_history_complete` | gauge | | 1 | 1 once the adaptive capacity has a complete history. |

### Chronik

| Name | Type | Labels | Max series | Meaning |
|---|---|---|---|---|
| `fullnode_chronik_requests_total` | counter | `endpoint` (24), `code` (`2xx`, `4xx`, `5xx`, `other`) | 96 | Requests to Chronik's HTTP server (direct, or proxied under `/chronik`), by route family: `blockchain_info`, `block`, `block_header`, `block_txs`, `blocks`, `block_headers`, `unconfirmed_txs`, `chronik_info`, `tx`, `token`, `raw_tx`, `validate_tx`, `broadcast_tx`, `broadcast_txs`, `script_batch`, `script`, `token_id`, `lokad_id`, `plugin`, `ws`, `pause`, `resume`, `not_found`, `other`. |
| `fullnode_chronik_request_duration_seconds` | histogram | `endpoint` (24) | 24 | Time to answer a request (for `ws`, until the upgrade). |
| `fullnode_chronik_ws_connections` | gauge | | 1 | Open WebSocket connections. |
| `fullnode_chronik_ws_subscriptions` | gauge | | 1 | Active WebSocket subscriptions over all connections. |
| `fullnode_chronik_indexed_height` | gauge | | 1 | Height of the last block Chronik indexed (0 without Chronik). |
| `fullnode_chronik_lag_blocks` | gauge | | 1 | Blocks the index is behind the chain tip, at scrape time. |


### Native Chronik observation boundaries

Both backend choices report the same bounded request families, status classes,
connection/subscription gauges and indexed-height/lag gauges. Native callbacks
are installed by the ABC host; the portable core has no node-metrics dependency.
Native request duration measures router dispatch; a successful WebSocket upgrade
measures response-header preparation, excluding socket and query-pool waiting.
Rust duration retains its middleware boundary. Compare timing workloads within
a backend rather than treating these boundaries as identical. Connections count
accepted handlers, and subscriptions count successfully reserved slots until
release. Metrics callbacks cannot change a response or subscription outcome.

The callbacks are fixed before publication and perform atomic recording only;
they must not acquire registry, host or indexer locks. Native limiter callbacks
run under its existing mutex. Shutdown drains the Chronik workers/sessions;
node metrics remain allocated through process exit even after scraping stops.

## Tests

`test/functional/test_framework/metrics.py` scrapes and checks an
exposition (format, histogram consistency, duplicate series) and looks up
series by name and labels, ignoring the constant labels unless asked.
