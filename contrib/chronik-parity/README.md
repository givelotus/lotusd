# Chronik parity harness

Tools that compare two Chronik builds on the same deterministic regtest chain
(design C1, section 8.3). Implementation A is normally the Rust Chronik and
B the native C++ Chronik, but any two builds of the same chain can be used.
For example, A and B can be the same binary when validating the harness.

| File | Purpose |
|------|---------|
| `parity_chain.py` | Runs the chain on two nodes, drives the corpus at checkpoints and writes the report |
| `corpus.py` | Builds the HTTP and WebSocket request corpus from a run record; it can also run standalone against two running Chronik instances |
| `compare.py` | Compares responses, WebSocket sessions and DB dumps; it can also compare two saved response files |

## Requirements

- Two CMake build dirs. Each needs `src/bitcoind` or `src/lotusd` and
  `test/config.ini`, and both must be built with Chronik.
- Python with `protobuf` and `websocket-client`, plus `chronik_pb2`. The
  harness finds `chronik_pb2` on `PYTHONPATH`, via `--pb2-dir`, or by running
  `protoc` on `<srcdir>/chronik/chronik-proto/proto/chronik.proto`.

For example:

```
python3 -m venv venv && venv/bin/pip install protobuf websocket-client
PY=venv/bin/python
```

## Running

```
# eCash tier: Rust (A) vs native (B), 400 blocks, the design's full run
$PY contrib/chronik-parity/parity_chain.py \
    --build-a build/ecash-rust --build-b build/ecash-native --blocks 400

# Quick check
$PY contrib/chronik-parity/parity_chain.py \
    --build-a build/ecash-rust --build-b build/ecash-rust --blocks 120

# V2 tier (v7 transactions, no SLP/ALP; the V2 tier needs --no-tokens)
$PY contrib/chronik-parity/parity_chain.py \
    --build-a build/v2-rust --build-b build/v2-native --no-tokens --blocks 120

# With DB dump comparison (chronik-native-dump: table\tkey_hex\tvalue_hex, sorted)
$PY contrib/chronik-parity/parity_chain.py ... \
    --dump-tool build/native/chronik/native/chronik-native-dump \
    [--dump-mode stopped|live] [--dump-live-arg --readonly]
```

### Options

| Option | Effect |
|--------|--------|
| `--blocks N` | Chain length (≥ 110; default 400) |
| `--checkpoint-interval N` | Blocks between checkpoints (default 50) |
| `--corpus-mode light` | At intermediate checkpoints, query only blocks/txs from the last 60 blocks (the final checkpoint always uses the full corpus) |
| `--max-scripts N` | Cap on the scripts queried per checkpoint (default 400). The V2 tier encodes the value into each output, so almost every output is a separate script |
| `--no-tokens` | No SLP/ALP scenarios, and passes `-chroniktokenindex=0` |
| `--tier auto/ecash/v2` | Transaction format (auto: `v2` when the binary is `lotusd`) |
| `--miner separate/a` | Which node builds the blocks (see "Block production" below) |
| `--no-ws`, `--no-http`, `--no-broadcast` | Skip parts of the run |
| `--allow PATH` | Add an accepted difference (fnmatch on the field path) |
| `--extra-arg-a/-b ARG` | Extra node arguments, e.g. for negative controls |
| `--save-responses` | Keep every raw response pair under `<tmpdir>/responses/` |
| `--keep-going` | Do not stop at the first checkpoint with differences |
| `--seed N` | Scenario RNG seed (default 7). `--randomseed` (framework) defaults to 1 |
| `--portseed N` | Framework port seed. Ports are always ≥ 20000, so they never touch the live ports 10604/10605/8331/18331/19331/11604/12604 |
| `--tmpdir DIR` | Run dir (default `$CHRONIK_PARITY_TMPDIR/run-*`, or `<system temp>/chronik-parity-runs/run-*`). It is kept after the run unless `--cleanup` is given |

The run dir contains:

- `report.json`: the result;
- `records/<checkpoint>.json`: the objects seen;
- `dumps/`: DB dumps, when a dump tool is given;
- `responses/`: raw responses, with `--save-responses`;
- the node datadirs.

The exit status is 0 only if there are no unexpected differences. All nodes
are stopped (or killed on failure) at exit.

### Standalone corpus and compare

```
# Run a recorded corpus against two running Chronik instances
$PY contrib/chronik-parity/corpus.py --record RUN/records/h401-final.json \
    --url-a http://127.0.0.1:PA --url-b http://127.0.0.1:PB \
    [--ws-static] [--save-responses DIR] [--report r.json]

# Compare two saved response files
$PY contrib/chronik-parity/compare.py DIR/cli.A.jsonl DIR/cli.B.jsonl --report r.json
```

## What a run covers

### Chain stream

- **Block production.** By default (`--miner separate`), a third node without
  Chronik, built from `--build-a`, builds every block. A and B both receive
  each block through `submitblock`, and every tx through
  `sendrawtransaction`, in the same order and with the same `setmocktime`.
  `--miner a` mines on A and submits to B, as the design text describes.
  On the V2 Rust tier this is not symmetric (see "Known issues" below).
- **Isolation.** The nodes are never connected.
- **Settings.** All nodes run with `-acceptnonstdtxn=1` and
  `-chronikscripthashindex=1`. `-avalanche=0` is added where the option
  exists, so the run is avalanche-free.
- **Scripts.** Coinbases rotate over P2SH(OP_TRUE), P2PKH, P2PK (33 and 65
  bytes), bare OP_TRUE, an "other" script, and P2SH with a scriptSig LOKAD
  push. Fan-outs create every script kind, and signed P2PKH/P2PK outputs are
  spent again.
- **Mempool.** The run builds mempool chains and consolidations. Unconfirmed
  txs remain at the checkpoints.
- **OP_RETURN.** Outputs include LOKAD pushes (`PRTY`, `TEST`), eMPP
  sections (`LKD1`, `LKD2`), bare OP_RETURN, a short push and a non-LOKAD
  push.
- **Tokens.** These scenarios run in three passes on full runs:
  - SLP fungible: genesis, mint, send that burns 10, invalid overspend, BURN,
    a parse failure, and an unknown token type.
  - NFT1: group genesis, group fan-out, two child geneses, child send, and a
    child genesis without a group input.
  - SLP mint vault: vault setup, genesis, mint before the vault confirms
    ("Missing MINT vault"), and a valid vault mint.
  - ALP: genesis with data and auth pubkey, mint, genesis+send in one tx,
    intentional burn+send, overspend, invalid/unknown sections, an SLP tx
    spending ALP tokens, and a mint with 2 batons.
- **Conflicts.** A mempool tx and its child are double-spent by a block
  (`generateblock`) every few rounds.
- **Canonical-order spends.** Every few rounds a block (`generateblock`)
  holds a chain of 2–4 txs in which each child's txid sorts before its
  parent's, so in the block's canonical order a tx spends a coin created
  later in the same block.
- **Reorgs.** Each run includes four:
  - R1: `invalidateblock` on all nodes, then a longer fork and
    `reconsiderblock`.
  - R2: a competing chain built in Python with a double spend, submitted to
    both nodes. On the V2 tier this falls back to R1.
  - R3: `invalidateblock` of depth 3, a mempool tx, then `reconsiderblock`.
  - R4: replace the tip, then reconsider the stale tip.
- **Final broadcast phase.** These requests change the mempool. Each is sent
  identically to A and then to B:
  - a valid tx, twice (the second time it is already known);
  - a token-burning tx that fails token checks, then the same tx with
    `skip_token_checks`;
  - a batch with a parent and its child;
  - a broadcast with `finalization_timeout_secs=1`;
  - a conflicting batch.

### HTTP corpus at each checkpoint

The corpus runs every 50 blocks, at the end, and also at height 1, where it
opens the first WebSocket stretch. Every route of `chronik-http/src/server.rs`
is queried:

- **Info:** `/blockchain-info` (GET and HEAD), `/chronik-info`,
  `/unconfirmed-txs`.
- **Blocks:**
  - `/block`, `/block-header` (also with `checkpoint_height`) and `/block-txs`
    for every height and hash;
  - stale (reorged-out) block hashes;
  - invalid heights and hashes;
  - `/blocks` and `/block-headers` ranges, including the 500-block limit,
    reversed and negative ranges, and `checkpoint_height` variants.
- **Txs:** `/tx`, `/raw-tx` and `/token` for every txid seen. This includes
  conflicted txs and txs from stale blocks, plus malformed txids.
- **Groups:** `/script/:type/:payload/{history,confirmed-txs,unconfirmed-txs,utxos}`
  for every script, with the scripthash variant. `/token-id/...` covers all
  four sub-routes and `/lokad-id/...` all three.
- **Pagination edges** for history routes:
  - page 0;
  - page_size 1, 200, 201 and 0;
  - malformed and huge values;
  - the last page and one page past it, computed from A's first response;
  - `page=num_txs-1&page_size=1`.
- **Malformed groups:** wrong lengths, unknown types, an oversized "other"
  script.
- **Plugin routes** (disabled), and `/pause` and `/resume` (403).
- **Fallback and methods:** unknown paths, wrong methods (405), OPTIONS on
  every POST route, and GET `/ws` without an upgrade.
- **POST bodies:**
  - good, bad, missing, charset-suffixed, upper-case and non-UTF-8
    Content-Types;
  - empty, garbage and truncated protobuf;
  - a 2,000,000-byte body and a 2,000,001-byte body (413).
- **`/validate-tx`:** never-sent valid txs, a token-burning tx, an overspend,
  sampled mempool and confirmed txs, and junk.
- **`/broadcast-tx(s)`** (no mempool change): confirmed txs, mempool txs,
  junk, an empty batch, and finalization timeouts over the limit.
- **`/script/batch/{utxos,summary}`:** every script up to the limit, exactly
  500, 501 (limit), empty, duplicates, bad type, bad length, scripthash.

The full 400-block run sends about 85,000 requests to each node.

### WebSocket corpus

At every checkpoint the scripted sessions are opened on both nodes, with
identical subscriptions. They record every data frame until the next
checkpoint, where they are quiesced and compared:

| Session | Mode |
|---------|------|
| `blocks`, `txs` | strict |
| one session per script, token id, LOKAD id, scripthash and txid (up to 60) | strict |
| an "errors" session: text frame, garbage, plugin sub, bad type, bad length, oversized script (> 201 bytes), bad token id or txid, short LOKAD id, unsub without sub, empty frame, then a blocks sub | strict |
| `scripts-all`, `tokens-all`, `lokad-all` | set |
| `mixed` (duplicate subs, sub/unsub, every type) | set |

"strict" means the message sequence must be identical. "set" means the set of
distinct messages must be identical.

### DB dumps (optional)

When `--dump-tool` is given, the tool runs at every checkpoint as
`TOOL [--readonly] <datadir>/regtest/indexes/chronik`. Its stdout must be
sorted `table\tkey_hex\tvalue_hex` lines, and the A and B dumps are compared
line by line.

- `--dump-mode stopped` (the default) stops all nodes for a consistent dump,
  then restarts them with the same mocktime.
- `--dump-mode live` dumps while the nodes run. The tool must open the env
  read-only (MDBX read transaction).

## Comparison rules and accepted differences

- **Classes.** Every HTTP pair falls into one of:
  - `identical`: same status, content type, other headers (except `Date`)
    and raw bytes;
  - `parsed_equal`: the bytes differ, but the parsed protobuf messages differ
    only in allow-listed field paths;
  - `different`.
- **Message type.** The expected message is known per route; non-200
  protobuf bodies are parsed as `Error`.
- **Field paths.** Paths look like `TxHistoryPage.txs[3].inputs[0].sats`.
  Allow patterns match the indexed path or the path without indices.
- **Accepted differences:**
  - `ChronikInfo.version` (`FormatFullVersion()` of the host build).
  - The §1 defects (V2 spent-coin txid, per-IP key) are not exercised here.
    Add them with `--allow` once their field paths are known.
- **Two kinds of WebSocket nondeterminism are inherent to Chronik:**
  1. A session merges its subscriptions with `tokio::select!` and
     `select_all`, and drops consecutive identical messages. The interleaving
     across different subscriptions of one session is therefore
     scheduling-dependent, even for one binary. The harness compares
     multi-subscription sessions as sets, and gives every subscription its
     own strict session.
  2. Each subscription channel has a fixed capacity (blocks 16, txs 32,
     groups 16), and overflow silently drops messages, depending on timing.
     The feeder keeps every burst well below capacity:
     - blocks hold at most 6 txs (`generateblock` with ancestor-closed
       chunks);
     - change scripts rotate;
     - reorgs are at most 3 blocks deep;
     - WS sessions are quiesced after every block or reorg event.

## Validation runs

All runs below use `build/ecash-rust` or `build/v2-rust` for both A and B
(same binary), with a stub dump tool where noted.

| Run | Blocks | HTTP requests | WS sessions | Dumps | Result |
|-----|--------|---------------|-------------|-------|--------|
| eCash, miner on A | 400 | 74,312 identical | 474 identical (16,783 msgs) | stub dump, 10 equal | 0 differences |
| eCash, separate miner, 3 token passes | 400 | 85,766 identical | 469 identical (15,597 msgs) | stub dump, 10 equal | 0 differences (850 txs, 25 conflicts, 4 reorgs, 51 token steps) |
| eCash, miner on A | 120 | 10,090 identical | 72 identical | stub dump | 0 differences |
| eCash, separate miner | 120 | 10,096 identical | 72 identical | – | 0 differences |
| V2, `--no-tokens`, separate miner | 120 | 17,322 identical | 66 identical | – | 0 differences |
| V2, `--no-tokens`, separate miner | 400 | ~40k identical per checkpoint through h402 | 66 identical per checkpoint | – | 0 differences through h402; final phase hung on node A (see Known issues) |
| V2, `--miner a` | 110 | 270 differences | 5 differences | – | coinbase script asymmetry (see Known issues) |
| Negative control: B with `-chroniklokadidindex=0` | 110 | 196 `/lokad-id` differences and 1 WS difference | | | detected, exit 1 |

## Known issues

- **V2 Rust tier, `--miner a`.** The node that mines a block indexes its
  coinbase output under a different script than a node that receives the same
  block via `submitblock`. For example,
  `/script/other/0000f2052a01…/history` returns 0 txs on the miner and 25 on
  the receiver; WS script sessions differ the same way. The mined block's
  in-memory outputs keep the legacy template script, while deserialized
  blocks carry the V2 output encoding. This is why `--miner separate` is the
  default. It is probably a Rust V2 defect worth a separate look, since the
  index depends on how the block arrived.
- **V2 400-block run: node A stopped responding during the broadcast phase.**
  Every checkpoint through height 402 was identical. Then the first
  `POST /broadcast-tx` to A timed out after 60 s. A never logged mempool
  PreChecks for the tx, and after 13:36:18 it logged no further RPC
  activity. The next `submitblock` to A then hit the 240 s RPC timeout. B,
  running the same binary, answered every broadcast (504 and 200/400
  responses). The process was alive, so this looks like an intermittent
  lock-up in the Rust broadcast path on lotusd, such as a lock-order
  inversion between the indexer lock and cs_main or the validation queue. It
  did not happen in the 120-block V2 run. No stack trace was captured. To
  reproduce, rerun with `--blocks 400 --no-tokens` and sample the hung
  process.
- **No real DB dump tool yet.** The dump path was exercised only with a stub
  tool that lists file names.
- **Python-built blocks on the V2 tier.** R2 (a competing chain built in
  Python) is not implemented there and falls back to R1.
- **Token scenarios** are asserted only for parity, not for the expected
  token results; the `chronik_token_*` functional tests cover those.
