# Disk state storage candidate

`DiskStateStore` persists both canonical P02 coin records and the collapsed
sparse authenticated tree in Bitcoin ABC's bundled LevelDB. The implementation
uses that library's API directly to keep the isolated review target independent
of `CDBWrapper`'s node-wide logging/system dependencies. It introduces no new
storage engine or dependency. The public API and LevelDB implementation are
separated by a PImpl; callers supply already-validated opaque header, monetary
and auxiliary metadata. This component does not execute consensus or select a
network/profile.

## Version 1 keys and values

| Key | Value |
| --- | --- |
| `V` | `LotusV2State` + version byte 1 + 32-byte identity + 32-byte profile digest |
| `S` | Same schema/identity/profile, root summary, tip ID, framed header/monetary/auxiliary bytes |
| `C` + tx ID + index u32le | Exact `EncodeCoin` bytes |
| `N` + zero-padded logical key prefix + depth u16le | Leaf summary and canonical coin, or branch summary and two child summaries |
| `U` + block/tip ID | Predecessor/successor heads and ordered before/after values of changed `C`/`N` keys |

Tree summaries distinguish empty, one leaf, and multiple leaves, with the exact
P02 digest; no global UTXO count or coin-count limit is required. Branch hashes
include their absolute depth. Zero/one-leaf collapse, little-endian bit order,
empty hashing, proof bitmap and deepest-first siblings use the existing P02
helpers. Logical prefix keys keep tree position stable as its hash changes.

A single sync `WriteBatch` writes changed coin/tree keys, head, schema identity
and profile, and immutable undo. The transaction overlay coalesces shared
ancestors and removes net no-op changes. Disconnect verifies current changed
values and the successor head before atomically restoring predecessor values
and metadata. Undo survives disconnect; reusing a tip ID with different undo
rejects. An aborted transaction writes nothing.

## Memory and storage behavior

Open reads only schema/head/root (and the coin for a singleton root). It checks
the root record and its immediate summaries without claiming to scan or certify
all descendants. Descendants and coin/table agreement are authenticated when
read. Lookup, insert, erase and proofs access a bounded 256-bit path; they never
scan/load all UTXOs. The overlay grows with changed paths/coins in one block,
not the entire set. Clean nodes are not retained in an application cache.

`cache_bytes` bounds LevelDB's LRU block cache. The separately configured write
buffer (minimum 64 KiB), current/immutable memtables, table handles, compaction
buffers and metadata also use memory. `max_pending_bytes` limits retained
overlay key/value payload; it is **not a hard process RAM limit**. Map overhead,
coin objects and temporary undo/WriteBatch encodings add memory. A large block
can exceed this operational budget and must be retried under an adequate
resource configuration; it must not be labeled consensus-invalid.

Disk usage includes immutable undo for every committed branch. No finalized
undo pruning or storage migration is implemented. Deletes create LevelDB
tombstones; normal LevelDB compaction reclaims obsolete mutable versions, while
retained undo continues to occupy disk. A future pruning policy must preserve
supported reorgs. An immutable/content-addressed staging backend could reduce
block-sized memory further, but would also need ownership and unreferenced-node
cleanup. No LevelDB-versus-RocksDB performance result is asserted.

`DiskStateStats` exposes database Gets, distinct dirty coin/node keys, final
batch puts/deletes, logical batch key/value bytes, and overlay payload bytes.
These are operation counters, not physical I/O or write amplification metrics.
Callers serialize access to a store and its single active transaction. A write
or sync error poisons the store until reopen because durability may be
ambiguous; the recovered database may contain the complete previous or complete
new batch. Database, corruption, profile and resource errors are operational.

## Retained metadata reads

`ReadRetainedState(BlockID, optional<RetainedDiskState>&, error)` returns raw
metadata and its historical UTXO root. It rereads `S` with checksums and compares
it to the cached head on every lookup, then uses current `S` or immutable
`U<BlockID>.after`. Success with an empty optional means no directly addressable
record. Failure preserves output and reports an operational error. Historical
undo parsing checks both heads, schema/profile/metadata limits, requested ID,
ordered unique canonical keys, changed-value grammar/hash consistency, exact
framing and trailing bytes. It never compares historical records to live C/N
rows or scans the UTXO set. One current-state read uses one Get; a historical
read or missing ID uses two Gets.

This is a raw storage accessor: it neither revalidates contextual block/VM
acceptance nor proves active-chain membership. A validator-side body wrapper
must authenticate retained header/BlockID, monetary/state commitments, ancestry
and complete body framing/transaction root before exposing bytes. Generic
storage transactions accept opaque metadata, so the presence of a `U` record
alone is not evidence of consensus execution.

Every successful commit retains its own after-head, including its body when
the enclosing validator supplies one; disconnected branches remain retained.
There is no pruning, height index or network availability promise. A nonempty
initial state supplied directly to generic `Open` has only `S`, not its own `U`;
after advancing, its metadata may survive in a child's before-head without
being directly addressable by its own ID. Missing does not claim that no copy
exists elsewhere. The normal development initializer commits genesis and thus
creates its own `U` record.

LevelDB Get materializes the entire undo value, including changed coins/nodes,
before the accessor parses it. Caller body-size limits cannot prevent that
allocation. Temporary head/value parsing and returned metadata add memory;
concurrency, request rate and future dedicated body rows require separate
operational policy. The latest auxiliary contains at most eleven headers and
one exact body; older bodies are in undo heads rather than that window.

Tests cover retained reads through advancement, disconnect, alternate branches
and restart; missing IDs; twelve malformed historical-record cases; unchanged
outputs on error; and current-S corruption. An Env injection rewrites a
persisted S value within an SST read while maintaining a valid block CRC,
proving a valid-but-different head is rejected by the cached-head comparison.
These tests exercise the existing bundled LevelDB, not a substitute engine.

## Reproduce

```sh
cmake -S src/lotus_v2/disk_state_test -B build-disk-state -GNinja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-disk-state -j4
ctest --test-dir build-disk-state --output-on-failure
```

The isolated build exposes the reusable `lotus_v2_disk_state` target (storage
source plus bundled LevelDB linkage); enclosing targets provide existing P02
primitives. Tests compare roots after every one of 4096 inserts and 512 mixed
delete/insert operations with `IncrementalUtxoSet`, and compare exact inclusion
and absence proof structures. The database exceeds the 1 KiB block cache by
more than 100 times; reopen performs at most four Gets. This checks storage
behavior, not a production-size RAM or throughput benchmark.

Additional cases cover multi-leaf/singleton/empty collapse, no-op coalescing,
staging/abort, metadata atomicity, reopen/disconnect, alternate branches and
immutable undo reuse, profile/identity mismatch, operational memory exhaustion,
injected first WAL Append and WAL Sync failures, missing/changed canonical coin
rows, orphan rows, and missing root nodes. Failure artifacts are preserved on
assertion failure. Debug and AddressSanitizer/UndefinedBehaviorSanitizer runs
are the intended local review gates; full daemon integration is separate.
