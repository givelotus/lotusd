# Block validation A/B benchmarks

Tools for comparing two builds (a base and a patched tree) on the block
validation costs that grow with block size: the Merkle root over the
transaction ids, block deserialization (which hashes each transaction for
its id), the UTXO prefetch walk, and connecting a block whose coins are not
in the page cache.

Every driver runs its arms interleaved (A B A B ..., or A B B A with
`--alternate-order`), reports per arm the median over rounds and the range
of the rounds' values, and the ratio of each arm's median to the first
arm's. `--out` keeps every raw sample as JSON. Nothing here hard-codes a
path: arms are given as `NAME=BUILD_DIR_OR_BINARY [extra args]`.

These numbers are only as quiet as the machine. On a shared machine (other
builds, other benchmarks) expect several percent of round-to-round noise;
compare the ranges, not only the medians, and rerun on a quiet machine
before drawing fine conclusions.

## Microbenchmarks (`ab_microbench.py`)

`src/bench/block_validation_scaling.cpp` adds, at several block sizes:

| benchmark | what it measures |
|---|---|
| `BlockMerkleRoot_<n>` | `BlockMerkleRoot` (the single-threaded consensus function) over a block of n transactions, with mutation detection |
| `CheckBlockMerkleRoot_<n>` | the Merkle check of block validation (`IsBlockMutated`, i.e. `CheckMerkleRoot`), recomputed each iteration: where a node computes a received block's root |
| `DeserializeBlock_<n>` | deserializing a block of n small transactions (layout plus one id hash each) |
| `HashBlockTxIds_<n>` | the transaction id hashing part of that alone |
| `CoinsPrefetchWalk_<n>` | `CCoinsViewDB::PrefetchOutpointsAsync` over n random coins of a 500k-coin in-memory database (the walk's CPU cost on a warm cache) |

```sh
contrib/bench/block-validation/ab_microbench.py \
    --arm base=/path/to/base/build --arm patched=/path/to/patched/build \
    --filter 'CheckBlockMerkleRoot_.*' --rounds 7 --min-time 300 --out merkle.json
```

Output: one Markdown table row per benchmark, e.g.

```
| metric | base median [min-max] (ns/unit) | patched median [min-max] (ns/unit) | patched/base |
| CheckBlockMerkleRoot_100000 | 61.2 [58.9-66.0] n=7 | 21.4 [19.8-25.1] n=7 | 0.350 |
```

(values are nanoseconds per transaction, from nanobench's median epoch).

## Cold-cache block connection (`ab_block_connect.py`)

1. Build a fixture once with any bitcoind of the tier (about two minutes):

   ```sh
   contrib/bench/block-validation/ab_block_connect.py fixture \
       --bitcoind /path/to/base/build --dir /tmp/block-connect-fixture
   ```

   This makes a regtest datadir holding 2,000,000 anyone-can-spend coins
   (`--fanout-txs` x `--outputs-per-tx`) and `blocks.hex`: 6 test blocks
   (`--blocks`) of 10,000 transactions (`--txs-per-block`), each spending 2
   (`--inputs-per-tx`) random fixture coins. Coins are spent at random, so
   the inputs are spread over the whole database.

2. Run the arms:

   ```sh
   contrib/bench/block-validation/ab_block_connect.py run \
       --fixture /tmp/block-connect-fixture --rounds 5 \
       --arm base=/path/to/base/build --arm patched=/path/to/patched/build \
       --arm 'patched-off=/path/to/patched/build -blockprefetch=0' \
       --out connect.json
   ```

   For each round and arm it clones the fixture datadir (APFS
   copy-on-write on macOS), starts that arm's bitcoind with `-dbcache=4`
   and `-debug=bench`, and submits the test blocks one by one with
   `submitblock`. Before each block it evicts the UTXO database file
   (`chainstate/mdbx.dat`) from the page cache and checks with `mincore`
   that none of it stayed resident (`resident_before_block` in the JSON).

   Metrics: `submitblock_total_ms` (wall time of the 6 RPCs),
   `connectblock_total_ms` (sum of the node's `Connect total`, i.e.
   ConnectBlock), `connecttip_total_ms` (`Connect block`, ConnectTip
   including flush), and the per-block medians.

Eviction without root: `purge` needs root on macOS. The driver maps the file
and calls `msync(MS_SYNC | MS_INVALIDATE)`, which writes back and then drops
the file's cached pages (what `vmtouch -e` does). On Linux it uses
`fdatasync` and `posix_fadvise(POSIX_FADV_DONTNEED)`. It only evicts files
in its own cloned datadirs. The SSD's own cache and the block files are
not affected.

Limitations: blocks arrive by RPC (`ProcessNewBlock`), not by P2P `block` /
compact block messages; transactions use anyone-can-spend outputs, so script
checks are trivial and the UTXO reads dominate; one node, no peers.
