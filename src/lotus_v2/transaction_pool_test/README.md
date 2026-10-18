# Bounded native V2 transaction pool

This standalone native test uses the real ordinary validator, VM and authenticated
transaction cost calculation. It does not start a node or establish block validity.

```sh
cmake -S src/lotus_v2/transaction_pool_test -B /tmp/lotus-v2-pool-build \
  -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a \
  -DLOTUS_BOOST_INCLUDE=/path/to/boost/include
cmake --build /tmp/lotus-v2-pool-build -j4
ctest --test-dir /tmp/lotus-v2-pool-build --output-on-failure
```

Coverage includes parent/child and diamond ordering, inventory TxHash versus
TxID lookup, first accepted witness retention, conflicting spends, missing versus
known-spent active inputs, actual VM rejection, byte/entry/edge/ancestor/descendant
and authenticated transaction cost caps, validation/invocation budgets, maturity
and absolute-time lock revalidation, confirmed parent survival, connected conflict
descendant removal, child-first detached resurrection, stale anchor fences and
storage failure preservation with disabled serving followed by successful retry.

The caller serializes pool access and owns the stable backend snapshot and
current-context fence. Context height and parent MTP apply to the next candidate
block. CoinLookup reads only referenced active coins; accepted parent outputs form
an overlay, and no active UTXO map is copied. Optional classify_missing distinguishes
a known active spent output from an unknown parent; absent classification means
unknown. Reconcile must run after authoritative connect/disconnect changes before
serving or mining. Its operational/stale/capacity failure retains old data while
disabling reads. The caller must retry, or discard the pool explicitly.

Limits are explicit development policy, not protocol defaults. max_ancestors and
max_descendants exclude the transaction itself. Reconcile bounds its entire input
and retries missing-parent candidates in dependency passes; exhausted validation
budget disables the old view for a caller-scheduled retry. No orphans, replacement,
persistence, relay punishment or transaction status history are implemented here.
The relay owns bounded missing-parent retries, and the coordinator owns authoritative
transition/status history. The pool computes both authenticated linear costs and
applies a local per-transaction cap. Mining must still use BuildTemplate and normal
block validation for effective/parabolic fees, block resources and commitments.
