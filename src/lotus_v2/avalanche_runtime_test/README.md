# Native Avalanche chain policy review

This isolated target exercises the runtime boundary used by the Avalanche poll
adapter. It uses real V2 fork bodies, header validation, monetary transitions,
UTXO commitments and bundled LevelDB sync batches. It does not run a node or
claim network quorum interoperability.

The implementation follows the pinned ABC `1fb7db17` rules audited in
`src/validation.cpp` (`FindMostWorkChain`, `UnparkBlockImpl`,
`AvalancheFinalizeBlock`) and `src/net_processing.cpp` block vote handling:
negative block votes park; accepted votes clear the named block and its
ancestors while retaining independent child parks; finality is active-chain-only
and volatile; conflicting forks park. No automatic work-based unparking is
configured, matching Avalanche's default. The optional ABC auto-unpark mode is
not exposed here.

An enabled home is explicit in `DiskStateOptions.avalanche`; its storage schema
binds the policy and ancestry read cap. Existing default homes retain their
schema and strictly heavier selection. Policy ancestry and conflict inventory
work is bounded and may refuse operational capacity without marking a block
consensus-invalid. The runtime provides no mutable backend escape.

`ApplyAvalancheUpdates` validates one expected tip/generation for the complete
response and commits parking changes in one sync batch under stable tip and
inventory revision. It refuses J/R/P recovery fences. Finality publishes after
that batch succeeds. A failed sync revokes cached authority until reopening;
reopening retains parking markers and clears finality. Active parking prepares
an ancestor-only unwind through the existing J/R/P recovery machinery. The
explicit planning switch cannot authorize an unparked or arbitrary weaker fork.

The tests cover mixed fences with no partial mutation, explicit unwind
authority, bounded read refusal, negative-vote separation from consensus
invalidity, independent child parking, restart before and during recovery,
finalized conflict parking (including new headers), active-only finalization,
volatile finality reset and an injected reported failure after durable sync.
Shared immutable runtime fixtures use explicit absolute genesis anchors.

Build from the candidate root:

```sh
cmake -S src/lotus_v2/avalanche_runtime_test -B build-avalanche-runtime-review \
  -G Ninja -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a \
  -DLOTUS_BOOST_INCLUDE=/path/to/boost/include
cmake --build build-avalanche-runtime-review
ctest --test-dir build-avalanche-runtime-review --output-on-failure
```
