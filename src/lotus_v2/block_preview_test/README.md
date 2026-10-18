# Pure block-template preview tests

This is a disjoint test packet for `PreviewBlockTemplate` and its shared exact
transaction evaluator. It owns no implementation, chainstate or shared build
registration. The independently owned `block_transition.{h,cpp}` prerequisite
is supplied explicitly through `LOTUS_PREVIEW_CORE_SOURCE` until root integrates
it. Core source reviewed/tested here is `7c8ced2fca581ffd089c4028010a72fbdc68cc46`.

## Fixture and boundary

The new fixture follows existing `test_block_complete.cpp` and
`test_block_checksig.cpp`: an explicitly trusted synthetic parent commits a
large pre-existing coin and monetary record. Its exact history links, fixture
genesis ID, target work, UTXO root and monetary/state-root tuple are bound before
preview evaluation. The synthetic funding is not claimed to arise from genesis.
Existing DevelopmentGenesis coefficients and explicit ASERT arguments are module
test inputs, not selected production/network defaults or a launch profile.

The funding branch executes actual BIP340 CHECKSIG with public test-vector scalar
3, a known x-only key and zero test-only auxiliary bytes. The signature is created
through native signing and independently checked through native BIP340 verify.
A one-byte signature mutation demonstrably fails verification. The fixture also
previews an ordered dependent transaction spending that signed parent's output.
No existing golden or test source is modified.

Every preview receives a fresh private map/tree overlay backed by the same
external authenticated parent image. The overlay records root reads, coin reads,
mutations and Abort. Success and every tested failure require exactly one Abort,
discarded private contents and byte-identical external parent coins. All fields
of caller preview output are compared against a sentinel on failures. Compile
checks establish distinct Preview/Accepted result types and absence of a block-ID
or failure-proof field in the preview output. This output is an unsealed template
and resource observation, not accepted status or an invalidity proof.

Tests cover:

- Actual signed ready transaction, exact canonical full framing/roundtrip and
  coinbase/frame-prefix byte counts; resulting coins, invocation/effective costs,
  monetary record and state root compared with lower-level calculations.
- Separately sealed and PoW-mined output admitted through StageCompleteBlock with
  identical roots/money/costs; a deliberately failing nonce rejected at the PoW
  gate with no coin reads/mutations or deterministic failure proof.
- Stage's unchanged complete, commitment-matching invalid signature still creates
  an exact identity/profile/parent-state failure proof; provider error clears a
  stale proof, and operational host execution failure produces no proof.
- Preview invalid signature, truthful nonexistent-outpoint lookup, wrong returned
  outpoint, provider read/mutation failures and exceptions after private mutation,
  and provider root exceptions, all with abort and unchanged caller output.
- Real local VM step guard and unavailable/invalid local cost configuration yield
  Inconclusive. Current authenticated native execution implements its assigned
  opcodes; the suite does not invent an unsupported opcode or pretend the host
  step guard is literal VmStatus::Unsupported. Both unsupported/operational paths
  share the reviewed Inconclusive boundary; a naturally unsupported VM fixture
  remains separate if a future implementation introduces one.
- First-and-only coinbase, misplaced/missing/duplicate coinbase, derived-height
  mismatch, duplicate TxIDs including different witness variants, and a witness
  beyond the transaction profile's byte bound.
- Nonzero insufficient count/byte limits, exact successful limits and zero-limit
  local configuration; refusals precede coin reads/mutations and complete-block
  copies. Parent authentication deliberately precedes local quota refusal.
- Candidate time at/beyond bounds, malformed history/profile, mismatched parent
  root/work, independently required ASERT target differing from parent bits, and
  reversed signed-parent dependency order.

The lower-level calculations are native module oracles, not a new independent
protocol reference implementation. Full disk preview/assembler, durable-store
atomicity, networking, mining and node acceptance are separate owners/gates.

## Build and focused validation

```sh
cmake -S src/lotus_v2/block_preview_test -B /tmp/lotus-v2-preview-build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DLOTUS_PREVIEW_CORE_SOURCE=/absolute/native/src/lotus_v2 -DLOTUS_SECP_LIBRARY=/absolute/path/libsecp256k1.a
cmake --build /tmp/lotus-v2-preview-build
ctest --test-dir /tmp/lotus-v2-preview-build --output-on-failure
```

The standalone target builds the new preview suite plus the unchanged existing
complete-block and CHECKSIG suites against the same borrowed evaluator. It
copies or modifies no prerequisite source and needs no sockets or disk homes.
`LOTUS_PREVIEW_CORE_SOURCE` defaults to the local module directory after root
integration. Root owns full-tree registration of the new test.

Use a fresh build with `-DLOTUS_SANITIZE=ON` for ASan+UBSan on the C++ evaluator,
module and test sources. The separate BLAKE3 C and supplied secp libraries remain
unchanged. Fixture nonce searches, history, transaction lists and cap tests are
explicitly bounded; no wall-clock benchmark or maximum-RSS claim is made.

Packet evidence (2026-10-15), base `9345b70ec`, borrowed core `7c8ced2fc`
(integrated by root as `14c99c342`): Debug 3/3 passed in 0.41 seconds and
ASan+UBSan 3/3 passed in 1.20 seconds. The core owner independently reran the
initial Debug three-suite gate successfully before committing its source packet.
