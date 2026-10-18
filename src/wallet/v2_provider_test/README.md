# Native wallet provider regression tests

This test packet starts at `eaecdb04b`. Its minimal disk fixture is copied from
`src/wallet/test/v2_wallet_tests.cpp` at that revision and uses explicit synthetic
authenticated metadata and coin commits. Proofs come from the real disk sparse
tree. This isolates provider verification; fixture creation does not claim normal
complete-block acceptance, peer synchronization or a network trust bootstrap.

The suite will compare unsigned transaction bytes and verified signed meaning.
BIP340 signatures use fresh auxiliary randomness, so independently signed raw
transaction bytes are not expected to match. Existing wallet SQLite atomic-failure
and reorg tests remain a separate required gate.

## Coverage

The real JSON node provider supplies funding tracking, payment preparation,
signing/ordinary validation and reconciliation. Its unsigned bytes match the disk
adapter exactly; independently signed transactions verify against the same digest
and reduce to the same unsigned intent after removing signatures. Ordinary
validation also authenticates absence at newly created output outpoints.

A separate proof-verifying disk provider injects Stale at anchor observation,
initial lookup, ordinary-validation lookup and final recheck. Export sentinels
remain untouched and subsequent preparation proves no reservation leaked.
StorageError and Inconclusive remain distinct even when returned inside the
ordinary validation lookup callback. Broken successful provider bindings and
outpoint returns are rejected, and caller profile mismatch avoids the provider.
Maturity, reservation and authenticated absence remain enforced.

The JSON exchange uses real disk inclusion and nonmembership proofs. Mutations
cover chain/genesis/profile bindings, UTXO/state roots, monetary bytes, tip header,
history links, coin bytes and proof bitmap. Sibling/history bounds, unknown and
duplicate fields, excess frame bytes and extra JSON lines reject. Valid changed
chain contexts produce Stale for pinned lookup/recheck. Remote typed failures are
preserved; callback failure cannot become authenticated absence.

## Build and evidence

Prerequisites are engine `4dd1ee3570701550186974dce880935efc700bac` and node adapter
`46321a272`, compiled explicitly with this test. Linked reviewed native libraries
come from `/private/tmp/lotus-v2-daemon-runtime-staging-20261015/build` (root source
`eaecdb04b`; unchanged wallet/native library source from the reviewed b968 build).
The standalone recipe checks critical native header hashes against the library
source root to reject mismatched storage ABI.

```sh
cmake -S src/wallet/v2_provider_test -B /tmp/lotus-provider-debug -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DLOTUS_BUILD_DIR=/path/to/reviewed/full-build
cmake --build /tmp/lotus-provider-debug -j 4
ctest --test-dir /tmp/lotus-provider-debug --output-on-failure
```

Use a separate directory and `-DCMAKE_BUILD_TYPE=Release` for optimized tests.
ABC requires assertions enabled, so the recipe explicitly uses `-UNDEBUG` in both
configurations. This optimizes the new test/adapters and wallet objects while
linking the reviewed Debug native dependency archives; it is not a claim of an
independent full-tree Release build.

Both configurations run the new provider suite and the unchanged existing wallet
suite, preserving its SQLite atomic write-failure and reorg gates. Build/test logs
are `/private/tmp/lotus-v2-provider-tests-build.log`,
`/private/tmp/lotus-v2-provider-tests-debug-ctest.log`,
`/private/tmp/lotus-v2-provider-tests-release-build.log`, and
`/private/tmp/lotus-v2-provider-tests-release-ctest.log`.

Only the new test, fixture, standalone recipe and this document belong to this
packet. Borrowed production sources/build products are excluded. No actual socket,
JSON command service, full-node bootstrap or end-to-end node payment is claimed;
those are separate integration gates. Context/proof verification trusts the
explicit local node authority and does not independently establish chain validity.

Final frozen test SHA256 is
`92e0ec3a123332e857705627813818fa1cd1bde126a5a4b125d39a8d0714df69`.
Borrowed node header/source SHA256 values are
`471139152f099c5ca9f8dd44e88e3b6a1169e464d7251f9fa7d3d93aba0868fd` and
`982fd49721ac24855fdf55e2c9eae02583d7b38cacdab85a8480d5e1af2d5bca`.
Final Debug: 2/2 passed in 1.09s. Final optimized Release: 2/2 passed in 1.12s.

## Submission and restart regression

The provider now exchanges `submittransaction` (`wire`, `expected_tip`) and
`transactionstatus` (`txid`, `txhash`, `wire`) through the same private AF_UNIX
channel. `PaymentEngine::Broadcast` and `Status` recover and validate existing
SQLite outgoing bytes while locked. They never sign or release reservations.
Status comes from current node transaction history each time, including a
confirmed transaction becoming pending or conflicted after a reorganization.

The client `pay` command accepts the same recipient/fee request and private
passphrase FD as `sign`, durably reserves the signed transaction, then submits.
`broadcast` and `status` accept `{"txid":"<stored transaction id>"}` without a
passphrase FD. After a lost response, recover IDs with `pending`, query `status`,
and retry `broadcast` with the same ID; never create another payment to retry.
Submission receipts classify acceptance, duplicate, conflict, missing parents,
invalid, capacity refusal, stale tip and inconclusive independently of signing.
Existing `prepare`, `sign`, `export` and explicit `abandon` remain available.

Mock exchange coverage reopens the locked SQLite wallet after signing, injects
an ambiguous submission, verifies a byte-identical duplicate retry, and queries
pending → confirmed → pending → conflicted → unknown history. The input stays
reserved across all observations. This proves client recovery behavior; actual
network relay/mining/reorganization remains an integration gate.

Validation on the anchor-profile native libraries at `49376470e`: standalone
provider and wallet regression suites both pass; strict client syntax check
passes. Build directory: `/private/tmp/lotus-v2-wallet-broadcast-test`.
