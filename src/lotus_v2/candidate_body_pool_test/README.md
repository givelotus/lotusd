# Volatile authenticated candidate-body pool

This packet retains exact candidate bytes after structural/commitment checks. It
uses caller-supplied ChainID, TxProfile, indexed Header, BlockID and resource caps.
There is no genesis/profile adoption, socket, disk persistence or block acceptance.
`RetainedAuthenticated` describes bytes retained in RAM. It does not certify
contextual header/PoW eligibility, coinbase entitlement, locks, VM execution,
monetary accounting, state root or chainstate admission.

`PutAuthenticated` checks body length, resident count/bytes and fixed transaction
count before decoding or copying. It compares the complete serialized header,
checks its size and computed BlockID, then reuses `DecodeBlockWire` for canonical
framing, exact consumption, first-only coinbase, unique identities and TxRoot.
The constructor reuses `EncodeInputCore` on a fixed core input to reject an
unsupported TxProfile; local profile errors never become peer-body malformed
results. Duplicate exact bytes need no decoding/copy or epoch increment. A
conflicting body/header under an existing ID refuses without replacing it.

Resident wire-byte and body-count quotas exclude headers, map/shared ownership
metadata, allocator/vector slack, borrowed input and caller copies. Decode and
identity verification transient allocations are separately bounded by the body
length, transaction-count cap, explicit TxProfile and existing codec grammar;
they are not charged as resident wire bytes. The packet makes no exact RSS bound
or global memory claim. Decoded objects are destroyed before the resident copy.
The enclosing runtime must provide independent transient/workspace budgets and
account for retained pool bytes while a download staging lease is still live.

Pins are move-only const views. Every lease counts against max_pins and charges
its full body's wire length, including repeated pins of one body. Pin acquisition
and copy failure preserve the caller output. Release before replacing a lease if
pin caps are already full. Pinned bodies cannot be evicted. Destruction releases
unpinned bodies; surviving pins retain only their own bytes and shared accounting
until their final release. CopyTo allocates a caller-owned copy under its supplied
cap; the caller must budget this separately.

No insertion triggers eviction. Explicit successful insertions and evictions
increment the availability epoch without wrapping; refused operations, exact
duplicates and pin changes leave it unchanged. At UINT64_MAX new availability
mutations refuse. The initial epoch belongs to the runtime's inventory generation
namespace. A replacement pool must invalidate the combined body epoch; reusing an
old epoch must never revive an old selector observation. Evictions are operational
and bodies remain eligible for re-download, without deterministic-invalid facts.

## Runtime integration contract

The root-owned DownloadManager extension distinguishes RetainedAuthenticated
from Accepted. Its retention callback can call PutAuthenticated synchronously
under the live DownloadReservation. Acquire the pool's independent resident and
transient budgets before copying; release staging after retention returns. Never
map retention success to BodyDisposition::Accepted or claim atomic chain admission.

A CandidateBodyProbe adapter calls Probe with the exact indexed header and cap.
The coordinator must supply role explicitly or use a safe routing priority: source
restoration always uses ReadRetainedBlockBody and required undo, even if the same
ID also exists in the volatile pool. It must not substitute a RAM candidate for
source restoration. Target ReorgBodySource can Pin then CopyTo its caller cap;
PrepareDevelopmentSwitch independently checks target bodies and copies them into
its bounded durable journal before any state mutation. Pool pins may then release.
A unified body epoch must cover relevant inventory changes and pool replacement;
no single callback can infer source/target role from BlockID alone.

## Standalone tests

```sh
cmake -S src/lotus_v2/candidate_body_pool_test -B /tmp/candidate-body-pool \
  -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/candidate-body-pool
ctest --test-dir /tmp/candidate-body-pool --output-on-failure
```

Use Release or `-DLOTUS_SANITIZE=ON` for the additional configurations. The target
retains strict warnings for pool/tests and suppresses only the inherited SHA256
assert-only SelfTest unused-function warning. Root integration adds
candidate_body_pool.cpp to its V2 library and a test_candidate_body_pool executable;
this packet edits no shared build files.

Tests retain framing-authenticated bytes whose coinbase fails the existing
CheckCoinbaseContext helper, proving the narrow retention result. They reject
all truncations and header/ID/TxRoot corruptions, exercise exact byte/count/pin
caps, immutable leases surviving pool destruction, explicit evictions and epoch
exhaustion. An executable-local allocation fail-after-N seam sweeps decode,
identity, resident-copy and map-insertion allocations, and separately fails pin
and output-copy allocations. Every refusal preserves entries/counters/epoch and
caller outputs. No production allocation hook is exposed by the pool.
