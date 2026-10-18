# Development initializer checks

Standalone `development_chain_test` exercises caller-supplied, manifest-pinned
synthetic easy-target genesis bytes. It binds no ports and adopts no peer data.
No fixture supplies native issuance or a preloaded funding snapshot.

Configure with `LOTUS_SECP_LIBRARY` pointing to an existing ABC secp256k1 archive,
then build and run CTest. This directory uses the bundled LevelDB/CRC32C through
`disk_state_test`; OpenSSL and Boost are required.

Coverage includes burn pruning, spendable zero-valued genesis coins, exact
header/ID/body/root/monetary persistence, reopen, empty profile-bound store retry,
and invalid genesis rejection before database creation. Root-mutation tests
mine the mutated header again to reach the intended commitment checks rather
than fail opportunistically on PoW. Existing-store identity mismatches and
already-open output arguments preserve existing state.

These are initializer/module checks, not complete daemon acceptance, network
profile selection, peer genesis adoption, clock policy, or best-chain selection.

Retained-body checks exercise exact genesis bytes, historical retrieval after a
raw local checkpoint advance/disconnect/reopen, local response capacities,
missing IDs, and operational rejection of profile, body-root, monetary-work,
state-root and framing mismatches. Every non-available result preserves the
output buffer and stored state. Corrupted-body vectors retain canonical output
framing, header and length, reaching the transaction-root check. Short metadata
rejects even with a zero response capacity.

The raw checkpoint has canonical framing and internally consistent commitments;
it is explicitly not evidence of complete-block monetary/VM acceptance or active
chain membership. Historical retrieval does not rerun those transitions.

Indexed development checks bind the exact header profile at initialization,
compare active tip/height/header records and independently encoded cumulative
work, then verify disconnect/reopen keeps active indexes synchronized while
retaining the disconnected header's ever-connected record. Generic schema stores
are rejected without implicit migration or reset. Synthetic checkpoint commits
supply explicit headers; no complete-block acceptance is claimed for them.

Header-only admission tests deliberately use untrusted body/state commitments.
A mined header becomes HeaderChecked without changing active state or providing
a retained body. Tests cover known IDs, missing parents, wrong height/target/MTP,
alternative genesis, profile mismatch and persistence without active promotion.
Clock eligibility, malicious raw database index corruption, body validation and
best-chain activation remain separate gates.
