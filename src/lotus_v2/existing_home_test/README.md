# Existing home initialization policy checks

Configure this standalone native target with `LOTUS_SECP_LIBRARY` pointing to
an existing ABC `libsecp256k1.a`, then build and run CTest. It uses the bundled
LevelDB/CRC32C and requires OpenSSL and Boost, like `development_chain_test`.

`DiskStateOptions::existing_only` defaults to false. Setting it prevents schema,
empty metadata, and development genesis initialization. Missing `CURRENT` is
checked before engine open, since bundled LevelDB can create a directory/log
with `create_if_missing=false`. Valid existing homes still take the exclusive
LevelDB lock. This is not physical read-only operation: engine WAL/log/manifest
maintenance can occur, including when application validation later refuses.

Coverage includes absent paths, a preexisting directory without CURRENT, a valid
empty LevelDB with CURRENT, initialized schema with empty metadata, missing head,
missing schema, mismatched schema, valid initialized homes, exclusive locking,
already-open output preservation, and ordinary initialization/retry with the
option disabled. Refusal snapshots compare every logical key/value and preserve
caller outputs and supplied initial metadata; they do not assert byte-identical
engine files.

A valid pending recovery journal survives existing-only reopen unchanged. This
option controls initialization only; provisioning/runtime admission must reject
pending recovery separately. The tests use synthetic genesis bytes and perform
no network or production-data operations.
