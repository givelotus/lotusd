# Overlapping Avalanche update batch regression

Configure with the same native secp256k1 archive used by the runtime suites:

```
cmake -S src/lotus_v2/avalanche_update_batch_test -B /new/build -G Ninja -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a -DCMAKE_BUILD_TYPE=Release
cmake --build /new/build --target avalanche_update_batch_test avalanche_runtime_test -j2
ctest --test-dir /new/build -R '^avalanche_(runtime|update_batch)_test$' --output-on-failure
```

The regression creates 2024 mechanically checked indexed headers and applies
1024 distinct overlapping Accepted updates with the native default 100000-read
budget. These headers are not represented as contextually executed blocks. The
case checks update processing and atomic policy publication, without claiming
body validity or finality. Real connected block fixtures separately check
Finalized/Rejected/Accepted ordering and rejection of parked finalized ancestry.

Additional cases cover bounded cache payload refusal, unique-read budget
refusal, missing headers without an authority fault, and malformed first-miss
headers with authority revocation. Every case uses a fresh temporary home with
an isolated LevelDB MemEnv; all homes are cleaned.

Before the cache repair, exact source `7808120ec6` fails the normal regression
with `1024 overlapping updates: Avalanche ancestry read capacity`.
`--expect-capacity-failure` is an explicit historical mode that checks this
refusal leaves revision, generation, tip and root unchanged. It succeeds only
against the original implementation and is excluded from the normal CTest gate.
The repaired implementation passes the same normal regression and the existing
native Avalanche runtime suite.

The cache covers one serialized ApplyAvalancheUpdates call. Only successful
checked header reads are retained. Cache hits still execute each original
ordered ancestor staging step; they do not skip an earlier rejection. Unique
header reads retain the original budget and database fault behavior. Each entry
reserves sizeof(Hash)+sizeof(IndexedHeader)+34 logical bytes against the existing
pending-byte cap, including the staged policy payload because each staged key
has a cached header. Map nodes and allocator overhead are excluded from this
logical bound. The cache is released before allocating the existing disk policy
vector. No consensus, default voting policy or storage/read limits change.

This repair does not remove bounded refusal for a single ancestry deeper than
the read limit, nor change the separately bounded disk policy candidate scan.
