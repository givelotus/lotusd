# Native p2p-v2 compression corpus

This is generated **regtest-only** data, captured from a running Lotus node
at commit `0d01962fb2ca07dbd6cd336c5e3a77940947c64f`, tree
`36d903a79a2098e4ff6557180c39fd275a6506ce`. No production data was read or
modified. `corpus-manifest.json` records the binary and capture-script hashes,
message counts and independent format/key checks.

Each JSONL record contains the exact p2p-v2 body (message ID followed by
payload), direction, SHA256 and workload group. The gzip envelope has mtime
zero. The fixture exercises normal block serving as IBD, signed V7 transaction
admission over P2P, 134-byte headers, compact blocks, and addrman responses.
The 80 public-looking addresses are deliberately seeded regtest fixtures.
They were not contacted.

There are four independent workload groups. Each uses a **different** native
BIP340 signing key, disjoint initial block/header ranges, 140 mined funding
blocks, and four blocks containing 20-transaction chains. Group 3 is held out;
it is never given to the trainer. Its transaction bodies and headers have
zero exact overlap with groups 0–2. This is still one small regtest chain,
not a representative mainnet replay or a statistically independent network
sample. Empty/small control messages can naturally repeat between groups.

## Reproduce

Use Python with `zstandard==0.25.0` / zstd 1.5.7, and libzstd 1.5.7. Different
trainer versions may produce different bytes: never silently replace a
published dictionary. The generator strips the trained dictionary's entropy
header and uses only its raw content, as required by both native codecs.

From the source root:

```sh
python contrib/devtools/gen-p2p-zstd-dict-v2.py \
  contrib/testdata/p2p-zstd-v2/corpus.jsonl.gz \
  --size=8192 --output=/tmp/net_zstd_dict_v2_data.h
cmp /tmp/net_zstd_dict_v2_data.h src/net_zstd_dict_v2_data.h
python contrib/devtools/test-p2p-zstd-dict-v2.py
python contrib/devtools/bench-p2p-zstd-dict.py \
  contrib/testdata/p2p-zstd-v2/corpus.jsonl.gz \
  --repetitions=11 --iterations=25 --output=/tmp/dictionary-comparison.json
```

The selected dictionary has 8,076 raw-content bytes (an 8,192-byte trained
container minus its header), SHA256
`15b846b0cc57bfbd0aa14bcd3f0cc505754735e8bab63ad6b3e402302c17ca1a`.
Its size was chosen before held-out measurement, not tuned on validation data.

To generate a fresh corpus, run `test/functional/p2p_zstd_dictionary_capture.py`
with `--corpus=...`, an isolated `--tmpdir=...`, and a normal functional-test
`--configfile=...`. Use `--dictionary-version=1` only against the frozen
pre-training p2p-v2 binary; a binary containing this patch uses the default
version 2. The test signs and submits real native transactions and verifies
that the node accepts them. It does not use a production datadir.

## Measurement meaning

The benchmark alternates V1/V2 and V2/V1 for 11 repetitions, with 25 fresh
trials per point. It reports the median thread CPU per body and exact byte
counts. Shared CDict preparation is excluded, matching the native codec.
Both controls use level 1 and the native session parameters. Bodies smaller
than 64 bytes remain plain and do not advance the compression history, just
as in the node. Cold means a new streaming context for each compressed
message; it does **not** model the separate self-contained compress-once
format. Warm `ALL_MIXED` preserves the captured message order. Other warm
rows isolate each message type rather than model a mixed network stream.
WebSocket/TLS overhead is excluded from byte counts.

On an Apple M5 Max/macOS arm64, the held-out 368 bodies (69,337 raw bytes)
produce 18,839 bytes with V1 and 18,752 with V2 in a warm mixed stream:
**0.46% fewer bytes**, not a large bandwidth or TPS improvement. Cold first
messages produce 50,489 and 48,052 bytes respectively (4.83% fewer). Address
responses regress by two bytes. These exact warm byte counts were also
reproduced using the C++ `P2PZstdSession` implementations for both versions.

CPU measurements use the python-zstandard binding, including its harness
overhead; they are not measurements of the node socket thread. The separate
C++ check verifies bytes and roundtrips, not CPU. Measurements were
interleaved on a heavily loaded shared development machine. Warm mixed CPU was approximately unchanged; do not generalize the
microbenchmark into an end-to-end throughput claim. The raw machine-recorded
comparison and build/functional receipts are delivered separately with the
lane report. No Linux/Windows, mainnet-shaped corpus, sanitizers, or complete
functional-suite validation is claimed here.

Earlier exploratory captures reused the MiniWallet default key or overlapping
header ranges. They are **excluded** from this committed corpus and from its
reported figures. Their larger apparent gains were not promoted as results.
