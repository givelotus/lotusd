# P2P-v2 loopback load baseline

`p2p-load` is a standalone C++ target linked to `server`. It uses the actual
node dialer, TLS layer, WebSocketSock, Sock::WaitMany, and P2P-v2 serializer
and deserializer. Four workers poll their shares of peers. It does not send
sendcmpct or validate blocks, and answers ping. Received blocks are decoded
by the production framing/transport code and then discarded. Every received
message has a steady-clock timestamp in the JSON output.

Build:

    cmake -GNinja -S . -B /path/to/build -DCMAKE_BUILD_TYPE=Release -DBUILD_CHRONIK=OFF -DBUILD_WALLET=OFF -DBUILD_QT=OFF
    ninja -C /path/to/build p2p-load bitcoind bitcoin-cli
    python3 contrib/p2p-load/run_matrix.py --build /path/to/build --output /path/to/results

The runner raises the descriptor limit to 4096 and starts one isolated regtest
node, maximum 600 connections. All peer connections are in the C++ client;
Python only controls RPC, fixture generation, process sampling and output.
It copies the same stopped-node fixture with APFS clone copies for each run.
The local RPC credentials are fixed benchmark-only strings on loopback.

The reusable fixture contains 150 maturity blocks followed by 20 approximately
8 MB and 20 approximately 32 MB blocks. Each large block spends a mature
coinbase into a fanout transaction and 1000/4000 real child transactions. Each
child spends one UTXO and creates an OP_TRUE output and a varied deterministic
8 KB OP_RETURN output. This intentionally tests a high-entropy byte workload;
it is **not** a representative mainnet transaction or compression corpus.
All blocks pass actual node validation. Exact bytes, transaction counts and
SHA256 hashes are recorded. The serving scenario requests these 40 blocks
plus the 10 preceding small blocks. A separate 32 MB block is submitted only
after every relay peer completes version/verack.

`matrix.json` and `MATRIX.md` are resumable: only successful cells are skipped.
Per-cell files preserve peer/message timestamps, node/client commands, and
separate server/client `ps -M` CPU samples. Serving completion is measured
from each peer's getdata enqueue time; relay completion is measured from the
RPC submission start. Python monotonic and C++ steady clocks must share the
same OS clock (verified on the measured macOS host). Client CPU comes from
getrusage; server per-thread CPU is sampled separately. A timeout or short
block count is a failed cell, never a throughput result.

These are one-run baseline measurements on a shared loopback host, not a WAN
bandwidth result or evidence of a speedup. Linux, Windows and sanitizers have
not been run. Compress-once (Part B) and event-driven I/O are separate work.

The runner guards shared-host resources before and during each cell. The
preflight estimate allows six maximum-size frame buffers per peer across
client and server. By default it refuses cases estimated above 24 GiB, and
stops an active case if combined resident memory exceeds that budget or
system swap grows by 2 GiB. macOS can compress/swap allocations while RSS
stays deceptively small; swap growth is therefore checked independently.
These conservative limits can be changed explicitly on a larger isolated host.
A blocked 250/500-peer cell is not evidence about socket-thread saturation.

The client polls with zero timeout while a WebSocketSock already has buffered
receive bytes, matching the node's buffering semantics. Earlier exploratory
receipts made with an unconditional 10 ms wait are retained as harness pilot
runs and must not be used as final performance attribution.
