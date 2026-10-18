#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end 3-node native Lotus V2 + Chronik + 1KB BigInt VM + Persistence acceptance test.

Exercises:
1. 3-node `lotusd -regtest -chronik=1` cluster over real AppInitMain (CConnman +
   net_processing + httprpc + libmdbx CDBWrapper + in-process libmdbx Chronik).
2. 134-byte V2 header mining, non-null advancing hashStateRoot (UtxoSet +
   AdvanceMonetary), and P2P block/header sync across all 3 nodes.
3. Native V2 v7 transactions exercising:
   a) Multi-input spend with cross-input introspection (CoinAt(i).value 0xd6,
      OutputAt(i).value 0xe1)
   b) >16-byte (64-byte + 32-byte) BigInt arithmetic (ADD 0x9e, NUMEQUALVERIFY 0xa7)
      and mismatched-length zero-padded bitwise (XOR 0x90, EQUALVERIFY 0x92)
   c) Invalid V2 witness rejection (v2-tx-eval-failed)
   d) Token mint (nFlags == 3) and token transfer ((nFlags & 1) != 0) conservation
4. Live in-process Chronik HTTP queries (/blockchain-info, /block/:hash, /tx/:txid)
   confirming Chronik indexes 134-byte V2 blocks and V2 v7 transactions on libmdbx.
5. Node restart + VerifyDB level-3 check + persisted V2 state restoration +
   post-restart block mining and V2 UTXO spending.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_BUILD_DIR = next(
    (
        os.path.join(REPO_ROOT, d)
        for d in ("out-v2-full", "build", "out-lane-f")
        if os.path.exists(os.path.join(REPO_ROOT, d, "src", "lotusd"))
    ),
    os.path.join(REPO_ROOT, "out-v2-full"),
)
BUILD_DIR = os.environ.get("LOTUS_BUILD_DIR", DEFAULT_BUILD_DIR)
LOTUSD = os.environ.get("LOTUSD", os.path.join(BUILD_DIR, "src", "lotusd"))
LOTUS_CLI = os.environ.get("LOTUS_CLI", os.path.join(BUILD_DIR, "src", "lotus-cli"))


# =============================================================================
# Pure-Python Single-Block BLAKE3 for Lotus/v2/branch Leaf Hashing
# =============================================================================
BLAKE3_IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]
BLAKE3_MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def _g(state: list, a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 7)


def _round(state: list, m: list) -> None:
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def blake3_single_block(data: bytes) -> bytes:
    assert len(data) <= 64, "Single-block BLAKE3 helper expects <= 64 bytes"
    padded = data + b"\x00" * (64 - len(data))
    m = list(struct.unpack("<16I", padded))
    # flags: CHUNK_START (1) | CHUNK_END (2) | ROOT (8) = 11
    state = list(BLAKE3_IV) + list(BLAKE3_IV[:4]) + [0, 0, len(data), 11]
    for r in range(7):
        _round(state, m)
        if r < 6:
            m = [m[BLAKE3_MSG_PERM[i]] for i in range(16)]
    out_words = [state[i] ^ state[i + 8] for i in range(8)]
    return struct.pack("<8I", *out_words)


def compact_size(n: int) -> bytes:
    if n < 253:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def branch_leaf(script: bytes) -> bytes:
    tag = b"Lotus/v2/branch\x00\x00"
    return blake3_single_block(tag + compact_size(len(script)) + script)


# =============================================================================
# Native V2 v7 Transaction Serialization Helpers
# =============================================================================
def ser_bytes(b: bytes) -> bytes:
    return compact_size(len(b)) + b


def ser_v2_spend_input(
    prev_txid_le: bytes,
    prev_vout: int,
    script: bytes,
    arguments: list = None,
    siblings: list = None,
    path_index: int = 0,
    sequence: int = 0xFFFFFFFF,
) -> bytes:
    assert len(prev_txid_le) == 32
    if arguments is None:
        arguments = []
    if siblings is None:
        siblings = []
    out = prev_txid_le + struct.pack("<IIB", prev_vout, sequence, 1)
    out += compact_size(path_index)
    out += compact_size(1)  # 1 branch witness
    out += ser_bytes(script)
    out += compact_size(len(siblings)) + b"".join(siblings)
    out += compact_size(len(arguments)) + b"".join(ser_bytes(a) for a in arguments)
    return out


def ser_v2_mint_input(
    token_id_le: bytes,
    script: bytes,
    arguments: list = None,
    siblings: list = None,
) -> bytes:
    assert len(token_id_le) == 32
    if arguments is None:
        arguments = []
    if siblings is None:
        siblings = []
    out = token_id_le + struct.pack("<IIB", 0, 0xFFFFFFFF, 3)
    out += ser_bytes(script)
    out += compact_size(len(siblings)) + b"".join(siblings)
    out += compact_size(len(arguments)) + b"".join(ser_bytes(a) for a in arguments)
    return out


def ser_v2_output(
    value: int,
    branch_root: bytes,
    flags: int = 0,
    token_id_le: bytes = b"",
) -> bytes:
    assert len(branch_root) == 32
    out = struct.pack("<BQ", flags, value)
    if (flags & 1) != 0:
        assert len(token_id_le) == 32
        out += token_id_le
    out += compact_size(1) + branch_root
    # 1 path: [0]
    out += compact_size(1) + compact_size(1) + compact_size(0)
    return out


def build_v7_tx(inputs: list, outputs: list, lock: int = 0) -> str:
    raw = struct.pack("<IQHH", 7, lock, len(inputs), len(outputs))
    raw += b"".join(inputs)
    raw += b"".join(outputs)
    return raw.hex()


# =============================================================================
# Node Cluster Management & Chronik HTTP Helper
# =============================================================================
class LotusNode:
    def __init__(
        self, idx: int, base_dir: str, p2p_port: int, rpc_port: int, chronik_port: int
    ):
        self.idx = idx
        self.datadir = os.path.join(base_dir, f"node{idx}")
        os.makedirs(self.datadir, exist_ok=True)
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.chronik_port = chronik_port
        self.proc = None
        self.log_path = os.path.join(self.datadir, "node_console.log")
        self.log_file = None

    def start(self, extra_args=None):
        if extra_args is None:
            extra_args = []
        self.log_file = open(self.log_path, "ab")
        cmd = [
            LOTUSD,
            "-regtest",
            f"-datadir={self.datadir}",
            f"-port={self.p2p_port}",
            f"-bind=127.0.0.1:{self.p2p_port}",
            f"-rpcport={self.rpc_port}",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-rpcuser=lotusv2",
            "-rpcpassword=lotusv2pass",
            "-chronik=1",
            f"-chronikbind=127.0.0.1:{self.chronik_port}",
            "-listen=1",
            "-listenonion=0",
            "-dnsseed=0",
            "-discover=0",
            "-upnp=0",
            "-natpmp=0",
            "-acceptnonstdtxn=1",
            "-checkblocks=6",
            "-checklevel=3",
        ] + extra_args
        self.proc = subprocess.Popen(
            cmd, stdout=self.log_file, stderr=subprocess.STDOUT
        )
        self.wait_for_rpc()
        self.wait_for_chronik()

    def tail_log(self, max_bytes: int = 4096) -> str:
        if not os.path.exists(self.log_path):
            return ""
        with open(self.log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes), os.SEEK_SET)
            return f.read().decode("utf-8", errors="replace")

    def rpc(self, *args) -> str:
        if self.proc is not None and self.proc.poll() is not None:
            raise RuntimeError(
                f"Node {self.idx} process exited unexpectedly (rc={self.proc.returncode}):\n{self.tail_log()}"
            )
        cmd = [
            LOTUS_CLI,
            "-regtest",
            f"-datadir={self.datadir}",
            f"-rpcport={self.rpc_port}",
            "-rpcuser=lotusv2",
            "-rpcpassword=lotusv2pass",
            "-rpcclienttimeout=30",
        ] + [str(a) for a in args]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(
                f"Node {self.idx} RPC {args} failed (rc={res.returncode}): {res.stderr.strip()}\nLog tail:\n{self.tail_log(1024)}"
            )
        return res.stdout.strip()

    def send_and_get_txid(self, raw_hex: str) -> str:
        import json

        decoded = json.loads(self.rpc("decoderawtransaction", raw_hex))
        self.rpc("sendrawtransaction", raw_hex)
        return decoded["txid"]

    def wait_for_rpc(self, timeout: float = 30.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"Node {self.idx} exited early (rc={self.proc.returncode}):\n{self.tail_log()}"
                )
            try:
                self.rpc("getblockcount")
                return
            except Exception:
                time.sleep(0.2)
        raise TimeoutError(
            f"Node {self.idx} RPC did not become ready within {timeout}s"
        )

    def chronik_get(self, path: str) -> bytes:
        url = f"http://127.0.0.1:{self.chronik_port}{path}"
        with urllib.request.urlopen(url, timeout=5.0) as resp:
            assert resp.status == 200, (
                f"Expected HTTP 200 from {url}, got {resp.status}"
            )
            return resp.read()

    def chronik_get_json(self, path: str) -> dict:
        import json

        return json.loads(self.chronik_get(path).decode("utf-8"))

    def chronik_post_json(self, path: str, payload: dict) -> dict:
        import json

        url = f"http://127.0.0.1:{self.chronik_port}{path}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            assert resp.status == 200, (
                f"Expected HTTP 200 from {url}, got {resp.status}"
            )
            return json.loads(resp.read().decode("utf-8"))

    def wait_for_chronik(self, timeout: float = 30.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.chronik_get("/blockchain-info")
                return
            except Exception:
                time.sleep(0.2)
        raise TimeoutError(
            f"Node {self.idx} Chronik HTTP did not become ready within {timeout}s"
        )

    def stop(self, timeout: float = 30.0):
        if self.proc is None or self.proc.poll() is not None:
            if self.log_file is not None:
                self.log_file.close()
                self.log_file = None
            return
        try:
            self.rpc("stop")
        except Exception:
            self.proc.terminate()
        self.proc.wait(timeout=timeout)
        self.proc = None
        if self.log_file is not None:
            self.log_file.close()
            self.log_file = None


def wait_until(predicate, description: str, timeout: float = 20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise TimeoutError(f"Timed out waiting for: {description}")


def main():
    import json

    assert os.path.exists(LOTUSD), f"lotusd binary not found at {LOTUSD}"
    assert os.path.exists(LOTUS_CLI), f"lotus-cli binary not found at {LOTUS_CLI}"

    tmp_dir = tempfile.mkdtemp(prefix="lotus_v2_native_e2e_")
    nodes = [
        LotusNode(0, tmp_dir, p2p_port=29110, rpc_port=29111, chronik_port=29112),
        LotusNode(1, tmp_dir, p2p_port=29120, rpc_port=29121, chronik_port=29122),
        LotusNode(2, tmp_dir, p2p_port=29130, rpc_port=29131, chronik_port=29132),
    ]

    try:
        print(
            "=== [1/6] Starting 3-node lotusd + in-process libmdbx Chronik cluster ==="
        )
        for node in nodes:
            node.start()

        for node in nodes:
            node.rpc("createwallet", f"wallet{node.idx}")

        # Connect Node 0 <-> Node 1 <-> Node 2
        nodes[0].rpc("addnode", f"127.0.0.1:{nodes[1].p2p_port}", "onetry")
        nodes[1].rpc("addnode", f"127.0.0.1:{nodes[2].p2p_port}", "onetry")
        nodes[0].rpc("addnode", f"127.0.0.1:{nodes[2].p2p_port}", "onetry")

        wait_until(
            lambda: all(int(n.rpc("getconnectioncount")) >= 2 for n in nodes),
            "all 3 nodes interconnected over P2P",
        )
        print("  -> All 3 nodes connected over P2P (CConnman + net_processing).")

        print(
            "=== [2/6] Verifying 134-byte V2 header mining, hashStateRoot, and 3-node sync ==="
        )
        addr0 = nodes[0].rpc("getnewaddress")
        nodes[0].rpc("generatetoaddress", 105, addr0)

        wait_until(
            lambda: all(int(n.rpc("getblockcount")) == 105 for n in nodes),
            "all 3 nodes synced to height 105",
        )

        # Verify 134-byte (268 hex chars) V2 headers and strictly advancing non-null state_root
        state_roots = []
        for h in [1, 2, 50, 104, 105]:
            bhash = nodes[0].rpc("getblockhash", h)
            for n in nodes:
                assert n.rpc("getblockhash", h) == bhash, (
                    f"Block hash mismatch at height {h}"
                )
            hdr_hex = nodes[0].rpc("getblockheader", bhash, "false")
            assert len(hdr_hex) == 268, (
                f"Expected 134-byte (268 hex char) V2 header at height {h}, got {len(hdr_hex)}"
            )
            hdr_bytes = bytes.fromhex(hdr_hex)
            state_root = hdr_bytes[102:134]
            assert state_root != b"\x00" * 32, (
                f"Expected non-null hashStateRoot at height {h}"
            )
            state_roots.append(state_root)

        assert len(set(state_roots)) == len(state_roots), (
            "Expected hashStateRoot to advance distinctly across blocks"
        )
        print(
            "  -> 134-byte V2 headers verified; hashStateRoot advances deterministically across all 3 nodes."
        )

        print(
            "=== [3/6] Testing Native V2 v7 Multi-Input Introspection + 1KB BigInt + Mismatched Bitwise ==="
        )
        # Combined 12-byte Lotus V2 VM script:
        #   0x9e (ADD): pops 32-byte bigint_b, pops 64-byte bigint_a, pushes 64-byte sum
        #   0xa7 (NUMEQUALVERIFY): verifies 64-byte sum == 64-byte bigint_expected
        #   0x90 (XOR): pops 8-byte bw_b, pops 4-byte bw_a (zero-padded to 8 bytes), pushes 8-byte XOR
        #   0x92 (EQUALVERIFY): verifies 8-byte XOR == 8-byte bw_expected
        #   0x00 (OP_0) 0xd6 (CoinAt(0).value)
        #   0x4e (OP_1) 0xd6 (CoinAt(1).value)
        #   0x9e (ADD)
        #   0x00 (OP_0) 0xe1 (OutputAt(0).value)
        #   0xac (GREATERTHANOREQUAL)
        combined_script = bytes(
            [0x9E, 0xA7, 0x90, 0x92, 0x00, 0xD6, 0x4E, 0xD6, 0x9E, 0x00, 0xE1, 0xAC]
        )
        combined_root = branch_leaf(combined_script)

        # Simple OP_1 (0x4e in Lotus V2 VM) branch root
        op1_script = b"\x4e"
        op1_root = branch_leaf(op1_script)

        unspent = json.loads(nodes[0].rpc("listunspent", 1, 9999))
        assert len(unspent) >= 3, "Expected at least 3 mature coinbase UTXOs"

        def fund_v2_output(utxo, branch_root: bytes, amount_sats: int) -> tuple:
            txid_le = bytes.fromhex(utxo["txid"])[::-1]
            vout_n = int(utxo["vout"])
            in_sats = int(round(float(utxo["amount"]) * 100))
            change_sats = in_sats - amount_sats - 2000
            change_addr = nodes[0].rpc("getnewaddress")
            addr_info = json.loads(nodes[0].rpc("getaddressinfo", change_addr))
            change_spk = bytes.fromhex(addr_info["scriptPubKey"])

            # Encode V2 output wire format into scriptPubKey so CTxOut::ToV2Output decodes it
            v2_out_wire = ser_v2_output(amount_sats, branch_root)

            raw = struct.pack("<i", 2)
            raw += compact_size(1)
            raw += (
                txid_le
                + struct.pack("<I", vout_n)
                + b"\x00"
                + struct.pack("<I", 0xFFFFFFFF)
            )
            raw += compact_size(2)
            raw += struct.pack("<q", amount_sats) + ser_bytes(v2_out_wire)
            raw += struct.pack("<q", change_sats) + ser_bytes(change_spk)
            raw += struct.pack("<I", 0)

            signed = json.loads(nodes[0].rpc("signrawtransactionwithwallet", raw.hex()))
            assert signed["complete"], f"Failed to sign funding tx: {signed}"
            funded_txid = nodes[0].send_and_get_txid(signed["hex"])
            return funded_txid, 0, amount_sats

        fund_txid_1, fund_vout_1, fund_val_1 = fund_v2_output(
            unspent[0], combined_root, 50_000_000
        )
        fund_txid_2, fund_vout_2, fund_val_2 = fund_v2_output(
            unspent[1], combined_root, 60_000_000
        )
        fund_txid_3, fund_vout_3, fund_val_3 = fund_v2_output(
            unspent[2], op1_root, 40_000_000
        )

        # Mine the funding transactions and sync all 3 nodes
        nodes[0].rpc("generatetoaddress", 1, addr0)
        wait_until(
            lambda: all(int(n.rpc("getblockcount")) == 106 for n in nodes),
            "all 3 nodes synced to height 106",
        )

        # Construct 64-byte and 32-byte little-endian two's complement BigInts for Lane E VM test
        val_a = (1 << 400) + (1 << 200) + 0x123456789ABCDEF0
        val_b = (1 << 180) + 0x0FEDCBA987654321
        val_sum = val_a + val_b
        bigint_a_64 = val_a.to_bytes(64, "little", signed=True)
        bigint_b_32 = val_b.to_bytes(32, "little", signed=True)
        bigint_expected_64 = val_sum.to_bytes(64, "little", signed=True)

        # Construct mismatched-length bitwise operands: 4-byte ^ 8-byte
        bw_a_4 = bytes.fromhex("11223344")
        bw_b_8 = bytes.fromhex("ff00ff0055667788")
        bw_expected_8 = bytes(
            (bw_a_4 + b"\x00\x00\x00\x00")[i] ^ bw_b_8[i] for i in range(8)
        )

        # First test negative case: corrupted 64-byte expected sum must be rejected by mempool
        bad_expected_64 = (val_sum + 1).to_bytes(64, "little", signed=True)
        bad_args = [
            bw_expected_8,
            bw_a_4,
            bw_b_8,
            bad_expected_64,
            bigint_a_64,
            bigint_b_32,
        ]
        bad_txin_0 = ser_v2_spend_input(
            bytes.fromhex(fund_txid_1)[::-1], fund_vout_1, combined_script, bad_args
        )
        bad_txin_1 = ser_v2_spend_input(
            bytes.fromhex(fund_txid_2)[::-1], fund_vout_2, combined_script, bad_args
        )
        introspect_out_val = fund_val_1 + fund_val_2 - 2000
        txout_0 = ser_v2_output(introspect_out_val, op1_root)

        bad_v7_hex = build_v7_tx([bad_txin_0, bad_txin_1], [txout_0])
        rejected = False
        try:
            nodes[0].rpc("sendrawtransaction", bad_v7_hex)
        except RuntimeError as exc:
            assert "mandatory-script-verify-flag-failed" in str(
                exc
            ) or "v2-tx-eval-failed" in str(exc), (
                f"Unexpected error for bad witness: {exc}"
            )
            rejected = True
        assert rejected, "Expected invalid 64-byte BigInt witness to be rejected"
        print(
            "  -> Invalid V2 v7 witness properly rejected by V2 VM (mandatory-script-verify-flag-failed)."
        )

        # Now submit valid v7 transaction spending both inputs with combined_script
        good_args = [
            bw_expected_8,
            bw_a_4,
            bw_b_8,
            bigint_expected_64,
            bigint_a_64,
            bigint_b_32,
        ]
        good_txin_0 = ser_v2_spend_input(
            bytes.fromhex(fund_txid_1)[::-1], fund_vout_1, combined_script, good_args
        )
        good_txin_1 = ser_v2_spend_input(
            bytes.fromhex(fund_txid_2)[::-1], fund_vout_2, combined_script, good_args
        )
        good_v7_hex = build_v7_tx([good_txin_0, good_txin_1], [txout_0])
        v7_introspect_txid = nodes[1].send_and_get_txid(good_v7_hex)
        print(
            f"  -> Valid multi-input V2 v7 BigInt+Bitwise+Introspection tx accepted: {v7_introspect_txid}"
        )

        # Wait for P2P mempool relay to Node 0 and Node 2, then mine on Node 0
        wait_until(
            lambda: v7_introspect_txid in nodes[0].rpc("getrawmempool"),
            "v7_introspect_txid relayed to Node 0 mempool",
        )
        nodes[0].rpc("generatetoaddress", 1, addr0)
        wait_until(
            lambda: all(int(n.rpc("getblockcount")) == 107 for n in nodes),
            "all 3 nodes synced to height 107",
        )
        print(
            "  -> Mined V2 v7 BigInt+Bitwise+Introspection tx in block 107 and synced across all 3 nodes."
        )

        print(
            "=== [4/6] Testing Native V2 v7 Token Mint (nFlags == 3) and Token Transfer (nFlags == 1) ==="
        )
        # Mint script: 0x9d (OP_0NOTEQUAL). For a mint input (nFlags == 3), the V2 VM pushes the
        # 16-byte signed token delta onto the initial stack before executing the mint script.
        # 0x9d pops the non-zero 16-byte positive delta and pushes 1 (true).
        mint_script = b"\x9d"
        token_id_le = branch_leaf(mint_script)  # 32-byte token_id == prevout.txid

        mint_amount = 777_000

        # Input 0: spend the funded op1_root XPI UTXO (fund_txid_3:0)
        mint_txin_0 = ser_v2_spend_input(
            bytes.fromhex(fund_txid_3)[::-1], fund_vout_3, op1_script
        )
        # Input 1: token mint pseudo-input (nFlags == 3) with prev_txid == token_id_le
        mint_txin_1 = ser_v2_mint_input(token_id_le, mint_script)

        # Output 0: minted token output (flags == 1, value == mint_amount, token_id == token_id_le)
        mint_txout_0 = ser_v2_output(
            value=mint_amount,
            branch_root=op1_root,
            flags=1,
            token_id_le=token_id_le,
        )
        # Output 1: XPI change output (flags == 0, value == fund_val_3 - 2000)
        mint_xpi_change = fund_val_3 - 2000
        mint_txout_1 = ser_v2_output(
            value=mint_xpi_change,
            branch_root=op1_root,
            flags=0,
        )

        mint_v7_hex = build_v7_tx(
            [mint_txin_0, mint_txin_1],
            [mint_txout_0, mint_txout_1],
        )
        v7_mint_txid = nodes[0].send_and_get_txid(mint_v7_hex)
        print(f"  -> Native V2 v7 Token Mint tx accepted: {v7_mint_txid}")

        nodes[0].rpc("generatetoaddress", 1, addr0)
        wait_until(
            lambda: all(int(n.rpc("getblockcount")) == 108 for n in nodes),
            "all 3 nodes synced to height 108",
        )

        # Now spend the minted token output (v7_mint_txid:0) AND the XPI change output (v7_mint_txid:1)
        # in a V2 v7 Token Transfer transaction, splitting 777,000 tokens into 500,000 + 277,000.
        transfer_txin_0 = ser_v2_spend_input(
            bytes.fromhex(v7_mint_txid)[::-1], 0, op1_script
        )
        transfer_txin_1 = ser_v2_spend_input(
            bytes.fromhex(v7_mint_txid)[::-1], 1, op1_script
        )
        transfer_txout_0 = ser_v2_output(
            value=500_000,
            branch_root=op1_root,
            flags=1,
            token_id_le=token_id_le,
        )
        transfer_txout_1 = ser_v2_output(
            value=277_000,
            branch_root=op1_root,
            flags=1,
            token_id_le=token_id_le,
        )
        transfer_txout_2 = ser_v2_output(
            value=mint_xpi_change - 2000,
            branch_root=op1_root,
            flags=0,
        )

        transfer_v7_hex = build_v7_tx(
            [transfer_txin_0, transfer_txin_1],
            [transfer_txout_0, transfer_txout_1, transfer_txout_2],
        )
        v7_transfer_txid = nodes[2].send_and_get_txid(transfer_v7_hex)
        print(f"  -> Native V2 v7 Token Transfer tx accepted: {v7_transfer_txid}")

        wait_until(
            lambda: v7_transfer_txid in nodes[0].rpc("getrawmempool"),
            "v7_transfer_txid relayed to Node 0 mempool",
        )
        nodes[0].rpc("generatetoaddress", 1, addr0)
        wait_until(
            lambda: all(int(n.rpc("getblockcount")) == 109 for n in nodes),
            "all 3 nodes synced to height 109",
        )
        print(
            "  -> Mined V2 v7 Token Mint (108) and Token Transfer (109) across all 3 nodes."
        )

        print(
            "=== [5/6] Verifying Live In-Process Chronik HTTP Indexing Across All 3 Nodes ==="
        )
        tip_hash_hex = nodes[0].rpc("getblockhash", 109)
        tip_hash_le = bytes.fromhex(tip_hash_hex)[::-1]

        for node in nodes:
            # 1. /blockchain-info must contain tip_hash_le and height 109 (varint 0x10 0x6d)
            binfo_pb = node.chronik_get("/blockchain-info")
            assert tip_hash_le in binfo_pb, (
                f"Node {node.idx} Chronik /blockchain-info missing tip hash {tip_hash_hex}"
            )
            assert b"\x10\x6d" in binfo_pb, (
                f"Node {node.idx} Chronik /blockchain-info missing height 109"
            )

            # 2. /block/<tip_hash> and /block-txs/<tip_hash> must return 200 and contain expected bytes
            blk_pb = node.chronik_get(f"/block/{tip_hash_hex}")
            assert tip_hash_le in blk_pb, (
                f"Node {node.idx} Chronik /block/{tip_hash_hex} missing block hash"
            )
            blk_txs_pb = node.chronik_get(f"/block-txs/{tip_hash_hex}")
            assert bytes.fromhex(v7_transfer_txid)[::-1] in blk_txs_pb, (
                f"Node {node.idx} Chronik /block-txs/{tip_hash_hex} missing transfer txid"
            )

            # 3. /tx/<txid> for all three V2 v7 transactions (introspect, mint, transfer)
            for txid_hex in [v7_introspect_txid, v7_mint_txid, v7_transfer_txid]:
                tx_pb = node.chronik_get(f"/tx/{txid_hex}")
                assert bytes.fromhex(txid_hex)[::-1] in tx_pb, (
                    f"Node {node.idx} Chronik /tx/{txid_hex} missing txid bytes"
                )
                assert op1_root in tx_pb, (
                    f"Node {node.idx} Chronik /tx/{txid_hex} missing output branch root"
                )

            # 4. /v2/status and /v2/explorer/v1/* live HTTP endpoints
            tip_wire_hex = tip_hash_le.hex()
            v2_st = node.chronik_get_json("/v2/status")
            assert v2_st["ready"] is True, (
                f"Node {node.idx} /v2/status not ready: {v2_st}"
            )
            assert v2_st["snapshot"]["height"] == "109", (
                f"Node {node.idx} /v2/status height mismatch: {v2_st}"
            )
            assert v2_st["snapshot"]["tip"] == tip_wire_hex

            exp_st = node.chronik_get_json("/v2/explorer/v1/status")
            assert exp_st["api_version"] == "1"
            assert exp_st["ready"] is True
            assert exp_st["indexed_anchor"]["height"] == "109"
            assert exp_st["indexed_anchor"]["block_id"] == tip_wire_hex

            exp_blocks = node.chronik_get_json("/v2/explorer/v1/blocks")
            assert exp_blocks["api_version"] == "1"
            assert exp_blocks["data"]["items"][0]["height"] == "109"
            assert exp_blocks["data"]["items"][0]["block_id"] == tip_wire_hex

            for txid_hex in [v7_introspect_txid, v7_mint_txid, v7_transfer_txid]:
                wire_txid = bytes.fromhex(txid_hex)[::-1].hex()
                exp_tx = node.chronik_get_json(
                    f"/v2/explorer/v1/transactions/by-id/{wire_txid}"
                )
                assert exp_tx["api_version"] == "1"
                assert exp_tx["data"]["txid"] == wire_txid

            exp_utxos = node.chronik_post_json(
                "/v2/explorer/v1/branches/utxos",
                {"any_branch": [op1_root.hex()]},
            )
            assert exp_utxos["api_version"] == "1"
            assert len(exp_utxos["data"]["items"]) >= 3

        print(
            "  -> All 3 nodes' in-process libmdbx Chronik instances indexed all V2 blocks and v7 transactions (legacy + /v2/explorer/v1/*)."
        )

        print(
            "=== [6/6] Testing Node Restart, VerifyDB Level-3, and Post-Restart V2 Spending ==="
        )
        # Verify v2_state snapshot file exists on disk for tip
        v2_state_file = os.path.join(
            nodes[0].datadir, "regtest", "v2_state", f"{tip_hash_hex}.bin"
        )
        assert os.path.exists(v2_state_file), (
            f"Missing V2 state snapshot file: {v2_state_file}"
        )

        nodes[0].stop()
        nodes[0].start()
        nodes[0].rpc("loadwallet", "wallet0")
        nodes[0].rpc("addnode", f"127.0.0.1:{nodes[1].p2p_port}", "onetry")
        nodes[0].rpc("addnode", f"127.0.0.1:{nodes[2].p2p_port}", "onetry")

        assert int(nodes[0].rpc("getblockcount")) == 109
        assert nodes[0].rpc("getblockhash", 109) == tip_hash_hex

        # Spend the first output of v7_introspect_txid after restart
        post_restart_txin = ser_v2_spend_input(
            bytes.fromhex(v7_introspect_txid)[::-1], 0, op1_script
        )
        post_restart_txout = ser_v2_output(
            value=introspect_out_val - 2000,
            branch_root=op1_root,
        )
        post_restart_v7_hex = build_v7_tx([post_restart_txin], [post_restart_txout])
        post_restart_txid = nodes[0].send_and_get_txid(post_restart_v7_hex)
        nodes[0].rpc("generatetoaddress", 1, addr0)

        wait_until(
            lambda: all(int(n.rpc("getblockcount")) == 110 for n in nodes),
            "all 3 nodes synced to height 110 after Node 0 restart",
        )

        tip_110_hex = nodes[0].rpc("getblockhash", 110)
        tip_110_wire_hex = bytes.fromhex(tip_110_hex)[::-1].hex()
        post_restart_wire_txid = bytes.fromhex(post_restart_txid)[::-1].hex()
        for node in nodes:
            assert node.rpc("getblockhash", 110) == tip_110_hex
            tx_pb = node.chronik_get(f"/tx/{post_restart_txid}")
            assert bytes.fromhex(post_restart_txid)[::-1] in tx_pb
            exp_st = node.chronik_get_json("/v2/explorer/v1/status")
            assert exp_st["ready"] is True
            assert exp_st["indexed_anchor"]["height"] == "110"
            assert exp_st["indexed_anchor"]["block_id"] == tip_110_wire_hex
            exp_tx = node.chronik_get_json(
                f"/v2/explorer/v1/transactions/by-id/{post_restart_wire_txid}"
            )
            assert exp_tx["data"]["txid"] == post_restart_wire_txid
            assert exp_tx["data"]["location"]["height"] == "110"

        print(
            "  -> Node 0 restarted cleanly, passed VerifyDB level-3, and mined post-restart V2 v7 spend at height 110."
        )
        print(
            "\nALL END-TO-END NATIVE LOTUS V2 + CHRONIK + 1KB BIGINT + PERSISTENCE CHECKS PASSED!"
        )

    finally:
        for node in nodes:
            try:
                node.stop()
            except Exception:
                pass
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
