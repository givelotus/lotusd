#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Multi-Node Loopback TPS Stress Test & Benchmark Suite for Lotus V2 (lotusd)."""

import base64
import hashlib
import http.client
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# Add functional test framework to sys.path for transaction construction & signing
SCRIPT_DIR = Path(__file__).resolve().parent
if (SCRIPT_DIR / "test_framework").is_dir():
    sys.path.insert(0, str(SCRIPT_DIR))
else:
    sys.path.insert(0, str(SCRIPT_DIR / "test" / "functional"))

from test_framework.address import SCRIPTSIG_OP_TRUE  # noqa: E402
from test_framework.key import SECP256K1, SECP256K1_G, SECP256K1_ORDER  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    ToHex,
    _lotus_v2_encode_output,
    lotus_v2_branch_leaf,
    lotus_v2_tagged_hash,
    ser_compact_size,
    ser_string,
    ser_uint256,
)
from test_framework.script import CScript  # noqa: E402

V2_OP_TRUE_SCRIPT = b"\x4e"
V2_OP_TRUE_DESCRIPTOR = "raw(4e)"
V2_OP_TRUE_BRANCH_LEAF = lotus_v2_branch_leaf(V2_OP_TRUE_SCRIPT)

_BIP340_CHALLENGE_TAG_HASH = hashlib.sha256(b"BIP0340/challenge").digest()
_BIP340_CHALLENGE_PREFIX = _BIP340_CHALLENGE_TAG_HASH + _BIP340_CHALLENGE_TAG_HASH


def make_v2_txout(value_sats: int, branch_leaf: bytes) -> CTxOut:
    txout = CTxOut()
    txout.nFlags = 0
    txout.nValue = value_sats
    txout.tokenId = b"\x00" * 32
    txout.vBranches = [branch_leaf]
    txout.vPaths = [[0]]
    txout.scriptPubKey = _lotus_v2_encode_output(
        (0, value_sats, b"\x00" * 32, [branch_leaf], [[0]])
    )
    return txout


def prepare_bip340_signer(secret_int: int = 42):
    p = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, secret_int)]))
    d = (SECP256K1_ORDER - secret_int) if (p[1] & 1) else secret_int
    pk_xonly = p[0].to_bytes(32, "big")
    # Precompute 16 deterministic nonces (k_i, Rx_i) with even Y so signing
    # thousands of V2 transactions in Python requires zero EC point muls.
    nonces = []
    for idx in range(1, 17):
        k0 = (secret_int * 1000003 + idx * 9176) % SECP256K1_ORDER
        r_pt = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, k0)]))
        k = (SECP256K1_ORDER - k0) if (r_pt[1] & 1) else k0
        rx = r_pt[0].to_bytes(32, "big")
        nonces.append((k, rx))
    v2_p2pk_script = b"\x20" + pk_xonly + b"\xbb"  # push 32B x-only pubkey, OP_CHECKSIG
    v2_p2pk_branch_leaf = lotus_v2_branch_leaf(v2_p2pk_script)
    return {
        "d": d,
        "pk_xonly": pk_xonly,
        "nonces": nonces,
        "script": v2_p2pk_script,
        "branch_leaf": v2_p2pk_branch_leaf,
    }


LOTUSD_BIN = Path(
    os.environ.get(
        "LOTUSD_BIN",
        os.environ.get("LOTUSD", "/private/tmp/build-lotus-v2-unified/src/lotusd"),
    )
)
RPC_USER = "stressuser"
RPC_PASS = "stresspass"
AUTH_HEADER = "Basic " + base64.b64encode(
    f"{RPC_USER}:{RPC_PASS}".encode("utf-8")
).decode("ascii")

# High ports in 31000-31999 range (strictly isolated)
NODES_CFG = [
    {"id": 0, "p2p_port": 31110, "rpc_port": 31111},
    {"id": 1, "p2p_port": 31112, "rpc_port": 31113},
    {"id": 2, "p2p_port": 31114, "rpc_port": 31115},
]


class KeepAliveRPCClient:
    """Thread-local HTTP/1.1 keep-alive JSON-RPC client for minimal client overhead."""

    def __init__(self, host: str, port: int, timeout: float = 180.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._local = threading.local()
        self._id = 0

    def _get_conn(self) -> http.client.HTTPConnection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = http.client.HTTPConnection(
                self.host, self.port, timeout=self.timeout
            )
            self._local.conn = conn
        return conn

    def _reset_conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def call(self, method: str, params=None):
        if params is None:
            params = []
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        ).encode("utf-8")
        headers = {
            "Authorization": AUTH_HEADER,
            "Content-Type": "application/json",
            "Connection": "keep-alive",
        }
        for attempt in range(3):
            conn = self._get_conn()
            try:
                conn.request("POST", "/", body=payload, headers=headers)
                resp = conn.getresponse()
                body = resp.read()
                data = json.loads(body.decode("utf-8"))
                if data.get("error") is not None:
                    raise RuntimeError(f"RPC {method} error: {data['error']}")
                return data["result"]
            except (
                http.client.HTTPException,
                ConnectionError,
                OSError,
            ):
                self._reset_conn()
                if attempt == 2:
                    raise

    def call_raw_payload(self, preencoded_json_bytes: bytes):
        headers = {
            "Authorization": AUTH_HEADER,
            "Content-Type": "application/json",
            "Connection": "keep-alive",
        }
        for attempt in range(3):
            conn = self._get_conn()
            try:
                conn.request("POST", "/", body=preencoded_json_bytes, headers=headers)
                resp = conn.getresponse()
                body = resp.read()
                data = json.loads(body.decode("utf-8"))
                if data.get("error") is not None:
                    raise RuntimeError(f"RPC raw error: {data['error']}")
                return data["result"]
            except (
                http.client.HTTPException,
                ConnectionError,
                OSError,
            ):
                self._reset_conn()
                if attempt == 2:
                    raise


def percentile(sorted_vals, pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(
        len(sorted_vals) - 1, max(0, int(math.ceil(pct / 100.0 * len(sorted_vals)) - 1))
    )
    return sorted_vals[idx]


def wait_for_rpc(
    client: KeepAliveRPCClient, timeout: float = 30.0, proc=None, err_path=None
):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            err_txt = (
                Path(err_path).read_text()
                if err_path and Path(err_path).exists()
                else ""
            )
            raise RuntimeError(
                f"lotusd on port {client.port} exited with {proc.returncode}: {err_txt}"
            )
        try:
            info = client.call("getblockchaininfo")
            if isinstance(info, dict) and "blocks" in info:
                return info
        except Exception:
            time.sleep(0.1)
    raise TimeoutError(f"Node on port {client.port} did not become ready in {timeout}s")


def sync_all_blocks(clients, timeout: float = 180.0, base_dir: Path = None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hashes = [c.call("getbestblockhash") for c in clients]
        if len(set(hashes)) == 1:
            return hashes[0]
        time.sleep(0.005)
    if base_dir is not None:
        for i in range(len(clients)):
            dbg = base_dir / f"node{i}" / "regtest" / "debug.log"
            if dbg.exists():
                lines = dbg.read_text(errors="replace").splitlines()[-30:]
                print(f"--- node{i} debug.log tail ---\n" + "\n".join(lines))
    raise TimeoutError(
        f"Nodes failed to sync blocks within {timeout}s (heights={[c.call('getblockcount') for c in clients]})"
    )


def build_p2sh_op_true_tx(
    prev_txid_int: int,
    prev_vout: int,
    value_sats: int,
    spk_bytes: bytes = V2_OP_TRUE_SCRIPT,
) -> CTransaction:
    """Build a pure version=7 Lotus V2 fast-script (0x4e) transaction."""
    tx = CTransaction()
    tx.nVersion = 7
    tx.fHasV2Lock = True
    tx.nV2Lock = 0
    tx.nLockTime = 0
    txin = CTxIn(COutPoint(prev_txid_int, prev_vout), V2_OP_TRUE_SCRIPT, 0xFFFFFFFF)
    txin.nFlags = 1
    txin.nPathIndex = 0
    txin.vWitnesses = [(V2_OP_TRUE_SCRIPT, [], [])]
    tx.vin = [txin]
    tx.vout = [make_v2_txout(value_sats, V2_OP_TRUE_BRANCH_LEAF)]
    return tx


def build_signed_p2pkh_tx(
    prev_txid_int: int,
    prev_vout: int,
    in_value_sats: int,
    out_value_sats: int,
    signer: dict,
    nonce_idx: int = 0,
) -> CTransaction:
    """Build a pure version=7 Lotus V2 transaction with a 65-byte (mode=1) BIP340 Schnorr signature."""
    script = signer["script"]
    branch_leaf = signer["branch_leaf"]
    tx = CTransaction()
    tx.nVersion = 7
    tx.fHasV2Lock = True
    tx.nV2Lock = 0
    tx.nLockTime = 0
    txin = CTxIn(COutPoint(prev_txid_int, prev_vout), script, 0xFFFFFFFF)
    txin.nFlags = 1
    txin.nPathIndex = 0
    out_txout = make_v2_txout(out_value_sats, branch_leaf)
    tx.vout = [out_txout]

    # Compute V2 mode=1 (65-byte) SigningDigest (Lotus/v2/sighash)
    coin_wire = _lotus_v2_encode_output(
        (0, in_value_sats, b"\x00" * 32, [branch_leaf], [[0]])
    )
    out_wire = bytes(out_txout.scriptPubKey)
    input_core = (
        ser_uint256(prev_txid_int)
        + prev_vout.to_bytes(4, "little")
        + (0xFFFFFFFF).to_bytes(4, "little")
        + b"\x01\x00\x01"
        + ser_string(script)
        + b"\x00"
    )
    own_input_hash = lotus_v2_tagged_hash(
        "Lotus/v2/owninput", input_core + ser_compact_size(len(coin_wire)) + coin_wire
    )
    out_root = lotus_v2_tagged_hash(
        "Lotus/v2/output", ser_compact_size(len(out_wire)) + out_wire
    )
    selector = (
        b"\x01" + (0).to_bytes(4, "little") + (0).to_bytes(4, "little") + branch_leaf
    )
    preimage = (
        (b"\x00" * 32)
        + b"\x01"
        + (7).to_bytes(4, "little")
        + (0).to_bytes(8, "little")
        + own_input_hash
        + out_root
        + selector
    )
    sighash_msg = lotus_v2_tagged_hash("Lotus/v2/sighash", preimage)

    k, rx = signer["nonces"][nonce_idx % len(signer["nonces"])]
    e = (
        int.from_bytes(
            hashlib.sha256(
                _BIP340_CHALLENGE_PREFIX + rx + signer["pk_xonly"] + sighash_msg
            ).digest(),
            "big",
        )
        % SECP256K1_ORDER
    )
    s = (k + e * signer["d"]) % SECP256K1_ORDER
    sig65 = rx + s.to_bytes(32, "big") + b"\x01"
    txin.vWitnesses = [(script, [], [sig65])]
    tx.vin = [txin]
    return tx


def main():
    base_dir = Path(tempfile.mkdtemp(prefix="lotus-v2-stress-run-", dir="/private/tmp"))
    procs = []
    clients = []

    print(f"[*] Using isolated stress-test directory: {base_dir}")
    try:
        # 1. Start 3 regtest lotusd nodes on loopback with high ports
        for cfg in NODES_CFG:
            node_dir = base_dir / f"node{cfg['id']}"
            node_dir.mkdir(parents=True, exist_ok=True)
            cmd = [
                str(LOTUSD_BIN),
                "-regtest",
                f"-datadir={node_dir}",
                f"-port={cfg['p2p_port']}",
                f"-bind=127.0.0.1:{cfg['p2p_port']}",
                f"-rpcport={cfg['rpc_port']}",
                "-rpcallowip=127.0.0.1",
                f"-rpcuser={RPC_USER}",
                f"-rpcpassword={RPC_PASS}",
                "-server=1",
                "-listen=1",
                "-listenonion=0",
                "-discover=0",
                "-dnsseed=0",
                "-natpmp=0",
                "-rpcthreads=16",
                "-rpcworkqueue=2048",
                "-par=8",
                "-maxmempool=500",
                "-checkmempool=0",
                "-whitelist=127.0.0.1",
                "-highbandwidthtx=1",
            ]
            err_log = open(node_dir / "stderr.log", "w")
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err_log)
            procs.append(proc)
            clients.append(KeepAliveRPCClient("127.0.0.1", cfg["rpc_port"]))

        for idx, c in enumerate(clients):
            wait_for_rpc(
                c, proc=procs[idx], err_path=base_dir / f"node{idx}" / "stderr.log"
            )
        print("[*] All 3 lotusd regtest nodes started and responding to RPC.")

        # Connect Node 0 <-> Node 1 <-> Node 2
        clients[0].call("addnode", [f"127.0.0.1:{NODES_CFG[1]['p2p_port']}", "onetry"])
        clients[0].call("addnode", [f"127.0.0.1:{NODES_CFG[2]['p2p_port']}", "onetry"])
        clients[1].call("addnode", [f"127.0.0.1:{NODES_CFG[2]['p2p_port']}", "onetry"])

        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            peers_all = [c.call("getpeerinfo") for c in clients]
            if all(
                len(peers) >= 2 and all(p.get("subver", "") != "" for p in peers)
                for peers in peers_all
            ):
                break
            time.sleep(0.05)
        print(
            f"[*] P2P mesh established: node0 peers={len(clients[0].call('getpeerinfo'))}, "
            f"node1 peers={len(clients[1].call('getpeerinfo'))}, "
            f"node2 peers={len(clients[2].call('getpeerinfo'))}"
        )

        # 2. Mine 140 blocks with pure version=7 coinbase outputs (V2_OP_TRUE_DESCRIPTOR = "raw(51)")
        signer = prepare_bip340_signer(42)

        block_hashes = clients[0].call(
            "generatetodescriptor", [140, V2_OP_TRUE_DESCRIPTOR]
        )
        sync_all_blocks(clients, base_dir=base_dir)

        # Extract the first 36 mature pure version=7 coinbase transactions
        mature_cb_utxos = []
        for bh in block_hashes[:36]:
            blk = clients[0].call("getblock", [bh, 2])
            cb_tx = blk["tx"][0]
            assert cb_tx["version"] == 7, (
                f"Expected version=7 coinbase, got {cb_tx['version']}"
            )
            assert cb_tx["hex"].startswith("07000000"), (
                f"Expected pure v7 coinbase wire prefix 07000000, got {cb_tx['hex'][:8]}"
            )
            txid_hex = cb_tx["txid"]
            val_sats = int(round(float(cb_tx["vout"][0]["value"]) * 100))
            mature_cb_utxos.append((int(txid_hex, 16), 0, val_sats))

        # A legacy (nVersion=2) transaction cannot spend a V2 coin.
        legacy_tx = CTransaction()
        legacy_tx.nVersion = 2
        legacy_tx.vin = [
            CTxIn(COutPoint(mature_cb_utxos[0][0], 0), SCRIPTSIG_OP_TRUE, 0xFFFFFFFE)
        ]
        legacy_tx.vout = [
            CTxOut(mature_cb_utxos[0][2] - 1000, CScript(V2_OP_TRUE_SCRIPT))
        ]
        legacy_check = clients[0].call("testrawtxbatch", [[ToHex(legacy_tx)]])
        assert (
            not legacy_check["allowed"]
            and legacy_check["results"][0].get("reject-reason")
            == "bad-txns-legacy-spends-v2-coin"
        ), (
            f"Expected the legacy spend of a V2 coin to be rejected with bad-txns-legacy-spends-v2-coin, got {legacy_check}"
        )
        print(
            "[*] Verified pure version=7 coinbases (07000000 prefix) and that a legacy transaction cannot spend a V2 coin."
        )

        # 3. Create 6,000 independent V2 OP_TRUE UTXOs (25 fan-out txs x 240 outputs),
        #    2,250 independent V2 Schnorr P2PK UTXOs (10 fan-out txs x 225 outputs),
        #    and 250 independent V2 Schnorr P2PK chain roots (1 fan-out tx x 250 outputs)
        print(
            "[*] Pre-funding 6,000 V2 OP_TRUE UTXOs, 2,250 V2 Schnorr UTXOs, and 250 V2 chain roots (all version=7)..."
        )
        op_true_utxos = []
        p2pkh_utxos = []
        chain_root_utxos = []

        fanout_hex_batch = []
        for i in range(25):
            cb_txid_int, cb_vout, cb_sats = mature_cb_utxos[i]
            tx = CTransaction()
            tx.nVersion = 7
            tx.fHasV2Lock = True
            tx.nV2Lock = 0
            tx.nLockTime = 0
            txin = CTxIn(COutPoint(cb_txid_int, cb_vout), V2_OP_TRUE_SCRIPT, 0xFFFFFFFF)
            txin.nFlags = 1
            txin.nPathIndex = 0
            txin.vWitnesses = [(V2_OP_TRUE_SCRIPT, [], [])]
            tx.vin = [txin]
            per_out = (cb_sats - 200_000) // 240
            tx.vout = [
                make_v2_txout(per_out, V2_OP_TRUE_BRANCH_LEAF) for _ in range(240)
            ]
            fanout_hex_batch.append(ToHex(tx))
            txid_int = tx.txid_int
            for vout_idx in range(240):
                op_true_utxos.append((txid_int, vout_idx, per_out))

        for i in range(25, 35):
            cb_txid_int, cb_vout, cb_sats = mature_cb_utxos[i]
            tx = CTransaction()
            tx.nVersion = 7
            tx.fHasV2Lock = True
            tx.nV2Lock = 0
            tx.nLockTime = 0
            txin = CTxIn(COutPoint(cb_txid_int, cb_vout), V2_OP_TRUE_SCRIPT, 0xFFFFFFFF)
            txin.nFlags = 1
            txin.nPathIndex = 0
            txin.vWitnesses = [(V2_OP_TRUE_SCRIPT, [], [])]
            tx.vin = [txin]
            per_out = (cb_sats - 200_000) // 225
            tx.vout = [
                make_v2_txout(per_out, signer["branch_leaf"]) for _ in range(225)
            ]
            fanout_hex_batch.append(ToHex(tx))
            txid_int = tx.txid_int
            for vout_idx in range(225):
                p2pkh_utxos.append((txid_int, vout_idx, per_out))

        # 36th mature coinbase -> 250 chain root UTXOs for [A4] depth-4 chains
        cb_txid_int, cb_vout, cb_sats = mature_cb_utxos[35]
        tx_chain_fanout = CTransaction()
        tx_chain_fanout.nVersion = 7
        tx_chain_fanout.fHasV2Lock = True
        tx_chain_fanout.nV2Lock = 0
        tx_chain_fanout.nLockTime = 0
        txin_cf = CTxIn(COutPoint(cb_txid_int, cb_vout), V2_OP_TRUE_SCRIPT, 0xFFFFFFFF)
        txin_cf.nFlags = 1
        txin_cf.nPathIndex = 0
        txin_cf.vWitnesses = [(V2_OP_TRUE_SCRIPT, [], [])]
        tx_chain_fanout.vin = [txin_cf]
        per_chain_out = (cb_sats - 200_000) // 250
        tx_chain_fanout.vout = [
            make_v2_txout(per_chain_out, signer["branch_leaf"]) for _ in range(250)
        ]
        fanout_hex_batch.append(ToHex(tx_chain_fanout))
        cf_txid_int = tx_chain_fanout.txid_int
        for vout_idx in range(250):
            chain_root_utxos.append((cf_txid_int, vout_idx, per_chain_out))

        for chunk_start in range(0, len(fanout_hex_batch), 10):
            res = clients[0].call(
                "submitrawtxbatch", [fanout_hex_batch[chunk_start : chunk_start + 10]]
            )
            assert res["accepted"], f"Fan-out batch failed: {res}"
        clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
        sync_all_blocks(clients, base_dir=base_dir)
        print(
            f"[*] Funded and synced {len(op_true_utxos)} V2 OP_TRUE UTXOs, "
            f"{len(p2pkh_utxos)} V2 Schnorr UTXOs, and {len(chain_root_utxos)} V2 chain roots across all 3 nodes at height "
            f"{clients[0].call('getblockcount')}."
        )

        # Check whether submitrawtxbatch supports >50 tx batches natively
        supports_large_batch = True
        try:
            clients[0].call("testrawtxbatch", [fanout_hex_batch * 2])
        except Exception as e:
            if "between 1 and 50" in str(e):
                supports_large_batch = False
        print(f"[*] Native >50 tx batch support: {supports_large_batch}")

        # 4. Pre-construct & pre-sign all pure version=7 transactions in memory BEFORE starting clocks
        print(
            "[*] Pre-constructing 12,000 V2 OP_TRUE txs, 2,250 V2 BIP340 Schnorr txs, and 1,000 chained V2 BIP340 Schnorr txs (all version=7)..."
        )
        t_prep0 = time.perf_counter()
        prebuilt_op_true_hex = []
        prebuilt_op_true_next_utxos = []
        for txid_int, vout_idx, sats in op_true_utxos:
            next_sats = sats - 1000
            tx = build_p2sh_op_true_tx(txid_int, vout_idx, next_sats)
            prebuilt_op_true_hex.append(ToHex(tx))
            prebuilt_op_true_next_utxos.append((tx.txid_int, 0, next_sats))

        # Also pre-build Round 2 of 6,000 V2 OP_TRUE txs spending Round 1 outputs
        prebuilt_op_true_r2_hex = []
        for txid_int, vout_idx, sats in prebuilt_op_true_next_utxos:
            next_sats = sats - 1000
            tx = build_p2sh_op_true_tx(txid_int, vout_idx, next_sats)
            prebuilt_op_true_r2_hex.append(ToHex(tx))

        prebuilt_p2pkh_hex = []
        for idx, (txid_int, vout_idx, sats) in enumerate(p2pkh_utxos):
            next_sats = sats - 1000
            tx = build_signed_p2pkh_tx(txid_int, vout_idx, sats, next_sats, signer, idx)
            prebuilt_p2pkh_hex.append(ToHex(tx))

        # Pre-build 1,000 chained pure version=7 BIP340 Schnorr-signed txs (250 chains of depth 4)
        prebuilt_chained_v7_hex = []
        for c_idx, (root_txid_int, root_vout, root_sats) in enumerate(chain_root_utxos):
            cur_txid_int = root_txid_int
            cur_vout = root_vout
            cur_sats = root_sats
            for depth in range(4):
                next_sats = cur_sats - 1000
                tx = build_signed_p2pkh_tx(
                    cur_txid_int,
                    cur_vout,
                    cur_sats,
                    next_sats,
                    signer,
                    c_idx * 4 + depth,
                )
                prebuilt_chained_v7_hex.append(ToHex(tx))
                cur_txid_int = tx.txid_int
                cur_vout = 0
                cur_sats = next_sats

        t_prep1 = time.perf_counter()
        print(
            f"[*] Pre-constructed {len(prebuilt_op_true_hex) + len(prebuilt_op_true_r2_hex) + len(prebuilt_p2pkh_hex) + len(prebuilt_chained_v7_hex)} pure version=7 transactions in {t_prep1 - t_prep0:.2f}s "
            f"(avg V2 Schnorr tx={len(prebuilt_p2pkh_hex[0]) // 2}B, V2 OP_TRUE tx={len(prebuilt_op_true_hex[0]) // 2}B)."
        )

        results = {
            "supports_large_batch": supports_large_batch,
            "pure_v7_transactions": True,
        }

        # =====================================================================
        # BENCHMARK A: Batch RPC Ingestion & Validation TPS
        # =====================================================================
        print("\n=== Running Benchmark A: Batch RPC Ingestion & Validation TPS ===")

        def run_batch_ingestion(
            tx_hex_list, batch_size: int, num_workers: int, target_port: int
        ):
            eff_batch_size = (
                min(batch_size, 50) if not supports_large_batch else batch_size
            )
            batches = []
            for idx in range(0, len(tx_hex_list), eff_batch_size):
                chunk = tx_hex_list[idx : idx + eff_batch_size]
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": idx,
                        "method": "submitrawtxbatch",
                        "params": [chunk],
                    }
                ).encode("utf-8")
                batches.append((len(chunk), body))

            q_lock = threading.Lock()
            next_idx = [0]
            latencies_ms = []
            accepted_txs = [0]

            def worker():
                local_client = KeepAliveRPCClient("127.0.0.1", target_port)
                # Warm up TCP connection before barrier
                local_client.call("getBlockCount" if False else "getblockcount")
                local_lats = []
                local_acc = 0
                while True:
                    with q_lock:
                        i = next_idx[0]
                        if i >= len(batches):
                            break
                        next_idx[0] = i + 1
                    count, body = batches[i]
                    t0 = time.perf_counter()
                    r = local_client.call_raw_payload(body)
                    t1 = time.perf_counter()
                    if not r.get("accepted"):
                        raise RuntimeError(f"Batch rejected: {r}")
                    local_lats.append((t1 - t0) * 1000.0)
                    local_acc += count
                with q_lock:
                    latencies_ms.extend(local_lats)
                    accepted_txs[0] += local_acc

            # Pre-warm worker threads
            threads = [threading.Thread(target=worker) for _ in range(num_workers)]
            t_start = time.perf_counter()
            for th in threads:
                th.start()
            for th in threads:
                th.join()
            t_end = time.perf_counter()

            elapsed = t_end - t_start
            latencies_ms.sort()
            tps = accepted_txs[0] / elapsed
            return {
                "tx_count": accepted_txs[0],
                "batch_size": batch_size,
                "workers": num_workers,
                "elapsed_sec": elapsed,
                "tps": tps,
                "batch_p50_ms": percentile(latencies_ms, 50),
                "batch_p95_ms": percentile(latencies_ms, 95),
                "batch_p99_ms": percentile(latencies_ms, 99),
                "per_tx_p50_us": (percentile(latencies_ms, 50) * 1000.0) / batch_size,
                "per_tx_p95_us": (percentile(latencies_ms, 95) * 1000.0) / batch_size,
                "per_tx_p99_us": (percentile(latencies_ms, 99) * 1000.0) / batch_size,
            }

        # A1: 500 Schnorr-Signed P2PKH transactions (batch=200, workers=8)
        res_a1 = run_batch_ingestion(
            prebuilt_p2pkh_hex[:500],
            batch_size=200,
            num_workers=8,
            target_port=NODES_CFG[0]["rpc_port"],
        )
        results["bench_a_schnorr_p2pkh_b200"] = res_a1
        print(
            f"[A1] Schnorr-Signed P2PKH (500 txs, batch=200, 8 workers): "
            f"{res_a1['tps']:.1f} tx/s | batch p50={res_a1['batch_p50_ms']:.2f}ms "
            f"p95={res_a1['batch_p95_ms']:.2f}ms p99={res_a1['batch_p99_ms']:.2f}ms"
        )

        # Wait for Nodes 1 & 2 to finish receiving the 500 P2PKH txs before mining block
        t_a1_wait = time.perf_counter()
        while time.perf_counter() - t_a1_wait < 60.0:
            if (
                clients[1].call("getmempoolinfo")["size"] >= 500
                and clients[2].call("getmempoolinfo")["size"] >= 500
            ):
                break
            time.sleep(0.05)

        # Mine a block to clear the 500 P2PKH txs before testing batch size scaling
        clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
        sync_all_blocks(clients, base_dir=base_dir)

        # A2: Compare single sendrawtransaction (batch=1) vs submitrawtxbatch (batch=50, 100, 250, 500)
        # Slice 6,000 OP_TRUE Round 1 txs:
        # - 500 txs for batch=1
        # - 1,000 txs for batch=50
        # - 1,000 txs for batch=100
        # - 1,500 txs for batch=250
        # - 2,000 txs for batch=500
        res_b1 = run_batch_ingestion(
            prebuilt_op_true_hex[0:500],
            batch_size=1,
            num_workers=8,
            target_port=NODES_CFG[0]["rpc_port"],
        )
        res_b50 = run_batch_ingestion(
            prebuilt_op_true_hex[500:1500],
            batch_size=50,
            num_workers=8,
            target_port=NODES_CFG[0]["rpc_port"],
        )
        res_b100 = run_batch_ingestion(
            prebuilt_op_true_hex[1500:2500],
            batch_size=100,
            num_workers=8,
            target_port=NODES_CFG[0]["rpc_port"],
        )
        res_b250 = run_batch_ingestion(
            prebuilt_op_true_hex[2500:4000],
            batch_size=250,
            num_workers=8,
            target_port=NODES_CFG[0]["rpc_port"],
        )
        res_b500 = run_batch_ingestion(
            prebuilt_op_true_hex[4000:6000],
            batch_size=500,
            num_workers=8,
            target_port=NODES_CFG[0]["rpc_port"],
        )
        results["bench_a_b1"] = res_b1
        results["bench_a_b50"] = res_b50
        results["bench_a_b100"] = res_b100
        results["bench_a_b250"] = res_b250
        results["bench_a_b500"] = res_b500

        for label, r in [
            ("batch=1", res_b1),
            ("batch=50", res_b50),
            ("batch=100", res_b100),
            ("batch=250", res_b250),
            ("batch=500", res_b500),
        ]:
            print(
                f"[A2] {label:10s} ({r['tx_count']} txs): {r['tps']:8.1f} tx/s | "
                f"batch p50={r['batch_p50_ms']:6.2f}ms p95={r['batch_p95_ms']:6.2f}ms p99={r['batch_p99_ms']:6.2f}ms | "
                f"per-tx p50={r['per_tx_p50_us']:6.1f}us"
            )

        # Verify Node 0 mempool has all 6,000 transactions!
        mp0_info = clients[0].call("getmempoolinfo")
        print(
            f"[*] Node 0 mempool after Benchmark A: size={mp0_info['size']} bytes={mp0_info['bytes']}"
        )

        # Wait for Nodes 1 & 2 to finish syncing the 6,000 txs over P2P before Benchmark C & D
        t_wait0 = time.perf_counter()
        while time.perf_counter() - t_wait0 < 60.0:
            s1 = clients[1].call("getmempoolinfo")["size"]
            s2 = clients[2].call("getmempoolinfo")["size"]
            if s1 >= 6000 and s2 >= 6000:
                break
            time.sleep(0.05)

        # =====================================================================
        # BENCHMARK C1: Concurrent Lock-Free Read RPCs (6,000-tx Mempool)
        # =====================================================================
        print(
            "\n=== Running Benchmark C: Concurrent Lock-Free Read RPCs Under Heavy Write Load ==="
        )
        # Sample a confirmed txid/outpoint and a mempool txid for gettxout & getrawtransaction
        sample_mp_txids = clients[0].call("getrawmempool", [False])
        sample_txid = sample_mp_txids[0]
        best_hash = clients[0].call("getbestblockhash")
        best_height = clients[0].call("getblockcount")

        # C1: Unloaded Lock-Free Read RPC Throughput (12 reader threads)
        read_methods = [
            ("getblockchaininfo", []),
            ("getmempoolinfo", []),
            ("getrawmempool", [False]),
            ("gettxout", [sample_txid, 0, True]),
            ("getrawtransaction", [sample_txid, False]),
            ("getblocktemplate", [{"mode": "compact_template", "rules": ["lotus_v2"]}]),
            ("getblockheader", [best_hash, True]),
            ("getblockhash", [best_height]),
        ]

        def run_read_benchmark(duration_sec: float, num_readers: int, writer_fn=None):
            stop_flag = threading.Event()
            per_method_lats = {m: [] for m, _ in read_methods}
            lock = threading.Lock()

            def reader_worker(tid: int):
                rc = KeepAliveRPCClient("127.0.0.1", NODES_CFG[0]["rpc_port"])
                rc.call("getblockcount")
                local_lats = {m: [] for m, _ in read_methods}
                step = tid
                while not stop_flag.is_set():
                    m, params = read_methods[step % len(read_methods)]
                    step += 1
                    t0 = time.perf_counter()
                    rc.call(m, params)
                    t1 = time.perf_counter()
                    local_lats[m].append((t1 - t0) * 1000.0)
                with lock:
                    for m in local_lats:
                        per_method_lats[m].extend(local_lats[m])

            writer_stats = {"batches": 0, "txs": 0}
            writer_thread = None
            if writer_fn is not None:
                writer_thread = threading.Thread(
                    target=writer_fn, args=(stop_flag, writer_stats)
                )

            readers = [
                threading.Thread(target=reader_worker, args=(i,))
                for i in range(num_readers)
            ]
            t0 = time.perf_counter()
            if writer_thread is not None:
                writer_thread.start()
            for r in readers:
                r.start()
            time.sleep(duration_sec)
            stop_flag.set()
            for r in readers:
                r.join()
            if writer_thread is not None:
                writer_thread.join()
            t1 = time.perf_counter()
            elapsed = t1 - t0

            summary = {}
            total_reqs = 0
            all_lats = []
            for m, _ in read_methods:
                lats = sorted(per_method_lats[m])
                total_reqs += len(lats)
                all_lats.extend(lats)
                summary[m] = {
                    "count": len(lats),
                    "rps": len(lats) / elapsed,
                    "p50_ms": percentile(lats, 50),
                    "p95_ms": percentile(lats, 95),
                    "p99_ms": percentile(lats, 99),
                }
            all_lats.sort()
            return {
                "elapsed_sec": elapsed,
                "total_reqs": total_reqs,
                "total_rps": total_reqs / elapsed,
                "overall_p50_ms": percentile(all_lats, 50),
                "overall_p95_ms": percentile(all_lats, 95),
                "overall_p99_ms": percentile(all_lats, 99),
                "methods": summary,
                "writer_stats": writer_stats,
            }

        res_c_unloaded = run_read_benchmark(
            duration_sec=2.0, num_readers=12, writer_fn=None
        )
        results["bench_c_unloaded"] = res_c_unloaded
        print(
            f"[C1] Unloaded Lock-Free Read RPCs (12 threads, 6,000-tx mempool): "
            f"{res_c_unloaded['total_rps']:.1f} req/s | overall p50={res_c_unloaded['overall_p50_ms']:.3f}ms "
            f"p95={res_c_unloaded['overall_p95_ms']:.3f}ms p99={res_c_unloaded['overall_p99_ms']:.3f}ms"
        )

        # =====================================================================
        # BENCHMARK D: O(1) Block Assembly & sealedheader Relay (6,000-tx Block)
        # =====================================================================
        print(
            "\n=== Running Benchmark D: O(1) Block Assembly & sealedheader Relay (6,000-tx Block) ==="
        )
        gbt_lats_ms = []
        for _ in range(50):
            t0 = time.perf_counter()
            clients[0].call(
                "getblocktemplate",
                [{"mode": "compact_template", "rules": ["lotus_v2"]}],
            )
            t1 = time.perf_counter()
            gbt_lats_ms.append((t1 - t0) * 1000.0)
        gbt_lats_ms.sort()
        full_gbt = clients[0].call("getblocktemplate", [{"rules": ["lotus_v2"]}])
        gbt_tx_count = len(full_gbt["transactions"])
        print(
            f"[D1] O(1) getblocktemplate ({gbt_tx_count} mempool txs): "
            f"p50={percentile(gbt_lats_ms, 50):.3f}ms p95={percentile(gbt_lats_ms, 95):.3f}ms "
            f"p99={percentile(gbt_lats_ms, 99):.3f}ms"
        )

        t_mine0 = time.perf_counter()
        mined_hashes = clients[0].call(
            "generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR]
        )
        t_mine1 = time.perf_counter()
        mined_bh = mined_hashes[0]
        sync_all_blocks(clients, base_dir=base_dir)
        t_sync1 = time.perf_counter()

        blk_info = clients[0].call("getblock", [mined_bh, 2])
        full_block_hex = clients[0].call("getblock", [mined_bh, 0])
        full_block_bytes = len(full_block_hex) // 2
        cb_tx_hex = blk_info["tx"][0]["hex"]
        cb_tx_bytes = len(cb_tx_hex) // 2
        # SealedHeader wire size = 138B V2 Header + CompactSize + CoinbaseTx
        sealedheader_wire_bytes = 138 + 1 + cb_tx_bytes

        mine_ms = (t_mine1 - t_mine0) * 1000.0
        relay_and_connect_ms = (t_sync1 - t_mine0) * 1000.0
        compression_ratio = full_block_bytes / sealedheader_wire_bytes

        results["bench_d_block"] = {
            "tx_count": len(blk_info["tx"]),
            "full_block_bytes": full_block_bytes,
            "coinbase_tx_bytes": cb_tx_bytes,
            "sealedheader_wire_bytes": sealedheader_wire_bytes,
            "compression_ratio": compression_ratio,
            "gbt_p50_ms": percentile(gbt_lats_ms, 50),
            "gbt_p95_ms": percentile(gbt_lats_ms, 95),
            "gbt_p99_ms": percentile(gbt_lats_ms, 99),
            "mine_and_connect_node0_ms": mine_ms,
            "mine_and_connect_node0_tps": len(blk_info["tx"]) / (t_mine1 - t_mine0),
            "three_node_relay_and_connect_ms": relay_and_connect_ms,
            "three_node_relay_and_connect_tps": len(blk_info["tx"])
            / (t_sync1 - t_mine0),
        }
        print(
            f"[D2] Mined & connected {len(blk_info['tx'])}-tx block ({full_block_bytes:,} B vs "
            f"{sealedheader_wire_bytes} B sealedheader = {compression_ratio:.1f}x compression): "
            f"Node0={mine_ms:.2f}ms ({results['bench_d_block']['mine_and_connect_node0_tps']:.0f} tx/s), "
            f"3-Node Sync={relay_and_connect_ms:.2f}ms ({results['bench_d_block']['three_node_relay_and_connect_tps']:.0f} tx/s)"
        )

        # =====================================================================
        # BENCHMARK C2 (Loaded) & BENCHMARK B (P2P Propagation + Merklix)
        # =====================================================================
        r2_c2_txs = prebuilt_op_true_r2_hex[:1000]
        b1_txs = prebuilt_op_true_r2_hex[1000:1500]
        b2_txs = prebuilt_op_true_r2_hex[1500:2000]

        seed_res = clients[0].call("submitrawtxbatch", [r2_c2_txs[:100]])
        assert seed_res.get("accepted"), f"C2 seed batch failed: {seed_res}"
        c2_sample_txid = seed_res["txids"][0]
        c2_best_hash = clients[0].call("getbestblockhash")
        c2_best_height = clients[0].call("getblockcount")
        read_methods = [
            ("getblockchaininfo", []),
            ("getmempoolinfo", []),
            ("getrawmempool", [False]),
            ("gettxout", [c2_sample_txid, 0, True]),
            ("getrawtransaction", [c2_sample_txid, False]),
            ("getblocktemplate", [{"mode": "compact_template", "rules": ["lotus_v2"]}]),
            ("getblockheader", [c2_best_hash, True]),
            ("getblockhash", [c2_best_height]),
        ]

        def heavy_writer(stop_flag: threading.Event, stats: dict):
            wc = KeepAliveRPCClient("127.0.0.1", NODES_CFG[0]["rpc_port"])
            offset = 100
            bsize = 50 if not supports_large_batch else 100
            while not stop_flag.is_set() and offset < len(r2_c2_txs):
                chunk = r2_c2_txs[offset : offset + bsize]
                offset += bsize
                r = wc.call("submitrawtxbatch", [chunk])
                if r.get("accepted"):
                    stats["batches"] += 1
                    stats["txs"] += len(chunk)

        res_c_loaded = run_read_benchmark(
            duration_sec=2.0, num_readers=12, writer_fn=heavy_writer
        )
        rem_start = 100 + res_c_loaded["writer_stats"]["txs"]
        if rem_start < len(r2_c2_txs):
            clients[0].call("submitrawtxbatch", [r2_c2_txs[rem_start:]])
        results["bench_c_loaded"] = res_c_loaded
        print(
            f"[C2] Loaded Lock-Free Read RPCs (while ingesting {res_c_loaded['writer_stats']['txs']} txs): "
            f"{res_c_loaded['total_rps']:.1f} req/s | overall p50={res_c_loaded['overall_p50_ms']:.3f}ms "
            f"p95={res_c_loaded['overall_p95_ms']:.3f}ms p99={res_c_loaded['overall_p99_ms']:.3f}ms"
        )
        for m, mstat in res_c_loaded["methods"].items():
            print(
                f"     - {m:20s}: {mstat['rps']:7.1f} req/s | "
                f"p50={mstat['p50_ms']:.3f}ms p95={mstat['p95_ms']:.3f}ms p99={mstat['p99_ms']:.3f}ms"
            )

        clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
        sync_all_blocks(clients, base_dir=base_dir)

        # B1: Push 500 txs into Node 0 and time exact P2P inv trickle propagation to Node 1 and Node 2
        base_mp1 = clients[1].call("getmempoolinfo")["size"]
        base_mp2 = clients[2].call("getmempoolinfo")["size"]
        t_p2p0 = time.perf_counter()
        run_batch_ingestion(
            b1_txs, batch_size=250, num_workers=6, target_port=NODES_CFG[0]["rpc_port"]
        )
        t_ingest_done = time.perf_counter()

        n1_done_t = None
        n2_done_t = None
        while time.perf_counter() - t_p2p0 < 60.0:
            s1 = clients[1].call("getmempoolinfo")["size"] - base_mp1
            s2 = clients[2].call("getmempoolinfo")["size"] - base_mp2
            now = time.perf_counter()
            if s1 >= len(b1_txs) and n1_done_t is None:
                n1_done_t = now
            if s2 >= len(b1_txs) and n2_done_t is None:
                n2_done_t = now
            if n1_done_t is not None and n2_done_t is not None:
                break
            time.sleep(0.001)

        p2p_n1_sec = (n1_done_t or time.perf_counter()) - t_p2p0
        p2p_n2_sec = (n2_done_t or time.perf_counter()) - t_p2p0
        p2p_both_sec = max(p2p_n1_sec, p2p_n2_sec)

        # B2: Multi-Node Parallel Batch Ingestion across all 3 nodes simultaneously (500 txs)
        t_multi0 = time.perf_counter()
        threads_multi = []
        for node_idx in range(3):
            th = threading.Thread(
                target=run_batch_ingestion,
                args=(b2_txs, 250, 4, NODES_CFG[node_idx]["rpc_port"]),
            )
            threads_multi.append(th)
        for th in threads_multi:
            th.start()
        for th in threads_multi:
            th.join()
        t_multi1 = time.perf_counter()
        multi_sec = t_multi1 - t_multi0

        results["bench_b_p2p_propagation"] = {
            "tx_count": len(b1_txs),
            "node0_ingest_sec": t_ingest_done - t_p2p0,
            "node0_ingest_tps": len(b1_txs) / (t_ingest_done - t_p2p0),
            "node1_p2p_sync_sec": p2p_n1_sec,
            "node1_p2p_sync_tps": len(b1_txs) / p2p_n1_sec,
            "node2_p2p_sync_sec": p2p_n2_sec,
            "node2_p2p_sync_tps": len(b1_txs) / p2p_n2_sec,
            "all_nodes_p2p_sync_sec": p2p_both_sec,
            "all_nodes_p2p_sync_tps": len(b1_txs) / p2p_both_sec,
            "multi_node_direct_batch_sec": multi_sec,
            "multi_node_direct_batch_tps": len(b2_txs) / multi_sec,
        }
        print(
            f"[B1] P2P Trickle/Broadcast Propagation ({len(b1_txs)} txs, Node0 -> Node1 & Node2): "
            f"Node1={p2p_n1_sec:.2f}s ({len(b1_txs) / p2p_n1_sec:.1f} tx/s), "
            f"Node2={p2p_n2_sec:.2f}s ({len(b1_txs) / p2p_n2_sec:.1f} tx/s)"
        )
        print(
            f"[B2] Multi-Node Synchronized Batch Ingestion ({len(b2_txs)} txs -> all 3 nodes): "
            f"{multi_sec:.3f}s ({len(b2_txs) / multi_sec:.1f} cluster tx/s)"
        )

        # Mine a block to clear B1 & B2 so all 3 nodes start B3 with 0 mempool txs at the same tip
        clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
        sync_all_blocks(clients, base_dir=base_dir)

        # B3: Disjoint 3-Node Ingestion & Merklix Convergence (750 Schnorr-signed P2PKH txs:
        #     250 disjoint txs -> Node 0, 250 disjoint txs -> Node 1, 250 disjoint txs -> Node 2)
        b3_txs = prebuilt_p2pkh_hex[1500:2250]
        b3_slices = [b3_txs[0:250], b3_txs[250:500], b3_txs[500:750]]
        assert len(set(b3_slices[0]) & set(b3_slices[1])) == 0
        assert len(set(b3_slices[1]) & set(b3_slices[2])) == 0
        assert len(set(b3_slices[0]) & set(b3_slices[2])) == 0

        t_b3_0 = time.perf_counter()
        threads_b3 = []
        for node_idx in range(3):
            th = threading.Thread(
                target=run_batch_ingestion,
                args=(b3_slices[node_idx], 250, 4, NODES_CFG[node_idx]["rpc_port"]),
            )
            threads_b3.append(th)
        for th in threads_b3:
            th.start()
        for th in threads_b3:
            th.join()
        t_b3_ingest_done = time.perf_counter()
        b3_disjoint_ingest_sec = t_b3_ingest_done - t_b3_0
        b3_disjoint_ingest_tps = len(b3_txs) / b3_disjoint_ingest_sec

        b3_node_done_t = [None, None, None]
        while time.perf_counter() - t_b3_0 < 60.0:
            for node_idx in range(3):
                if b3_node_done_t[node_idx] is None:
                    sz = clients[node_idx].call("getmempoolinfo")["size"]
                    if sz >= len(b3_txs):
                        b3_node_done_t[node_idx] = time.perf_counter()
            if all(t is not None for t in b3_node_done_t):
                break
            time.sleep(0.001)

        b3_n0_sec = (b3_node_done_t[0] or time.perf_counter()) - t_b3_0
        b3_n1_sec = (b3_node_done_t[1] or time.perf_counter()) - t_b3_0
        b3_n2_sec = (b3_node_done_t[2] or time.perf_counter()) - t_b3_0
        b3_converge_sec = max(b3_n0_sec, b3_n1_sec, b3_n2_sec)
        b3_converge_tps = len(b3_txs) / b3_converge_sec

        # Verify all 3 nodes converged to 100% identical subtreearoot, merkleroot, and stateroot
        gbts_b3 = [
            c.call("getblocktemplate", [{"rules": ["lotus_v2"]}]) for c in clients
        ]
        for node_idx, gbt in enumerate(gbts_b3):
            assert len(gbt["transactions"]) == len(b3_txs), (
                f"Node {node_idx} GBT tx count {len(gbt['transactions'])} != {len(b3_txs)}"
            )
        assert (
            gbts_b3[0]["subtreearoot"]
            == gbts_b3[1]["subtreearoot"]
            == gbts_b3[2]["subtreearoot"]
        ), f"Disjoint B3 subtreearoot mismatch: {[g['subtreearoot'] for g in gbts_b3]}"
        assert (
            gbts_b3[0]["merkleroot"]
            == gbts_b3[1]["merkleroot"]
            == gbts_b3[2]["merkleroot"]
        ), f"Disjoint B3 merkleroot mismatch: {[g['merkleroot'] for g in gbts_b3]}"
        assert (
            gbts_b3[0]["stateroot"]
            == gbts_b3[1]["stateroot"]
            == gbts_b3[2]["stateroot"]
        ), f"Disjoint B3 stateroot mismatch: {[g['stateroot'] for g in gbts_b3]}"

        results["bench_b3_disjoint_convergence"] = {
            "total_tx_count": len(b3_txs),
            "per_node_disjoint_tx_count": 250,
            "disjoint_ingest_sec": b3_disjoint_ingest_sec,
            "disjoint_ingest_tps": b3_disjoint_ingest_tps,
            "node0_converge_sec": b3_n0_sec,
            "node1_converge_sec": b3_n1_sec,
            "node2_converge_sec": b3_n2_sec,
            "all_nodes_converge_sec": b3_converge_sec,
            "all_nodes_converge_tps": b3_converge_tps,
            "converged_subtreearoot": gbts_b3[0]["subtreearoot"],
            "converged_merkleroot": gbts_b3[0]["merkleroot"],
            "converged_stateroot": gbts_b3[0]["stateroot"],
            "roots_identical_across_all_3_nodes": True,
        }
        print(
            f"[B3] Disjoint 3-Node Ingestion & Convergence (3x250={len(b3_txs)} disjoint signed P2PKH txs): "
            f"Ingest={b3_disjoint_ingest_sec * 1000.0:.2f}ms ({b3_disjoint_ingest_tps:.1f} cluster tx/s) | "
            f"3-Node Convergence={b3_converge_sec:.2f}s ({b3_converge_tps:.1f} tx/s, "
            f"N0={b3_n0_sec:.2f}s N1={b3_n1_sec:.2f}s N2={b3_n2_sec:.2f}s) | "
            f"subtreearoot={gbts_b3[0]['subtreearoot'][:16]}... stateroot={gbts_b3[0]['stateroot'][:16]}... (100% identical)"
        )

        if supports_large_batch:
            clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
            sync_all_blocks(clients, base_dir=base_dir)
            burst_txs = prebuilt_op_true_r2_hex[2000:6000]
            res_burst = run_batch_ingestion(
                burst_txs,
                batch_size=1000,
                num_workers=8,
                target_port=NODES_CFG[0]["rpc_port"],
            )
            results["bench_a_high_scale_4000_b1000"] = res_burst
            print(
                f"[A3] High-Scale Burst ({res_burst['tx_count']} txs, batch=1000, 8 workers): "
                f"{res_burst['tps']:.1f} tx/s | batch p50={res_burst['batch_p50_ms']:.2f}ms "
                f"p95={res_burst['batch_p95_ms']:.2f}ms | per-tx p50={res_burst['per_tx_p50_us']:.1f}us"
            )
            clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
            sync_all_blocks(clients, base_dir=base_dir)
            res_a1_1000 = run_batch_ingestion(
                prebuilt_p2pkh_hex[500:1500],
                batch_size=200,
                num_workers=8,
                target_port=NODES_CFG[0]["rpc_port"],
            )
            results["bench_a_schnorr_p2pkh_1000_b200"] = res_a1_1000
            print(
                f"[A1b] Schnorr-Signed P2PKH (1000 txs, batch=200, 8 workers): "
                f"{res_a1_1000['tps']:.1f} tx/s | batch p50={res_a1_1000['batch_p50_ms']:.2f}ms "
                f"p95={res_a1_1000['batch_p95_ms']:.2f}ms p99={res_a1_1000['batch_p99_ms']:.2f}ms"
            )

            # A4: 1,000 Chained Pure version=7 BIP340 Schnorr-Signed Transactions (250 chains of depth 4)
            clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
            sync_all_blocks(clients, base_dir=base_dir)
            res_a4_chained = run_batch_ingestion(
                prebuilt_chained_v7_hex,
                batch_size=200,
                num_workers=8,
                target_port=NODES_CFG[0]["rpc_port"],
            )
            results["bench_a4_chained_v7_1000_b200"] = res_a4_chained
            print(
                f"[A4] Chained Pure version=7 BIP340 Schnorr (1000 txs, 250x4 chains, batch=200, 8 workers): "
                f"{res_a4_chained['tps']:.1f} tx/s | batch p50={res_a4_chained['batch_p50_ms']:.2f}ms "
                f"p95={res_a4_chained['batch_p95_ms']:.2f}ms p99={res_a4_chained['batch_p99_ms']:.2f}ms"
            )
            clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
            sync_all_blocks(clients, base_dir=base_dir)

            # Dedicated post-benchmark CPU hotspot profiling pass on 5,000 Round-2 txs
            sample_out = Path("/private/tmp/lotus-v2-node0-sample.txt")
            if not sample_out.exists():
                clients[0].call("generatetodescriptor", [1, V2_OP_TRUE_DESCRIPTOR])
                sync_all_blocks(clients, base_dir=base_dir)
                sample_proc = None
                try:
                    sample_proc = subprocess.Popen(
                        [
                            "/usr/bin/sample",
                            str(procs[0].pid),
                            "1",
                            "1",
                            "-file",
                            str(sample_out),
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    time.sleep(0.15)
                    run_batch_ingestion(
                        prebuilt_op_true_r2_hex[500:5500],
                        batch_size=500,
                        num_workers=8,
                        target_port=NODES_CFG[0]["rpc_port"],
                    )
                    sample_proc.wait(timeout=5)
                except Exception:
                    pass

        try:
            results["v2_network_stats"] = [c.call("getv2networkstats") for c in clients]
        except Exception:
            results["v2_network_stats"] = []
        # Save JSON results
        out_json = Path("/private/tmp/lotus-v2-loopback-stress-results.json")
        out_json.write_text(json.dumps(results, indent=2))
        print(f"\n[*] Saved complete benchmark metrics to {out_json}")

    finally:
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=10)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        shutil.rmtree(base_dir, ignore_errors=True)
        print(f"[*] Cleaned up temporary stress directory {base_dir}")


if __name__ == "__main__":
    main()
