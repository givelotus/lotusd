#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Deterministic two-node Chronik parity run (design C1 section 8.3, step 1-3).

Starts node A from --build-a and node B from --build-b (each a CMake build
dir with src/bitcoind or src/lotusd and test/config.ini). The nodes are not
connected; both run regtest with -chronik and the same -mocktime. The chain
is generated on A (or built in Python) and every raw block/tx is submitted to
B (submitblock / sendrawtransaction), so both indexers see the same stream.

At every --checkpoint-interval blocks and at the end, both Chronik indexes
are synced to the same tip, then:
  * the HTTP corpus (corpus.py) is sent to both and compared (compare.py),
  * the WebSocket sessions opened at the previous checkpoint are closed and
    their message sequences compared,
  * optionally the DB dumps (--dump-tool) are compared.

Example:
  venv/bin/python parity_chain.py --build-a build/ecash-rust \\
      --build-b build/ecash-native --blocks 400
"""

import argparse
import configparser
import json
import os
import shlex
import subprocess
import tempfile
import sys
import time

DEFAULT_SCRATCH = os.environ.get(
    "CHRONIK_PARITY_TMPDIR",
    os.path.join(tempfile.gettempdir(), "chronik-parity-runs"),
)
HERE = os.path.dirname(os.path.abspath(__file__))


def _find_binary(build: str) -> str:
    for name in ("bitcoind", "lotusd"):
        path = os.path.join(build, "src", name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise SystemExit(f"no src/bitcoind or src/lotusd in {build}")


def _bootstrap() -> None:
    """Make the functional test framework importable and default some of its
    own options before it parses sys.argv."""
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--srcdir")
    pre.add_argument("--build-a")
    pre.add_argument("--build-b")
    pre.add_argument("--pb2-dir")
    pre.add_argument("--tmpdir")
    pre.add_argument("--configfile")
    pre.add_argument("--randomseed")
    pre.add_argument("--portseed")
    ns, _ = pre.parse_known_args()
    if not ns.build_a or not ns.build_b:
        raise SystemExit("--build-a and --build-b are required")
    ns.build_a = os.path.abspath(ns.build_a)
    ns.build_b = os.path.abspath(ns.build_b)
    config_a = os.path.join(ns.build_a, "test", "config.ini")
    srcdir = ns.srcdir
    if not srcdir:
        cfg = configparser.ConfigParser()
        cfg.read(config_a)
        srcdir = cfg["environment"]["SRCDIR"]
    sys.path.insert(0, os.path.join(os.path.abspath(srcdir), "test", "functional"))
    sys.path.insert(0, HERE)
    if ns.pb2_dir:
        sys.path.insert(0, ns.pb2_dir)
    if not ns.configfile:
        sys.argv.append(f"--configfile={config_a}")
    if not ns.tmpdir:
        os.makedirs(DEFAULT_SCRATCH, exist_ok=True)
        sys.argv.append(
            f"--tmpdir={DEFAULT_SCRATCH}/run-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}")
    if "--nocleanup" not in sys.argv and "--cleanup" not in sys.argv:
        sys.argv.append("--nocleanup")  # keep the run dir (report, records, dumps)
    if "--cleanup" in sys.argv:
        sys.argv.remove("--cleanup")
    if not ns.randomseed:
        sys.argv.append("--randomseed=1")
    if not ns.portseed:
        # Framework ports are >= 20000 (PORT_MIN), so they never collide with
        # mainnet/live ports (10604/10605/8331/18331/19331/11604/12604).
        sys.argv.append(f"--portseed={4000 + os.getpid() % 2000}")
    os.environ.setdefault("CHRONIK_PARITY_SRCDIR", os.path.abspath(srcdir))


_bootstrap()

import random  # noqa: E402

import compare  # noqa: E402
import corpus  # noqa: E402
from test_framework.address import P2SH_OP_TRUE, SCRIPTSIG_OP_TRUE  # noqa: E402
from test_framework.authproxy import JSONRPCException  # noqa: E402
from test_framework.blocktools import create_block, create_coinbase  # noqa: E402
from test_framework.hash import hash160  # noqa: E402
from test_framework.key import ECKey  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
)
from test_framework.script import (  # noqa: E402
    OP_12,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_RESERVED,
    OP_RETURN,
    OP_TRUE,
    CScript,
)
from test_framework.signature_hash import (  # noqa: E402
    SIGHASH_ALL,
    SIGHASH_FORKID,
    SignatureHashForkId,
)
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.txtools import pad_tx  # noqa: E402

try:
    from test_framework.chronik.alp import (  # noqa: E402
        alp_burn,
        alp_genesis,
        alp_mint,
        alp_opreturn,
        alp_send,
    )
    from test_framework.chronik.slp import (  # noqa: E402
        SlpScript,
        slp_burn,
        slp_genesis,
        slp_mint,
        slp_mint_vault,
        slp_send,
    )

    HAVE_TOKEN_HELPERS = True
except ImportError:
    HAVE_TOKEN_HELPERS = False

SLP_FUNGIBLE = 1
SLP_MINT_VAULT = 2
SLP_NFT1_CHILD = 0x41
SLP_NFT1_GROUP = 0x81
TOKEN_DUST = 546
COINBASE_MATURITY = 100
V2_OP1 = b"\x4e"  # Lotus V2 VM OP_1
# Max txs per block (see mempool_chunk) and rotated change scripts.
MAX_BLOCK_TXS = 6
TOKEN_STEPS_PER_PASS = 17
CHANGE_KINDS = ["p2sh_true", "bare_true", "other_drop"]
LOKAD_SLP = b"SLP\0"
LOKAD_ALP = b"SLP2"
LOKAD_IDS = [b"PRTY", b"TEST", b"LKD1", b"LKD2", b"INPT"]


def v2_frame_members(spk: bytes):
    """(branch roots, asset ID or None) of a native V2 output frame (or
    0x6a || frame) used as an output script, else None. Lenient: only the
    framing up to the branches is checked; both sides are queried alike."""
    for raw in (spk, spk[1:] if spk[:1] == b"\x6a" and len(spk) >= 44 else None):
        if raw is None or len(raw) < 11 or raw[0] & 0xFC:
            continue
        pos = 9
        token = None
        if raw[0] & 1:
            token = raw[pos:pos + 32]
            pos += 32
        if pos >= len(raw):
            continue
        n = raw[pos]
        pos += 1
        if n == 0 or n > 16 or pos + 32 * n >= len(raw):
            continue
        branches = [raw[pos + 32 * i:pos + 32 * (i + 1)] for i in range(n)]
        if raw[0] & 2:
            continue  # burns are not indexed
        return branches, (token if token and any(token) else None)
    return None


def classify_script(spk: bytes):
    """Chronik script type/payload of an output script."""
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        return "p2pkh", spk[3:23]
    if len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[22:] == b"\x87":
        return "p2sh", spk[2:22]
    if len(spk) == 35 and spk[0] == 0x21 and spk[34] == 0xAC:
        return "p2pk", spk[1:34]
    if len(spk) == 67 and spk[0] == 0x41 and spk[66] == 0xAC:
        return "p2pk", spk[1:66]
    return "other", spk


def _cs(n: int) -> bytes:
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


class V2Out:
    __slots__ = ("nValue", "scriptPubKey", "script")

    def __init__(self, value, legacy_spk, script):
        self.nValue, self.scriptPubKey, self.script = value, legacy_spk, script


class V2Tx:
    """Minimal Lotus V2 v7 transaction: spends branch outputs whose single
    leaf is the script 0x4e (OP_1) and creates single-leaf branch outputs
    (OP_RETURN scripts become flags=2 outputs without paths)."""

    def __init__(self, wallet, coins, outs):
        self.w = wallet
        self.vin = [(c.txid, c.n) for c in coins]
        self.vout = outs

    def serialize(self) -> bytes:
        raw = bytearray((7).to_bytes(4, "little") + (0).to_bytes(8, "little")
                        + len(self.vin).to_bytes(2, "little")
                        + len(self.vout).to_bytes(2, "little"))
        for txid, n in self.vin:
            raw += bytes.fromhex(txid)[::-1] + n.to_bytes(4, "little")
            raw += (0xFFFFFFFF).to_bytes(4, "little") + b"\x01"
            raw += _cs(0) + _cs(1) + _cs(len(V2_OP1)) + V2_OP1 + _cs(0) + _cs(0)
        for o in self.vout:
            is_opret = len(o.script) > 0 and o.script[0] == 0x6A
            raw += bytes([2 if is_opret else 0]) + int(o.nValue).to_bytes(8, "little")
            raw += _cs(1) + self.w.v2_leaf(o.script)
            raw += _cs(0) if is_opret else (_cs(1) + _cs(1) + _cs(0))
        return bytes(raw)


class Coin:
    __slots__ = ("txid", "n", "value", "kind", "spk")

    def __init__(self, txid, n, value, kind, spk):
        self.txid, self.n, self.value, self.kind, self.spk = txid, n, value, kind, spk

    def outpoint(self):
        return COutPoint(int(self.txid, 16), self.n)


class Wallet:
    """Deterministic keys and script kinds used by the feeder."""

    SIGNED = ("p2pkh", "p2pk", "p2pk65")

    def __init__(self):
        self.k1 = ECKey()
        self.k1.set((1111).to_bytes(32, "big"), True)
        self.k2 = ECKey()
        self.k2.set((2222).to_bytes(32, "big"), True)
        self.k3 = ECKey()
        self.k3.set((3333).to_bytes(32, "big"), False)
        self.lokad_redeem = CScript([OP_DROP, OP_TRUE])
        self.vault_redeem = CScript([OP_12])
        self.spks = {
            "p2sh_true": bytes(P2SH_OP_TRUE),
            "p2sh_lokad": bytes(CScript([OP_HASH160, hash160(self.lokad_redeem), OP_EQUAL])),
            "bare_true": bytes(CScript([OP_TRUE])),
            "other_drop": bytes(CScript([b"\xab\xcd\xef", OP_DROP, OP_TRUE])),
            "p2pkh": bytes(CScript([OP_DUP, OP_HASH160, hash160(self.k1.get_pubkey().get_bytes()),
                                    OP_EQUALVERIFY, OP_CHECKSIG])),
            "p2pk": bytes(CScript([self.k2.get_pubkey().get_bytes(), OP_CHECKSIG])),
            "p2pk65": bytes(CScript([self.k3.get_pubkey().get_bytes(), OP_CHECKSIG])),
            "vault": bytes(CScript([OP_HASH160, hash160(self.vault_redeem), OP_EQUAL])),
        }
        self._kind_of = {v: k for k, v in self.spks.items()}
        # Lotus V2 tier (v7 txs, branch outputs, V2 VM where 0x4e is OP_1):
        # every anyone-can-spend kind maps to the branch script 0x4e; the
        # signed/vault kinds map to distinct output-only scripts.
        self.v2_scripts = {
            "p2sh_true": V2_OP1, "p2sh_lokad": V2_OP1, "bare_true": V2_OP1,
            "other_drop": V2_OP1, "p2pkh": b"\x4e\x00", "p2pk": b"\x00",
            "p2pk65": b"\x4e\x4e\x00", "vault": b"\x00\x00",
        }
        try:  # Lotus V2 tier: outputs deserialize to the V2 output encoding
            from test_framework import messages as _m

            self._v2_decode = _m._lotus_v2_decode_output_bytes
            self.v2_leaf = _m.lotus_v2_branch_leaf
            self._v2_leaf_kind = {}
            for k in ("vault", "p2pk65", "p2pk", "p2pkh", "p2sh_true"):
                self._v2_leaf_kind[self.v2_leaf(self.v2_scripts[k])] = k
        except AttributeError:
            self._v2_decode = None

    def v2_script(self, spk: bytes) -> bytes:
        """Branch script used on the V2 tier for a (legacy) output script."""
        kind = self._kind_of.get(spk)
        return self.v2_scripts[kind] if kind else spk

    def kind_of_spk(self, spk: bytes):
        kind = self._kind_of.get(spk)
        if kind is None and self._v2_decode is not None and len(spk) >= 43:
            dec = self._v2_decode(spk)
            if dec is not None and len(dec[2]) == 1:
                kind = self._v2_leaf_kind.get(dec[2][0])
        return kind

    def unsigned_script_sig(self, kind):
        if kind == "p2sh_true":
            return SCRIPTSIG_OP_TRUE
        if kind == "p2sh_lokad":
            return CScript([b"INPT", bytes(self.lokad_redeem)])
        if kind in ("bare_true", "other_drop"):
            return CScript([])
        if kind == "vault":
            return CScript([bytes(self.vault_redeem)])
        return CScript([])

    def sign(self, tx: CTransaction, coins):
        for i, coin in enumerate(coins):
            if coin.kind not in self.SIGNED:
                tx.vin[i].scriptSig = self.unsigned_script_sig(coin.kind)
        for i, coin in enumerate(coins):
            if coin.kind not in self.SIGNED:
                continue
            hashtype = SIGHASH_ALL | SIGHASH_FORKID
            sighash = SignatureHashForkId(CScript(coin.spk), tx, i, hashtype, coin.value)
            if coin.kind == "p2pkh":
                sig = self.k1.sign_ecdsa(sighash) + bytes([hashtype])
                tx.vin[i].scriptSig = CScript([sig, self.k1.get_pubkey().get_bytes()])
            elif coin.kind == "p2pk":
                sig = self.k2.sign_ecdsa(sighash) + bytes([hashtype])
                tx.vin[i].scriptSig = CScript([sig])
            else:
                sig = self.k3.sign_ecdsa(sighash) + bytes([hashtype])
                tx.vin[i].scriptSig = CScript([sig])


class ParityChain(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3 if self.options.miner == "separate" else 2
        self.rpc_timeout = 240

    def add_options(self, parser):
        g = parser.add_argument_group("parity")
        g.add_argument("--srcdir", help="source tree for the test framework "
                       "(default: SRCDIR of --build-a/test/config.ini)")
        g.add_argument("--build-a", required=True, help="build dir of implementation A")
        g.add_argument("--build-b", required=True, help="build dir of implementation B")
        g.add_argument("--blocks", type=int, default=400, help="chain length (>= 110)")
        g.add_argument("--miner", choices=["a", "separate"], default="separate",
                       help="a: blocks are generated on node A and submitted to B; "
                       "separate (default): a third non-Chronik node of build A "
                       "generates them and both A and B get them via submitblock")
        g.add_argument("--checkpoint-interval", type=int, default=50)
        g.add_argument("--max-scripts", type=int, default=400,
                       help="max scripts queried per checkpoint (0: all)")
        g.add_argument("--corpus-mode", choices=["full", "light"], default="full",
                       help="corpus at intermediate checkpoints (the final one is full)")
        g.add_argument("--tier", choices=["auto", "ecash", "v2"], default="auto",
                       help="tx format: ecash (legacy txs) or v2 (Lotus V2 v7 txs); "
                       "auto: v2 if the binary is lotusd")
        g.add_argument("--no-tokens", action="store_true",
                       help="no SLP/ALP scenarios, -chroniktokenindex=0 (V2 tier)")
        g.add_argument("--no-ws", action="store_true", help="skip the WebSocket corpus")
        g.add_argument("--no-http", action="store_true", help="skip the HTTP corpus")
        g.add_argument("--no-broadcast", action="store_true",
                       help="skip the final mutating /broadcast-tx(s) phase")
        g.add_argument("--dump-tool", help="DB dump command (e.g. chronik-native-dump); "
                       "the DB dir is appended as last argument")
        g.add_argument("--dump-mode", choices=["stopped", "live"], default="stopped",
                       help="stopped: stop both nodes for the dump and restart them; "
                       "live: dump while running (tool must open read-only)")
        g.add_argument("--dump-live-arg", default="--readonly",
                       help="extra tool argument used in --dump-mode=live")
        g.add_argument("--extra-arg-a", action="append", default=[],
                       help="extra node argument for A (repeatable)")
        g.add_argument("--extra-arg-b", action="append", default=[],
                       help="extra node argument for B (repeatable)")
        g.add_argument("--allow", action="append", default=[],
                       help="additional allowed difference path (fnmatch)")
        g.add_argument("--report", help="JSON report path (default: <tmpdir>/report.json)")
        g.add_argument("--save-responses", action="store_true",
                       help="save every raw response pair under <tmpdir>/responses")
        g.add_argument("--pb2-dir", help="directory containing chronik_pb2.py")
        g.add_argument("--seed", type=int, default=7, help="scenario RNG seed")
        g.add_argument("--keep-going", action="store_true",
                       help="do not abort at the first checkpoint with differences")

    def skip_test_if_missing_module(self):
        self.skip_if_no_chronik()

    def shutdown(self):
        # Never leave nodes running, also not on failure.
        for ws in [getattr(self, "ws", None)]:
            if ws is not None:
                for _, ca, cb in ws.sessions:
                    ca.close()
                    cb.close()
        from test_framework.test_framework import TestStatus

        if self.success != TestStatus.PASSED:
            for n in self.nodes:
                if n.process is not None:
                    n.process.kill()
                    try:
                        n.process.wait(timeout=60)
                    except Exception:
                        pass
                    n.process = None
                    n.running = False
        return super().shutdown()

    # ------------------------------------------------------------------
    # Node setup
    # ------------------------------------------------------------------

    def _node_supports(self, binary, opts):
        try:
            out = subprocess.run([binary, "-help", "-help-debug"], capture_output=True,
                                 text=True, timeout=60).stdout
        except Exception:
            out = ""
        return {opt: (f"{opt}=" in out or f"{opt}\n" in out or f"{opt} " in out)
                for opt in opts}

    def setup_network(self):
        self.setup_nodes()  # nodes are deliberately NOT connected

    def setup_nodes(self):
        o = self.options
        self.bin_a = _find_binary(os.path.abspath(o.build_a))
        self.bin_b = _find_binary(os.path.abspath(o.build_b))
        self.mocktime = 1_700_000_000
        opts = ["-avalanche", "-chronikscripthashindex", "-acceptnonstdtxn",
                "-chroniktokenindex"]
        sup_a = self._node_supports(self.bin_a, opts)
        sup_b = self._node_supports(self.bin_b, opts)
        self.supports = {k: sup_a[k] and sup_b[k] for k in opts}
        common = ["-chronik", f"-mocktime={self.mocktime}", "-acceptnonstdtxn=1",
                  "-persistmempool=1"]
        if self.supports["-avalanche"]:
            common.append("-avalanche=0")
        self.scripthash_index = self.supports["-chronikscripthashindex"]
        if self.scripthash_index:
            common.append("-chronikscripthashindex=1")
        self.v2 = o.tier == "v2" or (o.tier == "auto" and
                                     os.path.basename(self.bin_a) == "lotusd")
        if self.v2 and not o.no_tokens:
            raise AssertionError("the V2 tier has no SLP/ALP; use --no-tokens")
        self.tokens = not o.no_tokens and HAVE_TOKEN_HELPERS
        if not self.tokens and self.supports["-chroniktokenindex"]:
            common.append("-chroniktokenindex=0")
        self.node_args = [common + o.extra_arg_a, common + o.extra_arg_b]
        binaries = [self.bin_a, self.bin_b]
        if o.miner == "separate":
            # Plain node (no Chronik) that builds every block; A and B both
            # receive each block via submitblock, so neither indexes a block
            # object that was assembled in-process.
            margs = [f"-mocktime={self.mocktime}", "-acceptnonstdtxn=1",
                     "-persistmempool=1"]
            if self.supports["-avalanche"]:
                margs.append("-avalanche=0")
            self.node_args.append(margs)
            binaries.append(self.bin_a)
        self.add_nodes(len(binaries), [list(a) for a in self.node_args], binary=binaries)
        self.start_nodes()
        self.log.info(f"A: {self.bin_a}\nB: {self.bin_b}\nminer: {o.miner}\n"
                      f"args: {self.node_args}")

    # ------------------------------------------------------------------
    # Stream helpers (every mutation goes to A and B identically)
    # ------------------------------------------------------------------

    @property
    def a(self):
        return self.nodes[0]

    @property
    def b(self):
        return self.nodes[1]

    @property
    def miner(self):
        return self.nodes[2] if self.options.miner == "separate" else self.nodes[0]

    def tick(self, dt=1):
        self.mocktime += dt
        for n in self.nodes:
            n.setmocktime(self.mocktime)

    def desc(self, kind):
        spk = self.w.v2_scripts[kind] if self.v2 else self.w.spks[kind]
        return f"raw({spk.hex()})"

    def submit_to_b(self, hashes):
        """Submit blocks produced by the miner to every other node."""
        for h in hashes:
            raw = self.miner.getblock(h, 0)
            for n in self.nodes:
                if n is self.miner:
                    continue
                res = n.submitblock(raw)
                assert res in (None, "duplicate"), f"node {n.index} rejected {h}: {res}"
            self.ws_settle()
        self.assert_same_tip()

    def assert_same_tip(self):
        tips = [n.getbestblockhash() for n in self.nodes]
        assert len(set(tips)) == 1, f"tip mismatch {tips}"

    def mine(self, n=1, kind=None):
        hashes = []
        for _ in range(n):
            self.tick(self.rng.randint(5, 240))
            k = kind or self.cb_kinds[self.cb_rot % len(self.cb_kinds)]
            self.cb_rot += 1
            chunk = self.mempool_chunk()
            if chunk is None:
                h = self.generatetodescriptor(self.miner, 1, self.desc(k),
                                              sync_fun=self.no_op)[0]
            else:
                h = self.miner.generateblock(self.desc(k), chunk,
                                             invalid_call=False)["hash"]
            self.submit_to_b([h])
            self.cb_blocks.append(h)
            hashes.append(h)
            self.blocks_mined += 1
        self.after_blocks()
        return hashes

    def mempool_chunk(self):
        """None if the whole mempool fits into one block of at most
        MAX_BLOCK_TXS txs; otherwise an ancestor-closed subset (txids).

        Small blocks keep every per-event WebSocket burst below Chronik's
        channel capacities (blocks 16, txs 32, groups 16), whose overflow drops
        messages in a timing-dependent way (tokio broadcast lag)."""
        pool = self.miner.getrawmempool(True)
        if len(pool) <= MAX_BLOCK_TXS:
            return None
        chosen = []
        chosen_set = set()
        while len(chosen) < MAX_BLOCK_TXS:
            ready = sorted((pool[t].get("time", 0), t) for t in pool
                           if t not in chosen_set and
                           all(d in chosen_set for d in pool[t]["depends"]))
            if not ready:
                break
            txid = ready[0][1]
            chosen.append(txid)
            chosen_set.add(txid)
        return sorted(chosen)  # canonical (CTOR) order

    def ws_settle(self):
        if self.ws is not None:
            self.ws.quiesce(idle=0.05, timeout=5)

    def mine_with(self, txs, kind="p2sh_true"):
        """Mine a block on A with exactly the given txs (may conflict with the
        mempool) and submit it to B."""
        self.tick(30)
        res = self.miner.generateblock(self.desc(kind),
                                       [t.serialize().hex() for t in txs],
                                       invalid_call=False)
        self.submit_to_b([res["hash"]])
        self.cb_blocks.append(res["hash"])
        self.blocks_mined += 1
        for t in txs:
            self.seen_txids.add(self.txid_of(t))
        self.after_blocks()
        return res["hash"]

    def submit_block_both(self, block):
        raw = block.serialize().hex()
        ra = self.a.submitblock(raw)
        rb = self.b.submitblock(raw)
        if self.miner is not self.a:
            self.miner.submitblock(raw)
        self.ws_settle()
        assert ra == rb, f"submitblock differs A={ra} B={rb}"
        return ra

    def txid_of(self, tx):
        return self.a.decoderawtransaction(tx.serialize().hex())["txid"]

    def send(self, tx, coins=None, outputs_kinds=None, expect_ok=None):
        """sendrawtransaction to A then B; both must agree. Returns txid|None."""
        raw = tx.serialize().hex()
        results = []
        for n in self.nodes:
            try:
                results.append(("ok", n.sendrawtransaction(raw, 0)))
            except JSONRPCException as e:
                results.append(("err", e.error.get("message", "")))
        assert results[0] == results[1], f"A/B disagree on tx: {results}"
        if len(results) > 2 and results[2][0] != results[0][0]:
            self.notes.append(f"miner disagrees on tx: {results}")
        status, val = results[0]
        if status == "ok":
            self.seen_txids.add(val)
            self.recent_txids.add(val)
            if coins:
                self.spend(coins)
            self.add_outputs(val, tx)
            self.stats["txs_sent"] += 1
            if expect_ok is False:
                self.stats["unexpected_accept"] += 1
            return val
        self.stats["txs_rejected"] += 1
        if expect_ok is not False:
            self.rejects.append(val)
            self.log.debug(f"tx rejected by both: {val}")
        return None

    def spend(self, coins):
        ids = {(c.txid, c.n) for c in coins}
        self.coins = [c for c in self.coins if (c.txid, c.n) not in ids]

    def add_outputs(self, txid, tx):
        for i, out in enumerate(tx.vout):
            spk = bytes(out.scriptPubKey)
            kind = self.w.kind_of_spk(spk)
            if kind is None or out.nValue < 1000 or kind == "vault":
                continue
            if kind in Wallet.SIGNED and not self.can_sign:
                continue
            self.coins.append(Coin(txid, i, out.nValue, kind, spk))

    def after_blocks(self):
        pass

    def refresh_coins(self):
        """Drop coins that no longer exist (reorgs, conflicts)."""
        keep = []
        for c in self.coins:
            if self.a.gettxout(c.txid, c.n, True) is not None:
                keep.append(c)
        self.coins = keep

    def take_coinbase(self):
        """A mature coinbase coin of one of our scripts."""
        tip = self.a.getblockcount()
        while self.cb_blocks:
            h = self.cb_blocks[0]
            hdr = self.a.getblockheader(h)
            if hdr["confirmations"] < 0:
                self.cb_blocks.pop(0)
                continue
            if tip - hdr["height"] + 1 < COINBASE_MATURITY + 1:
                return None
            self.cb_blocks.pop(0)
            blk = self.a.getblock(h, 2)
            cb = CTransaction()
            FromHex(cb, blk["tx"][0]["hex"])
            txid = blk["tx"][0]["txid"]
            for i, out in enumerate(cb.vout):
                spk = bytes(out.scriptPubKey)
                kind = self.w.kind_of_spk(spk)
                if kind is None or out.nValue < 100_000:
                    continue
                if kind in Wallet.SIGNED and not self.can_sign:
                    continue
                if self.a.gettxout(txid, i, True) is None:
                    continue
                return Coin(txid, i, out.nValue, kind, self.w.spks[kind])
        return None

    def take(self, min_value=100_000, kinds=None, confirmed=False):
        cands = [c for c in self.coins if c.value >= min_value and
                 (kinds is None or c.kind in kinds)]
        if confirmed:
            cands = [c for c in cands if self.a.gettxout(c.txid, c.n, False) is not None]
        if not cands:
            cb = self.take_coinbase()
            if cb is None:
                return None
            if kinds is not None and cb.kind not in kinds:
                # convert to a usable coin first
                txid = self.simple_spend([cb], ["p2sh_true"])
                return next((c for c in self.coins if c.txid == txid), None)
            return cb
        c = self.rng.choice(cands)
        return c

    def fee_for(self, tx):
        return 300 + 4 * (len(tx.serialize()) + 110 * len(tx.vin))

    def build(self, coins, outputs, change_kind="auto", pad=True):
        """outputs: list of CTxOut; appends change. Signs. Returns tx."""
        if self.v2:
            return self.build_v2(coins, outputs, change_kind)
        tx = CTransaction()
        tx.vin = [CTxIn(c.outpoint(), self.w.unsigned_script_sig(c.kind), 0xFFFFFFFF)
                  for c in coins]
        tx.vout = list(outputs)
        if change_kind == "auto":
            change_kind = CHANGE_KINDS[self.change_rot % len(CHANGE_KINDS)]
            self.change_rot += 1
        total_in = sum(c.value for c in coins)
        total_out = sum(o.nValue for o in tx.vout)
        if change_kind:
            tx.vout.append(CTxOut(0, CScript(self.w.spks[change_kind])))
        if pad:
            pad_tx(tx, deterministic=True)
        fee = self.fee_for(tx)
        if change_kind:
            change = total_in - total_out - fee
            assert change >= 1000, f"insufficient funds {total_in} {total_out}"
            tx.vout[len(outputs)].nValue = change
        self.w.sign(tx, coins)
        return tx

    def build_v2(self, coins, outputs, change_kind="auto"):
        outs = [V2Out(o.nValue, bytes(o.scriptPubKey),
                      self.w.v2_script(bytes(o.scriptPubKey))) for o in outputs]
        total_in = sum(c.value for c in coins)
        total_out = sum(o.nValue for o in outs)
        if change_kind:
            spk = self.w.spks["p2sh_true"]
            outs.append(V2Out(0, spk, V2_OP1))
        tx = V2Tx(self.w, coins, outs)
        fee = 300 + 4 * (len(tx.serialize()) + 40 * len(coins))
        if change_kind:
            change = total_in - total_out - fee
            assert change >= 1000, f"insufficient funds {total_in} {total_out}"
            outs[-1].nValue = change
        return tx

    def simple_spend(self, coins, kinds, value_each=None):
        total = sum(c.value for c in coins)
        each = value_each or max(1000, (total - 20_000) // (len(kinds) + 1))
        outs = [CTxOut(each, CScript(self.w.spks[k])) for k in kinds]
        tx = self.build(coins, outs)
        return self.send(tx, coins)

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def act_fanout(self):
        coin = self.take(5_000_000)
        if coin is None:
            return
        kinds = ["p2sh_true", "p2sh_true", "p2sh_lokad", "bare_true", "other_drop"]
        if self.can_sign:
            kinds += ["p2pkh", "p2pk", "p2pk65"]
        self.rng.shuffle(kinds)
        each = min(coin.value // (len(kinds) + 2), 2_000_000_000)
        outs = [CTxOut(each - self.rng.randint(0, 999), CScript(self.w.spks[k]))
                for k in kinds]
        lokad = self.rng.choice(LOKAD_IDS[:3])
        outs.insert(0, CTxOut(0, CScript([OP_RETURN, lokad, b"fanout"])))
        self.send(self.build([coin], outs), [coin])

    def act_chain(self, length=3):
        coin = self.take(200_000)
        if coin is None:
            return
        for _ in range(length):
            k = self.rng.choice(["p2sh_true", "p2sh_lokad", "bare_true"] +
                                (["p2pkh", "p2pk"] if self.can_sign else []))
            tx = self.build([coin], [CTxOut(coin.value // 3, CScript(self.w.spks[k]))])
            txid = self.send(tx, [coin])
            if txid is None:
                return
            coin = next((c for c in self.coins if c.txid == txid and c.n == 1), None)
            if coin is None or coin.value < 50_000:
                return
            self.tick(1)

    def act_ctor_chain(self, length=3):
        """Mine a block with a chain of txs whose children sort before their
        parents in the block's canonical (txid) order, so the indexers apply
        spends of coins created later in the same block."""
        coin = self.take(1_000_000, kinds=["p2sh_true"], confirmed=True)
        if coin is None or self.a.gettxout(coin.txid, coin.n, False) is None:
            return
        first = coin
        spk = self.w.spks["p2sh_true"]
        txs = []
        parent_txid = None
        for _ in range(length):
            for attempt in range(64):
                out_value = coin.value - 20_000 - attempt
                tx = self.build([coin], [CTxOut(out_value, CScript(spk))],
                                change_kind=None)
                txid = self.txid_of(tx)
                if parent_txid is None or txid < parent_txid:
                    break
            else:
                break
            txs.append((txid, tx))
            parent_txid = txid
            coin = Coin(txid, 0, out_value, "p2sh_true", spk)
        if len(txs) < 2:
            return
        self.spend([first])
        # Canonical order: each child before its parent
        self.mine_with([tx for _, tx in sorted(txs, key=lambda t: t[0])])
        self.add_outputs(parent_txid, txs[-1][1])
        self.stats["ctor_chains"] += 1

    def act_consolidate(self):
        small = [c for c in self.coins if c.value >= 5000]
        if len(small) < 3:
            return
        self.rng.shuffle(small)
        coins = small[: self.rng.randint(2, 5)]
        self.send(self.build(coins, [CTxOut(2000, CScript(self.w.spks["other_drop"]))]),
                  coins)

    def act_opreturns(self):
        coin = self.take(200_000)
        if coin is None:
            return
        variants = [
            CScript([OP_RETURN, b"TEST", b"hello"]),
            CScript([OP_RETURN, OP_RESERVED, b"LKD1section-one", b"LKD2section-two"]),
            CScript([OP_RETURN]),
            CScript([OP_RETURN, b"abc"]),
            CScript([OP_RETURN, b"PRTY"]),
            CScript([OP_RETURN, OP_RESERVED, b"xy"]),
        ]
        spk = variants[self.op_rot % len(variants)]
        self.op_rot += 1
        self.send(self.build([coin], [CTxOut(0, spk), CTxOut(5000, P2SH_OP_TRUE)]), [coin])

    def act_conflict(self):
        """Mempool tx X (+ child) conflicted by a block containing X'."""
        coin = self.take(500_000, kinds=["p2sh_true", "bare_true", "p2sh_lokad"],
                         confirmed=True)
        if coin is None:
            return
        x = self.build([coin], [CTxOut(100_000, P2SH_OP_TRUE)])
        xid = self.send(x, [coin])
        if xid is None:
            return
        child_coin = next((c for c in self.coins if c.txid == xid and c.n == 0), None)
        if child_coin:
            self.tick(1)
            self.send(self.build([child_coin], [CTxOut(10_000, P2SH_OP_TRUE)]), [child_coin])
        x2 = self.build([coin], [CTxOut(77_000, CScript(self.w.spks["other_drop"]))])
        self.conflicted.add(xid)
        self.mine_with([x2])
        self.add_outputs(self.txid_of(x2), x2)
        self.refresh_coins()
        self.stats["conflicts"] += 1

    # ---------------- tokens

    def token_script(self):
        """Generator of token steps; each yield is one step (txs sent)."""
        w = self.w
        P2SH = P2SH_OP_TRUE

        def fund(min_value=2_000_000):
            return self.take(min_value, kinds=["p2sh_true", "bare_true", "p2sh_lokad"])

        def send_tok(coins, outs, change=True):
            tx = self.build(coins, outs, change_kind="p2sh_true" if change else None,
                            pad=True)
            txid = self.send(tx, coins)
            return txid

        # --- SLP fungible
        c = fund()
        g = send_tok([c], [CTxOut(0, slp_genesis(
            token_type=SLP_FUNGIBLE, token_ticker=b"PAR", token_name=b"Parity Token",
            token_document_url=b"http://example/parity", token_document_hash=b"h" * 32,
            decimals=2, mint_baton_vout=2, initial_mint_amount=5000)),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)])
        self.token_ids.append(g)
        yield
        c = fund()
        m = send_tok([Coin(g, 2, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_mint(token_type=SLP_FUNGIBLE, token_id=g, mint_baton_vout=3,
                               mint_amount=20)),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)])
        yield
        c = fund()
        s = send_tok([Coin(g, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_send(token_type=SLP_FUNGIBLE, token_id=g, amounts=[1000, 3990])),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)])  # burns 10
        yield
        c = fund()
        send_tok([Coin(s, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_send(token_type=SLP_FUNGIBLE, token_id=g, amounts=[2000])),
            CTxOut(TOKEN_DUST, P2SH)])  # invalid: more than input
        c = fund()
        send_tok([Coin(s, 2, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_burn(token_type=SLP_FUNGIBLE, token_id=g, amount=3990))])
        yield
        c = fund()
        send_tok([Coin(m, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, SlpScript([OP_RETURN, LOKAD_SLP, b"\x01", b"FOO"])),
            CTxOut(TOKEN_DUST, P2SH)])  # parse failure, burns 20
        c = fund()
        send_tok([c], [CTxOut(0, SlpScript([OP_RETURN, LOKAD_SLP, b"\x09", b"GENESIS"])),
                       CTxOut(TOKEN_DUST, P2SH)])  # unknown token type
        yield
        # --- NFT1 group / child
        c = fund()
        grp = send_tok([c], [CTxOut(0, slp_genesis(
            token_type=SLP_NFT1_GROUP, token_ticker=b"GRP", token_name=b"Group",
            mint_baton_vout=2, initial_mint_amount=10)),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)])
        self.token_ids.append(grp)
        yield
        c = fund()
        gs = send_tok([Coin(grp, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_send(token_type=SLP_NFT1_GROUP, token_id=grp, amounts=[1, 1, 1, 7])),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH),
            CTxOut(TOKEN_DUST, P2SH)])
        yield
        c = fund()
        child = send_tok([Coin(gs, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_genesis(token_type=SLP_NFT1_CHILD, token_ticker=b"NFT",
                                  token_name=b"Child 1", initial_mint_amount=1)),
            CTxOut(TOKEN_DUST, P2SH)])
        self.token_ids.append(child)
        c = fund()
        child2 = send_tok([Coin(gs, 2, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_genesis(token_type=SLP_NFT1_CHILD, token_ticker=b"NFT2",
                                  token_name=b"Child 2", initial_mint_amount=1)),
            CTxOut(TOKEN_DUST, P2SH)])
        self.token_ids.append(child2)
        yield
        c = fund()
        send_tok([Coin(child, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_send(token_type=SLP_NFT1_CHILD, token_id=child, amounts=[1])),
            CTxOut(TOKEN_DUST, P2SH)])
        c = fund()
        bad_child = send_tok([c], [  # child genesis without group input: invalid
            CTxOut(0, slp_genesis(token_type=SLP_NFT1_CHILD, token_ticker=b"BAD",
                                  initial_mint_amount=1)),
            CTxOut(TOKEN_DUST, P2SH)])
        if bad_child:
            self.token_ids.append(bad_child)
        yield
        # --- Mint vault
        c = fund()
        vs = send_tok([c], [CTxOut(10_000, CScript(w.spks["vault"])),
                            CTxOut(10_000, CScript(w.spks["vault"]))])
        c = fund()
        vg = send_tok([c], [CTxOut(0, slp_genesis(
            token_type=SLP_MINT_VAULT, token_ticker=b"VLT", token_name=b"Vault",
            mint_vault_scripthash=hash160(w.vault_redeem), initial_mint_amount=1000)),
            CTxOut(TOKEN_DUST, P2SH)])
        self.token_ids.append(vg)
        # mint before the vault setup confirms: "Missing MINT vault"
        vault0 = Coin(vs, 0, 10_000, "vault", w.spks["vault"])
        early = self.build([vault0], [
            CTxOut(0, slp_mint_vault(token_id=vg, mint_amounts=[1])),
            CTxOut(TOKEN_DUST, P2SH)], change_kind=None)
        self.send(early, [vault0])
        self.need_mine = True
        yield
        vault1 = Coin(vs, 1, 10_000, "vault", w.spks["vault"])
        vm = self.build([vault1], [
            CTxOut(0, slp_mint_vault(token_id=vg, mint_amounts=[500, 250])),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)], change_kind=None)
        self.send(vm, [vault1])
        yield
        # --- ALP
        c = fund()
        ag = send_tok([c], [
            alp_opreturn(alp_genesis(token_ticker=b"ALP", token_name=b"Alp Token",
                                     url=b"http://alp", data=b"\x01\x02",
                                     auth_pubkey=w.k1.get_pubkey().get_bytes(),
                                     decimals=4, mint_amounts=[10, 20], num_batons=1)),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)])
        self.token_ids.append(ag)
        yield
        c = fund()
        am = send_tok([Coin(ag, 3, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            alp_opreturn(alp_mint(ag, [5, 0], 1)),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)])
        yield
        c = fund()
        # genesis of a second token plus a send of the first, in one tx
        two = send_tok([Coin(ag, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)),
                        Coin(ag, 2, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            alp_opreturn(alp_genesis(token_ticker=b"ALP2", mint_amounts=[100], num_batons=0),
                         alp_send(ag, [0, 3, 27])),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)])
        if two:
            self.token_ids.append(two)
        yield
        c = fund()
        send_tok([Coin(two, 3, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            alp_opreturn(alp_burn(ag, 7), alp_send(ag, [20])),
            CTxOut(TOKEN_DUST, P2SH)])  # intentional burn
        c = fund()
        send_tok([Coin(two, 2, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            alp_opreturn(alp_send(ag, [1000])), CTxOut(TOKEN_DUST, P2SH)])  # overspend
        yield
        c = fund()
        send_tok([Coin(am, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            alp_opreturn(b"SLP2\x00\x03FOO", b"SLP2\x09junk", b"SLP2\x00\x04SE"),
            CTxOut(TOKEN_DUST, P2SH)])  # unknown/failed sections, burns
        c = fund()
        send_tok([Coin(two, 1, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            CTxOut(0, slp_send(token_type=SLP_FUNGIBLE, token_id=g, amounts=[1])),
            CTxOut(TOKEN_DUST, P2SH)])  # SLP tx spending ALP tokens
        yield
        c = fund()
        send_tok([Coin(am, 4, TOKEN_DUST, "p2sh_true", bytes(P2SH)), c], [
            alp_opreturn(alp_mint(ag, [1], 2)), CTxOut(TOKEN_DUST, P2SH),
            CTxOut(TOKEN_DUST, P2SH), CTxOut(TOKEN_DUST, P2SH)])
        yield

    def token_step(self):
        if self.token_gen is None:
            return
        try:
            next(self.token_gen)
            self.stats["token_steps"] += 1
        except StopIteration:
            self.token_gen = None
            if self.token_passes_left > 0:
                # Another pass with fresh tokens, so token txs also cross the
                # later reorgs and checkpoints.
                self.token_passes_left -= 1
                self.token_gen = self.token_script()
                self.token_step()

    # ---------------- reorgs

    def reorg_invalidate_fork(self, depth=2):
        """R1: invalidateblock on both, longer fork mined on A, reconsider."""
        tip = self.a.getblockcount()
        target = self.a.getblockhash(tip - depth + 1)
        old = [self.a.getblockhash(h) for h in range(tip - depth + 1, tip + 1)]
        for n in self.nodes:
            n.invalidateblock(target)
            self.ws_settle()
        self.assert_same_tip()
        self.mine(depth + 1, kind="other_drop")
        for n in self.nodes:
            n.reconsiderblock(target)
            self.ws_settle()
        self.assert_same_tip()
        assert self.a.getbestblockhash() not in old
        self.stale_blocks.update(old)
        self.refresh_coins()
        self.stats["reorgs"] += 1
        self.log.info(f"reorg R1 (invalidate + fork) depth {depth} at {tip}")

    def reorg_competing_chain(self):
        """R2: competing chain built in Python (with a double spend), submitted
        to both; both reorg via submitblock."""
        coin = self.take(1_000_000, kinds=["p2sh_true", "bare_true"])
        if coin is None or self.v2:
            if self.v2:
                self.notes.append("R2 (Python-built competing chain) not available on "
                                  "the V2 tier; used R1")
            return self.reorg_invalidate_fork(2)
        x = self.build([coin], [CTxOut(300_000, P2SH_OP_TRUE)])
        self.mine(1)  # coin confirmed below the fork point
        xid = self.send(x, [coin])
        self.mine(1)  # x at height h1
        h1 = self.a.getblockcount()
        child = next((c for c in self.coins if c.txid == xid and c.n == 0), None)
        if child is not None:
            self.send(self.build([child], [CTxOut(50_000, P2SH_OP_TRUE)]), [child])
        self.mine(1)
        tip = self.a.getblockcount()
        old = [self.a.getblockhash(h) for h in range(h1, tip + 1)]
        fork_parent = self.a.getblockhash(h1 - 1)
        ds = self.build([coin], [CTxOut(123_000, CScript(self.w.spks["bare_true"]))])
        prev = fork_parent
        prev_time = self.a.getblockheader(fork_parent)["time"]
        ok = True
        new = []
        for i in range(tip - h1 + 2):
            height = h1 + i
            self.tick(20)
            cb = create_coinbase(height, script_pubkey=P2SH_OP_TRUE)
            blk = create_block(int(prev, 16), cb, max(self.mocktime, prev_time + 1),
                               txlist=[ds] if i == 0 else None)
            blk.solve()
            res = self.submit_block_both(blk)
            if res not in (None, "inconclusive"):
                self.log.warning(f"python fork block rejected: {res}; falling back")
                ok = False
                break
            prev = blk.hash_hex() if callable(blk.hash_hex) else blk.hash_hex
            prev_time = blk.nTime
            new.append(prev)
        if not ok:
            self.notes.append(f"R2 python competing chain rejected ({res}); used R1")
            return self.reorg_invalidate_fork(2)
        self.assert_same_tip()
        assert self.a.getbestblockhash() == prev, "competing chain did not win"
        self.stale_blocks.update(old)
        self.conflicted.add(xid)
        self.seen_txids.add(self.txid_of(ds))
        self.refresh_coins()
        self.add_outputs(self.txid_of(ds), ds)
        self.stats["reorgs"] += 1
        self.log.info(f"reorg R2 (competing chain) {len(old)} -> {len(new)} blocks")

    def reorg_invalidate_reconsider(self, depth=3):
        """R3: deep invalidate on both, a mempool tx meanwhile, reconsider."""
        tip = self.a.getblockcount()
        target = self.a.getblockhash(tip - depth + 1)
        for n in self.nodes:
            n.invalidateblock(target)
            self.ws_settle()
        self.assert_same_tip()
        self.refresh_coins()
        self.tick(5)
        self.act_chain(2)
        for n in self.nodes:
            n.reconsiderblock(target)
            self.ws_settle()
        self.assert_same_tip()
        assert self.a.getblockcount() == tip
        self.refresh_coins()
        self.stats["reorgs"] += 1
        self.log.info(f"reorg R3 (invalidate/reconsider) depth {depth} at {tip}")

    def reorg_replace_tip(self):
        """R4: invalidate the tip on both, replace it with an empty block plus
        one more, reconsider the old tip (stays stale)."""
        old = self.a.getbestblockhash()
        for n in self.nodes:
            n.invalidateblock(old)
            self.ws_settle()
        self.tick(3)
        self.mine_with([], kind="p2pk65" if self.can_sign else "other_drop")
        self.mine(1)
        for n in self.nodes:
            n.reconsiderblock(old)
            self.ws_settle()
        self.assert_same_tip()
        self.stale_blocks.add(old)
        self.refresh_coins()
        self.stats["reorgs"] += 1
        self.log.info("reorg R4 (replace tip)")

    # ------------------------------------------------------------------
    # Checkpoints
    # ------------------------------------------------------------------

    def chronik_url(self, node):
        return f"http://127.0.0.1:{node.chronik_port}"

    def chronik_tip(self, ep):
        resp = ep.request({"method": "GET", "path": "/blockchain-info", "headers": {}})
        if resp.get("status") != 200:
            return None
        info = compare.load_pb().BlockchainInfo()
        info.ParseFromString(resp["body_bytes"])
        return info.tip_hash[::-1].hex(), info.tip_height

    def sync_both(self, timeout=120):
        for n in self.nodes:
            n.syncwithvalidationinterfacequeue()
        self.assert_same_tip()
        ma = sorted(self.a.getrawmempool())
        mb = sorted(self.b.getrawmempool())
        assert ma == mb, f"mempool mismatch: {set(ma) ^ set(mb)}"
        tip = self.a.getbestblockhash()
        height = self.a.getblockcount()
        P = compare.load_pb()
        deadline = time.time() + timeout
        for n in (self.a, self.b):
            ep = corpus.HttpEndpoint(self.chronik_url(n))
            while True:
                t = self.chronik_tip(ep)
                resp = ep.request({"method": "GET", "path": "/unconfirmed-txs", "headers": {}})
                n_mem = None
                if resp.get("status") == 200:
                    page = P.TxHistoryPage()
                    page.ParseFromString(resp["body_bytes"])
                    n_mem = page.num_txs
                if t == (tip, height) and n_mem == len(ma):
                    break
                if time.time() > deadline:
                    raise AssertionError(f"chronik not synced: {t} vs {(tip, height)}, "
                                         f"mempool {n_mem} vs {len(ma)}")
                time.sleep(0.05)
            ep.close()
        return ma

    def collect_record(self, mempool):
        a = self.a
        tip = a.getblockcount()
        blocks = []
        txids = set(self.seen_txids)
        scripts = {}
        recent = set(self.recent_txids)
        for h in range(tip + 1):
            bhash = a.getblockhash(h)
            info = self.block_cache.get(bhash)
            if info is None:
                blk = a.getblock(bhash, 2)
                info = {"txids": [t["txid"] for t in blk["tx"]],
                        "hexes": [t["hex"] for t in blk["tx"]],
                        "spks": [o["scriptPubKey"]["hex"] for t in blk["tx"]
                                 for o in t["vout"]]}
                self.block_cache[bhash] = info
            blocks.append({"height": h, "hash": bhash, "num_txs": len(info["txids"])})
            txids.update(info["txids"])
            if h > tip - 60:
                recent.update(info["txids"])
            for spk in info["spks"]:
                scripts[spk] = None
        for bhash in self.stale_blocks:
            info = self.block_cache.get(bhash)
            if info is None:
                try:
                    blk = a.getblock(bhash, 2)
                    info = {"txids": [t["txid"] for t in blk["tx"]],
                            "spks": [o["scriptPubKey"]["hex"] for t in blk["tx"]
                                     for o in t["vout"]]}
                    self.block_cache[bhash] = info
                except JSONRPCException:
                    continue
            txids.update(info["txids"])
            recent.update(info["txids"])
        for txid in mempool:
            if txid not in self.mempool_spk_cache:
                dec = a.getrawtransaction(txid, True)
                self.mempool_spk_cache[txid] = [o["scriptPubKey"]["hex"] for o in dec["vout"]]
            for spk in self.mempool_spk_cache[txid]:
                scripts[spk] = None
        txids.update(mempool)
        recent.update(mempool)
        recent.update(self.conflicted)
        script_rows = {}
        for spk_hex in scripts:
            stype, payload = classify_script(bytes.fromhex(spk_hex))
            script_rows[(stype, payload.hex())] = spk_hex
        rows = sorted([[s, p, spk] for (s, p), spk in script_rows.items()])
        v2_branches, v2_assets = set(), set()
        if self.v2:
            for spk_hex in scripts:
                members = v2_frame_members(bytes.fromhex(spk_hex))
                if members is not None:
                    v2_branches.update(b.hex() for b in members[0])
                    if members[1] is not None:
                        v2_assets.add(members[1].hex())
        # deterministic raw tx sample: some mempool, some confirmed
        sample = []
        for txid in sorted(mempool)[:10]:
            sample.append(a.getrawtransaction(txid))
        conf = [x for b in blocks[-30:] if b["height"] > 0
                for x in self.block_cache[b["hash"]]["hexes"]]
        sample += conf[:: max(1, len(conf) // 15)][:15]
        lokads = sorted({lk.hex() for lk in LOKAD_IDS + [LOKAD_SLP, LOKAD_ALP]})
        return {
            "tip_height": tip,
            "tip_hash": a.getbestblockhash(),
            "blocks": blocks,
            "stale_blocks": sorted(self.stale_blocks),
            "txids": sorted(txids),
            "recent_txids": sorted(recent),
            "mempool": sorted(mempool),
            "scripts": rows,
            "token_ids": sorted(set(t for t in self.token_ids if t)) if self.tokens else [],
            "lokad_ids": lokads,
            # Lotus V2: branch roots / asset IDs of the native output frames,
            # for the "v2-branch"/"taproot"/"v2-asset" WS subscriptions.
            "v2_branches": sorted(v2_branches),
            "v2_assets": sorted(v2_assets),
            "validate_txs": self.make_validate_txs(),
            "raw_txs_sample": sample,
            "tokens_enabled": self.tokens,
            "scripthash_index": self.scripthash_index,
        }

    def make_validate_txs(self):
        """Fresh, never-sent txs for /validate-tx (not mutating)."""
        out = []
        for c in self.coins[:3]:
            try:
                out.append(self.build([c], [CTxOut(1000, P2SH_OP_TRUE)]).serialize().hex())
            except AssertionError:
                pass
        if self.coins and self.tokens and self.token_ids:
            c = self.coins[-1]
            try:
                tx = self.build([c], [CTxOut(0, slp_send(
                    token_type=SLP_FUNGIBLE, token_id=self.token_ids[0], amounts=[5])),
                    CTxOut(TOKEN_DUST, P2SH_OP_TRUE)])
                out.append(tx.serialize().hex())
            except AssertionError:
                pass
        if self.coins and self.v2:
            c = self.coins[0]
            out.append(V2Tx(self.w, [c], [V2Out(c.value + 1, b"", V2_OP1)])
                       .serialize().hex())  # overspend
        elif self.coins:
            c = self.coins[0]
            tx = CTransaction()
            tx.vin = [CTxIn(c.outpoint(), b"", 0xFFFFFFFF)]  # bad script
            tx.vout = [CTxOut(c.value + 1, P2SH_OP_TRUE)]  # overspend
            pad_tx(tx, deterministic=True)
            out.append(tx.serialize().hex())
        return out

    def make_broadcast_spec(self):
        """Final mutating broadcasts: each request is sent to A then B."""
        spec = {"single": [], "batch": []}
        coins = [c for c in self.coins if c.value >= 50_000 and c.kind in CHANGE_KINDS]
        if len(coins) < 4:
            self.notes.append("not enough coins for broadcast phase")
            return spec
        c0, c1, c2, c3 = coins[:4]
        t0 = self.build([c0], [CTxOut(10_000, CScript(self.w.spks["p2sh_lokad"]))])
        spec["single"].append({"raw": t0.serialize().hex()})
        spec["single"].append({"raw": t0.serialize().hex()})  # again: already known
        if self.tokens and self.token_ids:
            burn = self.build([Coin(self.token_ids[0], 1, TOKEN_DUST, "p2sh_true",
                                    bytes(P2SH_OP_TRUE)), c1],
                              [CTxOut(5000, P2SH_OP_TRUE)])
            spec["single"].append({"raw": burn.serialize().hex()})  # token checks fail
            spec["single"].append({"raw": burn.serialize().hex(), "skip_token_checks": True})
        t2 = self.build([c2], [CTxOut(20_000, P2SH_OP_TRUE)])
        t2_id = self.txid_of(t2)
        t2_child = self.build([Coin(t2_id, 0, 20_000, "p2sh_true", bytes(P2SH_OP_TRUE))],
                              [CTxOut(5_000, P2SH_OP_TRUE)])
        spec["batch"].append({"raws": [t2.serialize().hex(), t2_child.serialize().hex()]})
        t3 = self.build([c3], [CTxOut(20_000, P2SH_OP_TRUE)])
        spec["single"].append({"raw": t3.serialize().hex(), "timeout": 1})
        bad = self.build([c3], [CTxOut(30_000, P2SH_OP_TRUE)])  # conflicts with t3
        spec["batch"].append({"raws": [bad.serialize().hex()]})
        self.spend([c0, c1, c2, c3])
        return spec

    def run_dumps(self, label):
        o = self.options
        if not o.dump_tool:
            return
        dirs = [os.path.join(n.datadir, self.chain, "indexes", "chronik")
                for n in (self.a, self.b)]
        if o.dump_mode == "stopped":
            self.stop_nodes()
        outs = []
        for side, d in zip("AB", dirs):
            path = os.path.join(o.tmpdir, "dumps", f"{label}.{side}.tsv")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            cmd = shlex.split(o.dump_tool)
            if o.dump_mode == "live" and o.dump_live_arg:
                cmd.append(o.dump_live_arg)
            cmd.append(d)
            with open(path, "w", encoding="utf8") as f:
                rc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            if rc.returncode != 0:
                self.report.add_dump({"checkpoint": label, "equal": False,
                                      "error": f"{side}: rc={rc.returncode} {rc.stderr[-500:]}"})
                outs = None
                break
            outs.append(path)
        if o.dump_mode == "stopped":
            for i, n in enumerate(self.nodes):
                args = [a for a in self.node_args[i] if not a.startswith("-mocktime=")]
                self.start_node(i, args + [f"-mocktime={self.mocktime}"])
            self.tick(0)
            self.sync_both()
        if outs:
            res = compare.compare_dump_files(outs[0], outs[1], label)
            self.report.add_dump(res)
            self.log.info(f"dump {label}: {'equal' if res['equal'] else 'DIFFERENT'} "
                          f"({res['lines_a']} / {res['lines_b']} lines)")

    def checkpoint(self, final=False):
        label = f"h{self.a.getblockcount()}" + ("-final" if final else "")
        t0 = time.time()
        if final and not self.options.no_broadcast and not self.options.no_http:
            spec = self.make_broadcast_spec()
            reqs = corpus.broadcast_requests(spec)
            self.sync_both()
            c = self.runner.run(reqs, label + "-broadcast")
            self.log.info(f"broadcast phase: {c}")
            self.mine(1)
        mempool = self.sync_both()
        label = f"h{self.a.getblockcount()}" + ("-final" if final else "")
        cp = {"label": label, "tip": self.a.getblockcount(), "mempool": len(mempool)}
        if self.ws is not None:
            cp["ws"] = self.ws.finish(self.report, self.ws_label,
                                      self.save_dir)
            self.ws = None
        record = self.collect_record(mempool)
        with open(os.path.join(self.options.tmpdir, "records", f"{label}.json"), "w",
                  encoding="utf8") as f:
            json.dump(record, f, indent=1)
        if not self.options.no_http:
            mode = "full" if final else self.options.corpus_mode
            reqs = corpus.build_requests(record, mode,
                                         max_scripts=self.options.max_scripts)
            cp["http"] = self.runner.run(reqs, label)
        self.run_dumps(label)
        if not final and not self.options.no_ws:
            self.ws_label = label
            self.ws = corpus.WsStretch(
                self.chronik_url(self.a).replace("http", "ws") + "/ws",
                self.chronik_url(self.b).replace("http", "ws") + "/ws",
                corpus.build_ws_plans(record, label))
            self.ws.quiesce(idle=0.3)
        self.recent_txids = set()
        cp["seconds"] = round(time.time() - t0, 1)
        cp["records"] = {"txids": len(record["txids"]), "scripts": len(record["scripts"]),
                         "tokens": len(record["token_ids"]),
                         "stale_blocks": len(record["stale_blocks"])}
        self.report.checkpoints.append(cp)
        self.log.info(f"checkpoint {label}: {json.dumps(cp)}")
        if not self.report.ok() and not self.options.keep_going and not final:
            raise AssertionError(f"differences at checkpoint {label}; see report")

    def maybe_checkpoint(self):
        h = self.a.getblockcount()
        if h >= self.next_cp:
            self.checkpoint()
            while self.next_cp <= h:
                self.next_cp += self.options.checkpoint_interval

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------

    def run_test(self):
        o = self.options
        compare.load_pb(o.pb2_dir, os.environ.get("CHRONIK_PARITY_SRCDIR"))
        assert o.blocks >= 110, "--blocks must be >= 110"
        self.rng = random.Random(o.seed)
        self.w = Wallet()
        allow = compare.DEFAULT_ALLOW + o.allow
        if self.v2:
            allow += compare.V2_ACCEPTED
        self.report = compare.Report(allow)
        self.notes = self.report.notes
        os.makedirs(os.path.join(o.tmpdir, "records"), exist_ok=True)
        self.save_dir = os.path.join(o.tmpdir, "responses") if o.save_responses else None
        self.runner = corpus.Runner(self.chronik_url(self.a), self.chronik_url(self.b),
                                    self.report, self.save_dir, log=self.log.info)
        self.coins = []
        self.cb_blocks = []
        self.cb_rot = 0
        self.op_rot = 0
        self.change_rot = 0
        self.blocks_mined = 0
        self.seen_txids = set()
        self.recent_txids = set()
        self.conflicted = set()
        self.stale_blocks = set()
        self.token_ids = []
        self.block_cache = {}
        self.mempool_spk_cache = {}
        self.rejects = []
        self.need_mine = False
        self.ws = None
        self.ws_label = None
        self.stats = {k: 0 for k in ("txs_sent", "txs_rejected", "unexpected_accept",
                                     "conflicts", "reorgs", "token_steps",
                                     "ctor_chains")}
        self.can_sign = not self.v2
        self.cb_kinds = ["p2sh_true", "p2sh_true", "p2pkh", "bare_true", "p2pk",
                         "p2sh_lokad", "other_drop", "p2pk65"]
        if self.v2:
            self.notes.append("V2 tier: v7 txs spending 0x4e branch outputs; "
                              "no legacy scripts/signatures, no tokens")
        self.next_cp = o.checkpoint_interval
        self.token_gen = self.token_script() if self.tokens else None
        self.token_passes_left = 0
        if not self.tokens:
            self.notes.append("tokens disabled (-chroniktokenindex=0)")

        # ---- Initial maturity, with checkpoints along the way
        self.log.info(f"mining {COINBASE_MATURITY + 2} initial blocks")
        while self.a.getblockcount() < COINBASE_MATURITY + 2:
            self.mine(1)
            if self.a.getblockcount() == 1 and not self.options.no_ws:
                # open the first WS stretch early so it covers the run start
                self.checkpoint()
                self.next_cp = o.checkpoint_interval
            self.maybe_checkpoint()

        # Probe signing (legacy sighash may not apply to every tier).
        probe = None
        for _ in range(30):
            probe = self.take_coinbase()
            if probe is not None:
                break
            self.mine(1)
        if probe is None:
            raise AssertionError("no spendable coinbase output of a known script found")
        if probe.kind in Wallet.SIGNED:
            tx = self.build([probe], [CTxOut(10_000, P2SH_OP_TRUE)])
            res = self.a.testmempoolaccept([tx.serialize().hex()])[0]
            self.can_sign = res["allowed"]
            if self.can_sign:
                self.send(tx, [probe])
        else:
            self.send(self.build([probe], [CTxOut(10_000, P2SH_OP_TRUE)]), [probe])
        if not self.can_sign:
            if not self.v2:
                self.notes.append("signed P2PKH/P2PK spends rejected by node; outputs only")
            self.cb_kinds = [k for k in self.cb_kinds if k not in Wallet.SIGNED] + ["p2pkh"]
        self.log.info(f"can_sign={self.can_sign}")

        start = self.a.getblockcount()
        span = o.blocks - start
        reorg_plan = [
            (start + int(span * 0.30), self.reorg_invalidate_fork),
            (start + int(span * 0.50), self.reorg_competing_chain),
            (start + int(span * 0.70), self.reorg_invalidate_reconsider),
            (start + int(span * 0.85), self.reorg_replace_tip),
        ]
        est_rounds = max(1, span // 2)
        passes = 1 if est_rounds < 60 else 3
        self.token_passes_left = passes - 1 if self.tokens else 0
        total_steps = TOKEN_STEPS_PER_PASS * passes
        token_steps_per_round = max(1, -(-total_steps // max(1, int(est_rounds * 0.6))))
        token_every = max(1, int(est_rounds * 0.8) // total_steps)
        rnd = 0
        while self.a.getblockcount() < o.blocks:
            rnd += 1
            self.tick(self.rng.randint(1, 30))
            self.act_fanout()
            self.act_chain(self.rng.randint(1, 4))
            if rnd % 2 == 0:
                self.act_opreturns()
            if rnd % 3 == 0:
                self.act_consolidate()
            if rnd % 4 == 1:
                self.act_ctor_chain(self.rng.randint(2, 4))
            for _ in range(token_steps_per_round if rnd % token_every == 0 else 0):
                self.token_step()
                if self.need_mine:
                    self.need_mine = False
                    break
            if rnd % 6 == 3:
                self.act_conflict()
            while reorg_plan and self.a.getblockcount() >= reorg_plan[0][0]:
                _, fn = reorg_plan.pop(0)
                fn()
            if self.a.getblockcount() >= o.blocks:
                break
            # Leave some txs unconfirmed: send a few after mining.
            self.mine(self.rng.choice([1, 1, 2, 3]))
            if self.rng.random() < 0.5:
                self.act_chain(1)
            self.maybe_checkpoint()
        # flush remaining token steps and reorgs (small runs)
        while self.token_gen is not None:
            self.token_step()
            if self.need_mine:
                self.need_mine = False
                self.mine(1)
        for _, fn in reorg_plan:
            fn()
        self.act_chain(2)
        self.act_opreturns()
        self.checkpoint(final=True)

        self.report.notes.append(f"stats: {json.dumps(self.stats)}")
        self.report.notes.append(f"distinct rejected tx messages: "
                                 f"{sorted(set(self.rejects))[:20]}")
        path = o.report or os.path.join(o.tmpdir, "report.json")
        self.report.write(path)
        self.runner.close()
        print(self.report.summary())
        self.log.info(f"stats {self.stats}; report {path}")
        assert self.report.ok(), f"unexpected differences, see {path}"


if __name__ == "__main__":
    ParityChain().main()
