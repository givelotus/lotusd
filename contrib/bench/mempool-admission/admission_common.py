# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Shared helpers for the mempool admission benchmark.

Only the Python standard library and the in-tree functional test framework
(test/functional/test_framework) are used. Binaries and directories are
always passed in by the caller; nothing here guesses a build location.
"""

import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(SOURCE_ROOT / "test" / "functional"))

from test_framework.key import ECKey  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    hash256,
    msg_verack,
    msg_version,
)
from test_framework.script import (  # noqa: E402
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_HASH160,
    CScript,
)
from test_framework.signature_hash import (  # noqa: E402
    SIGHASH_ALL,
    SIGHASH_FORKID,
    SignatureHashForkId,
)

REGTEST_MAGIC = b"\xda\xb5\xbf\xfa"
P2P_VERSION = 70017
RPC_USER = "admissionbench"
RPC_PASS = "admissionbench"
HASHTYPE = SIGHASH_ALL | SIGHASH_FORKID


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def derive_key(seed: str, index: int) -> ECKey:
    secret = hashlib.sha256(f"{seed}:{index}".encode()).digest()
    key = ECKey()
    key.set(secret, True)
    return key


def p2pkh_script(pubkey: bytes) -> CScript:
    return CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG])


def sign_p2pkh_inputs(tx: CTransaction, spent, keys, schnorr_flags):
    """Sign every input of tx as P2PKH.

    spent[i] = (scriptPubKey bytes, amount sats), keys[i] = (ECKey, pubkey),
    schnorr_flags[i] selects a 64-byte Schnorr or a DER ECDSA signature.
    """
    for i, ((spk, amount), (key, pub), schnorr) in enumerate(
        zip(spent, keys, schnorr_flags)
    ):
        sighash = SignatureHashForkId(CScript(spk), tx, i, HASHTYPE, amount)
        if schnorr:
            sig = key.sign_schnorr(sighash)
        else:
            sig = key.sign_ecdsa(sighash)
        tx.vin[i].scriptSig = CScript([sig + bytes([HASHTYPE]), pub])


def build_tx(prevouts, outputs):
    tx = CTransaction()
    tx.nVersion = 2
    for txid_hex, n in prevouts:
        tx.vin.append(CTxIn(COutPoint(int(txid_hex, 16), n), b"", 0xFFFFFFFF))
    for spk, amount in outputs:
        tx.vout.append(CTxOut(amount, spk))
    return tx


# ---------------------------------------------------------------- node control


class RPC:
    def __init__(self, port: int, timeout: float = 300.0):
        self.port = port
        self.timeout = timeout
        self.auth = (
            "Basic " + base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
        )
        self.conn = None

    def _connect(self):
        self.conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=self.timeout
        )

    def call(self, method, *params):
        body = json.dumps(
            {"jsonrpc": "1.0", "id": method, "method": method, "params": list(params)}
        )
        for attempt in range(2):
            if self.conn is None:
                self._connect()
            try:
                self.conn.request(
                    "POST",
                    "/",
                    body,
                    {"Authorization": self.auth, "Content-Type": "application/json"},
                )
                resp = self.conn.getresponse()
                data = resp.read()
                break
            except (ConnectionError, http.client.HTTPException, OSError):
                self.conn = None
                if attempt:
                    raise
        reply = json.loads(data)
        if reply.get("error"):
            raise RuntimeError(f"{method}: {reply['error']}")
        return reply["result"]


def ports_for(portseed: int):
    """Ports outside 20000-34999; one block of 4 per seed starting at 47000."""
    if not 0 <= portseed < 2000:
        raise ValueError("portseed must be in [0, 2000)")
    base = 47000 + 4 * portseed
    return {"p2p": base, "rpc": base + 1, "zmq": base + 2}


def start_node(bitcoind, datadir, ports, extra_args=(), log_path=None):
    datadir = Path(datadir)
    datadir.mkdir(parents=True, exist_ok=True)
    args = [
        str(bitcoind),
        "-regtest",
        f"-datadir={datadir}",
        f"-port={ports['p2p']}",
        f"-rpcport={ports['rpc']}",
        "-bind=127.0.0.1",
        "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1",
        f"-rpcuser={RPC_USER}",
        f"-rpcpassword={RPC_PASS}",
        "-listen=1",
        "-listenonion=0",
        "-discover=0",
        "-dnsseed=0",
        "-fixedseeds=0",
        "-connect=0",
        "-server=1",
        "-printtoconsole=0",
        "-rpcthreads=16",
        "-rpcworkqueue=256",
        "-whitelist=noban@127.0.0.1",
        "-maxmempool=2000",
        "-dbcache=1024",
        "-shrinkdebugfile=0",
    ] + list(extra_args)
    out = open(log_path, "wb") if log_path else subprocess.DEVNULL
    proc = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT)
    rpc = RPC(ports["rpc"])
    deadline = time.time() + 180
    while True:
        if proc.poll() is not None:
            raise RuntimeError(f"node exited early with {proc.returncode}: {args}")
        try:
            rpc.call("getblockcount")
            break
        except Exception:
            if time.time() > deadline:
                proc.kill()
                raise
            time.sleep(0.25)
    return proc, rpc, args


def stop_node(proc, rpc, timeout=120):
    try:
        rpc.call("stop")
    except Exception:
        pass
    try:
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def clone_tree(src, dst):
    """APFS clone copy when available (cp -c), otherwise an ordinary copy."""
    dst = Path(dst)
    if dst.exists():
        shutil.rmtree(dst)
    if sys.platform == "darwin":
        r = subprocess.run(["cp", "-c", "-R", str(src), str(dst)])
        if r.returncode == 0:
            return
    shutil.copytree(src, dst)


# ---------------------------------------------------------------- raw P2P


def p2p_frame(msgtype: bytes, payload: bytes) -> bytes:
    return (
        REGTEST_MAGIC
        + msgtype
        + b"\x00" * (12 - len(msgtype))
        + struct.pack("<I", len(payload))
        + hash256(payload)[:4]
        + payload
    )


def p2p_connect(port: int, timeout: float = 30.0, relay: bool = True) -> socket.socket:
    """Connect and finish version/verack; returns a blocking socket.

    relay=False sets the version relay flag to 0: the node then announces no
    transactions to this peer (it still accepts transactions from it).
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    v = msg_version()
    v.nVersion = P2P_VERSION
    v.nServices = 1
    v.strSubVer = "/admission-bench:0.1/"
    v.relay = 1 if relay else 0
    v.addrTo.ip = "127.0.0.1"
    v.addrTo.port = port
    v.addrFrom.ip = "0.0.0.0"
    v.addrFrom.port = 0
    sock.sendall(p2p_frame(b"version", v.serialize()))
    got_version = got_verack = False
    buf = b""
    deadline = time.time() + timeout
    while not (got_version and got_verack):
        if time.time() > deadline:
            raise TimeoutError("p2p handshake")
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("node closed during handshake")
        buf += chunk
        while len(buf) >= 24:
            length = struct.unpack("<I", buf[16:20])[0]
            if len(buf) < 24 + length:
                break
            cmd = buf[4:16].rstrip(b"\x00")
            buf = buf[24 + length :]
            if cmd == b"version":
                got_version = True
                sock.sendall(p2p_frame(b"verack", msg_verack().serialize()))
            elif cmd == b"verack":
                got_verack = True
    return sock


# ---------------------------------------------------------------- ZMQ (ctypes)


class ZmqSub:
    """Minimal libzmq SUB socket over ctypes (no pyzmq dependency)."""

    ZMQ_SUB = 2
    ZMQ_SUBSCRIBE = 6
    ZMQ_RCVHWM = 24
    ZMQ_RCVTIMEO = 27
    ZMQ_RCVMORE = 13

    def __init__(self, libpath, endpoint, topic=b"sequence"):
        import ctypes

        self.ct = ctypes
        self.lib = ctypes.CDLL(libpath)
        self.lib.zmq_ctx_new.restype = ctypes.c_void_p
        self.lib.zmq_socket.restype = ctypes.c_void_p
        self.lib.zmq_socket.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.zmq_setsockopt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.lib.zmq_getsockopt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.lib.zmq_connect.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.zmq_recv.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        self.lib.zmq_close.argtypes = [ctypes.c_void_p]
        self.lib.zmq_ctx_term.argtypes = [ctypes.c_void_p]
        self.ctx = self.lib.zmq_ctx_new()
        self.sock = self.lib.zmq_socket(self.ctx, self.ZMQ_SUB)
        hwm = ctypes.c_int(0)
        self.lib.zmq_setsockopt(
            self.sock, self.ZMQ_RCVHWM, ctypes.byref(hwm), ctypes.sizeof(hwm)
        )
        tmo = ctypes.c_int(200)
        self.lib.zmq_setsockopt(
            self.sock, self.ZMQ_RCVTIMEO, ctypes.byref(tmo), ctypes.sizeof(tmo)
        )
        self.lib.zmq_setsockopt(self.sock, self.ZMQ_SUBSCRIBE, topic, len(topic))
        if self.lib.zmq_connect(self.sock, endpoint.encode()) != 0:
            raise RuntimeError("zmq_connect failed")
        self.buf = ctypes.create_string_buffer(256)

    def recv_multipart(self):
        """Returns a list of frames, or None on timeout."""
        frames = []
        while True:
            n = self.lib.zmq_recv(self.sock, self.buf, 256, 0)
            if n < 0:
                if frames:
                    continue
                return None
            frames.append(self.buf.raw[: min(n, 256)])
            more = self.ct.c_int(0)
            size = self.ct.c_size_t(self.ct.sizeof(more))
            self.lib.zmq_getsockopt(
                self.sock, self.ZMQ_RCVMORE, self.ct.byref(more), self.ct.byref(size)
            )
            if not more.value:
                return frames

    def close(self):
        self.lib.zmq_close(self.sock)
        self.lib.zmq_ctx_term(self.ctx)


def find_libzmq(explicit=None):
    if explicit:
        return explicit
    for cand in (
        os.environ.get("LIBZMQ"),
        "/opt/homebrew/lib/libzmq.dylib",
        "/usr/local/lib/libzmq.dylib",
        "/usr/lib/x86_64-linux-gnu/libzmq.so.5",
        "/usr/lib/aarch64-linux-gnu/libzmq.so.5",
    ):
        if cand and Path(cand).exists():
            return cand
    raise FileNotFoundError("libzmq not found; pass --libzmq")


def percentile(values, q):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def scrape_metrics(port, path="/metrics"):
    """Fetch Prometheus text from the RPC port (requires -metrics=1)."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        auth = "Basic " + base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
        conn.request("GET", path, headers={"Authorization": auth})
        resp = conn.getresponse()
        if resp.status != 200:
            return {}
        text = resp.read().decode()
    except Exception:
        return {}
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            name, value = line.rsplit(" ", 1)
            out[name] = float(value)
        except ValueError:
            continue
    return out
