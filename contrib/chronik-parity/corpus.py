#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""HTTP and WebSocket request corpus for Chronik parity checks.

The corpus is generated from a *record* (JSON, written by parity_chain.py)
listing every block, tx, script, token id and LOKAD id seen in a chain run.
Every request is sent to both implementations, in the same order, and the
response pairs are compared with compare.py.

Route coverage follows chronik-http/src/server.rs (make_router): every GET
route for every recorded object, pagination edges (page 0, last page, one past
the last page, page_size 1/200/201/0, malformed values), malformed path
params, wrong methods, OPTIONS, bad/missing/non-UTF-8 content types, bad
protobuf bodies, oversized bodies (> 2,000,000 bytes), the 500-script batch
limit, /validate-tx, /broadcast-tx(s) and the plugin/pause routes.

CLI (run a recorded corpus against two already running Chronik instances):

    corpus.py --record record.json --url-a http://127.0.0.1:PA \\
              --url-b http://127.0.0.1:PB --report report.json

Mutating requests (successful broadcasts) are only generated when the record
contains a `broadcast` section and --allow-mutating is given; they are sent to
A and then to B with identical bodies.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare  # noqa: E402

MAX_REQUEST_BODY_SIZE = 2_000_000
MAX_NUM_BATCH_SCRIPTS = 500
MAX_BLOCKS_PAGE_SIZE = 500
PROTOBUF_CT = "application/x-protobuf"

HISTORY_PAGE_EDGES = [
    "?page=0",
    "?page_size=1",
    "?page_size=200",
    "?page_size=201",
    "?page_size=0",
    "?page=0&page_size=25",
    "?page=abc",
    "?page=-1",
    "?page_size=-5",
    "?page=99999999",
    "?page_size=4294967296",
    "?foo=bar",
]


def pb():
    return compare.load_pb()


def _req(route, method, path, pb_type=None, body=None, headers=None, paged=False,
         mutating=False, fresh_conn=False):
    return {
        "route": route,
        "method": method,
        "path": path,
        "pb_type": pb_type,
        "body": body,
        "headers": headers or {},
        "paged": paged,
        "mutating": mutating,
        "fresh_conn": fresh_conn,
    }


def _post(route, path, msg_bytes, pb_type, content_type=PROTOBUF_CT, **kw):
    headers = {} if content_type is None else {"Content-Type": content_type}
    return _req(route, "POST", path, pb_type, body=msg_bytes, headers=headers, **kw)


def hex_be_sha256(script: bytes) -> str:
    return hashlib.sha256(script).digest()[::-1].hex()


# --------------------------------------------------------------------------
# Corpus generation
# --------------------------------------------------------------------------


def _history_routes(prefix_route, prefix_path, subroutes) -> List[Dict[str, Any]]:
    """History-like GET routes plus pagination edges."""
    out = []
    for sub, pb_type, paged in subroutes:
        route = f"{prefix_route}/{sub}"
        path = f"{prefix_path}/{sub}"
        out.append(_req(route, "GET", path, pb_type, paged=paged))
        if paged:
            for edge in HISTORY_PAGE_EDGES:
                out.append(_req(route, "GET", path + edge, pb_type))
    return out


SCRIPT_SUBROUTES = [
    ("history", "TxHistoryPage", True),
    ("confirmed-txs", "TxHistoryPage", True),
    ("unconfirmed-txs", "TxHistoryPage", False),
    ("utxos", "ScriptUtxos", False),
]
TOKEN_SUBROUTES = [
    ("history", "TxHistoryPage", True),
    ("confirmed-txs", "TxHistoryPage", True),
    ("unconfirmed-txs", "TxHistoryPage", False),
    ("utxos", "Utxos", False),
]
LOKAD_SUBROUTES = [
    ("history", "TxHistoryPage", True),
    ("confirmed-txs", "TxHistoryPage", True),
    ("unconfirmed-txs", "TxHistoryPage", False),
]


def sample_scripts(scripts: List, max_scripts: Optional[int]) -> List:
    """Deterministic, evenly spaced subset (all if max_scripts is None/0)."""
    if not max_scripts or len(scripts) <= max_scripts:
        return scripts
    step = len(scripts) / max_scripts
    return [scripts[int(i * step)] for i in range(max_scripts)]


def build_requests(record: Dict[str, Any], mode: str = "full",
                   allow_mutating: bool = False,
                   max_scripts: Optional[int] = None) -> List[Dict[str, Any]]:
    """Generate the HTTP corpus for a record. mode: full | light.

    max_scripts caps the per-script GET routes (the V2 tier encodes the value
    into each output script, so nearly every output is its own script)."""
    P = pb()
    reqs: List[Dict[str, Any]] = []
    blocks = record["blocks"]
    tip = record["tip_height"]
    light_from = max(0, tip - 60) if mode == "light" else 0

    # ---- Info
    reqs.append(_req("/blockchain-info", "GET", "/blockchain-info", "BlockchainInfo"))
    reqs.append(_req("/chronik-info", "GET", "/chronik-info", "ChronikInfo"))
    reqs.append(_req("/blockchain-info", "HEAD", "/blockchain-info", "BlockchainInfo"))
    reqs.append(_req("/unconfirmed-txs", "GET", "/unconfirmed-txs", "TxHistoryPage"))
    reqs.append(_req("/unconfirmed-txs", "GET", "/unconfirmed-txs?page=1&page_size=1",
                     "TxHistoryPage"))

    # ---- Blocks
    for blk in blocks:
        h, bhash, ntx = blk["height"], blk["hash"], blk["num_txs"]
        if h < light_from and h % 50 != 0:
            continue
        reqs.append(_req("/block/:hash_or_height", "GET", f"/block/{h}", "Block"))
        reqs.append(_req("/block/:hash_or_height", "GET", f"/block/{bhash}", "Block"))
        reqs.append(_req("/block-header/:hash_or_height", "GET", f"/block-header/{h}",
                         "BlockHeader"))
        reqs.append(_req("/block-header/:hash_or_height", "GET",
                         f"/block-header/{bhash}?checkpoint_height={tip}", "BlockHeader"))
        reqs.append(_req("/block-txs/:hash_or_height", "GET", f"/block-txs/{h}",
                         "TxHistoryPage", paged=ntx > 1))
        if ntx > 1:
            for edge in ["?page=0", "?page_size=1", "?page_size=200", "?page_size=201"]:
                reqs.append(_req("/block-txs/:hash_or_height", "GET",
                                 f"/block-txs/{bhash}{edge}", "TxHistoryPage"))
    for edge in ["?page_size=0", "?page=abc", "?page=-1", "?page=99999999"]:
        reqs.append(_req("/block-txs/:hash_or_height", "GET", f"/block-txs/{tip}{edge}",
                         "TxHistoryPage"))
    for ck in [0, 1, tip // 2, tip, tip + 1, -1, "abc"]:
        reqs.append(_req("/block-header/:hash_or_height", "GET",
                         f"/block-header/{tip // 2}?checkpoint_height={ck}", "BlockHeader"))
    for bhash in record.get("stale_blocks", []):
        reqs.append(_req("/block/:hash_or_height", "GET", f"/block/{bhash}", "Block"))
        reqs.append(_req("/block-header/:hash_or_height", "GET", f"/block-header/{bhash}",
                         "BlockHeader"))
        reqs.append(_req("/block-txs/:hash_or_height", "GET", f"/block-txs/{bhash}",
                         "TxHistoryPage"))
    for bad in [tip + 1, tip + 1000, -1, 2**31, "abc", "0" * 64, "0" * 63, "zz" * 32, ""]:
        reqs.append(_req("/block/:hash_or_height", "GET", f"/block/{bad}", "Block"))
        reqs.append(_req("/block-txs/:hash_or_height", "GET", f"/block-txs/{bad}",
                         "TxHistoryPage"))
        reqs.append(_req("/block-header/:hash_or_height", "GET", f"/block-header/{bad}",
                         "BlockHeader"))
    ranges = [
        (0, 0), (0, min(tip, MAX_BLOCKS_PAGE_SIZE - 1)), (0, MAX_BLOCKS_PAGE_SIZE),
        (max(0, tip - 10), tip), (tip, tip + 5), (tip + 1, tip + 2), (5, 3), (-1, 3),
        (3, -1), (0, 2**31 - 1), ("a", 3),
    ]
    for s, e in ranges:
        reqs.append(_req("/blocks/:start/:end", "GET", f"/blocks/{s}/{e}", "Blocks"))
        reqs.append(_req("/block-headers/:start/:end", "GET", f"/block-headers/{s}/{e}",
                         "BlockHeaders"))
    for ck in [tip, tip // 2, tip + 1, 0]:
        reqs.append(_req("/block-headers/:start/:end", "GET",
                         f"/block-headers/0/{min(tip, 20)}?checkpoint_height={ck}",
                         "BlockHeaders"))
        reqs.append(_req("/block-headers/:start/:end", "GET",
                         f"/block-headers/{max(0, tip - 5)}/{tip}?checkpoint_height={ck}",
                         "BlockHeaders"))

    # ---- Txs
    recent = set(record.get("recent_txids", [])) if mode == "light" else None
    for txid in record["txids"]:
        if recent is not None and txid not in recent:
            continue
        reqs.append(_req("/tx/:txid", "GET", f"/tx/{txid}", "Tx"))
        reqs.append(_req("/raw-tx/:txid", "GET", f"/raw-tx/{txid}", "RawTx"))
        reqs.append(_req("/token/:txid", "GET", f"/token/{txid}", "TokenInfo"))
    for bad in ["zz", "0" * 63, "0" * 64, "0" * 65, "g" * 64, "%20"]:
        reqs.append(_req("/tx/:txid", "GET", f"/tx/{bad}", "Tx"))
        reqs.append(_req("/raw-tx/:txid", "GET", f"/raw-tx/{bad}", "RawTx"))
        reqs.append(_req("/token/:txid", "GET", f"/token/{bad}", "TokenInfo"))

    # ---- Scripts
    for stype, payload, script_hex in sample_scripts(record["scripts"], max_scripts):
        reqs += _history_routes("/script/:type/:payload", f"/script/{stype}/{payload}",
                                SCRIPT_SUBROUTES)
        if record.get("scripthash_index"):
            sh = hex_be_sha256(bytes.fromhex(script_hex))
            reqs += _history_routes("/script/:type/:payload", f"/script/scripthash/{sh}",
                                    SCRIPT_SUBROUTES)
    bad_scripts = [
        ("p2pkh", "00" * 20), ("p2sh", "00" * 20), ("p2pk", "02" + "00" * 32),
        ("other", "6a"), ("scripthash", "00" * 32),
        ("p2pkh", "00" * 19), ("p2pkh", "zz"), ("p2sh", "00" * 21), ("p2pk", "00" * 32),
        ("p2pk", "04" + "00" * 64), ("other", "00" * 10_000), ("other", ""),
        ("scripthash", "00" * 31), ("foo", "00"), ("P2PKH", "00" * 20), ("p2tr", "00" * 33),
    ]
    for stype, payload in bad_scripts:
        for sub, pb_type, _ in SCRIPT_SUBROUTES:
            reqs.append(_req(f"/script/:type/:payload/{sub}", "GET",
                             f"/script/{stype}/{payload}/{sub}", pb_type))
    reqs.append(_req("/script/:type/:payload/history", "GET", "/script/p2pkh/history",
                     "TxHistoryPage"))

    # ---- Tokens
    for token_id in record.get("token_ids", []):
        reqs += _history_routes("/token-id/:token_id", f"/token-id/{token_id}",
                                TOKEN_SUBROUTES)
    for bad in ["00" * 32, "zz", "00" * 31, "00" * 33]:
        for sub, pb_type, _ in TOKEN_SUBROUTES:
            reqs.append(_req(f"/token-id/:token_id/{sub}", "GET",
                             f"/token-id/{bad}/{sub}", pb_type))

    # ---- LOKAD ids
    for lokad in record.get("lokad_ids", []):
        reqs += _history_routes("/lokad-id/:lokad_id", f"/lokad-id/{lokad}",
                                LOKAD_SUBROUTES)
    for bad in ["00000000", "zz", "001122", "0011223344"]:
        for sub, pb_type, _ in LOKAD_SUBROUTES:
            reqs.append(_req(f"/lokad-id/:lokad_id/{sub}", "GET",
                             f"/lokad-id/{bad}/{sub}", pb_type))

    # ---- Plugins (disabled), pause/resume (403 without -chronikallowpause)
    for path in ["/plugin/foo/00/utxos", "/plugin/foo/00/history",
                 "/plugin/foo/00/confirmed-txs", "/plugin/foo/00/unconfirmed-txs",
                 "/plugin/foo/groups", "/plugin/foo/zz/utxos", "/plugin/foo/groups?prefix=zz"]:
        reqs.append(_req("/plugin/...", "GET", path, "PluginGroups"))
    reqs.append(_req("/pause", "GET", "/pause", "Empty"))
    reqs.append(_req("/resume", "GET", "/resume", "Empty"))

    # ---- Fallback / methods
    for path in ["/", "/nonexistent", "/block", "/tx/", "/script/batch",
                 "/blockchain-info/extra", "/BLOCKCHAIN-INFO"]:
        reqs.append(_req("<fallback>", "GET", path, None))
    reqs.append(_req("/ws", "GET", "/ws", None))
    reqs.append(_req("/tx/:txid", "POST", f"/tx/{'00' * 32}", "Tx",
                     headers={"Content-Type": PROTOBUF_CT}, body=b""))
    reqs.append(_req("/blockchain-info", "DELETE", "/blockchain-info", None))
    for path in ["/validate-tx", "/broadcast-tx", "/broadcast-txs",
                 "/script/batch/utxos", "/script/batch/summary"]:
        reqs.append(_req(path, "GET", path, None))
        reqs.append(_req(path, "OPTIONS", path, None))
        reqs.append(_req(path, "PUT", path, None, body=b""))

    # ---- POST bodies: content type / protobuf / size
    raw_ok = P.RawTx(raw_tx=bytes.fromhex(record["validate_txs"][0])).SerializeToString() \
        if record.get("validate_txs") else P.RawTx(raw_tx=b"\x01").SerializeToString()
    bodies = [
        ("valid", raw_ok, PROTOBUF_CT),
        ("text/plain", raw_ok, "text/plain"),
        ("ct-with-charset", raw_ok, PROTOBUF_CT + "; charset=utf-8"),
        ("ct-upper", raw_ok, "Application/X-Protobuf"),
        ("no-ct", raw_ok, None),
        ("ct-non-utf8", raw_ok, "application/x-protobuf\xff"),
        ("empty", b"", PROTOBUF_CT),
        ("bad-protobuf", b"\xff\xff\xff\xff", PROTOBUF_CT),
        ("truncated", raw_ok[:-1] if len(raw_ok) > 1 else b"\x0a", PROTOBUF_CT),
        ("at-limit-zeros", b"\x00" * MAX_REQUEST_BODY_SIZE, PROTOBUF_CT),
        ("over-limit", b"\x00" * (MAX_REQUEST_BODY_SIZE + 1), PROTOBUF_CT),
        ("over-limit-text", b"\x00" * (MAX_REQUEST_BODY_SIZE + 1), "text/plain"),
    ]
    for path, pb_type in [("/validate-tx", "Tx"), ("/broadcast-tx", "BroadcastTxResponse"),
                          ("/broadcast-txs", "BroadcastTxsResponse"),
                          ("/script/batch/utxos", "ScriptBatchUtxosResponse"),
                          ("/script/batch/summary", "ScriptBatchSummaryResponse")]:
        for name, body, ct in bodies:
            if path in ("/broadcast-tx", "/broadcast-txs") and name in (
                    "valid", "ct-with-charset", "ct-upper"):
                # A valid fresh tx would mutate the mempool; covered below.
                continue
            big = len(body) >= MAX_REQUEST_BODY_SIZE
            reqs.append(_post(path, path, body, pb_type, content_type=ct, fresh_conn=big))

    # ---- /validate-tx
    for raw in record.get("validate_txs", []) + record.get("raw_txs_sample", []):
        reqs.append(_post("/validate-tx", "/validate-tx",
                          P.RawTx(raw_tx=bytes.fromhex(raw)).SerializeToString(), "Tx"))
    for junk in [b"", b"\x01", b"\x01\x00\x00\x00", b"\x00" * 100, b"\xff" * 300]:
        reqs.append(_post("/validate-tx", "/validate-tx",
                          P.RawTx(raw_tx=junk).SerializeToString(), "Tx"))

    # ---- /broadcast-tx(s) (non-mutating: invalid, confirmed, already in mempool)
    for raw in record.get("raw_txs_sample", [])[:20]:
        rb = bytes.fromhex(raw)
        reqs.append(_post("/broadcast-tx", "/broadcast-tx",
                          P.BroadcastTxRequest(raw_tx=rb).SerializeToString(),
                          "BroadcastTxResponse"))
        reqs.append(_post("/broadcast-txs", "/broadcast-txs",
                          P.BroadcastTxsRequest(raw_txs=[rb, rb]).SerializeToString(),
                          "BroadcastTxsResponse"))
    for junk in [b"", b"\x01\x02", b"\x00" * 100]:
        reqs.append(_post("/broadcast-tx", "/broadcast-tx",
                          P.BroadcastTxRequest(raw_tx=junk).SerializeToString(),
                          "BroadcastTxResponse"))
        reqs.append(_post("/broadcast-txs", "/broadcast-txs",
                          P.BroadcastTxsRequest(raw_txs=[junk]).SerializeToString(),
                          "BroadcastTxsResponse"))
    reqs.append(_post("/broadcast-txs", "/broadcast-txs",
                      P.BroadcastTxsRequest(raw_txs=[]).SerializeToString(),
                      "BroadcastTxsResponse"))
    for timeout in [121, 2**63]:
        reqs.append(_post("/broadcast-tx", "/broadcast-tx",
                          P.BroadcastTxRequest(raw_tx=b"\x01",
                                               finalization_timeout_secs=timeout)
                          .SerializeToString(), "BroadcastTxResponse"))
        reqs.append(_post("/broadcast-txs", "/broadcast-txs",
                          P.BroadcastTxsRequest(raw_txs=[b"\x01"],
                                                finalization_timeout_secs=timeout)
                          .SerializeToString(), "BroadcastTxsResponse"))

    # ---- Script batches
    scripts = [(s, bytes.fromhex(p)) for s, p, _ in record["scripts"]]
    fill = [("p2pkh", i.to_bytes(20, "big")) for i in range(1, 600)]
    batches = {
        "all": scripts[:MAX_NUM_BATCH_SCRIPTS],
        "one": scripts[:1],
        "empty": [],
        "500": (scripts + fill)[:MAX_NUM_BATCH_SCRIPTS],
        "501": (scripts + fill)[:MAX_NUM_BATCH_SCRIPTS + 1],
        "dups": scripts[:3] * 3,
        "bad-type": scripts[:2] + [("foo", b"\x00")],
        "bad-len": scripts[:2] + [("p2pkh", b"\x00" * 19)],
        "scripthash": [("scripthash", b"\x00" * 32)] + scripts[:2],
    }
    for name, batch in batches.items():
        refs = [P.ScriptRef(script_type=s, payload=p) for s, p in batch]
        body_u = P.ScriptBatchUtxosRequest(
            params=P.ScriptBatchUtxosParams(scripts=refs)).SerializeToString()
        body_s = P.ScriptBatchSummaryRequest(
            params=P.ScriptBatchSummaryParams(scripts=refs)).SerializeToString()
        reqs.append(_post("/script/batch/utxos", "/script/batch/utxos", body_u,
                          "ScriptBatchUtxosResponse"))
        reqs.append(_post("/script/batch/summary", "/script/batch/summary", body_s,
                          "ScriptBatchSummaryResponse"))
    reqs.append(_post("/script/batch/utxos", "/script/batch/utxos",
                      P.ScriptBatchUtxosRequest().SerializeToString(),
                      "ScriptBatchUtxosResponse"))

    # ---- Mutating broadcasts (only at the end of a run)
    if allow_mutating and record.get("broadcast"):
        reqs += broadcast_requests(record["broadcast"])

    for i, r in enumerate(reqs):
        r["id"] = i
    return reqs


def broadcast_requests(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Requests that may add txs to the mempool. Each is sent to A, then B."""
    P = pb()
    out = []
    for item in spec.get("single", []):
        out.append(_post("/broadcast-tx", "/broadcast-tx",
                         P.BroadcastTxRequest(
                             raw_tx=bytes.fromhex(item["raw"]),
                             skip_token_checks=item.get("skip_token_checks", False),
                             finalization_timeout_secs=item.get("timeout", 0),
                         ).SerializeToString(),
                         "BroadcastTxResponse", mutating=True))
    for item in spec.get("batch", []):
        out.append(_post("/broadcast-txs", "/broadcast-txs",
                         P.BroadcastTxsRequest(
                             raw_txs=[bytes.fromhex(r) for r in item["raws"]],
                             skip_token_checks=item.get("skip_token_checks", False),
                             finalization_timeout_secs=item.get("timeout", 0),
                         ).SerializeToString(),
                         "BroadcastTxsResponse", mutating=True))
    return out


def paged_followups(req: Dict[str, Any], resp_a: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Requests derived from the first page: last page, one past last, etc."""
    if resp_a.get("status") != 200:
        return []
    P = pb()
    page = P.TxHistoryPage()
    try:
        page.ParseFromString(compare._body(resp_a))
    except Exception:
        return []
    base = req["path"].split("?")[0]
    out = []
    n_pages, n_txs = page.num_pages, page.num_txs
    edges = [f"?page={max(n_pages - 1, 0)}", f"?page={n_pages}",
             f"?page={n_pages + 1}"]
    if n_txs:
        edges += [f"?page={n_txs - 1}&page_size=1", f"?page={n_txs}&page_size=1",
                  f"?page={(n_txs - 1) // 200}&page_size=200",
                  f"?page={(n_txs - 1) // 7}&page_size=7"]
    for edge in edges:
        out.append(_req(req["route"], "GET", base + edge, req["pb_type"]))
    return out


# --------------------------------------------------------------------------
# HTTP execution
# --------------------------------------------------------------------------


class HttpEndpoint:
    def __init__(self, url: str, timeout: float = 60):
        parsed = urllib.parse.urlparse(url)
        self.host = parsed.hostname
        self.port = parsed.port
        self.timeout = timeout
        self.conn: Optional[http.client.HTTPConnection] = None

    def _connect(self):
        self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        # Mutating requests are never retried; they always use a fresh
        # connection so a keep-alive connection the server closed while idle
        # cannot swallow them.
        attempts = 1 if (req.get("mutating") or req.get("fresh_conn")) else 2
        if req.get("fresh_conn") or req.get("mutating"):
            self.close()
        last_err = None
        for _ in range(attempts):
            if self.conn is None:
                self._connect()
            try:
                return self._do(req)
            except (http.client.RemoteDisconnected, http.client.BadStatusLine,
                    ConnectionResetError, BrokenPipeError, ConnectionAbortedError,
                    socket.timeout, OSError) as err:
                last_err = err
                self.close()
        resp = {"status": None, "headers": {}, "body_bytes": b"",
                "error": type(last_err).__name__}
        return resp

    def _do(self, req: Dict[str, Any]) -> Dict[str, Any]:
        conn = self.conn
        body = req.get("body")
        conn.putrequest(req["method"], req["path"], skip_accept_encoding=True)
        for k, v in req.get("headers", {}).items():
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body:
            try:
                conn.send(body)
            except (BrokenPipeError, ConnectionResetError):
                # Server may answer (e.g. 413) before reading the full body.
                pass
        resp = conn.getresponse()
        data = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        result = {"status": resp.status, "headers": headers, "body_bytes": data}
        if resp.will_close or req.get("fresh_conn"):
            self.close()
        return result


def serialize_response(resp: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in resp.items() if k != "body_bytes"}
    out["body_b64"] = base64.b64encode(resp.get("body_bytes", b"")).decode()
    return out


def serialize_request(req: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in req.items() if k != "body"}
    body = req.get("body")
    if body is not None:
        out["body_len"] = len(body)
        out["body_sha256"] = hashlib.sha256(body).hexdigest()
    return out


class Runner:
    """Sends each request to A then B and compares the pair."""

    def __init__(self, url_a: str, url_b: str, report: compare.Report,
                 save_dir: Optional[str] = None, log: Callable[[str], None] = print):
        self.a = HttpEndpoint(url_a)
        self.b = HttpEndpoint(url_b)
        self.report = report
        self.save_dir = save_dir
        self.log = log
        self._save_files = None

    def _open_save(self, label):
        if not self.save_dir:
            return None
        os.makedirs(self.save_dir, exist_ok=True)
        fa = open(os.path.join(self.save_dir, f"{label}.A.jsonl"), "w", encoding="utf8")
        fb = open(os.path.join(self.save_dir, f"{label}.B.jsonl"), "w", encoding="utf8")
        return fa, fb

    def run(self, requests: Iterable[Dict[str, Any]], label: str) -> Dict[str, int]:
        counts = {"requests": 0, "identical": 0, "parsed_equal": 0, "different": 0}
        files = self._open_save(label)
        queue = list(requests)
        next_id = (max([r.get("id", 0) for r in queue]) + 1) if queue else 0
        idx = 0
        t0 = time.time()
        while idx < len(queue):
            req = queue[idx]
            idx += 1
            if "id" not in req:
                req["id"] = next_id
                next_id += 1
            ra = self.a.request(req)
            rb = self.b.request(req)
            res = compare.compare_http(req, ra, rb, self.report.allow)
            self.report.add_http(res, label)
            counts["requests"] += 1
            counts[res["verdict"]] += 1
            if res["verdict"] == "different" and counts["different"] <= 5:
                self.log(f"DIFF {req['method']} {req['path'][:120]}: "
                         f"{json.dumps(res.get('unexpected', [])[:3], default=str)[:400]}")
            if req.get("paged"):
                queue[idx:idx] = paged_followups(req, ra)
            if files:
                sreq = serialize_request(req)
                files[0].write(json.dumps({"id": req["id"], "checkpoint": label,
                                           "request": sreq,
                                           "response": serialize_response(ra)}) + "\n")
                files[1].write(json.dumps({"id": req["id"], "checkpoint": label,
                                           "request": sreq,
                                           "response": serialize_response(rb)}) + "\n")
        if files:
            files[0].close()
            files[1].close()
        counts["seconds"] = round(time.time() - t0, 1)
        return counts

    def close(self):
        self.a.close()
        self.b.close()


# --------------------------------------------------------------------------
# WebSocket corpus
# --------------------------------------------------------------------------


class WsConn:
    """One WebSocket connection; a reader thread records every data frame."""

    def __init__(self, url: str):
        import websocket

        self.ws = websocket.create_connection(url, timeout=30)
        self.frames: List[Tuple[int, bytes]] = []
        self.closed = False
        self.error: Optional[str] = None
        self._lock = threading.Lock()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        import websocket

        self.ws.settimeout(1.0)
        while not self.closed:
            try:
                opcode, data = self.ws.recv_data(control_frame=False)
            except websocket.WebSocketTimeoutException:
                continue
            except Exception as err:  # connection closed
                if not self.closed:
                    self.error = type(err).__name__
                break
            if opcode == websocket.ABNF.OPCODE_CLOSE:
                # The server's reply to our own close handshake is not an
                # error; only an unsolicited close is.
                if not self.closed:
                    self.error = "closed-by-server"
                break
            with self._lock:
                self.frames.append((opcode, bytes(data)))

    def send(self, action: Tuple[str, Any]):
        import websocket

        kind, payload = action
        if kind == "text":
            self.ws.send(payload, opcode=websocket.ABNF.OPCODE_TEXT)
        else:
            self.ws.send(payload, opcode=websocket.ABNF.OPCODE_BINARY)

    def count(self) -> int:
        with self._lock:
            return len(self.frames)

    def close(self) -> List[Tuple[int, bytes]]:
        self.closed = True
        try:
            self.ws.close()
        except Exception:
            pass
        self.thread.join(timeout=5)
        with self._lock:
            return list(self.frames)


def ws_sub(**kwargs) -> bytes:
    P = pb()
    is_unsub = kwargs.pop("is_unsub", False)
    (kind, value), = kwargs.items()
    if kind == "blocks":
        sub = P.WsSub(is_unsub=is_unsub, blocks=P.WsSubBlocks())
    elif kind == "txs":
        sub = P.WsSub(is_unsub=is_unsub, txs=P.WsSubTxs())
    elif kind == "script":
        sub = P.WsSub(is_unsub=is_unsub,
                      script=P.WsSubScript(script_type=value[0], payload=value[1]))
    elif kind == "token_id":
        sub = P.WsSub(is_unsub=is_unsub, token_id=P.WsSubTokenId(token_id=value))
    elif kind == "lokad_id":
        sub = P.WsSub(is_unsub=is_unsub, lokad_id=P.WsSubLokadId(lokad_id=value))
    elif kind == "txid":
        sub = P.WsSub(is_unsub=is_unsub, txid=P.WsSubTxId(txid=value))
    elif kind == "plugin":
        sub = P.WsSub(is_unsub=is_unsub,
                      plugin=P.WsPlugin(plugin_name=value[0], group=value[1]))
    else:
        raise ValueError(kind)
    return sub.SerializeToString()


MAX_WS_GROUP_SESSIONS = 60


def build_ws_plans(record: Dict[str, Any], label: str) -> List[Tuple[str, List, str]]:
    """Scripted sessions: (name, [actions], mode).

    action = ("bin"|"text", payload). mode "strict": the message sequence
    must be identical. A Chronik WS session merges its subscriptions with
    tokio::select!/select_all and suppresses consecutive duplicates, so the
    interleaving across *different* subscriptions of one session is not
    deterministic even for one binary; sessions with several subscriptions are
    therefore compared in mode "set" (the set of distinct messages). Every
    subscription also gets its own strict single-subscription session.
    """
    scripts = [(s, bytes.fromhex(p)) for s, p, _ in record["scripts"]]
    token_ids = record.get("token_ids", [])
    lokads = record.get("lokad_ids", [])
    plans: List[Tuple[str, List, str]] = []
    plans.append((f"{label}/blocks", [("bin", ws_sub(blocks=True))], "strict"))
    plans.append((f"{label}/txs", [("bin", ws_sub(txs=True))], "strict"))
    groups = [("script", s, f"script:{s[0]}:{s[1].hex()[:16]}") for s in scripts]
    groups += [("token_id", t, f"token:{t[:16]}") for t in token_ids]
    groups += [("lokad_id", bytes.fromhex(lk), f"lokad:{lk}") for lk in lokads]
    if record.get("scripthash_index") and record["scripts"]:
        sh = bytes.fromhex(hex_be_sha256(bytes.fromhex(record["scripts"][0][2])))
        groups.append(("script", ("scripthash", sh), "scripthash"))
    v2_branches = [bytes.fromhex(b) for b in record.get("v2_branches", [])]
    v2_assets = [bytes.fromhex(a) for a in record.get("v2_assets", [])]
    groups += [("script", ("v2-branch", b), f"v2-branch:{b.hex()[:16]}")
               for b in v2_branches[:8]]
    groups += [("script", ("taproot", b), f"taproot:{b.hex()[:16]}")
               for b in v2_branches[:1]]
    groups += [("script", ("v2-asset", a), f"v2-asset:{a.hex()[:16]}")
               for a in v2_assets[:4]]
    mempool = record.get("mempool", [])
    for txid in (mempool[:10] + record["txids"][-5:]):
        groups.append(("txid", txid, f"txid:{txid[:16]}"))
    for i, (kind, value, name) in enumerate(groups[:MAX_WS_GROUP_SESSIONS]):
        plans.append((f"{label}/{i:02d}-{name}", [("bin", ws_sub(**{kind: value}))],
                      "strict"))
    plans.append((f"{label}/scripts-all",
                  [("bin", ws_sub(script=s)) for s in scripts], "set"))
    if token_ids:
        plans.append((f"{label}/tokens-all",
                      [("bin", ws_sub(token_id=t)) for t in token_ids], "set"))
    if v2_branches or v2_assets:
        v2_all = [("bin", ws_sub(script=("v2-branch", b))) for b in v2_branches]
        v2_all += [("bin", ws_sub(script=("taproot", b))) for b in v2_branches[:2]]
        v2_all += [("bin", ws_sub(script=("v2-asset", a))) for a in v2_assets]
        plans.append((f"{label}/v2-all", v2_all, "set"))
    plans.append((f"{label}/lokad-all",
                  [("bin", ws_sub(lokad_id=bytes.fromhex(lk))) for lk in lokads], "set"))
    # Everything at once, with duplicate subs, sub+unsub.
    mixed = [("bin", ws_sub(blocks=True)), ("bin", ws_sub(blocks=True)),
             ("bin", ws_sub(txs=True)), ("bin", ws_sub(txs=True, is_unsub=True)),
             ("bin", ws_sub(txs=True))]
    mixed += [("bin", ws_sub(script=s)) for s in scripts[:5]]
    mixed += [("bin", ws_sub(script=scripts[0], is_unsub=True))] if scripts else []
    mixed += [("bin", ws_sub(token_id=t)) for t in token_ids[:3]]
    mixed += [("bin", ws_sub(lokad_id=bytes.fromhex(lk))) for lk in lokads[:3]]
    mixed += [("bin", ws_sub(script=("v2-branch", b))) for b in v2_branches[:3]]
    mixed += ([("bin", ws_sub(script=("taproot", v2_branches[0]), is_unsub=True))]
              if v2_branches else [])
    plans.append((f"{label}/mixed", mixed, "set"))
    # Error replies are produced in order of the client messages; the final
    # blocks sub is the only live subscription.
    errors = [
        ("text", "hello"),
        ("bin", b"\xff\xff\xff"),
        ("bin", ws_sub(plugin=("foo", b"\x00"))),
        ("bin", ws_sub(script=("foo", b"\x00"))),
        ("bin", ws_sub(script=("p2pkh", b"\x00" * 19))),
        ("bin", ws_sub(script=("other", b"\x51" * 202))),
        ("bin", ws_sub(token_id="zz")),
        ("bin", ws_sub(token_id="00" * 31)),
        ("bin", ws_sub(lokad_id=b"\x00\x01\x02")),
        ("bin", ws_sub(txid="zz")),
    ]
    if v2_branches:
        # Other payload sizes fall through to the script-type parser.
        errors += [
            ("bin", ws_sub(script=("v2-branch", b"\x11" * 31))),
            ("bin", ws_sub(script=("v2-asset", b"\x11" * 33))),
            ("bin", ws_sub(script=("taproot", b"\x11" * 33))),
        ]
    errors += [
        ("bin", ws_sub(blocks=True, is_unsub=True)),
        ("bin", b""),
        ("bin", ws_sub(blocks=True)),
    ]
    plans.append((f"{label}/errors", errors, "strict"))
    return plans


class WsStretch:
    """A set of scripted sessions opened on both nodes for a stretch of the run."""

    def __init__(self, url_a: str, url_b: str, plans: List[Tuple[str, List, str]]):
        self.plans = plans
        self.sessions: List[Tuple[str, WsConn, WsConn]] = []
        self.modes: Dict[str, str] = {}
        for name, actions, mode in plans:
            ca = WsConn(url_a)
            cb = WsConn(url_b)
            for action in actions:
                ca.send(action)
                cb.send(action)
            self.sessions.append((name, ca, cb))
            self.modes[name] = mode

    def quiesce(self, idle: float = 0.6, timeout: float = 30.0) -> None:
        """Wait until no session received anything for `idle` seconds."""
        deadline = time.time() + timeout
        last = None
        stable_since = time.time()
        while time.time() < deadline:
            cur = [(a.count(), b.count()) for _, a, b in self.sessions]
            if cur != last:
                last = cur
                stable_since = time.time()
            elif time.time() - stable_since >= idle:
                return
            time.sleep(0.05)

    def finish(self, report: compare.Report, label: str,
               save_dir: Optional[str] = None) -> Dict[str, int]:
        self.quiesce()
        counts = {"sessions": 0, "messages": 0, "different": 0}
        out = None
        if save_dir:
            os.makedirs(save_dir, exist_ok=True)
            out = (open(os.path.join(save_dir, f"{label}.ws.A.jsonl"), "w", encoding="utf8"),
                   open(os.path.join(save_dir, f"{label}.ws.B.jsonl"), "w", encoding="utf8"))
        for name, ca, cb in self.sessions:
            fa, fb = ca.close(), cb.close()
            res = compare.compare_ws(name, fa, fb, report.allow,
                                     mode=self.modes.get(name, "strict"))
            if ca.error != cb.error:
                res["verdict"] = "different"
                res.setdefault("unexpected", []).append(
                    {"path": "WsSession.<transport>", "a": ca.error, "b": cb.error})
            report.add_ws(res, label)
            counts["sessions"] += 1
            counts["messages"] += max(len(fa), len(fb))
            if res["verdict"] == "different":
                counts["different"] += 1
            if out:
                for f, frames in ((out[0], fa), (out[1], fb)):
                    f.write(json.dumps({
                        "kind": "ws", "id": name, "checkpoint": label,
                        "mode": self.modes.get(name, "strict"),
                        "messages": [{"opcode": op, "data": base64.b64encode(d).decode()}
                                     for op, d in frames]}) + "\n")
        if out:
            out[0].close()
            out[1].close()
        return counts


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--record", required=True, help="record JSON from parity_chain.py")
    parser.add_argument("--url-a", required=True, help="Chronik base URL of implementation A")
    parser.add_argument("--url-b", required=True, help="Chronik base URL of implementation B")
    parser.add_argument("--mode", choices=["full", "light"], default="full")
    parser.add_argument("--max-scripts", type=int, default=0,
                        help="cap the number of scripts queried (0: all)")
    parser.add_argument("--allow-mutating", action="store_true",
                        help="also send the record's successful broadcasts")
    parser.add_argument("--ws-static", action="store_true",
                        help="also open the scripted WS sessions (no chain events)")
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--report", help="write JSON report here")
    parser.add_argument("--save-responses", help="directory for raw JSON-lines responses")
    parser.add_argument("--pb2-dir")
    parser.add_argument("--srcdir")
    args = parser.parse_args()
    compare.load_pb(args.pb2_dir, args.srcdir)
    with open(args.record, encoding="utf8") as f:
        record = json.load(f)
    report = compare.Report(compare.DEFAULT_ALLOW + args.allow)
    runner = Runner(args.url_a, args.url_b, report, args.save_responses)
    if args.ws_static:
        ws_a = args.url_a.replace("http://", "ws://").rstrip("/") + "/ws"
        ws_b = args.url_b.replace("http://", "ws://").rstrip("/") + "/ws"
        stretch = WsStretch(ws_a, ws_b, build_ws_plans(record, "static"))
    counts = runner.run(build_requests(record, args.mode, args.allow_mutating,
                                       args.max_scripts), "cli")
    if args.ws_static:
        stretch.finish(report, "static", args.save_responses)
    runner.close()
    print(json.dumps(counts))
    print(report.summary())
    if args.report:
        report.write(args.report)
    return 0 if report.ok() else 1


if __name__ == "__main__":
    sys.exit(main())
