#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compare Chronik responses of two implementations (A and B).

Used as a library by parity_chain.py / corpus.py, and as a CLI to compare two
saved response files (JSON lines written by `corpus.py --save-responses`):

    compare.py A.jsonl B.jsonl [--report report.json] [--allow PATH ...]

Each HTTP response is classified as:
  identical     status, content-type, compared headers and raw body bytes equal
  parsed_equal  status/content-type/headers equal, bytes differ, but the parsed
                protobuf messages differ only in allow-listed field paths
  different     anything else (unexpected difference)

WebSocket sessions are compared message by message (raw bytes first, then the
parsed `WsMsg`).

Exit status is nonzero if any unexpected difference was found.
"""

import argparse
import base64
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import OrderedDict
from typing import Any, Dict, List, Optional

# Field paths whose difference is accepted. Paths are `Message.field[idx].sub`;
# patterns are fnmatch'ed against the indexed path and the index-free path.
DEFAULT_ALLOW = [
    # FormatFullVersion() of the host build; the same function in both
    # implementations but may differ between two build trees.
    "ChronikInfo.version",
    # Lotus V2 service: the per-process random service epoch, the only
    # difference between two nodes once it is zeroed (normalize_v2_epoch).
    "json.<service_epoch>",
]

# Lotus V2 tier, Rust (A) vs native (B): the design C1 section 1 defects.
# The Rust bridge recomputes the txid of a decoded raw tx from its
# legacy-shaped fields (lookup_spent_coins), which differs from the real V2
# txid of native V2 txs; the native host reports the real one.
V2_ACCEPTED = [
    "/validate-tx::Tx.txid",
]

# Response headers never compared.
IGNORED_HEADERS = {"date"}

_pb = None


def load_pb(pb2_dir: Optional[str] = None, srcdir: Optional[str] = None):
    """Import chronik_pb2: from pb2_dir, from sys.path, or generate it with
    protoc from <srcdir>/chronik/chronik-proto/proto/chronik.proto."""
    global _pb
    if _pb is not None:
        return _pb
    if pb2_dir:
        sys.path.insert(0, pb2_dir)
    try:
        import chronik_pb2 as pb  # noqa: F401
    except ImportError:
        if not srcdir:
            raise
        proto_dir = os.path.join(srcdir, "chronik", "chronik-proto", "proto")
        out = tempfile.mkdtemp(prefix="chronik-parity-pb2-")
        subprocess.check_call(
            ["protoc", f"-I{proto_dir}", f"--python_out={out}", "chronik.proto"]
        )
        sys.path.insert(0, out)
        import chronik_pb2 as pb  # noqa: F401
    _pb = pb
    return pb


def pb_class(name: Optional[str]):
    if not name:
        return None
    return getattr(load_pb(), name, None)


# --------------------------------------------------------------------------
# Protobuf diff
# --------------------------------------------------------------------------


def _strip_idx(path: str) -> str:
    return re.sub(r"\[\d+\]", "", path)


def is_allowed(path: str, allow: List[str], route: Optional[str] = None) -> bool:
    """Whether a difference at `path` is accepted. A pattern "ROUTE::PATH"
    only applies to responses of that route (e.g. "/validate-tx::Tx.txid")."""
    stripped = _strip_idx(path)
    for pattern in allow:
        if "::" in pattern:
            route_pattern, pattern = pattern.split("::", 1)
            if route is None or not fnmatch.fnmatchcase(route, route_pattern):
                continue
        if fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(
            stripped, pattern
        ):
            return True
    return False


def _short(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex() if len(value) <= 64 else value[:64].hex() + "..."
    if isinstance(value, str) and len(value) > 200:
        return value[:200] + "..."
    return value


def _v2_epoch(value) -> Optional[str]:
    if isinstance(value, dict):
        for holder in (value, value.get("snapshot")):
            if isinstance(holder, dict) and isinstance(holder.get("service_epoch"), str):
                return holder["service_epoch"]
    return None


def _epoch_raw(body: bytes, parsed) -> bytes:
    """Raw JSON body with its service epoch zeroed (see normalize_v2_epoch)."""
    epoch = _v2_epoch(parsed)
    if not epoch or len(epoch) != 32:
        return body
    zero = "0" * 32
    return (body.replace(epoch.encode(), zero.encode())
            .replace(epoch.encode().hex().encode(), zero.encode().hex().encode()))


def normalize_v2_epoch(value):
    """Lotus V2 service responses carry the per-process random service epoch
    (`service_epoch`), also inside `snapshot_token` and inside the hex-encoded
    JSON of explorer cursors. Two nodes never share it, so it is replaced by
    zeros (in plain and hex-of-ASCII form) before comparing; every other byte
    of tokens and cursors is still compared."""
    epoch = _v2_epoch(value)
    if not epoch or len(epoch) != 32:
        return value
    zero = "0" * 32
    nested, nested_zero = epoch.encode().hex(), zero.encode().hex()

    def walk(v):
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            return v.replace(epoch, zero).replace(nested, nested_zero)
        return v

    return walk(value)


def diff_json(a, b, path: str, out: List[Dict[str, Any]]) -> None:
    """Append every differing leaf of two parsed JSON values to out
    (objects by key, arrays by index as "path[i]")."""
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            sub = f"{path}.{key}"
            if key not in a or key not in b:
                out.append({"path": sub, "a": _short(a.get(key)), "b": _short(b.get(key))})
            else:
                diff_json(a[key], b[key], sub, out)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append({"path": f"{path}.<len>", "a": len(a), "b": len(b)})
        for i, (x, y) in enumerate(zip(a, b)):
            diff_json(x, y, f"{path}[{i}]", out)
    elif a != b or type(a) is not type(b):
        out.append({"path": path, "a": _short(a), "b": _short(b)})


def diff_messages(a, b, path: str, out: List[Dict[str, Any]]) -> None:
    """Append every differing leaf of two messages of the same type to out."""
    from google.protobuf.descriptor import FieldDescriptor

    for field in a.DESCRIPTOR.fields:
        fpath = f"{path}.{field.name}"
        va = getattr(a, field.name)
        vb = getattr(b, field.name)
        is_msg = field.type == FieldDescriptor.TYPE_MESSAGE
        is_repeated = getattr(field, "is_repeated", None)
        if is_repeated is None:
            is_repeated = field.label == FieldDescriptor.LABEL_REPEATED
        if is_repeated:
            is_map = is_msg and field.message_type.GetOptions().map_entry
            if is_map:
                keys = sorted(set(va.keys()) | set(vb.keys()), key=repr)
                for key in keys:
                    kpath = f"{fpath}[{key!r}]"
                    if key not in va or key not in vb:
                        out.append({"path": kpath, "a": key in va, "b": key in vb})
                    elif hasattr(va[key], "DESCRIPTOR"):
                        diff_messages(va[key], vb[key], kpath, out)
                    elif va[key] != vb[key]:
                        out.append(
                            {"path": kpath, "a": _short(va[key]), "b": _short(vb[key])}
                        )
                continue
            if len(va) != len(vb):
                out.append({"path": f"{fpath}.<len>", "a": len(va), "b": len(vb)})
            for i, (ea, eb) in enumerate(zip(va, vb)):
                ipath = f"{fpath}[{i}]"
                if is_msg:
                    diff_messages(ea, eb, ipath, out)
                elif ea != eb:
                    out.append({"path": ipath, "a": _short(ea), "b": _short(eb)})
            continue
        if is_msg:
            ha = a.HasField(field.name)
            hb = b.HasField(field.name)
            if ha != hb:
                out.append({"path": f"{fpath}.<present>", "a": ha, "b": hb})
                continue
            if ha:
                diff_messages(va, vb, fpath, out)
            continue
        if field.containing_oneof is not None or field.has_presence:
            try:
                ha, hb = a.HasField(field.name), b.HasField(field.name)
                if ha != hb:
                    out.append({"path": f"{fpath}.<present>", "a": ha, "b": hb})
                    continue
            except ValueError:
                pass
        if va != vb:
            out.append({"path": fpath, "a": _short(va), "b": _short(vb)})
    # Unknown fields (e.g. a field one build knows and the other doesn't)
    try:
        ua = a.UnknownFields() if hasattr(a, "UnknownFields") else None
        ub = b.UnknownFields() if hasattr(b, "UnknownFields") else None
        if ua is not None and ub is not None:
            la = [(f.field_number, f.wire_type, f.data) for f in ua]
            lb = [(f.field_number, f.wire_type, f.data) for f in ub]
            if la != lb:
                out.append({"path": f"{path}.<unknown>", "a": len(la), "b": len(lb)})
    except Exception:
        pass


def parse_body(type_name: Optional[str], body: bytes):
    if type_name == "json":
        try:
            return json.loads(body), None
        except Exception as err:  # JSONDecodeError, UnicodeDecodeError
            return None, f"parse error: {err}"
    cls = pb_class(type_name)
    if cls is None:
        return None, "no message type"
    msg = cls()
    try:
        msg.ParseFromString(body)
    except Exception as err:  # DecodeError
        return None, f"parse error: {err}"
    return msg, None


PROTOBUF_CT = "application/x-protobuf"


def response_type(req: Dict[str, Any], resp: Dict[str, Any]) -> Optional[str]:
    """Protobuf message type of a response body."""
    if resp.get("status") is None:
        return None
    ctype = (resp.get("headers") or {}).get("content-type", "")
    if ctype.startswith("application/json"):
        return "json"
    if not ctype.startswith(PROTOBUF_CT):
        return None
    if resp["status"] == 200:
        return req.get("pb_type")
    return "Error"


# --------------------------------------------------------------------------
# HTTP comparison
# --------------------------------------------------------------------------


def _body(resp: Dict[str, Any]) -> bytes:
    if "body_bytes" in resp:
        return resp["body_bytes"]
    if resp.get("body_b64") is not None:
        return base64.b64decode(resp["body_b64"])
    if resp.get("body_hex") is not None:
        return bytes.fromhex(resp["body_hex"])
    return b""


def _cmp_headers(ra, rb):
    ha = {k: v for k, v in (ra.get("headers") or {}).items() if k not in IGNORED_HEADERS}
    hb = {k: v for k, v in (rb.get("headers") or {}).items() if k not in IGNORED_HEADERS}
    if ha == hb:
        return []
    out = []
    for k in sorted(set(ha) | set(hb)):
        if ha.get(k) != hb.get(k):
            out.append({"path": f"header:{k}", "a": ha.get(k), "b": hb.get(k)})
    return out


def compare_http(req, ra, rb, allow: List[str]) -> Dict[str, Any]:
    """Compare one HTTP response pair; returns a result dict with `verdict`."""
    result: Dict[str, Any] = {
        "route": req["route"],
        "method": req["method"],
        "path": req["path"],
        "status_a": ra.get("status"),
        "status_b": rb.get("status"),
    }
    diffs: List[Dict[str, Any]] = []
    if ra.get("status") != rb.get("status"):
        diffs.append({"path": "status", "a": ra.get("status"), "b": rb.get("status")})
    if ra.get("error") != rb.get("error"):
        diffs.append({"path": "transport", "a": ra.get("error"), "b": rb.get("error")})
    header_diffs = _cmp_headers(ra, rb)
    # content-length follows from the body; the body comparison covers it.
    header_diffs = [d for d in header_diffs if d["path"] != "header:content-length"]
    diffs += header_diffs
    ba, bb = _body(ra), _body(rb)
    bytes_equal = ba == bb
    result["bytes_equal"] = bytes_equal
    if not bytes_equal:
        ta, tb = response_type(req, ra), response_type(req, rb)
        if ta and ta == tb:
            ma, ea = parse_body(ta, ba)
            mb, eb = parse_body(tb, bb)
            if ma is not None and mb is not None:
                pdiffs: List[Dict[str, Any]] = []
                if ta == "json":
                    diff_json(normalize_v2_epoch(ma), normalize_v2_epoch(mb),
                              "json", pdiffs)
                else:
                    diff_messages(ma, mb, ta, pdiffs)
                if not pdiffs and ta == "json" and _epoch_raw(ba, ma) == _epoch_raw(bb, mb):
                    # Same bytes once each side's service epoch is zeroed.
                    pdiffs.append({"path": "json.<service_epoch>",
                                   "a": _v2_epoch(ma), "b": _v2_epoch(mb)})
                elif not pdiffs:
                    # Same message, different encoding (e.g. field order).
                    pdiffs.append({"path": f"{ta}.<encoding>", "a": len(ba), "b": len(bb)})
                diffs += pdiffs
            else:
                diffs.append({"path": "body.<parse>", "a": ea, "b": eb})
        else:
            diffs.append(
                {
                    "path": "body.<raw>",
                    "a": _short(ba),
                    "b": _short(bb),
                }
            )
    route = req["route"]
    unexpected = [d for d in diffs if not is_allowed(d["path"], allow, route)]
    accepted = [d for d in diffs if is_allowed(d["path"], allow, route)]
    if not diffs:
        result["verdict"] = "identical"
    elif not unexpected:
        result["verdict"] = "parsed_equal"
    else:
        result["verdict"] = "different"
    if diffs:
        result["unexpected"] = unexpected[:50]
        result["accepted"] = accepted[:50]
        result["num_diffs"] = len(diffs)
    return result


# --------------------------------------------------------------------------
# WebSocket comparison
# --------------------------------------------------------------------------


def _ws_frame(frame) -> Dict[str, Any]:
    if isinstance(frame, dict):
        return frame
    opcode, data = frame
    return {"opcode": opcode, "data": data}


def compare_ws(name: str, msgs_a: List, msgs_b: List, allow: List[str],
               mode: str = "strict"):
    """Compare two WebSocket message sequences of one session.

    mode "strict": identical sequences. mode "set": identical sets of distinct
    messages (for sessions with several subscriptions, whose interleaving and
    consecutive-duplicate suppression are scheduling dependent).
    """
    fa = [_ws_frame(m) for m in msgs_a]
    fb = [_ws_frame(m) for m in msgs_b]
    result: Dict[str, Any] = {
        "session": name,
        "mode": mode,
        "num_a": len(fa),
        "num_b": len(fb),
    }
    if mode == "set":
        def key(m):
            return (m["opcode"], m["data"])
        uniq_a = sorted({key(m) for m in fa})
        uniq_b = sorted({key(m) for m in fb})
        fa = [{"opcode": o, "data": d} for o, d in uniq_a]
        fb = [{"opcode": o, "data": d} for o, d in uniq_b]
        result["distinct_a"] = len(fa)
        result["distinct_b"] = len(fb)
        if len(fa) != len(fb) or fa != fb:
            only_a = [d.hex() for o, d in sorted(set(uniq_a) - set(uniq_b))][:20]
            only_b = [d.hex() for o, d in sorted(set(uniq_b) - set(uniq_a))][:20]
            result["verdict"] = "different"
            result["unexpected"] = [{"path": "WsSession.<set>", "a": only_a, "b": only_b}]
            result["num_identical"] = len(set(uniq_a) & set(uniq_b))
            return result
    diffs: List[Dict[str, Any]] = []
    if len(fa) != len(fb):
        diffs.append({"path": "WsSession.<len>", "a": len(fa), "b": len(fb)})
    num_identical = 0
    for i, (ma, mb) in enumerate(zip(fa, fb)):
        if ma["opcode"] == mb["opcode"] and ma["data"] == mb["data"]:
            num_identical += 1
            continue
        if ma["opcode"] != mb["opcode"]:
            diffs.append({"path": f"WsSession[{i}].opcode", "a": ma["opcode"], "b": mb["opcode"]})
            continue
        pa, ea = parse_body("WsMsg", ma["data"])
        pb_, eb = parse_body("WsMsg", mb["data"])
        if pa is None or pb_ is None:
            diffs.append({"path": f"WsSession[{i}].<parse>", "a": ea, "b": eb})
            continue
        pdiffs: List[Dict[str, Any]] = []
        diff_messages(pa, pb_, f"WsMsg[{i}]", pdiffs)
        if not pdiffs:
            pdiffs.append({"path": f"WsMsg[{i}].<encoding>", "a": 0, "b": 0})
        diffs += pdiffs
    unexpected = [d for d in diffs if not is_allowed(d["path"], allow)]
    result["num_identical"] = num_identical
    result["verdict"] = (
        "identical" if not diffs else ("parsed_equal" if not unexpected else "different")
    )
    if diffs:
        result["unexpected"] = unexpected[:50]
        result["num_diffs"] = len(diffs)
    return result


# --------------------------------------------------------------------------
# Report aggregation
# --------------------------------------------------------------------------


class Report:
    """Accumulates comparison results across checkpoints."""

    def __init__(self, allow: List[str]):
        self.allow = allow
        self.routes: Dict[str, Dict[str, int]] = OrderedDict()
        self.ws: Dict[str, int] = {"sessions": 0, "messages": 0, "identical": 0,
                                   "parsed_equal": 0, "different": 0}
        self.dumps: List[Dict[str, Any]] = []
        self.failures: List[Dict[str, Any]] = []
        self.accepted: List[Dict[str, Any]] = []
        self.checkpoints: List[Dict[str, Any]] = []
        self.notes: List[str] = []

    def add_http(self, result: Dict[str, Any], checkpoint: str = "") -> None:
        key = f"{result['method']} {result['route']}"
        counts = self.routes.setdefault(
            key, {"requests": 0, "identical": 0, "parsed_equal": 0, "different": 0}
        )
        counts["requests"] += 1
        counts[result["verdict"]] += 1
        if result["verdict"] == "different":
            if len(self.failures) < 500:
                self.failures.append(dict(result, checkpoint=checkpoint))
        elif result["verdict"] == "parsed_equal":
            if len(self.accepted) < 200:
                self.accepted.append(dict(result, checkpoint=checkpoint))

    def add_ws(self, result: Dict[str, Any], checkpoint: str = "") -> None:
        self.ws["sessions"] += 1
        self.ws["messages"] += max(result["num_a"], result["num_b"])
        self.ws[result["verdict"]] += 1
        if result["verdict"] == "different" and len(self.failures) < 500:
            self.failures.append(dict(result, checkpoint=checkpoint, kind="ws"))

    def add_dump(self, result: Dict[str, Any]) -> None:
        self.dumps.append(result)
        if not result.get("equal", False):
            self.failures.append(dict(result, kind="dump"))

    def totals(self) -> Dict[str, int]:
        tot = {"requests": 0, "identical": 0, "parsed_equal": 0, "different": 0}
        for counts in self.routes.values():
            for k in tot:
                tot[k] += counts[k]
        return tot

    def ok(self) -> bool:
        return not self.failures

    def to_json(self) -> Dict[str, Any]:
        return {
            "ok": self.ok(),
            "allow": self.allow,
            "http_totals": self.totals(),
            "http_routes": self.routes,
            "ws": self.ws,
            "dumps": self.dumps,
            "checkpoints": self.checkpoints,
            "failures": self.failures,
            "accepted_differences": self.accepted,
            "notes": self.notes,
        }

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf8") as f:
            json.dump(self.to_json(), f, indent=1, default=str)

    def summary(self) -> str:
        lines = []
        width = max([len(k) for k in self.routes] + [10])
        lines.append(
            f"{'route':<{width}} {'reqs':>7} {'bytes=':>7} {'parsed=':>7} {'diff':>6}"
        )
        for key, c in self.routes.items():
            lines.append(
                f"{key:<{width}} {c['requests']:>7} {c['identical']:>7} "
                f"{c['parsed_equal']:>7} {c['different']:>6}"
            )
        t = self.totals()
        lines.append(
            f"{'TOTAL':<{width}} {t['requests']:>7} {t['identical']:>7} "
            f"{t['parsed_equal']:>7} {t['different']:>6}"
        )
        w = self.ws
        lines.append(
            f"WebSocket: {w['sessions']} sessions, {w['messages']} messages; "
            f"identical {w['identical']}, parsed-equal {w['parsed_equal']}, "
            f"different {w['different']}"
        )
        if self.dumps:
            neq = sum(1 for d in self.dumps if not d.get("equal"))
            lines.append(f"DB dumps: {len(self.dumps)} compared, {neq} different")
        else:
            lines.append("DB dumps: not run (no --dump-tool)")
        lines.append(f"Unexpected differences: {len(self.failures)}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# DB dump comparison
# --------------------------------------------------------------------------


# meta\t<hex("NATIVE_LAST_WRITER")>
DUMP_IGNORED_PREFIXES = ("meta\t" + b"NATIVE_LAST_WRITER".hex() + "\t",)


def compare_dump_files(path_a: str, path_b: str, label: str, max_lines: int = 50):
    """Compare two `table\\tkey_hex\\tvalue_hex` dumps; returns a result dict."""
    import difflib

    with open(path_a, encoding="utf8") as f:
        la = f.read().splitlines()
    with open(path_b, encoding="utf8") as f:
        lb = f.read().splitlines()
    # The native indexer records which implementation last wrote the DB
    # (meta NATIVE_LAST_WRITER); Rust never writes it. It is expected to
    # differ, so it is reported but not compared.
    ignored = [line for line in la + lb if line.startswith(DUMP_IGNORED_PREFIXES)]
    la = [line for line in la if not line.startswith(DUMP_IGNORED_PREFIXES)]
    lb = [line for line in lb if not line.startswith(DUMP_IGNORED_PREFIXES)]
    result: Dict[str, Any] = {
        "checkpoint": label,
        "lines_a": len(la),
        "lines_b": len(lb),
        "equal": la == lb,
        "ignored": ignored,
    }
    per_table_a: Dict[str, int] = {}
    for line in la:
        t = line.split("\t", 1)[0]
        per_table_a[t] = per_table_a.get(t, 0) + 1
    result["tables"] = per_table_a
    if la != lb:
        diff = list(
            difflib.unified_diff(la, lb, "A", "B", n=0, lineterm="")
        )
        result["diff_head"] = diff[: max_lines]
        result["num_diff_lines"] = len(diff)
    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    with open(path, encoding="utf8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("responses_a", help="JSON-lines responses of implementation A")
    parser.add_argument("responses_b", help="JSON-lines responses of implementation B")
    parser.add_argument("--report", help="write the JSON report here")
    parser.add_argument("--allow", action="append", default=[],
                        help="additional allowed field path (fnmatch pattern)")
    parser.add_argument("--pb2-dir", help="directory containing chronik_pb2.py")
    parser.add_argument("--srcdir", help="source tree to generate chronik_pb2 from")
    args = parser.parse_args()
    load_pb(args.pb2_dir, args.srcdir)
    allow = DEFAULT_ALLOW + args.allow
    report = Report(allow)
    ra = _load_jsonl(args.responses_a)
    rb = {(r.get("kind", "http"), r["id"]): r for r in _load_jsonl(args.responses_b)}
    for entry in ra:
        kind = entry.get("kind", "http")
        other = rb.pop((kind, entry["id"]), None)
        if other is None:
            report.failures.append({"kind": "missing_in_b", "id": entry["id"]})
            continue
        if kind == "ws":
            msgs_a = [(m["opcode"], base64.b64decode(m["data"])) for m in entry["messages"]]
            msgs_b = [(m["opcode"], base64.b64decode(m["data"])) for m in other["messages"]]
            report.add_ws(compare_ws(entry["id"], msgs_a, msgs_b, allow,
                                     mode=entry.get("mode", "strict")),
                          entry.get("checkpoint", ""))
        else:
            report.add_http(compare_http(entry["request"], entry["response"],
                                         other["response"], allow),
                            entry.get("checkpoint", ""))
    for key in rb:
        report.failures.append({"kind": "missing_in_a", "id": key[1]})
    print(report.summary())
    if args.report:
        report.write(args.report)
    return 0 if report.ok() else 1


if __name__ == "__main__":
    sys.exit(main())
