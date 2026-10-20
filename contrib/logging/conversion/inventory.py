#!/usr/bin/env python3
"""Inventory every tracked C/C++ logging call with AST source boundaries.

Unreviewed calls stay explicitly deferred; this report never treats a successful
parse or a JSON envelope as structured-field conversion. Comments and quoted
examples are excluded by the parser. Parser errors are retained per file/site.
"""

import argparse
import hashlib
import importlib.metadata
import json
import subprocess
from collections import Counter
from pathlib import Path

from ast_grep_py import SgRoot

TIMER_PRODUCERS = {
    "LOG_TIME_MICROS_WITH_CATEGORY",
    "LOG_TIME_MILLIS_WITH_CATEGORY",
    "LOG_TIME_MILLIS_WITH_CATEGORY_MSG_ONCE",
    "LOG_TIME_SECONDS",
}

LEGACY = {
    "LogPrintf",
    "LogInfo",
    "LogWarning",
    "LogError",
    "LogDebug",
    "LogTrace",
    "LogPrint",
    "LogPrintLevel",
    "LogPrintLevel_",
    "LogPrintf_",
    "LogPrintfToBeContinued",
    "LogPrintToBeContinued",
    "LogPrintLevelToBeContinued",
    "WalletLogPrintf",
    "WalletLogPrintfToBeContinued",
    "LogPrintStr",
    "LogPrintMovedStr",
} | TIMER_PRODUCERS
STRUCTURED = {
    "LogEvent",
    "LogTraceEvent",
    "LogInfoEvent",
    "LogWarningEvent",
    "LogErrorEvent",
    "LogInfoEventNoRateLimit",
}


def inventory(root, revision=None, dispositions=None):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args])

    revision = git("rev-parse", revision or "HEAD").decode().strip()
    files = git("ls-tree", "-r", "--name-only", revision).decode().splitlines()
    sites, errors, hashes = [], [], {}
    for path in files:
        if Path(path).suffix not in {".h", ".hpp", ".cpp", ".cc", ".c"}:
            continue
        raw = git("show", revision + ":" + path)
        if not any(name.encode() in raw for name in LEGACY | STRUCTURED):
            continue
        source = raw.decode("utf-8")
        hashes[path] = hashlib.sha256(raw).hexdigest()
        ast = SgRoot(source, "cpp").root()
        parse_errors = list(ast.find_all(kind="ERROR"))
        if parse_errors:
            errors.append({"path": path, "count": len(parse_errors)})
        occurrences = Counter()
        for call in ast.find_all(kind="call_expression"):
            function = call.field("function")
            if not function:
                continue
            # Wallet and bridge wrappers may be invoked as member functions.
            identifier = (
                function
                if function.kind() == "identifier"
                else function.field("field")
                if function.kind() == "field_expression"
                else function.field("name")
                if function.kind() == "qualified_identifier"
                else None
            )
            if not identifier:
                continue
            name = identifier.text()
            if name not in LEGACY | STRUCTURED:
                continue
            text = call.text()
            digest = hashlib.sha256(text.encode()).hexdigest()
            occurrences[digest] += 1
            line = call.range().start.line + 1
            in_test = path.startswith(
                ("src/test/", "src/bench/", "test/", "chronik/test/")
            )
            implementation = path in {"src/logging.h", "src/logging/event.h"}
            disposition = (
                "already_structured"
                if name in STRUCTURED
                else "infrastructure"
                if implementation
                else "deferred"
            )
            reason = (
                "Typed event API; field semantics still require review."
                if disposition == "already_structured"
                else "Logging implementation or macro definition, not consumer."
                if implementation
                else "Explicitly pending semantic review and conversion; not waived."
            )
            sites.append(
                {
                    "id": f"{path}:{digest[:20]}:{occurrences[digest]}",
                    "path": path,
                    "line": line,
                    "macro": name,
                    "scope": "test_or_benchmark" if in_test else "production",
                    "disposition": disposition,
                    "reason": reason,
                    "intersects_parse_error": bool(call.find(kind="ERROR"))
                    or any(a.kind() == "ERROR" for a in call.ancestors()),
                    "source": text,
                }
            )
    known = {site["id"] for site in sites}
    for identity, decision in (dispositions or {}).items():
        if identity not in known:
            raise ValueError("stale disposition needs review: " + identity)
        if (
            set(decision) != {"disposition", "reason"}
            or decision.get("disposition")
            not in {"intentionally_freeform", "infrastructure", "deferred"}
            or not isinstance(decision.get("reason"), str)
            or not decision["reason"].strip()
        ):
            raise ValueError("invalid disposition: " + identity)
    for site in sites:
        if site["id"] in (dispositions or {}):
            site.update(dispositions[site["id"]])
    return {
        "schema": 1,
        "revision": revision,
        "engine": "ast-grep-py==" + importlib.metadata.version("ast-grep-py"),
        "scope": "all tracked C/C++ files, including Chronik/seeder/tools/vendor",
        "counts": dict(Counter(s["disposition"] for s in sites)),
        "macros": dict(Counter(s["macro"] for s in sites)),
        "source_hashes": hashes,
        "parser_errors": errors,
        "sites": sites,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--revision")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dispositions", type=Path)
    options = parser.parse_args()
    root = options.root.resolve()
    decisions_path = (
        options.dispositions or root / "contrib/logging/conversion/dispositions.json"
    )
    decisions = (
        json.loads(decisions_path.read_text())["sites"]
        if decisions_path.exists()
        else {}
    )
    report = inventory(root, options.revision, decisions)
    options.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "revision": report["revision"],
                "counts": report["counts"],
                "macros": report["macros"],
                "files_with_parser_errors": len(report["parser_errors"]),
            }
        )
    )
