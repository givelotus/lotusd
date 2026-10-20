#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check structured event keys, templates and category/scope conventions."""

import argparse
import ast
import re
import subprocess
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

MACROS = {
    "LogEvent",
    "LogTraceEvent",
    "LogInfoEvent",
    "LogInfoEventNoRateLimit",
    "LogWarningEvent",
    "LogErrorEvent",
}
# Names encode event scope. Global listener/server events use different names,
# rather than inventing a peer id or RPC method that does not exist.
REQUIRED = {
    "peer_": {"PeerId"},
    "rpc_call_": {"Method"},
    "mempool_tx_": {"TxId"},
    "block_connect_": {"BlockHash"},
}
TOKEN = re.compile(
    r"(?P<space>\s+)|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|"
    r'(?P<string>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|'
    r"(?P<ident>[A-Za-z_][A-Za-z_0-9]*)|(?P<punct>.)"
)


@dataclass
class Token:
    text: str
    kind: str
    pos: int


def tokens(source):
    result = []
    pos = 0
    while pos < len(source):
        # Raw C++ strings can contain apparent calls/comments/quotes.
        raw = re.match(r'(?:u8|u|U|L)?R"([^ ()\\\t\r\n]{0,16})\(', source[pos:])
        if raw:
            end = source.find(")" + raw.group(1) + '"', pos + raw.end())
            if end < 0:
                raise ValueError("unterminated raw string")
            end += len(raw.group(1)) + 2
            result.append(Token(source[pos:end], "string", pos))
            pos = end
            continue
        match = TOKEN.match(source, pos)
        if not match:
            raise ValueError("cannot tokenize source")
        if match.lastgroup not in ("space", "comment"):
            result.append(Token(match.group(), match.lastgroup, pos))
        pos = match.end()
    return result


def arguments(items, opening):
    """Split a C++ argument list, respecting nested (), [] and {} and literals."""
    stack = [")"]
    parts = [[]]
    i = opening + 1
    closes = {"(": ")", "[": "]", "{": "}"}
    while i < len(items):
        item = items[i]
        if item.kind == "punct":
            if item.text in closes:
                stack.append(closes[item.text])
            elif item.text == stack[-1]:
                stack.pop()
                if not stack:
                    return parts, i
            elif item.text == "," and len(stack) == 1:
                parts.append([])
                i += 1
                continue
        parts[-1].append(item)
        i += 1
    raise ValueError("unterminated argument list")


def literal(items):
    if not items or any(
        t.kind != "string" or not t.text.startswith('"') for t in items
    ):
        raise ValueError("event names/templates must use string literals")
    return "".join(ast.literal_eval(t.text) for t in items)


def registry(root):
    text = (root / "src/logging/fields.h").read_text(encoding="utf-8")
    return dict(re.findall(r"\bX\(\s*(\w+)\s*,\s*(\w+)\s*,", text))


def check(source, names, types=None):
    issues = []
    items = tokens(source)
    calls = 0
    for i, item in enumerate(items):
        if item.kind != "ident" or item.text not in MACROS:
            continue
        if i + 1 >= len(items) or items[i + 1].text != "(":
            continue
        line = source.count("\n", 0, item.pos) + 1
        calls += 1
        try:
            args, end = arguments(items, i + 1)
            if len(args) not in (2, 3):
                raise ValueError("expected category, event name and optional template")
            name = literal(args[1])
            if not re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", name):
                raise ValueError("event name must be snake_case")
            fields = set()
            cursor = end + 1
            while cursor + 2 < len(items) and [
                t.text for t in items[cursor : cursor + 3]
            ] == [".", "Field", "("]:
                field_args, cursor = arguments(items, cursor + 2)
                if len(field_args) < 2:
                    raise ValueError("Field requires a registry key and value")
                key = "".join(t.text for t in field_args[0])
                match = re.fullmatch(r"(?:BCLog::)?LogField::(\w+)", key)
                if not match or match.group(1) not in names:
                    raise ValueError("Field must use a canonical LogField registry key")
                key = match.group(1)
                if key in fields:
                    raise ValueError(f"duplicate field {key}")
                fields.add(key)
                cursor += 1
            for prefix, required in REQUIRED.items():
                if name.startswith(prefix) and not required <= fields:
                    raise ValueError(
                        f"{prefix} events require {', '.join(sorted(required - fields))}"
                    )
            if len(args) == 3:
                message = literal(args[2])
                # Double braces are not a single registry placeholder.
                message = message.replace("{{", "").replace("}}", "")
                placeholders = list(
                    re.finditer(r"\{([a-z][a-z0-9_]*)(?::([^}]*))?\}", message)
                )
                for placeholder in placeholders:
                    spec = placeholder.group(2)
                    if spec is None:
                        continue
                    key = next(
                        (key for key in fields if names[key] == placeholder.group(1)),
                        None,
                    )
                    if spec == "fsq":
                        if types is None or types.get(key) != "STRING":
                            raise ValueError(
                                "fsq format requires a STRING registry field"
                            )
                    elif re.fullmatch(r"(?:0(?:[1-9]|1[0-6]))?x", spec):
                        if types is None or types.get(key) not in {"INT", "UINT"}:
                            raise ValueError(
                                "hex format requires an INT/UINT registry field"
                            )
                    elif re.fullmatch(r"(?:0?(?:[1-9]|1[0-9]|20))?[du]", spec):
                        if types is None or types.get(key) not in {"INT", "UINT"}:
                            raise ValueError(
                                "decimal format requires an INT/UINT registry field"
                            )
                    elif re.fullmatch(r"(?:\.(?:[0-9]|1[0-8]))?[fg]", spec):
                        if types is None or types.get(key) not in {
                            "FLOAT",
                            "INT",
                            "UINT",
                        }:
                            raise ValueError(
                                "float format requires a FLOAT/INT/UINT registry field"
                            )
                    else:
                        raise ValueError("template format spec is not supported")
                used = {placeholder.group(1) for placeholder in placeholders}
                missing = used - {names[key] for key in fields}
                if missing:
                    raise ValueError(
                        f"template fields missing values: {', '.join(sorted(missing))}"
                    )
        except (ValueError, SyntaxError) as error:
            issues.append((line, str(error)))
    return calls, issues


class ContractTests(unittest.TestCase):
    names = {
        "PeerId": "peer_id",
        "Addr": "addr",
        "Method": "method",
        "TxId": "txid",
        "BlockHash": "block_hash",
    }

    def test_peer_fields(self):
        count, issues = check(
            'LogEvent(BCLog::NET, "peer_received", "peer {peer_id}").Field(LogField::PeerId, f(x, (y)));',
            self.names,
        )
        self.assertEqual((count, issues), (1, []))

    def test_template_argument_commas(self):
        source = 'LogEvent(BCLog::NET, "global").Field(LogField::Addr, Value<A, B>{});'
        self.assertFalse(check(source, self.names)[1])

    def test_missing_peer(self):
        self.assertIn(
            "require PeerId",
            check('LogEvent(BCLog::NET, "peer_received");', self.names)[1][0][1],
        )

    def test_missing_rpc(self):
        self.assertIn(
            "require Method",
            check('LogInfoEvent(BCLog::RPC, "rpc_call_done");', self.names)[1][0][1],
        )

    def test_unknown_and_duplicate(self):
        for chain in (
            '.Field("peer_id", 1)',
            ".Field(LogField::MadeUp, 1)",
            ".Field(LogField::PeerId, 1).Field(LogField::PeerId, 2)",
        ):
            self.assertTrue(
                check('LogEvent(BCLog::NET, "peer_x")' + chain + ";", self.names)[1]
            )

    def test_template(self):
        self.assertIn(
            "missing values",
            check('LogEvent(BCLog::NET, "global", "address {addr}");', self.names)[1][
                0
            ][1],
        )

    def test_unsupported_format_spec(self):
        source = 'LogEvent(BCLog::NET, "peer_x", "peer={peer_id:08}").Field(LogField::PeerId, 1);'
        self.assertIn("not supported", check(source, self.names)[1][0][1])

    def test_float_precision_contract(self):
        names = {"ElapsedMs": "elapsed_ms"}
        source = 'LogInfoEvent(BCLog::ALL,"elapsed","{elapsed_ms:%s}").Field(LogField::ElapsedMs, value);'
        for spec in ["f", "g", ".0f", ".2f", ".18g"]:
            self.assertFalse(check(source % spec, names, {"ElapsedMs": "FLOAT"})[1])
        for spec in ["", ".19f", ".-1f", "08.2f", "*f", ".2x"]:
            self.assertTrue(check(source % spec, names, {"ElapsedMs": "FLOAT"})[1])
        self.assertIn(
            "requires a FLOAT",
            check(source % ".2f", names, {"ElapsedMs": "STRING"})[1][0][1],
        )

    def test_integral_numeric_format_contract(self):
        names = {"Count": "count"}
        source = 'LogInfoEvent(BCLog::ALL,"counted","{count:%s}").Field(LogField::Count, value);'
        for kind in ("INT", "UINT"):
            for spec in (
                "d",
                "u",
                "1d",
                "01u",
                "05u",
                "15d",
                "20u",
                "020d",
                "f",
                "g",
                ".0f",
                ".2f",
                ".18g",
            ):
                self.assertFalse(
                    check(source % spec, names, {"Count": kind})[1], (kind, spec)
                )
            for spec in (
                "0d",
                "00u",
                "005u",
                "21d",
                "021u",
                "+5d",
                "-5d",
                "1.0d",
                ".19f",
                "08.2f",
            ):
                self.assertTrue(
                    check(source % spec, names, {"Count": kind})[1], (kind, spec)
                )
        for kind in ("STRING", "BOOL", "HASH", "DURATION"):
            for spec in ("15d", "05u", "f", ".2g"):
                self.assertTrue(
                    check(source % spec, names, {"Count": kind})[1], (kind, spec)
                )
        self.assertTrue(check(source % "15d", names, {"Count": "FLOAT"})[1])

    def test_hex_precision_contract(self):
        names = {"Version": "version"}
        source = 'LogInfoEventNoRateLimit(BCLog::ALL,"v","{version:%s}").Field(LogField::Version, v);'
        for spec in ["x", "01x", "08x", "016x"]:
            self.assertFalse(check(source % spec, names, {"Version": "INT"})[1])
        for spec in ["0x", "00x", "017x", "8x", ".2x", "08X"]:
            self.assertTrue(check(source % spec, names, {"Version": "INT"})[1])
        self.assertTrue(check(source % "08x", names, {"Version": "STRING"})[1])

    def test_filesystem_quote_contract(self):
        names = {"Path": "path"}
        source = 'LogInfoEvent(BCLog::ALL,"file_loaded","{path:fsq}").Field(LogField::Path, value);'
        self.assertFalse(check(source, names, {"Path": "STRING"})[1])
        for wrong in ["INT", "UINT", "FLOAT", "HASH"]:
            self.assertIn(
                "requires a STRING", check(source, names, {"Path": wrong})[1][0][1]
            )
        for changed in ["q", "fsquote", "fsq:1"]:
            self.assertTrue(
                check(source.replace(":fsq", ":" + changed), names, {"Path": "STRING"})[
                    1
                ]
            )

    def test_comments_and_strings(self):
        source = '// LogEvent(NET, "peer_bad");\nconst char *x = R"q(LogEvent(NET, "peer_bad"))q";\n/* LogEvent(NET,"bad"); */'
        self.assertEqual(check(source, self.names), (0, []))

    def test_source_archive_without_git(self):
        with tempfile.TemporaryDirectory(prefix="log-lint-archive-") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            path = root / "src/node.cpp"
            path.write_text("// source", encoding="utf-8")
            self.assertEqual(production_paths(root), [path])

    def test_literal_concatenation(self):
        self.assertFalse(
            check(
                'LogEvent(BCLog::NET, "peer_" "received").Field(BCLog::LogField::PeerId, 1);',
                self.names,
            )[1]
        )


def production_paths(root):
    try:
        raw = subprocess.check_output(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--",
                "src/",
                "chronik/chronik-cpp/",
            ],
            stderr=subprocess.DEVNULL,
        )
        return [root / path.decode() for path in raw.split(b"\0") if path]
    except (OSError, subprocess.CalledProcessError):
        # A git archive may retain maintainer lint scripts but no .git metadata.
        return [
            path
            for directory in (root / "src", root / "chronik/chronik-cpp")
            for path in directory.rglob("*")
            if path.suffix in (".cpp", ".h")
        ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    if options.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)
        )
        return not result.wasSuccessful()
    root = Path(__file__).resolve().parents[2]
    names = registry(root)
    types = dict(
        re.findall(
            r"\bX\(\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)\s*,",
            (root / "src/logging/fields.h").read_text(encoding="utf-8"),
        )
    )
    if options.paths:
        paths = [Path(path) for path in options.paths]
    else:
        paths = production_paths(root)
    total = 0
    failed = False
    for path in paths:
        relative = path.resolve().relative_to(root)
        if path.suffix not in (".cpp", ".h") or any(
            part in ("test", "bench", "secp256k1", "leveldb", "univalue", "crc32c")
            for part in relative.parts
        ):
            continue
        if relative.parts[:2] == ("src", "logging") or str(relative) == "src/logging.h":
            continue
        text = path.read_text(encoding="utf-8")
        if not re.search(r"\bLog(?:Trace|Info|Warning|Error)?Event\b", text):
            continue
        count, issues = check(text, names, types)
        total += count
        for line, issue in issues:
            print(f"{relative}:{line}: {issue}")
            failed = True
    if not failed:
        print(f"Structured event lint: {total} production call sites checked")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
