#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Turn functional tests' skip_test_if_missing_module() into `requires`.

An override whose body only calls self.skip_if_*() helpers that have a
requirement name (see REQUIREMENTS in test_framework/test_framework.py) is
replaced by `requires = {...}`. Other overrides are left alone and reported.

Usage: declarative-test-requires.py FILE...   (rewrites the files in place)
"""

import ast
import sys

HELPERS = {
    "skip_if_no_wallet": "wallet",
    "skip_if_no_wallet_tool": "wallet_tool",
    "skip_if_no_cli": "cli",
    "skip_if_no_bitcoind_zmq": "zmq",
    "skip_if_no_py3_zmq": "py3_zmq",
    "skip_if_no_chronik": "chronik",
    "skip_if_no_chronik_plugins": "chronik_plugins",
    "skip_if_platform_not_linux": "linux",
    "skip_if_no_bitcoind_tracepoints": "usdt",
    "skip_if_no_python_bcc": "bcc",
    "skip_if_no_bpf_permissions": "bpf_permissions",
}


def convert(source):
    """Return (new_source, None) or (None, reason it was left alone)."""
    tree = ast.parse(source)
    methods = [
        node
        for cls in tree.body
        if isinstance(cls, ast.ClassDef)
        for node in cls.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "skip_test_if_missing_module"
    ]
    if not methods:
        return None, "no skip_test_if_missing_module"
    if len(methods) > 1:
        return None, "several overrides"
    method = methods[0]
    names = []
    for stmt in method.body:
        call = stmt.value if isinstance(stmt, ast.Expr) else None
        if not (
            isinstance(call, ast.Call)
            and not call.args
            and not call.keywords
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "self"
            and call.func.attr in HELPERS
        ):
            return None, f"line {stmt.lineno}: not a requirement helper call"
        names.append(HELPERS[call.func.attr])
    lines = source.splitlines(keepends=True)
    first = method.lineno - 1
    # Comments directly in the method body would be lost: keep them out
    body = "".join(lines[first : method.end_lineno])
    if "#" in body:
        return None, "has comments"
    attribute = "    requires = {" + ", ".join(f'"{n}"' for n in names) + "}\n"
    return "".join(lines[:first] + [attribute] + lines[method.end_lineno :]), None


def main():
    changed = 0
    for path in sys.argv[1:]:
        with open(path, encoding="utf8") as f:
            source = f.read()
        new, reason = convert(source)
        if new is None:
            if reason != "no skip_test_if_missing_module":
                print(f"skip {path}: {reason}")
            continue
        with open(path, "w", encoding="utf8") as f:
            f.write(new)
        changed += 1
    print(f"converted {changed} files")


if __name__ == "__main__":
    main()
