#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Turn functional tests' set_test_params() into class attributes.

A set_test_params() whose body only assigns constants to self.<name> (each
value may use names assigned before it, e.g. `[[]] * self.num_nodes`) is
replaced by the same assignments as class attributes. Comments are kept.
Methods that compute anything else (use self.options, call methods, have
control flow or a docstring) are left alone.

Usage: declarative-test-params.py FILE...   (rewrites the files in place;
prints what it changed and why it skipped the others)
"""

import ast
import re
import sys


def convert(source):
    """Return (new_source, None) or (None, reason it was left alone)."""
    tree = ast.parse(source)
    methods = [
        node
        for cls in tree.body
        if isinstance(cls, ast.ClassDef)
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name == "set_test_params"
    ]
    if not methods:
        return None, "no set_test_params"
    if len(methods) > 1:
        return None, "several set_test_params"
    method = methods[0]
    if method.decorator_list or len(method.args.args) != 1:
        return None, "unusual signature"
    assigned = []
    for stmt in method.body:
        if not (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Attribute)
            and isinstance(stmt.targets[0].value, ast.Name)
            and stmt.targets[0].value.id == "self"
        ):
            return None, f"line {stmt.lineno}: not a plain self.<name> assignment"
        # self.<name> may only refer to a parameter assigned above
        allowed = set()
        for node in ast.walk(stmt.value):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "self"
            ):
                if node.attr not in assigned:
                    return None, f"line {stmt.lineno}: uses self.{node.attr}"
                allowed.add(id(node.value))
        for node in ast.walk(stmt.value):
            if isinstance(node, ast.Name) and node.id == "self":
                if id(node) not in allowed:
                    return None, f"line {stmt.lineno}: uses self other than attributes"
            if isinstance(node, (ast.Call, ast.Lambda)) and not _is_simple_call(node):
                return None, f"line {stmt.lineno}: calls something"
        assigned.append(stmt.targets[0].attr)

    lines = source.splitlines(keepends=True)
    start = method.lineno - 1  # the def line
    end = method.end_lineno  # last line of the body (exclusive index)
    body = lines[start + 1 : end]
    out = []
    for line in body:
        if line.strip() and not line.startswith(" " * 8):
            return None, "unexpected indentation"
        dedented = line[4:] if line.strip() else line
        out.append(re.sub(r"\bself\.(\w+)", r"\1", dedented))
    # Drop a blank line left before the next method, keep one separator
    new_lines = lines[:start] + out + lines[end:]
    return "".join(new_lines), None


def _is_simple_call(node):
    """Calls allowed in a parameter value: list(), range() and the like."""
    if isinstance(node, ast.Lambda):
        return False
    return isinstance(node.func, ast.Name) and node.func.id in (
        "list",
        "range",
        "dict",
        "set",
        "tuple",
        "str",
        "int",
        "len",
    )


def main():
    changed = 0
    for path in sys.argv[1:]:
        with open(path, encoding="utf8") as f:
            source = f.read()
        new, reason = convert(source)
        if new is None:
            print(f"skip {path}: {reason}")
            continue
        with open(path, "w", encoding="utf8") as f:
            f.write(new)
        changed += 1
    print(f"converted {changed} of {len(sys.argv) - 1} files")


if __name__ == "__main__":
    main()
