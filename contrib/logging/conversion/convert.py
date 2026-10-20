#!/usr/bin/env python3
"""Conservative reviewed C++ logging conversion; AST boundaries, never source regex.

No event names, field semantics, severity or argument types are inferred. A rule
is an explicitly reviewed old call/new expression pair. The token fingerprint
includes every argument and format token, so changed inputs fail closed. Use
--apply only after reviewing the dry-run inventory and diff.
"""
import argparse
from collections import Counter
import difflib
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import sys
from ast_grep_py import SgRoot

ENGINE = "0.51.0"
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
}
EVENTS = {
    "LogInfoEvent",
    "LogInfoEventNoRateLimit",
    "LogWarningEvent",
    "LogErrorEvent",
    "LogEvent",
    "LogTraceEvent",
}
SPEC = re.compile(
    r"%(?:[-+ #0]*)(?:\d+)?(?:\.\d+)?(?:hh|ll|[hljztL])?[diuoxXfFeEgGaAcsp%]"
)


def parse(source):
    root = SgRoot(source, "cpp").root()
    return root


def fingerprint(node):
    if node.is_leaf():
        return (node.kind(), node.text())
    return (node.kind(), tuple(fingerprint(c) for c in node.children()))


def calls(source, names):
    result = []
    for n in parse(source).find_all(kind="call_expression"):
        fn = n.field("function")
        if fn and fn.kind() == "identifier" and fn.text() in names:
            if n.find(kind="ERROR") or any(a.kind() == "ERROR" for a in n.ancestors()):
                raise ValueError("parse error intersects logging call; no edits made")
            result.append(n)
    return result


def args(node):
    return [child for child in node.field("arguments").named_children()
            if child.kind() != "comment"]


def literal(node):
    # Parse adjacent ordinary literals through C++ AST children, not source regex.
    if node.kind() == "concatenated_string":
        return "".join(literal(c) for c in node.named_children())
    if node.kind() != "string_literal" or not node.text().startswith('"'):
        raise ValueError("dynamic, raw, prefixed or concatenated format")
    # Normalize the one standard C++ escape JSON lacks, tracking pairs so an
    # escaped backslash before an apostrophe keeps its original meaning.
    raw = node.text()
    normalized = []
    index = 0
    while index < len(raw):
        if raw[index] == "\\" and index + 1 < len(raw):
            following = raw[index + 1]
            normalized.append("'" if following == "'" else raw[index:index + 2])
            index += 2
        else:
            normalized.append(raw[index])
            index += 1
    try:
        return json.loads("".join(normalized))
    except (ValueError, TypeError):
        raise ValueError("unsupported C++ literal escape") from None


def format_parts(message):
    parts = []
    last = 0
    for m in re.finditer("%", message):
        if m.start() < last:
            continue
        spec = SPEC.match(message, m.start())
        if not spec:
            raise ValueError("unsupported printf specifier at byte " + str(m.start()))
        parts.append((message[last : m.start()], spec.group()))
        last = spec.end()
    parts.append((message[last:], ""))
    return parts


def describe(node):
    name = node.field("function").text()
    index = (
        3 if name == "LogPrintLevel_" else 2
        if name == "LogPrintLevel"
        else 1 if name in {"LogPrint", "LogDebug", "LogTrace"} else 0
    )
    values = args(node)
    if index >= len(values):
        raise ValueError("missing format argument")
    message = literal(values[index])
    parts = format_parts(message)
    count = sum(bool(spec) and spec != "%%" for _, spec in parts)
    if count != len(values) - index - 1:
        raise ValueError("specifier/argument count mismatch")
    return {
        "macro": name,
        "format": message,
        "specifiers": [s for _, s in parts if s and s != "%%"],
        "arguments": [v.text() for v in values[index + 1 :]],
    }


def outer_event(node):
    while node.parent() and node.parent().kind() == "field_expression":
        parent = node.parent().parent()
        if not parent or parent.kind() != "call_expression":
            break
        node = parent
    return node


def validate_mapping(old, event):
    description = describe(old)
    # Decimal integer length modifiers preserve decimal text. Explicit float
    # precision uses the separately tested consumer rendering contract.
    def rendering(spec, value=None):
        if spec == "%s":
            if (value is not None and value.kind() == "call_expression"
                    and value.field("function").text() == "fs::quoted"
                    and len(args(value)) == 1):
                return "fsq"
            return None
        if spec == "%c":
            return None  # Exact LogChar snapshot contract checked below.
        if re.fullmatch(r"%(?:ll|l|z|t|j)?[diu]", spec):
            return None
        if re.fullmatch(r"%(?:0(?:[1-9]|1[0-6]))?x", spec):
            return spec[1:]
        if re.fullmatch(r"%(?:\.(?:[0-9]|1[0-8]))?[fg]", spec):
            return spec[1:]
        raise ValueError("format width/precision/type needs manual rendering support")

    for spec in description["specifiers"]:
        rendering(spec)
    oldargs, newargs = args(old), args(event)
    # %c must snapshot its original argument directly in a STRING Field via
    # LogChar. An integer field or a rewritten byte must not silently replace it.
    source_values = oldargs[len(oldargs) - len(description["arguments"]):]
    required_chars = Counter()
    for spec, value in zip(description["specifiers"], source_values):
        if spec == "%c":
            expected = parse("auto snapshot = BCLog::LogChar{" + value.text() + "};")
            required_chars[fingerprint(expected.find(kind="compound_literal_expression"))] += 1
    actual_chars = Counter()
    for value in outer_event(event).find_all(kind="compound_literal_expression"):
        type_node = value.field("type")
        if type_node is None or type_node.text() != "BCLog::LogChar":
            continue
        arguments = value.parent()
        call = arguments.parent() if arguments else None
        function = call.field("function") if call and call.kind() == "call_expression" else None
        field = function.field("field") if function and function.kind() == "field_expression" else None
        if (arguments.kind() != "argument_list" or field is None
                or field.text() != "Field" or len(args(call)) != 2
                or args(call)[1].text() != value.text()):
            raise ValueError("character snapshot must be a direct Field argument")
        actual_chars[fingerprint(value)] += 1
    if required_chars != actual_chars:
        raise ValueError("character formatting requires an exact LogChar snapshot")
    macro = description["macro"]
    category = (
        oldargs[0].text()
        if macro in {"LogDebug", "LogTrace", "LogPrint", "LogPrintLevel", "LogPrintLevel_"}
        else "BCLog::ALL"
    )
    expected = {
        "LogPrintf": "LogInfoEvent",
        "LogInfo": "LogInfoEvent",
        "LogWarning": "LogWarningEvent",
        "LogError": "LogErrorEvent",
        "LogDebug": "LogEvent",
        "LogTrace": "LogTraceEvent",
        "LogPrint": "LogEvent",
    }.get(macro)
    if macro == "LogPrintLevel":
        expected = {
            "BCLog::Level::Warning": "LogWarningEvent",
            "BCLog::Level::Error": "LogErrorEvent",
            "BCLog::Level::Info": "LogInfoEvent",
            "BCLog::Level::Debug": "LogEvent",
            "BCLog::Level::Trace": "LogTraceEvent",
        }.get(oldargs[1].text())
    if macro == "LogPrintLevel_":
        if oldargs[1].text() == "BCLog::Level::Info" and oldargs[2].text() == "false":
            expected = "LogInfoEventNoRateLimit"
        else:
            raise ValueError("unreviewed low-level logging rate-limit contract")
    if event.field("function").text() != expected or newargs[0].text() != category:
        raise ValueError("severity/category changed")
    message = literal(newargs[2])
    # Regex only examines captured literal bodies, never source boundaries.
    placeholders = re.findall(r"\{[a-z][a-z0-9_]*(?::[^}]*)?\}", message)
    parts = format_parts(description["format"])
    rebuilt = ""
    cursor = 0
    for text, spec in parts:
        rebuilt += text
        if spec == "%%":
            rebuilt += "%"
        elif spec:
            if cursor >= len(placeholders):
                raise ValueError("missing message placeholder")
            placeholder = placeholders[cursor]
            # The old AST, not a label or regex, establishes fs::quoted's
            # nonstandard '&' escaping. A plain %s must not gain this format.
            value = oldargs[len(oldargs) - len(description["arguments"]) + cursor]
            format_spec = rendering(spec, value)
            suffix = ":" + format_spec + "}" if format_spec is not None else None
            if (suffix is not None and not placeholder.endswith(suffix)) or (
                suffix is None and ":" in placeholder
            ):
                raise ValueError("message float precision changed")
            rebuilt += placeholder
            cursor += 1
    if rebuilt.endswith("\n"):
        rebuilt = rebuilt[:-1]
    if cursor != len(placeholders) or rebuilt != message:
        raise ValueError("message wording/escaping changed")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def convert(source, rules):
    nodes = calls(source, LEGACY)
    edits = []
    report = []
    seen = {}
    by_key = {}
    for rule in rules:
        old = calls(rule["old"], LEGACY)
        if len(old) != 1:
            raise ValueError("rule must contain exactly one legacy call")
        description = describe(old[0])
        if description != rule["reviewed_input"]:
            raise ValueError("reviewed input does not describe rule " + rule["id"])
        new = calls(rule["replacement"], EVENTS)
        if len(new) != 1 or outer_event(new[0]).text() != rule["replacement"]:
            raise ValueError("replacement must be one structured event expression")
        validate_mapping(old[0], new[0])
        if not rule.get("review_note"):
            raise ValueError("missing explicit mapping review")
        key = fingerprint(old[0])
        if key in by_key:
            raise ValueError("duplicate input rule")
        by_key[key] = rule
        seen[rule["id"]] = 0
    for n in nodes:
        entry = {"line": n.range().start.line + 1, "call": n.text()}
        try:
            description = describe(n)
            rule = by_key.get(fingerprint(n))
            if not rule:
                entry.update(
                    status="rejected",
                    reason="no reviewed semantic mapping",
                    input=description,
                )
            else:
                seen[rule["id"]] += 1
                edits.append(n.replace(rule["replacement"]))
                entry.update(status="converted", rule=rule["id"], input=description)
        except ValueError as e:
            entry.update(status="rejected", reason=str(e))
        report.append(entry)
    # Missing input is only idempotent when exactly the expected output exists.
    output_nodes = [outer_event(n) for n in calls(source, EVENTS)]
    for rule in rules:
        if seen[rule["id"]] == 0:
            expected = fingerprint(
                parse(rule["replacement"]).find(kind="call_expression")
            )
            matches = sum(fingerprint(n) == expected for n in output_nodes)
            if matches != rule.get("count", 1):
                raise ValueError("missing/drifted rule " + rule["id"])
        elif seen[rule["id"]] != rule.get("count", 1):
            raise ValueError("unexpected match count for " + rule["id"])
    return parse(source).commit_edits(edits), report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--rules", required=True, type=Path)
    p.add_argument("--report", type=Path)
    p.add_argument("--apply", action="store_true")
    o = p.parse_args()
    actual = importlib.metadata.version("ast-grep-py")
    if actual != ENGINE:
        p.error("requires ast-grep-py==" + ENGINE + ", got " + actual)
    raw = o.rules.read_bytes()
    catalog = json.loads(raw)
    prepared = []
    receipt = {
        "engine": "ast-grep-py " + actual,
        "rules_sha256": digest(raw),
        "script_sha256": digest(Path(__file__).read_bytes()),
        "applied": o.apply,
        "files": [],
    }
    for item in catalog["files"]:
        path = o.root / item["path"]
        before = path.read_text()
        after, inventory = convert(before, item["rules"])
        # Explicit non-call support adjustments are reviewed separately: fields,
        # includes and functional assertions. They are never guessed from text.
        for adjustment in item.get("support_adjustments", []):
            old, new = adjustment["old"], adjustment["new"]
            if new in after:
                # A replacement can contain its old anchor (e.g. an include
                # insertion). Recognize the complete result before the anchor.
                if after.count(new) != 1 or old in after.replace(new, "", 1):
                    raise ValueError(
                        "ambiguous support adjustment " + adjustment["purpose"]
                    )
            elif after.count(old) == 1:
                after = after.replace(old, new, 1)
            else:
                raise ValueError(
                    "drifted/ambiguous support adjustment " + adjustment["purpose"]
                )
        if after != before:
            prepared.append((path, after))
        receipt["files"].append(
            {
                "path": item["path"],
                "before_sha256": digest(before.encode()),
                "after_sha256": digest(after.encode()),
                "converted": sum(i["status"] == "converted" for i in inventory),
                "rejected": sum(i["status"] == "rejected" for i in inventory),
                "inventory": inventory,
            }
        )
        sys.stdout.writelines(
            difflib.unified_diff(
                before.splitlines(True),
                after.splitlines(True),
                fromfile="a/" + item["path"],
                tofile="b/" + item["path"],
            )
        )
    if o.apply:
        for path, after in prepared:
            path.write_text(after)
    if o.report:
        o.report.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
