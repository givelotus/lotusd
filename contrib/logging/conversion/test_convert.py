#!/usr/bin/env python3
"""AST and fail-closed fixtures, plus exact reviewed before/after batch proof."""
import json
from pathlib import Path
import unittest
import subprocess
import sys
import tempfile
import convert


def rule(old, new, count=1):
    node = convert.calls(old, convert.LEGACY)[0]
    return {
        "id": "fixture",
        "old": old,
        "replacement": new,
        "count": count,
        "reviewed_input": convert.describe(node),
        "review_note": "Explicit fixture mapping; not inferred.",
    }


class ConversionTest(unittest.TestCase):
    def test_nested_template_and_lambda_arguments(self):
        old = 'LogPrintf("foo=%d", f<T,U>([] { return 1; }));'
        new = 'LogInfoEvent(BCLog::ALL,"example","foo={value}").Field(BCLog::LogField::Value,f<T,U>([] { return 1; }))'
        r = rule(old, new)
        after, report = convert.convert(old, [r])
        self.assertEqual(after, new + ";")
        self.assertEqual(report[0]["input"]["arguments"], ["f<T,U>([] { return 1; })"])
        self.assertEqual(convert.convert(after, [r])[0], after)

    def test_comments_and_strings_are_not_calls(self):
        source = '// LogPrintf("hi");\nconst char *x="LogPrintf(hi)";'
        self.assertEqual(convert.calls(source, convert.LEGACY), [])

    def test_concatenation_escapes_and_percent(self):
        source = 'LogPrintf("foo=%% " "value=%08.2f\\n", v);'
        description = convert.describe(convert.calls(source, convert.LEGACY)[0])
        self.assertEqual(description["format"], "foo=%% value=%08.2f\n")
        self.assertEqual(description["specifiers"], ["%08.2f"])

    def test_cpp_apostrophe_escape_and_backslash_parity(self):
        # Standard C++ allows escaped apostrophes even inside a double-quoted
        # literal. Preserve escaped backslashes and normal JSON-compatible
        # escapes; never strip a backslash based on a raw regex replacement.
        for run in range(1, 6):
            raw = "\\" * run + "'"
            expression = 'LogPrintf("value=' + raw + '\\n")'
            node = convert.calls(expression, convert.LEGACY)[0]
            expected = "value=" + "\\" * (run // 2) + "'\n"
            self.assertEqual(convert.describe(node)["format"], expected)
        old = r'LogPrintf("Missing input %d in transaction \'%s\'\n", i, label)'
        new = ('LogInfoEvent(BCLog::ALL,"missing_input",'
               '"Missing input {count} in transaction \'{name}\'")'
               '.Field(BCLog::LogField::Count,i)'
               '.Field(BCLog::LogField::Name,label)')
        after, _ = convert.convert(old, [rule(old, new)])
        self.assertEqual(after, new)
        self.assertEqual(convert.convert(after, [rule(old, new)])[0], after)
        for escape in (r"\a", r"\v", r"\x27", r"\047", r"\?"):
            with self.assertRaises(ValueError):
                convert.describe(convert.calls('LogPrintf("' + escape + '")', convert.LEGACY)[0])

    def test_unsupported_formats_are_rejected(self):
        for expression in [
            "LogPrintf(fmt, x)",
            'LogPrintf("%*f", w, x)',
            'LogPrintf("%2$s", x)',
            'LogPrintf(R"(%s)", x)',
        ]:
            _, inventory = convert.convert(expression, [])
            self.assertEqual(inventory[0]["status"], "rejected")
        _, inventory = convert.convert('LogPrintf("foo=%d", x)', [])
        self.assertEqual(inventory[0]["reason"], "no reviewed semantic mapping")

    def test_exact_input_and_expected_counts(self):
        r = rule(
            'LogPrintf("x=%d", x)',
            'LogInfoEvent(BCLog::ALL,"x","x={value}").Field(BCLog::LogField::Value,x)',
        )
        for source in ['LogPrintf("x=%d", y)', r["old"] + ";" + r["old"]]:
            with self.assertRaises(ValueError):
                convert.convert(source, [r])
        r["reviewed_input"]["format"] = "changed"
        with self.assertRaises(ValueError):
            convert.convert(r["old"], [r])

    def test_mapping_cannot_change_level_category_or_text(self):
        old = 'LogDebug(BCLog::NET,"x=%d", x)'
        for new in [
            'LogInfoEvent(BCLog::NET,"x","x={value}")',
            'LogEvent(BCLog::ALL,"x","x={value}")',
            'LogEvent(BCLog::NET,"x","different={value}")',
        ]:
            with self.assertRaises(ValueError):
                convert.convert(old, [rule(old, new)])

    def test_width_precision_requires_rendering_support(self):
        old = 'LogPrintf("foo=%08.2f", x)'
        new = (
            'LogInfoEvent(BCLog::ALL,"x","foo={value}").Field(BCLog::LogField::Value,x)'
        )
        with self.assertRaises(ValueError):
            convert.convert(old, [rule(old, new)])

    def test_decimal_integer_lengths(self):
        for spec in ["%i", "%ld", "%lu", "%lld", "%llu", "%zu", "%td", "%ju"]:
            old = 'LogPrintf("value=' + spec + '", x)'
            new = 'LogInfoEvent(BCLog::ALL,"value","value={count}").Field(BCLog::LogField::Count,x)'
            self.assertEqual(convert.convert(old, [rule(old, new)])[0], new)

    def test_character_requires_original_byte_snapshot(self):
        old = 'LogError("key=(%c,%d)", DB_PREFIX, height)'
        new = ('LogErrorEvent(BCLog::ALL,"key_error","key=({value},{height})")'
               '.Field(BCLog::LogField::Value,BCLog::LogChar{DB_PREFIX})'
               '.Field(BCLog::LogField::Height,height)')
        self.assertEqual(convert.convert(old, [rule(old, new)])[0], new)
        for changed in [new.replace('LogChar{DB_PREFIX}', 'LogChar{OTHER_PREFIX}'),
                        new.replace('BCLog::LogChar{DB_PREFIX}', 'DB_PREFIX'),
                        new.replace('BCLog::LogChar{DB_PREFIX}', 'sizeof(BCLog::LogChar{DB_PREFIX})')]:
            with self.assertRaises(ValueError):
                convert.convert(old, [rule(old, changed)])
        for spec in ['%2c', '%lc']:
            wide = old.replace('%c', spec)
            with self.assertRaises(ValueError):
                convert.convert(wide, [rule(wide, new)])

    def test_float_precision_is_exact(self):
        for spec in ["%f", "%g", "%.0f", "%.2f", "%.18g"]:
            old = 'LogPrintf("elapsed=' + spec + '", x)'
            new = ('LogInfoEvent(BCLog::ALL,"elapsed","elapsed={elapsed_ms:'
                   + spec[1:] + '}").Field(BCLog::LogField::ElapsedMs,x)')
            self.assertEqual(convert.convert(old, [rule(old, new)])[0], new)
            for changed in [new.replace(spec[1:] + '}', '.1f}'),
                            new.replace(':' + spec[1:], '')]:
                with self.assertRaises(ValueError):
                    convert.convert(old, [rule(old, changed)])
        for spec in ["%.19f", "%08.2f", "%+f", "%e"]:
            old = 'LogPrintf("elapsed=' + spec + '", x)'
            new = 'LogInfoEvent(BCLog::ALL,"elapsed","elapsed={elapsed_ms:f}").Field(BCLog::LogField::ElapsedMs,x)'
            with self.assertRaises(ValueError):
                convert.convert(old, [rule(old, new)])

    def test_hex_and_explicit_unthrottled_info(self):
        old = 'LogPrintLevel_(BCLog::ALL, BCLog::Level::Info, /*should_ratelimit=*/false, "v=%08x", v)'
        new = ('LogInfoEventNoRateLimit(BCLog::ALL,"version","v={version:08x}")'
               '.Field(BCLog::LogField::Version,uint32_t(v))')
        self.assertEqual(convert.convert(old, [rule(old, new)])[0], new)
        for changed in [new.replace('NoRateLimit', ''),
                        new.replace(':08x', ':x')]:
            with self.assertRaises(ValueError):
                convert.convert(old, [rule(old, changed)])
        with self.assertRaises(ValueError):
            changed = old.replace('false', 'true')
            convert.convert(changed, [rule(changed, new)])

    def test_filesystem_quoting_requires_old_ast_contract(self):
        old = 'LogPrintf("path=(%s)\\n", fs::quoted(fs::PathToString(path)))'
        new = 'LogInfoEvent(BCLog::ALL,"path_loaded","path=({path:fsq})").Field(BCLog::LogField::Path,fs::PathToString(path))'
        self.assertEqual(convert.convert(old, [rule(old, new)])[0], new)
        self.assertEqual(convert.convert(new, [rule(old, new)])[0], new)
        with self.assertRaises(ValueError):
            changed = new.replace(":fsq", "")
            convert.convert(old, [rule(old, changed)])
        for plain in ['LogPrintf("path=(%s)\\n", fs::PathToString(path))',
                      'LogPrintf("path=(%s)\\n", other::quoted(path))']:
            with self.assertRaises(ValueError):
                convert.convert(plain, [rule(plain, new)])

    def test_all_catalog_rules_and_idempotence(self):
        for path in sorted((Path(__file__).parent / "rules").glob("*.json")):
            catalog = json.loads(path.read_text())
            for item in catalog["files"]:
                for r in item["rules"]:
                    with self.subTest(rule=r["id"]):
                        source = (";\n".join([r["old"]] * r.get("count", 1))) + ";"
                        after, inventory = convert.convert(source, [r])
                        self.assertEqual(
                            sum(x["status"] == "converted" for x in inventory),
                            r.get("count", 1),
                        )
                        self.assertEqual(convert.convert(after, [r])[0], after)

    def test_late_file_validation_failure_does_not_write_earlier_file(self):
        old = 'LogPrintf("x=%d", x)'
        new = 'LogInfoEvent(BCLog::ALL,"x","x={value}").Field(BCLog::LogField::Value,x)'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "first.cpp").write_text(old + ";")
            (root / "second.cpp").write_text('LogPrintf("x=%d", drifted);')
            catalog = {
                "files": [
                    {"path": name, "rules": [rule(old, new)]}
                    for name in ["first.cpp", "second.cpp"]
                ]
            }
            (root / "rules.json").write_text(json.dumps(catalog))
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).parent / "convert.py"),
                    "--root",
                    str(root),
                    "--rules",
                    str(root / "rules.json"),
                    "--apply",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing/drifted rule", result.stderr)
            self.assertEqual((root / "first.cpp").read_text(), old + ";")
            self.assertEqual(
                (root / "second.cpp").read_text(), 'LogPrintf("x=%d", drifted);'
            )

    def test_overlapping_support_adjustment_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = "#include <a.h>\n"
            expected = "#include <a.h>\n#include <b.h>\n"
            (root / "input.cpp").write_text(original)
            catalog = {
                "files": [
                    {
                        "path": "input.cpp",
                        "rules": [],
                        "support_adjustments": [
                            {
                                "purpose": "fixture include",
                                "old": original,
                                "new": expected,
                            }
                        ],
                    }
                ]
            }
            (root / "rules.json").write_text(json.dumps(catalog))
            command = [
                sys.executable,
                str(Path(__file__).parent / "convert.py"),
                "--root",
                str(root),
                "--rules",
                str(root / "rules.json"),
                "--apply",
            ]
            subprocess.run(command, capture_output=True, text=True, check=True)
            second = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(second.stdout, "")
            self.assertEqual((root / "input.cpp").read_text(), expected)

    def test_trace_calls_are_inventoried_and_keep_trace_severity(self):
        for old in [
            'LogTrace(BCLog::NET,"peer=%d", id)',
            'LogPrintLevel(BCLog::NET,BCLog::Level::Trace,"peer=%d", id)',
        ]:
            self.assertEqual(len(convert.calls(old, convert.LEGACY)), 1)
            new = 'LogTraceEvent(BCLog::NET,"peer_trace","peer={peer_id}").Field(BCLog::LogField::PeerId,id)'
            after, _ = convert.convert(old, [rule(old, new)])
            self.assertEqual(after, new)
            self.assertEqual(convert.convert(after, [rule(old, new)])[0], after)

    def test_disable_branch_and_no_evaluation(self):
        old = 'LogDebug(BCLog::NET,"x=%d", expensive())'
        new = 'LogEvent(BCLog::NET,"x","x={value}").Field(BCLog::LogField::Value,expensive())'
        # The tool only edits the call, not surrounding branch/argument order.
        source = "if (enabled) { " + old + "; }"
        after, _ = convert.convert(source, [rule(old, new)])
        self.assertEqual(after, "if (enabled) { " + new + "; }")


if __name__ == "__main__":
    unittest.main()
