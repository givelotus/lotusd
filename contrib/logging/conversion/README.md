# Reviewed structured logging conversions

`convert.py` uses the C++ parser in pinned `ast-grep-py==0.51.0` to find logging
calls and their arguments, including nested template and lambda expressions.
It does not rewrite source with regular expressions. A small format parser uses
regular expressions only on captured literal bodies. It retains the complete
printf specifier in its inventory and rejects unsupported conversions rather
than silently losing width, precision or escaping.

Comby was considered first. It was absent on the macOS arm64 development host;
the official 1.8.1 release provided Linux x86_64 assets only. The available
ast-grep Python wheel correctly parsed the representative nested-template
argument fixture. No claim that Comby could not implement these rules is made.

Reviewed mappings support plain decimal integer length modifiers and explicit
FLOAT `f`/`g` precision 0..18. A floating placeholder must preserve the original
printf precision exactly. Other width/sign/type formatting remains rejected;
this capability does not infer a field type or domain from its label.

The checked-in JSON rules are reviewed semantic mappings, not inferred schemas.
They specify exact input ASTs, expected counts, event expressions, and review
notes. Whitespace may differ in input; argument tokens may not. Missing,
ambiguous, changed or unsupported mappings fail closed. Severity, category and
literal message skeletons are checked independently. Adjacent ordinary C++
string literals are supported. Raw/prefixed/dynamic formats, positional or
star-width arguments, and formatting requiring unsupported renderer behavior
remain legacy. General unsupported input appears in the rejection inventory;
a matched invalid rule aborts without changing any file. C++ macro-related
parse errors outside matched calls do not prevent conversion; parse errors
intersecting a logging call abort.

Fields such as `foo=%f` do not establish a domain name or type. New field
semantics and argument adapters require review, registry checks, compilation
and behavior tests. The tool never moves evaluation outside a logging macro or
changes the surrounding control flow. The typed logging macros' disabled-arg
and allocation contracts are independently covered by native tests and probes.

Non-call changes (field registry entries, includes, functional assertions, and
local formatting) are explicit `support_adjustments` in the rule catalog.
Commit messages must identify them separately from call conversions. The rules
preserve exact source snippets and reject ambiguous support adjustments.

## Reproduce a conversion from its parent

Use a caller-selected virtual environment outside the source tree:

```sh
python3 -m venv /path/to/logging-conversion-venv
/path/to/logging-conversion-venv/bin/python -m pip install -r contrib/logging/conversion/requirements.txt
/path/to/logging-conversion-venv/bin/python contrib/logging/conversion/test_convert.py
/path/to/logging-conversion-venv/bin/python contrib/logging/conversion/convert.py --root . --rules contrib/logging/conversion/rules/rpc-lifecycle.json --report /path/to/rpc-inventory.json
/path/to/logging-conversion-venv/bin/python contrib/logging/conversion/convert.py --root . --rules contrib/logging/conversion/rules/rpc-lifecycle.json --report /path/to/rpc-applied.json --apply
```

The first invocation prints a unified diff without editing. The report records
the engine version, script/rules SHA256, input/output hashes, converted calls,
and rejected calls with reasons. All files are prepared and validated before
any write. Run against a clean parent checkout and inspect the diff. A second
application produces an empty diff. No clang-format invocation or temporary
draft is required to reproduce the checked-in mappings.

Each consumer commit records its exact shell-quoted command, engine version,
script/rules hashes, input scope, and explicit support adjustments. Earlier
manual/reviewed conversions are not retroactively described as reproducible
codemod consumers. Conversion commits still require structured-event lint,
relevant native tests, and their own unchanged-source full functional gate;
the script's textual checks do not replace behavioral validation.
