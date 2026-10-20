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
printf precision exactly. Bounded integer `%x`/`%0Nx` (width 1..16) is also supported with
`:x`/`:0Nx` placeholders; signed header bitfields must be explicitly cast to
their wire-width unsigned type. Other width/sign/type formatting remains rejected;
this capability does not infer a field type or domain from its label.

The message-only `:fsq` format preserves `fs::quoted` filesystem diagnostics:
double quotes surround the value, and `&` escapes embedded quotes and ampersands
(backslashes are unchanged). Structured JSON keeps the original unquoted string.
The converter accepts this format only when the old `%s` argument is an exact
`fs::quoted(...)` AST call; a plain string may not silently gain quoting. The
consumer accepts copied or static string fields only, not custom adapters.

For reviewed `%c` byte diagnostics, `BCLog::LogChar` copies the unchanged byte
into a STRING field. The converter requires that exact original argument as a
direct Field adapter; raw integers, rewritten bytes, width/length modifiers
and indirect adapters fail closed. This preserves existing ASCII database-key
prefixes rather than defining Unicode code-point formatting.

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
application produces an empty diff. If a consumer commit records a
`git clang-format` command, run it after the conversion to reproduce that
commit's whitespace. AST matching remains insensitive to whitespace; keep
string-literal splitting disabled when the recorded command requires it.

Each consumer commit records its exact command, engine version, input scope,
and explicit support adjustments. Its machine receipt records script/rules
hashes and input/output source hashes. Earlier
manual/reviewed conversions are not retroactively described as reproducible
codemod consumers. Record structured-event lint, relevant native and focused
behavior checks, and any pending combined-source validation gate separately.
The script's textual checks do not replace behavioral validation or justify
claiming a native/runtime pass that has not run.

## Coverage inventory

`inventory.py` scans an immutable committed tree, including tests, benchmarks,
Chronik bridges, wallet member wrappers, continuation aliases, seeder, tools
and vendor C/C++ sources. It records typed events separately from pending
legacy calls; a JSON envelope does not count as a typed conversion. Every
pending site has a stable source identity and explicit deferred reason. Parser
errors remain annotated rather than silently excluded. Timing producer
macros (`LOG_TIME_SECONDS` and the three category/duration variants) are counted
at their application call sites too. Their generic `logging/timer.h` forwarding
calls have explicit infrastructure dispositions; this does not count a timer
producer as converted. Expanding the known alias set can increase the deferred
count without adding source logging or regressing a conversion.

```sh
/path/to/logging-conversion-venv/bin/python contrib/logging/conversion/test_inventory.py
/path/to/logging-conversion-venv/bin/python contrib/logging/conversion/inventory.py --root . --revision HEAD --output /path/to/coverage.json
```

The `chain-tip-progress` rule retains the existing low-level unthrottled Info
contract through `LogInfoEventNoRateLimit`. The converter rejects other
low-level combinations until separately reviewed. This bypass applies only to
the site rate limiter, with the same ring-full/drop policy as existing Info
events; it is not a blocking mode.
