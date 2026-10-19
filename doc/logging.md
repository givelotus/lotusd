# Log formats

`-logformat=text` is the default. Format selection applies when the logger
writes a queued record. Set options before starting the logger; tests that
change options or callbacks must first call `LogInstance().Flush()`.

`-logformat=logfmt` writes one record per physical line. Core keys are `time`
(UTC RFC 3339 with microseconds, omitted with `-logtimestamps=0`), `level`,
`category`, `thread` and `message`. String values are double quoted with JSON
escapes; integer and boolean event fields retain their types. Embedded newline
characters cannot create extra records. `-logsourcelocations` adds
`source_file`, `source_line` and `source_function`; functions use bare names.

Structured events add `event` and the typed registry's snake_case keys. A record
that cannot fit all fields says `fields_truncated=true`. `continued` marks a
message fragment, and `ratelimited` marks a record affected by source-site rate
limiting. These are different from queue overflow: debug/info queue drops are
reported explicitly by the logger and the dropped-lines metric.

The quoted-string encoding follows the decoder used by
[go-logfmt](https://github.com/go-logfmt/logfmt), including Unicode escapes and
replacement of malformed UTF-8. The functional check reads the actual file
sink after startup, mining and shutdown; encoder tests cover quotes/newlines.
