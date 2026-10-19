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

`-logformat=json` writes one JSON object per physical line with `time`, `level`,
`category`, `thread` and `message`. `-logsourcelocations` adds a `source` object
with `file`, numeric `line`, and bare `function`. The timestamp and source
flags have the same meaning as for logfmt; thread, category and level are
always present. Event names and values are escaped as JSON strings, including
when an event descriptor was constructed outside the normal naming convention.
Numeric/boolean fields remain JSON numbers/booleans. The human message stays
available for consumers that do not interpret typed fields.

`-logformat=json-gcp` uses `time`, uppercase `severity`, `message`, and
`logging.googleapis.com/sourceLocation` (`file`, int64-string `line`, bare
`function`). Trace maps to DEBUG because Cloud Logging has no TRACE severity.
Category, thread and typed event fields stay in the JSON payload. Sources:
[agent structured logging](https://cloud.google.com/logging/docs/structured-logging)
and [LogEntrySourceLocation](https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogEntrySourceLocation).
Cloud behavior is checked against the specification; no cloud ingestion or
account deployment is part of the local tests.
