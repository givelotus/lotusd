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

`-logformat=json-ecs` writes ECS 8.11 fields using dotted JSON keys:
`@timestamp`, `log.level`, `log.logger`, `process.thread.name`, `message`,
`log.origin.file.name/line`, `log.origin.function`, `ecs.version`, and
`event.action`. ECS requires `@timestamp`, so this format retains it even with
`-logtimestamps=0`. Typed fields use their registry's ECS names, with all custom
fields under `lotus.*`. `DurationUs` becomes integer nanoseconds in
`event.duration`; generic JSON/logfmt retain microseconds. A peer endpoint stays
`lotus.addr`: it is not necessarily the sender described by `source.address`.
See [ECS log fields](https://www.elastic.co/guide/en/ecs/8.11/ecs-log.html),
[event fields](https://www.elastic.co/guide/en/ecs/8.11/ecs-event.html), and
[source roles](https://www.elastic.co/guide/en/ecs/8.11/ecs-source.html).
An actual Elasticsearch/collector deployment is not claimed by local tests.

`-logformat=journald` is Linux-only and writes the native journal protocol to
`/run/systemd/journal/socket`, without linking libsystemd. Selecting it enables
that sink even with `-nodebuglogfile`; it does not open the main debug file.
`-printtoconsole` and callbacks still receive readable text. An optional
`-debuglogjsonfile` continues to receive generic JSON. Startup fails explicitly
if the journal socket is unavailable. Later send failures fall back to stderr
and increment `lotus_log_journal_failures_total`; they are not counted as
successful journal writes. A successful socket send is collector acceptance,
not a durable-storage acknowledgment.

`MESSAGE`, `PRIORITY` and optional `CODE_FILE`, `CODE_LINE`, `CODE_FUNC` follow
the journal field conventions. Debug/trace map to priority 7, info to 6,
warning to 4 and error to 3. Custom metadata and typed values use `LOTUS_*`
uppercase names; the daemon never submits trusted `_` fields. Multiline/NUL
values use the length-prefixed binary representation. Oversize entries use
one sealed memfd via SCM_RIGHTS. Journal transport failures cannot indefinitely
block the logger: socket sends have a 100ms timeout and stderr fallback.
Source: [native journal protocol](https://systemd.io/JOURNAL_NATIVE_PROTOCOL/).

`-logformat=syslog` writes RFC 5424 records to the usual file/console sinks;
it does not open a remote network connection. It uses daemon facility 3 and
the same severity mapping as journald. The header version is 1, with an
RFC 3339 timestamp (or NILVALUE when timestamps are disabled). Unknown host,
application, process, message-id and structured-data are represented by the
specified NILVALUE, rather than made-up identity or enterprise identifiers.
The UTF-8 MSG starts with a BOM and contains a generic JSON event, preserving
all core and typed fields with JSON escaping. One physical line is one record.
Source: [RFC 5424 sections 6 and 6.4](https://datatracker.ietf.org/doc/html/rfc5424).
