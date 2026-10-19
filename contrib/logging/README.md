# Collecting daemon logs

These examples preserve structured fields and use only severity (`level`),
category and a static job name as Loki labels. Keep peer IDs, transaction IDs,
block hashes, addresses and byte offsets in the record body, not in labels.

| Collector | Daemon format | Example |
| --- | --- | --- |
| Grafana Alloy, file | `-logformat=json` | `alloy-file.alloy` |
| Grafana Alloy, Linux journal | `-logformat=journald` | `alloy-journal.alloy` |
| Promtail | `-logformat=json` | `promtail.yaml` |
| Vector | `-logformat=json` | `vector.toml` |
| Fluent Bit | `-logformat=json` | `fluent-bit.conf` and `fluent-bit-parsers.conf` |
| rsyslog | `-logformat=json` | `rsyslog.conf` |
| Google Cloud Logging structured JSON | `-logformat=json-gcp` | Schema checked; no cloud ingestion test |
| An ECS-aware JSON pipeline | `-logformat=json-ecs` | ECS 8.11 schema; examples above use generic JSON |

For the file examples, configure the daemon with:

```text
-logformat=json -logtimestamps=1 -logsourcelocations=1
-debuglogfile=/var/log/lotus/debug.jsonl
```

Create `/var/log/lotus` with permissions that let the daemon write and the
collector read. Use a durable, writable state directory for each collector:
`/var/lib/alloy`, `/var/lib/promtail`, `/var/lib/fluent-bit`,
`/var/lib/rsyslog` or Vector's configured data directory. Position files and
tail databases let readers resume rather than replay the file after restart.
The Fluent Bit parser file is expected under `/etc/lotus-logging/`.

The Alloy and Promtail examples send to a Loki server at
`http://127.0.0.1:3100`; set the endpoint and its authentication for your
installation. They retain the complete JSON line, so fields remain queryable
without turning identifiers into labels. Start the applicable configuration:

```sh
alloy run --storage.path=/var/lib/alloy alloy-file.alloy
promtail -config.file=promtail.yaml
vector --config vector.toml
fluent-bit -c /etc/lotus-logging/fluent-bit.conf
rsyslogd -N1 -f rsyslog.conf
```

Vector and Fluent Bit write parsed JSON to stdout; replace or extend their
output with your backend. rsyslog writes one parsed record per line to
`/var/log/lotus/collected.jsonl`, including imfile's input metadata. Its file
is a minimal standalone configuration; merge the input/ruleset into an
existing service configuration without loading the same module twice.

For Alloy's journal example, use `-logformat=journald` on Linux and grant the
reader access to the system journal. It selects `SYSLOG_IDENTIFIER=lotusd`,
keeps all native fields as JSON, and labels only `LOTUS_LEVEL` and
`LOTUS_CATEGORY`. `MESSAGE` remains the human-readable message; native
`LOTUS_*` and `CODE_*` fields remain available separately. Console text can
instead use the optional `-logtextpriority` prefix with a systemd stdout
stream; that is separate from the native journal example.

## Validation

The following real tools ran in isolated Linux arm64 containers. File tests
used ten actual daemon records, including source metadata and the final
numeric `dropped_lines` field. Every original field and type was compared;
collector-added timestamps or input metadata were allowed where applicable.

| Tool | Version | Verified path |
| --- | --- | --- |
| Alloy | 1.8.3 | File → parser/labels → Loki 3.4.2 query, 10 records |
| Alloy | 1.8.3 | JournalSink → systemd journal → parser/labels → Loki, 3 records |
| Promtail | 3.4.2 | File → parser/labels → Loki 3.4.2 query, 10 records |
| Vector | 0.45.0 | File → JSON parser → console, 10 records |
| Fluent Bit | 4.0.0 | Tail → JSON parser → console, 10 records |
| rsyslog | 8.2504.0 | imfile → mmjsonparse → JSONL omfile, 10 records |

The journal check preserves multiline messages, embedded NUL and native
fields, and verifies that peer IDs are not labels. This is component/collector
coverage, not a full Linux daemon run. Google Cloud Logging field names and
types were checked against its schema; no cloud service was contacted.

Reference documentation: [Alloy file source](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/),
[Alloy journal source](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.journal/),
[Alloy processing stages](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.process/),
[Vector configuration](https://vector.dev/docs/reference/configuration/),
[Fluent Bit JSON parser](https://docs.fluentbit.io/manual/data-pipeline/parsers/json),
[rsyslog JSON parsing](https://docs.rsyslog.com/doc/configuration/modules/mmjsonparse.html),
[Cloud Logging structured fields](https://cloud.google.com/logging/docs/structured-logging).
