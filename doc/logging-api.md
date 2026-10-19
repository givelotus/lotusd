# Typed structured log events

Use a stable snake_case event name and registry keys instead of formatting a
message on the calling thread:

```cpp
#include <logging/values.h>

LogEvent(BCLog::NET, "peer_received", "Received {bytes} bytes from peer={peer_id}")
    .Field(BCLog::LogField::PeerId, id)
    .Field(BCLog::LogField::Bytes, bytes)
    .Field(BCLog::LogField::Addr, service);
```

The logger captures time, level, category, thread and the actual caller's source
location. The descriptor is constexpr; it does not capture the descriptor
lambda as the caller. `LogInfoEvent`, `LogWarningEvent` and `LogErrorEvent`
provide other levels. A disabled event evaluates neither its builder nor field
arguments. Field ids are compile-time constants: free-form string keys, runtime
ids, out-of-range ids and a registry id paired with the wrong field type do not
compile. Registry names are resolved by the consumer, not copied into records.

After thread preparation, ordinary typed records use the fixed-size ring and
copy bounded values without allocating a message string or acquiring a logger
mutex. Numeric values, hashes and durations are stored in binary; `LogStatic`
accepts a string literal by pointer. Other strings are copied into the record.
Address adapters copy network bytes and format the address on the consumer.
Immutable shared objects retain one reference until the consumer renders and
releases them. A string or field that does not fit is marked truncated, including a final
string with no following field to exhaust the slot; large
blobs should be represented by their size or hash. Cold startup and severe
backpressure are separate paths; see [async guarantees](logging-async.md).
Legacy printf calls still format on the caller until converted.

Variable-size adapters may provide `LogValue<T>::Size(value)` bounded by
`MAX_SIZE`; the builder reserves only that value's actual bytes. Address
adapters retain the full raw WSS host/path payload instead of silently
shortening it to an unrelated endpoint. If the complete value exceeds the
record, it is omitted and `fields_truncated` is set; record size is unchanged.

A template refers to provided fields by generic name, such as `{peer_id}`.
Fields not used in the template remain available to structured encoders and
are appended in text output. Message wording should remain stable during
conversion. Do not call `ToString`, `HexStr` or `strprintf` merely to construct
an argument when a typed adapter can defer that work to the consumer.

FLOAT fields accept `{elapsed_ms:f}` or `{elapsed_ms:g}` (default precision
six), and explicit precision such as `{elapsed_ms:.2f}` or `{elapsed_ms:.3g}`.
Precision is bounded to 0..18; widths, sign flags and dynamic precision are
unsupported. Formatting uses the original printf backend on the consumer.
Structured JSON keeps the original finite number, independently of rounded
message text; NaN and infinities use JSON `null`.

Scope conventions are enforced by `check-log-events`: `peer_*` carries PeerId,
`rpc_call_*` carries Method, `mempool_tx_*` carries TxId, and `block_connect_*`
carries BlockHash. Global listener/server events use names that do not imply
an individual peer or method. The lint also rejects duplicate keys, unknown
registry keys and missing template values. Native maintainer `check`/`check-all` include
source lint and compiler contract tests when test/lint is present. Deliberately malformed test fixtures
are excluded from production source lint. The full source conversion is a
separate gate; adding the API/lint does not mean old calls have been converted.

The registry records standard names only when the field has the required
meaning. ECS names are checked against 8.11 and OTel against semantic
conventions 1.44. Custom fields retain their generic name (with `lotus.` in
ECS) instead of claiming an unrelated standard meaning:

- Addr is an opaque endpoint, potentially host:port. PeerAddress and PeerPort
  separate the IP/socket address and port for OTel network.peer.address and
  network.peer.port. An arbitrary peer is not necessarily the network sender,
  so these fields do not claim ECS source.address or source.port.
- UserAgent is a P2P subversion string and stays custom. HttpUserAgent denotes
  an actual HTTP User-Agent header and maps to user_agent.original.
- Error maps to ECS error.message. It stays custom in OTel, where the generic
  error.message attribute is deprecated.
- Method denotes a recognized RPC method or `_OTHER`; OriginalMethod preserves
  the raw client method name, including unknown methods.
- Path denotes a full filesystem path, including the filename where relevant,
  rather than a URI or an unresolved relative path. It maps to file.path.
- Direction is the logical connection direction (inbound/outbound), not an
  interface's transmit/receive direction. DurationUs is a duration stored in
  nanoseconds; generic rendering uses microseconds and ECS event.duration
  uses nanoseconds.

Sources: [ECS source roles](https://www.elastic.co/guide/en/ecs/8.11/ecs-source.html),
[ECS event fields](https://www.elastic.co/guide/en/ecs/8.11/ecs-event.html),
[OTel network attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/),
[OTel HTTP user agent](https://opentelemetry.io/docs/specs/semconv/registry/attributes/user-agent/),
[OTel RPC names](https://opentelemetry.io/docs/specs/semconv/registry/attributes/rpc/),
[OTel file paths](https://opentelemetry.io/docs/specs/semconv/registry/attributes/file/),
and [OTel error attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/error/).
Development/RC names in that registry are not a promise of stable ingestion
behavior. No external OTel or cloud deployment is claimed by these local tests.
