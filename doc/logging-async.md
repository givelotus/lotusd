# Asynchronous logging guarantees

Each prepared thread owns a bounded ring of fixed-size 512-byte records.
Cold thread setup allocates the ring. Ordinary publication does not acquire a
logger mutex. The half-full notification uses an atomic flag; the consumer
also wakes periodically, so a notification racing its wait cannot prevent
progress. Startup buffering and long strings passed through legacy formatting
have different allocation costs from the warmed structured producer path.

When a ring is full, debug/info records are discarded and counted. The logger
reports the count and `/metrics` exposes `lotus_log_dropped_lines_total`.
Warnings/errors use backpressure rather than being discarded because of a
full ring. With an active worker, producers wait for the consumer rather than
rendering or acquiring its mutex. This is not a configurable blocking mode.

A callback runs on the consumer and cannot wait for its own ring to drain.
Each ring therefore reserves one extra 512-byte record for a severe reentrant
write. This path preserves the outer callback's rendered string and does not
invoke callbacks recursively. File/console output is written directly; when
neither primary output is active, stderr is the fallback. An auxiliary sink
may also receive that record. Emergency records can overtake queued records;
ordinary queued records retain their per-thread order. The emergency path is
rare and may perform rendering/I/O on a thread already acting as the consumer.

Source-site byte quotas remain separate from ring overflow. They can suppress
file output intentionally and do not increment the ring-drop counter. Error
logging requests a consumer pass that starts after the record was
published and waits for an atomic acknowledgment after its stdio flush. This
also covers other rings registered before the request, not just the error
record itself. Explicit Flush, or a deliberately paused/stopped worker, may
render on the calling thread. Tests changing options or callbacks must Flush
first: those changes apply when records are written, not when queued.

The capacity is 131,072 records per prepared thread: 64 MiB of queue slots,
plus one 512-byte severe overflow record and metadata (704 bytes total beyond
slots on the tested macOS arm64 ABI). A ring reserves this address space;
record object lifetimes begin only when slots are claimed, so unused slot
pages are not initialized. A local allocation control measured a 32 KiB
initial RSS increase for this 131,072-slot raw-storage candidate. Resident memory can grow to the full
ring size under load. Thread-local pointers, allocation bookkeeping and the
registry containers add their own overhead.

The original typed-slot array default-constructed source_location in every
record, touching every page even though its constructor did not clear the
whole payload. The raw byte storage avoids that eager residency; each claimed
slot is placement-constructed before publication and read after acquire.
Records must remain trivially destructible; reference payloads are still
released by the consumer before their slot is reused.

The inherited 1,024-slot ring lost debug/info records during the full functional
suite. With the framework JSON sidecar, a 16,384-slot candidate still lost
44,787 lines in compactblocks. A 65,536-slot candidate still lost 4,482
lines, so the next power of two above that measured burst plus the existing
queue is 131,072. Wake notifications retain the original 512-record
threshold, independently of burst capacity. No user-facing sizing option is
added. This is burst capacity, not a promise to buffer an indefinitely stalled
sink. Sustained artificial floods may still drop; measurements must report
accepted, dropped and actually written counts.
