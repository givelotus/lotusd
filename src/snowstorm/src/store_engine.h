// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/setstore.h>
#include "sketch_engine.h"
namespace snowstorm::detail {
struct StoreIdRecord { ItemPowers powers; Sequence admitted; std::size_t bodies; };
struct StoreBodyRecord { TxHash hash; ShortId item; TxHandle body; };
struct StoreLogRecord { StoreChange change; TxHandle body; ItemPowers powers; };
/** Physical buffers remain individually visible for Node's resource attribution.
 * Host-owned immutable TxBody payloads and caller-owned observations are excluded.
 */
struct StoreMemory {
    std::size_t object_bytes{};
    std::size_t ids_capacity{};
    std::size_t bodies_capacity{};
    std::size_t log_capacity{};
    std::size_t pins_capacity{};
    SketchMemory cache;
    std::size_t requested_bytes() const noexcept {
        return object_bytes + ids_capacity * sizeof(StoreIdRecord) + bodies_capacity * sizeof(StoreBodyRecord) +
            log_capacity * sizeof(StoreLogRecord) + pins_capacity * sizeof(SnapshotPin) + cache.requested_bytes();
    }
};
/** One implementation for public SetStore and Node; borrowed views expire on
 * mutation. Explicit pin/cache preparation may allocate; removal/encode do not.
 */
class StoreEngine {
    class Impl;
    std::unique_ptr<Impl> impl_;
public:
    explicit StoreEngine(std::uint64_t maximum);
    ~StoreEngine();
    StoreEngine(StoreEngine &&) noexcept;
    StoreEngine &operator=(StoreEngine &&) noexcept;
    Error admit(ShortId item, TxHandle body);
    Error remove(ShortId item) noexcept;
    Error remove_body(ShortId item, const TxHash &hash) noexcept;
    Error pin(std::uint64_t token, Sequence seq) noexcept;
    void release(std::uint64_t token) noexcept;
    Error pinned(std::uint64_t token, Sequence &seq) const noexcept;
    StoreSnapshot snapshot(Sequence seq) const;
    Error encode_snapshot(Sequence seq, Range range, std::span<Cell> output) const noexcept;
    Error cache_range(Range range) noexcept;
    Sequence sequence() const noexcept;
    std::optional<Sequence> admission_sequence(ShortId item) const noexcept;
    bool contains(ShortId item) const noexcept;
    Error reset(std::span<const ShortId> ids, std::span<const TxHandle> bodies);
    StoreStats stats() const;
    StoreMemory memory() const noexcept;
    std::span<const StoreIdRecord> current_ids() const noexcept;
    std::span<const StoreBodyRecord> current_bodies() const noexcept;
    std::span<const StoreLogRecord> retained_log() const noexcept;
    std::span<const SnapshotPin> retained_pins() const noexcept;
};
} // namespace snowstorm::detail
