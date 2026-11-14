// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/sketch.h>
/** @defgroup snowstorm_setstore_contract Snowstorm setstore public contract
 * §§3,5,6.4,10: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §5: body-only events advance seq but make no ID-sketch delta. */
enum class StoreChangeKind : std::uint8_t { id_added, id_removed, body_added, body_removed };
/** §5: immutable change-log observation, no hidden admission bypass. */
struct StoreChange {
    Sequence seq{};
    ShortId item{};
    TxHash tx_hash{};
    StoreChangeKind kind{StoreChangeKind::id_added};
};
/** §5: a pin identity and its exact sequence; expiration never retargets a pin. */
struct SnapshotPin {
    std::uint64_t token{};
    Sequence seq{};
};
/** §5: exact snapshot ID/body view for non-hot-path independent checks. */
struct StoreSnapshot {
    Error error{Error::ok};
    Sequence seq{};
    std::vector<ShortId> ids;
    std::vector<TxHandle> bodies;
};
/** §§5,10: log/pin/capacity observations, no writable internals. */
struct StoreStats {
    Sequence seq{};
    Sequence oldest_retained_seq{};
    std::uint64_t id_count{};
    std::uint64_t body_count{};
    std::uint64_t log_length{};
    std::uint64_t state_bytes{};
    std::uint64_t expired_pins{};
    std::vector<SnapshotPin> pins;
    std::vector<StoreChange> changes;
};
/** §5: bounded ID/body store, explicit IDs at this layer permit bucket testing.
 * SnowstormNode always supplies IDs computed from current tx_hash+tip key.
 */
class SetStore {
public:
    /** §§5,6.4: reserve derived store/log capacities for validated M. */
    explicit SetStore(std::uint64_t max_set_size);
    /** §5: release owned handles, caches and snapshot pins. */
    ~SetStore();
    /** §5: transfer state ownership. */
    SetStore(SetStore &&) noexcept;
    /** §5: transfer state ownership. */
    SetStore &operator=(SetStore &&) noexcept;
    /** §5: mutable snapshot store has one owner. */
    SetStore(const SetStore &) = delete;
    /** §5: mutable snapshot store has one owner. */
    SetStore &operator=(const SetStore &) = delete;
    /** §§3,5: add body under explicit nonzero ID; duplicate tx_hash is a no-op. */
    Error admit(ShortId item, TxHandle body);
    /** §§3,5: remove whole bucket; unknown ID is a no-op. */
    Error remove(ShortId item) noexcept;
    /** §§3,5: partial body removal changes ID only when its last body leaves. */
    Error remove_body(ShortId item, const TxHash &hash) noexcept;
    /** §5: immutable pin at retained S, token nonzero and unique until release. */
    Error pin(std::uint64_t token, Sequence seq) noexcept;
    /** §5: release pin; missing/expired tokens are harmless no-ops. */
    void release(std::uint64_t token) noexcept;
    /** §5: query exact token, never silently repin an expired snapshot. */
    Error pinned(std::uint64_t token, Sequence &seq) const noexcept;
    /** §5: exact retained snapshot reconstruction; may allocate value copies. */
    StoreSnapshot snapshot(Sequence seq) const;
    /** §5: produce pinned symbols by reverting ID log changes, no heap. */
    Error encode_snapshot(Sequence seq, Range range,
                          std::span<Cell> output) const noexcept;
    /** §5: prime current-set indices in reserved cache for snapshot encoding. */
    Error cache_range(Range range) noexcept;
    /** §5: current strictly increasing mutation sequence. */
    Sequence sequence() const noexcept;
    /** §5: original sequence for current ID incarnation. */
    std::optional<Sequence> admission_sequence(ShortId item) const noexcept;
    /** §5: distinct-ID membership, independent of candidate exclusion. */
    bool contains(ShortId item) const noexcept;
    /** §5: clear all logs/pins and atomically install supplied ID/body pairs.
     * IDs are recomputed by Node before this layer; both spans have equal size.
     */
    Error reset(std::span<const ShortId> ids, std::span<const TxHandle> bodies);
    /** §§5,10: immutable diagnostic copy, outside hot-path allocation tests. */
    StoreStats stats() const;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace snowstorm
/** @} */
