// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

/** @defgroup snowstorm_types_contract Snowstorm types public contract
 * §§1–8: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §1: canonical byte, identifier and monotonic-microsecond value types. */
using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using ByteSpan = std::span<const Byte>;
using MutableByteSpan = std::span<Byte>;
using ShortId = std::uint64_t;
using PeerId = std::uint64_t;
using Sequence = std::uint64_t;
using SymbolIndex = std::uint64_t;
using SessionId = std::uint64_t;
using RequestId = std::uint64_t;
using PollId = std::uint64_t;
using FetchId = std::uint64_t;
using WaveId = std::uint64_t;
using Time = std::int64_t;
using TxId = std::array<Byte, 32>;
using TxHash = std::array<Byte, 32>;
using Root = std::array<Byte, 32>;
using TipContext = std::array<Byte, 32>;

/** §§1–8: assertion-free local/structural operation outcomes; ok is success. */
enum class Error {
    ok,
    invalid_argument,
    zero_inverse,
    overflow,
    capacity,
    invalid_range,
    invalid_id,
    not_found,
    duplicate,
    snapshot_expired,
    inconsistent_symbols,
    malformed_message,
    unsupported_version,
    wrong_context,
    nonmonotonic_time,
    host_contract_error,
    rejected_id,
    exhausted,
};

/** §1: host removal reasons; none changes the ID/body removal semantics. */
enum class RemovalReason : std::uint8_t {
    expiry, trim, conflict, reorg, batch_loser, variant, replaced, other,
};

/** §1: immutable body interface; getters return canonical bytes by value. */
class TxBody {
public:
    /** §1: release the opaque shared body without invoking core state. */
    virtual ~TxBody();
    /** §§1,3: canonical 32-byte transaction identifier. */
    virtual TxId txid() const noexcept = 0;
    /** §§1,3: canonical 32-byte raw transaction hash. */
    virtual TxHash tx_hash() const noexcept = 0;
    /** §§1,3: cached hint only; the core always rekeys from tx_hash. */
    virtual ShortId short_id() const noexcept = 0;
};
/** §1: shared immutable opaque ownership; payload bytes remain host-owned. */
using TxHandle = std::shared_ptr<const TxBody>;

/** §3: SipHash key supplied by the current tip. */
struct ShortIdKey {
    std::uint64_t k0{};
    std::uint64_t k1{};
};

/** §4.1: signed difference contribution, never a zero short ID. */
enum class Sign : std::int8_t { negative = -1, positive = 1 };
/** §4.1: one atomic signed item. */
struct SignedItem {
    ShortId item{};
    Sign sign{Sign::positive};
};
/** §§4.1,4.4: allocation-free reference membership callback, no hidden truth. */
struct ReferenceView {
    const void *context{};
    bool (*contains)(const void *, ShortId) noexcept{};
};
/** §§4.3,6.1: half-open symbol range [begin,end). */
struct Range {
    SymbolIndex begin{};
    SymbolIndex end{};
};

/** §1: complete finite body-result status domain. */
enum class BodyStatus : std::uint8_t {
    admitted, not_found, invalid, local_rejected,
};
/** §§1,6.3: host verified requested-ID binding, or unrelated/unparseable bytes. */
enum class BodyBinding : std::uint8_t { matched, unbound };
/** §§1,6.3: matched admitted/invalid/local_rejected require expected_tx_hash. */
struct BodyResult {
    FetchId fetch_id{};
    BodyStatus status{BodyStatus::not_found};
    BodyBinding binding{BodyBinding::unbound};
    std::optional<TxHash> expected_tx_hash;
};

/** §§6.1,6.3,6.4: explicit peer-attributable diagnostic categories. */
enum class Misbehavior : std::uint8_t {
    malformed_message,
    count_overflow,
    inconsistent_symbols,
    unexpected_ranges,
    snapshot_changed,
    invalid_body,
    body_not_found,
    wrong_body_binding,
    resource_limit,
};

/** §6.4: separately measured resource classes, including global storage. */
enum class Limit : std::uint8_t {
    admitted_ids,
    admitted_bodies,
    peers,
    ranges,
    message_cells,
    message_bytes,
    exclusions,
    change_log,
    symbol_index,
    pending,
    fetch_records,
    pending_fetch_union,
    probation,
    rejected,
    local_rejected,
    unavailable,
    donors_per_id,
    donor_records,
    plus,
    minus,
    snapshot_bodies,
    candidate_bodies,
    session_symbols,
    pass_claims,
    worklist,
    decode_audit,
    other_audit,
    actions,
    count,
};

/** §6.4: read-only derived/operational limits; no configurable pooling knob. */
struct Limits {
    std::uint64_t max_set_size{};
    std::uint64_t max_peers{};
    std::uint64_t max_ranges{};
    std::uint64_t max_cells{};
    std::uint64_t max_message_bytes{};
    std::uint64_t max_exclusions{};
    std::uint64_t max_change_log{};
    SymbolIndex max_symbol_index{};
    std::uint64_t max_pending{};
    std::uint64_t max_fetch_records{};
    std::uint64_t max_pending_fetch_union{};
    std::uint64_t max_probation{};
    std::uint64_t max_rejected{};
    std::uint64_t max_local_rejected{};
    std::uint64_t max_unavailable{};
    std::uint64_t max_donors_per_id{};
    std::uint64_t max_donor_records{};
    std::uint64_t max_plus{};
    std::uint64_t max_minus{};
    std::uint64_t reference_bound{};
    std::uint64_t peer_floor_bytes{};
    std::uint64_t node_floor_bytes{};
};
/** §6.4: derive limits; invalid M/D returns invalid_argument without mutation. */
Error derive_limits(std::uint64_t max_set_size, std::uint64_t peers,
                    Limits &out) noexcept;
/** §6.4: overflow-checked 3*(snapshot_size+declared_bound)+32. */
Error session_symbol_limit(std::uint64_t snapshot_size,
                          std::uint64_t declared_bound,
                          std::uint64_t &out) noexcept;
} // namespace snowstorm
/** @} */
