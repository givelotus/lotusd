// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "peeler_engine.h"
#include "cell_decode.h"
#include "cell_count.h"
#include <snowstorm/gf64.h>
#include <snowstorm/schedule.h>
#include <algorithm>
#include <cassert>
#include <limits>
#include <stdexcept>

namespace snowstorm::detail {
namespace {
constexpr unsigned INDEX_BITS = 40;
constexpr auto INDEX_BOUND = std::uint64_t{1} << INDEX_BITS;
bool same(const Cell &a, const Cell &b) noexcept {
    return a.count == b.count && a.s1 == b.s1 && a.s3 == b.s3 && a.s5 == b.s5;
}
auto ref_lower(auto &reference, ShortId item) noexcept {
    return std::lower_bound(reference.begin(), reference.end(), item,
        [](const ItemPowers &powers, ShortId id) { return powers.item < id; });
}
bool fits(PeelerCapacity storage, PeelerCapacity limits) noexcept {
    return storage.max_reference_items <= limits.max_reference_items &&
           storage.max_symbols <= limits.max_symbols && storage.max_claims <= limits.max_claims;
}
}
PeelerEngine::PeelerEngine(PeelerCapacity limits, PeelerCapacity storage) : limits_(limits) {
    if (limits.max_reference_items > CELL_MAX_COUNT || limits.max_symbol_index >= INDEX_BOUND ||
        limits.max_symbols > limits.max_symbol_index + 1 || !fits(storage, limits)) {
        throw std::invalid_argument("invalid Snowstorm peeler capacities");
    }
    reserve_storage(storage);
}
void PeelerEngine::reserve_storage(PeelerCapacity storage) {
    if (!fits(storage, limits_) || !fits(storage_, storage)) throw std::invalid_argument("invalid peeler reserve growth");
    reference_.reserve(storage.max_reference_items); claims_.reserve(storage.max_claims);
    const auto n = storage.max_symbols;
    indices_.reserve(n); versions_.reserve(n); work_.reserve(n);
    snapshot_.reserve(n); pairs_.reserve(n); staged_.reserve(n); changes_.reserve(n);
    raw_.reserve(n, indices_.size()); residual_.reserve(n, indices_.size());
    queued_.resize(n); cubes_.resize(n); inverses_.resize(n); inverse_scratch_.resize(n);
    storage_ = storage;
}
std::size_t PeelerEngine::lower(SymbolIndex index) const noexcept {
    return std::lower_bound(indices_.begin(), indices_.end(), index) - indices_.begin();
}
bool PeelerEngine::contains(ShortId item) const noexcept {
    const auto it = ref_lower(reference_, item);
    return it != reference_.end() && it->item == item;
}
ReferenceView PeelerEngine::reference_view() const noexcept {
    return {this, [](const void *context, ShortId item) noexcept {
        return static_cast<const PeelerEngine *>(context)->contains(item);
    }};
}
void PeelerEngine::mark(std::size_t pos) noexcept {
    if (!queued_[pos]) { queued_[pos] = 1; work_.push_back(pos); }
}
void PeelerEngine::mark_all() noexcept {
    work_.clear();
    std::fill(queued_.begin(), queued_.end(), 0);
    for (std::size_t pos = 0; pos < indices_.size(); ++pos) mark(pos);
}
Error PeelerEngine::reset(std::span<const ShortId> reference) noexcept {
    if (reference.size() > storage_.max_reference_items) return Error::capacity;
    ShortId previous{};
    for (const auto id : reference) {
        if (id == 0) return Error::invalid_id;
        if (id <= previous) return Error::invalid_argument;
        previous = id;
    }
    reference_.clear();
    for (const auto id : reference) reference_.push_back(item_powers(id));
    claims_.clear(); indices_.clear(); versions_.clear(); work_.clear(); snapshot_.clear();
    pairs_.clear(); staged_.clear(); changes_.clear();
    std::fill(queued_.begin(), queued_.end(), 0);
    steps_ = 0; pass_ = 1;
    return Error::ok;
}
Error PeelerEngine::stage_append(std::span<const IndexedCell> input) noexcept {
    staged_.clear();
    for (const auto &entry : input) {
        if (entry.index > limits_.max_symbol_index) return Error::invalid_range;
        if (!valid_cell_count(entry.cell.count)) return Error::overflow;
        const auto pos = lower(entry.index);
        if (pos < indices_.size() && indices_[pos] == entry.index) {
            if (!same(entry.cell, residual_.get(pos))) return Error::inconsistent_symbols;
            continue;
        }
        const auto staged = std::lower_bound(staged_.begin(), staged_.end(), entry.index,
            [](const Staged &cell, SymbolIndex index) { return cell.index < index; });
        if (staged != staged_.end() && staged->index == entry.index) {
            if (!same(staged->residual, entry.cell)) return Error::inconsistent_symbols;
            continue;
        }
        if (indices_.size() + staged_.size() == storage_.max_symbols) return Error::capacity;
        staged_.insert(staged, {entry.index, entry.cell, entry.cell});
    }
    return reconstruct_raw();
}
Error PeelerEngine::reconstruct_raw() noexcept {
    if (staged_.empty()) return Error::ok;
    const auto by_index = [](const Staged &cell, SymbolIndex value) { return cell.index < value; };
    for (const auto &powers : reference_) {
        ScheduleIterator iterator(powers.item, staged_.back().index);
        while (const auto index = iterator.next()) {
            const auto pos = std::lower_bound(staged_.begin(), staged_.end(), *index, by_index);
            if (pos == staged_.end() || pos->index != *index) continue;
            const auto error = cell_add(pos->raw, powers, Sign::positive);
            if (error != Error::ok) return error;
        }
    }
    return Error::ok;
}
Error PeelerEngine::append(std::span<const IndexedCell> input) noexcept {
    const auto error = stage_append(input);
    if (error != Error::ok || staged_.empty()) return error;
    for (const auto &entry : staged_) {
        const auto pos = lower(entry.index);
        for (auto dest = indices_.size(); dest > pos; --dest) {
            raw_.put(dest, raw_.get(dest - 1)); residual_.put(dest, residual_.get(dest - 1));
        }
        indices_.insert(indices_.begin() + pos, entry.index);
        versions_.insert(versions_.begin() + pos, 0);
        raw_.put(pos, entry.raw); residual_.put(pos, entry.residual);
    }
    mark_all();
    return Error::ok;
}
Error PeelerEngine::stage_item(const SignedItem &item) noexcept {
    if (indices_.empty()) return Error::ok;
    const auto powers = item_powers(item.item);
    ScheduleIterator iterator(item.item, indices_.back());
    while (const auto index = iterator.next()) {
        const auto pos = lower(*index);
        if (pos == indices_.size() || indices_[pos] != *index) continue;
        if (versions_[pos] == std::numeric_limits<std::uint64_t>::max()) return Error::overflow;
        auto change = std::lower_bound(changes_.begin(), changes_.end(), pos,
            [](const Change &entry, std::size_t value) { return entry.pos < value; });
        if (change == changes_.end() || change->pos != pos) {
            const auto cell = residual_.get(pos);
            change = changes_.insert(change, {pos, cell, cell.count});
        }
        change->count -= static_cast<int>(item.sign);
        change->cell.s1 ^= powers.item; change->cell.s3 ^= powers.cube; change->cell.s5 ^= powers.fifth;
    }
    return Error::ok;
}
Error PeelerEngine::stage_delta(const DecodeResult &decoded) noexcept {
    auto size = static_cast<std::int64_t>(reference_.size());
    changes_.clear();
    for (std::size_t i = 0; i < decoded.size; ++i) {
        size += static_cast<int>(decoded.items[i].sign);
        const auto error = stage_item(decoded.items[i]);
        if (error != Error::ok) return error;
    }
    if (size < 0 || static_cast<std::uint64_t>(size) > storage_.max_reference_items) return Error::capacity;
    for (auto &change : changes_) {
        if (!valid_cell_count(change.count)) return Error::overflow;
        change.cell.count = static_cast<std::int32_t>(change.count);
    }
    return Error::ok;
}
void PeelerEngine::apply_delta(const DecodeResult &decoded) noexcept {
    // Remove before insert so a full reference can atomically exchange two IDs.
    for (std::size_t i = 0; i < decoded.size; ++i) {
        const auto &item = decoded.items[i];
        if (item.sign == Sign::negative) reference_.erase(ref_lower(reference_, item.item));
    }
    for (std::size_t i = 0; i < decoded.size; ++i) {
        const auto &item = decoded.items[i];
        if (item.sign == Sign::positive) reference_.insert(ref_lower(reference_, item.item), item_powers(item.item));
        assert(contains(item.item) == (item.sign == Sign::positive));
    }
    for (const auto &change : changes_) {
        residual_.put(change.pos, change.cell); ++versions_[change.pos]; mark(change.pos);
    }
}
Error PeelerEngine::reference_change(ShortId item, Sign sign) noexcept {
    if (item == 0) return Error::invalid_id;
    if (sign != Sign::positive && sign != Sign::negative) return Error::invalid_argument;
    if (contains(item) == (sign == Sign::positive)) return sign == Sign::positive ? Error::duplicate : Error::not_found;
    if (pass_ == std::numeric_limits<std::uint64_t>::max()) return Error::overflow;
    const DecodeResult decoded{DecodeKind::one, {{{item, sign}, {}}}, 1};
    const auto error = stage_delta(decoded);
    if (error != Error::ok) return error;
    apply_delta(decoded); claims_.clear(); ++pass_; mark_all();
    return Error::ok;
}
Error PeelerEngine::commit(std::size_t pos, const DecodeResult &decoded, DecodePolicy policy,
                          std::span<SignedItem> output, std::span<DecodeAudit> audit,
                          PeelResult &result) noexcept {
    for (std::size_t i = 0; i < decoded.size; ++i) {
        if (std::binary_search(claims_.begin(), claims_.end(), decoded.items[i].item)) return Error::inconsistent_symbols;
    }
    if (decoded.size > storage_.max_claims - claims_.size()) return Error::capacity;
    const auto error = stage_delta(decoded);
    if (error != Error::ok) return error;
    if (policy.accept) {
        const auto decision = policy.accept(policy.context, decoded);
        if (decision != Error::ok) return decision;
    }
    DecodeAudit proof{indices_[pos], residual_.get(pos), decoded, {}, pass_};
    for (std::size_t i = 0; i < decoded.size; ++i) proof.in_reference_before[i] = contains(decoded.items[i].item);
    apply_delta(decoded);
    for (std::size_t i = 0; i < decoded.size; ++i) {
        const auto &item = decoded.items[i];
        claims_.insert(std::lower_bound(claims_.begin(), claims_.end(), item.item), item.item);
        output[result.item_count++] = item;
    }
    audit[result.audit_count++] = proof;
    return Error::ok;
}
bool PeelerEngine::current(const Candidate &candidate) const noexcept {
    return versions_[candidate.pos] == candidate.version && same(residual_.get(candidate.pos), candidate.cell);
}
Error PeelerEngine::singles(DecodePolicy policy, std::span<SignedItem> output,
                           std::span<DecodeAudit> audit, PeelResult &result) noexcept {
    for (const auto &candidate : snapshot_) {
        if (!current(candidate)) continue;
        if (candidate.cell.count != -1 && candidate.cell.count != 1) continue;
        ++steps_;
        const auto decoded = decode_singleton(candidate.cell, indices_[candidate.pos], reference_view());
        if (decoded.kind != DecodeKind::one) continue;
        const auto error = commit(candidate.pos, decoded, policy, output, audit, result);
        if (error != Error::ok) return error;
    }
    return Error::ok;
}
Error PeelerEngine::pairs(DecodePolicy policy, std::span<SignedItem> output,
                         std::span<DecodeAudit> audit, PeelResult &result) noexcept {
    pairs_.clear();
    for (const auto &candidate : snapshot_) {
        if (!current(candidate) || candidate.cell.s1 == 0) continue;
        const auto count = candidate.cell.count;
        if (count != -2 && count != 0 && count != 2) continue;
        cubes_[pairs_.size()] = item_powers(candidate.cell.s1).cube;
        pairs_.push_back(candidate);
    }
    const auto n = pairs_.size();
    const auto inverse_error = gf64::batch_inv(std::span(cubes_).first(n),
        std::span(inverses_).first(n), std::span(inverse_scratch_).first(n));
    if (inverse_error != Error::ok) return inverse_error;
    for (std::size_t i = 0; i < n; ++i) {
        const auto &candidate = pairs_[i];
        if (!current(candidate)) continue;
        // Both source/version and the actual inverse binding are checked before solve.
        if (gf64::mul(item_powers(residual_.get(candidate.pos).s1).cube, inverses_[i]) != 1) return Error::inconsistent_symbols;
        ++steps_;
        const auto decoded = decode_pair(candidate.cell, indices_[candidate.pos], reference_view(), inverses_[i]);
        if (decoded.kind != DecodeKind::two) continue;
        const auto error = commit(candidate.pos, decoded, policy, output, audit, result);
        if (error != Error::ok) return error;
    }
    return Error::ok;
}
PeelResult PeelerEngine::run(std::span<SignedItem> output, std::span<DecodeAudit> audit, DecodePolicy policy) noexcept {
    PeelResult result{};
    if (output.size() < storage_.max_claims || audit.size() < storage_.max_claims) {
        result.error = Error::capacity; result.decode_steps = steps_; return result;
    }
    while (!work_.empty()) {
        snapshot_.clear();
        for (const auto pos : work_) {
            snapshot_.push_back({pos, versions_[pos], residual_.get(pos)}); queued_[pos] = 0;
        }
        work_.clear();
        result.error = singles(policy, output, audit, result);
        if (result.error == Error::ok) result.error = pairs(policy, output, audit, result);
        if (result.error != Error::ok) { mark_all(); break; }
    }
    for (std::size_t pos = 0; pos < indices_.size(); ++pos) result.stuck += !cell_is_zero(residual_.get(pos));
    result.done = result.error == Error::ok && result.stuck == 0;
    result.decode_steps = steps_;
    return result;
}
Error PeelerEngine::observations(std::span<ResidualObservation> output, std::size_t &written) const noexcept {
    if (output.size() < indices_.size()) return Error::capacity;
    for (std::size_t pos = 0; pos < indices_.size(); ++pos) output[pos] = {indices_[pos], raw_.get(pos), residual_.get(pos)};
    written = indices_.size();
    return Error::ok;
}
std::size_t PeelerEngine::allocated_bytes() const noexcept {
    return reference_.capacity() * sizeof(ItemPowers) + claims_.capacity() * sizeof(ShortId) +
        indices_.capacity() * sizeof(SymbolIndex) + raw_.allocated_bytes() + residual_.allocated_bytes() +
        versions_.capacity() * sizeof(std::uint64_t) + queued_.capacity() * sizeof(std::uint8_t) +
        work_.capacity() * sizeof(std::size_t) + (snapshot_.capacity() + pairs_.capacity()) * sizeof(Candidate) +
        staged_.capacity() * sizeof(Staged) + changes_.capacity() * sizeof(Change) +
        (cubes_.capacity() + inverses_.capacity() + inverse_scratch_.capacity()) * sizeof(std::uint64_t);
}
} // namespace snowstorm::detail
