// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "session_model.h"
#include "scheduled_cells.h"
#include "message_size.h"
#include <snowstorm/schedule.h>
#include <algorithm>
#include <cassert>
namespace snowstorm::detail {
namespace {
bool has(std::span<const ShortId> ids, ShortId id) noexcept {
    return std::binary_search(ids.begin(), ids.end(), id);
}
void insert_id(std::vector<ShortId> &ids, ShortId id) noexcept {
    auto it = std::lower_bound(ids.begin(), ids.end(), id);
    if (it == ids.end() || *it != id) ids.insert(it, id);
}
void erase_id(std::vector<ShortId> &ids, ShortId id) noexcept {
    auto it = std::lower_bound(ids.begin(), ids.end(), id);
    if (it != ids.end() && *it == id) ids.erase(it);
}
} // namespace
Error SessionModel::open(std::span<const ShortId> pending) {
    if (pending.size() > limits_.max_plus) return Error::capacity;
    ShortId previous = 0;
    for (auto id : pending) {
        if (id <= previous) return Error::invalid_id;
        previous = id;
    }
    std::vector<ShortId> plus(pending.begin(), pending.end());
    clear();
    plus_.swap(plus);
    active_ = true;
    return Error::ok;
}
Error SessionModel::create_engine() {
    std::vector<ShortId> reference;
    reference.reserve(own_.current_ids().size() + plus_.size());
    for (const auto &id : own_.current_ids()) reference.push_back(id.powers.item);
    reference.insert(reference.end(), plus_.begin(), plus_.end());
    std::sort(reference.begin(), reference.end());
    reference.erase(std::unique(reference.begin(), reference.end()), reference.end());
    std::erase_if(reference, [this](ShortId id) { return has(minus_, id); });
    std::uint64_t budget = 0;
    const auto error = session_symbol_limit(limits_.max_set_size, limits_.reference_bound, budget);
    if (error != Error::ok) return error;
    PeelerCapacity logical{limits_.reference_bound,
        std::min(budget, limits_.max_symbol_index + 1),
        limits_.max_set_size + limits_.reference_bound, limits_.max_symbol_index};
    PeelerCapacity storage{reference.size(), 1, 0, limits_.max_symbol_index};
    auto engine = std::make_unique<PeelerEngine>(logical, storage);
    const auto reset = engine->reset(reference);
    if (reset != Error::ok) return reset;
    engine_.swap(engine);
    return Error::ok;
}
Error SessionModel::prepare_membership(std::size_t plus, std::size_t minus) {
    if (!active_) return Error::not_found;
    if (plus > limits_.max_plus || minus > limits_.max_minus) return Error::capacity;
    plus_.reserve(plus); minus_.reserve(minus);
    return Error::ok;
}
Error SessionModel::prepare(std::size_t reference, std::size_t symbols, std::size_t claims,
                            std::size_t plus, std::size_t minus) {
    if (!active_) return Error::not_found;
    if (!engine_ && inferred_) return prepare_membership(plus, minus);
    std::uint64_t maximum_symbols = 0;
    const auto error = session_symbol_limit(inferred_ ? snapshot_size_ : limits_.max_set_size,
                                            limits_.reference_bound, maximum_symbols);
    if (error != Error::ok) return error;
    if (reference > limits_.reference_bound || symbols > maximum_symbols ||
        symbols > limits_.max_symbol_index + 1 || claims > limits_.max_set_size + limits_.reference_bound ||
        plus > limits_.max_plus || minus > limits_.max_minus) return Error::capacity;
    if (!engine_) {
        const auto created = create_engine();
        if (created != Error::ok) return created;
    }
    const auto old = engine_->storage();
    engine_->reserve_storage({std::max(reference, old.max_reference_items),
        std::max(symbols, old.max_symbols), std::max(claims, old.max_claims), limits_.max_symbol_index});
    plus_.reserve(plus);
    minus_.reserve(minus);
    return Error::ok;
}
Error SessionModel::check_metadata(const ReconSymbols &response, std::optional<std::uint64_t> known) const noexcept {
    if (response.status != SymbolsStatus::normal) return Error::invalid_argument;
    if (!response.exclusions && (!known || *known != response.exclusion_version)) return Error::malformed_message;
    if (inferred_ && (response.snapshot_seq != snapshot_ || response.root_vote != root_ ||
                     response.exclusion_version != version_)) return Error::inconsistent_symbols;
    if (inferred_ && response.exclusions && *response.exclusions != exclusions_) return Error::inconsistent_symbols;
    if (!inferred_ && (known || !response.exclusions || response.ranges.size() != 1 ||
        response.ranges[0].begin != 0 || response.ranges[0].end != 1)) return Error::malformed_message;
    return Error::ok;
}
Error SessionModel::append(const ReconSymbols &response, std::optional<std::uint64_t> known) {
    if (!engine_) return Error::not_found;
    const auto metadata = check_metadata(response, known);
    if (metadata != Error::ok) return metadata;
    std::size_t bytes = 0;
    const auto syntax = serialized_size(response, limits_, bytes);
    if (syntax != Error::ok) return syntax;
    const auto size = inferred_ ? snapshot_size_ : static_cast<std::uint64_t>(response.cells[0].count);
    if (size > limits_.max_set_size) return Error::inconsistent_symbols;
    std::uint64_t budget = 0;
    const auto bounded = session_symbol_limit(size, limits_.reference_bound, budget);
    if (bounded != Error::ok) return bounded;
    if (response.cells.size() > budget - engine_->symbol_count()) return Error::capacity;
    std::vector<IndexedCell> residuals;
    residuals.reserve(response.cells.size());
    std::size_t offset = 0;
    for (const auto &range : response.ranges) {
        for (auto index = range.begin; index < range.end; ++index) {
            Cell cell = response.cells[offset++];
            residuals.push_back({index, cell});
        }
    }
    const auto subtracted = apply_scheduled(engine_->reference_items(), std::span<IndexedCell>(residuals),
        Sign::negative, [](IndexedCell &entry) -> Cell & { return entry.cell; });
    if (subtracted != Error::ok) return subtracted;
    std::vector<ShortId> exclusions;
    if (!inferred_) exclusions = *response.exclusions;
    const auto appended = engine_->append(residuals);
    if (appended != Error::ok) return appended;
    if (!inferred_) {
        snapshot_ = response.snapshot_seq;
        snapshot_size_ = size;
        root_ = response.root_vote;
        version_ = response.exclusion_version;
        reference_at_zero_ = engine_->reference_items().size();
        initial_zero_ = residuals.front().cell.count;
        budget_ = budget;
        exclusions_.swap(exclusions);
        inferred_ = true;
    }
    current_ = response.current_seq;
    return Error::ok;
}
Error SessionModel::accept(void *context, const DecodeResult &decoded) noexcept {
    auto &run = *static_cast<RunContext *>(context);
    auto &self = run.model;
    if (decoded.size > self.snapshot_size_ + self.limits_.reference_bound - self.engine_->claim_count())
        return Error::inconsistent_symbols;
    std::size_t plus = self.plus_.size(), minus = self.minus_.size();
    for (std::size_t i = 0; i < decoded.size; ++i) {
        const auto item = decoded.items[i];
        if (item.sign == Sign::positive) { plus += !has(self.plus_, item.item); minus -= has(self.minus_, item.item); }
        else { minus += !has(self.minus_, item.item); plus -= has(self.plus_, item.item); }
    }
    if (plus > self.plus_.capacity() || minus > self.minus_.capacity() ||
        plus > self.limits_.max_plus || minus > self.limits_.max_minus) return Error::capacity;
    return run.policy.accept ? run.policy.accept(run.policy.context, decoded) : Error::ok;
}
void SessionModel::committed(void *context, const DecodeAudit &proof) noexcept {
    auto &run = *static_cast<RunContext *>(context);
    auto &self = run.model;
    // Remove first so an atomic mixed pair needs only its final membership capacity.
    for (std::size_t i = 0; i < proof.decoded.size; ++i) {
        const auto item = proof.decoded.items[i];
        erase_id(item.sign == Sign::positive ? self.minus_ : self.plus_, item.item);
    }
    for (std::size_t i = 0; i < proof.decoded.size; ++i) {
        const auto item = proof.decoded.items[i];
        insert_id(item.sign == Sign::positive ? self.plus_ : self.minus_, item.item);
    }
    self.assert_reference();
    if (run.observer.committed) run.observer.committed(run.observer.context, proof);
}
PeelResult SessionModel::run(std::span<SignedItem> output, std::span<DecodeAudit> audit,
                            DecodePolicy policy, PeelObserver observer) noexcept {
    if (!engine_ || !inferred_) { PeelResult result; result.error = Error::not_found; return result; }
    RunContext context{*this, policy, observer};
    return engine_->run(output, audit, {&context, accept}, {&context, committed});
}
bool SessionModel::contains(ShortId item) const noexcept {
    return (own_.contains(item) || has(plus_, item)) && !has(minus_, item);
}
void SessionModel::assert_reference() const noexcept {
#ifndef NDEBUG
    if (!engine_) return;
    for (const auto &item : engine_->reference_items()) assert(contains(item.item));
    for (const auto &item : own_.current_ids()) assert(contains(item.powers.item) == engine_->contains(item.powers.item));
    for (const auto item : plus_) assert(contains(item) == engine_->contains(item));
    for (const auto item : minus_) assert(contains(item) == engine_->contains(item));
#endif
}
Error SessionModel::own_delta(ShortId item, Sign sign) noexcept {
    if (item == 0) return Error::invalid_id;
    if (sign != Sign::positive && sign != Sign::negative) return Error::invalid_argument;
    if (!active_) return Error::ok;
    if (has(plus_, item) || has(minus_, item)) return engine_ ? engine_->restart_pass() : Error::ok;
    if (sign == Sign::positive) return engine_ ? engine_->reference_change(item, sign) : Error::ok;
    if (plus_.size() == plus_.capacity() || plus_.size() == limits_.max_plus) return Error::capacity;
    if (engine_) {
        const auto error = engine_->restart_pass();
        if (error != Error::ok) return error;
    }
    insert_id(plus_, item);
    return Error::ok;
}
Error SessionModel::next_range(std::uint64_t stuck, std::int32_t residual_zero,
                               SymbolIndex next, Range &range) const {
    if (!inferred_ || !engine_ || next == 0 || next > limits_.max_symbol_index) return Error::invalid_argument;
    if (stuck >= budget_ || engine_->symbol_count() >= budget_) return Error::capacity;
    const auto magnitude = static_cast<std::uint64_t>(residual_zero < 0 ?
        -static_cast<std::int64_t>(residual_zero) : residual_zero);
    const auto wanted = std::max(stuck + 1, magnitude);
    auto count = std::min(wanted, limits_.max_cells);
    std::size_t bytes = 0;
    auto error = normal_symbols_size(1, count, {}, limits_, bytes);
    if (error != Error::ok && error != Error::capacity) return error;
    if (error == Error::capacity) {
        std::uint64_t low = 0, high = count;
        while (low + 1 < high) {
            const auto middle = low + (high - low) / 2;
            error = normal_symbols_size(1, middle, {}, limits_, bytes);
            if (error == Error::ok) low = middle;
            else if (error == Error::capacity) high = middle;
            else return error;
        }
        count = low;
    }
    if (count == 0 || count > budget_ - engine_->symbol_count() ||
        count > limits_.max_symbol_index - next + 1) return Error::capacity;
    range = {next, next + count};
    return Error::ok;
}
void SessionModel::compact_done() noexcept {
    std::erase_if(plus_, [this](ShortId id) { return own_.contains(id); });
    std::erase_if(minus_, [this](ShortId id) { return !own_.contains(id); });
    assert_reference();
    engine_.reset();
}
void SessionModel::clear() noexcept {
    engine_.reset();
    std::vector<ShortId>().swap(plus_);
    std::vector<ShortId>().swap(minus_);
    std::vector<ShortId>().swap(exclusions_);
    active_ = inferred_ = false;
    snapshot_ = current_ = snapshot_size_ = budget_ = reference_at_zero_ = version_ = 0;
    initial_zero_ = 0;
    root_ = {};
}
} // namespace snowstorm::detail
