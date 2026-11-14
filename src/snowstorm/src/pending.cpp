// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "pending.h"
#include <snowstorm/short_id.h>
#include <algorithm>
#include <cassert>
#include <limits>
#include <utility>
namespace snowstorm::detail {
namespace {
constexpr std::size_t RECORD_BYTES = 128;
static_assert(sizeof(PendingEntry) <= RECORD_BYTES && sizeof(PendingDonor) <= RECORD_BYTES &&
              sizeof(PendingUnavailable) <= RECORD_BYTES && sizeof(PendingEffect) <= RECORD_BYTES);
struct ByItem {
    bool operator()(const PendingEntry &entry, ShortId item) const noexcept { return entry.item < item; }
};
PendingEffect limited(ShortId item, Limit limit) noexcept {
    PendingEffect effect; effect.item = item; effect.error = Error::capacity; effect.limit = limit; return effect;
}
} // namespace
PendingEntry *Pending::find(ShortId item) noexcept {
    return const_cast<PendingEntry *>(std::as_const(*this).find(item));
}
const PendingEntry *Pending::find(ShortId item) const noexcept {
    const auto it = std::lower_bound(entries_.begin(), entries_.end(), item, ByItem{});
    return it != entries_.end() && it->item == item ? &*it : nullptr;
}
Error Pending::prepare(PendingCapacity capacity) {
    if (capacity.entries > limits_.max_pending_fetch_union || capacity.donors > limits_.max_donor_records ||
        capacity.unavailable > limits_.max_unavailable || capacity.probation > limits_.max_probation ||
        capacity.rejected > limits_.max_rejected || capacity.local_rejected > limits_.max_local_rejected)
        return Error::capacity;
    entries_.reserve(capacity.entries); donors_.reserve(capacity.donors); unavailable_.reserve(capacity.unavailable);
    probation_.reserve(capacity.probation); rejected_.reserve(capacity.rejected); local_rejected_.reserve(capacity.local_rejected);
    return Error::ok;
}
PendingMemory Pending::memory() const noexcept {
    return {{entries_.capacity(), donors_.capacity(), unavailable_.capacity(), probation_.capacity(),
             rejected_.capacity(), local_rejected_.capacity()}};
}
ClaimDisposition Pending::disposition(ShortId item) const noexcept {
    if (std::binary_search(rejected_.begin(), rejected_.end(), item)) return ClaimDisposition::rejected;
    if (own_.contains(item)) return ClaimDisposition::admitted;
    if (suspended_) return ClaimDisposition::suspended;
    if (std::binary_search(local_rejected_.begin(), local_rejected_.end(), item)) return ClaimDisposition::local_rejected;
    if (std::binary_search(probation_.begin(), probation_.end(), item)) return ClaimDisposition::probation;
    return ClaimDisposition::eligible;
}
bool Pending::pending(const PendingEntry &entry) const noexcept {
    if (own_.contains(entry.item) || std::binary_search(rejected_.begin(), rejected_.end(), entry.item) ||
        std::binary_search(probation_.begin(), probation_.end(), entry.item) ||
        std::binary_search(local_rejected_.begin(), local_rejected_.end(), entry.item)) return false;
    if (suspended_) return entry.token != 0 && entry.state == FetchState::awaiting_admission;
    return entry.supports != 0 || entry.token != 0;
}
bool Pending::is_pending(ShortId item) const noexcept {
    const auto entry = find(item); return entry && pending(*entry);
}
bool Pending::has_donor(ShortId item, DonorConnection connection) const noexcept {
    return std::any_of(donors_.begin(), donors_.end(), [&](const PendingDonor &donor) {
        return donor.item == item && donor.connection == connection;
    });
}
bool Pending::unavailable(ShortId item, DonorConnection connection) const noexcept {
    return std::any_of(unavailable_.begin(), unavailable_.end(), [&](const PendingUnavailable &entry) {
        return entry.item == item && entry.connection == connection;
    });
}
const PendingDonor *Pending::first_donor(ShortId item, std::optional<DonorConnection> skip) const noexcept {
    const auto donor = std::find_if(donors_.begin(), donors_.end(), [&](const PendingDonor &entry) {
        return entry.item == item && (!skip || entry.connection != *skip);
    });
    return donor != donors_.end() ? &*donor : nullptr;
}
FetchTicket Pending::start(PendingEntry &entry, const PendingDonor &donor) noexcept {
    assert(last_token_ != std::numeric_limits<FetchId>::max());
    entry.token = ++last_token_; entry.donor = donor.connection;
    entry.state = FetchState::in_flight; entry.expected_hash = {};
    return {entry.item, donor.connection.peer, entry.token};
}
void Pending::erase_entry(ShortId item) noexcept {
    const auto it = std::lower_bound(entries_.begin(), entries_.end(), item, ByItem{});
    if (it != entries_.end() && it->item == item) entries_.erase(it);
}
void Pending::erase_donors(ShortId item) noexcept {
    std::erase_if(donors_, [item](const PendingDonor &entry) { return entry.item == item; });
}
PendingEffect Pending::check_discover(std::span<const ShortId> items, DonorConnection donor) const noexcept {
    PendingEffect effect;
    if (donor.peer == 0 || donor.generation == 0) { effect.error = Error::invalid_argument; return effect; }
    std::size_t new_entries = 0, new_donors = 0, new_fetches = 0;
    for (auto it = items.begin(); it != items.end(); ++it) {
        effect.item = *it;
        if (*it == 0) { effect.error = Error::invalid_id; return effect; }
        if (std::find(items.begin(), it, *it) != it) continue;
        const auto kind = disposition(*it);
        if (kind != ClaimDisposition::eligible && kind != ClaimDisposition::probation) continue;
        const auto count = std::count_if(donors_.begin(), donors_.end(), [&](const PendingDonor &entry) { return entry.item == *it; });
        const bool add = !unavailable(*it, donor) && !has_donor(*it, donor) &&
            static_cast<std::uint64_t>(count) < limits_.max_donors_per_id;
        new_donors += add;
        const auto entry = find(*it);
        const bool fetch = (!entry || entry->token == 0) && (add || first_donor(*it));
        new_fetches += fetch; new_entries += !entry && (fetch || kind == ClaimDisposition::eligible);
    }
    if (new_entries > limits_.max_pending_fetch_union - entries_.size() ||
        new_entries > entries_.capacity() - entries_.size()) return limited(effect.item, Limit::pending_fetch_union);
    if (new_donors > limits_.max_donor_records - donors_.size() ||
        new_donors > donors_.capacity() - donors_.size()) return limited(effect.item, Limit::donor_records);
    if (new_fetches > std::numeric_limits<FetchId>::max() - last_token_ ||
        new_donors > std::numeric_limits<std::uint64_t>::max() - last_discovery_) effect.error = Error::exhausted;
    return effect;
}
PendingEffect Pending::discover(ShortId item, DonorConnection donor) noexcept {
    auto effect = check_discover(std::span<const ShortId>(&item, 1), donor);
    if (effect.error != Error::ok) return effect;
    const auto kind = disposition(item);
    if (kind != ClaimDisposition::eligible && kind != ClaimDisposition::probation) return effect;
    const bool before = is_pending(item);
    const auto count = std::count_if(donors_.begin(), donors_.end(), [item](const PendingDonor &entry) { return entry.item == item; });
    if (!unavailable(item, donor) && !has_donor(item, donor) && static_cast<std::uint64_t>(count) < limits_.max_donors_per_id)
        donors_.push_back({item, donor, ++last_discovery_});
    const auto source = first_donor(item);
    if (!source) return effect;
    auto entry = find(item);
    if (!entry) entry = &*entries_.insert(std::lower_bound(entries_.begin(), entries_.end(), item, ByItem{}), PendingEntry{.item = item});
    if (entry->token == 0) effect.fetch = start(*entry, *source);
    effect.pending_changed = before != is_pending(item);
    return effect;
}
PendingEffect Pending::support(ShortId item, std::uint64_t decoded_plus_count) noexcept {
    PendingEffect effect; effect.item = item;
    if (item == 0) { effect.error = Error::invalid_id; return effect; }
    auto entry = find(item);
    const auto kind = disposition(item);
    if (kind != ClaimDisposition::eligible) decoded_plus_count = 0;
    const bool before = is_pending(item);
    if (!entry && decoded_plus_count != 0) {
        if (entries_.size() == limits_.max_pending_fetch_union || entries_.size() == entries_.capacity())
            return limited(item, Limit::pending_fetch_union);
        entry = &*entries_.insert(std::lower_bound(entries_.begin(), entries_.end(), item, ByItem{}), PendingEntry{.item = item});
    }
    if (entry) {
        entry->supports = decoded_plus_count;
        if (entry->supports == 0 && entry->token == 0) { erase_entry(item); effect.clear_confidence = !own_.contains(item); }
    }
    effect.pending_changed = before != is_pending(item);
    return effect;
}
Error Pending::validate_result(ShortId item, const BodyResult &result) const noexcept {
    if (result.status > BodyStatus::local_rejected || result.binding > BodyBinding::unbound)
        return Error::host_contract_error;
    if (result.status == BodyStatus::not_found ||
        (result.status == BodyStatus::invalid && result.binding == BodyBinding::unbound)) return Error::ok;
    if (result.binding != BodyBinding::matched || !result.expected_tx_hash ||
        short_id(key_, *result.expected_tx_hash) != item) return Error::host_contract_error;
    return Error::ok;
}
PendingEffect Pending::preflight_failure(ShortId item, DonorConnection donor, const BodyResult &result) const noexcept {
    const bool missing = result.status == BodyStatus::not_found || result.binding == BodyBinding::unbound;
    const auto &marks = missing ? probation_ : result.status == BodyStatus::invalid ? rejected_ : local_rejected_;
    const auto maximum = missing ? limits_.max_probation : result.status == BodyStatus::invalid ?
        limits_.max_rejected : limits_.max_local_rejected;
    const auto resource = missing ? Limit::probation : result.status == BodyStatus::invalid ? Limit::rejected : Limit::local_rejected;
    if (!std::binary_search(marks.begin(), marks.end(), item)) {
        if (marks.size() == maximum || marks.size() == marks.capacity()) {
            auto effect = limited(item, resource); effect.suspended = marks.size() == maximum; return effect;
        }
    }
    if (missing && !unavailable(item, donor)) {
        if (unavailable_.size() == limits_.max_unavailable || unavailable_.size() == unavailable_.capacity()) {
            auto effect = limited(item, Limit::unavailable);
            effect.suspended = unavailable_.size() == limits_.max_unavailable; return effect;
        }
    }
    PendingEffect effect; effect.item = item;
    if (missing && first_donor(item, donor) && last_token_ == std::numeric_limits<FetchId>::max())
        effect.error = Error::exhausted;
    return effect;
}
PendingEffect Pending::suspend(ShortId item, Limit limit) noexcept {
    suspended_ = true;
    std::erase_if(entries_, [](const PendingEntry &entry) {
        return entry.token == 0 || entry.state != FetchState::awaiting_admission;
    });
    for (auto &entry : entries_) entry.supports = 0;
    donors_.clear();
    PendingEffect effect; effect.item = item; effect.limit = limit;
    effect.suspended = effect.clear_models = effect.clear_confidence = effect.pending_changed = true;
    return effect;
}
PendingEffect Pending::failure(PendingEntry &entry, const BodyResult &result) noexcept {
    PendingEffect effect; effect.item = entry.item; effect.blamed = entry.donor.peer;
    effect.clear_models = effect.clear_confidence = true;
    const bool before = pending(entry);
    const bool missing = result.status == BodyStatus::not_found || result.binding == BodyBinding::unbound;
    auto &marks = missing ? probation_ : result.status == BodyStatus::invalid ? rejected_ : local_rejected_;
    if (!std::binary_search(marks.begin(), marks.end(), entry.item))
        marks.insert(std::lower_bound(marks.begin(), marks.end(), entry.item), entry.item);
    entry.supports = 0; entry.token = 0;
    if (missing) {
        if (!unavailable(entry.item, entry.donor)) unavailable_.push_back({entry.item, entry.donor});
        std::erase_if(donors_, [&](const PendingDonor &donor) {
            return donor.item == entry.item && donor.connection == entry.donor;
        });
        effect.reason = result.status == BodyStatus::not_found ? Misbehavior::body_not_found : Misbehavior::wrong_body_binding;
        effect.penalize = true;
        if (const auto alternate = first_donor(entry.item)) effect.fetch = start(entry, *alternate);
    } else {
        erase_donors(entry.item);
        std::erase(probation_, entry.item);
        effect.penalize = result.status == BodyStatus::invalid;
        effect.reason = Misbehavior::invalid_body;
    }
    if (entry.token == 0) erase_entry(effect.item);
    effect.pending_changed = before != is_pending(effect.item);
    return effect;
}
PendingEffect Pending::body_result(DonorConnection donor, ShortId item, const BodyResult &result) noexcept {
    PendingEffect effect; effect.item = item;
    auto entry = find(item);
    // Completed/unknown generation/token is discarded before any payload check.
    if (!entry || entry->token == 0 || entry->token != result.fetch_id ||
        entry->donor != donor || entry->state != FetchState::in_flight) return effect;
    effect.error = validate_result(item, result);
    if (effect.error != Error::ok) return effect;
    if (result.status == BodyStatus::admitted) {
        const bool before = pending(*entry);
        entry->state = FetchState::awaiting_admission; entry->expected_hash = *result.expected_tx_hash;
        std::erase(probation_, item);
        effect.pending_changed = before != pending(*entry);
        return effect;
    }
    effect = preflight_failure(item, donor, result);
    if (effect.error == Error::ok) return failure(*entry, result);
    if (!effect.suspended) return effect;
    effect = suspend(item, effect.limit);
    effect.blamed = donor.peer; effect.penalize = result.status != BodyStatus::local_rejected;
    effect.reason = result.status == BodyStatus::not_found ? Misbehavior::body_not_found :
        result.binding == BodyBinding::unbound ? Misbehavior::wrong_body_binding : Misbehavior::invalid_body;
    return effect;
}
PendingEffect Pending::admitted(ShortId item, const TxHash &hash) noexcept {
    PendingEffect effect; effect.item = item;
    std::erase(probation_, item); std::erase(local_rejected_, item); erase_donors(item);
    auto entry = find(item);
    if (!entry) return effect;
    // Store already contains item, so mathematical Pending is now false even
    // when a different colliding awaited body must retain its callback token.
    effect.pending_changed = true;
    entry->supports = 0;
    if (entry->token == 0 || entry->state == FetchState::in_flight || entry->expected_hash == hash) erase_entry(item);
    return effect;
}
Error Pending::disconnect(DonorConnection donor, std::span<PendingEffect> effects, std::size_t &written) noexcept {
    written = 0;
    if (effects.size() < entries_.size()) return Error::capacity;
    std::uint64_t retries = 0;
    for (const auto &entry : entries_) {
        if (entry.token != 0 && entry.state == FetchState::in_flight && entry.donor == donor)
            retries += first_donor(entry.item, donor) != nullptr;
    }
    if (retries > std::numeric_limits<FetchId>::max() - last_token_) return Error::exhausted;
    std::erase_if(donors_, [donor](const PendingDonor &entry) { return entry.connection == donor; });
    for (auto &entry : entries_) {
        if (entry.token == 0 || entry.state != FetchState::in_flight || entry.donor != donor) continue;
        PendingEffect effect; effect.item = entry.item;
        const bool before = pending(entry);
        entry.token = 0;
        if (const auto alternate = first_donor(entry.item)) effect.fetch = start(entry, *alternate);
        effect.pending_changed = before != pending(entry);
        effect.clear_confidence = entry.token == 0 && entry.supports == 0 && !own_.contains(entry.item);
        effects[written++] = effect;
    }
    std::erase_if(entries_, [](const PendingEntry &entry) { return entry.token == 0 && entry.supports == 0; });
    return Error::ok;
}
Error Pending::reset(ShortIdKey key) noexcept {
    if (height_generation_ == std::numeric_limits<std::uint64_t>::max()) return Error::overflow;
    entries_.clear(); donors_.clear(); unavailable_.clear(); probation_.clear(); rejected_.clear(); local_rejected_.clear();
    suspended_ = false; key_ = key; ++height_generation_;
    return Error::ok;
}
} // namespace snowstorm::detail
