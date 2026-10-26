// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/setstore.h>
#include <snowstorm/schedule.h>
#include "store_engine.h"
#include "limits.h"
#include <algorithm>
#include <cassert>
#include <limits>
#include <stdexcept>

namespace snowstorm {
class detail::StoreEngine::Impl {
public:
    using IdRecord = detail::StoreIdRecord;
    using BodyRecord = detail::StoreBodyRecord;
    using LogRecord = detail::StoreLogRecord;
    static constexpr std::size_t RECORD_BYTE_LIMIT = 128;
    static_assert(sizeof(IdRecord) <= RECORD_BYTE_LIMIT && sizeof(BodyRecord) <= RECORD_BYTE_LIMIT &&
                  sizeof(LogRecord) <= RECORD_BYTE_LIMIT);
    Limits limits;
    detail::SketchEngine cache;
    std::vector<IdRecord> ids;
    std::vector<BodyRecord> bodies;
    std::vector<LogRecord> log;
    std::vector<SnapshotPin> pins;
    Sequence seq{}, oldest{};
    std::uint64_t expired{};
    explicit Impl(Limits derived) : limits(derived), cache(derived.max_set_size, 0, derived.max_symbol_index) {
        ids.reserve(limits.max_set_size); bodies.reserve(limits.max_set_size);
        log.reserve(limits.max_change_log);
    }
    auto id_position(ShortId item) const noexcept {
        return std::lower_bound(ids.begin(), ids.end(), item,
            [](const IdRecord &entry, ShortId value) { return entry.powers.item < value; });
    }
    auto body_position(const TxHash &hash) const noexcept {
        return std::lower_bound(bodies.begin(), bodies.end(), hash,
            [](const BodyRecord &entry, const TxHash &value) { return entry.hash < value; });
    }
    std::size_t log_start(Sequence cutoff) const noexcept {
        return std::upper_bound(log.begin(), log.end(), cutoff,
            [](Sequence value, const LogRecord &entry) { return value < entry.change.seq; }) - log.begin();
    }
    void prune() noexcept {
        oldest = pins.empty() ? seq : pins.front().seq;
        log.erase(log.begin(), log.begin() + log_start(oldest));
        if (pins.empty()) std::vector<SnapshotPin>{}.swap(pins);
    }
    Error prepare(std::size_t changes) noexcept {
        if (changes > std::numeric_limits<Sequence>::max() - seq) return Error::overflow;
        if (changes > limits.max_change_log) return Error::capacity;
        std::size_t expire{};
        while (expire < pins.size()) {
            const auto retained = log.size() - log_start(pins[expire].seq);
            if (retained <= limits.max_change_log - changes) break;
            ++expire;
        }
        if (expire > std::numeric_limits<std::uint64_t>::max() - expired) return Error::overflow;
        expired += expire; pins.erase(pins.begin(), pins.begin() + expire); prune();
        return Error::ok;
    }
    void record(ShortId item, const BodyRecord &body, StoreChangeKind kind, const ItemPowers &powers) noexcept {
        log.push_back({{++seq, item, body.hash, kind}, body.body, powers});
    }
    Error admit(ShortId item, TxHandle body) {
        if (item == 0) return Error::invalid_id;
        if (!body) return Error::invalid_argument;
        const auto hash = body->tx_hash();
        const auto existing = body_position(hash);
        if (existing != bodies.end() && existing->hash == hash) return Error::ok;
        if (bodies.size() == limits.max_set_size) return Error::capacity;
        const auto position = id_position(item);
        const auto offset = static_cast<std::size_t>(position - ids.begin());
        const bool present = position != ids.end() && position->powers.item == item;
        if (!present && ids.size() == limits.max_set_size) return Error::capacity;
        const auto ready = prepare(1);
        if (ready != Error::ok) return ready;
        const BodyRecord incoming{hash, item, std::move(body)};
        const auto powers = present ? ids[offset].powers : item_powers(item);
        if (!present) {
            const auto error = cache.add(item); assert(error == Error::ok); (void)error;
            ids.insert(ids.begin() + offset, {powers, seq + 1, 0});
        }
        ++ids[offset].bodies;
        record(item, incoming, present ? StoreChangeKind::body_added : StoreChangeKind::id_added, powers);
        bodies.insert(existing, incoming); prune();
        return Error::ok;
    }
    void erase_body(std::size_t body_offset) noexcept {
        const auto &body = bodies[body_offset];
        const auto id_offset = static_cast<std::size_t>(id_position(body.item) - ids.begin());
        auto &id = ids[id_offset];
        const bool last = id.bodies == 1;
        record(body.item, body, last ? StoreChangeKind::id_removed : StoreChangeKind::body_removed, id.powers);
        --id.bodies;
        if (last) {
            const auto error = cache.remove(body.item); assert(error == Error::ok); (void)error;
            ids.erase(ids.begin() + id_offset);
        }
        bodies.erase(bodies.begin() + body_offset);
    }
    Error valid_sequence(Sequence requested) const noexcept {
        if (requested > seq) return Error::invalid_range;
        return requested < oldest ? Error::snapshot_expired : Error::ok;
    }
    detail::StoreMemory memory() const noexcept {
        return {sizeof(Impl), ids.capacity(), bodies.capacity(), log.capacity(), pins.capacity(), cache.memory()};
    }
};
detail::StoreEngine::StoreEngine(std::uint64_t maximum) {
    Limits limits;
    if (derive_limits(maximum, 0, limits) != Error::ok) throw std::invalid_argument("invalid Snowstorm store capacity");
    impl_ = std::make_unique<Impl>(limits);
}
detail::StoreEngine::~StoreEngine() = default;
detail::StoreEngine::StoreEngine(StoreEngine &&) noexcept = default;
detail::StoreEngine &detail::StoreEngine::operator=(StoreEngine &&) noexcept = default;
Error detail::StoreEngine::admit(ShortId item, TxHandle body) { return impl_->admit(item, std::move(body)); }
Error detail::StoreEngine::remove(ShortId item) noexcept {
    const auto found = impl_->id_position(item);
    if (found == impl_->ids.end() || found->powers.item != item) return Error::ok;
    const auto ready = impl_->prepare(found->bodies);
    if (ready != Error::ok) return ready;
    std::size_t index{};
    while (index < impl_->bodies.size()) {
        if (impl_->bodies[index].item != item) { ++index; continue; }
        impl_->erase_body(index);
    }
    impl_->prune();
    return Error::ok;
}
Error detail::StoreEngine::remove_body(ShortId item, const TxHash &hash) noexcept {
    const auto found = impl_->body_position(hash);
    if (found == impl_->bodies.end() || found->hash != hash || found->item != item) return Error::ok;
    const auto ready = impl_->prepare(1);
    if (ready != Error::ok) return ready;
    impl_->erase_body(found - impl_->bodies.begin()); impl_->prune();
    return Error::ok;
}
Error detail::StoreEngine::pin(std::uint64_t token, Sequence seq) noexcept {
    if (token == 0) return Error::invalid_argument;
    const auto valid = impl_->valid_sequence(seq);
    if (valid != Error::ok) return valid;
    if (std::any_of(impl_->pins.begin(), impl_->pins.end(), [token](auto pin) { return pin.token == token; })) return Error::duplicate;
    if (impl_->pins.size() == params::MAX_PEERS) return Error::capacity;
    if (impl_->pins.size() == impl_->pins.capacity()) {
        const auto capacity = std::min<std::size_t>(params::MAX_PEERS, std::max<std::size_t>(1, 2 * impl_->pins.capacity()));
        try { impl_->pins.reserve(capacity); }
        catch (const std::bad_alloc &) { return Error::capacity; }
    }
    const SnapshotPin pin{token, seq};
    const auto position = std::lower_bound(impl_->pins.begin(), impl_->pins.end(), pin, [](auto a, auto b) {
        return a.seq < b.seq || (a.seq == b.seq && a.token < b.token);
    });
    impl_->pins.insert(position, pin);
    return Error::ok;
}
void detail::StoreEngine::release(std::uint64_t token) noexcept {
    const auto found = std::find_if(impl_->pins.begin(), impl_->pins.end(), [token](auto pin) { return pin.token == token; });
    if (found == impl_->pins.end()) return;
    impl_->pins.erase(found); impl_->prune();
}
Error detail::StoreEngine::pinned(std::uint64_t token, Sequence &seq) const noexcept {
    const auto found = std::find_if(impl_->pins.begin(), impl_->pins.end(), [token](auto pin) { return pin.token == token; });
    if (found == impl_->pins.end()) return Error::snapshot_expired;
    seq = found->seq;
    return Error::ok;
}
StoreSnapshot detail::StoreEngine::snapshot(Sequence seq) const {
    StoreSnapshot result{}; result.seq = seq; result.error = impl_->valid_sequence(seq);
    if (result.error != Error::ok) return result;
    auto bodies = impl_->bodies;
    for (auto entry = impl_->log.rbegin(); entry != impl_->log.rend() && entry->change.seq > seq; ++entry) {
        const auto position = std::lower_bound(bodies.begin(), bodies.end(), entry->change.tx_hash,
            [](const Impl::BodyRecord &body, const TxHash &hash) { return body.hash < hash; });
        const auto kind = entry->change.kind;
        if (kind == StoreChangeKind::id_added || kind == StoreChangeKind::body_added) bodies.erase(position);
        else bodies.insert(position, {entry->change.tx_hash, entry->change.item, entry->body});
    }
    result.ids.reserve(bodies.size()); result.bodies.reserve(bodies.size());
    for (const auto &body : bodies) { result.ids.push_back(body.item); result.bodies.push_back(body.body); }
    std::sort(result.ids.begin(), result.ids.end());
    result.ids.erase(std::unique(result.ids.begin(), result.ids.end()), result.ids.end());
    std::sort(result.bodies.begin(), result.bodies.end(), [](const TxHandle &a, const TxHandle &b) {
        const auto first = a->txid(); const auto second = b->txid();
        return first < second || (first == second && a->tx_hash() < b->tx_hash());
    });
    return result;
}
Error detail::StoreEngine::encode_snapshot(Sequence seq, Range range, std::span<Cell> output) const noexcept {
    const auto valid = impl_->valid_sequence(seq);
    if (valid != Error::ok) return valid;
    const auto encoded = impl_->cache.encode(range, output);
    if (encoded != Error::ok || range.begin == range.end) return encoded;
    for (auto entry = impl_->log.rbegin(); entry != impl_->log.rend() && entry->change.seq > seq; ++entry) {
        const auto kind = entry->change.kind;
        if (kind != StoreChangeKind::id_added && kind != StoreChangeKind::id_removed) continue;
        const auto sign = kind == StoreChangeKind::id_added ? Sign::negative : Sign::positive;
        ScheduleIterator iterator(entry->change.item, range.end - 1);
        while (const auto index = iterator.next()) {
            if (*index < range.begin) continue;
            const auto error = cell_add(output[*index - range.begin], entry->powers, sign);
            assert(error == Error::ok); (void)error;
        }
    }
    return Error::ok;
}
Error detail::StoreEngine::cache_range(Range range) noexcept {
    const auto cached = impl_->cache.cache_range(range);
    if (cached != Error::capacity) return cached;
    const auto indices = impl_->cache.view().indices;
    const auto first = std::lower_bound(indices.begin(), indices.end(), range.begin);
    const auto last = std::lower_bound(indices.begin(), indices.end(), range.end);
    const auto needed = indices.size() + (range.end - range.begin) - static_cast<std::size_t>(last - first);
    if (needed > impl_->limits.max_cells) return Error::capacity;
    try { impl_->cache.reserve_symbols(needed); }
    catch (const std::bad_alloc &) { return Error::capacity; }
    return impl_->cache.cache_range(range);
}
Sequence detail::StoreEngine::sequence() const noexcept { return impl_->seq; }
std::optional<Sequence> detail::StoreEngine::admission_sequence(ShortId item) const noexcept {
    const auto found = impl_->id_position(item);
    if (found == impl_->ids.end() || found->powers.item != item) return std::nullopt;
    return found->admitted;
}
bool detail::StoreEngine::contains(ShortId item) const noexcept { return impl_->cache.contains(item); }
Error detail::StoreEngine::reset(std::span<const ShortId> ids, std::span<const TxHandle> bodies) {
    if (ids.size() != bodies.size()) return Error::invalid_argument;
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (ids[i] == 0) return Error::invalid_id;
        if (!bodies[i]) return Error::invalid_argument;
    }
    std::size_t distinct{};
    for (std::size_t i = 0; i < bodies.size(); ++i) {
        const auto hash = bodies[i]->tx_hash();
        const auto previous = bodies.first(i);
        if (std::any_of(previous.begin(), previous.end(), [&](const TxHandle &body) { return body->tx_hash() == hash; })) continue;
        if (++distinct > impl_->limits.max_set_size) return Error::capacity;
    }
    // All possible local errors precede this boundary; commit reuses reserved
    // storage rather than owning a second full store during tip reset.
    impl_->pins.clear(); impl_->log.clear(); impl_->ids.clear(); impl_->bodies.clear(); impl_->cache.clear();
    impl_->seq = 0; impl_->oldest = 0; impl_->expired = 0; impl_->prune();
    for (std::size_t i = 0; i < ids.size(); ++i) {
        const auto error = impl_->admit(ids[i], bodies[i]);
        assert(error == Error::ok); (void)error;
    }
    impl_->seq = 0; impl_->oldest = 0;
    for (auto &id : impl_->ids) id.admitted = 0;
    return Error::ok;
}
StoreStats detail::StoreEngine::stats() const {
    StoreStats result{};
    result.seq = impl_->seq; result.oldest_retained_seq = impl_->oldest;
    result.id_count = impl_->ids.size(); result.body_count = impl_->bodies.size();
    result.log_length = impl_->log.size(); result.state_bytes = impl_->memory().requested_bytes();
    result.expired_pins = impl_->expired; result.pins = impl_->pins;
    result.changes.reserve(impl_->log.size());
    for (const auto &entry : impl_->log) result.changes.push_back(entry.change);
    return result;
}
detail::StoreMemory detail::StoreEngine::memory() const noexcept { return impl_->memory(); }
std::span<const detail::StoreIdRecord> detail::StoreEngine::current_ids() const noexcept { return impl_->ids; }
std::span<const detail::StoreBodyRecord> detail::StoreEngine::current_bodies() const noexcept { return impl_->bodies; }
std::span<const detail::StoreLogRecord> detail::StoreEngine::retained_log() const noexcept { return impl_->log; }
std::span<const SnapshotPin> detail::StoreEngine::retained_pins() const noexcept { return impl_->pins; }
class SetStore::Impl : public detail::StoreEngine {
public:
    using StoreEngine::StoreEngine;
};
SetStore::SetStore(std::uint64_t maximum) : impl_(std::make_unique<Impl>(maximum)) {}
SetStore::~SetStore() = default;
SetStore::SetStore(SetStore &&) noexcept = default;
SetStore &SetStore::operator=(SetStore &&) noexcept = default;
Error SetStore::admit(ShortId item, TxHandle body) { return impl_->admit(item, std::move(body)); }
Error SetStore::remove(ShortId item) noexcept { return impl_->remove(item); }
Error SetStore::remove_body(ShortId item, const TxHash &hash) noexcept { return impl_->remove_body(item, hash); }
Error SetStore::pin(std::uint64_t token, Sequence seq) noexcept { return impl_->pin(token, seq); }
void SetStore::release(std::uint64_t token) noexcept { impl_->release(token); }
Error SetStore::pinned(std::uint64_t token, Sequence &seq) const noexcept { return impl_->pinned(token, seq); }
StoreSnapshot SetStore::snapshot(Sequence seq) const { return impl_->snapshot(seq); }
Error SetStore::encode_snapshot(Sequence seq, Range range, std::span<Cell> output) const noexcept { return impl_->encode_snapshot(seq, range, output); }
Error SetStore::cache_range(Range range) noexcept { return impl_->cache_range(range); }
Sequence SetStore::sequence() const noexcept { return impl_->sequence(); }
std::optional<Sequence> SetStore::admission_sequence(ShortId item) const noexcept { return impl_->admission_sequence(item); }
bool SetStore::contains(ShortId item) const noexcept { return impl_->contains(item); }
Error SetStore::reset(std::span<const ShortId> ids, std::span<const TxHandle> bodies) { return impl_->reset(ids, bodies); }
StoreStats SetStore::stats() const {
    auto result = impl_->stats();
    result.state_bytes += sizeof(Impl); // Public wrapper heap, absent for Node's inline private engine.
    return result;
}
} // namespace snowstorm
