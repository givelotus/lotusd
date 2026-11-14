// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "session_responder.h"
#include <algorithm>
#include <new>
namespace snowstorm::detail {
SessionResponder::~SessionResponder() { expire(); }
void SessionResponder::expire() noexcept {
    store_.release(token_);
    token_ = 0;
    std::vector<TxHandle>().swap(raw_bodies_);
    std::vector<TxHandle>().swap(candidates_);
    std::vector<ShortId>().swap(exclusions_);
    std::vector<SymbolIndex>().swap(served_);
}
void SessionResponder::close(SessionId session) noexcept {
    if (session == highwater_) expire();
}
bool SessionResponder::sweep() noexcept {
    Sequence seq = 0;
    if (!active() || store_.pinned(token_, seq) == Error::ok) return false;
    expire();
    return true;
}
ResponderMemory SessionResponder::memory() const noexcept {
    return {raw_bodies_.capacity(), candidates_.capacity(), exclusions_.capacity(), served_.capacity()};
}
Error SessionResponder::open(const ReconReq &request, const ResponderMetadata &metadata,
                             std::uint64_t token, const Limits &limits) {
    if (token == 0 || metadata.exclusions.size() > limits.max_exclusions ||
        metadata.candidates.size() > limits.max_set_size) return Error::invalid_argument;
    auto snapshot = store_.snapshot(store_.sequence());
    if (snapshot.error != Error::ok) return snapshot.error;
    std::uint64_t budget = 0;
    const auto error = session_symbol_limit(snapshot.ids.size(), request.reference_size, budget);
    if (error != Error::ok) return error;
    std::vector<TxHandle> candidates(metadata.candidates.begin(), metadata.candidates.end());
    std::vector<ShortId> exclusions(metadata.exclusions.begin(), metadata.exclusions.end());
    const auto pinned = store_.pin(token, snapshot.seq);
    if (pinned != Error::ok) return pinned;
    token_ = token;
    snapshot_ = snapshot.seq;
    declared_ = request.reference_size;
    budget_ = budget;
    root_ = metadata.root;
    exclusion_version_ = metadata.exclusion_version;
    raw_bodies_ = std::move(snapshot.bodies);
    candidates_.swap(candidates);
    exclusions_.swap(exclusions);
    return Error::ok;
}
Error SessionResponder::normal(const ReconReq &request, const Limits &limits,
                               ReconSymbols &response) {
    std::size_t missing = 0;
    for (const auto &range : request.ranges) {
        for (auto index = range.begin; index < range.end; ++index)
            missing += !std::binary_search(served_.begin(), served_.end(), index);
    }
    if (missing > budget_ - served_.size()) {
        response.status = SymbolsStatus::resource_limited;
        response.resource_reason = ResourceReason::symbol_budget;
        return Error::ok;
    }
    std::vector<SymbolIndex> additions;
    additions.reserve(missing);
    for (const auto &range : request.ranges) {
        for (auto index = range.begin; index < range.end; ++index) {
            if (!std::binary_search(served_.begin(), served_.end(), index)) additions.push_back(index);
        }
    }
    response.snapshot_seq = snapshot_;
    response.current_seq = store_.sequence();
    response.root_vote = root_;
    response.exclusion_version = exclusion_version_;
    if (request.known_excl_version != exclusion_version_) response.exclusions = exclusions_;
    response.ranges = request.ranges;
    std::size_t count = 0;
    for (const auto &range : request.ranges) count += range.end - range.begin;
    response.cells.resize(count);
    std::size_t offset = 0;
    for (const auto &range : request.ranges) {
        const auto size = static_cast<std::size_t>(range.end - range.begin);
        const auto error = store_.encode_snapshot(snapshot_, range,
            std::span<Cell>(response.cells).subspan(offset, size));
        if (error != Error::ok) return error;
        offset += size;
    }
    std::size_t wire_size = 0;
    const auto error = serialized_size(response, limits, wire_size);
    if (error != Error::ok) return error;
    served_.reserve(served_.size() + additions.size());
    served_.insert(served_.end(), additions.begin(), additions.end());
    std::sort(served_.begin(), served_.end());
    return Error::ok;
}
Error SessionResponder::route(const ReconReq &request, const ResponderMetadata *metadata,
                              std::uint64_t token, const Limits &limits, ReconSymbols &result) {
    sweep();
    if (request.session_id > highwater_ && request.open) {
        expire();
        highwater_ = request.session_id;
        if (request.reference_size > limits.reference_bound) {
            result.status = SymbolsStatus::resource_limited;
            result.resource_reason = ResourceReason::declared_reference_capacity;
            return Error::ok;
        }
        if (!metadata || request.known_excl_version || request.ranges.size() != 1 ||
            request.ranges.front().begin != 0 || request.ranges.front().end != 1)
            return Error::malformed_message;
        const auto error = open(request, *metadata, token, limits);
        if (error != Error::ok) return error;
    }
    if (request.session_id != highwater_ || !active()) {
        result.status = SymbolsStatus::expired;
        return Error::ok;
    }
    if (request.reference_size != declared_) return Error::malformed_message;
    return normal(request, limits, result);
}
Error SessionResponder::respond(const ReconReq &request, const ResponderMetadata *metadata,
                                std::uint64_t token, const Limits &limits, ReconSymbols &response) {
    // Check even private callers before allocating or enumerating index ranges.
    std::size_t bytes = 0;
    const auto syntax = serialized_size(request, limits, bytes);
    if (syntax != Error::ok) return syntax;
    ReconSymbols result;
    result.tip_context = request.tip_context;
    result.session_id = request.session_id;
    result.request_id = request.request_id;
    result.poll_id = request.poll_id;
    try {
        const auto error = route(request, metadata, token, limits, result);
        if (error == Error::capacity) {
            result.status = SymbolsStatus::resource_limited;
            result.resource_reason = ResourceReason::storage_capacity;
        } else if (error == Error::snapshot_expired) {
            result.status = SymbolsStatus::expired;
        } else if (error != Error::ok) return error;
    } catch (const std::bad_alloc &) {
        result.status = SymbolsStatus::resource_limited;
        result.resource_reason = ResourceReason::storage_capacity;
    }
    if (result.status == SymbolsStatus::resource_limited) expire();
    response = std::move(result);
    return Error::ok;
}
} // namespace snowstorm::detail
