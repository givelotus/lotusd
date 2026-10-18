// Copyright (c) 2026 The Lotus developers
#include "candidate_body_pool.h"
#include <algorithm>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <utility>
namespace lotus::v2 {
namespace {
    struct Body {
        Header header;
        std::vector<uint8_t> wire;
        uint64_t pins = 0;
    };
    struct Accounting {
        uint64_t pins = 0, pinned_bytes = 0;
    };
    bool EqualHeader(const Header &a, const Header &b) {
        std::array<uint8_t, HEADER_SIZE> x{}, y{};
        return SerializeHeader(a, x) && SerializeHeader(b, y) && x == y;
    }
} // namespace
struct CandidateBodyPin::Impl {
    std::shared_ptr<Body> body;
    std::shared_ptr<Accounting> account;
    Impl(std::shared_ptr<Body> b, std::shared_ptr<Accounting> a)
        : body(std::move(b)), account(std::move(a)) {}
    ~Impl() {
        --body->pins;
        --account->pins;
        account->pinned_bytes -= body->wire.size();
    }
};
struct CandidateBodyPool::Impl {
    ChainId chain;
    TxProfile profile;
    CandidateBodyLimits limits;
    uint64_t resident = 0, epoch;
    std::map<Hash, std::shared_ptr<Body>> bodies;
    std::shared_ptr<Accounting> account = std::make_shared<Accounting>();
    Impl(ChainId c, TxProfile p, CandidateBodyLimits l, uint64_t e)
        : chain(c), profile(p), limits(l), epoch(e) {}
};
CandidateBodyPin::CandidateBodyPin() noexcept = default;
CandidateBodyPin::~CandidateBodyPin() = default;
CandidateBodyPin::CandidateBodyPin(CandidateBodyPin &&) noexcept = default;
CandidateBodyPin &
CandidateBodyPin::operator=(CandidateBodyPin &&) noexcept = default;
std::span<const uint8_t> CandidateBodyPin::Wire() const {
    return impl_ ? std::span<const uint8_t>(impl_->body->wire)
                 : std::span<const uint8_t>{};
}
const Header *CandidateBodyPin::BoundHeader() const {
    return impl_ ? &impl_->body->header : nullptr;
}
CandidateBodyStatus CandidateBodyPin::CopyTo(uint64_t maximum,
                                             std::vector<uint8_t> &out) const {
    if (!impl_) return CandidateBodyStatus::Missing;
    if (impl_->body->wire.size() > maximum)
        return CandidateBodyStatus::CapacityRefused;
    try {
        auto copy = impl_->body->wire;
        out = std::move(copy);
        return CandidateBodyStatus::Available;
    } catch (const std::bad_alloc &) {
        return CandidateBodyStatus::CapacityRefused;
    } catch (const std::length_error &) {
        return CandidateBodyStatus::CapacityRefused;
    }
}
CandidateBodyPool::CandidateBodyPool(ChainId chain, TxProfile profile,
                                     CandidateBodyLimits limits,
                                     uint64_t initial_epoch) {
    if (!limits.max_bodies || !limits.max_body_bytes ||
        !limits.max_resident_wire_bytes || !limits.max_pins ||
        !limits.max_pinned_wire_bytes || !limits.max_decode_transactions ||
        limits.max_body_bytes > std::numeric_limits<size_t>::max() ||
        limits.max_decode_transactions > UINT32_MAX)
        throw std::invalid_argument("candidate body pool limits");
    // Reuse the transaction codec's profile check with a fixed core input;
    // unsupported caller configuration must not become a peer Malformed result.
    Input profile_probe;
    profile_probe.flags = 2;
    profile_probe.sequence = UINT32_MAX;
    std::vector<uint8_t> encoded;
    std::string error;
    if (!EncodeInputCore(profile_probe, profile, encoded, error))
        throw std::invalid_argument("candidate body pool transaction profile");
    impl_ = std::make_unique<Impl>(chain, profile, limits, initial_epoch);
}
CandidateBodyPool::~CandidateBodyPool() noexcept = default;
CandidateBodyStats CandidateBodyPool::Stats() const {
    return {impl_->bodies.size(), impl_->resident, impl_->account->pins,
            impl_->account->pinned_bytes, impl_->epoch};
}
CandidateBodyStatus CandidateBodyPool::Probe(const Hash &id,
                                             const Header &header,
                                             uint64_t maximum) const {
    const auto found = impl_->bodies.find(id);
    if (found == impl_->bodies.end()) return CandidateBodyStatus::Missing;
    if (!EqualHeader(found->second->header, header))
        return CandidateBodyStatus::Malformed;
    return found->second->wire.size() <= maximum
               ? CandidateBodyStatus::Available
               : CandidateBodyStatus::CapacityRefused;
}
CandidateBodyStatus
CandidateBodyPool::PutAuthenticated(const Hash &id, const Header &header,
                                    const std::vector<uint8_t> &wire) {
    auto &s = *impl_;
    if (wire.size() > s.limits.max_body_bytes)
        return CandidateBodyStatus::CapacityRefused;
    const auto existing = s.bodies.find(id);
    if (existing != s.bodies.end()) {
        return EqualHeader(existing->second->header, header) &&
                       existing->second->wire == wire
                   ? CandidateBodyStatus::Duplicate
                   : CandidateBodyStatus::Malformed;
    }
    if (s.epoch == UINT64_MAX) return CandidateBodyStatus::EpochExhausted;
    if (s.bodies.size() >= s.limits.max_bodies ||
        wire.size() > s.limits.max_resident_wire_bytes - s.resident)
        return CandidateBodyStatus::CapacityRefused;
    if (wire.size() < HEADER_SIZE + 4) return CandidateBodyStatus::Malformed;
    uint32_t count = 0;
    for (unsigned i = 0; i < 4; ++i)
        count |= uint32_t(wire[HEADER_SIZE + i]) << (8 * i);
    if (count > s.limits.max_decode_transactions)
        return CandidateBodyStatus::CapacityRefused;
    // Header/ID preflight needs no decode allocation and prevents copying a
    // body for an unrelated indexed target. Full framing stays in the codec.
    Header actual;
    Hash actual_id;
    if (!ParseHeader(wire.data(), HEADER_SIZE, actual) ||
        !EqualHeader(header, actual) || header.size != wire.size() ||
        !BlockId(s.chain, header, actual_id) || actual_id != id)
        return CandidateBodyStatus::Malformed;
    try {
        FramedBlock decoded;
        std::string error;
        if (!DecodeBlockWire(wire, s.profile, s.chain, decoded, error))
            return CandidateBodyStatus::Malformed;
        // Destroy decoded objects before allocating the resident copy. The
        // decoder already authenticates CompleteTransactionRoot against header.
        decoded = {};
        auto body = std::make_shared<Body>();
        body->header = header;
        body->wire = wire;
        const auto inserted = s.bodies.emplace(id, std::move(body));
        if (!inserted.second) return CandidateBodyStatus::OperationalError;
        s.resident += wire.size();
        ++s.epoch;
        return CandidateBodyStatus::RetainedAuthenticated;
    } catch (const std::bad_alloc &) {
        return CandidateBodyStatus::CapacityRefused;
    } catch (const std::length_error &) {
        return CandidateBodyStatus::CapacityRefused;
    } catch (...) {
        return CandidateBodyStatus::OperationalError;
    }
}
CandidateBodyStatus CandidateBodyPool::Pin(const Hash &id, const Header &header,
                                           uint64_t maximum,
                                           CandidateBodyPin &out) {
    const auto result = Probe(id, header, maximum);
    if (result != CandidateBodyStatus::Available) return result;
    auto &s = *impl_;
    const auto body = s.bodies.find(id)->second;
    if (s.account->pins >= s.limits.max_pins ||
        body->wire.size() >
            s.limits.max_pinned_wire_bytes - s.account->pinned_bytes)
        return CandidateBodyStatus::CapacityRefused;
    try {
        auto pin = std::make_unique<CandidateBodyPin::Impl>(body, s.account);
        ++body->pins;
        ++s.account->pins;
        s.account->pinned_bytes += body->wire.size();
        out.impl_ = std::move(pin);
        return CandidateBodyStatus::Available;
    } catch (const std::bad_alloc &) {
        return CandidateBodyStatus::CapacityRefused;
    } catch (const std::length_error &) {
        return CandidateBodyStatus::CapacityRefused;
    }
}
CandidateBodyStatus CandidateBodyPool::Evict(const Hash &id) {
    auto &s = *impl_;
    const auto found = s.bodies.find(id);
    if (found == s.bodies.end()) return CandidateBodyStatus::Missing;
    if (found->second->pins) return CandidateBodyStatus::Pinned;
    if (s.epoch == UINT64_MAX) return CandidateBodyStatus::EpochExhausted;
    s.resident -= found->second->wire.size();
    s.bodies.erase(found);
    ++s.epoch;
    return CandidateBodyStatus::Evicted;
}
} // namespace lotus::v2
