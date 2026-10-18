// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_CANDIDATE_BODY_POOL_H
#define LOTUS_V2_CANDIDATE_BODY_POOL_H
#include "block_wire.h"
#include <memory>
#include <span>
namespace lotus::v2 {
struct CandidateBodyLimits {
    uint64_t max_bodies, max_body_bytes, max_resident_wire_bytes;
    uint64_t max_pins, max_pinned_wire_bytes, max_decode_transactions;
};
struct CandidateBodyStats {
    uint64_t bodies{}, resident_wire_bytes{}, pins{}, pinned_wire_bytes{},
        epoch{};
};
enum class CandidateBodyStatus {
    RetainedAuthenticated,
    Duplicate,
    Available,
    Missing,
    Evicted,
    Malformed,
    CapacityRefused,
    Pinned,
    EpochExhausted,
    OperationalError
};
class CandidateBodyPool;
// Move-only immutable view. Release before its bytes are no longer needed.
// Outlives its pool safely; no method can mutate or replace the retained bytes.
class CandidateBodyPin {
public:
    CandidateBodyPin() noexcept;
    ~CandidateBodyPin();
    CandidateBodyPin(CandidateBodyPin &&) noexcept;
    CandidateBodyPin &operator=(CandidateBodyPin &&) noexcept;
    CandidateBodyPin(const CandidateBodyPin &) = delete;
    CandidateBodyPin &operator=(const CandidateBodyPin &) = delete;
    explicit operator bool() const { return bool(impl_); }
    std::span<const uint8_t> Wire() const;
    const Header *BoundHeader() const;
    // Caller reserves separate copy/temporary budget. Failure preserves out.
    CandidateBodyStatus CopyTo(uint64_t max_bytes,
                               std::vector<uint8_t> &out) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class CandidateBodyPool;
};
// Single-owner, volatile, framing/commitment-authenticated candidate bytes.
// No contextual header/PoW/VM/state/monetary validation or block acceptance.
// Explicit caps precede decode/copy: body length, resident bytes/count, and the
// fixed block transaction count. DecodeBlockWire owns the full grammar, exact
// consumption, first-only coinbase, identities and transaction-root binding.
// Transient decoding/identity/encoding allocations are bounded by body length,
// transaction count and the supplied TxProfile, not by resident_wire_bytes.
// Logical wire-byte quotas exclude vector growth/allocator/container overhead,
// caller borrowed input/copies and DownloadReservation staging allocations.
//
// No eviction on insertion. Evict is explicit and refuses pinned entries.
// Every pin is charged independently (even repeated pins of one body). Pins
// and Duplicate do not change availability epoch; insert/evict increments it
// without wrapping. initial_epoch is a caller-owned inventory namespace: pool
// replacement must invalidate combined inventory epochs, never reuse an old
// selector observation. No callbacks, disk writes, sockets or profile defaults.
class CandidateBodyPool {
public:
    CandidateBodyPool(ChainId, TxProfile, CandidateBodyLimits,
                      uint64_t initial_epoch);
    ~CandidateBodyPool() noexcept;
    CandidateBodyPool(const CandidateBodyPool &) = delete;
    CandidateBodyPool &operator=(const CandidateBodyPool &) = delete;
    CandidateBodyPool(CandidateBodyPool &&) = delete;
    CandidateBodyPool &operator=(CandidateBodyPool &&) = delete;
    CandidateBodyStatus
    PutAuthenticated(const Hash &expected_id, const Header &expected_header,
                     const std::vector<uint8_t> &borrowed_wire);
    CandidateBodyStatus Probe(const Hash &, const Header &,
                              uint64_t max_bytes) const;
    CandidateBodyStatus Pin(const Hash &, const Header &, uint64_t max_bytes,
                            CandidateBodyPin &out);
    CandidateBodyStatus Evict(const Hash &);
    CandidateBodyStats Stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace lotus::v2
#endif
