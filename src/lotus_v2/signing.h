// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_SIGNING_H
#define LOTUS_V2_SIGNING_H

#include "tagged_hash.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace lotus::v2 {

struct BatchSigItem {
    std::array<uint8_t, 32> pubkey{};
    std::array<uint8_t, 64> parsed_pubkey{};
    std::array<uint8_t, 64> sig{};
    Hash msg{};
};

struct LegacyBatchSigItem {
    std::array<uint8_t, 64> parsed_pubkey{};
    std::array<uint8_t, 64> sig{};
    Hash msg{};
    std::array<uint8_t, 32> cache_entry{};
    bool store_in_cache{false};
};

// Collects BIP340 Schnorr and legacy 64-byte Schnorr (pubkey, sig64, msg32)
// tuples during NULLFAIL script execution for deferred multi-scalar
// multiplication batch verification (Strauss / Pippenger via
// secp256k1_schnorrsig_verify_batch and secp256k1_schnorr_verify_batch) and
// bisection fallback to pinpoint the exact failing signature index.
class BatchSigCollector {
public:
    BatchSigCollector() = default;

    // Validates that `pubkey` is a canonical 32-byte x-only secp256k1 key and
    // `sig` has at least 64 bytes (using the 64-byte R||s prefix), then records
    // the tuple for deferred batch verification. Returns false if `pubkey` or
    // `sig` encoding is invalid.
    bool Add(std::span<const uint8_t> pubkey, std::span<const uint8_t> sig,
             const Hash &msg);

    // Validates that `pubkey` is a valid 33/65-byte secp256k1 public key and
    // `sig64` is 64 bytes, then records the tuple for deferred legacy Schnorr
    // batch verification.
    bool AddLegacySchnorr(std::span<const uint8_t> pubkey,
                          std::span<const uint8_t> sig64,
                          const uint8_t *msg32,
                          const uint8_t *cache_entry32 = nullptr,
                          bool store_in_cache = false);

    void Reserve(size_t n) {
        items_.reserve(n);
        legacy_items_.reserve(n);
    }
    void Clear() noexcept {
        items_.clear();
        legacy_items_.clear();
    }
    bool Empty() const noexcept {
        return items_.empty() && legacy_items_.empty();
    }
    size_t Size() const noexcept {
        return items_.size() + legacy_items_.size();
    }
    const std::vector<BatchSigItem> &Items() const noexcept { return items_; }
    const std::vector<LegacyBatchSigItem> &LegacyItems() const noexcept {
        return legacy_items_;
    }

    void Merge(const BatchSigCollector &other);
    void Merge(BatchSigCollector &&other);

    // Verifies all collected signatures in batch using multi-scalar
    // multiplication. When `num_threads == 0`, automatically partitions large
    // batches across hardware worker threads.
    bool VerifyAll(size_t num_threads = 0) const;

    // Returns std::nullopt if all collected signatures are valid, or the
    // 0-based index of the first invalid signature via batch bisection.
    std::optional<size_t> FirstFailingIndex(size_t num_threads = 0) const;

private:
    std::vector<BatchSigItem> items_;
    std::vector<LegacyBatchSigItem> legacy_items_;
};

} // namespace lotus::v2
#endif
