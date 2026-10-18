// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utxo_fast_filter.h"

#include <crypto/siphash.h>
#include <random.h>

#include <cstring>

namespace lotus::v2 {

namespace {

constexpr size_t kInitialShardTableCap = 256;

Outpoint MakeOutpoint(const uint8_t *txid32, uint32_t index) {
    Outpoint result{};
    std::memcpy(result.tx_id.data(), txid32, result.tx_id.size());
    result.index = index;
    return result;
}

inline std::pair<size_t, uint64_t> BloomBit1(uint64_t fp) noexcept {
    const uint32_t bit = static_cast<uint32_t>(fp & 2047ULL);
    return {bit >> 6, 1ULL << (bit & 63u)};
}

inline std::pair<size_t, uint64_t> BloomBit2(uint64_t fp) noexcept {
    const uint32_t bit = static_cast<uint32_t>((fp >> 11) & 2047ULL);
    return {bit >> 6, 1ULL << (bit & 63u)};
}

} // namespace

// ============================================================================
// UtxoFastFilter::FlatFpSet
// ============================================================================

UtxoFastFilter::FlatFpSet::FlatFpSet()
    : slots(kInitialShardTableCap, kEmpty), references(kInitialShardTableCap, 0) {}

void UtxoFastFilter::FlatFpSet::Clear() {
    std::fill(slots.begin(), slots.end(), kEmpty);
    std::fill(references.begin(), references.end(), 0);
    count = 0;
    tombstones = 0;
}

void UtxoFastFilter::FlatFpSet::Reserve(size_t min_entries) {
    size_t target_cap = kInitialShardTableCap;
    while (target_cap < min_entries * 2) {
        target_cap *= 2;
    }
    if (target_cap > slots.size()) {
        Rehash(target_cap);
    }
}

void UtxoFastFilter::FlatFpSet::Rehash(size_t new_cap) {
    std::vector<uint64_t> old = std::move(slots);
    auto old_references = std::move(references);
    slots.assign(new_cap, kEmpty);
    references.assign(new_cap, 0);
    count = 0;
    tombstones = 0;
    const size_t mask = new_cap - 1;
    for (size_t old_idx = 0; old_idx < old.size(); ++old_idx) {
        const uint64_t val = old[old_idx];
        if (val > kTombstone) {
            size_t idx = static_cast<size_t>(val) & mask;
            while (slots[idx] != kEmpty) {
                idx = (idx + 1) & mask;
            }
            slots[idx] = val;
            references[idx] = old_references[old_idx];
            ++count;
        }
    }
}

bool UtxoFastFilter::FlatFpSet::Insert(uint64_t fp) {
    if ((count + tombstones + 1) * 2 >= slots.size()) {
        const size_t next_cap =
            (count * 4 >= slots.size()) ? (slots.size() * 2) : slots.size();
        Rehash(next_cap);
    }
    const size_t mask = slots.size() - 1;
    size_t idx = static_cast<size_t>(fp) & mask;
    size_t first_tomb = slots.size();
    while (true) {
        const uint64_t cur = slots[idx];
        if (cur == fp) {
            ++references[idx];
            return false;
        }
        if (cur == kEmpty) {
            if (first_tomb != slots.size()) {
                slots[first_tomb] = fp;
                references[first_tomb] = 1;
                --tombstones;
            } else {
                slots[idx] = fp;
                references[idx] = 1;
            }
            ++count;
            return true;
        }
        if (cur == kTombstone && first_tomb == slots.size()) {
            first_tomb = idx;
        }
        idx = (idx + 1) & mask;
    }
}

bool UtxoFastFilter::FlatFpSet::Erase(uint64_t fp) {
    const size_t mask = slots.size() - 1;
    size_t idx = static_cast<size_t>(fp) & mask;
    while (true) {
        const uint64_t cur = slots[idx];
        if (cur == fp) {
            if (--references[idx] != 0) {
                return true;
            }
            slots[idx] = kTombstone;
            --count;
            ++tombstones;
            return true;
        }
        if (cur == kEmpty) {
            return false;
        }
        idx = (idx + 1) & mask;
    }
}

bool UtxoFastFilter::FlatFpSet::Contains(uint64_t fp) const noexcept {
    const size_t mask = slots.size() - 1;
    size_t idx = static_cast<size_t>(fp) & mask;
    while (true) {
        const uint64_t cur = slots[idx];
        if (cur == fp) {
            return true;
        }
        if (cur == kEmpty) {
            return false;
        }
        idx = (idx + 1) & mask;
    }
}

// ============================================================================
// UtxoFastFilter::Shard
// ============================================================================

UtxoFastFilter::Shard::Shard() {
    for (auto &w : spent_bloom) {
        w.store(0ULL, std::memory_order_relaxed);
    }
    for (auto &w : unspent_bloom) {
        w.store(0ULL, std::memory_order_relaxed);
    }
}

void UtxoFastFilter::Shard::RebuildSpentBloomLocked() noexcept {
    std::array<uint64_t, kBloomWords> next_bloom{};
    for (uint64_t val : spent_set.slots) {
        if (val > FlatFpSet::kTombstone) {
            const auto [w1, m1] = BloomBit1(val);
            const auto [w2, m2] = BloomBit2(val);
            next_bloom[w1] |= m1;
            next_bloom[w2] |= m2;
        }
    }
    for (size_t i = 0; i < kBloomWords; ++i) {
        spent_bloom[i].store(next_bloom[i], std::memory_order_release);
    }
}

void UtxoFastFilter::Shard::RebuildUnspentBloomLocked() noexcept {
    std::array<uint64_t, kBloomWords> next_bloom{};
    for (uint64_t val : unspent_set.slots) {
        if (val > FlatFpSet::kTombstone) {
            const auto [w1, m1] = BloomBit1(val);
            const auto [w2, m2] = BloomBit2(val);
            next_bloom[w1] |= m1;
            next_bloom[w2] |= m2;
        }
    }
    for (size_t i = 0; i < kBloomWords; ++i) {
        unspent_bloom[i].store(next_bloom[i], std::memory_order_release);
    }
}

// ============================================================================
// UtxoFastFilter
// ============================================================================

UtxoFastFilter::UtxoFastFilter() = default;

void UtxoFastFilter::ReservePerShard(size_t unspent_cap, size_t spent_cap) {
    for (Shard &shard : shards_) {
        std::lock_guard<std::mutex> lock(shard.mutex);
        shard.unspent_set.Reserve(unspent_cap);
        shard.spent_set.Reserve(spent_cap);
    }
}

uint64_t UtxoFastFilter::ComputeFingerprint(const uint8_t *txid32,
                                            uint32_t index) noexcept {
    // One process-local secret; use every txid byte plus the output index.
    static const uint256 salt = GetRandHash();
    const uint64_t fp = CSipHasher(salt.GetUint64(0), salt.GetUint64(1))
                            .Write(Span<const uint8_t>(txid32, 32))
                            .Write(uint64_t(index))
                            .Finalize();
    return fp <= FlatFpSet::kTombstone ? 2ULL : fp;
}

bool UtxoFastFilter::MarkSpentInMempool(const uint8_t *txid32, uint32_t index) {
    const size_t sidx = ShardIndex(txid32);
    const uint64_t fp = ComputeFingerprint(txid32, index);
    Shard &shard = shards_[sidx];
    std::lock_guard<std::mutex> lock(shard.mutex);
    if (!shard.spent_outpoints.insert(MakeOutpoint(txid32, index)).second) {
        return false;
    }
    shard.spent_set.Insert(fp);
    shard.spent_count.store(shard.spent_outpoints.size(),
                              std::memory_order_relaxed);
    const auto [w1, m1] = BloomBit1(fp);
    const auto [w2, m2] = BloomBit2(fp);
    shard.spent_bloom[w1].fetch_or(m1, std::memory_order_release);
    shard.spent_bloom[w2].fetch_or(m2, std::memory_order_release);
    return true;
}

bool UtxoFastFilter::UnmarkSpentInMempool(const uint8_t *txid32,
                                          uint32_t index) {
    const size_t sidx = ShardIndex(txid32);
    const uint64_t fp = ComputeFingerprint(txid32, index);
    Shard &shard = shards_[sidx];
    std::lock_guard<std::mutex> lock(shard.mutex);
    if (!shard.spent_outpoints.erase(MakeOutpoint(txid32, index))) {
        return false;
    }
    shard.spent_set.Erase(fp);
    shard.spent_count.store(shard.spent_outpoints.size(),
                              std::memory_order_relaxed);
    shard.RebuildSpentBloomLocked();
    return true;
}

bool UtxoFastFilter::IsSpentInMempool(const uint8_t *txid32,
                                      uint32_t index) const noexcept {
    const size_t sidx = ShardIndex(txid32);
    const Shard &shard = shards_[sidx];
    if (shard.spent_count.load(std::memory_order_relaxed) == 0) {
        return false;
    }
    const uint64_t fp = ComputeFingerprint(txid32, index);
    const auto [w1, m1] = BloomBit1(fp);
    if ((shard.spent_bloom[w1].load(std::memory_order_acquire) & m1) == 0) {
        return false;
    }
    const auto [w2, m2] = BloomBit2(fp);
    if ((shard.spent_bloom[w2].load(std::memory_order_acquire) & m2) == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(shard.mutex);
    return shard.spent_set.Contains(fp);
}

bool UtxoFastFilter::AddUnspent(const uint8_t *txid32, uint32_t index) {
    const size_t sidx = ShardIndex(txid32);
    const uint64_t fp = ComputeFingerprint(txid32, index);
    Shard &shard = shards_[sidx];
    std::lock_guard<std::mutex> lock(shard.mutex);
    if (!shard.unspent_outpoints.insert(MakeOutpoint(txid32, index)).second) {
        return false;
    }
    shard.unspent_set.Insert(fp);
    {
        shard.unspent_count.store(shard.unspent_outpoints.size(),
                                  std::memory_order_relaxed);
    }
    const auto [w1, m1] = BloomBit1(fp);
    const auto [w2, m2] = BloomBit2(fp);
    shard.unspent_bloom[w1].fetch_or(m1, std::memory_order_release);
    shard.unspent_bloom[w2].fetch_or(m2, std::memory_order_release);
    return true;
}

bool UtxoFastFilter::RemoveUnspent(const uint8_t *txid32, uint32_t index) {
    const size_t sidx = ShardIndex(txid32);
    const uint64_t fp = ComputeFingerprint(txid32, index);
    Shard &shard = shards_[sidx];
    std::lock_guard<std::mutex> lock(shard.mutex);
    if (!shard.unspent_outpoints.erase(MakeOutpoint(txid32, index))) {
        return false;
    }
    shard.unspent_set.Erase(fp);
    {
        shard.unspent_count.store(shard.unspent_outpoints.size(),
                                  std::memory_order_relaxed);
        shard.RebuildUnspentBloomLocked();
    }
    return true;
}

bool UtxoFastFilter::ContainsUnspent(const uint8_t *txid32,
                                     uint32_t index) const noexcept {
    const size_t sidx = ShardIndex(txid32);
    const Shard &shard = shards_[sidx];
    if (shard.unspent_count.load(std::memory_order_relaxed) == 0) {
        return false;
    }
    const uint64_t fp = ComputeFingerprint(txid32, index);
    const auto [w1, m1] = BloomBit1(fp);
    if ((shard.unspent_bloom[w1].load(std::memory_order_acquire) & m1) == 0) {
        return false;
    }
    const auto [w2, m2] = BloomBit2(fp);
    if ((shard.unspent_bloom[w2].load(std::memory_order_acquire) & m2) == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(shard.mutex);
    return shard.unspent_set.Contains(fp);
}

void UtxoFastFilter::ClearMempool() {
    for (Shard &shard : shards_) {
        std::lock_guard<std::mutex> lock(shard.mutex);
        shard.spent_outpoints.clear();
        shard.spent_set.Clear();
        shard.spent_count.store(0, std::memory_order_relaxed);
        for (auto &w : shard.spent_bloom) {
            w.store(0ULL, std::memory_order_release);
        }
    }
}

void UtxoFastFilter::ClearAll() {
    chain_uhs_authoritative_.store(false, std::memory_order_release);
    for (Shard &shard : shards_) {
        std::lock_guard<std::mutex> lock(shard.mutex);
        shard.spent_outpoints.clear();
        shard.spent_set.Clear();
        shard.unspent_outpoints.clear();
        shard.unspent_set.Clear();
        shard.spent_count.store(0, std::memory_order_relaxed);
        shard.unspent_count.store(0, std::memory_order_relaxed);
        for (auto &w : shard.spent_bloom) {
            w.store(0ULL, std::memory_order_release);
        }
        for (auto &w : shard.unspent_bloom) {
            w.store(0ULL, std::memory_order_release);
        }
    }
}

size_t UtxoFastFilter::GetMempoolSpentCount() const noexcept {
    size_t total = 0;
    for (const Shard &shard : shards_) {
        total += shard.spent_count.load(std::memory_order_relaxed);
    }
    return total;
}

size_t UtxoFastFilter::GetUnspentCount() const noexcept {
    size_t total = 0;
    for (const Shard &shard : shards_) {
        total += shard.unspent_count.load(std::memory_order_relaxed);
    }
    return total;
}

} // namespace lotus::v2
