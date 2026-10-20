// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sigcache.h>

#include <node/metrics.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <lotus_v2/signing.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <vector>

namespace {
uint64_t NextTlsCacheOwner() noexcept {
    static std::atomic<uint64_t> next{1};
    uint64_t owner = next.load(std::memory_order_relaxed);
    while (owner != std::numeric_limits<uint64_t>::max()) {
        if (next.compare_exchange_weak(owner, owner + 1,
                                       std::memory_order_relaxed)) return owner;
    }
    // Never wrap and reuse an identity, even in a theoretically exhausted process.
    std::terminate();
}

struct TlsSigCache {
    static constexpr size_t kMask = 4095;
    struct Slot {
        uint64_t owner{0};
        uint256 entry{};
    };
    std::array<Slot, kMask + 1> slots{};

    static size_t Index(const uint256 &entry) noexcept {
        return static_cast<size_t>(ReadLE64(entry.begin())) & kMask;
    }

    bool Contains(const SignatureCache *owner,
                  const uint256 &entry) const noexcept {
        const Slot &s = slots[Index(entry)];
        return s.owner == owner->TlsOwner() && s.entry == entry;
    }

    void Insert(const SignatureCache *owner, const uint256 &entry) noexcept {
        Slot &s = slots[Index(entry)];
        s.owner = owner->TlsOwner();
        s.entry = entry;
    }

    void Erase(const SignatureCache *owner, const uint256 &entry) noexcept {
        Slot &s = slots[Index(entry)];
        if (s.owner == owner->TlsOwner() && s.entry == entry) {
            s.owner = 0;
        }
    }
};

thread_local TlsSigCache g_tls_sigcache;
} // namespace

SignatureCache::SignatureCache(const size_t max_size_bytes)
    : m_tls_owner(NextTlsCacheOwner()) {
    uint256 nonce = GetRandHash();
    // We want the nonce to be 64 bytes long to force the hasher to process
    // this chunk, which makes later hash computations more efficient. We
    // just write our 32-byte entropy twice to fill the 64 bytes.
    m_salted_hasher.Write(nonce.begin(), 32);
    m_salted_hasher.Write(nonce.begin(), 32);

    const size_t per_shard_bytes = std::max<size_t>(1, max_size_bytes / kNumShards);
    size_t total_elems = 0;
    size_t total_approx_bytes = 0;
    for (auto &shard : m_shards) {
        const auto [num_elems, approx_size_bytes] =
            shard.setValid.setup_bytes(per_shard_bytes);
        total_elems += num_elems;
        total_approx_bytes += approx_size_bytes;
    }
    LogInfoEvent(
        BCLog::ALL, "signature_cache_initialized",
        "Using {cache_allocated_mib} MiB out of {cache_requested_mib} MiB requested for signature cache, able to store {cache_capacity} elements")
        .Field(BCLog::LogField::CacheAllocatedMiB, total_approx_bytes >> 20)
        .Field(BCLog::LogField::CacheRequestedMiB, max_size_bytes >> 20)
        .Field(BCLog::LogField::CacheCapacity, total_elems);
}

void SignatureCache::ComputeEntry(uint256 &entry, const uint256 &hash,
                                  const std::vector<uint8_t> &vchSig,
                                  const CPubKey &pubkey) const {
    CSHA256 hasher = m_salted_hasher;
    hasher.Write(hash.begin(), 32)
        .Write(pubkey.data(), pubkey.size())
        .Write(vchSig.data(), vchSig.size())
        .Finalize(entry.begin());
}

bool SignatureCache::Get(const uint256 &entry, const bool erase) {
    if (!erase && g_tls_sigcache.Contains(this, entry)) {
        node::CountValidationCacheLookup(/*script_execution=*/false, true);
        return true;
    }
    if (erase) {
        g_tls_sigcache.Erase(this, entry);
    }
    Shard &shard =
        m_shards[static_cast<size_t>(ReadLE64(entry.begin())) & (kNumShards - 1)];
    if (!shard.has_entries.load(std::memory_order_acquire)) {
        node::CountValidationCacheLookup(/*script_execution=*/false, false);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(shard.mutex);
    const bool found = shard.setValid.contains(entry, erase);
    if (found && !erase) {
        g_tls_sigcache.Insert(this, entry);
    }
    node::CountValidationCacheLookup(/*script_execution=*/false, found);
    return found;
}

void SignatureCache::Set(const uint256 &entry) {
    g_tls_sigcache.Insert(this, entry);
    Shard &shard =
        m_shards[static_cast<size_t>(ReadLE64(entry.begin())) & (kNumShards - 1)];
    std::unique_lock<std::shared_mutex> lock(shard.mutex);
    shard.setValid.insert(entry);
    shard.has_entries.store(true, std::memory_order_release);
}

void SignatureCache::SetBatch(const lotus::v2::BatchSigCollector &collector) {
    const auto &items = collector.LegacyItems();
    uint32_t touched_mask = 0;
    for (const auto &item : items) {
        if (item.store_in_cache) {
            const size_t s = static_cast<size_t>(ReadLE64(item.cache_entry.data())) &
                             (kNumShards - 1);
            touched_mask |= (uint32_t{1} << s);
        }
    }
    if (touched_mask == 0) {
        return;
    }
    uint256 entry;
    for (size_t s = 0; s < kNumShards; ++s) {
        if ((touched_mask & (uint32_t{1} << s)) == 0) {
            continue;
        }
        Shard &shard = m_shards[s];
        std::unique_lock<std::shared_mutex> lock(shard.mutex);
        for (const auto &item : items) {
            if (!item.store_in_cache) {
                continue;
            }
            const size_t item_s =
                static_cast<size_t>(ReadLE64(item.cache_entry.data())) &
                (kNumShards - 1);
            if (item_s != s) {
                continue;
            }
            std::memcpy(entry.begin(), item.cache_entry.data(), 32);
            g_tls_sigcache.Insert(this, entry);
            shard.setValid.insert(entry);
        }
        shard.has_entries.store(true, std::memory_order_release);
    }
}

template <typename F>
bool RunMemoizedCheck(SignatureCache &signatureCache,
                      const std::vector<uint8_t> &vchSig, const CPubKey &pubkey,
                      const uint256 &sighash, bool storeOrErase, const F &fun) {
    uint256 entry;
    signatureCache.ComputeEntry(entry, sighash, vchSig, pubkey);
    if (signatureCache.Get(entry, !storeOrErase)) {
        return true;
    }
    if (!fun()) {
        return false;
    }
    if (storeOrErase) {
        signatureCache.Set(entry);
    }
    return true;
}

bool CachingTransactionSignatureChecker::IsCached(
    const std::vector<uint8_t> &vchSig, const CPubKey &pubkey,
    const uint256 &sighash) const {
    return RunMemoizedCheck(m_signature_cache, vchSig, pubkey, sighash, true,
                            [] { return false; });
}

bool CachingTransactionSignatureChecker::VerifySignature(
    const std::vector<uint8_t> &vchSig, const CPubKey &pubkey,
    const uint256 &sighash) const {
    if (m_sig_collector != nullptr && vchSig.size() == 64) {
        if (!pubkey.IsValid()) {
            return false;
        }
        uint256 entry;
        m_signature_cache.ComputeEntry(entry, sighash, vchSig, pubkey);
        if (m_signature_cache.Get(entry, !store)) {
            return true;
        }
        return m_sig_collector->AddLegacySchnorr(
            std::span<const uint8_t>(pubkey.data(), pubkey.size()),
            std::span<const uint8_t>(vchSig.data(), vchSig.size()),
            sighash.begin(), entry.begin(), store);
    }
    return RunMemoizedCheck(
        m_signature_cache, vchSig, pubkey, sighash, store, [&] {
            return TransactionSignatureChecker::VerifySignature(vchSig, pubkey,
                                                                sighash);
        });
}
