// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGCACHE_H
#define BITCOIN_SCRIPT_SIGCACHE_H

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <cuckoocache.h>
#include <script/interpreter.h>
#include <uint256.h>
#include <util/hasher.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <shared_mutex>
#include <vector>

class CPubKey;
class CTransaction;

// DoS prevention: limit cache size to 32MiB (over 1000000 entries on 64-bit
// systems). Due to how we count cache size, actual memory usage is slightly
// more (~32.25 MiB)
static constexpr size_t DEFAULT_SIGNATURE_CACHE_BYTES{32 << 20};

/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class SignatureCache {
private:
    static constexpr size_t kNumShards = 16;
    //! Entries are SHA256(nonce || signature hash || public key || signature):
    CSHA256 m_salted_hasher;
    //! Process-unique lifetime token; TLS slots must not follow reused addresses.
    const uint64_t m_tls_owner;
    typedef CuckooCache::cache<CuckooCache::KeyOnly<uint256>,
                               SignatureCacheHasher>
        map_type;
    struct alignas(64) Shard {
        std::shared_mutex mutex;
        map_type setValid;
        std::atomic<bool> has_entries{false};
    };
    std::array<Shard, kNumShards> m_shards;

public:
    //! Internal TLS ownership discriminator; distinct across cache lifetimes.
    uint64_t TlsOwner() const noexcept { return m_tls_owner; }
    SignatureCache(size_t max_size_bytes);

    SignatureCache(const SignatureCache &) = delete;
    SignatureCache &operator=(const SignatureCache &) = delete;

    void ComputeEntry(uint256 &entry, const uint256 &hash,
                      const std::vector<uint8_t> &vchSig,
                      const CPubKey &pubkey) const;

    bool Get(const uint256 &entry, const bool erase);

    void Set(const uint256 &entry);

};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker {
private:
    bool store;
    SignatureCache &m_signature_cache;

    bool IsCached(const std::vector<uint8_t> &vchSig, const CPubKey &vchPubKey,
                  const uint256 &sighash) const;

public:
    CachingTransactionSignatureChecker(const CTransaction *txToIn,
                                       unsigned int nInIn,
                                       const Amount amountIn, bool storeIn,
                                       SignatureCache &signature_cache,
                                       PrecomputedTransactionData &txdataIn)
        : TransactionSignatureChecker(txToIn, nInIn, amountIn, txdataIn),
          store(storeIn), m_signature_cache(signature_cache) {}

    bool VerifySignature(const std::vector<uint8_t> &vchSig,
                         const CPubKey &vchPubKey,
                         const uint256 &sighash) const override;

    friend class TestCachingTransactionSignatureChecker;
};

#endif // BITCOIN_SCRIPT_SIGCACHE_H
