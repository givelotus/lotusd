// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPTCACHE_H
#define BITCOIN_SCRIPT_SCRIPTCACHE_H

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <shared_mutex>

#include <crypto/common.h>
#include <cuckoocache.h>
#include <uint256.h>
#include <util/hasher.h>

class CTransaction;

/**
 * The script cache is a map using a key/value element, that caches the
 * success of executing a specific transaction's input scripts under a
 * specific set of flags, along with any associated information learned
 * during execution.
 *
 * The key is slightly shorter than a power-of-two size to make room for
 * the value.
 */
class ScriptCacheKey {
    std::array<uint8_t, 28> data;

public:
    ScriptCacheKey() = default;
    ScriptCacheKey(const ScriptCacheKey &rhs) = default;
    ScriptCacheKey(const CTransaction &tx, uint32_t flags, CSHA256 &&hasher);

    ScriptCacheKey &operator=(const ScriptCacheKey &rhs) = default;

    bool operator==(const ScriptCacheKey &rhs) const {
        return rhs.data == data;
    }

    const uint8_t *begin() const noexcept { return data.data(); }

    friend class ScriptCacheHasher;
};

/**
 * In future if many more values are added, it should be considered to
 * expand the element size to 64 bytes (with padding the spare space as
 * needed) so the key can be long. Shortening the key too much risks
 * opening ourselves up to consensus-failing collisions, however it should
 * be noted that our cache nonce is private and unique, so collisions would
 * affect only one node and attackers have no way of offline-preparing a
 * collision attack even on short keys.
 */
struct ScriptCacheElement {
    using KeyType = ScriptCacheKey;

    KeyType key;
    int nSigChecks;

    ScriptCacheElement() = default;

    ScriptCacheElement(const KeyType &keyIn, int nSigChecksIn)
        : key(keyIn), nSigChecks(nSigChecksIn) {}

    const KeyType &getKey() const { return key; }
};

static_assert(sizeof(ScriptCacheElement) == 32,
              "ScriptCacheElement should be 32 bytes");

class ScriptCacheHasher {
public:
    template <uint8_t hash_select>
    uint32_t operator()(const ScriptCacheKey &k) const {
        static_assert(hash_select < 8, "only has 8 hashes available.");

        const auto &d = k.data;

        static_assert(sizeof(d) == 28,
                      "modify the following if key size changes");

        uint32_t u;
        static_assert(sizeof(u) == 4 && sizeof(d[0]) == 1, "basic assumptions");
        if (hash_select < 7) {
            std::memcpy(&u, d.data() + 4 * hash_select, 4);
        } else {
            // We are required to produce 8 subhashes, and all bytes have
            // been used once. We re-use the bytes but mix together different
            // entries (and flip the order) to get a new, distinct value.
            uint8_t arr[4];
            arr[0] = d[3] ^ d[7] ^ d[11] ^ d[15];
            arr[1] = d[6] ^ d[10] ^ d[14] ^ d[18];
            arr[2] = d[9] ^ d[13] ^ d[17] ^ d[21];
            arr[3] = d[12] ^ d[16] ^ d[20] ^ d[24];
            std::memcpy(&u, arr, 4);
        }
        return u;
    }
};

// DoS prevention: limit cache size to 32MiB (over 1000000 entries on 64-bit
// systems). Due to how we count cache size, actual memory usage is slightly
// more (~32.25 MiB)
static constexpr size_t DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES{32 << 20};

/**
 * Sharded script execution cache with 16 cacheline-aligned std::shared_mutex
 * shards (matching SignatureCache), enabling concurrent lock-free/shared-lock
 * script cache lookups and updates across worker threads without cs_main.
 */
class ScriptExecutionCache {
private:
    static constexpr size_t kNumShards = 16;
    using map_type = CuckooCache::cache<ScriptCacheElement, ScriptCacheHasher>;

    struct alignas(64) Shard {
        mutable std::shared_mutex mutex;
        map_type cache;
        std::atomic<bool> has_entries{false};
    };
    std::array<Shard, kNumShards> m_shards;

    static size_t ShardIndex(const ScriptCacheKey &key) noexcept {
        return static_cast<size_t>(ReadLE64(key.begin())) & (kNumShards - 1);
    }

public:
    ScriptExecutionCache() = default;
    ScriptExecutionCache(const ScriptExecutionCache &) = delete;
    ScriptExecutionCache &operator=(const ScriptExecutionCache &) = delete;

    std::pair<size_t, size_t> setup_bytes(size_t max_size_bytes) {
        const size_t per_shard_bytes =
            std::max<size_t>(1, max_size_bytes / kNumShards);
        size_t total_elems = 0;
        size_t total_approx_bytes = 0;
        for (auto &shard : m_shards) {
            std::unique_lock<std::shared_mutex> lock(shard.mutex);
            const auto [num_elems, approx_size_bytes] =
                shard.cache.setup_bytes(per_shard_bytes);
            total_elems += num_elems;
            total_approx_bytes += approx_size_bytes;
            shard.has_entries.store(false, std::memory_order_release);
        }
        return {total_elems, total_approx_bytes};
    }

    bool get(ScriptCacheElement &elem, const bool erase) const {
        const Shard &const_shard = m_shards[ShardIndex(elem.getKey())];
        if (!const_shard.has_entries.load(std::memory_order_acquire)) {
            return false;
        }
        Shard &shard = const_cast<Shard &>(const_shard);
        if (erase) {
            std::unique_lock<std::shared_mutex> lock(shard.mutex);
            return shard.cache.get(elem, /*erase=*/true);
        }
        std::shared_lock<std::shared_mutex> lock(shard.mutex);
        return shard.cache.get(elem, /*erase=*/false);
    }

    void insert(const ScriptCacheElement &elem) {
        Shard &shard = m_shards[ShardIndex(elem.getKey())];
        std::unique_lock<std::shared_mutex> lock(shard.mutex);
        shard.cache.insert(elem);
        shard.has_entries.store(true, std::memory_order_release);
    }
};

#endif // BITCOIN_SCRIPT_SCRIPTCACHE_H
