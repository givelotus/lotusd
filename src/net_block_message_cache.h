// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_BLOCK_MESSAGE_CACHE_H
#define BITCOIN_NET_BLOCK_MESSAGE_CACHE_H

#include <hash.h>
#include <primitives/blockhash.h>
#include <protocol.h>
#include <sync.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <optional>
#include <vector>

/**
 * Serialized `block` message payloads recently served, with their P2P
 * checksums, so that further peers asking for the same block (typically a
 * new tip) get a copy of the bytes instead of another disk read or
 * serialization plus a double-SHA256 of the whole block.
 *
 * Bounded by the bytes of the kept payloads and by an entry count. The
 * bytes are what is stored on disk and sent on the wire for that block
 * hash; the block header commits to its transactions, so one hash has one
 * valid serialization.
 */
class BlockMessageCache {
public:
    struct Message {
        std::shared_ptr<const std::vector<uint8_t>> data;
        std::array<uint8_t, CMessageHeader::CHECKSUM_SIZE> checksum;
    };
    struct Stats {
        uint64_t hits{0};
        uint64_t misses{0};
        size_t bytes{0};
        size_t entries{0};
    };

    explicit BlockMessageCache(size_t max_bytes, size_t max_entries = 4)
        : m_max_bytes{max_bytes}, m_max_entries{max_entries} {}

    bool Enabled() const { return m_max_bytes > 0 && m_max_entries > 0; }

    std::optional<Message> Get(const BlockHash &hash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        for (auto it = m_lru.begin(); it != m_lru.end(); ++it) {
            if (it->hash == hash) {
                ++m_stats.hits;
                m_lru.splice(m_lru.begin(), m_lru, it);
                return it->message;
            }
        }
        ++m_stats.misses;
        return std::nullopt;
    }

    /** Checksum `data` and keep it (if it fits); returns the message */
    Message Put(const BlockHash &hash, std::vector<uint8_t> &&data)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        Message message;
        const uint256 sum{Hash(data)};
        std::memcpy(message.checksum.data(), sum.begin(),
                    message.checksum.size());
        message.data =
            std::make_shared<const std::vector<uint8_t>>(std::move(data));
        const size_t size{message.data->size()};
        LOCK(m_mutex);
        if (size > m_max_bytes || !m_max_entries) {
            return message;
        }
        for (auto it = m_lru.begin(); it != m_lru.end(); ++it) {
            if (it->hash == hash) {
                // Concurrent miss: keep the first copy.
                return it->message;
            }
        }
        while (!m_lru.empty() && (m_stats.bytes + size > m_max_bytes ||
                                  m_lru.size() >= m_max_entries)) {
            m_stats.bytes -= m_lru.back().message.data->size();
            m_lru.pop_back();
        }
        m_lru.push_front({hash, message});
        m_stats.bytes += size;
        return message;
    }

    Stats GetStats() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        Stats stats{m_stats};
        stats.entries = m_lru.size();
        return stats;
    }

private:
    struct Entry {
        BlockHash hash;
        Message message;
    };
    mutable Mutex m_mutex;
    const size_t m_max_bytes;
    const size_t m_max_entries;
    std::list<Entry> m_lru GUARDED_BY(m_mutex);
    Stats m_stats GUARDED_BY(m_mutex);
};

#endif // BITCOIN_NET_BLOCK_MESSAGE_CACHE_H
