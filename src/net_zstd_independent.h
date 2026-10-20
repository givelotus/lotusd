// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_ZSTD_INDEPENDENT_H
#define BITCOIN_NET_ZSTD_INDEPENDENT_H

#include <span.h>
#include <sync.h>
#include <uint256.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <vector>

/**
 * Independent ("compress once, serve many") P2P frames of the zstd
 * WebSocket subprotocols, p2p-zstd-v1 and p2p-zstd (see
 * doc/p2p-websocket.md).
 *
 * An independent frame is `[format byte = 1][dictionary version LE32]
 * [one zstd frame]`. The zstd frame records its content size and uses only
 * the immutable prebaked P2P dictionary (P2P_ZSTD_DICT_V1), never a
 * connection's streaming history, so the same bytes can be sent to every
 * zstd peer. Ported from the V2 tier (patch 095).
 */

//! Format byte of an independent frame
static constexpr uint8_t P2P_INDEPENDENT_FORMAT{1};
//! Version of P2P_ZSTD_DICT_V1 as carried in independent frames
static constexpr uint32_t P2P_INDEPENDENT_DICT_VERSION{1};
//! Format byte + dictionary version
static constexpr size_t P2P_INDEPENDENT_ENVELOPE{5};

//! Default -p2pcompressoncethreshold: smallest block message (P2P header
//! included) sent as an independent frame; 0 never sends them
static constexpr int64_t DEFAULT_P2P_COMPRESS_ONCE_THRESHOLD{64 * 1024};
//! Default -p2pcompressoncecache, MiB of retained encoded block frames
static constexpr int64_t DEFAULT_P2P_COMPRESS_ONCE_CACHE_MB{128};
//! Cached block frames, whatever their size
static constexpr size_t P2P_COMPRESS_ONCE_CACHE_ENTRIES{64};

//! Outgoing policy only: independent frames from peers are accepted
//! whatever its value.
inline std::atomic<size_t> g_p2p_compress_once_threshold{
    size_t(DEFAULT_P2P_COMPRESS_ONCE_THRESHOLD)};

/**
 * Compress one complete P2P message (24-byte header, then payload) as an
 * independent frame. Throws std::runtime_error or std::bad_alloc.
 */
std::vector<uint8_t> CompressP2PIndependent(Span<const uint8_t> header,
                                            Span<const uint8_t> payload);

/**
 * Decode an independent frame, appending the P2P bytes to `out`. Rejects
 * (std::runtime_error) unknown format/dictionary versions, frames without a
 * content size or whose content size exceeds `maximum`, windows above
 * 2^P2P_ZSTD_MAX_WINDOW_LOG, skippable, truncated, concatenated and
 * trailing data. Nothing is appended on error beyond a bounded scratch
 * region that is removed again.
 */
void DecompressP2PIndependent(Span<const uint8_t> frame,
                              std::vector<uint8_t> &out, size_t maximum);

/**
 * Shared LRU cache of independent frames of block messages, bounded by the
 * allocated bytes of its frames and by an entry count. Keys are the block
 * hash plus a full double-SHA256 payload digest, the exact 24-byte P2P
 * header and the dictionary version. The short P2P checksum alone is not
 * sufficient to identify arbitrary supplied payloads. Peers
 * asking for a block that is being compressed wait for that compression
 * instead of repeating it. Handed-out frames stay valid after eviction.
 */
class P2PIndependentFrameCache {
public:
    using Frame = std::shared_ptr<const std::vector<uint8_t>>;

    struct Stats {
        uint64_t hits{0};
        uint64_t misses{0};
        uint64_t evictions{0};
        //! Compressions done (cache misses plus uncacheable messages)
        uint64_t encodes{0};
        size_t bytes{0};
        size_t entries{0};
    };

    explicit P2PIndependentFrameCache(
        size_t max_bytes = size_t(DEFAULT_P2P_COMPRESS_ONCE_CACHE_MB) << 20,
        size_t max_entries = P2P_COMPRESS_ONCE_CACHE_ENTRIES);

    /**
     * The independent frame of a P2P message: from the cache for a block
     * message, else freshly compressed. `header` is the 24-byte P2P header.
     */
    Frame Encode(Span<const uint8_t> header, Span<const uint8_t> payload)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Change the byte budget, evicting as needed */
    void SetMaxBytes(size_t max_bytes) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    Stats GetStats() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Key {
        uint256 block_hash;
        uint256 payload_hash;
        std::array<uint8_t, 24> header;
        uint32_t dict_version;
        bool operator<(const Key &o) const;
    };
    struct Entry {
        Frame frame;
        std::list<Key>::iterator position;
    };

    Frame Fresh(Span<const uint8_t> header, Span<const uint8_t> payload);
    void EvictLocked(size_t incoming) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void PublishLocked() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    mutable Mutex m_mutex;
    size_t m_max_bytes GUARDED_BY(m_mutex);
    const size_t m_max_entries;
    std::map<Key, Entry> m_cache GUARDED_BY(m_mutex);
    std::list<Key> m_lru GUARDED_BY(m_mutex);
    //! Compressions in progress; other requesters wait on them
    std::map<Key, std::shared_future<Frame>> m_pending GUARDED_BY(m_mutex);
    Stats m_stats GUARDED_BY(m_mutex);
    //! Whether this is the node's shared cache (reports to node metrics)
    bool m_report_metrics{false};
    friend P2PIndependentFrameCache &GetP2PIndependentFrameCache();
};

/** The node's cache, shared by all WebSocket peers */
P2PIndependentFrameCache &GetP2PIndependentFrameCache();

#endif // BITCOIN_NET_ZSTD_INDEPENDENT_H
