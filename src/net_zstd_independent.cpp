// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_zstd_independent.h>

#include <crypto/common.h>
#include <hash.h>
#include <net_zstd_dict.h>
#include <node/metrics.h>
#include <primitives/block.h>
#include <protocol.h>
#include <streams.h>

#include <zstd.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <tuple>

namespace {
size_t Check(size_t result) {
    if (ZSTD_isError(result)) {
        throw std::runtime_error(ZSTD_getErrorName(result));
    }
    return result;
}

using CCtxPtr = std::unique_ptr<ZSTD_CCtx, size_t (*)(ZSTD_CCtx *)>;
using DCtxPtr = std::unique_ptr<ZSTD_DCtx, size_t (*)(ZSTD_DCtx *)>;

//! The P2P header's command field, if this is a block message
bool IsBlockMessage(Span<const uint8_t> header) {
    if (header.size() != CMessageHeader::HEADER_SIZE) {
        return false;
    }
    char command[CMessageHeader::MESSAGE_TYPE_SIZE];
    std::memcpy(command, header.data() + CMessageHeader::MESSAGE_START_SIZE,
                sizeof(command));
    return std::string_view{command, strnlen(command, sizeof(command))} ==
           NetMsgType::BLOCK;
}
} // namespace

std::vector<uint8_t> CompressP2PIndependent(Span<const uint8_t> header,
                                            Span<const uint8_t> payload) {
    CCtxPtr ctx{ZSTD_createCCtx(), &ZSTD_freeCCtx};
    if (!ctx) {
        throw std::bad_alloc();
    }
    // The CDict carries the compression level. Same window as the streams.
    Check(ZSTD_CCtx_refCDict(ctx.get(), GetP2PZstdCDict()));
    Check(ZSTD_CCtx_setParameter(ctx.get(), ZSTD_c_windowLog,
                                 P2P_ZSTD_WINDOW_LOG));
    Check(ZSTD_CCtx_setParameter(ctx.get(), ZSTD_c_contentSizeFlag, 1));
    Check(ZSTD_CCtx_setParameter(ctx.get(), ZSTD_c_checksumFlag, 0));
    const size_t total{header.size() + payload.size()};
    Check(ZSTD_CCtx_setPledgedSrcSize(ctx.get(), total));
    std::vector<uint8_t> frame(P2P_INDEPENDENT_ENVELOPE +
                               ZSTD_compressBound(total));
    frame[0] = P2P_INDEPENDENT_FORMAT;
    WriteLE32(frame.data() + 1, P2P_INDEPENDENT_DICT_VERSION);
    ZSTD_outBuffer output{frame.data(), frame.size(), P2P_INDEPENDENT_ENVELOPE};
    ZSTD_inBuffer input{header.data(), header.size(), 0};
    while (input.pos < input.size) {
        Check(
            ZSTD_compressStream2(ctx.get(), &output, &input, ZSTD_e_continue));
    }
    input = ZSTD_inBuffer{payload.data(), payload.size(), 0};
    // Output room is compressBound, so this ends in one call; loop anyway.
    while (Check(ZSTD_compressStream2(ctx.get(), &output, &input,
                                      ZSTD_e_end)) != 0) {
        if (output.pos == output.size) {
            throw std::runtime_error("independent frame exceeds bound");
        }
    }
    frame.resize(output.pos);
    // Do not keep compressBound-sized storage for a well compressed frame.
    // Cache accounting uses capacity, as shrink_to_fit is nonbinding.
    frame.shrink_to_fit();
    return frame;
}

void DecompressP2PIndependent(Span<const uint8_t> frame,
                              std::vector<uint8_t> &out, size_t maximum) {
    if (frame.size() < P2P_INDEPENDENT_ENVELOPE ||
        frame[0] != P2P_INDEPENDENT_FORMAT ||
        ReadLE32(frame.data() + 1) != P2P_INDEPENDENT_DICT_VERSION) {
        throw std::runtime_error(
            "unsupported independent frame format/dictionary version");
    }
    frame = frame.subspan(P2P_INDEPENDENT_ENVELOPE);
    // Magic plus frame header descriptor; skippable frames have another magic.
    if (frame.size() < 6 || ReadLE32(frame.data()) != ZSTD_MAGICNUMBER) {
        throw std::runtime_error("independent payload is not a zstd frame");
    }
    const size_t frame_size{
        Check(ZSTD_findFrameCompressedSize(frame.data(), frame.size()))};
    if (frame_size != frame.size()) {
        throw std::runtime_error("independent frame has trailing data");
    }
    const unsigned long long size{
        ZSTD_getFrameContentSize(frame.data(), frame.size())};
    if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN ||
        size > maximum) {
        throw std::runtime_error("invalid independent frame content size");
    }
    // libzstd may skip its window allocation for a complete single-segment
    // frame, so check the declared window before allocating any output, as
    // well as limiting the decoder. Frame header descriptor bit 5 is
    // single-segment (window = content size); otherwise the next byte is the
    // window descriptor: 2^(10 + exponent) plus mantissa eighths.
    const uint64_t window_limit{uint64_t{1} << P2P_ZSTD_MAX_WINDOW_LOG};
    const bool single_segment{(frame[4] & 0x20) != 0};
    uint64_t window_size{size};
    if (!single_segment) {
        const uint64_t base{uint64_t{1} << (10 + (frame[5] >> 3))};
        window_size = base + (base / 8) * (frame[5] & 7);
    }
    if (window_size > window_limit) {
        throw std::runtime_error("independent frame window exceeds limit");
    }
    DCtxPtr ctx{ZSTD_createDCtx(), &ZSTD_freeDCtx};
    if (!ctx) {
        throw std::bad_alloc();
    }
    Check(ZSTD_DCtx_refDDict(ctx.get(), GetP2PZstdDDict()));
    Check(ZSTD_DCtx_setParameter(ctx.get(), ZSTD_d_windowLogMax,
                                 P2P_ZSTD_MAX_WINDOW_LOG));
    const size_t start{out.size()};
    // One spare byte detects content beyond the declared size.
    out.resize(start + size + 1);
    try {
        ZSTD_inBuffer input{frame.data(), frame.size(), 0};
        ZSTD_outBuffer output{out.data() + start, size_t(size) + 1, 0};
        size_t remaining{1};
        while (remaining) {
            const size_t in_before{input.pos};
            const size_t out_before{output.pos};
            remaining =
                Check(ZSTD_decompressStream(ctx.get(), &output, &input));
            if (remaining &&
                (input.pos == input.size || output.pos == output.size ||
                 (input.pos == in_before && output.pos == out_before))) {
                throw std::runtime_error("incomplete independent frame");
            }
        }
        if (input.pos != input.size || output.pos != size) {
            throw std::runtime_error("independent frame length mismatch");
        }
    } catch (...) {
        out.resize(start);
        throw;
    }
    out.resize(start + size);
}

bool P2PIndependentFrameCache::Key::operator<(const Key &o) const {
    return std::tie(block_hash, payload_hash, header, dict_version) <
           std::tie(o.block_hash, o.payload_hash, o.header, o.dict_version);
}

P2PIndependentFrameCache::P2PIndependentFrameCache(size_t max_bytes,
                                                   size_t max_entries)
    : m_max_bytes{max_bytes}, m_max_entries{max_entries} {}

P2PIndependentFrameCache::Frame
P2PIndependentFrameCache::Fresh(Span<const uint8_t> header,
                                Span<const uint8_t> payload) {
    auto frame{std::make_shared<const std::vector<uint8_t>>(
        CompressP2PIndependent(header, payload))};
    if (m_report_metrics) {
        if (auto *m{node::GetNodeMetrics()}) {
            m->p2p_compress_once_encodes.Inc();
        }
    }
    return frame;
}

void P2PIndependentFrameCache::PublishLocked() {
    if (!m_report_metrics) {
        return;
    }
    if (auto *m{node::GetNodeMetrics()}) {
        m->p2p_compress_once_cache_bytes.Set(double(m_stats.bytes));
        m->p2p_compress_once_cache_entries.Set(double(m_cache.size()));
    }
}

void P2PIndependentFrameCache::EvictLocked(size_t incoming) {
    uint64_t evicted{0};
    while (!m_lru.empty() &&
           (m_stats.bytes + incoming > m_max_bytes ||
            m_cache.size() + (incoming ? 1 : 0) > m_max_entries)) {
        const auto old{m_cache.find(m_lru.back())};
        m_stats.bytes -= old->second.frame->capacity();
        m_cache.erase(old);
        m_lru.pop_back();
        ++evicted;
    }
    m_stats.evictions += evicted;
    if (evicted && m_report_metrics) {
        if (auto *m{node::GetNodeMetrics()}) {
            m->p2p_compress_once_cache_evictions.Add(0, evicted);
        }
    }
}

P2PIndependentFrameCache::Frame
P2PIndependentFrameCache::Encode(Span<const uint8_t> header,
                                 Span<const uint8_t> payload) {
    if (!IsBlockMessage(header)) {
        const auto frame{Fresh(header, payload)};
        WITH_LOCK(m_mutex, ++m_stats.encodes);
        return frame;
    }
    Key key;
    try {
        SpanReader reader{payload};
        CBlockHeader block_header;
        reader >> block_header;
        key.block_hash = block_header.GetHash();
    } catch (const std::exception &) {
        // Not a block body: nothing to share.
        const auto frame{Fresh(header, payload)};
        WITH_LOCK(m_mutex, ++m_stats.encodes);
        return frame;
    }
    std::copy(header.begin(), header.end(), key.header.begin());
    key.dict_version = P2P_INDEPENDENT_DICT_VERSION;
    // Encode accepts arbitrary bytes, not only validated canonical blocks.
    key.payload_hash = Hash(payload);

    std::promise<Frame> promise;
    {
        WAIT_LOCK(m_mutex, lock);
        if (const auto found{m_cache.find(key)}; found != m_cache.end()) {
            ++m_stats.hits;
            m_lru.splice(m_lru.begin(), m_lru, found->second.position);
            if (m_report_metrics) {
                if (auto *m{node::GetNodeMetrics()}) {
                    m->p2p_compress_once_cache_hits.Inc();
                }
            }
            return found->second.frame;
        }
        if (const auto pending{m_pending.find(key)};
            pending != m_pending.end()) {
            // Another peer is compressing this block: share its result.
            auto future{pending->second};
            ++m_stats.hits;
            if (m_report_metrics) {
                if (auto *m{node::GetNodeMetrics()}) {
                    m->p2p_compress_once_cache_hits.Inc();
                }
            }
            REVERSE_LOCK(lock);
            return future.get();
        }
        ++m_stats.misses;
        if (m_report_metrics) {
            if (auto *m{node::GetNodeMetrics()}) {
                m->p2p_compress_once_cache_misses.Inc();
            }
        }
        m_pending.emplace(key, promise.get_future().share());
    }

    Frame frame;
    try {
        frame = Fresh(header, payload);
    } catch (...) {
        promise.set_exception(std::current_exception());
        WITH_LOCK(m_mutex, m_pending.erase(key));
        throw;
    }
    {
        LOCK(m_mutex);
        m_pending.erase(key);
        ++m_stats.encodes;
        const size_t allocated{frame->capacity()};
        if (allocated <= m_max_bytes && m_max_entries) {
            EvictLocked(allocated);
            m_lru.push_front(key);
            m_cache.emplace(key, Entry{frame, m_lru.begin()});
            m_stats.bytes += allocated;
        }
        PublishLocked();
    }
    promise.set_value(frame);
    return frame;
}

void P2PIndependentFrameCache::SetMaxBytes(size_t max_bytes) {
    LOCK(m_mutex);
    m_max_bytes = max_bytes;
    EvictLocked(0);
    PublishLocked();
}

P2PIndependentFrameCache::Stats P2PIndependentFrameCache::GetStats() const {
    LOCK(m_mutex);
    Stats stats{m_stats};
    stats.entries = m_cache.size();
    return stats;
}

P2PIndependentFrameCache &GetP2PIndependentFrameCache() {
    static P2PIndependentFrameCache cache;
    // Set once, during the thread-safe initialization of this static.
    static const bool reports{cache.m_report_metrics = true};
    (void)reports;
    return cache;
}
