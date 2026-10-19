// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_ZSTD_DICT_H
#define BITCOIN_NET_ZSTD_DICT_H

#include <net_zstd_dict_data.h>
#include <net_zstd_dict_v2_data.h>
#include <span.h>

#include <zstd.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

/**
 * Streaming zstd compression of P2P WebSocket message bodies.
 * Lotus defaults to V2; explicit version 1 preserves the legacy codec.
 *
 * Each direction is a single zstd frame that never ends: every message is
 * compressed with ZSTD_e_flush, so it can be decoded as soon as it arrives,
 * while later messages still reference earlier ones (a warm sliding window
 * across the whole connection). Lotus p2p-v2 streams start primed with
 * P2P_ZSTD_DICT_V2, trained on native message bodies without v1 framing.
 */

//! Compression level of P2P streams (fast; the window does most of the work)
static constexpr int P2P_ZSTD_LEVEL = 1;
//! log2 of the sliding window used when compressing (128 KiB)
static constexpr int P2P_ZSTD_WINDOW_LOG = 17;
//! Largest window accepted from a peer (bounds decoder memory to ~1 MiB)
static constexpr int P2P_ZSTD_MAX_WINDOW_LOG = 20;

//! p2p-v2 fixes the dictionary at version 2; legacy V1 bytes remain immutable.
inline constexpr uint32_t P2P_ZSTD_DICT_VERSION = 2;
inline Span<const uint8_t> GetP2PZstdDictionaryBytes() {
    return {P2P_ZSTD_DICT_V2, sizeof(P2P_ZSTD_DICT_V2)};
}

/** Dictionary shared by all p2p-v2 compressors (created once). */
inline const ZSTD_CDict *GetP2PZstdCDict(uint32_t version = P2P_ZSTD_DICT_VERSION) {
    if (version == 1) {
        static const std::unique_ptr<ZSTD_CDict, size_t (*)(ZSTD_CDict *)> legacy{
            ZSTD_createCDict(P2P_ZSTD_DICT_V1, sizeof(P2P_ZSTD_DICT_V1), P2P_ZSTD_LEVEL),
            &ZSTD_freeCDict};
        return legacy.get();
    }
    if (version != P2P_ZSTD_DICT_VERSION) {
        throw std::invalid_argument("Unsupported P2P zstd dictionary version");
    }
    static const std::unique_ptr<ZSTD_CDict, size_t (*)(ZSTD_CDict *)> cdict{
        ZSTD_createCDict(P2P_ZSTD_DICT_V2, sizeof(P2P_ZSTD_DICT_V2),
                         P2P_ZSTD_LEVEL),
        &ZSTD_freeCDict};
    return cdict.get();
}

/** Dictionary shared by all p2p-v2 decompressors (created once). */
inline const ZSTD_DDict *GetP2PZstdDDict(uint32_t version = P2P_ZSTD_DICT_VERSION) {
    if (version == 1) {
        static const std::unique_ptr<ZSTD_DDict, size_t (*)(ZSTD_DDict *)> legacy{
            ZSTD_createDDict(P2P_ZSTD_DICT_V1, sizeof(P2P_ZSTD_DICT_V1)), &ZSTD_freeDDict};
        return legacy.get();
    }
    if (version != P2P_ZSTD_DICT_VERSION) {
        throw std::invalid_argument("Unsupported P2P zstd dictionary version");
    }
    static const std::unique_ptr<ZSTD_DDict, size_t (*)(ZSTD_DDict *)> ddict{
        ZSTD_createDDict(P2P_ZSTD_DICT_V2, sizeof(P2P_ZSTD_DICT_V2)),
        &ZSTD_freeDDict};
    return ddict.get();
}

/** Bound the compressed wire body for a bounded plain message. Streaming
 * flushes and optional per-message envelopes have 32 bytes of extra slack.
 * This is a limit calculation only; it does not allocate its returned size.
 */
inline uint64_t P2PZstdMaxWireSize(uint64_t plain_limit) {
    return ZSTD_compressBound(static_cast<size_t>(plain_limit)) + uint64_t{32};
}

class P2PZstdSession {
public:
    explicit P2PZstdSession(bool use_dict,
                            uint32_t dictionary_version = P2P_ZSTD_DICT_VERSION)
        : m_cctx{ZSTD_createCCtx(), &ZSTD_freeCCtx},
          m_dctx{ZSTD_createDCtx(), &ZSTD_freeDCtx} {
        if (!m_cctx || !m_dctx) {
            throw std::bad_alloc();
        }
        if (use_dict) {
            // The CDict carries the compression level.
            Check(ZSTD_CCtx_refCDict(m_cctx.get(), GetP2PZstdCDict(dictionary_version)));
            Check(ZSTD_DCtx_refDDict(m_dctx.get(), GetP2PZstdDDict(dictionary_version)));
        } else {
            Check(ZSTD_CCtx_setParameter(m_cctx.get(), ZSTD_c_compressionLevel,
                                         P2P_ZSTD_LEVEL));
        }
        Check(ZSTD_CCtx_setParameter(m_cctx.get(), ZSTD_c_windowLog,
                                     P2P_ZSTD_WINDOW_LOG));
        // The stream never ends, so these would never be written anyway.
        Check(ZSTD_CCtx_setParameter(m_cctx.get(), ZSTD_c_checksumFlag, 0));
        Check(ZSTD_CCtx_setParameter(m_cctx.get(), ZSTD_c_contentSizeFlag, 0));
        Check(ZSTD_DCtx_setParameter(m_dctx.get(), ZSTD_d_windowLogMax,
                                     P2P_ZSTD_MAX_WINDOW_LOG));
    }

    /**
     * Compress `in` as the next chunk of the outgoing stream, appending to
     * `out`. Everything is flushed: the peer can decode all of `in` from
     * `out` alone (plus the earlier chunks).
     */
    void CompressFrame(Span<const uint8_t> in, std::vector<uint8_t> &out) {
        ZSTD_inBuffer input{in.data(), in.size(), 0};
        const size_t start{out.size()};
        size_t written{0};
        while (true) {
            // Room for the rest of the input plus the flush, growing only if
            // zstd reports more pending. Sized to the message, not to
            // ZSTD_CStreamOutSize(): resizing zero-fills, and 128 KiB of it
            // per small message dominated the cost.
            const size_t want{ZSTD_compressBound(input.size - input.pos) +
                              FLUSH_SLACK};
            if (out.size() - start - written < want) {
                out.resize(start + written + want);
            }
            ZSTD_outBuffer output{out.data() + start, out.size() - start,
                                  written};
            const size_t remaining{Check(ZSTD_compressStream2(
                m_cctx.get(), &output, &input, ZSTD_e_flush))};
            written = output.pos;
            if (remaining == 0 && input.pos == input.size) {
                break;
            }
        }
        out.resize(start + written);
    }

    /**
     * Feed the next chunk of the incoming stream. Calls `sink(Span)` with
     * decompressed bytes as they are produced, at most `max_chunk` at a time.
     * Throws std::runtime_error on corrupt input.
     */
    template <typename Sink>
    void DecompressFrame(Span<const uint8_t> in, Sink &&sink,
                         size_t max_chunk = 128 * 1024) {
        ZSTD_inBuffer input{in.data(), in.size(), 0};
        m_dbuf.resize(max_chunk);
        while (true) {
            ZSTD_outBuffer output{m_dbuf.data(), m_dbuf.size(), 0};
            Check(ZSTD_decompressStream(m_dctx.get(), &output, &input));
            if (output.pos > 0) {
                sink(Span<const uint8_t>{m_dbuf.data(), output.pos});
            }
            // Done once the input is consumed and the output buffer was not
            // filled (so no more data is buffered inside the decoder).
            if (input.pos == input.size && output.pos < output.size) {
                break;
            }
        }
    }

    /** Convenience overload collecting all output in `out` */
    void DecompressFrame(Span<const uint8_t> in, std::vector<uint8_t> &out) {
        DecompressFrame(in, [&out](Span<const uint8_t> chunk) {
            out.insert(out.end(), chunk.begin(), chunk.end());
        });
    }

private:
    //! Extra output room for the block headers of a flush
    static constexpr size_t FLUSH_SLACK = 32;

    static size_t Check(size_t ret) {
        if (ZSTD_isError(ret)) {
            throw std::runtime_error(ZSTD_getErrorName(ret));
        }
        return ret;
    }

    std::unique_ptr<ZSTD_CCtx, size_t (*)(ZSTD_CCtx *)> m_cctx;
    std::unique_ptr<ZSTD_DCtx, size_t (*)(ZSTD_DCtx *)> m_dctx;
    std::vector<uint8_t> m_dbuf;
};

#endif // BITCOIN_NET_ZSTD_DICT_H
