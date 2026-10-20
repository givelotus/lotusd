// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_websocket_codec.h>

#include <net_zstd_independent.h>

#include <tinyformat.h>

#include <algorithm>
#include <cassert>
#include <cstring>

namespace {
constexpr uint8_t OP_CONTINUATION = 0x0;
constexpr uint8_t OP_TEXT = 0x1;
constexpr uint8_t OP_BINARY = 0x2;
constexpr uint8_t OP_CLOSE = 0x8;
constexpr uint8_t OP_PING = 0x9;
constexpr uint8_t OP_PONG = 0xA;
//! Marks an independent frame (zstd modes only)
constexpr uint8_t RSV2 = 0x20;

/** Parsed frame header */
struct FrameHeader {
    bool fin;
    uint8_t rsv;
    uint8_t opcode;
    bool masked;
    uint64_t length;
    uint8_t mask[4];
    size_t header_size;
};

/**
 * Parse a frame header at the start of `in`. Returns nullopt if more bytes
 * are needed.
 */
std::optional<FrameHeader> ParseHeader(Span<const uint8_t> in) {
    if (in.size() < 2) {
        return std::nullopt;
    }
    FrameHeader h{};
    h.fin = in[0] & 0x80;
    h.rsv = in[0] & 0x70;
    h.opcode = in[0] & 0x0F;
    h.masked = in[1] & 0x80;
    uint64_t len = in[1] & 0x7F;
    size_t pos = 2;
    if (len == 126) {
        if (in.size() < pos + 2) {
            return std::nullopt;
        }
        len = (uint64_t{in[2]} << 8) | in[3];
        pos += 2;
    } else if (len == 127) {
        if (in.size() < pos + 8) {
            return std::nullopt;
        }
        len = 0;
        for (int i = 0; i < 8; ++i) {
            len = (len << 8) | in[pos + i];
        }
        pos += 8;
    }
    if (h.masked) {
        if (in.size() < pos + 4) {
            return std::nullopt;
        }
        std::memcpy(h.mask, in.data() + pos, 4);
        pos += 4;
    }
    h.length = len;
    h.header_size = pos;
    return h;
}
} // namespace

WebSocketCodec::WebSocketCodec(Role role, P2PWebSocketCompression compression)
    : m_role{role}, m_compression{compression},
      m_independent{compression == P2PWebSocketCompression::ZSTD ||
                    compression == P2PWebSocketCompression::ZSTD_DICT} {
    if (compression == P2PWebSocketCompression::ZSTD ||
        compression == P2PWebSocketCompression::ZSTD_DICT) {
        m_zstd = std::make_unique<P2PZstdSession>(
            compression == P2PWebSocketCompression::ZSTD_DICT);
    }
}

uint64_t WebSocketCodec::MaxWireMessageSize() const {
    const uint64_t plain_limit{GetP2PWebSocketMessageSizeLimit()};
    return m_zstd ? P2PZstdMaxWireSize(plain_limit) : plain_limit;
}

void WebSocketCodec::AppendFrame(uint8_t opcode, Span<const uint8_t> payload,
                                 std::vector<uint8_t> &out, uint8_t rsv) {
    const size_t start{out.size()};
    const bool mask{m_role == Role::CLIENT};
    out.push_back(0x80 | rsv | opcode);
    const uint8_t mask_bit = mask ? 0x80 : 0;
    const uint64_t len{payload.size()};
    if (len <= 125) {
        out.push_back(mask_bit | uint8_t(len));
    } else if (len <= 0xFFFF) {
        out.push_back(mask_bit | 126);
        out.push_back(len >> 8);
        out.push_back(len & 0xFF);
    } else {
        out.push_back(mask_bit | 127);
        for (int i = 7; i >= 0; --i) {
            out.push_back((len >> (8 * i)) & 0xFF);
        }
    }
    uint8_t key[4] = {0, 0, 0, 0};
    if (mask) {
        const uint32_t r{m_rng.rand32()};
        std::memcpy(key, &r, 4);
        out.insert(out.end(), key, key + 4);
    }
    const size_t body{out.size()};
    out.insert(out.end(), payload.begin(), payload.end());
    if (mask) {
        for (size_t i = 0; i < payload.size(); ++i) {
            out[body + i] ^= key[i & 3];
        }
    }
    m_wire_sent += out.size() - start;
}

void WebSocketCodec::EncodeMessage(Span<const uint8_t> payload,
                                   std::vector<uint8_t> &out) {
    if (m_zstd) {
        m_scratch.clear();
        m_zstd->CompressFrame(payload, m_scratch);
        AppendFrame(OP_BINARY, m_scratch, out);
    } else {
        AppendFrame(OP_BINARY, payload, out);
    }
}

void WebSocketCodec::EncodeIndependent(Span<const uint8_t> frame,
                                       std::vector<uint8_t> &out) {
    assert(m_independent);
    AppendFrame(OP_BINARY, frame, out, RSV2);
}

void WebSocketCodec::EncodeClose(uint16_t code, std::vector<uint8_t> &out) {
    if (m_close_sent) {
        return;
    }
    m_close_sent = true;
    const uint8_t payload[2] = {uint8_t(code >> 8), uint8_t(code & 0xFF)};
    AppendFrame(OP_CLOSE, payload, out);
}

bool WebSocketCodec::HasCompleteFrame(Span<const uint8_t> in) {
    const auto h{ParseHeader(in)};
    return h && in.size() - h->header_size >= h->length;
}

std::optional<std::string>
WebSocketCodec::FinishMessage(std::vector<uint8_t> &plain) {
    const uint64_t plain_limit{GetP2PWebSocketMessageSizeLimit()};
    if (!m_zstd) {
        if (m_message.size() > plain_limit) {
            return std::string{"message too large"};
        }
        if (plain.empty()) {
            plain.swap(m_message);
        } else {
            plain.insert(plain.end(), m_message.begin(), m_message.end());
        }
        return std::nullopt;
    }
    if (m_message_independent) {
        try {
            DecompressP2PIndependent(m_message, plain, plain_limit);
        } catch (const std::exception &e) {
            return strprintf("independent zstd: %s", e.what());
        }
        ++m_independent_recv;
        return std::nullopt;
    }
    size_t produced{0};
    try {
        m_zstd->DecompressFrame(m_message, [&](Span<const uint8_t> chunk) {
            if (chunk.size() > plain_limit - produced) {
                throw std::runtime_error("decompressed message too large");
            }
            produced += chunk.size();
            plain.insert(plain.end(), chunk.begin(), chunk.end());
        });
    } catch (const std::exception &e) {
        return strprintf("zstd: %s", e.what());
    }
    return std::nullopt;
}

WebSocketCodec::DecodeResult
WebSocketCodec::Decode(Span<const uint8_t> in, std::vector<uint8_t> &plain,
                       std::vector<uint8_t> &reply) {
    DecodeResult result;
    while (!m_peer_closed) {
        const Span<const uint8_t> rest{in.subspan(result.consumed)};
        const auto h{ParseHeader(rest)};
        if (!h) {
            break;
        }
        // Validate as soon as the header is known, before buffering.
        // RSV2 marks an unfragmented independent binary message (zstd
        // modes only).
        if (h->rsv != 0 && !(m_independent && h->rsv == RSV2 &&
                             h->opcode == OP_BINARY && h->fin)) {
            result.error = "reserved bits set (extensions not supported)";
            return result;
        }
        if (h->masked != (m_role == Role::SERVER)) {
            result.error = m_role == Role::SERVER ? "unmasked client frame"
                                                  : "masked server frame";
            return result;
        }
        const bool control{(h->opcode & 0x8) != 0};
        if (control && (!h->fin || h->length > 125)) {
            result.error = "invalid control frame";
            return result;
        }
        const uint64_t wire_limit{MaxWireMessageSize()};
        if (h->length > wire_limit ||
            (!control && (m_message.size() > wire_limit ||
                          h->length > wire_limit - m_message.size()))) {
            result.error = "message too large";
            return result;
        }
        if (rest.size() - h->header_size < h->length) {
            break;
        }

        const auto body{rest.subspan(h->header_size, h->length)};
        result.consumed += h->header_size + h->length;
        m_wire_recv += h->header_size + h->length;

        // Unmask straight into its destination (no copy for data frames).
        const auto unmask_into = [&](std::vector<uint8_t> &dst) {
            const size_t start{dst.size()};
            dst.insert(dst.end(), body.begin(), body.end());
            if (h->masked) {
                for (size_t i = 0; i < body.size(); ++i) {
                    dst[start + i] ^= h->mask[i & 3];
                }
            }
        };
        std::vector<uint8_t> payload;
        if (control) {
            unmask_into(payload);
        }

        switch (h->opcode) {
            case OP_BINARY:
            case OP_CONTINUATION: {
                if ((h->opcode == OP_BINARY) == m_in_message) {
                    result.error = "unexpected continuation state";
                    return result;
                }
                if (h->opcode == OP_BINARY) {
                    m_message_independent = h->rsv == RSV2;
                }
                m_in_message = !h->fin;
                unmask_into(m_message);
                if (h->fin) {
                    if (auto err{FinishMessage(plain)}) {
                        result.error = err;
                        return result;
                    }
                    m_message.clear();
                }
                break;
            }
            case OP_TEXT:
                result.error = "text frames are not P2P data";
                return result;
            case OP_PING:
                AppendFrame(OP_PONG, payload, reply);
                break;
            case OP_PONG:
                break;
            case OP_CLOSE: {
                m_peer_closed = true;
                uint16_t code{1000};
                if (payload.size() >= 2) {
                    code = (uint16_t{payload[0]} << 8) | payload[1];
                }
                EncodeClose(code, reply);
                break;
            }
            default:
                result.error = strprintf("unknown opcode %u", h->opcode);
                return result;
        }
    }
    return result;
}
