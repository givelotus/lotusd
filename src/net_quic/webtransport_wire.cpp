// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_quic/webtransport_wire.h>

#include <algorithm>

namespace wt {

size_t VarintSize(uint64_t v) {
    if (v < 64) {
        return 1;
    }
    if (v < 16384) {
        return 2;
    }
    if (v < (uint64_t{1} << 30)) {
        return 4;
    }
    return 8;
}

void PutVarint(std::vector<uint8_t> &out, uint64_t v) {
    const size_t n{VarintSize(v)};
    const uint8_t prefix{static_cast<uint8_t>(n == 1   ? 0x00
                                              : n == 2 ? 0x40
                                              : n == 4 ? 0x80
                                                       : 0xc0)};
    for (size_t i = 0; i < n; ++i) {
        uint8_t b{static_cast<uint8_t>(v >> (8 * (n - 1 - i)))};
        if (i == 0) {
            b = (b & 0x3f) | prefix;
        }
        out.push_back(b);
    }
}

size_t GetVarint(Span<const uint8_t> in, uint64_t &value) {
    if (in.empty()) {
        return 0;
    }
    const size_t n{size_t{1} << (in[0] >> 6)};
    if (in.size() < n) {
        return 0;
    }
    uint64_t v{in[0] & 0x3fu};
    for (size_t i = 1; i < n; ++i) {
        v = (v << 8) | in[i];
    }
    value = v;
    return n;
}

uint64_t WebTransportCodeToHttp(uint32_t code) {
    return APP_ERROR_FIRST + code + code / 0x1e;
}

std::optional<uint32_t> HttpCodeToWebTransport(uint64_t http_code) {
    if (http_code < APP_ERROR_FIRST || http_code > APP_ERROR_LAST) {
        return std::nullopt;
    }
    // Reserved HTTP/3 codepoints 0x1f * N + 0x21 are skipped by the mapping.
    if ((http_code - 0x21) % 0x1f == 0) {
        return std::nullopt;
    }
    const uint64_t shifted{http_code - APP_ERROR_FIRST};
    return static_cast<uint32_t>(shifted - shifted / 0x1f);
}

StreamPrefix ParseStreamPrefix(Span<const uint8_t> in, bool unidirectional) {
    StreamPrefix out;
    uint64_t first{0};
    const size_t n1{GetVarint(in, first)};
    if (n1 == 0) {
        return out;
    }
    if (first != (unidirectional ? UNI_STREAM_TYPE : BIDI_SIGNAL)) {
        out.status = StreamPrefix::Status::HTTP3;
        return out;
    }
    uint64_t session{0};
    const size_t n2{GetVarint(in.subspan(n1), session)};
    if (n2 == 0) {
        return out;
    }
    out.status = StreamPrefix::Status::WEBTRANSPORT;
    out.session_id = session;
    out.header_len = n1 + n2;
    return out;
}

std::vector<uint8_t> BidiStreamHeader(uint64_t session_id) {
    std::vector<uint8_t> out;
    PutVarint(out, BIDI_SIGNAL);
    PutVarint(out, session_id);
    return out;
}

std::vector<uint8_t> UniStreamHeader(uint64_t session_id) {
    std::vector<uint8_t> out;
    PutVarint(out, UNI_STREAM_TYPE);
    PutVarint(out, session_id);
    return out;
}

CapsuleParse ParseCapsule(Span<const uint8_t> in) {
    CapsuleParse out;
    uint64_t type{0}, length{0};
    const size_t n1{GetVarint(in, type)};
    if (n1 == 0) {
        return out;
    }
    const size_t n2{GetVarint(in.subspan(n1), length)};
    if (n2 == 0) {
        return out;
    }
    if (length > MAX_CAPSULE_SIZE) {
        out.status = CapsuleParse::Status::ERROR;
        out.error = "capsule too large";
        return out;
    }
    if (in.size() - n1 - n2 < length) {
        return out;
    }
    out.status = CapsuleParse::Status::OK;
    out.capsule.type = type;
    const auto value{in.subspan(n1 + n2, static_cast<size_t>(length))};
    out.capsule.value.assign(value.begin(), value.end());
    out.consumed = n1 + n2 + static_cast<size_t>(length);
    return out;
}

void EncodeCapsule(std::vector<uint8_t> &out, uint64_t type,
                   Span<const uint8_t> value) {
    PutVarint(out, type);
    PutVarint(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

std::optional<CloseSession> DecodeCloseSession(Span<const uint8_t> value) {
    if (value.size() < 4 || value.size() - 4 > MAX_CLOSE_REASON) {
        return std::nullopt;
    }
    CloseSession out;
    out.code = (uint32_t{value[0]} << 24) | (uint32_t{value[1]} << 16) |
               (uint32_t{value[2]} << 8) | uint32_t{value[3]};
    out.reason.assign(value.begin() + 4, value.end());
    return out;
}

std::vector<uint8_t> EncodeCloseSession(uint32_t code,
                                        std::string_view reason) {
    reason = reason.substr(0, MAX_CLOSE_REASON);
    std::vector<uint8_t> value{
        static_cast<uint8_t>(code >> 24), static_cast<uint8_t>(code >> 16),
        static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code)};
    value.insert(value.end(), reason.begin(), reason.end());
    std::vector<uint8_t> out;
    EncodeCapsule(out, CAPSULE_CLOSE_SESSION, value);
    return out;
}

std::optional<std::vector<std::string>>
ParseProtocolList(std::string_view field) {
    std::vector<std::string> out;
    size_t i{0};
    const auto skip_ows{[&] {
        while (i < field.size() && (field[i] == ' ' || field[i] == '\t')) {
            ++i;
        }
    }};
    skip_ows();
    if (i == field.size()) {
        return out;
    }
    while (true) {
        if (i >= field.size() || field[i] != '"') {
            return std::nullopt;
        }
        ++i;
        std::string s;
        while (true) {
            if (i >= field.size()) {
                return std::nullopt;
            }
            const char c{field[i++]};
            if (c == '\\') {
                if (i >= field.size() ||
                    (field[i] != '"' && field[i] != '\\')) {
                    return std::nullopt;
                }
                s.push_back(field[i++]);
            } else if (c == '"') {
                break;
            } else if (c < 0x20 || c > 0x7e) {
                return std::nullopt;
            } else {
                s.push_back(c);
            }
        }
        // Parameters (";key=value") are allowed and ignored.
        while (i < field.size() && field[i] == ';') {
            while (i < field.size() && field[i] != ',') {
                ++i;
            }
        }
        out.push_back(std::move(s));
        skip_ows();
        if (i == field.size()) {
            return out;
        }
        if (field[i] != ',') {
            return std::nullopt;
        }
        ++i;
        skip_ows();
    }
}

std::string SerializeProtocol(std::string_view protocol) {
    std::string out{"\""};
    for (const char c : protocol) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

int DraftRank(uint64_t settings_id) {
    switch (settings_id) {
        case SETTINGS_ENABLE_WEBTRANSPORT_D02:
            return 1;
        case SETTINGS_WT_MAX_SESSIONS_D07:
            return 2;
        case SETTINGS_WT_MAX_SESSIONS_D13:
            return 3;
        case SETTINGS_WT_ENABLED:
            return 4;
        default:
            return 0;
    }
}

} // namespace wt
