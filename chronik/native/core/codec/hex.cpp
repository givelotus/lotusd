// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/codec/hex.h>

namespace chronik::native {

static constexpr char kHexDigits[] = "0123456789abcdef";

std::string HexEncode(ByteView bytes) {
    std::string out;
    out.resize(bytes.size() * 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        out[2 * i] = kHexDigits[bytes[i] >> 4];
        out[2 * i + 1] = kHexDigits[bytes[i] & 0x0f];
    }
    return out;
}

std::string HexEncodeRev(ByteView bytes) {
    std::string out;
    out.resize(bytes.size() * 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        const uint8_t b = bytes[bytes.size() - 1 - i];
        out[2 * i] = kHexDigits[b >> 4];
        out[2 * i + 1] = kHexDigits[b & 0x0f];
    }
    return out;
}

static int HexDigit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

std::optional<Bytes> HexDecode(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    Bytes out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = HexDigit(hex[2 * i]);
        const int lo = HexDigit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out[i] = uint8_t((hi << 4) | lo);
    }
    return out;
}

} // namespace chronik::native
