// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "address.h"

#include <array>
#include <cstdint>

namespace lotus::v2 {
namespace {

constexpr char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr uint8_t VERSION_ROOT = 0;
constexpr size_t PAYLOAD_SYMBOLS = 52;
constexpr size_t CHECKSUM_SYMBOLS = 8;
constexpr size_t BODY_SYMBOLS = 1 + PAYLOAD_SYMBOLS + CHECKSUM_SYMBOLS;

struct NetworkInfo {
    AddressNetwork network;
    std::string_view prefix;
    // Per-network checksum constant; chosen so that no pattern of up to four
    // substitutions turns one network's address into another's (see spec).
    uint64_t constant;
};

constexpr std::array<NetworkInfo, 3> NETWORKS{{
    {AddressNetwork::MAINNET, "xpi", 0xb70061479e},
    {AddressNetwork::TESTNET, "txpi", 0xadda0f1635},
    {AddressNetwork::REGTEST, "rxpi", 0x8172b45d63},
}};

const NetworkInfo &Info(AddressNetwork network) {
    for (const auto &info : NETWORKS) {
        if (info.network == network) {
            return info;
        }
    }
    return NETWORKS[0];
}

// cashaddr's 40-bit BCH polymod, without its final "^ 1".
template <typename Symbols> uint64_t PolyMod(const Symbols &symbols) {
    uint64_t c = 1;
    for (const uint8_t d : symbols) {
        const uint8_t c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ d;
        if (c0 & 0x01) {
            c ^= 0x98f2bc8e61;
        }
        if (c0 & 0x02) {
            c ^= 0x79b76d99e2;
        }
        if (c0 & 0x04) {
            c ^= 0xf33e5fb3c4;
        }
        if (c0 & 0x08) {
            c ^= 0xae2eabe2a8;
        }
        if (c0 & 0x10) {
            c ^= 0x1e4f43e470;
        }
    }
    return c;
}

int8_t SymbolValue(char c) {
    for (int8_t i = 0; i < 32; ++i) {
        if (CHARSET[i] == c) {
            return i;
        }
    }
    return -1;
}

} // namespace

std::string_view AddressPrefix(AddressNetwork network) {
    return Info(network).prefix;
}

std::string EncodeAddress(AddressNetwork network, const Hash32 &root) {
    const NetworkInfo &info = Info(network);
    std::array<uint8_t, BODY_SYMBOLS> body{};
    body[0] = VERSION_ROOT;
    // 256 root bits, high bit first, then 4 zero padding bits.
    for (size_t i = 0; i < PAYLOAD_SYMBOLS; ++i) {
        uint8_t symbol = 0;
        for (size_t b = 0; b < 5; ++b) {
            const size_t bit = 5 * i + b;
            const uint8_t value =
                bit < 256 ? (root[bit / 8] >> (7 - bit % 8)) & 1 : 0;
            symbol = (symbol << 1) | value;
        }
        body[1 + i] = symbol;
    }
    // The checksum symbols are still zero here.
    const uint64_t mod = PolyMod(body) ^ info.constant;
    for (size_t i = 0; i < CHECKSUM_SYMBOLS; ++i) {
        body[1 + PAYLOAD_SYMBOLS + i] = (mod >> (5 * (7 - i))) & 31;
    }

    std::string out(info.prefix);
    out += '1';
    for (const uint8_t symbol : body) {
        out += CHARSET[symbol];
    }
    return out;
}

std::optional<DecodedAddress> DecodeAddress(std::string_view address,
                                            std::string &error) {
    bool has_lower = false, has_upper = false;
    for (const char c : address) {
        has_lower |= c >= 'a' && c <= 'z';
        has_upper |= c >= 'A' && c <= 'Z';
    }
    if (has_lower && has_upper) {
        error = "mixed case";
        return std::nullopt;
    }
    std::string lower(address);
    for (char &c : lower) {
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }
    }

    const size_t separator = lower.rfind('1');
    const NetworkInfo *info = nullptr;
    if (separator != std::string::npos) {
        const std::string_view prefix(lower.data(), separator);
        for (const auto &candidate : NETWORKS) {
            if (candidate.prefix == prefix) {
                info = &candidate;
            }
        }
    }
    if (!info) {
        error = "unknown prefix";
        return std::nullopt;
    }

    const std::string_view body_chars =
        std::string_view(lower).substr(separator + 1);
    if (body_chars.size() != BODY_SYMBOLS) {
        error = "bad length";
        return std::nullopt;
    }
    std::array<uint8_t, BODY_SYMBOLS> body{};
    for (size_t i = 0; i < BODY_SYMBOLS; ++i) {
        const int8_t value = SymbolValue(body_chars[i]);
        if (value < 0) {
            error = "bad character";
            return std::nullopt;
        }
        body[i] = value;
    }
    if (PolyMod(body) != info->constant) {
        error = "bad checksum";
        return std::nullopt;
    }
    if (body[0] != VERSION_ROOT) {
        error = "unknown version";
        return std::nullopt;
    }
    // 52 payload symbols carry 260 bits: the last symbol holds root bit 255
    // followed by the 4 padding bits.
    if (body[PAYLOAD_SYMBOLS] & 0x0f) {
        error = "nonzero padding";
        return std::nullopt;
    }

    DecodedAddress decoded{info->network, {}};
    for (size_t bit = 0; bit < 256; ++bit) {
        const uint8_t symbol = body[1 + bit / 5];
        const uint8_t value = (symbol >> (4 - bit % 5)) & 1;
        decoded.root[bit / 8] |= value << (7 - bit % 8);
    }
    return decoded;
}

} // namespace lotus::v2
