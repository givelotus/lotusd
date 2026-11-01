// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/short_id.h>
#include "wire_bytes.h"
#include <bit>
namespace snowstorm {
namespace {
constexpr std::uint64_t SIP_IV0 = 0x736f6d6570736575ULL;
constexpr std::uint64_t SIP_IV1 = 0x646f72616e646f6dULL;
constexpr std::uint64_t SIP_IV2 = 0x6c7967656e657261ULL;
constexpr std::uint64_t SIP_IV3 = 0x7465646279746573ULL;
constexpr unsigned ROTATE_A = 13, ROTATE_B = 16, ROTATE_C = 21, ROTATE_D = 17, ROTATE_HALF = 32;
constexpr unsigned LENGTH_SHIFT = 56;
constexpr std::uint64_t FINAL_MARKER = 0xff;
struct SipState {
    std::uint64_t a, b, c, d;
    void round() noexcept {
        a += b; b = std::rotl(b, ROTATE_A); b ^= a; a = std::rotl(a, ROTATE_HALF);
        c += d; d = std::rotl(d, ROTATE_B); d ^= c;
        a += d; d = std::rotl(d, ROTATE_C); d ^= a;
        c += b; b = std::rotl(b, ROTATE_D); b ^= c; c = std::rotl(c, ROTATE_HALF);
    }
    void compress(std::uint64_t word) noexcept { d ^= word; round(); round(); a ^= word; }
};
}
ShortId normalize_short_id(std::uint64_t result) noexcept { return result == 0 ? 1 : result; }
ShortId short_id(ShortIdKey key, const TxHash &hash) noexcept {
    SipState state{SIP_IV0 ^ key.k0, SIP_IV1 ^ key.k1, SIP_IV2 ^ key.k0, SIP_IV3 ^ key.k1};
    constexpr auto WORD_BYTES = sizeof(std::uint64_t);
    for (std::size_t offset = 0; offset < hash.size(); offset += WORD_BYTES) {
        state.compress(detail::read_le<std::uint64_t>(ByteSpan(hash).subspan(offset)));
    }
    state.compress(static_cast<std::uint64_t>(hash.size()) << LENGTH_SHIFT);
    state.c ^= FINAL_MARKER;
    state.round(); state.round(); state.round(); state.round();
    return normalize_short_id(state.a ^ state.b ^ state.c ^ state.d);
}
} // namespace snowstorm
