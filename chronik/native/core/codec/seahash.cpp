// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/codec/seahash.h>

namespace chronik::native {

namespace {

constexpr uint64_t Diffuse(uint64_t x) {
    x *= 0x6eed0e9da4d94a4fULL;
    const uint64_t a = x >> 32;
    const uint64_t b = x >> 60;
    x ^= a >> b;
    x *= 0x6eed0e9da4d94a4fULL;
    return x;
}

/** Little-endian read of up to 8 bytes (seahash helper::read_int/read_u64). */
uint64_t ReadLe(const uint8_t *p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v |= uint64_t(p[i]) << (8 * i);
    }
    return v;
}

} // namespace

uint64_t SeaHashSeeded(ByteView buf, uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d) {
    const uint8_t *ptr = buf.data();
    const size_t n_blocks = buf.size() / 32;
    for (size_t i = 0; i < n_blocks; ++i, ptr += 32) {
        a = Diffuse(a ^ ReadLe(ptr, 8));
        b = Diffuse(b ^ ReadLe(ptr + 8, 8));
        c = Diffuse(c ^ ReadLe(ptr + 16, 8));
        d = Diffuse(d ^ ReadLe(ptr + 24, 8));
    }
    // The excess (< 32 bytes) fills the lanes a, b, c, d in order; every
    // touched lane is diffused, the last one with a zero-extended partial
    // little-endian word (State::hash in seahash/src/buffer.rs).
    size_t excessive = buf.size() - n_blocks * 32;
    uint64_t *lanes[4] = {&a, &b, &c, &d};
    for (size_t lane = 0; excessive > 0; ++lane) {
        const size_t take = excessive < 8 ? excessive : 8;
        *lanes[lane] = Diffuse(*lanes[lane] ^ ReadLe(ptr, take));
        ptr += take;
        excessive -= take;
    }
    // finalize
    a ^= b;
    c ^= d;
    a ^= c;
    a ^= uint64_t(buf.size());
    return Diffuse(a);
}

uint64_t SeaHash(ByteView data) {
    return SeaHashSeeded(data, 0x16f11fe89b0d677cULL, 0xb480a793d8e6c86cULL,
                         0x6fe2e5aaf078ebc9ULL, 0x14f994a4c5259381ULL);
}

} // namespace chronik::native
