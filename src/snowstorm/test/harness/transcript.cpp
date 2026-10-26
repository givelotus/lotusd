// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#include <bit>
#include <cstdlib>
#include <fstream>
#include "transcript.h"
#include <stdexcept>
#include <type_traits>
namespace snowstorm::test {
namespace {
    void u64(Bytes &b, std::uint64_t x) {
        for (int i = 0; i < 8; ++i)
            b.push_back(static_cast<Byte>(x >> (8 * i)));
    }
    template <class C> void append(Bytes &b, const C &v) {
        b.insert(b.end(), v.begin(), v.end());
    }
} // namespace
void Transcript::event(std::uint8_t kind, std::uint64_t node, Time time,
                       ByteSpan payload) {
    bytes_.push_back(kind);
    u64(bytes_, node);
    u64(bytes_, static_cast<std::uint64_t>(time));
    u64(bytes_, payload.size());
    append(bytes_, payload);
}
void Transcript::action(std::uint64_t node, Time time, const Action &action) {
    Bytes b;
    b.push_back(static_cast<Byte>(action.index()));
    std::visit(
        [&](const auto &a) {
            using T = std::decay_t<decltype(a)>;
            if constexpr (std::is_same_v<T, Send>) {
                u64(b, a.peer);
                u64(b, a.bytes.size());
                append(b, a.bytes);
            } else if constexpr (std::is_same_v<T, FetchBody>) {
                u64(b, a.peer);
                u64(b, a.short_id);
                u64(b, a.fetch_id);
            } else if constexpr (std::is_same_v<T, Frozen>) {
                append(b, a.root);
                u64(b, a.txids.size());
                for (const auto &x : a.txids)
                    append(b, x);
            } else if constexpr (std::is_same_v<T, PeerMisbehaved>) {
                u64(b, a.peer);
                b.push_back(static_cast<Byte>(a.reason));
            } else {
                u64(b, static_cast<std::uint64_t>(a.at));
            }
        },
        action);
    event(128, node, time, b);
}
void Transcript::write(const std::string &path) const {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char *>(bytes_.data()),
            static_cast<std::streamsize>(bytes_.size()));
    if (!f) throw std::runtime_error("transcript write failed");
}
void Transcript::write_from_environment() const {
    const char *p = std::getenv("SNOWSTORM_TRANSCRIPT_FILE");
    if (!p || !*p)
        throw std::runtime_error("SNOWSTORM_TRANSCRIPT_FILE missing");
    write(p);
}
// FIPS 180-4 SHA-256; host commitment only, never a reconciliation oracle.
Root sha256(ByteSpan input) {
    constexpr std::uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    std::array<std::uint32_t, 8> h{0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                   0xa54ff53a, 0x510e527f, 0x9b05688c,
                                   0x1f83d9ab, 0x5be0cd19};
    Bytes b(input.begin(), input.end());
    const auto bits = static_cast<std::uint64_t>(b.size()) * 8;
    b.push_back(128);
    while (b.size() % 64 != 56)
        b.push_back(0);
    for (int i = 7; i >= 0; --i)
        b.push_back(static_cast<Byte>(bits >> (8 * i)));
    for (std::size_t off = 0; off < b.size(); off += 64) {
        std::uint32_t w[64]{};
        for (int i = 0; i < 16; ++i)
            for (int j = 0; j < 4; ++j)
                w[i] = (w[i] << 8) | b[off + 4 * i + j];
        for (int i = 16; i < 64; ++i) {
            auto x = w[i - 15], y = w[i - 2];
            w[i] = w[i - 16] + (std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3)) +
                   w[i - 7] + (std::rotr(y, 17) ^ std::rotr(y, 19) ^ (y >> 10));
        }
        auto a = h[0], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6],
             z = h[7], v = h[1];
        for (int i = 0; i < 64; ++i) {
            auto t = z +
                     (std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25)) +
                     ((e & f) ^ (~e & g)) + k[i] + w[i];
            auto u = (std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22)) +
                     ((a & v) ^ (a & c) ^ (v & c));
            z = g;
            g = f;
            f = e;
            e = d + t;
            d = c;
            c = v;
            v = a;
            a = t + u;
        }
        h[0] += a;
        h[1] += v;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += z;
    }
    Root result{};
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j)
            result[4 * i + j] = static_cast<Byte>(h[i] >> (24 - 8 * j));
    return result;
}
} // namespace snowstorm::test
