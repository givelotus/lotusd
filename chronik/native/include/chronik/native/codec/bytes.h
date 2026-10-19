// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CODEC_BYTES_H
#define CHRONIK_NATIVE_CODEC_BYTES_H

#include <chronik/native/types.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <type_traits>

/** Fixed-width big-/little-endian integer helpers used by the DB keys. */
namespace chronik::native {

template <typename T> inline std::array<uint8_t, sizeof(T)> ToBe(T v) {
    std::array<uint8_t, sizeof(T)> out;
    using U = std::make_unsigned_t<T>;
    U u = static_cast<U>(v);
    for (size_t i = 0; i < sizeof(T); ++i) {
        out[sizeof(T) - 1 - i] = uint8_t(u >> (8 * i));
    }
    return out;
}

template <typename T> inline std::array<uint8_t, sizeof(T)> ToLe(T v) {
    std::array<uint8_t, sizeof(T)> out;
    using U = std::make_unsigned_t<T>;
    U u = static_cast<U>(v);
    for (size_t i = 0; i < sizeof(T); ++i) {
        out[i] = uint8_t(u >> (8 * i));
    }
    return out;
}

/** Reads sizeof(T) bytes; the caller guarantees bytes.size() >= sizeof(T). */
template <typename T> inline T FromBe(ByteView bytes) {
    using U = std::make_unsigned_t<T>;
    U u = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        u = U(u << 8) | U(bytes[i]);
    }
    return static_cast<T>(u);
}

template <typename T> inline T FromLe(ByteView bytes) {
    using U = std::make_unsigned_t<T>;
    U u = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        u |= U(U(bytes[i]) << (8 * i));
    }
    return static_cast<T>(u);
}

template <typename T> inline void PutBe(Bytes &out, T v) {
    const auto a = ToBe(v);
    out.insert(out.end(), a.begin(), a.end());
}

template <typename T> inline void PutLe(Bytes &out, T v) {
    const auto a = ToLe(v);
    out.insert(out.end(), a.begin(), a.end());
}

inline void Append(Bytes &out, ByteView v) {
    out.insert(out.end(), v.begin(), v.end());
}

inline ByteView AsView(const Bytes &b) {
    return ByteView(b.data(), b.size());
}

template <size_t N> inline ByteView AsView(const std::array<uint8_t, N> &a) {
    return ByteView(a.data(), N);
}

inline ByteView AsView(std::string_view s) {
    return ByteView(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

inline bool StartsWith(ByteView v, ByteView prefix) {
    return v.size() >= prefix.size() &&
           (prefix.empty() ||
            std::memcmp(v.data(), prefix.data(), prefix.size()) == 0);
}

inline bool Equal(ByteView a, ByteView b) {
    return a.size() == b.size() &&
           (a.empty() || std::memcmp(a.data(), b.data(), a.size()) == 0);
}

} // namespace chronik::native

#endif // CHRONIK_NATIVE_CODEC_BYTES_H
