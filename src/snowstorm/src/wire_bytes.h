// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>
#include <type_traits>

namespace snowstorm::detail {
inline constexpr unsigned WIRE_BYTE_BITS = 8;
/** Caller validates storage before these allocation-free wire primitives. */
template <typename UInt> UInt read_le(ByteSpan bytes) noexcept {
    static_assert(std::is_unsigned_v<UInt>);
    UInt value{};
    for (std::size_t i = 0; i < sizeof(UInt); ++i) {
        value |= UInt{bytes[i]} << (i * WIRE_BYTE_BITS);
    }
    return value;
}
template <typename UInt> void write_le(UInt value, MutableByteSpan bytes) noexcept {
    static_assert(std::is_unsigned_v<UInt>);
    for (std::size_t i = 0; i < sizeof(UInt); ++i) {
        bytes[i] = static_cast<Byte>(value >> (i * WIRE_BYTE_BITS));
    }
}
} // namespace snowstorm::detail
