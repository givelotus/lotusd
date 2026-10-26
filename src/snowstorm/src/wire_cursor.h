// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include "wire_bytes.h"
#include "params.h"
#include <algorithm>
#include <limits>
namespace snowstorm::detail {
class WireReader {
    ByteSpan bytes_;
    std::size_t position_{};
public:
    Error error{Error::ok};
    explicit WireReader(ByteSpan bytes) : bytes_(bytes) {}
    std::size_t remaining() const noexcept { return bytes_.size() - position_; }
    ByteSpan take(std::size_t count) noexcept {
        if (error != Error::ok || count > remaining()) { error = Error::malformed_message; return {}; }
        const auto result = bytes_.subspan(position_, count); position_ += count; return result;
    }
    template <typename UInt> UInt integer() noexcept {
        const auto bytes = take(sizeof(UInt));
        return bytes.size() == sizeof(UInt) ? read_le<UInt>(bytes) : 0;
    }
    bool flag() noexcept {
        const auto value = integer<Byte>();
        if (value > 1) error = Error::malformed_message;
        return value == 1;
    }
    std::uint64_t compact() noexcept {
        const auto marker = integer<Byte>();
        if (marker < params::COMPACT_U16) return marker;
        std::uint64_t result{};
        std::uint64_t minimum{};
        if (marker == params::COMPACT_U16) { result = integer<std::uint16_t>(); minimum = params::COMPACT_U16; }
        if (marker == params::COMPACT_U32) { result = integer<std::uint32_t>(); minimum = std::uint64_t{1} + std::numeric_limits<std::uint16_t>::max(); }
        if (marker == params::COMPACT_U64) { result = integer<std::uint64_t>(); minimum = std::uint64_t{1} + std::numeric_limits<std::uint32_t>::max(); }
        if (result < minimum) error = Error::malformed_message;
        return result;
    }
    template <std::size_t N> void fixed(std::array<Byte, N> &out) noexcept {
        const auto bytes = take(N);
        if (bytes.size() == N) std::copy(bytes.begin(), bytes.end(), out.begin());
    }
};
/** Identical writing grammar supplies both size measurement and actual bytes. */
class WireWriter {
    MutableByteSpan bytes_;
    std::size_t maximum_;
    bool measure_;
public:
    std::size_t position{};
    Error error{Error::ok};
    WireWriter(MutableByteSpan bytes, std::size_t maximum, bool measure)
        : bytes_(bytes), maximum_(maximum), measure_(measure) {}
    void put(ByteSpan bytes) noexcept {
        if (error != Error::ok) return;
        if (bytes.size() > maximum_ - position) { error = Error::capacity; return; }
        if (!measure_) std::copy(bytes.begin(), bytes.end(), bytes_.begin() + position);
        position += bytes.size();
    }
    template <typename UInt> void integer(UInt value) noexcept {
        std::array<Byte, sizeof(UInt)> bytes{}; write_le(value, bytes); put(bytes);
    }
    void compact(std::uint64_t value) noexcept {
        if (value < params::COMPACT_U16) { integer(static_cast<Byte>(value)); return; }
        if (value <= std::numeric_limits<std::uint16_t>::max()) {
            integer(params::COMPACT_U16); integer(static_cast<std::uint16_t>(value)); return;
        }
        if (value <= std::numeric_limits<std::uint32_t>::max()) {
            integer(params::COMPACT_U32); integer(static_cast<std::uint32_t>(value)); return;
        }
        integer(params::COMPACT_U64); integer(value);
    }
};
} // namespace snowstorm::detail
