// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <cstddef>
#include <cstdint>
namespace snowstorm::params {
// Fixed protocol encoding: negotiated wire version.
inline constexpr std::uint8_t PROTOCOL_VERSION = 1;
// Operational maximum payload bytes.
inline constexpr std::uint64_t MESSAGE_BYTES = std::uint64_t{1} << 21;
// Operational framing allowance used by the derived Config M ceiling.
inline constexpr std::uint64_t FIRST_MESSAGE_OVERHEAD = 256;
// Operational connected-peer ceiling.
inline constexpr std::uint64_t MAX_PEERS = 1024;
// Operational ranges-per-request ceiling.
inline constexpr std::uint64_t MAX_RANGES = 64;
// Operational cells-per-message ceiling.
inline constexpr std::uint64_t MAX_MESSAGE_CELLS = 65536;
// Operational usable donors per ID.
inline constexpr std::uint64_t MAX_DONORS = 8;
// Operational upper bound on fixed peer-owned allocation bytes.
inline constexpr std::uint64_t PEER_FLOOR_BYTES = 1024;
// Operational upper bound on fixed node-owned allocation bytes.
inline constexpr std::uint64_t NODE_FLOOR_BYTES = 4096;
// Derived fixed wire encoding: int32 + three uint64, independent of padding.
inline constexpr std::size_t CELL_WIRE_BYTES = 28;
// Fixed protocol encoding: CompactSize uint16 marker.
inline constexpr std::uint8_t COMPACT_U16 = 253;
// Fixed protocol encoding: CompactSize uint32 marker.
inline constexpr std::uint8_t COMPACT_U32 = 254;
// Fixed protocol encoding: CompactSize uint64 marker.
inline constexpr std::uint8_t COMPACT_U64 = 255;
} // namespace snowstorm::params
