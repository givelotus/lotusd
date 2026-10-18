// Copyright (c) 2026 The Lotus developers
// Candidate V2 header primitives. No legacy block type depends on this file.
#ifndef LOTUS_V2_HEADER_H
#define LOTUS_V2_HEADER_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace lotus::v2 {

using Hash = std::array<uint8_t, 32>;
using ChainId = Hash;
constexpr size_t HEADER_SIZE = 134;
constexpr uint64_t MAX_TIME = (uint64_t{1} << 48) - 1;
constexpr uint32_t kHeaderVersion = 2;

struct Header {
    Hash prev_id{};
    uint32_t bits{};
    uint64_t time{};
    uint64_t nonce{};
    uint32_t version{};
    uint64_t size{};
    uint64_t height{};
    Hash tx_root{};
    Hash state_root{};
};

// Hash byte arrays retain digest order. Interpret them as little-endian
// unsigned integers only for PoW target comparison.
bool SerializeHeader(const Header &header, std::array<uint8_t, HEADER_SIZE> &out);
// Structural parse only. Caller validates version, height, target, size,
// roots, time eligibility and parent against its chain manifest and context.
bool ParseHeader(const uint8_t *data, size_t size, Header &out);
Hash BodyHash(const ChainId &chain_id, const Header &header);
bool WorkHash(const ChainId &chain_id, const Header &header, Hash &out);
bool BlockId(const ChainId &chain_id, const Header &header, Hash &out);

// Decode only canonical positive compact targets at or below pow_limit.
// pow_limit is a 32-byte little-endian unsigned integer. Failure leaves
// target unchanged. The parser and work/block hash functions likewise leave
// their outputs unchanged on failure.
bool DecodeTarget(uint32_t bits, const Hash &pow_limit, Hash &target);
bool MeetsTarget(const Hash &block_id, const Hash &target);

} // namespace lotus::v2
#endif
