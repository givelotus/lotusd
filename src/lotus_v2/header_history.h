// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_HEADER_HISTORY_H
#define LOTUS_V2_HEADER_HISTORY_H

#include "tagged_hash.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace lotus::v2 {

using Hash256 = Hash;

inline constexpr Hash256 NULL_HASH{};

struct HeaderHistoryFrontier {
    uint64_t count{0};
    std::array<Hash256, 64> peaks{};

    bool operator==(const HeaderHistoryFrontier &) const = default;
    bool operator!=(const HeaderHistoryFrontier &) const = default;
};

struct HeaderInclusionProof {
    uint64_t leaf_height{0};
    uint64_t total_count{0};
    Hash256 block_hash{};
    std::vector<Hash256> siblings;

    bool operator==(const HeaderInclusionProof &) const = default;
    bool operator!=(const HeaderInclusionProof &) const = default;
};

Hash256 HeaderLeafHash(std::span<const uint8_t, 32> chain_id, uint64_t height,
                       const Hash256 &block_hash);

Hash256 HeaderInternalHash(std::span<const uint8_t, 32> chain_id, uint8_t level,
                           const Hash256 &left, const Hash256 &right);

HeaderHistoryFrontier AppendHeaderToFrontier(
    std::span<const uint8_t, 32> chain_id,
    const HeaderHistoryFrontier &prev,
    const Hash256 &block_hash);

Hash256 HeaderHistoryRoot(std::span<const uint8_t, 32> chain_id,
                          const HeaderHistoryFrontier &frontier);

bool VerifyHeaderInclusionProof(std::span<const uint8_t, 32> chain_id,
                                const HeaderInclusionProof &proof,
                                const Hash256 &expected_root);

std::vector<uint8_t> EncodeHeaderHistoryFrontier(
    const HeaderHistoryFrontier &frontier);
bool DecodeHeaderHistoryFrontier(std::span<const uint8_t> bytes,
                                 HeaderHistoryFrontier &out);

std::vector<uint8_t> EncodeHeaderInclusionProof(
    const HeaderInclusionProof &proof);
bool DecodeHeaderInclusionProof(std::span<const uint8_t> bytes,
                                HeaderInclusionProof &out);

class HeaderHistoryTree {
public:
    HeaderHistoryTree() = default;

    void Clear();
    uint64_t Count() const noexcept { return m_frontier.count; }
    const HeaderHistoryFrontier &GetFrontier() const noexcept {
        return m_frontier;
    }
    bool GetFrontierAt(uint64_t target_count,
                       HeaderHistoryFrontier &out) const;

    void Append(std::span<const uint8_t, 32> chain_id,
                const Hash256 &block_hash);
    bool PopBack();

    Hash256 GetRoot(std::span<const uint8_t, 32> chain_id) const;
    Hash256 GetRootAt(std::span<const uint8_t, 32> chain_id,
                      uint64_t target_count) const;
    Hash256 GetLeafBlockHash(uint64_t height) const;

    bool BuildInclusionProof(std::span<const uint8_t, 32> chain_id,
                             uint64_t height,
                             HeaderInclusionProof &out) const;
    bool BuildInclusionProofAt(std::span<const uint8_t, 32> chain_id,
                               uint64_t height, uint64_t target_count,
                               HeaderInclusionProof &out) const;

    bool SaveToFile(const std::filesystem::path &path) const;
    bool LoadFromFile(const std::filesystem::path &path);

private:
    HeaderHistoryFrontier m_frontier{};
    std::vector<Hash256> m_block_hashes;
    std::array<std::vector<Hash256>, 64> m_levels{};
};

} // namespace lotus::v2

#endif // LOTUS_V2_HEADER_HISTORY_H
