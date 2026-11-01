// Copyright (c) 2026 The Lotus developers
#include "header_history.h"

#include <algorithm>
#include <bit>
#include <cstring>

namespace lotus::v2 {
namespace {

void PutLE64(uint8_t *dst, uint64_t val) noexcept {
    for (unsigned i = 0; i < 8; ++i) {
        dst[i] = static_cast<uint8_t>((val >> (8 * i)) & 0xFFu);
    }
}

uint64_t ReadLE64(const uint8_t *src) noexcept {
    uint64_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
        val |= static_cast<uint64_t>(src[i]) << (8 * i);
    }
    return val;
}

unsigned ComputeTreeDepth(uint64_t total_count) noexcept {
    if (total_count <= 1) {
        return 0;
    }
    if ((total_count & (total_count - 1)) == 0) {
        return static_cast<unsigned>(std::countr_zero(total_count));
    }
    return static_cast<unsigned>(64 - std::countl_zero(total_count));
}

// Commits the leaf count on top of the tree root. Without this, a proof's count
// is unauthenticated: a leaf whose path crosses only complete subtrees verifies
// against the same tree root under many different counts.
Hash256 BindCountToTreeRoot(std::span<const uint8_t, 32> chain_id, uint64_t count,
                            const Hash256 &tree_root) {
    std::array<uint8_t, 32 + 1 + 8 + 32> payload{};
    std::memcpy(payload.data(), chain_id.data(), 32);
    payload[32] = 0x02;
    PutLE64(payload.data() + 33, count);
    std::memcpy(payload.data() + 41, tree_root.data(), 32);
    return TaggedHash(HashDomain::HeaderHistory, payload);
}

} // namespace

Hash256 HeaderLeafHash(std::span<const uint8_t, 32> chain_id, uint64_t height,
                       const Hash256 &block_hash) {
    std::array<uint8_t, 32 + 1 + 8 + 32> payload{};
    std::memcpy(payload.data(), chain_id.data(), 32);
    payload[32] = 0x00;
    PutLE64(payload.data() + 33, height);
    std::memcpy(payload.data() + 41, block_hash.data(), 32);
    return TaggedHash(HashDomain::HeaderHistory, payload);
}

Hash256 HeaderInternalHash(std::span<const uint8_t, 32> chain_id, uint8_t level,
                           const Hash256 &left, const Hash256 &right) {
    std::array<uint8_t, 32 + 1 + 1 + 32 + 32> payload{};
    std::memcpy(payload.data(), chain_id.data(), 32);
    payload[32] = 0x01;
    payload[33] = level;
    std::memcpy(payload.data() + 34, left.data(), 32);
    std::memcpy(payload.data() + 66, right.data(), 32);
    return TaggedHash(HashDomain::HeaderHistory, payload);
}

HeaderHistoryFrontier AppendHeaderToFrontier(
    std::span<const uint8_t, 32> chain_id,
    const HeaderHistoryFrontier &prev,
    const Hash256 &block_hash) {
    HeaderHistoryFrontier next = prev;
    const uint64_t height = prev.count;
    Hash256 cur = HeaderLeafHash(chain_id, height, block_hash);
    for (uint8_t k = 0; k < 64; ++k) {
        if (((height >> k) & 1ULL) != 0) {
            cur = HeaderInternalHash(chain_id, k, next.peaks[k], cur);
            next.peaks[k] = NULL_HASH;
        } else {
            next.peaks[k] = cur;
            break;
        }
    }
    next.count = height + 1;
    return next;
}

Hash256 HeaderHistoryRoot(std::span<const uint8_t, 32> chain_id,
                          const HeaderHistoryFrontier &frontier) {
    if (frontier.count == 0) {
        return Hash256{};
    }
    const unsigned k0 = static_cast<unsigned>(std::countr_zero(frontier.count));
    const unsigned L = static_cast<unsigned>(63 - std::countl_zero(frontier.count));
    if (k0 == L) {
        return BindCountToTreeRoot(chain_id, frontier.count, frontier.peaks[L]);
    }
    Hash256 acc = HeaderInternalHash(
        chain_id, static_cast<uint8_t>(k0), frontier.peaks[k0], NULL_HASH);
    for (unsigned k = k0 + 1; k <= L; ++k) {
        if (((frontier.count >> k) & 1ULL) != 0) {
            acc = HeaderInternalHash(
                chain_id, static_cast<uint8_t>(k), frontier.peaks[k], acc);
        } else {
            acc = HeaderInternalHash(
                chain_id, static_cast<uint8_t>(k), acc, NULL_HASH);
        }
    }
    return BindCountToTreeRoot(chain_id, frontier.count, acc);
}

bool VerifyHeaderInclusionProof(std::span<const uint8_t, 32> chain_id,
                                const HeaderInclusionProof &proof,
                                const Hash256 &expected_root) {
    if (proof.total_count == 0 || proof.leaf_height >= proof.total_count) {
        return false;
    }
    const unsigned D = ComputeTreeDepth(proof.total_count);
    if (proof.siblings.size() != D) {
        return false;
    }
    Hash256 cur = HeaderLeafHash(chain_id, proof.leaf_height, proof.block_hash);
    for (unsigned k = 0; k < D; ++k) {
        const uint64_t idx = proof.leaf_height >> k;
        if ((idx & 1ULL) == 0) {
            const uint64_t right_subtree_start = (idx + 1ULL) << k;
            if (right_subtree_start >= proof.total_count) {
                if (proof.siblings[k] != NULL_HASH) {
                    return false;
                }
            } else {
                if (proof.siblings[k] == NULL_HASH) {
                    return false;
                }
            }
            cur = HeaderInternalHash(
                chain_id, static_cast<uint8_t>(k), cur, proof.siblings[k]);
        } else {
            if (proof.siblings[k] == NULL_HASH) {
                return false;
            }
            cur = HeaderInternalHash(
                chain_id, static_cast<uint8_t>(k), proof.siblings[k], cur);
        }
    }
    return BindCountToTreeRoot(chain_id, proof.total_count, cur) == expected_root;
}

std::vector<uint8_t> EncodeHeaderHistoryFrontier(
    const HeaderHistoryFrontier &frontier) {
    const unsigned active_peaks = static_cast<unsigned>(std::popcount(frontier.count));
    std::vector<uint8_t> out(8 + static_cast<size_t>(active_peaks) * 32);
    PutLE64(out.data(), frontier.count);
    size_t offset = 8;
    for (unsigned k = 0; k < 64; ++k) {
        if (((frontier.count >> k) & 1ULL) != 0) {
            std::memcpy(out.data() + offset, frontier.peaks[k].data(), 32);
            offset += 32;
        }
    }
    return out;
}

bool DecodeHeaderHistoryFrontier(std::span<const uint8_t> bytes,
                                 HeaderHistoryFrontier &out) {
    if (bytes.size() < 8) {
        return false;
    }
    const uint64_t count = ReadLE64(bytes.data());
    const unsigned active_peaks = static_cast<unsigned>(std::popcount(count));
    if (bytes.size() != 8 + static_cast<size_t>(active_peaks) * 32) {
        return false;
    }
    HeaderHistoryFrontier decoded{};
    decoded.count = count;
    size_t offset = 8;
    for (unsigned k = 0; k < 64; ++k) {
        if (((count >> k) & 1ULL) != 0) {
            std::memcpy(decoded.peaks[k].data(), bytes.data() + offset, 32);
            offset += 32;
        }
    }
    out = decoded;
    return true;
}

std::vector<uint8_t> EncodeHeaderInclusionProof(
    const HeaderInclusionProof &proof) {
    const uint8_t num_siblings = static_cast<uint8_t>(
        std::min<size_t>(proof.siblings.size(), 64));
    std::vector<uint8_t> out(8 + 8 + 32 + 1 + static_cast<size_t>(num_siblings) * 32);
    PutLE64(out.data(), proof.leaf_height);
    PutLE64(out.data() + 8, proof.total_count);
    std::memcpy(out.data() + 16, proof.block_hash.data(), 32);
    out[48] = num_siblings;
    size_t offset = 49;
    for (uint8_t i = 0; i < num_siblings; ++i) {
        std::memcpy(out.data() + offset, proof.siblings[i].data(), 32);
        offset += 32;
    }
    return out;
}

bool DecodeHeaderInclusionProof(std::span<const uint8_t> bytes,
                                HeaderInclusionProof &out) {
    if (bytes.size() < 49) {
        return false;
    }
    const uint64_t leaf_height = ReadLE64(bytes.data());
    const uint64_t total_count = ReadLE64(bytes.data() + 8);
    const uint8_t num_siblings = bytes[48];
    if (num_siblings > 64 ||
        bytes.size() != 49 + static_cast<size_t>(num_siblings) * 32) {
        return false;
    }
    HeaderInclusionProof decoded{};
    decoded.leaf_height = leaf_height;
    decoded.total_count = total_count;
    std::memcpy(decoded.block_hash.data(), bytes.data() + 16, 32);
    decoded.siblings.resize(num_siblings);
    size_t offset = 49;
    for (uint8_t i = 0; i < num_siblings; ++i) {
        std::memcpy(decoded.siblings[i].data(), bytes.data() + offset, 32);
        offset += 32;
    }
    out = std::move(decoded);
    return true;
}

void HeaderHistoryTree::Clear() {
    m_frontier = HeaderHistoryFrontier{};
    m_block_hashes.clear();
    for (auto &lvl : m_levels) {
        lvl.clear();
    }
}

bool HeaderHistoryTree::GetFrontierAt(uint64_t target_count,
                                      HeaderHistoryFrontier &out) const {
    if (target_count > m_frontier.count) {
        return false;
    }
    HeaderHistoryFrontier f{};
    f.count = target_count;
    for (unsigned k = 0; k < 64; ++k) {
        if (((target_count >> k) & 1ULL) != 0) {
            const uint64_t idx = (target_count >> k) - 1;
            if (idx >= m_levels[k].size()) {
                return false;
            }
            f.peaks[k] = m_levels[k][static_cast<size_t>(idx)];
        }
    }
    out = f;
    return true;
}

void HeaderHistoryTree::Append(std::span<const uint8_t, 32> chain_id,
                               const Hash256 &block_hash) {
    const uint64_t height = m_frontier.count;
    m_block_hashes.push_back(block_hash);
    Hash256 cur = HeaderLeafHash(chain_id, height, block_hash);
    m_levels[0].push_back(cur);
    for (uint8_t k = 0; k < 64; ++k) {
        if (((height >> k) & 1ULL) != 0) {
            cur = HeaderInternalHash(chain_id, k, m_frontier.peaks[k], cur);
            m_frontier.peaks[k] = NULL_HASH;
            if (static_cast<size_t>(k + 1) < m_levels.size()) {
                m_levels[k + 1].push_back(cur);
            }
        } else {
            m_frontier.peaks[k] = cur;
            break;
        }
    }
    m_frontier.count = height + 1;
}

bool HeaderHistoryTree::PopBack() {
    if (m_frontier.count == 0) {
        return false;
    }
    const uint64_t new_count = m_frontier.count - 1;
    m_block_hashes.pop_back();
    for (unsigned k = 0; k < 64; ++k) {
        const uint64_t expected_size = new_count >> k;
        while (m_levels[k].size() > expected_size) {
            m_levels[k].pop_back();
        }
    }
    HeaderHistoryFrontier restored{};
    if (!GetFrontierAt(new_count, restored)) {
        return false;
    }
    m_frontier = restored;
    return true;
}

Hash256 HeaderHistoryTree::GetRoot(
    std::span<const uint8_t, 32> chain_id) const {
    return HeaderHistoryRoot(chain_id, m_frontier);
}

Hash256 HeaderHistoryTree::GetRootAt(std::span<const uint8_t, 32> chain_id,
                                     uint64_t target_count) const {
    HeaderHistoryFrontier f{};
    if (!GetFrontierAt(target_count, f)) {
        return Hash256{};
    }
    return HeaderHistoryRoot(chain_id, f);
}

Hash256 HeaderHistoryTree::GetLeafBlockHash(uint64_t height) const {
    if (height >= m_block_hashes.size()) {
        return Hash256{};
    }
    return m_block_hashes[static_cast<size_t>(height)];
}

bool HeaderHistoryTree::BuildInclusionProof(
    std::span<const uint8_t, 32> chain_id, uint64_t height,
    HeaderInclusionProof &out) const {
    return BuildInclusionProofAt(chain_id, height, m_frontier.count, out);
}

bool HeaderHistoryTree::BuildInclusionProofAt(
    std::span<const uint8_t, 32> chain_id, uint64_t height,
    uint64_t target_count, HeaderInclusionProof &out) const {
    if (target_count == 0 || target_count > m_frontier.count ||
        height >= target_count) {
        return false;
    }
    const unsigned D = ComputeTreeDepth(target_count);

    // Precompute right_edge_acc[k]: root of the partial subtree starting at
    // (target_count >> k) << k at level k, when (target_count & ((1ULL << k) - 1)) != 0.
    std::array<Hash256, 65> right_edge_acc{};
    const unsigned k0 = static_cast<unsigned>(std::countr_zero(target_count));
    if (k0 < D) {
        const uint64_t idx0 = (target_count >> k0) - 1;
        if (idx0 >= m_levels[k0].size()) {
            return false;
        }
        Hash256 acc = HeaderInternalHash(
            chain_id, static_cast<uint8_t>(k0),
            m_levels[k0][static_cast<size_t>(idx0)], NULL_HASH);
        right_edge_acc[k0 + 1] = acc;
        for (unsigned k = k0 + 1; k < D; ++k) {
            if (((target_count >> k) & 1ULL) != 0) {
                const uint64_t idx = (target_count >> k) - 1;
                if (idx >= m_levels[k].size()) {
                    return false;
                }
                acc = HeaderInternalHash(
                    chain_id, static_cast<uint8_t>(k),
                    m_levels[k][static_cast<size_t>(idx)], acc);
            } else {
                acc = HeaderInternalHash(
                    chain_id, static_cast<uint8_t>(k), acc, NULL_HASH);
            }
            right_edge_acc[k + 1] = acc;
        }
    }

    HeaderInclusionProof proof{};
    proof.leaf_height = height;
    proof.total_count = target_count;
    proof.block_hash = m_block_hashes[static_cast<size_t>(height)];
    proof.siblings.resize(D);

    for (unsigned k = 0; k < D; ++k) {
        const uint64_t idx = height >> k;
        const uint64_t sib_idx = idx ^ 1ULL;
        const uint64_t complete_count = target_count >> k;
        if (sib_idx < complete_count) {
            if (sib_idx >= m_levels[k].size()) {
                return false;
            }
            proof.siblings[k] = m_levels[k][static_cast<size_t>(sib_idx)];
        } else if (sib_idx == complete_count) {
            const uint64_t rem = target_count & ((1ULL << k) - 1ULL);
            proof.siblings[k] = (rem == 0) ? NULL_HASH : right_edge_acc[k];
        } else {
            proof.siblings[k] = NULL_HASH;
        }
    }

    out = std::move(proof);
    return true;
}

} // namespace lotus::v2
