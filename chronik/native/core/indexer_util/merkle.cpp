// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer merkle.rs.

#include <chronik/native/merkle.h>

#include <algorithm>
#include <bit>
#include <optional>
#include <stdexcept>
#include <string>

namespace chronik::native {

Sha256dFn Sha256dFromSha256(std::function<void(ByteView, uint8_t[32])> sha256) {
    return [sha256 = std::move(sha256)](ByteView data) {
        uint8_t first[32];
        sha256(data, first);
        Hash32 out;
        sha256(ByteView(first, 32), out.b.data());
        return out;
    };
}

MerkleTreeError MerkleTreeError::BadArgs() {
    return MerkleTreeError(Kind::BadArgs, "Invalid merkle tree arguments", 0,
                           0);
}

MerkleTreeError MerkleTreeError::HashCountMismatch(size_t expected,
                                                   size_t actual) {
    return MerkleTreeError(Kind::HashCountMismatch,
                           "Expected " + std::to_string(expected) +
                               " hashes from provider, got " +
                               std::to_string(actual),
                           expected, actual);
}

size_t CalcBranchLen(size_t num_hashes) {
    if (num_hashes == 0) {
        throw std::invalid_argument("assertion failed: num_hashes > 0");
    }
    // Ceil of log2(num_hashes) without floating-point arithmetic.
    return size_t(64 - std::countl_zero(uint64_t(num_hashes - 1)));
}

namespace {

Hash32 HashConcatenated(const Sha256dFn &sha256d, const Hash32 &h1,
                        const Hash32 &h2) {
    uint8_t concatenated[64];
    std::copy(h1.b.begin(), h1.b.end(), concatenated);
    std::copy(h2.b.begin(), h2.b.end(), concatenated + 32);
    return sha256d(ByteView(concatenated, 64));
}

std::pair<Hash32, std::vector<Hash32>>
BranchAndRoot(const Sha256dFn &sha256d, std::span<const Hash32> hashes,
              size_t index, std::optional<size_t> length_opt) {
    if (hashes.empty() || index >= hashes.size()) {
        throw MerkleTreeError::BadArgs();
    }
    const size_t nat_len = CalcBranchLen(hashes.size());
    const size_t length = length_opt.value_or(nat_len);
    if (length < nat_len) {
        throw MerkleTreeError::BadArgs();
    }
    std::vector<Hash32> working(hashes.begin(), hashes.end());
    std::vector<Hash32> branch;
    branch.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        // Bitcoin-style merkle: odd levels duplicate the last hash so pairs
        // are even before hashing.
        if (working.size() % 2 == 1) {
            working.push_back(working.back());
        }
        branch.push_back(working[index ^ 1]);
        index >>= 1;
        std::vector<Hash32> next;
        next.reserve(working.size() / 2);
        for (size_t j = 0; j < working.size(); j += 2) {
            next.push_back(HashConcatenated(sha256d, working[j], working[j + 1]));
        }
        working = std::move(next);
    }
    if (working.empty()) {
        throw MerkleTreeError::BadArgs();
    }
    return {working[0], std::move(branch)};
}

std::vector<Hash32> MerkleLevel(const Sha256dFn &sha256d,
                                std::span<const Hash32> hashes,
                                size_t depth_higher) {
    // length aligned to the segment size yields an empty partial segment.
    if (hashes.empty()) {
        return {};
    }
    const size_t size = size_t(1) << depth_higher;
    std::vector<Hash32> level;
    level.reserve((hashes.size() + size - 1) / size);
    size_t i = 0;
    while (i < hashes.size()) {
        const size_t end = std::min(i + size, hashes.size());
        level.push_back(
            BranchAndRoot(sha256d, hashes.subspan(i, end - i), 0, depth_higher)
                .first);
        i = end;
    }
    return level;
}

std::pair<Hash32, std::vector<Hash32>>
BranchAndRootFromLevel(const Sha256dFn &sha256d, std::span<const Hash32> level,
                       std::span<const Hash32> leaf_hashes, size_t index,
                       size_t depth_higher) {
    if (level.empty() || leaf_hashes.empty()) {
        throw MerkleTreeError::BadArgs();
    }
    const size_t leaf_index = (index >> depth_higher) << depth_higher;
    auto [leaf_root, leaf_branch] =
        BranchAndRoot(sha256d, leaf_hashes, index - leaf_index, depth_higher);
    const size_t level_index = index >> depth_higher;
    if (level_index >= level.size() || leaf_root != level[level_index]) {
        throw MerkleTreeError::BadArgs();
    }
    auto [root, level_branch] =
        BranchAndRoot(sha256d, level, level_index, std::nullopt);
    leaf_branch.insert(leaf_branch.end(), level_branch.begin(),
                       level_branch.end());
    return {root, std::move(leaf_branch)};
}

std::vector<Hash32> GetHashes(const MerkleHashGetter &get_hashes, size_t start,
                              size_t count) {
    std::vector<Hash32> hashes = get_hashes(start, count);
    if (hashes.size() != count) {
        throw MerkleTreeError::HashCountMismatch(count, hashes.size());
    }
    return hashes;
}

size_t DivCeil2(size_t n) { return (n + 1) / 2; }

} // namespace

std::pair<Hash32, std::vector<Hash32>>
MerkleRootAndBranch(const Sha256dFn &sha256d, std::span<const Hash32> hashes,
                    size_t index) {
    try {
        return BranchAndRoot(sha256d, hashes, index, std::nullopt);
    } catch (const MerkleTreeError &) {
        throw std::logic_error(
            "merkle_root_and_branch called with invalid args");
    }
}

void MerkleTree::Reset() {
    m_length = 0;
    m_depth_higher = 0;
    m_level.clear();
    m_initialized = false;
}

void MerkleTree::InitializeWithHashes(std::span<const Hash32> hashes) {
    if (hashes.empty()) {
        throw MerkleTreeError::BadArgs();
    }
    m_length = hashes.size();
    // Cache mid-tree: (branch_len + 1) / 2 above the leaves.
    m_depth_higher = DivCeil2(CalcBranchLen(m_length));
    m_level = MerkleLevel(m_sha256d, hashes, m_depth_higher);
    m_initialized = true;
}

void MerkleTree::ExtendTo(size_t length, const MerkleHashGetter &get_hashes) {
    if (length <= m_length) {
        return;
    }
    // Cache mid-tree: (branch_len + 1) / 2 above the leaves.
    const size_t new_depth = DivCeil2(CalcBranchLen(length));
    if (new_depth != m_depth_higher) {
        const auto hashes = GetHashes(get_hashes, 0, length);
        InitializeWithHashes(hashes);
        return;
    }
    const size_t start = LeafStart(m_length);
    const auto hashes = GetHashes(get_hashes, start, length - start);
    const size_t limit = start >> m_depth_higher;
    if (limit > m_level.size()) {
        throw MerkleTreeError::BadArgs();
    }
    m_level.resize(limit);
    const auto extra = MerkleLevel(m_sha256d, hashes, m_depth_higher);
    m_level.insert(m_level.end(), extra.begin(), extra.end());
    m_length = length;
}

std::vector<Hash32>
MerkleTree::LevelFor(size_t length, const MerkleHashGetter &get_hashes) const {
    // When length is segment-aligned and equals the cache length, the cached
    // mid-level is already complete.
    if (length == m_length && LeafStart(length) == length) {
        return m_level;
    }
    const size_t limit = length >> m_depth_higher;
    if (limit > m_level.size()) {
        throw MerkleTreeError::BadArgs();
    }
    std::vector<Hash32> ret(m_level.begin(), m_level.begin() + limit);
    const size_t leaf_start = LeafStart(length);
    const size_t count = std::min(
        SegmentLength(), length > leaf_start ? length - leaf_start : 0);
    if (count > 0) {
        const auto hashes = GetHashes(get_hashes, leaf_start, count);
        const auto extra = MerkleLevel(m_sha256d, hashes, m_depth_higher);
        ret.insert(ret.end(), extra.begin(), extra.end());
    }
    return ret;
}

void MerkleTree::Truncate(size_t length) {
    if (!m_initialized) {
        return;
    }
    if (length == 0) {
        Reset();
        return;
    }
    if (length >= m_length) {
        return;
    }
    // Drop any partial segment that intersects the truncated region.
    length = LeafStart(length);
    if (length == 0) {
        Reset();
        return;
    }
    const size_t limit = length >> m_depth_higher;
    if (limit < m_level.size()) {
        m_level.resize(limit);
    }
    m_length = length;
}

std::pair<Hash32, std::vector<Hash32>>
MerkleTree::MerkleRootAndBranch(size_t length, size_t index,
                                const MerkleHashGetter &get_hashes) {
    if (length == 0 || index >= length) {
        throw MerkleTreeError::BadArgs();
    }
    if (!m_initialized) {
        const auto hashes = GetHashes(get_hashes, 0, length);
        InitializeWithHashes(hashes);
    } else {
        ExtendTo(length, get_hashes);
    }
    if (length > m_length) {
        throw MerkleTreeError::BadArgs();
    }
    const size_t leaf_start = LeafStart(index);
    const size_t count = std::min(SegmentLength(), length - leaf_start);
    const auto leaf_hashes = GetHashes(get_hashes, leaf_start, count);

    if (length < SegmentLength()) {
        return BranchAndRoot(m_sha256d, leaf_hashes, index, std::nullopt);
    }
    const auto level = LevelFor(length, get_hashes);
    return BranchAndRootFromLevel(m_sha256d, level, leaf_hashes, index,
                                  m_depth_higher);
}

} // namespace chronik::native
