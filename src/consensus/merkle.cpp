// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <hash.h>

#include <algorithm>
#include <cassert>

/*     WARNING! If you're reading this because you're learning about crypto
       and/or designing a new system that will use merkle trees, keep in mind
       that the following merkle tree algorithm has a serious flaw related to
       duplicate txids, resulting in a vulnerability (CVE-2012-2459).

       The reason is that if the number of hashes in the list at a given level
       is odd, the last one is duplicated before computing the next level (which
       is unusual in Merkle trees). This results in certain sequences of
       transactions leading to the same merkle root. For example, these two
       trees:

                    A               A
                  /  \            /   \
                B     C         B       C
               / \    |        / \     / \
              D   E   F       D   E   F   F
             / \ / \ / \     / \ / \ / \ / \
             1 2 3 4 5 6     1 2 3 4 5 6 5 6

       for transaction lists [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6] (where 5 and
       6 are repeated) result in the same root hash A (because the hash of both
       of (F) and (F,F) is C).

       The vulnerability results from being able to send a block with such a
       transaction list, with the same merkle root, and the same block hash as
       the original without duplication, resulting in failed validation. If the
       receiving node proceeds to mark that block as permanently invalid
       however, it will fail to accept further unmodified (and thus potentially
       valid) versions of the same block. We defend against this by detecting
       the case where we would hash two identical hashes at the end of the list
       together, and treating that identically to the block having an invalid
       merkle root. Assuming no double-SHA256 collisions, this will detect all
       known ways of changing the transactions without affecting the merkle
       root.
*/

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool *mutated) {
    bool mutation = false;
    while (hashes.size() > 1) {
        if (mutated) {
            for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
                if (hashes[pos] == hashes[pos + 1]) {
                    mutation = true;
                }
            }
        }
        if (hashes.size() & 1) {
            hashes.push_back(hashes.back());
        }
        SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
        hashes.resize(hashes.size() / 2);
    }
    if (mutated) {
        *mutated = mutation;
    }
    if (hashes.size() == 0) {
        return uint256();
    }
    return hashes[0];
}

uint256 BlockMerkleRoot(const CBlock &block, bool *mutated) {
    std::vector<uint256> leaves;
    // capacity rounded up to even
    leaves.reserve((block.vtx.size() + 1) & ~1ULL);
    for (size_t s = 0; s < block.vtx.size(); s++) {
        leaves.push_back(block.vtx[s]->GetId());
    }
    return ComputeMerkleRoot(std::move(leaves), mutated);
}

uint256 ComputeMerkleRootChunked(size_t n,
                                 const std::function<uint256(size_t)> &leaf,
                                 bool *mutated, size_t chunk_leaves,
                                 const MerkleTaskRunner &run) {
    assert(chunk_leaves > 0 && (chunk_leaves & (chunk_leaves - 1)) == 0);
    const size_t n_chunks{(n + chunk_leaves - 1) / chunk_leaves};
    if (n_chunks <= 1) {
        std::vector<uint256> hashes;
        hashes.reserve((n + 1) & ~size_t{1});
        for (size_t i = 0; i < n; ++i) {
            hashes.push_back(leaf(i));
        }
        return ComputeMerkleRoot(std::move(hashes), mutated);
    }
    std::vector<uint256> roots(n_chunks);
    // Not std::vector<bool>: tasks write their own elements concurrently.
    std::vector<uint8_t> chunk_mutated(n_chunks, 0);
    run(n_chunks, [&](size_t c) {
        const size_t begin{c * chunk_leaves};
        const size_t end{std::min(n, begin + chunk_leaves)};
        std::vector<uint256> hashes;
        // capacity rounded up to even, as BlockMerkleRoot does
        hashes.reserve(((end - begin) + 1) & ~size_t{1});
        for (size_t i = begin; i < end; ++i) {
            hashes.push_back(leaf(i));
        }
        bool m{false};
        uint256 root{
            ComputeMerkleRoot(std::move(hashes), mutated ? &m : nullptr)};
        // Only the last chunk can be partial. ComputeMerkleRoot stops once
        // its level has one node, after ceil(log2(size)) levels; in the
        // whole tree that node is the odd last node of each remaining level
        // below the chunk's height, so it is hashed with itself once per
        // missing level. (No pair is formed, so no mutation check applies.)
        size_t levels_done{0};
        while ((size_t{1} << levels_done) < end - begin) {
            ++levels_done;
        }
        size_t chunk_height{0};
        while ((size_t{1} << chunk_height) < chunk_leaves) {
            ++chunk_height;
        }
        for (size_t l = levels_done; l < chunk_height; ++l) {
            uint256 pair[2]{root, root};
            SHA256D64(root.begin(), pair[0].begin(), 1);
        }
        roots[c] = root;
        chunk_mutated[c] = m;
    });
    bool top_mutated{false};
    uint256 root{
        ComputeMerkleRoot(std::move(roots), mutated ? &top_mutated : nullptr)};
    if (mutated) {
        *mutated = top_mutated ||
                   std::any_of(chunk_mutated.begin(), chunk_mutated.end(),
                               [](uint8_t m) { return m != 0; });
    }
    return root;
}

uint256 BlockMerkleRootParallel(const CBlock &block, bool *mutated,
                                size_t n_tasks, const MerkleTaskRunner &run) {
    const size_t n{block.vtx.size()};
    // The smallest power of two giving at most n_tasks subtrees.
    size_t chunk{1};
    while (chunk * std::max<size_t>(n_tasks, 1) < n) {
        chunk <<= 1;
    }
    return ComputeMerkleRootChunked(
        n, [&](size_t i) -> uint256 { return block.vtx[i]->GetId(); }, mutated,
        chunk, run);
}
