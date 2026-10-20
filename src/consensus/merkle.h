// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MERKLE_H
#define BITCOIN_CONSENSUS_MERKLE_H

#include <cstddef>
#include <functional>
#include <vector>

#include <primitives/block.h>
#include <uint256.h>

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool *mutated = nullptr);

/**
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockMerkleRoot(const CBlock &block, bool *mutated = nullptr);

/**
 * Runs fn(i) for every i in [0, n_tasks), possibly on several threads, and
 * returns once all have returned. Supplied by the caller (consensus code
 * owns no threads); running every task on the calling thread is valid.
 */
using MerkleTaskRunner = std::function<void(
    size_t n_tasks, const std::function<void(size_t)> &fn)>;

/**
 * The same root and mutation flag as ComputeMerkleRoot over leaf(0) ...
 * leaf(n - 1), computed as independent subtrees of chunk_leaves leaves (a
 * power of two) passed to run, then combined. Each full subtree is exactly
 * the corresponding part of the tree; the last, partial one is completed by
 * hashing its root with itself once for every level that it lacks, which is
 * what ComputeMerkleRoot's duplication of an odd level's last node does.
 * Pairs never straddle subtrees, so mutation detection sees the same pairs.
 */
uint256 ComputeMerkleRootChunked(size_t n,
                                 const std::function<uint256(size_t)> &leaf,
                                 bool *mutated, size_t chunk_leaves,
                                 const MerkleTaskRunner &run);

/** BlockMerkleRoot through ComputeMerkleRootChunked, with n_tasks subtrees
 * (rounded so each has a power-of-two number of transactions). */
uint256 BlockMerkleRootParallel(const CBlock &block, bool *mutated,
                                size_t n_tasks, const MerkleTaskRunner &run);

#endif // BITCOIN_CONSENSUS_MERKLE_H
