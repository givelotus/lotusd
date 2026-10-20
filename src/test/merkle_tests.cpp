// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>

#include <util/strencodings.h>
#include <validation.h>

#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(merkle_tests, TestingSetup)

static uint256
ComputeMerkleRootFromBranch(const uint256 &leaf,
                            const std::vector<uint256> &vMerkleBranch,
                            uint32_t nIndex) {
    uint256 hash = leaf;
    for (std::vector<uint256>::const_iterator it = vMerkleBranch.begin();
         it != vMerkleBranch.end(); ++it) {
        if (nIndex & 1) {
            hash = Hash(*it, hash);
        } else {
            hash = Hash(hash, *it);
        }
        nIndex >>= 1;
    }
    return hash;
}

/**
 * This implements a constant-space merkle root/path calculator, limited to 2^32
 * leaves.
 */
static void MerkleComputation(const std::vector<uint256> &leaves,
                              uint256 *proot, bool *pmutated,
                              uint32_t branchpos,
                              std::vector<uint256> *pbranch) {
    if (pbranch) {
        pbranch->clear();
    }
    if (leaves.size() == 0) {
        if (pmutated) {
            *pmutated = false;
        }
        if (proot) {
            *proot = uint256();
        }
        return;
    }
    bool mutated = false;
    // count is the number of leaves processed so far.
    uint32_t count = 0;
    // inner is an array of eagerly computed subtree hashes, indexed by tree
    // level (0 being the leaves).
    // For example, when count is 25 (11001 in binary), inner[4] is the hash of
    // the first 16 leaves, inner[3] of the next 8 leaves, and inner[0] equal to
    // the last leaf. The other inner entries are undefined.
    uint256 inner[32];
    // Which position in inner is a hash that depends on the matching leaf.
    int matchlevel = -1;
    // First process all leaves into 'inner' values.
    while (count < leaves.size()) {
        uint256 h = leaves[count];
        bool matchh = count == branchpos;
        count++;
        int level;
        // For each of the lower bits in count that are 0, do 1 step. Each
        // corresponds to an inner value that existed before processing the
        // current leaf, and each needs a hash to combine it.
        for (level = 0; !(count & (((uint32_t)1) << level)); level++) {
            if (pbranch) {
                if (matchh) {
                    pbranch->push_back(inner[level]);
                } else if (matchlevel == level) {
                    pbranch->push_back(h);
                    matchh = true;
                }
            }
            mutated |= (inner[level] == h);
            CHash256().Write(inner[level]).Write(h).Finalize(h);
        }
        // Store the resulting hash at inner position level.
        inner[level] = h;
        if (matchh) {
            matchlevel = level;
        }
    }
    // Do a final 'sweep' over the rightmost branch of the tree to process
    // odd levels, and reduce everything to a single top value.
    // Level is the level (counted from the bottom) up to which we've sweeped.
    int level = 0;
    // As long as bit number level in count is zero, skip it. It means there
    // is nothing left at this level.
    while (!(count & (((uint32_t)1) << level))) {
        level++;
    }
    uint256 h = inner[level];
    bool matchh = matchlevel == level;
    while (count != (((uint32_t)1) << level)) {
        // If we reach this point, h is an inner value that is not the top.
        // We combine it with itself (Bitcoin's special rule for odd levels in
        // the tree) to produce a higher level one.
        if (pbranch && matchh) {
            pbranch->push_back(h);
        }
        CHash256().Write(h).Write(h).Finalize(h);
        // Increment count to the value it would have if two entries at this
        // level had existed.
        count += (((uint32_t)1) << level);
        level++;
        // And propagate the result upwards accordingly.
        while (!(count & (((uint32_t)1) << level))) {
            if (pbranch) {
                if (matchh) {
                    pbranch->push_back(inner[level]);
                } else if (matchlevel == level) {
                    pbranch->push_back(h);
                    matchh = true;
                }
            }
            CHash256().Write(inner[level]).Write(h).Finalize(h);
            level++;
        }
    }
    // Return result.
    if (pmutated) {
        *pmutated = mutated;
    }
    if (proot) {
        *proot = h;
    }
}

static std::vector<uint256>
ComputeMerkleBranch(const std::vector<uint256> &leaves, uint32_t position) {
    std::vector<uint256> ret;
    MerkleComputation(leaves, nullptr, nullptr, position, &ret);
    return ret;
}

static std::vector<uint256> BlockMerkleBranch(const CBlock &block,
                                              uint32_t position) {
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    for (size_t s = 0; s < block.vtx.size(); s++) {
        leaves[s] = block.vtx[s]->GetHash();
    }
    return ComputeMerkleBranch(leaves, position);
}

// Older version of the merkle root computation code, for comparison.
static uint256 BlockBuildMerkleTree(const CBlock &block, bool *fMutated,
                                    std::vector<uint256> &vMerkleTree) {
    vMerkleTree.clear();
    // Safe upper bound for the number of total nodes.
    vMerkleTree.reserve(block.vtx.size() * 2 + 16);
    for (std::vector<CTransactionRef>::const_iterator it(block.vtx.begin());
         it != block.vtx.end(); ++it) {
        vMerkleTree.push_back((*it)->GetId());
    }
    int j = 0;
    bool mutated = false;
    for (int nSize = block.vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
        for (int i = 0; i < nSize; i += 2) {
            int i2 = std::min(i + 1, nSize - 1);
            if (i2 == i + 1 && i2 + 1 == nSize &&
                vMerkleTree[j + i] == vMerkleTree[j + i2]) {
                // Two identical hashes at the end of the list at a particular
                // level.
                mutated = true;
            }
            vMerkleTree.push_back(
                Hash(vMerkleTree[j + i], vMerkleTree[j + i2]));
        }
        j += nSize;
    }
    if (fMutated) {
        *fMutated = mutated;
    }
    return (vMerkleTree.empty() ? uint256() : vMerkleTree.back());
}

// Older version of the merkle branch computation code, for comparison.
static std::vector<uint256>
BlockGetMerkleBranch(const CBlock &block,
                     const std::vector<uint256> &vMerkleTree, int nIndex) {
    std::vector<uint256> vMerkleBranch;
    int j = 0;
    for (int nSize = block.vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
        int i = std::min(nIndex ^ 1, nSize - 1);
        vMerkleBranch.push_back(vMerkleTree[j + i]);
        nIndex >>= 1;
        j += nSize;
    }
    return vMerkleBranch;
}

static inline int ctz(uint32_t i) {
    if (i == 0) {
        return 0;
    }
    int j = 0;
    while (!(i & 1)) {
        j++;
        i >>= 1;
    }
    return j;
}

BOOST_AUTO_TEST_CASE(merkle_test) {
    for (int i = 0; i < 32; i++) {
        // Try 32 block sizes: all sizes from 0 to 16 inclusive, and then 15
        // random sizes.
        int ntx = (i <= 16) ? i : 17 + (m_rng.randrange(4000));
        // Try up to 3 mutations.
        for (int mutate = 0; mutate <= 3; mutate++) {
            // The last how many transactions to duplicate first.
            int duplicate1 = mutate >= 1 ? 1 << ctz(ntx) : 0;
            if (duplicate1 >= ntx) {
                // Duplication of the entire tree results in a different root
                // (it adds a level).
                break;
            }

            // The resulting number of transactions after the first duplication.
            int ntx1 = ntx + duplicate1;
            // Likewise for the second mutation.
            int duplicate2 = mutate >= 2 ? 1 << ctz(ntx1) : 0;
            if (duplicate2 >= ntx1) {
                break;
            }
            int ntx2 = ntx1 + duplicate2;
            // And for the third mutation.
            int duplicate3 = mutate >= 3 ? 1 << ctz(ntx2) : 0;
            if (duplicate3 >= ntx2) {
                break;
            }
            int ntx3 = ntx2 + duplicate3;
            // Build a block with ntx different transactions.
            CBlock block;
            block.vtx.resize(ntx);
            for (int j = 0; j < ntx; j++) {
                CMutableTransaction mtx;
                mtx.nLockTime = j;
                block.vtx[j] = MakeTransactionRef(std::move(mtx));
            }
            // Compute the root of the block before mutating it.
            bool unmutatedMutated = false;
            uint256 unmutatedRoot = BlockMerkleRoot(block, &unmutatedMutated);
            BOOST_CHECK(unmutatedMutated == false);
            // Optionally mutate by duplicating the last transactions, resulting
            // in the same merkle root.
            block.vtx.resize(ntx3);
            for (int j = 0; j < duplicate1; j++) {
                block.vtx[ntx + j] = block.vtx[ntx + j - duplicate1];
            }
            for (int j = 0; j < duplicate2; j++) {
                block.vtx[ntx1 + j] = block.vtx[ntx1 + j - duplicate2];
            }
            for (int j = 0; j < duplicate3; j++) {
                block.vtx[ntx2 + j] = block.vtx[ntx2 + j - duplicate3];
            }
            // Compute the merkle root and merkle tree using the old mechanism.
            bool oldMutated = false;
            std::vector<uint256> merkleTree;
            uint256 oldRoot =
                BlockBuildMerkleTree(block, &oldMutated, merkleTree);
            // Compute the merkle root using the new mechanism.
            bool newMutated = false;
            uint256 newRoot = BlockMerkleRoot(block, &newMutated);
            BOOST_CHECK(oldRoot == newRoot);
            BOOST_CHECK(newRoot == unmutatedRoot);
            BOOST_CHECK((newRoot == uint256()) == (ntx == 0));
            BOOST_CHECK(oldMutated == newMutated);
            BOOST_CHECK(newMutated == !!mutate);
            // If no mutation was done (once for every ntx value), try up to 16
            // branches.
            if (mutate == 0) {
                for (int loop = 0; loop < std::min(ntx, 16); loop++) {
                    // If ntx <= 16, try all branches. Otherwise, try 16 random
                    // ones.
                    int mtx = loop;
                    if (ntx > 16) {
                        mtx = m_rng.randrange(ntx);
                    }
                    std::vector<uint256> newBranch =
                        BlockMerkleBranch(block, mtx);
                    std::vector<uint256> oldBranch =
                        BlockGetMerkleBranch(block, merkleTree, mtx);
                    BOOST_CHECK(oldBranch == newBranch);
                    BOOST_CHECK(
                        ComputeMerkleRootFromBranch(block.vtx[mtx]->GetId(),
                                                    newBranch, mtx) == oldRoot);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(merkle_test_empty_block) {
    bool mutated = false;
    CBlock block;
    uint256 root = BlockMerkleRoot(block, &mutated);

    BOOST_CHECK_EQUAL(root.IsNull(), true);
    BOOST_CHECK_EQUAL(mutated, false);
}

BOOST_AUTO_TEST_CASE(merkle_test_oneTx_block) {
    bool mutated = false;
    CBlock block;

    block.vtx.resize(1);
    CMutableTransaction mtx;
    mtx.nLockTime = 0;
    block.vtx[0] = MakeTransactionRef(std::move(mtx));
    uint256 root = BlockMerkleRoot(block, &mutated);
    BOOST_CHECK_EQUAL(root, block.vtx[0]->GetHash());
    BOOST_CHECK_EQUAL(mutated, false);
}

BOOST_AUTO_TEST_CASE(merkle_test_OddTxWithRepeatedLastTx_block) {
    bool mutated;
    CBlock block, blockWithRepeatedLastTx;

    block.vtx.resize(3);

    for (std::size_t pos = 0; pos < block.vtx.size(); pos++) {
        CMutableTransaction mtx;
        mtx.nLockTime = pos;
        block.vtx[pos] = MakeTransactionRef(std::move(mtx));
    }

    blockWithRepeatedLastTx = block;
    blockWithRepeatedLastTx.vtx.push_back(blockWithRepeatedLastTx.vtx.back());

    uint256 rootofBlock = BlockMerkleRoot(block, &mutated);
    BOOST_CHECK_EQUAL(mutated, false);

    uint256 rootofBlockWithRepeatedLastTx =
        BlockMerkleRoot(blockWithRepeatedLastTx, &mutated);
    BOOST_CHECK_EQUAL(rootofBlock, rootofBlockWithRepeatedLastTx);
    BOOST_CHECK_EQUAL(mutated, true);
}

BOOST_AUTO_TEST_CASE(merkle_test_LeftSubtreeRightSubtree) {
    CBlock block, leftSubtreeBlock, rightSubtreeBlock;

    block.vtx.resize(4);
    std::size_t pos;
    for (pos = 0; pos < block.vtx.size(); pos++) {
        CMutableTransaction mtx;
        mtx.nLockTime = pos;
        block.vtx[pos] = MakeTransactionRef(std::move(mtx));
    }

    for (pos = 0; pos < block.vtx.size() / 2; pos++) {
        leftSubtreeBlock.vtx.push_back(block.vtx[pos]);
    }

    for (pos = block.vtx.size() / 2; pos < block.vtx.size(); pos++) {
        rightSubtreeBlock.vtx.push_back(block.vtx[pos]);
    }

    uint256 root = BlockMerkleRoot(block);
    uint256 rootOfLeftSubtree = BlockMerkleRoot(leftSubtreeBlock);
    uint256 rootOfRightSubtree = BlockMerkleRoot(rightSubtreeBlock);
    std::vector<uint256> leftRight;
    leftRight.push_back(rootOfLeftSubtree);
    leftRight.push_back(rootOfRightSubtree);
    uint256 rootOfLR = ComputeMerkleRoot(leftRight);

    BOOST_CHECK_EQUAL(root, rootOfLR);
}
namespace {
//! Runs every task on the calling thread, in reverse order (any order must
//! give the same result).
void RunSerially(size_t n_tasks, const std::function<void(size_t)> &fn) {
    for (size_t i = n_tasks; i-- > 0;) {
        fn(i);
    }
}

//! Runs the tasks on several real threads.
void RunThreads(size_t n_tasks, const std::function<void(size_t)> &fn) {
    std::vector<std::thread> threads;
    for (size_t i = 0; i < n_tasks; ++i) {
        threads.emplace_back([&fn, i] { fn(i); });
    }
    for (auto &t : threads) {
        t.join();
    }
}

void CheckChunkedMatches(const std::vector<uint256> &leaves, size_t chunk,
                         const MerkleTaskRunner &run) {
    bool mutated_seq{false}, mutated_par{true};
    const uint256 seq{ComputeMerkleRoot(leaves, &mutated_seq)};
    const uint256 par{ComputeMerkleRootChunked(
        leaves.size(), [&](size_t i) { return leaves[i]; }, &mutated_par, chunk,
        run)};
    BOOST_CHECK_MESSAGE(seq == par,
                        "n=" << leaves.size() << " chunk=" << chunk);
    BOOST_CHECK_MESSAGE(mutated_seq == mutated_par,
                        "mutated n=" << leaves.size() << " chunk=" << chunk);
    // Without a mutation flag requested, the root is the same.
    BOOST_CHECK(ComputeMerkleRootChunked(
                    leaves.size(), [&](size_t i) { return leaves[i]; }, nullptr,
                    chunk, run) == seq);
}
} // namespace

BOOST_AUTO_TEST_CASE(merkle_chunked_matches_sequential) {
    FastRandomContext rng{/*fDeterministic=*/true};
    // Every leaf count up to 300 (odd and even, powers of two and their
    // neighbours) with every chunk size up to 64, and some larger trees.
    for (size_t n = 0; n <= 300; ++n) {
        std::vector<uint256> leaves(n);
        for (auto &l : leaves) {
            l = rng.rand256();
        }
        for (size_t chunk = 1; chunk <= 64; chunk <<= 1) {
            CheckChunkedMatches(leaves, chunk, RunSerially);
        }
    }
    for (size_t n : {1023, 1024, 1025, 4097, 9001, 12345}) {
        std::vector<uint256> leaves(n);
        for (auto &l : leaves) {
            l = rng.rand256();
        }
        for (size_t chunk : {128, 256, 1024, 2048}) {
            CheckChunkedMatches(leaves, chunk, RunThreads);
        }
    }
}

BOOST_AUTO_TEST_CASE(merkle_chunked_detects_mutation) {
    FastRandomContext rng{/*fDeterministic=*/true};
    // CVE-2012-2459: repeating the last leaves (here a whole subtree) gives
    // the same root; both computations must flag it, wherever chunk
    // boundaries fall relative to the duplicated pair or subtree.
    for (size_t n = 2; n <= 160; ++n) {
        std::vector<uint256> leaves(n);
        for (auto &l : leaves) {
            l = rng.rand256();
        }
        for (size_t dup : {size_t{1}, size_t{2}, size_t{4}, size_t{8}}) {
            if (dup > n) {
                continue;
            }
            // Duplicate the last `dup` leaves when they form an odd-level
            // tail, as in the CVE example ([1..6] -> [1..6, 5, 6]).
            std::vector<uint256> mutated_leaves{leaves};
            mutated_leaves.insert(mutated_leaves.end(), leaves.end() - dup,
                                  leaves.end());
            for (size_t chunk = 1; chunk <= 32; chunk <<= 1) {
                CheckChunkedMatches(mutated_leaves, chunk, RunSerially);
            }
        }
        // An identical adjacent pair anywhere (pos even) is a mutation too.
        for (size_t pos = 0; pos + 1 < n; pos += 7) {
            std::vector<uint256> pair_leaves{leaves};
            pair_leaves[pos + 1] = pair_leaves[pos];
            for (size_t chunk = 1; chunk <= 32; chunk <<= 1) {
                CheckChunkedMatches(pair_leaves, chunk, RunSerially);
            }
        }
    }
    // The explicit CVE example: [1..6] and [1..6, 5, 6] share their root,
    // and only the second is flagged, at every chunk size.
    std::vector<uint256> six(6);
    for (auto &l : six) {
        l = rng.rand256();
    }
    std::vector<uint256> eight{six};
    eight.push_back(six[4]);
    eight.push_back(six[5]);
    for (size_t chunk = 1; chunk <= 8; chunk <<= 1) {
        bool m6{true}, m8{false};
        const uint256 r6{ComputeMerkleRootChunked(
            6, [&](size_t i) { return six[i]; }, &m6, chunk, RunSerially)};
        const uint256 r8{ComputeMerkleRootChunked(
            8, [&](size_t i) { return eight[i]; }, &m8, chunk, RunSerially)};
        BOOST_CHECK(r6 == r8);
        BOOST_CHECK(!m6);
        BOOST_CHECK(m8);
    }
}

BOOST_AUTO_TEST_CASE(block_merkle_root_parallel_matches) {
    FastRandomContext rng{/*fDeterministic=*/true};
    for (size_t n : {1, 2, 3, 15, 16, 17, 100, 1001, 3333}) {
        CBlock block;
        block.vtx.resize(n);
        for (size_t j = 0; j < n; j++) {
            CMutableTransaction mtx;
            mtx.nLockTime = uint32_t(rng.rand32());
            block.vtx[j] = MakeTransactionRef(std::move(mtx));
        }
        bool m_seq{true}, m_par{true}, m_val{true};
        const uint256 seq{BlockMerkleRoot(block, &m_seq)};
        for (size_t tasks : {1, 2, 3, 8, 64}) {
            BOOST_CHECK(BlockMerkleRootParallel(block, &m_par, tasks,
                                                RunThreads) == seq);
            BOOST_CHECK_EQUAL(m_par, m_seq);
        }
        // The validation entry point, forced onto the worker pool at any
        // size and with any thread count.
        for (size_t threads : {1, 2, 4, 8}) {
            BOOST_CHECK(ValidationBlockMerkleRoot(block, &m_val,
                                                  /*min_parallel_txs=*/0,
                                                  threads) == seq);
            BOOST_CHECK_EQUAL(m_val, m_seq);
        }
        // A duplicated last transaction (odd count) is flagged the same way.
        if (n % 2 == 1 && n > 1) {
            CBlock dup{block};
            dup.vtx.push_back(dup.vtx.back());
            bool d_seq{false}, d_val{false};
            BOOST_CHECK(BlockMerkleRoot(dup, &d_seq) ==
                        ValidationBlockMerkleRoot(dup, &d_val, 0, 4));
            BOOST_CHECK_EQUAL(d_seq, d_val);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
