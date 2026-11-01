// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/header_history.h>

#include <chainparams.h>
#include <config.h>
#include <consensus/validation.h>
#include <lotus_v2/fast_sync.h>
#include <script/script.h>
#include <timedata.h>
#include <txdb.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

lotus::v2::ChainId MakeTestChainId(uint8_t seed = 0x42) {
    lotus::v2::ChainId chain_id{};
    for (size_t i = 0; i < chain_id.size(); ++i) {
        chain_id[i] = static_cast<uint8_t>(seed + i * 17u);
    }
    return chain_id;
}

lotus::v2::Hash256 MakeDeterministicBlockHash(uint64_t height, uint8_t fork_tag = 0) {
    std::array<uint8_t, 9> preimage{};
    for (size_t i = 0; i < 8; ++i) {
        preimage[i] = static_cast<uint8_t>((height >> (8 * i)) & 0xffu);
    }
    preimage[8] = fork_tag;
    return lotus::v2::TaggedHash(lotus::v2::HashDomain::BlockId, preimage);
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_header_history_tests)

BOOST_AUTO_TEST_CASE(frontier_vs_tree_root_equivalence) {
    const lotus::v2::ChainId chain_id = MakeTestChainId(0x11);
    lotus::v2::HeaderHistoryFrontier frontier{};
    lotus::v2::HeaderHistoryTree tree;

    BOOST_CHECK_EQUAL(frontier.count, 0U);
    BOOST_CHECK_EQUAL(tree.Count(), 0U);
    BOOST_CHECK(lotus::v2::HeaderHistoryRoot(chain_id, frontier) ==
                lotus::v2::Hash256{});
    BOOST_CHECK(tree.GetRoot(chain_id) == lotus::v2::Hash256{});
    BOOST_CHECK(tree.GetFrontier() == frontier);

    std::vector<lotus::v2::Hash256> historical_roots;
    historical_roots.reserve(501);
    historical_roots.push_back(lotus::v2::Hash256{});

    for (uint64_t h = 0; h < 500; ++h) {
        const lotus::v2::Hash256 block_hash = MakeDeterministicBlockHash(h);
        frontier = lotus::v2::AppendHeaderToFrontier(chain_id, frontier, block_hash);
        tree.Append(chain_id, block_hash);

        BOOST_CHECK_EQUAL(frontier.count, h + 1);
        BOOST_CHECK_EQUAL(tree.Count(), h + 1);
        BOOST_CHECK(tree.GetFrontier() == frontier);

        const lotus::v2::Hash256 root_from_frontier =
            lotus::v2::HeaderHistoryRoot(chain_id, frontier);
        const lotus::v2::Hash256 root_from_tree = tree.GetRoot(chain_id);
        BOOST_CHECK(root_from_frontier != lotus::v2::Hash256{});
        BOOST_CHECK(root_from_frontier == root_from_tree);
        historical_roots.push_back(root_from_tree);
    }

    for (uint64_t count = 0; count <= 500; ++count) {
        BOOST_CHECK(tree.GetRootAt(chain_id, count) == historical_roots[count]);
    }
    BOOST_CHECK(tree.GetRootAt(chain_id, 501) == lotus::v2::Hash256{});
}

BOOST_AUTO_TEST_CASE(inclusion_proofs_across_boundary_counts) {
    const lotus::v2::ChainId chain_id = MakeTestChainId(0x22);
    lotus::v2::HeaderHistoryTree tree;
    std::vector<lotus::v2::Hash256> block_hashes;
    block_hashes.reserve(300);

    for (uint64_t h = 0; h < 300; ++h) {
        const lotus::v2::Hash256 bh = MakeDeterministicBlockHash(h);
        block_hashes.push_back(bh);
        tree.Append(chain_id, bh);
    }

    const std::vector<uint64_t> boundary_counts = {
        1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 300};

    for (const uint64_t target_count : boundary_counts) {
        const lotus::v2::Hash256 expected_root =
            tree.GetRootAt(chain_id, target_count);
        BOOST_REQUIRE(expected_root != lotus::v2::Hash256{});

        for (uint64_t leaf_height = 0; leaf_height < target_count; ++leaf_height) {
            lotus::v2::HeaderInclusionProof proof{};
            BOOST_REQUIRE(tree.BuildInclusionProofAt(
                chain_id, leaf_height, target_count, proof));
            BOOST_CHECK_EQUAL(proof.leaf_height, leaf_height);
            BOOST_CHECK_EQUAL(proof.total_count, target_count);
            BOOST_CHECK(proof.block_hash == block_hashes[leaf_height]);
            BOOST_CHECK(lotus::v2::VerifyHeaderInclusionProof(
                chain_id, proof, expected_root));
        }

        lotus::v2::HeaderInclusionProof invalid_proof{};
        BOOST_CHECK(!tree.BuildInclusionProofAt(
            chain_id, target_count, target_count, invalid_proof));
    }

    // Also verify BuildInclusionProof at tip (count = 300).
    const lotus::v2::Hash256 tip_root = tree.GetRoot(chain_id);
    for (uint64_t leaf_height : {uint64_t{0}, uint64_t{1}, uint64_t{128}, uint64_t{299}}) {
        lotus::v2::HeaderInclusionProof proof{};
        BOOST_REQUIRE(tree.BuildInclusionProof(chain_id, leaf_height, proof));
        BOOST_CHECK(proof.block_hash == block_hashes[leaf_height]);
        BOOST_CHECK(lotus::v2::VerifyHeaderInclusionProof(
            chain_id, proof, tip_root));
    }
}

BOOST_AUTO_TEST_CASE(tamper_rejection_and_non_canonical_null_right_sibling_rejection) {
    const lotus::v2::ChainId chain_id = MakeTestChainId(0x33);
    const lotus::v2::ChainId wrong_chain_id = MakeTestChainId(0x99);
    lotus::v2::HeaderHistoryTree tree;
    std::vector<lotus::v2::Hash256> block_hashes;
    for (uint64_t h = 0; h < 65; ++h) {
        const lotus::v2::Hash256 bh = MakeDeterministicBlockHash(h);
        block_hashes.push_back(bh);
        tree.Append(chain_id, bh);
    }

    const uint64_t target_count = 65;
    const lotus::v2::Hash256 root = tree.GetRootAt(chain_id, target_count);
    for (uint64_t h : {uint64_t{0}, uint64_t{17}, uint64_t{63}, uint64_t{64}}) {
        lotus::v2::HeaderInclusionProof proof{};
        BOOST_REQUIRE(tree.BuildInclusionProofAt(chain_id, h, target_count, proof));
        BOOST_REQUIRE(lotus::v2::VerifyHeaderInclusionProof(
            chain_id, proof, root));

        // 1. Corrupted block_hash
        {
            lotus::v2::HeaderInclusionProof p = proof;
            p.block_hash[0] ^= 0x01;
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, p, root));
        }

        // 2. Corrupted expected_root
        {
            lotus::v2::Hash256 bad_root = root;
            bad_root[31] ^= 0x80;
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, proof, bad_root));
        }

        // 3. Wrong chain_id
        BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
            wrong_chain_id, proof, root));

        // 4. Corrupted leaf_height
        {
            lotus::v2::HeaderInclusionProof p = proof;
            p.leaf_height = (h + 1 < target_count) ? (h + 1) : (h - 1);
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, p, root));
        }

        // 5. Corrupted total_count
        {
            lotus::v2::HeaderInclusionProof p = proof;
            p.total_count = 0;
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, p, root));
            p.total_count = h;
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, p, root));
            p.total_count = target_count * 2;
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, p, root));
            if (h == target_count - 1) {
                p.total_count = target_count + 1;
                BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                    chain_id, p, root));
            }
        }

        // 6. Corrupted sibling
        for (size_t i = 0; i < proof.siblings.size(); ++i) {
            lotus::v2::HeaderInclusionProof p = proof;
            p.siblings[i][i % 32] ^= 0x40;
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, p, root));
        }

        // 7. Extra sibling appended
        {
            lotus::v2::HeaderInclusionProof p = proof;
            p.siblings.push_back(lotus::v2::Hash256{});
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, p, root));
        }

        // 8. Missing sibling
        if (!proof.siblings.empty()) {
            lotus::v2::HeaderInclusionProof p = proof;
            p.siblings.pop_back();
            BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
                chain_id, p, root));
        }
    }

    // 9. Explicit non-canonical null-right-sibling rejection test:
    // (a) When a right subtree beyond total_count is empty (right_subtree_start >= total_count),
    //     the sibling MUST be NULL_HASH. Even if a prover computes a root using a non-null
    //     dummy sibling at that position, VerifyHeaderInclusionProof must reject it.
    // (b) When a prover appends an extra NULL_HASH sibling at level D and folds it into the root,
    //     VerifyHeaderInclusionProof must reject it due to non-canonical sibling count.
    for (uint64_t count : {uint64_t{3}, uint64_t{5}, uint64_t{7}, uint64_t{9}, uint64_t{65}}) {
        const uint64_t last_leaf = count - 1;
        lotus::v2::HeaderInclusionProof canonical_proof{};
        BOOST_REQUIRE(tree.BuildInclusionProofAt(chain_id, last_leaf, count, canonical_proof));
        BOOST_REQUIRE(!canonical_proof.siblings.empty());
        BOOST_CHECK(canonical_proof.siblings[0] == lotus::v2::NULL_HASH);

        // (a) Replace the required NULL_HASH at level 0 with a non-zero hash and recompute root
        lotus::v2::HeaderInclusionProof forged_non_null = canonical_proof;
        forged_non_null.siblings[0][0] = 0x99;
        lotus::v2::Hash256 forged_root = lotus::v2::HeaderLeafHash(
            chain_id, last_leaf, forged_non_null.block_hash);
        for (unsigned k = 0; k < forged_non_null.siblings.size(); ++k) {
            const uint64_t idx = last_leaf >> k;
            if ((idx & 1ULL) == 0) {
                forged_root = lotus::v2::HeaderInternalHash(
                    chain_id, static_cast<uint8_t>(k), forged_root,
                    forged_non_null.siblings[k]);
            } else {
                forged_root = lotus::v2::HeaderInternalHash(
                    chain_id, static_cast<uint8_t>(k),
                    forged_non_null.siblings[k], forged_root);
            }
        }
        BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
            chain_id, forged_non_null, forged_root));

        // (b) Append an extra trailing NULL_HASH at level D and recompute root
        lotus::v2::HeaderInclusionProof forged_extra_null = canonical_proof;
        const uint8_t top_level =
            static_cast<uint8_t>(canonical_proof.siblings.size());
        forged_extra_null.siblings.push_back(lotus::v2::NULL_HASH);
        const lotus::v2::Hash256 extra_root = lotus::v2::HeaderInternalHash(
            chain_id, top_level, tree.GetRootAt(chain_id, count),
            lotus::v2::NULL_HASH);
        BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
            chain_id, forged_extra_null, extra_root));
    }
}

BOOST_AUTO_TEST_CASE(reorg_popback_and_fork_divergence) {
    const lotus::v2::ChainId chain_id = MakeTestChainId(0x44);
    lotus::v2::HeaderHistoryTree tree;
    std::vector<lotus::v2::Hash256> main_hashes;
    std::vector<lotus::v2::Hash256> main_roots;
    std::vector<lotus::v2::HeaderHistoryFrontier> main_frontiers;

    for (uint64_t h = 0; h < 200; ++h) {
        const lotus::v2::Hash256 bh = MakeDeterministicBlockHash(h, /*fork_tag=*/0);
        main_hashes.push_back(bh);
        tree.Append(chain_id, bh);
        main_roots.push_back(tree.GetRoot(chain_id));
        main_frontiers.push_back(tree.GetFrontier());
    }

    // Pop back from 200 to 120
    for (uint64_t count = 200; count > 120; --count) {
        BOOST_REQUIRE(tree.PopBack());
        BOOST_CHECK_EQUAL(tree.Count(), count - 1);
        BOOST_CHECK(tree.GetRoot(chain_id) == main_roots[count - 2]);
        BOOST_CHECK(tree.GetFrontier() == main_frontiers[count - 2]);
    }

    // Append 80 fork blocks
    std::vector<lotus::v2::Hash256> fork_hashes;
    for (uint64_t h = 120; h < 200; ++h) {
        const lotus::v2::Hash256 fork_bh = MakeDeterministicBlockHash(h, /*fork_tag=*/1);
        fork_hashes.push_back(fork_bh);
        tree.Append(chain_id, fork_bh);
    }
    const lotus::v2::Hash256 fork_tip_root = tree.GetRoot(chain_id);
    BOOST_CHECK(fork_tip_root != main_roots.back());

    // Common ancestor (height 50) proves against fork_tip_root; divergent leaf (height 150) proves fork_bh, not main_bh
    {
        lotus::v2::HeaderInclusionProof ancestor_proof{};
        BOOST_REQUIRE(tree.BuildInclusionProof(chain_id, 50, ancestor_proof));
        BOOST_CHECK(ancestor_proof.block_hash == main_hashes[50]);
        BOOST_CHECK(lotus::v2::VerifyHeaderInclusionProof(
            chain_id, ancestor_proof, fork_tip_root));

        lotus::v2::HeaderInclusionProof fork_proof{};
        BOOST_REQUIRE(tree.BuildInclusionProof(chain_id, 150, fork_proof));
        BOOST_CHECK(fork_proof.block_hash == fork_hashes[150 - 120]);
        BOOST_CHECK(lotus::v2::VerifyHeaderInclusionProof(
            chain_id, fork_proof, fork_tip_root));

        lotus::v2::HeaderInclusionProof wrong_bh_proof = fork_proof;
        wrong_bh_proof.block_hash = main_hashes[150];
        BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(
            chain_id, wrong_bh_proof, fork_tip_root));
    }

    // Pop back fork blocks to 120 and replay original main blocks 120..199
    for (uint64_t count = 200; count > 120; --count) {
        BOOST_REQUIRE(tree.PopBack());
    }
    for (uint64_t h = 120; h < 200; ++h) {
        tree.Append(chain_id, main_hashes[h]);
    }
    BOOST_CHECK_EQUAL(tree.Count(), 200U);
    BOOST_CHECK(tree.GetRoot(chain_id) == main_roots.back());
    BOOST_CHECK(tree.GetFrontier() == main_frontiers.back());
}

BOOST_AUTO_TEST_CASE(total_count_is_authenticated_by_the_root) {
    const lotus::v2::ChainId chain_id = MakeTestChainId(0x77);
    lotus::v2::HeaderHistoryTree tree;
    for (uint64_t h = 0; h < 100; ++h) {
        tree.Append(chain_id, MakeDeterministicBlockHash(h));
    }

    // Leaf 0 sits behind complete left subtrees, so every count from 65 to 128
    // has the same tree shape along its path. Only the root can tell them apart.
    lotus::v2::HeaderInclusionProof proof{};
    BOOST_REQUIRE(tree.BuildInclusionProofAt(chain_id, 0, 65, proof));
    const lotus::v2::Hash256 root_65 = tree.GetRootAt(chain_id, 65);
    BOOST_CHECK(lotus::v2::VerifyHeaderInclusionProof(chain_id, proof, root_65));
    for (const uint64_t claimed : {uint64_t{66}, uint64_t{100}, uint64_t{128}}) {
        lotus::v2::HeaderInclusionProof overstated = proof;
        overstated.total_count = claimed;
        BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(chain_id, overstated,
                                                           root_65));
    }

    BOOST_REQUIRE(tree.BuildInclusionProofAt(chain_id, 0, 100, proof));
    const lotus::v2::Hash256 root_100 = tree.GetRootAt(chain_id, 100);
    BOOST_CHECK(lotus::v2::VerifyHeaderInclusionProof(chain_id, proof, root_100));
    lotus::v2::HeaderInclusionProof understated = proof;
    understated.total_count = 65;
    BOOST_CHECK(!lotus::v2::VerifyHeaderInclusionProof(chain_id, understated,
                                                       root_100));
}

// Computed outside this codebase from the formulas in the specification, using
// a separate BLAKE3 implementation, so another implementation can check itself
// against them. A change here is a consensus change.
BOOST_AUTO_TEST_CASE(known_answer_vectors) {
    lotus::v2::ChainId chain_id{};
    for (size_t i = 0; i < chain_id.size(); ++i) {
        chain_id[i] = static_cast<uint8_t>(i);
    }
    const auto filled = [](uint8_t value) {
        lotus::v2::Hash256 out{};
        out.fill(value);
        return out;
    };
    BOOST_CHECK_EQUAL(HexStr(lotus::v2::HeaderLeafHash(chain_id, 5, filled(5))),
                      "beef84dabea208b06e4c929eaf27d137fdaa9b5a33feb3b60524c23054b814fc");
    BOOST_CHECK_EQUAL(
        HexStr(lotus::v2::HeaderInternalHash(chain_id, 3, filled(1), filled(2))),
        "361dd3811bf75a2efbd499563e1885a1d6b916320493880e9275e7f622749287");

    const std::vector<std::pair<uint64_t, std::string>> roots{
        {0, "0000000000000000000000000000000000000000000000000000000000000000"},
        {1, "b886d9387b95774f35aae9df5649b7db43bb4c36c774c73d287e1cf14d9d4dc0"},
        {2, "23b47cd24db78b281d1483cb70d2dd933589474215917aa9e8d3dd2ba2b785c0"},
        {3, "5db8c4cb990d8b915d163c0fb0cd4ddedd66402dea4007bf205354e9017aa37c"},
        {4, "edf27ef0e97bf6bb90d5504f600a7c24bd67f5b17cad6f0e19f6f871bb26000a"},
        {6, "0ea84b1e33a8928c4421a9585823c96ecf0ec02fe3d89a7ca28b227c30968b37"},
        {65, "5cc55074539236ab8ae4f212b5e466ccfb5f85e6ede1e8d9c145d4dc0807eee0"},
        {100, "c2da3ea816064711c2826f054923aa6d3748cdd6354291d684a98a1fe50b7161"},
    };
    lotus::v2::HeaderHistoryFrontier frontier{};
    lotus::v2::HeaderHistoryTree tree;
    uint64_t count = 0;
    for (const auto &[expected_count, expected_root] : roots) {
        while (count < expected_count) {
            const auto block = filled(static_cast<uint8_t>(count));
            frontier = lotus::v2::AppendHeaderToFrontier(chain_id, frontier, block);
            tree.Append(chain_id, block);
            ++count;
        }
        BOOST_CHECK_EQUAL(HexStr(lotus::v2::HeaderHistoryRoot(chain_id, frontier)),
                          expected_root);
        BOOST_CHECK_EQUAL(HexStr(tree.GetRoot(chain_id)), expected_root);
    }
}

BOOST_AUTO_TEST_CASE(proof_wire_encoding_roundtrip_and_bounds) {
    const lotus::v2::ChainId chain_id = MakeTestChainId(0x66);
    lotus::v2::HeaderHistoryTree tree;
    for (uint64_t h = 0; h < 45; ++h) {
        tree.Append(chain_id, MakeDeterministicBlockHash(h));
    }

    lotus::v2::HeaderInclusionProof proof{};
    BOOST_REQUIRE(tree.BuildInclusionProof(chain_id, 19, proof));

    const std::vector<uint8_t> encoded =
        lotus::v2::EncodeHeaderInclusionProof(proof);
    BOOST_CHECK_EQUAL(encoded.size(), 49 + proof.siblings.size() * 32);

    lotus::v2::HeaderInclusionProof decoded{};
    BOOST_REQUIRE(lotus::v2::DecodeHeaderInclusionProof(encoded, decoded));
    BOOST_CHECK(decoded == proof);

    // Truncated buffer rejected
    std::vector<uint8_t> truncated = encoded;
    truncated.pop_back();
    BOOST_CHECK(!lotus::v2::DecodeHeaderInclusionProof(truncated, decoded));

    // Trailing byte rejected
    std::vector<uint8_t> trailing = encoded;
    trailing.push_back(0x01);
    BOOST_CHECK(!lotus::v2::DecodeHeaderInclusionProof(trailing, decoded));

    // Sibling count > 64 rejected
    std::vector<uint8_t> bad_count = encoded;
    bad_count[48] = 65;
    BOOST_CHECK(!lotus::v2::DecodeHeaderInclusionProof(bad_count, decoded));
}

BOOST_FIXTURE_TEST_SUITE(lotus_v2_header_history_chain_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(blocks_commit_root_of_all_ancestors_and_tree_rebuilds) {
    const lotus::v2::ChainId chain_id = GetActiveV2ChainId();
    LOCK(::cs_main);
    Chainstate &cs = m_node.chainman->ActiveChainstate();
    BOOST_REQUIRE_EQUAL(cs.m_chain.Height(), 100);
    BOOST_REQUIRE_EQUAL(cs.m_header_history_tree.Count(), 101U);

    // Genesis has a null history root, and each block H in 1..100 commits to
    // the root over blocks 0..H-1.
    for (int h = 0; h <= 100; ++h) {
        CBlockIndex *pindex = cs.m_chain[h];
        BOOST_REQUIRE(pindex != nullptr);
        std::vector<lotus::v2::Coin> coins;
        lotus::v2::MonetaryState mon{};
        BOOST_REQUIRE(GetV2BlockStateCoinsAndMonetary(
            pindex->GetBlockHash(), static_cast<uint64_t>(h), coins, mon));
        BOOST_CHECK(mon.history_root ==
                    cs.m_header_history_tree.GetRootAt(
                        chain_id, static_cast<uint64_t>(h)));
    }

    // Startup has nothing but m_chain to work from. Rebuilding from it, with no
    // block data involved, must reproduce the same tree, and nothing gets written.
    const lotus::v2::HeaderHistoryFrontier expected =
        cs.m_header_history_tree.GetFrontier();
    cs.m_header_history_tree.Clear();
    cs.SyncHeaderHistoryTreeToChain();
    BOOST_CHECK(cs.m_header_history_tree.GetFrontier() == expected);
    BlockValidationState state;
    BOOST_REQUIRE(cs.FlushStateToDisk(state, FlushStateMode::ALWAYS));
    BOOST_CHECK(!fs::exists(m_args.GetDataDirNet() / "v2_state" /
                            "header_history_tree.bin"));

    // A stale tree left on another fork is corrected to the active chain.
    cs.m_header_history_tree.PopBack();
    cs.m_header_history_tree.PopBack();
    cs.m_header_history_tree.Append(chain_id, lotus::v2::Hash256{1});
    cs.SyncHeaderHistoryTreeToChain();
    BOOST_CHECK(cs.m_header_history_tree.GetFrontier() == expected);
}

BOOST_AUTO_TEST_CASE(template_overlay_and_block_paths_agree_on_the_root) {
    Chainstate &cs = m_node.chainman->ActiveChainstate();
    CBlock block = CreateBlock({}, CScript() << OP_TRUE, cs);
    const uint256 declared = block.hashStateRoot;
    BOOST_REQUIRE(!declared.IsNull());
    const BlockHash parent = block.hashPrevBlock;
    const uint64_t height = block.nHeight;
    const uint64_t parent_mtp = WITH_LOCK(
        cs_main, return cs.m_chain.Tip()->GetMedianTimePast());

    BOOST_CHECK_EQUAL(ComputeV2BlockStateRoot(block, parent, height, parent_mtp,
                                              false),
                      declared);

    const V2TemplateBaseState base =
        BuildV2TemplateBaseState({}, parent, height, parent_mtp);
    BOOST_CHECK_EQUAL(ComputeV2StateRootFromTemplate(base, *block.vtx[0],
                                                     block.nBits),
                      declared);

    std::shared_ptr<const lotus::v2::SmtNode> root;
    lotus::v2::MonetaryState monetary;
    BOOST_REQUIRE(GetV2BlockStateSnapshot(parent, root, monetary));
    lotus::v2::Hash parent_id{};
    std::copy_n(parent.begin(), 32, parent_id.begin());
    lotus::v2::MempoolOverlayLayer overlay(parent_id, root, monetary, height,
                                           parent_mtp);
    BOOST_CHECK_EQUAL(ComputeV2StateRootFromOverlay(*block.vtx[0], overlay,
                                                    block.nBits, height,
                                                    parent_mtp),
                      declared);

    // A template whose frontier doesn't cover exactly its height's ancestors
    // refuses to produce a root.
    V2TemplateBaseState short_frontier = base;
    short_frontier.history_frontier.count -= 1;
    BOOST_CHECK(ComputeV2StateRootFromTemplate(short_frontier, *block.vtx[0],
                                               block.nBits)
                    .IsNull());
}

BOOST_AUTO_TEST_CASE(state_file_requires_exactly_one_history_frontier) {
    const auto dir = std::filesystem::temp_directory_path() /
        ("lotus-history-trailer-" +
         std::to_string(std::chrono::steady_clock::now()
                            .time_since_epoch()
                            .count()));
    SetV2StatePersistDir(dir.string());
    lotus::v2::HeaderHistoryFrontier frontier{};
    frontier = lotus::v2::AppendHeaderToFrontier(GetActiveV2ChainId(), frontier,
                                                 lotus::v2::Hash256{7});
    lotus::v2::MonetaryState monetary{};
    monetary.prev_work = lotus::v2::Hash{2};
    const BlockHash hash{uint256::ONE};
    BOOST_REQUIRE(ImportV2BlockStateCoinsAndMonetary(hash, {}, monetary, frontier));
    BOOST_REQUIRE(FlushV2BlockStatesToDisk());
    const auto path = dir / (hash.GetHex() + ".bin");
    std::vector<uint8_t> good;
    {
        std::ifstream in(path, std::ios::binary);
        good.assign(std::istreambuf_iterator<char>(in),
                    std::istreambuf_iterator<char>());
    }
    const auto loads = [&](const std::vector<uint8_t> &bytes) {
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char *>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        }
        // Resetting the directory empties the cache, forcing a read of the file.
        SetV2StatePersistDir("");
        SetV2StatePersistDir(dir.string());
        std::shared_ptr<const lotus::v2::SmtNode> root;
        lotus::v2::MonetaryState loaded{};
        const bool ok = GetV2BlockStateSnapshot(hash, root, loaded);
        if (ok) {
            BOOST_CHECK(loaded.history_root ==
                        lotus::v2::HeaderHistoryRoot(GetActiveV2ChainId(),
                                                     frontier));
        }
        return ok;
    };
    BOOST_CHECK(loads(good));
    const size_t trailer_size =
        4 + lotus::v2::EncodeHeaderHistoryFrontier(frontier).size();
    std::vector<uint8_t> no_trailer(good.begin(), good.end() - trailer_size);
    BOOST_CHECK(!loads(no_trailer));
    std::vector<uint8_t> trailing = good;
    trailing.push_back(0);
    BOOST_CHECK(!loads(trailing));
    SetV2StatePersistDir("");
    std::filesystem::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(pivot_must_commit_the_locally_derived_history_root) {
    LOCK(cs_main);
    Chainstate &cs = m_node.chainman->ActiveChainstate();
    CBlockIndex *tip = cs.m_chain.Tip();
    const BlockHash best = cs.CoinsTip().GetBestBlock();

    // A header can have proof of work and still commit a history root that
    // full validation would reject. Fast-sync has to reject both forms.
    std::vector<lotus::v2::Coin> coins;
    lotus::v2::MonetaryState honest{};
    BOOST_REQUIRE(GetV2BlockStateCoinsAndMonetary(tip->GetBlockHash(),
                                                  tip->nHeight, coins, honest));
    lotus::v2::UtxoSet utxo;
    for (const auto &coin : coins) {
        BOOST_REQUIRE(utxo.Insert(coin));
    }

    lotus::v2::Hash256 wrong_root = honest.history_root;
    wrong_root[0] ^= 1;
    uint32_t nonce = 0x4d00;
    for (const lotus::v2::Hash256 &committed :
         {lotus::v2::Hash256{}, wrong_root}) {
        lotus::v2::MonetaryState forged = honest;
        forged.history_root = committed;
        CBlockHeader header = tip->GetBlockHeader();
        const lotus::v2::Hash forged_root = lotus::v2::StateRoot(
            GetActiveV2ChainId(), tip->nHeight, utxo.Root(), forged);
        std::memcpy(header.hashStateRoot.begin(), forged_root.data(), 32);
        header.nNonce = ++nonce;
        CBlockIndex *best_header = tip;
        CBlockIndex *forged_index =
            m_node.chainman->m_blockman.AddToBlockIndex(header, best_header);
        BOOST_REQUIRE(forged_index != nullptr);

        std::string error;
        BOOST_CHECK(!cs.ActivateVerifiedFastSyncPivot(forged_index, coins,
                                                      forged, error));
        BOOST_CHECK(cs.CoinsTip().GetBestBlock() == best);
        BOOST_CHECK(cs.m_chain.Tip() == tip);
        BOOST_CHECK(!cs.CoinsDB().GetFastSyncSnapshot());
    }
}

BOOST_AUTO_TEST_CASE(missing_parent_frontier_fails_instead_of_a_wrong_root) {
    Chainstate &cs = m_node.chainman->ActiveChainstate();
    CBlock block = CreateBlock({}, CScript() << OP_TRUE, cs);
    uint256 unknown_parent;
    unknown_parent.begin()[0] = 0x4d;
    BOOST_CHECK(ComputeV2BlockStateRoot(block, BlockHash{unknown_parent},
                                        block.nHeight, 0, false)
                    .IsNull());

    // Losing the parent's state is a local fault. It must not look like a
    // consensus failure of a block that may be perfectly valid.
    const auto empty_dir = std::filesystem::temp_directory_path() /
        ("lotus-history-lost-state-" +
         std::to_string(std::chrono::steady_clock::now()
                            .time_since_epoch()
                            .count()));
    SetV2StatePersistDir(empty_dir.string());
    LOCK(cs_main);
    CBlockIndex *tip = cs.m_chain.Tip();
    BlockValidationState state;
    TestBlockValidity(state, m_node.chainman->GetParams(), cs, block, tip,
                      GetAdjustedTime,
                      BlockValidationOptions(m_node.chainman->GetConfig())
                          .withCheckPoW(false)
                          .withCheckMerkleRoot(false));
    BOOST_CHECK_MESSAGE(state.IsError(), state.ToString());
    SetV2StatePersistDir("");
    std::error_code ec;
    std::filesystem::remove_all(empty_dir, ec);
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
