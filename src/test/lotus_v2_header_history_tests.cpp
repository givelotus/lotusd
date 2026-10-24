// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/header_history.h>

#include <config.h>
#include <primitives/block.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

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

BOOST_AUTO_TEST_CASE(persistence_roundtrip_and_corruption_rejection) {
    const lotus::v2::ChainId chain_id = MakeTestChainId(0x55);
    const std::filesystem::path temp_dir =
        std::filesystem::temp_directory_path() / "lotus_v2_header_history_test_persist";
    std::filesystem::create_directories(temp_dir);
    const std::filesystem::path file_path = temp_dir / "header_history_tree.bin";

    // 1. Empty tree round-trip
    {
        lotus::v2::HeaderHistoryTree empty_tree;
        BOOST_REQUIRE(empty_tree.SaveToFile(file_path));

        lotus::v2::HeaderHistoryTree loaded_empty;
        loaded_empty.Append(chain_id, MakeDeterministicBlockHash(0));
        BOOST_REQUIRE(loaded_empty.LoadFromFile(file_path));
        BOOST_CHECK_EQUAL(loaded_empty.Count(), 0U);
        BOOST_CHECK(loaded_empty.GetRoot(chain_id) == lotus::v2::Hash256{});
    }

    // 2. Populated tree (257 leaves) round-trip
    lotus::v2::HeaderHistoryTree tree;
    std::vector<lotus::v2::Hash256> leaves;
    for (uint64_t h = 0; h < 257; ++h) {
        const lotus::v2::Hash256 bh = MakeDeterministicBlockHash(h);
        leaves.push_back(bh);
        tree.Append(chain_id, bh);
    }
    BOOST_REQUIRE(tree.SaveToFile(file_path));

    lotus::v2::HeaderHistoryTree loaded;
    BOOST_REQUIRE(loaded.LoadFromFile(file_path));
    BOOST_CHECK_EQUAL(loaded.Count(), tree.Count());
    BOOST_CHECK(loaded.GetRoot(chain_id) == tree.GetRoot(chain_id));
    BOOST_CHECK(loaded.GetFrontier() == tree.GetFrontier());

    for (uint64_t h : {uint64_t{0}, uint64_t{1}, uint64_t{127}, uint64_t{128}, uint64_t{256}}) {
        lotus::v2::HeaderInclusionProof p1{}, p2{};
        BOOST_REQUIRE(tree.BuildInclusionProof(chain_id, h, p1));
        BOOST_REQUIRE(loaded.BuildInclusionProof(chain_id, h, p2));
        BOOST_CHECK(p1 == p2);
        BOOST_CHECK(lotus::v2::VerifyHeaderInclusionProof(
            chain_id, p2, loaded.GetRoot(chain_id)));
    }

    // 3. Corruption rejection: bad magic, bad version, truncated, trailing bytes
    std::vector<uint8_t> raw_bytes;
    {
        std::ifstream in(file_path, std::ios::binary);
        raw_bytes.assign(std::istreambuf_iterator<char>(in),
                         std::istreambuf_iterator<char>());
    }
    BOOST_REQUIRE_GT(raw_bytes.size(), 16U);

    auto write_and_expect_fail = [&](const std::vector<uint8_t> &corrupt) {
        const std::filesystem::path bad_path = temp_dir / "corrupt.bin";
        {
            std::ofstream out(bad_path, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char *>(corrupt.data()),
                      static_cast<std::streamsize>(corrupt.size()));
        }
        lotus::v2::HeaderHistoryTree dst;
        BOOST_CHECK(!dst.LoadFromFile(bad_path));
    };

    // Bad magic
    {
        auto corrupt = raw_bytes;
        corrupt[0] ^= 0xff;
        write_and_expect_fail(corrupt);
    }
    // Bad version
    {
        auto corrupt = raw_bytes;
        corrupt[4] = 99;
        write_and_expect_fail(corrupt);
    }
    // Truncated file
    {
        auto corrupt = raw_bytes;
        corrupt.resize(corrupt.size() - 10);
        write_and_expect_fail(corrupt);
    }
    // Trailing garbage byte
    {
        auto corrupt = raw_bytes;
        corrupt.push_back(0x00);
        write_and_expect_fail(corrupt);
    }

    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
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

BOOST_FIXTURE_TEST_SUITE(lotus_v2_header_history_chain_rpc_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(chainstate_sync_and_rpc_proofs_end_to_end) {
    const lotus::v2::ChainId chain_id = GetActiveV2ChainId();
    {
        LOCK(::cs_main);
        Chainstate &cs = m_node.chainman->ActiveChainstate();
        BOOST_REQUIRE_EQUAL(cs.m_chain.Height(), 100);
        BOOST_REQUIRE_EQUAL(cs.m_header_history_tree.Count(), 101U);

        // Verify genesis has history_root == 0, and every block H in 1..100
        // commits to the HeaderHistoryRoot of ancestor blocks 0..H-1.
        for (int h = 0; h <= 100; ++h) {
            CBlockIndex *pindex = cs.m_chain[h];
            BOOST_REQUIRE(pindex != nullptr);
            std::vector<lotus::v2::Coin> coins;
            lotus::v2::MonetaryState mon{};
            BOOST_REQUIRE(GetV2BlockStateCoinsAndMonetary(
                pindex->GetBlockHash(), static_cast<uint64_t>(h), coins, mon));
            const lotus::v2::Hash256 expected_history_root =
                cs.m_header_history_tree.GetRootAt(
                    chain_id, static_cast<uint64_t>(h));
            BOOST_CHECK(mon.history_root == expected_history_root);
        }

        // Flush state to disk and verify header_history_tree.bin is persisted.
        BlockValidationState state;
        BOOST_REQUIRE(cs.FlushStateToDisk(state, FlushStateMode::ALWAYS));
        const fs::path tree_path = cs.HeaderHistoryTreePath();
        BOOST_CHECK(fs::exists(tree_path));

        lotus::v2::HeaderHistoryTree disk_tree;
        BOOST_REQUIRE(disk_tree.LoadFromFile(std::filesystem::path(tree_path.u8string())));
        BOOST_CHECK_EQUAL(disk_tree.Count(), cs.m_header_history_tree.Count());
        BOOST_CHECK(disk_tree.GetRoot(chain_id) ==
                    cs.m_header_history_tree.GetRoot(chain_id));
    }

    GlobalConfig config;
    auto call_rpc = [&](const std::string &method, UniValue params) -> UniValue {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = method;
        req.params = std::move(params);
        return tableRPC.execute(config, req);
    };

    // 1. Prove genesis (height 0) and blocks against active tip (height 100, count 101)
    for (int target_h : {0, 1, 42, 99, 100}) {
        UniValue get_params(UniValue::VARR);
        get_params.push_back(target_h);
        const UniValue proof_res =
            call_rpc("getheaderhistoryproof", std::move(get_params));

        BOOST_CHECK_EQUAL(proof_res["leaf_height"].getInt<int>(), target_h);
        BOOST_CHECK_EQUAL(proof_res["total_count"].getInt<int>(), 101);
        const std::string block_hash_hex = proof_res["block_hash"].get_str();
        const std::string history_root_hex = proof_res["history_root"].get_str();
        const std::string proof_hex = proof_res["proof_hex"].get_str();

        // Verify via verifyheaderhistoryproof(proof_hex, expected_root)
        {
            UniValue ver_params(UniValue::VARR);
            ver_params.push_back(proof_hex);
            ver_params.push_back(history_root_hex);
            const UniValue ver_res =
                call_rpc("verifyheaderhistoryproof", std::move(ver_params));
            BOOST_CHECK(ver_res["valid"].get_bool());
            BOOST_CHECK_EQUAL(ver_res["block_hash"].get_str(), block_hash_hex);
            BOOST_CHECK_EQUAL(ver_res["leaf_height"].getInt<int>(), target_h);
            BOOST_CHECK_EQUAL(ver_res["total_count"].getInt<int>(), 101);
        }

        // Tamper with expected_root -> must return valid == false
        {
            std::string bad_root = history_root_hex;
            bad_root[0] = (bad_root[0] == '0') ? '1' : '0';
            UniValue ver_params(UniValue::VARR);
            ver_params.push_back(proof_hex);
            ver_params.push_back(bad_root);
            const UniValue ver_res =
                call_rpc("verifyheaderhistoryproof", std::move(ver_params));
            BOOST_CHECK(!ver_res["valid"].get_bool());
        }
    }

    // 2. Prove block 25 against historical anchor at height 50 (by blockhash)
    std::string block25_hash;
    std::string block50_hash;
    {
        LOCK(::cs_main);
        Chainstate &cs = m_node.chainman->ActiveChainstate();
        block25_hash = cs.m_chain[25]->GetBlockHash().GetHex();
        block50_hash = cs.m_chain[50]->GetBlockHash().GetHex();
    }
    {
        UniValue get_params(UniValue::VARR);
        get_params.push_back(block25_hash);
        get_params.push_back(block50_hash);
        const UniValue proof_res =
            call_rpc("getheaderhistoryproof", std::move(get_params));
        BOOST_CHECK_EQUAL(proof_res["leaf_height"].getInt<int>(), 25);
        BOOST_CHECK_EQUAL(proof_res["total_count"].getInt<int>(), 51);
        BOOST_CHECK_EQUAL(proof_res["block_hash"].get_str(), block25_hash);

        // Moreover, total_count == 51 means history_root is committed in block 51's MonetaryState!
        {
            LOCK(::cs_main);
            Chainstate &cs = m_node.chainman->ActiveChainstate();
            std::vector<lotus::v2::Coin> coins51;
            lotus::v2::MonetaryState mon51{};
            BOOST_REQUIRE(GetV2BlockStateCoinsAndMonetary(
                cs.m_chain[51]->GetBlockHash(), 51, coins51, mon51));
            BOOST_CHECK_EQUAL(HexStr(mon51.history_root),
                              proof_res["history_root"].get_str());
        }

        UniValue ver_params(UniValue::VARR);
        ver_params.push_back(proof_res["proof_hex"].get_str());
        ver_params.push_back(proof_res["history_root"].get_str());
        const UniValue ver_res =
            call_rpc("verifyheaderhistoryproof", std::move(ver_params));
        BOOST_CHECK(ver_res["valid"].get_bool());
    }

    // 3. Target height > anchor height must throw RPC_INVALID_PARAMETER
    {
        UniValue bad_params(UniValue::VARR);
        bad_params.push_back(60);
        bad_params.push_back(50);
        BOOST_CHECK_THROW(call_rpc("getheaderhistoryproof", std::move(bad_params)),
                          UniValue);
    }
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
