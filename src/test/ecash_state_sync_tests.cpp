// eCash state-transfer invariants: legacy scripts and consensus stay unchanged.
#include <lotus_v2/fast_sync.h>
#include <lotus_v2/legacy_coin.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <txdb.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(ecash_state_sync_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(legacy_state_coin_roundtrip_preserves_arbitrary_scripts) {
    for (size_t size : {size_t(0), size_t(1), size_t(25), size_t(10000)}) {
        std::vector<uint8_t> bytes(size, OP_NOP);
        CTxOut out(12345 * SATOSHI, CScript(bytes.begin(), bytes.end()));
        lotus::v2::Coin coin{};
        coin.creation_height = 1;
        coin.output = lotus::v2::LegacyStateOutput(out);
        std::vector<uint8_t> encoded;
        BOOST_REQUIRE(lotus::v2::EncodeCoin(coin, encoded));
        lotus::v2::Coin decoded;
        BOOST_REQUIRE(lotus::v2::DecodeCoinBytes(encoded, decoded));
        BOOST_CHECK(lotus::v2::LegacyTxOutput(decoded.output) == out);
        std::string error;
        BOOST_CHECK(!lotus::v2::EncodeOutput(decoded.output, encoded, error));
    }
    lotus::v2::Output wrong;
    wrong.legacy_script.emplace(10001, OP_NOP);
    BOOST_CHECK_THROW(lotus::v2::LegacyTxOutput(wrong), std::invalid_argument);
    wrong.legacy_script.emplace(); wrong.flags = 1;
    BOOST_CHECK_THROW(lotus::v2::LegacyTxOutput(wrong), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(state_index_matches_abc_utxo_set_and_rejects_corrupt_transfer) {
    LOCK(cs_main);
    auto &chainstate = m_node.chainman->ActiveChainstate();
    Chainstate::FastSyncBlockState state;
    std::string error;
    auto *tip = chainstate.m_chain.Tip();
    BOOST_REQUIRE(chainstate.ExportV2BlockStateCoinsAndMonetary(tip, state, error));
    BOOST_CHECK_EQUAL(state.utxo.Coins().size(), 100);
    for (const auto &coin : state.utxo.Coins()) {
        BOOST_CHECK_GT(coin.creation_height, 0);
        // Compare exact bytes without interpreting the internal hash as display hex.
        uint256 id; std::copy(coin.outpoint.tx_id.begin(), coin.outpoint.tx_id.end(), id.begin());
        auto op = COutPoint(TxId(id), coin.outpoint.index);
        const auto &legacy = chainstate.CoinsTip().AccessCoin(op);
        BOOST_REQUIRE(!legacy.IsSpent());
        BOOST_CHECK(lotus::v2::LegacyTxOutput(coin.output) == legacy.GetTxOut());
    }
    lotus::v2::Hash pivot{};
    std::copy_n(tip->GetBlockHash().begin(), 32, pivot.begin());
    lotus::v2::UtxoRootsMessage roots;
    BOOST_REQUIRE(lotus::v2::ExportUtxoRootsForBlock(state.utxo, pivot, tip->nHeight, state.monetary, roots, error));
    std::vector<lotus::v2::UtxoShardMessage> shards;
    BOOST_REQUIRE(lotus::v2::ExportAdaptiveUtxoShards(state.utxo, pivot, shards, error));
    lotus::v2::UtxoSet verified;
    lotus::v2::MonetaryState meta;
    BOOST_REQUIRE(lotus::v2::AssembleAndVerifyFastSyncPivot(pivot, tip->nHeight, state.utxo_root, roots, shards, verified, meta, error));
    BOOST_CHECK(verified.Root() == state.utxo_root);
    BOOST_CHECK(!lotus::v2::AssembleAndVerifyFastSyncPivot(pivot, tip->nHeight, std::nullopt, roots, shards, verified, meta, error));
    BOOST_REQUIRE(!shards.empty());
    BOOST_REQUIRE(!shards.front().coins.empty());
    shards.front().coins.front().output.value++;
    const auto best_before = chainstate.CoinsTip().GetBestBlock();
    BOOST_CHECK(!chainstate.ActivateVerifiedFastSyncPivot(tip, roots, shards, error));
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == best_before);
    BOOST_CHECK(chainstate.m_chain.Tip() == tip);
}
BOOST_AUTO_TEST_CASE(atomic_pivot_restart_and_full_reverse_history) {
    LOCK(cs_main);
    auto &cs = m_node.chainman->ActiveChainstate();
    cs.SetFastSyncMaxPeelBlocks(0);
    auto *tip = cs.m_chain.Tip();
    Chainstate::FastSyncBlockState state;
    std::string error;
    BOOST_REQUIRE(cs.ExportV2BlockStateCoinsAndMonetary(tip, state, error));
    lotus::v2::Hash id{};
    std::copy_n(tip->GetBlockHash().begin(), 32, id.begin());
    lotus::v2::UtxoRootsMessage roots;
    BOOST_REQUIRE(lotus::v2::ExportUtxoRootsForBlock(state.utxo, id, tip->nHeight, state.monetary, roots, error));
    std::vector<lotus::v2::UtxoShardMessage> shards;
    BOOST_REQUIRE(lotus::v2::ExportAdaptiveUtxoShards(state.utxo, id, shards, error));
    BOOST_REQUIRE_MESSAGE(cs.ActivateVerifiedFastSyncPivot(tip, roots, shards, error), error);
    BOOST_REQUIRE(cs.CoinsDB().GetFastSyncSnapshot());
    // Exercise startup reconstruction from the committed database marker.
    cs.m_chain.SetTip(*cs.m_chain.Genesis());
    BOOST_REQUIRE(cs.LoadChainTip());
    BOOST_CHECK(cs.m_chain.Tip() == tip);
    BOOST_CHECK_EQUAL(cs.GetEarliestVerifiedHeight(), 100);
    BOOST_REQUIRE(cs.IsFastSyncActive());
    while (cs.GetEarliestVerifiedHeight() > 0) {
        auto *index = const_cast<CBlockIndex *>(cs.GetEarliestVerifiedBlock());
        CBlock block;
        BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlock(block, *index));
        BOOST_REQUIRE_MESSAGE(cs.PeelFastSyncBlock(block, index, {}, error), error);
    }
    BOOST_CHECK(!cs.IsFastSyncActive());
    BOOST_CHECK(!cs.CoinsDB().GetFastSyncSnapshot());
    BOOST_CHECK(cs.CoinsTip().GetBestBlock() == tip->GetBlockHash());
    BOOST_CHECK(cs.SnapshotBase() == nullptr);
    m_node.chainman->CheckBlockIndex();
}
BOOST_AUTO_TEST_CASE(snapshot_database_commit_and_failed_replacement_survive_reopen) {
    const DBParams params{.path = m_path_root / "snapshot-atomic", .cache_bytes = 1 << 20,
                          .memory_only = false, .wipe_data = false, .obfuscate = true};
    const BlockHash first{uint256{101}}, second{uint256{102}};
    const uint256 root{103};
    const COutPoint outpoint{TxId(uint256{104}), 0};
    const Coin coin{CTxOut(10 * SATOSHI, CScript() << OP_TRUE), 1, false};
    {
        CCoinsViewDB db(params, {});
        db.InstallFastSyncSnapshot(first, root, {{outpoint, coin}});
        BOOST_CHECK_THROW(db.InstallFastSyncSnapshot(second, root,
            {{outpoint, coin}, {COutPoint{TxId(uint256{105}), 0}, Coin{}}}), std::invalid_argument);
        BOOST_CHECK(db.GetBestBlock() == first);
        BOOST_REQUIRE(db.GetCoin(outpoint));
    }
    {
        CCoinsViewDB db(params, {});
        BOOST_CHECK(db.GetBestBlock() == first);
        BOOST_CHECK(!db.NeedsUpgrade());
        auto marker = db.GetFastSyncSnapshot();
        BOOST_REQUIRE(marker);
        BOOST_CHECK(marker->first == first);
        BOOST_CHECK(marker->second == root);
        const auto progress = db.GetFastSyncProgress();
        BOOST_REQUIRE(progress);
        BOOST_CHECK(progress->first == first);
        BOOST_CHECK(progress->second == root);
        db.SetFastSyncProgress(second, uint256{106});
        BOOST_REQUIRE(db.GetFastSyncProgress());
        BOOST_CHECK(db.GetFastSyncProgress()->first == second);
        BOOST_REQUIRE(db.GetCoin(outpoint));
        BOOST_CHECK(db.GetCoin(outpoint)->GetTxOut() == coin.GetTxOut());
        db.ClearFastSyncSnapshot();
    }
    {
        CCoinsViewDB db(params, {});
        BOOST_CHECK(!db.GetFastSyncSnapshot());
        BOOST_CHECK(!db.GetFastSyncProgress());
        BOOST_CHECK(db.GetBestBlock() == first);
    }
}
BOOST_AUTO_TEST_CASE(reverse_cache_is_not_an_authenticated_parent_anchor) {
    LOCK(cs_main);
    auto &active = m_node.chainman->ActiveChainstate();
    auto *tip = active.m_chain.Tip();
    Chainstate::FastSyncBlockState state;
    std::string error;
    BOOST_REQUIRE(active.ExportV2BlockStateCoinsAndMonetary(tip, state, error));
    lotus::v2::Hash id{};
    std::copy_n(tip->GetBlockHash().begin(), 32, id.begin());
    lotus::v2::UtxoRootsMessage roots;
    std::vector<lotus::v2::UtxoShardMessage> shards;
    BOOST_REQUIRE(lotus::v2::ExportUtxoRootsForBlock(state.utxo, id, tip->nHeight, state.monetary, roots, error));
    BOOST_REQUIRE(lotus::v2::ExportAdaptiveUtxoShards(state.utxo, id, shards, error));
    Chainstate isolated(nullptr, m_node.chainman->m_blockman, *m_node.chainman);
    isolated.InitCoinsDB(1 << 20, true, true, "isolated-state");
    isolated.InitCoinsCache(1 << 20);
    isolated.m_chain.SetTip(*active.m_chain.Genesis());
    isolated.CoinsTip().SetBestBlock(active.m_chain.Genesis()->GetBlockHash());
    isolated.SetFastSyncStateAnchor(tip->GetBlockHash(), state.utxo_root);
    BOOST_REQUIRE_MESSAGE(isolated.ActivateVerifiedFastSyncPivot(tip, roots, shards, error), error);
    BOOST_CHECK(!isolated.GetFastSyncStateAnchor(tip->pprev->GetBlockHash()));
    CBlock block;
    BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlock(block, *tip));
    BOOST_REQUIRE_MESSAGE(isolated.PeelFastSyncBlock(block, tip, {}, error), error);
    BOOST_CHECK(!isolated.GetFastSyncStateAnchor(tip->pprev->GetBlockHash()));
    BOOST_CHECK(isolated.SnapshotBase() == tip);
    isolated.CoinsTip().Flush();
}
BOOST_AUTO_TEST_CASE(reverse_peel_binds_exact_legacy_output_script) {
    lotus::v2::Coin coin{};
    coin.creation_height = 1;
    coin.coinbase = true;
    coin.output = lotus::v2::LegacyStateOutput(CTxOut(10 * SATOSHI, CScript() << OP_TRUE));
    lotus::v2::UtxoSet state;
    BOOST_REQUIRE(state.Insert(coin));
    const auto before = state.Root();
    lotus::v2::BlockCreatedOutput created{coin.outpoint,
        lotus::v2::LegacyStateOutput(CTxOut(10 * SATOSHI, CScript() << OP_FALSE)), true};
    lotus::v2::Hash parent{};
    std::string error;
    BOOST_CHECK(!lotus::v2::VerifyAndPeelReverseBlock(1, 0, {created}, {}, {}, state,
        lotus::v2::EmptyUtxoRoot(), parent, error));
    BOOST_CHECK(state.Root() == before);
}
BOOST_AUTO_TEST_SUITE_END()
