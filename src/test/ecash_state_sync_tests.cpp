// Native state-transfer invariants use authenticated V2 header commitments.
#include <lotus_v2/fast_sync.h>
#include <primitives/block.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <pow/pow.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <txdb.h>
#include <boost/test/unit_test.hpp>
#include <filesystem>
#include <fstream>

namespace {
struct PivotState {
    std::vector<lotus::v2::Coin> coins;
    lotus::v2::MonetaryState monetary;
    lotus::v2::UtxoSet utxo;
};
PivotState ReadState(CBlockIndex *index) {
    PivotState state;
    BOOST_REQUIRE(GetV2BlockStateCoinsAndMonetary(index->GetBlockHash(), index->nHeight,
                                                state.coins, state.monetary));
    for (const auto &coin : state.coins) BOOST_REQUIRE(state.utxo.Insert(coin));
    return state;
}
lotus::v2::BlockUndoMessage CoinbaseUndo(CBlockIndex *index) {
    auto parent = ReadState(index->pprev);
    lotus::v2::BlockUndoMessage undo;
    std::copy_n(index->GetBlockHash().begin(), 32, undo.block_id.begin());
    undo.parent_monetary_state = lotus::v2::EncodeMonetaryState(parent.monetary);
    return undo;
}
}
BOOST_FIXTURE_TEST_SUITE(ecash_state_sync_tests, TestChain100Setup)
BOOST_AUTO_TEST_CASE(native_state_coin_roundtrip_preserves_programs_and_creation_provenance) {
    for (size_t size : {size_t(1), size_t(25), size_t(10000)}) {
        lotus::v2::Coin coin{};
        coin.creation_height = 1;
        coin.creation_parent_mtp = 123;
        coin.output.value = 12345;
        coin.output.branches = {lotus::v2::BranchLeaf(std::vector<uint8_t>(size, 0x4e))};
        coin.output.paths = {{0}};
        std::vector<uint8_t> encoded, roundtrip;
        BOOST_REQUIRE(lotus::v2::EncodeCoin(coin, encoded));
        lotus::v2::Coin decoded;
        BOOST_REQUIRE(lotus::v2::DecodeCoinBytes(encoded, decoded));
        BOOST_REQUIRE(lotus::v2::EncodeCoin(decoded, roundtrip));
        BOOST_CHECK(encoded == roundtrip);
        BOOST_CHECK_EQUAL(decoded.creation_parent_mtp, 123);
        BOOST_CHECK_EQUAL(decoded.fee_per_output, 0);
        BOOST_CHECK_EQUAL(decoded.expiration_height, lotus::v2::ComputeUtxoExpirationHeight(1, false, 0));
    }
}
BOOST_AUTO_TEST_CASE(state_index_matches_native_coins_and_rejects_corrupt_transfer) {
    LOCK(cs_main);
    auto &cs = m_node.chainman->ActiveChainstate();
    auto *tip = cs.m_chain.Tip();
    auto state = ReadState(tip);
    BOOST_CHECK_EQUAL(state.coins.size(), 100);
    for (const auto &coin : state.coins) {
        uint256 id; std::copy(coin.outpoint.tx_id.begin(), coin.outpoint.tx_id.end(), id.begin());
        const auto &stored = cs.CoinsTip().AccessCoin(COutPoint(TxId(id), coin.outpoint.index));
        BOOST_REQUIRE(!stored.IsSpent());
        BOOST_CHECK(CTxOut::FromV2Output(coin.output) == stored.GetTxOut());
    }
    const auto header = tip->GetBlockHeader().ToV2Header();
    const auto chain_id = GetActiveV2ChainId();
    std::string error;
    lotus::v2::UtxoRootsMessage roots;
    BOOST_REQUIRE(lotus::v2::ExportUtxoRoots(state.utxo, chain_id, header, state.monetary, roots, error));
    std::vector<lotus::v2::UtxoShardMessage> shards;
    BOOST_REQUIRE(lotus::v2::ExportAdaptiveUtxoShards(state.utxo, roots.pivot_block_id, shards, error));
    lotus::v2::UtxoSet verified;
    lotus::v2::MonetaryState meta;
    BOOST_REQUIRE(lotus::v2::AssembleAndVerifyFastSyncPivot(header, chain_id, roots, shards, verified, meta, error));
    auto wrong_header = header;
    wrong_header.state_root[0] ^= 1;
    BOOST_CHECK(!lotus::v2::AssembleAndVerifyFastSyncPivot(wrong_header, chain_id, roots, shards, verified, meta, error));
    BOOST_REQUIRE(!shards.empty());
    BOOST_REQUIRE(!shards.front().coins.empty());
    shards.front().coins.front().output.value++;
    BOOST_CHECK(!lotus::v2::AssembleAndVerifyFastSyncPivot(header, chain_id, roots, shards, verified, meta, error));
    state.coins.front().output.value++;
    const auto best = cs.CoinsTip().GetBestBlock();
    BOOST_CHECK(!cs.ActivateVerifiedFastSyncPivot(tip, state.coins, state.monetary, error));
    BOOST_CHECK(cs.CoinsTip().GetBestBlock() == best);
    BOOST_CHECK(cs.m_chain.Tip() == tip);
    BOOST_CHECK(!cs.CoinsDB().GetFastSyncSnapshot());
}
BOOST_AUTO_TEST_CASE(pivot_persistence_failure_does_not_publish_atomic_marker) {
    LOCK(cs_main);
    auto &cs = m_node.chainman->ActiveChainstate();
    auto *tip = cs.m_chain.Tip();
    const auto state = ReadState(tip);
    const auto best = cs.CoinsTip().GetBestBlock();
    const auto path = std::filesystem::path(m_args.GetDataDirNet().u8string()) / "blocked-native-state";
    { std::ofstream obstruction(path); obstruction << "not a directory"; }
    SetV2StatePersistDir(path.string());
    std::string error;
    BOOST_CHECK(!cs.ActivateVerifiedFastSyncPivot(tip, state.coins, state.monetary, error));
    BOOST_CHECK_EQUAL(error, "Failed to persist authenticated pivot state");
    BOOST_CHECK(!cs.CoinsDB().GetFastSyncSnapshot());
    BOOST_CHECK(cs.CoinsTip().GetBestBlock() == best);
    BOOST_CHECK(cs.m_chain.Tip() == tip);
    std::filesystem::remove(path);
    std::filesystem::create_directory(path);
    BOOST_REQUIRE_MESSAGE(cs.ActivateVerifiedFastSyncPivot(tip, state.coins, state.monetary, error), error);
    BOOST_CHECK(cs.CoinsDB().GetFastSyncSnapshot().has_value());
    SetV2StatePersistDir("");
    std::filesystem::remove_all(path);
}
BOOST_AUTO_TEST_CASE(atomic_pivot_restart_and_full_reverse_history) {
    LOCK(cs_main);
    auto &cs = m_node.chainman->ActiveChainstate();
    auto *tip = cs.m_chain.Tip();
    auto state = ReadState(tip);
    std::string error;
    // Bodies are available locally, but this chainstate has not established
    // their execution provenance yet (as after a transferred pivot).
    for (int height = 1; height <= tip->nHeight; ++height)
        cs.m_chain[height]->nStatus = cs.m_chain[height]->nStatus.withValidity(BlockValidity::TRANSACTIONS);
    BOOST_REQUIRE_MESSAGE(cs.ActivateVerifiedFastSyncPivot(tip, state.coins, state.monetary, error), error);
    BOOST_REQUIRE(cs.CoinsDB().GetFastSyncSnapshot());
    cs.m_chain.SetTip(*cs.m_chain.Genesis());
    BOOST_REQUIRE(cs.LoadChainTip());
    BOOST_CHECK(cs.m_chain.Tip() == tip);
    BOOST_CHECK_EQUAL(cs.GetEarliestVerifiedHeight(), 100);
    BOOST_REQUIRE(cs.IsFastSyncActive());
    while (cs.GetEarliestVerifiedHeight() > 0) {
        auto *index = cs.m_chain[cs.GetEarliestVerifiedHeight()];
        auto undo = CoinbaseUndo(index);
        Chainstate::FastSyncPeelResult result;
        BOOST_REQUIRE_MESSAGE(cs.PeelFastSyncBlock(index->GetBlockHash(), undo, nullptr, result, error), error);
        if (cs.GetEarliestVerifiedHeight() > 0) {
            BOOST_CHECK(!tip->IsValid(BlockValidity::SCRIPTS));
            BOOST_CHECK(cs.SnapshotBase() == tip);
        }
    }
    BOOST_CHECK(tip->IsValid(BlockValidity::SCRIPTS));
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
BOOST_AUTO_TEST_CASE(reverse_parent_state_is_bound_to_header_not_cache) {
    LOCK(cs_main);
    auto &cs = m_node.chainman->ActiveChainstate();
    auto *tip = cs.m_chain.Tip();
    auto state = ReadState(tip);
    std::string error;
    BOOST_REQUIRE(cs.ActivateVerifiedFastSyncPivot(tip, state.coins, state.monetary, error));
    auto undo = CoinbaseUndo(tip);
    undo.parent_monetary_state[0] ^= 1;
    Chainstate::FastSyncPeelResult result;
    BOOST_CHECK(!cs.PeelFastSyncBlock(tip->GetBlockHash(), undo, nullptr, result, error));
    BOOST_CHECK_EQUAL(cs.GetEarliestVerifiedHeight(), tip->nHeight);
    BOOST_CHECK(cs.CoinsDB().GetFastSyncSnapshot().has_value());
    BOOST_CHECK(cs.m_chain.Tip() == tip);
}
BOOST_AUTO_TEST_CASE(pivot_binds_exact_output_program_and_rejects_duplicate_coins) {
    LOCK(cs_main);
    auto &cs = m_node.chainman->ActiveChainstate();
    auto *tip = cs.m_chain.Tip();
    auto state = ReadState(tip);
    std::string error;
    const auto best = cs.CoinsTip().GetBestBlock();
    auto corrupt = state.coins;
    BOOST_REQUIRE(!corrupt.empty());
    auto &output = corrupt.front().output;
    // Regtest setup mines version-2 coinbases, so the bound program is the
    // legacy script. A native branch program is corrupted the same way.
    if (output.legacy_script && !output.legacy_script->empty()) {
        (*output.legacy_script)[0] ^= 0x01;
    } else {
        BOOST_REQUIRE(!output.branches.empty());
        output.branches[0] = lotus::v2::BranchLeaf(std::vector<uint8_t>{0x00});
    }
    BOOST_CHECK(!cs.ActivateVerifiedFastSyncPivot(tip, corrupt, state.monetary, error));
    BOOST_CHECK(error.find("authenticated header") != std::string::npos);
    state.coins.push_back(state.coins.front());
    error.clear();
    BOOST_CHECK(!cs.ActivateVerifiedFastSyncPivot(tip, state.coins, state.monetary, error));
    BOOST_CHECK(error.find("duplicate") != std::string::npos);
    BOOST_CHECK(cs.CoinsTip().GetBestBlock() == best);
    BOOST_CHECK(!cs.CoinsDB().GetFastSyncSnapshot());
}
BOOST_AUTO_TEST_CASE(reverse_peel_rejects_native_coinbase_context_before_publication) {
    auto &cs = m_node.chainman->ActiveChainstate();
    // The 100-block fixture uses a version-2 coinbase. This case needs the
    // version-7 form, whose input commits to the parent and height.
    const uint32_t saved_version = m_coinbase_version;
    m_coinbase_version = 7;
    auto block = CreateBlock({}, CScript() << OP_TRUE, cs);
    m_coinbase_version = saved_version;
    LOCK(cs_main);
    auto *parent = cs.m_chain.Tip();
    CMutableTransaction coinbase(*block.vtx.front());
    BOOST_REQUIRE_EQUAL(coinbase.vin[0].nFlags, 2);
    // A structurally valid V7 coinbase with the wrong native height.
    coinbase.vin[0].prevout = COutPoint(TxId(parent->GetBlockHash()), parent->nHeight);
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.hashStateRoot = ComputeV2BlockStateRoot(block, block.hashPrevBlock,
        block.nHeight, parent->GetMedianTimePast(), false);
    block.SetSize(::GetSerializeSize(block));
    block.fChecked = false;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus()))
        ++block.nNonce;
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(CheckBlock(block, state, m_node.chainman->GetConsensus(),
        BlockValidationOptions(m_node.chainman->GetConfig())), state.ToString());
    CBlockIndex *best_header = parent;
    auto *index = m_node.chainman->m_blockman.AddToBlockIndex(block, best_header);
    BOOST_REQUIRE(index != nullptr);
    RecordV2BlockState(block, block.GetHash(), block.hashPrevBlock,
                       block.nHeight, parent->GetMedianTimePast());
    auto pivot = ReadState(index);
    std::string error;
    BOOST_REQUIRE(cs.ActivateVerifiedFastSyncPivot(index, pivot.coins, pivot.monetary, error));
    auto undo = CoinbaseUndo(index);
    Chainstate::FastSyncPeelResult result;
    BOOST_CHECK(!cs.PeelFastSyncBlock(block.GetHash(), undo, &block, result, error));
    BOOST_CHECK(error.find("bad-cb-height") != std::string::npos);
    BOOST_CHECK_EQUAL(cs.GetEarliestVerifiedHeight(), index->nHeight);
    BOOST_CHECK(!index->IsValid(BlockValidity::SCRIPTS));
    BOOST_CHECK(!index->nStatus.hasUndo());
    BOOST_CHECK(cs.CoinsDB().GetFastSyncSnapshot().has_value());
}
BOOST_AUTO_TEST_SUITE_END()
