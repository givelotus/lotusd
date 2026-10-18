// Native state-sync node bridge and shared storage invariants.
// eCash's Avalanche StateAnchor API is replaced by the V2 header state_root.
#include <lotus_v2/fast_sync.h>
#include <lotus_v2/legacy_coin.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <txdb.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(native_state_sync_tests, TestChain100Setup)

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
        const auto progress = db.GetFastSyncProgress();
        BOOST_REQUIRE(progress);
        BOOST_CHECK(progress->first == first);
        BOOST_CHECK(progress->second == root);
        db.SetFastSyncProgress(second, uint256{106});
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
        BOOST_CHECK(progress->first == second);
        BOOST_CHECK(progress->second == uint256{106});
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

BOOST_AUTO_TEST_CASE(verified_native_pivot_installs_exact_coins_and_rejects_wrong_undo) {
    LOCK(cs_main);
    auto &chainstate = m_node.chainman->ActiveChainstate();
    auto *tip = chainstate.m_chain.Tip();
    std::vector<lotus::v2::Coin> coins;
    lotus::v2::MonetaryState monetary;
    BOOST_REQUIRE(GetV2BlockStateCoinsAndMonetary(tip->GetBlockHash(),
        tip->nHeight, coins, monetary));
    BOOST_REQUIRE(!coins.empty());
    // The node bridge accepts already-verified native state. Header/shard
    // authentication is exercised separately by fast_sync_shard_tests.
    std::string pivot_error;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateVerifiedFastSyncPivot(
        tip, coins, monetary, pivot_error), pivot_error);
    BOOST_CHECK(chainstate.m_chain.Tip() == tip);
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == tip->GetBlockHash());
    BOOST_CHECK_EQUAL(chainstate.GetEarliestVerifiedHeight(), tip->nHeight);
    BOOST_CHECK(chainstate.IsFastSyncActive());
    for (const auto &coin : coins) {
        uint256 id;
        std::copy(coin.outpoint.tx_id.begin(), coin.outpoint.tx_id.end(), id.begin());
        const Coin &installed = chainstate.CoinsTip().AccessCoin(
            COutPoint(TxId(id), coin.outpoint.index));
        BOOST_REQUIRE(!installed.IsSpent());
        BOOST_CHECK(installed.GetTxOut() == CTxOut::FromV2Output(coin.output));
    }
    const auto best_before = chainstate.CoinsTip().GetBestBlock();
    const int earliest_before = chainstate.GetEarliestVerifiedHeight();
    lotus::v2::BlockUndoMessage bad_undo;
    Chainstate::FastSyncPeelResult result;
    std::string error;
    BOOST_CHECK(!chainstate.PeelFastSyncBlock(tip->GetBlockHash(),
        bad_undo, nullptr, result, error));
    BOOST_CHECK(error.find("BLOCKUNDO block_id mismatch") != std::string::npos);
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == best_before);
    BOOST_CHECK_EQUAL(chainstate.GetEarliestVerifiedHeight(), earliest_before);
}

// Native cold restart/provisional ancestry/full reverse history require their
// own node integration tests; kernel proof tests are not claimed as parity.
BOOST_AUTO_TEST_SUITE_END()
