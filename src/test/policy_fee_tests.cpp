// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>
#include <protocol.h>
#include <streams.h>
#include <common/args.h>
#include <consensus/consensus.h>
#include <validation.h>
#include <consensus/amount.h>
#include <feerate.h>
#include <lotus_v2/fee_hysteresis.h>
#include <policy/fees.h>
#include <rpc/server.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/moneystr.h>
#include <util/time.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(policy_fee_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(FeeRounder) {
    FastRandomContext rng{/*fDeterministic=*/true};
    FeeFilterRounder fee_rounder{CFeeRate{1000 * SATOSHI}, rng};

    // check that 1000 rounds to 974 or 1071
    std::set<Amount> results;
    while (results.size() < 2) {
        results.emplace(fee_rounder.round(1000 * SATOSHI));
    }
    BOOST_CHECK_EQUAL(*results.begin(), 974 * SATOSHI);
    BOOST_CHECK_EQUAL(*++results.begin(), 1071 * SATOSHI);

    // check that negative amounts rounds to 0
    BOOST_CHECK_EQUAL(fee_rounder.round(-0 * SATOSHI), Amount::zero());
    BOOST_CHECK_EQUAL(fee_rounder.round(-1 * SATOSHI), Amount::zero());

    // check that MAX_MONEY rounds to 9170997
    BOOST_CHECK_EQUAL(fee_rounder.round(MAX_MONEY), 9170997 * SATOSHI);
}

BOOST_AUTO_TEST_CASE(AdaptiveBlockSizeAndFeeHysteresis) {
    lotus::v2::FeeHysteresisController ctrl{};

    // At idle baseline with 0 backlog, generated block size is 16 MB and max block size is 32 MB
    BOOST_CHECK_EQUAL(ctrl.GetEmaBlockSizeBytes(),
                      lotus::v2::DEFAULT_MIN_ADAPTIVE_TARGET_BYTES);
    BOOST_CHECK_EQUAL(ctrl.GetAdaptiveMaxGeneratedBlockSize(), 16'000'000ULL);
    BOOST_CHECK_EQUAL(ctrl.GetAdaptiveMaxBlockSize(), 32'000'000ULL);

    // Recording a 40 MB mempool backlog expands adaptive max generated block size
    // while accepted block capacity remains independent of local demand.
    ctrl.RecordMempoolBacklog(40'000'000ULL, 1000);
    BOOST_CHECK_GE(ctrl.GetAdaptiveMaxGeneratedBlockSize(), 41'000'000ULL);
    BOOST_CHECK_EQUAL(ctrl.GetAdaptiveMaxBlockSize(), 32'000'000ULL);

    // Recording connected 64 MB blocks raises the EMA block size and adaptive target.
    for (int i = 0; i < 32; ++i) {
        ctrl.RecordConnectedBlock(64'000'000ULL, 2000 + i * 100);
    }
    BOOST_CHECK_GT(ctrl.GetEmaBlockSizeBytes(), 32'000'000ULL);
    const auto info = ctrl.GetFeeRateInfo(6000);
    BOOST_CHECK_EQUAL(info.ema_block_size_bytes, ctrl.GetEmaBlockSizeBytes());
    BOOST_CHECK_GT(info.adaptive_target_block_size,
                   lotus::v2::DEFAULT_MIN_ADAPTIVE_TARGET_BYTES);
    BOOST_CHECK_LE(info.adaptive_max_block_size,
                   lotus::v2::DEFAULT_ADAPTIVE_MAX_BLOCK_CEILING);

    // Recording an empty mempool backlog immediately after a 128 MB connected
    // block must not overwrite the congestion rate induced by the connected block.
    ctrl.RecordConnectedBlock(128'000'000ULL, 7000);
    const uint64_t rate_after_block = ctrl.GetRpcAdmissionRatePerKCu(7000);
    BOOST_CHECK_GT(rate_after_block, 1000ULL);
    ctrl.RecordMempoolBacklog(0ULL, 7001);
    BOOST_CHECK_EQUAL(ctrl.GetRpcAdmissionRatePerKCu(7001), rate_after_block);

    // Marginal P05 burn fee rate rises with block cost and EMA under tight shifts
    const uint64_t burn_rate_1gb =
        lotus::v2::FeeHysteresisController::ComputeMarginalBurnFeeRatePerKCu(
            1'000'000'000ULL, 1'000'000'000ULL, /*linear_shift=*/24,
            /*quad_shift=*/44, /*ema_min=*/4);
    BOOST_CHECK_GT(burn_rate_1gb, 100'000ULL);
}

BOOST_AUTO_TEST_CASE(adaptive_history_reorg_cache_eviction_and_unavailable_ancestry) {
    std::vector<CBlockIndex> chain(4098);
    std::vector<BlockHash> hashes(chain.size());
    for (size_t i = 0; i < chain.size(); ++i) {
        uint256 value;
        WriteLE64(value.begin(), i + 1);
        hashes[i] = BlockHash(value);
        chain[i].phashBlock = &hashes[i];
        chain[i].pprev = i ? &chain[i - 1] : nullptr;
        chain[i].nHeight = i;
        chain[i].nSize = 17'000'000;
    }
    lotus::v2::FeeHysteresisController a, b;
    a.SyncActiveTip(&chain.back(), 1000);
    b.SyncActiveTip(&chain[1], 1000);
    // Ancestor 1 has been evicted: rollback must reconstruct, not retain the tip EMA.
    a.SyncActiveTip(&chain[1], 2000);
    BOOST_CHECK_EQUAL(a.GetEmaBlockSizeBytes(), b.GetEmaBlockSizeBytes());
    BOOST_CHECK(a.HasCompleteAdaptiveHistory());
    chain[2].nSize = 0;
    a.Reset(3000);
    a.SyncActiveTip(&chain.back(), 3000);
    BOOST_CHECK(!a.HasCompleteAdaptiveHistory());
    BOOST_CHECK(!a.GetFeeRateInfo(3000).adaptive_history_available);
    BOOST_CHECK_EQUAL(a.GetAdaptiveMaxBlockSize(), 32'000'000);
    BOOST_CHECK_EQUAL(a.GetEmaBlockSizeBytes(), 16'000'000);
    // Restoring complete ancestry and rebuilding (as at restart) recovers history.
    chain[2].nSize = 17'000'000;
    a.Reset(4000);
    a.SyncActiveTip(&chain.back(), 4000);
    BOOST_CHECK(a.HasCompleteAdaptiveHistory());
    BOOST_CHECK_GT(a.GetAdaptiveMaxBlockSize(), 32'000'000);
}

BOOST_AUTO_TEST_CASE(adaptive_ancestry_size_survives_pruned_index_roundtrip) {
    LOCK(cs_main);
    CBlockIndex index;
    index.nHeight = 123;
    index.nSize = 17'000'000;
    index.nStatus = index.nStatus.withData(false);
    CDiskBlockIndex stored(&index), loaded;
    DataStream stream;
    stream << stored;
    stream >> loaded;
    BOOST_CHECK_EQUAL(loaded.nSize, index.nSize);

    // Legacy unpruned records have the same payload with the old version tag.
    index.nStatus = index.nStatus.withData(true);
    CDiskBlockIndex unpruned(&index), legacy_loaded;
    DataStream legacy, old_tag;
    legacy << unpruned;
    int old_version = 320400;
    old_tag << VARINT_MODE(old_version, VarIntMode::NONNEGATIVE_SIGNED);
    std::copy(old_tag.begin(), old_tag.end(), legacy.begin());
    legacy >> legacy_loaded;
    BOOST_CHECK_EQUAL(legacy_loaded.nSize, index.nSize);

    // Old pruned records omitted size entirely: decode it as unavailable, not zero history.
    index.nStatus = index.nStatus.withData(false);
    CDiskBlockIndex pruned(&index), old_pruned;
    DataStream old_pruned_bytes, prefix, encoded_size;
    old_pruned_bytes << pruned;
    int version = 320401;
    prefix << VARINT_MODE(version, VarIntMode::NONNEGATIVE_SIGNED)
           << VARINT_MODE(pruned.nHeight, VarIntMode::NONNEGATIVE_SIGNED)
           << pruned.nStatus << VARINT(pruned.nTx);
    encoded_size << VARINT(pruned.nSize);
    old_pruned_bytes.erase(old_pruned_bytes.begin() + prefix.size(),
                           old_pruned_bytes.begin() + prefix.size() + encoded_size.size());
    std::copy(old_tag.begin(), old_tag.end(), old_pruned_bytes.begin());
    old_pruned_bytes >> old_pruned;
    BOOST_CHECK_EQUAL(old_pruned.nSize, 0);
    BOOST_CHECK(old_pruned_bytes.empty());

    DataStream future, future_tag;
    future << unpruned;
    version = 320402;
    future_tag << VARINT_MODE(version, VarIntMode::NONNEGATIVE_SIGNED);
    std::copy(future_tag.begin(), future_tag.end(), future.begin());
    BOOST_CHECK_THROW(future >> legacy_loaded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(adaptive_block_message_bound_tracks_current_capacity) {
    GlobalConfig config;
    auto &controller = lotus::v2::GetGlobalFeeHysteresisController();
    controller.Reset(0);
    const auto size = controller.GetAdaptiveMaxBlockSize() + 256 * 1024 + 1;
    CMessageHeader header(config.GetChainParams().NetMagic(), NetMsgType::BLOCK, size);
    BOOST_CHECK(header.IsOversized(config));
    for (int i = 0; i < 32; ++i) controller.RecordConnectedBlock(64'000'000, i);
    BOOST_CHECK(!header.IsOversized(config));
    controller.Reset(0);
}

BOOST_AUTO_TEST_CASE(adaptive_policy_preserves_ecash_block_validity_limit) {
    GlobalConfig config;
    auto &controller = lotus::v2::GetGlobalFeeHysteresisController();
    controller.Reset(0);
    controller.RecordConnectedBlock(64'000'000, 1000);
    BOOST_CHECK_GT(controller.GetAdaptiveMaxBlockSize(), DEFAULT_MAX_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(config.GetMaxBlockSize(), DEFAULT_MAX_BLOCK_SIZE);
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    cb.vout.emplace_back(SATOSHI, CScript() << OP_TRUE);
    while (::GetSerializeSize(cb) < MIN_TRANSACTION_SIZE) cb.vout[0].scriptPubKey << OP_NOP;
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(TxId(uint256S("11")), 0), CScript() << OP_TRUE);
    tx.vout.emplace_back(SATOSHI, CScript() << OP_TRUE);
    while (::GetSerializeSize(tx) < MIN_TRANSACTION_SIZE) tx.vout[0].scriptPubKey << OP_NOP;
    CBlock block;
    block.nBits = 0x207fffff;
    block.vtx.assign(DEFAULT_MAX_BLOCK_SIZE / MIN_TRANSACTION_SIZE + 1, MakeTransactionRef(tx));
    block.vtx[0] = MakeTransactionRef(cb);
    BlockValidationState state;
    const BlockValidationOptions options(DEFAULT_MAX_BLOCK_SIZE, false, false);
    BOOST_CHECK(!CheckBlock(block, state, config.GetChainParams().GetConsensus(), options));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-length");
    controller.Reset(0);
}

BOOST_AUTO_TEST_SUITE_END()
