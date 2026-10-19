// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>
#include <core_io.h>
#include <protocol.h>
#include <streams.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <common/args.h>
#include <consensus/consensus.h>
#include <validation.h>
#include <consensus/amount.h>
#include <feerate.h>
#include <key.h>
#include <lotus_v2/fee_hysteresis.h>
#include <lotus_v2/vm.h>
#include <policy/fees.h>
#include <primitives/v2_outputs.h>
#include <rpc/server.h>
#include <rpc/protocol.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <test/util/setup_common.h>
#include <test/util/native_snapshot_setup.h>
#include <test/util/transaction_utils.h>

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

BOOST_AUTO_TEST_CASE(FeeHysteresisScheduleAndWindow) {
    lotus::v2::FeeHysteresisController ctrl;

    // Default uncongested state at t = 0 ms
    const auto info0 = ctrl.GetFeeRateInfo(0);
    BOOST_CHECK_EQUAL(info0.consensus_floor_per_kcu, 1000ULL);
    BOOST_CHECK_EQUAL(info0.p2p_relay_feerate_per_kcu, 1000ULL);
    BOOST_CHECK_EQUAL(info0.rpc_admission_feerate_per_kcu, 1000ULL);
    BOOST_CHECK_EQUAL(info0.recommended_sdk_feerate_per_kcu, 1050ULL);
    BOOST_CHECK_EQUAL(info0.hysteresis_window_ms, 30000);
    BOOST_CHECK_EQUAL(info0.hysteresis_discount_permille, 150ULL);

    // Rising congestion at t = 10,000 ms: RPC admission jumps to 2,000 per kCU.
    // Because t = 0 ms (rate 1,000) is still inside the 30-second rolling window
    // [t - 30,000, t], P2P relay stays anchored at 1,000 so in-flight transactions
    // signed just before the spike still propagate across P2P.
    ctrl.SetRpcAdmissionRatePerKCu(2000, 10000);
    const auto info_rising = ctrl.GetFeeRateInfo(10000);
    BOOST_CHECK_EQUAL(info_rising.rpc_admission_feerate_per_kcu, 2000ULL);
    BOOST_CHECK_EQUAL(info_rising.recommended_sdk_feerate_per_kcu, 2100ULL);
    BOOST_CHECK_EQUAL(info_rising.p2p_relay_feerate_per_kcu, 1000ULL);

    // After 30 seconds of sustained congestion (t = 40,001 ms), the t = 0 sample
    // expires from the rolling window; rolling min is 2,000, so P2P relay rate
    // becomes floor(0.85 * 2000) = 1,700 per kCU.
    const auto info_sustained = ctrl.GetFeeRateInfo(40001);
    BOOST_CHECK_EQUAL(info_sustained.rpc_admission_feerate_per_kcu, 2000ULL);
    BOOST_CHECK_EQUAL(info_sustained.recommended_sdk_feerate_per_kcu, 2100ULL);
    BOOST_CHECK_EQUAL(info_sustained.p2p_relay_feerate_per_kcu, 1700ULL);

    // Falling congestion at t = 45,000 ms: RPC admission drops to 1,400 per kCU.
    // Rolling min in [15,000, 45,000] immediately becomes 1,400, so P2P relay drops
    // to floor(0.85 * 1400) = 1,190 per kCU.
    ctrl.SetRpcAdmissionRatePerKCu(1400, 45000);
    const auto info_falling = ctrl.GetFeeRateInfo(45000);
    BOOST_CHECK_EQUAL(info_falling.rpc_admission_feerate_per_kcu, 1400ULL);
    BOOST_CHECK_EQUAL(info_falling.recommended_sdk_feerate_per_kcu, 1470ULL);
    BOOST_CHECK_EQUAL(info_falling.p2p_relay_feerate_per_kcu, 1190ULL);

    // Congestion clears via UpdateCongestion below target capacity: clamped at 1,000.
    const uint64_t cleared_rate = ctrl.UpdateCongestion(10'000'000, 25'000'000, 50000);
    BOOST_CHECK_EQUAL(cleared_rate, 1000ULL);
    BOOST_CHECK_EQUAL(ctrl.GetP2pRelayRatePerKCu(50000), 1000ULL);

    // Dynamic congestion above target capacity scales quadratically above 1,000.
    const uint64_t congested_rate = ctrl.UpdateCongestion(50'000'000, 25'000'000, 90000);
    BOOST_CHECK_EQUAL(congested_rate, 3000ULL);
}

BOOST_AUTO_TEST_CASE(ThreeTierAdmissionAndBounceDiagnostics) {
    lotus::v2::FeeHysteresisController ctrl;
    ctrl.Reset(0);
    ctrl.SetRpcAdmissionRatePerKCu(2000, 0);
    // Advance past the 30s window so rolling min is 2,000 and P2P rate is 1,700.
    const int64_t now_ms = 35000;
    const uint64_t tx_cu = 2500;

    // 1. RPC Bounce Diagnostics (Tier 1):
    // Required fee at 2,000 sats/kCU for 2,500 CU = 5,000 sats.
    // Recommended SDK fee (+5% cushion = 2,100 sats/kCU) = 5,250 sats.
    // A transaction paying 4,500 sats is rejected at Tier 1 with exact diagnostics.
    const auto rpc_reject = ctrl.EvaluateTransactionFee(
        lotus::v2::FeeTier::RpcAdmission, tx_cu, /*paid_fee_sats=*/4500, now_ms);
    BOOST_CHECK(!rpc_reject.accepted);
    BOOST_CHECK_EQUAL(rpc_reject.required_rate_per_kcu, 2000ULL);
    BOOST_CHECK_EQUAL(rpc_reject.required_fee_sats, 5000ULL);
    BOOST_CHECK_EQUAL(rpc_reject.recommended_sdk_fee_sats, 5250ULL);

    // Re-signing with required_fee_sats (or recommended_sdk_fee_sats) succeeds in 1 round-trip.
    const auto rpc_accept = ctrl.EvaluateTransactionFee(
        lotus::v2::FeeTier::RpcAdmission, tx_cu, rpc_reject.recommended_sdk_fee_sats, now_ms);
    BOOST_CHECK(rpc_accept.accepted);

    // 2. P2P Relay Hysteresis Band (Tier 2):
    // The same 4,500-sat transaction (>= 4,250 sats required at 1,700 sats/kCU)
    // is accepted over P2P relay, preventing mempool divergence across peers.
    const auto p2p_accept = ctrl.EvaluateTransactionFee(
        lotus::v2::FeeTier::P2pRelay, tx_cu, /*paid_fee_sats=*/4500, now_ms);
    BOOST_CHECK(p2p_accept.accepted);
    BOOST_CHECK_EQUAL(p2p_accept.required_rate_per_kcu, 1700ULL);
    BOOST_CHECK_EQUAL(p2p_accept.required_fee_sats, 4250ULL);

    // 3. Consensus Floor Invariance (Tier 3):
    // Even if local RPC admission spikes to 50,000 sats/kCU, avabatch and block
    // validation only enforce the 1,000 sats/kCU consensus floor (2,500 sats).
    ctrl.SetRpcAdmissionRatePerKCu(50000, now_ms);
    const auto consensus_accept = ctrl.EvaluateTransactionFee(
        lotus::v2::FeeTier::ConsensusFloor, tx_cu, /*paid_fee_sats=*/2500, now_ms);
    BOOST_CHECK(consensus_accept.accepted);
    BOOST_CHECK_EQUAL(consensus_accept.required_rate_per_kcu, 1000ULL);
    BOOST_CHECK_EQUAL(consensus_accept.required_fee_sats, 2500ULL);
}

BOOST_AUTO_TEST_CASE(VmEnumerateConstantBoundAndExecutedCost) {
    const lotus::v2::VmProfile profile{4096, 16, 1024, 128, 32, 8192, 16, 1000};
    lotus::v2::VmCostProfile schedule{};
    schedule.max_invocation_cost = 1'000'000;
    schedule.structural_byte_cost = 1;
    for (auto &op : schedule.opcode) {
        op = {1, 1, 1};
    }

    auto eval_script = [&](const std::string &hex,
                           const std::vector<lotus::v2::VmBytes> &args = {}) {
        const auto code = ParseHex(hex);
        return lotus::v2::EvaluateVmCharged(code, args, profile, schedule);
    };

    // <1> ENUMERATE DROP ENDENUMERATE <1>: constant k = 1 charges 1 iteration (74 CU),
    // not 256 iterations (4,664 CU).
    const auto enum1 = eval_script("4e69796a4e");
    BOOST_CHECK(enum1.charged);
    BOOST_CHECK_EQUAL(static_cast<int>(enum1.invocation.status),
                      static_cast<int>(lotus::v2::VmStatus::Success));
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(enum1.accounting_cost), 74ULL);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(enum1.invocation.executed_cost), 74ULL);

    // <5> ENUMERATE DROP ENDENUMERATE <1>: constant k = 5 charges 5 iterations (146 CU).
    const auto enum5 = eval_script("5269796a4e");
    BOOST_CHECK(enum5.charged);
    BOOST_CHECK_EQUAL(static_cast<int>(enum5.invocation.status),
                      static_cast<int>(lotus::v2::VmStatus::Success));
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(enum5.accounting_cost), 56ULL + 5ULL * 18ULL);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(enum5.invocation.executed_cost), 56ULL + 5ULL * 18ULL);

    // Dynamic ENUMERATE (top of stack is runtime value 1, not a literal opcode)
    // retains the worst-case 256 bound for accounting_cost (4,646 CU) while reporting
    // exact runtime executed_cost (56 CU).
    const lotus::v2::VmBytes one_arg(lotus::v2::VM_MIN_NUMERIC_BYTES, 0);
    std::vector<lotus::v2::VmBytes> dyn_args{one_arg};
    dyn_args[0][0] = 1;
    const auto enum_dyn = eval_script("69796a4e", dyn_args);
    BOOST_CHECK(enum_dyn.charged);
    BOOST_CHECK_EQUAL(static_cast<int>(enum_dyn.invocation.status),
                      static_cast<int>(lotus::v2::VmStatus::Success));
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(enum_dyn.accounting_cost), 4646ULL);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(enum_dyn.invocation.executed_cost), 56ULL);
    BOOST_CHECK_LT(static_cast<uint64_t>(enum_dyn.invocation.executed_cost),
                   static_cast<uint64_t>(enum_dyn.accounting_cost));

    // Early BREAK inside <5> ENUMERATE DROP <1> <1> BREAK ENDENUMERATE <1>
    // (condition true, depth 1): static accounting_cost charges all 5
    // iterations, while executed_cost charges only 1.
    const auto enum_break = eval_script("5269794e4e6b6a4e");
    BOOST_CHECK(enum_break.charged);
    BOOST_CHECK_EQUAL(static_cast<int>(enum_break.invocation.status),
                      static_cast<int>(lotus::v2::VmStatus::Success));
    BOOST_CHECK_GT(static_cast<uint64_t>(enum_break.invocation.executed_cost), 0ULL);
    BOOST_CHECK_LT(static_cast<uint64_t>(enum_break.invocation.executed_cost),
                   static_cast<uint64_t>(enum_break.accounting_cost));
}

BOOST_FIXTURE_TEST_CASE(GetFeeRateInfoAndTestRawTxBatchRpc, NativeSnapshotChainSetup) {
    GlobalConfig config;
    auto &fee_ctrl = lotus::v2::GetGlobalFeeHysteresisController();
    fee_ctrl.Reset(TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now()));

    // 1. Verify getfeerateinfo RPC returns all expected hysteresis and adaptive block size fields.
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "getfeerateinfo";
        req.params = UniValue(UniValue::VARR);
        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK_EQUAL(res.find_value("consensus_floor_per_kcu").getInt<uint64_t>(), 1000ULL);
        BOOST_CHECK_EQUAL(res.find_value("p2p_relay_feerate_per_kcu").getInt<uint64_t>(), 1000ULL);
        BOOST_CHECK_EQUAL(res.find_value("rpc_admission_feerate_per_kcu").getInt<uint64_t>(), 1000ULL);
        BOOST_CHECK_EQUAL(res.find_value("recommended_sdk_feerate_per_kcu").getInt<uint64_t>(), 1050ULL);
        BOOST_CHECK_EQUAL(
            res.find_value("marginal_burn_feerate_per_kcu").getInt<uint64_t>(),
            lotus::v2::FeeHysteresisController::ComputeMarginalBurnFeeRatePerKCu(
                0, lotus::v2::DEFAULT_MIN_ADAPTIVE_TARGET_BYTES));
        BOOST_CHECK_EQUAL(res.find_value("hysteresis_window_ms").getInt<int64_t>(), 30000);
        BOOST_CHECK_EQUAL(res.find_value("hysteresis_discount_permille").getInt<uint64_t>(), 150ULL);
        BOOST_CHECK_EQUAL(res.find_value("ema_block_size_bytes").getInt<uint64_t>(),
                          lotus::v2::DEFAULT_MIN_ADAPTIVE_TARGET_BYTES);
        BOOST_CHECK_EQUAL(res.find_value("adaptive_target_block_size").getInt<uint64_t>(),
                          lotus::v2::DEFAULT_MIN_ADAPTIVE_TARGET_BYTES);
        BOOST_CHECK_EQUAL(res.find_value("adaptive_max_block_size").getInt<uint64_t>(),
                          32'000'000ULL);
        BOOST_CHECK_EQUAL(res.find_value("adaptive_max_generated_block_size").getInt<uint64_t>(),
                          16'000'000ULL);
    }

    // 2. Verify testrawtxbatch accepts a legacy transaction spending a legacy
    // coin, and reports required_cu, required_fee_sats, and recommended_sdk_fee_sats
    // on pure version=7 transactions while enforcing Tier 1 RPC fee hysteresis.
    const std::vector<uint8_t> v2_op_true_script{0x4e};
    const lotus::v2::Hash v2_op_true_leaf = lotus::v2::BranchLeaf(v2_op_true_script);
    const Amount cb_val = m_coinbase_txns[0]->vout[0].nValue;
    // This fixture mines V2 coinbases only. The legacy payment spends a legacy
    // coin: a legacy (version 2) coinbase paying a P2PKH key, matured before
    // the native funding enters the mempool.
    CKey legacy_key;
    legacy_key.MakeNewKey(true);
    const CScript legacy_spk =
        GetScriptForDestination(PKHash(legacy_key.GetPubKey()));
    CTransactionRef legacy_coinbase;
    for (int i = 0; i <= COINBASE_MATURITY; ++i) {
        node::BlockAssembler::Options options;
        options.coinbase_version = i == 0 ? 2 : 7;
        auto block =
            node::BlockAssembler{node::BlockFitter(config),
                                 m_node.chainman->ActiveChainstate(), nullptr,
                                 options}
                .CreateNewBlock(i == 0 ? CTxOut(Amount::zero(), legacy_spk)
                                       : V0LeafOutput(Amount::zero(),
                                                      CScript(program.begin(),
                                                              program.end())))
                ->block;
        while (!CheckProofOfWork(block.GetHash(), block.nBits,
                                 config.GetChainParams().GetConsensus())) {
            ++block.nNonce;
        }
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
            std::make_shared<const CBlock>(block), true, true, nullptr));
        if (i == 0) legacy_coinbase = block.vtx[0];
        SetMockTime(GetTime() + 1);
    }
    BOOST_REQUIRE(legacy_coinbase->vout[0].IsLegacy());

    const CMutableTransaction funding = CreateNativeMempoolTransaction(
        m_coinbase_txns[0], 0, cb_val - 2000 * SATOSHI);
    const CTransactionRef funding_tx = MakeTransactionRef(funding);
    CMutableTransaction legacy_mtx;
    legacy_mtx.nVersion = 2;
    legacy_mtx.vin.emplace_back(COutPoint(legacy_coinbase->GetId(), 0));
    legacy_mtx.vout.emplace_back(
        legacy_coinbase->vout[0].nValue - 2000 * SATOSHI,
        GetScriptForDestination(PKHash(legacy_key.GetPubKey())));
    {
        FillableSigningProvider keystore;
        BOOST_REQUIRE(keystore.AddKey(legacy_key));
        BOOST_REQUIRE(SignSignature(keystore, legacy_spk, legacy_mtx, 0,
                                    legacy_coinbase->vout[0].nValue,
                                    SigHashType().withForkId()));
    }
    const CTransactionRef legacy_tx = MakeTransactionRef(legacy_mtx);
    const std::string legacy_tx_hex = EncodeHexTx(*legacy_tx);

    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "testrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(legacy_tx_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK_MESSAGE(res.find_value("allowed").get_bool(), res.write());
        const UniValue &tx_res = res.find_value("results").get_array()[0];
        BOOST_CHECK(tx_res.find_value("allowed").get_bool());
    }

    // Confirm genuinely admitted native funding before evaluating the candidate.
    auto block =
        node::BlockAssembler(config, m_node.chainman->ActiveChainstate(),
                             m_node.mempool.get())
            .CreateNewBlock(V0LeafOutput(
                Amount::zero(), CScript(program.begin(), program.end())))
            ->block;
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 2U);
    BOOST_REQUIRE(block.vtx[1]->GetId() == funding_tx->GetId());
    while (!CheckProofOfWork(block.GetHash(), block.nBits,
                             config.GetChainParams().GetConsensus())) {
        ++block.nNonce;
    }
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
        std::make_shared<const CBlock>(block), true, true, nullptr));
    BOOST_REQUIRE(m_node.chainman->ActiveTip()->GetBlockHash() == block.GetHash());
    BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 0U);

    CMutableTransaction mtx;
    mtx.nVersion = 7;
    mtx.nV2Lock = 0;
    mtx.nLockTime = 0;
    CTxIn txin(COutPoint(funding_tx->GetId(), 0), CScript(), CTxIn::SEQUENCE_FINAL);
    txin.nFlags = 1;
    txin.nPathIndex = 0;
    lotus::v2::BranchWitness wit;
    wit.script = v2_op_true_script;
    txin.vWitnesses = {wit};
    mtx.vin.push_back(std::move(txin));
    lotus::v2::Output v2_out;
    v2_out.flags = 0;
    v2_out.value = static_cast<uint64_t>((funding.vout[0].nValue - 2000 * SATOSHI) / SATOSHI);
    v2_out.branches = {v2_op_true_leaf};
    v2_out.paths = {{0}};
    mtx.vout.push_back(CTxOut::FromV2Output(v2_out));
    CTransactionRef tx = MakeTransactionRef(mtx);
    const std::string tx_hex = EncodeHexTx(*tx);

    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "testrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(tx_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK(res.find_value("allowed").get_bool());
        const UniValue &tx_res = res.find_value("results").get_array()[0];
        const uint64_t req_cu = tx_res.find_value("required_cu").getInt<uint64_t>();
        const uint64_t req_fee = tx_res.find_value("required_fee_sats").getInt<uint64_t>();
        const uint64_t sdk_fee = tx_res.find_value("recommended_sdk_fee_sats").getInt<uint64_t>();
        BOOST_CHECK_GT(req_cu, 0ULL);
        BOOST_CHECK_EQUAL(req_fee, req_cu);
        BOOST_CHECK_GE(sdk_fee, req_fee);
    }

    // Raise RPC admission rate to 50,000 sats/kCU so 2,000 sats is insufficient at Tier 1.
    const int64_t now_ms = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    fee_ctrl.SetRpcAdmissionRatePerKCu(50000, now_ms);
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "testrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(tx_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK(!res.find_value("allowed").get_bool());
        const UniValue &tx_res = res.find_value("results").get_array()[0];
        BOOST_CHECK(!tx_res.find_value("allowed").get_bool());
        BOOST_CHECK_EQUAL(tx_res.find_value("reject-reason").get_str(),
                          "rpc-fee-hysteresis-insufficient");
        const uint64_t req_cu = tx_res.find_value("required_cu").getInt<uint64_t>();
        BOOST_CHECK_EQUAL(tx_res.find_value("required_fee_sats").getInt<uint64_t>(),
                          req_cu * 50ULL);
        BOOST_CHECK_EQUAL(tx_res.find_value("recommended_sdk_fee_sats").getInt<uint64_t>(),
                          (req_cu * 52500ULL + 999ULL) / 1000ULL);
    }
    fee_ctrl.Reset(now_ms);
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

BOOST_FIXTURE_TEST_CASE(UnifiedFeeEstimationRpcsUnderCongestion,
                        TestChain100Setup) {
    GlobalConfig config;
    auto &fee_ctrl = lotus::v2::GetGlobalFeeHysteresisController();
    const int64_t base_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    fee_ctrl.Reset(base_ms);

    auto call_rpc = [&](const std::string &method,
                        UniValue params = UniValue(UniValue::VARR)) {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = method;
        req.params = std::move(params);
        return tableRPC.execute(config, req);
    };

    // 1. At idle, estimatefee, estimatesmartfee("ECONOMICAL"), and getmempoolinfo
    // report 1,000 sats/kB, and estimatesmartfee("CONSERVATIVE") reports 1,050 sats/kB.
    {
        const UniValue info_res = call_rpc("getfeerateinfo");
        BOOST_CHECK_EQUAL(
            info_res.find_value("rpc_admission_feerate_per_kcu").getInt<uint64_t>(),
            1000ULL);
        BOOST_CHECK_EQUAL(
            info_res.find_value("recommended_sdk_feerate_per_kcu").getInt<uint64_t>(),
            1050ULL);

        const UniValue est_res = call_rpc("estimatefee");
        Amount est_amt;
        BOOST_CHECK(ParseMoney(est_res.getValStr(), est_amt));
        BOOST_CHECK_EQUAL(est_amt, 1000 * SATOSHI);

        const UniValue smart_cons = call_rpc("estimatesmartfee");
        BOOST_CHECK_EQUAL(
            smart_cons.find_value("feerate_sats_per_kb").getInt<uint64_t>(),
            1050ULL);
        BOOST_CHECK_EQUAL(
            smart_cons.find_value("rpc_admission_feerate_per_kcu").getInt<uint64_t>(),
            1000ULL);
        BOOST_CHECK_EQUAL(
            smart_cons.find_value("recommended_sdk_feerate_per_kcu").getInt<uint64_t>(),
            1050ULL);

        UniValue econ_params(UniValue::VARR);
        econ_params.push_back(1);
        econ_params.push_back("ECONOMICAL");
        const UniValue smart_econ =
            call_rpc("estimatesmartfee", std::move(econ_params));
        BOOST_CHECK_EQUAL(
            smart_econ.find_value("feerate_sats_per_kb").getInt<uint64_t>(),
            1000ULL);

        const UniValue mp_info = call_rpc("getmempoolinfo");
        Amount mp_min_amt;
        BOOST_CHECK(
            ParseMoney(mp_info.find_value("mempoolminfee").getValStr(), mp_min_amt));
        BOOST_CHECK_EQUAL(mp_min_amt, 1000 * SATOSHI);
        BOOST_CHECK_EQUAL(
            mp_info.find_value("rpc_admission_feerate_sats_per_kb").getInt<uint64_t>(),
            1000ULL);
        BOOST_CHECK_EQUAL(
            mp_info.find_value("recommended_feerate_sats_per_kb").getInt<uint64_t>(),
            1050ULL);
    }

    // 2. Simulate 1 GB block / high congestion where fees rise above 100,000 sats/kB.
    // All fee RPCs (getfeerateinfo, estimatefee, estimatesmartfee, getmempoolinfo)
    // must consistently return the elevated fee rate.
    const int64_t congested_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    const uint64_t congested_rpc_rate =
        fee_ctrl.UpdateCongestion(1'000'000'000ULL, 100'000'000ULL, congested_ms);
    BOOST_CHECK_EQUAL(congested_rpc_rate, 91'000ULL);
    const uint64_t high_rpc_rate =
        fee_ctrl.UpdateCongestion(1'000'000'000ULL, 80'000'000ULL, congested_ms);
    BOOST_CHECK_GT(high_rpc_rate, 100'000ULL);

    {
        const UniValue info_res = call_rpc("getfeerateinfo");
        const uint64_t expected_sdk_rate =
            info_res.find_value("recommended_sdk_feerate_per_kcu").getInt<uint64_t>();
        BOOST_CHECK_EQUAL(
            info_res.find_value("rpc_admission_feerate_per_kcu").getInt<uint64_t>(),
            high_rpc_rate);
        BOOST_CHECK_GT(expected_sdk_rate, high_rpc_rate);

        const UniValue est_res = call_rpc("estimatefee");
        Amount est_amt;
        BOOST_CHECK(ParseMoney(est_res.getValStr(), est_amt));
        BOOST_CHECK_EQUAL(est_amt,
                          static_cast<int64_t>(high_rpc_rate) * SATOSHI);

        const UniValue smart_cons = call_rpc("estimatesmartfee");
        BOOST_CHECK_EQUAL(
            smart_cons.find_value("feerate_sats_per_kb").getInt<uint64_t>(),
            expected_sdk_rate);

        UniValue econ_params(UniValue::VARR);
        econ_params.push_back(1);
        econ_params.push_back("ECONOMICAL");
        const UniValue smart_econ =
            call_rpc("estimatesmartfee", std::move(econ_params));
        BOOST_CHECK_EQUAL(
            smart_econ.find_value("feerate_sats_per_kb").getInt<uint64_t>(),
            high_rpc_rate);

        const UniValue mp_info = call_rpc("getmempoolinfo");
        Amount mp_min_amt;
        BOOST_CHECK(
            ParseMoney(mp_info.find_value("mempoolminfee").getValStr(), mp_min_amt));
        BOOST_CHECK_EQUAL(mp_min_amt,
                          static_cast<int64_t>(high_rpc_rate) * SATOSHI);
        BOOST_CHECK_EQUAL(
            mp_info.find_value("rpc_admission_feerate_sats_per_kb").getInt<uint64_t>(),
            high_rpc_rate);
        BOOST_CHECK_EQUAL(
            mp_info.find_value("recommended_feerate_sats_per_kb").getInt<uint64_t>(),
            expected_sdk_rate);
    }

    fee_ctrl.Reset(TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now()));
}


BOOST_FIXTURE_TEST_CASE(single_rpc_admission_attempt_under_congestion, TestChain100Setup) {
    auto &controller = lotus::v2::GetGlobalFeeHysteresisController();
    const auto now = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    controller.Reset(now);
    controller.SetRpcAdmissionRatePerKCu(9000, now);
    CMutableTransaction tx;
    tx.nVersion = 7;
    tx.nV2Lock = 0;
    const COutPoint funding(TxId(uint256S("123456")), 0);
    const std::vector<uint8_t> script{0x4e}; // Native VM OP_1.
    lotus::v2::Output output;
    output.flags = 0;
    output.value = 10 * COIN / SATOSHI;
    output.branches = {lotus::v2::BranchLeaf(script)};
    output.paths = {{0}};
    const CTxOut funding_output = CTxOut::FromV2Output(output);
    CTxIn input(funding, CScript(), CTxIn::SEQUENCE_FINAL);
    input.nFlags = 1;
    input.nPathIndex = 0;
    lotus::v2::BranchWitness witness;
    witness.script = script;
    input.vWitnesses = {witness};
    tx.vin.push_back(input);
    output.value -= 2000;
    tx.vout.push_back(CTxOut::FromV2Output(output));
    {
        LOCK(cs_main);
        m_node.chainman->ActiveChainstate().CoinsTip().AddCoin(
            funding, Coin(funding_output, 0, false), false);
    }
    JSONRPCRequest req;
    req.context = &m_node;
    req.strMethod = "sendrawtransaction";
    req.params = UniValue(UniValue::VARR);
    req.params.push_back(EncodeHexTx(CTransaction(tx)));
    const auto before = GetMempoolAdmissionAttempts();
    UniValue result;
    try {
        result = tableRPC.execute(m_node.chainman->GetConfig(), req);
    } catch (const UniValue &error) {
        controller.Reset(now);
        BOOST_FAIL(error.write());
    }
    BOOST_CHECK_EQUAL(result.get_str(), tx.GetId().ToString());
    BOOST_CHECK_EQUAL(GetMempoolAdmissionAttempts() - before, 1);
    BOOST_CHECK(m_node.mempool->exists(tx.GetId()));
    auto reject_without_insertion = [&](const char *id, Amount fee, bool cap_maximum) {
        // A successful admission can update local policy. Each rejection
        // scenario must establish its own congestion-rate precondition.
        controller.SetRpcAdmissionRatePerKCu(9000, now);
        BOOST_REQUIRE_EQUAL(controller.GetRpcAdmissionRatePerKCu(now), 9000);
        auto rejected = tx;
        rejected.vin[0].prevout = COutPoint(TxId(uint256S(id)), 0);
        lotus::v2::Output rejected_output = output;
        rejected_output.value = uint64_t((10 * COIN - fee) / SATOSHI);
        rejected.vout[0] = CTxOut::FromV2Output(rejected_output);
        {
            LOCK(cs_main);
            m_node.chainman->ActiveChainstate().CoinsTip().AddCoin(
                rejected.vin[0].prevout, Coin(funding_output, 0, false), false);
        }
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(EncodeHexTx(CTransaction(rejected)));
        if (cap_maximum) req.params.push_back(UniValue(UniValue::VNUM, "0.01"));
        const auto attempts = GetMempoolAdmissionAttempts();
        try {
            tableRPC.execute(m_node.chainman->GetConfig(), req);
            BOOST_ERROR("fee-constrained transaction unexpectedly admitted: " << id << " fee=" << fee / SATOSHI << " size=" << ::GetSerializeSize(CTransaction(rejected)) << " rate=" << controller.GetFeeRateInfo(now).rpc_admission_feerate_per_kcu);
        } catch (const UniValue &error) {
            if (cap_maximum) BOOST_CHECK_EQUAL(error.find_value("code").getInt<int>(), RPC_VERIFY_ERROR);
            else BOOST_CHECK(error.find_value("message").get_str().find("rpc-fee-hysteresis-insufficient") != std::string::npos);
        }
        BOOST_CHECK_EQUAL(GetMempoolAdmissionAttempts() - attempts, 1);
        BOOST_CHECK(!m_node.mempool->exists(rejected.GetId()));
    };
    reject_without_insertion("123457", 500 * SATOSHI, false);
    reject_without_insertion("123458", 2000 * SATOSHI, true);
    controller.Reset(now);
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

    // Legacy native records omitted the redundant cache size when pruned,
    // but retain nSize in the 134-byte header; decode the old layout exactly.
    index.nStatus = index.nStatus.withData(false);
    CDiskBlockIndex pruned(&index), old_pruned;
    DataStream old_pruned_bytes, prefix, encoded_size;
    old_pruned_bytes << pruned;
    int version = 320401;
    prefix << VARINT_MODE(version, VarIntMode::NONNEGATIVE_SIGNED)
           << pruned.nStatus << VARINT(pruned.nTx);
    encoded_size << VARINT(pruned.nSize);
    old_pruned_bytes.erase(old_pruned_bytes.begin() + prefix.size(),
                           old_pruned_bytes.begin() + prefix.size() + encoded_size.size());
    std::copy(old_tag.begin(), old_tag.end(), old_pruned_bytes.begin());
    old_pruned_bytes >> old_pruned;
    BOOST_CHECK_EQUAL(old_pruned.nSize, index.nSize);
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

BOOST_AUTO_TEST_CASE(adaptive_policy_native_capacity_hook) {
    GlobalConfig config;
    auto &controller = lotus::v2::GetGlobalFeeHysteresisController();
    controller.Reset(0);
    BOOST_CHECK_EQUAL(config.GetMaxBlockSize(), DEFAULT_MAX_BLOCK_SIZE);
    controller.RecordConnectedBlock(64'000'000, 1000);
    BOOST_CHECK_GT(controller.GetAdaptiveMaxBlockSize(), DEFAULT_MAX_BLOCK_SIZE);
    // This is a V2-only consensus/config hook. The shared eCash owner tests
    // the opposite invariant: local adaptive policy never expands ABC validity.
    BOOST_CHECK_EQUAL(config.GetMaxBlockSize(), controller.GetAdaptiveMaxBlockSize());
    BOOST_CHECK_EQUAL(lotus::v2::GetBlockPayloadLimit(config),
                      config.GetMaxBlockSize() + 256 * 1024);
    controller.Reset(0);
    BOOST_CHECK_EQUAL(config.GetMaxBlockSize(), DEFAULT_MAX_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(native_adaptive_validity_limit_respects_explicit_block_bound) {
    GlobalConfig config;
    auto &controller = lotus::v2::GetGlobalFeeHysteresisController();
    controller.Reset(0);
    // G capacity follows connected block history, not a synthetic backlog.
    controller.RecordConnectedBlock(64'000'000, 1000);
    BOOST_CHECK_GT(controller.GetAdaptiveMaxBlockSize(), DEFAULT_MAX_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(config.GetMaxBlockSize(), controller.GetAdaptiveMaxBlockSize());
    // Native consensus follows the adaptive configuration, while an explicit
    // validation bound still rejects a header claiming a larger block.
    CBlock block;
    block.nHeaderVersion = lotus::v2::kHeaderVersion;
    block.nBits = 0x207fffff;
    block.nSize = DEFAULT_MAX_BLOCK_SIZE + 1;
    BlockValidationState state;
    const BlockValidationOptions options(DEFAULT_MAX_BLOCK_SIZE, false, false);
    BOOST_CHECK(!CheckBlock(block, state, config.GetChainParams().GetConsensus(), options));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-size");
    controller.Reset(0);
}

BOOST_AUTO_TEST_SUITE_END()
