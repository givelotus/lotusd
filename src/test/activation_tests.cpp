// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockindex.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/activation.h>
#include <key.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <util/string.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

static void SetMTP(std::array<CBlockIndex, 12> &blocks, int64_t mtp) {
    size_t len = blocks.size();

    for (size_t i = 0; i < len; ++i) {
        blocks[i].nTime = mtp + (i - (len / 2));
    }

    BOOST_CHECK_EQUAL(blocks.back().GetMedianTimePast(), mtp);
}

BOOST_AUTO_TEST_CASE(isexodusenabled) {
    const Consensus::Params &params = Params().GetConsensus();
    const auto activation =
        gArgs.GetIntArg("-exodusactivationtime", params.exodusActivationTime);
    SetMockTime(activation - 1000000);

    BOOST_CHECK(!IsExodusEnabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    BOOST_CHECK(!IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsExodusEnabled(params, &blocks.back()));
}

BOOST_AUTO_TEST_CASE(is_leviticus_enabled) {
    const Consensus::Params &params = Params().GetConsensus();
    const auto activation =
        gArgs.GetIntArg("-leviticusactivationtime", params.leviticusActivationTime);
    SetMockTime(activation - 1000000);

    BOOST_CHECK(!IsLeviticusEnabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    BOOST_CHECK(!IsLeviticusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsLeviticusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsLeviticusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsLeviticusEnabled(params, &blocks.back()));
}

BOOST_AUTO_TEST_CASE(is_numbers_enabled) {
    const Consensus::Params &params = Params().GetConsensus();
    const auto activation =
        gArgs.GetIntArg("-numbersactivationtime", params.numbersActivationTime);
    SetMockTime(activation - 1000000);

    BOOST_CHECK(!IsNumbersEnabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    BOOST_CHECK(!IsNumbersEnabled(params, &blocks.back()));
    BOOST_CHECK_EQUAL(
        IsNumbersEnabled(params, &blocks.back()),
        IsNumbersEnabled(params, blocks.back().GetMedianTimePast()));

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsNumbersEnabled(params, &blocks.back()));
    BOOST_CHECK_EQUAL(
        IsNumbersEnabled(params, &blocks.back()),
        IsNumbersEnabled(params, blocks.back().GetMedianTimePast()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsNumbersEnabled(params, &blocks.back()));
    BOOST_CHECK_EQUAL(
        IsNumbersEnabled(params, &blocks.back()),
        IsNumbersEnabled(params, blocks.back().GetMedianTimePast()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsNumbersEnabled(params, &blocks.back()));
    BOOST_CHECK_EQUAL(
        IsNumbersEnabled(params, &blocks.back()),
        IsNumbersEnabled(params, blocks.back().GetMedianTimePast()));
}

BOOST_AUTO_TEST_CASE(is_second_kings_enabled) {
    const Consensus::Params &params = Params().GetConsensus();
    // 2026-12-21T20:50:00Z, the same on regtest as on mainnet.
    const int64_t activation = 1797886200;
    BOOST_CHECK_EQUAL(params.secondKingsActivationTime, activation);

    BOOST_CHECK(!IsSecondKingsEnabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsSecondKingsEnabled(params, &blocks.back()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsSecondKingsEnabled(params, &blocks.back()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsSecondKingsEnabled(params, &blocks.back()));

    // -secondkingsactivationtime overrides the time.
    gArgs.ForceSetArg("-secondkingsactivationtime", util::ToString(activation + 2));
    BOOST_CHECK(!IsSecondKingsEnabled(params, &blocks.back()));
    SetMTP(blocks, activation + 2);
    BOOST_CHECK(IsSecondKingsEnabled(params, &blocks.back()));
    gArgs.ClearForcedArg("-secondkingsactivationtime");
}

// Replay protection is enabled at the 2nd Kings upgrade,
// 2026-12-21T20:50:00Z.
static constexpr int64_t SECOND_KINGS_TIME = 1797886200;
static constexpr int64_t FIRST_CHRONICLES_TIME = 1813587000;
static constexpr int64_t TESTNET_OFFSET = 21 * 24 * 3600;

BOOST_AUTO_TEST_CASE(replay_protection_activation_times) {
    const ArgsManager args{};
    const auto main = CreateChainParams(args, ChainType::MAIN);
    const auto test = CreateChainParams(args, ChainType::TESTNET);
    const auto reg = CreateChainParams(args, ChainType::REGTEST);

    BOOST_CHECK_EQUAL(main->GetConsensus().secondKingsActivationTime,
                      SECOND_KINGS_TIME);
    BOOST_CHECK_EQUAL(test->GetConsensus().secondKingsActivationTime,
                      SECOND_KINGS_TIME - TESTNET_OFFSET);
    BOOST_CHECK_EQUAL(reg->GetConsensus().secondKingsActivationTime,
                      SECOND_KINGS_TIME);
    BOOST_CHECK_EQUAL(main->GetConsensus().firstChroniclesActivationTime,
                      FIRST_CHRONICLES_TIME);
    BOOST_CHECK_EQUAL(test->GetConsensus().firstChroniclesActivationTime,
                      FIRST_CHRONICLES_TIME - TESTNET_OFFSET);
    BOOST_CHECK_EQUAL(reg->GetConsensus().firstChroniclesActivationTime,
                      FIRST_CHRONICLES_TIME);
}

namespace {
struct ReplayProtectionSetup : public TestChain100Setup {
    const CScript coinbaseScript = CScript()
                                   << ToByteVector(coinbaseKey.GetPubKey())
                                   << OP_CHECKSIG;
    size_t nextCoinbase = 0;

    int64_t TipMedianTimePast() {
        LOCK(cs_main);
        return m_node.chainman->ActiveTip()->GetMedianTimePast();
    }

    // Mine empty blocks until the tip's median time past reaches mtp, so the
    // next block and the mempool use the script flags in force at mtp. The
    // mock time is set for each block because mineBlocks() moves it one
    // second ahead; otherwise the blocks carry later times and the next block
    // mined can take the median time past beyond mtp.
    void MineUntilMedianTimePast(int64_t mtp) {
        while (TipMedianTimePast() < mtp) {
            SetMockTime(mtp);
            mineBlocks(1);
        }
    }

    // Spend the next mature coinbase output paying coinbaseKey. When
    // replayProtected is set, sign over the replay-protected fork value.
    CMutableTransaction Spend(bool replayProtected) {
        const CTransactionRef coinbase = m_coinbase_txns.at(nextCoinbase++);
        uint32_t n = 0;
        while (coinbase->vout.at(n).scriptPubKey != coinbaseScript) {
            ++n;
        }
        const Amount amount = coinbase->vout[n].nValue;

        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint(coinbase->GetId(), n));
        tx.vout.emplace_back(amount - 10000 * SATOSHI, coinbaseScript);

        const SigHashType sigHashType = SigHashType().withForkId();
        uint32_t flags = SCRIPT_ENABLE_SIGHASH_FORKID;
        if (replayProtected) {
            flags |= SCRIPT_ENABLE_REPLAY_PROTECTION;
        }
        uint256 hash;
        BOOST_REQUIRE(SignatureHash(hash, std::nullopt, coinbaseScript,
                                    CTransaction(tx), 0, sigHashType, amount,
                                    nullptr, flags));
        std::vector<uint8_t> sig;
        BOOST_REQUIRE(coinbaseKey.SignSchnorr(hash, sig));
        sig.push_back(uint8_t(sigHashType.getRawSigHashType()));
        tx.vin[0].scriptSig = CScript() << sig;
        return tx;
    }

    MempoolAcceptResult Submit(const CMutableTransaction &tx) {
        LOCK(cs_main);
        return m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
    }

    bool IsMandatoryScriptFailure(const MempoolAcceptResult &result) {
        return result.m_result_type ==
                   MempoolAcceptResult::ResultType::INVALID &&
               result.m_state.GetRejectReason().rfind(
                   "mandatory-script-verify-flag-failed", 0) == 0;
    }

    // Mine tx in a block and report whether the block became the tip.
    bool Confirm(const CMutableTransaction &tx) {
        const CBlock block = CreateAndProcessBlock({tx}, coinbaseScript);
        LOCK(cs_main);
        return m_node.chainman->ActiveTip()->GetBlockHash() ==
               block.GetHash();
    }
};
} // namespace

// Regtest uses the mainnet activation time, and no
// -replayprotectionactivationtime override is set, so this exercises the
// default schedule used by mainnet nodes.
BOOST_FIXTURE_TEST_CASE(replay_protection_follows_schedule,
                        ReplayProtectionSetup) {
    const int64_t activation =
        m_node.chainman->GetConsensus().secondKingsActivationTime;
    BOOST_CHECK_EQUAL(activation, SECOND_KINGS_TIME);

    // Until 2nd Kings, ordinary ForkID signatures are the only valid ones.
    MineUntilMedianTimePast(activation - 1);
    BOOST_CHECK_EQUAL(TipMedianTimePast(), activation - 1);
    const CMutableTransaction ordinary = Spend(false);
    BOOST_CHECK(Submit(ordinary).m_result_type ==
                MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(Confirm(ordinary));
    BOOST_CHECK_EQUAL(TipMedianTimePast(), activation - 1);
    BOOST_CHECK(IsMandatoryScriptFailure(Submit(Spend(true))));

    // From 2nd Kings, the replay-protected fork value is required.
    MineUntilMedianTimePast(activation);
    BOOST_CHECK_EQUAL(TipMedianTimePast(), activation);
    BOOST_CHECK(IsMandatoryScriptFailure(Submit(Spend(false))));
    const CMutableTransaction protectedSpend = Spend(true);
    BOOST_CHECK(Submit(protectedSpend).m_result_type ==
                MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(Confirm(protectedSpend));
}

// The mainnet upgrade times of the Lotus V1 network, as run by
// LotusiaStewardship/lotusd.
BOOST_AUTO_TEST_CASE(mainnet_activation_times) {
    const ArgsManager args{};
    const auto main = CreateChainParams(args, ChainType::MAIN);
    const Consensus::Params &c = main->GetConsensus();
    BOOST_CHECK_EQUAL(c.exodusActivationTime, 1640102340);
    BOOST_CHECK_EQUAL(c.leviticusActivationTime, 1655802840);
    BOOST_CHECK_EQUAL(c.numbersActivationTime, 1671659280);
    BOOST_CHECK_EQUAL(c.deuteronomyActivationTime, 1687359480);
    BOOST_CHECK_EQUAL(c.joshuaActivationTime, 1703215620);
    // 2024-06-20T20:51:00Z
    BOOST_CHECK_EQUAL(c.judgesActivationTime, 1718916660);
    BOOST_CHECK_EQUAL(c.ruthActivationTime, 1734772800);
    BOOST_CHECK_EQUAL(c.firstSamuelActivationTime, 1750473720);
    BOOST_CHECK_EQUAL(c.secondSamuelActivationTime, 1766329380);
    BOOST_CHECK_EQUAL(c.firstKingsActivationTime, 1782030240);
    BOOST_CHECK_EQUAL(c.secondKingsActivationTime, 1797886200);
    BOOST_CHECK_EQUAL(c.firstChroniclesActivationTime, 1813587000);
}

BOOST_AUTO_TEST_SUITE_END()
