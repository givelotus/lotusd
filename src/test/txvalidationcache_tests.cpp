// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <config.h>
#include <consensus/validation.h>
#include <consensus/consensus.h>
#include <key.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/signing.h>
#include <algorithm>
#include <array>
#include <future>
#include <policy/policy.h>
#include <script/scriptcache.h>
#include <script/sighashtype.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <txmempool.h>
#include <validation.h>

#include <test/lcg.h>
#include <test/sigutil.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

struct NativeValidationCacheSetup : TestChain100Setup {
    CScript program;

    NativeValidationCacheSetup() {
        const auto public_key = coinbaseKey.GetPubKey();
        std::vector<uint8_t> bytes{0x20};
        bytes.insert(bytes.end(), public_key.begin() + 1, public_key.end());
        bytes.push_back(0xbb); // Native BIP340 CHECKSIG.
        program = CScript(bytes.begin(), bytes.end());
        m_coinbase_txns.clear();
        // Native spends need V2 coinbases; this fixture mines legacy ones by
        // default.
        m_coinbase_version = 7;
        for (int i = 0; i < COINBASE_MATURITY; ++i) {
            const auto block = CreateAndProcessBlock({}, program);
            BOOST_REQUIRE(m_node.chainman->ActiveTip()->GetBlockHash() == block.GetHash());
            m_coinbase_txns.push_back(block.vtx[0]);
        }
    }

    CMutableTransaction NativeSpend(
        const std::vector<std::pair<CTransactionRef, uint32_t>> &previous,
        const std::vector<Amount> &values) {
        using namespace lotus::v2;
        CMutableTransaction tx;
        tx.nVersion = 7;
        tx.fHasV2Lock = true;
        ResolvedCoins resolved;
        for (const auto &[parent, index] : previous) {
            CTxIn input(COutPoint(parent->GetId(), index));
            input.nFlags = 1;
            input.nPathIndex = 0;
            BranchWitness witness;
            witness.script.assign(program.begin(), program.end());
            input.vWitnesses = {witness};
            tx.vin.push_back(std::move(input));
            resolved.emplace_back(parent->vout[index].ToV2Output());
        }
        for (Amount value : values) {
            Output output;
            output.value = value / SATOSHI;
            output.branches = {BranchLeaf(std::span<const uint8_t>(program.data(), program.size()))};
            output.paths = {{0}};
            tx.vout.push_back(CTxOut::FromV2Output(output));
        }
        PreparedSigningContext prepared;
        std::string error;
        BOOST_REQUIRE_MESSAGE(PrepareSigningContext(
            tx.ToV2Transaction(), DefaultTxProfile, GetActiveV2ChainId(),
            resolved, prepared, error), error);
        std::array<uint8_t, 32> secret{}, aux{};
        std::copy(coinbaseKey.begin(), coinbaseKey.end(), secret.begin());
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            lotus::v2::Hash message{};
            BOOST_REQUIRE_MESSAGE(SigningMessage(
                prepared, i, 0, 0, std::nullopt, message, error), error);
            std::vector<uint8_t> signature;
            BOOST_REQUIRE_MESSAGE(SignBip340Message(
                secret, message, 0, aux, signature, error), error);
            tx.vin[i].vWitnesses[0].arguments = {std::move(signature)};
        }
        return tx;
    }
};

BOOST_AUTO_TEST_SUITE(txvalidationcache_tests)

BOOST_FIXTURE_TEST_CASE(native_advisory_precompute_avoids_locks, TestingSetup) {
    // An invalid native transaction is sufficient: advisory staging must leave
    // its verdict to the unchanged authoritative admission path.
    CMutableTransaction native_mtx;
    native_mtx.nVersion = 7;
    native_mtx.nV2Lock = 0;
    const std::vector<uint8_t> script{0x4e}; // Native OP_1.
    CTxIn input(COutPoint(TxId(uint256S("123456")), 0));
    input.nFlags = 1;
    lotus::v2::BranchWitness witness;
    witness.script = script;
    input.vWitnesses = {witness};
    native_mtx.vin.push_back(std::move(input));
    lotus::v2::Output output;
    output.value = 1;
    output.branches = {lotus::v2::BranchLeaf(script)};
    output.paths = {{0}};
    native_mtx.vout.push_back(CTxOut::FromV2Output(output));
    const auto tx = MakeTransactionRef(native_mtx);
    const auto check_default = [](const PrecomputedAdmissionChecks &checks) {
        BOOST_CHECK(checks.txid.IsNull());
        BOOST_CHECK(checks.spent_outputs.empty());
        BOOST_CHECK(!checks.regular_tx_checked);
        BOOST_CHECK(!checks.standard.ran);
        BOOST_CHECK(!checks.consensus.ran);
    };
    const auto check_without_lock = [&](auto &mutex) {
        std::promise<void> started;
        std::future<PrecomputedAdmissionChecks> result;
        {
            LOCK(mutex);
            result = std::async(std::launch::async, [&] {
                started.set_value();
                return PrecomputeMempoolAdmission(*m_node.chainman, tx, {});
            });
            started.get_future().wait();
            BOOST_CHECK(result.wait_for(std::chrono::seconds{1}) ==
                        std::future_status::ready);
        }
        check_default(result.get());
    };
    check_without_lock(cs_main);
    check_without_lock(m_node.mempool->cs);

    // A native-only batch must reach the unlocked phase without first waiting
    // for cs_main. Phase C must still take the lock and reject both transactions.
    std::promise<void> between;
    std::future<std::vector<std::optional<MempoolAcceptResult>>> staged;
    StagedAdmissionStats stats;
    {
        LOCK(cs_main);
        StagedAdmissionOptions options;
        options.test_between_phases = [&] { between.set_value(); };
        staged = std::async(std::launch::async, [&, options] {
            return AcceptToMemoryPoolStaged(*m_node.chainman, {tx, tx}, options,
                                            &stats);
        });
        BOOST_CHECK(between.get_future().wait_for(std::chrono::seconds{1}) ==
                    std::future_status::ready);
    }
    const auto results = staged.get();
    BOOST_REQUIRE_EQUAL(results.size(), 2U);
    BOOST_CHECK_EQUAL(stats.precomputed, 0U);
    for (const auto &result : results) {
        BOOST_REQUIRE(result.has_value());
        BOOST_CHECK(result->m_result_type != MempoolAcceptResult::ResultType::VALID);
    }
    // Mixed legacy/native staging must retain authoritative rejection as well.
    CMutableTransaction legacy_mtx;
    legacy_mtx.nVersion = 2;
    const auto mixed = AcceptToMemoryPoolStaged(*m_node.chainman,
        {MakeTransactionRef(legacy_mtx), tx}, {}, nullptr);
    BOOST_REQUIRE_EQUAL(mixed.size(), 2U);
    for (const auto &result : mixed) {
        BOOST_REQUIRE(result.has_value());
        BOOST_CHECK(result->m_result_type != MempoolAcceptResult::ResultType::VALID);
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, NativeValidationCacheSetup) {
    // Make sure skipping validation of transactions that were validated going
    // into the memory pool does not allow double-spends in blocks to pass
    // validation when they should not.
    const CScript scriptPubKey = program;

    const auto ToMemPool = [this](const CMutableTransaction &tx) {
        LOCK(cs_main);

        const MempoolAcceptResult result =
            m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
        return result.m_result_type == MempoolAcceptResult::ResultType::VALID;
    };

    // Create a double-spend of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++) {
        spends[i] = NativeSpend({{m_coinbase_txns[0], 0}},
                                {11 * CENT + i * SATOSHI});
    }
    BOOST_REQUIRE(spends[0].GetId() != spends[1].GetId());
    BOOST_REQUIRE(spends[0].vin[0].prevout == spends[1].vin[0].prevout);

    CBlock block;

    // Test 1: block with both of those transactions should be rejected.
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveTip()->GetBlockHash() !=
                    block.GetHash());
    }

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveTip()->GetBlockHash() !=
                    block.GetHash());
    }
    m_node.mempool->clear();

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveTip()->GetBlockHash() !=
                    block.GetHash());
    }
    m_node.mempool->clear();

    // Final sanity test: first spend in mempool, second in block, that's OK:
    std::vector<CMutableTransaction> oneSpend;
    oneSpend.push_back(spends[0]);
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(oneSpend, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveTip()->GetBlockHash() ==
                    block.GetHash());
    }
    // spends[1] should have been removed from the mempool when the block with
    // spends[0] is accepted:
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}

static inline bool
CheckInputScripts(const CTransaction &tx, TxValidationState &state,
                  const CCoinsViewCache &view, const uint32_t flags,
                  bool sigCacheStore, bool scriptCacheStore,
                  const PrecomputedTransactionData &txdata,
                  ValidationCache &validation_cache, int &nSigChecksOut,
                  std::vector<CScriptCheck> *pvChecks,
                  CheckInputsLimiter *pBlockLimitSigChecks = nullptr)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    // nSigChecksTxLimiter need to outlive this function call, because test
    // cases are using pvChecks, so the verification is done asynchronously.
    static TxSigCheckLimiter nSigChecksTxLimiter;
    nSigChecksTxLimiter = TxSigCheckLimiter();
    return CheckInputScripts(tx, state, view, flags, sigCacheStore,
                             scriptCacheStore, txdata, validation_cache,
                             nSigChecksOut, nSigChecksTxLimiter,
                             pBlockLimitSigChecks, pvChecks);
}

// Run CheckInputScripts (using CoinsTip()) on the given transaction, for all
// script flags. Test that CheckInputScripts passes for all flags that don't
// overlap with the failing_flags argument, but otherwise fails.
// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY (and future NOP codes that may
// get reassigned) have an interaction with DISCOURAGE_UPGRADABLE_NOPS: if the
// script flags used contain DISCOURAGE_UPGRADABLE_NOPS but don't contain
// CHECKLOCKTIMEVERIFY (or CHECKSEQUENCEVERIFY), but the script does contain
// OP_CHECKLOCKTIMEVERIFY (or OP_CHECKSEQUENCEVERIFY), then script execution
// should fail.
// Capture this interaction with the upgraded_nop argument: set it when
// evaluating any script flag that is implemented as an upgraded NOP code.
static void ValidateCheckInputsForAllFlags(
    const CTransaction &tx, uint32_t failing_flags, uint32_t required_flags,
    bool add_to_cache, CCoinsViewCache &active_coins_tip,
    ValidationCache &validation_cache, int expected_sigchecks)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    PrecomputedTransactionData txdata(tx);

    MMIXLinearCongruentialGenerator lcg;
    for (int i = 0; i < 4096; i++) {
        uint32_t test_flags = lcg.next() | required_flags;
        TxValidationState state;

        // Filter out incompatible flag choices
        if ((test_flags & SCRIPT_VERIFY_CLEANSTACK)) {
            // CLEANSTACK requires P2SH, see VerifyScript() in
            // script/interpreter.cpp
            test_flags |= SCRIPT_VERIFY_P2SH;
        }

        int nSigChecksDirect = 0xf00d;
        bool ret = CheckInputScripts(tx, state, &active_coins_tip, test_flags,
                                     true, add_to_cache, txdata,
                                     validation_cache, nSigChecksDirect);

        // CheckInputScripts should succeed iff test_flags doesn't intersect
        // with failing_flags
        bool expected_return_value = !(test_flags & failing_flags);
        BOOST_CHECK_EQUAL(ret, expected_return_value);

        if (ret) {
            BOOST_CHECK(nSigChecksDirect == expected_sigchecks);
        }

        // Test the caching
        if (ret && add_to_cache) {
            // Check that we get a cache hit if the tx was valid
            std::vector<CScriptCheck> scriptchecks;
            int nSigChecksCached = 0xbeef;
            BOOST_CHECK(CheckInputScripts(
                tx, state, &active_coins_tip, test_flags, true, add_to_cache,
                txdata, validation_cache, nSigChecksCached, &scriptchecks));
            BOOST_CHECK(nSigChecksCached == nSigChecksDirect);
            BOOST_CHECK(scriptchecks.empty());
        } else {
            // Check that we get script executions to check, if the transaction
            // was invalid, or we didn't add to cache.
            std::vector<CScriptCheck> scriptchecks;
            int nSigChecksUncached = 0xbabe;
            BOOST_CHECK(CheckInputScripts(
                tx, state, &active_coins_tip, test_flags, true, add_to_cache,
                txdata, validation_cache, nSigChecksUncached, &scriptchecks));
            BOOST_CHECK(!ret || nSigChecksUncached == 0);
            BOOST_CHECK_EQUAL(scriptchecks.size(), tx.vin.size());
        }
    }
}

BOOST_FIXTURE_TEST_CASE(native_bip340_execution_cache,
                        NativeValidationCacheSetup) {
    const auto funding_mtx = NativeSpend({{m_coinbase_txns[0], 0}},
                                         {20 * COIN, 20 * COIN});
    const auto funding = MakeTransactionRef(funding_mtx);
    {
        LOCK(cs_main);
        const auto accepted = m_node.chainman->ProcessTransaction(funding);
        BOOST_REQUIRE_MESSAGE(
            accepted.m_result_type == MempoolAcceptResult::ResultType::VALID,
            accepted.m_state.ToString());
    }
    const auto block = CreateAndProcessBlock({funding_mtx}, program);
    LOCK(cs_main);
    BOOST_REQUIRE(m_node.chainman->ActiveTip()->GetBlockHash() == block.GetHash());
    auto &view = m_node.chainman->ActiveChainstate().CoinsTip();
    BOOST_REQUIRE(view.GetBestBlock() == block.GetHash());
    BOOST_REQUIRE(view.HaveCoin(COutPoint(funding->GetId(), 0)));
    BOOST_REQUIRE(view.HaveCoin(COutPoint(funding->GetId(), 1)));

    const auto good_mtx = NativeSpend({{funding, 0}, {funding, 1}}, {39 * COIN});
    const CTransaction good(good_mtx);
    const PrecomputedTransactionData good_data(good);
    auto &cache = m_node.chainman->m_validation_cache;
    const uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_ENABLE_SIGHASH_FORKID;
    TxValidationState state;
    int checked_sigchecks;
    std::vector<CScriptCheck> cold;
    BOOST_REQUIRE(CheckInputScripts(good, state, view, flags, true, false,
                                     good_data, cache, checked_sigchecks, &cold));
    BOOST_REQUIRE_EQUAL(cold.size(), 2U);
    for (auto &check : cold) BOOST_REQUIRE(!check().has_value());

    // Deferred execution alone does not populate the whole-transaction cache.
    std::vector<CScriptCheck> still_cold;
    BOOST_REQUIRE(CheckInputScripts(good, state, view, flags, true, false,
                                     good_data, cache, checked_sigchecks,
                                     &still_cold));
    BOOST_REQUIRE_EQUAL(still_cold.size(), 2U);
    BOOST_REQUIRE(CheckInputScripts(good, state, view, flags, true, true,
                                     good_data, cache, checked_sigchecks, nullptr));
    const int stored_sigchecks = checked_sigchecks;
    std::vector<CScriptCheck> hit;
    BOOST_REQUIRE(CheckInputScripts(good, state, view, flags, true, true,
                                     good_data, cache, checked_sigchecks, &hit));
    BOOST_CHECK(hit.empty());
    BOOST_CHECK_EQUAL(checked_sigchecks, stored_sigchecks);

    // Flag identity is part of the cache key, even for native VM inputs.
    std::vector<CScriptCheck> other_flags;
    BOOST_REQUIRE(CheckInputScripts(good, state, view,
                                     flags | SCRIPT_VERIFY_NULLFAIL, true, true,
                                     good_data, cache, checked_sigchecks,
                                     &other_flags));
    BOOST_REQUIRE_EQUAL(other_flags.size(), 2U);
    for (auto &check : other_flags) BOOST_REQUIRE(!check().has_value());

    auto invalid_mtx = good_mtx;
    invalid_mtx.vin[1].vWitnesses[0].arguments[0][10] ^= 1;
    const CTransaction invalid(invalid_mtx);
    BOOST_REQUIRE(invalid.GetHash() != good.GetHash());
    const PrecomputedTransactionData invalid_data(invalid);
    std::vector<CScriptCheck> invalid_checks;
    BOOST_REQUIRE(CheckInputScripts(invalid, state, view, flags, true, true,
                                     invalid_data, cache, checked_sigchecks,
                                     &invalid_checks));
    BOOST_REQUIRE_EQUAL(invalid_checks.size(), 2U);
    BOOST_REQUIRE(!invalid_checks[0]().has_value());
    const auto invalid_result = invalid_checks[1]();
    BOOST_REQUIRE(invalid_result.has_value());
    BOOST_CHECK(invalid_result->first == ScriptError::EVAL_FALSE);

    TxValidationState invalid_state;
    BOOST_CHECK(!CheckInputScripts(invalid, invalid_state, view, flags, true, true,
                                   invalid_data, cache, checked_sigchecks, nullptr));
    BOOST_CHECK(invalid_state.GetResult() == TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(invalid_state.GetRejectReason(),
        "mandatory-script-verify-flag-failed (Script evaluated without error but "
        "finished with a false/empty top stack element)");
    std::vector<CScriptCheck> not_cached;
    BOOST_REQUIRE(CheckInputScripts(invalid, state, view, flags, true, true,
                                     invalid_data, cache, checked_sigchecks,
                                     &not_cached));
    BOOST_CHECK_EQUAL(not_cached.size(), 2U);
    std::vector<CScriptCheck> good_still_cached;
    BOOST_REQUIRE(CheckInputScripts(good, state, view, flags, true, true,
                                     good_data, cache, checked_sigchecks,
                                     &good_still_cached));
    BOOST_CHECK(good_still_cached.empty());

    // This covers BIP340 VM execution caching, not an individual-signature
    // cache: the native VM does not use the legacy SignatureCache path.
    const auto accepted = m_node.chainman->ProcessTransaction(MakeTransactionRef(good_mtx));
    BOOST_REQUIRE_MESSAGE(
        accepted.m_result_type == MempoolAcceptResult::ResultType::VALID,
        accepted.m_state.ToString());
}

BOOST_FIXTURE_TEST_CASE(checkinputs_test, TestChain100Setup) {
    // Test that passing CheckInputScripts with one set of script flags doesn't
    // imply that we would pass again with a different set of flags.
    CScript p2pk_scriptPubKey =
        CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CScript p2sh_scriptPubKey =
        GetScriptForDestination(ScriptHash(p2pk_scriptPubKey));
    CScript p2pkh_scriptPubKey =
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(coinbaseKey));
    BOOST_CHECK(keystore.AddCScript(p2pk_scriptPubKey));

    // These are explicit legacy interpreter/cache vectors, not native-chain
    // transactions. Their Coins live only in this isolated white-box view.
    CCoinsView legacy_base;
    CCoinsViewCache legacy_coins(&legacy_base);
    CMutableTransaction legacy_coinbase(*m_coinbase_txns[0]);
    legacy_coinbase.nVersion = 1;
    legacy_coinbase.vout[0] = CTxOut(50 * COIN, p2pk_scriptPubKey);
    const auto legacy_parent = MakeTransactionRef(legacy_coinbase);
    BOOST_REQUIRE(legacy_parent->GetId() != m_coinbase_txns[0]->GetId());
    AddCoins(legacy_coins, *legacy_parent, 1);

    CMutableTransaction funding_tx;
    // Needed when spending the output of this transaction
    CScript noppyScriptPubKey;
    // Create a transaction output that can fail DISCOURAGE_UPGRADABLE_NOPS
    // checks when spent. This is for testing consensus vs non-standard rules in
    // `checkinputs_test`.
    {
        funding_tx.nVersion = 1;
        funding_tx.vin.resize(1);
        funding_tx.vin[0].prevout = COutPoint(legacy_parent->GetId(), 0);
        funding_tx.vout.resize(1);
        funding_tx.vout[0].nValue = 50 * COIN;

        noppyScriptPubKey << OP_IF << OP_NOP10 << OP_ENDIF << OP_1;
        funding_tx.vout[0].scriptPubKey = noppyScriptPubKey;
        std::vector<uint8_t> fundingVchSig;
        uint256 fundingSigHash = SignatureHash(
            p2pk_scriptPubKey, CTransaction(funding_tx), 0,
            SigHashType().withForkId(), m_coinbase_txns[0]->vout[0].nValue);
        BOOST_CHECK(coinbaseKey.SignECDSA(fundingSigHash, fundingVchSig));
        fundingVchSig.push_back(uint8_t(SIGHASH_ALL | SIGHASH_FORKID));
        funding_tx.vin[0].scriptSig << fundingVchSig;
    }

    // Verify legacy signatures directly, then populate only the synthetic view.
    {
        LOCK(cs_main);
        const CTransaction funding(funding_tx);
        PrecomputedTransactionData data(funding);
        TxValidationState state;
        int sigchecks;
        BOOST_REQUIRE(CheckInputScripts(
            funding, state, legacy_coins, SCRIPT_ENABLE_SIGHASH_FORKID,
            true, false, data, m_node.chainman->m_validation_cache,
            sigchecks, nullptr));
        BOOST_REQUIRE(legacy_coins.SpendCoin(funding_tx.vin[0].prevout));
        AddCoins(legacy_coins, funding, 101);
        BOOST_REQUIRE(legacy_coins.HaveCoin(COutPoint(funding.GetId(), 0)));
        BOOST_REQUIRE(!m_node.chainman->ActiveChainstate().CoinsTip().HaveCoin(
            COutPoint(funding.GetId(), 0)));
    }

    // flags to test: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    // SCRIPT_VERIFY_CHECKSEQUENCE_VERIFY,
    // SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, uncompressed pubkey thing

    // Create 2 outputs that match the three scripts above, spending the first
    // coinbase tx.
    CMutableTransaction spend_tx;
    spend_tx.nVersion = 1;
    spend_tx.vin.resize(1);
    spend_tx.vin[0].prevout = COutPoint(funding_tx.GetId(), 0);
    spend_tx.vout.resize(4);
    spend_tx.vout[0].nValue = 11 * CENT;
    spend_tx.vout[0].scriptPubKey = p2sh_scriptPubKey;
    spend_tx.vout[1].nValue = 11 * CENT;
    spend_tx.vout[1].scriptPubKey =
        CScript() << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                  << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    spend_tx.vout[2].nValue = 11 * CENT;
    spend_tx.vout[2].scriptPubKey =
        CScript() << OP_CHECKSEQUENCEVERIFY << OP_DROP
                  << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    spend_tx.vout[3].nValue = 11 * CENT;
    spend_tx.vout[3].scriptPubKey = p2sh_scriptPubKey;

    // "Sign" the main transaction that we spend from.
    {
        // This will cause OP_NOP10 to execute.
        spend_tx.vin[0].scriptSig << OP_1;
    }

    // Test that invalidity under a set of flags doesn't preclude validity under
    // other (eg consensus) flags.
    // spend_tx is invalid according to DISCOURAGE_UPGRADABLE_NOPS
    {
        const CTransaction tx(spend_tx);

        LOCK(cs_main);

        TxValidationState state;
        PrecomputedTransactionData ptd_spend_tx(tx);
        int nSigChecksDummy;

        BOOST_CHECK(!CheckInputScripts(
            tx, state, &legacy_coins,
            STANDARD_SCRIPT_VERIFY_FLAGS, true, true, ptd_spend_tx,
            m_node.chainman->m_validation_cache, nSigChecksDummy, nullptr));

        // If we call again asking for scriptchecks (as happens in
        // ConnectBlock), we should add a script check object for this -- we're
        // not caching invalidity (if that changes, delete this test case).
        std::vector<CScriptCheck> scriptchecks;
        BOOST_CHECK(CheckInputScripts(
            tx, state, &legacy_coins,
            STANDARD_SCRIPT_VERIFY_FLAGS, true, true, ptd_spend_tx,
            m_node.chainman->m_validation_cache, nSigChecksDummy,
            &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 1U);

        // Test that CheckInputScripts returns true iff cleanstack-enforcing
        // flags are not present. Don't add these checks to the cache, so that
        // we can test later that block validation works fine in the absence of
        // cached successes.
        ValidateCheckInputsForAllFlags(
            tx, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, 0, false,
            legacy_coins,
            m_node.chainman->m_validation_cache, 0);
    }

    // Consensus-flag direct validation must succeed without a cache entry.
    // This does not claim native-chain acceptance of the legacy vector.
    {
        LOCK(cs_main);
        const CTransaction spend(spend_tx);
        PrecomputedTransactionData data(spend);
        TxValidationState state;
        int sigchecks;
        BOOST_REQUIRE(CheckInputScripts(
            spend, state, legacy_coins, SCRIPT_ENABLE_SIGHASH_FORKID,
            true, false, data, m_node.chainman->m_validation_cache,
            sigchecks, nullptr));
        BOOST_REQUIRE(legacy_coins.SpendCoin(spend_tx.vin[0].prevout));
        AddCoins(legacy_coins, spend, 102);
        for (uint32_t i = 0; i < spend.vout.size(); ++i) {
            BOOST_REQUIRE(legacy_coins.HaveCoin(COutPoint(spend.GetId(), i)));
        }
    }
    LOCK(cs_main);

    // Test P2SH: construct a transaction that is valid without P2SH, and then
    // test validity with P2SH.
    {
        CMutableTransaction invalid_under_p2sh_tx;
        invalid_under_p2sh_tx.nVersion = 1;
        invalid_under_p2sh_tx.vin.resize(1);
        invalid_under_p2sh_tx.vin[0].prevout = COutPoint(spend_tx.GetId(), 0);
        invalid_under_p2sh_tx.vout.resize(1);
        invalid_under_p2sh_tx.vout[0].nValue = 11 * CENT;
        invalid_under_p2sh_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;
        std::vector<uint8_t> vchSig2(p2pk_scriptPubKey.begin(),
                                     p2pk_scriptPubKey.end());
        invalid_under_p2sh_tx.vin[0].scriptSig << vchSig2;

        ValidateCheckInputsForAllFlags(
            CTransaction(invalid_under_p2sh_tx), SCRIPT_VERIFY_P2SH, 0, true,
            legacy_coins,
            m_node.chainman->m_validation_cache, 0);
    }

    // Test CHECKLOCKTIMEVERIFY
    {
        CMutableTransaction invalid_with_cltv_tx;
        invalid_with_cltv_tx.nVersion = 1;
        invalid_with_cltv_tx.nLockTime = 100;
        invalid_with_cltv_tx.vin.resize(1);
        invalid_with_cltv_tx.vin[0].prevout = COutPoint(spend_tx.GetId(), 1);
        invalid_with_cltv_tx.vin[0].nSequence = 0;
        invalid_with_cltv_tx.vout.resize(1);
        invalid_with_cltv_tx.vout[0].nValue = 11 * CENT;
        invalid_with_cltv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<uint8_t> vchSig;
        uint256 hash = SignatureHash(
            spend_tx.vout[1].scriptPubKey, CTransaction(invalid_with_cltv_tx),
            0, SigHashType().withForkId(), spend_tx.vout[1].nValue);
        BOOST_CHECK(coinbaseKey.SignECDSA(hash, vchSig));
        vchSig.push_back(uint8_t(SIGHASH_ALL | SIGHASH_FORKID));
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(
            CTransaction(invalid_with_cltv_tx),
            SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_ENABLE_REPLAY_PROTECTION,
            SCRIPT_ENABLE_SIGHASH_FORKID, true,
            legacy_coins,
            m_node.chainman->m_validation_cache, 1);

        // Make it valid, and check again
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        TxValidationState state;

        CTransaction transaction(invalid_with_cltv_tx);
        PrecomputedTransactionData txdata(transaction);

        int nSigChecksRet;
        BOOST_CHECK(CheckInputScripts(
            transaction, state, legacy_coins,
            STANDARD_SCRIPT_VERIFY_FLAGS, true, true, txdata,
            m_node.chainman->m_validation_cache, nSigChecksRet, nullptr));
        BOOST_CHECK(nSigChecksRet == 1);
    }

    // TEST CHECKSEQUENCEVERIFY
    {
        CMutableTransaction invalid_with_csv_tx;
        invalid_with_csv_tx.nVersion = 2;
        invalid_with_csv_tx.vin.resize(1);
        invalid_with_csv_tx.vin[0].prevout = COutPoint(spend_tx.GetId(), 2);
        invalid_with_csv_tx.vin[0].nSequence = 100;
        invalid_with_csv_tx.vout.resize(1);
        invalid_with_csv_tx.vout[0].nValue = 11 * CENT;
        invalid_with_csv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<uint8_t> vchSig;
        uint256 hash = SignatureHash(
            spend_tx.vout[2].scriptPubKey, CTransaction(invalid_with_csv_tx), 0,
            SigHashType().withForkId(), spend_tx.vout[2].nValue);
        BOOST_CHECK(coinbaseKey.SignECDSA(hash, vchSig));
        vchSig.push_back(uint8_t(SIGHASH_ALL | SIGHASH_FORKID));
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(
            CTransaction(invalid_with_csv_tx),
            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_ENABLE_REPLAY_PROTECTION,
            SCRIPT_ENABLE_SIGHASH_FORKID, true,
            legacy_coins,
            m_node.chainman->m_validation_cache, 1);

        // Make it valid, and check again
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        TxValidationState state;

        CTransaction transaction(invalid_with_csv_tx);
        PrecomputedTransactionData txdata(transaction);

        int nSigChecksRet;
        BOOST_CHECK(CheckInputScripts(
            transaction, state, &legacy_coins,
            STANDARD_SCRIPT_VERIFY_FLAGS, true, true, txdata,
            m_node.chainman->m_validation_cache, nSigChecksRet, nullptr));
        BOOST_CHECK(nSigChecksRet == 1);
    }

    // TODO: add tests for remaining script flags

    {
        // Test a transaction with multiple inputs.
        CMutableTransaction tx;

        tx.nVersion = 1;
        tx.vin.resize(2);
        tx.vin[0].prevout = COutPoint(spend_tx.GetId(), 0);
        tx.vin[1].prevout = COutPoint(spend_tx.GetId(), 3);
        tx.vout.resize(1);
        tx.vout[0].nValue = 22 * CENT;
        tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        {
            SignatureData sigdata;
            BOOST_CHECK(ProduceSignature(
                keystore,
                MutableTransactionSignatureCreator(&tx, 0, 11 * CENT,
                                                   SigHashType().withForkId()),
                spend_tx.vout[0].scriptPubKey, sigdata));
            UpdateInput(tx.vin[0], sigdata);
        }
        {
            SignatureData sigdata;
            BOOST_CHECK(ProduceSignature(
                keystore,
                MutableTransactionSignatureCreator(&tx, 1, 11 * CENT,
                                                   SigHashType().withForkId()),
                spend_tx.vout[3].scriptPubKey, sigdata));
            UpdateInput(tx.vin[1], sigdata);
        }

        // This should be valid under all script flags that support our sighash
        // convention.
        ValidateCheckInputsForAllFlags(
            CTransaction(tx), SCRIPT_ENABLE_REPLAY_PROTECTION,
            SCRIPT_ENABLE_SIGHASH_FORKID | SCRIPT_VERIFY_P2SH, true,
            legacy_coins,
            m_node.chainman->m_validation_cache, 2);

        {
            // Try checking this valid transaction with sigchecks limiter
            // supplied. Each input consumes 1 sigcheck.

            TxValidationState state;
            CTransaction transaction(tx);
            PrecomputedTransactionData txdata(transaction);
            const uint32_t flags =
                STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENFORCE_SIGCHECKS;
            int nSigChecksDummy;

            /**
             * Parallel validation initially works (no cached value), but
             * evaluation of the script checks produces a failure.
             */
            std::vector<CScriptCheck> scriptchecks1;
            CheckInputsLimiter sigchecklimiter1(1);
            BOOST_CHECK(CheckInputScripts(
                transaction, state,
                &legacy_coins, flags, true,
                true, txdata, m_node.chainman->m_validation_cache,
                nSigChecksDummy, &scriptchecks1, &sigchecklimiter1));
            // the first check passes but it did consume the limit.
            auto result1 = scriptchecks1[1]();
            BOOST_CHECK(!result1.has_value());
            BOOST_CHECK(sigchecklimiter1.check());
            // the second check (the first input) fails due to the limiter.
            auto result2 = scriptchecks1[0]();
            BOOST_REQUIRE(result2.has_value());
            BOOST_CHECK_EQUAL(result2->first,
                              ScriptError::SIGCHECKS_LIMIT_EXCEEDED);
            BOOST_CHECK(!sigchecklimiter1.check());

            // Serial validation fails with the limiter.
            CheckInputsLimiter sigchecklimiter2(1);
            TxValidationState state2;
            BOOST_CHECK(!CheckInputScripts(
                transaction, state2,
                &legacy_coins, flags, true,
                true, txdata, m_node.chainman->m_validation_cache,
                nSigChecksDummy, nullptr, &sigchecklimiter2));
            BOOST_CHECK(!sigchecklimiter2.check());
            BOOST_CHECK_EQUAL(state2.GetRejectReason(),
                              "non-mandatory-script-verify-flag (Validation "
                              "resources exceeded (SigChecks))");

            /**
             * A slightly more permissive limiter (just enough) passes, and
             * allows caching the result.
             */
            std::vector<CScriptCheck> scriptchecks3;
            CheckInputsLimiter sigchecklimiter3(2);
            // first in parallel
            BOOST_CHECK(CheckInputScripts(
                transaction, state,
                &legacy_coins, flags, true,
                true, txdata, m_node.chainman->m_validation_cache,
                nSigChecksDummy, &scriptchecks3, &sigchecklimiter3));
            BOOST_CHECK(!scriptchecks3[1]().has_value());
            BOOST_CHECK(!scriptchecks3[0]().has_value());
            BOOST_CHECK(sigchecklimiter3.check());
            // then in serial, caching the result.
            CheckInputsLimiter sigchecklimiter4(2);
            BOOST_CHECK(CheckInputScripts(
                transaction, state,
                &legacy_coins, flags, true,
                true, txdata, m_node.chainman->m_validation_cache,
                nSigChecksDummy, nullptr, &sigchecklimiter4));
            BOOST_CHECK(sigchecklimiter4.check());
            // now in parallel again, grabbing the cached result.
            std::vector<CScriptCheck> scriptchecks5;
            CheckInputsLimiter sigchecklimiter5(2);
            BOOST_CHECK(CheckInputScripts(
                transaction, state,
                &legacy_coins, flags, true,
                true, txdata, m_node.chainman->m_validation_cache,
                nSigChecksDummy, &scriptchecks5, &sigchecklimiter5));
            BOOST_CHECK(scriptchecks5.empty());
            BOOST_CHECK(sigchecklimiter5.check());

            /**
             * Going back to the lower limit, we now fail immediately due to the
             * caching.
             */
            CheckInputsLimiter sigchecklimiter6(1);
            TxValidationState state6;
            BOOST_CHECK(!CheckInputScripts(
                transaction, state6,
                &legacy_coins, flags, true,
                true, txdata, m_node.chainman->m_validation_cache,
                nSigChecksDummy, nullptr, &sigchecklimiter6));
            BOOST_CHECK_EQUAL(state6.GetRejectReason(), "too-many-sigchecks");
            BOOST_CHECK_EQUAL(state6.GetResult(),
                              TxValidationResult::TX_CONSENSUS);
            BOOST_CHECK(!sigchecklimiter6.check());
            // even in parallel validation, immediate fail from the cache.
            std::vector<CScriptCheck> scriptchecks7;
            CheckInputsLimiter sigchecklimiter7(1);
            TxValidationState state7;
            BOOST_CHECK(!CheckInputScripts(
                transaction, state7,
                &legacy_coins, flags, true,
                true, txdata, m_node.chainman->m_validation_cache,
                nSigChecksDummy, &scriptchecks7, &sigchecklimiter7));
            BOOST_CHECK_EQUAL(state7.GetRejectReason(), "too-many-sigchecks");
            BOOST_CHECK_EQUAL(state6.GetResult(),
                              TxValidationResult::TX_CONSENSUS);
            BOOST_CHECK(!sigchecklimiter7.check());
            BOOST_CHECK(scriptchecks7.empty());
        }

        // Check that if the second input is invalid, but the first input is
        // valid, the transaction is not cached.
        // Invalidate vin[1]
        tx.vin[1].scriptSig = CScript();

        TxValidationState state;
        CTransaction transaction(tx);
        PrecomputedTransactionData txdata(transaction);

        // This transaction is now invalid because the second signature is
        // missing.
        int nSigChecksDummy;
        BOOST_CHECK(!CheckInputScripts(
            transaction, state, &legacy_coins,
            STANDARD_SCRIPT_VERIFY_FLAGS, true, true, txdata,
            m_node.chainman->m_validation_cache, nSigChecksDummy, nullptr));

        // Make sure this transaction was not cached (ie becausethe first input
        // was valid)
        std::vector<CScriptCheck> scriptchecks;
        BOOST_CHECK(CheckInputScripts(
            transaction, state, &legacy_coins,
            STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENFORCE_SIGCHECKS, true, true,
            txdata, m_node.chainman->m_validation_cache, nSigChecksDummy,
            &scriptchecks));
        // Should get 2 script checks back -- caching is on a whole-transaction
        // basis.
        BOOST_CHECK_EQUAL(scriptchecks.size(), 2U);

        // Execute the first check, and check its result
        auto result1 = scriptchecks[0]();
        BOOST_CHECK(!result1.has_value());
        BOOST_CHECK_EQUAL(
            scriptchecks[0].GetScriptExecutionMetrics().nSigChecks, 1);
        // The second check does fail
        auto result2 = scriptchecks[1]();
        BOOST_REQUIRE(result2.has_value());
        BOOST_CHECK_EQUAL(result2->first, ScriptError::INVALID_STACK_OPERATION);
    }
}

static bool IsKeyInScriptCache(ScriptCacheKey key, bool erase,
                               int &nSigChecksOut, ChainstateManager &chainman)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);
    ScriptCacheElement elem(key, 0);
    bool ret =
        chainman.m_validation_cache.m_script_execution_cache.get(elem, erase);
    nSigChecksOut = elem.nSigChecks;
    return ret;
}

static void AddKeyInScriptCache(ScriptCacheKey key, int nSigChecks,
                                ChainstateManager &chainman)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);
    ScriptCacheElement elem(key, nSigChecks);
    chainman.m_validation_cache.m_script_execution_cache.insert(elem);
}

BOOST_FIXTURE_TEST_CASE(scriptcache_values, TestChain100Setup) {
    LOCK(cs_main);
    // Test insertion and querying of keys&values from the script cache.

    // Define a couple of macros (handier than functions since errors will print
    // out the correct line number)
#define CHECK_CACHE_HAS(key, expected_sigchecks)                               \
    {                                                                          \
        int nSigChecksRet(0x12345678 ^ (expected_sigchecks));                  \
        BOOST_CHECK(                                                           \
            IsKeyInScriptCache(key, false, nSigChecksRet, *m_node.chainman));  \
        BOOST_CHECK(nSigChecksRet == (expected_sigchecks));                    \
    }
#define CHECK_CACHE_MISSING(key)                                               \
    {                                                                          \
        int dummy;                                                             \
        BOOST_CHECK(!IsKeyInScriptCache(key, false, dummy, *m_node.chainman)); \
    }

    // construct four distinct keys from very slightly different data
    CMutableTransaction tx1;
    tx1.nVersion = 1;
    CMutableTransaction tx2;
    tx2.nVersion = 2;
    uint32_t flagsA = 0x7fffffff;
    uint32_t flagsB = 0xffffffff;
    ScriptCacheKey key1A(
        CTransaction(tx1), flagsA,
        m_node.chainman->m_validation_cache.ScriptExecutionCacheHasher());
    ScriptCacheKey key1B(
        CTransaction(tx1), flagsB,
        m_node.chainman->m_validation_cache.ScriptExecutionCacheHasher());
    ScriptCacheKey key2A(
        CTransaction(tx2), flagsA,
        m_node.chainman->m_validation_cache.ScriptExecutionCacheHasher());
    ScriptCacheKey key2B(
        CTransaction(tx2), flagsB,
        m_node.chainman->m_validation_cache.ScriptExecutionCacheHasher());

    BOOST_CHECK(key1A == key1A);
    BOOST_CHECK(!(key1A == key1B));
    BOOST_CHECK(!(key1A == key2A));
    BOOST_CHECK(!(key1A == key2B));
    BOOST_CHECK(key1B == key1B);
    BOOST_CHECK(!(key1B == key2A));
    BOOST_CHECK(!(key1B == key2B));
    BOOST_CHECK(key2A == key2A);
    BOOST_CHECK(!(key2A == key2B));
    BOOST_CHECK(key2B == key2B);

    // Key is not yet inserted.
    CHECK_CACHE_MISSING(key1A);
    // Add the key and check it worked
    AddKeyInScriptCache(key1A, 42, *m_node.chainman);
    CHECK_CACHE_HAS(key1A, 42);

    CHECK_CACHE_MISSING(key1B);
    CHECK_CACHE_MISSING(key2A);
    CHECK_CACHE_MISSING(key2B);

    // 0 may be stored
    AddKeyInScriptCache(key1B, 0, *m_node.chainman);

    // Calculate the most possible transaction sigchecks that can occur in a
    // standard transaction, and make sure the cache can hold it.
    //
    // To be pessimistic, use consensus (MAX_TX_SIZE) instead of policy
    // (MAX_STANDARD_TX_SIZE) since that particular policy limit is bypassed on
    // testnet.
    //
    // Assume that a standardness rule limiting density to ~33 bytes/sigcheck is
    // in place.
    const int max_standard_sigchecks = 1 + (MAX_TX_SIZE / 33);
    AddKeyInScriptCache(key2A, max_standard_sigchecks, *m_node.chainman);

    // Read out values again.
    CHECK_CACHE_HAS(key1A, 42);
    CHECK_CACHE_HAS(key1B, 0);
    CHECK_CACHE_HAS(key2A, max_standard_sigchecks);
    CHECK_CACHE_MISSING(key2B);

    // Try overwriting an existing entry with different value (should never
    // happen in practice but see what happens).
    AddKeyInScriptCache(key1A, 99, *m_node.chainman);
    // This succeeds without error, but (currently) no replacement is done.
    // It would also be acceptable to overwrite, but if we ever come to a
    // situation where this matters then neither alternative is better.
    CHECK_CACHE_HAS(key1A, 42);
}

BOOST_AUTO_TEST_SUITE_END()
