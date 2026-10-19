// Copyright (c) 2011-2019 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h> // For CChainParams
#include <checkqueue.h>
#include <clientversion.h>
#include <common/system.h>
#include <config.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <core_memusage.h>
#include <key.h>
#include <lotus_v2/output.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>

#include <test/data/tx_invalid.json.h>
#include <test/data/tx_valid.json.h>
#include <test/jsonutil.h>
#include <test/scriptflags.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <atomic>
#include <map>
#include <string>
#include <thread>

typedef std::vector<uint8_t> valtype;

static CFeeRate g_dust{DUST_RELAY_TX_FEE};
static bool g_bare_multi{DEFAULT_PERMIT_BAREMULTISIG};

BOOST_FIXTURE_TEST_SUITE(transaction_tests, BasicTestingSetup)

static COutPoint buildOutPoint(const UniValue &vinput) {
    TxId txid;
    txid.SetHexDeprecated(vinput[0].get_str());
    return COutPoint(txid, vinput[1].getInt<int>());
}

BOOST_AUTO_TEST_CASE(serialized_size_all_constructors) {
    auto check = [](const CTransaction &tx) {
        const auto direct_size = ::GetSerializeSize(CMutableTransaction{tx});
        BOOST_CHECK_EQUAL(tx.GetTotalSize(), direct_size);
        BOOST_CHECK_EQUAL(::GetSerializeSize(tx), direct_size);
    };
    check(CTransaction{});
    for (size_t length : {size_t{0}, size_t{28}, size_t{253}, size_t{1000}}) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        CScript script;
        script.resize(length);
        mtx.vout.emplace_back(1 * SATOSHI, std::move(script));
        const CTransaction copied{mtx};
        check(copied);
        const CTransaction moved{std::move(mtx)};
        check(moved);
        DataStream wire;
        wire << copied;
        const CTransaction decoded{deserialize, wire};
        check(decoded);
    }
}

// Slab-backed long scripts borrow from immutable transaction storage. Moving a
// borrowed script must make an owning copy, including at the V2 bridge boundary.
BOOST_AUTO_TEST_CASE(slab_script_v2_bridge_and_move) {
    for (size_t length : {size_t{0}, size_t{1}, size_t{28}, size_t{29},
                          size_t{31}, size_t{128}, size_t{494}}) {
        CMutableTransaction mutable_tx;
        mutable_tx.vin.resize(1);
        CScript expected;
        expected.resize(length);
        std::fill(expected.begin(), expected.end(), OP_TRUE);
        mutable_tx.vout.emplace_back(123 * SATOSHI, expected);
        CTransactionRef tx = MakeTransactionRef(std::move(mutable_tx));
        const CTxOut &original = tx->vout[0];
        const CTxOut roundtrip = CTxOut::FromV2Output(original.ToV2Output());
        BOOST_CHECK(roundtrip == original);
        // The transaction's const view must copy on std::move, rather than
        // transferring a view whose lifetime would end with its slab owner.
        const auto *storage = original.scriptPubKey.data();
        CScript moved{std::move(tx->vout[0].scriptPubKey)};
        BOOST_CHECK(moved == expected);
        if (length > 28) BOOST_CHECK(moved.data() != storage);
        tx.reset();
        BOOST_CHECK(moved == expected);
        if (!moved.empty()) moved[0] = OP_FALSE;
        BOOST_CHECK(roundtrip.scriptPubKey == expected);
    }
}

BOOST_AUTO_TEST_CASE(tx_valid) {
    // Read tests from test/data/tx_valid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2],
    // ...],"], serializedTransaction, verifyFlags
    // ... where all scripts are stringified scripts.
    //
    // verifyFlags is a comma separated list of script verification flags to
    // apply, or "NONE"
    UniValue tests = read_json(json_tests::tx_valid);

    ScriptError err;
    for (size_t idx = 0; idx < tests.size(); idx++) {
        const UniValue &test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray()) {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr()) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, Amount> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (size_t inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue &input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue &vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4) {
                    fValid = false;
                    break;
                }
                COutPoint outpoint = buildOutPoint(vinput);
                mapprevOutScriptPubKeys[outpoint] =
                    ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4) {
                    mapprevOutValues[outpoint] =
                        vinput[3].getInt<int64_t>() * SATOSHI;
                }
            }
            if (!fValid) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            DataStream stream{ParseHex(transaction)};
            CTransaction tx(deserialize, stream);

            TxValidationState state;
            BOOST_CHECK_MESSAGE(tx.IsCoinBase()
                                    ? CheckCoinbase(tx, state)
                                    : CheckRegularTransaction(tx, state),
                                strTest);
            BOOST_CHECK(state.IsValid());

            // Check that CheckCoinbase reject non-coinbase transactions and
            // vice versa.
            BOOST_CHECK_MESSAGE(!(tx.IsCoinBase()
                                      ? CheckRegularTransaction(tx, state)
                                      : CheckCoinbase(tx, state)),
                                strTest);
            BOOST_CHECK(state.IsInvalid());

            PrecomputedTransactionData txdata(tx);
            for (size_t i = 0; i < tx.vin.size(); i++) {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout)) {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                Amount amount = Amount::zero();
                if (mapprevOutValues.count(tx.vin[i].prevout)) {
                    amount = mapprevOutValues[tx.vin[i].prevout];
                }

                uint32_t verify_flags = ParseScriptFlags(test[2].get_str());
                BOOST_CHECK_MESSAGE(
                    VerifyScript(
                        tx.vin[i].scriptSig,
                        mapprevOutScriptPubKeys[tx.vin[i].prevout],
                        verify_flags,
                        TransactionSignatureChecker(&tx, i, amount, txdata),
                        &err),
                    strTest);
                BOOST_CHECK_MESSAGE(err == ScriptError::OK,
                                    ScriptErrorString(err));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_invalid) {
    // Read tests from test/data/tx_invalid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2],
    // ...],"], serializedTransaction, verifyFlags
    // ... where all scripts are stringified scripts.
    //
    // verifyFlags is a comma separated list of script verification flags to
    // apply, or "NONE"
    UniValue tests = read_json(json_tests::tx_invalid);

    // Initialize to ScriptError::OK. The tests expect err to be changed to a
    // value other than ScriptError::OK.
    ScriptError err = ScriptError::OK;
    for (size_t idx = 0; idx < tests.size(); idx++) {
        const UniValue &test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray()) {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr()) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, Amount> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (size_t inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue &input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue &vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4) {
                    fValid = false;
                    break;
                }
                COutPoint outpoint = buildOutPoint(vinput);
                mapprevOutScriptPubKeys[outpoint] =
                    ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4) {
                    mapprevOutValues[outpoint] =
                        vinput[3].getInt<int64_t>() * SATOSHI;
                }
            }
            if (!fValid) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            DataStream stream{ParseHex(transaction)};
            CTransaction tx(deserialize, stream);

            TxValidationState state;
            fValid = CheckRegularTransaction(tx, state) && state.IsValid();

            PrecomputedTransactionData txdata(tx);
            for (size_t i = 0; i < tx.vin.size() && fValid; i++) {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout)) {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                Amount amount = Amount::zero();
                if (0 != mapprevOutValues.count(tx.vin[i].prevout)) {
                    amount = mapprevOutValues[tx.vin[i].prevout];
                }

                uint32_t verify_flags = ParseScriptFlags(test[2].get_str());
                fValid = VerifyScript(
                    tx.vin[i].scriptSig,
                    mapprevOutScriptPubKeys[tx.vin[i].prevout], verify_flags,
                    TransactionSignatureChecker(&tx, i, amount, txdata), &err);
            }
            BOOST_CHECK_MESSAGE(!fValid, strTest);
            BOOST_CHECK_MESSAGE(err != ScriptError::OK, ScriptErrorString(err));
        }
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests) {
    // Random real transaction
    // (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    uint8_t ch[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65,
        0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8,
        0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74,
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00,
        0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77,
        0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f,
        0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2,
        0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e,
        0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4,
        0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2,
        0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a,
        0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34,
        0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97,
        0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b,
        0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f,
        0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00,
        0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef,
        0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39,
        0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93,
        0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43,
        0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<uint8_t> vch(ch, ch + sizeof(ch) - 1);
    DataStream stream{vch};
    CMutableTransaction tx;
    stream >> tx;
    TxValidationState state;
    BOOST_CHECK_MESSAGE(CheckRegularTransaction(CTransaction(tx), state) &&
                            state.IsValid(),
                        "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckRegularTransaction(CTransaction(tx), state) ||
                            !state.IsValid(),
                        "Transaction with duplicate txins should be invalid.");
}

BOOST_AUTO_TEST_CASE(test_Get) {
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(
        keystore, coins, {{11 * CENT, 50 * CENT, 21 * CENT, 22 * CENT}});

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout = COutPoint(dummyTransactions[0].GetId(), 1);
    t1.vin[0].scriptSig << std::vector<uint8_t>(65, 0);
    t1.vin[1].prevout = COutPoint(dummyTransactions[1].GetId(), 0);
    t1.vin[1].scriptSig << std::vector<uint8_t>(65, 0)
                        << std::vector<uint8_t>(33, 4);
    t1.vin[2].prevout = COutPoint(dummyTransactions[1].GetId(), 1);
    t1.vin[2].scriptSig << std::vector<uint8_t>(65, 0)
                        << std::vector<uint8_t>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90 * CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(CTransaction(t1), coins,
                                  STANDARD_SCRIPT_VERIFY_FLAGS));
}

static void CreateCreditAndSpend(const FillableSigningProvider &keystore,
                                 const CScript &outscript,
                                 CTransactionRef &output,
                                 CMutableTransaction &input,
                                 bool success = true) {
    CMutableTransaction outputm;
    outputm.nVersion = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout = COutPoint();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = SATOSHI;
    outputm.vout[0].scriptPubKey = outscript;
    DataStream ssout{};
    ssout << outputm;
    ssout >> output;
    BOOST_CHECK_EQUAL(output->vin.size(), 1UL);
    BOOST_CHECK(output->vin[0] == outputm.vin[0]);
    BOOST_CHECK_EQUAL(output->vout.size(), 1UL);
    BOOST_CHECK(output->vout[0] == outputm.vout[0]);

    CMutableTransaction inputm;
    inputm.nVersion = 1;
    inputm.vin.resize(1);
    inputm.vin[0].prevout = COutPoint(output->GetId(), 0);
    inputm.vout.resize(1);
    inputm.vout[0].nValue = SATOSHI;
    inputm.vout[0].scriptPubKey = CScript();
    bool ret =
        SignSignature(keystore, *output, inputm, 0, SigHashType().withForkId());
    BOOST_CHECK_EQUAL(ret, success);
    DataStream ssin{};
    ssin << inputm;
    ssin >> input;
    BOOST_CHECK_EQUAL(input.vin.size(), 1UL);
    BOOST_CHECK(input.vin[0] == inputm.vin[0]);
    BOOST_CHECK_EQUAL(input.vout.size(), 1UL);
    BOOST_CHECK(input.vout[0] == inputm.vout[0]);
}

static void CheckWithFlag(const CTransactionRef &output,
                          const CMutableTransaction &input, int flags,
                          bool success) {
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(
        inputi.vin[0].scriptSig, output->vout[0].scriptPubKey,
        flags | SCRIPT_ENABLE_SIGHASH_FORKID,
        TransactionSignatureChecker(&inputi, 0, output->vout[0].nValue),
        &error);
    BOOST_CHECK_EQUAL(ret, success);
}

static CScript PushAll(const std::vector<valtype> &values) {
    CScript result;
    for (const valtype &v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

static void ReplaceRedeemScript(CScript &script, const CScript &redeemScript) {
    std::vector<valtype> stack;
    EvalScript(stack, script, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker());
    BOOST_CHECK(stack.size() > 0);
    stack.back() =
        std::vector<uint8_t>(redeemScript.begin(), redeemScript.end());
    script = PushAll(stack);
}

BOOST_AUTO_TEST_CASE(test_big_transaction) {
    CKey key;
    key.MakeNewKey(false);
    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKeyPubKey(key, key.GetPubKey()));
    CScript scriptPubKey = CScript()
                           << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    std::vector<SigHashType> sigHashes;
    sigHashes.emplace_back(SIGHASH_NONE | SIGHASH_FORKID);
    sigHashes.emplace_back(SIGHASH_SINGLE | SIGHASH_FORKID);
    sigHashes.emplace_back(SIGHASH_ALL | SIGHASH_FORKID);
    sigHashes.emplace_back(SIGHASH_NONE | SIGHASH_FORKID |
                           SIGHASH_ANYONECANPAY);
    sigHashes.emplace_back(SIGHASH_SINGLE | SIGHASH_FORKID |
                           SIGHASH_ANYONECANPAY);
    sigHashes.emplace_back(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY);

    CMutableTransaction mtx;
    mtx.nVersion = 1;

    // create a big transaction of 4500 inputs signed by the same key.
    const static size_t OUTPUT_COUNT = 4500;
    mtx.vout.reserve(OUTPUT_COUNT);

    for (size_t ij = 0; ij < OUTPUT_COUNT; ij++) {
        size_t i = mtx.vin.size();
        TxId prevId(uint256S("0000000000000000000000000000000000000000000000000"
                             "000000000000100"));
        COutPoint outpoint(prevId, i);

        mtx.vin.resize(mtx.vin.size() + 1);
        mtx.vin[i].prevout = outpoint;
        mtx.vin[i].scriptSig = CScript();

        mtx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_1);
    }

    // sign all inputs
    for (size_t i = 0; i < mtx.vin.size(); i++) {
        bool hashSigned =
            SignSignature(keystore, scriptPubKey, mtx, i, 1000 * SATOSHI,
                          sigHashes.at(i % sigHashes.size()));
        BOOST_CHECK_MESSAGE(hashSigned, "Failed to sign test transaction");
    }

    CTransaction tx(mtx);

    // check all inputs concurrently, with the cache
    PrecomputedTransactionData txdata(tx);
    CCheckQueue<CScriptCheck> scriptcheckqueue(/*batch_size=*/128,
                                               /*worker_threads_num=*/20);
    CCheckQueueControl<CScriptCheck> control(scriptcheckqueue);

    std::vector<Coin> coins;
    for (size_t i = 0; i < mtx.vin.size(); i++) {
        CTxOut out;
        out.nValue = 1000 * SATOSHI;
        out.scriptPubKey = scriptPubKey;
        coins.emplace_back(std::move(out), 1, false);
    }

    SignatureCache signature_cache{DEFAULT_SIGNATURE_CACHE_BYTES};

    for (size_t i = 0; i < mtx.vin.size(); i++) {
        std::vector<CScriptCheck> vChecks;
        vChecks.emplace_back(coins[tx.vin[i].prevout.GetN()].GetTxOut(), tx,
                             signature_cache, i, STANDARD_SCRIPT_VERIFY_FLAGS,
                             false, txdata);
        control.Add(std::move(vChecks));
    }

    bool controlCheck = !control.Complete().has_value();
    BOOST_CHECK(controlCheck);
}

SignatureData CombineSignatures(const CMutableTransaction &input1,
                                const CMutableTransaction &input2,
                                const CTransactionRef tx) {
    SignatureData sigdata;
    sigdata = DataFromTransaction(input1, 0, tx->vout[0]);
    sigdata.MergeSignatureData(DataFromTransaction(input2, 0, tx->vout[0]));
    ProduceSignature(
        DUMMY_SIGNING_PROVIDER,
        MutableTransactionSignatureCreator(&input1, 0, tx->vout[0].nValue),
        tx->vout[0].scriptPubKey, sigdata);
    return sigdata;
}

BOOST_AUTO_TEST_CASE(test_witness) {
    FillableSigningProvider keystore, keystore2;
    CKey key1, key2, key3, key1L, key2L;
    CPubKey pubkey1, pubkey2, pubkey3, pubkey1L, pubkey2L;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    key3.MakeNewKey(true);
    key1L.MakeNewKey(false);
    key2L.MakeNewKey(false);
    pubkey1 = key1.GetPubKey();
    pubkey2 = key2.GetPubKey();
    pubkey3 = key3.GetPubKey();
    pubkey1L = key1L.GetPubKey();
    pubkey2L = key2L.GetPubKey();
    BOOST_CHECK(keystore.AddKeyPubKey(key1, pubkey1));
    BOOST_CHECK(keystore.AddKeyPubKey(key2, pubkey2));
    BOOST_CHECK(keystore.AddKeyPubKey(key1L, pubkey1L));
    BOOST_CHECK(keystore.AddKeyPubKey(key2L, pubkey2L));
    CScript scriptPubkey1, scriptPubkey2, scriptPubkey1L, scriptPubkey2L,
        scriptMulti;
    scriptPubkey1 << ToByteVector(pubkey1) << OP_CHECKSIG;
    scriptPubkey2 << ToByteVector(pubkey2) << OP_CHECKSIG;
    scriptPubkey1L << ToByteVector(pubkey1L) << OP_CHECKSIG;
    scriptPubkey2L << ToByteVector(pubkey2L) << OP_CHECKSIG;
    std::vector<CPubKey> oneandthree;
    oneandthree.push_back(pubkey1);
    oneandthree.push_back(pubkey3);
    scriptMulti = GetScriptForMultisig(2, oneandthree);
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1L));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2L));
    BOOST_CHECK(keystore.AddCScript(scriptMulti));
    BOOST_CHECK(keystore2.AddCScript(scriptMulti));
    BOOST_CHECK(keystore2.AddKeyPubKey(key3, pubkey3));

    CTransactionRef output1, output2;
    CMutableTransaction input1, input2;

    // Normal pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2, output2, input2);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptHash(scriptPubkey1)),
                         output1, input1);
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptHash(scriptPubkey2)),
                         output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1L, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2L, output2, input2);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptHash(scriptPubkey1L)),
                         output1, input1);
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptHash(scriptPubkey2L)),
                         output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1L);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal 2-of-2 multisig
    CreateCreditAndSpend(keystore, scriptMulti, output1, input1, false);
    CheckWithFlag(output1, input1, 0, false);
    CreateCreditAndSpend(keystore2, scriptMulti, output2, input2, false);
    CheckWithFlag(output2, input2, 0, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH 2-of-2 multisig
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptHash(scriptMulti)),
                         output1, input1, false);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, false);
    CreateCreditAndSpend(keystore2,
                         GetScriptForDestination(ScriptHash(scriptMulti)),
                         output2, input2, false);
    CheckWithFlag(output2, input2, 0, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
}

BOOST_AUTO_TEST_CASE(test_IsStandard) {
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(
        keystore, coins, {{11 * CENT, 50 * CENT, 21 * CENT, 22 * CENT}});

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout = COutPoint(dummyTransactions[0].GetId(), 1);
    t.vin[0].scriptSig << std::vector<uint8_t>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90 * CENT;
    CKey key;
    key.MakeNewKey(true);
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    // Check dust with default relay fee:
    Amount nDustThreshold = 182 * g_dust.GetFeePerK() / 1000;
    BOOST_CHECK_EQUAL(nDustThreshold, 546 * SATOSHI);
    // dust:
    t.vout[0].nValue = nDustThreshold - SATOSHI;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "dust");
    // not dust:
    t.vout[0].nValue = nDustThreshold;
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    // Disallowed nVersion
    t.nVersion = std::numeric_limits<uint32_t>::max();
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "version");

    t.nVersion = 0;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "version");

    t.nVersion = 3;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "version");

    // Allowed nVersion
    t.nVersion = 1;
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    t.nVersion = 2;
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    // Check dust with odd relay fee to verify rounding:
    // nDustThreshold = 182 * 3702 / 1000
    g_dust = CFeeRate(3702 * SATOSHI);
    // dust:
    t.vout[0].nValue = (673 - 1) * SATOSHI;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "dust");
    // not dust:
    t.vout[0].nValue = 673 * SATOSHI;
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));
    g_dust = CFeeRate{DUST_RELAY_TX_FEE};

    t.vout[0].scriptPubKey = CScript() << OP_1;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");

    // MAX_OP_RETURN_RELAY-byte TxoutType::NULL_DATA (standard)
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("646578784062697477617463682e636f2092c558ed52c56d"
                              "8dd14ca76226bc936a84820d898443873eb03d8854b21fa3"
                              "952b99a2981873e74509281730d78a21786d34a38bd1ebab"
                              "822fad42278f7f4420db6ab1fd2b6826148d4f73bb41ec2d"
                              "40a6d5793d66e17074a0c56a8a7df21062308f483dd6e38d"
                              "53609d350038df0a1b2a9ac8332016e0b904f66880dd0108"
                              "81c4e8074cce8e4ad6c77cb3460e01bf0e7e811b5f945f83"
                              "732ba6677520a893d75d9a966cb8f85dc301656b1635c631"
                              "f5d00d4adf73f2dd112ca75cf19754651909becfbe65aed1"
                              "3afb2ab8");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    // MAX_OP_RETURN_RELAY+1-byte TxoutType::NULL_DATA (non-standard)
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("646578784062697477617463682e636f2092c558ed52c56d"
                              "8dd14ca76226bc936a84820d898443873eb03d8854b21fa3"
                              "952b99a2981873e74509281730d78a21786d34a38bd1ebab"
                              "822fad42278f7f4420db6ab1fd2b6826148d4f73bb41ec2d"
                              "40a6d5793d66e17074a0c56a8a7df21062308f483dd6e38d"
                              "53609d350038df0a1b2a9ac8332016e0b904f66880dd0108"
                              "81c4e8074cce8e4ad6c77cb3460e01bf0e7e811b5f945f83"
                              "732ba6677520a893d75d9a966cb8f85dc301656b1635c631"
                              "f5d00d4adf73f2dd112ca75cf19754651909becfbe65aed1"
                              "3afb2ab800");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1, t.vout[0].scriptPubKey.size());
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");

    /**
     * Check when a custom value is used for max_datacarrier_bytes.
     */
    unsigned newMaxSize = 90;

    // Max user provided payload size is standard
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548"
                              "271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                              "b649f6bc3f4cef3877696e64657878");
    BOOST_CHECK_EQUAL(t.vout[0].scriptPubKey.size(), newMaxSize);
    BOOST_CHECK(IsStandardTx(CTransaction{t}, newMaxSize, g_bare_multi, g_dust,
                             reason));

    // Max user provided payload size + 1 is non-standard
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548"
                              "271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                              "b649f6bc3f4cef3877696e6465787800");
    BOOST_CHECK_EQUAL(t.vout[0].scriptPubKey.size(), newMaxSize + 1);
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, newMaxSize, g_bare_multi, g_dust,
                              reason));

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("");
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));
    t.vout[0].scriptPubKey = CScript()
                             << OP_RETURN << ParseHex("00") << ParseHex("01");
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED << -1 << 0
                                       << ParseHex("01") << 2 << 3 << 4 << 5
                                       << 6 << 7 << 8 << 9 << 10 << 11 << 12
                                       << 13 << 14 << 15 << 16;
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));
    t.vout[0].scriptPubKey = CScript()
                             << OP_RETURN << 0 << ParseHex("01") << 2
                             << ParseHex("fffffffffffffffffffffffffffffffffffff"
                                         "fffffffffffffffffffffffffffffffffff");
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    // ...so long as it only contains PUSHDATA's
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");

    // TxoutType::NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    // Only one TxoutType::NULL_DATA permitted in all cases
    t.vout.resize(2);
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "multi-op-return");

    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "multi-op-return");

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "multi-op-return");

    // Check large scriptSig (non-standard if size is >1650 bytes)
    t.vout.resize(1);
    t.vout[0].nValue = MAX_MONEY;
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    // OP_PUSHDATA2 with len (3 bytes) + data (1647 bytes) = 1650 bytes
    t.vin[0].scriptSig = CScript() << std::vector<uint8_t>(1647, 0); // 1650
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    t.vin[0].scriptSig = CScript() << std::vector<uint8_t>(1648, 0); // 1651
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "scriptsig-size");

    // Check scriptSig format (non-standard if there are any other ops than just
    // PUSHs)
    t.vin[0].scriptSig = CScript()
                         // OP_n (single byte pushes: n = 1, 0, -1, 16)
                         << OP_TRUE << OP_0 << OP_1NEGATE
                         << OP_16
                         // OP_PUSHx [...x bytes...]
                         << std::vector<uint8_t>(75, 0)
                         // OP_PUSHDATA1 x [...x bytes...]
                         << std::vector<uint8_t>(235, 0)
                         // OP_PUSHDATA2 x [...x bytes...]
                         << std::vector<uint8_t>(1234, 0) << OP_9;
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    const std::vector<uint8_t> non_push_ops = {
        // arbitrary set of non-push operations
        OP_NOP,
        OP_VERIFY,
        OP_IF,
        OP_ROT,
        OP_3DUP,
        OP_SIZE,
        OP_EQUAL,
        OP_ADD,
        OP_SUB,
        OP_HASH256,
        OP_CODESEPARATOR,
        OP_CHECKSIG,
        OP_CHECKLOCKTIMEVERIFY};

    CScript::const_iterator pc = t.vin[0].scriptSig.begin();
    while (pc < t.vin[0].scriptSig.end()) {
        opcodetype opcode;
        CScript::const_iterator prev_pc = pc;
        // advance to next op
        t.vin[0].scriptSig.GetOp(pc, opcode);
        // for the sake of simplicity, we only replace single-byte push
        // operations
        if (opcode >= 1 && opcode <= OP_PUSHDATA4) {
            continue;
        }

        int index = prev_pc - t.vin[0].scriptSig.begin();
        // save op
        uint8_t orig_op = *prev_pc;
        // replace current push-op with each non-push-op
        for (auto op : non_push_ops) {
            t.vin[0].scriptSig[index] = op;
            BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                                      g_bare_multi, g_dust, reason));
            BOOST_CHECK_EQUAL(reason, "scriptsig-not-pushonly");
        }
        // restore op
        t.vin[0].scriptSig[index] = orig_op;
        BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                                 g_bare_multi, g_dust, reason));
    }

    // Check bare multisig (standard if policy flag g_bare_multi is set)
    g_bare_multi = true;
    // simple 1-of-1
    t.vout[0].scriptPubKey = GetScriptForMultisig(1, {key.GetPubKey()});
    t.vin[0].scriptSig = CScript() << std::vector<uint8_t>(65, 0);
    BOOST_CHECK(IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY, g_bare_multi,
                             g_dust, reason));

    g_bare_multi = false;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{t}, MAX_OP_RETURN_RELAY,
                              g_bare_multi, g_dust, reason));
    BOOST_CHECK_EQUAL(reason, "bare-multisig");
    g_bare_multi = DEFAULT_PERMIT_BAREMULTISIG;
}

BOOST_FIXTURE_TEST_CASE(txsize_activation_test, ChainTestingSetup) {
    const Consensus::Params &params = m_node.chainman->GetConsensus();
    const int32_t magneticAnomalyActivationHeight =
        params.magneticAnomalyHeight;

    // A minimaly sized transction.
    CTransaction minTx;
    TxValidationState state;

    BOOST_CHECK(ContextualCheckTransaction(
        params, minTx, state, magneticAnomalyActivationHeight - 1, 5678));
    BOOST_CHECK(!ContextualCheckTransaction(
        params, minTx, state, magneticAnomalyActivationHeight, 5678));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-undersize");
}

BOOST_AUTO_TEST_CASE(tx_getvalueout) {
    CMutableTransaction mtx;

    // Negative output value
    mtx.vout.resize(1);
    mtx.vout[0].nValue = -1 * SATOSHI;
    CTransaction negative_tx{mtx};
    BOOST_CHECK_THROW(negative_tx.GetValueOut(), std::runtime_error);

    // Good output
    mtx.vout[0].nValue = 10000 * SATOSHI;
    CTransaction valid_one_output_tx{mtx};
    BOOST_CHECK_EQUAL(valid_one_output_tx.GetValueOut(), 10000 * SATOSHI);

    // Maximum output
    mtx.vout[0].nValue = MAX_MONEY;
    CTransaction max_one_output_tx{mtx};
    BOOST_CHECK_EQUAL(max_one_output_tx.GetValueOut(), MAX_MONEY);

    // Too high output
    mtx.vout[0].nValue = MAX_MONEY + 1 * SATOSHI;
    CTransaction too_high_tx{mtx};
    BOOST_CHECK_THROW(too_high_tx.GetValueOut(), std::runtime_error);

    // Valid sum
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 42 * SATOSHI;
    mtx.vout[1].nValue = 1337 * SATOSHI;
    CTransaction valid_tx{mtx};
    BOOST_CHECK_EQUAL(valid_tx.GetValueOut(), 1379 * SATOSHI);

    // Maximum sum
    mtx.vout[0].nValue = MAX_MONEY - 1 * SATOSHI;
    mtx.vout[1].nValue = 1 * SATOSHI;
    CTransaction max_two_outputs_tx{mtx};
    BOOST_CHECK_EQUAL(max_two_outputs_tx.GetValueOut(), MAX_MONEY);

    // Too high sum
    mtx.vout[0].nValue = MAX_MONEY - 1 * SATOSHI;
    mtx.vout[1].nValue = 2 * SATOSHI;
    CTransaction too_high_sum_tx{mtx};
    BOOST_CHECK_THROW(too_high_sum_tx.GetValueOut(), std::runtime_error);

    // First output valid, but the second output would cause an int64 overflow.
    // This issue was encountered while fuzzing:
    // https://github.com/bitcoin/bitcoin/issues/18046
    mtx.vout[0].nValue = 2 * SATOSHI;
    mtx.vout[1].nValue = (std::numeric_limits<int64_t>::max() - 1) * SATOSHI;
    CTransaction overflow_sum_tx{mtx};
    BOOST_CHECK_THROW(overflow_sum_tx.GetValueOut(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(precompute_and_script_checks_share_transaction_cache) {
    const COutPoint previous{TxId{uint256::ONE}, 0};
    CMutableTransaction mtx;
    mtx.vin.emplace_back(previous);
    mtx.vout.emplace_back(90 * SATOSHI, CScript() << OP_TRUE);
    const CTransaction tx{std::move(mtx)};
    PrecomputedBatchTxData prepared;
    PrecomputeSingleTxData(tx, prepared);
    BOOST_REQUIRE(prepared.regular_tx_checked);
    BOOST_REQUIRE(prepared.regular_tx_valid);
    const auto *cached = &tx.GetPrecomputedData();
    CCoinsView base;
    CCoinsViewCache coins{&base};
    coins.AddCoin(previous, Coin{CTxOut{100 * SATOSHI, CScript() << OP_TRUE},
                                 1, false}, false);
    ValidationCache cache{1 << 20, 1 << 20};
    LOCK(cs_main);
    // Exercise the same checker used by mempool and block validation, then
    // its deferred script-worker variant, against the cache warmed above.
    for (bool deferred : {false, true}) {
        TxValidationState state;
        TxSigCheckLimiter limiter;
        int sigchecks = 0;
        std::vector<CScriptCheck> checks;
        BOOST_REQUIRE(CheckInputScripts(tx, state, coins, 0, false, false,
            tx.GetPrecomputedData(), cache, sigchecks, limiter, nullptr,
            deferred ? &checks : nullptr));
        for (auto &check : checks) BOOST_CHECK(!check().has_value());
        BOOST_CHECK(cached == &tx.GetPrecomputedData());
    }
}

BOOST_AUTO_TEST_CASE(cached_size_and_precomputed_data) {
    // CTransaction caches its serialized size at construction and its
    // sighash midstate on first use; both must match a fresh computation.
    auto check = [](const CMutableTransaction &mtx) {
        const CTransaction tx{mtx};
        DataStream ss{};
        ss << tx;
        BOOST_CHECK_EQUAL(tx.GetTotalSize(), ss.size());
        BOOST_CHECK_EQUAL(::GetSerializeSize(tx), ss.size());
        BOOST_CHECK_EQUAL(::GetSerializeSize(mtx), ss.size());

        const PrecomputedTransactionData fresh{mtx};
        const PrecomputedTransactionData &cached = tx.GetPrecomputedData();
        BOOST_CHECK(cached.hashPrevouts == fresh.hashPrevouts);
        BOOST_CHECK(cached.hashSequence == fresh.hashSequence);
        BOOST_CHECK(cached.hashOutputs == fresh.hashOutputs);
        const PrecomputedTransactionData copied{tx};
        BOOST_CHECK(copied.hashOutputs == fresh.hashOutputs);
        BOOST_CHECK(PrecomputedTransactionData::Compute(tx).hashPrevouts ==
                    fresh.hashPrevouts);
    };

    // Null transaction.
    check(CMutableTransaction{});
    {
        const CTransaction null_tx;
        BOOST_CHECK_EQUAL(null_tx.GetTotalSize(), ::GetSerializeSize(
                                                      CMutableTransaction{}));
    }
    // Varying input/output counts and script sizes, including scripts that
    // spill out of CScript's inline prevector storage.
    FastRandomContext rng{/*fDeterministic=*/true};
    for (size_t n_in = 0; n_in < 4; ++n_in) {
        for (size_t n_out = 0; n_out < 4; ++n_out) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.nLockTime = rng.rand32();
            for (size_t i = 0; i < n_in; ++i) {
                mtx.vin.emplace_back(TxId{rng.rand256()}, rng.rand32(),
                                     CScript() << rng.randbytes(i * 40),
                                     rng.rand32());
            }
            for (size_t i = 0; i < n_out; ++i) {
                mtx.vout.emplace_back(int64_t(rng.rand32()) * SATOSHI,
                                      CScript() << rng.randbytes(i * 30));
            }
            check(mtx);
            // Moving the mutable transaction in must give the same caches.
            CMutableTransaction moved{mtx};
            const CTransaction tx_moved{std::move(moved)};
            BOOST_CHECK_EQUAL(tx_moved.GetTotalSize(),
                              ::GetSerializeSize(mtx));
            BOOST_CHECK(tx_moved.GetPrecomputedData().hashSequence ==
                        PrecomputedTransactionData{mtx}.hashSequence);
        }
    }
}

BOOST_AUTO_TEST_CASE(precomputed_data_concurrent_first_use) {
    // Many threads racing on the first GetPrecomputedData() call must all see
    // the same fully written cache, and the fill must happen in place.
    constexpr int NUM_THREADS{8};
    FastRandomContext rng{/*fDeterministic=*/true};
    for (int round = 0; round < 200; ++round) {
        CMutableTransaction mtx;
        for (int i = 0; i < 3; ++i) {
            mtx.vin.emplace_back(TxId{rng.rand256()}, rng.rand32(), CScript(),
                                 rng.rand32());
            mtx.vout.emplace_back(int64_t(rng.rand32()) * SATOSHI,
                                  CScript() << rng.randbytes(25));
        }
        const PrecomputedTransactionData fresh{mtx};
        const CTransactionRef tx = MakeTransactionRef(mtx);

        std::atomic<bool> go{false};
        std::vector<const PrecomputedTransactionData *> seen(NUM_THREADS);
        std::vector<PrecomputedTransactionData> values(NUM_THREADS);
        std::vector<std::thread> threads;
        for (int t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&, t] {
                while (!go.load(std::memory_order_acquire)) {
                }
                const PrecomputedTransactionData &data =
                    tx->GetPrecomputedData();
                seen[t] = &data;
                values[t] = data;
            });
        }
        go.store(true, std::memory_order_release);
        for (auto &thread : threads) {
            thread.join();
        }

        const PrecomputedTransactionData *const cached =
            &tx->GetPrecomputedData();
        for (int t = 0; t < NUM_THREADS; ++t) {
            BOOST_CHECK(seen[t] == cached);
            BOOST_CHECK(values[t].hashPrevouts == fresh.hashPrevouts);
            BOOST_CHECK(values[t].hashSequence == fresh.hashSequence);
            BOOST_CHECK(values[t].hashOutputs == fresh.hashOutputs);
        }
    }
}

/** A stream that only supports reading, so its bytes are never contiguous. */
class SequentialReader {
    SpanReader m_reader;

public:
    explicit SequentialReader(Span<const uint8_t> data) : m_reader(data) {}
    void read(Span<std::byte> dst) { m_reader.read(dst); }
    size_t size() const { return m_reader.size(); }
    template <typename T> SequentialReader &operator>>(T &&obj) {
        ::Unserialize(*this, obj);
        return *this;
    }
};
static_assert(ContiguousReadStream<SpanReader>);
static_assert(ContiguousReadStream<DataStream>);
static_assert(!ContiguousReadStream<SequentialReader>);

static CScript RawScript(const std::vector<uint8_t> &bytes) {
    return CScript(bytes.begin(), bytes.end());
}

BOOST_AUTO_TEST_CASE(serialized_storage) {
    // A CTransaction stores its inputs and outputs in one allocation, followed
    // by the bytes of the scripts too long for CScript's inline buffer, which
    // they borrow. Every way of building one must agree with the
    // std::vector-based CMutableTransaction.
    FastRandomContext rng{/*fDeterministic=*/true};
    // Script sizes on both sides of CScript's inline capacity.
    const size_t script_sizes[] = {0, 1, CScriptBase::STATIC_SIZE,
                                   CScriptBase::STATIC_SIZE + 1, 107, 600};
    for (size_t n_in = 0; n_in <= 3; ++n_in) {
        for (size_t n_out = 0; n_out <= 4; ++n_out) {
            CMutableTransaction mtx;
            mtx.nVersion = rng.rand32();
            mtx.nLockTime = rng.rand32();
            for (size_t i = 0; i < n_in; ++i) {
                const auto size = script_sizes[rng.randrange(6)];
                mtx.vin.emplace_back(TxId{rng.rand256()}, rng.rand32(),
                                     RawScript(rng.randbytes(size)),
                                     rng.rand32());
            }
            for (size_t i = 0; i < n_out; ++i) {
                const auto size = script_sizes[rng.randrange(6)];
                mtx.vout.emplace_back(int64_t(rng.rand32()) * SATOSHI,
                                      RawScript(rng.randbytes(size)));
            }
            DataStream expected{};
            expected << mtx;
            const std::string expected_hex = HexStr(expected);

            DataStream ss1{expected};
            DataStream ss2{expected};
            CTransactionRef deserialized_ref;
            ss1 >> deserialized_ref;
            const CTransaction deserialized{deserialize, ss2};
            const CTransaction converted{mtx};
            const CTransactionRef ref = MakeTransactionRef(mtx);
            for (const CTransaction *tx :
                 {ref.get(), deserialized_ref.get(), &converted,
                  &deserialized}) {
                DataStream actual{};
                actual << *tx;
                BOOST_CHECK_EQUAL(HexStr(actual), expected_hex);
                BOOST_CHECK_EQUAL(tx->GetTotalSize(), expected.size());
                BOOST_CHECK_EQUAL(::GetSerializeSize(*tx), expected.size());
                BOOST_CHECK(tx->GetId() == mtx.GetId());
                BOOST_CHECK(tx->nVersion == mtx.nVersion);
                BOOST_CHECK(tx->nLockTime == mtx.nLockTime);
                BOOST_CHECK(CMutableTransaction{*tx}.vin == mtx.vin);
                BOOST_CHECK(CMutableTransaction{*tx}.vout == mtx.vout);
                BOOST_CHECK_EQUAL(RecursiveDynamicUsage(*tx),
                                  tx->GetStorageSize());

                // Long scripts point into the script bytes that follow the
                // outputs in the transaction's storage, and report no memory
                // of their own; short ones are stored inline.
                const auto *storage =
                    reinterpret_cast<const uint8_t *>(tx->vin.data());
                const auto *scripts = reinterpret_cast<const uint8_t *>(
                    tx->vout.data() + tx->vout.size());
                auto borrows = [&](const CScript &script) {
                    return script.data() >= scripts &&
                           script.data() + script.size() <=
                               storage + tx->GetStorageSize();
                };
                for (const CTxIn &in : tx->vin) {
                    BOOST_CHECK_EQUAL(borrows(in.scriptSig),
                                      in.scriptSig.size() >
                                          CScriptBase::STATIC_SIZE);
                    BOOST_CHECK_EQUAL(RecursiveDynamicUsage(in), 0U);
                }
                for (const CTxOut &out : tx->vout) {
                    BOOST_CHECK_EQUAL(borrows(out.scriptPubKey),
                                      out.scriptPubKey.size() >
                                          CScriptBase::STATIC_SIZE);
                    BOOST_CHECK_EQUAL(RecursiveDynamicUsage(out), 0U);
                }

                // Copies of inputs and outputs own their scripts.
                for (const CTxIn &in : tx->vin) {
                    CTxIn copy{in};
                    BOOST_CHECK(!borrows(copy.scriptSig));
                    copy.scriptSig << OP_TRUE;
                    BOOST_CHECK(copy.scriptSig.size() == in.scriptSig.size() + 1);
                }
                for (const CTxOut &out : tx->vout) {
                    CTxOut copy{out};
                    BOOST_CHECK(copy == out);
                    BOOST_CHECK(!borrows(copy.scriptPubKey));
                }
            }
            // Mutating the copies left the shared transaction unchanged.
            DataStream after{};
            after << *ref;
            BOOST_CHECK_EQUAL(HexStr(after), expected_hex);
        }
    }
}

BOOST_AUTO_TEST_CASE(serialized_storage_rejects_like_mutable) {
    // Reading a CTransaction must accept and reject exactly the inputs that
    // CMutableTransaction deserialization does.
    FastRandomContext rng{/*fDeterministic=*/true};
    CMutableTransaction mtx;
    mtx.vin.emplace_back(TxId{rng.rand256()}, 7, RawScript(rng.randbytes(107)));
    mtx.vin.emplace_back(TxId{rng.rand256()}, 1, RawScript(rng.randbytes(3)));
    mtx.vout.emplace_back(10 * SATOSHI, RawScript(rng.randbytes(25)));
    mtx.vout.emplace_back(20 * SATOSHI, RawScript(rng.randbytes(40)));
    DataStream full{};
    full << mtx;
    const std::vector<uint8_t> bytes(UCharCast(full.data()),
                                     UCharCast(full.data()) + full.size());

    auto check = [](const std::vector<uint8_t> &data) {
        bool mutable_ok = true;
        size_t mutable_left = 0;
        try {
            SpanReader reader{data};
            CMutableTransaction m{deserialize, reader};
            mutable_left = reader.size();
        } catch (const std::ios_base::failure &) {
            mutable_ok = false;
        }
        // Scanned in place (SpanReader, DataStream) and copied through the
        // scratch buffer (any other stream).
        auto read_ref = [&](auto &stream) {
            bool ok = true;
            size_t left = 0;
            try {
                CTransactionRef ref;
                stream >> ref;
                left = stream.size();
            } catch (const std::ios_base::failure &) {
                ok = false;
            }
            BOOST_CHECK_EQUAL(mutable_ok, ok);
            if (ok) {
                BOOST_CHECK_EQUAL(mutable_left, left);
            }
        };
        SpanReader span_reader{data};
        DataStream data_stream{data};
        SequentialReader sequential_reader{data};
        read_ref(span_reader);
        read_ref(data_stream);
        read_ref(sequential_reader);
    };
    // Every truncation, and trailing data.
    for (size_t len = 0; len <= bytes.size(); ++len) {
        check({bytes.begin(), bytes.begin() + len});
    }
    std::vector<uint8_t> trailing{bytes};
    trailing.push_back(0x42);
    check(trailing);
    // A non-canonical input count (0xfd followed by 2 bytes encoding 2).
    std::vector<uint8_t> non_canonical{bytes.begin(), bytes.begin() + 4};
    non_canonical.insert(non_canonical.end(), {0xfd, 0x02, 0x00});
    non_canonical.insert(non_canonical.end(), bytes.begin() + 5, bytes.end());
    check(non_canonical);
    // A script length far beyond the remaining data.
    std::vector<uint8_t> huge_script{bytes.begin(), bytes.begin() + 41};
    huge_script.insert(huge_script.end(), {0xfe, 0x00, 0x00, 0x00, 0x01});
    check(huge_script);
}

BOOST_AUTO_TEST_CASE(contiguous_streams_are_read_in_place) {
    // Bytes of a contiguous stream go straight into the transaction storage;
    // only other streams pass through the per-thread scratch buffer.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(TxId{uint256::ONE}, 0,
                         RawScript(std::vector<uint8_t>(107, 1)));
    mtx.vout.emplace_back(SATOSHI, RawScript(std::vector<uint8_t>(25, 2)));
    DataStream serialized{};
    serialized << mtx << uint8_t{0x42};
    const std::vector<uint8_t> bytes(UCharCast(serialized.data()),
                                     UCharCast(serialized.data()) +
                                         serialized.size());

    std::vector<uint8_t> &scratch = TransactionScratchBuffer();
    const std::vector<uint8_t> sentinel(8, 0xee);
    auto check = [&](auto &stream, bool in_place) {
        scratch = sentinel;
        CTransactionRef ref;
        stream >> ref;
        BOOST_CHECK(ref->GetId() == mtx.GetId());
        // Exactly the transaction was consumed.
        BOOST_CHECK_EQUAL(stream.size(), 1U);
        BOOST_CHECK_EQUAL(scratch == sentinel, in_place);
        // The long script was copied out of the stream's bytes.
        const uint8_t *script = ref->vin[0].scriptSig.data();
        BOOST_CHECK(script < bytes.data() ||
                    script >= bytes.data() + bytes.size());
    };
    SpanReader span_reader{bytes};
    DataStream data_stream{bytes};
    SequentialReader sequential_reader{bytes};
    check(span_reader, /*in_place=*/true);
    check(data_stream, /*in_place=*/true);
    check(sequential_reader, /*in_place=*/false);

    // The deserializing constructor takes the same path.
    SpanReader reader{bytes};
    scratch = sentinel;
    const CTransaction tx{deserialize, reader};
    BOOST_CHECK(tx.GetId() == mtx.GetId());
    BOOST_CHECK_EQUAL(reader.size(), 1U);
    BOOST_CHECK(scratch == sentinel);
}

BOOST_AUTO_TEST_SUITE_END()
