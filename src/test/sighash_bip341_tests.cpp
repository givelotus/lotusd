// Copyright (c) 2012-2019 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <core_io.h>
#include <hash.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/standard.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <test/data/sighash_bip341.json.h>
#include <test/jsonutil.h>
#include <test/lcg.h>
#include <test/scriptflags.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

BOOST_FIXTURE_TEST_SUITE(sighash_bip341_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(prepare_spent_outputs) {
    LOCK(cs_main);
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);

    CMutableTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_1));
    txFrom.vout[0].nValue = 1000 * SATOSHI;

    AddCoins(coins, CTransaction(txFrom), 0);

    CMutableTransaction txTo;
    txTo.vin.resize(1);
    txTo.vin[0].prevout = COutPoint(txFrom.GetId(), 0);
    txTo.vout.resize(1);
    txTo.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_2));
    txTo.vout[0].nValue = 3000 * SATOSHI;

    PrecomputedTransactionData txdata =
        PrecomputedTransactionData::FromCoinsView(txTo, coins);
    BOOST_CHECK(txdata.m_spent_outputs == txFrom.vout);
}

BOOST_AUTO_TEST_CASE(precompute_bip341_hashes) {
    CMutableTransaction txFrom;
    txFrom.vout.resize(2);
    txFrom.vout[0] = CTxOut{1000 * SATOSHI, CScript() << OP_1};
    txFrom.vout[1] = CTxOut{2000 * SATOSHI, CScript() << OP_2};
    CMutableTransaction txTo;
    txTo.vin.resize(2);
    txTo.vin[0].prevout = COutPoint(txFrom.GetId(), 0);
    txTo.vin[0].nSequence = 0xffff'fffe;
    txTo.vin[1].prevout = COutPoint(txFrom.GetId(), 1);
    txTo.vin[1].nSequence = 0xffff'ffff;
    txTo.vout.resize(1);
    txTo.vout[0].scriptPubKey = CScript() << OP_3;
    txTo.vout[0].nValue = 3000 * SATOSHI;

    BOOST_CHECK_EQUAL(txFrom.GetId(),
                      uint256S("b691de70195fab2d9ca4f3600657439eb7892d9d593766e"
                               "3ed4d0e85da2c1c85"));

    PrecomputedTransactionData txdata(txTo, std::move(txFrom.vout));

    BOOST_CHECK_EQUAL(txdata.m_prevouts_single_hash,
                      uint256S("a7665bc0836a487c6c35b9745ce48d9a4d249336989451b"
                               "604f9b741c1b3ee50"));
    BOOST_CHECK_EQUAL(txdata.m_sequences_single_hash,
                      uint256S("01282d1aeed227f3c168067a934f754805702a15317106e"
                               "b2f76788b7f7fb381"));
    BOOST_CHECK_EQUAL(txdata.m_outputs_single_hash,
                      uint256S("01e2054d5e24f0163cb2862cca70d36ca9f2b1f1f3ee6bc"
                               "7e32118f150e5ebae"));

    BOOST_CHECK_EQUAL(txdata.hashPrevouts,
                      uint256S("4b665423628c1d0365c6bb55123f0132384b4c019f1cf3d"
                               "1ed1c34400b36f432"));
    BOOST_CHECK_EQUAL(txdata.hashPrevouts,
                      SHA256Uint256(txdata.m_prevouts_single_hash));

    BOOST_CHECK_EQUAL(txdata.hashSequence,
                      uint256S("b805fcb22768d3701b2fb60a55b5a5d7122bfdb2ba3d313"
                               "40c6e2bf17d425e98"));
    BOOST_CHECK_EQUAL(txdata.hashSequence,
                      SHA256Uint256(txdata.m_sequences_single_hash));

    BOOST_CHECK_EQUAL(txdata.hashOutputs,
                      uint256S("bbfa4eda7307e5de2aaeccb963beb427f51e9a3d4912ad2"
                               "ac9e1dc5f3407d4dc"));
    BOOST_CHECK_EQUAL(txdata.hashOutputs,
                      SHA256Uint256(txdata.m_outputs_single_hash));

    BOOST_CHECK_EQUAL(txdata.m_spent_amounts_single_hash,
                      uint256S("a6ad32a03e35d509baa268e437ea28289d6d07529c6efd8"
                               "f1f7ced8ef2aba365"));
    BOOST_CHECK_EQUAL(txdata.m_spent_scripts_single_hash,
                      uint256S("abf93a5b45ba5cda5b1eb8bf2272c060127d390a6e020ba"
                               "a5345b6977e89ea3c"));
}

static const std::vector<uint32_t> allflags{
    SCRIPT_VERIFY_NONE,
    STANDARD_SCRIPT_VERIFY_FLAGS,
};

void CheckCodesepPos(const CScript &script,
                     const uint32_t expected_codesep_pos) {
    for (uint32_t flags : allflags) {
        BaseSignatureChecker sigchecker;
        ScriptExecutionMetrics metrics = {};
        ScriptExecutionData execdata{CScript()};
        stacktype stack = {};
        bool r =
            EvalScript(stack, script, flags, sigchecker, metrics, execdata);
        BOOST_CHECK(r);
        BOOST_CHECK_EQUAL(execdata.m_codeseparator_pos, expected_codesep_pos);
        BOOST_CHECK_MESSAGE(execdata.m_codeseparator_pos ==
                                expected_codesep_pos,
                            "For script '" << ScriptToAsmStr(script) << "'");
    }
}

BOOST_AUTO_TEST_CASE(script_execution_data) {
    valtype data10(10);
    valtype data520(520);
    // Test unconditional cases
    CheckCodesepPos(CScript() << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << data10 << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << data520 << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << OP_CODESEPARATOR << data10 << OP_1, 0);
    CheckCodesepPos(CScript() << OP_CODESEPARATOR << data520 << OP_1, 0);
    CheckCodesepPos(CScript() << data520 << OP_CODESEPARATOR << OP_1, 1);
    CheckCodesepPos(CScript() << data10 << OP_CODESEPARATOR << OP_1, 1);
    CheckCodesepPos(CScript() << data520 << OP_1 << OP_CODESEPARATOR, 2);
    CheckCodesepPos(CScript() << data520 << data10 << OP_1 << OP_CODESEPARATOR,
                    3);
    CheckCodesepPos(CScript() << data520 << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                              << OP_NOP << OP_CODESEPARATOR,
                    6);

    // Test conditional cases
    CheckCodesepPos(CScript() << 0 << OP_IF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript() << 1 << OP_IF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    3);
    CheckCodesepPos(CScript() << 0 << OP_NOTIF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    3);
    CheckCodesepPos(CScript() << 1 << OP_NOTIF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript()
                        << 1 << 1 << 1 << OP_IF << OP_IF << OP_IF
                        << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF << OP_ENDIF,
                    6);
    CheckCodesepPos(CScript()
                        << 1 << 0 << 1 << OP_IF << OP_IF << OP_IF
                        << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript() << 1 << 0 << 1 << OP_IF << OP_IF << OP_IF
                              << OP_CODESEPARATOR << OP_ENDIF << OP_ELSE
                              << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF,
                    9);
    CheckCodesepPos(CScript() << 1 << 0 << 1 << OP_IF << OP_CODESEPARATOR
                              << OP_IF << OP_IF << OP_CODESEPARATOR << OP_ENDIF
                              << OP_ELSE << OP_CODESEPARATOR << OP_ENDIF
                              << OP_ELSE << OP_CODESEPARATOR << OP_ENDIF,
                    10);
}

// Test that SIGHASH_BIP341 can only be used with SIGHASH_FORKID
BOOST_AUTO_TEST_CASE(bip341_only_with_fork_id) {
    SigHashType sigHashType = SigHashType(0x21);
    BOOST_CHECK(!sigHashType.isDefined());
    BOOST_CHECK(!SigHashType(0x20).isDefined()); // SIGHASH_BUG
    BOOST_CHECK(!sigHashType.withAnyoneCanPay().isDefined());
    BOOST_CHECK(!sigHashType.withBaseType(BaseSigHashType::NONE).isDefined());
    BOOST_CHECK(!sigHashType.withBaseType(BaseSigHashType::SINGLE).isDefined());
    BOOST_CHECK(!SigHashType(SIGHASH_BIP341).isDefined());
    BOOST_CHECK(!SigHashType(SIGHASH_FORKID).isDefined());
    // withForkId resets the other bit in SIGHASH_TYPE_MASK
    BOOST_CHECK(sigHashType.withForkId().isDefined());
    BOOST_CHECK(sigHashType.withForkId(false).isDefined());
    BOOST_CHECK(sigHashType.withForkId(false).withAnyoneCanPay().isDefined());
}

BOOST_AUTO_TEST_CASE(bip341_invalid_hash_type) {
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(1);
    const PrecomputedTransactionData txdata(tx, {CTxOut()});
    const ScriptExecutionData execdata{CScript()};
    uint256 sighash;

    MMIXLinearCongruentialGenerator lcg;
    for (uint32_t sig_bits = 0; sig_bits <= 0xff; ++sig_bits) {
        uint32_t hash_type = (lcg.next() << 8) | sig_bits;
        // 0x20 is a reserved sig hash type
        bool is_valid = (hash_type & SIGHASH_TYPE_MASK) != 0x20;
        // Invalid bits make SignatureHash using BIP341 fail
        if ((hash_type & SIGHASH_TYPE_MASK) == SIGHASH_BIP341 &&
            (!(hash_type & 0x03) || (hash_type & 0x1c))) {
            // hash_type 0 is invalid, any undefined bits are invalid
            is_valid = false;
        }
        const bool success = SignatureHash(
            sighash, execdata, CScript(), tx, 0, SigHashType(hash_type),
            Amount::zero(), &txdata, SCRIPT_ENABLE_SIGHASH_FORKID);
        BOOST_CHECK_EQUAL(is_valid, success);
        if (is_valid != success) {
            BOOST_ERROR("Unexpected result for hash type: " << std::hex
                                                            << hash_type);
        }
    }
}

BOOST_AUTO_TEST_CASE(bip341_sighash_from_data) {
    UniValue tests = read_json(std::string(
        json_tests::sighash_bip341,
        json_tests::sighash_bip341 + sizeof(json_tests::sighash_bip341)));

    for (size_t idx = 0; idx < tests.size(); idx++) {
        CTransactionRef tx;
        std::vector<CTxOut> spent_outputs;
        SigHashType sig_hash_type;
        uint32_t input_idx;
        uint32_t codeseparator_pos;
        uint32_t script_flags;
        std::vector<uint8_t> sighash_preimage;
        bool expect_success = true;

        const UniValue &test = tests[idx];
        std::string str_test = test.write();
        if (test.size() < 4) {
            continue;
        }

        std::string raw_tx;
        const UniValue tx_parts = test[0];
        for (size_t part_idx = 0; part_idx < tx_parts.size(); ++part_idx) {
            raw_tx += tx_parts[part_idx].get_str();
        }
        try {
            CDataStream stream(ParseHex(raw_tx), SER_NETWORK, PROTOCOL_VERSION);
            stream >> tx;
        } catch (...) {
            BOOST_ERROR("Invalid spent output: " << raw_tx);
            BOOST_ERROR("Test: " << str_test);
            continue;
        }

        const UniValue &spent_outputs_list = test[1];
        spent_outputs.resize(spent_outputs_list.size());
        for (size_t output_idx = 0; output_idx < spent_outputs_list.size();
             ++output_idx) {
            const UniValue &output = spent_outputs_list[output_idx];
            spent_outputs[output_idx].nValue = output[0].get_int64() * SATOSHI;
            try {
                spent_outputs[output_idx].scriptPubKey =
                    ParseScript(output[1].get_str());
            } catch (...) {
                BOOST_ERROR("Invalid spent output: " << output[1].write());
                BOOST_ERROR("Test: " << str_test);
                return;
            }
        }

        try {
            sig_hash_type = ParseSighashString(test[2].get_str());
        } catch (...) {
            BOOST_ERROR("Invalid sig_hash_type: " << test[2].write());
            BOOST_ERROR("Test: " << str_test);
            continue;
        }
        try {
            input_idx = test[3].get_int();
        } catch (...) {
            BOOST_ERROR("Invalid input_idx: " << test[3].write());
            BOOST_ERROR("Test: " << str_test);
            continue;
        }
        try {
            codeseparator_pos = test[4].get_int64();
        } catch (...) {
            BOOST_ERROR("Invalid codeseparator_pos: " << test[4].write());
            BOOST_ERROR("Test: " << str_test);
            continue;
        }
        try {
            script_flags = ParseScriptFlags(test[5].get_str());
        } catch (...) {
            BOOST_ERROR("Invalid script_flags: " << test[5].write());
            BOOST_ERROR("Test: " << str_test);
            continue;
        }

        std::string sighash_preimage_hex;
        const UniValue &preimage_parts = test[6];
        for (size_t part_idx = 0; part_idx < preimage_parts.size();
             ++part_idx) {
            const UniValue &part = preimage_parts[part_idx];
            try {
                if (part.isArray()) {
                    std::vector<uint8_t> preimage;
                    for (size_t i = 0; i < part.size(); ++i) {
                        std::vector<uint8_t> preimage_part =
                            ParseHex(part[i].get_str());
                        preimage.insert(preimage.end(), preimage_part.begin(),
                                        preimage_part.end());
                    }
                    uint256 hash;
                    CSHA256()
                        .Write(preimage.data(), preimage.size())
                        .Finalize(hash.begin());
                    sighash_preimage_hex += HexStr(hash);
                } else {
                    sighash_preimage_hex += part.get_str();
                }
            } catch (...) {
                BOOST_ERROR("Invalid sighash preimage: " << test[6].write());
                BOOST_ERROR("Test: " << str_test);
                return;
            }
        }
        if (sighash_preimage_hex == "failure") {
            expect_success = false;
        } else {
            sighash_preimage = ParseHex(sighash_preimage_hex);
        }

        BOOST_CHECK_EQUAL(spent_outputs.size(), tx->vin.size());
        if (spent_outputs.size() != tx->vin.size()) {
            BOOST_ERROR("Test: " << str_test);
            continue;
        }

        const uint256 taghash = uint256S(
            "31a0e428c697752387eb13a366fd953ded614665f24b92b4c8702a4bdf480af4");
        std::vector<uint8_t> data;
        data.reserve(taghash.size() * 2 + sighash_preimage.size());
        data.insert(data.end(), taghash.begin(), taghash.end());
        data.insert(data.end(), taghash.begin(), taghash.end());
        data.insert(data.end(), sighash_preimage.begin(),
                    sighash_preimage.end());
        uint256 expected_sighash;
        CSHA256()
            .Write(data.data(), data.size())
            .Finalize(expected_sighash.begin());

        const CTxOut &utxo = spent_outputs[input_idx];
        const ScriptExecutionData execdata(utxo.scriptPubKey,
                                           codeseparator_pos);
        const PrecomputedTransactionData txdata{*tx,
                                                std::vector(spent_outputs)};
        uint256 actual_sighash;
        const bool success = SignatureHash(
            actual_sighash, execdata, utxo.scriptPubKey, *tx, input_idx,
            sig_hash_type, utxo.nValue, &txdata, script_flags);
        if (expect_success) {
            BOOST_CHECK(success);
            BOOST_CHECK_EQUAL(expected_sighash, actual_sighash);
        } else {
            BOOST_CHECK(!success);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
