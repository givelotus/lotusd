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

#include <test/data/sighash_lotus.json.h>
#include <test/jsonutil.h>
#include <test/lcg.h>
#include <test/scriptflags.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

BOOST_FIXTURE_TEST_SUITE(sighash_lotus_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(precompute_lotus_sighash) {
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
    txTo.vout.resize(3);
    txTo.vout[0].scriptPubKey = CScript() << OP_3;
    txTo.vout[0].nValue = 3000 * SATOSHI;
    txTo.vout[1].scriptPubKey = CScript() << OP_4;
    txTo.vout[1].nValue = 4000 * SATOSHI;
    txTo.vout[2].scriptPubKey = CScript() << OP_5;
    txTo.vout[2].nValue = 5000 * SATOSHI;

    BOOST_CHECK_EQUAL(txFrom.GetId(),
                      uint256S("28990ad4de25dd2c1c20a4321081e7d72fb7de80fd9d7cd"
                               "2345d17691626d140"));

    PrecomputedTransactionData txdata(txTo, std::move(txFrom.vout));

    BOOST_CHECK_EQUAL(txdata.hashPrevouts,
                      uint256S("91737a8b58112c5bb792245e22700f22c88fa84944ff46c"
                               "5cae3fd522f5da68e"));
    BOOST_CHECK_EQUAL(txdata.hashSequence,
                      uint256S("b805fcb22768d3701b2fb60a55b5a5d7122bfdb2ba3d313"
                               "40c6e2bf17d425e98"));
    BOOST_CHECK_EQUAL(txdata.hashOutputs,
                      uint256S("b351743e5d8984941a46ec73b2cbbc41ee858abae9928ce"
                               "2c52d52fdc567a50c"));

    BOOST_CHECK_EQUAL(txdata.m_inputs_merkle_root,
                      uint256S("8b516e759e1628a4bd02743d3006e042e25dbf98d4f4ebc"
                               "1042fde7d6660542a"));
    BOOST_CHECK_EQUAL(txdata.m_inputs_spent_outputs_merkle_root,
                      uint256S("2c87544fb644b4ee6e955738e5e1feca7019890859314b0"
                               "4da0526b47d22aa73"));
    BOOST_CHECK_EQUAL(txdata.m_inputs_merkle_height, 2);
    BOOST_CHECK_EQUAL(txdata.m_outputs_merkle_root,
                      uint256S("9b14ae09281d70dc35243ade1ad172fc9e16b726990f173"
                               "cad905ed7da83780f"));
    BOOST_CHECK_EQUAL(txdata.m_outputs_merkle_height, 3);
    BOOST_CHECK_EQUAL(txdata.m_amount_inputs_sum, 3000 * SATOSHI);
    BOOST_CHECK_EQUAL(txdata.m_amount_outputs_sum, 12000 * SATOSHI);

    CHashWriter hasher_txid(SER_GETHASH, 0);
    hasher_txid << txTo.nVersion;
    hasher_txid << txdata.m_inputs_merkle_root;
    hasher_txid << uint8_t(txdata.m_inputs_merkle_height);
    hasher_txid << txdata.m_outputs_merkle_root;
    hasher_txid << uint8_t(txdata.m_outputs_merkle_height);
    hasher_txid << txTo.nLockTime;
    BOOST_CHECK_EQUAL(txTo.GetId(), hasher_txid.GetHash());
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

// Test that SIGHASH_LOTUS can only be used with SIGHASH_FORKID
BOOST_AUTO_TEST_CASE(lotus_sighash_only_with_fork_id) {
    SigHashType sigHashType = SigHashType(0x21);
    BOOST_CHECK(!sigHashType.isDefined());
    BOOST_CHECK(!SigHashType(SIGHASH_RESERVED).isDefined());
    BOOST_CHECK(!sigHashType.withAnyoneCanPay().isDefined());
    BOOST_CHECK(!sigHashType.withBaseType(BaseSigHashType::NONE).isDefined());
    BOOST_CHECK(!sigHashType.withBaseType(BaseSigHashType::SINGLE).isDefined());
    BOOST_CHECK(!SigHashType(SIGHASH_LOTUS).isDefined());
    BOOST_CHECK(!SigHashType(SIGHASH_FORKID).isDefined());
    // withForkId resets the other bit in SIGHASH_TYPE_MASK
    BOOST_CHECK(sigHashType.withForkId().isDefined());
    BOOST_CHECK(sigHashType.withAlgorithm(SIGHASH_LEGACY).isDefined());
    BOOST_CHECK(sigHashType.withAlgorithm(SIGHASH_LEGACY)
                    .withAnyoneCanPay()
                    .isDefined());
}

BOOST_AUTO_TEST_CASE(lotus_sighash_invalid_hash_type) {
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(1);
    const PrecomputedTransactionData txdata(tx, {CTxOut()});
    const ScriptExecutionData execdata{CScript()};
    uint256 sighash;

    MMIXLinearCongruentialGenerator lcg;
    for (uint32_t sig_bits = 0; sig_bits <= 0xff; ++sig_bits) {
        SigHashType sig_hash_type{(lcg.next() << 8) | sig_bits};
        bool is_valid = !sig_hash_type.isReserved();
        // Invalid bits make SignatureHash using Lotus fail
        if (sig_hash_type.hasLotus() &&
            (!(sig_bits & 0x03) || (sig_hash_type.getUnusedBits()))) {
            // hash_type 0 is invalid, any usused bits are invalid
            is_valid = false;
        }
        const bool success = SignatureHash(
            sighash, execdata, CScript(), tx, 0, sig_hash_type, Amount::zero(),
            &txdata, SCRIPT_ENABLE_SIGHASH_FORKID);
        BOOST_CHECK_EQUAL(is_valid, success);
        if (is_valid != success) {
            BOOST_ERROR("Unexpected result for hash type: "
                        << std::hex << sig_hash_type.getRawSigHashType());
        }
    }
}

void GetPreimageHexRecursive(std::string &sighash_preimage_hex,
                             const UniValue &part) {
    if (part.isArray()) {
        std::string inner_preimage_hex;
        for (size_t i = 0; i < part.size(); ++i) {
            GetPreimageHexRecursive(inner_preimage_hex, part[i]);
        }
        std::vector<uint8_t> inner_preimage = ParseHex(inner_preimage_hex);
        uint256 hash;
        CHash256()
            .Write({inner_preimage.data(), inner_preimage.size()})
            .Finalize(hash);
        sighash_preimage_hex += HexStr(hash);
    } else {
        sighash_preimage_hex += part.get_str();
    }
}

BOOST_AUTO_TEST_CASE(lotus_sighash_from_data) {
    UniValue tests = read_json(std::string(
        json_tests::sighash_lotus,
        json_tests::sighash_lotus + sizeof(json_tests::sighash_lotus)));

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
            try {
                GetPreimageHexRecursive(sighash_preimage_hex,
                                        preimage_parts[part_idx]);
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

        uint256 expected_sighash;
        CHash256()
            .Write({sighash_preimage.data(), sighash_preimage.size()})
            .Finalize(expected_sighash);

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
