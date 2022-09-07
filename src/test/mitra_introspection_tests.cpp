// Copyright (c) 2012-2019 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>

#include <test/lcg.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <core_io.h>

BOOST_FIXTURE_TEST_SUITE(mitra_introspection_tests, BasicTestingSetup)

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;
std::array<uint32_t, 1> flagset{
    {STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_MITRA}};

static void CheckSuccess(const CMutableTransaction &tx, uint32_t inputIdx,
                         const CScript &script) {
    PrecomputedTransactionData txdata;
    MutableTransactionSignatureChecker sigchecker(&tx, inputIdx, Amount::zero(),
                                                  txdata);
    for (uint32_t flags : flagset) {
        ScriptError err = ScriptError::OK;
        stacktype stack{};
        bool r = EvalScript(stack, script, flags, sigchecker, &err);
        BOOST_CHECK_MESSAGE(r, "Expected OK but got "
                                   << ScriptErrorString(err) << " for '"
                                   << ScriptToAsmStr(script) << "'");
        BOOST_CHECK_EQUAL(stack.size(), 0);
    }
}

BOOST_AUTO_TEST_CASE(introspection_opcodes) {
    CMutableTransaction txbase;
    txbase.nVersion = TX_VERSION_MITRA;
    CheckSuccess(txbase, 0,
                 CScript() << OP_NUMPREAMBLES << OP_0 << OP_EQUALVERIFY);
    CheckSuccess(txbase, 0,
                 CScript() << OP_NUMINPUTS << OP_0 << OP_EQUALVERIFY);
    CheckSuccess(txbase, 0,
                 CScript() << OP_NUMOUTPUTS << OP_0 << OP_EQUALVERIFY);
    CheckSuccess(txbase, 0,
                 CScript() << OP_THISINDEX << OP_0 << OP_EQUALVERIFY);
    CheckSuccess(txbase, 1,
                 CScript() << OP_THISINDEX << OP_1 << OP_EQUALVERIFY);
    {
        CMutableTransaction tx(txbase);
        tx.preambles.resize(1);
        CheckSuccess(tx, 0,
                     CScript() << OP_NUMPREAMBLES << OP_1 << OP_EQUALVERIFY);
    }
    {
        CMutableTransaction tx(txbase);
        tx.vin.resize(1);
        CheckSuccess(tx, 0,
                     CScript() << OP_NUMINPUTS << OP_1 << OP_EQUALVERIFY);
    }
    {
        CMutableTransaction tx(txbase);
        tx.vout.resize(1);
        CheckSuccess(tx, 0,
                     CScript() << OP_NUMOUTPUTS << OP_1 << OP_EQUALVERIFY);
    }
    {
        CMutableTransaction tx(txbase);
        tx.preambles.push_back(CTxPreamble(CScript() << OP_1, {}, {}));
        CheckSuccess(tx, 0,
                     CScript() << OP_0 << OP_PICKPREAMBLEHASH << ParseHex("51")
                               << OP_HASH256 << OP_EQUALVERIFY);
    }
    {
        std::vector<uint8_t> inputraw = ParseHex(
            // txid
            "1122334455667788990011223344556677889900112233445566778899001122"
            // vout
            "01000000"
            // sequence
            "ffffffff"
            // amount
            "0102030405000000"
            // scriptPubKey
            "03515253"
            // carryover
            "0411223344"
            // preamble merkle root
            "01"
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
            // witnesses
            "00"
            // loops
            "00");
        CDataStream stream(inputraw, SER_NETWORK, PROTOCOL_VERSION);
        CTxIn input;
        stream >> Using<CTxInMitraFormatter>(input);
        CMutableTransaction tx(txbase);
        tx.vin.push_back(input);
        CheckSuccess(tx, 0,
                     CScript()
                         << OP_0 << OP_PICKINPUTOUTPOINT
                         << ParseHex("11223344556677889900112233445566778899001"
                                     "1223344556677889900112201000000")
                         << OP_EQUALVERIFY);
        CheckSuccess(tx, 0,
                     CScript() << OP_0 << OP_PICKINPUTVALUE << 0x0504030201
                               << OP_EQUALVERIFY);
        CheckSuccess(tx, 0,
                     CScript() << OP_0 << OP_PICKINPUTSCRIPTPUBKEY
                               << ParseHex("515253") << OP_EQUALVERIFY);
        CheckSuccess(tx, 0,
                     CScript() << OP_0 << OP_PICKINPUTCARRYOVER
                               << ParseHex("11223344") << OP_EQUALVERIFY);
        CheckSuccess(tx, 0,
                     CScript() << OP_0 << OP_PICKINPUTPREAMBLEMERKLEROOT
                               << ParseHex("000102030405060708090a0b0c0d0e0f000"
                                           "102030405060708090a0b0c0d0e0f")
                               << OP_EQUALVERIFY);
    }
    {
        std::vector<uint8_t> outputraw = ParseHex(
            // amount
            "0102030405000000"
            // scriptPubKey
            "03515253"
            // carryover
            "0411223344");
        CDataStream stream(outputraw, SER_NETWORK, PROTOCOL_VERSION);
        CTxOut output;
        stream >> Using<CTxOutMitraFormatter>(output);
        CMutableTransaction tx(txbase);
        tx.vout.push_back(output);
        CheckSuccess(tx, 0,
                     CScript() << OP_0 << OP_PICKOUTPUTVALUE << 0x0504030201
                               << OP_EQUALVERIFY);
        CheckSuccess(tx, 0,
                     CScript() << OP_0 << OP_PICKOUTPUTSCRIPTPUBKEY
                               << ParseHex("515253") << OP_EQUALVERIFY);
        CheckSuccess(tx, 0,
                     CScript() << OP_0 << OP_PICKOUTPUTCARRYOVER
                               << ParseHex("11223344") << OP_EQUALVERIFY);
    }
}

BOOST_AUTO_TEST_SUITE_END()
