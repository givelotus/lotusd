// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/sigencoding.h>
#include <script/taproot.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

BOOST_FIXTURE_TEST_SUITE(taproot_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(taproot_cpubkey_add_scalar) {
    valtype vch_base, vch_tweaked;
    uint256 tweak;
    CPubKey pubkey_base, pubkey_tweaked, pubkey_result;

    vch_base = ParseHex(
        "020000000000000000000000000000000000000000000000000000000000000001");
    // coincurve.PublicKey(bytes.fromhex('02' + '00'*31 + '01'))
    //     .add(bytes.fromhex('0123456789abcdef' * 4)).format().hex()
    vch_tweaked = ParseHex(
        "032e3e15ea4cf7d0c88503a3d9d514ecd63443736a5907de89ba38f1d5d00ffe41");
    tweak = uint256(ParseHex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    pubkey_base = CPubKey(vch_base.begin(), vch_base.end());
    pubkey_tweaked = CPubKey(vch_tweaked.begin(), vch_tweaked.end());
    BOOST_CHECK(pubkey_base.AddScalar(pubkey_result, tweak));
    BOOST_CHECK_EQUAL(HexStr(pubkey_result), HexStr(pubkey_tweaked));

    vch_base = ParseHex(
        "030000000000000000000000000000000000000000000000000000000000000045");
    vch_tweaked = ParseHex(
        "021c2d2372cdb3accaaeb40ea9c96392df28d00f0aa503a42bd1edef117cba333c");
    tweak = uint256(ParseHex(
        "0707070707070707070707070707070707070707070707070707070707070707"));
    pubkey_base = CPubKey(vch_base.begin(), vch_base.end());
    pubkey_tweaked = CPubKey(vch_tweaked.begin(), vch_tweaked.end());
    BOOST_CHECK(pubkey_base.AddScalar(pubkey_result, tweak));
    BOOST_CHECK_EQUAL(HexStr(pubkey_result), HexStr(pubkey_tweaked));
}

/**
 * The control blocks have been generated using these Python functions, based
 * on the Python code in BIP341:
 * ```
 * from dataclasses import dataclass
 * from typing import List, Union
 *
 * from coincurve import PrivateKey, PublicKey
 * import hashlib
 *
 * @dataclass
 * class ScriptLeaf:
 *     leaf_version: int
 *     script: bytes
 *
 * @dataclass
 * class ScriptBranch:
 *     left: Union['ScriptBranch', ScriptLeaf]
 *     right: Union['ScriptBranch', ScriptLeaf]
 *
 * @dataclass
 * class TreeResult:
 *     items: List['ResultItem']
 *     hash: bytes
 *
 * @dataclass
 * class ResultItem:
 *     leaf: ScriptLeaf
 *     path: bytes
 *
 * def tagged_hash(tag: str, data: bytes) -> bytes:
 *     tag_hash = hashlib.sha256(tag.encode()).digest()
 *     return hashlib.sha256(tag_hash + tag_hash + data).digest()
 *
 * def taproot_tweak_pubkey(pubkey: PublicKey, tweak_hash: bytes) -> PublicKey:
 *     t = tagged_hash("TapTweak", pubkey.format() + tweak_hash)
 *     return pubkey.add(t)
 *
 * def ser_script(script: bytes) -> bytes:
 *     if len(script) < 0xfd:
 *         return bytes([len(script)]) + script
 *     elif len(script) <= 0xffff:
 *         return b'\xfd' + len(script).to_bytes(2, 'little') + script
 *     else:
 *         raise ValueError('script too long')
 *
 * def taproot_tree_helper(script_tree: Union[ScriptBranch, ScriptLeaf]) -> \
 *         TreeResult:
 *     if isinstance(script_tree, ScriptLeaf):
 *         h = tagged_hash("TapLeaf", bytes([script_tree.leaf_version]) +
 *                         ser_script(script_tree.script))
 *         return TreeResult(items=[ResultItem(script_tree, bytes())], hash=h)
 *     left_result = taproot_tree_helper(script_tree.left)
 *     right_result = taproot_tree_helper(script_tree.right)
 *     ret = [ResultItem(item.leaf, item.path + right_result.hash)
 *            for item in left_result.items] + \
 *           [ResultItem(item.leaf, item.path + left_result.hash)
 *            for item in right_result.items]
 *     if right_result.hash < left_result.hash:
 *         left_hash, right_hash = right_result.hash, left_result.hash
 *     else:
 *         left_hash, right_hash = left_result.hash, right_result.hash
 *     return TreeResult(ret, tagged_hash("TapBranch", left_hash + right_hash))
 *
 * def taproot_output_script(
 *         internal_pubkey: PublicKey,
 *         script_tree: Union[None, ScriptBranch, ScriptLeaf]) -> bytes:
 *     if script_tree is None:
 *         h = bytes()
 *     else:
 *         h = taproot_tree_helper(script_tree).hash
 *     output_pubkey = taproot_tweak_pubkey(internal_pubkey, h)
 *     return bytes([]) + output_pubkey.format()
 *
 * def taproot_sign_script(internal_pubkey: PublicKey,
 *                         script_tree: Union[None, ScriptBranch, ScriptLeaf],
 *                         script_num: int,
 *                         inputs: List[bytes]) -> List[bytes]:
 *     tree_result = taproot_tree_helper(script_tree)
 *     item = tree_result.items[script_num]
 *     pubkey_ser = internal_pubkey.format()
 *     parity = int(pubkey_ser[0] == 3)
 *     pubkey_data = bytes([item.leaf.leaf_version | parity]) + pubkey_ser[1:]
 *     return inputs + [item.leaf.script, pubkey_data + item.path]
 * ```
 */
BOOST_AUTO_TEST_CASE(verify_taproot_commitment_1) {
    // Test taproot commitment for a merkle tree of only one script.
    CScript script = CScript() << 12 << 5 << OP_ADD << 17 << OP_EQUAL;
    valtype program_pubkey = ParseHex(
        "03f4d8f35fc9bd150aa9071471adaef4edbfcabc7b29c2a80b6564b0b7a06318f2");
    valtype control_block = ParseHex(
        "0079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    uint256 taproot_leaf;
    BOOST_CHECK(VerifyTaprootCommitment(taproot_leaf, control_block,
                                        program_pubkey, script));
    std::vector<uint8_t> expected_taproot_leaf = ParseHex(
        "d391a5068704b630ec4a50f2ba1e48aab89696aee831f1c4513034bc3a999165");
    BOOST_CHECK_EQUAL(taproot_leaf, uint256(expected_taproot_leaf));
}

BOOST_AUTO_TEST_CASE(verify_taproot_commitment_1_leaf_version) {
    // Test taproot commitment for a merkle tree of only one script, with leaf
    // version 0xe8.
    CScript script = CScript() << 1 << 5 << OP_ADD << 6 << OP_EQUAL;
    valtype program_pubkey = ParseHex(
        "0311197854872410770e5d13edd8277bdc2c262026dcd3089c3a7cbe1c5f564270");
    valtype control_block = ParseHex(
        "e8c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    uint256 taproot_leaf;
    BOOST_CHECK(VerifyTaprootCommitment(taproot_leaf, control_block,
                                        program_pubkey, script));
    std::vector<uint8_t> expected_taproot_leaf = ParseHex(
        "e9bcbe4f6876670fe71704fd7af6b058316b5b4dd0dbf44988078cf0d7d26971");
    BOOST_CHECK_EQUAL(taproot_leaf, uint256(expected_taproot_leaf));
}

BOOST_AUTO_TEST_CASE(verify_taproot_commitment_2) {
    // Test taproot commitment for a merkle tree of two scripts with different
    // leaf versions.
    CScript script1 = CScript() << 2 << 3 << OP_ADD << 5 << OP_EQUAL;
    CScript script2 = CScript() << 7 << 2 << OP_ADD << 9 << OP_EQUAL;
    valtype program_pubkey = ParseHex(
        "02b908223769e60046dee140a788fa96977012033adcfa8e328fa8c98fa3a3feba");
    valtype control_block1 = ParseHex(
        "fef9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9e82b"
        "65cb9d7df2c20ffc76492b0c1f11bfeafc4df63344446d3b07d3327ffce9");
    valtype control_block2 = ParseHex(
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f91cba"
        "0b8238d48ff30e70971c56553ec181d4df06262ff9345043b44df0c92506");
    uint256 taproot_leaf;
    BOOST_CHECK(VerifyTaprootCommitment(taproot_leaf, control_block1,
                                        program_pubkey, script1));
    std::vector<uint8_t> expected_taproot_leaf = ParseHex(
        "1cba0b8238d48ff30e70971c56553ec181d4df06262ff9345043b44df0c92506");
    BOOST_CHECK_EQUAL(taproot_leaf, uint256(expected_taproot_leaf));
    BOOST_CHECK(!VerifyTaprootCommitment(taproot_leaf, control_block2,
                                         program_pubkey, script1));
    BOOST_CHECK(!VerifyTaprootCommitment(taproot_leaf, control_block1,
                                         program_pubkey, script2));
    BOOST_CHECK(VerifyTaprootCommitment(taproot_leaf, control_block2,
                                        program_pubkey, script2));
    expected_taproot_leaf = ParseHex(
        "e82b65cb9d7df2c20ffc76492b0c1f11bfeafc4df63344446d3b07d3327ffce9");
    BOOST_CHECK_EQUAL(taproot_leaf, uint256(expected_taproot_leaf));
}

BOOST_AUTO_TEST_CASE(verify_taproot_commitment_3) {
    /** Test taproot commitment for this merkle tree:
     *             /\
     *            /  \
     *           /\ script3
     *          /  \
     *         /    \
     *    script1  script2
     */
    CScript script1 = CScript() << 3 << 5 << OP_ADD << 8 << OP_EQUAL;
    CScript script2 = CScript() << valtype{1, 2} << valtype{3} << OP_CAT
                                << valtype{1, 2, 3} << OP_EQUAL;
    CScript script3 = CScript() << OP_1;
    valtype program_pubkey = ParseHex(
        "0205e25701c5ba0e9549c9d3b3d68446ba0c2820cd5c6df627c4e171a8707d3197");
    valtype control_block1 = ParseHex(
        "01fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556d81a"
        "eb54b742dd72fb69749163babdba30cca1b5afd4981353810862141c6e2f8fe98416ae"
        "edc4ff4bdd55d79dd3e5399c9c2b1d2d2beea8c300c2ba262c5bbc");
    valtype control_block2 = ParseHex(
        "01fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a146029755677bf"
        "ee7828dd0847e3d62ca232f39db7d2074cb06fd8120f8564a7bd15a912b68fe98416ae"
        "edc4ff4bdd55d79dd3e5399c9c2b1d2d2beea8c300c2ba262c5bbc");
    valtype control_block3 = ParseHex(
        "01fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975567aa2"
        "675f80f547eb9dc2166a3b43dc9aabcd316d7a7e372094b2607da9a0a8eb");
    uint256 taproot_leaf;
    BOOST_CHECK(VerifyTaprootCommitment(taproot_leaf, control_block1,
                                        program_pubkey, script1));
    std::vector<uint8_t> expected_taproot_leaf = ParseHex(
        "77bfee7828dd0847e3d62ca232f39db7d2074cb06fd8120f8564a7bd15a912b6");
    BOOST_CHECK_EQUAL(taproot_leaf, uint256(expected_taproot_leaf));
    BOOST_CHECK(!VerifyTaprootCommitment(taproot_leaf, control_block2,
                                         program_pubkey, script1));
    BOOST_CHECK(!VerifyTaprootCommitment(taproot_leaf, control_block3,
                                         program_pubkey, script1));

    BOOST_CHECK(!VerifyTaprootCommitment(taproot_leaf, control_block1,
                                         program_pubkey, script2));
    BOOST_CHECK(VerifyTaprootCommitment(taproot_leaf, control_block2,
                                        program_pubkey, script2));
    expected_taproot_leaf = ParseHex(
        "d81aeb54b742dd72fb69749163babdba30cca1b5afd4981353810862141c6e2f");
    BOOST_CHECK_EQUAL(taproot_leaf, uint256(expected_taproot_leaf));
    BOOST_CHECK(!VerifyTaprootCommitment(taproot_leaf, control_block3,
                                         program_pubkey, script2));

    BOOST_CHECK(!VerifyTaprootCommitment(taproot_leaf, control_block1,
                                         program_pubkey, script3));
    BOOST_CHECK(!VerifyTaprootCommitment(taproot_leaf, control_block2,
                                         program_pubkey, script3));
    BOOST_CHECK(VerifyTaprootCommitment(taproot_leaf, control_block3,
                                        program_pubkey, script3));
    expected_taproot_leaf = ParseHex(
        "8fe98416aeedc4ff4bdd55d79dd3e5399c9c2b1d2d2beea8c300c2ba262c5bbc");
    BOOST_CHECK_EQUAL(taproot_leaf, uint256(expected_taproot_leaf));
}

BOOST_AUTO_TEST_CASE(is_p2tr) {
    BOOST_CHECK(!IsPayToTaproot(CScript() << OP_SCRIPTTYPE << OP_1));
    BOOST_CHECK(
        !IsPayToTaproot(CScript() << OP_SCRIPTTYPE << OP_1 << valtype(0)));
    BOOST_CHECK(
        !IsPayToTaproot(CScript() << OP_SCRIPTTYPE << OP_1 << valtype(32)));
    BOOST_CHECK(
        !IsPayToTaproot(CScript() << OP_SCRIPTTYPE << OP_1 << valtype(34)));
    for (uint32_t commitment_len = 0; commitment_len < 70; ++commitment_len) {
        bool is_valid_commitment = commitment_len == 33;
        BOOST_CHECK_EQUAL(is_valid_commitment,
                          IsPayToTaproot(CScript() << OP_SCRIPTTYPE << OP_1
                                                   << valtype(commitment_len)));
        for (uint32_t state_len = 0; state_len < 70; ++state_len) {
            bool is_valid_state = state_len == 32;
            BOOST_CHECK_EQUAL(is_valid_commitment && is_valid_state,
                              IsPayToTaproot(CScript()
                                             << OP_SCRIPTTYPE << OP_1
                                             << valtype(commitment_len)
                                             << valtype(state_len)));
            for (uint32_t junk_len = 0; junk_len < 70; ++junk_len) {
                BOOST_CHECK(!IsPayToTaproot(CScript() << OP_SCRIPTTYPE << OP_1
                                                      << valtype(commitment_len)
                                                      << valtype(state_len)
                                                      << valtype(junk_len)));
            }
        }
    }
}

std::array<uint32_t, 2> flagset{
    {SCRIPT_ENABLE_SIGHASH_FORKID, STANDARD_SCRIPT_VERIFY_FLAGS}};

struct TestUtxo {
    CScript script_sig;
    CScript script_pubkey;
    CScript exec_script;
    Amount amount;
    uint32_t sequence = 0xffff'ffff;
    COutPoint outpoint = COutPoint();
};

struct TestInput {
    CScript script_sig;
    CScript script_pubkey;
    CScript exec_script;
    Amount amount;
    SigHashType sig_hash_type;
    bool use_schnorr;
    bool is_key_path_spend = true;
    uint32_t sequence = 0xffff'ffff;
    COutPoint outpoint = COutPoint();
    uint32_t codeseparator_pos = 0xffff'ffff;
    TestUtxo utxo() const {
        return {
            script_sig, script_pubkey, exec_script, amount, sequence, outpoint,
        };
    }
};

void CheckTxScripts(const std::vector<TestUtxo> &inputs,
                    const std::vector<CTxOut> &outputs, const uint32_t flags,
                    const ScriptError expected_error = ScriptError::OK) {
    CMutableTransaction tx;
    std::vector<CTxOut> spent_outputs;
    for (const TestUtxo &input : inputs) {
        tx.vin.push_back(
            CTxIn(input.outpoint, input.script_sig, input.sequence));
        spent_outputs.push_back({input.amount, input.script_pubkey});
    }
    tx.vout = outputs;
    const PrecomputedTransactionData txdata(tx, std::move(spent_outputs));
    for (uint32_t i = 0; i < tx.vin.size(); ++i) {
        const MutableTransactionSignatureChecker sig_checker(
            &tx, i, inputs[i].amount, txdata);
        ScriptExecutionMetrics metrics;
        ScriptError serror;
        bool result =
            VerifyScript(inputs[i].script_sig, inputs[i].script_pubkey, flags,
                         sig_checker, metrics, &serror);
        BOOST_CHECK_EQUAL(serror, expected_error);
        std::string script_asm = ScriptToAsmStr(inputs[i].exec_script);
        if (expected_error == ScriptError::OK) {
            BOOST_CHECK_MESSAGE(result, "Script: " << script_asm);
        } else {
            BOOST_CHECK_MESSAGE(!result, "Script: " << script_asm);
        }
    }
}

std::vector<valtype> MakeSigs(const CKey &seckey,
                              const std::vector<TestInput> &inputs,
                              const std::vector<CTxOut> &outputs,
                              const uint32_t flags) {
    CMutableTransaction tx;
    std::vector<CTxOut> spent_outputs;
    for (const TestInput &input : inputs) {
        tx.vin.push_back(
            CTxIn(input.outpoint, input.script_sig, input.sequence));
        spent_outputs.push_back({input.amount, input.script_pubkey});
    }
    tx.vout = outputs;
    const PrecomputedTransactionData txdata(tx, std::move(spent_outputs));
    std::vector<valtype> sigs(inputs.size());
    for (uint32_t input_idx = 0; input_idx < inputs.size(); ++input_idx) {
        const TestInput &input = inputs[input_idx];
        std::optional<ScriptExecutionData> execdata;
        assert(input.is_key_path_spend);
        const CScript script_code = CScript();
        uint256 sighash;
        BOOST_CHECK(SignatureHash(
            sighash, execdata, script_code, tx, input_idx, input.sig_hash_type,
            txdata.m_spent_outputs[input_idx].nValue, &txdata, flags));
        if (input.use_schnorr) {
            BOOST_CHECK(seckey.SignSchnorr(sighash, sigs[input_idx]));
        } else {
            BOOST_CHECK(seckey.SignECDSA(sighash, sigs[input_idx]));
        }
        sigs[input_idx].push_back(input.sig_hash_type.getRawSigHashType() &
                                  0xff);
    }
    return sigs;
}

BOOST_AUTO_TEST_CASE(verify_invalid_taproot_script) {
    valtype vch_pubkey = ParseHex(
        "020000000000000000000000000000000000000000000000000000000000000001");
    std::vector<std::pair<CScript, ScriptError>> invalid_scripts = {
        {{CScript() << OP_SCRIPTTYPE << OP_0},
         ScriptError::SCRIPTTYPE_INVALID_TYPE},
        {{CScript() << OP_SCRIPTTYPE << OP_2},
         ScriptError::SCRIPTTYPE_INVALID_TYPE},
        {{CScript() << OP_SCRIPTTYPE << OP_3},
         ScriptError::SCRIPTTYPE_INVALID_TYPE},
        {{CScript() << OP_SCRIPTTYPE << OP_1},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(0)},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(32)},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(34)},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33) << valtype(0)},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33) << valtype(31)},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33) << valtype(33)},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(10) << valtype(55)},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(32) << valtype(33)},
         ScriptError::SCRIPTTYPE_MALFORMED_SCRIPT},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
         ScriptError::INVALID_STACK_OPERATION},
        {{CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33) << valtype(32)},
         ScriptError::INVALID_STACK_OPERATION},
    };
    for (auto &pair : invalid_scripts) {
        std::vector<TestUtxo> inputs = {{{}, pair.first, {}, Amount::zero()}};
        const std::vector<CTxOut> outputs = {{Amount::zero(), {}}};
        for (uint32_t flags : flagset) {
            CheckTxScripts(inputs, outputs, flags, pair.second);
        }
    }
}

BOOST_AUTO_TEST_CASE(verify_invalid_taproot_spend) {
    valtype vch_pubkey = ParseHex(
        "020000000000000000000000000000000000000000000000000000000000000001");
    std::vector<std::pair<std::pair<stacktype, CScript>, ScriptError>>
        invalid_scripts = {
            {{{}, CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::INVALID_STACK_OPERATION},
            {{{{}, {0x50}}, CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_ANNEX_NOT_SUPPORTED},
            {{{{0x00, 0x00}, {0x50}},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_ANNEX_NOT_SUPPORTED},
            {{{{}, {0x50, 0x00, 0x00}},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_ANNEX_NOT_SUPPORTED},
            {{{{}}, CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::PUBKEYTYPE},
            {{{{}}, CScript() << OP_SCRIPTTYPE << OP_1 << vch_pubkey},
             ScriptError::TAPROOT_VERIFY_SIGNATURE_FAILED},
            {{{valtype(65)}, CScript() << OP_SCRIPTTYPE << OP_1 << vch_pubkey},
             ScriptError::SIG_HASHTYPE},
            {{{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x61}},
              CScript() << OP_SCRIPTTYPE << OP_1 << vch_pubkey},
             ScriptError::TAPROOT_VERIFY_SIGNATURE_FAILED},
            {{{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65}},
              CScript() << OP_SCRIPTTYPE << OP_1 << vch_pubkey},
             ScriptError::SIG_HASHTYPE},
        };
    for (auto &pair : invalid_scripts) {
        CScript script_sig;
        for (const valtype &item : pair.first.first) {
            script_sig = script_sig << item;
        }
        TestUtxo input = {
            .script_sig = script_sig,
            .script_pubkey = pair.first.second,
            .exec_script = pair.first.second,
            .amount = Amount::zero(),
        };
        const std::vector<CTxOut> outputs = {{Amount::zero(), {}}};
        for (uint32_t flags : flagset) {
            CheckTxScripts({input}, outputs, flags, pair.second);
        }
    }
}

BOOST_AUTO_TEST_CASE(verify_key_spend) {
    CKey seckey;
    const valtype vch_seckey = ParseHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    seckey.Set(vch_seckey.begin(), vch_seckey.end(), true);
    CPubKey pubkey = seckey.GetPubKey();
    const valtype vch_pubkey(pubkey.begin(), pubkey.end());
    const CScript script = CScript() << OP_SCRIPTTYPE << OP_1 << vch_pubkey;
    const Amount amount = 1337 * COIN;
    const SigHashType sighash_all = SigHashType(SIGHASH_ALL).withBIP341();
    const SigHashType sighash_none = SigHashType(SIGHASH_NONE).withBIP341();
    const SigHashType sighash_single = SigHashType(SIGHASH_SINGLE).withBIP341();
    const std::vector<std::vector<TestInput>> success_input_cases = {
        {{{}, script, {}, amount, sighash_all, true}},
        {{{}, script, {}, amount, sighash_all.withAnyoneCanPay(), true}},
        {{{}, script, {}, amount, sighash_none, true}},
        {{{}, script, {}, amount, sighash_none.withAnyoneCanPay(), true}},
        {{{}, script, {}, amount, sighash_single, true}},
        {{{}, script, {}, amount, sighash_single.withAnyoneCanPay(), true}},
        {{{}, script, {}, amount, sighash_single, true},
         {{}, script, {}, amount, sighash_all, true},
         {{}, script, {}, amount, sighash_all.withAnyoneCanPay(), true},
         {{}, script, {}, amount, sighash_none, true},
         {{}, script, {}, amount, sighash_none.withAnyoneCanPay(), true}},
    };
    const std::vector<std::pair<std::vector<TestInput>, ScriptError>>
        error_input_cases = {
            {{{{}, script, {}, amount, sighash_all, false}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG},
            {{{{}, script, {}, amount, sighash_all.withAnyoneCanPay(), false}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG},
            {{{{}, script, {}, amount, sighash_none, false}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG},
            {{{{}, script, {}, amount, sighash_none.withAnyoneCanPay(), false}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG},
            {{{{}, script, {}, amount, sighash_single, false}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG},
            {{{{},
               script,
               {},
               amount,
               sighash_single.withAnyoneCanPay(),
               false}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG},
            {{{{},
               script,
               {},
               amount,
               sighash_all.withAlgorithm(SIGHASH_LEGACY),
               true}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_BIP341_SIGHASH},
            {{{{},
               script,
               {},
               amount,
               sighash_all.withAlgorithm(SIGHASH_FORKID),
               true}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_BIP341_SIGHASH},
        };
    const std::vector<std::vector<CTxOut>> output_cases = {
        {{Amount::zero(), {}}},
        {{10 * COIN, CScript() << OP_1}},
        {{10 * COIN, CScript() << OP_1},
         {20 * COIN, CScript() << OP_3},
         {30 * COIN, CScript() << OP_4}}};
    std::vector<std::pair<std::vector<TestInput>, ScriptError>> input_cases;
    for (const auto &inputs : success_input_cases) {
        input_cases.push_back({inputs, ScriptError::OK});
    }
    input_cases.insert(input_cases.end(), error_input_cases.begin(),
                       error_input_cases.end());
    for (const auto &pair : input_cases) {
        const std::vector<TestInput> &inputs = pair.first;
        const ScriptError serror = pair.second;
        std::vector<TestUtxo> signed_inputs(inputs.size());
        for (const std::vector<CTxOut> &outputs : output_cases) {
            for (uint32_t flags : flagset) {
                std::vector<valtype> sigs =
                    MakeSigs(seckey, inputs, outputs, flags);
                for (uint32_t i = 0; i < inputs.size(); ++i) {
                    signed_inputs[i] = inputs[i].utxo();
                    signed_inputs[i].script_sig = CScript() << sigs[i];
                }
                CheckTxScripts(signed_inputs, outputs, flags, serror);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(verify_taproot_simple_contract_disabled) {
    const std::vector<CTxOut> outputs = {{Amount::zero(), {}}};
    for (uint32_t flags : flagset) {
        CheckTxScripts({{CScript() << valtype(0) << valtype(1),
                         CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33),
                         CScript(), Amount::zero()}},
                       outputs, flags, ScriptError::UNKNOWN);
        CheckTxScripts(
            {{CScript() << valtype(0) << valtype(1),
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33) << valtype(32),
              CScript(), Amount::zero()}},
            outputs, flags, ScriptError::UNKNOWN);
    }
}

BOOST_AUTO_TEST_SUITE_END()
