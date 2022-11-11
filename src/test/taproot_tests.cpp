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
 * on the Python code in Lotus sighash:
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
            VerifyScript(inputs[i].script_sig, {}, inputs[i].script_pubkey, flags,
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

uint256 MakeTapleafHash(const CScript &exec_script) {
    const uint256 tapleaf_hash =
        (TaggedHash("TapLeaf") << uint8_t(0xc0) << exec_script).GetSHA256();
    return tapleaf_hash;
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
        if (!input.is_key_path_spend) {
            execdata = std::optional(ScriptExecutionData(
                MakeTapleafHash(input.exec_script), input.codeseparator_pos));
        }
        CScript script_code;
        if (execdata && execdata->m_codeseparator_pos != 0xffff'ffff) {
            CScript::const_iterator pc = input.exec_script.begin();
            for (uint32_t i = 0; i <= execdata->m_codeseparator_pos; ++i) {
                opcodetype opcode;
                valtype vch_push_value;
                BOOST_CHECK(
                    input.exec_script.GetOp(pc, opcode, vch_push_value));
            }
            script_code = CScript(pc, input.exec_script.end());
        } else {
            script_code = input.exec_script;
        }
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
            {{{{}, {}}, CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_WRONG_CONTROL_SIZE},
            {{{{}, valtype(32)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_WRONG_CONTROL_SIZE},
            {{{{}, valtype(34)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_WRONG_CONTROL_SIZE},
            {{{{}, valtype(33 + 31)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_WRONG_CONTROL_SIZE},
            {{{{}, valtype(33 + 33)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_WRONG_CONTROL_SIZE},
            {{{{}, valtype(33 + 12 * 32 - 1)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_WRONG_CONTROL_SIZE},
            {{{{}, valtype(33)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_LEAF_VERSION_NOT_SUPPORTED},
            {{{{}, valtype(33 + 32)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_LEAF_VERSION_NOT_SUPPORTED},
            {{{{}, valtype(33 + 2 * 32)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_LEAF_VERSION_NOT_SUPPORTED},
            {{{{}, valtype(33 + 12 * 32)},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_LEAF_VERSION_NOT_SUPPORTED},
            {{{{}, {0xc2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_LEAF_VERSION_NOT_SUPPORTED},
            {{{{},
               {
                   0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               }},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_VERIFY_COMMITMENT_FAILED},
            {{{{}, {0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_VERIFY_COMMITMENT_FAILED},
            {{{{}, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00}},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_VERIFY_COMMITMENT_FAILED},
            {{{{}, {0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00}},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_VERIFY_COMMITMENT_FAILED},
            {{{valtype(22),
               {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_VERIFY_COMMITMENT_FAILED},
            {{{valtype(22),
               {0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
              CScript() << OP_SCRIPTTYPE << OP_1 << valtype(33)},
             ScriptError::TAPROOT_VERIFY_COMMITMENT_FAILED},
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
    const SigHashType sighash_all = SigHashType(SIGHASH_ALL).withLotus();
    const SigHashType sighash_none = SigHashType(SIGHASH_NONE).withLotus();
    const SigHashType sighash_single = SigHashType(SIGHASH_SINGLE).withLotus();
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
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_LOTUS_SIGHASH},
            {{{{},
               script,
               {},
               amount,
               sighash_all.withAlgorithm(SIGHASH_FORKID),
               true}},
             ScriptError::TAPROOT_KEY_SPEND_MUST_USE_LOTUS_SIGHASH},
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

BOOST_AUTO_TEST_CASE(verify_taproot_simple_contract_one_leaf) {
    std::vector<std::string> internal_pubkeys_hex = {
        "020000000000000000000000000000000000000000000000000000000000000014",
        "030000000000000000000000000000000000000000000000000000000000000014",
        "020101010101010101010101010101010101010101010101010101010101010101",
        "030101010101010101010101010101010101010101010101010101010101010101",
    };
    std::vector<std::pair<std::pair<CScript, CScript>, ScriptError>> scripts = {
        {{CScript() << 4, CScript() << 5 << OP_ADD << 9 << OP_EQUAL},
         ScriptError::OK},
        {{CScript(), CScript()}, ScriptError::EVAL_FALSE},
        {{CScript() << OP_0, CScript()}, ScriptError::EVAL_FALSE},
        {{CScript() << OP_1, CScript()}, ScriptError::OK},
        {{CScript() << 4, CScript() << 5 << OP_ADD << 9 << OP_EQUALVERIFY},
         ScriptError::EVAL_FALSE},
        {{CScript() << 4, CScript() << 5 << OP_ADD << 10 << OP_EQUAL},
         ScriptError::EVAL_FALSE},
        {{CScript() << 4, CScript() << 5 << OP_ADD << 10 << OP_EQUALVERIFY},
         ScriptError::EQUALVERIFY},
    };
    const std::vector<CTxOut> outputs = {{Amount::zero(), {}}};
    for (const auto &pair : scripts) {
        const CScript &exec_script = pair.first.second;
        const ScriptError serror = pair.second;
        const uint256 tapleaf_hash = MakeTapleafHash(exec_script);
        for (const std::string &internal_pubkey_hex : internal_pubkeys_hex) {
            CScript script_sig = pair.first.first;
            valtype vch_internal_pubkey = ParseHex(internal_pubkey_hex);
            CPubKey pubkey_internal(vch_internal_pubkey.begin(),
                                    vch_internal_pubkey.end());
            const uint256 tweak_hash =
                (TaggedHash("TapTweak")
                 << MakeSpan(pubkey_internal) << tapleaf_hash)
                    .GetSHA256();
            CPubKey pubkey_commitment;
            BOOST_CHECK(
                pubkey_internal.AddScalar(pubkey_commitment, tweak_hash));
            valtype control_block(pubkey_internal.begin(),
                                  pubkey_internal.end());
            control_block[0] = control_block[0] == 0x02 ? 0 : 1;
            control_block[0] |= 0xc0;
            TestUtxo input{
                script_sig << valtype(exec_script.begin(), exec_script.end())
                           << control_block,
                CScript() << OP_SCRIPTTYPE << OP_1
                          << valtype(pubkey_commitment.begin(),
                                     pubkey_commitment.end()),
                exec_script, 3 * COIN};
            for (uint32_t flags : flagset) {
                CheckTxScripts({input}, outputs, flags, serror);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(verify_taproot_checksig_contract_one_leaf) {
    valtype vch_pubkey_internal(ParseHex(
        "020000000000000000000000000000000000000000000000000000000000000001"));
    CPubKey pubkey_internal(vch_pubkey_internal.begin(),
                            vch_pubkey_internal.end());
    valtype control_block(pubkey_internal.begin(), pubkey_internal.end());
    control_block[0] = control_block[0] == 0x02 ? 0 : 1;
    control_block[0] |= 0xc0;
    CKey sig_seckey;
    const valtype vch_sig_seckey = ParseHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    sig_seckey.Set(vch_sig_seckey.begin(), vch_sig_seckey.end(), true);
    CPubKey sig_pubkey = sig_seckey.GetPubKey();
    const valtype vch_sig_pubkey(sig_pubkey.begin(), sig_pubkey.end());
    struct TestScript {
        CScript exec_script;
        SigHashType sig_hash_type;
        bool use_schnorr;
        uint32_t sequence = 0xffff'ffff;
        uint32_t codeseparator_pos = 0xffff'ffff;
        std::optional<valtype> state = std::nullopt;
    };
    const SigHashType sighash_all = SigHashType(SIGHASH_ALL);
    const SigHashType sighash_none = SigHashType(SIGHASH_NONE);
    const SigHashType sighash_single = SigHashType(SIGHASH_SINGLE);
    const CScript script = CScript() << vch_sig_pubkey << OP_CHECKSIG;
    const ScriptError ok = ScriptError::OK;
    using Pair = std::pair<std::vector<TestScript>, ScriptError>;
    uint32_t seq = 0x1234'0001;
    const std::vector<Pair> script_cases = {
        {{{script, sighash_all.withForkId(), false, seq++}}, ok},
        {{{script, sighash_all.withLotus(), false, seq++}}, ok},
        {{{script, sighash_all.withForkId(), true, seq++}}, ok},
        {{{script, sighash_all.withLotus(), true, seq++}}, ok},
        {{{script, sighash_all.withForkId().withAnyoneCanPay(), false, seq++}},
         ok},
        {{{script, sighash_all.withLotus().withAnyoneCanPay(), false}}, ok},
        {{{script, sighash_all.withForkId().withAnyoneCanPay(), true}}, ok},
        {{{script, sighash_all.withLotus().withAnyoneCanPay(), true}}, ok},
        {{{script, sighash_none.withForkId(), false, seq++}}, ok},
        {{{script, sighash_none.withLotus(), false, seq++}}, ok},
        {{{script, sighash_none.withForkId(), true, seq++}}, ok},
        {{{script, sighash_none.withLotus(), true, seq++}}, ok},
        {{{script, sighash_none.withForkId().withAnyoneCanPay(), false}}, ok},
        {{{script, sighash_none.withLotus().withAnyoneCanPay(), false, seq++}},
         ok},
        {{{script, sighash_none.withForkId().withAnyoneCanPay(), true, seq++}},
         ok},
        {{{script, sighash_none.withLotus().withAnyoneCanPay(), true}}, ok},
        {{{script, sighash_single.withForkId(), false}}, ok},
        {{{script, sighash_single.withLotus(), false}}, ok},
        {{{script, sighash_single.withForkId(), true}}, ok},
        {{{script, sighash_single.withLotus(), true}}, ok},
        {{{script, sighash_single.withForkId().withAnyoneCanPay(), false}}, ok},
        {{{script, sighash_single.withLotus().withAnyoneCanPay(), false}}, ok},
        {{{script, sighash_single.withForkId().withAnyoneCanPay(), true}}, ok},
        {{{script, sighash_single.withLotus().withAnyoneCanPay(), true}}, ok},
        {{{script, sighash_single.withLotus(), true, seq++},
          {script, sighash_single.withForkId().withAnyoneCanPay(), false},
          {script, sighash_all.withForkId(), false, seq++},
          {script, sighash_all.withLotus(), false, seq++},
          {script, sighash_all.withForkId(), true, seq++},
          {script, sighash_all.withLotus(), true, seq++},
          {script, sighash_all.withForkId().withAnyoneCanPay(), false, seq++},
          {script, sighash_all.withLotus().withAnyoneCanPay(), false, seq++},
          {script, sighash_all.withForkId().withAnyoneCanPay(), true, seq++},
          {script, sighash_all.withLotus().withAnyoneCanPay(), true, seq++},
          {script, sighash_none.withForkId(), false, seq++},
          {script, sighash_none.withLotus(), false, seq++},
          {script, sighash_none.withForkId(), true, seq++},
          {script, sighash_none.withLotus(), true, seq++},
          {script, sighash_none.withForkId().withAnyoneCanPay(), false, seq++},
          {script, sighash_none.withLotus().withAnyoneCanPay(), false, seq++},
          {script, sighash_none.withForkId().withAnyoneCanPay(), true, seq++},
          {script, sighash_none.withLotus().withAnyoneCanPay(), true, seq++}},
         ok},
        // use 000000..00 as state and check equality in script
        {{{CScript() << valtype(32) << OP_EQUALVERIFY << vch_sig_pubkey
                     << OP_CHECKSIG,
           sighash_single.withLotus(), true, seq++, 0xffff'ffff, valtype(32)}},
         ok},
        // use 000102..1f as state and check equality in script
        {{{CScript() << valtype{0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                                22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
                     << OP_EQUALVERIFY << vch_sig_pubkey << OP_CHECKSIG,
           sighash_single.withLotus(), true, seq++, 0xffff'ffff,
           valtype{0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                   22, 23, 24, 25, 26, 27, 28, 29, 30, 31}}},
         ok},
        // OP_CODESEPARATOR tests
        {{{CScript() << OP_CODESEPARATOR << vch_sig_pubkey << OP_CHECKSIG,
           sighash_single.withLotus(), true, seq++, 0}},
         ok},
        {{{CScript() << OP_CODESEPARATOR << vch_sig_pubkey << OP_CHECKSIG,
           sighash_single.withLotus(), false, seq++, 0}},
         ok},
        {{{CScript() << vch_sig_pubkey << OP_CODESEPARATOR << OP_CHECKSIG,
           sighash_single.withLotus(), true, seq++, 1}},
         ok},
        {{{CScript() << OP_CODESEPARATOR << vch_sig_pubkey << OP_CHECKSIG,
           sighash_single.withForkId(), true, seq++, 0}},
         ok},
        {{{CScript() << vch_sig_pubkey << OP_CODESEPARATOR << OP_CHECKSIG,
           sighash_single.withForkId(), true, seq++, 1}},
         ok},
        {{{CScript() << vch_sig_pubkey << 0 << OP_IF << OP_CODESEPARATOR
                     << OP_ENDIF << OP_CHECKSIG,
           sighash_single.withForkId(), true, seq++}},
         ok},
        {{{CScript() << vch_sig_pubkey << 1 << OP_IF << OP_CODESEPARATOR
                     << OP_ENDIF << OP_CHECKSIG,
           sighash_single.withForkId(), true, seq++, 3}},
         ok},
        {{{CScript() << vch_sig_pubkey << 0 << OP_IF << OP_CODESEPARATOR
                     << OP_ENDIF << OP_CHECKSIG,
           sighash_single.withLotus(), true, seq++}},
         ok},
        {{{CScript() << vch_sig_pubkey << 1 << OP_IF << OP_CODESEPARATOR
                     << OP_ENDIF << OP_CHECKSIG,
           sighash_single.withLotus(), true, seq++, 3}},
         ok},
        {{{CScript() << vch_sig_pubkey << 1 << OP_IF << OP_CODESEPARATOR
                     << OP_ENDIF << OP_CHECKSIG,
           sighash_single.withLotus(), false, seq++, 3}},
         ok},
        {{{CScript() << valtype(32) << OP_EQUALVERIFY << OP_CODESEPARATOR
                     << vch_sig_pubkey << OP_CHECKSIG,
           sighash_single.withLotus(), true, seq++, 2, valtype(32)}},
         ok},
        // test using legacy sighash
        {{{script, sighash_single.withAlgorithm(SIGHASH_LEGACY), true, seq++}},
         ScriptError::MUST_USE_FORKID}};
    const std::vector<CTxOut> outputs = {{Amount::zero(), {}},
                                         {Amount::zero(), {}}};
    std::vector<std::vector<TestInput>> input_cases;
    uint32_t script_counter = 0;
    for (const auto &pair : script_cases) {
        const std::vector<TestScript> scripts = pair.first;
        std::vector<TestInput> inputs;
        for (const auto &script : scripts) {
            const uint256 tweak_hash =
                (TaggedHash("TapTweak") << MakeSpan(pubkey_internal)
                                        << MakeTapleafHash(script.exec_script))
                    .GetSHA256();
            CPubKey pubkey_commitment;
            BOOST_CHECK(
                pubkey_internal.AddScalar(pubkey_commitment, tweak_hash));
            CScript script_pubkey = CScript()
                                    << OP_SCRIPTTYPE << OP_1
                                    << valtype(pubkey_commitment.begin(),
                                               pubkey_commitment.end());
            if (script.state) {
                script_pubkey << *script.state;
            }
            inputs.push_back({
                .script_sig = CScript() << valtype(script.exec_script.begin(),
                                                   script.exec_script.end())
                                        << control_block,
                .script_pubkey = script_pubkey,
                .exec_script = script.exec_script,
                .amount = int64_t(script_counter) * COIN,
                .sig_hash_type = script.sig_hash_type,
                .use_schnorr = script.use_schnorr,
                .is_key_path_spend = false,
                .sequence = script.sequence,
                .outpoint = COutPoint(TxId(uint256()), script_counter++),
                .codeseparator_pos = script.codeseparator_pos,
            });
        }
        for (uint32_t flags : flagset) {
            std::vector<valtype> sigs =
                MakeSigs(sig_seckey, inputs, outputs, flags);
            std::vector<TestUtxo> utxos(inputs.size());
            for (uint32_t i = 0; i < inputs.size(); ++i) {
                utxos[i] = inputs[i].utxo();
                utxos[i].script_sig = CScript()
                                      << sigs[i]
                                      << valtype(scripts[i].exec_script.begin(),
                                                 scripts[i].exec_script.end())
                                      << control_block;
            }
            CheckTxScripts(utxos, outputs, flags, pair.second);
        }
    }
}

/**
 * Tests spending branches of the following tree:
 * ```
 * script_tree = ScriptBranch(
 *     ScriptBranch(
 *         ScriptBranch(
 *             ScriptLeaf(0xc0, bytes.fromhex('52935987')),
 *             ScriptLeaf(0xc0,
 *                        bytes.fromhex('21e59e705cb909acaba73cef8c4b8e775cd87c'
 *                                      'c0956e4045306d7ded41947f04c602bcac')),
 *         ),
 *         ScriptLeaf(0xc0, bytes.fromhex('537e0301020387')),
 *     ),
 *     ScriptLeaf(0xc0,
 *                bytes.fromhex('2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8c'
 *                              'ef3ca7abac09b95c709ee5ac')),
 * )
 * ```
 */
BOOST_AUTO_TEST_CASE(verify_taproot_checksig_contract_tree) {
    valtype vch_pubkey_internal(ParseHex(
        "030000000000000000000000000000000000000000000000000000000000000001"));
    CKey sig_seckey;
    const valtype vch_sig_seckey = ParseHex(
        "0000000000000000000000000000000000000000000000000000000000000002");
    valtype vch_pubkey_commitment(ParseHex(
        "022614104f2ff34195c79544001a0e34e6641b71eb15c8377cb29e194072bba9ca"));
    sig_seckey.Set(vch_sig_seckey.begin(), vch_sig_seckey.end(), true);
    CPubKey sig_pubkey = sig_seckey.GetPubKey();
    const valtype vch_sig_pubkey(sig_pubkey.begin(), sig_pubkey.end());
    const std::vector<CTxOut> outputs = {{Amount::zero(), {}}};
    const CScript simple_script = CScript() << vch_sig_pubkey << OP_CHECKSIG;
    TestInput input = {
        {},
        CScript() << OP_SCRIPTTYPE << OP_1 << vch_pubkey_commitment,
        simple_script,
        12 * COIN,
        SigHashType(),
        true,
        false,
    };
    valtype control_block = ParseHex(
        "c100000000000000000000000000000000000000000000000000000000000000016d5b"
        "cada2aad300646d1a6156d93c4e224572842de30503cfa48269506df5042");
    const std::vector<std::pair<SigHashType, ScriptError>> test_cases = {
        {SigHashType(SIGHASH_ALL).withForkId(), ScriptError::OK},
        {SigHashType(SIGHASH_ALL).withForkId().withAnyoneCanPay(),
         ScriptError::OK},
        {SigHashType(SIGHASH_NONE).withForkId(), ScriptError::OK},
        {SigHashType(SIGHASH_NONE).withForkId().withAnyoneCanPay(),
         ScriptError::OK},
        {SigHashType(SIGHASH_SINGLE).withForkId(), ScriptError::OK},
        {SigHashType(SIGHASH_SINGLE).withForkId().withAnyoneCanPay(),
         ScriptError::OK},
        {SigHashType(SIGHASH_ALL).withLotus(), ScriptError::OK},
        {SigHashType(SIGHASH_ALL).withLotus().withAnyoneCanPay(),
         ScriptError::OK},
        {SigHashType(SIGHASH_NONE).withLotus(), ScriptError::OK},
        {SigHashType(SIGHASH_NONE).withLotus().withAnyoneCanPay(),
         ScriptError::OK},
        {SigHashType(SIGHASH_SINGLE).withLotus(), ScriptError::OK},
        {SigHashType(SIGHASH_SINGLE).withLotus().withAnyoneCanPay(),
         ScriptError::OK},
        {SigHashType(SIGHASH_ALL), ScriptError::MUST_USE_FORKID},
        {SigHashType(SIGHASH_ALL).withAnyoneCanPay(),
         ScriptError::MUST_USE_FORKID},
        {SigHashType(SIGHASH_NONE), ScriptError::MUST_USE_FORKID},
        {SigHashType(SIGHASH_NONE).withAnyoneCanPay(),
         ScriptError::MUST_USE_FORKID},
        {SigHashType(SIGHASH_SINGLE), ScriptError::MUST_USE_FORKID},
        {SigHashType(SIGHASH_SINGLE).withAnyoneCanPay(),
         ScriptError::MUST_USE_FORKID},
    };
    for (const auto &test_case : test_cases) {
        for (uint32_t flags : flagset) {
            input.sig_hash_type = test_case.first;
            std::vector<valtype> sigs =
                MakeSigs(sig_seckey, {input}, outputs, flags);
            input.script_sig =
                CScript() << sigs[0]
                          << valtype(simple_script.begin(), simple_script.end())
                          << control_block;
            CheckTxScripts({input.utxo()}, outputs, flags, test_case.second);
        }
    }
    valtype vch_pubkey_reversed(vch_sig_pubkey);
    std::reverse(vch_pubkey_reversed.begin(), vch_pubkey_reversed.end());
    const CScript reversebytes_script =
        CScript() << vch_pubkey_reversed << OP_REVERSEBYTES << OP_CHECKSIG;
    input.exec_script = reversebytes_script;
    control_block = ParseHex(
        "c10000000000000000000000000000000000000000000000000000000000000001d87d"
        "d8a2a2c9eee36960394f72e3e1cddc0fad436632f5e4300eb2ea3534c3d22abb84bfbc"
        "0d359a06a66092f89bcca0d4575516c28a7d1c763b4bf9fd8c905faa209c7079e4a14f"
        "4c633e1fe7b9ee9e5463d13003b4dc7c2eeb02115740fc48");
    for (const auto &test_case : test_cases) {
        for (uint32_t flags : flagset) {
            input.sig_hash_type = test_case.first;
            std::vector<valtype> sigs =
                MakeSigs(sig_seckey, {input}, outputs, flags);
            input.script_sig = CScript() << sigs[0]
                                         << valtype(reversebytes_script.begin(),
                                                    reversebytes_script.end())
                                         << control_block;
            CheckTxScripts({input.utxo()}, outputs, flags, test_case.second);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
