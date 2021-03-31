// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
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

BOOST_AUTO_TEST_SUITE_END()
