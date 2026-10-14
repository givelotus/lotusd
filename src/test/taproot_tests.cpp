// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

BOOST_AUTO_TEST_SUITE_END()
