// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresses/xaddress.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <test/lcg.h>

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <functional>
#include <random>
#include <string>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
const std::string pszBase58 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

BOOST_FIXTURE_TEST_SUITE(xaddress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(raw_encode_decode_succeeds) {
    std::random_device rd;
    auto lcg = MMIXLinearCongruentialGenerator(rd());
    auto gen = [&lcg]() { return uint8_t(lcg.next()); };

    // Assert that encode/decode works.
    for (size_t i = 0; i < 10000; i++) {
        std::vector<uint8_t> payload(1);
        std::generate(begin(payload), end(payload), gen);
        const std::string encodedAddress = XAddress::Encode(
            XAddress::Content(XAddress::TOKEN_NAME, XAddress::MAINNET,
                              XAddress::SCRIPT_PUB_KEY, payload));
        XAddress::Content parsedAddress;
        BOOST_CHECK_EQUAL(XAddress::Decode(encodedAddress, parsedAddress),
                          XAddress::DECODE_OK);
        BOOST_CHECK_EQUAL(parsedAddress.token, XAddress::TOKEN_NAME);
        BOOST_CHECK_MESSAGE(parsedAddress.network == XAddress::MAINNET,
                            "Network byte incorrect");
        BOOST_CHECK_EQUAL(parsedAddress.type, XAddress::SCRIPT_PUB_KEY);
        BOOST_CHECK_MESSAGE(parsedAddress.payload == payload,
                            "Parsed payload incorrect");
    }
}

BOOST_AUTO_TEST_CASE(raw_encode_decode_fails) {
    std::random_device rd;
    auto lcg = MMIXLinearCongruentialGenerator(rd());
    auto gen = [&lcg]() { return uint8_t(lcg.next()); };
    FastRandomContext randContext;

    // Assert that we get some XAddress::BASE58_DECODE_FAILED or
    // XAddress::INTEGRITY_CHECK_FAILED failures.
    for (size_t i = 0; i < 1000; i++) {
        std::vector<uint8_t> payload(20);
        std::generate(begin(payload), end(payload), gen);
        std::string encodedAddress = XAddress::Encode(
            XAddress::Content(XAddress::TOKEN_NAME, XAddress::MAINNET,
                              XAddress::SCRIPT_PUB_KEY, payload));
        const size_t mutatedPosition =
            randContext.randrange(encodedAddress.size());
        const unsigned char replacedCharacter =
            pszBase58[randContext.randrange(pszBase58.size())];
        const auto error = encodedAddress[mutatedPosition] == replacedCharacter
                               ? XAddress::DECODE_OK
                               : XAddress::BASE58_DECODE_FAILED |
                                     XAddress::INTEGRITY_CHECK_FAILED;
        encodedAddress[mutatedPosition] = replacedCharacter;
        XAddress::Content parsedAddress;
        const auto decodeResult =
            XAddress::Decode(encodedAddress, parsedAddress);
        // Error of one of the 2 types or passes
        BOOST_CHECK_MESSAGE((decodeResult & ~error) == 0,
                            "Decode or check failed: " << int(decodeResult));
    }

    // Assert that we receive a NO_NETWORK_POSITION error.
    {
        XAddress::Content parsedAddress;
        const auto decodeResult =
            XAddress::Decode("lotusabcfdsafdsafdsfdasfdsa", parsedAddress);
        // Error of one of the 2 types or passes
        BOOST_CHECK_MESSAGE(decodeResult == XAddress::NO_NETWORK_POSITION,
                            "Should have errored as NO_NETWORK_POSITION: "
                                << int(decodeResult));
    }

    // Assert that undersized payloads fail.
    {
        XAddress::Content parsedAddress;
        const auto decodeResult =
            XAddress::Decode("lotus_fdasf", parsedAddress);
        // Error of one of the 2 types or passes
        BOOST_CHECK_MESSAGE(decodeResult == XAddress::UNDERSIZED_PAYLOAD,
                            "Should have errored as NO_NETWORK_POSITION: "
                                << int(decodeResult));
    }
}

BOOST_AUTO_TEST_SUITE_END()
