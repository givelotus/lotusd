// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresses/xaddress.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <functional>
#include <iostream>
#include <random>
#include <string>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
const std::string pszBase58 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

BOOST_FIXTURE_TEST_SUITE(xaddress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(raw_encode_decode_succeeds) {
    // First create an instance of an engine.
    std::random_device rnd_device;
    // Specify the engine and distribution.
    std::mt19937 mersenne_engine{rnd_device()}; // Generates random integers
    std::uniform_int_distribution<uint8_t> dist{0, 255};

    auto gen = [&dist, &mersenne_engine]() { return dist(mersenne_engine); };

    // Assert that encode/decode works.
    for (size_t i = 0; i < 10000; i++) {
        std::vector<uint8_t> payload(10);
        std::generate(begin(payload), end(payload), gen);
        const std::string encodedAddress =
            XAddress::Encode("lotus", '_', payload);
        XAddress::Content parsedAddress;
        BOOST_CHECK_EQUAL(XAddress::Decode(encodedAddress, parsedAddress),
                          true);
        BOOST_CHECK_EQUAL(parsedAddress.token, "lotus");
        BOOST_CHECK_MESSAGE(parsedAddress.network == uint8_t('_'),
                            "Network byte incorrect");
        BOOST_CHECK_MESSAGE(parsedAddress.payload == payload,
                            "Parsed payload incorrect");
    }
}

BOOST_AUTO_TEST_CASE(raw_encode_decode_fails) {
    // First create an instance of an engine.
    std::random_device rnd_device;
    // Specify the engine and distribution.
    std::mt19937 mersenne_engine{rnd_device()}; // Generates random integers
    std::uniform_int_distribution<uint8_t> dist{0, 255};

    auto gen = [&dist, &mersenne_engine]() { return dist(mersenne_engine); };

    FastRandomContext randContext;

    // Assert that check fails.
    for (size_t i = 0; i < 10000; i++) {
        std::vector<uint8_t> payload(10);
        std::generate(begin(payload), end(payload), gen);
        std::string encodedAddress = XAddress::Encode("lotus", 'T', payload);
        const size_t mutatedPosition =
            randContext.randrange(encodedAddress.size());
        const unsigned char replacedCharacter =
            pszBase58[randContext.randrange(pszBase58.size())];
        const bool isValid =
            encodedAddress[mutatedPosition] == replacedCharacter;
        encodedAddress[mutatedPosition] = replacedCharacter;
        XAddress::Content parsedAddress;
        BOOST_CHECK_EQUAL(XAddress::Decode(encodedAddress, parsedAddress),
                          isValid);
    }
}

BOOST_AUTO_TEST_SUITE_END()
