// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresses/xaddress.h>
#include <config.h>
#include <random.h>
#include <script/standard.h>
#include <span.h>
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
    auto gen = [&rd]() { return uint8_t(rd()); };

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
        BOOST_CHECK_EQUAL(parsedAddress.m_token, XAddress::TOKEN_NAME);
        BOOST_CHECK_MESSAGE(parsedAddress.m_network == XAddress::MAINNET,
                            "Network byte incorrect");
        BOOST_CHECK_EQUAL(parsedAddress.m_type, XAddress::SCRIPT_PUB_KEY);
        BOOST_CHECK_MESSAGE(parsedAddress.m_payload == payload,
                            "Parsed payload incorrect");
    }
}

BOOST_AUTO_TEST_CASE(raw_encode_decode_fails) {
    std::random_device rd;
    auto gen = [&rd]() { return uint8_t(rd()); };

    // Assert that we get some XAddress::BASE58_DECODE_FAILED or
    // XAddress::INTEGRITY_CHECK_FAILED failures.
    for (size_t i = 0; i < 1000; i++) {
        std::vector<uint8_t> payload(20);
        std::generate(begin(payload), end(payload), gen);
        std::string encodedAddress = XAddress::Encode(
            XAddress::Content(XAddress::TOKEN_NAME, XAddress::MAINNET,
                              XAddress::SCRIPT_PUB_KEY, payload));
        const size_t mutatedPosition = rd() % encodedAddress.size();
        const unsigned char replacedCharacter = rd() % pszBase58.size();
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

BOOST_AUTO_TEST_CASE(parse_p2pkh_works) {
    // First create an instance of an engine.
    std::random_device rd;
    auto gen = [&rd]() { return uint8_t(rd()); };

    GlobalConfig config;
    // Assert that parsing returns a correct CTxDestination for PKHash.
    for (size_t i = 0; i < 10000; i++) {
        std::vector<uint8_t> fakeKeyBytes(20);
        std::generate(begin(fakeKeyBytes), end(fakeKeyBytes), gen);
        CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                         << ToByteVector(fakeKeyBytes)
                                         << OP_EQUALVERIFY << OP_CHECKSIG;
        const std::string encodedAddress = XAddress::Encode(XAddress::Content(
            XAddress::TOKEN_NAME, XAddress::MAINNET, XAddress::SCRIPT_PUB_KEY,
            ToByteVector(scriptPubKey)));
        CTxDestination dest;
        BOOST_CHECK_EQUAL(
            XAddress::Parse(config.GetChainParams(), encodedAddress, dest),
            true);
        const PKHash pkDest = boost::get<PKHash>(dest);
        BOOST_CHECK_EQUAL(MakeSpan(pkDest) == fakeKeyBytes, true);
    }

    // Assert that parsing returns a correct CTxDestination for ScriptHash.
    for (size_t i = 0; i < 10000; i++) {
        std::vector<uint8_t> fakeHashBytes(20);
        std::generate(begin(fakeHashBytes), end(fakeHashBytes), gen);
        CScript scriptPubKey =
            CScript() << OP_HASH160 << ToByteVector(fakeHashBytes) << OP_EQUAL;
        const std::string encodedAddress = XAddress::Encode(XAddress::Content(
            XAddress::TOKEN_NAME, XAddress::MAINNET, XAddress::SCRIPT_PUB_KEY,
            ToByteVector(scriptPubKey)));
        CTxDestination dest;
        BOOST_CHECK_EQUAL(
            XAddress::Parse(config.GetChainParams(), encodedAddress, dest),
            true);
        const ScriptHash pkDest = boost::get<ScriptHash>(dest);
        BOOST_CHECK_EQUAL(MakeSpan(pkDest) == fakeHashBytes, true);
    }

    // Check that parsing return CNoDestination for garbage.
    for (size_t i = 0; i < 10000; i++) {
        std::vector<uint8_t> garbledyGook(20);
        std::generate(begin(garbledyGook), end(garbledyGook), gen);
        const std::string encodedAddress = XAddress::Encode(
            XAddress::Content(XAddress::TOKEN_NAME, XAddress::MAINNET,
                              XAddress::SCRIPT_PUB_KEY, garbledyGook));
        CTxDestination dest;
        XAddress::Content parsedAddress;
        BOOST_CHECK_EQUAL(
            XAddress::Parse(config.GetChainParams(), encodedAddress, dest),
            false);
        BOOST_CHECK_NO_THROW(boost::get<CNoDestination>(dest));
    }
    // Check that parsing return CNoDestination for unknown type byte.
    {
        CTxDestination dest;
        std::vector<uint8_t> fakeHashBytes(20);
        std::generate(begin(fakeHashBytes), end(fakeHashBytes), gen);
        CScript scriptPubKey =
            CScript() << OP_HASH160 << ToByteVector(fakeHashBytes) << OP_EQUAL;

        // Check that parsing return CNoDestination for unknown type byte.
        BOOST_CHECK_EQUAL(
            XAddress::Parse(
                config.GetChainParams(),
                XAddress::Encode(XAddress::Content(
                    XAddress::TOKEN_NAME, XAddress::MAINNET,
                    static_cast<XAddress::AddressType>(0xf0), fakeHashBytes)),
                dest),
            false);
        BOOST_CHECK_NO_THROW(boost::get<CNoDestination>(dest));

        // Check that parsing return CNoDestination for unknown token.
        BOOST_CHECK_EQUAL(
            XAddress::Parse(config.GetChainParams(),
                            XAddress::Encode(XAddress::Content(
                                "poop", XAddress::MAINNET,
                                XAddress::SCRIPT_PUB_KEY, fakeHashBytes)),
                            dest),
            false);
        BOOST_CHECK_NO_THROW(boost::get<CNoDestination>(dest));

        // Check that parsing return CNoDestination for wrong network.
        BOOST_CHECK_EQUAL(
            XAddress::Parse(config.GetChainParams(),
                            XAddress::Encode(XAddress::Content(
                                XAddress::TOKEN_NAME, XAddress::TESTNET,
                                XAddress::SCRIPT_PUB_KEY, fakeHashBytes)),
                            dest),
            false);
        BOOST_CHECK_NO_THROW(boost::get<CNoDestination>(dest));
    }
}

BOOST_AUTO_TEST_CASE(encode_destination_works) {
    // First create an instance of an engine.
    std::random_device rd;
    auto gen = [&rd]() { return uint8_t(rd()); };
    GlobalConfig config;
    std::vector<uint8_t> fakeKeyBytes(32);
    std::generate(begin(fakeKeyBytes), end(fakeKeyBytes), gen);
    const auto fakeKeyId = Hash160(fakeKeyBytes);
    // Assert that encode works for PKHash.
    {
        CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                         << ToByteVector(fakeKeyId)
                                         << OP_EQUALVERIFY << OP_CHECKSIG;
        const std::string encodedAddress = XAddress::Encode(XAddress::Content(
            XAddress::TOKEN_NAME, XAddress::MAINNET, XAddress::SCRIPT_PUB_KEY,
            ToByteVector(scriptPubKey)));
        BOOST_CHECK_EQUAL(
            XAddress::EncodeDestination(config.GetChainParams(),
                                        PKHash(CKeyID(fakeKeyId))),
            encodedAddress);
    }

    // Assert that encode works for ScriptHash.
    {
        CScript redeemScript = CScript() << OP_TRUE;
        CScript scriptPubKey =
            CScript() << OP_HASH160
                      << ToByteVector(Hash160(ToByteVector(redeemScript)))
                      << OP_EQUAL;

        const std::string encodedAddress = XAddress::Encode(XAddress::Content(
            XAddress::TOKEN_NAME, XAddress::MAINNET, XAddress::SCRIPT_PUB_KEY,
            ToByteVector(scriptPubKey)));
        BOOST_CHECK_EQUAL(XAddress::EncodeDestination(config.GetChainParams(),
                                                      ScriptHash(redeemScript)),
                          encodedAddress);
    }

    // Assert null address for CNoDestination.
    {
        BOOST_CHECK_EQUAL(XAddress::EncodeDestination(config.GetChainParams(),
                                                      CNoDestination()),
                          "");
    }
}

BOOST_AUTO_TEST_CASE(encode_broken_checksum_works) {
    // Test that we validate addresses that had the old
    // checksum commitment that include varints for the
    // size of "lotus" and the payload.
    GlobalConfig config;

    const std::string encodedAddress =
        "lotus_16PSJLk9W86KAZp26x3uM176w6N9vUU8YNQQnQTHN";
    const std::vector<uint8_t> expectedPayload = {
        118, 169, 20,  118, 160, 64,  83,  189, 160, 168, 139, 218, 81,
        119, 184, 106, 21,  195, 178, 159, 85,  152, 115, 136, 172};
    XAddress::Content parsedAddress;

    BOOST_CHECK_EQUAL(XAddress::Decode(encodedAddress, parsedAddress),
                      XAddress::DECODE_OK);
    BOOST_CHECK_EQUAL(parsedAddress.m_network, XAddress::MAINNET);
    BOOST_CHECK_EQUAL(parsedAddress.m_type, XAddress::SCRIPT_PUB_KEY);
    BOOST_CHECK_MESSAGE(parsedAddress.m_payload == expectedPayload,
                        "Parsed payload incorrect");
    BOOST_CHECK_EQUAL(parsedAddress.m_token, XAddress::TOKEN_NAME);

    // Check encodes with correct checksum
    XAddress::Content oldCheckSumDecoded;
    BOOST_CHECK_EQUAL(
        XAddress::Decode("lotus_1PrQxBkWiRorG9kcMKvFq3hoRdN8XLUy4YzAHe",
                         oldCheckSumDecoded),
        XAddress::DECODE_OK);
    BOOST_CHECK_EQUAL(XAddress::Encode(oldCheckSumDecoded),
                      "lotus_1PrQxBkWiRorG9kcMKvFq3hoRdN8XLUy4YzAHe");
}

BOOST_AUTO_TEST_SUITE_END()
