// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/address.h>

#include <test/data/lotus_v2_address.json.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>

using lotus::v2::AddressNetwork;

namespace {
AddressNetwork NetworkFromPrefix(const std::string &prefix) {
    for (const auto network : {AddressNetwork::MAINNET,
                               AddressNetwork::TESTNET,
                               AddressNetwork::REGTEST}) {
        if (lotus::v2::AddressPrefix(network) == prefix) {
            return network;
        }
    }
    BOOST_FAIL("unknown prefix in test vector: " + prefix);
    return AddressNetwork::MAINNET;
}

// The vector file is an object (constants, valid, invalid), so it does not go
// through read_json, which requires an array.
UniValue ReadVectors() {
    UniValue v;
    BOOST_REQUIRE(v.read(json_tests::lotus_v2_address) && v.isObject());
    return v;
}

std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}
} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_address_tests)

BOOST_AUTO_TEST_CASE(valid_vectors) {
    const UniValue tests = ReadVectors();
    const UniValue &valid = tests["valid"];
    BOOST_REQUIRE(valid.size() > 0);
    for (size_t i = 0; i < valid.size(); ++i) {
        const UniValue &test = valid[i];
        const std::string address = test["address"].get_str();
        const AddressNetwork network =
            NetworkFromPrefix(test["hrp"].get_str());
        const std::vector<uint8_t> root_bytes =
            ParseHex(test["root"].get_str());
        BOOST_REQUIRE_EQUAL(root_bytes.size(), 32U);
        lotus::v2::Hash32 root;
        std::memcpy(root.data(), root_bytes.data(), 32);

        std::string error;
        const auto decoded = lotus::v2::DecodeAddress(address, error);
        BOOST_REQUIRE_MESSAGE(decoded, address + ": " + error);
        BOOST_CHECK(decoded->network == network);
        BOOST_CHECK(decoded->root == root);
        // Encoders always produce lowercase, including for uppercase inputs.
        BOOST_CHECK_EQUAL(lotus::v2::EncodeAddress(network, root),
                          Lower(address));
    }
}

BOOST_AUTO_TEST_CASE(invalid_vectors) {
    const UniValue tests = ReadVectors();
    const UniValue &invalid = tests["invalid"];
    BOOST_REQUIRE(invalid.size() > 0);
    for (size_t i = 0; i < invalid.size(); ++i) {
        const UniValue &test = invalid[i];
        const std::string address = test["address"].get_str();
        std::string error;
        BOOST_CHECK_MESSAGE(!lotus::v2::DecodeAddress(address, error),
                            address + " decoded");
        BOOST_CHECK_EQUAL(error, test["reason"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(network_constants) {
    const UniValue tests = ReadVectors();
    BOOST_CHECK_EQUAL(tests["constants"]["xpi"].get_str(), "0xb70061479e");
    BOOST_CHECK_EQUAL(tests["constants"]["txpi"].get_str(), "0xadda0f1635");
    BOOST_CHECK_EQUAL(tests["constants"]["rxpi"].get_str(), "0x8172b45d63");
}

BOOST_AUTO_TEST_CASE(round_trip) {
    lotus::v2::Hash32 root{};
    for (uint32_t n = 0; n < 2000; ++n) {
        for (size_t i = 0; i < root.size(); ++i) {
            root[i] = static_cast<uint8_t>((n * 131 + i * 29 + (n >> 3)) ^ i);
        }
        for (const auto network : {AddressNetwork::MAINNET,
                                   AddressNetwork::TESTNET,
                                   AddressNetwork::REGTEST}) {
            const std::string address =
                lotus::v2::EncodeAddress(network, root);
            BOOST_CHECK_EQUAL(address.size(),
                              lotus::v2::AddressPrefix(network).size() + 62);
            std::string error;
            const auto decoded = lotus::v2::DecodeAddress(address, error);
            BOOST_REQUIRE_MESSAGE(decoded, address + ": " + error);
            BOOST_CHECK(decoded->network == network);
            BOOST_CHECK(decoded->root == root);
        }
    }
}

BOOST_AUTO_TEST_CASE(keyhash_template) {
    const auto key = ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const auto hash = lotus::v2::NativeKeyHash(std::span<const uint8_t, 32>(key.data(), 32));
    // Independent Python blake3 1.0.8 oracle, x-only generator point.
    BOOST_CHECK_EQUAL(HexStr(hash), "f9f2a0b353f482f415281da3a00929d08a7d9a6498054f5ef6623b5580e607f7");
    BOOST_CHECK_EQUAL(lotus::v2::EncodeKeyHashAddress(AddressNetwork::REGTEST, hash),
        "rxpi1pl8e2pv6n7jp0g9fgrk36qzff6z98mxnynqz57hhkvga4tq8xqlmsq2859j5u");
    const auto program = lotus::v2::KeyHashProgram(hash);
    BOOST_REQUIRE_EQUAL(program.size(), 37U);
    BOOST_CHECK_EQUAL(HexStr(lotus::v2::KeyHashRoot(hash)),
        "84f3ac422780d391bc9210fa6e19dc8d0fd2bb1acd390e065c6a0acda9f667bb");
    BOOST_CHECK_EQUAL(program.front(), 0x7a);
    BOOST_CHECK_EQUAL(program.back(), 0xbb);
    for (const auto network : {AddressNetwork::MAINNET, AddressNetwork::TESTNET, AddressNetwork::REGTEST}) {
        const auto address = lotus::v2::EncodeKeyHashAddress(network, hash);
        std::string error;
        const auto decoded = lotus::v2::DecodeAddress(address, error);
        BOOST_REQUIRE(decoded);
        BOOST_CHECK_EQUAL(decoded->type, 1);
        BOOST_CHECK(decoded->root == hash);
        BOOST_CHECK(decoded->BranchRoot() == lotus::v2::KeyHashRoot(hash));
        BOOST_CHECK(decoded->BranchRoot() != hash);
        BOOST_CHECK(address != lotus::v2::EncodeAddress(network, hash));
    }
}

BOOST_AUTO_TEST_SUITE_END()
