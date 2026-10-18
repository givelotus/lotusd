// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(schnorr_batch_api_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip340_batch_matches_individual_verification) {
    const std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)>
        ctx(secp256k1_context_create(SECP256K1_CONTEXT_NONE),
            &secp256k1_context_destroy);
    constexpr size_t COUNT = 64;
    std::array<std::array<unsigned char, 64>, COUNT> signatures;
    std::array<secp256k1_xonly_pubkey, COUNT> pubkeys;
    std::array<uint256, COUNT> messages;
    std::array<unsigned char, COUNT * 32> coefficients;
    std::array<const unsigned char *, COUNT> sig_ptrs, msg_ptrs;
    std::array<const secp256k1_xonly_pubkey *, COUNT> pk_ptrs;
    for (size_t i = 0; i < COUNT; ++i) {
        std::array<unsigned char, 32> secret{};
        secret.back() = i + 1;
        secp256k1_keypair keypair;
        BOOST_REQUIRE(secp256k1_keypair_create(ctx.get(), &keypair, secret.data()));
        BOOST_REQUIRE(secp256k1_keypair_xonly_pub(ctx.get(), &pubkeys[i], nullptr, &keypair));
        messages[i] = Hash(strprintf("BIP340 batch fixture %u", i));
        BOOST_REQUIRE(secp256k1_schnorrsig_sign32(ctx.get(), signatures[i].data(), messages[i].begin(), &keypair, nullptr));
        sig_ptrs[i] = signatures[i].data();
        msg_ptrs[i] = messages[i].begin();
        pk_ptrs[i] = &pubkeys[i];
        const auto coefficient = Hash(strprintf("fixed test coefficient %u", i));
        std::copy(coefficient.begin(), coefficient.end(), coefficients.begin() + i * 32);
        BOOST_REQUIRE(secp256k1_schnorrsig_verify(ctx.get(), sig_ptrs[i], msg_ptrs[i], 32, pk_ptrs[i]));
    }
    BOOST_CHECK(secp256k1_schnorrsig_verify_batch(ctx.get(), nullptr, nullptr, nullptr, nullptr, 0));
    BOOST_CHECK(secp256k1_schnorrsig_verify_batch(ctx.get(), sig_ptrs.data(), msg_ptrs.data(), pk_ptrs.data(), nullptr, 1));
    for (size_t count : {2U, 8U, 32U, 64U}) {
        BOOST_CHECK(secp256k1_schnorrsig_verify_batch(ctx.get(), sig_ptrs.data(), msg_ptrs.data(), pk_ptrs.data(), coefficients.data(), count));
    }
    for (size_t i : {0U, 1U, 63U}) {
        signatures[i][63] ^= 1;
        BOOST_CHECK(!secp256k1_schnorrsig_verify(ctx.get(), sig_ptrs[i], msg_ptrs[i], 32, pk_ptrs[i]));
        BOOST_CHECK(!secp256k1_schnorrsig_verify_batch(ctx.get(), sig_ptrs.data(), msg_ptrs.data(), pk_ptrs.data(), coefficients.data(), COUNT));
        signatures[i][63] ^= 1;
    }
    messages.back().begin()[0] ^= 1;
    BOOST_CHECK(!secp256k1_schnorrsig_verify_batch(ctx.get(), sig_ptrs.data(), msg_ptrs.data(), pk_ptrs.data(), coefficients.data(), COUNT));
    messages.back().begin()[0] ^= 1;
    std::fill(signatures.back().begin(), signatures.back().begin() + 32, 0xff);
    BOOST_CHECK(!secp256k1_schnorrsig_verify_batch(ctx.get(), sig_ptrs.data(), msg_ptrs.data(), pk_ptrs.data(), coefficients.data(), COUNT));
    sig_ptrs.back() = nullptr;
    BOOST_CHECK(!secp256k1_schnorrsig_verify_batch(ctx.get(), sig_ptrs.data(), msg_ptrs.data(), pk_ptrs.data(), coefficients.data(), COUNT));
}

BOOST_AUTO_TEST_SUITE_END()
