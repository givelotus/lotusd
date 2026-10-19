// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/error.h>
#include <chronik/native/types.h>
#include <chronik/native/version.h>

#include <boost/test/unit_test.hpp>

#include <string>

using namespace chronik::native;

BOOST_AUTO_TEST_SUITE(skeleton_tests)

BOOST_AUTO_TEST_CASE(implementation_name) {
    BOOST_CHECK_EQUAL(std::string(ImplementationName()), "native");
}

BOOST_AUTO_TEST_CASE(hash32_order) {
    Hash32 h;
    h.b[0] = 1;
    h.b[31] = 2;
    const auto rev = h.Reversed();
    BOOST_CHECK_EQUAL(rev[0], 2);
    BOOST_CHECK_EQUAL(rev[31], 1);
    BOOST_CHECK(Hash32::FromReversed(rev) == h);
    BOOST_CHECK(!h.IsNull());
    BOOST_CHECK(Hash32{}.IsNull());
}

BOOST_AUTO_TEST_CASE(tx_is_coinbase) {
    Tx tx;
    tx.inputs.resize(1);
    BOOST_CHECK(tx.is_coinbase());
    tx.inputs[0].prev_out.txid.b[3] = 7;
    BOOST_CHECK(!tx.is_coinbase());
}

BOOST_AUTO_TEST_CASE(error_status_prefix) {
    // Same rule as abc_rust_error::parse_error_status
    BOOST_CHECK(ParseErrorStatus("404: Block not found") == 404);
    BOOST_CHECK(ParseErrorStatus("400: x") == 400);
    BOOST_CHECK(!ParseErrorStatus("Something obscure"));
    BOOST_CHECK(!ParseErrorStatus("40: x"));
    BOOST_CHECK(!ParseErrorStatus("404:x"));
    BOOST_CHECK(!ParseErrorStatus("4a4: x"));
}

BOOST_AUTO_TEST_SUITE_END()
