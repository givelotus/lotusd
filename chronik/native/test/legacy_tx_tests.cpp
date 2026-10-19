// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/tx/legacy_tx.h>

#include <boost/test/unit_test.hpp>

#include <string>

using namespace chronik::native;

namespace {

Bytes FromHex(const std::string &hex) {
    Bytes out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(uint8_t(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

void VerifySer(const Tx &tx, const Bytes &ser) {
    BOOST_CHECK(SerializeLegacyTx(tx) == ser);
    const LegacyTxDecodeResult decoded = DecodeLegacyTx(ser);
    BOOST_REQUIRE(!decoded.error);
    BOOST_CHECK_EQUAL(decoded.consumed, ser.size());
    BOOST_CHECK_EQUAL(decoded.tx.version, tx.version);
    BOOST_CHECK(decoded.tx.inputs == tx.inputs);
    BOOST_CHECK(decoded.tx.outputs == tx.outputs);
    BOOST_CHECK_EQUAL(decoded.tx.locktime, tx.locktime);
}

} // namespace

BOOST_AUTO_TEST_SUITE(legacy_tx_tests)

// Port of bitcoinsuite-core tx::tests::test_ser_tx
BOOST_AUTO_TEST_CASE(ser_tx) {
    VerifySer(Tx{}, Bytes(10, 0));
    Tx tx;
    tx.version = 0x12345678;
    tx.locktime = 0x9abcdef1;
    VerifySer(tx, FromHex("785634120000f1debc9a"));

    Tx genesis;
    genesis.version = 1;
    TxInput input;
    input.prev_out.out_idx = 0xffff'ffff;
    input.script = FromHex(
        "04ffff001d0104455468652054696d65732030332f4a616e2f3230"
        "3039204368616e63656c6c6f72206f6e206272696e6b206f662073"
        "65636f6e64206261696c6f757420666f722062616e6b73");
    input.sequence = 0xffff'ffff;
    genesis.inputs.push_back(input);
    genesis.outputs.push_back(
        {5000000000,
         FromHex("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a679"
                 "62e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7"
                 "ba0b8d578a4c702b6bf11d5fac")});
    VerifySer(
        genesis,
        FromHex("01000000010000000000000000000000000000000000000000000000000000"
                "000000000000ffffffff4d04ffff001d0104455468652054696d6573203033"
                "2f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f"
                "66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff01"
                "00f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828"
                "e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384d"
                "f7ba0b8d578a4c702b6bf11d5fac00000000"));
}

BOOST_AUTO_TEST_CASE(errors_match_rust_data_error) {
    BOOST_CHECK_EQUAL(*DecodeLegacyTx(Bytes{}).error,
                      "Invalid length, expected 4 bytes but got 0 bytes");
    BOOST_CHECK_EQUAL(*DecodeLegacyTx(Bytes{1, 0, 0, 0, 1, 0}).error,
                      "Invalid length, expected 32 bytes but got 1 bytes");
    // Trailing bytes are accepted, like TxMut::deser
    Bytes ser(10, 0);
    ser.push_back(0xaa);
    const auto res = DecodeLegacyTx(ser);
    BOOST_CHECK(!res.error);
    BOOST_CHECK_EQUAL(res.consumed, 10U);
}

BOOST_AUTO_TEST_CASE(compact_size) {
    for (uint64_t v : {0ULL, 0xfcULL, 0xfdULL, 0xffffULL, 0x10000ULL,
                       0xffffffffULL, 0x100000000ULL}) {
        Bytes out;
        WriteCompactSize(out, v);
        BOOST_CHECK_EQUAL(out.size(), CompactSizeLen(v));
    }
}

BOOST_AUTO_TEST_SUITE_END()
