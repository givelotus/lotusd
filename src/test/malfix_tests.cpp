// Copyright (c) 2012-2019 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <script/standard.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

BOOST_FIXTURE_TEST_SUITE(malfix_tests, BasicTestingSetup)

uint256 hash256(std::string str) {
    uint256 result;
    CHash256().Write(ParseHex(str)).Finalize(result);
    return result;
}

CHashWriter h() {
    return CHashWriter(SER_GETHASH, 0);
}

BOOST_AUTO_TEST_CASE(txid_test_version) {
    CMutableTransaction tx;
    tx.nVersion = 0x12345678;

    // test empty tx
    BOOST_CHECK_EQUAL(tx.GetHash(), hash256("78563412"
                                            "00"
                                            "00"
                                            "00000000"));
    BOOST_CHECK_EQUAL(
        tx.GetId(),
        hash256(
            // nVersion
            "78563412"
            // inputs merkle root
            "0000000000000000000000000000000000000000000000000000000000000000"
            // inputs merkle tree height
            "00"
            // outputs merkle root
            "0000000000000000000000000000000000000000000000000000000000000000"
            // outputs merkle tree height
            "00"
            // nLockTime
            "00000000"));
}

BOOST_AUTO_TEST_CASE(txid_test_inputs) {
    CMutableTransaction tx;
    tx.nVersion = 1;

    // test empty tx
    BOOST_CHECK_EQUAL(tx.GetHash(), hash256("01000000"
                                            "00"
                                            "00"
                                            "00000000"));
    BOOST_CHECK_EQUAL(
        tx.GetId(),
        hash256(
            // nVersion
            "01000000"
            // inputs merkle root
            "0000000000000000000000000000000000000000000000000000000000000000"
            // inputs merkle tree height
            "00"
            // outputs merkle root
            "0000000000000000000000000000000000000000000000000000000000000000"
            // outputs merkle tree height
            "00"
            // nLockTime
            "00000000"));

    // test tx with 1 input
    tx.vin.resize(1);
    tx.vin[0].prevout =
        COutPoint(TxId(uint256S("0123456789abcdef0123456789abcdef0123456789abcd"
                                "ef0123456789abcdef")),
                  0x1234);
    tx.vin[0].nSequence = 0x12345678;
    BOOST_CHECK_EQUAL(
        tx.GetHash(),
        hash256(
            "01000000"
            "01"
            "efcdab8967452301efcdab8967452301efcdab8967452301efcdab8967452301"
            "34120000" // n
            "00"       // scriptSig
            "78563412" // nSequence
            "00"       // outputs
            "00000000"));
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << uint32_t(1); // nVersion
        ss << (h() << tx.vin[0].prevout << tx.vin[0].nSequence).GetHash()
           << uint8_t(1); // inputs merkle tree height
        ss << uint256() << uint8_t(0);
        ss << uint32_t(0);
        BOOST_CHECK_EQUAL(tx.GetId(), ss.GetHash());
    }
    // add script sig
    uint256 txid1 = tx.GetId();
    uint256 txhash1 = tx.GetHash();
    tx.vin[0].scriptSig = CScript() << ParseHex("4f6e652052696e67");
    BOOST_CHECK(txhash1 != tx.GetHash()); // changes txhash
    BOOST_CHECK_EQUAL(txid1, tx.GetId()); // but keeps txid unaltered

    // test tx with 2 inputs
    tx.vin.resize(2);
    tx.vin[1].prevout =
        COutPoint(TxId(uint256S("000102030405060708090a0b0c0d0e0f00010203040506"
                                "0708090a0b0c0d0e0f")),
                  0x01020304);
    tx.vin[1].nSequence = 0xabcdef;

    BOOST_CHECK_EQUAL(
        tx.GetHash(),
        hash256(
            "01000000"
            "02"
            // input 0
            "efcdab8967452301efcdab8967452301efcdab8967452301efcdab8967452301"
            "34120000"             // n
            "09084f6e652052696e67" // scriptSig
            "78563412"             // nSequence
            // input 1
            "0f0e0d0c0b0a090807060504030201000f0e0d0c0b0a09080706050403020100"
            "04030201" // n
            "00"       // scriptSig
            "efcdab00" // nSequence
            // outputs
            "00"
            "00000000"));
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << uint32_t(1); // nVersion
        ss << (h()
               << (h() << tx.vin[0].prevout << tx.vin[0].nSequence).GetHash()
               << (h() << tx.vin[1].prevout << tx.vin[1].nSequence).GetHash())
                  .GetHash()
           << uint8_t(2); // inputs merkle tree height
        ss << uint256() << uint8_t(0);
        ss << uint32_t(0);
        BOOST_CHECK_EQUAL(tx.GetId(), ss.GetHash());
    }
    // also add script sig
    uint256 txid2 = tx.GetId();
    uint256 txhash2 = tx.GetHash();
    tx.vin[1].scriptSig = CScript() << ParseHex("32f09f97bde28880");
    BOOST_CHECK(txhash2 != tx.GetHash()); // changes txhash
    BOOST_CHECK_EQUAL(txid2, tx.GetId()); // but keeps txid unaltered

    // test tx with 3 inputs
    tx.vin.resize(3);
    tx.vin[2].prevout =
        COutPoint(TxId(uint256S("0000000100020003000400050006000700080009000a00"
                                "0b000c000d000e000f")),
                  0x05040302);
    tx.vin[2].nSequence = 0x654321;
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << uint32_t(1); // nVersion
        ss << (h() << (h() << (h() << tx.vin[0].prevout << tx.vin[0].nSequence)
                                  .GetHash()
                           << (h() << tx.vin[1].prevout << tx.vin[1].nSequence)
                                  .GetHash())
                          .GetHash()
                   << (h() << (h() << tx.vin[2].prevout << tx.vin[2].nSequence)
                                  .GetHash()
                           << uint256())
                          .GetHash())
                  .GetHash()
           << uint8_t(3); // inputs merkle tree height
        ss << uint256() << uint8_t(0);
        ss << uint32_t(0);
        BOOST_CHECK_EQUAL(tx.GetId(), ss.GetHash());
    }
    // also add script sig
    uint256 txid3 = tx.GetId();
    uint256 txhash3 = tx.GetHash();
    tx.vin[2].scriptSig = CScript() << OP_0;
    BOOST_CHECK(txhash3 != tx.GetHash()); // changes txhash
    BOOST_CHECK_EQUAL(txid3, tx.GetId()); // but keeps txid unaltered

    // test tx with 4 inputs
    tx.vin.resize(4);
    tx.vin[2].prevout =
        COutPoint(TxId(uint256S("fedcba9876543210fedcba9876543210fedcba98765432"
                                "10fedcba9876543210")),
                  0x7654321);
    tx.vin[2].nSequence = 0x654321;
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << uint32_t(1); // nVersion
        ss << (h() << (h() << (h() << tx.vin[0].prevout << tx.vin[0].nSequence)
                                  .GetHash()
                           << (h() << tx.vin[1].prevout << tx.vin[1].nSequence)
                                  .GetHash())
                          .GetHash()
                   << (h() << (h() << tx.vin[2].prevout << tx.vin[2].nSequence)
                                  .GetHash()
                           << (h() << tx.vin[3].prevout << tx.vin[3].nSequence)
                                  .GetHash())
                          .GetHash())
                  .GetHash()
           << uint8_t(3); // inputs merkle tree height
        ss << uint256() << uint8_t(0);
        ss << uint32_t(0);
        BOOST_CHECK_EQUAL(tx.GetId(), ss.GetHash());
    }
    // also add script sig
    uint256 txid4 = tx.GetId();
    uint256 txhash4 = tx.GetHash();
    tx.vin[3].scriptSig = CScript() << OP_1;
    BOOST_CHECK(txhash4 != tx.GetHash()); // changes txhash
    BOOST_CHECK_EQUAL(txid4, tx.GetId()); // but keeps txid unaltered
}

BOOST_AUTO_TEST_CASE(txid_test_outputs) {
    CMutableTransaction tx;
    tx.nVersion = 1;

    // test empty tx
    BOOST_CHECK_EQUAL(tx.GetHash(), hash256("01000000"
                                            "00"
                                            "00"
                                            "00000000"));
    BOOST_CHECK_EQUAL(
        tx.GetId(),
        hash256(
            // nVersion
            "01000000"
            // inputs merkle root
            "0000000000000000000000000000000000000000000000000000000000000000"
            // inputs merkle tree height
            "00"
            // outputs merkle root
            "0000000000000000000000000000000000000000000000000000000000000000"
            // outputs merkle tree height
            "00"
            // nLockTime
            "00000000"));

    // test tx with 1 output
    tx.vout.resize(1);
    tx.vout[0].nValue = 0x1234 * SATOSHI;
    tx.vout[0].scriptPubKey = CScript() << OP_EQUAL;
    BOOST_CHECK_EQUAL(tx.GetHash(),
                      hash256("01000000"
                              "00" // inputs
                              "01"
                              "3412000000000000"
                              "0187"
                              "00000000"));
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << uint32_t(1); // nVersion
        ss << uint256() << uint8_t(0);
        ss << SerializeHash(tx.vout[0])
           << uint8_t(1); // inputs merkle tree height
        ss << uint32_t(0);
        BOOST_CHECK_EQUAL(tx.GetId(), ss.GetHash());
    }

    // test tx with 2 outputs
    tx.vout.resize(2);
    tx.vout[1].nValue = 0xabcd * SATOSHI;
    tx.vout[1].scriptPubKey = CScript() << OP_CHECKSIG;

    BOOST_CHECK_EQUAL(tx.GetHash(),
                      hash256("01000000"
                              "00" // inputs
                              "02"
                              "3412000000000000"
                              "0187"
                              "cdab000000000000"
                              "01ac"
                              "00000000"));
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << uint32_t(1); // nVersion
        ss << uint256() << uint8_t(0);
        ss << (h() << SerializeHash(tx.vout[0]) << SerializeHash(tx.vout[1]))
                  .GetHash()
           << uint8_t(2); // inputs merkle tree height
        ss << uint32_t(0);
        BOOST_CHECK_EQUAL(tx.GetId(), ss.GetHash());
    }

    // test tx with 3 outputs
    tx.vout.resize(3);
    tx.vout[2].nValue = 0x4321 * SATOSHI;
    tx.vout[2].scriptPubKey = CScript() << OP_HASH160;

    BOOST_CHECK_EQUAL(tx.GetHash(),
                      hash256("01000000"
                              "00" // inputs
                              "03"
                              "3412000000000000"
                              "0187"
                              "cdab000000000000"
                              "01ac"
                              "2143000000000000"
                              "01a9"
                              "00000000"));
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << uint32_t(1); // nVersion
        ss << uint256() << uint8_t(0);
        ss << (h() << (h() << SerializeHash(tx.vout[0])
                           << SerializeHash(tx.vout[1]))
                          .GetHash()
                   << (h() << SerializeHash(tx.vout[2]) << uint256()).GetHash())
                  .GetHash()
           << uint8_t(3); // inputs merkle tree height
        ss << uint32_t(0);
        BOOST_CHECK_EQUAL(tx.GetId(), ss.GetHash());
    }

    // test tx with 4 outputs
    tx.vout.resize(4);
    tx.vout[3].nValue = 0x5342 * SATOSHI;
    tx.vout[3].scriptPubKey = CScript() << OP_DUP;

    BOOST_CHECK_EQUAL(tx.GetHash(),
                      hash256("01000000"
                              "00" // inputs
                              "04"
                              "3412000000000000"
                              "0187"
                              "cdab000000000000"
                              "01ac"
                              "2143000000000000"
                              "01a9"
                              "4253000000000000"
                              "0176"
                              "00000000"));
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << uint32_t(1); // nVersion
        ss << uint256() << uint8_t(0);
        ss << (h() << (h() << SerializeHash(tx.vout[0])
                           << SerializeHash(tx.vout[1]))
                          .GetHash()
                   << (h() << SerializeHash(tx.vout[2])
                           << SerializeHash(tx.vout[3]))
                          .GetHash())
                  .GetHash()
           << uint8_t(3); // inputs merkle tree height
        ss << uint32_t(0);
        BOOST_CHECK_EQUAL(tx.GetId(), ss.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(txid_test_locktime) {
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0x12345678;

    // test empty tx
    BOOST_CHECK_EQUAL(tx.GetHash(), hash256("01000000"
                                            "00"
                                            "00"
                                            "78563412"));
    BOOST_CHECK_EQUAL(
        tx.GetId(),
        hash256(
            // nVersion
            "01000000"
            // inputs merkle root
            "0000000000000000000000000000000000000000000000000000000000000000"
            // inputs merkle tree height
            "00"
            // outputs merkle root
            "0000000000000000000000000000000000000000000000000000000000000000"
            // outputs merkle tree height
            "00"
            // nLockTime
            "78563412"));
}

BOOST_AUTO_TEST_SUITE_END()
