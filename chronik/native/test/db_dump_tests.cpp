// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests of the parity DB dump (core/db/dump.h).

#include <core/db/dump.h>

#include <chronik/native/schema.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

#include <sstream>

using namespace chronik::native;
using chronik::native::test::TestDb;

BOOST_AUTO_TEST_SUITE(db_dump_tests)

BOOST_AUTO_TEST_CASE(dump_plain_and_dup_tables) {
    TestDb db("dump");
    const TableId blk = db->Table(schema::kBlk);
    const TableId script_utxo = db->Table(schema::kScriptUtxo);
    const TableId token_id_utxo = db->Table(schema::kTokenIdUtxo);
    {
        auto txn = db->BeginWrite();
        txn->Put(blk, Bytes{0, 0, 0, 1}, Bytes{0xbb});
        txn->Put(blk, Bytes{0, 0, 0, 0}, Bytes{0xaa, 0x01});
        // DUPFIXED (20-byte) dups, inserted out of order
        Bytes dup_b(20, 0x02), dup_a(20, 0x01);
        txn->PutDup(script_utxo, Bytes{0x07, 0x51}, dup_b);
        txn->PutDup(script_utxo, Bytes{0x07, 0x51}, dup_a);
        txn->PutDup(script_utxo, Bytes{0x07, 0x52}, dup_a);
        // variable-length dups
        txn->PutDup(token_id_utxo, Bytes{0x01}, Bytes(13, 0x09));
        txn->PutDup(token_id_utxo, Bytes{0x01}, Bytes(12, 0x09));
        txn->Commit();
    }
    auto txn = db->BeginRead();
    const std::vector<std::string> lines = db::DumpLines(*db, *txn, db.tables);
    std::string dup_a_hex, dup_b_hex, nines12, nines13;
    for (int i = 0; i < 20; ++i) {
        dup_a_hex += "01";
        dup_b_hex += "02";
    }
    for (int i = 0; i < 12; ++i) {
        nines12 += "09";
    }
    nines13 = nines12 + "09";
    const std::vector<std::string> expected = {
        "blk\t00000000\taa01",
        "blk\t00000001\tbb",
        "script_utxo\t0751\t" + dup_a_hex,
        "script_utxo\t0751\t" + dup_b_hex,
        "script_utxo\t0752\t" + dup_a_hex,
        "token_id_utxo\t01\t" + nines12,
        "token_id_utxo\t01\t" + nines13,
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(lines.begin(), lines.end(), expected.begin(),
                                  expected.end());

    // Single table and stream form
    const std::vector<std::string> blk_lines = db::DumpTableLines(
        *db, *txn, TableSpec{schema::kBlk, TableSpec::Kind::Plain, {}});
    BOOST_CHECK_EQUAL(blk_lines.size(), 2U);
    txn.reset();
    std::ostringstream out;
    db::DumpStore(*db, db.tables, out);
    std::string joined;
    for (const std::string &line : expected) {
        joined += line + "\n";
    }
    BOOST_CHECK_EQUAL(out.str(), joined);
}

BOOST_AUTO_TEST_CASE(dump_long_keys_are_physical) {
    TestDb db("dump_long_keys");
    const TableId history = db->Table(schema::kScriptHistory);
    const Bytes long_key(8000, 0x42);
    {
        auto txn = db->BeginWrite();
        txn->Put(history, long_key, Bytes{0x01});
        txn->Commit();
    }
    auto txn = db->BeginRead();
    const std::vector<std::string> lines = db::DumpTableLines(
        *db, *txn,
        TableSpec{schema::kScriptHistory, TableSpec::Kind::Plain, {}});
    BOOST_REQUIRE_EQUAL(lines.size(), 1U);
    // "MDBX_SHA256_KEY:" || sha256(key)
    BOOST_CHECK(lines[0].rfind("script_history\t4d4442585f5348413235365f4b45593a",
                               0) == 0);
    BOOST_CHECK_EQUAL(lines[0].size(),
                      std::string("script_history\t").size() + 96 + 3);
}

BOOST_AUTO_TEST_SUITE_END()
