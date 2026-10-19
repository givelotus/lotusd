// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db io/blocks.rs tests.

#include <chronik/native/index/blocks.h>
#include <chronik/native/schema.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::ErrorMsg;
using chronik::native::test::TestDb;

namespace {
BlockHash HashOf(uint8_t byte) {
    BlockHash hash;
    hash.b.fill(byte);
    return hash;
}
} // namespace

BOOST_AUTO_TEST_SUITE(index_blocks_tests)

BOOST_AUTO_TEST_CASE(test_blocks) {
    TestDb db("blocks");
    const BlockWriter writer(*db);
    const TableId cf = db->Table(schema::kBlk);
    auto reader = [&](const ReadTxn &txn) { return BlockReader(*db, txn); };
    {
        auto txn = db->BeginRead();
        BOOST_CHECK_EQUAL(reader(*txn).Height(), -1);
        BOOST_CHECK(reader(*txn).Tip() == std::nullopt);
        BOOST_CHECK(reader(*txn).ByHeight(0) == std::nullopt);
    }
    const DbBlock block0{HashOf(44), HashOf(0), 0, 0x1c100000,
                         1600000000, 6,         100};
    const DbBlock block1{HashOf(22), HashOf(44), 1, 0x1c100001,
                         1600000001, 7,          200};
    {
        auto txn = db->BeginWrite();
        writer.Insert(*txn, block0);
        txn->Commit();
        auto rtxn = db->BeginRead();
        const Bytes key{0, 0, 0, 0};
        BOOST_CHECK(DeserializeSerBlock(*rtxn->Get(cf, key)) ==
                    (SerBlock{block0.hash.b, block0.n_bits, block0.timestamp,
                              block0.file_num, block0.data_pos}));
        const BlockReader blocks = reader(*rtxn);
        BOOST_CHECK_EQUAL(blocks.Height(), 0);
        BOOST_CHECK(blocks.Tip() == block0);
        BOOST_CHECK(blocks.ByHeight(0) == block0);
        BOOST_CHECK(blocks.ByHeight(1) == std::nullopt);
    }
    {
        auto txn = db->BeginWrite();
        writer.Insert(*txn, block1);
        txn->Commit();
        auto rtxn = db->BeginRead();
        const Bytes key{0, 0, 0, 1};
        BOOST_CHECK(DeserializeSerBlock(*rtxn->Get(cf, key)) ==
                    (SerBlock{block1.hash.b, block1.n_bits, block1.timestamp,
                              block1.file_num, block1.data_pos}));
        const BlockReader blocks = reader(*rtxn);
        BOOST_CHECK_EQUAL(blocks.Height(), 1);
        BOOST_CHECK(blocks.Tip() == block1);
        BOOST_CHECK(blocks.ByHeight(0) == block0);
        BOOST_CHECK(blocks.ByHeight(1) == block1);
        BOOST_CHECK(blocks.ByHeight(2) == std::nullopt);
        // by_hash (not covered by the Rust test, but by its callers)
        BOOST_CHECK(blocks.ByHash(HashOf(44)) == block0);
        BOOST_CHECK(blocks.ByHash(HashOf(22)) == block1);
        BOOST_CHECK(blocks.ByHash(HashOf(23)) == std::nullopt);
        const auto hashes = blocks.HashesByRange(0, 5);
        BOOST_CHECK_EQUAL(hashes.size(), 2U);
        BOOST_CHECK(hashes[1] == block1.hash.b);
    }
    {
        auto txn = db->BeginWrite();
        writer.Delete(*txn, block1);
        txn->Commit();
        auto rtxn = db->BeginRead();
        BOOST_CHECK(!rtxn->Get(cf, Bytes{0, 0, 0, 1}));
        BOOST_CHECK(rtxn->Get(cf, Bytes{0, 0, 0, 0}));
        const BlockReader blocks = reader(*rtxn);
        BOOST_CHECK_EQUAL(blocks.Height(), 0);
        BOOST_CHECK(blocks.Tip() == block0);
        BOOST_CHECK(blocks.ByHeight(0) == block0);
        BOOST_CHECK(blocks.ByHeight(1) == std::nullopt);
    }
    {
        auto txn = db->BeginWrite();
        writer.Delete(*txn, block0);
        txn->Commit();
        auto rtxn = db->BeginRead();
        BOOST_CHECK(!rtxn->Get(cf, Bytes{0, 0, 0, 1}));
        BOOST_CHECK(!rtxn->Get(cf, Bytes{0, 0, 0, 0}));
        const BlockReader blocks = reader(*rtxn);
        BOOST_CHECK_EQUAL(blocks.Height(), -1);
        BOOST_CHECK(blocks.Tip() == std::nullopt);
        BOOST_CHECK(blocks.ByHeight(0) == std::nullopt);
        // Lookup index is empty again
        BOOST_CHECK(!rtxn->OpenCursor(db->Table(schema::kLookupBlkByHash))
                         ->SeekFirst());
    }
    {
        auto txn = db->BeginWrite();
        txn->Put(cf, Bytes{0, 0, 0}, Bytes{});
        txn->Commit();
        auto rtxn = db->BeginRead();
        BOOST_CHECK_EQUAL(
            ErrorMsg([&] { reader(*rtxn).Height(); }),
            "Inconsistent DB: Invalid height bytes: [0, 0, 0]");
    }
    {
        auto txn = db->BeginWrite();
        txn->Put(cf, Bytes{0, 0, 0, 0}, Bytes{0xff, 0xff, 0xff});
        txn->Commit();
        auto rtxn = db->BeginRead();
        BOOST_CHECK_EQUAL(
            ErrorMsg([&] { reader(*rtxn).ByHeight(0); }),
            "Inconsistent DB: Cannot deserialize byte sequence as "
            "chronik_db::io::blocks::SerBlock: Hit the end of buffer, "
            "expected more data. Byte sequence: ffffff");
    }
}

BOOST_AUTO_TEST_SUITE_END()
