// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db io/merge.rs tests.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/error.h>
#include <chronik/native/index/merge.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::ErrorMsg;
using chronik::native::test::TestDb;

namespace {

uint32_t InitMerge(ByteView, std::optional<ByteView> existing_value, size_t) {
    if (!existing_value) {
        return 0;
    }
    if (existing_value->size() != 4) {
        throw ChronikError("Test init merge error");
    }
    return FromBe<uint32_t>(*existing_value);
}

void ApplyMerge(ByteView, uint32_t &value, ByteView operand) {
    if (operand.size() != 4) {
        throw ChronikError("Test apply merge error");
    }
    value += FromBe<uint32_t>(operand);
}

Bytes SerMerge(ByteView, uint32_t &&value) {
    if (value == 1337) {
        throw ChronikError("Test ser merge error");
    }
    const auto be = ToBe<uint32_t>(value);
    return Bytes(be.begin(), be.end());
}

Bytes U32Be(uint32_t v) {
    const auto be = ToBe<uint32_t>(v);
    return Bytes(be.begin(), be.end());
}

Bytes Str(std::string_view s) {
    return Bytes(s.begin(), s.end());
}

void Merge(WriteTxn &txn, TableId cf, std::string_view key,
           const std::vector<Bytes> &operands) {
    merge::CatchMergeErrors(txn, cf, AsView(key), operands, InitMerge,
                            ApplyMerge, SerMerge);
}

std::optional<Bytes> Get(KvStore &store, TableId cf, std::string_view key) {
    auto txn = store.BeginRead();
    const auto value = txn->Get(cf, AsView(key));
    if (!value) {
        return std::nullopt;
    }
    return Bytes(value->begin(), value->end());
}

} // namespace

BOOST_AUTO_TEST_SUITE(index_merge_tests)

BOOST_AUTO_TEST_CASE(test_catch_merge) {
    TestDb db("catch_merge",
              {TableSpec{"test_cf", TableSpec::Kind::Plain, std::nullopt}});
    const TableId cf = db->Table("test_cf");
    // Clear errors left over by other tests
    ErrorMsg([] { merge::CheckForErrors(); });

    {
        auto txn = db->BeginWrite();
        txn->Put(cf, AsView(std::string_view("bad_init")), Str("bad"));
        Merge(*txn, cf, "bad_init", {U32Be(1234)});
        txn->Commit();
    }
    // Merge op called: turned into no-op (keeps "bad" value)
    BOOST_CHECK(Get(*db, cf, "bad_init") == Str("bad"));
    // Error caught
    BOOST_CHECK_EQUAL(ErrorMsg([] { merge::CheckForErrors(); }),
                      "Test init merge error");
    BOOST_CHECK_EQUAL(ErrorMsg([] { merge::CheckForErrors(); }),
                      "<no exception>");

    {
        auto txn = db->BeginWrite();
        Merge(*txn, cf, "bad_apply", {Str("bad")});
        txn->Commit();
    }
    // Merge op called: turned into no-op (insert default value)
    BOOST_CHECK(Get(*db, cf, "bad_apply") == Bytes(4, 0));
    BOOST_CHECK_EQUAL(ErrorMsg([] { merge::CheckForErrors(); }),
                      "Test apply merge error");

    {
        auto txn = db->BeginWrite();
        Merge(*txn, cf, "chain_apply",
              {U32Be(1), U32Be(2), Str("bad"), U32Be(4), U32Be(8)});
        txn->Commit();
    }
    // Merge op called: Only 1 and 2 merged, "bad" stops the apply chain
    BOOST_CHECK(Get(*db, cf, "chain_apply") == U32Be(3));
    BOOST_CHECK_EQUAL(ErrorMsg([] { merge::CheckForErrors(); }),
                      "Test apply merge error");

    {
        auto txn = db->BeginWrite();
        Merge(*txn, cf, "bad_ser", {U32Be(1337)});
        txn->Commit();
    }
    // Merge op called: Serialization failed, inserts empty string
    BOOST_CHECK(Get(*db, cf, "bad_ser") == Bytes{});
    BOOST_CHECK_EQUAL(ErrorMsg([] { merge::CheckForErrors(); }),
                      "Test ser merge error");

    // Successful merges onto existing values; logger sees failures
    std::vector<std::string> logged;
    merge::SetErrorLogger([&](const std::string &msg) { logged.push_back(msg); });
    {
        auto txn = db->BeginWrite();
        Merge(*txn, cf, "chain_apply", {U32Be(10)});
        Merge(*txn, cf, "chain_apply", {U32Be(100)});
        Merge(*txn, cf, "bad_init", {U32Be(1)});
        txn->Commit();
    }
    merge::SetErrorLogger(nullptr);
    BOOST_CHECK(Get(*db, cf, "chain_apply") == U32Be(113));
    BOOST_CHECK(logged ==
                std::vector<std::string>{"MERGE ERROR: Test init merge error\n"});
    BOOST_CHECK_EQUAL(ErrorMsg([] { merge::CheckForErrors(); }),
                      "Test init merge error");
}

BOOST_AUTO_TEST_SUITE_END()
