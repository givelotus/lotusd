// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db reverse_lookup.rs tests.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/index/reverse_lookup.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

#include <random>

using namespace chronik::native;
using namespace chronik::native::index;
using chronik::native::test::TestDb;

namespace {

struct TestData {
    Key32 key{};
    uint32_t payload{};
    bool operator==(const TestData &) const = default;
};

Bytes SerTestData(const TestData &data) {
    Bytes out;
    postcard::Writer w(out);
    w.Raw(data.key);
    w.U32(data.payload);
    return out;
}

TestData DeserTestData(ByteView bytes) {
    return postcard::DbDeserialize(bytes, "chronik_db::reverse_lookup::tests::TestData",
                                   [](postcard::Reader &r) {
                                       TestData data;
                                       data.key = r.Array<32>();
                                       data.payload = r.U32();
                                       return data;
                                   });
}

constexpr std::string_view CF_TEST = "test";
constexpr std::string_view CF_TEST_INDEX = "test_index";

struct TestColumn {
    using SerialNum = uint32_t;
    using Data = TestData;
    static constexpr std::string_view kCfData = CF_TEST;
    static constexpr std::string_view kCfIndex = CF_TEST_INDEX;
    static constexpr std::string_view kSerialTypeName = "u32";
    static constexpr std::string_view kSerialVecTypeName =
        "alloc::vec::Vec<u32>";

    const ReadTxn &txn;
    TableId cf_data;
    TableId cf_index;

    static Bytes CheapHash(const Key32 &key) {
        // "Hash" here simply takes the mod 10, giving us lots of collisions
        return Bytes{uint8_t(key[0] % 10)};
    }
    static const Key32 &DataKey(const TestData &data) { return data.key; }
    static void SerSerial(postcard::Writer &w, uint32_t num) { w.U32(num); }
    static uint32_t DeserSerial(postcard::Reader &r) { return r.U32(); }
    TableId IndexTable() const { return cf_index; }

    std::optional<TestData> GetData(uint32_t number) const {
        const auto bytes = txn.Get(cf_data, ToBe<uint32_t>(number));
        if (!bytes) {
            return std::nullopt;
        }
        return DeserTestData(*bytes);
    }
    std::vector<std::optional<TestData>>
    GetDataMulti(const std::vector<uint32_t> &numbers) const {
        std::vector<std::optional<TestData>> out;
        for (const uint32_t number : numbers) {
            out.push_back(GetData(number));
        }
        return out;
    }
};

using Index = ReverseLookup<TestColumn>;

const std::vector<TableSpec> kTestTables = {
    {CF_TEST, TableSpec::Kind::Plain, std::nullopt},
    {CF_TEST_INDEX, TableSpec::Kind::Plain, std::nullopt},
};

Key32 KeyOf(uint8_t byte) {
    Key32 key;
    key.fill(byte);
    return key;
}

Bytes SerNums(const std::vector<uint32_t> &nums) {
    return Index::SerSerials(nums);
}

std::optional<Bytes> GetIndex(KvStore &store, uint8_t cheap_hash) {
    auto txn = store.BeginRead();
    const auto value =
        txn->Get(store.Table(CF_TEST_INDEX), Bytes{cheap_hash});
    if (!value) {
        return std::nullopt;
    }
    return Bytes(value->begin(), value->end());
}

} // namespace

BOOST_AUTO_TEST_SUITE(index_reverse_lookup_tests)

BOOST_AUTO_TEST_CASE(test_reverse_lookup) {
    TestDb db("lookup", kTestTables);
    const TableId cf_data = db->Table(CF_TEST);
    const TableId cf_index = db->Table(CF_TEST_INDEX);
    auto get = [&](const Key32 &key) {
        auto txn = db->BeginRead();
        return Index::Get(TestColumn{*txn, cf_data, cf_index}, *txn, key);
    };
    using Found = std::optional<std::pair<uint32_t, TestData>>;
    // First insert
    const uint32_t number0 = 100;
    const Key32 key0 = KeyOf(100);
    const TestData data0{key0, 0xdeadbeef};
    {
        auto txn = db->BeginWrite();
        txn->Put(cf_data, ToBe<uint32_t>(number0), SerTestData(data0));
        Index::InsertPairs(TestColumn{*txn, cf_data, cf_index}, *txn,
                           {{number0, key0}});
        txn->Commit();
        BOOST_CHECK(get(key0) == Found(std::make_pair(number0, data0)));
        BOOST_CHECK(GetIndex(*db, 0) == SerNums({number0}));
    }
    // Second insert, inserts 3 at once
    const uint32_t number1 = 101;
    const Key32 key1 = KeyOf(101); // collides with key3
    const TestData data1{key1, 0xcafe};
    const uint32_t number2 = 110;
    const Key32 key2 = KeyOf(110); // collides with key0
    const TestData data2{key2, 0xabcd};
    const uint32_t number3 = 111;
    const Key32 key3 = KeyOf(111); // collides with key1
    const TestData data3{key3, 0xfedc};
    {
        auto txn = db->BeginWrite();
        txn->Put(cf_data, ToBe<uint32_t>(number1), SerTestData(data1));
        txn->Put(cf_data, ToBe<uint32_t>(number2), SerTestData(data2));
        txn->Put(cf_data, ToBe<uint32_t>(number3), SerTestData(data3));
        Index::InsertPairs(TestColumn{*txn, cf_data, cf_index}, *txn,
                           {{number1, key1}, {number2, key2}, {number3, key3}});
        txn->Commit();
        BOOST_CHECK(get(key0) == Found(std::make_pair(number0, data0)));
        BOOST_CHECK(get(key1) == Found(std::make_pair(number1, data1)));
        BOOST_CHECK(get(key2) == Found(std::make_pair(number2, data2)));
        BOOST_CHECK(get(key3) == Found(std::make_pair(number3, data3)));
        BOOST_CHECK(GetIndex(*db, 0) == SerNums({number0, number2}));
        BOOST_CHECK(GetIndex(*db, 1) == SerNums({number1, number3}));
    }
    // Delete key1, key2, key3
    {
        auto txn = db->BeginWrite();
        Index::DeletePairs(TestColumn{*txn, cf_data, cf_index}, *txn,
                           {{number1, key1}, {number2, key2}, {number3, key3}});
        txn->Commit();
        BOOST_CHECK(get(key1) == std::nullopt);
        BOOST_CHECK(get(key2) == std::nullopt);
        BOOST_CHECK(get(key3) == std::nullopt);
        BOOST_CHECK(get(key0) == Found(std::make_pair(number0, data0)));
        BOOST_CHECK(GetIndex(*db, 0) == SerNums({number0}));
        BOOST_CHECK(GetIndex(*db, 1) == std::nullopt);
    }
    // Delete key0
    {
        auto txn = db->BeginWrite();
        Index::DeletePairs(TestColumn{*txn, cf_data, cf_index}, *txn,
                           {{number0, key0}});
        txn->Commit();
        BOOST_CHECK(get(key0) == std::nullopt);
        BOOST_CHECK(GetIndex(*db, 0) == std::nullopt);
        BOOST_CHECK(GetIndex(*db, 1) == std::nullopt);
    }
    // Deleting an unknown serial fails (NotInDataColumn)
    {
        auto txn = db->BeginWrite();
        BOOST_CHECK_EQUAL(
            test::ErrorMsg([&] {
                Index::DeletePairs(TestColumn{*txn, cf_data, cf_index}, *txn,
                                   {{number0, key0}});
            }),
            "Inconsistent DB: Lookup index test contains 100, but value "
            "column test_index doesn't");
    }
}

BOOST_AUTO_TEST_CASE(test_reverse_lookup_rng) {
    std::mt19937 rng(0);
    TestDb db("lookup_rng", kTestTables);
    const TableId cf_data = db->Table(CF_TEST);
    const TableId cf_index = db->Table(CF_TEST_INDEX);

    using Entry = std::pair<uint32_t, TestData>;
    std::vector<Entry> test_data;
    for (uint32_t num = 0; num < 1000; ++num) {
        TestData data;
        data.payload = uint32_t(rng());
        for (uint8_t &byte : data.key) {
            byte = uint8_t(rng());
        }
        test_data.emplace_back(num, data);
    }
    auto slice = [&](size_t begin, size_t end) {
        return std::vector<Entry>(test_data.begin() + begin,
                                  test_data.begin() + end);
    };

    auto insert_data = [&](const std::vector<Entry> &entries) {
        auto txn = db->BeginWrite();
        std::vector<std::pair<uint32_t, Key32>> pairs;
        for (const auto &[num, data] : entries) {
            pairs.emplace_back(num, data.key);
        }
        Index::InsertPairs(TestColumn{*txn, cf_data, cf_index}, *txn, pairs);
        for (const auto &[num, data] : entries) {
            txn->Put(cf_data, ToBe<uint32_t>(num), SerTestData(data));
        }
        txn->Commit();
    };
    auto delete_data = [&](const std::vector<Entry> &entries) {
        auto txn = db->BeginWrite();
        std::vector<std::pair<uint32_t, Key32>> pairs;
        for (const auto &[num, data] : entries) {
            pairs.emplace_back(num, data.key);
        }
        Index::DeletePairs(TestColumn{*txn, cf_data, cf_index}, *txn, pairs);
        for (const auto &[num, data] : entries) {
            txn->Del(cf_data, ToBe<uint32_t>(num));
        }
        txn->Commit();
    };
    auto check_data = [&](const std::vector<Entry> &entries) {
        auto txn = db->BeginRead();
        const TestColumn col{*txn, cf_data, cf_index};
        std::vector<Key32> keys;
        for (const auto &[expected_num, expected_data] : entries) {
            const auto actual = Index::Get(col, *txn, expected_data.key);
            BOOST_REQUIRE(actual.has_value());
            BOOST_CHECK_EQUAL(actual->first, expected_num);
            BOOST_CHECK(actual->second == expected_data);
            keys.push_back(expected_data.key);
        }
        const auto batch_result = Index::GetMulti(col, *txn, keys);
        BOOST_REQUIRE_EQUAL(batch_result.size(), entries.size());
        for (size_t i = 0; i < entries.size(); ++i) {
            BOOST_CHECK(batch_result[i] == std::optional<Entry>(entries[i]));
        }
    };
    auto check_not_data = [&](const std::vector<Entry> &entries) {
        auto txn = db->BeginRead();
        const TestColumn col{*txn, cf_data, cf_index};
        std::vector<Key32> keys;
        for (const auto &[num, data] : entries) {
            BOOST_CHECK(!Index::Get(col, *txn, data.key).has_value());
            keys.push_back(data.key);
        }
        const auto batch_result = Index::GetMulti(col, *txn, keys);
        BOOST_REQUIRE_EQUAL(batch_result.size(), entries.size());
        for (const auto &result : batch_result) {
            BOOST_CHECK(!result.has_value());
        }
    };

    // Insert first 400 entries
    insert_data(slice(0, 400));
    check_data(slice(0, 400));
    check_not_data(slice(400, 1000));

    // Insert next 600 entries
    insert_data(slice(400, 1000));
    check_data(test_data);

    // Delete last 600 entries again
    delete_data(slice(400, 1000));
    check_data(slice(0, 400));
    check_not_data(slice(400, 1000));

    // Delete remaining 400 entries
    delete_data(slice(0, 400));
    check_not_data(test_data);
}

BOOST_AUTO_TEST_SUITE_END()
