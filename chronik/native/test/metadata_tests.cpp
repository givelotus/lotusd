// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Ports of chronik-db io/metadata.rs and the chronik-indexer verify_* checks.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/error.h>
#include <chronik/native/metadata.h>
#include <chronik/native/schema.h>
#include <chronik/native/store.h>
#if CHRONIK_NATIVE_HAVE_MDBX
#include <chronik/native/mdbx_store.h>
#endif

#include <test/test_sha256.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <random>

using namespace chronik::native;

namespace {

struct TempDir {
    std::filesystem::path path;
    explicit TempDir(const std::string &name) {
        static std::atomic<int> counter{0};
        std::random_device rd;
        path = std::filesystem::temp_directory_path() /
               ("chronik-native-meta-" + name + "-" + std::to_string(rd()) +
                "-" + std::to_string(counter++));
        std::filesystem::remove_all(path);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

struct Logs {
    std::vector<std::string> lines;
    MetaLogFn Fn() {
        return [this](const std::string &s) { lines.push_back(s); };
    }
};

#if CHRONIK_NATIVE_HAVE_MDBX
struct Fixture {
    TempDir dir{"db"};
    std::unique_ptr<KvStore> store;
    Fixture() { Open(); }
    void Open() {
        RegisterMdbxStore();
        store.reset();
        StoreOptions opts;
        opts.sha256 = [](ByteView d, uint8_t out[32]) {
            test::TestSha256(d, out);
        };
        store = OpenStore(StoreBackend::Mdbx, dir.path, schema::EcashTables(),
                          opts);
    }
    TableId T(std::string_view name) const { return store->Table(name); }
    void Put(std::string_view table, ByteView key, ByteView value) {
        auto txn = store->BeginWrite();
        txn->Put(T(table), key, value);
        txn->Commit();
    }
    void PutMeta(std::string_view field, ByteView value) {
        Put(schema::kMeta, AsView(field), value);
    }
    uint64_t Count(std::string_view table) const {
        return store->BeginRead()->EstimateEntries(T(table));
    }
    MetadataReader Reader(const ReadTxn &txn) const {
        return MetadataReader(txn, T(schema::kMeta));
    }
    /** Something non-meta, so the DB is non-empty */
    void MakeNonEmpty() { Put(schema::kBlk, Bytes{0, 0, 0, 0}, Bytes{1}); }
};

Bytes PostcardU64(uint64_t v) {
    Bytes out;
    postcard::Writer(out).U64(v);
    return out;
}

void CheckThrowsText(const std::function<void()> &f,
                     const std::string &expected) {
    try {
        f();
        BOOST_ERROR("expected exception: " << expected);
    } catch (const ChronikError &e) {
        BOOST_CHECK_EQUAL(std::string(e.what()), expected);
    }
}
#endif

} // namespace

BOOST_AUTO_TEST_SUITE(metadata_tests)

BOOST_AUTO_TEST_CASE(ecash_schema_tables) {
    const auto tables = schema::EcashTables();
    BOOST_CHECK_EQUAL(tables.size(), 26u);
    BOOST_CHECK_EQUAL(tables[0].name, "blk");
    BOOST_CHECK_EQUAL(tables[3].name, "meta");
    for (const TableSpec &t : tables) {
        BOOST_CHECK(t.name.rfind("v2_", 0) != 0);
        if (t.name == "script_utxo") {
            BOOST_CHECK(t.kind == TableSpec::Kind::Dup);
            BOOST_CHECK(t.dup_fixed_size == std::optional<uint32_t>(20));
        } else if (t.name == "token_id_utxo" || t.name == "plugin_utxos") {
            BOOST_CHECK(t.kind == TableSpec::Kind::Dup);
            BOOST_CHECK(!t.dup_fixed_size);
        } else {
            BOOST_CHECK(t.kind == TableSpec::Kind::Plain);
        }
    }
    schema::Schema s;
    BOOST_CHECK_EQUAL(s.Tables().size(), 26u);
    s.Add({"ext_table", TableSpec::Kind::Plain, std::nullopt});
    BOOST_CHECK_EQUAL(s.Tables().size(), 27u);
    BOOST_CHECK_EQUAL(s.Tables().back().name, "ext_table");
    BOOST_CHECK_THROW(s.Add({"blk", TableSpec::Kind::Plain, std::nullopt}),
                      ChronikError);
}

BOOST_AUTO_TEST_CASE(legacy_rocksdb_refused) {
    TempDir dir("rocks");
    BOOST_CHECK_NO_THROW(RefuseLegacyRocksDb(dir.path)); // nonexistent
    std::filesystem::create_directories(dir.path);
    BOOST_CHECK_NO_THROW(RefuseLegacyRocksDb(dir.path));
    std::ofstream(dir.path / "mdbx.dat") << "x";
    BOOST_CHECK_NO_THROW(RefuseLegacyRocksDb(dir.path));
    for (const char *name : {"CURRENT", "IDENTITY", "rocksdb.bak",
                             "MANIFEST-000005", "OPTIONS-000007", "000042.sst"}) {
        BOOST_TEST_CONTEXT(name) {
            TempDir d2("rocks2");
            std::filesystem::create_directories(d2.path);
            std::ofstream(d2.path / name) << "x";
            try {
                RefuseLegacyRocksDb(d2.path);
                BOOST_ERROR("not refused");
            } catch (const ChronikError &e) {
                const std::string msg = e.what();
                BOOST_CHECK(msg.rfind("Existing RocksDB index at " +
                                          d2.path.string() +
                                          "; automatic MDBX migration is "
                                          "unsupported.",
                                      0) == 0);
                BOOST_CHECK(msg.find("-chronikreindex=1") != std::string::npos);
            }
            BOOST_CHECK(std::filesystem::exists(d2.path / name));
        }
    }
}

#if CHRONIK_NATIVE_HAVE_MDBX

// io/metadata.rs test_metadata
BOOST_AUTO_TEST_CASE(metadata_roundtrip) {
    Fixture f;
    {
        auto txn = f.store->BeginRead();
        auto r = f.Reader(*txn);
        BOOST_CHECK(!r.GetSchemaVersion());
        BOOST_CHECK(r.IsTokenIndexEnabled());
        BOOST_CHECK(!r.IsLokadIdIndexEnabled());
        BOOST_CHECK(!r.IsScripthashIndexEnabled());
        BOOST_CHECK(!r.NativeLastWriter());
    }
    {
        auto txn = f.store->BeginWrite();
        MetadataWriter w(*txn, f.T(schema::kMeta));
        w.UpdateSchemaVersion(1337);
        w.UpdateIsTokenIndexEnabled(false);
        w.UpdateIsLokadIdIndexEnabled(true);
        w.UpdateIsScripthashIndexEnabled(false);
        w.UpdateNativeLastWriter("native/v0.34.1");
        txn->Commit();
    }
    auto txn = f.store->BeginRead();
    auto r = f.Reader(*txn);
    BOOST_CHECK_EQUAL(*r.GetSchemaVersion(), 1337u);
    BOOST_CHECK(!r.IsTokenIndexEnabled());
    BOOST_CHECK(*r.IsLokadIdIndexEnabled());
    BOOST_CHECK(!*r.IsScripthashIndexEnabled());
    BOOST_CHECK_EQUAL(*r.NativeLastWriter(), "native/v0.34.1");
    // Exact postcard bytes
    const auto raw = txn->Get(f.T(schema::kMeta), AsView(meta_fields::kSchemaVersion));
    BOOST_CHECK(Bytes(raw->begin(), raw->end()) == (Bytes{0xb9, 0x0a}));
    const auto rawb = txn->Get(f.T(schema::kMeta), AsView(meta_fields::kTokenIndexEnabled));
    BOOST_CHECK(Bytes(rawb->begin(), rawb->end()) == (Bytes{0x00}));
    const auto raww = txn->Get(f.T(schema::kMeta), AsView(meta_fields::kNativeLastWriter));
    BOOST_CHECK_EQUAL(raww->size(), 15u);
    BOOST_CHECK_EQUAL((*raww)[0], 14);
}

BOOST_AUTO_TEST_CASE(schema_version_fresh_db) {
    Fixture f;
    Logs logs;
    VerifySchemaVersion(*f.store, logs.Fn());
    BOOST_REQUIRE_EQUAL(logs.lines.size(), 1u);
    BOOST_CHECK_EQUAL(logs.lines[0],
                      "Chronik has version 13, initialized DB with that version\n");
    {
        auto txn = f.store->BeginRead();
        BOOST_CHECK_EQUAL(*f.Reader(*txn).GetSchemaVersion(), 13u);
    }
    // Reopen: the DB now has the current version
    logs.lines.clear();
    VerifySchemaVersion(*f.store, logs.Fn());
    BOOST_CHECK_EQUAL(logs.lines.at(0), "Chronik has version 13, DB has version 13\n");
}

BOOST_AUTO_TEST_CASE(schema_version_errors) {
    Logs logs;
    {
        Fixture f;
        f.MakeNonEmpty();
        CheckThrowsText([&] { VerifySchemaVersion(*f.store, logs.Fn()); },
                        "Missing schema version in non-empty Chronik database, "
                        "consider running -reindex/-chronikreindex");
    }
    {
        Fixture f;
        f.PutMeta(meta_fields::kSchemaVersion, PostcardU64(14));
        CheckThrowsText([&] { VerifySchemaVersion(*f.store, logs.Fn()); },
                        "Chronik outdated: Chronik has version 13, but the "
                        "database has version 14. Upgrade your node to the "
                        "appropriate version.");
    }
    {
        Fixture f;
        f.PutMeta(meta_fields::kSchemaVersion, PostcardU64(12));
        CheckThrowsText([&] { VerifySchemaVersion(*f.store, logs.Fn()); },
                        "DB outdated: Chronik has version 13, but the database "
                        "has version 12. -reindex/-chronikreindex to reindex "
                        "the database to the new version.");
    }
    {
        Fixture f;
        f.PutMeta(meta_fields::kSchemaVersion, Bytes{0xff});
        CheckThrowsText([&] { VerifySchemaVersion(*f.store, logs.Fn()); },
                        "Corrupted schema version in the Chronik database, "
                        "consider running -reindex/-chronikreindex");
    }
    {
        // Leftover bytes are corruption too
        Fixture f;
        f.PutMeta(meta_fields::kSchemaVersion, Bytes{13, 0});
        BOOST_CHECK_THROW(VerifySchemaVersion(*f.store, logs.Fn()), ChronikError);
    }
}

BOOST_AUTO_TEST_CASE(token_index_flag) {
    Logs logs;
    {
        // Empty DB: either setting is accepted and recorded
        Fixture f;
        VerifyEnableTokenIndex(*f.store, false, logs.Fn());
        auto txn = f.store->BeginRead();
        BOOST_CHECK(!f.Reader(*txn).IsTokenIndexEnabled());
        BOOST_CHECK(logs.lines.empty());
    }
    {
        // Non-empty DB, previously disabled -> enabling is refused
        Fixture f;
        f.MakeNonEmpty();
        f.PutMeta(meta_fields::kTokenIndexEnabled, Bytes{0});
        CheckThrowsText(
            [&] { VerifyEnableTokenIndex(*f.store, true, logs.Fn()); },
            "Cannot enable -chroniktokenindex on a DB that previously had it "
            "disabled. Provide -reindex/-chronikreindex to reindex the "
            "database with token data, or specify -chroniktokenindex=0 to "
            "disable the token index again.");
        // Staying disabled is fine
        BOOST_CHECK_NO_THROW(VerifyEnableTokenIndex(*f.store, false, logs.Fn()));
        BOOST_CHECK(logs.lines.empty());
    }
    {
        // Non-empty DB, unset (= enabled) -> disabling wipes the token tables
        Fixture f;
        f.MakeNonEmpty();
        f.Put(schema::kTokenMeta, Bytes{1}, Bytes{2});
        f.Put(schema::kTokenTx, Bytes{1}, Bytes{2});
        f.Put(schema::kTokenGenesisInfo, Bytes{1}, Bytes{2});
        f.Put(schema::kTokenIdHistory, Bytes{1}, Bytes{2});
        VerifyEnableTokenIndex(*f.store, false, logs.Fn());
        BOOST_CHECK_EQUAL(f.Count(schema::kTokenMeta), 0u);
        BOOST_CHECK_EQUAL(f.Count(schema::kTokenTx), 0u);
        BOOST_CHECK_EQUAL(f.Count(schema::kTokenGenesisInfo), 0u);
        // TokenWriter::wipe leaves the token_id group tables alone
        BOOST_CHECK_EQUAL(f.Count(schema::kTokenIdHistory), 1u);
        BOOST_REQUIRE_EQUAL(logs.lines.size(), 2u);
        BOOST_CHECK_EQUAL(logs.lines[0],
                          "Warning: Wiping existing token index, since "
                          "-chroniktokenindex=0\n");
        auto txn = f.store->BeginRead();
        BOOST_CHECK(!f.Reader(*txn).IsTokenIndexEnabled());
    }
}

BOOST_AUTO_TEST_CASE(lokad_and_scripthash_flags) {
    Logs logs;
    {
        Fixture f;
        BOOST_CHECK(!VerifyLokadIdIndex(*f.store, true, true, logs.Fn()));
        BOOST_CHECK(!VerifyScripthashIndex(*f.store, true, true, logs.Fn()));
        auto txn = f.store->BeginRead();
        BOOST_CHECK(*f.Reader(*txn).IsLokadIdIndexEnabled());
        BOOST_CHECK(*f.Reader(*txn).IsScripthashIndexEnabled());
    }
    {
        // Non-empty without the index: enabling requests a reindex and does
        // not record the flag
        Fixture f;
        f.MakeNonEmpty();
        BOOST_CHECK(VerifyLokadIdIndex(*f.store, false, true, logs.Fn()));
        BOOST_CHECK(VerifyScripthashIndex(*f.store, false, true, logs.Fn()));
        auto txn = f.store->BeginRead();
        BOOST_CHECK(!f.Reader(*txn).IsLokadIdIndexEnabled());
        BOOST_CHECK(!f.Reader(*txn).IsScripthashIndexEnabled());
    }
    {
        // Non-empty with the index: disabling wipes it
        Fixture f;
        f.MakeNonEmpty();
        f.PutMeta(meta_fields::kLokadIdIndexEnabled, Bytes{1});
        f.PutMeta(meta_fields::kScripthashIndexEnabled, Bytes{1});
        f.Put(schema::kLokadIdHistory, Bytes{1}, Bytes{2});
        f.Put(schema::kLokadIdHistoryNumTxs, Bytes{1}, Bytes{2});
        f.Put(schema::kScripthash, Bytes{1}, Bytes{2});
        f.Put(schema::kScriptHistory, Bytes{1}, Bytes{2});
        logs.lines.clear();
        BOOST_CHECK(!VerifyLokadIdIndex(*f.store, false, false, logs.Fn()));
        BOOST_CHECK(!VerifyScripthashIndex(*f.store, false, false, logs.Fn()));
        BOOST_CHECK_EQUAL(f.Count(schema::kLokadIdHistory), 0u);
        BOOST_CHECK_EQUAL(f.Count(schema::kLokadIdHistoryNumTxs), 0u);
        BOOST_CHECK_EQUAL(f.Count(schema::kScripthash), 0u);
        BOOST_CHECK_EQUAL(f.Count(schema::kScriptHistory), 1u);
        BOOST_REQUIRE_EQUAL(logs.lines.size(), 4u);
        BOOST_CHECK_EQUAL(logs.lines[2],
                          "Warning: Wiping existing scripthash index, since "
                          "-chronikscripthashindex=0\n");
        auto txn = f.store->BeginRead();
        BOOST_CHECK(!*f.Reader(*txn).IsLokadIdIndexEnabled());
        BOOST_CHECK(!*f.Reader(*txn).IsScripthashIndexEnabled());
    }
}

BOOST_AUTO_TEST_CASE(plugin_data_refused) {
    Logs logs;
    Fixture f;
    BOOST_CHECK_NO_THROW(RefuseIfPluginData(*f.store));
    f.PutMeta(meta_fields::kSchemaVersion, PostcardU64(13));
    f.Put(schema::kPluginMeta, Bytes{1}, Bytes{2});
    PrepareDbParams params;
    params.enable_token_index = false;
    CheckThrowsText([&] { PrepareDb(*f.store, params, logs.Fn()); },
                    std::string(kPluginDataError));
    // Refused before any flag was rewritten
    auto txn = f.store->BeginRead();
    BOOST_CHECK(!txn->Get(f.T(schema::kMeta), AsView(meta_fields::kTokenIndexEnabled)));
}

BOOST_AUTO_TEST_CASE(prepare_db_sequence) {
    Logs logs;
    Fixture f;
    PrepareDbParams params;
    params.native_last_writer = "native/test";
    PreparedDb p = PrepareDb(*f.store, params, logs.Fn());
    BOOST_CHECK(!p.needs_lokad_id_reindex);
    BOOST_CHECK(!p.needs_scripthash_reindex);
    {
        auto txn = f.store->BeginRead();
        auto r = f.Reader(*txn);
        BOOST_CHECK_EQUAL(*r.GetSchemaVersion(), 13u);
        BOOST_CHECK(r.IsTokenIndexEnabled());
        BOOST_CHECK(*r.IsLokadIdIndexEnabled());
        BOOST_CHECK(!*r.IsScripthashIndexEnabled());
        BOOST_CHECK_EQUAL(*r.NativeLastWriter(), "native/test");
    }
    // Reopen with indexed data and scripthash newly enabled -> reindex
    f.MakeNonEmpty();
    f.Open();
    params.enable_scripthash_index = true;
    params.native_last_writer.clear();
    p = PrepareDb(*f.store, params, logs.Fn());
    BOOST_CHECK(!p.needs_lokad_id_reindex);
    BOOST_CHECK(p.needs_scripthash_reindex);
    auto txn = f.store->BeginRead();
    BOOST_CHECK_EQUAL(*f.Reader(*txn).NativeLastWriter(), "native/test");
}

#endif // CHRONIK_NATIVE_HAVE_MDBX

BOOST_AUTO_TEST_SUITE_END()
