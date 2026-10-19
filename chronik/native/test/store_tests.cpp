// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// KvStore conformance suite, run against every storage backend linked into
// the test binary, plus MDBX-specific environment checks.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/schema.h>
#include <chronik/native/store.h>
#if CHRONIK_NATIVE_HAVE_MDBX
#include <chronik/native/mdbx_store.h>
#endif
#if CHRONIK_NATIVE_HAVE_LEVELDB
#include <chronik/native/leveldb_store.h>
#endif

#include <test/test_sha256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <chrono>
#include <map>
#include <random>
#include <set>
#include <thread>

using namespace chronik::native;

namespace {

/** Registers every backend linked into this test binary. */
void RegisterTestStoreBackends() {
#if CHRONIK_NATIVE_HAVE_MDBX
    RegisterMdbxStore();
#endif
#if CHRONIK_NATIVE_HAVE_LEVELDB
    RegisterLevelDbStore();
#endif
}

/** Fresh temporary directory, removed on destruction. */
struct TempDir {
    std::filesystem::path path;
    explicit TempDir(const std::string &name) {
        static std::atomic<int> counter{0};
        std::random_device rd;
        path = std::filesystem::temp_directory_path() /
               ("chronik-native-" + name + "-" + std::to_string(rd()) + "-" +
                std::to_string(counter++));
        std::filesystem::remove_all(path);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

const TableSpec kTestTables[] = {
    {"plain", TableSpec::Kind::Plain, std::nullopt},
    {"dup_var", TableSpec::Kind::Dup, std::nullopt},
    {"dup_fixed", TableSpec::Kind::Dup, 20},
};

StoreOptions Opts() {
    StoreOptions opts;
    opts.sha256 = [](ByteView data, uint8_t out[32]) {
        test::TestSha256(data, out);
    };
    return opts;
}

std::vector<StoreBackend> Backends() {
    RegisterTestStoreBackends();
    std::vector<StoreBackend> out;
    for (StoreBackend b : {StoreBackend::Mdbx, StoreBackend::LevelDb}) {
        if (HasStoreBackend(b)) {
            out.push_back(b);
        }
    }
    BOOST_REQUIRE(!out.empty());
    return out;
}

Bytes B(std::initializer_list<uint8_t> v) {
    return Bytes(v);
}

Bytes S(std::string_view s) {
    return Bytes(s.begin(), s.end());
}

Bytes Dup20(uint64_t tx_num, uint32_t out_idx, int64_t sats) {
    Bytes v;
    PutBe<uint64_t>(v, tx_num);
    PutBe<uint32_t>(v, out_idx);
    PutLe<int64_t>(v, sats);
    return v;
}

std::vector<Bytes> AllDups(const ReadTxn &txn, TableId t, ByteView key) {
    std::vector<Bytes> out;
    auto c = txn.OpenDupCursor(t);
    for (bool ok = c->Seek(key); ok; ok = c->Next()) {
        out.emplace_back(c->Value().begin(), c->Value().end());
    }
    return out;
}

Bytes ToBytes(ByteView v) {
    return Bytes(v.begin(), v.end());
}

} // namespace

BOOST_AUTO_TEST_SUITE(store_tests)

BOOST_AUTO_TEST_CASE(plain_ordering_and_seeks) {
    for (StoreBackend backend : Backends()) {
        BOOST_TEST_CONTEXT("backend " << StoreBackendName(backend)) {
            TempDir dir("plain");
            auto store = OpenStore(backend, dir.path, kTestTables, Opts());
            const TableId t = store->Table("plain");
            BOOST_CHECK_THROW(store->Table("nope"), ChronikError);
            {
                auto txn = store->BeginWrite();
                for (uint32_t i : {5u, 1u, 3u, 200u, 0x100u}) {
                    txn->Put(t, AsView(ToBe<uint32_t>(i)), S("v" + std::to_string(i)));
                }
                txn->Put(t, B({0x00}), B({}));
                txn->Commit();
            }
            auto txn = store->BeginRead();
            BOOST_CHECK(!txn->Get(t, B({0x99})));
            BOOST_CHECK(ToBytes(*txn->Get(t, AsView(ToBe<uint32_t>(3)))) == S("v3"));
            BOOST_CHECK(txn->Get(t, B({0x00}))->empty());
            BOOST_CHECK_EQUAL(txn->EstimateEntries(t), 6u);

            auto c = txn->OpenCursor(t);
            std::vector<Bytes> keys;
            for (bool ok = c->SeekFirst(); ok; ok = c->Next()) {
                keys.push_back(ToBytes(c->Key()));
            }
            BOOST_REQUIRE_EQUAL(keys.size(), 6u);
            BOOST_CHECK(keys[0] == B({0x00}));
            BOOST_CHECK(keys[1] == ToBytes(AsView(ToBe<uint32_t>(1))));
            BOOST_CHECK(keys[5] == ToBytes(AsView(ToBe<uint32_t>(0x100))));
            BOOST_CHECK(!c->Valid());

            BOOST_CHECK(c->SeekLast());
            BOOST_CHECK(ToBytes(c->Key()) == ToBytes(AsView(ToBe<uint32_t>(0x100))));
            BOOST_CHECK(c->Prev());
            BOOST_CHECK(ToBytes(c->Key()) == ToBytes(AsView(ToBe<uint32_t>(200))));

            BOOST_CHECK(c->SeekGe(AsView(ToBe<uint32_t>(4))));
            BOOST_CHECK(ToBytes(c->Key()) == ToBytes(AsView(ToBe<uint32_t>(5))));
            BOOST_CHECK(ToBytes(c->Value()) == S("v5"));
            BOOST_CHECK(c->SeekGe(AsView(ToBe<uint32_t>(5))));
            BOOST_CHECK(ToBytes(c->Key()) == ToBytes(AsView(ToBe<uint32_t>(5))));
            BOOST_CHECK(!c->SeekGe(AsView(ToBe<uint32_t>(0x101))));

            BOOST_CHECK(c->SeekLe(AsView(ToBe<uint32_t>(4))));
            BOOST_CHECK(ToBytes(c->Key()) == ToBytes(AsView(ToBe<uint32_t>(3))));
            BOOST_CHECK(c->SeekLe(AsView(ToBe<uint32_t>(3))));
            BOOST_CHECK(ToBytes(c->Key()) == ToBytes(AsView(ToBe<uint32_t>(3))));
            BOOST_CHECK(c->SeekLe(AsView(ToBe<uint32_t>(0xffffffff))));
            BOOST_CHECK(ToBytes(c->Key()) == ToBytes(AsView(ToBe<uint32_t>(0x100))));
            BOOST_CHECK(!c->SeekLe(B({})));
        }
    }
}

BOOST_AUTO_TEST_CASE(read_your_writes_and_delete) {
    for (StoreBackend backend : Backends()) {
        BOOST_TEST_CONTEXT("backend " << StoreBackendName(backend)) {
            TempDir dir("ryw");
            auto store = OpenStore(backend, dir.path, kTestTables, Opts());
            const TableId t = store->Table("plain");
            auto txn = store->BeginWrite();
            txn->Put(t, S("a"), S("1"));
            BOOST_CHECK(ToBytes(*txn->Get(t, S("a"))) == S("1"));
            txn->Put(t, S("a"), S("2"));
            BOOST_CHECK(ToBytes(*txn->Get(t, S("a"))) == S("2"));
            txn->Put(t, S("b"), S("3"));
            {
                auto c = txn->OpenCursor(t);
                BOOST_CHECK(c->SeekFirst());
                BOOST_CHECK(ToBytes(c->Key()) == S("a"));
                BOOST_CHECK(c->Next());
                BOOST_CHECK(ToBytes(c->Key()) == S("b"));
            }
            txn->Del(t, S("a"));
            txn->Del(t, S("missing")); // no-op
            BOOST_CHECK(!txn->Get(t, S("a")));
            {
                // Not visible to readers before commit
                auto rtxn = store->BeginRead();
                BOOST_CHECK(!rtxn->Get(t, S("b")));
            }
            txn->Commit();
            BOOST_CHECK_THROW(txn->Put(t, S("c"), S("4")), ChronikError);
            auto rtxn = store->BeginRead();
            BOOST_CHECK(!rtxn->Get(t, S("a")));
            BOOST_CHECK(ToBytes(*rtxn->Get(t, S("b"))) == S("3"));

            // Uncommitted txn is rolled back
            {
                auto wtxn = store->BeginWrite();
                wtxn->Put(t, S("z"), S("9"));
            }
            auto rtxn2 = store->BeginRead();
            BOOST_CHECK(!rtxn2->Get(t, S("z")));
        }
    }
}

BOOST_AUTO_TEST_CASE(dup_semantics) {
    for (StoreBackend backend : Backends()) {
        BOOST_TEST_CONTEXT("backend " << StoreBackendName(backend)) {
            TempDir dir("dup");
            auto store = OpenStore(backend, dir.path, kTestTables, Opts());
            const TableId fixed = store->Table("dup_fixed");
            const TableId var = store->Table("dup_var");
            const Bytes member = S("member");
            {
                auto txn = store->BeginWrite();
                txn->PutDup(fixed, member, Dup20(7, 1, 100));
                txn->PutDup(fixed, member, Dup20(2, 0, -5));
                txn->PutDup(fixed, member, Dup20(7, 0, 50));
                txn->PutDup(fixed, member, Dup20(7, 0, 50)); // idempotent
                txn->PutDup(fixed, S("other"), Dup20(1, 1, 1));
                // variable: outpoint || sats LE8 || script
                Bytes v1 = Dup20(3, 0, 10);
                v1.push_back(0xac);
                Bytes v2 = Dup20(3, 1, 11);
                v2.insert(v2.end(), {0x76, 0xa9});
                txn->PutDup(var, member, v2);
                txn->PutDup(var, member, v1);
                // read-your-writes on dups
                BOOST_CHECK_EQUAL(AllDups(*txn, fixed, member).size(), 3u);
                txn->Commit();
            }
            auto txn = store->BeginRead();
            auto dups = AllDups(*txn, fixed, member);
            BOOST_REQUIRE_EQUAL(dups.size(), 3u);
            BOOST_CHECK(dups[0] == Dup20(2, 0, -5));
            BOOST_CHECK(dups[1] == Dup20(7, 0, 50));
            BOOST_CHECK(dups[2] == Dup20(7, 1, 100));
            BOOST_CHECK(AllDups(*txn, fixed, S("nope")).empty());
            BOOST_CHECK_EQUAL(txn->EstimateEntries(fixed), 4u);
            {
                auto c = txn->OpenDupCursor(fixed);
                BOOST_CHECK(c->Seek(member));
                BOOST_CHECK_EQUAL(c->CountRemaining(), 3u);
                BOOST_CHECK(c->Next());
                BOOST_CHECK_EQUAL(c->CountRemaining(), 2u);
                // SeekValueGe with a 12-byte outpoint prefix
                Bytes prefix;
                PutBe<uint64_t>(prefix, 7);
                PutBe<uint32_t>(prefix, 1);
                BOOST_CHECK(c->SeekValueGe(member, prefix));
                BOOST_CHECK(ToBytes(c->Value()) == Dup20(7, 1, 100));
                BOOST_CHECK(!c->Next());
                Bytes prefix_hi;
                PutBe<uint64_t>(prefix_hi, 8);
                PutBe<uint32_t>(prefix_hi, 0);
                BOOST_CHECK(!c->SeekValueGe(member, prefix_hi));
            }
            auto vdups = AllDups(*txn, var, member);
            BOOST_REQUIRE_EQUAL(vdups.size(), 2u);
            BOOST_CHECK_EQUAL(vdups[0].size(), 21u);
            BOOST_CHECK_EQUAL(vdups[1].size(), 22u);
            txn.reset();

            {
                auto wtxn = store->BeginWrite();
                Bytes prefix;
                PutBe<uint64_t>(prefix, 7);
                PutBe<uint32_t>(prefix, 0);
                wtxn->DelDupByPrefix(fixed, member, prefix);
                // Missing prefix: no-op
                Bytes prefix_none;
                PutBe<uint64_t>(prefix_none, 7);
                PutBe<uint32_t>(prefix_none, 9);
                wtxn->DelDupByPrefix(fixed, member, prefix_none);
                wtxn->DelDupByPrefix(fixed, S("nope"), prefix_none);
                wtxn->DelDup(fixed, member, Dup20(2, 0, -5));
                wtxn->DelDup(fixed, member, Dup20(2, 0, -6)); // not present
                Bytes vprefix;
                PutBe<uint64_t>(vprefix, 3);
                PutBe<uint32_t>(vprefix, 1);
                wtxn->DelDupByPrefix(var, member, vprefix);
                wtxn->Commit();
            }
            auto txn2 = store->BeginRead();
            dups = AllDups(*txn2, fixed, member);
            BOOST_REQUIRE_EQUAL(dups.size(), 1u);
            BOOST_CHECK(dups[0] == Dup20(7, 1, 100));
            vdups = AllDups(*txn2, var, member);
            BOOST_REQUIRE_EQUAL(vdups.size(), 1u);
            BOOST_CHECK(vdups[0] == [] {
                Bytes v1 = Dup20(3, 0, 10);
                v1.push_back(0xac);
                return v1;
            }());
            txn2.reset();
            // Deleting the last dup removes the key
            {
                auto wtxn = store->BeginWrite();
                wtxn->DelDup(fixed, member, Dup20(7, 1, 100));
                wtxn->Commit();
            }
            auto txn3 = store->BeginRead();
            BOOST_CHECK(AllDups(*txn3, fixed, member).empty());
            BOOST_CHECK_EQUAL(txn3->EstimateEntries(fixed), 1u);
        }
    }
}

BOOST_AUTO_TEST_CASE(clear_table) {
    for (StoreBackend backend : Backends()) {
        BOOST_TEST_CONTEXT("backend " << StoreBackendName(backend)) {
            TempDir dir("clear");
            auto store = OpenStore(backend, dir.path, kTestTables, Opts());
            const TableId t = store->Table("plain");
            const TableId d = store->Table("dup_fixed");
            {
                auto txn = store->BeginWrite();
                for (int i = 0; i < 100; ++i) {
                    txn->Put(t, AsView(ToBe<uint32_t>(i)), S("x"));
                    txn->PutDup(d, S("m"), Dup20(i, 0, i));
                }
                txn->Commit();
            }
            {
                auto txn = store->BeginWrite();
                txn->Clear(t);
                BOOST_CHECK(!txn->Get(t, AsView(ToBe<uint32_t>(5))));
                txn->Put(t, S("after"), S("y")); // usable after Clear
                txn->Commit();
            }
            auto txn = store->BeginRead();
            BOOST_CHECK_EQUAL(txn->EstimateEntries(t), 1u);
            BOOST_CHECK_EQUAL(txn->EstimateEntries(d), 100u);
        }
    }
}

BOOST_AUTO_TEST_CASE(snapshot_isolation_concurrent_writer) {
    for (StoreBackend backend : Backends()) {
        BOOST_TEST_CONTEXT("backend " << StoreBackendName(backend)) {
            TempDir dir("snap");
            auto store = OpenStore(backend, dir.path, kTestTables, Opts());
            const TableId t = store->Table("plain");
            {
                auto txn = store->BeginWrite();
                txn->Put(t, S("counter"), AsView(ToBe<uint64_t>(0)));
                txn->Put(t, S("mirror"), AsView(ToBe<uint64_t>(0)));
                txn->Commit();
            }
            // A snapshot taken now never sees later commits.
            auto snapshot = store->BeginRead();
            std::atomic<bool> stop{false};
            std::thread writer([&] {
                for (uint64_t i = 1; i <= 300; ++i) {
                    auto txn = store->BeginWrite();
                    txn->Put(t, S("counter"), AsView(ToBe<uint64_t>(i)));
                    txn->Put(t, S("mirror"), AsView(ToBe<uint64_t>(i)));
                    txn->Commit();
                }
                stop = true;
            });
            std::atomic<int> inconsistent{0};
            std::vector<std::thread> readers;
            for (int r = 0; r < 4; ++r) {
                readers.emplace_back([&] {
                    while (!stop) {
                        auto txn = store->BeginRead();
                        const uint64_t a = FromBe<uint64_t>(*txn->Get(t, S("counter")));
                        std::this_thread::yield();
                        const uint64_t b = FromBe<uint64_t>(*txn->Get(t, S("mirror")));
                        if (a != b) {
                            inconsistent++;
                        }
                    }
                });
            }
            writer.join();
            for (auto &th : readers) {
                th.join();
            }
            BOOST_CHECK_EQUAL(inconsistent.load(), 0);
            BOOST_CHECK_EQUAL(FromBe<uint64_t>(*snapshot->Get(t, S("counter"))), 0u);
            snapshot.reset();
            auto fresh = store->BeginRead();
            BOOST_CHECK_EQUAL(FromBe<uint64_t>(*fresh->Get(t, S("counter"))), 300u);
        }
    }
}

BOOST_AUTO_TEST_CASE(reopen_persistence_and_destroy) {
    for (StoreBackend backend : Backends()) {
        BOOST_TEST_CONTEXT("backend " << StoreBackendName(backend)) {
            TempDir dir("reopen");
            {
                auto store = OpenStore(backend, dir.path, kTestTables, Opts());
                auto txn = store->BeginWrite();
                txn->Put(store->Table("plain"), S("k"), S("v"));
                txn->PutDup(store->Table("dup_fixed"), S("m"), Dup20(1, 2, 3));
                txn->Commit();
                store->Sync(true);
            }
            {
                auto store = OpenStore(backend, dir.path, kTestTables, Opts());
                auto txn = store->BeginRead();
                BOOST_CHECK(ToBytes(*txn->Get(store->Table("plain"), S("k"))) == S("v"));
                BOOST_CHECK(AllDups(*txn, store->Table("dup_fixed"), S("m")).size() == 1);
                std::vector<std::string> names = store->TableNames();
                BOOST_CHECK(names == (std::vector<std::string>{"plain", "dup_var", "dup_fixed"}));
            }
            DestroyStore(backend, dir.path);
            BOOST_CHECK(!std::filesystem::exists(dir.path));
            auto store = OpenStore(backend, dir.path, kTestTables, Opts());
            auto txn = store->BeginRead();
            BOOST_CHECK(!txn->Get(store->Table("plain"), S("k")));
        }
    }
}

BOOST_AUTO_TEST_CASE(long_keys) {
    for (StoreBackend backend : Backends()) {
        BOOST_TEST_CONTEXT("backend " << StoreBackendName(backend)) {
            TempDir dir("longkey");
            auto store = OpenStore(backend, dir.path, kTestTables, Opts());
            const TableId t = store->Table("plain");
            const TableId d = store->Table("dup_fixed");
            const Bytes k7500(7500, 0x42);
            Bytes k10000(10000, 0x43);
            {
                auto txn = store->BeginWrite();
                txn->Put(t, k7500, S("inline"));
                txn->Put(t, k10000, S("hashed"));
                txn->PutDup(d, k10000, Dup20(1, 1, 1));
                txn->Commit();
            }
            auto txn = store->BeginRead();
            BOOST_CHECK(ToBytes(*txn->Get(t, k7500)) == S("inline"));
            BOOST_CHECK(ToBytes(*txn->Get(t, k10000)) == S("hashed"));
            BOOST_CHECK_EQUAL(AllDups(*txn, d, k10000).size(), 1u);
            Bytes k10000b = k10000;
            k10000b.back() ^= 1;
            BOOST_CHECK(!txn->Get(t, k10000b));
#if CHRONIK_NATIVE_HAVE_MDBX
            if (backend == StoreBackend::Mdbx) {
                // Physical key = "MDBX_SHA256_KEY:" || sha256(key), like Rust
                uint8_t digest[32];
                test::TestSha256(k10000, digest);
                Bytes phys = S("MDBX_SHA256_KEY:");
                phys.insert(phys.end(), digest, digest + 32);
                auto c = txn->OpenCursor(t);
                bool found = false;
                for (bool ok = c->SeekFirst(); ok; ok = c->Next()) {
                    if (ToBytes(c->Key()) == phys) {
                        found = true;
                        BOOST_CHECK(ToBytes(c->Value()) == S("hashed"));
                    }
                    BOOST_CHECK(c->Key().size() <= 7500);
                }
                BOOST_CHECK(found);
                // The 7500-byte key is stored inline.
                BOOST_CHECK(c->SeekGe(k7500));
                BOOST_CHECK(ToBytes(c->Key()) == k7500);
            }
#endif
        }
    }
}

BOOST_AUTO_TEST_CASE(randomized_against_model) {
    // Random writes, clears and commits; after every operation the write
    // txn (read-your-writes) and, after commits, a read txn must match an
    // in-memory model through Get, forward/backward cursors and dup cursors.
    for (StoreBackend backend : Backends()) {
        BOOST_TEST_CONTEXT("backend " << StoreBackendName(backend)) {
            TempDir dir("model");
            auto store = OpenStore(backend, dir.path, kTestTables, Opts());
            const TableId t = store->Table("plain");
            const TableId d = store->Table("dup_var");
            using Plain = std::map<Bytes, Bytes>;
            using Dups = std::map<Bytes, std::set<Bytes>>;
            Plain committed_plain, plain;
            Dups committed_dups, dups;
            std::mt19937 rng(12345);
            auto rnd_key = [&]() {
                // Short keys over a tiny alphabet, incl. 0x00 and 0xff, so
                // seeks hit exact keys, neighbours and prefix boundaries.
                static const uint8_t alphabet[] = {0x00, 0x01, 0x7f, 0x80, 0xff};
                Bytes k(rng() % 3);
                for (auto &b : k) {
                    b = alphabet[rng() % 5];
                }
                return k;
            };
            auto check = [&](const ReadTxn &txn, const Plain &mp,
                             const Dups &md) {
                // Forward and backward scans
                std::vector<std::pair<Bytes, Bytes>> fwd, bwd;
                auto c = txn.OpenCursor(t);
                for (bool ok = c->SeekFirst(); ok; ok = c->Next()) {
                    fwd.emplace_back(ToBytes(c->Key()), ToBytes(c->Value()));
                }
                for (bool ok = c->SeekLast(); ok; ok = c->Prev()) {
                    bwd.emplace_back(ToBytes(c->Key()), ToBytes(c->Value()));
                }
                std::vector<std::pair<Bytes, Bytes>> expected(mp.begin(),
                                                              mp.end());
                BOOST_REQUIRE(fwd == expected);
                std::reverse(expected.begin(), expected.end());
                BOOST_REQUIRE(bwd == expected);
                // A plain cursor over a dup table visits (key, dup) pairs
                std::vector<std::pair<Bytes, Bytes>> dfwd, dbwd, dexp;
                for (const auto &[key, values] : md) {
                    for (const Bytes &value : values) {
                        dexp.emplace_back(key, value);
                    }
                }
                auto dt = txn.OpenCursor(d);
                for (bool ok = dt->SeekFirst(); ok; ok = dt->Next()) {
                    dfwd.emplace_back(ToBytes(dt->Key()), ToBytes(dt->Value()));
                }
                for (bool ok = dt->SeekLast(); ok; ok = dt->Prev()) {
                    dbwd.emplace_back(ToBytes(dt->Key()), ToBytes(dt->Value()));
                }
                BOOST_REQUIRE(dfwd == dexp);
                std::reverse(dexp.begin(), dexp.end());
                BOOST_REQUIRE(dbwd == dexp);
                {
                    const Bytes k = rnd_key();
                    auto ge = md.lower_bound(k);
                    BOOST_REQUIRE_EQUAL(dt->SeekGe(k), ge != md.end());
                    if (ge != md.end()) {
                        BOOST_REQUIRE(ToBytes(dt->Key()) == ge->first);
                        BOOST_REQUIRE(ToBytes(dt->Value()) ==
                                      *ge->second.begin());
                    }
                }
                // Seeks and gets
                for (int i = 0; i < 8; ++i) {
                    const Bytes k = rnd_key();
                    auto ge = mp.lower_bound(k);
                    BOOST_REQUIRE_EQUAL(c->SeekGe(k), ge != mp.end());
                    if (ge != mp.end()) {
                        BOOST_REQUIRE(ToBytes(c->Key()) == ge->first);
                    }
                    auto le = mp.upper_bound(k);
                    const bool has_le = le != mp.begin();
                    BOOST_REQUIRE_EQUAL(c->SeekLe(k), has_le);
                    if (has_le) {
                        --le;
                        BOOST_REQUIRE(ToBytes(c->Key()) == le->first);
                    }
                    auto got = txn.Get(t, k);
                    auto it = mp.find(k);
                    BOOST_REQUIRE_EQUAL(got.has_value(), it != mp.end());
                    if (got) {
                        BOOST_REQUIRE(ToBytes(*got) == it->second);
                    }
                    // Dups of k
                    std::vector<Bytes> want;
                    if (auto dit = md.find(k); dit != md.end()) {
                        want.assign(dit->second.begin(), dit->second.end());
                    }
                    BOOST_REQUIRE(AllDups(txn, d, k) == want);
                    auto dc = txn.OpenDupCursor(d);
                    const Bytes vp = rnd_key();
                    auto vge = std::lower_bound(want.begin(), want.end(), vp);
                    BOOST_REQUIRE_EQUAL(dc->SeekValueGe(k, vp),
                                        vge != want.end());
                    if (vge != want.end()) {
                        BOOST_REQUIRE(ToBytes(dc->Value()) == *vge);
                        BOOST_REQUIRE_EQUAL(dc->CountRemaining(),
                                            size_t(want.end() - vge));
                    }
                }
            };
            auto txn = store->BeginWrite();
            for (int step = 0; step < 3000; ++step) {
                const int op = rng() % 100;
                const Bytes k = rnd_key();
                const Bytes v = rnd_key();
                if (op < 30) {
                    txn->Put(t, k, v);
                    plain[k] = v;
                } else if (op < 45) {
                    txn->Del(t, k);
                    plain.erase(k);
                } else if (op < 70) {
                    txn->PutDup(d, k, v);
                    dups[k].insert(v);
                } else if (op < 82) {
                    txn->DelDup(d, k, v);
                    if (auto it = dups.find(k); it != dups.end()) {
                        it->second.erase(v);
                        if (it->second.empty()) {
                            dups.erase(it);
                        }
                    }
                } else if (op < 88) {
                    txn->DelDupByPrefix(d, k, v);
                    if (auto it = dups.find(k); it != dups.end()) {
                        auto first = it->second.lower_bound(v);
                        if (first != it->second.end() &&
                            StartsWith(*first, v)) {
                            it->second.erase(first);
                            if (it->second.empty()) {
                                dups.erase(it);
                            }
                        }
                    }
                } else if (op < 90) {
                    if (rng() % 2) {
                        txn->Clear(t);
                        plain.clear();
                    } else {
                        txn->Clear(d);
                        dups.clear();
                    }
                } else if (op < 97) {
                    check(*txn, plain, dups);
                } else {
                    txn->Commit();
                    committed_plain = plain;
                    committed_dups = dups;
                    {
                        auto read = store->BeginRead();
                        check(*read, committed_plain, committed_dups);
                    }
                    txn = store->BeginWrite();
                }
            }
            txn.reset();
            auto read = store->BeginRead();
            check(*read, committed_plain, committed_dups);
        }
    }
}

#if CHRONIK_NATIVE_HAVE_LEVELDB
BOOST_AUTO_TEST_CASE(leveldb_table_ids_and_refusals) {
    RegisterTestStoreBackends();
    TempDir dir("ldbids");
    {
        auto store = OpenStore(StoreBackend::LevelDb, dir.path, kTestTables,
                               Opts());
        auto txn = store->BeginWrite();
        txn->Put(store->Table("plain"), S("k"), S("v"));
        txn->PutDup(store->Table("dup_var"), S("m"), S("x"));
        txn->Commit();
    }
    {
        // Tables reordered and a new one added: ids are persistent, so the
        // data stays with its table.
        const TableSpec reordered[] = {
            {"extra", TableSpec::Kind::Plain, std::nullopt},
            {"dup_fixed", TableSpec::Kind::Dup, 20},
            {"dup_var", TableSpec::Kind::Dup, std::nullopt},
            {"plain", TableSpec::Kind::Plain, std::nullopt},
        };
        auto store =
            OpenStore(StoreBackend::LevelDb, dir.path, reordered, Opts());
        auto txn = store->BeginRead();
        BOOST_CHECK(ToBytes(*txn->Get(store->Table("plain"), S("k"))) == S("v"));
        BOOST_CHECK(!txn->Get(store->Table("extra"), S("k")));
        BOOST_CHECK(AllDups(*txn, store->Table("dup_var"), S("m")) ==
                    std::vector<Bytes>{S("x")});
        BOOST_CHECK(AllDups(*txn, store->Table("dup_fixed"), S("m")).empty());
    }
    {
        // A table whose kind changed must not be reinterpreted
        const TableSpec changed[] = {
            {"plain", TableSpec::Kind::Dup, std::nullopt},
        };
        BOOST_CHECK_THROW(
            OpenStore(StoreBackend::LevelDb, dir.path, changed, Opts()),
            ChronikError);
    }
#if CHRONIK_NATIVE_HAVE_MDBX
    {
        // An MDBX index directory is refused
        TempDir mdbx_dir("ldbmdbx");
        OpenStore(StoreBackend::Mdbx, mdbx_dir.path, kTestTables, Opts());
        BOOST_CHECK_THROW(OpenStore(StoreBackend::LevelDb, mdbx_dir.path,
                                    kTestTables, Opts()),
                          ChronikError);
    }
#endif
}
#endif

BOOST_AUTO_TEST_CASE(sha256_helper) {
    uint8_t out[32];
    test::TestSha256(Bytes{}, out);
    BOOST_CHECK_EQUAL(HexEncode(ByteView(out, 32)),
                      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
                      "7852b855");
    test::TestSha256(S("abc"), out);
    BOOST_CHECK_EQUAL(HexEncode(ByteView(out, 32)),
                      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
                      "f20015ad");
}

#if CHRONIK_NATIVE_HAVE_MDBX
BOOST_AUTO_TEST_CASE(mdbx_env_matches_rust) {
    // chronik-db/src/db.rs Db::open_with_cfs and test_mdbx_durability_policy
    TempDir dir("mdbxenv");
    RegisterTestStoreBackends();
    const auto tables = schema::EcashTables();
    auto store = OpenStore(StoreBackend::Mdbx, dir.path, tables, Opts());
    const MdbxStoreInfo info = GetMdbxStoreInfo(*store);
    BOOST_CHECK_EQUAL(info.pagesize, 16384u);
    BOOST_CHECK_EQUAL(info.geo_upper, uint64_t(256) << 30);
    BOOST_CHECK_EQUAL(info.geo_grow, uint64_t(64) << 20);
    BOOST_CHECK_EQUAL(info.geo_shrink, uint64_t(128) << 20);
    // mdbx_env_set_maxreaders(256), which libmdbx rounds up to fill the lock
    // file's pages, exactly as for the Rust env.
    BOOST_CHECK_GE(info.max_readers, 256u);
    BOOST_CHECK(info.env_flags & mdbx_flags::kSafeNoSync);
    BOOST_CHECK(info.env_flags & mdbx_flags::kNoMetaSync);
    BOOST_CHECK(info.env_flags & mdbx_flags::kLifoReclaim);
    BOOST_CHECK(info.env_flags & mdbx_flags::kNoStickyThreads);
    BOOST_CHECK(info.env_flags & mdbx_flags::kNoMemInit);
    BOOST_CHECK_EQUAL(info.sync_bytes, uint64_t(16) << 20);
    BOOST_CHECK_EQUAL(info.sync_period, uint64_t(1) << 16);
    BOOST_REQUIRE_EQUAL(info.dbi_flags.size(), tables.size());
    for (size_t i = 0; i < tables.size(); ++i) {
        const bool dup = tables[i].kind == TableSpec::Kind::Dup;
        BOOST_CHECK_EQUAL(bool(info.dbi_flags[i] & mdbx_flags::kDupSort), dup);
        BOOST_CHECK_EQUAL(bool(info.dbi_flags[i] & mdbx_flags::kDupFixed),
                          dup && tables[i].dup_fixed_size.has_value());
    }
    const auto perms = std::filesystem::status(dir.path / "mdbx.dat").permissions();
    BOOST_CHECK((perms & std::filesystem::perms::all) ==
                (std::filesystem::perms::owner_read |
                 std::filesystem::perms::owner_write));
}
#endif

BOOST_AUTO_TEST_SUITE_END()
