// Copyright (c) 2018 The Bitcoin Core developers
// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <fstream>
#include <test/util/setup_common.h>
#include <util/translation.h>
#include <wallet/sqlite.h>
#include <wallet/walletdb.h>

BOOST_FIXTURE_TEST_SUITE(db_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sqlite_transactions_reopen_backup) {
    const auto path = gArgs.GetDataDirNet() / "sqlite-wallet";
    DatabaseOptions options;
    options.require_create = true;
    options.wallet_profile = "explicit-test-profile-a";
    DatabaseStatus status;
    bilingual_str error;
    auto db = MakeDatabase(path, options, status, error);
    BOOST_REQUIRE_MESSAGE(db, error.original);
    BOOST_CHECK(status == DatabaseStatus::SUCCESS);
    BOOST_CHECK(ExistsSQLiteDatabase(path));
    BOOST_CHECK(!fs::exists(path / "wallet.dat"));
    {
        auto batch = db->MakeBatch();
        BOOST_REQUIRE(batch->Write(std::string("persistent"), 7));
        BOOST_REQUIRE(batch->TxnBegin());
        BOOST_REQUIRE(batch->Write(std::string("aborted"), 8));
        BOOST_REQUIRE(batch->TxnAbort());
        BOOST_CHECK(!batch->Exists(std::string("aborted")));
        BOOST_REQUIRE(batch->TxnBegin());
        {
            auto nested = db->MakeBatch();
            BOOST_REQUIRE(nested->Write(std::string("committed"), 9));
        }
        BOOST_REQUIRE(batch->TxnCommit());
        BOOST_REQUIRE(batch->TxnBegin());
        BOOST_REQUIRE(batch->Write(std::string("implicit-abort"), 10));
    }
    const auto backup = gArgs.GetDataDirNet() / "sqlite-backup";
    fs::create_directories(backup);
    BOOST_REQUIRE(db->Backup(fs::PathToString(backup)));
    BOOST_CHECK(!db->Backup(db->Filename()));
    BOOST_CHECK(db->Rewrite());
    BOOST_CHECK(!db->Rewrite("\x04pool"));
    db.reset();
    options.require_create = false;
    options.require_existing = true;
    for (const auto &wallet : {path, backup}) {
        db = MakeDatabase(wallet, options, status, error);
        BOOST_REQUIRE_MESSAGE(db, error.original);
        auto batch = db->MakeBatch();
        int value = 0;
        BOOST_REQUIRE(batch->Read(std::string("persistent"), value));
        BOOST_CHECK_EQUAL(value, 7);
        BOOST_REQUIRE(batch->Read(std::string("committed"), value));
        BOOST_CHECK_EQUAL(value, 9);
        BOOST_CHECK(!batch->Exists(std::string("aborted")));
        BOOST_CHECK(!batch->Exists(std::string("implicit-abort")));
        batch.reset();
        db.reset();
    }
    options.wallet_profile = "explicit-test-profile-b";
    BOOST_CHECK(!MakeDatabase(path, options, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_FORMAT);
    options.wallet_profile.clear();
    BOOST_CHECK(!MakeDatabase(path, options, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_FORMAT);
}

BOOST_AUTO_TEST_CASE(sqlite_reject_legacy_and_foreign) {
    DatabaseOptions options;
    options.wallet_profile = "explicit-test-profile";
    DatabaseStatus status;
    bilingual_str error;
    const auto legacy = gArgs.GetDataDirNet() / "legacy";
    fs::create_directories(legacy);
    {
        std::ofstream f{legacy / "wallet.dat", std::ios::binary};
        std::string bdb(4096, '\0');
        bdb.replace(12, 4, "\x62\x31\x05\x00", 4);
        f.write(bdb.data(), bdb.size());
    }
    BOOST_CHECK(!MakeDatabase(legacy, options, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_FORMAT);
    BOOST_CHECK(!fs::exists(legacy / WALLET_DATABASE_FILENAME));
    BOOST_CHECK(!MakeDatabase(legacy / "wallet.dat", options, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_PATH);
    const auto foreign = gArgs.GetDataDirNet() / "foreign";
    fs::create_directories(foreign);
    sqlite3 *raw{nullptr};
    BOOST_REQUIRE_EQUAL(
        sqlite3_open(
            fs::PathToString(foreign / WALLET_DATABASE_FILENAME).c_str(), &raw),
        SQLITE_OK);
    BOOST_REQUIRE_EQUAL(sqlite3_exec(raw,
                                     "CREATE TABLE valuable(data TEXT); INSERT "
                                     "INTO valuable VALUES('untouched')",
                                     nullptr, nullptr, nullptr),
                        SQLITE_OK);
    sqlite3_close(raw);
    BOOST_CHECK(!ExistsSQLiteDatabase(foreign));
    BOOST_CHECK(!MakeDatabase(foreign, options, status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_BAD_FORMAT);
    BOOST_REQUIRE_EQUAL(
        sqlite3_open(
            fs::PathToString(foreign / WALLET_DATABASE_FILENAME).c_str(), &raw),
        SQLITE_OK);
    sqlite3_stmt *stmt{nullptr};
    BOOST_REQUIRE_EQUAL(sqlite3_prepare_v2(raw, "SELECT data FROM valuable", -1,
                                           &stmt, nullptr),
                        SQLITE_OK);
    BOOST_REQUIRE_EQUAL(sqlite3_step(stmt), SQLITE_ROW);
    BOOST_CHECK_EQUAL(
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)),
        "untouched");
    sqlite3_finalize(stmt);
    sqlite3_close(raw);
    options.require_existing = true;
    BOOST_CHECK(!MakeDatabase(gArgs.GetDataDirNet() / "missing", options,
                              status, error));
    BOOST_CHECK(status == DatabaseStatus::FAILED_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(sqlite_mock_isolation) {
    auto first = CreateMockWalletDatabase();
    auto second = CreateMockWalletDatabase();
    auto a = first->MakeBatch();
    auto b = second->MakeBatch();
    BOOST_REQUIRE(a->Write(std::string("key"), 42));
    BOOST_CHECK(!b->Exists(std::string("key")));
    BOOST_REQUIRE(a->TxnBegin());
    BOOST_REQUIRE(a->Erase(std::string("key")));
    BOOST_REQUIRE(a->TxnAbort());
    BOOST_CHECK(a->Exists(std::string("key")));
}

BOOST_AUTO_TEST_SUITE_END()
