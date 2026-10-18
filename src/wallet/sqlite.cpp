// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/sqlite.h>

#include <logging.h>
#include <sync.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/db.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <sqlite3.h>

// Storage format identity, independent of any future production ChainID.
static constexpr int WALLET_APPLICATION_ID = 0x4c563257; // LV2W
static constexpr int WALLET_SCHEMA_VERSION = 1;

static bool CheckSQLiteIdentity(sqlite3 *db,
                                const std::string *profile = nullptr) {
    auto integer = [&](const char *sql, int expected) {
        sqlite3_stmt *stmt{nullptr};
        bool ok =
            sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_ROW &&
            sqlite3_column_int(stmt, 0) == expected;
        sqlite3_finalize(stmt);
        return ok;
    };
    if (!integer("PRAGMA application_id", WALLET_APPLICATION_ID) ||
        !integer("PRAGMA user_version", WALLET_SCHEMA_VERSION))
        return false;
    sqlite3_stmt *stmt{nullptr};
    bool ok = sqlite3_prepare_v2(
                  db, "SELECT profile FROM wallet_metadata WHERE id = 1", -1,
                  &stmt, nullptr) == SQLITE_OK &&
              sqlite3_step(stmt) == SQLITE_ROW;
    if (ok) {
        const auto *text = sqlite3_column_text(stmt, 0);
        const int size = sqlite3_column_bytes(stmt, 0);
        ok = text && size > 0 &&
             (!profile ||
              *profile ==
                  std::string(reinterpret_cast<const char *>(text), size));
    }
    sqlite3_finalize(stmt);
    if (!ok) return false;
    // Prepare the expected table query before any writable connection is made.
    stmt = nullptr;
    ok = sqlite3_prepare_v2(db, "SELECT key, value FROM main LIMIT 0", -1,
                            &stmt, nullptr) == SQLITE_OK;
    sqlite3_finalize(stmt);
    return ok;
}

SQLiteDatabase::SQLiteDatabase(const fs::path &dir_path,
                               const fs::path &file_path, bool mock,
                               std::string profile)
    : WalletDatabase(), m_mock(mock), m_dir_path(fs::PathToString(dir_path)),
      m_file_path(fs::PathToString(file_path)), m_profile(std::move(profile)) {
    LogInfoEvent(BCLog::ALL, "sqlite_version",
                 "Using SQLite Version {database_version}")
        .Field(BCLog::LogField::DatabaseVersion, SQLiteDatabaseVersion());
    if (m_profile.empty())
        throw std::runtime_error("SQLiteDatabase: Empty wallet profile");
    if (!m_mock && fs::exists(file_path)) {
        sqlite3 *existing{nullptr};
        int ret = sqlite3_open_v2(m_file_path.c_str(), &existing,
                                  SQLITE_OPEN_READONLY, nullptr);
        bool ok = ret == SQLITE_OK && CheckSQLiteIdentity(existing, &m_profile);
        int err = existing ? sqlite3_errcode(existing) : ret;
        sqlite3_close(existing);
        if (!ok) {
            if (err == SQLITE_BUSY || err == SQLITE_LOCKED) {
                throw std::runtime_error(
                    "SQLiteDatabase: Unable to obtain an exclusive lock on the "
                    "database, is it being used by another process?\n");
            }
            throw std::runtime_error("SQLiteDatabase: Unsupported wallet "
                                     "format, version or profile");
        }
    }

    try {
        Open();
    } catch (const std::runtime_error &) {
        // If open fails, cleanup this object and rethrow the exception
        Cleanup();
        throw;
    }
}

void SQLiteBatch::SetupSQLStatements() {
    int res;
    if (!m_read_stmt) {
        if ((res = sqlite3_prepare_v2(
                 m_database.m_db, "SELECT value FROM main WHERE key = ?", -1,
                 &m_read_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf(
                "SQLiteDatabase: Failed to setup SQL statements: %s\n",
                sqlite3_errstr(res)));
        }
    }
    if (!m_insert_stmt) {
        if ((res = sqlite3_prepare_v2(m_database.m_db,
                                      "INSERT INTO main VALUES(?, ?)", -1,
                                      &m_insert_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf(
                "SQLiteDatabase: Failed to setup SQL statements: %s\n",
                sqlite3_errstr(res)));
        }
    }
    if (!m_overwrite_stmt) {
        if ((res = sqlite3_prepare_v2(
                 m_database.m_db, "INSERT or REPLACE into main values(?, ?)",
                 -1, &m_overwrite_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf(
                "SQLiteDatabase: Failed to setup SQL statements: %s\n",
                sqlite3_errstr(res)));
        }
    }
    if (!m_delete_stmt) {
        if ((res = sqlite3_prepare_v2(m_database.m_db,
                                      "DELETE FROM main WHERE key = ?", -1,
                                      &m_delete_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf(
                "SQLiteDatabase: Failed to setup SQL statements: %s\n",
                sqlite3_errstr(res)));
        }
    }
    if (!m_cursor_stmt) {
        if ((res = sqlite3_prepare_v2(
                 m_database.m_db, "SELECT key, value FROM main ORDER BY key",
                 -1, &m_cursor_stmt, nullptr)) != SQLITE_OK) {
            throw std::runtime_error(strprintf(
                "SQLiteDatabase: Failed to setup SQL statements : %s\n",
                sqlite3_errstr(res)));
        }
    }
}

SQLiteDatabase::~SQLiteDatabase() {
    Cleanup();
}

void SQLiteDatabase::Cleanup() noexcept {
    if (m_db && sqlite3_close_v2(m_db) != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "wallet_sqlite_close_failed",
                     "SQLiteDatabase: Failed to close database");
    }
    m_db = nullptr;
}

bool SQLiteDatabase::Verify(bilingual_str &error) {
    assert(m_db);

    sqlite3_stmt *stmt{nullptr};
    int ret =
        sqlite3_prepare_v2(m_db, "PRAGMA integrity_check", -1, &stmt, nullptr);
    if (ret != SQLITE_OK) {
        sqlite3_finalize(stmt);
        error = strprintf(_("SQLiteDatabase: Failed to prepare statement to "
                            "verify database: %s"),
                          sqlite3_errstr(ret));
        return false;
    }
    while (true) {
        ret = sqlite3_step(stmt);
        if (ret == SQLITE_DONE) {
            break;
        }
        if (ret != SQLITE_ROW) {
            error = strprintf(_("SQLiteDatabase: Failed to execute statement "
                                "to verify database: %s"),
                              sqlite3_errstr(ret));
            break;
        }
        const char *msg = (const char *)sqlite3_column_text(stmt, 0);
        if (!msg) {
            error = strprintf(_("SQLiteDatabase: Failed to read database "
                                "verification error: %s"),
                              sqlite3_errstr(ret));
            break;
        }
        std::string str_msg(msg);
        if (str_msg == "ok") {
            continue;
        }
        if (error.empty()) {
            error = _("Failed to verify database") + Untranslated("\n");
        }
        error += Untranslated(strprintf("%s\n", str_msg));
    }
    sqlite3_finalize(stmt);
    return error.empty();
}

void SQLiteDatabase::Open() {
    int flags =
        SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (m_mock) {
        // In memory database for mock db
        flags |= SQLITE_OPEN_MEMORY;
    }

    if (m_db == nullptr) {
        if (!m_mock) TryCreateDirectories(fs::PathFromString(m_dir_path));
        int ret = sqlite3_open_v2(m_file_path.c_str(), &m_db, flags, nullptr);
        if (ret != SQLITE_OK) {
            throw std::runtime_error(
                strprintf("SQLiteDatabase: Failed to open database: %s\n",
                          sqlite3_errstr(ret)));
        }
    }

    if (sqlite3_db_readonly(m_db, "main") != 0) {
        throw std::runtime_error("SQLiteDatabase: Database opened in readonly "
                                 "mode but read-write permissions are needed");
    }

    // Acquire an exclusive lock on the database
    // First change the locking mode to exclusive
    int ret = sqlite3_exec(m_db, "PRAGMA locking_mode = exclusive", nullptr,
                           nullptr, nullptr);
    if (ret != SQLITE_OK) {
        throw std::runtime_error(
            strprintf("SQLiteDatabase: Unable to change database locking mode "
                      "to exclusive: %s\n",
                      sqlite3_errstr(ret)));
    }
    // Now begin a transaction to acquire the exclusive lock. This lock won't be
    // released until we close because of the exclusive locking mode.
    ret = sqlite3_exec(m_db, "BEGIN EXCLUSIVE TRANSACTION", nullptr, nullptr,
                       nullptr);
    if (ret != SQLITE_OK) {
        throw std::runtime_error(
            "SQLiteDatabase: Unable to obtain an exclusive lock on the "
            "database, is it being used by another process?\n");
    }
    ret = sqlite3_exec(m_db, "COMMIT", nullptr, nullptr, nullptr);
    if (ret != SQLITE_OK) {
        throw std::runtime_error(strprintf(
            "SQLiteDatabase: Unable to end exclusive lock transaction: %s\n",
            sqlite3_errstr(ret)));
    }

    // Enable fullfsync for the platforms that use it
    ret = sqlite3_exec(m_db, "PRAGMA fullfsync = true", nullptr, nullptr,
                       nullptr);
    if (ret != SQLITE_OK) {
        throw std::runtime_error(
            strprintf("SQLiteDatabase: Failed to enable fullfsync: %s\n",
                      sqlite3_errstr(ret)));
    }

    // Make the table for our key-value pairs
    // First check that the main table exists
    sqlite3_stmt *check_main_stmt{nullptr};
    ret = sqlite3_prepare_v2(
        m_db,
        "SELECT name FROM sqlite_master WHERE type='table' AND name='main'", -1,
        &check_main_stmt, nullptr);
    if (ret != SQLITE_OK) {
        throw std::runtime_error(
            strprintf("SQLiteDatabase: Failed to prepare statement to check "
                      "table existence: %s\n",
                      sqlite3_errstr(ret)));
    }
    ret = sqlite3_step(check_main_stmt);
    if (sqlite3_finalize(check_main_stmt) != SQLITE_OK) {
        throw std::runtime_error(
            strprintf("SQLiteDatabase: Failed to finalize statement checking "
                      "table existence: %s\n",
                      sqlite3_errstr(ret)));
    }
    bool table_exists;
    if (ret == SQLITE_DONE) {
        table_exists = false;
    } else if (ret == SQLITE_ROW) {
        table_exists = true;
    } else {
        throw std::runtime_error(
            strprintf("SQLiteDatabase: Failed to execute statement to check "
                      "table existence: %s\n",
                      sqlite3_errstr(ret)));
    }

    if (!table_exists) {
        // Keep table creation and format identity in the same transaction.
        const char *schema = "BEGIN EXCLUSIVE;"
                             "PRAGMA application_id = 1280717399;" // 0x4c563257
                             "PRAGMA user_version = 1;"
                             "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, "
                             "value BLOB NOT NULL);"
                             "CREATE TABLE wallet_metadata(id INTEGER PRIMARY "
                             "KEY CHECK(id = 1), profile TEXT NOT NULL);";
        if (sqlite3_exec(m_db, schema, nullptr, nullptr, nullptr) !=
            SQLITE_OK) {
            sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, nullptr);
            throw std::runtime_error(
                "SQLiteDatabase: Failed to create wallet schema");
        }
        sqlite3_stmt *stmt{nullptr};
        bool ok =
            sqlite3_prepare_v2(m_db, "INSERT INTO wallet_metadata VALUES(1, ?)",
                               -1, &stmt, nullptr) == SQLITE_OK &&
            sqlite3_bind_text(stmt, 1, m_profile.data(), m_profile.size(),
                              SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        if (!ok || sqlite3_exec(m_db, "COMMIT", nullptr, nullptr, nullptr) !=
                       SQLITE_OK) {
            sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, nullptr);
            throw std::runtime_error(
                "SQLiteDatabase: Failed to store wallet profile");
        }
    }
    if (!CheckSQLiteIdentity(m_db, &m_profile)) {
        throw std::runtime_error(
            "SQLiteDatabase: Unsupported wallet format, version or profile");
    }
    // Erased unencrypted keys must not remain in free pages after encryption.
    if (sqlite3_exec(m_db, "PRAGMA secure_delete = ON", nullptr, nullptr,
                     nullptr) != SQLITE_OK) {
        throw std::runtime_error(
            "SQLiteDatabase: Failed to enable secure deletion");
    }
}

bool SQLiteDatabase::Rewrite(const char *skip) {
    // Rewrite the database using the VACUUM command:
    // https://sqlite.org/lang_vacuum.html
    if (skip) return false; // Legacy BDB record-prefix recovery is unsupported.
    return sqlite3_exec(m_db, "VACUUM", nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool SQLiteDatabase::Backup(const std::string &dest) const {
    fs::path target = fs::PathFromString(dest);
    if (fs::is_directory(target)) target /= WALLET_DATABASE_FILENAME;
    std::error_code ec;
    if (fs::equivalent(fs::PathFromString(m_file_path), target, ec))
        return false;
    sqlite3 *db_copy{nullptr};
    int res = sqlite3_open(fs::PathToString(target).c_str(), &db_copy);
    if (res != SQLITE_OK) {
        sqlite3_close(db_copy);
        return false;
    }
    sqlite3_backup *backup = sqlite3_backup_init(db_copy, "main", m_db, "main");
    if (!backup) {
        LogInfoEvent(BCLog::ALL, "sqlite_backup_begin_failed",
                     "{name}: Unable to begin backup: {error}")
            .Field(BCLog::LogField::Name, __func__)
            .Field(BCLog::LogField::Error, sqlite3_errmsg(m_db));
        sqlite3_close(db_copy);
        return false;
    }
    // Specifying -1 will copy all of the pages
    res = sqlite3_backup_step(backup, -1);
    if (res != SQLITE_DONE) {
        LogInfoEvent(BCLog::ALL, "sqlite_backup_failed",
                     "{name}: Unable to backup: {error}")
            .Field(BCLog::LogField::Name, __func__)
            .Field(BCLog::LogField::Error, sqlite3_errstr(res));
        sqlite3_backup_finish(backup);
        sqlite3_close(db_copy);
        return false;
    }
    res = sqlite3_backup_finish(backup);
    sqlite3_close(db_copy);
    return res == SQLITE_OK;
}

void SQLiteDatabase::Close() {
    if (!m_db) return;
    int res = sqlite3_close(m_db);
    if (res != SQLITE_OK) {
        throw std::runtime_error(
            strprintf("SQLiteDatabase: Failed to close database: %s\n",
                      sqlite3_errstr(res)));
    }
    m_db = nullptr;
}

std::unique_ptr<DatabaseBatch> SQLiteDatabase::MakeBatch(bool flush_on_close) {
    // We ignore flush_on_close because we don't do manual flushing for SQLite
    return std::make_unique<SQLiteBatch>(*this);
}

SQLiteBatch::SQLiteBatch(SQLiteDatabase &database) : m_database(database) {
    // Make sure we have a db handle
    assert(m_database.m_db);

    SetupSQLStatements();
}

void SQLiteBatch::Close() {
    // Abort only a transaction begun by this batch. Other batches can write
    // inside it without taking ownership of its lifetime.
    if (m_active_txn) {
        if (TxnAbort()) {
            LogInfoEvent(BCLog::ALL, "sqlite_batch_closed_uncommitted",
                         "SQLiteBatch: Batch closed unexpectedly without the "
                         "transaction being explicitly committed or aborted");
        } else {
            LogInfoEvent(
                BCLog::ALL, "sqlite_batch_abort_failed",
                "SQLiteBatch: Batch closed and failed to abort transaction");
        }
    }

    // Free all of the prepared statements
    int ret = sqlite3_finalize(m_read_stmt);
    if (ret != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_read_finalize_failed",
                     "SQLiteBatch: Batch closed but could not finalize read "
                     "statement: {error}")
            .Field(BCLog::LogField::Error, sqlite3_errstr(ret));
    }
    ret = sqlite3_finalize(m_insert_stmt);
    if (ret != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_insert_finalize_failed",
                     "SQLiteBatch: Batch closed but could not finalize insert "
                     "statement: {error}")
            .Field(BCLog::LogField::Error, sqlite3_errstr(ret));
    }
    ret = sqlite3_finalize(m_overwrite_stmt);
    if (ret != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_overwrite_finalize_failed",
                     "SQLiteBatch: Batch closed but could not finalize "
                     "overwrite statement: {error}")
            .Field(BCLog::LogField::Error, sqlite3_errstr(ret));
    }
    ret = sqlite3_finalize(m_delete_stmt);
    if (ret != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_delete_finalize_failed",
                     "SQLiteBatch: Batch closed but could not finalize delete "
                     "statement: {error}")
            .Field(BCLog::LogField::Error, sqlite3_errstr(ret));
    }
    ret = sqlite3_finalize(m_cursor_stmt);
    if (ret != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_cursor_finalize_failed",
                     "SQLiteBatch: Batch closed but could not finalize cursor "
                     "statement: {error}")
            .Field(BCLog::LogField::Error, sqlite3_errstr(ret));
    }
    m_read_stmt = nullptr;
    m_insert_stmt = nullptr;
    m_overwrite_stmt = nullptr;
    m_delete_stmt = nullptr;
    m_cursor_stmt = nullptr;
}

bool SQLiteBatch::ReadKey(DataStream &&key, DataStream &value) {
    if (!m_database.m_db) {
        return false;
    }
    assert(m_read_stmt);

    // Bind: leftmost parameter in statement is index 1
    int res = sqlite3_bind_blob(m_read_stmt, 1, key.data(), key.size(),
                                SQLITE_STATIC);
    if (res != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_statement_bind_failed",
                     "{name}: Unable to bind statement: {error}")
            .Field(BCLog::LogField::Name, __func__)
            .Field(BCLog::LogField::Error, sqlite3_errstr(res));
        sqlite3_clear_bindings(m_read_stmt);
        sqlite3_reset(m_read_stmt);
        return false;
    }
    res = sqlite3_step(m_read_stmt);
    if (res != SQLITE_ROW) {
        if (res != SQLITE_DONE) {
            // SQLITE_DONE means "not found", don't log an error in that case.
            LogInfoEvent(BCLog::ALL, "sqlite_statement_execute_failed",
                         "{name}: Unable to execute statement: {error}")
                .Field(BCLog::LogField::Name, __func__)
                .Field(BCLog::LogField::Error, sqlite3_errstr(res));
        }
        sqlite3_clear_bindings(m_read_stmt);
        sqlite3_reset(m_read_stmt);
        return false;
    }
    // Leftmost column in result is index 0
    const std::byte *data{BytePtr(sqlite3_column_blob(m_read_stmt, 0))};
    size_t data_size(sqlite3_column_bytes(m_read_stmt, 0));
    value.write({data, data_size});

    sqlite3_clear_bindings(m_read_stmt);
    sqlite3_reset(m_read_stmt);
    return true;
}

bool SQLiteBatch::WriteKey(DataStream &&key, DataStream &&value,
                           bool overwrite) {
    if (!m_database.m_db) {
        return false;
    }
    assert(m_insert_stmt && m_overwrite_stmt);

    sqlite3_stmt *stmt;
    if (overwrite) {
        stmt = m_overwrite_stmt;
    } else {
        stmt = m_insert_stmt;
    }

    // Bind: leftmost parameter in statement is index 1
    // Insert index 1 is key, 2 is value
    int res = sqlite3_bind_blob(stmt, 1, key.data(), key.size(), SQLITE_STATIC);
    if (res != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_key_bind_failed",
                     "{name}: Unable to bind key to statement: {error}")
            .Field(BCLog::LogField::Name, __func__)
            .Field(BCLog::LogField::Error, sqlite3_errstr(res));
        sqlite3_clear_bindings(stmt);
        sqlite3_reset(stmt);
        return false;
    }
    res = sqlite3_bind_blob(stmt, 2, value.data(), value.size(), SQLITE_STATIC);
    if (res != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_value_bind_failed",
                     "{name}: Unable to bind value to statement: {error}")
            .Field(BCLog::LogField::Name, __func__)
            .Field(BCLog::LogField::Error, sqlite3_errstr(res));
        sqlite3_clear_bindings(stmt);
        sqlite3_reset(stmt);
        return false;
    }

    // Execute
    res = sqlite3_step(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_reset(stmt);
    if (res != SQLITE_DONE) {
        LogInfoEvent(BCLog::ALL, "sqlite_statement_execute_failed",
                     "{name}: Unable to execute statement: {error}")
            .Field(BCLog::LogField::Name, __func__)
            .Field(BCLog::LogField::Error, sqlite3_errstr(res));
    }
    return res == SQLITE_DONE;
}

bool SQLiteBatch::EraseKey(DataStream &&key) {
    if (!m_database.m_db) {
        return false;
    }
    assert(m_delete_stmt);

    // Bind: leftmost parameter in statement is index 1
    int res = sqlite3_bind_blob(m_delete_stmt, 1, key.data(), key.size(),
                                SQLITE_STATIC);
    if (res != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_statement_bind_failed",
                     "{name}: Unable to bind statement: {error}")
            .Field(BCLog::LogField::Name, __func__)
            .Field(BCLog::LogField::Error, sqlite3_errstr(res));
        sqlite3_clear_bindings(m_delete_stmt);
        sqlite3_reset(m_delete_stmt);
        return false;
    }

    // Execute
    res = sqlite3_step(m_delete_stmt);
    sqlite3_clear_bindings(m_delete_stmt);
    sqlite3_reset(m_delete_stmt);
    if (res != SQLITE_DONE) {
        LogInfoEvent(BCLog::ALL, "sqlite_statement_execute_failed",
                     "{name}: Unable to execute statement: {error}")
            .Field(BCLog::LogField::Name, __func__)
            .Field(BCLog::LogField::Error, sqlite3_errstr(res));
    }
    return res == SQLITE_DONE;
}

bool SQLiteBatch::HasKey(DataStream &&key) {
    if (!m_database.m_db) {
        return false;
    }
    assert(m_read_stmt);

    // Bind: leftmost parameter in statement is index 1
    bool ret = false;
    int res = sqlite3_bind_blob(m_read_stmt, 1, key.data(), key.size(),
                                SQLITE_STATIC);
    if (res == SQLITE_OK) {
        res = sqlite3_step(m_read_stmt);
        if (res == SQLITE_ROW) {
            ret = true;
        }
    }

    sqlite3_clear_bindings(m_read_stmt);
    sqlite3_reset(m_read_stmt);
    return ret;
}

bool SQLiteBatch::StartCursor() {
    assert(!m_cursor_init);
    if (!m_database.m_db) {
        return false;
    }
    m_cursor_init = true;
    return true;
}

bool SQLiteBatch::ReadAtCursor(DataStream &key, DataStream &value,
                               bool &complete) {
    complete = false;

    if (!m_cursor_init) {
        return false;
    }

    int res = sqlite3_step(m_cursor_stmt);
    if (res == SQLITE_DONE) {
        complete = true;
        return true;
    }
    if (res != SQLITE_ROW) {
        LogInfoEvent(
            BCLog::ALL, "sqlite_cursor_step_failed",
            "SQLiteBatch::ReadAtCursor: Unable to execute cursor step: {error}")
            .Field(BCLog::LogField::Error, sqlite3_errstr(res));
        return false;
    }

    // Leftmost column in result is index 0
    const std::byte *key_data{BytePtr(sqlite3_column_blob(m_cursor_stmt, 0))};
    size_t key_data_size(sqlite3_column_bytes(m_cursor_stmt, 0));
    key.write({key_data, key_data_size});
    const std::byte *value_data{BytePtr(sqlite3_column_blob(m_cursor_stmt, 1))};
    size_t value_data_size(sqlite3_column_bytes(m_cursor_stmt, 1));
    value.write({value_data, value_data_size});
    return true;
}

void SQLiteBatch::CloseCursor() {
    sqlite3_reset(m_cursor_stmt);
    m_cursor_init = false;
}

bool SQLiteBatch::TxnBegin() {
    if (!m_database.m_db || sqlite3_get_autocommit(m_database.m_db) == 0) {
        return false;
    }
    int res = sqlite3_exec(m_database.m_db, "BEGIN TRANSACTION", nullptr,
                           nullptr, nullptr);
    if (res != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_transaction_begin_failed",
                     "SQLiteBatch: Failed to begin the transaction");
    }
    if (res == SQLITE_OK) m_active_txn = true;
    return res == SQLITE_OK;
}

bool SQLiteBatch::TxnCommit() {
    if (!m_active_txn || !m_database.m_db ||
        sqlite3_get_autocommit(m_database.m_db) != 0) {
        return false;
    }
    int res = sqlite3_exec(m_database.m_db, "COMMIT TRANSACTION", nullptr,
                           nullptr, nullptr);
    if (res != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_transaction_commit_failed",
                     "SQLiteBatch: Failed to commit the transaction");
    }
    if (res == SQLITE_OK) m_active_txn = false;
    return res == SQLITE_OK;
}

bool SQLiteBatch::TxnAbort() {
    if (!m_active_txn || !m_database.m_db ||
        sqlite3_get_autocommit(m_database.m_db) != 0) {
        return false;
    }
    int res = sqlite3_exec(m_database.m_db, "ROLLBACK TRANSACTION", nullptr,
                           nullptr, nullptr);
    if (res != SQLITE_OK) {
        LogInfoEvent(BCLog::ALL, "sqlite_transaction_abort_failed",
                     "SQLiteBatch: Failed to abort the transaction");
    }
    if (res == SQLITE_OK) m_active_txn = false;
    return res == SQLITE_OK;
}

bool ExistsSQLiteDatabase(const fs::path &path) {
    const fs::path file = path / WALLET_DATABASE_FILENAME;
    std::ifstream stream{file, std::ios::binary};
    std::array<unsigned char, 72> header{};
    if (!stream.read(reinterpret_cast<char *>(header.data()), header.size()) ||
        std::string(reinterpret_cast<const char *>(header.data()), 16) !=
            std::string("SQLite format 3\0", 16))
        return false;
    auto u32 = [&](size_t offset) {
        return uint32_t(header[offset]) << 24 |
               uint32_t(header[offset + 1]) << 16 |
               uint32_t(header[offset + 2]) << 8 | uint32_t(header[offset + 3]);
    };
    // Read only the stable format header so loaded, exclusively locked wallets
    // remain discoverable. Full schema/profile validation happens before open.
    return u32(68) == WALLET_APPLICATION_ID && u32(60) == WALLET_SCHEMA_VERSION;
}

std::unique_ptr<SQLiteDatabase>
MakeSQLiteDatabase(const fs::path &path, const DatabaseOptions &options,
                   DatabaseStatus &status, bilingual_str &error) {
    if (options.wallet_profile.empty()) {
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        error = Untranslated(
            "Wallet storage requires an explicit profile identity.");
        return nullptr;
    }
    const fs::path file = path / WALLET_DATABASE_FILENAME;
    if (fs::exists(file)) {
        sqlite3 *db{nullptr};
        const int ret = sqlite3_open_v2(fs::PathToString(file).c_str(), &db,
                                        SQLITE_OPEN_READONLY, nullptr);
        const bool ok = ret == SQLITE_OK &&
                        CheckSQLiteIdentity(db, &options.wallet_profile);
        const int err = db ? sqlite3_errcode(db) : ret;
        sqlite3_close(db);
        if (!ok) {
            if (err == SQLITE_BUSY || err == SQLITE_LOCKED) {
                status = DatabaseStatus::FAILED_LOAD;
                error = Untranslated(
                    "SQLiteDatabase: Unable to obtain an exclusive lock on the "
                    "database, is it being used by another process?\n");
                return nullptr;
            }
            status = DatabaseStatus::FAILED_BAD_FORMAT;
            error = Untranslated(
                "Wallet SQLite format, version or profile does not match.");
            return nullptr;
        }
    }
    try {
        auto db = std::make_unique<SQLiteDatabase>(path, file, false,
                                                   options.wallet_profile);
        if (options.verify && !db->Verify(error)) {
            status = DatabaseStatus::FAILED_VERIFY;
            return nullptr;
        }
        status = DatabaseStatus::SUCCESS;
        return db;
    } catch (const std::runtime_error &e) {
        status = DatabaseStatus::FAILED_LOAD;
        error = Untranslated(e.what());
        return nullptr;
    }
}

std::string SQLiteDatabaseVersion() {
    return std::string(sqlite3_libversion());
}
