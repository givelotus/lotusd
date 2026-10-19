// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CORE_DB_DUMP_H
#define CHRONIK_NATIVE_CORE_DB_DUMP_H

#include <chronik/native/store.h>

#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

/**
 * DB dump for parity checks (design §8): every table as
 * `table\tkey_hex\tvalue_hex` lines, sorted, with dup values expanded (one
 * line per dup value). Keys are the stored (physical) keys, i.e. long keys
 * appear in their hashed form, exactly as in a dump of a Rust-built env.
 */
namespace chronik::native::db {

/** Dump lines (without newline) of one table, sorted. */
std::vector<std::string> DumpTableLines(const KvStore &store,
                                        const ReadTxn &txn,
                                        const TableSpec &table);

/** Dump lines of all `tables`, sorted. */
std::vector<std::string> DumpLines(const KvStore &store, const ReadTxn &txn,
                                   std::span<const TableSpec> tables);

/** Write DumpLines of a fresh read txn, one per line ("\n"-terminated). */
void DumpStore(const KvStore &store, std::span<const TableSpec> tables,
               std::ostream &out);

} // namespace chronik::native::db

#endif // CHRONIK_NATIVE_CORE_DB_DUMP_H
