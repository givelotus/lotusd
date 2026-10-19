// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core/db/dump.h>

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/hex.h>

#include <algorithm>

namespace chronik::native::db {

namespace {

std::string Line(std::string_view table, ByteView key, ByteView value) {
    std::string line(table);
    line += '\t';
    line += HexEncode(key);
    line += '\t';
    line += HexEncode(value);
    return line;
}

} // namespace

std::vector<std::string> DumpTableLines(const KvStore &store,
                                        const ReadTxn &txn,
                                        const TableSpec &table) {
    const TableId id = store.Table(table.name);
    std::vector<std::string> lines;
    const std::unique_ptr<Cursor> cursor = txn.OpenCursor(id);
    if (table.kind == TableSpec::Kind::Plain) {
        for (bool ok = cursor->SeekFirst(); ok; ok = cursor->Next()) {
            lines.push_back(Line(table.name, cursor->Key(), cursor->Value()));
        }
    } else {
        // Visit each distinct key once (a backend's cursor may or may not
        // step through the dups), then expand its dups with a DupCursor.
        const std::unique_ptr<DupCursor> dups = txn.OpenDupCursor(id);
        bool ok = cursor->SeekFirst();
        while (ok) {
            const Bytes key(cursor->Key().begin(), cursor->Key().end());
            for (bool has = dups->Seek(key); has; has = dups->Next()) {
                lines.push_back(Line(table.name, key, dups->Value()));
            }
            do {
                ok = cursor->Next();
            } while (ok && Equal(cursor->Key(), key));
        }
    }
    std::sort(lines.begin(), lines.end());
    return lines;
}

std::vector<std::string> DumpLines(const KvStore &store, const ReadTxn &txn,
                                   std::span<const TableSpec> tables) {
    std::vector<std::string> lines;
    for (const TableSpec &table : tables) {
        std::vector<std::string> table_lines =
            DumpTableLines(store, txn, table);
        lines.insert(lines.end(), std::make_move_iterator(table_lines.begin()),
                     std::make_move_iterator(table_lines.end()));
    }
    std::sort(lines.begin(), lines.end());
    return lines;
}

void DumpStore(const KvStore &store, std::span<const TableSpec> tables,
               std::ostream &out) {
    const std::unique_ptr<ReadTxn> txn = store.BeginRead();
    for (const std::string &line : DumpLines(store, *txn, tables)) {
        out << line << '\n';
    }
}

} // namespace chronik::native::db
