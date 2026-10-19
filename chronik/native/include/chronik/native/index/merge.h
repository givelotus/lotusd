// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_MERGE_H
#define CHRONIK_NATIVE_INDEX_MERGE_H

#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <exception>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>

/**
 * Port of chronik-db io/merge.rs.
 *
 * The Rust Chronik uses merge operators (RocksDB-style, emulated by its MDBX
 * `Db` at write_batch time). Here each merge is an explicit read-modify-write
 * inside the WriteTxn, applying all operands queued for one key in one call,
 * so the stored bytes are exactly the ones the Rust merge produces, including
 * its error handling (`catch_merge_errors`):
 *  - init fails: the existing value is kept (or "" is inserted if none);
 *  - an operand fails: the operands applied so far are kept, the rest is
 *    dropped;
 *  - serialization fails: like init failing.
 * The error is not thrown but stored, and reported by CheckForErrors(), which
 * the indexer calls after every block (Rust `merge::check_for_errors`).
 */
namespace chronik::native::index::merge {

/** Throws (and clears) the error of a previously failed merge, if any. */
void CheckForErrors();

/** Record a failed merge (Rust `handle_err`). */
void HandleErr(const std::string &msg);

/**
 * Optional logger for failed merges (Rust logs "MERGE ERROR: <msg>\n").
 * Process-wide, like the stored error.
 */
void SetErrorLogger(std::function<void(const std::string &)> logger);

/**
 * Apply `operands` to the value at `key`, the way `catch_merge_errors`
 * wraps a full merge.
 *  - f_init(key, existing, num_operands) -> T
 *  - f_apply(key, T &, operand)
 *  - f_ser(key, T &&) -> Bytes
 * Each may throw to signal an error.
 */
template <typename Init, typename Apply, typename Ser>
void CatchMergeErrors(WriteTxn &txn, TableId table, ByteView key,
                      std::span<const Bytes> operands, Init &&f_init,
                      Apply &&f_apply, Ser &&f_ser) {
    std::optional<Bytes> existing;
    if (const std::optional<ByteView> value = txn.Get(table, key)) {
        existing.emplace(value->begin(), value->end());
    }
    const std::optional<ByteView> existing_view =
        existing ? std::optional<ByteView>(ByteView(*existing)) : std::nullopt;
    auto put_fallback = [&] {
        const Bytes fallback = existing ? *existing : Bytes{};
        txn.Put(table, key, fallback);
    };

    using T = decltype(f_init(key, existing_view, operands.size()));
    std::optional<T> value;
    try {
        value.emplace(f_init(key, existing_view, operands.size()));
    } catch (const std::exception &err) {
        HandleErr(err.what());
        put_fallback();
        return;
    }

    auto handle_ser = [&] {
        Bytes ser;
        try {
            ser = f_ser(key, std::move(*value));
        } catch (const std::exception &err) {
            HandleErr(err.what());
            put_fallback();
            return;
        }
        txn.Put(table, key, ser);
    };

    for (const Bytes &operand : operands) {
        try {
            f_apply(key, *value, ByteView(operand));
        } catch (const std::exception &err) {
            // Turn failed merge op into a no-op (returns the serialized
            // existing value)
            HandleErr(err.what());
            handle_ser();
            return;
        }
    }
    handle_ser();
}

} // namespace chronik::native::index::merge

#endif // CHRONIK_NATIVE_INDEX_MERGE_H
