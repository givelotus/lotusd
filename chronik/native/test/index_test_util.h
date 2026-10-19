// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TEST_INDEX_TEST_UTIL_H
#define CHRONIK_NATIVE_TEST_INDEX_TEST_UTIL_H

#include <chronik/native/mdbx_store.h>
#include <chronik/native/schema.h>
#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <test/test_sha256.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <tuple>
#include <vector>

/**
 * Helpers for the index/mem unit tests, ports of chronik-db's test module
 * (test/value_group.rs make_inputs_tx/make_value_tx) and of the tempdir +
 * `Db::open` setup of the Rust tests. Stores use the MDBX backend.
 */
namespace chronik::native::test {

/** Fresh temporary directory, removed on destruction. */
struct IndexTempDir {
    std::filesystem::path path;
    explicit IndexTempDir(const std::string &name) {
        static std::atomic<int> counter{0};
        std::random_device rd;
        path = std::filesystem::temp_directory_path() /
               ("chronik-native-" + name + "-" + std::to_string(rd()) + "-" +
                std::to_string(counter++));
        std::filesystem::remove_all(path);
    }
    ~IndexTempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

/**
 * An MDBX store in a temp dir with the 26 eCash-tier tables (Rust
 * `Db::open`) plus `extra` test tables.
 */
struct TestDb {
    IndexTempDir dir;
    std::vector<TableSpec> tables;
    std::unique_ptr<KvStore> store;

    explicit TestDb(const std::string &name,
                    const std::vector<TableSpec> &extra = {})
        : dir(name) {
        RegisterMdbxStore();
        schema::Schema schema;
        for (const TableSpec &spec : extra) {
            schema.Add(spec);
        }
        tables.assign(schema.Tables().begin(), schema.Tables().end());
        StoreOptions opts;
        opts.sha256 = [](ByteView data, uint8_t out[32]) {
            TestSha256(data, out);
        };
        store = OpenStore(StoreBackend::Mdbx, dir.path, tables, opts);
    }
    ~TestDb() { store.reset(); }

    KvStore &operator*() { return *store; }
    KvStore *operator->() { return store.get(); }
};

inline TxId TxIdNum(uint8_t num) {
    TxId txid;
    txid.b.fill(num);
    return txid;
}

/**
 * Make a tx with inputs and outputs having the given values (Rust
 * `make_inputs_tx`): inputs are (input_txid_num, out_idx, sats) and carry a
 * coin with empty script.
 */
inline Tx MakeInputsTx(
    uint8_t txid_num,
    const std::vector<std::tuple<uint8_t, uint32_t, int64_t>> &input_values,
    const std::vector<int64_t> &output_values) {
    Tx tx;
    tx.txid = TxIdNum(txid_num);
    tx.version = 0;
    for (const auto &[input_txid_num, out_idx, sats] : input_values) {
        TxInput input;
        input.prev_out.txid = TxIdNum(input_txid_num);
        input.prev_out.out_idx = out_idx;
        Coin coin;
        coin.output.sats = sats;
        input.coin = coin;
        tx.inputs.push_back(std::move(input));
    }
    for (const int64_t sats : output_values) {
        TxOutput output;
        output.sats = sats;
        tx.outputs.push_back(std::move(output));
    }
    tx.locktime = 0;
    return tx;
}

/** Rust `make_value_tx`: inputs spend (0, 0) with the given values. */
inline Tx MakeValueTx(uint8_t txid_num,
                      const std::vector<int64_t> &input_values,
                      const std::vector<int64_t> &output_values) {
    std::vector<std::tuple<uint8_t, uint32_t, int64_t>> inputs;
    for (const int64_t sats : input_values) {
        inputs.emplace_back(0, 0, sats);
    }
    return MakeInputsTx(txid_num, inputs, output_values);
}

/** Message of the exception thrown by `f`, or "<no exception>". */
template <typename F> std::string ErrorMsg(F &&f) {
    try {
        f();
    } catch (const std::exception &e) {
        return e.what();
    }
    return "<no exception>";
}

/** The pointers of `txs`, for PrepareIndexedTxs. */
inline std::vector<const Tx *> TxPtrs(const std::vector<Tx> &txs) {
    std::vector<const Tx *> ptrs;
    for (const Tx &tx : txs) {
        ptrs.push_back(&tx);
    }
    return ptrs;
}

} // namespace chronik::native::test

#endif // CHRONIK_NATIVE_TEST_INDEX_TEST_UTIL_H
