// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TEST_TOKEN_IO_MOCK_H
#define CHRONIK_NATIVE_TEST_TOKEN_IO_MOCK_H

// Port of chronik-db io/token/tests/mock.rs (MockTokenDb, make_tx, ...).

#include <chronik/native/index/index_tx.h>
#include <chronik/native/index/txs.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/token_io/data.h>
#include <chronik/native/token_io/io.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace chronik::native::test {

using token_io::DbToken;
using token_io::DbTokenTx;

inline token::TokenId token_id(uint8_t num) {
    return token::TokenId{TxIdNum(num)};
}

template <uint32_t N> DbToken db_atoms(token::Atoms atoms) {
    return DbToken::MakeAtoms(N, atoms);
}

template <uint32_t N> DbToken db_baton() {
    return DbToken::MintBaton(N);
}

inline const DbToken NoToken = DbToken::NoToken();

/**
 * Tx with the given inputs (txid_num, out_idx, spent script), an OP_RETURN
 * output `op_return_script` followed by `num_outputs` empty outputs.
 */
inline Tx make_tx_with_scripts(
    uint8_t txid_num,
    const std::vector<std::tuple<uint8_t, uint32_t, Bytes>> &inputs,
    size_t num_outputs, const Bytes &op_return_script) {
    Tx tx;
    tx.txid = TxIdNum(txid_num);
    tx.version = 0;
    for (const auto &[input_txid_num, out_idx, script] : inputs) {
        TxInput input;
        input.prev_out.txid = TxIdNum(input_txid_num);
        input.prev_out.out_idx = out_idx;
        Coin coin;
        coin.output.sats = 0;
        coin.output.script = script;
        input.coin = coin;
        tx.inputs.push_back(std::move(input));
    }
    tx.outputs.push_back(TxOutput{0, op_return_script});
    for (size_t i = 0; i < num_outputs; ++i) {
        tx.outputs.push_back(TxOutput{});
    }
    tx.locktime = 0;
    return tx;
}

inline Tx make_tx(uint8_t txid_num,
                  const std::vector<std::pair<uint8_t, uint32_t>> &inputs,
                  size_t num_outputs, const Bytes &op_return_script) {
    std::vector<std::tuple<uint8_t, uint32_t, Bytes>> with_scripts;
    for (const auto &[num, out_idx] : inputs) {
        with_scripts.emplace_back(num, out_idx, Bytes{});
    }
    return make_tx_with_scripts(txid_num, with_scripts, num_outputs,
                                op_return_script);
}

/** Rust Debug-like rendering of a DbTokenTx, for failure messages. */
inline std::string DebugDbTokenTx(const std::optional<DbTokenTx> &tx) {
    if (!tx) {
        return "None";
    }
    std::string s = "DbTokenTx { token_tx_nums: [";
    for (size_t i = 0; i < tx->token_tx_nums.size(); ++i) {
        s += (i ? ", " : "") + std::to_string(tx->token_tx_nums[i]);
    }
    s += "], group_token_indices: {";
    bool first = true;
    for (const auto &[k, v] : tx->group_token_indices) {
        s += (first ? "" : ", ") + std::to_string(k) + ": " +
             std::to_string(v);
        first = false;
    }
    s += "}, inputs: [";
    for (size_t i = 0; i < tx->inputs.size(); ++i) {
        s += (i ? ", " : "") + tx->inputs[i].Debug();
    }
    s += "], outputs: [";
    for (size_t i = 0; i < tx->outputs.size(); ++i) {
        s += (i ? ", " : "") + tx->outputs[i].Debug();
    }
    s += "], flags: " + std::to_string(tx->flags) + " }";
    return s;
}

inline void CheckTokenTx(const std::optional<DbTokenTx> &actual,
                         const std::optional<DbTokenTx> &expected) {
    BOOST_CHECK_MESSAGE(actual == expected,
                        "got " << DebugDbTokenTx(actual) << ", expected "
                               << DebugDbTokenTx(expected));
}

inline DbTokenTx MakeDbTokenTx(std::vector<token_io::TxNum> token_tx_nums,
                               std::vector<DbToken> inputs,
                               std::vector<DbToken> outputs,
                               std::map<uint32_t, uint32_t> groups = {},
                               uint8_t flags = 0) {
    DbTokenTx tx;
    tx.token_tx_nums = std::move(token_tx_nums);
    tx.group_token_indices = std::move(groups);
    tx.inputs = std::move(inputs);
    tx.outputs = std::move(outputs);
    tx.flags = flags;
    return tx;
}

/** Rust `MockTokenDb`: connect/disconnect blocks of txs (txs + tokens). */
struct MockTokenDb {
    KvStore &store;
    index::BlockHeight block_height = -1;

    explicit MockTokenDb(KvStore &store_) : store(store_) {}

    static index::BlockTxs TxsBatch(const std::vector<Tx> &txs,
                                    index::BlockHeight height) {
        index::BlockTxs batch;
        for (const Tx &tx : txs) {
            index::TxEntry entry;
            entry.txid = tx.txid;
            batch.txs.push_back(entry);
        }
        batch.block_height = height;
        return batch;
    }

    token_io::ProcessedTokenTxBatch Connect(const std::vector<Tx> &txs) {
        const index::TxWriter tx_writer(store);
        const token_io::TokenWriter token_writer(store);
        auto txn = store.BeginWrite();
        index::TxsMemData txs_mem_data;
        const index::TxNum first_tx_num = tx_writer.Insert(
            *txn, TxsBatch(txs, block_height + 1), txs_mem_data);
        const auto index_txs =
            index::PrepareIndexedTxs(store, *txn, first_tx_num, txs);
        auto result = token_writer.Insert(*txn, index_txs);
        txn->Commit();
        block_height += 1;
        return result;
    }

    void Disconnect(const std::vector<Tx> &txs) {
        const index::TxWriter tx_writer(store);
        const token_io::TokenWriter token_writer(store);
        auto txn = store.BeginWrite();
        index::TxsMemData txs_mem_data;
        const index::TxNum first_tx_num = tx_writer.Delete(
            *txn, TxsBatch(txs, block_height), txs_mem_data);
        const auto index_txs =
            index::PrepareIndexedTxs(store, *txn, first_tx_num, txs);
        token_writer.Delete(*txn, index_txs);
        txn->Commit();
        block_height -= 1;
    }
};

/** TokenReader on a fresh read txn per call. */
struct MockTokenReader {
    const KvStore &store;

    std::optional<DbTokenTx> token_tx(token_io::TxNum tx_num) const {
        auto txn = store.BeginRead();
        return token_io::TokenReader(store, *txn).TokenTx(tx_num);
    }
    std::optional<token::GenesisInfo>
    genesis_info(token_io::TxNum tx_num) const {
        auto txn = store.BeginRead();
        return token_io::TokenReader(store, *txn).GenesisInfo(tx_num);
    }
    std::optional<token::TokenMeta> token_meta(token_io::TxNum tx_num) const {
        auto txn = store.BeginRead();
        return token_io::TokenReader(store, *txn).TokenMeta(tx_num);
    }
};

} // namespace chronik::native::test

#endif // CHRONIK_NATIVE_TEST_TOKEN_IO_MOCK_H
