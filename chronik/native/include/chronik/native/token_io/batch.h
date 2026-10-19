// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_IO_BATCH_H
#define CHRONIK_NATIVE_TOKEN_IO_BATCH_H

#include <chronik/native/error.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/token/color.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/token/verify.h>
#include <chronik/native/token_io/data.h>

#include <map>
#include <optional>
#include <set>
#include <span>
#include <tuple>
#include <vector>

/** Port of chronik-db io/token/batch.rs */
namespace chronik::native::token_io {

/**
 * Rust `BatchError`: error when batch-processing txs, usually implies a
 * critical failure. Messages:
 *  - Cycle: "Cycle in SLP txs"
 *  - MissingTokenTxNum: "Inconsistent BatchDbData: Missing TokenId for token
 *    tx num {0}"
 *  - MissingTxInputCoin: "Inconsistent Tx: Missing coin for TxInput {0:?}"
 */
class BatchError : public ChronikError {
public:
    using ChronikError::ChronikError;
    static BatchError Cycle();
    static BatchError MissingTokenTxNum(TxNum tx_num);
    static BatchError MissingTxInputCoin(const OutPoint &outpoint);
};

/** Tx that has token data encoded in it and is ready for token validation */
struct PreparedTx {
    /** Tx with index data (tx_num etc.) */
    const index::IndexTx *tx = nullptr;
    /**
     * Parsed & colored tx. Note that in this context we only store txs with
     * a non-empty list of sections.
     */
    token::ColoredTx colored;
};

/**
 * Bidirectional TxNum <-> TokenMeta map (Rust `BiMap<TxNum, TokenMeta>`).
 * Insert removes any existing pair with the same left or right value.
 */
class TokenMetaBiMap {
public:
    void Insert(TxNum tx_num, const token::TokenMeta &meta);
    const token::TokenMeta *GetByLeft(TxNum tx_num) const;
    const TxNum *GetByRight(const token::TokenMeta &meta) const;
    size_t Size() const { return m_left.size(); }
    const std::map<TxNum, token::TokenMeta> &Left() const { return m_left; }

private:
    std::map<TxNum, token::TokenMeta> m_left;
    std::map<token::TokenMeta, TxNum> m_right;
};

/** DB data required to process a batch of txs */
struct BatchDbData {
    /** Token tx data coming from the DB */
    std::map<TxNum, DbTokenTx> token_txs;
    /**
     * token_nums assigned for each [`TokenMeta`]. This is a bi-map so we can
     * lookup either direction.
     */
    TokenMetaBiMap token_metas;
    /** [`GenesisInfo`] from the database; required for SLP V2 Mint Vault txs */
    std::map<token::TokenMeta, token::GenesisInfo> genesis_infos;
};

/** Result of the batch verification before inserting */
struct ProcessedTokenTxBatch {
    /** New tokens to be added to the DB */
    std::vector<std::tuple<TxNum, token::TokenMeta, token::GenesisInfo>>
        new_tokens;
    /** New DB data for txs to be added to the DB. */
    std::map<TxNum, DbTokenTx> db_token_txs;
    /** Validated token txs in the batch. */
    std::map<TxNum, token::TokenTx> valid_txs;
    /** Validated spent tokens in the batch, can have entries not in valid_txs */
    std::map<TxNum, std::vector<std::optional<token::SpentToken>>>
        spent_tokens;
    /**
     * True if validation of txs was performed, or false if validation was
     * safely skipped because no tokens are in the DB and the batch contained
     * no token txs.
     */
    bool did_validation = false;
};

/**
 * Struct bundling all the data necessary to process a batch (i.e. a block)
 * of token txs. `txs` must outlive the processor.
 */
class BatchProcessor {
public:
    /** Prepare the given indexed txs as token txs. */
    static BatchProcessor Prepare(std::span<const index::IndexTx> txs);

    /** Collect all [`TokenMeta`]s of the SLP V2 Mint Vault txs in the batch */
    std::set<token::TokenMeta> CollectMintVaultMetas() const;

    /**
     * Verify the entire batch of txs. It updates the DB data with some token
     * data during validation, but that can be discarded. The result of the
     * verification is returned as [`ProcessedTokenTxBatch`]. Consumes the
     * prepared txs.
     */
    ProcessedTokenTxBatch Verify(BatchDbData db_data);

    /** Tx that have any token info attached */
    std::map<TxNum, PreparedTx> prepared_txs;
    /** Non-token txs may still have token inputs */
    std::vector<const index::IndexTx *> non_token_txs;
    /**
     * Whether the batch has any GENESIS txs; if the token index is empty and
     * we have no GENESIS, we can safely ignore the batch.
     */
    bool has_any_genesis = false;

private:
    void VerifyTokenTx(PreparedTx prepared_tx, BatchDbData &db_data,
                       ProcessedTokenTxBatch &processed_batch) const;
    void ProcessNonTokenTx(const index::IndexTx &tx, BatchDbData &db_data,
                           ProcessedTokenTxBatch &processed_batch) const;
    static std::vector<script::Script>
    TxSpentScripts(const index::IndexTx &tx);
    std::vector<std::optional<token::SpentToken>>
    TxTokenInputs(const index::IndexTx &tx, const BatchDbData &db_data,
                  const std::map<TxNum, token::TokenTx> &valid_txs) const;
    std::optional<token::SpentToken>
    TokenOutput(TxNum tx_num, size_t out_idx, const BatchDbData &db_data,
                const std::map<TxNum, token::TokenTx> &valid_txs) const;
};

} // namespace chronik::native::token_io

#endif // CHRONIK_NATIVE_TOKEN_IO_BATCH_H
