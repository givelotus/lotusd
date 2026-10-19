// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_IO_IO_H
#define CHRONIK_NATIVE_TOKEN_IO_IO_H

#include <chronik/native/error.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/store.h>
#include <chronik/native/token/structs.h>
#include <chronik/native/token/verify.h>
#include <chronik/native/token_io/batch.h>
#include <chronik/native/token_io/data.h>

#include <optional>
#include <set>
#include <span>
#include <utility>
#include <vector>

/**
 * Port of chronik-db io/token/io.rs: TokenWriter / TokenReader.
 *
 * Token data is split into these tables:
 *  - token_genesis_info: TxNum (of GENESIS tx) -> serialized [`GenesisInfo`]
 *  - token_meta: TxNum (of GENESIS tx) -> serialized [`TokenMeta`]
 *  - token_tx: TxNum -> serialized [`DbTokenTx`]
 * TxNums are serialized big-endian 8 bytes (like TxWriter).
 *
 * Verification steps (TokenWriter::Insert): prepare (parse & color), skip
 * (empty token DB and no GENESIS in the batch), fetch input token txs and
 * their TokenMetas, topo-sort and verify the token txs, process non-token
 * txs (burns), insert.
 */
namespace chronik::native::token_io {

/**
 * Rust `TokenIndexError`:
 * "Inconsistent DB: Token TxNum {0} not found in DB"
 */
class TokenIndexError : public ChronikError {
public:
    using ChronikError::ChronikError;
    static TokenIndexError TokenTxNumNotFound(TxNum tx_num);
};

/** Writes token data to the indexer. */
class TokenWriter {
public:
    explicit TokenWriter(const KvStore &store);

    /**
     * Parse, color & validate the txs as token txs and add them to the index.
     * Returns the processed result so we can use it in subsequent indices
     * (TokenIdGroupAux::FromBatch).
     *
     * `txn` is the block's write txn. It must already contain the batch's txs
     * (TxWriter::Insert); like the Rust RocksDB reads, which never see the
     * pending WriteBatch, data of txs with TxNum >= the batch's first TxNum
     * is ignored when looking up SLP V2 mint vault GENESIS txs.
     */
    ProcessedTokenTxBatch Insert(WriteTxn &txn,
                                 std::span<const index::IndexTx> txs) const;

    /** Delete the batch of txs from the token index */
    void Delete(WriteTxn &txn, std::span<const index::IndexTx> txs) const;

    /** Clear all token data from the DB */
    void Wipe(WriteTxn &txn) const;

private:
    const KvStore &m_store;
    TableId m_genesis_info, m_token_meta, m_token_tx;
};

/** Read token data from the indexer */
class TokenReader {
public:
    TokenReader(const KvStore &store, const ReadTxn &txn);

    /** Look up a [`TokenMeta`] by [`TxNum`]. */
    std::optional<token::TokenMeta> TokenMeta(TxNum token_tx_num) const;

    /**
     * Batch-lookup a set of [`TokenMeta`]s by [`TxNum`]. Throws
     * TokenIndexError::TokenTxNumNotFound for missing ones.
     */
    std::vector<std::pair<TxNum, token::TokenMeta>>
    TokenMetas(const std::set<TxNum> &token_tx_nums) const;

    /** Look up a the DB data of a token tx by [`TxNum`]. */
    std::optional<DbTokenTx> TokenTx(TxNum tx_num) const;

    /** Batch-lookup a set of [`DbTokenTx`]s by [`TxNum`] (missing skipped). */
    std::vector<std::pair<TxNum, DbTokenTx>>
    TokenTxs(const std::set<TxNum> &tx_nums) const;

    /** Look up the DB genesis data of a GENESIS token tx by [`TxNum`]. */
    std::optional<token::GenesisInfo> GenesisInfo(TxNum tx_num) const;

    /** Whether there is any TokenMeta in the DB. */
    bool HasAnyTokens() const;

    /** Look up the DbTokenTx by [`TxNum`] and the TokenMetas referenced by it. */
    std::optional<
        std::pair<std::vector<std::optional<token::SpentToken>>, DbTokenTx>>
    SpentTokensAndDbTx(TxNum tx_num) const;

private:
    const ReadTxn &m_txn;
    TableId m_genesis_info, m_token_meta, m_token_tx;
};

} // namespace chronik::native::token_io

#endif // CHRONIK_NATIVE_TOKEN_IO_IO_H
