// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_INDEX_H
#define CHRONIK_NATIVE_TOKEN_INDEX_H

#include <chronik/native/extension.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/mem/mempool.h>
#include <chronik/native/store.h>
#include <chronik/native/subs.h>

#include <functional>
#include <memory>
#include <span>

/**
 * Seam between the indexer (core/indexer) and the SLP/ALP token index
 * (chronik-db io/token, groups/token_id.rs, mem/tokens.rs).
 *
 * The indexer calls a TokenIndex exactly where chronik-indexer indexer.rs
 * calls TokenWriter / TokenIdGroupAux / MempoolTokens, in the Rust order:
 *
 *  handle_block_connected (inside the block's write txn, after spent_by and
 *  the LOKAD ID history):
 *      aux = ConnectBlock(store, txn, index_txs)        // TokenWriter::insert
 *                                                       // + TokenIdGroupAux::from_batch
 *      GroupHistoryWriter(TokenIdGroup()).Insert(txn, index_txs, aux)
 *      GroupUtxoWriter(TokenIdGroup()).Insert(txn, index_txs, aux)
 *
 *  handle_block_disconnected (inside the write txn, after the LOKAD ID
 *  history; the txn already holds the deletes of blk/tx/stats/script/
 *  spent_by, but no token table was touched yet):
 *      aux = AuxFromDb(store, txn, index_txs)           // TokenIdGroupAux::from_db
 *      GroupHistoryWriter(TokenIdGroup()).Delete(txn, index_txs, aux)
 *      GroupUtxoWriter(TokenIdGroup()).Delete(txn, index_txs, aux)
 *      DisconnectBlock(store, txn, index_txs)           // TokenWriter::delete
 *
 *  handle_block_finalized / handle_transaction_finalized (tx in the DB):
 *      aux = AuxFromDb(store, read_txn, index_txs)
 *
 *  mempool: the Mempool owns the hook returned by MakeMempoolHook() and calls
 *  it itself (mem/mempool.h); tx finalized/invalidated in the mempool use
 *  hook->AuxFromMempool, invalidated txs not in the mempool use Probe.
 *
 *  subscriptions: every aux handed to the subscription hub is converted with
 *  SubsAux() (TokenIdGroupAux -> TokenIdSubsAux).
 *
 * The token tables are wiped by PrepareDb (metadata.h) when the index is
 * disabled, exactly like Rust's verify_enable_token_index.
 *
 * Threading: all calls come from the indexer's writer thread, except that
 * queries may use the TokenIndex (and the mempool hook through
 * IndexerSnapshot::Mempool()) concurrently while holding the indexer's
 * shared lock; implementations must keep their const methods free of
 * unsynchronized mutation.
 */
namespace chronik::native {

class TokenIndex {
public:
    virtual ~TokenIndex() = default;

    /** The TokenIdGroup (token_id_history / token_id_utxo tables). */
    virtual const GroupDef &TokenIdGroup() const = 0;

    /** The mempool part of the token index (Rust MempoolTokens). */
    virtual std::unique_ptr<mem::MempoolTokenHook> MakeMempoolHook() = 0;

    /**
     * TokenWriter::insert into `txn` followed by
     * TokenIdGroupAux::from_batch; returns the TokenIdGroupAux.
     */
    virtual std::shared_ptr<const GroupAux>
    ConnectBlock(const KvStore &store, WriteTxn &txn,
                 std::span<const index::IndexTx> txs) = 0;

    /** TokenIdGroupAux::from_db, reading through `txn`. */
    virtual std::shared_ptr<const GroupAux>
    AuxFromDb(const KvStore &store, const ReadTxn &txn,
              std::span<const index::IndexTx> txs) const = 0;

    /** TokenWriter::delete into `txn`. */
    virtual void DisconnectBlock(const KvStore &store, WriteTxn &txn,
                                 std::span<const index::IndexTx> txs) = 0;

    /**
     * The per-tx token IDs of `aux` for the subscription hub's TokenIdGroup
     * (aux may be nullptr: empty result).
     */
    virtual TokenIdSubsAux SubsAux(const GroupAux *aux) const = 0;
};

/** Creates the token index for an opened store. */
using TokenIndexFactory =
    std::function<std::unique_ptr<TokenIndex>(const KvStore &store)>;

/**
 * Process-wide default factory, used when IndexerParams::token_index_factory
 * is empty (the token library registers itself here, like the store
 * backends). Pass an empty function to unregister.
 */
void RegisterTokenIndexFactory(TokenIndexFactory factory);
/** The registered factory, or an empty function. */
TokenIndexFactory RegisteredTokenIndexFactory();

} // namespace chronik::native

#endif // CHRONIK_NATIVE_TOKEN_INDEX_H
