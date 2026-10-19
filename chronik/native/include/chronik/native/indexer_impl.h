// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEXER_IMPL_H
#define CHRONIK_NATIVE_INDEXER_IMPL_H

#include <chronik/native/avalanche.h>
#include <chronik/native/extension.h>
#include <chronik/native/groups/lokad_id.h>
#include <chronik/native/groups/script.h>
#include <chronik/native/host.h>
#include <chronik/native/index/blocks.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/indexer.h>
#include <chronik/native/mem/data.h>
#include <chronik/native/mem/mempool.h>
#include <chronik/native/merkle.h>
#include <chronik/native/store.h>
#include <chronik/native/subs.h>
#include <chronik/native/token_index.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

/**
 * Indexer internals and the READ API used by the query layer (port of the
 * `ChronikIndexer::{blocks, txs, script_history, ...}` accessors of
 * chronik-indexer indexer.rs).
 *
 * Consistency model (design C1 §3):
 *  - The writer (event thread) prepares each block's WriteTxn WITHOUT any
 *    lock, then takes the state lock EXCLUSIVELY only to commit and apply the
 *    matching mempool/avalanche/merkle changes, and publishes subscription
 *    messages after releasing it. It never calls Host while holding the
 *    exclusive lock.
 *  - A query takes an IndexerSnapshot: the state lock SHARED plus one store
 *    read txn opened under it. While the snapshot is locked, the DB, the
 *    mempool, Avalanche and the merkle cache are mutually consistent.
 *
 * Rules for queries (the "query" worker, chronik-indexer src/query):
 *  1. One snapshot per response:
 *         IndexerSnapshot snap = indexer.Impl().Snapshot();
 *     Build every index reader on snap.Store() / snap.Txn(), e.g.
 *         index::BlockReader blocks(snap.Store(), snap.Txn());
 *         index::GroupHistoryReader hist(snap.Store(), snap.Txn(),
 *                                        snap.Indexer().ScriptGroup());
 *     and read mempool data through snap.Mempool() (ScriptHistory(),
 *     ScriptUtxos(), SpentBy(), TokenIdHistory(), LokadIdHistory(), Tokens()
 *     ...), Avalanche through snap.GetAvalanche(), the block merkle cache
 *     through snap.WithMerkleTree(...).
 *  2. Copy what you need from the mempool, then call snap.Unlock() before any
 *     Host call that may block or take node locks (LoadTx, LoadRawTx,
 *     RawHeader(s), Broadcast, LookupSpentCoins, ...). Txn() stays valid
 *     after Unlock() (MDBX MVCC snapshot); Mempool()/GetAvalanche()/
 *     WithMerkleTree() throw afterwards. Unlocking is optional for plain
 *     immutable block-file reads, but REQUIRED before
 *     Host::SyncWithIndexer() / Host::Broadcast() (the writer needs the
 *     exclusive lock to process the resulting events).
 *  3. Never take a second snapshot (or any shared lock) while holding one on
 *     the same thread: std::shared_mutex is writer-preferring, so a nested
 *     shared lock deadlocks against a waiting writer.
 *  4. Destroy the snapshot (and every reader/cursor built on it) before the
 *     handler returns.
 *  5. Subscriptions (broadcast finalization waits, WebSocket): use
 *     SubsPtr()->Write(); the hub has its own lock, independent of the state
 *     lock. Never hold the hub guard while taking a snapshot.
 *  6. If the indexer failed (an event threw), Snapshot() throws a
 *     ChronikError without status prefix (HTTP 500 "Unknown error, contact
 *     admins").
 *
 * Group objects (ScriptGroup(), LokadIdGroup(), Tokens()->TokenIdGroup())
 * are immutable and live as long as the indexer; they may be used without
 * a snapshot.
 */
namespace chronik::native {

class IndexerImpl;

/** A consistent read view of the indexer: shared state lock + read txn. */
class IndexerSnapshot {
public:
    IndexerSnapshot(IndexerSnapshot &&) noexcept;
    IndexerSnapshot &operator=(IndexerSnapshot &&) = delete;
    IndexerSnapshot(const IndexerSnapshot &) = delete;
    IndexerSnapshot &operator=(const IndexerSnapshot &) = delete;
    ~IndexerSnapshot();

    const IndexerImpl &Indexer() const { return *m_impl; }
    const KvStore &Store() const;
    /** Read txn opened under the shared lock; valid until destruction. */
    const ReadTxn &Txn() const { return *m_txn; }

    /** Whether the shared state lock is still held. */
    bool IsLocked() const { return m_lock.owns_lock(); }
    /** Release the shared state lock early (keeps Txn()). */
    void Unlock();

    /** The indexer's mempool (locked snapshots only). */
    const mem::Mempool &Mempool() const;
    /** Avalanche state (locked snapshots only). */
    const Avalanche &GetAvalanche() const;
    /**
     * Run `f(MerkleTree &)` with the block merkle cache (Rust
     * `block_merkle_tree.lock()`), locked snapshots only.
     */
    template <typename F> auto WithMerkleTree(F &&f) const;

private:
    friend class IndexerImpl;
    IndexerSnapshot(const IndexerImpl &impl,
                    std::shared_lock<std::shared_mutex> lock);
    void RequireLocked() const;

    const IndexerImpl *m_impl;
    std::shared_lock<std::shared_mutex> m_lock;
    std::unique_ptr<ReadTxn> m_txn;
};

/** Effective configuration of an opened indexer. */
struct IndexerConfig {
    bool token_index = false;
    bool lokad_id_index = false;
    bool scripthash_index = false;
    bool perf_stats = false;
    std::filesystem::path db_path;
    std::filesystem::path perf_path;
};

class IndexerImpl {
public:
    IndexerImpl(const Host &host, IndexerParams params,
                std::vector<std::unique_ptr<Extension>> exts);
    ~IndexerImpl();
    IndexerImpl(const IndexerImpl &) = delete;
    IndexerImpl &operator=(const IndexerImpl &) = delete;

    // ---------------- read API (any thread) ----------------

    /** A consistent snapshot; throws if the indexer failed or is closed. */
    IndexerSnapshot Snapshot() const;

    const Host &GetHost() const { return m_host; }
    const KvStore &Store() const { return *m_store; }
    const IndexerConfig &Config() const { return m_config; }
    bool IsTokenIndexEnabled() const { return m_config.token_index; }
    bool IsLokadIdIndexEnabled() const { return m_config.lokad_id_index; }
    bool IsScripthashIndexEnabled() const {
        return m_config.scripthash_index;
    }

    const groups::ScriptGroup &ScriptGroup() const { return *m_script_group; }
    std::shared_ptr<const groups::ScriptGroup> ScriptGroupPtr() const {
        return m_script_group;
    }
    const groups::LokadIdGroup &LokadIdGroup() const {
        return m_lokad_id_group;
    }
    /** nullptr iff the token index is disabled. */
    const TokenIndex *Tokens() const { return m_tokens.get(); }
    const std::vector<std::unique_ptr<Extension>> &Extensions() const {
        return m_exts;
    }

    /** Subscription hub (Rust `indexer.subs()`). */
    SubsHub &Subs() const { return *m_subs; }
    std::shared_ptr<SubsHub> SubsPtr() const { return m_subs; }

    /** Whether an event failed (see Indexer). */
    bool Failed() const { return m_failed.load(); }
    /** Message of the failed event, if any. */
    std::string FailureMessage() const;

    /** Writer-thread stats (Rust MemData::stats). */
    mem::StatsData Stats() const { return m_mem_data.Stats(); }

    // ---------------- writer API (event thread only) ----------------

    void Resync();
    void OnTxAddedToMempool(TxRef tx, int64_t time_first_seen);
    void OnTxRemovedFromMempool(const TxId &txid);
    void OnBlockConnected(const Block &block);
    void OnBlockDisconnected(const Block &block);
    void OnBlockFinalized(const BlockInfo &info);
    void OnBlockInvalidated(const Block &block);
    void OnTxFinalized(const TxId &txid);
    void OnTxInvalidated(TxRef tx);
    void Close();

private:
    friend class IndexerSnapshot;
    struct Writers;

    template <typename F> void Guarded(F &&f);

    // Rust handle_* bodies (no failed-state handling)
    void ConnectBlock(const Block &block);
    void DisconnectBlock(const Block &block);
    void AddTxToMempool(TxRef tx, int64_t time_first_seen);
    void RemoveTxFromMempool(const TxId &txid);
    void FinalizeBlock(const Block &block);
    void InvalidateBlock(const Block &block);
    void FinalizeTx(const TxId &txid);
    void InvalidateTx(TxRef tx);

    index::BlockHeight RewindIndexer(const BlockInfo &indexer_tip_info,
                                     const index::DbBlock &indexer_db_tip);
    void ReindexLokadIdIndex(index::BlockHeight end_height);
    void ReindexScripthashIndex();
    void WritePerfStats();

    /** Rust make_chronik_block: the BlockTxs entries of `block`. */
    std::vector<index::TxEntry> MakeTxEntries(const Block &block) const;

    void PublishTxEvent(const Tx &tx, TxMsgType msg_type,
                        const GroupAux *token_aux);
    void PublishBlockTxEvents(const Block &block, TxMsgType msg_type,
                              const GroupAux *token_aux);

    void Log(LogLevel level, const std::string &msg) const;

    const Host &m_host;
    IndexerParams m_params;
    IndexerConfig m_config;
    std::vector<std::unique_ptr<Extension>> m_exts;
    std::vector<const GroupDef *> m_ext_groups;
    std::unique_ptr<KvStore> m_store;
    std::shared_ptr<const groups::ScriptGroup> m_script_group;
    groups::LokadIdGroup m_lokad_id_group;
    std::unique_ptr<TokenIndex> m_tokens;
    std::unique_ptr<Writers> m_writers;

    // ---- state guarded by m_state_mutex (writer mutates under X lock;
    //      the writer itself may read it without the lock) ----
    mutable std::shared_mutex m_state_mutex;
    std::unique_ptr<mem::Mempool> m_mempool;
    Avalanche m_avalanche;
    mutable std::mutex m_merkle_mutex;
    mutable MerkleTree m_merkle_tree;

    // ---- writer-thread only ----
    mem::MemData m_mem_data;
    bool m_needs_lokad_id_reindex = false;
    bool m_needs_scripthash_reindex = false;

    std::shared_ptr<SubsHub> m_subs;
    std::atomic<bool> m_failed{false};
    std::atomic<bool> m_closed{false};
    mutable std::mutex m_failure_mutex;
    std::string m_failure_msg;
};

template <typename F> auto IndexerSnapshot::WithMerkleTree(F &&f) const {
    RequireLocked();
    std::lock_guard lock(m_impl->m_merkle_mutex);
    return f(m_impl->m_merkle_tree);
}

} // namespace chronik::native

#endif // CHRONIK_NATIVE_INDEXER_IMPL_H
