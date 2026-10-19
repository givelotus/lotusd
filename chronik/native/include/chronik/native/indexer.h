// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEXER_H
#define CHRONIK_NATIVE_INDEXER_H

#include <chronik/native/codec/script_compress.h>
#include <chronik/native/host.h>
#include <chronik/native/store.h>
#include <chronik/native/token_index.h>
#include <chronik/native/types.h>

#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace chronik::native {

/** Port of ChronikIndexerParams (chronik-indexer/src/indexer.rs). */
struct IndexerParams {
    /**
     * Index at <datadir_net>/indexes/chronik (MDBX, same as Rust) or
     * indexes/chronik-leveldb (LevelDB), see StoreIndexDirName.
     */
    std::filesystem::path datadir_net;
    /** -chronikreindex / -reindex */
    bool wipe = false;
    bool token_index = true;
    bool lokad_id_index = true;
    bool scripthash_index = false;
    bool perf_stats = false;
    size_t tx_num_cache_buckets = 10;
    size_t tx_num_cache_bucket_size = 100'000;
    StoreBackend backend = StoreBackend::Mdbx;
    /**
     * Token index implementation; empty => RegisteredTokenIndexFactory().
     * The token index is enabled iff token_index &&
     * HostCapabilities::slp_alp_tokens. Opening fails if it is enabled but
     * no implementation is available (instead of silently wiping an
     * existing token index).
     */
    TokenIndexFactory token_index_factory;
    /**
     * EC point decompression for uncompressed P2PK scripts (only used by
     * the scripthash reindex, Rust decompress_script). Optional.
     */
    DecompressPubKeyFn decompress_pubkey;
    /** Immutable observer after successful writer commit. Called under the
     * existing writer lock: must be atomic-only/noexcept and acquire no locks. */
    std::function<void(int32_t)> observe_indexed_height;
};

class Extension;
class IndexerImpl;

/**
 * The native Chronik indexer (port of chronik-indexer indexer.rs). Event
 * methods must be called from one thread at a time, in validation-signal
 * order (the host adapter owns threading). A failing event throws (the
 * caller reports it with OkOrAbort -> Host::FatalError, like Rust's
 * ok_or_abort) and puts the indexer in a failed state: later events are
 * ignored and every query (IndexerSnapshot) fails with 500.
 *
 * The read API for queries is IndexerImpl / IndexerSnapshot
 * (chronik/native/indexer_impl.h).
 */
class Indexer {
public:
    /** Opens/creates the store and verifies the schema (no resync yet). */
    static std::unique_ptr<Indexer>
    Open(const Host &host, IndexerParams params,
         std::vector<std::unique_ptr<Extension>> exts = {});
    ~Indexer();

    /** Catch up with the node's active chain (port of resync_indexer). */
    void Resync();

    // ---- events (writer thread only) ----
    /** tx inputs carry spent coins */
    void OnTxAddedToMempool(TxRef tx, int64_t time_first_seen);
    void OnTxRemovedFromMempool(const TxId &txid);
    /** Pre-loaded block (spent coins from undo, offsets set) */
    void OnBlockConnected(Block block);
    void OnBlockDisconnected(Block block);
    void OnBlockFinalized(const BlockInfo &info);
    void OnBlockInvalidated(Block block);
    void OnTxFinalized(const TxId &txid);
    void OnTxInvalidated(TxRef tx);

    /** Flush and sync the store. */
    void Close();

    IndexerImpl &Impl() { return *m_impl; }
    const IndexerImpl &Impl() const { return *m_impl; }

private:
    explicit Indexer(std::unique_ptr<IndexerImpl> impl);
    std::unique_ptr<IndexerImpl> m_impl;
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_INDEXER_H
