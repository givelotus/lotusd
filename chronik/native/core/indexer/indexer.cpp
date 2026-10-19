// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer/src/indexer.rs (eCash tier, without plugins):
// ChronikIndexer setup, resync, and the handle_* event methods.

#include <chronik/native/indexer.h>
#include <chronik/native/indexer_impl.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/codec/script_compress.h>
#include <chronik/native/error.h>
#include <chronik/native/index/block_stats.h>
#include <chronik/native/index/blocks.h>
#include <chronik/native/index/group_history.h>
#include <chronik/native/index/group_utxos.h>
#include <chronik/native/index/merge.h>
#include <chronik/native/index/spent_by.h>
#include <chronik/native/index/txs.h>
#include <chronik/native/metadata.h>
#include <chronik/native/schema.h>
#include <chronik/native/version.h>

#include <core/indexer/indexer_errors.h>

#include <cstdio>
#include <fstream>
#include <limits>
#include <mutex>
#include <sstream>

namespace chronik::native {

// ---------------------------------------------------------------------------
// Token index factory registry
// ---------------------------------------------------------------------------

namespace {
std::mutex g_token_factory_mutex;
TokenIndexFactory g_token_factory;
} // namespace

void RegisterTokenIndexFactory(TokenIndexFactory factory) {
    std::lock_guard lock(g_token_factory_mutex);
    g_token_factory = std::move(factory);
}

TokenIndexFactory RegisteredTokenIndexFactory() {
    std::lock_guard lock(g_token_factory_mutex);
    return g_token_factory;
}

// ---------------------------------------------------------------------------
// Error texts (ChronikIndexerError)
// ---------------------------------------------------------------------------

namespace indexer_errors {

std::string CreateDirFailed(const std::filesystem::path &path) {
    return "Failed creating path " + path.string();
}
std::string CannotRewindChronik(const BlockHash &hash) {
    return "Cannot rewind Chronik, it contains block " + HashToHex(hash) +
           " that the node doesn't have. You may need to use "
           "-reindex/-chronikreindex, or delete indexes/chronik and restart";
}
std::string BlocksBelowMissing(int32_t missing, int32_t exists) {
    return "Inconsistent DB: Block " + std::to_string(missing) +
           " doesn't exist, but " + std::to_string(exists) + " does";
}
std::string TxNotFound(uint64_t tx_num) {
    return "Inconsistent DB: Tx with tx_num " + std::to_string(tx_num) +
           " doesn't exist";
}
std::string TxIdNotFound(const TxId &txid) {
    return "Inconsistent DB: Tx with id " + HashToHex(txid) +
           " doesn't exist";
}
std::string BlockNotFound(int32_t height) {
    return "Inconsistent DB: Block with height " + std::to_string(height) +
           " doesn't exist";
}
std::string DbTxHasNoBlock(const TxId &txid) {
    return "Inconsistent DB: Tx with id " + HashToHex(txid) + " has no block";
}
std::string TokenIndexUnavailable() {
    return "The token index (-chroniktokenindex) is enabled, but this native "
           "Chronik build has no token index implementation; use "
           "-chroniktokenindex=0";
}

} // namespace indexer_errors

namespace {

using namespace index;

Sha256Fn HostSha256(const Host &host) {
    return [&host](ByteView data, uint8_t out[32]) { host.Sha256(data, out); };
}

DbBlock MakeDbBlock(const BlockInfo &info) {
    DbBlock db_block;
    db_block.hash = info.hash;
    db_block.prev_hash = info.prev_hash;
    db_block.height = info.height;
    db_block.n_bits = info.n_bits;
    db_block.timestamp = info.timestamp;
    db_block.file_num = info.file_num;
    db_block.data_pos = info.data_pos;
    return db_block;
}

std::vector<const Tx *> BlockTxPtrs(const Block &block) {
    std::vector<const Tx *> ptrs;
    ptrs.reserve(block.txs.size());
    for (const native::BlockTx &tx : block.txs) {
        ptrs.push_back(tx.tx.get());
    }
    return ptrs;
}

/** Rust `{:.3?}` of an f64 */
std::string FmtF64(double v) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.3f", v);
    return buf;
}

/** Rust `{:#.3?}` of mem::StatsData */
std::string FormatStatsPretty(const mem::StatsData &s) {
    std::ostringstream o;
    o << "StatsData {\n";
    o << "    txs: TxsStats {\n";
    o << "        n_total: " << s.txs.n_total << ",\n";
    o << "        t_total: " << FmtF64(s.txs.t_total) << ",\n";
    o << "        t_index: " << FmtF64(s.txs.t_index) << ",\n";
    o << "    },\n";
    o << "    script_history: GroupHistoryStats {\n";
    o << "        n_total: " << s.script_history.n_total << ",\n";
    o << "        t_total: " << FmtF64(s.script_history.t_total) << ",\n";
    o << "        t_group: " << FmtF64(s.script_history.t_group) << ",\n";
    o << "        t_ser_members: " << FmtF64(s.script_history.t_ser_members)
      << ",\n";
    o << "        t_fetch: " << FmtF64(s.script_history.t_fetch) << ",\n";
    o << "    },\n";
    o << "    script_utxos: GroupUtxoStats {\n";
    o << "        n_total: " << s.script_utxos.n_total << ",\n";
    o << "        t_total: " << FmtF64(s.script_utxos.t_total) << ",\n";
    o << "    },\n";
    o << "    spent_by: SpentByStats {\n";
    o << "        n_total: " << s.spent_by.n_total << ",\n";
    o << "        t_total: " << FmtF64(s.spent_by.t_total) << ",\n";
    o << "        t_fetch: " << FmtF64(s.spent_by.t_fetch) << ",\n";
    o << "    },\n";
    o << "}";
    return o.str();
}

/** Rust prepare_db_folder: create_dir (not recursive) unless it exists. */
void CreateDirIfMissing(const std::filesystem::path &path) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        return;
    }
    if (!std::filesystem::create_directory(path, ec) || ec) {
        throw ChronikError(indexer_errors::CreateDirFailed(path));
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Writers (Rust: created per handle_* call; they only hold table ids here)
// ---------------------------------------------------------------------------

struct IndexerImpl::Writers {
    BlockWriter block;
    TxWriter tx;
    BlockStatsWriter block_stats;
    GroupHistoryWriter script_history;
    GroupUtxoWriter script_utxos;
    SpentByWriter spent_by;
    GroupHistoryWriter lokad_id_history;
    std::optional<GroupHistoryWriter> token_id_history;
    std::optional<GroupUtxoWriter> token_id_utxos;
    struct ExtGroup {
        const GroupDef *group;
        std::optional<GroupHistoryWriter> history;
        std::optional<GroupUtxoWriter> utxos;
    };
    std::vector<ExtGroup> ext_groups;

    Writers(const KvStore &store, const groups::ScriptGroup &script_group,
            const groups::LokadIdGroup &lokad_id_group, const TokenIndex *tokens,
            const std::vector<const GroupDef *> &ext_groups_in)
        : block(store), tx(store), block_stats(store),
          script_history(store, script_group),
          script_utxos(store, script_group), spent_by(store),
          lokad_id_history(store, lokad_id_group) {
        if (tokens) {
            token_id_history.emplace(store, tokens->TokenIdGroup());
            token_id_utxos.emplace(store, tokens->TokenIdGroup());
        }
        for (const GroupDef *group : ext_groups_in) {
            ExtGroup ext{group, std::nullopt, std::nullopt};
            if (group->TxHistoryConf()) {
                ext.history.emplace(store, *group);
            }
            if (group->UtxoConf()) {
                ext.utxos.emplace(store, *group);
            }
            ext_groups.push_back(std::move(ext));
        }
    }
};

// ---------------------------------------------------------------------------
// IndexerSnapshot
// ---------------------------------------------------------------------------

IndexerSnapshot::IndexerSnapshot(const IndexerImpl &impl,
                                 std::shared_lock<std::shared_mutex> lock)
    : m_impl(&impl), m_lock(std::move(lock)),
      m_txn(impl.m_store->BeginRead()) {}

IndexerSnapshot::IndexerSnapshot(IndexerSnapshot &&other) noexcept
    : m_impl(other.m_impl), m_lock(std::move(other.m_lock)),
      m_txn(std::move(other.m_txn)) {}

IndexerSnapshot::~IndexerSnapshot() {
    // Read txn first (it may outlive the lock, never the store)
    m_txn.reset();
}

const KvStore &IndexerSnapshot::Store() const { return *m_impl->m_store; }

void IndexerSnapshot::Unlock() {
    if (m_lock.owns_lock()) {
        m_lock.unlock();
    }
}

void IndexerSnapshot::RequireLocked() const {
    if (!m_lock.owns_lock()) {
        throw ChronikError(
            "IndexerSnapshot: mempool/avalanche/merkle accessed after Unlock");
    }
}

const mem::Mempool &IndexerSnapshot::Mempool() const {
    RequireLocked();
    return *m_impl->m_mempool;
}

const Avalanche &IndexerSnapshot::GetAvalanche() const {
    RequireLocked();
    return m_impl->m_avalanche;
}

// ---------------------------------------------------------------------------
// Setup (ChronikIndexer::setup, prepare_db_folder, prepare_db)
// ---------------------------------------------------------------------------

IndexerImpl::IndexerImpl(const Host &host, IndexerParams params,
                         std::vector<std::unique_ptr<Extension>> exts)
    : m_host(host), m_params(std::move(params)), m_exts(std::move(exts)),
      m_merkle_tree(Sha256dFromSha256(HostSha256(host))),
      m_mem_data(mem::MemDataConf{
          index::TxNumCacheSettings{m_params.tx_num_cache_buckets,
                                    m_params.tx_num_cache_bucket_size},
          index::GroupHistorySettings{m_params.scripthash_index}}) {
    const HostCapabilities &caps = m_host.Capabilities();
    m_config.token_index = m_params.token_index && caps.slp_alp_tokens;
    m_config.lokad_id_index = m_params.lokad_id_index;
    m_config.scripthash_index = m_params.scripthash_index;
    m_config.perf_stats = m_params.perf_stats;

    merge::SetErrorLogger([&host](const std::string &msg) {
        host.Log(LogLevel::Info, msg);
    });

    // ---- prepare_db_folder ----
    const std::filesystem::path indexes_path =
        m_params.datadir_net / "indexes";
    const std::filesystem::path perf_path = m_params.datadir_net / "perf";
    CreateDirIfMissing(indexes_path);
    if (m_params.perf_stats) {
        CreateDirIfMissing(perf_path);
    }
    const std::filesystem::path db_path = indexes_path / "chronik";
    m_config.db_path = db_path;
    m_config.perf_path = perf_path;
    if (m_params.wipe) {
        Log(LogLevel::Info, "Wiping Chronik at " + db_path.string() + "\n");
        DestroyStore(m_params.backend, db_path);
    }

    // ---- token index implementation (fail closed, see IndexerParams) ----
    TokenIndexFactory token_factory = m_params.token_index_factory
                                          ? m_params.token_index_factory
                                          : RegisteredTokenIndexFactory();
    if (m_config.token_index && !token_factory) {
        throw ChronikError(indexer_errors::TokenIndexUnavailable());
    }

    // ---- prepare_db ----
    Log(LogLevel::Debug, "Opening Chronik at " + db_path.string() + "\n");
    for (const auto &ext : m_exts) {
        for (const GroupDef *group : ext->Groups()) {
            m_ext_groups.push_back(group);
        }
    }
    schema::Schema schema;
    for (const GroupDef *group : m_ext_groups) {
        for (const TableSpec &spec : GroupTableSpecs(*group)) {
            schema.Add(spec);
        }
    }
    RefuseLegacyRocksDb(db_path);
    StoreOptions store_opts;
    store_opts.sha256 = HostSha256(m_host);
    m_store = OpenStore(m_params.backend, db_path, schema.Tables(), store_opts);

    PrepareDbParams prepare;
    prepare.enable_token_index = m_config.token_index;
    prepare.enable_lokad_id_index = m_config.lokad_id_index;
    prepare.enable_scripthash_index = m_config.scripthash_index;
    prepare.native_last_writer =
        std::string(ImplementationName()) + "/" + m_host.FormatFullVersion();
    const PreparedDb prepared =
        PrepareDb(*m_store, prepare, [this](const std::string &msg) {
            Log(LogLevel::Info, msg);
        });
    m_needs_lokad_id_reindex = prepared.needs_lokad_id_reindex;
    m_needs_scripthash_reindex = prepared.needs_scripthash_reindex;

    // ---- groups, mempool, subs ----
    m_script_group =
        std::make_shared<const groups::ScriptGroup>(HostSha256(m_host));
    if (m_config.token_index) {
        m_tokens = token_factory(*m_store);
        if (!m_tokens) {
            throw ChronikError(indexer_errors::TokenIndexUnavailable());
        }
    }
    m_mempool = std::make_unique<mem::Mempool>(
        m_script_group, m_config.token_index, m_config.lokad_id_index,
        m_tokens ? m_tokens->MakeMempoolHook() : nullptr);
    m_writers = std::make_unique<Writers>(*m_store, *m_script_group,
                                          m_lokad_id_group, m_tokens.get(),
                                          m_ext_groups);
    m_subs = std::make_shared<SubsHub>(HostSha256(m_host));

    for (const auto &ext : m_exts) {
        ext->Open(indexes_path, m_params.wipe);
    }
}

IndexerImpl::~IndexerImpl() {
    // Drop users of the store before the store
    m_writers.reset();
    m_mempool.reset();
    m_tokens.reset();
    m_store.reset();
}

void IndexerImpl::Log(LogLevel level, const std::string &msg) const {
    m_host.Log(level, msg);
}

std::string IndexerImpl::FailureMessage() const {
    std::lock_guard lock(m_failure_mutex);
    return m_failure_msg;
}

IndexerSnapshot IndexerImpl::Snapshot() const {
    if (m_failed.load()) {
        throw ChronikError("Chronik indexer failed: " + FailureMessage());
    }
    if (m_closed.load()) {
        throw ChronikError("Chronik indexer is closed");
    }
    std::shared_lock lock(m_state_mutex);
    return IndexerSnapshot(*this, std::move(lock));
}

template <typename F> void IndexerImpl::Guarded(F &&f) {
    if (m_failed.load()) {
        // A previous event failed; the node is shutting down (FatalError).
        return;
    }
    try {
        f();
    } catch (const std::exception &e) {
        {
            std::lock_guard lock(m_failure_mutex);
            m_failure_msg = e.what();
        }
        m_failed.store(true);
        throw;
    }
}

// ---------------------------------------------------------------------------
// Resync (resync_indexer, rewind_indexer, reindex_*)
// ---------------------------------------------------------------------------

void IndexerImpl::Resync() {
    std::optional<DbBlock> indexer_tip;
    {
        auto txn = m_store->BeginRead();
        indexer_tip = BlockReader(*m_store, *txn).Tip();
    }
    const std::optional<BlockInfo> node_tip_info = m_host.ActiveTip();
    if (!node_tip_info) {
        if (indexer_tip) {
            throw ChronikError(
                indexer_errors::CannotRewindChronik(indexer_tip->hash));
        }
        return;
    }
    const int32_t node_height = node_tip_info->height;
    const std::string node_tip_hash = HashToHex(node_tip_info->hash);
    BlockHeight start_height;
    if (indexer_tip && indexer_tip->hash != node_tip_info->hash) {
        Log(LogLevel::Info,
            "Node and Chronik diverged, node is on block " + node_tip_hash +
                " at height " + std::to_string(node_height) +
                ", and Chronik is on block " + HashToHex(indexer_tip->hash) +
                " at height " + std::to_string(indexer_tip->height) + ".\n");
        const std::optional<BlockInfo> indexer_tip_info =
            m_host.LookupBlock(indexer_tip->hash);
        if (!indexer_tip_info) {
            throw ChronikError(
                indexer_errors::CannotRewindChronik(indexer_tip->hash));
        }
        start_height = RewindIndexer(*indexer_tip_info, *indexer_tip);
    } else if (indexer_tip) {
        start_height = indexer_tip->height;
    } else {
        Log(LogLevel::Info, "Chronik database empty, syncing to block " +
                                node_tip_hash + " at height " +
                                std::to_string(node_height) + ".\n");
        start_height = -1;
    }
    if (m_needs_lokad_id_reindex) {
        ReindexLokadIdIndex(start_height);
        m_needs_lokad_id_reindex = false;
    }
    if (m_needs_scripthash_reindex) {
        ReindexScripthashIndex();
        m_needs_scripthash_reindex = false;
    }
    const int32_t tip_height = node_tip_info->height;
    // `start_height + 1` wraps like Rust (release) when rewinding was
    // interrupted (start_height == BlockHeight::MAX).
    const int32_t first_height =
        int32_t(uint32_t(start_height) + uint32_t(1));
    for (int64_t height = first_height; height <= tip_height; ++height) {
        if (m_host.ShutdownRequested()) {
            Log(LogLevel::Info, "Stopped re-sync adding blocks\n");
            return;
        }
        const std::optional<BlockInfo> info =
            m_host.ActiveAtHeight(int32_t(height));
        if (!info) {
            throw ChronikError("Block at height " + std::to_string(height) +
                               " not found in the node's active chain");
        }
        const Block block = m_host.LoadBlock(*info);
        const std::string hash = HashToHex(block.info.hash);
        ConnectBlock(block);
        Log(LogLevel::Debug, "Added block " + hash + ", height " +
                                 std::to_string(height) + "/" +
                                 std::to_string(tip_height) + " to Chronik\n");
        if (height % 100 == 0) {
            Log(LogLevel::InfoNoRateLimit,
                "Synced Chronik up to block " + hash + " at height " +
                    std::to_string(height) + "/" + std::to_string(tip_height) +
                    "\n");
        }
    }
    Log(LogLevel::Info,
        "Chronik completed re-syncing with the node, both are now at block " +
            node_tip_hash + " at height " + std::to_string(node_height) +
            ".\n");
    if (m_config.perf_stats) {
        WritePerfStats();
    }
    for (const auto &ext : m_exts) {
        ext->Resync();
    }
}

void IndexerImpl::WritePerfStats() {
    const std::filesystem::path path = m_config.perf_path / "resync_stats.txt";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw ChronikError("Failed creating " + path.string());
    }
    out << FormatStatsPretty(m_mem_data.Stats());
    if (!out) {
        throw ChronikError("Failed writing " + path.string());
    }
}

BlockHeight IndexerImpl::RewindIndexer(const BlockInfo &indexer_tip_info,
                                       const DbBlock &indexer_db_tip) {
    const BlockHeight indexer_height = indexer_db_tip.height;
    const std::optional<BlockInfo> fork_info =
        m_host.FindFork(indexer_tip_info.hash);
    if (!fork_info) {
        throw ChronikError(
            indexer_errors::CannotRewindChronik(indexer_db_tip.hash));
    }
    const int32_t fork_height = fork_info->height;
    const int32_t revert_height = fork_height + 1;
    Log(LogLevel::Info, "The last common block is " +
                            HashToHex(fork_info->hash) + " at height " +
                            std::to_string(fork_height) + ".\n");
    Log(LogLevel::Info, "Reverting Chronik blocks " +
                            std::to_string(revert_height) + " to " +
                            std::to_string(indexer_height) + ".\n");
    for (int32_t height = indexer_height; height >= revert_height; --height) {
        if (m_host.ShutdownRequested()) {
            Log(LogLevel::Info, "Stopped re-sync rewinding blocks\n");
            // return MAX here so we don't add any blocks
            return std::numeric_limits<BlockHeight>::max();
        }
        std::optional<DbBlock> db_block;
        {
            auto txn = m_store->BeginRead();
            db_block = BlockReader(*m_store, *txn).ByHeight(height);
        }
        if (!db_block) {
            throw ChronikError(
                indexer_errors::BlocksBelowMissing(height, indexer_height));
        }
        const std::optional<BlockInfo> info =
            m_host.LookupBlock(db_block->hash);
        if (!info) {
            throw ChronikError(
                indexer_errors::CannotRewindChronik(db_block->hash));
        }
        const Block block = m_host.LoadBlock(*info);
        DisconnectBlock(block);
    }
    return fork_info->height;
}

void IndexerImpl::ReindexLokadIdIndex(BlockHeight end_height) {
    // First, wipe the LOKAD ID index
    {
        auto txn = m_store->BeginWrite();
        m_writers->lokad_id_history.Wipe(*txn);
        txn->Commit();
    }
    for (int64_t height = 0; height <= end_height; ++height) {
        if (m_host.ShutdownRequested()) {
            Log(LogLevel::Info, "Stopped reindexing LOKAD ID index\n");
            return;
        }
        const std::optional<BlockInfo> info =
            m_host.ActiveAtHeight(int32_t(height));
        if (!info) {
            throw ChronikError("Block at height " + std::to_string(height) +
                               " not found in the node's active chain");
        }
        const Block block = m_host.LoadBlock(*info);
        auto txn = m_store->BeginWrite();
        const std::optional<TxNum> first_tx_num =
            TxReader(*m_store, *txn).FirstTxNumByBlock(block.info.height);
        if (!first_tx_num) {
            throw ChronikError(
                indexer_errors::BlockNotFound(block.info.height));
        }
        const std::vector<const Tx *> ptrs = BlockTxPtrs(block);
        const std::vector<IndexTx> index_txs = PrepareIndexedTxsCached(
            *m_store, *txn, *first_tx_num, ptrs, m_mem_data.tx_num_cache,
            PrepareUpdateMode::Add);
        GroupHistoryMemData lokad_mem_data;
        m_writers->lokad_id_history.Insert(*txn, index_txs, nullptr,
                                           lokad_mem_data);
        txn->Commit();
        if (height % 100 == 0) {
            Log(LogLevel::InfoNoRateLimit,
                "Synced Chronik LOKAD ID index up to block " +
                    HashToHex(block.info.hash) + " at height " +
                    std::to_string(height) + "/" + std::to_string(end_height) +
                    " (-chroniklokadidindex=0 to disable)\n");
        }
    }
    auto txn = m_store->BeginWrite();
    MetadataWriter(*txn, m_store->Table(schema::kMeta))
        .UpdateIsLokadIdIndexEnabled(true);
    txn->Commit();
}

void IndexerImpl::ReindexScripthashIndex() {
    // First, wipe the scripthash index
    {
        auto txn = m_store->BeginWrite();
        m_writers->script_history.WipeMemberHash(*txn);
        txn->Commit();
    }
    const DecompressPubKeyFn decompress_pubkey = m_params.decompress_pubkey;
    m_writers->script_history.ReindexMemberHash(
        *m_store,
        [&decompress_pubkey](ByteView compressed) -> Bytes {
            std::optional<Bytes> script =
                DecompressScript(compressed, decompress_pubkey);
            if (!script) {
                throw ChronikError("Failed decompressing script " +
                                   HexEncode(compressed));
            }
            return std::move(*script);
        },
        [this] { return m_host.ShutdownRequested(); },
        [this](const std::string &msg, bool no_rate_limit) {
            Log(no_rate_limit ? LogLevel::InfoNoRateLimit : LogLevel::Info,
                msg);
        });
    // If the user requested a shutdown, it is very unlikely that the
    // reindexing completed successfully. We don't set the flag to true, to
    // trigger a full scripthash reindex on next restart if
    // -chronikscripthashindex=1 is still set. We also wipe the db now to be
    // sure to not keep a useless partial index on disk in case
    // -chronikscripthashindex=0 is set on next restart.
    auto txn = m_store->BeginWrite();
    if (m_host.ShutdownRequested()) {
        m_writers->script_history.WipeMemberHash(*txn);
        txn->Commit();
        return;
    }
    MetadataWriter(*txn, m_store->Table(schema::kMeta))
        .UpdateIsScripthashIndexEnabled(true);
    txn->Commit();
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

std::vector<TxEntry> IndexerImpl::MakeTxEntries(const Block &block) const {
    // Writer thread: the mempool is only mutated by this thread, so reading
    // it without the state lock is safe.
    std::vector<TxEntry> entries;
    entries.reserve(block.txs.size());
    for (const native::BlockTx &block_tx : block.txs) {
        TxEntry entry;
        entry.txid = block_tx.tx->txid;
        entry.data_pos = block_tx.data_pos;
        entry.undo_pos = block_tx.undo_pos;
        const mem::MempoolTx *mempool_tx = m_mempool->GetTx(entry.txid);
        entry.time_first_seen = mempool_tx ? mempool_tx->time_first_seen : 0;
        entry.is_coinbase = block_tx.undo_pos == 0;
        entries.push_back(entry);
    }
    return entries;
}

void IndexerImpl::PublishTxEvent(const Tx &tx, TxMsgType msg_type,
                                 const GroupAux *token_aux) {
    TokenIdSubsAux token_subs_aux;
    SubsAux aux;
    if (m_tokens) {
        token_subs_aux = m_tokens->SubsAux(token_aux);
        aux.token_id = &token_subs_aux;
    }
    auto subs = m_subs->Write();
    subs->HandleTxEvent(tx, msg_type, aux);
}

void IndexerImpl::PublishBlockTxEvents(const Block &block, TxMsgType msg_type,
                                       const GroupAux *token_aux) {
    TokenIdSubsAux token_subs_aux;
    SubsAux aux;
    if (m_tokens) {
        token_subs_aux = m_tokens->SubsAux(token_aux);
        aux.token_id = &token_subs_aux;
    }
    std::vector<TxRef> txs;
    txs.reserve(block.txs.size());
    for (const native::BlockTx &tx : block.txs) {
        txs.push_back(tx.tx);
    }
    auto subs = m_subs->Write();
    subs->HandleBlockTxEvents(txs, msg_type, aux);
}

void IndexerImpl::AddTxToMempool(TxRef tx, int64_t time_first_seen) {
    mem::MempoolResult result;
    {
        std::unique_lock lock(m_state_mutex);
        result =
            m_mempool->Insert(*m_store, mem::MempoolTx{tx, time_first_seen});
    }
    PublishTxEvent(*result.mempool_tx.tx, TxMsgType::AddedToMempool(),
                   result.token_id_aux.get());
}

void IndexerImpl::RemoveTxFromMempool(const TxId &txid) {
    mem::MempoolResult result;
    {
        std::unique_lock lock(m_state_mutex);
        result = m_mempool->Remove(txid);
    }
    PublishTxEvent(*result.mempool_tx.tx, TxMsgType::RemovedFromMempool(),
                   result.token_id_aux.get());
}

void IndexerImpl::ConnectBlock(const Block &block) {
    const BlockHeight height = block.info.height;
    const DbBlock db_block = MakeDbBlock(block.info);
    BlockTxs block_txs{MakeTxEntries(block), height};
    const std::vector<const Tx *> ptrs = BlockTxPtrs(block);
    Writers &w = *m_writers;

    // Build the block's write txn without holding the state lock: concurrent
    // readers keep seeing the previous committed state.
    std::unique_ptr<WriteTxn> txn = m_store->BeginWrite();
    w.block.Insert(*txn, db_block);
    const TxNum first_tx_num = w.tx.Insert(*txn, block_txs, m_mem_data.txs);
    const std::vector<IndexTx> index_txs = PrepareIndexedTxsCached(
        *m_store, *txn, first_tx_num, ptrs, m_mem_data.tx_num_cache,
        PrepareUpdateMode::Add);
    w.block_stats.Insert(*txn, height, block.info.size, index_txs);
    w.script_history.Insert(*txn, index_txs, nullptr,
                            m_mem_data.script_history);
    w.script_utxos.Insert(*txn, index_txs, nullptr, m_mem_data.script_utxos);
    w.spent_by.Insert(*txn, index_txs, m_mem_data.spent_by);
    if (m_config.lokad_id_index) {
        GroupHistoryMemData lokad_mem_data;
        w.lokad_id_history.Insert(*txn, index_txs, nullptr, lokad_mem_data);
    }
    std::shared_ptr<const GroupAux> token_id_aux;
    if (m_tokens) {
        token_id_aux = m_tokens->ConnectBlock(*m_store, *txn, index_txs);
        GroupHistoryMemData history_mem_data;
        w.token_id_history->Insert(*txn, index_txs, token_id_aux.get(),
                                   history_mem_data);
        GroupUtxoMemData utxo_mem_data;
        w.token_id_utxos->Insert(*txn, index_txs, token_id_aux.get(),
                                 utxo_mem_data);
    }
    for (Writers::ExtGroup &ext : w.ext_groups) {
        if (ext.history) {
            GroupHistoryMemData mem_data;
            ext.history->Insert(*txn, index_txs, nullptr, mem_data);
        }
        if (ext.utxos) {
            GroupUtxoMemData mem_data;
            ext.utxos->Insert(*txn, index_txs, nullptr, mem_data);
        }
    }
    for (const auto &ext : m_exts) {
        if (ext->TxnMode() == Extension::Txn::SameEnv) {
            ext->Connect(block, txn.get());
        }
    }

    {
        // Publish: the DB txn and the mempool removals become visible to
        // snapshots atomically.
        std::unique_lock lock(m_state_mutex);
        txn->Commit();
        txn.reset();
        for (const TxEntry &tx : block_txs.txs) {
            m_mempool->RemoveMined(tx.txid);
        }
    }
    merge::CheckForErrors();
    for (const auto &ext : m_exts) {
        if (ext->TxnMode() == Extension::Txn::OwnEnv) {
            ext->Connect(block, nullptr);
        }
    }
    {
        BlockMsg msg;
        msg.msg_type = BlockMsgType::Connected;
        msg.hash = block.info.hash;
        msg.height = height;
        msg.timestamp = block.info.timestamp;
        auto subs = m_subs->Write();
        subs->BroadcastBlockMsg(msg);
    }
    PublishBlockTxEvents(block, TxMsgType::Confirmed(), token_id_aux.get());
}

void IndexerImpl::DisconnectBlock(const Block &block) {
    const BlockHeight height = block.info.height;
    const DbBlock db_block = MakeDbBlock(block.info);
    BlockTxs block_txs{MakeTxEntries(block), height};
    const std::vector<const Tx *> ptrs = BlockTxPtrs(block);
    Writers &w = *m_writers;

    std::unique_ptr<WriteTxn> txn = m_store->BeginWrite();
    w.block.Delete(*txn, db_block);
    const TxNum first_tx_num = w.tx.Delete(*txn, block_txs, m_mem_data.txs);
    const std::vector<IndexTx> index_txs = PrepareIndexedTxsCached(
        *m_store, *txn, first_tx_num, ptrs, m_mem_data.tx_num_cache,
        PrepareUpdateMode::Delete);
    w.block_stats.Delete(*txn, height);
    w.script_history.Delete(*txn, index_txs, nullptr,
                            m_mem_data.script_history);
    w.script_utxos.Delete(*txn, index_txs, nullptr, m_mem_data.script_utxos);
    w.spent_by.Delete(*txn, index_txs, m_mem_data.spent_by);
    if (m_config.lokad_id_index) {
        // Skip delete if rewinding indexer; will be wiped later anyway
        if (!m_needs_lokad_id_reindex) {
            GroupHistoryMemData lokad_mem_data;
            w.lokad_id_history.Delete(*txn, index_txs, nullptr,
                                      lokad_mem_data);
        }
    }
    if (m_tokens) {
        const std::shared_ptr<const GroupAux> token_id_aux =
            m_tokens->AuxFromDb(*m_store, *txn, index_txs);
        GroupHistoryMemData history_mem_data;
        w.token_id_history->Delete(*txn, index_txs, token_id_aux.get(),
                                   history_mem_data);
        GroupUtxoMemData utxo_mem_data;
        w.token_id_utxos->Delete(*txn, index_txs, token_id_aux.get(),
                                 utxo_mem_data);
        m_tokens->DisconnectBlock(*m_store, *txn, index_txs);
    }
    for (Writers::ExtGroup &ext : w.ext_groups) {
        if (ext.history) {
            GroupHistoryMemData mem_data;
            ext.history->Delete(*txn, index_txs, nullptr, mem_data);
        }
        if (ext.utxos) {
            GroupUtxoMemData mem_data;
            ext.utxos->Delete(*txn, index_txs, nullptr, mem_data);
        }
    }
    for (const auto &ext : m_exts) {
        if (ext->TxnMode() == Extension::Txn::SameEnv) {
            ext->Disconnect(block, txn.get());
        }
    }

    {
        std::unique_lock lock(m_state_mutex);
        // Errors here abort the txn (Rust: the batch is never written)
        m_avalanche.DisconnectBlock(height);
        txn->Commit();
        txn.reset();
        // Remaining hashes are heights 0..height-1 after disconnecting
        // `height`.
        std::lock_guard merkle_lock(m_merkle_mutex);
        m_merkle_tree.Truncate(size_t(height));
    }
    for (const auto &ext : m_exts) {
        if (ext->TxnMode() == Extension::Txn::OwnEnv) {
            ext->Disconnect(block, nullptr);
        }
    }
    BlockMsg msg;
    msg.msg_type = BlockMsgType::Disconnected;
    msg.hash = block.info.hash;
    msg.height = height;
    msg.timestamp = block.info.timestamp;
    if (!block.txs.empty()) {
        msg.coinbase_tx = block.txs[0].tx;
    }
    auto subs = m_subs->Write();
    subs->BroadcastBlockMsg(msg);
}

void IndexerImpl::FinalizeBlock(const Block &block) {
    const BlockHeight height = block.info.height;
    {
        std::unique_lock lock(m_state_mutex);
        m_avalanche.FinalizeBlock(height);
    }
    std::shared_ptr<const GroupAux> token_id_aux;
    {
        auto txn = m_store->BeginRead();
        const std::optional<TxNum> first_tx_num =
            TxReader(*m_store, *txn).FirstTxNumByBlock(height);
        if (!first_tx_num) {
            throw ChronikError(indexer_errors::BlockNotFound(height));
        }
        const std::vector<const Tx *> ptrs = BlockTxPtrs(block);
        const std::vector<IndexTx> index_txs = PrepareIndexedTxsCached(
            *m_store, *txn, *first_tx_num, ptrs, m_mem_data.tx_num_cache,
            PrepareUpdateMode::Read);
        if (m_tokens) {
            token_id_aux = m_tokens->AuxFromDb(*m_store, *txn, index_txs);
        }
    }
    {
        BlockMsg msg;
        msg.msg_type = BlockMsgType::Finalized;
        msg.hash = block.info.hash;
        msg.height = height;
        msg.timestamp = block.info.timestamp;
        auto subs = m_subs->Write();
        subs->BroadcastBlockMsg(msg);
    }
    PublishBlockTxEvents(
        block, TxMsgType::Finalized(TxFinalizationReason::PostConsensus),
        token_id_aux.get());
}

void IndexerImpl::InvalidateBlock(const Block &block) {
    BlockMsg msg;
    msg.msg_type = BlockMsgType::Invalidated;
    msg.hash = block.info.hash;
    msg.height = block.info.height;
    msg.timestamp = block.info.timestamp;
    if (!block.txs.empty()) {
        msg.coinbase_tx = block.txs[0].tx;
    }
    auto subs = m_subs->Write();
    subs->BroadcastBlockMsg(msg);
}

void IndexerImpl::FinalizeTx(const TxId &txid) {
    TxRef tx;
    std::shared_ptr<const GroupAux> token_id_aux;
    if (const mem::MempoolTx *mempool_tx = m_mempool->GetTx(txid)) {
        tx = mempool_tx->tx;
        if (m_tokens) {
            // The hook may keep internal state: exclusive lock
            std::unique_lock lock(m_state_mutex);
            token_id_aux = m_mempool->Tokens()->AuxFromMempool(*tx);
        }
    } else {
        // It is possible that the transaction has been mined and is no longer
        // in the mempool when it gets finalized, either because of the vote
        // or because the callback is asynchronous. We need to handle both the
        // mempool (above) and the DB case.
        std::optional<std::pair<TxNum, index::BlockTx>> found;
        std::optional<DbBlock> block;
        {
            auto txn = m_store->BeginRead();
            found = TxReader(*m_store, *txn).TxAndNumByTxid(txid);
            if (!found) {
                throw ChronikError(indexer_errors::TxIdNotFound(txid));
            }
            block = BlockReader(*m_store, *txn)
                        .ByHeight(found->second.block_height);
            if (!block) {
                throw ChronikError(indexer_errors::DbTxHasNoBlock(txid));
            }
        }
        const TxNum tx_num = found->first;
        const TxEntry &entry = found->second.entry;
        try {
            tx = std::make_shared<const Tx>(m_host.LoadTx(
                block->file_num, entry.data_pos, entry.undo_pos));
        } catch (const std::exception &) {
            throw ChronikError(indexer_errors::TxNotFound(tx_num));
        }
        auto txn = m_store->BeginRead();
        const Tx *const ptrs[] = {tx.get()};
        const std::vector<IndexTx> index_txs =
            PrepareIndexedTxsCached(*m_store, *txn, tx_num, ptrs,
                                    m_mem_data.tx_num_cache,
                                    PrepareUpdateMode::Read);
        if (m_tokens) {
            token_id_aux = m_tokens->AuxFromDb(*m_store, *txn, index_txs);
        }
    }
    PublishTxEvent(*tx, TxMsgType::Finalized(TxFinalizationReason::PreConsensus),
                   token_id_aux.get());
}

void IndexerImpl::InvalidateTx(TxRef tx) {
    const TxId txid = tx->txid;
    if (const mem::MempoolTx *mempool_tx = m_mempool->GetTx(txid)) {
        const TxRef mempool_tx_ref = mempool_tx->tx;
        std::shared_ptr<const GroupAux> token_id_aux;
        if (m_tokens) {
            std::unique_lock lock(m_state_mutex);
            token_id_aux = m_mempool->Tokens()->AuxFromMempool(*mempool_tx_ref);
        }
        PublishTxEvent(*mempool_tx_ref, TxMsgType::Invalidated(),
                       token_id_aux.get());
        return;
    }
    // If the tx is no longer in the mempool we need to parse it again.
    mem::MempoolResult result;
    {
        std::shared_lock lock(m_state_mutex);
        result = m_mempool->ProbeTx(*m_store, mem::MempoolTx{tx, 0});
    }
    PublishTxEvent(*result.mempool_tx.tx, TxMsgType::Invalidated(),
                   result.token_id_aux.get());
}

// ---- public writer API (with failed-state handling) ----

void IndexerImpl::OnTxAddedToMempool(TxRef tx, int64_t time_first_seen) {
    Guarded([&] { AddTxToMempool(std::move(tx), time_first_seen); });
}
void IndexerImpl::OnTxRemovedFromMempool(const TxId &txid) {
    Guarded([&] { RemoveTxFromMempool(txid); });
}
void IndexerImpl::OnBlockConnected(const Block &block) {
    Guarded([&] {
        ConnectBlock(block);
        if (m_params.observe_indexed_height) {
            try { m_params.observe_indexed_height(block.info.height); } catch (...) {}
        }
    });
}
void IndexerImpl::OnBlockDisconnected(const Block &block) {
    Guarded([&] {
        DisconnectBlock(block);
        if (m_params.observe_indexed_height) {
            try { m_params.observe_indexed_height(block.info.height - 1); } catch (...) {}
        }
    });
}
void IndexerImpl::OnBlockFinalized(const BlockInfo &info) {
    Guarded([&] {
        // Rust Chronik::finalize_block loads the block (and undo) first
        const Block block = m_host.LoadBlock(info);
        FinalizeBlock(block);
        m_host.Log(LogLevel::Debug, "Chronik: block " + HashToHex(info.hash) +
                                        " finalized with " +
                                        std::to_string(block.txs.size()) +
                                        " txs\n");
    });
}
void IndexerImpl::OnBlockInvalidated(const Block &block) {
    Guarded([&] { InvalidateBlock(block); });
}
void IndexerImpl::OnTxFinalized(const TxId &txid) {
    Guarded([&] { FinalizeTx(txid); });
}
void IndexerImpl::OnTxInvalidated(TxRef tx) {
    Guarded([&] { InvalidateTx(std::move(tx)); });
}

void IndexerImpl::Close() {
    if (m_closed.exchange(true)) {
        return;
    }
    for (const auto &ext : m_exts) {
        ext->Close();
    }
    std::unique_lock lock(m_state_mutex);
    m_store->Sync(true);
}

// ---------------------------------------------------------------------------
// Indexer
// ---------------------------------------------------------------------------

Indexer::Indexer(std::unique_ptr<IndexerImpl> impl) : m_impl(std::move(impl)) {}
Indexer::~Indexer() = default;

std::unique_ptr<Indexer>
Indexer::Open(const Host &host, IndexerParams params,
              std::vector<std::unique_ptr<Extension>> exts) {
    return std::unique_ptr<Indexer>(new Indexer(std::make_unique<IndexerImpl>(
        host, std::move(params), std::move(exts))));
}

void Indexer::Resync() { m_impl->Resync(); }
void Indexer::OnTxAddedToMempool(TxRef tx, int64_t time_first_seen) {
    m_impl->OnTxAddedToMempool(std::move(tx), time_first_seen);
}
void Indexer::OnTxRemovedFromMempool(const TxId &txid) {
    m_impl->OnTxRemovedFromMempool(txid);
}
void Indexer::OnBlockConnected(Block block) { m_impl->OnBlockConnected(block); }
void Indexer::OnBlockDisconnected(Block block) {
    m_impl->OnBlockDisconnected(block);
}
void Indexer::OnBlockFinalized(const BlockInfo &info) {
    m_impl->OnBlockFinalized(info);
}
void Indexer::OnBlockInvalidated(Block block) {
    m_impl->OnBlockInvalidated(block);
}
void Indexer::OnTxFinalized(const TxId &txid) { m_impl->OnTxFinalized(txid); }
void Indexer::OnTxInvalidated(TxRef tx) {
    m_impl->OnTxInvalidated(std::move(tx));
}
void Indexer::Close() { m_impl->Close(); }

} // namespace chronik::native
