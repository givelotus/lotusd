// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CORE_QUERY_QUERY_H
#define CHRONIK_NATIVE_CORE_QUERY_QUERY_H

#include <chronik/native/avalanche.h>
#include <chronik/native/extension.h>
#include <chronik/native/host.h>
#include <chronik/native/index/blocks.h>
#include <chronik/native/codec/script_compress.h>
#include <chronik/native/index/data.h>
#include <chronik/native/index/group_history.h>
#include <chronik/native/index/spent_by.h>
#include <chronik/native/index/txs.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/mem/group_history.h>
#include <chronik/native/mem/group_utxos.h>
#include <chronik/native/mem/spent_by.h>
#include <chronik/native/mem/tokens.h>
#include <chronik/native/proto.h>
#include <chronik/native/script/script.h>
#include <chronik/native/store.h>
#include <chronik/native/token/verify.h>
#include <chronik/native/types.h>

#include <cstdint>
#include <exception>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

/**
 * Port of chronik-indexer src/query (eCash tier, without plugins): blocks,
 * txs, broadcast, group history/UTXOs and token data, building the protobuf
 * responses of chronik-http.
 *
 * Snapshot rules (indexer_impl.h): every query works in two phases on ONE
 * IndexerSnapshot. Phase 1 runs with the state lock held and reads the DB,
 * the mempool and Avalanche, producing a plan (copies of the mempool data it
 * needs). The snapshot is then unlocked and phase 2 performs the Host calls
 * (LoadTx, preconsensus finality, headers) and the remaining DB reads through
 * the still-valid read txn. An error of phase 1 at item k is deferred until
 * the items before k have been rendered, so errors surface in the same order
 * as in Rust, which does everything in one pass.
 */
namespace chronik::native::query {

using index::BlockHeight;
using index::TxNum;

/** Default `page_size` when the query param is omitted */
inline constexpr uint32_t DEFAULT_PAGE_SIZE = 25;
/** Max scripts per batch request. */
inline constexpr size_t MAX_NUM_BATCH_SCRIPTS = 500;
inline constexpr size_t MAX_BLOCKS_PAGE_SIZE = 500;
inline constexpr size_t MIN_BLOCK_TXS_PAGE_SIZE = 1;
inline constexpr size_t MAX_BLOCK_TXS_PAGE_SIZE = 200;
inline constexpr size_t MIN_HISTORY_PAGE_SIZE = 1;
inline constexpr size_t MAX_HISTORY_PAGE_SIZE = 200;
inline constexpr uint64_t MAX_TIMEOUT_FINALIZATION_SECS = 120;
inline constexpr size_t PLUGIN_GROUPS_MIN_PAGE_SIZE = 1;
inline constexpr size_t PLUGIN_GROUPS_MAX_PAGE_SIZE = 50;

using MempoolSpentEntries = mem::MempoolSpentBy::Entries;

// ---------------------------------------------------------------- util ----

/** `std::string` holding the raw bytes (protobuf `bytes` fields). */
inline std::string BytesStr(ByteView bytes) {
    return std::string(reinterpret_cast<const char *>(bytes.data()),
                       bytes.size());
}
inline std::string HashStr(const Hash32 &hash) {
    return BytesStr(ByteView(hash.b.data(), hash.b.size()));
}

/**
 * Rust's `Ord` of hashes (TxId, BlockHash): compares the big-endian bytes,
 * i.e. the internal bytes from the last to the first. Note Hash32's own
 * operator<=> compares the internal (LE) bytes, so the C++ mempool's
 * std::set<..TxId..> containers are not in Rust's order; queries re-sort.
 */
inline bool HashLessBe(const Hash32 &a, const Hash32 &b) {
    for (size_t i = 32; i-- > 0;) {
        if (a.b[i] != b.b[i]) {
            return a.b[i] < b.b[i];
        }
    }
    return false;
}
/** Rust Ord of OutPoint: (txid BE, out_idx). */
inline bool OutPointLessBe(const OutPoint &a, const OutPoint &b) {
    if (a.txid != b.txid) {
        return HashLessBe(a.txid, b.txid);
    }
    return a.out_idx < b.out_idx;
}
/** Rust Ord of (i64, TxId). */
inline bool TimeTxidLessBe(const std::pair<int64_t, TxId> &a,
                           const std::pair<int64_t, TxId> &b) {
    if (a.first != b.first) {
        return a.first < b.first;
    }
    return HashLessBe(a.second, b.second);
}

/** Rust `Sha256d::from_be_hex` (TxId/BlockHash/TokenId FromStr). */
std::optional<Hash32> ParseHashBeHex(std::string_view hex);

/** Rust `HashOrHeight::from_str`: "400: Not a hash or height: {0}" */
struct HashOrHeight {
    bool is_hash = false;
    BlockHash hash;
    BlockHeight height = 0;
};
HashOrHeight ParseHashOrHeight(std::string_view hash_or_height);

/**
 * Rust `OutputsSpent`: which outputs of a tx have been spent by DB or
 * mempool txs. The mempool entries are a copy taken under the state lock.
 */
class OutputsSpent {
public:
    OutputsSpent() = default;
    static OutputsSpent NewMempool(std::optional<MempoolSpentEntries> mempool);
    /** "500: Inconsistent DB: tx_num = .. has spent entry .. in the DB..." */
    static OutputsSpent Query(const index::SpentByReader &spent_by_reader,
                              const index::TxReader &tx_reader,
                              std::optional<MempoolSpentEntries> mempool,
                              TxNum tx_num);
    std::optional<mem::SpentBy> SpentBy(uint32_t output_idx) const;

private:
    std::optional<MempoolSpentEntries> m_mempool;
    std::vector<index::SpentByEntry> m_blocks;
    std::unordered_map<TxNum, TxId> m_txid_by_num;
};

/** Copy of the mempool spent-by entries of `txid` (locked snapshot). */
std::optional<MempoolSpentEntries>
CopyMempoolSpent(const IndexerSnapshot &snap, const TxId &txid);

/** The eCash MempoolTokens of the snapshot's mempool, or nullptr. */
const mem::MempoolTokens *SnapshotMempoolTokens(const IndexerSnapshot &snap);

/** Rust `TxTokenData` (owned copies of the token inputs and TokenTx). */
struct TxTokenData {
    std::vector<std::optional<token::SpentToken>> inputs;
    token::TokenTx tx;

    /** Load token data from the mempool (`tokens` may be nullptr). */
    static std::optional<TxTokenData>
    FromMempool(const mem::MempoolTokens *tokens, const Tx &tx);
    /** Load token data from the DB of a mined tx */
    static std::optional<TxTokenData> FromDb(const KvStore &store,
                                             const ReadTxn &txn, TxNum tx_num,
                                             const Tx &tx,
                                             bool is_token_index_enabled);
    /**
     * Token data of a tx not in the mempool or DB (`batch_txids` may be
     * nullptr). Inputs must have coins for SLP V2 mint vault MINTs.
     */
    static std::optional<TxTokenData> FromUnbroadcastTxBatch(
        const KvStore &store, const ReadTxn &txn, const mem::Mempool &mempool,
        const mem::MempoolTokens *tokens, const Tx &tx,
        const std::set<TxId> *batch_txids,
        const mem::BatchTokenTxs &batch_txs);

    std::optional<proto::Token> InputTokenProto(size_t input_idx) const;
    std::optional<proto::Token> OutputTokenProto(size_t output_idx) const;
    void EntriesProto(
        google::protobuf::RepeatedPtrField<proto::TokenEntry> &out) const;
};

/** Read just the output data of a token tx from the DB */
std::optional<token::SpentToken>
ReadDbTokenOutput(const KvStore &store, const ReadTxn &txn, TxNum tx_num,
                  uint32_t out_idx, bool is_token_index_enabled);

proto::TokenType MakeTokenTypeProto(const token::TokenType &token_type);
proto::GenesisInfo MakeGenesisInfoProto(const token::GenesisInfo &info);
proto::Token MakeUtxoTokenProto(const token::Token &token);
proto::OutPoint MakeOutpointProto(const OutPoint &outpoint);

struct MakeTxProtoParams {
    const Tx &tx;
    const OutputsSpent &outputs_spent;
    int64_t time_first_seen = 0;
    bool is_coinbase = false;
    const index::DbBlock *block = nullptr;
    const Avalanche &avalanche;
    const TxTokenData *token = nullptr;
    bool is_final_preconsensus = false;
};
/** Rust `make_tx_proto` (plugins always empty). */
proto::Tx MakeTxProto(const MakeTxProtoParams &params);

/** Host::IsFinalizedPreConsensus, nullopt => false. */
bool IsFinalPreconsensus(const Host &host, const TxId &txid);

// ------------------------------------------------- tx rendering plans ----

/** A mempool tx to render; everything copied under the state lock. */
struct MempoolTxJob {
    TxRef tx;
    int64_t time_first_seen = 0;
    std::optional<MempoolSpentEntries> mempool_spent;
    std::optional<TxTokenData> token;
};
/** A mined tx to render (Host::LoadTx in phase 2). */
struct DbTxJob {
    TxNum tx_num = 0;
    index::TxEntry entry;
    index::DbBlock block;
    std::optional<MempoolSpentEntries> mempool_spent;
};
using TxJob = std::variant<MempoolTxJob, DbTxJob>;

/** Mempool job of `txid`, nullopt if the tx isn't in the mempool. */
std::optional<MempoolTxJob> MakeMempoolJob(const IndexerSnapshot &snap,
                                           const TxId &txid);

/** Shared state for phase 2. */
struct RenderCtx {
    const KvStore &store;
    const ReadTxn &txn;
    const Host &host;
    Avalanche avalanche;
    bool is_token_index_enabled = false;
};

struct RenderDbOpts {
    bool include_spent_by = true;
    /** Wrap LoadTx failures as "500: Reading <txid> failed" */
    bool wrap_read_failure = true;
};

proto::Tx RenderTx(const RenderCtx &ctx, const TxJob &job,
                   const RenderDbOpts &opts = {});

/** A planned page of txs. */
struct TxPagePlan {
    std::vector<TxJob> jobs;
    RenderDbOpts db_opts;
    uint32_t num_pages = 0;
    uint32_t num_txs = 0;
    /**
     * rev_history: sort the rendered txs from this index on (the DB txs) by
     * (-height, time_first_seen) like Rust.
     */
    std::optional<size_t> sort_db_from;
    /** unconfirmed_txs: sort all by (time_first_seen, txid) */
    bool sort_by_time_txid = false;
    /** unconfirmed (mempool-only) pages: num_pages/num_txs from the result */
    bool counts_from_txs = false;
    /** Error of phase 1, thrown after rendering `jobs`. */
    std::exception_ptr deferred;
};
proto::TxHistoryPage RenderTxPage(const RenderCtx &ctx, TxPagePlan plan);

// ------------------------------------------------------------- blocks ----

proto::Block BlockByHashOrHeight(const IndexerSnapshot &snap,
                                 std::string_view hash_or_height);
proto::Blocks BlocksByRange(const IndexerSnapshot &snap,
                            BlockHeight start_height,
                            BlockHeight end_height);
TxPagePlan PlanBlockTxs(const IndexerSnapshot &snap,
                        std::string_view hash_or_height, size_t page_num,
                        size_t page_size);
/** QueryBlocks::header; takes its own snapshot (after the Host lookup). */
proto::BlockHeader BlockHeader(const IndexerImpl &indexer, const Host &host,
                               std::string_view hash_or_height,
                               int32_t checkpoint_height);
/** QueryBlocks::headers_by_range */
proto::BlockHeaders BlockHeadersByRange(const IndexerImpl &indexer,
                                        const Host &host,
                                        BlockHeight start_height,
                                        BlockHeight end_height,
                                        int32_t checkpoint_height,
                                        bool check_num_blocks);

// ---------------------------------------------------------------- txs ----

/** QueryTxs::tx_by_id; `snap` is unlocked by the call. */
proto::Tx TxById(IndexerSnapshot &snap, const Host &host, const TxId &txid);
proto::RawTx RawTxById(IndexerSnapshot &snap, const Host &host,
                       const TxId &txid);
proto::TokenInfo TokenInfoById(const IndexerSnapshot &snap,
                               const TxId &token_id_txid);
TxPagePlan PlanUnconfirmedTxs(const IndexerSnapshot &snap);

// ------------------------------------------------------ group history ----

/** Rust `GroupMember`: the member itself, or its hash (scripthash). */
struct GroupMemberArg {
    /** Raw member (e.g. script bytecode, token id LE bytes, LOKAD id) */
    std::optional<Bytes> member;
    /** Member hash, big-endian bytes (Sha256::to_be_bytes) */
    std::array<uint8_t, 32> member_hash{};
};

/** QueryGroupHistory for one group. */
struct GroupHistoryQuery {
    const IndexerSnapshot &snap;
    const GroupDef &group;
    /** Mempool part of the group (nullptr: empty) */
    const mem::MempoolGroupHistory *mempool_history;
    bool is_token_index_enabled = false;
    bool is_scripthash_index_enabled = false;

    TxPagePlan ConfirmedTxs(const GroupMemberArg &member, size_t page_num,
                            size_t page_size,
                            bool include_spent_by = true) const;
    TxPagePlan RevHistory(const GroupMemberArg &member, size_t page_num,
                          size_t page_size) const;
    TxPagePlan UnconfirmedTxs(const GroupMemberArg &member) const;

private:
    std::optional<Bytes> MemberSer(const GroupMemberArg &member,
                                   const index::GroupHistoryReader &db)
        const;
    /** read_block_tx phase 1 (MissingDbTx / MissingDbTxBlock) */
    DbTxJob ResolveDbTx(TxNum tx_num) const;
};

// -------------------------------------------------------- group utxos ----

/**
 * Planned UTXOs: protos built under the lock; `preconsensus` lists the
 * (index, txid) whose is_final must be OR-ed with the Host's preconsensus
 * finality in phase 2.
 */
template <typename P> struct UtxoPlan {
    std::vector<P> utxos;
    std::vector<std::pair<size_t, TxId>> preconsensus;
};
void FinishUtxos(const Host &host, UtxoPlan<proto::ScriptUtxo> &plan);
void FinishUtxos(const Host &host, UtxoPlan<proto::Utxo> &plan);

struct GroupUtxosQuery {
    const IndexerSnapshot &snap;
    const GroupDef &group;
    /** Mempool part (nullptr: empty) */
    const mem::MempoolGroupUtxos *mempool_utxos;
    bool is_token_index_enabled = false;
    bool is_scripthash_index_enabled = false;

    /** QueryGroupUtxos::script (ScriptGroup only) */
    script::Script Script(const GroupMemberArg &member,
                          const DecompressPubKeyFn &decompress_pubkey) const;
    UtxoPlan<proto::ScriptUtxo> ValueUtxos(ByteView member) const;
    UtxoPlan<proto::Utxo> OutputUtxos(ByteView member) const;

private:
    template <typename P> UtxoPlan<P> Utxos(ByteView member) const;
};

// ---------------------------------------------------------- broadcast ----

/** "400: Finalization timeout of {0}s exceeds maximum of 120s" */
uint64_t VerifyTimeoutFinalization(uint64_t timeout_finalization_secs);

/** Broadcast handler (Rust handle_broadcast_tx(s)); returns the txids. */
std::vector<TxId> BroadcastTxs(const IndexerImpl &indexer, const Host &host,
                               const std::vector<Bytes> &raw_txs,
                               bool skip_token_checks,
                               uint64_t finalization_timeout_secs);
/** QueryBroadcast::validate_tx */
proto::Tx ValidateTx(const IndexerImpl &indexer, const Host &host,
                     const Bytes &raw_tx);

} // namespace chronik::native::query

#endif // CHRONIK_NATIVE_CORE_QUERY_QUERY_H
