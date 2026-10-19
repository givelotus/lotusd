// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_DB_BRANCH_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_DB_BRANCH_H

#include <ext/lotus_v2/db/env.h>
#include <ext/lotus_v2/db/model.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

/**
 * Separate, versioned V2 confirmed branch database (port of
 * chronik-db/src/v2_branch.rs). Callers supply only authoritative committed
 * transitions. One synced write batch commits records, history postings,
 * explorer and asset facts, receipt, undo and checkpoint together; the flat
 * wire segments are written and synced before it.
 *
 * Errors are thrown as V2Error.
 */
namespace chronik::native::lotus_v2 {

/** Max serialized output record (output <= 812 B plus two locations). */
inline constexpr size_t MAX_BRANCH_RECORD_BYTES = 1200;

/** "Loc"/TxLocation key helpers shared with the explorer/asset modules. */
Bytes OutPointBytes(const OutPoint &op);
OutPoint OutPointDecode(ByteView b);
Bytes PrefixKey(uint8_t prefix, ByteView bytes);
/** 'p' || root || (position or 255) */
Bytes PostingPrefix(const Hash32 &root, std::optional<uint8_t> position);

/**
 * Order in which a block's transactions are resolved and applied: every
 * in-block parent before the children spending its outputs, otherwise block
 * order (a topologically ordered block keeps its own order). Hosts may
 * confirm blocks in canonical (txid) order. Members of a dependency cycle
 * follow in block order and are rejected as spending a missing coin.
 */
std::vector<size_t>
ProcessingOrder(const std::vector<ConfirmedTx> &transactions);

class ReadSnapshot;

/** Owns a dedicated database. Mutations require exclusive access. */
class V2Db {
public:
    /** Open or create a dedicated V2 directory; reject foreign schema. */
    V2Db(const std::filesystem::path &path, const Binding &binding);

    const Binding &GetBinding() const { return m_binding; }
    /** Last fully indexed block; a new database has no checkpoint. */
    std::optional<Anchor> Checkpoint() const;
    /** Index the caller-authenticated committed genesis. */
    void InitializeGenesis(const CommittedBlock &block);
    /**
     * Stable MVCC snapshot and its checkpoint; Invalid("uninitialized index")
     * until genesis. The snapshot must not outlive this V2Db.
     */
    ReadSnapshot Snapshot() const;
    /** Atomically index one committed child block; exact replay is a no-op. */
    void Connect(const CommittedBlock &block);
    /** Atomically undo the current block; repeating it is idempotent. */
    void Disconnect(const Anchor &anchor);

    /** The env itself (Rust's pub(crate) `db`, for tests and tooling). */
    V2Env &Env() { return *m_db; }
    const V2Env &Env() const { return *m_db; }

private:
    void ConnectImpl(const CommittedBlock &block, bool genesis);

    std::unique_ptr<V2Env> m_db;
    Binding m_binding;
};

/**
 * Bounded read facade over one MVCC snapshot: each call returns at most one
 * record/posting; consumers enforce request budgets.
 */
class ReadSnapshot {
public:
    ReadSnapshot(V2EnvSnapshot inner, Anchor anchor, Binding binding)
        : anchor(anchor), binding(binding), m_inner(std::move(inner)) {}

    /** Checkpoint matching this snapshot. */
    Anchor anchor;
    /** Immutable schema deployment binding. */
    Binding binding;

    const V2EnvSnapshot &Inner() const { return m_inner; }

    // ---- Branch records (v2_branch.rs) ----
    std::optional<TxLocation> Transaction(const TxId &txid) const;
    std::optional<TxLocation> TransactionCounted(const TxId &txid,
                                                 AssetReadBudget &budget) const;
    /** Full output with creation/spend history. Burns remain queryable. */
    std::optional<OutputRecord> GetOutput(const OutPoint &op) const;
    std::optional<OutputRecord> OutputCounted(const OutPoint &op,
                                              AssetReadBudget &budget) const;
    /** Unspent spendable output; burns are always excluded. */
    std::optional<OutputRecord> Utxo(const OutPoint &op) const;
    /** Strictly ordered next outpoint for root and optional position. */
    std::optional<OutPoint> NextPosting(const Hash32 &root,
                                        std::optional<uint8_t> position,
                                        std::optional<OutPoint> after) const;
    std::vector<OutPoint> PostingsAfter(const Hash32 &root,
                                        std::optional<uint8_t> position,
                                        std::optional<OutPoint> after) const;

    // ---- Explorer (v2_explorer.rs) ----
    std::optional<BlockMeta> ExplorerBlock(const Hash32 &id) const;
    std::optional<BlockMeta> ExplorerBlockAtHeight(uint64_t height) const;
    std::optional<TxMeta> ExplorerTx(const TxId &id) const;
    std::optional<TxMeta> ExplorerTxByHash(const TxHash &hash) const;
    std::optional<std::pair<TxId, TxHash>>
    ExplorerBlockTx(const Hash32 &block, uint32_t index) const;
    std::optional<InputMeta> ExplorerInput(const TxId &id,
                                           uint32_t index) const;
    std::optional<WitnessFact> ExplorerWitness(const TxId &id,
                                               uint32_t input_index,
                                               uint32_t index) const;
    /** [offset, min(offset + length, wire_size)) of the exact frame. */
    std::optional<Bytes> ExplorerWireSlice(const TxId &id, uint64_t offset,
                                           uint64_t length) const;
    /** 32 KiB chunk `index` of the exact frame. */
    std::optional<Bytes> ExplorerWireChunk(const TxId &id,
                                           uint32_t index) const;
    /** Exclusive bounded seek in eH/eO/eI/eW with an exact key width. */
    std::optional<std::pair<Bytes, Bytes>>
    ExplorerNextRaw(ByteView prefix, size_t key_len,
                    std::optional<ByteView> after) const;

    // ---- Assets (v2_asset.rs) ----
    std::optional<AssetSummary> GetAssetSummary(const Hash32 &token) const;
    std::optional<AssetSummary>
    AssetSummaryCounted(const Hash32 &token, AssetReadBudget &budget) const;
    std::optional<std::pair<Bytes, AssetSummary>>
    NextAssetSummary(std::optional<ByteView> after) const;
    std::optional<std::pair<Bytes, AssetSummary>>
    NextAssetSummaryCounted(std::optional<ByteView> after,
                            AssetReadBudget &budget) const;
    std::optional<std::pair<Bytes, AssetEvent>>
    NextAssetEvent(const Hash32 &token, std::optional<ByteView> after) const;
    std::optional<std::pair<Bytes, AssetEvent>>
    NextAssetEventCounted(const Hash32 &token, std::optional<ByteView> after,
                          AssetReadBudget &budget) const;
    std::optional<std::pair<Bytes, OutPoint>>
    NextAssetOutput(const Hash32 &token, std::optional<ByteView> after) const;
    std::optional<std::pair<Bytes, OutPoint>>
    NextAssetOutputCounted(const Hash32 &token, std::optional<ByteView> after,
                           AssetReadBudget &budget) const;

private:
    std::pair<uint64_t, uint64_t>
    ExplorerTableCount(const TxId &id, uint64_t wire_size,
                       const WireRange &range) const;
    void AssetCanonicalLocation(const TxLocation &location,
                                AssetReadBudget &budget) const;
    std::optional<std::pair<Bytes, Bytes>>
    NextAssetRaw(ByteView prefix, size_t key_len,
                 std::optional<ByteView> after, AssetReadBudget &budget) const;

    V2EnvSnapshot m_inner;
};

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_DB_BRANCH_H
