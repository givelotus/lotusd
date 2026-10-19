// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_EXPLORER_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_EXPLORER_H

#include <ext/lotus_v2/db/model.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

/**
 * Bounded explorer queries over one immutable read snapshot (port of
 * chronik-indexer/src/query/v2_explorer.rs). Authority, restart-safe cursor
 * binding and capped JSON encoding belong to HTTP. Errors are V2Error.
 */
namespace chronik::native::lotus_v2 {
class ReadSnapshot;
}

namespace chronik::native::lotus_v2::query_explorer {

/** New-schema page/work limits. */
inline constexpr size_t MAX_PAGE_SIZE = 100;
/** Maximum records examined in one page. */
inline constexpr size_t MAX_EXAMINED = 1024;
/** Maximum key reads reserved before querying. */
inline constexpr size_t MAX_KEY_READS = 4096;
/** Logical result cap, leaving room for decimal/hex JSON expansion. */
inline constexpr size_t MAX_PAGE_BYTES = 96 * 1024;

/** Read-only seam for pinned snapshots and fixture tests. */
class ExplorerSource {
public:
    virtual ~ExplorerSource() = default;
    virtual std::optional<BlockMeta> Block(const Hash32 &id) const = 0;
    virtual std::optional<BlockMeta> BlockAtHeight(uint64_t height) const = 0;
    virtual std::optional<TxMeta> Transaction(const TxId &id) const = 0;
    virtual std::optional<TxMeta>
    TransactionByHash(const TxHash &hash) const = 0;
    virtual std::optional<std::pair<TxId, TxHash>>
    BlockTransaction(const Hash32 &block, uint32_t index) const = 0;
    virtual std::optional<InputMeta> GetInput(const TxId &id,
                                           uint32_t index) const = 0;
    virtual std::optional<WitnessFact>
    Witness(const TxId &id, uint32_t input, uint32_t index) const = 0;
    virtual std::optional<OutputRecord> GetOutput(const OutPoint &op) const = 0;
    virtual std::optional<Bytes> Wire(const TxId &id, uint32_t chunk) const = 0;
};

/** ExplorerSource over the V2 DB snapshot. */
class SnapshotExplorerSource final : public ExplorerSource {
public:
    explicit SnapshotExplorerSource(const ReadSnapshot &s) : m_s(s) {}
    std::optional<BlockMeta> Block(const Hash32 &id) const override;
    std::optional<BlockMeta> BlockAtHeight(uint64_t height) const override;
    std::optional<TxMeta> Transaction(const TxId &id) const override;
    std::optional<TxMeta> TransactionByHash(const TxHash &hash) const override;
    std::optional<std::pair<TxId, TxHash>>
    BlockTransaction(const Hash32 &block, uint32_t index) const override;
    std::optional<InputMeta> GetInput(const TxId &id,
                                   uint32_t index) const override;
    std::optional<WitnessFact> Witness(const TxId &id, uint32_t input,
                                       uint32_t index) const override;
    std::optional<OutputRecord> GetOutput(const OutPoint &op) const override;
    std::optional<Bytes> Wire(const TxId &id, uint32_t chunk) const override;

private:
    const ReadSnapshot &m_s;
};

/** Typed continuation is exclusive. HTTP binds it to route/filter/snapshot. */
template <typename T> struct Page {
    std::vector<T> items;
    std::optional<uint64_t> next_index;
    bool exhausted = false;
    size_t examined = 0;
    /** Physical key-read reservation, including canonical joins. */
    size_t key_reads = 0;
    bool operator==(const Page &) const = default;
};

/** Exact byte chunk, at most 32768 bytes. */
struct WireChunk {
    TxId txid;
    TxHash txhash;
    uint64_t total_bytes = 0;
    uint64_t offset = 0;
    Bytes bytes;
    std::optional<uint64_t> next_offset;
    bool operator==(const WireChunk &) const = default;
};

/** Decimal string for every new JSON integer, including u128. */
std::string UnsignedDecimal(U128 value);
/** tip - creation + 1; Invalid("confirmation arithmetic") on under/overflow. */
uint64_t Confirmations(uint64_t tip_height, uint64_t creation_height);

/**
 * Ordinal page over [0, count) after `after`; load(i) returns the item and
 * its logical bytes.
 */
template <typename T>
Page<T> OrdinalPage(uint32_t count, std::optional<uint64_t> after, size_t size,
                    size_t initial_reads, size_t reads_per_item,
                    const std::function<std::pair<T, size_t>(uint32_t)> &load);

/** Descending canonical blocks; `before` is exclusive. */
Page<BlockMeta> BlocksPage(const ExplorerSource &source, uint64_t tip,
                           std::optional<uint64_t> before, size_t size);
/** Native block transaction order, with both typed identities. */
std::optional<Page<TxMeta>>
BlockTransactionsPage(const ExplorerSource &source, const Hash32 &block,
                      std::optional<uint64_t> after, size_t size);
/** Complete native input order, including non-spend ordinals. */
std::optional<Page<InputMeta>> InputsPage(const ExplorerSource &source,
                                          const TxId &id,
                                          std::optional<uint64_t> after,
                                          size_t size);
/** Every output, including burns and spent historical outputs. */
std::optional<Page<OutputRecord>> OutputsPage(const ExplorerSource &source,
                                              const TxId &id,
                                              std::optional<uint64_t> after,
                                              size_t size);
/** Witness descriptors of one input. */
std::optional<Page<WitnessFact>>
WitnessesPage(const ExplorerSource &source, const TxId &id,
              uint32_t input_index, std::optional<uint64_t> after,
              size_t size);
/** Exact native frame bytes [offset, offset + length). */
std::optional<WireChunk> GetWireChunk(const ExplorerSource &source,
                                      const TxId &id, uint64_t offset,
                                      size_t length);

} // namespace chronik::native::lotus_v2::query_explorer

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_EXPLORER_H
