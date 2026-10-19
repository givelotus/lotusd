// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_ASSETS_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_ASSETS_H

#include <ext/lotus_v2/db/model.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

/**
 * Bounded asset pages over the immutable confirmed snapshot (port of
 * chronik-indexer/src/query/v2_assets.rs). Transport owns the restart and
 * authority fence and binds `after` to its normalized route, token, view and
 * snapshot before calling this module.
 */
namespace chronik::native::lotus_v2 {
class ReadSnapshot;
}

namespace chronik::native::lotus_v2::query_assets {

/** Trusted caps; work is charged before each source call. */
struct Limits {
    /** Maximum returned records (1..=100). */
    size_t page_size = 25;
    /** Maximum examined index entries (1..=1024). */
    size_t examined = 1024;
    /** Maximum storage reads (1..=4096), including secondary joins. */
    size_t reads = 4096;
    /** Maximum logical binary result bytes. */
    size_t result_bytes = 128 * 1024;
};

/** v2_assets::Error; what() is the Rust Debug name. */
class Error : public std::runtime_error {
public:
    enum class Kind { InvalidLimits, InvalidCursor, Source, RecordLimit };
    explicit Error(Kind kind) : std::runtime_error(Name(kind)), m_kind(kind) {}
    Kind kind() const { return m_kind; }

private:
    static const char *Name(Kind kind);
    Kind m_kind;
};

/**
 * Each implementation charges actual storage reads before performing them,
 * including iterator rereads and canonical joins, on one pinned snapshot.
 * Failures throw Error.
 */
class Source {
public:
    virtual ~Source() = default;
    virtual std::optional<std::pair<Bytes, AssetSummary>>
    Summary(std::optional<ByteView> after, AssetReadBudget &budget) const = 0;
    virtual std::optional<std::pair<Bytes, AssetEvent>>
    Event(const Hash32 &token, std::optional<ByteView> after,
          AssetReadBudget &budget) const = 0;
    virtual std::optional<std::pair<Bytes, OutPoint>>
    Posting(const Hash32 &token, std::optional<ByteView> after,
            AssetReadBudget &budget) const = 0;
    virtual std::optional<OutputRecord>
    GetOutput(const OutPoint &op, AssetReadBudget &budget) const = 0;
};

/** Source over the V2 DB snapshot; every DB error becomes Error::Source. */
class SnapshotAssetSource final : public Source {
public:
    explicit SnapshotAssetSource(const ReadSnapshot &s) : m_s(s) {}
    std::optional<std::pair<Bytes, AssetSummary>>
    Summary(std::optional<ByteView> after,
            AssetReadBudget &budget) const override;
    std::optional<std::pair<Bytes, AssetEvent>>
    Event(const Hash32 &token, std::optional<ByteView> after,
          AssetReadBudget &budget) const override;
    std::optional<std::pair<Bytes, OutPoint>>
    Posting(const Hash32 &token, std::optional<ByteView> after,
            AssetReadBudget &budget) const override;
    std::optional<OutputRecord>
    GetOutput(const OutPoint &op, AssetReadBudget &budget) const override;

private:
    const ReadSnapshot &m_s;
};

/** Exclusive continuation must be wrapped in the common transport cursor. */
template <typename T> struct Page {
    std::vector<T> items;
    /** Last fully examined key; nullopt only at observed exhaustion. */
    std::optional<Bytes> next_key;
    bool exhausted = false;
    /** Exact charged storage reads. */
    size_t reads = 0;
    /** Examined index entries, including filtered outputs. */
    size_t examined = 0;
};

/** Known assets in native-byte lexicographic order. */
Page<AssetSummary> Assets(const Source &source, std::optional<ByteView> after,
                          const Limits &limits);
/** One aggregate event per touched transaction in height/index order. */
Page<AssetEvent> Events(const Source &source, const Hash32 &token,
                        std::optional<ByteView> after, const Limits &limits);
/** History includes burns; unspent excludes spent outputs and burns. */
Page<OutputRecord> Outputs(const Source &source, const Hash32 &token,
                           bool unspent, std::optional<ByteView> after,
                           const Limits &limits);

} // namespace chronik::native::lotus_v2::query_assets

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_ASSETS_H
