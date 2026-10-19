// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_BRANCHES_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_BRANCHES_H

#include <ext/lotus_v2/types.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

/**
 * Bounded confirmed V2 branch discovery over a pinned posting snapshot (port
 * of chronik-indexer/src/query/v2_branches.rs). Roots use native wire byte
 * order. Matching does not imply ownership.
 */
namespace chronik::native::lotus_v2 {
class ReadSnapshot;
}

namespace chronik::native::lotus_v2::query_branches {

/** SHA-256 supplied by the host (the core has none of its own). */
using Sha256Fn = std::function<void(ByteView data, uint8_t out[32])>;

/** Roots accepted at one public branch position. */
struct PositionClause {
    uint8_t position = 0;
    std::vector<Hash32> roots;
    bool operator==(const PositionClause &) const = default;
};

/** QueryError: filter, capacity, snapshot or source failure. */
class QueryError : public std::runtime_error {
public:
    enum class Kind {
        InvalidFilter,
        InvalidLimits,
        StaleCursor,
        Source,
        RecordTooLarge,
    };
    explicit QueryError(Kind kind, std::string_view source = {})
        : std::runtime_error(DebugString(kind, source)), m_kind(kind),
          m_source(source) {}
    static QueryError Source(std::string_view what) {
        return QueryError(Kind::Source, what);
    }
    Kind kind() const { return m_kind; }
    const std::string &source() const { return m_source; }
    /** Rust `{:?}`, e.g. `InvalidFilter` or `Source("DB posting")`. */
    std::string Debug() const { return what(); }

private:
    static std::string DebugString(Kind kind, std::string_view source);
    Kind m_kind;
    std::string m_source;
};

/** Trusted per-request allocation and per-page read/result caps. */
struct Limits {
    size_t roots = 256;
    size_t clauses = 16;
    size_t page_size = 100;
    size_t posting_reads = 4096;
    size_t work = 8192;
    size_t result_bytes = 128 * 1024;
};

/** Confirmed output selection and burn policy. */
struct QueryKind {
    /** Utxos (burns always excluded) or History. */
    bool utxos = false;
    /** History only: whether burns are included. */
    bool include_burn = false;
    static QueryKind Utxos() { return {true, false}; }
    static QueryKind History(bool include_burn) { return {false, include_burn}; }
    bool operator==(const QueryKind &) const = default;
};

/** OR within selectors and AND across position clauses, on one output. */
struct BranchFilter {
    std::vector<Hash32> any_branch;
    std::vector<PositionClause> positions;
    bool operator==(const BranchFilter &) const = default;

    /** Bounds are checked before sorting/copying; throws InvalidFilter. */
    BranchFilter Canonicalize(const Limits &limits) const;
    bool Matches(const Output &output) const;
    /** SHA256 commitment of the canonical filter and query kind. */
    Hash32 Digest(QueryKind kind, const Limits &limits,
                  const Sha256Fn &sha256) const;
};

/** Immutable indexed chain and profile identity anchoring reads. */
struct Snapshot {
    Hash32 chain_id;
    Hash32 profile_id;
    Hash32 tip;
    uint64_t height = 0;
    bool operator==(const Snapshot &) const = default;
};

/** Fixed-size, typed continuation. */
struct Cursor {
    uint8_t version = 1;
    Snapshot snapshot;
    Hash32 filter_digest;
    std::optional<OutPoint> last_key;
    bool operator==(const Cursor &) const = default;
};

/**
 * Bounded posting reads on one immutable snapshot. Implementations throw
 * QueryError for source failures.
 */
class PostingSource {
public:
    virtual ~PostingSource() = default;
    virtual Snapshot GetSnapshot() const = 0;
    /** Smallest matching outpoint strictly after `after`. */
    virtual std::optional<OutPoint>
    NextPosting(const Hash32 &root, std::optional<uint8_t> position,
                std::optional<OutPoint> after) const = 0;
    /** At most one bounded native record. */
    virtual std::optional<OutputRecord> GetOutput(const OutPoint &key) const = 0;
};

/** The V2 DB snapshot as a posting source (chronik-lib v2.rs `Source`). */
class SnapshotPostingSource final : public PostingSource {
public:
    explicit SnapshotPostingSource(const ReadSnapshot &snapshot)
        : m_snapshot(snapshot) {}
    Snapshot GetSnapshot() const override;
    std::optional<OutPoint>
    NextPosting(const Hash32 &root, std::optional<uint8_t> position,
                std::optional<OutPoint> after) const override;
    std::optional<OutputRecord> GetOutput(const OutPoint &key) const override;

private:
    const ReadSnapshot &m_snapshot;
};

/** One matching output and the public positions satisfying selectors. */
struct Match {
    OutputRecord record;
    std::vector<uint8_t> matching_positions;
};

/** A page of complete output records, each outpoint at most once. */
struct Page {
    Snapshot snapshot;
    std::vector<Match> matches;
    /** Resume token when capacity ended this page; absent at posting end. */
    std::optional<Cursor> continuation;
    size_t posting_reads = 0;
    size_t work = 0;
    size_t result_bytes = 0;
};

/** Fetch one bounded page; throws QueryError. */
Page Query(const PostingSource &source, const BranchFilter &filter,
           QueryKind kind, const Limits &limits,
           const std::optional<Cursor> &cursor, const Sha256Fn &sha256);

} // namespace chronik::native::lotus_v2::query_branches

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_QUERY_BRANCHES_H
