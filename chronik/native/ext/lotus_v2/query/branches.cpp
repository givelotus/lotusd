// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/query/branches.h>

#include <ext/lotus_v2/db/branch.h>

#include <algorithm>

namespace chronik::native::lotus_v2::query_branches {

std::string QueryError::DebugString(Kind kind, std::string_view source) {
    switch (kind) {
        case Kind::InvalidFilter:
            return "InvalidFilter";
        case Kind::InvalidLimits:
            return "InvalidLimits";
        case Kind::StaleCursor:
            return "StaleCursor";
        case Kind::Source:
            return "Source(\"" + std::string(source) + "\")";
        case Kind::RecordTooLarge:
            return "RecordTooLarge";
    }
    return "";
}

BranchFilter BranchFilter::Canonicalize(const Limits &limits) const {
    if (positions.size() > limits.clauses || positions.size() > 16) {
        throw QueryError(QueryError::Kind::InvalidFilter);
    }
    size_t count = any_branch.size();
    for (const PositionClause &c : positions) {
        count += c.roots.size();
    }
    if (count == 0 || count > limits.roots) {
        throw QueryError(QueryError::Kind::InvalidFilter);
    }
    bool seen[16] = {};
    for (const PositionClause &c : positions) {
        if (c.position >= 16 || c.roots.empty() || seen[c.position]) {
            throw QueryError(QueryError::Kind::InvalidFilter);
        }
        seen[c.position] = true;
    }
    BranchFilter f = *this;
    auto sort_dedup = [](std::vector<Hash32> &roots) {
        std::sort(roots.begin(), roots.end());
        roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    };
    sort_dedup(f.any_branch);
    for (PositionClause &c : f.positions) {
        sort_dedup(c.roots);
    }
    std::sort(f.positions.begin(), f.positions.end(),
              [](const PositionClause &a, const PositionClause &b) {
                  return a.position < b.position;
              });
    return f;
}

bool BranchFilter::Matches(const Output &output) const {
    auto contains = [](const std::vector<Hash32> &v, const Hash32 &r) {
        return std::find(v.begin(), v.end(), r) != v.end();
    };
    if (!any_branch.empty() &&
        std::none_of(output.branches.begin(), output.branches.end(),
                     [&](const Hash32 &r) { return contains(any_branch, r); })) {
        return false;
    }
    return std::all_of(positions.begin(), positions.end(),
                       [&](const PositionClause &c) {
                           return c.position < output.branches.size() &&
                                  contains(c.roots,
                                           output.branches[c.position]);
                       });
}

Hash32 BranchFilter::Digest(QueryKind kind, const Limits &limits,
                            const Sha256Fn &sha256) const {
    const BranchFilter f = Canonicalize(limits);
    static constexpr std::string_view tag{"LotusV2BranchQuery\0v1", 21};
    Bytes bytes(tag.begin(), tag.end());
    bytes.push_back(kind.utxos ? 0 : kind.include_burn ? 2 : 1);
    auto push_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            bytes.push_back(uint8_t(v >> (8 * i)));
        }
    };
    push_u64(f.any_branch.size());
    for (const Hash32 &r : f.any_branch) {
        bytes.insert(bytes.end(), r.b.begin(), r.b.end());
    }
    bytes.push_back(uint8_t(f.positions.size()));
    for (const PositionClause &c : f.positions) {
        bytes.push_back(c.position);
        push_u64(c.roots.size());
        for (const Hash32 &r : c.roots) {
            bytes.insert(bytes.end(), r.b.begin(), r.b.end());
        }
    }
    Hash32 digest;
    sha256(bytes, digest.b.data());
    return digest;
}

Snapshot SnapshotPostingSource::GetSnapshot() const {
    return Snapshot{H(m_snapshot.binding.chain_id),
                    H(m_snapshot.binding.profile),
                    H(m_snapshot.anchor.block_id), m_snapshot.anchor.height};
}

std::optional<OutPoint>
SnapshotPostingSource::NextPosting(const Hash32 &root,
                                   std::optional<uint8_t> position,
                                   std::optional<OutPoint> after) const {
    try {
        return m_snapshot.NextPosting(root, position, after);
    } catch (const V2Error &) {
        throw QueryError::Source("DB posting");
    }
}

std::optional<OutputRecord>
SnapshotPostingSource::GetOutput(const OutPoint &key) const {
    try {
        return m_snapshot.GetOutput(key);
    } catch (const V2Error &) {
        throw QueryError::Source("DB record");
    }
}

Page Query(const PostingSource &source, const BranchFilter &filter_in,
           QueryKind kind, const Limits &limits,
           const std::optional<Cursor> &cursor, const Sha256Fn &sha256) {
    const BranchFilter filter = filter_in.Canonicalize(limits);
    const Hash32 digest = filter.Digest(kind, limits, sha256);
    const Snapshot snapshot = source.GetSnapshot();
    if (cursor && (cursor->version != 1 || cursor->snapshot != snapshot ||
                   cursor->filter_digest != digest)) {
        throw QueryError(QueryError::Kind::StaleCursor);
    }
    const std::vector<Hash32> &roots = !filter.any_branch.empty()
                                           ? filter.any_branch
                                           : filter.positions[0].roots;
    const std::optional<uint8_t> position =
        !filter.any_branch.empty()
            ? std::nullopt
            : std::optional<uint8_t>(filter.positions[0].position);
    if (limits.page_size == 0 || limits.posting_reads < roots.size() ||
        limits.work < roots.size() + 1 || limits.result_bytes == 0) {
        throw QueryError(QueryError::Kind::InvalidLimits);
    }
    std::optional<OutPoint> last = cursor ? cursor->last_key : std::nullopt;
    Page page;
    page.snapshot = snapshot;
    while (true) {
        if (page.matches.size() == limits.page_size ||
            limits.posting_reads - page.posting_reads < roots.size() ||
            limits.work - page.work < roots.size() + 1) {
            break;
        }
        std::optional<OutPoint> candidate;
        for (const Hash32 &root : roots) {
            const auto key = source.NextPosting(root, position, last);
            ++page.posting_reads;
            ++page.work;
            if (key) {
                if (last && *key <= *last) {
                    throw QueryError::Source("unordered posting");
                }
                candidate = candidate ? std::min(*candidate, *key) : *key;
            }
        }
        if (!candidate) {
            return page;
        }
        const OutPoint key = *candidate;
        auto record = source.GetOutput(key);
        if (!record) {
            throw QueryError::Source("missing posting record");
        }
        ++page.work;
        if (record->outpoint != key || record->output.Validate()) {
            throw QueryError::Source("invalid posting record");
        }
        const bool eligible =
            kind.utxos ? !record->output.IsBurn() && !record->spend
                       : kind.include_burn || !record->output.IsBurn();
        if (eligible && filter.Matches(record->output)) {
            std::vector<uint8_t> matching_positions;
            const auto &branches = record->output.branches;
            for (size_t i = 0; i < branches.size(); ++i) {
                const Hash32 &r = branches[i];
                const bool any =
                    std::find(filter.any_branch.begin(),
                              filter.any_branch.end(),
                              r) != filter.any_branch.end();
                const bool pos = std::any_of(
                    filter.positions.begin(), filter.positions.end(),
                    [&](const PositionClause &c) {
                        return c.position == i &&
                               std::find(c.roots.begin(), c.roots.end(), r) !=
                                   c.roots.end();
                    });
                if (any || pos) {
                    matching_positions.push_back(uint8_t(i));
                }
            }
            const auto wire = record->output.Encode();
            if (!wire) {
                throw QueryError::Source("invalid output");
            }
            // Stable logical binary result budget: outpoint + framed output +
            // creation/spend locations + matching-position framing.
            const size_t size = 36 + wire->size() + 108 + 1 +
                                (record->spend ? 112 : 0) + 1 +
                                matching_positions.size();
            if (size > limits.result_bytes) {
                throw QueryError(QueryError::Kind::RecordTooLarge);
            }
            if (size > limits.result_bytes - page.result_bytes) {
                break;
            }
            page.result_bytes += size;
            page.matches.push_back(
                Match{std::move(*record), std::move(matching_positions)});
        }
        last = key;
    }
    page.continuation = Cursor{1, snapshot, digest, last};
    return page;
}

} // namespace chronik::native::lotus_v2::query_branches
