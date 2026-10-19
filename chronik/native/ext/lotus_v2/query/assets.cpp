// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/query/assets.h>

#include <ext/lotus_v2/db/asset.h>
#include <ext/lotus_v2/db/branch.h>

#include <algorithm>
#include <functional>

namespace chronik::native::lotus_v2::query_assets {

const char *Error::Name(Kind kind) {
    switch (kind) {
        case Kind::InvalidLimits:
            return "InvalidLimits";
        case Kind::InvalidCursor:
            return "InvalidCursor";
        case Kind::Source:
            return "Source";
        case Kind::RecordLimit:
            return "RecordLimit";
    }
    return "";
}

namespace {

template <typename F> auto AsSource(F &&f) -> decltype(f()) {
    try {
        return f();
    } catch (const V2Error &) {
        throw Error(Error::Kind::Source);
    }
}

bool StartsWith(ByteView bytes, ByteView prefix) {
    return bytes.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), bytes.begin());
}

void Validate(const Limits &limits, ByteView prefix, size_t len,
              std::optional<ByteView> after, size_t calls) {
    if (limits.page_size == 0 || limits.page_size > 100 ||
        limits.examined == 0 || limits.examined > 1024 ||
        limits.reads < calls || limits.reads > 4096 ||
        limits.result_bytes == 0) {
        throw Error(Error::Kind::InvalidLimits);
    }
    if (after && (after->size() != len || !StartsWith(*after, prefix))) {
        throw Error(Error::Kind::InvalidCursor);
    }
}

template <typename T>
using NextFn = std::function<std::optional<std::pair<Bytes, std::optional<T>>>(
    std::optional<ByteView>, AssetReadBudget &)>;

template <typename T>
Page<T> RunPage(ByteView prefix, size_t key_len, std::optional<ByteView> after,
                const Limits &limits, size_t calls, size_t record_bytes,
                const NextFn<T> &next) {
    Validate(limits, prefix, key_len, after, calls);
    Page<T> page;
    if (after) {
        page.next_key = Bytes(after->begin(), after->end());
    }
    size_t bytes = 0;
    AssetReadBudget budget(limits.reads);
    while (true) {
        if (page.items.size() == limits.page_size ||
            page.examined == limits.examined || budget.Remaining() < calls) {
            return page;
        }
        // Reserve the indivisible joined record before reading. If a prior
        // page item consumed capacity, resume after it without another read.
        if (limits.result_bytes - bytes < record_bytes) {
            if (page.items.empty()) {
                throw Error(Error::Kind::RecordLimit);
            }
            return page;
        }
        std::optional<ByteView> cur;
        if (page.next_key) {
            cur = ByteView(*page.next_key);
        }
        auto item = next(cur, budget);
        page.reads = budget.Reads();
        if (!item) {
            page.next_key.reset();
            page.exhausted = true;
            return page;
        }
        auto &[key, value] = *item;
        if (key.size() != key_len || !StartsWith(key, prefix) ||
            (page.next_key && key <= *page.next_key)) {
            throw Error(Error::Kind::Source);
        }
        ++page.examined;
        page.next_key = std::move(key);
        if (value) {
            bytes += record_bytes;
            page.items.push_back(std::move(*value));
        }
    }
}

Bytes TokenPrefix(char family, const Hash32 &token) {
    Bytes prefix{'e', uint8_t(family)};
    prefix.insert(prefix.end(), token.b.begin(), token.b.end());
    return prefix;
}

} // namespace

std::optional<std::pair<Bytes, AssetSummary>>
SnapshotAssetSource::Summary(std::optional<ByteView> after,
                             AssetReadBudget &budget) const {
    return AsSource([&] { return m_s.NextAssetSummaryCounted(after, budget); });
}

std::optional<std::pair<Bytes, AssetEvent>>
SnapshotAssetSource::Event(const Hash32 &token, std::optional<ByteView> after,
                           AssetReadBudget &budget) const {
    return AsSource(
        [&] { return m_s.NextAssetEventCounted(token, after, budget); });
}

std::optional<std::pair<Bytes, OutPoint>>
SnapshotAssetSource::Posting(const Hash32 &token,
                             std::optional<ByteView> after,
                             AssetReadBudget &budget) const {
    return AsSource(
        [&] { return m_s.NextAssetOutputCounted(token, after, budget); });
}

std::optional<OutputRecord>
SnapshotAssetSource::GetOutput(const OutPoint &op,
                               AssetReadBudget &budget) const {
    return AsSource([&] { return m_s.OutputCounted(op, budget); });
}

Page<AssetSummary> Assets(const Source &source, std::optional<ByteView> after,
                          const Limits &limits) {
    static const uint8_t prefix[] = {'e', 'A'};
    return RunPage<AssetSummary>(
        prefix, 34, after, limits, 4, 512,
        [&](std::optional<ByteView> a, AssetReadBudget &budget)
            -> std::optional<std::pair<Bytes, std::optional<AssetSummary>>> {
            auto item = source.Summary(a, budget);
            if (!item) {
                return std::nullopt;
            }
            return std::make_pair(std::move(item->first),
                                  std::optional<AssetSummary>(item->second));
        });
}

Page<AssetEvent> Events(const Source &source, const Hash32 &token,
                        std::optional<ByteView> after, const Limits &limits) {
    const Bytes prefix = TokenPrefix('E', token);
    return RunPage<AssetEvent>(
        prefix, 46, after, limits, 4, 512,
        [&](std::optional<ByteView> a, AssetReadBudget &budget)
            -> std::optional<std::pair<Bytes, std::optional<AssetEvent>>> {
            auto item = source.Event(token, a, budget);
            if (!item) {
                return std::nullopt;
            }
            return std::make_pair(std::move(item->first),
                                  std::optional<AssetEvent>(item->second));
        });
}

Page<OutputRecord> Outputs(const Source &source, const Hash32 &token,
                           bool unspent, std::optional<ByteView> after,
                           const Limits &limits) {
    const Bytes prefix = TokenPrefix('P', token);
    return RunPage<OutputRecord>(
        prefix, 50, after, limits, 7, 2048,
        [&](std::optional<ByteView> a, AssetReadBudget &budget)
            -> std::optional<std::pair<Bytes, std::optional<OutputRecord>>> {
            auto posting = source.Posting(token, a, budget);
            if (!posting) {
                return std::nullopt;
            }
            auto &[key, op] = *posting;
            auto record = source.GetOutput(op, budget);
            if (!record) {
                throw Error(Error::Kind::Source);
            }
            if (record->outpoint != op || !record->output.HasToken() ||
                record->output.token_id != token ||
                key != AssetOutputKey(token, record->creation, op.out_idx) ||
                record->creation.txid != op.txid) {
                throw Error(Error::Kind::Source);
            }
            const bool include =
                !unspent || (!record->spend && !record->output.IsBurn());
            return std::make_pair(
                std::move(key),
                include ? std::move(record) : std::optional<OutputRecord>());
        });
}

} // namespace chronik::native::lotus_v2::query_assets
