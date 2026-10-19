// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/db/asset.h>

#include <ext/lotus_v2/db/branch.h>

#include <algorithm>
#include <set>
#include <tuple>

namespace chronik::native::lotus_v2 {

namespace {

void PushBe(Bytes &k, uint64_t v, int bytes) {
    for (int i = bytes - 1; i >= 0; --i) {
        k.push_back(uint8_t(v >> (8 * i)));
    }
}

uint64_t BeU64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = v << 8 | p[i];
    }
    return v;
}

U128 SaturatingSub(U128 a, U128 b) { return a > b ? a - b : 0; }

} // namespace

void AssetAddUnits(U128 &total, uint64_t value) {
    const U128 max = ~U128(0);
    if (max - total < value) {
        ThrowInvalid("asset amount overflow");
    }
    total += value;
}

size_t PreflightAssetTx(const AssetTxView &view) {
    const size_t count = view.outputs.size() + view.resolved_spends.size() +
                         view.mint_token_ids.size();
    if (count > MAX_BATCH_BYTES / 4096) {
        ThrowInvalid("asset capacity");
    }
    return count * 4096;
}

std::vector<AssetEvent> DeriveAssetEvents(const AssetTxView &view) {
    PreflightAssetTx(view);
    // token -> (spent, output, explicit burn)
    std::map<Hash32, std::tuple<U128, U128, U128>> totals;
    std::set<OutPoint> spent;
    for (const ResolvedCreation &coin : view.resolved_spends) {
        if (!spent.insert(coin.outpoint).second || coin.output.IsBurn()) {
            ThrowInvalid("duplicate or burned asset spend");
        }
        if (coin.output.Validate()) {
            ThrowInvalid("asset spend output");
        }
        if (coin.output.HasToken()) {
            AssetAddUnits(std::get<0>(totals[coin.output.token_id]),
                          coin.output.value);
        }
    }
    for (const Output &output : view.outputs) {
        if (output.Validate()) {
            ThrowInvalid("asset output");
        }
        if (output.HasToken()) {
            auto &total = totals[output.token_id];
            AssetAddUnits(std::get<1>(total), output.value);
            if (output.IsBurn()) {
                AssetAddUnits(std::get<2>(total), output.value);
            }
        }
    }
    std::set<Hash32> mints;
    for (const Hash32 &token : view.mint_token_ids) {
        if (token == Hash32{} || !mints.insert(token).second) {
            ThrowInvalid("duplicate or zero asset mint selector");
        }
        totals[token];
    }
    std::vector<AssetEvent> events;
    for (const auto &[token_id, total] : totals) {
        const auto &[spent_units, output_units, explicit_burn_units] = total;
        const U128 minted_units = SaturatingSub(output_units, spent_units);
        const bool has_mint_input = mints.count(token_id) > 0;
        if ((minted_units > 0) != has_mint_input) {
            ThrowInvalid("asset mint/delta mismatch");
        }
        events.push_back(AssetEvent{
            token_id, view.location, spent_units, output_units,
            explicit_burn_units, minted_units,
            SaturatingSub(spent_units, output_units), has_mint_input});
    }
    return events;
}

Bytes AssetSummaryKey(const Hash32 &token) {
    Bytes k{'e', 'A'};
    k.insert(k.end(), token.b.begin(), token.b.end());
    return k;
}

Bytes AssetEventKey(const Hash32 &token, const TxLocation &location) {
    Bytes k{'e', 'E'};
    k.insert(k.end(), token.b.begin(), token.b.end());
    PushBe(k, location.height, 8);
    PushBe(k, location.tx_index, 4);
    return k;
}

Bytes AssetOutputKey(const Hash32 &token, const TxLocation &location,
                     uint32_t out_idx) {
    Bytes k{'e', 'P'};
    k.insert(k.end(), token.b.begin(), token.b.end());
    PushBe(k, location.height, 8);
    PushBe(k, location.tx_index, 4);
    PushBe(k, out_idx, 4);
    return k;
}

Bytes EncodeAssetSummary(const AssetSummary &summary) {
    return AssetEncode(summary);
}

AssetSummary DecodeAssetSummary(ByteView bytes) {
    auto summary = AssetDecode<AssetSummary>(bytes);
    if (summary.token_id == Hash32{} || summary.event_count == 0) {
        ThrowCorrupt();
    }
    return summary;
}

std::vector<std::pair<Bytes, Bytes>>
PlanAssetTx(const AssetTxView &view, const OldAssetSummaries &old) {
    PreflightAssetTx(view);
    const auto events = DeriveAssetEvents(view);
    std::vector<std::pair<Bytes, Bytes>> writes;
    std::map<Hash32, uint64_t> counts;
    for (const Output &output : view.outputs) {
        if (!output.HasToken()) {
            continue;
        }
        uint64_t &count = counts[output.token_id];
        if (count == UINT64_MAX) {
            ThrowInvalid("asset output count");
        }
        ++count;
    }
    for (const AssetEvent &event : events) {
        const auto it_count = counts.find(event.token_id);
        const uint64_t count = it_count == counts.end() ? 0 : it_count->second;
        const auto it = old.find(event.token_id);
        if (it == old.end()) {
            ThrowInvalid("missing old asset summary");
        }
        AssetSummary summary;
        if (const auto &s = it->second) {
            if (s->token_id != event.token_id || s->event_count == 0 ||
                std::make_pair(s->first_seen.height, s->first_seen.tx_index) >
                    std::make_pair(view.location.height,
                                   view.location.tx_index)) {
                ThrowCorrupt();
            }
            if (s->event_count == UINT64_MAX) {
                ThrowInvalid("asset event count overflow");
            }
            if (s->output_count > UINT64_MAX - count) {
                ThrowInvalid("asset output count overflow");
            }
            summary = *s;
            summary.event_count = s->event_count + 1;
            summary.output_count = s->output_count + count;
        } else {
            summary = AssetSummary{event.token_id, view.location, 1, count};
        }
        writes.emplace_back(AssetSummaryKey(event.token_id),
                            AssetEncode(summary));
        writes.emplace_back(AssetEventKey(event.token_id, view.location),
                            AssetEncode(event));
    }
    for (size_t index = 0; index < view.outputs.size(); ++index) {
        const Output &output = view.outputs[index];
        if (!output.HasToken()) {
            continue;
        }
        if (index > UINT32_MAX) {
            ThrowInvalid("asset output ordinal");
        }
        Bytes op(view.location.txid.hash.b.begin(),
                 view.location.txid.hash.b.end());
        PushBe(op, index, 4);
        writes.emplace_back(
            AssetOutputKey(output.token_id, view.location, uint32_t(index)),
            std::move(op));
    }
    return writes;
}

// ---- ReadSnapshot asset readers ----

void ReadSnapshot::AssetCanonicalLocation(const TxLocation &location,
                                          AssetReadBudget &budget) const {
    if (TransactionCounted(location.txid, budget) != location) {
        ThrowCorrupt();
    }
}

std::optional<AssetSummary>
ReadSnapshot::GetAssetSummary(const Hash32 &token) const {
    AssetReadBudget budget(SIZE_MAX);
    return AssetSummaryCounted(token, budget);
}

std::optional<AssetSummary>
ReadSnapshot::AssetSummaryCounted(const Hash32 &token,
                                  AssetReadBudget &budget) const {
    budget.Charge();
    const auto bytes = m_inner.Get(AssetSummaryKey(token));
    if (!bytes) {
        return std::nullopt;
    }
    const auto s = AssetDecode<AssetSummary>(*bytes);
    if (token == Hash32{} || s.token_id != token || s.event_count == 0 ||
        s.first_seen.height > anchor.height) {
        ThrowCorrupt();
    }
    AssetCanonicalLocation(s.first_seen, budget);
    return s;
}

std::optional<std::pair<Bytes, Bytes>>
ReadSnapshot::NextAssetRaw(ByteView prefix, size_t key_len,
                           std::optional<ByteView> after,
                           AssetReadBudget &budget) const {
    if (after && (after->size() != key_len ||
                  !std::equal(prefix.begin(), prefix.end(), after->begin()))) {
        ThrowInvalid("asset cursor key");
    }
    auto item =
        m_inner.SeekNextRegular(prefix, after, [&] { budget.Charge(); });
    if (!item) {
        return std::nullopt;
    }
    if (item->first.size() != key_len ||
        item->second.size() > MAX_ASSET_RECORD_BYTES) {
        ThrowCorrupt();
    }
    return item;
}

std::optional<std::pair<Bytes, AssetSummary>>
ReadSnapshot::NextAssetSummary(std::optional<ByteView> after) const {
    AssetReadBudget budget(SIZE_MAX);
    return NextAssetSummaryCounted(after, budget);
}

std::optional<std::pair<Bytes, AssetSummary>>
ReadSnapshot::NextAssetSummaryCounted(std::optional<ByteView> after,
                                      AssetReadBudget &budget) const {
    static const uint8_t prefix[] = {'e', 'A'};
    auto item = NextAssetRaw(prefix, 34, after, budget);
    if (!item) {
        return std::nullopt;
    }
    const auto s = AssetDecode<AssetSummary>(item->second);
    if (s.token_id == Hash32{} ||
        !std::equal(s.token_id.b.begin(), s.token_id.b.end(),
                    item->first.begin() + 2) ||
        s.event_count == 0 || s.first_seen.height > anchor.height) {
        ThrowCorrupt();
    }
    AssetCanonicalLocation(s.first_seen, budget);
    return std::make_pair(std::move(item->first), s);
}

std::optional<std::pair<Bytes, AssetEvent>>
ReadSnapshot::NextAssetEvent(const Hash32 &token,
                             std::optional<ByteView> after) const {
    AssetReadBudget budget(SIZE_MAX);
    return NextAssetEventCounted(token, after, budget);
}

std::optional<std::pair<Bytes, AssetEvent>>
ReadSnapshot::NextAssetEventCounted(const Hash32 &token,
                                    std::optional<ByteView> after,
                                    AssetReadBudget &budget) const {
    Bytes prefix{'e', 'E'};
    prefix.insert(prefix.end(), token.b.begin(), token.b.end());
    auto item = NextAssetRaw(prefix, 46, after, budget);
    if (!item) {
        return std::nullopt;
    }
    const auto e = AssetDecode<AssetEvent>(item->second);
    if (token == Hash32{} || e.token_id != token ||
        item->first != AssetEventKey(token, e.location) ||
        e.location.height > anchor.height ||
        e.explicit_burn_units > e.output_units ||
        e.minted_units != SaturatingSub(e.output_units, e.spent_units) ||
        e.implicit_burn_units != SaturatingSub(e.spent_units, e.output_units) ||
        e.has_mint_input != (e.minted_units > 0)) {
        ThrowCorrupt();
    }
    AssetCanonicalLocation(e.location, budget);
    return std::make_pair(std::move(item->first), e);
}

std::optional<std::pair<Bytes, OutPoint>>
ReadSnapshot::NextAssetOutput(const Hash32 &token,
                              std::optional<ByteView> after) const {
    AssetReadBudget budget(SIZE_MAX);
    return NextAssetOutputCounted(token, after, budget);
}

std::optional<std::pair<Bytes, OutPoint>>
ReadSnapshot::NextAssetOutputCounted(const Hash32 &token,
                                     std::optional<ByteView> after,
                                     AssetReadBudget &budget) const {
    Bytes prefix{'e', 'P'};
    prefix.insert(prefix.end(), token.b.begin(), token.b.end());
    auto item = NextAssetRaw(prefix, 50, after, budget);
    if (!item) {
        return std::nullopt;
    }
    const Bytes &key = item->first;
    const Bytes &bytes = item->second;
    if (token == Hash32{} || bytes.size() != 36 ||
        !std::equal(bytes.begin() + 32, bytes.end(), key.begin() + 46) ||
        BeU64(key.data() + 34) > anchor.height) {
        ThrowCorrupt();
    }
    return std::make_pair(std::move(item->first), OutPointDecode(bytes));
}

} // namespace chronik::native::lotus_v2
