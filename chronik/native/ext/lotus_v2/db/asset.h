// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_DB_ASSET_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_DB_ASSET_H

#include <ext/lotus_v2/db/model.h>

#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>

/**
 * Pure native asset accounting and its index plans (port of
 * chronik-db/src/v2_asset.rs). The transition owner applies these plans in
 * its receipt/undo batch; this module never writes. The ReadSnapshot readers
 * are declared in branch.h.
 */
namespace chronik::native::lotus_v2 {

/** Maximum serialized asset record. */
inline constexpr size_t MAX_ASSET_RECORD_BYTES = 512;

/**
 * Asset facts of a consumed coin (v2_asset::SpentCoin): its flags, value and
 * token, as recorded when the coin was created.
 */
struct SpentCoin {
    OutPoint outpoint;
    uint8_t flags = 0;
    uint64_t value = 0;
    /** Zero when the output carries no token. */
    Hash32 token_id;
    bool operator==(const SpentCoin &) const = default;
    static SpentCoin FromOutput(const OutPoint &outpoint, const Output &o) {
        return SpentCoin{outpoint, o.flags, o.value, o.token_id};
    }
    bool HasToken() const { return (flags & 1) != 0; }
    bool IsBurn() const { return (flags & 2) != 0; }
    bool Valid() const {
        return (flags & ~3) == 0 && HasToken() == (token_id != Hash32{});
    }
};

/** Immutable facts resolved by the transition owner before spending. */
struct AssetTxView {
    /** Exact confirmed transaction position. */
    TxLocation location;
    /** All outputs, including native outputs, zero units, and burns. */
    std::span<const Output> outputs;
    /** Frozen prior creations; not the runtime's current UTXO view. */
    std::span<const SpentCoin> resolved_spends;
    /** One selector per mint input; duplicates must remain visible. */
    std::span<const Hash32> mint_token_ids;
};

/** total += value; Invalid("asset amount overflow") leaves total unchanged. */
void AssetAddUnits(U128 &total, uint64_t value);
/** Full token union with the positive-delta/mint bijection enforced. */
std::vector<AssetEvent> DeriveAssetEvents(const AssetTxView &view);
/** Conservative reservation for this module's maps and writes. */
size_t PreflightAssetTx(const AssetTxView &view);

Bytes AssetSummaryKey(const Hash32 &token);
Bytes AssetEventKey(const Hash32 &token, const TxLocation &location);
Bytes AssetOutputKey(const Hash32 &token, const TxLocation &location,
                     uint32_t out_idx);

/** Bounded asset record codec (512 bytes): Invalid("asset record limit"). */
template <typename T> Bytes AssetEncode(const T &value) {
    Bytes bytes = codec::Encode(value);
    if (bytes.size() > MAX_ASSET_RECORD_BYTES) {
        ThrowInvalid("asset record limit");
    }
    return bytes;
}
template <typename T> T AssetDecode(ByteView bytes) {
    if (bytes.size() > MAX_ASSET_RECORD_BYTES) {
        ThrowCorrupt();
    }
    return codec::Decode<T>(bytes);
}

Bytes EncodeAssetSummary(const AssetSummary &summary);
/** Rejects a zero token or zero event count as Corrupt. */
AssetSummary DecodeAssetSummary(ByteView bytes);

using OldAssetSummaries = std::map<Hash32, std::optional<AssetSummary>>;
/** Pure complete write plan; old summaries must come from staged state. */
std::vector<std::pair<Bytes, Bytes>>
PlanAssetTx(const AssetTxView &view, const OldAssetSummaries &old);

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_DB_ASSET_H
