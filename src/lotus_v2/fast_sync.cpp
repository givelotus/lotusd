// Copyright (c) 2026 The Lotus developers
// Tachyon SnapSync: Fast UTXO Shard Sync protocol, Avalanche state-anchor
// verification, and bijective reverse block peeling without header changes.
#include "fast_sync.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <set>

namespace lotus::v2 {
namespace {

bool KeyBitAt(const Hash &key, uint8_t depth) {
    return ((key[depth / 8] >> (depth % 8)) & 1u) != 0;
}

void WriteLE16(std::vector<uint8_t> &out, uint16_t val) {
    out.push_back(static_cast<uint8_t>(val & 0xFFu));
    out.push_back(static_cast<uint8_t>((val >> 8) & 0xFFu));
}

void WriteLE64(std::vector<uint8_t> &out, uint64_t val) {
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xFFu));
    }
}

uint16_t ReadLE16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint64_t ReadLE64(const uint8_t *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    }
    return v;
}

void WriteCompactSize(std::vector<uint8_t> &out, uint64_t n) {
    if (n < 253) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xFFFFu) {
        out.push_back(253);
        WriteLE16(out, static_cast<uint16_t>(n));
    } else {
        out.push_back(254);
        for (unsigned i = 0; i < 4; ++i) {
            out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFFu));
        }
    }
}

bool ReadCompactSize(const std::vector<uint8_t> &bytes, size_t &offset,
                     uint64_t max_val, uint64_t &out) {
    if (offset >= bytes.size()) return false;
    const uint8_t lead = bytes[offset++];
    if (lead < 253) {
        out = lead;
    } else if (lead == 253) {
        if (bytes.size() - offset < 2) return false;
        out = ReadLE16(bytes.data() + offset);
        offset += 2;
        if (out < 253) return false;
    } else if (lead == 254) {
        if (bytes.size() - offset < 4) return false;
        uint64_t v = 0;
        for (unsigned i = 0; i < 4; ++i) {
            v |= static_cast<uint64_t>(bytes[offset + i]) << (8 * i);
        }
        offset += 4;
        if (v < 0x10000ULL) return false;
        out = v;
    } else {
        if (bytes.size() - offset < 8) return false;
        out = ReadLE64(bytes.data() + offset);
        offset += 8;
        if (out < 0x100000000ULL) return false;
    }
    return out <= max_val;
}

bool DecodeCanonicalCoinBytes(const uint8_t *data, size_t len, Coin &out,
                              std::string &error) {
    if (!DecodeCoinBytes(std::span<const uint8_t>(data, len), out)) {
        error = "non-canonical coin encoding";
        return false;
    }
    error.clear();
    return true;
}

struct KeyedCoinRef {
    Hash key{};
    const Coin *coin = nullptr;
};

bool ComputeSubtreeEntry(const std::vector<KeyedCoinRef> &entries,
                         unsigned depth, ShardRootEntry &out) {
    if (entries.empty()) {
        out = {0, EmptyUtxoRoot()};
        return true;
    }
    if (entries.size() == 1) {
        out.cardinality_tag = 1;
        return UtxoLeaf(*entries[0].coin, out.subtree_root);
    }
    if (depth >= 256) {
        return false;
    }
    std::vector<KeyedCoinRef> left;
    std::vector<KeyedCoinRef> right;
    left.reserve(entries.size());
    right.reserve(entries.size());
    for (const auto &entry : entries) {
        if (KeyBitAt(entry.key, static_cast<uint8_t>(depth))) {
            right.push_back(entry);
        } else {
            left.push_back(entry);
        }
    }
    ShardRootEntry left_entry, right_entry;
    if (!ComputeSubtreeEntry(left, depth + 1, left_entry) ||
        !ComputeSubtreeEntry(right, depth + 1, right_entry)) {
        return false;
    }
    return FoldShardPair(static_cast<uint8_t>(depth), left_entry, right_entry,
                         out);
}

bool SplitAndExportShardsRecursive(
    const UtxoSet &utxo, const Hash &pivot_block_id,
    const std::vector<KeyedCoinRef> &entries, uint8_t depth,
    uint16_t prefix_bits, size_t max_shard_leaves,
    std::vector<UtxoShardMessage> &out, std::string &error) {
    if (entries.empty()) {
        return true;
    }
    if (entries.size() <= max_shard_leaves) {
        UtxoShardMessage msg;
        if (!ExportUtxoShard(utxo, pivot_block_id, depth, prefix_bits, msg,
                             error, max_shard_leaves)) {
            return false;
        }
        out.push_back(std::move(msg));
        return true;
    }
    if (depth >= kMaxUtxoShardPrefixDepth) {
        error = "sub-shard at maximum depth 16 still exceeds leaf limit";
        return false;
    }
    std::vector<KeyedCoinRef> left;
    std::vector<KeyedCoinRef> right;
    for (const auto &e : entries) {
        if (KeyBitAt(e.key, depth)) {
            right.push_back(e);
        } else {
            left.push_back(e);
        }
    }
    const uint16_t left_prefix = prefix_bits;
    const uint16_t right_prefix =
        static_cast<uint16_t>(prefix_bits | (uint16_t{1} << depth));
    return SplitAndExportShardsRecursive(utxo, pivot_block_id, left,
                                         static_cast<uint8_t>(depth + 1),
                                         left_prefix, max_shard_leaves, out,
                                         error) &&
           SplitAndExportShardsRecursive(utxo, pivot_block_id, right,
                                         static_cast<uint8_t>(depth + 1),
                                         right_prefix, max_shard_leaves, out,
                                         error);
}

} // namespace

bool CheckFastSyncPivotEligibility(const FastSyncPivotCandidate &candidate,
                                   std::string &error) {
    if (!candidate.has_minimum_chain_work) {
        error = "pivot does not meet minimum chain work";
        return false;
    }
    if (candidate.pivot_height > candidate.best_header_height) {
        error = "pivot height exceeds best header height";
        return false;
    }
    if (!candidate.is_avalanche_finalized) {
        if (candidate.buried_blocks < kFastSyncMinBuriedBlocks ||
            candidate.distinct_netgroup_confirmations <
                kFastSyncMinNetgroupConfirmations) {
            error = "unfinalized pivot lacks 100 buried blocks across >= 3 distinct netgroups";
            return false;
        }
        if (candidate.best_header_height - candidate.pivot_height <
            kFastSyncPivotSafetyCushion) {
            error = "unfinalized pivot violates 10-block safety cushion below tip";
            return false;
        }
    }
    error.clear();
    return true;
}

uint16_t OutpointPrefixBits(const Hash &outpoint_key, uint8_t prefix_depth) {
    uint16_t bits = 0;
    const uint8_t limit = std::min<uint8_t>(prefix_depth, 16);
    for (uint8_t d = 0; d < limit; ++d) {
        if (KeyBitAt(outpoint_key, d)) {
            bits |= static_cast<uint16_t>(uint16_t{1} << d);
        }
    }
    return bits;
}

bool IsValidShardRootEntry(const ShardRootEntry &entry) {
    if (entry.cardinality_tag > 2) return false;
    if (entry.cardinality_tag == 0) {
        return entry.subtree_root == EmptyUtxoRoot();
    }
    return entry.subtree_root != EmptyUtxoRoot();
}

bool FoldShardPair(uint8_t depth, const ShardRootEntry &left,
                   const ShardRootEntry &right, ShardRootEntry &out) {
    if (!IsValidShardRootEntry(left) || !IsValidShardRootEntry(right)) {
        return false;
    }
    if (left.cardinality_tag == 0 && right.cardinality_tag == 0) {
        out = {0, EmptyUtxoRoot()};
        return true;
    }
    if (left.cardinality_tag == 1 && right.cardinality_tag == 0) {
        out = {1, left.subtree_root};
        return true;
    }
    if (left.cardinality_tag == 0 && right.cardinality_tag == 1) {
        out = {1, right.subtree_root};
        return true;
    }
    out.cardinality_tag = 2;
    return UtxoNode(depth, left.subtree_root, right.subtree_root,
                    out.subtree_root);
}

std::optional<Hash> FoldDepth8ShardRoots(
    const std::array<ShardRootEntry, kFastSyncShardCount> &shards,
    std::string *error) {
    for (size_t i = 0; i < shards.size(); ++i) {
        if (!IsValidShardRootEntry(shards[i])) {
            if (error) {
                *error = "invalid shard root entry tag or empty digest mismatch";
            }
            return std::nullopt;
        }
    }
    std::vector<ShardRootEntry> current(shards.begin(), shards.end());
    for (int d = 7; d >= 0; --d) {
        const size_t half = static_cast<size_t>(1u << d);
        std::vector<ShardRootEntry> next(half);
        for (size_t prefix = 0; prefix < half; ++prefix) {
            const ShardRootEntry &left = current[prefix];
            const ShardRootEntry &right = current[prefix | half];
            FoldShardPair(static_cast<uint8_t>(d), left, right, next[prefix]);
        }
        current = std::move(next);
    }
    if (error) error->clear();
    return current[0].subtree_root;
}

bool VerifyUtxoRootsAgainstAnchor(
    const Hash &expected_pivot_block_id, uint64_t expected_height,
    const std::optional<Hash> &expected_utxo_root_anchor,
    const UtxoRootsMessage &msg, Hash &out_folded_utxo_root,
    std::string &error) {
    if (msg.pivot_block_id != expected_pivot_block_id) {
        error = "utxoroots pivot_block_id does not match expected pivot block";
        return false;
    }
    if (msg.height != expected_height) {
        error = "utxoroots height does not match expected pivot height";
        return false;
    }
    if (!expected_utxo_root_anchor.has_value()) {
        error = "missing finalized Avalanche/epoch UtxoRoot state anchor for pivot";
        return false;
    }
    try {
        (void)DecodeMonetaryState(
            std::vector<uint8_t>(msg.monetary_state.begin(),
                                 msg.monetary_state.end()));
    } catch (const std::exception &e) {
        error = std::string("invalid utxoroots monetary_state: ") + e.what();
        return false;
    }
    const auto folded_utxo_root = FoldDepth8ShardRoots(msg.shards, &error);
    if (!folded_utxo_root) {
        return false;
    }
    out_folded_utxo_root = *folded_utxo_root;
    if (*folded_utxo_root != *expected_utxo_root_anchor) {
        error =
            "utxoroots folded UtxoRoot does not match Avalanche/epoch state anchor";
        return false;
    }
    error.clear();
    return true;
}

bool VerifyAndBuildUtxoShard(const ShardRootEntry &expected_depth8_entry,
                             uint64_t pivot_height,
                             const UtxoShardMessage &shard,
                             ShardRootEntry *computed_subshard_out,
                             std::string &error) {
    if (!IsValidShardRootEntry(expected_depth8_entry)) {
        error = "invalid expected depth-8 shard root entry";
        return false;
    }
    if (shard.prefix_depth < kMinUtxoShardPrefixDepth ||
        shard.prefix_depth > kMaxUtxoShardPrefixDepth) {
        error = "utxoshard prefix_depth out of range [8..16]";
        return false;
    }
    if (shard.prefix_depth < 16 &&
        (shard.prefix_bits >> shard.prefix_depth) != 0) {
        error = "utxoshard prefix_bits has non-zero bits above prefix_depth";
        return false;
    }
    const size_t expected_siblings =
        static_cast<size_t>(shard.prefix_depth - kMinUtxoShardPrefixDepth);
    if (shard.boundary_siblings.size() != expected_siblings) {
        error =
            "utxoshard boundary_siblings length does not match prefix_depth - 8";
        return false;
    }
    if (shard.coins.size() > kMaxUtxoShardLeaves) {
        error = "utxoshard exceeds maximum allowed 4096 leaves";
        return false;
    }

    std::vector<KeyedCoinRef> keyed;
    keyed.reserve(shard.coins.size());
    Hash prev_key{};
    for (size_t i = 0; i < shard.coins.size(); ++i) {
        const Coin &coin = shard.coins[i];
        if (coin.output.IsBurn()) {
            error = "utxoshard contains unspendable burn output";
            return false;
        }
        if (coin.creation_height > pivot_height) {
            error = "utxoshard coin creation_height exceeds pivot height";
            return false;
        }
        Hash leaf_hash{};
        if (!UtxoLeaf(coin, leaf_hash)) {
            error = "utxoshard coin failed canonical UtxoLeaf validation";
            return false;
        }
        const Hash key = OutpointKey(coin.outpoint);
        if (OutpointPrefixBits(key, shard.prefix_depth) != shard.prefix_bits) {
            error = "utxoshard coin OutpointKey does not match shard prefix_bits";
            return false;
        }
        if (i > 0 && !(prev_key < key)) {
            error =
                "utxoshard coins are not in strictly ascending OutpointKey order";
            return false;
        }
        prev_key = key;
        keyed.push_back(KeyedCoinRef{key, &coin});
    }

    ShardRootEntry sub_entry{};
    ComputeSubtreeEntry(keyed, shard.prefix_depth, sub_entry);
    if (computed_subshard_out) {
        *computed_subshard_out = sub_entry;
    }

    ShardRootEntry cur = sub_entry;
    for (size_t i = 0; i < expected_siblings; ++i) {
        const uint8_t d = static_cast<uint8_t>((shard.prefix_depth - 1) - i);
        const Hash &sib_hash = shard.boundary_siblings[i];
        const bool bit_is_right = ((shard.prefix_bits >> d) & 1u) != 0;

        ShardRootEntry sib_entry{};
        if (sib_hash == EmptyUtxoRoot()) {
            sib_entry = {0, EmptyUtxoRoot()};
        } else if (cur.cardinality_tag >= 1) {
            sib_entry = {2, sib_hash};
        } else {
            bool higher_all_empty = true;
            for (size_t j = i + 1; j < expected_siblings; ++j) {
                if (shard.boundary_siblings[j] != EmptyUtxoRoot()) {
                    higher_all_empty = false;
                    break;
                }
            }
            const uint8_t inferred_tag =
                (expected_depth8_entry.cardinality_tag == 1 && higher_all_empty)
                    ? 1
                    : 2;
            sib_entry = {inferred_tag, sib_hash};
        }

        const ShardRootEntry &left = bit_is_right ? sib_entry : cur;
        const ShardRootEntry &right = bit_is_right ? cur : sib_entry;
        ShardRootEntry next{};
        FoldShardPair(d, left, right, next);
        cur = next;
    }

    if (cur != expected_depth8_entry) {
        error =
            "utxoshard folded depth-8 entry does not match authenticated ShardRootEntry";
        return false;
    }
    error.clear();
    return true;
}

std::vector<uint8_t> EncodeGetUtxoRootsRequest(const GetUtxoRootsRequest &req) {
    return std::vector<uint8_t>(req.pivot_block_id.begin(),
                                req.pivot_block_id.end());
}

bool DecodeGetUtxoRootsRequest(const std::vector<uint8_t> &bytes,
                               GetUtxoRootsRequest &out,
                               std::string &error) {
    if (bytes.size() != 32) {
        error = "invalid getutxoroots request size";
        return false;
    }
    std::copy_n(bytes.data(), 32, out.pivot_block_id.begin());
    error.clear();
    return true;
}

std::vector<uint8_t> EncodeUtxoRootsMessage(const UtxoRootsMessage &msg) {
    std::vector<uint8_t> out;
    out.reserve(32 + 8 + 56 + kFastSyncShardCount * 33);
    out.insert(out.end(), msg.pivot_block_id.begin(), msg.pivot_block_id.end());
    WriteLE64(out, msg.height);
    out.insert(out.end(), msg.monetary_state.begin(), msg.monetary_state.end());
    for (const auto &shard : msg.shards) {
        out.push_back(shard.cardinality_tag);
        out.insert(out.end(), shard.subtree_root.begin(),
                   shard.subtree_root.end());
    }
    return out;
}

bool DecodeUtxoRootsMessage(const std::vector<uint8_t> &bytes,
                            UtxoRootsMessage &out,
                            std::string &error) {
    constexpr size_t kExpectedSize = 32 + 8 + 56 + kFastSyncShardCount * 33;
    if (bytes.size() != kExpectedSize) {
        error = "invalid utxoroots message size";
        return false;
    }
    UtxoRootsMessage parsed;
    std::copy_n(bytes.data(), 32, parsed.pivot_block_id.begin());
    parsed.height = ReadLE64(bytes.data() + 32);
    std::copy_n(bytes.data() + 40, 56, parsed.monetary_state.begin());
    size_t offset = 96;
    for (size_t i = 0; i < kFastSyncShardCount; ++i) {
        parsed.shards[i].cardinality_tag = bytes[offset++];
        std::copy_n(bytes.data() + offset, 32,
                    parsed.shards[i].subtree_root.begin());
        offset += 32;
        if (!IsValidShardRootEntry(parsed.shards[i])) {
            error = "utxoroots contains invalid shard root entry";
            return false;
        }
    }
    out = parsed;
    error.clear();
    return true;
}

bool EncodeGetUtxoShardRequest(const GetUtxoShardRequest &req,
                               std::vector<uint8_t> &out,
                               std::string &error) {
    if (req.prefix_depth < kMinUtxoShardPrefixDepth ||
        req.prefix_depth > kMaxUtxoShardPrefixDepth) {
        error = "getutxoshard prefix_depth out of range [8..16]";
        return false;
    }
    if (req.prefix_depth < 16 && (req.prefix_bits >> req.prefix_depth) != 0) {
        error = "getutxoshard prefix_bits out of range for prefix_depth";
        return false;
    }
    out.clear();
    out.reserve(35);
    out.insert(out.end(), req.pivot_block_id.begin(), req.pivot_block_id.end());
    out.push_back(req.prefix_depth);
    WriteLE16(out, req.prefix_bits);
    error.clear();
    return true;
}

bool DecodeGetUtxoShardRequest(const std::vector<uint8_t> &bytes,
                               GetUtxoShardRequest &out,
                               std::string &error) {
    if (bytes.size() != 35) {
        error = "invalid getutxoshard request size";
        return false;
    }
    GetUtxoShardRequest parsed;
    std::copy_n(bytes.data(), 32, parsed.pivot_block_id.begin());
    parsed.prefix_depth = bytes[32];
    parsed.prefix_bits = ReadLE16(bytes.data() + 33);
    if (parsed.prefix_depth < kMinUtxoShardPrefixDepth ||
        parsed.prefix_depth > kMaxUtxoShardPrefixDepth) {
        error = "getutxoshard prefix_depth out of range [8..16]";
        return false;
    }
    if (parsed.prefix_depth < 16 &&
        (parsed.prefix_bits >> parsed.prefix_depth) != 0) {
        error = "getutxoshard prefix_bits out of range for prefix_depth";
        return false;
    }
    out = parsed;
    error.clear();
    return true;
}

bool EncodeUtxoShardMessage(const UtxoShardMessage &msg,
                            std::vector<uint8_t> &out,
                            std::string &error) {
    if (msg.prefix_depth < kMinUtxoShardPrefixDepth ||
        msg.prefix_depth > kMaxUtxoShardPrefixDepth) {
        error = "utxoshard prefix_depth out of range [8..16]";
        return false;
    }
    if (msg.prefix_depth < 16 && (msg.prefix_bits >> msg.prefix_depth) != 0) {
        error = "utxoshard prefix_bits out of range for prefix_depth";
        return false;
    }
    const size_t expected_siblings =
        static_cast<size_t>(msg.prefix_depth - kMinUtxoShardPrefixDepth);
    if (msg.boundary_siblings.size() != expected_siblings) {
        error = "utxoshard boundary_siblings count mismatch";
        return false;
    }
    if (msg.coins.size() > kMaxUtxoShardLeaves) {
        error = "utxoshard coins exceed 4096 limit";
        return false;
    }
    std::vector<uint8_t> buf;
    buf.reserve(35 + expected_siblings * 32 + msg.coins.size() * 64);
    buf.insert(buf.end(), msg.pivot_block_id.begin(), msg.pivot_block_id.end());
    buf.push_back(msg.prefix_depth);
    WriteLE16(buf, msg.prefix_bits);
    for (const Hash &sib : msg.boundary_siblings) {
        buf.insert(buf.end(), sib.begin(), sib.end());
    }
    WriteCompactSize(buf, msg.coins.size());
    for (const Coin &coin : msg.coins) {
        std::vector<uint8_t> encoded_coin;
        if (!EncodeCoin(coin, encoded_coin)) {
            error = "utxoshard failed to encode coin";
            return false;
        }
        WriteCompactSize(buf, encoded_coin.size());
        buf.insert(buf.end(), encoded_coin.begin(), encoded_coin.end());
    }
    out = std::move(buf);
    error.clear();
    return true;
}

bool DecodeUtxoShardMessage(const std::vector<uint8_t> &bytes,
                            UtxoShardMessage &out,
                            std::string &error) {
    if (bytes.size() < 36) {
        error = "truncated utxoshard message header";
        return false;
    }
    UtxoShardMessage parsed;
    std::copy_n(bytes.data(), 32, parsed.pivot_block_id.begin());
    parsed.prefix_depth = bytes[32];
    parsed.prefix_bits = ReadLE16(bytes.data() + 33);
    if (parsed.prefix_depth < kMinUtxoShardPrefixDepth ||
        parsed.prefix_depth > kMaxUtxoShardPrefixDepth) {
        error = "utxoshard prefix_depth out of range [8..16]";
        return false;
    }
    if (parsed.prefix_depth < 16 &&
        (parsed.prefix_bits >> parsed.prefix_depth) != 0) {
        error = "utxoshard prefix_bits out of range for prefix_depth";
        return false;
    }
    const size_t expected_siblings =
        static_cast<size_t>(parsed.prefix_depth - kMinUtxoShardPrefixDepth);
    size_t offset = 35;
    if (bytes.size() - offset < expected_siblings * 32) {
        error = "truncated utxoshard boundary_siblings";
        return false;
    }
    parsed.boundary_siblings.resize(expected_siblings);
    for (size_t i = 0; i < expected_siblings; ++i) {
        std::copy_n(bytes.data() + offset, 32,
                    parsed.boundary_siblings[i].begin());
        offset += 32;
    }
    uint64_t coin_count = 0;
    if (!ReadCompactSize(bytes, offset, kMaxUtxoShardLeaves, coin_count)) {
        error = "invalid or excessive utxoshard coin count";
        return false;
    }
    if (coin_count > (bytes.size() - offset) / 55) {
        error = "truncated utxoshard coin records"; return false;
    }
    parsed.coins.resize(static_cast<size_t>(coin_count));
    for (size_t i = 0; i < parsed.coins.size(); ++i) {
        uint64_t coin_len = 0;
        if (!ReadCompactSize(bytes, offset, MAX_COIN_BYTES, coin_len) ||
            bytes.size() - offset < coin_len) {
            error = "truncated utxoshard coin record";
            return false;
        }
        if (!DecodeCanonicalCoinBytes(bytes.data() + offset,
                                      static_cast<size_t>(coin_len),
                                      parsed.coins[i], error)) {
            return false;
        }
        offset += static_cast<size_t>(coin_len);
    }
    if (offset != bytes.size()) {
        error = "trailing bytes in utxoshard message";
        return false;
    }
    out = std::move(parsed);
    error.clear();
    return true;
}

bool ExportUtxoRootsForBlock(const UtxoSet &utxo, const Hash &pivot_block_id,
                             uint64_t pivot_height,
                             const MonetaryState &monetary,
                             UtxoRootsMessage &out, std::string &error) {
    std::array<std::vector<KeyedCoinRef>, kFastSyncShardCount> buckets;
    for (const Coin &coin : utxo.Coins()) {
        const Hash key = OutpointKey(coin.outpoint);
        const uint8_t shard_idx = key[0];
        buckets[shard_idx].push_back(KeyedCoinRef{key, &coin});
    }
    for (auto &b : buckets) {
        std::sort(b.begin(), b.end(),
                  [](const KeyedCoinRef &a, const KeyedCoinRef &c) {
                      return a.key < c.key;
                  });
    }

    UtxoRootsMessage msg;
    msg.pivot_block_id = pivot_block_id;
    msg.height = pivot_height;
    msg.monetary_state = EncodeMonetaryState(monetary);
    for (size_t s = 0; s < kFastSyncShardCount; ++s) {
        ComputeSubtreeEntry(buckets[s], kMinUtxoShardPrefixDepth,
                            msg.shards[s]);
    }

    out = msg;
    error.clear();
    return true;
}

namespace {

void PopulateDepth8FromSmt(
    const std::shared_ptr<const SmtNode> &node, uint8_t depth,
    uint16_t prefix_bits,
    std::array<ShardRootEntry, kFastSyncShardCount> &shards) {
    if (!node || node->count == 0) {
        return;
    }
    if (node->IsLeaf()) {
        const uint8_t shard_idx = node->key[0];
        shards[shard_idx] = ShardRootEntry{1, node->digest};
        return;
    }
    if (depth == kMinUtxoShardPrefixDepth) {
        shards[prefix_bits] = ShardRootEntry{
            static_cast<uint8_t>(node->count == 1 ? 1 : 2), node->digest};
        return;
    }
    if (node->child[0]) {
        PopulateDepth8FromSmt(node->child[0], depth + 1, prefix_bits, shards);
    }
    if (node->child[1]) {
        PopulateDepth8FromSmt(
            node->child[1], depth + 1,
            static_cast<uint16_t>(prefix_bits | (uint16_t(1u) << depth)),
            shards);
    }
}

void CollectSmtSubtreeCoins(const std::shared_ptr<const SmtNode> &node,
                            std::vector<KeyedCoinRef> &out) {
    if (!node || node->count == 0) {
        return;
    }
    if (node->IsLeaf()) {
        out.push_back(KeyedCoinRef{node->key, node->coin.get()});
        return;
    }
    if (node->child[0]) {
        CollectSmtSubtreeCoins(node->child[0], out);
    }
    if (node->child[1]) {
        CollectSmtSubtreeCoins(node->child[1], out);
    }
}

} // namespace

bool ExportUtxoRootsFromSmt(const std::shared_ptr<const SmtNode> &root,
                            const Hash &pivot_block_id, uint64_t pivot_height,
                            const MonetaryState &monetary,
                            UtxoRootsMessage &out, std::string &error) {
    UtxoRootsMessage msg;
    msg.pivot_block_id = pivot_block_id;
    msg.height = pivot_height;
    msg.monetary_state = EncodeMonetaryState(monetary);
    for (size_t s = 0; s < kFastSyncShardCount; ++s) {
        msg.shards[s] = ShardRootEntry{0, EmptyUtxoRoot()};
    }
    PopulateDepth8FromSmt(root, 0, 0, msg.shards);
    out = std::move(msg);
    error.clear();
    return true;
}

bool ExportUtxoShard(const UtxoSet &utxo, const Hash &pivot_block_id,
                     uint8_t prefix_depth, uint16_t prefix_bits,
                     UtxoShardMessage &out, std::string &error,
                     size_t max_shard_leaves) {
    if (prefix_depth < kMinUtxoShardPrefixDepth ||
        prefix_depth > kMaxUtxoShardPrefixDepth) {
        error = "prefix_depth out of range [8..16]";
        return false;
    }
    if (prefix_depth < 16 && (prefix_bits >> prefix_depth) != 0) {
        error = "prefix_bits has bits set above prefix_depth";
        return false;
    }

    const uint8_t depth8_idx = static_cast<uint8_t>(prefix_bits & 0xFFu);
    std::vector<KeyedCoinRef> depth8_entries;
    for (const Coin &coin : utxo.Coins()) {
        const Hash key = OutpointKey(coin.outpoint);
        if (key[0] == depth8_idx) {
            depth8_entries.push_back(KeyedCoinRef{key, &coin});
        }
    }
    std::sort(depth8_entries.begin(), depth8_entries.end(),
              [](const KeyedCoinRef &a, const KeyedCoinRef &b) {
                  return a.key < b.key;
              });

    std::vector<Hash> siblings_top_down;
    siblings_top_down.reserve(prefix_depth - kMinUtxoShardPrefixDepth);
    std::vector<KeyedCoinRef> current = std::move(depth8_entries);
    for (uint8_t d = kMinUtxoShardPrefixDepth; d < prefix_depth; ++d) {
        const bool target_bit = ((prefix_bits >> d) & 1u) != 0;
        std::vector<KeyedCoinRef> target_side;
        std::vector<KeyedCoinRef> sibling_side;
        for (const auto &e : current) {
            if (KeyBitAt(e.key, d) == target_bit) {
                target_side.push_back(e);
            } else {
                sibling_side.push_back(e);
            }
        }
        ShardRootEntry sib_entry{};
        if (!ComputeSubtreeEntry(sibling_side, d + 1, sib_entry)) {
            error = "failed computing boundary sibling subtree";
            return false;
        }
        siblings_top_down.push_back(sib_entry.subtree_root);
        current = std::move(target_side);
    }

    if (current.size() > max_shard_leaves ||
        current.size() > kMaxUtxoShardLeaves) {
        error =
            "requested shard exceeds maximum leaf count; split to deeper prefix_depth";
        return false;
    }

    UtxoShardMessage msg;
    msg.pivot_block_id = pivot_block_id;
    msg.prefix_depth = prefix_depth;
    msg.prefix_bits = prefix_bits;
    msg.boundary_siblings.assign(siblings_top_down.rbegin(),
                                 siblings_top_down.rend());
    msg.coins.reserve(current.size());
    for (const auto &e : current) {
        msg.coins.push_back(*e.coin);
    }
    out = std::move(msg);
    error.clear();
    return true;
}

bool ExportUtxoShardFromSmt(const std::shared_ptr<const SmtNode> &root,
                            const Hash &pivot_block_id, uint8_t prefix_depth,
                            uint16_t prefix_bits, UtxoShardMessage &out,
                            std::string &error, size_t max_shard_leaves) {
    if (prefix_depth < kMinUtxoShardPrefixDepth ||
        prefix_depth > kMaxUtxoShardPrefixDepth) {
        error = "prefix_depth out of range [8..16]";
        return false;
    }
    if (prefix_depth < 16 && (prefix_bits >> prefix_depth) != 0) {
        error = "prefix_bits has bits set above prefix_depth";
        return false;
    }

    std::shared_ptr<const SmtNode> cur = root;
    std::vector<Hash> siblings_top_down;
    siblings_top_down.reserve(prefix_depth - kMinUtxoShardPrefixDepth);

    for (uint8_t d = 0; d < prefix_depth; ++d) {
        const bool target_bit = ((prefix_bits >> d) & 1u) != 0;
        Hash sib_hash = EmptyUtxoRoot();
        std::shared_ptr<const SmtNode> next_node = nullptr;

        if (cur && cur->count > 0) {
            if (cur->IsLeaf()) {
                const bool leaf_bit = SmtKeyBit(cur->key, d);
                if (leaf_bit == target_bit) {
                    next_node = cur;
                    sib_hash = EmptyUtxoRoot();
                } else {
                    next_node = nullptr;
                    sib_hash = cur->digest;
                }
            } else {
                next_node = cur->child[target_bit ? 1 : 0];
                sib_hash = cur->ChildHash(target_bit ? 0 : 1);
            }
        }

        if (d >= kMinUtxoShardPrefixDepth) {
            siblings_top_down.push_back(sib_hash);
        }
        cur = std::move(next_node);
    }

    const size_t sub_count = cur ? cur->count : 0;
    if (sub_count > max_shard_leaves || sub_count > kMaxUtxoShardLeaves) {
        error =
            "requested shard exceeds maximum leaf count; split to deeper prefix_depth";
        return false;
    }

    std::vector<KeyedCoinRef> entries;
    entries.reserve(sub_count);
    CollectSmtSubtreeCoins(cur, entries);
    std::sort(entries.begin(), entries.end(),
              [](const KeyedCoinRef &a, const KeyedCoinRef &b) {
                  return a.key < b.key;
              });

    UtxoShardMessage msg;
    msg.pivot_block_id = pivot_block_id;
    msg.prefix_depth = prefix_depth;
    msg.prefix_bits = prefix_bits;
    msg.boundary_siblings.assign(siblings_top_down.rbegin(),
                                 siblings_top_down.rend());
    msg.coins.reserve(entries.size());
    for (const auto &e : entries) {
        msg.coins.push_back(*e.coin);
    }
    out = std::move(msg);
    error.clear();
    return true;
}

bool ExportAdaptiveUtxoShards(const UtxoSet &utxo, const Hash &pivot_block_id,
                              std::vector<UtxoShardMessage> &out,
                              std::string &error, size_t max_shard_leaves) {
    if (max_shard_leaves == 0 || max_shard_leaves > kMaxUtxoShardLeaves) {
        error = "invalid max_shard_leaves parameter";
        return false;
    }
    std::array<std::vector<KeyedCoinRef>, kFastSyncShardCount> buckets;
    for (const Coin &coin : utxo.Coins()) {
        const Hash key = OutpointKey(coin.outpoint);
        buckets[key[0]].push_back(KeyedCoinRef{key, &coin});
    }
    for (auto &b : buckets) {
        std::sort(b.begin(), b.end(),
                  [](const KeyedCoinRef &a, const KeyedCoinRef &c) {
                      return a.key < c.key;
                  });
    }
    std::vector<UtxoShardMessage> shards;
    for (uint16_t s = 0; s < kFastSyncShardCount; ++s) {
        if (buckets[s].empty()) continue;
        if (!SplitAndExportShardsRecursive(utxo, pivot_block_id, buckets[s],
                                           kMinUtxoShardPrefixDepth, s,
                                           max_shard_leaves, shards, error)) {
            return false;
        }
    }
    out = std::move(shards);
    error.clear();
    return true;
}

bool AssembleAndVerifyFastSyncPivot(
    const Hash &pivot_block_id, uint64_t pivot_height,
    const std::optional<Hash> &expected_utxo_root_anchor,
    const UtxoRootsMessage &roots_msg,
    const std::vector<UtxoShardMessage> &shards, UtxoSet &out_utxo,
    MonetaryState &out_monetary, std::string &error) {
    Hash folded_root{};
    if (!VerifyUtxoRootsAgainstAnchor(pivot_block_id, pivot_height,
                                      expected_utxo_root_anchor, roots_msg,
                                      folded_root, error)) {
        return false;
    }

    std::array<std::vector<const UtxoShardMessage *>, kFastSyncShardCount>
        by_depth8;
    for (const auto &shard : shards) {
        if (shard.pivot_block_id != roots_msg.pivot_block_id) {
            error = "utxoshard pivot_block_id mismatch";
            return false;
        }
        if (shard.prefix_depth < kMinUtxoShardPrefixDepth ||
            shard.prefix_depth > kMaxUtxoShardPrefixDepth) {
            error = "utxoshard prefix_depth out of range";
            return false;
        }
        const uint8_t s = static_cast<uint8_t>(shard.prefix_bits & 0xFFu);
        by_depth8[s].push_back(&shard);
    }

    UtxoSet assembled;
    for (size_t s = 0; s < kFastSyncShardCount; ++s) {
        const ShardRootEntry &expected = roots_msg.shards[s];
        const auto &subshards = by_depth8[s];
        if (expected.cardinality_tag == 0) {
            for (const auto *sub : subshards) {
                ShardRootEntry sub_out{};
                if (!VerifyAndBuildUtxoShard(expected, pivot_height, *sub,
                                             &sub_out, error)) {
                    return false;
                }
            }
            continue;
        }

        if (subshards.empty()) {
            error = "missing utxoshard for non-empty depth-8 shard " +
                    std::to_string(s);
            return false;
        }

        std::vector<KeyedCoinRef> shard_coins;
        std::set<std::pair<uint8_t, uint16_t>> seen_prefixes;
        for (const auto *sub : subshards) {
            if (!seen_prefixes
                     .emplace(sub->prefix_depth, sub->prefix_bits)
                     .second) {
                error = "duplicate utxoshard prefix";
                return false;
            }
            ShardRootEntry sub_out{};
            if (!VerifyAndBuildUtxoShard(expected, pivot_height, *sub, &sub_out,
                                         error)) {
                return false;
            }
            for (const Coin &coin : sub->coins) {
                if (!assembled.Insert(coin)) {
                    error = "overlapping or invalid coin across subshards";
                    return false;
                }
                shard_coins.push_back(
                    KeyedCoinRef{OutpointKey(coin.outpoint), &coin});
            }
        }
        std::sort(shard_coins.begin(), shard_coins.end(),
                  [](const KeyedCoinRef &a, const KeyedCoinRef &b) {
                      return a.key < b.key;
                  });
        ShardRootEntry combined_depth8{};
        if (!ComputeSubtreeEntry(shard_coins, kMinUtxoShardPrefixDepth,
                                 combined_depth8) ||
            combined_depth8 != expected) {
            error = "incomplete subshard coverage for depth-8 shard " +
                    std::to_string(s);
            return false;
        }
    }

    MonetaryState mon = DecodeMonetaryState(
        std::vector<uint8_t>(roots_msg.monetary_state.begin(),
                             roots_msg.monetary_state.end()));

    out_utxo = std::move(assembled);
    out_monetary = mon;
    error.clear();
    return true;
}

std::vector<uint8_t> EncodeGetBlockUndoRequest(const GetBlockUndoRequest &req) {
    return std::vector<uint8_t>(req.block_id.begin(), req.block_id.end());
}

bool DecodeGetBlockUndoRequest(const std::vector<uint8_t> &bytes,
                               GetBlockUndoRequest &out,
                               std::string &error) {
    if (bytes.size() != 32) {
        error = "invalid getblockundo request size";
        return false;
    }
    std::copy_n(bytes.data(), 32, out.block_id.begin());
    error.clear();
    return true;
}

bool EncodeBlockUndoMessage(const BlockUndoMessage &msg,
                            std::vector<uint8_t> &out,
                            std::string &error) {
    if (msg.prior_spent_coins.size() > kMaxBlockUndoCoins) {
        error = "blockundo prior_spent_coins exceeds limit";
        return false;
    }
    std::vector<uint8_t> buf;
    buf.reserve(32 + 56 + msg.prior_spent_coins.size() * 64);
    buf.insert(buf.end(), msg.block_id.begin(), msg.block_id.end());
    buf.insert(buf.end(), msg.parent_monetary_state.begin(),
               msg.parent_monetary_state.end());
    WriteCompactSize(buf, msg.prior_spent_coins.size());
    for (const Coin &coin : msg.prior_spent_coins) {
        std::vector<uint8_t> encoded_coin;
        if (!EncodeCoin(coin, encoded_coin)) {
            error = "blockundo failed to encode coin";
            return false;
        }
        WriteCompactSize(buf, encoded_coin.size());
        buf.insert(buf.end(), encoded_coin.begin(), encoded_coin.end());
    }
    out = std::move(buf);
    error.clear();
    return true;
}

bool DecodeBlockUndoMessage(const std::vector<uint8_t> &bytes,
                            BlockUndoMessage &out,
                            std::string &error) {
    if (bytes.size() < 32 + 56 + 1) {
        error = "truncated blockundo message header";
        return false;
    }
    BlockUndoMessage parsed;
    std::copy_n(bytes.data(), 32, parsed.block_id.begin());
    std::copy_n(bytes.data() + 32, 56, parsed.parent_monetary_state.begin());
    size_t offset = 88;
    uint64_t count = 0;
    if (!ReadCompactSize(bytes, offset, kMaxBlockUndoCoins, count)) {
        error = "invalid blockundo coin count";
        return false;
    }
    if (count > (bytes.size() - offset) / 55) {
        error = "truncated blockundo coin records"; return false;
    }
    parsed.prior_spent_coins.resize(static_cast<size_t>(count));
    for (size_t i = 0; i < parsed.prior_spent_coins.size(); ++i) {
        uint64_t coin_len = 0;
        if (!ReadCompactSize(bytes, offset, MAX_COIN_BYTES, coin_len) ||
            bytes.size() - offset < coin_len) {
            error = "truncated blockundo coin record";
            return false;
        }
        if (!DecodeCanonicalCoinBytes(bytes.data() + offset,
                                      static_cast<size_t>(coin_len),
                                      parsed.prior_spent_coins[i], error)) {
            return false;
        }
        offset += static_cast<size_t>(coin_len);
    }
    if (offset != bytes.size()) {
        error = "trailing bytes in blockundo message";
        return false;
    }
    out = std::move(parsed);
    error.clear();
    return true;
}

namespace {

bool SameOutput(const Output &a, const Output &b) {
    return a == b;
}

bool SameCoin(const Coin &a, const Coin &b) {
    return a.outpoint == b.outpoint && a.creation_height == b.creation_height &&
           a.coinbase == b.coinbase &&
           a.creation_parent_mtp == b.creation_parent_mtp &&
           SameOutput(a.output, b.output);
}

} // namespace

bool VerifyAndPeelReverseBlock(
    uint64_t block_height, uint64_t parent_mtp,
    const std::vector<BlockCreatedOutput> &block_outputs,
    const std::vector<Outpoint> &block_spent_outpoints,
    const std::vector<Coin> &undo_spent_coins, UtxoSet &peel_utxo,
    const std::optional<Hash> &expected_parent_utxo_root,
    Hash &out_parent_utxo_root, std::string &error) {
    if (block_height == 0) {
        error = "cannot reverse-peel genesis block";
        return false;
    }

    std::map<Outpoint, BlockCreatedOutput, OutpointLess> created_spendable;
    for (const auto &created : block_outputs) {
        if (created.output.IsBurn()) {
            continue;
        }
        if (!created_spendable.emplace(created.outpoint, created).second) {
            error = "duplicate created outpoint in block";
            return false;
        }
    }

    std::set<Outpoint, OutpointLess> seen_spends;
    std::set<Outpoint, OutpointLess> intra_spends;
    std::vector<Outpoint> prior_spend_order;
    prior_spend_order.reserve(block_spent_outpoints.size());
    for (const Outpoint &sp : block_spent_outpoints) {
        if (!seen_spends.insert(sp).second) {
            error = "duplicate spent outpoint in block";
            return false;
        }
        if (created_spendable.count(sp) != 0) {
            intra_spends.insert(sp);
        } else {
            prior_spend_order.push_back(sp);
        }
    }

    // Accept either prior-only undo_spent_coins (from wire BlockUndoMessage) or
    // full-input undo_spent_coins (including intra-block spends).
    std::vector<Coin> prior_coins;
    if (undo_spent_coins.size() == prior_spend_order.size()) {
        prior_coins = undo_spent_coins;
    } else if (undo_spent_coins.size() == block_spent_outpoints.size()) {
        prior_coins.reserve(prior_spend_order.size());
        for (size_t i = 0; i < block_spent_outpoints.size(); ++i) {
            const Outpoint &sp = block_spent_outpoints[i];
            const Coin &c = undo_spent_coins[i];
            if (!(c.outpoint == sp)) {
                error = "undo spent coin outpoint mismatch";
                return false;
            }
            auto created_it = created_spendable.find(sp);
            if (created_it != created_spendable.end()) {
                Coin expected_intra;
                expected_intra.outpoint = sp;
                expected_intra.creation_height = block_height;
                expected_intra.coinbase = created_it->second.is_coinbase;
                expected_intra.creation_parent_mtp = c.creation_parent_mtp;
                expected_intra.output = created_it->second.output;
                if (!SameCoin(c, expected_intra)) {
                    error = "intra-block spent coin does not match block output";
                    return false;
                }
            } else {
                prior_coins.push_back(c);
            }
        }
    } else {
        error = "undo spent coins count mismatch";
        return false;
    }

    for (size_t i = 0; i < prior_spend_order.size(); ++i) {
        const Coin &c = prior_coins[i];
        if (!(c.outpoint == prior_spend_order[i])) {
            error = "prior spent coin outpoint order mismatch";
            return false;
        }
        if (c.output.IsBurn()) {
            error = "prior spent coin cannot be burn output";
            return false;
        }
        if (c.creation_height >= block_height) {
            error = "prior spent coin creation_height >= block_height";
            return false;
        }
        if (peel_utxo.Find(c.outpoint) != nullptr) {
            error = "prior spent coin is still present in current UTXO state";
            return false;
        }
    }

    UtxoSet scratch = peel_utxo;

    // 1. Verify and remove all net unspent outputs O_h^net created by block h.
    for (const auto &[outpoint, created] : created_spendable) {
        if (intra_spends.count(outpoint) != 0) {
            continue;
        }
        const Coin *existing = scratch.Find(outpoint);
        if (!existing) {
            error = "net block output missing from UTXO state at height " +
                    std::to_string(block_height);
            return false;
        }
        Coin expected_created;
        expected_created.outpoint = outpoint;
        expected_created.creation_height = block_height;
        expected_created.coinbase = created.is_coinbase;
        expected_created.creation_parent_mtp =
            (parent_mtp == 0 || existing->creation_parent_mtp == 0)
                ? existing->creation_parent_mtp
                : parent_mtp;
        expected_created.output = created.output;
        if (!SameCoin(*existing, expected_created)) {
            error = "net block output in UTXO state does not match block";
            return false;
        }
        if (!scratch.Erase(outpoint)) {
            error = "failed erasing net block output from UTXO state";
            return false;
        }
    }

    // 2. Restore all prior-block spent coins I_h^prior.
    for (const Coin &c : prior_coins) {
        if (!scratch.Insert(c)) {
            error = "failed inserting prior spent coin into parent UTXO state";
            return false;
        }
    }

    const Hash computed_parent_root = scratch.Root();
    if (expected_parent_utxo_root.has_value() &&
        computed_parent_root != *expected_parent_utxo_root) {
        error = "peeled parent UtxoRoot mismatch against state anchor";
        return false;
    }

    peel_utxo = std::move(scratch);
    out_parent_utxo_root = computed_parent_root;
    error.clear();
    return true;
}

} // namespace lotus::v2
