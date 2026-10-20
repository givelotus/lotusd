// Copyright (c) 2026 The Lotus developers
#include "fast_sync.h"
#include "disk_block.h"

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
    if (len < 37 + COIN_METADATA_BYTES || len > MAX_COIN_BYTES) {
        error = "invalid coin byte length";
        return false;
    }
    std::copy_n(data, 32, out.outpoint.tx_id.begin());
    out.outpoint.index = static_cast<uint32_t>(data[32]) |
                         (static_cast<uint32_t>(data[33]) << 8) |
                         (static_cast<uint32_t>(data[34]) << 16) |
                         (static_cast<uint32_t>(data[35]) << 24);
    std::vector<uint8_t> buf(data, data + len);
    size_t offset = 36;
    uint64_t out_len = 0;
    if (!ReadCompactSize(buf, offset, MAX_COIN_OUTPUT_BYTES, out_len) ||
        buf.size() - offset < out_len ||
        buf.size() - (offset + static_cast<size_t>(out_len)) != COIN_METADATA_BYTES) {
        error = "invalid coin output framing";
        return false;
    }
    std::vector<uint8_t> output_bytes(buf.begin() + offset,
                                      buf.begin() + offset + static_cast<size_t>(out_len));
    if (!DecodeCoinOutput(output_bytes, out.output, error)) {
        return false;
    }
    offset += static_cast<size_t>(out_len);
    out.creation_height = ReadLE64(buf.data() + offset);
    out.creation_parent_mtp = ReadLE64(buf.data() + offset + 8);
    const uint8_t cb_flag = buf[offset + 16];
    if (cb_flag > 1) {
        error = "invalid coinbase flag in coin";
        return false;
    }
    out.coinbase = (cb_flag == 1);
    if (buf[offset + 17] != COIN_ENCODING_VERSION) {
        error = "invalid coin encoding version";
        return false;
    }
    out.fee_per_output = ReadLE64(buf.data() + offset + 18);
    out.expiration_height = ReadLE64(buf.data() + offset + 26);

    std::vector<uint8_t> reencoded;
    if (!EncodeCoin(out, reencoded) || reencoded != buf) {
        error = "non-canonical coin encoding";
        return false;
    }
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
    return FoldShardPair(static_cast<uint8_t>(depth), left_entry, right_entry, out);
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
        // Hole 13: Dual Pivot Authentication Gate.
        if (candidate.buried_blocks < kFastSyncMinBuriedBlocks ||
            candidate.distinct_netgroup_confirmations <
                kFastSyncMinNetgroupConfirmations) {
            error = "unfinalized pivot lacks 100 buried blocks across >= 3 distinct netgroups";
            return false;
        }
        // Hole 14: Pivot Safety Cushion.
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
            if (error) *error = "invalid shard root entry tag or empty digest mismatch";
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

bool VerifyUtxoRootsAgainstHeader(const Header &pivot_header,
                                  const ChainId &chain_id,
                                  const UtxoRootsMessage &msg,
                                  std::string &error) {
    Hash expected_pivot_id{};
    if (!BlockId(chain_id, pivot_header, expected_pivot_id) ||
        msg.pivot_block_id != expected_pivot_id) {
        error = "utxoroots pivot_block_id does not match authenticated pivot header";
        return false;
    }
    if (msg.height != pivot_header.height) {
        error = "utxoroots height does not match pivot header height";
        return false;
    }
    MonetaryState decoded_monetary{};
    try {
        decoded_monetary = DecodeMonetaryState(
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
    const Hash computed_state_root = StateRoot(
        chain_id, pivot_header.height, *folded_utxo_root, decoded_monetary);
    if (computed_state_root != pivot_header.state_root) {
        error = "utxoroots folded StateRoot does not match pivot header state_root";
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
        error = "utxoshard boundary_siblings length does not match prefix_depth - 8";
        return false;
    }
    // Hole 15: Strict leaf cap.
    if (shard.coins.size() > kMaxUtxoShardLeaves) {
        error = "utxoshard exceeds maximum allowed 4096 leaves";
        return false;
    }

    std::vector<KeyedCoinRef> keyed;
    keyed.reserve(shard.coins.size());
    Hash prev_key{};
    for (size_t i = 0; i < shard.coins.size(); ++i) {
        const Coin &coin = shard.coins[i];
        // Hole 11: Reject burn outputs (C17) and invalid coins.
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
        // Hole 11: Strict prefix enforcement against cross-shard key smuggling.
        if (OutpointPrefixBits(key, shard.prefix_depth) != shard.prefix_bits) {
            error = "utxoshard coin OutpointKey does not match shard prefix_bits";
            return false;
        }
        // Strict ascending key order (also prevents duplicate keys).
        if (i > 0 && !(prev_key < key)) {
            error = "utxoshard coins are not in strictly ascending OutpointKey order";
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

    // Fold from depth (prefix_depth - 1) down to depth 8 using boundary_siblings.
    ShardRootEntry cur = sub_entry;
    for (size_t i = 0; i < expected_siblings; ++i) {
        const uint8_t d =
            static_cast<uint8_t>((shard.prefix_depth - 1) - i);
        const Hash &sib_hash = shard.boundary_siblings[i];
        const bool bit_is_right = ((shard.prefix_bits >> d) & 1u) != 0;

        ShardRootEntry sib_entry{};
        if (sib_hash == EmptyUtxoRoot()) {
            sib_entry = {0, EmptyUtxoRoot()};
        } else if (cur.cardinality_tag >= 1) {
            // Whenever cur has >= 1 leaf and sibling is non-empty, the parent
            // at depth d has >= 2 leaves (cardinality_tag = 2), so sib's tag
            // (1 or 2) produces the exact same UtxoNode(d, left, right) hash.
            sib_entry = {2, sib_hash};
        } else {
            // cur is empty (0 leaves), sibling is non-empty.
            // If expected_depth8_entry has cardinality_tag == 1 and all higher
            // siblings are empty, sibling is a single collapsed leaf (tag 1).
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
        error = "utxoshard folded depth-8 entry does not match authenticated ShardRootEntry";
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

bool ExportUtxoRoots(const UtxoSet &utxo, const ChainId &chain_id,
                     const Header &pivot_header, const MonetaryState &monetary,
                     UtxoRootsMessage &out, std::string &error) {
    Hash pivot_id{};
    if (!BlockId(chain_id, pivot_header, pivot_id)) {
        error = "invalid pivot header for ExportUtxoRoots";
        return false;
    }
    if (StateRoot(chain_id, pivot_header.height, utxo.Root(), monetary) !=
        pivot_header.state_root) {
        error = "utxo and monetary state do not match pivot_header.state_root";
        return false;
    }

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
    msg.pivot_block_id = pivot_id;
    msg.height = pivot_header.height;
    msg.monetary_state = EncodeMonetaryState(monetary);
    for (size_t s = 0; s < kFastSyncShardCount; ++s) {
        ComputeSubtreeEntry(buckets[s], kMinUtxoShardPrefixDepth,
                            msg.shards[s]);
    }

    out = msg;
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

    // Walk from depth 8 to prefix_depth, recording boundary sibling hashes.
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
        error = "requested shard exceeds maximum leaf count; split to deeper prefix_depth";
        return false;
    }

    UtxoShardMessage msg;
    msg.pivot_block_id = pivot_block_id;
    msg.prefix_depth = prefix_depth;
    msg.prefix_bits = prefix_bits;
    // Order boundary_siblings from depth (prefix_depth - 1) down to depth 8.
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
    const Header &pivot_header, const ChainId &chain_id,
    const UtxoRootsMessage &roots_msg,
    const std::vector<UtxoShardMessage> &shards, UtxoSet &out_utxo,
    MonetaryState &out_monetary, std::string &error) {
    if (!VerifyUtxoRootsAgainstHeader(pivot_header, chain_id, roots_msg,
                                      error)) {
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
                if (!VerifyAndBuildUtxoShard(expected, pivot_header.height,
                                             *sub, &sub_out, error)) {
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

        // Verify each subshard individually against the depth-8 entry and
        // collect all coins for depth-8 shard s to ensure no missing sub-branches.
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
            if (!VerifyAndBuildUtxoShard(expected, pivot_header.height, *sub,
                                         &sub_out, error)) {
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

bool ExportDiskUtxoRoots(const DiskStateStore &store, const ChainId &chain_id,
                         UtxoRootsMessage &out, std::string &error) {
    if (!store.IsOpen()) {
        error = "disk state store is closed";
        return false;
    }
    const DiskStateMetadata meta = store.Metadata();
    Header pivot_header{};
    if (!ParseHeader(meta.header.data(), meta.header.size(), pivot_header)) {
        error = "failed to parse pivot header from store metadata";
        return false;
    }
    MonetaryState mon{};
    try {
        mon = DecodeMonetaryState(meta.monetary);
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
    std::vector<Coin> coins;
    DiskStateError disk_err;
    if (!store.ExportCoins(coins, disk_err)) {
        error = disk_err.message;
        return false;
    }
    UtxoSet utxo;
    for (const Coin &c : coins) {
        utxo.Insert(c);
    }
    return ExportUtxoRoots(utxo, chain_id, pivot_header, mon, out, error);
}

bool ImportVerifiedFastSyncPivotToDisk(
    const Header &pivot_header, const ChainId &chain_id,
    const std::vector<Header> &history, const UtxoRootsMessage &roots_msg,
    const std::vector<UtxoShardMessage> &shards, DiskStateStore &store,
    std::string &error) {
    UtxoSet verified_utxo;
    MonetaryState verified_monetary{};
    if (!AssembleAndVerifyFastSyncPivot(pivot_header, chain_id, roots_msg,
                                        shards, verified_utxo,
                                        verified_monetary, error)) {
        return false;
    }
    DiskStateMetadata meta;
    meta.tip = roots_msg.pivot_block_id;
    std::array<uint8_t, HEADER_SIZE> raw_hdr{};
    SerializeHeader(pivot_header, raw_hdr);
    meta.header.assign(raw_hdr.begin(), raw_hdr.end());
    meta.monetary.assign(roots_msg.monetary_state.begin(),
                         roots_msg.monetary_state.end());
    if (!history.empty()) {
        try {
            meta.auxiliary = EncodeDiskChainContext(history, {});
        } catch (const std::exception &e) {
            error = e.what();
            return false;
        }
    }
    DiskStateError disk_err;
    if (!store.ImportFastSyncPivot(meta, pivot_header, verified_utxo.Coins(),
                                   disk_err)) {
        error = disk_err.message;
        return false;
    }
    error.clear();
    return true;
}

namespace {

constexpr size_t kMaxBlockUndoCoins = 1000000;

class InMemoryBlockStateTx final : public BlockStateTransaction {
public:
    DevelopmentUtxoView view;
    UtxoSet tree;

    explicit InMemoryBlockStateTx(const UtxoSet &initial) {
        for (const Coin &c : initial.Coins()) {
            view.emplace(c.outpoint, c);
            tree.Insert(c);
        }
    }

    CoinReadResult Read(const Outpoint &key, Coin &coin,
                        std::string &) override {
        const auto it = view.find(key);
        if (it == view.end()) return CoinReadResult::Missing;
        coin = it->second;
        return CoinReadResult::Found;
    }

    bool Insert(const Coin &coin, std::string &) override {
        view.emplace(coin.outpoint, coin);
        tree.Insert(coin);
        return true;
    }

    bool Erase(const Outpoint &key, std::string &) override {
        view.erase(key);
        tree.Erase(key);
        return true;
    }

    Hash Root() const override { return tree.Root(); }

    void Abort() noexcept override {}
};

bool PartitionBlockOutputsAndSpends(
    const FramedBlock &block, uint64_t parent_mtp,
    const BlockUndoMessage &undo_msg,
    std::vector<Coin> &out_net_created,
    std::vector<Coin> &out_prior_spent,
    std::string &error) {
    // Step 1: Collect all spendable outputs created in B_h (O_h^all).
    std::map<Outpoint, std::pair<size_t, Coin>, OutpointLess> created_in_block;
    std::vector<Outpoint> created_order;
    for (size_t tx_idx = 0; tx_idx < block.transactions.size(); ++tx_idx) {
        const Transaction &tx = block.transactions[tx_idx];
        const Hash &txid = block.transaction_identities[tx_idx].txid;
        for (size_t j = 0; j < tx.outputs.size(); ++j) {
            const Output &output = tx.outputs[j];
            if (output.IsBurn()) continue;
            Coin coin;
            coin.outpoint = Outpoint{txid, static_cast<uint32_t>(j)};
            coin.output = output;
            coin.creation_height = block.header.height;
            coin.creation_parent_mtp = parent_mtp;
            coin.coinbase = (tx_idx == 0);
            created_in_block.emplace(coin.outpoint, std::pair{tx_idx, coin});
            created_order.push_back(coin.outpoint);
        }
    }

    // Step 2: Partition spent inputs into I_h^intra and I_h^prior (Hole 12 defense).
    std::set<Outpoint, OutpointLess> seen_spends;
    std::set<Outpoint, OutpointLess> intra_spent;
    std::vector<Coin> prior_spent;
    size_t undo_cursor = 0;

    for (size_t tx_idx = 1; tx_idx < block.transactions.size(); ++tx_idx) {
        const Transaction &tx = block.transactions[tx_idx];
        for (const Input &input : tx.inputs) {
            if (input.flags != 1) continue;
            const Outpoint op{input.prev_txid, input.prev_index};
            if (!seen_spends.insert(op).second) {
                error = "duplicate input spend inside block";
                return false;
            }
            const auto created_it = created_in_block.find(op);
            if (created_it != created_in_block.end()) {
                // Intra-block spend (I_h^intra): must be created by an earlier tx in B_h,
                // and is NEVER read from undo_msg.prior_spent_coins.
                if (created_it->second.first >= tx_idx) {
                    error = "intra-block spend references same or later transaction";
                    return false;
                }
                intra_spent.insert(op);
            } else {
                // Prior-block spend (I_h^prior): consume next record from undo_msg.
                if (undo_cursor >= undo_msg.prior_spent_coins.size()) {
                    error = "blockundo missing prior spent coin record";
                    return false;
                }
                const Coin &prior_coin = undo_msg.prior_spent_coins[undo_cursor++];
                if (prior_coin.outpoint != op) {
                    error = "blockundo prior spent coin outpoint mismatch";
                    return false;
                }
                if (prior_coin.creation_height >= block.header.height) {
                    error = "blockundo prior spent coin has creation_height >= block height";
                    return false;
                }
                if (prior_coin.output.IsBurn()) {
                    error = "blockundo prior spent coin is a burn output";
                    return false;
                }
                Hash leaf_hash{};
                if (!UtxoLeaf(prior_coin, leaf_hash)) {
                    error = "blockundo prior spent coin failed UtxoLeaf validation";
                    return false;
                }
                prior_spent.push_back(prior_coin);
            }
        }
    }

    if (undo_cursor != undo_msg.prior_spent_coins.size()) {
        error = "blockundo contains trailing unconsumed coins (possible intra-block spend injection)";
        return false;
    }

    // Reconstruct the same authenticated lifetime metadata as forward
    // ordinary validation before comparing surviving canonical coin bytes.
    std::map<Outpoint, const Coin *, OutpointLess> prior_by_outpoint;
    for (const Coin &coin : prior_spent) {
        prior_by_outpoint.emplace(coin.outpoint, &coin);
    }
    for (size_t tx_idx = 0; tx_idx < block.transactions.size(); ++tx_idx) {
        const Transaction &tx = block.transactions[tx_idx];
        __uint128_t native_inputs = 0, native_outputs = 0;
        size_t spendable_outputs = 0;
        if (tx_idx != 0) {
            for (const Input &input : tx.inputs) {
                if (input.flags != 1) continue;
                const Outpoint op{input.prev_txid, input.prev_index};
                const auto created = created_in_block.find(op);
                const Coin &coin = created != created_in_block.end()
                    ? created->second.second : *prior_by_outpoint.at(op);
                if (!coin.output.HasToken()) native_inputs += coin.output.value;
            }
        }
        for (const Output &output : tx.outputs) {
            if (!output.HasToken()) native_outputs += output.value;
            if (!output.IsBurn()) ++spendable_outputs;
        }
        if (tx_idx != 0 && native_inputs < native_outputs) {
            error = "reverse peel native inflation";
            return false;
        }
        const __uint128_t fee = tx_idx == 0 ? 0 : native_inputs - native_outputs;
        const uint64_t fee_share = ComputeTxFeePerSpendableOutput(
            fee > UINT64_MAX ? UINT64_MAX : static_cast<uint64_t>(fee),
            spendable_outputs);
        for (size_t j = 0; j < tx.outputs.size(); ++j) {
            if (tx.outputs[j].IsBurn()) continue;
            Coin &coin = created_in_block.at(
                {block.transaction_identities[tx_idx].txid, uint32_t(j)}).second;
            coin.fee_per_output = fee_share;
            coin.expiration_height = ComputeUtxoExpirationHeight(
                block.header.height, coin.coinbase, fee_share);
        }
    }

    // O_h^net = O_h^all \ I_h^intra
    std::vector<Coin> net_created;
    net_created.reserve(created_order.size() - intra_spent.size());
    for (const Outpoint &op : created_order) {
        if (!intra_spent.contains(op)) {
            net_created.push_back(created_in_block.at(op).second);
        }
    }

    out_net_created = std::move(net_created);
    out_prior_spent = std::move(prior_spent);
    return true;
}

} // namespace

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
    if (msg.expired_swept_coins.size() > MAX_EXPIRY_SWEEPS_PER_BLOCK) {
        error = "blockundo expired_swept_coins exceeds limit";
        return false;
    }
    std::vector<uint8_t> buf;
    buf.reserve(32 + 56 + msg.prior_spent_coins.size() * 64 +
                msg.expired_swept_coins.size() * 64);
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
    if (!msg.expired_swept_coins.empty()) {
        WriteCompactSize(buf, msg.expired_swept_coins.size());
        for (const Coin &coin : msg.expired_swept_coins) {
            std::vector<uint8_t> encoded_coin;
            if (!EncodeCoin(coin, encoded_coin)) {
                error = "blockundo failed to encode expired swept coin";
                return false;
            }
            WriteCompactSize(buf, encoded_coin.size());
            buf.insert(buf.end(), encoded_coin.begin(), encoded_coin.end());
            WriteCompactSize(buf, coin.fee_per_output);
        }
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
    if (offset < bytes.size()) {
        uint64_t exp_count = 0;
        if (!ReadCompactSize(bytes, offset, MAX_EXPIRY_SWEEPS_PER_BLOCK,
                             exp_count) ||
            exp_count == 0) {
            error = "trailing bytes in blockundo message";
            return false;
        }
        parsed.expired_swept_coins.resize(static_cast<size_t>(exp_count));
        for (size_t i = 0; i < parsed.expired_swept_coins.size(); ++i) {
            uint64_t coin_len = 0;
            if (!ReadCompactSize(bytes, offset, MAX_COIN_BYTES, coin_len) ||
                bytes.size() - offset < coin_len) {
                error = "truncated blockundo expired coin record";
                return false;
            }
            if (!DecodeCanonicalCoinBytes(
                    bytes.data() + offset, static_cast<size_t>(coin_len),
                    parsed.expired_swept_coins[i], error)) {
                return false;
            }
            offset += static_cast<size_t>(coin_len);
            uint64_t fee_per_out = 0;
            if (!ReadCompactSize(bytes, offset,
                                 std::numeric_limits<uint64_t>::max(),
                                 fee_per_out)) {
                error = "truncated blockundo expired coin fee_per_output";
                return false;
            }
            if (parsed.expired_swept_coins[i].fee_per_output != fee_per_out) {
                error = "blockundo fee disagrees with committed coin";
                return false;
            }
        }
    }
    if (offset != bytes.size()) {
        error = "trailing bytes in blockundo message";
        return false;
    }
    out = std::move(parsed);
    error.clear();
    return true;
}

bool BuildBlockUndoMessage(const std::vector<uint8_t> &block_wire,
                           const ChainId &chain_id,
                           const TxProfile &tx_profile,
                           const MonetaryState &parent_monetary,
                           const UtxoSet &pre_block_utxo,
                           BlockUndoMessage &out,
                           std::string &error) {
    FramedBlock block;
    if (!DecodeBlockWire(block_wire, tx_profile, chain_id, block, error)) {
        return false;
    }
    Hash block_id{};
    BlockId(chain_id, block.header, block_id);

    DevelopmentUtxoView pre_view;
    for (const Coin &c : pre_block_utxo.Coins()) {
        pre_view.emplace(c.outpoint, c);
    }

    std::set<Outpoint, OutpointLess> created_in_block;
    for (size_t tx_idx = 0; tx_idx < block.transactions.size(); ++tx_idx) {
        const Transaction &tx = block.transactions[tx_idx];
        const Hash &txid = block.transaction_identities[tx_idx].txid;
        for (size_t j = 0; j < tx.outputs.size(); ++j) {
            if (!tx.outputs[j].IsBurn()) {
                created_in_block.insert(
                    Outpoint{txid, static_cast<uint32_t>(j)});
            }
        }
    }

    BlockUndoMessage msg;
    msg.block_id = block_id;
    msg.parent_monetary_state = EncodeMonetaryState(parent_monetary);
    UtxoSet post_spends_utxo = pre_block_utxo;
    for (size_t tx_idx = 1; tx_idx < block.transactions.size(); ++tx_idx) {
        const Transaction &tx = block.transactions[tx_idx];
        for (const Input &input : tx.inputs) {
            if (input.flags != 1) continue;
            const Outpoint op{input.prev_txid, input.prev_index};
            // Intra-block spends are omitted from prior_spent_coins (Hole 12).
            if (created_in_block.contains(op)) {
                continue;
            }
            const auto it = pre_view.find(op);
            if (it == pre_view.end()) {
                error = "missing pre-block coin for prior spend in BuildBlockUndoMessage";
                return false;
            }
            msg.prior_spent_coins.push_back(it->second);
            post_spends_utxo.Erase(op);
        }
    }
    msg.expired_swept_coins =
        post_spends_utxo.CollectExpiredCoins(block.header.height);

    out = std::move(msg);
    error.clear();
    return true;
}

bool PeelBlockReverse(const std::vector<uint8_t> &block_wire,
                      const BlockUndoMessage &undo_msg,
                      const Header &parent_header,
                      const std::vector<Header> &history,
                      const HeaderChainProfile &header_profile,
                      OrdinaryCandidateProfile ordinary_profile,
                      const MonetaryProfile &monetary_profile,
                      const BlockCostProfile &cost_profile,
                      UtxoSet &state_at_h,
                      MonetaryState &monetary_at_h,
                      std::string &error) {
    FramedBlock block;
    if (!DecodeBlockWire(block_wire, ordinary_profile.transaction,
                         header_profile.chain_id, block, error)) {
        return false;
    }
    Hash block_id_h{}, parent_id{};
    if (!BlockId(header_profile.chain_id, block.header, block_id_h) ||
        undo_msg.block_id != block_id_h) {
        error = "blockundo block_id does not match block_wire header";
        return false;
    }
    if (!BlockId(header_profile.chain_id, parent_header, parent_id) ||
        block.header.prev_id != parent_id ||
        parent_header.height == std::numeric_limits<uint64_t>::max() ||
        block.header.height != parent_header.height + 1) {
        error = "reverse peel parent header linkage or height mismatch";
        return false;
    }
    if (StateRoot(header_profile.chain_id, block.header.height,
                  state_at_h.Root(), monetary_at_h) != block.header.state_root) {
        error = "starting state_at_h does not match authenticated header_h.state_root";
        return false;
    }
    const auto parent_mtp =
        ParentMedianTime(header_profile, parent_header, history);
    if (!parent_mtp) {
        error = "reverse peel failed to compute ParentMedianTime";
        return false;
    }
    MonetaryState parent_monetary{};
    try {
        parent_monetary = DecodeMonetaryState(
            std::vector<uint8_t>(undo_msg.parent_monetary_state.begin(),
                                 undo_msg.parent_monetary_state.end()));
    } catch (const std::exception &e) {
        error = std::string("invalid parent_monetary_state in blockundo: ") +
                e.what();
        return false;
    }

    std::vector<Coin> net_created;
    std::vector<Coin> prior_spent;
    if (!PartitionBlockOutputsAndSpends(block, *parent_mtp, undo_msg,
                                        net_created, prior_spent, error)) {
        return false;
    }

    // Verify O_h^net membership with identical canonical bytes in state_at_h,
    // and verify I_h^prior absence in state_at_h.
    DevelopmentUtxoView current_view;
    for (const Coin &c : state_at_h.Coins()) {
        current_view.emplace(c.outpoint, c);
    }
    for (const Coin &expected_created : net_created) {
        const auto it = current_view.find(expected_created.outpoint);
        if (it == current_view.end()) {
            error = "reverse peel missing surviving output O_h^net in state_at_h";
            return false;
        }
        std::vector<uint8_t> b1, b2;
        if (!EncodeCoin(it->second, b1) || !EncodeCoin(expected_created, b2) ||
            b1 != b2) {
            error = "reverse peel surviving output coin bytes mismatch in state_at_h";
            return false;
        }
    }
    for (const Coin &prior_coin : prior_spent) {
        if (current_view.contains(prior_coin.outpoint)) {
            error = "reverse peel prior spent coin already exists in state_at_h";
            return false;
        }
    }
    for (const Coin &exp_coin : undo_msg.expired_swept_coins) {
        if (current_view.contains(exp_coin.outpoint)) {
            error = "reverse peel expired swept coin already exists in state_at_h";
            return false;
        }
        if (exp_coin.output.IsBurn() ||
            !IsUtxoExpired(exp_coin, block.header.height)) {
            error = "reverse peel expired swept coin is not expired at block height";
            return false;
        }
    }

    // Peel Merklix state backwards from height h to h - 1:
    // erase O_h^net and insert I_h^prior and expired_swept_coins.
    UtxoSet peeled_state = state_at_h;
    for (const Coin &created : net_created) {
        peeled_state.Erase(created.outpoint);
    }
    for (const Coin &spent : prior_spent) {
        if (!peeled_state.Insert(spent)) {
            error = "reverse peel failed inserting I_h^prior into Merklix state";
            return false;
        }
    }
    for (const Coin &exp_coin : undo_msg.expired_swept_coins) {
        if (!peeled_state.Insert(exp_coin)) {
            error = "reverse peel failed inserting expired_swept_coins into Merklix state";
            return false;
        }
    }

    // Verify peeled state root against authenticated parent header H_{h-1}!
    const Hash peeled_state_root =
        StateRoot(header_profile.chain_id, parent_header.height,
                  peeled_state.Root(), parent_monetary);
    if (peeled_state_root != parent_header.state_root) {
        error = "reverse peel parent StateRoot mismatch against H_{h-1}.state_root";
        return false;
    }

    // Execute full forward transaction, signature, VM script, and P05/P06 monetary
    // validation of B_h against the peeled parent state (Hole 12 complete check).
    ordinary_profile.candidate_height = block.header.height;
    ordinary_profile.parent_mtp = *parent_mtp;
    OrdinaryParentContext parent_ctx{parent_header, header_profile.chain_id,
                                     parent_monetary};
    InMemoryBlockStateTx forward_tx(peeled_state);
    StagedBlockTransition staged_forward{};
    if (StageCompleteBlock(block_wire, parent_ctx, history, header_profile,
                           ordinary_profile, monetary_profile, cost_profile,
                           forward_tx, staged_forward,
                           error) != CandidateCheckResult::Accepted) {
        return false;
    }

    state_at_h = std::move(peeled_state);
    monetary_at_h = parent_monetary;
    error.clear();
    return true;
}

bool PeelDiskBlockReverse(const std::vector<uint8_t> &block_wire,
                          const BlockUndoMessage &undo_msg,
                          const Header &parent_header,
                          const std::vector<Header> &history,
                          const HeaderChainProfile &header_profile,
                          OrdinaryCandidateProfile ordinary_profile,
                          const MonetaryProfile &monetary_profile,
                          const BlockCostProfile &cost_profile,
                          DiskStateStore &store,
                          std::string &error) {
    if (!store.IsOpen()) {
        error = "disk state store is closed";
        return false;
    }
    const DiskStateMetadata meta_h = store.Metadata();
    MonetaryState monetary_h{};
    try {
        monetary_h = DecodeMonetaryState(meta_h.monetary);
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
    std::vector<Coin> coins_h;
    DiskStateError disk_err{};
    if (!store.ExportCoins(coins_h, disk_err)) {
        error = disk_err.message;
        return false;
    }
    UtxoSet state_h;
    for (const Coin &c : coins_h) {
        state_h.Insert(c);
    }

    FramedBlock block;
    if (!DecodeBlockWire(block_wire, ordinary_profile.transaction,
                         header_profile.chain_id, block, error)) {
        return false;
    }
    const auto parent_mtp =
        ParentMedianTime(header_profile, parent_header, history);
    if (!parent_mtp) {
        error = "failed computing ParentMedianTime for disk reverse peel";
        return false;
    }
    std::vector<Coin> net_created;
    std::vector<Coin> prior_spent;
    if (!PartitionBlockOutputsAndSpends(block, *parent_mtp, undo_msg,
                                        net_created, prior_spent, error)) {
        return false;
    }

    if (!PeelBlockReverse(block_wire, undo_msg, parent_header, history,
                          header_profile, ordinary_profile, monetary_profile,
                          cost_profile, state_h, monetary_h, error)) {
        return false;
    }

    std::vector<Outpoint> net_created_outpoints;
    net_created_outpoints.reserve(net_created.size());
    for (const Coin &c : net_created) {
        net_created_outpoints.push_back(c.outpoint);
    }

    DiskStateMetadata parent_meta{};
    BlockId(header_profile.chain_id, parent_header, parent_meta.tip);
    std::array<uint8_t, HEADER_SIZE> raw_parent{};
    SerializeHeader(parent_header, raw_parent);
    parent_meta.header.assign(raw_parent.begin(), raw_parent.end());
    parent_meta.monetary.assign(undo_msg.parent_monetary_state.begin(),
                                undo_msg.parent_monetary_state.end());
    if (!history.empty()) {
        parent_meta.auxiliary = EncodeDiskChainContext(history, {});
    }

    if (!store.PeelBlockStateReverse(meta_h.tip, parent_meta, parent_header,
                                     net_created_outpoints, prior_spent,
                                     disk_err, undo_msg.expired_swept_coins)) {
        error = disk_err.message;
        return false;
    }
    error.clear();
    return true;
}

bool PeelDiskBlockWindowReverse(const std::vector<ReversePeelBlockStep> &steps,
                                const HeaderChainProfile &header_profile,
                                OrdinaryCandidateProfile ordinary_profile,
                                const MonetaryProfile &monetary_profile,
                                const BlockCostProfile &cost_profile,
                                DiskStateStore &store,
                                std::string &error) {
    if (steps.empty()) {
        error = "empty reverse peel block window";
        return false;
    }
    if (!store.IsOpen()) {
        error = "disk state store is closed";
        return false;
    }
    const DiskStateMetadata meta_h = store.Metadata();
    MonetaryState monetary_cur{};
    try {
        monetary_cur = DecodeMonetaryState(meta_h.monetary);
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
    std::vector<Coin> coins_h;
    DiskStateError disk_err{};
    if (!store.ExportCoins(coins_h, disk_err)) {
        error = disk_err.message;
        return false;
    }
    UtxoSet state_cur;
    for (const Coin &c : coins_h) {
        state_cur.Insert(c);
    }

    // Track net delta across the entire K-block reverse peel window:
    // - net_erased_from_initial: outpoints present in the initial disk store at
    //   height h that must be erased to reach height h - K.
    // - net_inserted_at_end: prior spent coins restored during the window that
    //   were NOT created later inside the same window (cross-block ephemeral
    //   UTXOs created at h_i and spent at h_j > h_i cancel out in RAM).
    std::set<Outpoint, OutpointLess> net_erased_from_initial;
    std::map<Outpoint, Coin, OutpointLess> net_inserted_at_end;

    for (const ReversePeelBlockStep &step : steps) {
        FramedBlock block;
        if (!DecodeBlockWire(step.block_wire, ordinary_profile.transaction,
                             header_profile.chain_id, block, error)) {
            return false;
        }
        const auto parent_mtp = ParentMedianTime(
            header_profile, step.parent_header, step.history);
        if (!parent_mtp) {
            error = "failed computing ParentMedianTime for windowed disk reverse peel";
            return false;
        }
        std::vector<Coin> net_created;
        std::vector<Coin> prior_spent;
        if (!PartitionBlockOutputsAndSpends(block, *parent_mtp, step.undo_msg,
                                            net_created, prior_spent, error)) {
            return false;
        }
        if (!PeelBlockReverse(step.block_wire, step.undo_msg,
                              step.parent_header, step.history, header_profile,
                              ordinary_profile, monetary_profile, cost_profile,
                              state_cur, monetary_cur, error)) {
            return false;
        }

        // Apply step (erase net_created, insert prior_spent) to cumulative delta:
        for (const Coin &c : net_created) {
            const auto ins_it = net_inserted_at_end.find(c.outpoint);
            if (ins_it != net_inserted_at_end.end()) {
                // Cross-block ephemeral UTXO: spent in a later block of the
                // window and created in this block; cancels out completely!
                net_inserted_at_end.erase(ins_it);
            } else {
                net_erased_from_initial.insert(c.outpoint);
            }
        }
        for (const Coin &spent : prior_spent) {
            net_inserted_at_end[spent.outpoint] = spent;
        }
    }

    std::vector<Outpoint> final_erased(net_erased_from_initial.begin(),
                                       net_erased_from_initial.end());
    std::vector<Coin> final_inserted;
    final_inserted.reserve(net_inserted_at_end.size());
    for (const auto &[op, coin] : net_inserted_at_end) {
        (void)op;
        final_inserted.push_back(coin);
    }

    const ReversePeelBlockStep &last_step = steps.back();
    DiskStateMetadata final_parent_meta{};
    BlockId(header_profile.chain_id, last_step.parent_header,
            final_parent_meta.tip);
    std::array<uint8_t, HEADER_SIZE> raw_parent{};
    SerializeHeader(last_step.parent_header, raw_parent);
    final_parent_meta.header.assign(raw_parent.begin(), raw_parent.end());
    final_parent_meta.monetary.assign(
        last_step.undo_msg.parent_monetary_state.begin(),
        last_step.undo_msg.parent_monetary_state.end());
    if (!last_step.history.empty()) {
        final_parent_meta.auxiliary =
            EncodeDiskChainContext(last_step.history, {});
    }

    if (!store.PeelBlockStateReverse(meta_h.tip, final_parent_meta,
                                     last_step.parent_header, final_erased,
                                     final_inserted, disk_err)) {
        error = disk_err.message;
        return false;
    }
    error.clear();
    return true;
}

} // namespace lotus::v2
