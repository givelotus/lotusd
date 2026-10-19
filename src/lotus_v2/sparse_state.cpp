#include "sparse_state.h"

#include "tagged_hash.h"

#include <algorithm>
#include <cassert>
#include <stdexcept>
#include <string>

namespace lotus::v2 {
namespace {
template <size_t N> void PutLE(std::array<uint8_t, N> &out, size_t at,
                              uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) out[at + i] = static_cast<uint8_t>(value >> (8 * i));
}

void PutCompactSize(std::vector<uint8_t> &out, uint64_t n) {
    if (n < 253) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        out.push_back(253);
        for (unsigned i = 0; i < 2; ++i) out.push_back(static_cast<uint8_t>(n >> (8 * i)));
    } else if (n <= 0xffffffffU) {
        out.push_back(254);
        for (unsigned i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(n >> (8 * i)));
    } else {
        out.push_back(255);
        for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(n >> (8 * i)));
    }
}

bool KeyBit(const Hash &key, unsigned depth) {
    return (key[depth / 8] >> (depth % 8)) & 1;
}

void SetBit(Hash &bitmap, unsigned depth) { bitmap[depth / 8] |= uint8_t{1} << (depth % 8); }
bool GetBit(const Hash &bitmap, unsigned depth) { return (bitmap[depth / 8] >> (depth % 8)) & 1; }

Hash NodeAtDepth(unsigned depth, const Hash &left, const Hash &right) {
    assert(depth < 256);
    std::array<uint8_t, 67> input{};
    input[0] = 1;
    input[1] = static_cast<uint8_t>(depth);
    input[2] = static_cast<uint8_t>(depth >> 8);
    std::copy(left.begin(), left.end(), input.begin() + 3);
    std::copy(right.begin(), right.end(), input.begin() + 35);
    return TaggedHash(HashDomain::Utxo, input);
}

struct Entry {
    Hash key;
    const Coin *coin;
};

Hash RootOf(const std::vector<Entry> &entries, unsigned depth) {
    if (entries.empty()) return EmptyUtxoRoot();
    if (entries.size() == 1) {
        Hash result;
        const bool valid = UtxoLeaf(*entries[0].coin, result);
        assert(valid);
        (void)valid;
        return result;
    }
    assert(depth < 256); // Insertion rejects equal keys.
    std::vector<Entry> left, right;
    for (const Entry &entry : entries) {
        (KeyBit(entry.key, depth) ? right : left).push_back(entry);
    }
    return NodeAtDepth(depth, RootOf(left, depth + 1), RootOf(right, depth + 1));
}

std::vector<Entry> Entries(const std::vector<Coin> &coins) {
    std::vector<Entry> entries;
    entries.reserve(coins.size());
    for (const Coin &coin : coins) entries.push_back({OutpointKey(coin.outpoint), &coin});
    return entries;
}

void ProveAt(const std::vector<Entry> &entries, unsigned depth,
             const Outpoint &query, const Hash &query_key, CoinProof &proof) {
    if (entries.empty()) {
        proof.presence = ProofPresence::Empty;
        return;
    }
    if (entries.size() == 1) {
        proof.coin = *entries[0].coin;
        proof.presence = entries[0].coin->outpoint == query
                             ? ProofPresence::Present : ProofPresence::OtherLeaf;
        return;
    }
    assert(depth < 256);
    std::vector<Entry> left, right;
    for (const Entry &entry : entries) {
        (KeyBit(entry.key, depth) ? right : left).push_back(entry);
    }
    const bool bit = KeyBit(query_key, depth);
    const auto &selected = bit ? right : left;
    const auto &other = bit ? left : right;
    ProveAt(selected, depth + 1, query, query_key, proof);
    if (!other.empty()) {
        SetBit(proof.bitmap, depth);
        proof.siblings.push_back(RootOf(other, depth + 1));
    }
}
} // namespace

bool EncodeCoin(const Coin &coin, std::vector<uint8_t> &encoded) {
    if (coin.output.IsBurn()) return false;
    std::vector<uint8_t> output;
    std::string error;
    // A legacy coin is recorded with its LegacyCoinWire (0x80 discriminator).
    if (!EncodeCoinOutput(coin.output, output, error)) return false;
    std::vector<uint8_t> result;
    result.reserve(36 + 9 + output.size() + COIN_METADATA_BYTES);
    result.insert(result.end(), coin.outpoint.tx_id.begin(), coin.outpoint.tx_id.end());
    for (unsigned i = 0; i < 4; ++i) result.push_back(static_cast<uint8_t>(coin.outpoint.index >> (8 * i)));
    PutCompactSize(result, output.size());
    result.insert(result.end(), output.begin(), output.end());
    for (unsigned i = 0; i < 8; ++i) result.push_back(static_cast<uint8_t>(coin.creation_height >> (8 * i)));
    for (unsigned i = 0; i < 8; ++i) result.push_back(static_cast<uint8_t>(coin.creation_parent_mtp >> (8 * i)));
    result.push_back(coin.coinbase ? 1 : 0);
    result.push_back(COIN_ENCODING_VERSION);
    for (unsigned i = 0; i < 8; ++i) result.push_back(uint8_t(coin.fee_per_output >> (8 * i)));
    const uint64_t expiry = ComputeUtxoExpirationHeight(coin);
    for (unsigned i = 0; i < 8; ++i) result.push_back(uint8_t(expiry >> (8 * i)));
    if (result.size() > MAX_COIN_BYTES) return false;
    encoded = std::move(result);
    return true;
}

bool DecodeCoinBytes(std::span<const uint8_t> encoded, Coin &out) {
    if (encoded.size() < 36 + 1 + COIN_METADATA_BYTES || encoded.size() > MAX_COIN_BYTES) {
        return false;
    }
    Coin coin;
    std::copy_n(encoded.data(), 32, coin.outpoint.tx_id.begin());
    coin.outpoint.index = uint32_t(encoded[32]) |
                          (uint32_t(encoded[33]) << 8) |
                          (uint32_t(encoded[34]) << 16) |
                          (uint32_t(encoded[35]) << 24);
    size_t pos = 36;
    uint64_t out_len = 0;
    const uint8_t lead = encoded[pos++];
    if (lead < 253) {
        out_len = lead;
    } else {
        const unsigned width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
        if (pos + width > encoded.size()) return false;
        for (unsigned i = 0; i < width; ++i) {
            out_len |= uint64_t(encoded[pos++]) << (8 * i);
        }
    }
    if (out_len > encoded.size() - pos || encoded.size() - pos - out_len != COIN_METADATA_BYTES) return false;
    std::string error;
    if (out_len && encoded[pos] == 0x80) {
        const size_t end = pos + size_t(out_len);
        size_t cursor = pos + 1;
        if (end - cursor < 9) return false;
        for (unsigned i = 0; i < 8; ++i) coin.output.value |= uint64_t(encoded[cursor++]) << (8 * i);
        uint64_t len = encoded[cursor++];
        if (len >= 253) {
            const unsigned width = len == 253 ? 2 : len == 254 ? 4 : 8;
            if (end - cursor < width) return false;
            len = 0;
            for (unsigned i = 0; i < width; ++i) len |= uint64_t(encoded[cursor++]) << (8 * i);
        }
        if (len > 10000 || len != end - cursor) return false;
        coin.output.legacy_script.emplace(encoded.begin() + cursor, encoded.begin() + end);
    } else if (!DecodeOutput(std::vector<uint8_t>(encoded.begin() + pos,
                                           encoded.begin() + pos + out_len),
                      coin.output, error)) {
        return false;
    }
    pos += static_cast<size_t>(out_len);
    coin.creation_height = 0;
    coin.creation_parent_mtp = 0;
    for (unsigned i = 0; i < 8; ++i) {
        coin.creation_height |= uint64_t(encoded[pos + i]) << (8 * i);
        coin.creation_parent_mtp |= uint64_t(encoded[pos + 8 + i]) << (8 * i);
    }
    const uint8_t cb_flag = encoded[pos + 16];
    if (cb_flag > 1) return false;
    coin.coinbase = (cb_flag == 1);
    if (encoded[pos + 17] != COIN_ENCODING_VERSION) return false;
    for (unsigned i = 0; i < 8; ++i) {
        coin.fee_per_output |= uint64_t(encoded[pos + 18 + i]) << (8 * i);
        coin.expiration_height |= uint64_t(encoded[pos + 26 + i]) << (8 * i);
    }
    std::vector<uint8_t> roundtrip;
    if (!EncodeCoin(coin, roundtrip) || roundtrip.size() != encoded.size() ||
        !std::equal(roundtrip.begin(), roundtrip.end(), encoded.begin())) {
        return false;
    }
    out = std::move(coin);
    return true;
}

Hash OutpointKey(const Outpoint &outpoint) {
    Hash key = outpoint.tx_id;
    for (unsigned i = 0; i < 4; ++i) {
        key[28 + i] ^= static_cast<uint8_t>(outpoint.index >> (8 * i));
    }
    return key;
}

Hash EmptyUtxoRoot() {
    static const Hash kEmpty =
        TaggedHash(HashDomain::Utxo, std::array<uint8_t, 1>{2});
    return kEmpty;
}

bool UtxoLeaf(const Coin &coin, Hash &out) {
    std::vector<uint8_t> serialized;
    serialized.reserve(128);
    if (!EncodeCoin(coin, serialized)) return false;
    const Hash key = OutpointKey(coin.outpoint);
    if (serialized.size() < 253) {
        std::array<uint8_t, 1 + 32 + 1 + 252> stack_buf{};
        stack_buf[0] = 0;
        std::memcpy(stack_buf.data() + 1, key.data(), 32);
        stack_buf[33] = static_cast<uint8_t>(serialized.size());
        std::memcpy(stack_buf.data() + 34, serialized.data(), serialized.size());
        out = TaggedHash(HashDomain::Utxo,
                         std::span<const uint8_t>(stack_buf.data(),
                                                  34 + serialized.size()));
        return true;
    }
    std::vector<uint8_t> input;
    input.reserve(1 + 32 + 9 + serialized.size());
    input.push_back(0);
    input.insert(input.end(), key.begin(), key.end());
    PutCompactSize(input, serialized.size());
    input.insert(input.end(), serialized.begin(), serialized.end());
    out = TaggedHash(HashDomain::Utxo, input);
    return true;
}

bool UtxoNode(uint16_t depth, const Hash &left, const Hash &right, Hash &out) {
    if (depth >= 256) return false;
    out = NodeAtDepth(depth, left, right);
    return true;
}

bool UtxoSet::Insert(const Coin &coin) {
    Hash ignored;
    if (!UtxoLeaf(coin, ignored)) return false;
    const Hash key = OutpointKey(coin.outpoint);
    for (const Coin &existing : coins_) {
        if (existing.outpoint == coin.outpoint || OutpointKey(existing.outpoint) == key) return false;
    }
    Coin stored = coin;
    if (stored.expiration_height == 0) {
        stored.expiration_height = ComputeUtxoExpirationHeight(
            stored.creation_height, stored.coinbase, stored.fee_per_output);
    }
    coins_.push_back(std::move(stored));
    return true;
}

bool UtxoSet::Erase(const Outpoint &outpoint) {
    auto it = std::find_if(coins_.begin(), coins_.end(),
                           [&](const Coin &coin) { return coin.outpoint == outpoint; });
    if (it == coins_.end()) return false;
    coins_.erase(it);
    return true;
}

const Coin *UtxoSet::Find(const Outpoint &outpoint) const {
    auto it = std::find_if(coins_.begin(), coins_.end(),
                           [&](const Coin &coin) { return coin.outpoint == outpoint; });
    return it == coins_.end() ? nullptr : &(*it);
}

std::vector<Coin> UtxoSet::CollectExpiredCoins(uint64_t block_height,
                                               size_t max_sweeps) const {
    if (max_sweeps == 0) return {};
    struct Candidate {
        uint64_t expiration_height;
        Hash key;
        Coin coin;
    };
    std::vector<Candidate> candidates;
    for (const Coin &coin : coins_) {
        if (IsUtxoExpired(coin, block_height)) {
            candidates.push_back(
                {ComputeUtxoExpirationHeight(coin), OutpointKey(coin.outpoint), coin});
        }
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate &a, const Candidate &b) {
                  if (a.expiration_height != b.expiration_height) {
                      return a.expiration_height < b.expiration_height;
                  }
                  return a.key < b.key;
              });
    const size_t count = std::min(candidates.size(), max_sweeps);
    std::vector<Coin> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        out.push_back(std::move(candidates[i].coin));
    }
    return out;
}

ExpirySweepResult UtxoSet::SweepExpired(uint64_t block_height,
                                        uint64_t total_block_fees_atoms,
                                        size_t max_sweeps) {
    ExpirySweepResult res{};
    res.swept_coins = CollectExpiredCoins(block_height, max_sweeps);
    res.swept_count = res.swept_coins.size();
    for (const Coin &coin : res.swept_coins) {
        if (!coin.output.HasToken()) {
            res.burned_value_atoms += coin.output.value;
        }
        Erase(coin.outpoint);
    }
    res.cleaning_crew_bounty_atoms =
        ComputeCleaningCrewBounty(res.swept_count, total_block_fees_atoms);
    return res;
}

Hash UtxoSet::Root() const { return RootOf(Entries(coins_), 0); }

CoinProof UtxoSet::Prove(const Outpoint &query) const {
    CoinProof proof;
    ProveAt(Entries(coins_), 0, query, OutpointKey(query), proof);
    return proof;
}

bool VerifyCoinProof(const Outpoint &query, const CoinProof &proof,
                     const Hash &expected_root) {
    if (static_cast<uint8_t>(proof.presence) > 2) return false;
    if ((proof.presence == ProofPresence::Empty) != !proof.coin.has_value()) return false;
    int highest = -1;
    size_t count = 0;
    for (unsigned d = 0; d < 256; ++d) {
        if (GetBit(proof.bitmap, d)) {
            highest = d;
            ++count;
        }
    }
    if (proof.siblings.size() != count) return false;
    const unsigned k = highest + 1;
    const Hash query_key = OutpointKey(query);
    Hash acc = EmptyUtxoRoot();
    if (proof.coin) {
        const Coin &coin = *proof.coin;
        if (proof.presence == ProofPresence::Present && coin.outpoint != query) return false;
        if (proof.presence == ProofPresence::OtherLeaf && coin.outpoint == query) return false;
        const Hash other_key = OutpointKey(coin.outpoint);
        if (proof.presence == ProofPresence::OtherLeaf) {
            for (unsigned d = 0; d < k; ++d) {
                if (KeyBit(query_key, d) != KeyBit(other_key, d)) return false;
            }
        }
        if (!UtxoLeaf(coin, acc)) return false;
    }
    size_t sibling_index = 0;
    for (int d = static_cast<int>(k) - 1; d >= 0; --d) {
        Hash sibling = EmptyUtxoRoot();
        if (GetBit(proof.bitmap, d)) {
            sibling = proof.siblings[sibling_index++];
            if (sibling == EmptyUtxoRoot()) return false;
        }
        acc = KeyBit(query_key, d) ? NodeAtDepth(d, sibling, acc)
                                   : NodeAtDepth(d, acc, sibling);
    }
    return acc == expected_root;
}

std::array<uint8_t, 56> EncodeMonetaryState(const MonetaryState &state) {
    std::array<uint8_t, 56> out{};
    PutLE(out, 0, state.bootstrap_reserve, 8);
    PutLE(out, 8, state.tail_subsidy, 8);
    std::copy(state.prev_work.begin(), state.prev_work.end(), out.begin() + 16);
    PutLE(out, 48, state.ema_block_cost, 8);
    return out;
}

MonetaryState DecodeMonetaryState(const std::vector<uint8_t> &wire) {
    if (wire.size() != 56) {
        throw std::invalid_argument("MonetaryState length");
    }
    auto read_u64 = [&](size_t offset) -> uint64_t {
        uint64_t value = 0;
        for (size_t i = 0; i < 8; ++i) {
            value |= static_cast<uint64_t>(wire[offset + i]) << (8 * i);
        }
        return value;
    };
    MonetaryState state{};
    state.bootstrap_reserve = read_u64(0);
    state.tail_subsidy = read_u64(8);
    bool nonzero_work = false;
    for (size_t i = 0; i < 32; ++i) {
        state.prev_work[i] = wire[16 + i];
        if (wire[16 + i] != 0) nonzero_work = true;
    }
    if (!nonzero_work) {
        throw std::invalid_argument("zero previous work");
    }
    state.ema_block_cost = read_u64(48);
    return state;
}

Hash StateRoot(const ChainId &chain_id, uint64_t height,
               const Hash &utxo_root, const MonetaryState &state) {
    std::array<uint8_t, 130> input{};
    input[0] = 0;
    std::copy(chain_id.begin(), chain_id.end(), input.begin() + 1);
    PutLE(input, 33, height, 8);
    std::copy(utxo_root.begin(), utxo_root.end(), input.begin() + 41);
    input[73] = 56; // Bytes(MonetaryState), fixed CompactSize length.
    const auto monetary = EncodeMonetaryState(state);
    std::copy(monetary.begin(), monetary.end(), input.begin() + 74);
    return TaggedHash(HashDomain::State, input);
}

} // namespace lotus::v2
