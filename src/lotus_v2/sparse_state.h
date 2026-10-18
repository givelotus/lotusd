// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_SPARSE_STATE_H
#define LOTUS_V2_SPARSE_STATE_H

#include "output.h"
#include "tagged_hash.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <vector>

namespace lotus::v2 {

// Internal legacy state coins may carry any spendable ABC script (<=10000).
// Versioned coin provenance includes the fee share and effective expiry.
constexpr uint8_t COIN_ENCODING_VERSION = 2;
constexpr size_t COIN_METADATA_BYTES = 34;
constexpr size_t MAX_COIN_BYTES = 10085;

// C17a Deterministic Fee-Backed UTXO Expiry & Fee-Capped Cleaning Crew constants.
constexpr uint64_t UTXO_MIN_LIFESPAN_BLOCKS = 131400;      // ~3 months at 1-min blocks
constexpr uint64_t UTXO_MAX_LIFESPAN_BLOCKS = 21024000;    // ~40 years at 1-min blocks (ordinary cap & coinbase lifespan)
constexpr uint64_t UTXO_RENT_ATOMS_PER_BLOCK = 1;          // 1 atom (10^-8 XPI) per block of lifespan extension
constexpr size_t MAX_EXPIRY_SWEEPS_PER_BLOCK = 1024;       // Hard cap on expired UTXO sweeps per block
constexpr uint64_t CLEANING_CREW_BASE_REWARD_ATOMS = 2000; // 2,000 atoms per swept expired UTXO (capped by block fees)

struct Outpoint {
    Hash tx_id{};
    uint32_t index{};
    bool operator==(const Outpoint &) const = default;
};

struct OutpointLess {
    bool operator()(const Outpoint &a, const Outpoint &b) const {
        return a.tx_id != b.tx_id ? a.tx_id < b.tx_id : a.index < b.index;
    }
};

struct Coin {
    Outpoint outpoint;
    Output output;
    uint64_t creation_height{};
    uint64_t creation_parent_mtp{};
    bool coinbase{};
    uint64_t fee_per_output{};
    uint64_t expiration_height{};
};

using CoinEntry = Coin;

constexpr uint64_t ComputeTxFeePerSpendableOutput(uint64_t total_fee_atoms,
                                                  size_t spendable_output_count) {
    return spendable_output_count == 0
               ? 0
               : total_fee_atoms / static_cast<uint64_t>(spendable_output_count);
}

constexpr uint64_t ComputeUtxoLifespanBlocks(bool coinbase,
                                             uint64_t fee_per_output = 0) {
    if (coinbase) {
        return UTXO_MAX_LIFESPAN_BLOCKS;
    }
    const uint64_t extension = fee_per_output / UTXO_RENT_ATOMS_PER_BLOCK;
    if (extension >= UTXO_MAX_LIFESPAN_BLOCKS - UTXO_MIN_LIFESPAN_BLOCKS) {
        return UTXO_MAX_LIFESPAN_BLOCKS;
    }
    return UTXO_MIN_LIFESPAN_BLOCKS + extension;
}

constexpr uint64_t ComputeUtxoExpirationHeight(uint64_t creation_height,
                                               bool coinbase,
                                               uint64_t fee_per_output = 0) {
    const uint64_t lifespan = ComputeUtxoLifespanBlocks(coinbase, fee_per_output);
    if (creation_height > std::numeric_limits<uint64_t>::max() - lifespan) {
        return std::numeric_limits<uint64_t>::max();
    }
    return creation_height + lifespan;
}

constexpr uint64_t ComputeUtxoLifespanBlocks(const Coin &coin) {
    return ComputeUtxoLifespanBlocks(coin.coinbase, coin.fee_per_output);
}

constexpr uint64_t ComputeUtxoExpirationHeight(const Coin &coin) {
    if (coin.expiration_height != 0) {
        return coin.expiration_height;
    }
    return ComputeUtxoExpirationHeight(coin.creation_height, coin.coinbase,
                                       coin.fee_per_output);
}

constexpr bool IsUtxoExpired(const Coin &coin, uint64_t block_height) {
    return block_height >= ComputeUtxoExpirationHeight(coin);
}

constexpr uint64_t ComputeCleaningCrewBounty(size_t swept_count,
                                             uint64_t total_block_fees_atoms) {
    const uint64_t capped_count = std::min<uint64_t>(
        static_cast<uint64_t>(swept_count), MAX_EXPIRY_SWEEPS_PER_BLOCK);
    const uint64_t uncapped = capped_count * CLEANING_CREW_BASE_REWARD_ATOMS;
    return std::min(uncapped, total_block_fees_atoms / 2);
}

struct ExpirySweepResult {
    std::vector<Coin> swept_coins;
    uint64_t swept_count{};
    uint64_t burned_value_atoms{};
    uint64_t cleaning_crew_bounty_atoms{};
};

// Coin output grammar is checked by the P01 Output codec. Burn outputs reject.
bool EncodeCoin(const Coin &coin, std::vector<uint8_t> &encoded);
bool DecodeCoinBytes(std::span<const uint8_t> encoded, Coin &coin);
Hash OutpointKey(const Outpoint &outpoint);
Hash EmptyUtxoRoot();
bool UtxoLeaf(const Coin &coin, Hash &out);
bool UtxoNode(uint16_t depth, const Hash &left, const Hash &right, Hash &out);

enum class ProofPresence : uint8_t { Empty = 0, Present = 1, OtherLeaf = 2 };
struct CoinProof {
    ProofPresence presence{};
    std::optional<Coin> coin;
    Hash bitmap{}; // Bit d marks a nonempty sibling at depth d.
    std::vector<Hash> siblings; // Deepest sibling first.
};

// Typed proof verifier. Wire framing and consensus context are separate.
bool VerifyCoinProof(const Outpoint &query, const CoinProof &proof,
                     const Hash &expected_root);

// Bounded scalar reference model, not a database or incremental production
// index. Every operation recomputes its root from the complete coin set.
class UtxoSet {
public:
    bool Insert(const Coin &coin); // Reject duplicate outpoint or occupied key.
    bool Erase(const Outpoint &outpoint);
    const Coin *Find(const Outpoint &outpoint) const;
    std::vector<Coin> CollectExpiredCoins(
        uint64_t block_height,
        size_t max_sweeps = MAX_EXPIRY_SWEEPS_PER_BLOCK) const;
    ExpirySweepResult SweepExpired(
        uint64_t block_height, uint64_t total_block_fees_atoms = 0,
        size_t max_sweeps = MAX_EXPIRY_SWEEPS_PER_BLOCK);
    Hash Root() const;
    CoinProof Prove(const Outpoint &query) const;
    size_t Size() const { return coins_.size(); }
    const std::vector<Coin> &Coins() const { return coins_; }

private:
    std::vector<Coin> coins_;
};

struct MonetaryState {
    uint64_t bootstrap_reserve{};
    uint64_t tail_subsidy{};
    Hash prev_work{}; // LE unsigned u256.
    uint64_t ema_block_cost{};
};
std::array<uint8_t, 56> EncodeMonetaryState(const MonetaryState &state);
MonetaryState DecodeMonetaryState(const std::vector<uint8_t> &wire);
Hash StateRoot(const ChainId &chain_id, uint64_t height,
               const Hash &utxo_root, const MonetaryState &state);

} // namespace lotus::v2
#endif
