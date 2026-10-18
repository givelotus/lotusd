// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_SPARSE_STATE_H
#define LOTUS_V2_SPARSE_STATE_H

#include "output.h"
#include "tagged_hash.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace lotus::v2 {

// Internal legacy state coins may carry any spendable ABC script (<=10000).
constexpr size_t MAX_COIN_BYTES = 10068;

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
