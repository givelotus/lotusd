// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_TAGGED_HASH_H
#define LOTUS_V2_TAGGED_HASH_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lotus::v2 {

using Hash = std::array<uint8_t, 32>;
using ChainId = Hash;
using Bytes32 = Hash;

enum class HashDomain {
    HeaderBody,
    HeaderWork,
    BlockId,
    Branch,
    InputCore,
    InputFull,
    OwnInput,
    Sighash,
    Output,
    CoinEntry,
    MerkleIndex,
    TxId,
    TxHash,
    TxRoot,
    OutpointKey,
    Utxo,
    State,
    PreconsensusBatch,
    ContractState,
    // Simulation-only placeholder branch roots (vm_simulation.h).
    SimPlaceholder,
    // Non-consensus VM profile commitment (VmProfileDigest).
    VmProfile,
    // Name of a transaction that is not a well-formed V2 structure: the
    // chain ID and its complete serialization (never a valid identity).
    TxIdFallback,
};

// Hardware-accelerated BIP-340 style tagged SHA-256:
// SHA256(SHA256(tag) || SHA256(tag) || payload).
Hash TaggedHash(HashDomain domain, std::span<const uint8_t> payload);

// STATEHASH digest over item_1..item_k (item_1 first, i.e. deepest on the
// stack): TaggedHash(ContractState, CS(k) || for each item CS(len) || item),
// with shortest-form CompactSize. Streams the preimage without building it.
Hash ContractStateHash(std::span<const std::vector<uint8_t>> items);

} // namespace lotus::v2
#endif
