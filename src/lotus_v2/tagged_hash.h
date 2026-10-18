// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_TAGGED_HASH_H
#define LOTUS_V2_TAGGED_HASH_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

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
};

// Hardware-accelerated BIP-340 style tagged SHA-256:
// SHA256(SHA256(tag) || SHA256(tag) || payload).
Hash TaggedHash(HashDomain domain, std::span<const uint8_t> payload);

} // namespace lotus::v2
#endif
