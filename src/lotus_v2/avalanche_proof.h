// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_AVALANCHE_PROOF_H
#define LOTUS_V2_AVALANCHE_PROOF_H
#include <avalanche/avalanche.h>
#include <avalanche/proof.h>
#include <avalanche/voterecord.h>
#include "sparse_state.h"
#include <functional>
namespace lotus::v2::ava {
// All amounts map one V2 base unit to one ABC SATOSHI. This adapter retains
// ABC proof signatures/ids/score; payout script is proof metadata, never a V2
// coinbase instruction. Only native single-key Payment locks are supported.
struct Profile {
    Hash chain_id{}, genesis_id{}, validation_digest{};
    Amount stake_dust{::avalanche::PROOF_DUST_THRESHOLD};
    uint32_t stake_confirmations{AVALANCHE_DEFAULT_STAKE_UTXO_CONFIRMATIONS};
    Amount min_quorum_stake{AVALANCHE_DEFAULT_MIN_QUORUM_STAKE};
    double min_connected_ratio{AVALANCHE_DEFAULT_MIN_QUORUM_CONNECTED_STAKE_RATIO};
    uint32_t min_avaproofs_nodes{8};
    uint64_t conflicting_proof_cooldown_seconds{AVALANCHE_DEFAULT_CONFLICTING_PROOF_COOLDOWN};
    uint64_t peer_replacement_cooldown_seconds{AVALANCHE_DEFAULT_PEER_REPLACEMENT_COOLDOWN};
    uint32_t stale_vote_threshold{AVALANCHE_VOTE_STALE_THRESHOLD}, stale_vote_factor{AVALANCHE_VOTE_STALE_FACTOR};
    uint32_t max_element_poll{1024}, query_timeout_ms{10000};
    bool persist_peers{DEFAULT_PERSIST_AVAPEERS};
    uint64_t max_proofs{10000}, max_nodes{10000}, max_queries{10000};
};
struct ChainSnapshot { Hash tip{}; uint64_t generation{}, height{}, median_time_past{}; bool initial_download{}; bool operator==(const ChainSnapshot &) const = default; };
using SnapshotReader = std::function<ChainSnapshot()>;
using CoinLookup = std::function<bool(const Outpoint &, std::optional<Coin> &, std::string &)>;
struct ProofEnvelope {
    ::avalanche::ProofRef proof;
    // Ordered with signed stakes. Each must be exactly PUSH32 x-only-key
    // followed by bytes 0xbc,0x4e (35 bytes), and match the coin's sole branch leaf.
    std::vector<std::vector<uint8_t>> payment_locks;
};
struct AdmittedProof { ProofEnvelope envelope; ChainSnapshot validated_at; };
bool ValidateProfile(const Profile &, std::string &);
bool AdmitProof(const Profile &, const ChainSnapshot &, const CoinLookup &,
                const ProofEnvelope &, AdmittedProof &, const SnapshotReader &, std::string &);
} // namespace lotus::v2::ava
#endif
