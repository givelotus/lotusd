// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_AVALANCHE_QUORUM_H
#define LOTUS_V2_AVALANCHE_QUORUM_H
#include "avalanche_protocol.h"
#include "avalanche_chain.h"
#include <memory>
namespace lotus::v2::ava {
struct PersistedPeer {
    ProofEnvelope envelope;
    bool finalized{};
    int64_t registration_time{}, next_conflict_time{};
};
// Counts describe current proof membership and authenticated bindings. Eligible
// peers have an active proof; cooldown does not change eligibility. Connected
// stake counts each active proof once, even when multiple peers bind it.
struct QuorumStatus {
    bool ready{}, established{};
    uint64_t proof_count{}, authenticated_peer_count{}, eligible_peer_count{};
    uint64_t active_stake_score{}, connected_stake_score{};
};
class Quorum {
public:
    explicit Quorum(Profile);
    ~Quorum();
    bool Register(const ProofEnvelope &, const ChainSnapshot &, const CoinLookup &,
                  int64_t now_seconds, const SnapshotReader &, std::string &);
    bool Bind(NodeId, const ::avalanche::Delegation &, const SchnorrSig &,
              const ConnectionTranscript &, uint32_t max_elements, std::string &);
    void Disconnect(NodeId);
    void SentProofInventory(NodeId, const ChainSnapshot &);
    bool Established(const ChainSnapshot &);
    bool Ready() const;
    QuorumStatus Status() const;
    std::optional<NodeId> Select(int64_t now_milliseconds);
    std::optional<AuthenticatedHello> Node(NodeId) const;
    void Cooldown(NodeId, int64_t until_milliseconds);
    bool Revalidate(const ChainSnapshot &, const CoinLookup &, int64_t now_seconds, const SnapshotReader &, std::string &);
    bool ApplyProofVote(const ::avalanche::ProofId &, ::lotus::v2::ava::Status, int64_t now_seconds,
                        std::string &);
    bool ApplyProofVotes(const std::vector<std::pair<::avalanche::ProofId,::lotus::v2::ava::Status>> &,
                         int64_t now_seconds,
                         const std::function<bool(std::string &)> &commit_blocks,
                         std::string &);
    uint32_t Vote(const ::avalanche::ProofId &) const;
    bool Immature(const ::avalanche::ProofId &) const;
    bool Known(const ::avalanche::ProofId &) const;
    bool Pollable(const ::avalanche::ProofId &) const;
    std::vector<::avalanche::ProofId> Proofs() const;
    std::vector<PersistedPeer> ExportPeers() const;
    // Restore is startup-only and atomic. Every native coin and signed proof
    // is revalidated; session bindings, poll confidence and final tip are volatile.
    bool RestorePeers(const std::vector<PersistedPeer> &, const ChainSnapshot &,
                      const CoinLookup &, const SnapshotReader &, std::string &);
private:
    struct Impl; std::unique_ptr<Impl> impl_;
};
} // namespace lotus::v2::ava
#endif
