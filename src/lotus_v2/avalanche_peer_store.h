// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_AVALANCHE_PEER_STORE_H
#define LOTUS_V2_AVALANCHE_PEER_STORE_H
#include "avalanche_quorum.h"
#include <filesystem>
namespace lotus::v2::ava {
enum class PeerStoreCode { Ok, Missing, Resource, Corrupt, ForeignProfile, Io, Ambiguous, Poisoned };
struct PeerStoreResult { PeerStoreCode code{PeerStoreCode::Ok}; std::string message; explicit operator bool() const { return code == PeerStoreCode::Ok; } };
struct PeerStoreLimits {
    uint64_t payload_bytes{16 << 20}, records{10000}, proof_bytes{256 << 10}, locks_per_proof{1000}, payout_bytes{10000};
};
// Paths must have real directory ancestors (including /private/tmp on macOS);
// symlink ancestors and parent traversal are rejected. Use one serialized owner.
// Public proofs and peer metadata only. Load validates storage framing, never
// chain validity: callers re-admit records individually and may skip stale proofs
// just as pinned ABC loadPeersFromFile does. No session/finality tip is stored.
class PeerStore {
public:
    enum class Fault { None, BeforeReplace, AfterReplace }; // deterministic durability tests
    PeerStore(std::filesystem::path path, Profile profile, PeerStoreLimits limits = {});
    PeerStoreResult Load(std::vector<PersistedPeer> &) const;
    PeerStoreResult Save(const std::vector<PersistedPeer> &, Fault = Fault::None);
    bool Poisoned() const { return poisoned_; }
private:
    std::filesystem::path path_; Profile profile_; PeerStoreLimits limits_; bool poisoned_{};
};
}
#endif
