// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_AVALANCHE_POLL_H
#define LOTUS_V2_AVALANCHE_POLL_H
#include "avalanche_chain.h"
#include "avalanche_diagnostics.h"
#include "avalanche_quorum.h"
#include <memory>
namespace lotus::v2::ava {
enum class ItemKind { Block, Proof };
struct PollItem { ItemKind kind{}; Hash id{}; bool operator<(const PollItem &) const; };
struct OutgoingPoll { NodeId node{}; uint64_t round{}; std::vector<PollItem> items; };
enum class PollReceiveResult { Applied, Ignored, Rejected, LocalFailure };
class PollEngine {
public:
    explicit PollEngine(Profile);
    ~PollEngine();
    bool Reconcile(const PollItem &, bool accepted, std::string &);
    // Remove obsolete proof records before admitting replacement inventory.
    // Work is bounded by max_queries; other vote histories remain intact.
    void PruneProofs(const Quorum &);
    bool Next(Quorum &, const ChainSnapshot &, int64_t now_milliseconds,
              OutgoingPoll &, std::string &);
    // Query deadlines use monotonic milliseconds; proof replacement times use
    // the independently supplied wall-clock seconds.
    // Single-owner operation: apply must atomically accept/reject the whole
    // block batch and must not reenter this engine or mutate quorum. Proof
    // transitions and staged vote confidence commit only after it accepts.
    PollReceiveResult ReceiveResponse(Quorum &, NodeId, const SignedResponse &, const ChainSnapshot &,
                 int64_t now_milliseconds, int64_t wall_seconds, const ApplyBlockUpdates &, std::string &);
    // Compatibility predicate: only Applied is true; an authenticated ignored
    // late/unknown response is false but is not grounds to disconnect its peer.
    bool Receive(Quorum &, NodeId, const SignedResponse &, const ChainSnapshot &,
                 int64_t now_milliseconds, int64_t wall_seconds, const ApplyBlockUpdates &, std::string &);
    // Signatures for incoming polls are not required by ABC; only authenticated
    // connection admission and signed outgoing responses. Observe is fenced.
    bool Respond(const OutgoingPoll &, const ObserveBlock &, const Quorum &,
                 const CKey &session_key, SignedResponse &, std::string &) const;
    void Disconnect(NodeId);
    // Passive native VoteRecord observation; never polls or expires queries.
    std::optional<uint16_t> Confidence(const PollItem &) const;
    PollDiagnostics Diagnostics() const;
private:
    PollReceiveResult ReceiveResponseImpl(Quorum &, NodeId, const SignedResponse &, const ChainSnapshot &,
        int64_t, int64_t, const ApplyBlockUpdates &, std::string &);
    struct Impl; std::unique_ptr<Impl> impl_;
};
} // namespace lotus::v2::ava
#endif
