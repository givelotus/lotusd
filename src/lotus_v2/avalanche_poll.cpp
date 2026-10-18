// Copyright (c) 2026 The Lotus developers
#include "avalanche_poll.h"
#include <avalanche/voterecord.h>
#include <common/bloom.h>
#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
namespace lotus::v2::ava {
namespace {
uint256 Native(const Hash &id) { uint256 out; std::copy(id.begin(),id.end(),out.begin()); return out; }
bool Fail(std::string &error,const char *message) { error=message; return false; }
int64_t Deadline(int64_t now,uint64_t delta) {
    if(delta>uint64_t(std::numeric_limits<int64_t>::max()) || now>std::numeric_limits<int64_t>::max()-int64_t(delta)) return std::numeric_limits<int64_t>::max();
    return now+int64_t(delta);
}
}
bool PollItem::operator<(const PollItem &other) const { return kind!=other.kind?kind<other.kind:id<other.id; }
struct PollEngine::Impl {
    Profile profile;
    uint64_t round{};
    PollDiagnostics diagnostics;
    std::map<PollItem,::avalanche::VoteRecord> records;
    struct Query { std::vector<PollItem> items; int64_t timeout{}; };
    std::map<std::pair<NodeId,uint64_t>,Query> queries;
    CRollingBloomFilter finalized{AVALANCHE_MAX_INFLIGHT_POLL * 20,0.0000001};
    CRollingBloomFilter invalidated{100,0.0000001};
    explicit Impl(Profile p):profile(std::move(p)) { std::string error; if(!ValidateProfile(profile,error)) throw std::invalid_argument(error); }
    void Release(const Query &query) { for(const auto &item:query.items) { auto it=records.find(item); if(it!=records.end()) it->second.clearInflightRequest(); } }
};
PollEngine::PollEngine(Profile p):impl_(std::make_unique<Impl>(std::move(p))) {}
PollEngine::~PollEngine()=default;
bool PollEngine::Reconcile(const PollItem &item,bool accepted,std::string &error) {
    if(impl_->finalized.contains(item.id) || (item.kind==ItemKind::Block && impl_->invalidated.contains(item.id))) return Fail(error,"already-finalized-item");
    if(impl_->records.contains(item)) return true;
    if(impl_->records.size()>=impl_->profile.max_queries) return Fail(error,"vote-record-capacity");
    impl_->records.try_emplace(item,accepted); return true;
}
void PollEngine::PruneProofs(const Quorum &quorum) {
    for(auto it=impl_->records.begin();it!=impl_->records.end();) {
        if(it->first.kind==ItemKind::Proof && !quorum.Pollable(::avalanche::ProofId(Native(it->first.id))) && !quorum.Immature(::avalanche::ProofId(Native(it->first.id)))) it=impl_->records.erase(it);
        else ++it;
    }
}
bool PollEngine::Next(Quorum &quorum,const ChainSnapshot &snapshot,int64_t now,OutgoingPoll &out,std::string &error) {
    PruneProofs(quorum);
    if(!quorum.Established(snapshot)) return Fail(error,"quorum-not-established");
    for(auto it=impl_->queries.begin();it!=impl_->queries.end();) {
        if(it->second.timeout<now) { impl_->Release(it->second); it=impl_->queries.erase(it); IncrementDiagnostic(impl_->diagnostics.queries_expired); } else ++it;
    }
    if(impl_->queries.size()>=impl_->profile.max_queries) return Fail(error,"query-capacity");
    auto node=quorum.Select(now); if(!node) return Fail(error,"no-poll-node");
    auto auth=quorum.Node(*node); if(!auth) return Fail(error,"stale-poll-node");
    OutgoingPoll next; next.node=*node; next.round=impl_->round;
    for(auto &[item,record]:impl_->records) {
        if(item.kind==ItemKind::Proof && !quorum.Pollable(::avalanche::ProofId(Native(item.id)))) continue;
        if(!record.registerPoll()) continue;
        next.items.push_back(item);
        if(next.items.size()>=std::min(auth->max_elements,impl_->profile.max_element_poll)) break;
    }
    if(next.items.empty()) return Fail(error,"no-poll-items");
    if(impl_->round==std::numeric_limits<uint64_t>::max()) { Impl::Query rollback{next.items,0}; impl_->Release(rollback); return Fail(error,"poll-round-exhausted"); }
    ++impl_->round;
    const auto timeout=Deadline(now,impl_->profile.query_timeout_ms);
    impl_->queries.emplace(std::make_pair(next.node,next.round),Impl::Query{next.items,timeout});
    IncrementDiagnostic(impl_->diagnostics.queries_created);
    quorum.Cooldown(next.node,timeout); out=std::move(next); return true;
}
PollReceiveResult PollEngine::ReceiveResponseImpl(Quorum &quorum,NodeId node,const SignedResponse &signed_response,
    const ChainSnapshot &snapshot,int64_t now,int64_t wall_seconds,const ApplyBlockUpdates &apply,std::string &error) {
    auto auth=quorum.Node(node); if(!auth) {Fail(error,"unknown-response-node");return PollReceiveResult::Rejected;}
    if(!AuthenticateResponse(auth->session_key,signed_response,error)) return PollReceiveResult::Rejected;
    const auto &response=signed_response.response;
    auto query=impl_->queries.find({node,response.getRound()});
    // Pinned ABC does not disconnect for an authenticated reply whose query
    // already timed out. No ownership, vote history or cooldown is changed.
    if(query==impl_->queries.end()) {Fail(error,"unexpected-ava-response");return PollReceiveResult::Ignored;}
    IncrementDiagnostic(impl_->diagnostics.responses_matched);
    auto items=std::move(query->second.items); impl_->queries.erase(query);
    Impl::Query release{items,0};
    quorum.Cooldown(node,Deadline(now,response.getCooldown()));
    if(items.size()!=response.GetVotes().size()) { impl_->Release(release); Fail(error,"invalid-ava-response-size");return PollReceiveResult::Rejected; }
    for(size_t i=0;i<items.size();++i) if(Native(items[i].id)!=response.GetVotes()[i].GetHash()) { impl_->Release(release); Fail(error,"invalid-ava-response-content");return PollReceiveResult::Rejected; }
    auto staged=impl_->records;
    impl_->Release(release);
    std::vector<BlockUpdate> blocks;
    std::vector<std::pair<PollItem,Status>> updates;
    for(size_t i=0;i<items.size();++i) {
        const auto &item=items[i]; auto record=staged.find(item); if(record==staged.end()) continue;
        if(item.kind==ItemKind::Proof && !quorum.Pollable(::avalanche::ProofId(Native(item.id)))) { record->second.clearInflightRequest(); continue; }
        auto &vote=record->second; Status status;
        if(!vote.registerVote(node,response.GetVotes()[i].GetError())) {
            if(!vote.isStale(impl_->profile.stale_vote_threshold,impl_->profile.stale_vote_factor)) continue;
            status=Status::Stale;
        } else if(vote.hasFinalized()) status=vote.isAccepted()?Status::Finalized:Status::Invalid;
        else status=vote.isAccepted()?Status::Accepted:Status::Rejected;
        updates.emplace_back(item,status);
        if(item.kind==ItemKind::Block) blocks.push_back(BlockUpdate{item.id,status,snapshot.tip,snapshot.generation});
        if(status==Status::Finalized || status==Status::Invalid || status==Status::Stale) staged.erase(record);
    }
    std::vector<std::pair<::avalanche::ProofId,Status>> proof_updates;
    for(const auto &[item,status]:updates) if(item.kind==ItemKind::Proof) proof_updates.emplace_back(::avalanche::ProofId(Native(item.id)),status);
    auto commit_blocks=[&](std::string &failure) { return blocks.empty() || (apply && apply(blocks,failure)); };
    if(!quorum.ApplyProofVotes(proof_updates,wall_seconds,commit_blocks,error)) return PollReceiveResult::LocalFailure;
    for(const auto &[item,status]:updates) {
        if(item.kind==ItemKind::Block && status==Status::Invalid) impl_->invalidated.insert(item.id);
        if(status==Status::Finalized) impl_->finalized.insert(item.id);
    }
    impl_->records.swap(staged);
    return PollReceiveResult::Applied;
}
PollReceiveResult PollEngine::ReceiveResponse(Quorum &quorum,NodeId node,const SignedResponse &response,
    const ChainSnapshot &snapshot,int64_t now,int64_t wall,const ApplyBlockUpdates &apply,std::string &error) {
    const auto result=ReceiveResponseImpl(quorum,node,response,snapshot,now,wall,apply,error);
    switch(result) {
        case PollReceiveResult::Applied:IncrementDiagnostic(impl_->diagnostics.responses_applied);break;
        case PollReceiveResult::Ignored:IncrementDiagnostic(impl_->diagnostics.responses_ignored);break;
        case PollReceiveResult::Rejected:IncrementDiagnostic(impl_->diagnostics.responses_rejected);break;
        case PollReceiveResult::LocalFailure:IncrementDiagnostic(impl_->diagnostics.responses_local_failure);break;
    }
    return result;
}
PollDiagnostics PollEngine::Diagnostics() const {
    auto result=impl_->diagnostics;result.live_queries=impl_->queries.size();result.live_records=impl_->records.size();return result;
}
bool PollEngine::Receive(Quorum &quorum,NodeId node,const SignedResponse &response,
    const ChainSnapshot &snapshot,int64_t now,int64_t wall,const ApplyBlockUpdates &apply,std::string &error) {
    return ReceiveResponse(quorum,node,response,snapshot,now,wall,apply,error)==PollReceiveResult::Applied;
}
std::optional<uint16_t> PollEngine::Confidence(const PollItem &item) const {
    const auto found=impl_->records.find(item);if(found==impl_->records.end())return {};
    return found->second.getConfidence();
}
bool PollEngine::Respond(const OutgoingPoll &poll,const ObserveBlock &observe,const Quorum &quorum,
    const CKey &session_key,SignedResponse &out,std::string &error) const {
    if(poll.items.size()>impl_->profile.max_element_poll) return Fail(error,"too-many-ava-poll");
    std::vector<::avalanche::Vote> votes;
    for(const auto &item:poll.items) {
        uint32_t vote=uint32_t(-1);
        if(!quorum.Ready()) { votes.emplace_back(vote,Native(item.id)); continue; }
        if(item.kind==ItemKind::Proof) vote=quorum.Vote(::avalanche::ProofId(Native(item.id)));
        else {
            BlockObservation state; if(!observe(item.id,state,error)) return false;
            if(!state.known) vote=uint32_t(-1); else if(!state.valid) vote=1;
            else if(state.parked) vote=2; else if(state.active) vote=0;
            else if(state.forks_active) vote=3; else if(!state.has_data) vote=uint32_t(-2); else vote=uint32_t(-3);
        }
        votes.emplace_back(vote,Native(item.id));
    }
    SignedResponse result; result.response=::avalanche::Response(poll.round,AVALANCHE_DEFAULT_COOLDOWN,std::move(votes));
    if(!session_key.SignSchnorr(ResponseDigest(result.response),result.signature)) return Fail(error,"response-signing-failed");
    out=std::move(result); return true;
}
void PollEngine::Disconnect(NodeId node) {
    for(auto it=impl_->queries.begin();it!=impl_->queries.end();) if(it->first.first==node) { impl_->Release(it->second); it=impl_->queries.erase(it); IncrementDiagnostic(impl_->diagnostics.queries_cancelled); } else ++it;
}
} // namespace lotus::v2::ava
