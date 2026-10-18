// Copyright (c) 2026 The Lotus developers
#include "avalanche_quorum.h"
#include <avalanche/proofpool.h>
#include <common/bloom.h>
#include <random.h>
#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
namespace lotus::v2::ava {
namespace {
bool Fail(std::string &error, const char *message) { error=message; return false; }
int64_t AddTime(int64_t now, uint64_t delta) {
    return delta > uint64_t(std::numeric_limits<int64_t>::max()) ||
        now > std::numeric_limits<int64_t>::max()-int64_t(delta)
        ? std::numeric_limits<int64_t>::max() : now+int64_t(delta);
}
}
struct Quorum::Impl {
    Profile profile;
    struct Entry { ProofEnvelope envelope; int64_t conflict_after{}; bool finalized{}; bool immature{}; int64_t registration_time{}; };
    struct Peer { AuthenticatedHello hello; int64_t next{}; bool inventory_sent{}; };
    std::map<::avalanche::ProofId,Entry> entries;
    ::avalanche::ProofPool active, conflicting, immature;
    std::map<NodeId,Peer> nodes;
    CRollingBloomFilter invalid{100000,0.000001};
    CRollingBloomFilter finalized{AVALANCHE_MAX_INFLIGHT_POLL * 20,0.0000001};
    uint64_t inventories{};
    bool established{};
    explicit Impl(Profile p):profile(std::move(p)) { std::string error; if(!ValidateProfile(profile,error)) throw std::invalid_argument(error); }
    bool StoreConflicting(const ::avalanche::ProofRef &proof) {
        active.removeProof(proof->getId());
        ::avalanche::ProofPool::ConflictingProofSet displaced;
        auto result=conflicting.addProofIfPreferred(proof,displaced);
        if(result==::avalanche::ProofPool::REJECTED) { entries.erase(proof->getId()); return false; }
        for(const auto &other:displaced) entries.erase(other->getId());
        return true;
    }
    void StoreImmature(const ProofEnvelope &envelope,int64_t now) {
        ::avalanche::ProofPool::ConflictingProofSet displaced;
        if(immature.addProofIfPreferred(envelope.proof,displaced)==::avalanche::ProofPool::REJECTED) return;
        for(const auto &proof:displaced) entries.erase(proof->getId());
        entries.insert_or_assign(envelope.proof->getId(),Entry{envelope,0,false,true,now});
        if(immature.countProofs()>std::min<uint64_t>(4000,profile.max_proofs)) {
            auto lowest=immature.getLowestScoreProof()->getId();
            immature.removeProof(lowest); entries.erase(lowest);
        }
    }
    void Remove(const ::avalanche::ProofId &id) {
        active.removeProof(id); conflicting.removeProof(id); immature.removeProof(id);
    }
};
Quorum::Quorum(Profile p):impl_(std::make_unique<Impl>(std::move(p))) {}
Quorum::~Quorum()=default;
bool Quorum::Register(const ProofEnvelope &envelope,const ChainSnapshot &snapshot,
    const CoinLookup &lookup,int64_t now,const SnapshotReader &reader,std::string &error) {
    AdmittedProof admitted;
    bool immature=false;
    if(!AdmitProof(impl_->profile,snapshot,lookup,envelope,admitted,reader,error)) {
        if(error!="immature-utxo") return false;
        auto relaxed=impl_->profile; relaxed.stake_confirmations=1;
        if(!AdmitProof(relaxed,snapshot,lookup,envelope,admitted,reader,error)) return false;
        immature=true;
    }
    auto proof=envelope.proof; auto id=proof->getId();
    if(impl_->invalid.contains(id)) return Fail(error,"avalanche-invalidated");
    if(impl_->entries.contains(id)) return Fail(error,"proof-already-registered");
    if(impl_->entries.size()>=impl_->profile.max_proofs) return Fail(error,"proof-capacity");
    if(immature) {
        impl_->StoreImmature(envelope,now);
        return Fail(error,"immature-utxo");
    }
    ::avalanche::ProofPool::ConflictingProofSet conflicts;
    auto result=impl_->active.addProofIfNoConflict(proof,conflicts);
    const auto cooldown=AddTime(now,impl_->profile.conflicting_proof_cooldown_seconds);
    if(result==::avalanche::ProofPool::REJECTED) {
        int64_t best=0;
        for(const auto &other:conflicts) {
            auto &entry=impl_->entries.at(other->getId());
            best=std::max(best,entry.conflict_after); entry.conflict_after=cooldown;
        }
        if(best>now) return Fail(error,"cooldown-not-elapsed");
        if(impl_->active.addProofIfPreferred(proof)==::avalanche::ProofPool::REJECTED) {
            if(!impl_->StoreConflicting(proof))
                return Fail(error,"rejected-proof");
            impl_->entries.emplace(id,Impl::Entry{envelope,cooldown,false,false,now});
            return Fail(error,"conflicting-utxos");
        }
        for(const auto &other:conflicts) impl_->StoreConflicting(other);
    }
    impl_->conflicting.removeProof(id);
    impl_->entries.emplace(id,Impl::Entry{envelope,cooldown,false,false,now});
    return true;
}
bool Quorum::Bind(NodeId id,const ::avalanche::Delegation &delegation,const SchnorrSig &signature,
    const ConnectionTranscript &transcript,uint32_t max_elements,std::string &error) {
    AuthenticatedHello hello;
    if(!AuthenticateHello(delegation,signature,transcript,max_elements,hello,error)) return false;
    if(impl_->nodes.contains(id)) return Fail(error,"node-already-bound");
    if(impl_->nodes.size()>=impl_->profile.max_nodes) return Fail(error,"node-capacity");
    if(hello.session_key.IsFullyValid()==false || hello.max_elements<16 || hello.max_elements>impl_->profile.max_element_poll)
        return Fail(error,"invalid-node-authentication");
    // Unknown proofs remain pending and have no voting weight.
    impl_->nodes.emplace(id,Impl::Peer{hello,0}); return true;
}
void Quorum::Disconnect(NodeId id) { impl_->nodes.erase(id); }
void Quorum::SentProofInventory(NodeId id,const ChainSnapshot &snapshot) {
    auto it=impl_->nodes.find(id);
    if(snapshot.initial_download || it==impl_->nodes.end() || it->second.inventory_sent) return;
    it->second.inventory_sent=true;
    if(impl_->inventories<impl_->profile.min_avaproofs_nodes) ++impl_->inventories;
}
bool Quorum::Established(const ChainSnapshot &snapshot) {
    size_t count=0; uint64_t total=0,connected=0;
    std::set<::avalanche::ProofId> connected_ids;
    for(const auto &[id,node]:impl_->nodes) if(impl_->active.getProof(node.hello.proof_id)) { ++count; connected_ids.insert(node.hello.proof_id); }
    if(count<8) return false;
    if(impl_->established) return true;
    if(snapshot.initial_download || impl_->inventories<impl_->profile.min_avaproofs_nodes) return false;
    impl_->active.forEachProof([&](const auto &proof) { total+=proof->getScore(); if(connected_ids.contains(proof->getId())) connected+=proof->getScore(); });
    // ABC public totals are uint32; fail closed instead of overflowing an
    // aggregate whose semantic score cannot be represented at the pin.
    if(total>std::numeric_limits<uint32_t>::max()) return false;
    if(total<::avalanche::Proof::amountToScore(impl_->profile.min_quorum_stake)) return false;
    if(connected<uint64_t(std::round(double(total)*impl_->profile.min_connected_ratio))) return false;
    impl_->established=true; return true;
}
bool Quorum::Ready() const {
    if(!impl_->established) return false;
    size_t count=0;
    for(const auto &[id,node]:impl_->nodes) if(impl_->active.getProof(node.hello.proof_id)) ++count;
    return count>=8;
}
QuorumStatus Quorum::Status() const {
    QuorumStatus status;
    status.established=impl_->established;
    status.proof_count=impl_->entries.size();
    status.authenticated_peer_count=impl_->nodes.size();
    std::set<::avalanche::ProofId> connected;
    for(const auto &[id,node]:impl_->nodes) {
        if(impl_->active.getProof(node.hello.proof_id)) {
            ++status.eligible_peer_count;
            connected.insert(node.hello.proof_id);
        }
    }
    impl_->active.forEachProof([&](const auto &proof) {
        status.active_stake_score+=proof->getScore();
        if(connected.contains(proof->getId())) status.connected_stake_score+=proof->getScore();
    });
    status.ready=status.established && status.eligible_peer_count>=8;
    return status;
}
std::optional<NodeId> Quorum::Select(int64_t now) {
    std::vector<std::pair<::avalanche::ProofId,uint32_t>> slots;
    uint64_t total=0;
    impl_->active.forEachProof([&](const auto &proof) {
        bool connected=false; for(const auto &[id,node]:impl_->nodes) if(node.hello.proof_id==proof->getId()) connected=true;
        if(connected && proof->getScore()) { slots.emplace_back(proof->getId(),proof->getScore()); total+=proof->getScore(); }
    });
    if(!total) return {};
    for(int retry=0;retry<3;++retry) {
        uint64_t pick=FastRandomContext().randrange(total);
        for(const auto &[proof,score]:slots) {
            if(pick>=score) { pick-=score; continue; }
            std::optional<NodeId> chosen; int64_t oldest=std::numeric_limits<int64_t>::max();
            for(const auto &[id,node]:impl_->nodes) if(node.hello.proof_id==proof && node.next<=now && node.next<oldest) { chosen=id; oldest=node.next; }
            if(chosen) return chosen;
            break;
        }
    }
    return {};
}
std::optional<AuthenticatedHello> Quorum::Node(NodeId id) const { auto it=impl_->nodes.find(id); if(it==impl_->nodes.end()) return {}; return it->second.hello; }
void Quorum::Cooldown(NodeId id,int64_t until) { auto it=impl_->nodes.find(id); if(it!=impl_->nodes.end()) it->second.next=until; }
bool Quorum::Revalidate(const ChainSnapshot &snapshot,const CoinLookup &lookup,int64_t now,const SnapshotReader &reader,std::string &error) {
    Quorum staged(impl_->profile); staged.impl_=std::make_unique<Impl>(*impl_);
    std::vector<::avalanche::ProofId> remove, mature, immature;
    for(const auto &[id,entry]:staged.impl_->entries) {
        AdmittedProof admitted;
        if(AdmitProof(staged.impl_->profile,snapshot,lookup,entry.envelope,admitted,reader,error)) {
            if(entry.immature) mature.push_back(id);
            continue;
        }
        if(error=="immature-utxo") {
            auto relaxed=staged.impl_->profile; relaxed.stake_confirmations=1;
            if(AdmitProof(relaxed,snapshot,lookup,entry.envelope,admitted,reader,error)) { immature.push_back(id); continue; }
        }
        remove.push_back(id);
    }
    if(reader()!=snapshot) return Fail(error,"stale-proof-snapshot");
    for(const auto &id:remove) { staged.impl_->Remove(id); staged.impl_->entries.erase(id); }
    for(const auto &id:immature) {
        if(!staged.impl_->entries.contains(id)) continue;
        auto envelope=staged.impl_->entries.at(id).envelope;
        staged.impl_->Remove(id); staged.impl_->entries.erase(id);
        staged.impl_->StoreImmature(envelope,now);
    }
    for(const auto &id:mature) {
        if(!staged.impl_->entries.contains(id)) continue;
        auto envelope=staged.impl_->entries.at(id).envelope;
        staged.impl_->immature.removeProof(id); staged.impl_->entries.erase(id);
        // The native immature pool has now released this proof. Ordinary
        // registration must still honor existing peers' replacement cooldown.
        staged.Register(envelope,snapshot,lookup,now,reader,error);
    }
    if(reader()!=snapshot) return Fail(error,"stale-proof-snapshot");
    impl_.swap(staged.impl_);
    error.clear();
    return true;
}
bool Quorum::ApplyProofVote(const ::avalanche::ProofId &id,::lotus::v2::ava::Status status,int64_t now,std::string &error) {
    auto it=impl_->entries.find(id); if(it==impl_->entries.end()) return Fail(error,"unknown-proof");
    auto proof=it->second.envelope.proof;
    if(it->second.immature) return Fail(error,"immature-proof-vote");
    if(status==Status::Invalid) impl_->invalid.insert(id);
    if(status==Status::Invalid || status==Status::Stale) { impl_->Remove(id); impl_->entries.erase(it); return true; }
    if(status==Status::Rejected) {
        impl_->StoreConflicting(proof); return true;
    }
    auto conflicts=impl_->active.getConflicts(proof);
    impl_->conflicting.removeProof(id);
    for(const auto &other:conflicts) impl_->StoreConflicting(other);
    impl_->active.addProofIfNoConflict(proof);
    it->second.conflict_after=AddTime(now,status==Status::Finalized?impl_->profile.peer_replacement_cooldown_seconds:0);
    if(status==Status::Finalized) { it->second.finalized=true; impl_->finalized.insert(id); }
    return true;
}
bool Quorum::ApplyProofVotes(const std::vector<std::pair<::avalanche::ProofId,::lotus::v2::ava::Status>> &votes,
    int64_t now,const std::function<bool(std::string &)> &commit_blocks,std::string &error) {
    if(votes.empty()) return commit_blocks && commit_blocks(error);
    Quorum staged(impl_->profile); staged.impl_=std::make_unique<Impl>(*impl_);
    // Reject a forged/unknown batch at admission. A proof which was known
    // here can legitimately disappear after an earlier conflicting update.
    for(const auto &[id,status]:votes) if(!impl_->entries.contains(id)) return Fail(error,"unknown-proof");
    for(const auto &[id,status]:votes) {
        if(!staged.impl_->entries.contains(id)) continue;
        if(!staged.ApplyProofVote(id,status,now,error)) return false;
    }
    if(!commit_blocks || !commit_blocks(error)) return false;
    impl_.swap(staged.impl_); return true;
}
uint32_t Quorum::Vote(const ::avalanche::ProofId &id) const {
    if(impl_->invalid.contains(id)) return 1;
    if(impl_->active.getProof(id)) return 0;
    auto entry=impl_->entries.find(id); if(entry!=impl_->entries.end() && entry->second.immature) return 2;
    if(impl_->conflicting.getProof(id)) return 3;
    return impl_->entries.contains(id)?uint32_t(-2):uint32_t(-1);
}
bool Quorum::Immature(const ::avalanche::ProofId &id) const { auto it=impl_->entries.find(id); return it!=impl_->entries.end() && it->second.immature; }
bool Quorum::Known(const ::avalanche::ProofId &id) const { return impl_->entries.contains(id); }
bool Quorum::Pollable(const ::avalanche::ProofId &id) const { auto it=impl_->entries.find(id); return it!=impl_->entries.end() && !it->second.immature && !it->second.finalized && !impl_->finalized.contains(id) && !impl_->invalid.contains(id); }
std::vector<::avalanche::ProofId> Quorum::Proofs() const { std::vector<::avalanche::ProofId> out; for(const auto &[id,entry]:impl_->entries) out.push_back(id); return out; }
std::vector<PersistedPeer> Quorum::ExportPeers() const {
    std::vector<PersistedPeer> result;
    if(!impl_->profile.persist_peers) return result;
    impl_->active.forEachProof([&](const auto &proof) {
        const auto &entry=impl_->entries.at(proof->getId());
        result.push_back({entry.envelope,entry.finalized,entry.registration_time,entry.conflict_after});
    });
    return result;
}
bool Quorum::RestorePeers(const std::vector<PersistedPeer> &peers,const ChainSnapshot &snapshot,
    const CoinLookup &lookup,const SnapshotReader &reader,std::string &error) {
    if(!impl_->profile.persist_peers) return Fail(error,"peer-persistence-disabled");
    if(!impl_->entries.empty() || !impl_->nodes.empty()) return Fail(error,"peer-restore-requires-empty-quorum");
    if(peers.size()>impl_->profile.max_proofs) return Fail(error,"persisted-peer-capacity");
    Quorum staged(impl_->profile);
    for(const auto &peer:peers) {
        if(!staged.Register(peer.envelope,snapshot,lookup,peer.registration_time,reader,error)) return false;
        auto &entry=staged.impl_->entries.at(peer.envelope.proof->getId());
        entry.conflict_after=peer.next_conflict_time; entry.finalized=peer.finalized;
        if(peer.finalized) staged.impl_->finalized.insert(peer.envelope.proof->getId());
    }
    if(reader()!=snapshot) return Fail(error,"stale-proof-snapshot");
    impl_.swap(staged.impl_); error.clear(); return true;
}
} // namespace lotus::v2::ava
