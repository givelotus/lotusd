// Copyright (c) 2026 The Lotus developers
#include "transaction_pool.h"
#include "signing.h"
#include <algorithm>
#include <exception>
namespace lotus::v2 {
PoolResult TransactionPool::Admit(const std::vector<uint8_t> &wire,
                                 const PoolContext &ctx, PoolBudget &budget) {
    PoolResult r;
    auto fail = [&](PoolStatus s, const std::string &e) { r.status=s; r.error=e; return r; };
    try {
        if (!enabled_ || !ctx.current || !ctx.current() ||
            (anchored_ && anchor_ != ctx.anchor)) return fail(PoolStatus::Stale,"pool context unavailable");
        if (wire.size() > limits_.max_transaction_bytes) return fail(PoolStatus::Capacity,"transaction byte limit");
        Transaction tx;
        if (!DecodeTransaction(wire,ctx.profile.transaction,tx,r.error)) { r.status=PoolStatus::Invalid; return r; }
        std::vector<uint8_t> canonical;
        if (!EncodeTransaction(tx,ctx.profile.transaction,canonical,r.error) || canonical != wire)
            return fail(PoolStatus::Invalid,"noncanonical transaction");
        IdentityDigests ids;
        if (!ComputeIdentities(tx,ctx.profile.transaction,ctx.chain_id,ids,r.error)) { r.status=PoolStatus::Invalid; return r; }
        r.txid=ids.txid; r.txhash=ids.txhash;
        auto existing=entries_.find(r.txid);
        if (existing!=entries_.end()) return fail(existing->second.effects.txhash==r.txhash ? PoolStatus::Duplicate : PoolStatus::Conflict,"first accepted witness retained");
        if (entries_.size() >= limits_.max_entries || wire.size()>limits_.max_bytes-bytes_)
            return fail(PoolStatus::Capacity,"pool byte or entry limit");
        // Refuse exhausted work before authoritative coin reads or graph scans.
        if(!budget.validations || !budget.invocation_cost) return fail(PoolStatus::Capacity,"validation budget");
        PoolEntry staged; staged.wire=wire;
        std::vector<Coin> resolved;
        // Resolve once into a transaction-sized cache, never a full UTXO copy.
        std::map<Outpoint,Coin,OutpointLess> cache;
        for (const auto &input:tx.inputs) {
            if (input.flags!=1) continue;
            Outpoint op{input.prev_txid,input.prev_index};
            if (spends_.contains(op)) return fail(PoolStatus::Conflict,"replacement disabled");
            Coin coin; bool found=false;
            auto parent=entries_.find(op.tx_id);
            if (parent!=entries_.end()) {
                for (const auto &c:parent->second.effects.created) if(c.outpoint==op) { coin=c; found=true; break; }
                if (!found) return fail(PoolStatus::Invalid,"parent output does not exist");
                staged.parents.insert(op.tx_id);
            } else {
                if (!ctx.active_coins) return fail(PoolStatus::Operational,"coin backend unavailable");
                auto read=ctx.active_coins(op,coin,r.error);
                if(read==CoinReadResult::Error) { r.status=PoolStatus::Operational; return r; }
                found=read==CoinReadResult::Found;
            }
            if(!found && ctx.classify_missing) {
                auto state=ctx.classify_missing(op,r.error);
                if(state==PoolMissingState::Error) {r.status=PoolStatus::Operational;return r;}
                if(state==PoolMissingState::Spent) return fail(PoolStatus::Conflict,"active chain already spent input");
            }
            if(!found) r.missing.push_back(op);
            else { cache.emplace(op,coin); resolved.push_back(coin); }
        }
        if(!r.missing.empty()) return fail(PoolStatus::MissingParents,"unresolved inputs");
        std::set<Hash> ancestors=staged.parents;
        std::vector<Hash> pending(ancestors.begin(),ancestors.end());
        for(size_t i=0;i<pending.size();++i) {
            for(const auto &p:entries_.at(pending[i]).parents)
                if(ancestors.insert(p).second) pending.push_back(p);
            if(ancestors.size()>limits_.max_ancestors) return fail(PoolStatus::Capacity,"ancestor limit");
        }
        if(staged.parents.size()>limits_.max_edges-edges_) return fail(PoolStatus::Capacity,"edge limit");
        for(const auto &a:ancestors) {
            size_t descendants=1;
            std::set<Hash> closure{a};
            bool changed=true;
            while(changed) { changed=false; for(const auto &[id,e]:entries_) if(!closure.contains(id))
                for(const auto &p:e.parents) if(closure.contains(p)) {closure.insert(id); ++descendants; changed=true; break;}}
            if(descendants>limits_.max_descendants) return fail(PoolStatus::Capacity,"descendant limit");
        }
        --budget.validations;
        auto profile=ctx.profile;
        profile.max_total_invocation_cost=std::min(profile.max_total_invocation_cost,budget.invocation_cost);
        CoinLookup lookup=[&](const Outpoint &op,Coin &coin,std::string &error) {
            auto it=cache.find(op);
            if(it!=cache.end()) { coin=it->second; return CoinReadResult::Found; }
            // The validator also checks created outpoints for collisions. An
            // uncached outpoint is unknown, rather than authoritatively absent.
            if(!ctx.active_coins) { error="coin backend unavailable"; return CoinReadResult::Error; }
            return ctx.active_coins(op,coin,error);
        };
        const uint64_t wire_bytes = wire.size();
        auto checked=CheckOrdinaryWithLookup(tx,profile,ctx.chain_id,lookup,staged.effects,r.error,&wire_bytes,&ids);
        if(!ctx.current()) return fail(PoolStatus::Stale,"context changed during validation");
        if(checked!=CandidateCheckResult::Accepted) {
            r.status=checked==CandidateCheckResult::Invalid ? PoolStatus::Invalid : PoolStatus::Operational;
            if(r.error=="invocation cost unavailable or over budget" && budget.invocation_cost<ctx.profile.max_total_invocation_cost) r.status=PoolStatus::Capacity;
            return r;
        }
        budget.invocation_cost-=staged.effects.invocation_cost;
        staged.costs=AuthenticatedTransactionCostsResolved(tx,profile.transaction,resolved,
            profile.candidate_height,profile.parent_mtp,staged.effects.invocation_cost,ctx.cost,&wire_bytes);
        if(staged.costs.enforce_linear>limits_.max_transaction_cost || staged.costs.account_linear>limits_.max_transaction_cost)
            return fail(PoolStatus::Capacity,"transaction cost policy");
        if(!ctx.current()) return fail(PoolStatus::Stale,"context changed during validation");
        // Publish via bounded copies so allocation failures cannot poison indices.
        auto entries=entries_; auto hashes=hashes_; auto spends=spends_;
        for(const auto &op:staged.effects.consumed) spends.emplace(op,r.txid);
        hashes.emplace(r.txhash,r.txid); entries.emplace(r.txid,std::move(staged));
        if(!ctx.current()) return fail(PoolStatus::Stale,"context changed before publication");
        entries_.swap(entries); hashes_.swap(hashes); spends_.swap(spends);
        bytes_+=wire.size(); edges_+=entries_.at(r.txid).parents.size();
        anchor_=ctx.anchor; anchored_=true; r.status=PoolStatus::Accepted; r.error.clear(); return r;
    } catch(const std::exception &e) { return fail(PoolStatus::Operational,e.what()); }
}
PoolSnapshot TransactionPool::Snapshot(PoolAnchor anchor,size_t count,size_t bytes) const {
    PoolSnapshot out; out.anchor=anchor;
    if(!enabled_ || (anchored_ && anchor!=anchor_)) return out;
    out.status=PoolStatus::Accepted; std::set<Hash> emitted;
    bool changed=true;
    while(changed && out.entries.size()<count) {
        changed=false;
        for(const auto &[id,e]:entries_) {
            if(emitted.contains(id) || e.wire.size()>bytes) continue;
            if(!std::all_of(e.parents.begin(),e.parents.end(),[&](const Hash&p){return emitted.contains(p);})) continue;
            out.entries.push_back(e); emitted.insert(id); bytes-=e.wire.size(); changed=true;
            if(out.entries.size()==count) break;
        }
    }
    return out;
}
bool TransactionPool::ReadWire(const Hash &hash,std::vector<uint8_t> &out) const {
    if(!enabled_) return false;
    auto it=hashes_.find(hash); if(it==hashes_.end()) return false;
    out=entries_.at(it->second).wire; return true;
}
bool TransactionPool::SelectedHash(const Hash&id,Hash&out) const {
    if(!enabled_) return false;
    auto it=entries_.find(id); if(it==entries_.end()) return false;
    out=it->second.effects.txhash; return true;
}
std::vector<Hash> TransactionPool::Inventory(size_t offset,size_t count) const {
    std::vector<Hash> out; if(!enabled_) return out;
    auto it=hashes_.begin(); while(offset && it!=hashes_.end()) {--offset; ++it;}
    while(count && it!=hashes_.end()) {out.push_back(it->first);--count;++it;} return out;
}
PoolResult TransactionPool::Reconcile(const PoolContext &ctx,const std::set<Hash>&connected,
    const std::vector<Outpoint>&connected_spends,const std::vector<std::vector<uint8_t>>&detached,PoolBudget&budget) {
    enabled_=false;
    PoolResult result;
    auto fail=[&](PoolStatus status,const std::string &error) {
        rebuild_.reset();result.status=status;result.error=error;return result;
    };
    try {
        if(!ctx.current || !ctx.current()) return fail(PoolStatus::Stale,"reconciliation context unavailable");
        if(rebuild_ && (rebuild_->anchor!=ctx.anchor || rebuild_->connected!=connected ||
                       rebuild_->connected_spends!=connected_spends || rebuild_->detached!=detached))
            rebuild_.reset();
        if(!rebuild_) {
            Rebuild stage;stage.anchor=ctx.anchor;stage.connected=connected;
            stage.connected_spends=connected_spends;
            std::map<Hash,std::vector<Hash>> descendants;
            for(const auto &[id,e]:entries_) for(const auto &parent:e.parents)
                descendants[parent].push_back(id);
            std::set<Hash> removed=connected;
            for(const auto &op:connected_spends) {
                auto it=spends_.find(op);
                if(it!=spends_.end() && !connected.contains(it->second)) removed.insert(it->second);
            }
            std::vector<Hash> pending;
            for(const auto &id:removed) if(!connected.contains(id)) pending.push_back(id);
            for(size_t i=0;i<pending.size();++i) for(const auto &child:descendants[pending[i]])
                if(removed.insert(child).second) pending.push_back(child);
            for(const auto &[id,e]:entries_) if(!removed.contains(id)) stage.wires.push_back(e.wire);
            if(detached.size()>limits_.max_entries || stage.wires.size()>limits_.max_entries-detached.size())
                return fail(PoolStatus::Capacity,"reconciliation input count");
            size_t total=0;
            for(const auto *batch:{static_cast<const std::vector<std::vector<uint8_t>> *>(&stage.wires),&detached}) for(const auto &wire:*batch) {
                if(wire.size()>limits_.max_bytes-total) return fail(PoolStatus::Capacity,"reconciliation input bytes");
                total+=wire.size();
            }
            stage.detached=detached;
            stage.wires.insert(stage.wires.end(),detached.begin(),detached.end());
            // Schedule each candidate once, after its in-batch parents. Missing
            // external inputs and rejected parents do not trigger retry scans.
            std::vector<Transaction> transactions(stage.wires.size());
            std::map<Hash,size_t> candidates;
            for(size_t i=0;i<stage.wires.size();++i) {
                IdentityDigests ids;std::string error;
                if(DecodeTransaction(stage.wires[i],ctx.profile.transaction,transactions[i],error) &&
                   ComputeIdentities(transactions[i],ctx.profile.transaction,ctx.chain_id,ids,error))
                    candidates.emplace(ids.txid,i);
            }
            stage.children.resize(stage.wires.size());stage.remaining.resize(stage.wires.size());
            size_t edges=0;
            for(size_t i=0;i<transactions.size();++i) {
                std::set<size_t> parents;
                for(const auto &input:transactions[i].inputs) if(input.flags==1) {
                    auto parent=candidates.find(input.prev_txid);
                    if(parent!=candidates.end()) parents.insert(parent->second);
                }
                if(parents.size()>limits_.max_edges-edges) return fail(PoolStatus::Capacity,"reconciliation input edges");
                edges+=parents.size();stage.remaining[i]=parents.size();
                for(auto parent:parents) stage.children[parent].push_back(i);
                if(parents.empty()) stage.ready.push_back(i);
            }
            rebuild_=std::move(stage);
        }
        auto &stage=*rebuild_;
        TransactionPool next(limits_);next.anchor_=ctx.anchor;next.anchored_=true;
        next.entries_=std::move(stage.entries);next.hashes_=std::move(stage.hashes);
        next.spends_=std::move(stage.spends);next.bytes_=stage.bytes;next.edges_=stage.edges;
        auto pause=[&]() {
            stage.entries=std::move(next.entries_);stage.hashes=std::move(next.hashes_);
            stage.spends=std::move(next.spends_);stage.bytes=next.bytes_;stage.edges=next.edges_;
            result.status=PoolStatus::Capacity;result.error="reconciliation validation budget";return result;
        };
        while(!stage.ready.empty()) {
            if(!ctx.current()) return fail(PoolStatus::Stale,"context changed during reconciliation");
            if(!budget.validations || !budget.invocation_cost) return pause();
            auto index=stage.ready.front();auto before=budget.validations;
            auto admitted=next.Admit(stage.wires[index],ctx,budget);
            // Even cheap refusals consume bounded reconciliation work.
            if(budget.validations==before) --budget.validations;
            if(admitted.status==PoolStatus::Capacity &&
               admitted.error=="invocation cost unavailable or over budget") return pause();
            if(admitted.status==PoolStatus::Operational || admitted.status==PoolStatus::Stale ||
               admitted.status==PoolStatus::Capacity) return fail(admitted.status,admitted.error);
            stage.ready.pop_front();
            for(auto child:stage.children[index]) if(--stage.remaining[child]==0) stage.ready.push_back(child);
        }
        if(!ctx.current()) return fail(PoolStatus::Stale,"context changed before reconciliation publication");
        *this=std::move(next);result.status=PoolStatus::Accepted;return result;
    } catch(const std::exception &e) {return fail(PoolStatus::Operational,e.what());}
}
}
