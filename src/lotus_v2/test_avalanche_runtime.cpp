// Copyright (c) 2026 The Lotus developers
#include "development_runtime.h"
#include "development_runtime_test/fixtures.h"
#include <iostream>
#include <leveldb/env.h>
using namespace lotus::v2;
using namespace runtime_fixture;
namespace {
DevelopmentRuntimeConfig Config(Home &h) {
    DevelopmentRuntimeConfig c;
    c.directory = h.path; c.genesis_wire = Bytes(genesis_wire); c.profiles = h.p;
    c.initial_money = DecodeMonetaryState(Bytes(initial_money));
    c.storage.recovery = DiskRecoveryOptions{32 << 20, 4 << 20};
    c.storage.candidates = CandidateStoreOptions{64, 64, 8};
    c.storage.avalanche = true; c.storage.env = h.env;
    c.bodies = {64, 1 << 20, 64 << 20, 64, 64 << 20, 64};
    c.initial_body_epoch = 1; c.initial_context_generation = 1;
    return c;
}
void Seed(Home &h) {
    h.store = {}; std::filesystem::remove_all(h.path);
    auto c = Config(h); std::string e;
    Check(OpenDevelopmentChain(h.path, c.genesis_wire, h.p.header, h.p.ordinary,
        h.p.monetary, h.p.cost, c.initial_money, c.storage, h.store, e), "seed: " + e);
    for (size_t i : {0, 1, 2, 3}) h.Connect(i);
    h.store = {};
}
std::unique_ptr<DevelopmentRuntime> Open(Home &h) {
    std::unique_ptr<DevelopmentRuntime> r; std::string e;
    Check(DevelopmentRuntime::Open(Config(h), r, e), "runtime open: " + e); return r;
}
DevelopmentTickLimits LimitsForTick() {
    DevelopmentTickLimits l;
    l.selection.query = {64, 100000, 100000, 1 << 20};
    l.selection.fork = {8, 8, 10000}; l.selection.max_probe_calls = 128;
    l.selection.max_probe_bytes = 1 << 20; l.selection.max_missing_bodies = 8;
    l.selection.max_resident_bytes = 1 << 20; l.recovery = Limits();
    l.propagation = {64, 100000, 100000, 1 << 20}; return l;
}
RuntimeBlockObservation Observe(DevelopmentRuntime &r, size_t n) {
    RuntimeBlockObservation o; std::string e;
    Check(r.ObserveAvalancheBlock(H(V(n).id), o, e), "observe: " + e); return o;
}
RuntimeBlockUpdate Update(DevelopmentRuntime &r, size_t n, RuntimeBlockStatus s) {
    const auto snap = r.Snapshot();
    return {H(V(n).id), s, snap.chain->stable_tip, snap.context_generation};
}
void Vote(DevelopmentRuntime &r, size_t n, RuntimeBlockStatus s) {
    std::string e; Check(r.ApplyAvalancheUpdates({Update(r,n,s)},e), "vote: " + e);
}
void Announce(DevelopmentRuntime &r, size_t n) {
    std::string e; HeaderAdmission a;
    Check(r.AdmitHeader(HeaderOf(V(n)),a,e) == DevelopmentRuntimeResult::Progress,
          "announce: " + e);
    CandidateBodyStatus b;
    Check(r.RetainBody(H(V(n).id), Bytes(V(n).wire), b,e) == DevelopmentRuntimeResult::Progress,
          "retain: " + e);
}
void Settle(DevelopmentRuntime &r, const Hash &tip) {
    for (unsigned i=0;i<100;++i) {
        auto t=r.Tick(UINT64_MAX,0,LimitsForTick());
        Check(!t.snapshot.reopen_required,"tick storage: " + t.diagnostic);

        if (t.snapshot.chain && t.snapshot.chain->stable_tip==tip &&
            !t.snapshot.chain->pending_journal && !t.snapshot.chain->pending_receipt &&
            !t.snapshot.chain->pending_propagation) return;
    }
    Check(false,"did not settle");
}
void ExplicitPolicyAuthority() {
    Home h; Seed(h); auto c=Config(h); std::string e;
    Check(OpenDevelopmentChain(h.path,c.genesis_wire,h.p.header,h.p.ordinary,h.p.monetary,
          h.p.cost,c.initial_money,c.storage,h.store,e),"policy store: "+e);
    DiskStateError failure; ForkPlan plan; const auto source=H(V(3).id), ancestor=H(V(1).id);
    Check(PlanHeaderFork(h.store,source,ancestor,Limits().fork,UINT64_MAX,0,plan,failure,true)==
          ChainIndexResult::NotHeavier,"explicit policy cannot authorize unparked lower work");
    CandidateView view; Check(h.store.ReadCandidateView(view,failure),"policy view");
    Check(!h.store.ApplyBlockPolicy(source,view.revision+1,{{H(V(2).id),true}},std::nullopt,failure),
          "disk revision fence");
    DiskBlockPolicy policy;
    Check(h.store.ReadBlockPolicy(source,10000,policy,failure)&&!policy.parked,"stale disk batch no park");
    Check(h.store.ApplyBlockPolicy(source,view.revision,{{H(V(2).id),true}},std::nullopt,failure),"park source");
    Check(PlanHeaderFork(h.store,source,ancestor,Limits().fork,UINT64_MAX,0,plan,failure)==
          ChainIndexResult::NotHeavier,"default planner remains strict heavier");
    Check(PlanHeaderFork(h.store,source,ancestor,Limits().fork,UINT64_MAX,0,plan,failure,true)==
          ChainIndexResult::Complete && plan.target==plan.fork && plan.connect.empty() && plan.disconnect.size()==2,
          "parked policy authorizes ancestor-only unwind");
    policy.known=true;
    Check(!h.store.ReadBlockPolicy(source,1,policy,failure)&&failure.code==DiskStateErrorCode::Resource&&policy.known,
          "bounded policy refusal preserves output");
    h.store={};
    auto disabled=Config(h); disabled.storage.avalanche=false;
    std::unique_ptr<DevelopmentRuntime> r;
    Check(!DevelopmentRuntime::Open(disabled,r,e),"Avalanche home refuses silently disabled policy");
}
void ParkingAndFences() {
    Home h; Seed(h); auto r=Open(h); std::string e;
    const auto original=r->Snapshot();
    Vote(*r,3,RuntimeBlockStatus::Stale);
    Check(r->Snapshot().context_generation==original.context_generation,"stale vote leaves chain generation unchanged");
    auto first=Update(*r,2,RuntimeBlockStatus::Rejected);
    auto stale=Update(*r,3,RuntimeBlockStatus::Invalid); ++stale.expected_generation;
    Check(!r->ApplyAvalancheUpdates({first,stale},e),"mixed fence refused atomically");
    Check(!Observe(*r,2).parked && r->Snapshot().context_generation==original.context_generation,
          "no first update or generation published on stale batch");
    Check(r->ApplyAvalancheUpdates({first,Update(*r,3,RuntimeBlockStatus::Invalid)},e),"negative batch");
    Check(Observe(*r,2).parked && Observe(*r,3).parked,"park inherited");
    std::optional<Hash> invalid;
    Check(r->ReadInvalidity(H(V(3).id),invalid,e)==DevelopmentRuntimeResult::Progress && !invalid,
          "negative vote preserves deterministic invalid ledger");
    // Durable marker must survive before any disconnect has executed.
    r.reset(); r=Open(h); Check(Observe(*r,3).parked,"restart retains parks");
    auto t=r->Tick(UINT64_MAX,0,LimitsForTick());
    Check(t.result==DevelopmentRuntimeResult::Prepared,"park prepares bounded ancestor unwind: "+t.diagnostic);
    Check(!r->ApplyAvalancheUpdates({Update(*r,3,RuntimeBlockStatus::Accepted)},e),"journal fence refuses votes");
    r.reset(); r=Open(h); Settle(*r,H(V(1).id));
    Check(!Observe(*r,3).active && Observe(*r,3).parked,"lower-work rollback persists parking");
    Vote(*r,2,RuntimeBlockStatus::Accepted);
    Check(!Observe(*r,2).parked && Observe(*r,3).parked,"accept clears ancestors, keeps independent child park");
    Settle(*r,H(V(2).id));
    Vote(*r,3,RuntimeBlockStatus::Accepted); Settle(*r,H(V(3).id));
    Check(Observe(*r,3).active,"accepted branch activates through validation");
    Check(!r->ApplyAvalancheUpdates({first},e),"old tip/generation cannot replay");
}
void Finality() {
    Home h; Seed(h); auto r=Open(h); std::string e;
    for(size_t n:{4,5}) Announce(*r,n);
    Vote(*r,2,RuntimeBlockStatus::Finalized);
    Announce(*r,6);
    Check(Observe(*r,0).finalized && Observe(*r,2).finalized && !Observe(*r,3).finalized,
          "finality covers ancestors only");
    Check(Observe(*r,6).conflicting_finalized && Observe(*r,6).parked,
          "conflicting heavier fork parked durably");
    const auto before=r->Snapshot().context_generation;
    Check(!r->ApplyAvalancheUpdates({Update(*r,6,RuntimeBlockStatus::Finalized)},e),
          "cannot finalize inactive block");
    Check(r->Snapshot().context_generation==before && Observe(*r,2).finalized,"failed finalize keeps state");
    for(unsigned i=0;i<5;++i) r->Tick(UINT64_MAX,0,LimitsForTick());
    Check(Observe(*r,3).active,"heavier conflict cannot replace finalized chain");
    r.reset(); r=Open(h);
    Check(!Observe(*r,2).finalized && !Observe(*r,6).conflicting_finalized && Observe(*r,6).parked,
          "restart clears volatile finality, retains conflict parking");
    for(size_t n:{4,5,6}) Announce(*r,n);
    Vote(*r,6,RuntimeBlockStatus::Accepted);
    Settle(*r,H(V(6).id));
}
class FaultEnv final : public leveldb::EnvWrapper {
public:
    bool fail{}; FaultEnv():EnvWrapper(leveldb::Env::Default()){}
    class File final : public leveldb::WritableFile {
        FaultEnv &env; std::unique_ptr<leveldb::WritableFile> f;
    public:
        File(FaultEnv &e,leveldb::WritableFile *p):env(e),f(p){}
        std::string GetName()const override{return f->GetName();}
        leveldb::Status Append(const leveldb::Slice &s)override{return f->Append(s);}
        leveldb::Status Flush()override{return f->Flush();}
        leveldb::Status Close()override{return f->Close();}
        leveldb::Status Sync()override{
            auto s=f->Sync(); if(s.ok() && env.fail){env.fail=false; return leveldb::Status::IOError("after durable sync");}return s;
        }
    };
    leveldb::Status NewWritableFile(const std::string &n,leveldb::WritableFile **o)override{
        auto s=target()->NewWritableFile(n,o);if(s.ok()&&n.ends_with(".log"))*o=new File(*this,*o);return s;
    }
    leveldb::Status NewAppendableFile(const std::string &n,leveldb::WritableFile **o)override{
        auto s=target()->NewAppendableFile(n,o);if(s.ok()&&n.ends_with(".log"))*o=new File(*this,*o);return s;
    }
};
void DurableFailure() {
    FaultEnv env; Home h(32<<20,Profiles(),true,&env); Seed(h); auto r=Open(h);
    env.fail=true;std::string e;
    Check(!r->ApplyAvalancheUpdates({Update(*r,2,RuntimeBlockStatus::Rejected),
          Update(*r,3,RuntimeBlockStatus::Invalid)},e),"failed sync rejects batch callback");
    Check(r->Snapshot().reopen_required && !r->Snapshot().chain,"ambiguous batch revokes authority");
    auto t=r->Tick(UINT64_MAX,0,LimitsForTick());
    Check(t.result==DevelopmentRuntimeResult::Reopened,"authoritative reopen");
    Check(Observe(*r,2).parked && Observe(*r,3).parked,"durable batch recovered together");
    Settle(*r,H(V(1).id));
}
}
int main(){try{ExplicitPolicyAuthority();ParkingAndFences();Finality();DurableFailure();std::cout<<"Avalanche runtime checks passed\n";return 0;}
catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
