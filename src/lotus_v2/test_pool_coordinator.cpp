// Copyright (c) 2026 The Lotus developers
#include "pool_coordinator.h"
#include "development_runtime_test/fixtures.h"
#include "signing.h"
#include <iostream>
#include <leveldb/env.h>
using namespace lotus::v2;
using namespace runtime_fixture;
namespace {
DevelopmentRuntimeConfig Config(Home &home) {
    DevelopmentRuntimeConfig config;
    config.directory = home.path;
    config.genesis_wire = Bytes(genesis_wire);
    config.profiles = home.p;
    config.initial_money = DecodeMonetaryState(Bytes(initial_money));
    config.storage.cache_bytes = 1024;
    config.storage.write_buffer_bytes = 64 << 10;
    config.storage.recovery = DiskRecoveryOptions{32 << 20, 4 << 20};
    config.storage.candidates = CandidateStoreOptions{64, 64, 8};
    config.storage.env = home.env;
    config.bodies = {3, 1 << 20, 3 << 20, 3, 3 << 20, 64};
    config.initial_body_epoch = 1;
    config.initial_context_generation = 1;
    return config;
}
DevelopmentTickLimits TickLimits() {
    DevelopmentTickLimits limits;
    limits.selection.query = {64, 20000, 20000, 1 << 20};
    limits.selection.fork = {8, 8, 1000};
    limits.selection.max_probe_calls = 128;
    limits.selection.max_probe_bytes = 1 << 20;
    limits.selection.max_missing_bodies = 8;
    limits.selection.max_resident_bytes = 1 << 20;
    limits.recovery = runtime_fixture::Limits();
    limits.propagation = {1, 1000, 1000, 1 << 20};
    return limits;
}
std::unique_ptr<DevelopmentRuntime> Open(DevelopmentRuntimeConfig config) {
    std::unique_ptr<DevelopmentRuntime> out;
    std::string error;
    Check(DevelopmentRuntime::Open(std::move(config), out, error) && out,
          "open explicit runtime: " + error);
    return out;
}
void Announce(DevelopmentRuntime &runtime, const std::vector<size_t> &path,
              bool bodies = true) {
    std::string error;
    for (size_t n : path) {
        HeaderAdmission admitted = HeaderAdmission::Invalid;
        Check(runtime.AdmitHeader(HeaderOf(V(n)), admitted, error) ==
                      DevelopmentRuntimeResult::Progress &&
                  admitted == HeaderAdmission::Stored,
              "runtime contextual header admission: " + error);
        if (!bodies) continue;
        CandidateBodyStatus retained = CandidateBodyStatus::Malformed;
        Check(runtime.RetainBody(H(V(n).id), Bytes(V(n).wire), retained,
                                 error) == DevelopmentRuntimeResult::Progress &&
                  retained == CandidateBodyStatus::RetainedAuthenticated,
              "pool retains replacement bytes without contextual acceptance: " +
                  error);
    }
}
DevelopmentTick Tick(DevelopmentRuntime &runtime, uint64_t now = UINT64_MAX,
                     const DevelopmentTickLimits &limits = TickLimits()) {
    auto tick = runtime.Tick(now, 0, limits);
    Check(tick.usage.recovery_calls <= 1,
          "one recovery phase/block transition per tick");
    Check(tick.usage.selection.query.rows <= limits.selection.query.max_rows &&
              tick.usage.selection.query.reads <=
                  limits.selection.query.max_reads &&
              tick.usage.selection.query.iterator_steps <=
                  limits.selection.query.max_iterator_steps &&
              tick.usage.selection.query.decoded_bytes <=
                  limits.selection.query.max_decoded_bytes &&
              tick.usage.selection.probe_calls <=
                  limits.selection.max_probe_calls,
          "selector reports its own bounded usage");
    Check(tick.usage.propagation.rows <= limits.propagation.max_rows &&
              tick.usage.propagation.reads <= limits.propagation.max_reads &&
              tick.usage.propagation.iterator_steps <=
                  limits.propagation.max_iterator_steps &&
              tick.usage.propagation.decoded_bytes <=
                  limits.propagation.max_decoded_bytes,
          "propagation reports its own bounded usage");
    Check(tick.result != DevelopmentRuntimeResult::StorageError &&
              tick.result != DevelopmentRuntimeResult::InvalidConfiguration,
          "runtime tick: " + tick.diagnostic);
    return tick;
}
class FaultEnv final : public leveldb::EnvWrapper {
public:
    bool fail_after_sync = false;
    unsigned failures = 0;
    std::function<void()> on_sync;
    FaultEnv() : EnvWrapper(leveldb::Env::Default()) {}
    class File final : public leveldb::WritableFile {
        FaultEnv &owner;
        std::unique_ptr<leveldb::WritableFile> file;

    public:
        File(FaultEnv &env, leveldb::WritableFile *raw)
            : owner(env), file(raw) {}
        std::string GetName() const override { return file->GetName(); }
        leveldb::Status Append(const leveldb::Slice &bytes) override {
            return file->Append(bytes);
        }
        leveldb::Status Flush() override { return file->Flush(); }
        leveldb::Status Close() override { return file->Close(); }
        leveldb::Status Sync() override {
            if (owner.on_sync) owner.on_sync();
            const auto status = file->Sync();
            if (status.ok() && owner.fail_after_sync) {
                owner.fail_after_sync = false;
                ++owner.failures;
                return leveldb::Status::IOError(
                    "injected reported failure after durable sync");
            }
            return status;
        }
    };
    leveldb::Status NewWritableFile(const std::string &name,
                                    leveldb::WritableFile **out) override {
        auto status = target()->NewWritableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return status;
    }
    leveldb::Status NewAppendableFile(const std::string &name,
                                      leveldb::WritableFile **out) override {
        auto status = target()->NewAppendableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return status;
    }
};

PoolCoordinatorConfig PoolConfig(DevelopmentRuntime &runtime, Home &home) {
    auto s=runtime.Snapshot(); Check(bool(s.chain),"runtime chain view");
    PoolCoordinatorConfig c;
    c.directory=home.path+"/chainstate-v2/transaction-index";
    c.identity=s.chain->identity; c.profile_digest=s.chain->profile_digest;
    c.headers=home.p.header; c.ordinary=home.p.ordinary; c.cost=home.p.cost;
    // Match manifest-loaded rules: the coordinator must supply the context.
    c.ordinary.candidate_height=0;
    return c;
}
std::unique_ptr<PoolCoordinator> Coordinator(DevelopmentRuntime &runtime,PoolCoordinatorConfig c) {
    std::unique_ptr<PoolCoordinator> out; std::string e;
    Check(PoolCoordinator::Open(runtime,c,out,e),"coordinator open: "+e);return out;
}
void Sync(PoolCoordinator &pool) {
    std::string e;
    for(unsigned i=0;i<100;++i) {
        PoolCoordinatorBudget b{32,1,{1000,100000000}};
        auto r=pool.Tick(b,e);
        if(r==CoordinatorResult::Ready) return;
        Check(r==CoordinatorResult::Progress,"index synchronization: "+e);
    }
    Check(false,"index synchronization bounded completion");
}
IdentityDigests Ordinary(Home &home,size_t n,std::vector<uint8_t> &wire) {
    FramedBlock block; std::string e;
    Check(DecodeBlockWire(Bytes(V(n).wire),home.p.ordinary.transaction,home.p.header.chain_id,block,e),e);
    Check(block.transactions.size()>1,"ordinary fixture");
    IdentityDigests ids;
    Check(ComputeIdentities(block.transactions[1],home.p.ordinary.transaction,home.p.header.chain_id,ids,e),e);
    Check(EncodeTransaction(block.transactions[1],home.p.ordinary.transaction,wire,e),e);return ids;
}
void Settle(DevelopmentRuntime &runtime,const Hash &tip,PoolCoordinator &pool) {
    for(unsigned i=0;i<100;++i) {
        Tick(runtime);
        auto s=runtime.Snapshot();
        if(s.chain && s.chain->stable_tip==tip && !s.chain->pending_journal && !s.chain->pending_receipt && !s.chain->pending_propagation) {Sync(pool);return;}
        if(!s.chain || s.reopen_required || s.execution_paused || s.chain->pending_journal || s.chain->pending_receipt || s.chain->pending_propagation)
            Check(pool.Status({}).state==TransactionState::Inconclusive,"pending runtime state fences status");
    }
    Check(false,"runtime settled");
}
void Lifecycle() {
    Home home; home.Connect(0);home.Connect(1);home.store={};
    auto runtime=Open(Config(home));auto config=PoolConfig(*runtime,home);config.max_path=1;
    auto pool=Coordinator(*runtime,config);
    std::vector<uint8_t> wire;auto ids=Ordinary(home,2,wire);
    Check(pool->Status(ids.txid).state==TransactionState::Inconclusive,"initial unsynchronized status");
    PoolCoordinatorBudget zero{0,0,{0,0}}; std::string e;
    Check(pool->Tick(zero,e)==CoordinatorResult::Progress,"zero budget makes no progress");
    Sync(*pool);
    Check(pool->Status(ids.txid).state==TransactionState::Unknown,"never infer confirmation from coin state");
    PoolBudget b{10,100000000};
    auto admitted=pool->Submit(wire,runtime->Snapshot().chain->stable_tip,b);
    Check(admitted.status==PoolStatus::Accepted,"ordinary admission: "+admitted.error);
    Check(pool->Status(ids.txid,ids.txhash,&wire).state==TransactionState::Pending,"pending selected transaction");
    std::vector<uint8_t> competing;auto competing_ids=Ordinary(home,4,competing);
    Check(pool->Status(competing_ids.txid,competing_ids.txhash,&competing).state==TransactionState::Conflicted,"pending input conflict");
    std::vector<uint8_t> served;Hash selected{};
    Check(pool->ReadWire(ids.txhash,served,wire.size()) && served==wire &&
          pool->Inventory(0,10)==std::vector<Hash>{ids.txhash} &&
          pool->SelectedHash(ids.txid,selected) && selected==ids.txhash,"gated relay facade");
    served={42};Check(!pool->ReadWire(ids.txhash,served,wire.size()-1)&&served==std::vector<uint8_t>{42},"serving cap preserves output");
    Announce(*runtime,{2,3});Settle(*runtime,H(V(3).id),*pool);
    auto status=pool->Status(ids.txid,ids.txhash);
    Check(status.state==TransactionState::Confirmed && status.confirmation && status.confirmation->block==H(V(2).id) && status.confirmation->height==3,"exact confirmation");
    Check(!pool->ReadWire(ids.txhash,served) && pool->Inventory(0,10).empty(),"confirmed wire no longer relayed");
    Check(pool->Snapshot(100,1000000).entries.empty(),"confirmed removed from pool");
    auto different=ids.txhash;different[0]^=1;
    Check(pool->Status(ids.txid,different).state==TransactionState::Conflicted,"witness mismatch");
    pool.reset();runtime.reset();runtime=Open(Config(home));pool=Coordinator(*runtime,config);
    Check(pool->Status(ids.txid).state==TransactionState::Inconclusive,"restart requires runtime fencing");Sync(*pool);
    Check(pool->Status(ids.txid).state==TransactionState::Confirmed,"durable confirmation after reopen");
    Announce(*runtime,{4,5,6});Settle(*runtime,H(V(6).id),*pool);
    Check(pool->Status(ids.txid,ids.txhash,&wire).state==TransactionState::Conflicted,"reorg replaced spend");
    pool.reset();runtime.reset();
}
void IncrementalSurvivors() {
    Home home;home.Connect(0);home.Connect(1);home.store={};
    auto runtime=Open(Config(home));auto pool=Coordinator(*runtime,PoolConfig(*runtime,home));Sync(*pool);
    std::vector<uint8_t> parent,child;auto parent_ids=Ordinary(home,2,parent);auto child_ids=Ordinary(home,3,child);
    PoolBudget admission{10,100000000};const auto tip=runtime->Snapshot().chain->stable_tip;
    Check(pool->Submit(parent,tip,admission).status==PoolStatus::Accepted,"pending parent admitted");
    Check(pool->Submit(child,tip,admission).status==PoolStatus::Accepted,"pending child admitted");
    const auto generation=runtime->Snapshot().context_generation;
    Announce(*runtime,{2});
    Check(runtime->Snapshot().chain->stable_tip==tip && runtime->Snapshot().context_generation!=generation,"body inventory changes generation without tip");
    unsigned ticks=0;std::string e;bool ready=false;
    for(;ticks<20;++ticks) {
        PoolCoordinatorBudget budget{32,1,{1,100000000}};
        const auto result=pool->Tick(budget,e);
        if(result==CoordinatorResult::Ready) {ready=true;++ticks;break;}
        Check(result==CoordinatorResult::Progress,"resumable reconciliation: "+e);
        Check(pool->Status(parent_ids.txid).state==TransactionState::Inconclusive && pool->Inventory(0,10).empty(),"staging remains unpublished");
    }
    Check(ready && ticks>=2,"multiple survivors reconcile across one-validation ticks");
    Check(pool->Status(parent_ids.txid).state==TransactionState::Pending &&
          pool->Status(child_ids.txid).state==TransactionState::Pending && pool->Snapshot(10,1000000).entries.size()==2,"staged survivor publication preserves parent and child");
    admission={1,100000000};
    Check(pool->Submit(std::vector<uint8_t>(1000001),tip,admission).status==PoolStatus::Capacity,"local wire limit is policy capacity");
    pool.reset();runtime.reset();
}
void RefusalFences() {
    Home home;home.Connect(0);home.Connect(1);home.store={};
    auto runtime=Open(Config(home));auto config=PoolConfig(*runtime,home);std::string e;
    config.max_path=1;auto pool=Coordinator(*runtime,config);
    PoolCoordinatorBudget budget{32,10,{100,100000000}};
    Check(pool->Tick(budget,e)==CoordinatorResult::Progress,"initial indexing commits bounded chunk");
    Check(pool->Status({}).state==TransactionState::Inconclusive && pool->Snapshot(10,10000).status==PoolStatus::Stale,"initial chunk does not publish incomplete history");
    pool.reset();
    TransactionHistory checkpoint;
    Check(TransactionHistory::Open(config.directory,config.identity,config.profile_digest,config.history,checkpoint,e) &&
          checkpoint.Anchor()==std::optional<Hash>(home.p.header.genesis_id),"initial chunk has durable progress beyond ancestry cap");
    checkpoint={};pool=Coordinator(*runtime,config);Sync(*pool);
    Check(pool->Status({}).state==TransactionState::Unknown,"multiple chunks finish chain longer than max_path");
    pool.reset();
    // Start a separate index so the injected write occurs during catch-up.
    config.directory+="-failure";FaultEnv env;config.history_env=&env;
    pool=Coordinator(*runtime,config);env.fail_after_sync=true;
    budget={32,10,{100,100000000}};
    Check(pool->Tick(budget,e)==CoordinatorResult::StorageError && env.failures==1,"index write failure surfaced");
    Check(pool->Status({}).state==TransactionState::Inconclusive,"failed index cannot publish status");
    PoolBudget admission{10,100000000};
    Check(pool->Submit({},runtime->Snapshot().chain->stable_tip,admission).status==PoolStatus::Stale,"failed index fences admission");
    pool.reset();pool=Coordinator(*runtime,config);Sync(*pool);
    Check(pool->Status({}).state==TransactionState::Unknown,"reopen recovers ambiguous committed history");
    pool.reset();runtime.reset();
}
void DetachedOverflow() {
    Home home;for(size_t n:{0,1,2,3}) home.Connect(n);home.store={};
    auto runtime=Open(Config(home));auto config=PoolConfig(*runtime,home);
    config.max_detached_transactions=1;auto pool=Coordinator(*runtime,config);Sync(*pool);
    Announce(*runtime,{4,5,6});
    bool settled=false;
    for(unsigned i=0;i<100;++i) {
        Tick(*runtime);auto s=runtime->Snapshot();
        if(s.chain && s.chain->stable_tip==H(V(6).id) && !s.chain->pending_journal && !s.chain->pending_receipt && !s.chain->pending_propagation) {settled=true;break;}
    }
    Check(settled,"overflow runtime settled");
    std::string e;CoordinatorResult result=CoordinatorResult::Progress;
    for(unsigned i=0;i<20 && result==CoordinatorResult::Progress;++i) {
        PoolCoordinatorBudget budget{32,1,{100,100000000}};result=pool->Tick(budget,e);
    }
    Check(result==CoordinatorResult::Capacity && e=="detached pool replay capacity","detached overflow explicit");
    Check(pool->Status({}).state==TransactionState::Inconclusive && pool->Inventory(0,10).empty(),"detached overflow suppresses publication and relay");
    pool.reset();runtime.reset();
}
void PausedFence() {
    auto profiles=Profiles();profiles.ordinary.vm.max_steps=1;Home home(32<<20,profiles);
    for(size_t n:{9,10,11,12}) home.Connect(n);home.store={};
    auto runtime=Open(Config(home));auto pool=Coordinator(*runtime,PoolConfig(*runtime,home));Sync(*pool);
    Announce(*runtime,{13,14,15});bool paused=false;
    for(unsigned i=0;i<100;++i) {
        auto tick=Tick(*runtime);
        if(tick.snapshot.execution_paused) {paused=true;break;}
    }
    Check(paused,"host execution paused");std::string e;PoolCoordinatorBudget budget;
    Check(pool->Tick(budget,e)==CoordinatorResult::Deferred && pool->Status({}).state==TransactionState::Inconclusive,"paused J fences transaction status");
    PoolBudget b;Check(pool->Submit({},Hash{},b).status==PoolStatus::Stale,"paused admission refused");
    pool.reset();runtime.reset();
}
void HistoryAtomicity() {
    Home home; Hash identity{},profile{}; identity[0]=1;profile[0]=2;
    const auto path=home.path+"/history";std::string e;FaultEnv env;TransactionHistory h;
    Check(TransactionHistory::Open(path,identity,profile,{},h,e,&env),e);
    Hash g{},one{},two{},id{},hash{};g[0]=3;one[0]=4;two[0]=5;id[0]=6;hash[0]=7;
    Outpoint point{id,1};
    Check(h.Connect({g,{},0,{}},e),e);
    TransactionConfirmation row{id,hash,one,1,{point}};
    Check(h.Connect({one,g,1,{row}},e),e);
    std::optional<TransactionConfirmation> got;std::optional<Hash> spender;
    Check(h.Lookup(id,got,e)&&got&&got->txhash==hash,"history identity mapping");
    Check(h.Spender(point,spender,e)&&spender==std::optional<Hash>(id),"exact spent mapping");
    auto bad=row;bad.block=two;bad.height=2;
    Check(!h.Connect({two,one,2,{bad,bad}},e)&&h.Anchor()==std::optional<Hash>(one),"invalid batch leaves anchor untouched");
    env.fail_after_sync=true;
    Check(!h.Disconnect(one,e)&&env.failures==1,"ambiguous durable disconnect reports failure");
    Check(!h.Lookup(id,got,e),"ambiguous write poisons reads");
    h={};Check(TransactionHistory::Open(path,identity,profile,{},h,e,&env),e);
    Check(h.Anchor()==std::optional<Hash>(g),"reopen observes atomic durable undo anchor");
    Check(h.Lookup(id,got,e)&&!got&&h.Spender(point,spender,e)&&!spender,"undo restored both indexes");
    Check(h.Connect({one,g,1,{row}},e),e);
    auto replacement=row;replacement.block=two;replacement.height=2;replacement.txhash[0]=8;replacement.consumed.clear();
    Check(h.Connect({two,one,2,{replacement}},e),e);
    Check(h.Disconnect(two,e)&&h.Lookup(id,got,e)&&got&&got->txhash==hash,"repeated TxID undo restores exact predecessor");
    h={};profile[0]^=1;Check(!TransactionHistory::Open(path,identity,profile,{},h,e),"profile mismatch rejected");
}
}
int main() {try {HistoryAtomicity();IncrementalSurvivors();RefusalFences();Lifecycle();DetachedOverflow();PausedFence();std::cout<<"pool coordinator checks passed\n";return 0;}catch(const std::exception &e){std::cerr<<e.what()<<"\n";return 1;}}
