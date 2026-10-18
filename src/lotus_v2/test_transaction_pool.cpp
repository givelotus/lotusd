#include "transaction_pool_test/fixtures.h"
#include <iostream>
using namespace pool_fixture;
#define CHECK(x) do {if(!(x)) throw std::runtime_error("failed: " #x);}while(false)
int main() {try {
    Fixture f;auto ctx=f.Context();PoolLimits limits;TransactionPool pool(limits);PoolBudget b{100,10000000};
    auto parent=Spend({f.funding},{Native(40000),Native(40000)});auto pid=Id(parent);
    auto left=Spend({{pid,0}},{Native(30000)}),right=Spend({{pid,1}},{Native(30000)});
    auto diamond=Spend({{Id(left),0},{Id(right),0}},{Native(50000)});
    CHECK(pool.Admit(Wire(left),ctx,b).status==PoolStatus::MissingParents);
    CHECK(pool.Admit(Wire(parent),ctx,b).status==PoolStatus::Accepted);
    CHECK(pool.Admit(Wire(parent),ctx,b).status==PoolStatus::Duplicate);
    auto alternate=parent;alternate.inputs[0].witnesses[0].arguments.push_back({});
    CHECK(Id(alternate)==pid);CHECK(pool.Admit(Wire(alternate),ctx,b).status==PoolStatus::Conflict);
    auto conflict=parent;conflict.outputs[0].value=39000;
    CHECK(pool.Admit(Wire(conflict),ctx,b).status==PoolStatus::Conflict);
    CHECK(pool.Admit(Wire(left),ctx,b).status==PoolStatus::Accepted);
    CHECK(pool.Admit(Wire(right),ctx,b).status==PoolStatus::Accepted);
    CHECK(pool.Admit(Wire(diamond),ctx,b).status==PoolStatus::Accepted);
    auto snap=pool.Snapshot(ctx.anchor,10,1000000);CHECK(snap.entries.size()==4);CHECK(snap.entries.front().effects.txid==pid);CHECK(snap.entries.back().effects.txid==Id(diamond));
    Hash hash;CHECK(pool.SelectedHash(pid,hash));std::vector<uint8_t>w;CHECK(pool.ReadWire(hash,w)&&w==Wire(parent));CHECK(pool.Inventory(1,2).size()==2);
    // Created outpoints must be checked against authoritative state too.
    Fixture occupied;auto oc=occupied.Context();Outpoint output{pid,0};
    occupied.coins.emplace(output,Coin{output,parent.outputs[0],90,49000,false});
    OrdinaryCandidateEffects direct;std::string error;
    CHECK(CheckOrdinaryWithLookup(parent,oc.profile,oc.chain_id,oc.active_coins,direct,error)==CandidateCheckResult::Invalid);
    CHECK(error=="created outpoint already occupied");
    TransactionPool collision(limits);auto rejected=collision.Admit(Wire(parent),oc,b);
    CHECK(rejected.status==PoolStatus::Invalid);CHECK(rejected.error==error);CHECK(collision.Size()==0);
    CHECK(collision.Inventory(0,10).empty());
    // Input reads succeed while the first output read fails.
    Fixture unreadable;auto rc=unreadable.Context();auto read=rc.active_coins;size_t output_reads=0;
    rc.active_coins=[&](const Outpoint&op,Coin&coin,std::string&e) {
        if(op.tx_id==pid) {++output_reads;e="output disk error";return CoinReadResult::Error;}
        return read(op,coin,e);
    };
    TransactionPool read_failure(limits);auto failed=read_failure.Admit(Wire(parent),rc,b);
    CHECK(failed.status==PoolStatus::Operational);CHECK(failed.error=="output disk error");
    CHECK(output_reads==1);CHECK(read_failure.Size()==0);CHECK(read_failure.Inventory(0,10).empty());
    // An output lookup cannot publish against a changed snapshot.
    rc.active_coins=[&](const Outpoint&op,Coin&coin,std::string&e) {
        if(op.tx_id==pid) unreadable.current=false;
        return read(op,coin,e);
    };
    CHECK(read_failure.Admit(Wire(parent),rc,b).status==PoolStatus::Stale);CHECK(read_failure.Size()==0);
    // A confirmed parent is resolved from the new active view; descendants survive.
    for(size_t i=0;i<parent.outputs.size();++i) {Outpoint op{pid,uint32_t(i)};f.coins.emplace(op,Coin{op,parent.outputs[i],100,50000,false});}
    ctx.anchor.generation=2;ctx.profile.candidate_height=101;
    CHECK(pool.Reconcile(ctx,{pid},{f.funding},{},b).status==PoolStatus::Accepted);CHECK(pool.Size()==3);
    // Failed authoritative storage reads disable all old serving/mining views.
    f.error=true;ctx.anchor.generation=3;
    CHECK(pool.Reconcile(ctx,{}, {},{},b).status==PoolStatus::Operational);CHECK(!pool.Enabled());CHECK(!pool.ReadWire(hash,w));CHECK(pool.Inventory(0,10).empty());CHECK(pool.Snapshot(ctx.anchor,10,100000).status==PoolStatus::Stale);
    f.error=false;CHECK(pool.Reconcile(ctx,{}, {},{},b).status==PoolStatus::Accepted);
    // Conflicting chain spend removes the spender and its descendants.
    CHECK(pool.Reconcile(ctx,{},{{pid,0}},{},b).status==PoolStatus::Accepted);CHECK(pool.Size()==1);
    // Subsequent independent admissions use a view without the confirmed parent.
    for(size_t i=0;i<parent.outputs.size();++i) f.coins.erase(Outpoint{pid,uint32_t(i)});
    // Detached transactions supplied child first are resurrected in dependency order.
    TransactionPool resurrect(limits);CHECK(resurrect.Reconcile(f.Context(),{}, {},{Wire(diamond),Wire(right),Wire(left),Wire(parent)},b).status==PoolStatus::Accepted);CHECK(resurrect.Size()==4);
    Fixture g;auto gc=g.Context();TransactionPool stale(limits);gc.current=[&]{return g.reads==0;};PoolBudget sb{20,10000000};
    CHECK(stale.Admit(Wire(parent),gc,sb).status==PoolStatus::Stale);CHECK(stale.Size()==0);
    g.reads=0;gc=g.Context();g.error=true;CHECK(stale.Admit(Wire(parent),gc,sb).status==PoolStatus::Operational);CHECK(stale.Size()==0);g.error=false;
    auto bad=parent;bad.inputs[0].witnesses[0].script={0x00};CHECK(stale.Admit(Wire(bad),gc,sb).status==PoolStatus::Invalid);
    // Maturity and locks are rechecked after height decreases.
    g.coins.at(g.funding).coinbase=true;g.coins.at(g.funding).creation_height=99;
    CHECK(stale.Admit(Wire(parent),gc,sb).status==PoolStatus::Invalid);gc.profile.candidate_height=101;
    CHECK(stale.Admit(Wire(parent),gc,sb).status==PoolStatus::Accepted);gc.profile.candidate_height=100;gc.anchor.generation=2;
    CHECK(stale.Reconcile(gc,{}, {},{},sb).status==PoolStatus::Accepted);CHECK(stale.Size()==0);
    PoolLimits tiny=limits;tiny.max_transaction_bytes=1;TransactionPool cap(tiny);CHECK(cap.Admit(Wire(parent),f.Context(),b).status==PoolStatus::Capacity);
    // Exhaustion must avoid both authoritative lookup callbacks, even when
    // an input is absent and would ordinarily need missing-state classification.
    Fixture exhausted;exhausted.coins.clear();auto ec=exhausted.Context();
    size_t coin_reads=0,missing_reads=0;
    ec.active_coins=[&](const Outpoint&,Coin&,std::string&){++coin_reads;return CoinReadResult::Missing;};
    ec.classify_missing=[&](const Outpoint&,std::string&){++missing_reads;return PoolMissingState::Unknown;};
    TransactionPool no_work(limits);
    for(auto zero:{PoolBudget{0,100},PoolBudget{1,0}}) {
        const auto refused=no_work.Admit(Wire(parent),ec,zero);
        CHECK(refused.status==PoolStatus::Capacity);CHECK(refused.error=="validation budget");
        CHECK(coin_reads==0);CHECK(missing_reads==0);CHECK(no_work.Size()==0);
    }
    tiny=limits;tiny.max_ancestors=0;TransactionPool graph(tiny);CHECK(graph.Admit(Wire(parent),f.Context(),b).status==PoolStatus::Accepted);CHECK(graph.Admit(Wire(left),f.Context(),b).status==PoolStatus::Capacity);
    // Independent local caps are refusal, never invalidity.
    for(int kind=0;kind<4;++kind) {
        tiny=limits;
        if(kind==0) tiny.max_entries=0;
        if(kind==1) tiny.max_bytes=1;
        if(kind==2) tiny.max_transaction_cost=1;
        if(kind==3) tiny.max_descendants=0;
        TransactionPool limited(tiny);auto lc=f.Context();
        auto first=limited.Admit(Wire(parent),lc,b);
        if(kind==3) {CHECK(first.status==PoolStatus::Accepted);CHECK(limited.Admit(Wire(left),lc,b).status==PoolStatus::Capacity);}
        else CHECK(first.status==PoolStatus::Capacity);
    }
    tiny=limits;tiny.max_edges=0;TransactionPool edges(tiny);
    CHECK(edges.Admit(Wire(parent),f.Context(),b).status==PoolStatus::Accepted);
    CHECK(edges.Admit(Wire(left),f.Context(),b).status==PoolStatus::Capacity);
    TransactionPool policy(limits);PoolBudget low{1,1};
    CHECK(policy.Admit(Wire(parent),f.Context(),low).status==PoolStatus::Capacity);
    CHECK(policy.Size()==0);
    auto noncanonical=Wire(parent);noncanonical.push_back(0);
    CHECK(policy.Admit(noncanonical,f.Context(),b).status==PoolStatus::Invalid);
    Fixture unknown;unknown.coins.clear();auto uc=unknown.Context();
    CHECK(policy.Admit(Wire(parent),uc,b).status==PoolStatus::MissingParents);
    uc.classify_missing=[](const Outpoint&,std::string&){return PoolMissingState::Spent;};
    CHECK(policy.Admit(Wire(parent),uc,b).status==PoolStatus::Conflict);
    uc.classify_missing=[](const Outpoint&,std::string&){return PoolMissingState::Error;};
    CHECK(policy.Admit(Wire(parent),uc,b).status==PoolStatus::Operational);
    // Contextual absolute locks drop after a parent MTP regression.
    Fixture locked;auto lc=locked.Context();auto time_locked=parent;time_locked.lock=(uint64_t(49999)<<8)|2;
    TransactionPool locks(limits);CHECK(locks.Admit(Wire(time_locked),lc,b).status==PoolStatus::Accepted);
    lc.profile.parent_mtp=49998;lc.anchor.generation=2;
    CHECK(locks.Reconcile(lc,{}, {},{},b).status==PoolStatus::Accepted);CHECK(locks.Size()==0);
    // Rebuilds retain progress with one validation per call, including a
    // child-first detached batch and a subsequent survivor-only rebuild.
    Fixture incremental;auto ic=incremental.Context();TransactionPool staged(limits);
    std::vector<std::vector<uint8_t>> detached{Wire(left),Wire(parent)};
    PoolBudget one{1,10000000};
    CHECK(staged.Reconcile(ic,{}, {},detached,one).status==PoolStatus::Capacity);
    CHECK(one.validations==0);CHECK(staged.ReconcilePending());CHECK(!staged.Enabled());
    CHECK(staged.Size()==0);CHECK(staged.Inventory(0,10).empty());
    one={1,10000000};CHECK(staged.Reconcile(ic,{}, {},detached,one).status==PoolStatus::Accepted);
    CHECK(staged.Size()==2);CHECK(staged.Enabled());CHECK(!staged.ReconcilePending());
    auto initial=staged.Snapshot(ic.anchor,10,1000000);CHECK(initial.entries.size()==2);
    CHECK(initial.entries[0].effects.txid==pid);CHECK(initial.entries[1].effects.txid==Id(left));
    ic.anchor.generation=2;one={1,10000000};
    CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Capacity);
    CHECK(staged.Size()==2);CHECK(!staged.Enabled());CHECK(staged.ReconcilePending());
    // A new anchor must discard the prior staged parent and spend fresh work.
    ic.anchor.generation=3;one={1,10000000};
    CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Capacity);
    CHECK(one.validations==0);CHECK(staged.ReconcilePending());
    one={1,10000000};CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Accepted);
    CHECK(staged.Size()==2);CHECK(staged.Snapshot(ic.anchor,10,1000000).entries.size()==2);
    // An authoritative output read error on the second tick discards staging
    // while retaining the old disabled data for a complete retry.
    ic.anchor.generation=4;one={1,10000000};
    CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Capacity);
    incremental.error=true;one={1,10000000};
    CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Operational);
    CHECK(!staged.ReconcilePending());CHECK(!staged.Enabled());CHECK(staged.Size()==2);
    incremental.error=false;one={1,10000000};
    CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Capacity);
    one={1,10000000};CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Accepted);
    // A failed snapshot fence also discards the staged rebuild.
    ic.anchor.generation=5;one={1,10000000};
    CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Capacity);
    incremental.current=false;one={1,10000000};
    CHECK(staged.Reconcile(ic,{}, {},{},one).status==PoolStatus::Stale);
    CHECK(!staged.ReconcilePending());CHECK(!staged.Enabled());CHECK(staged.Size()==2);
    // Hard resource refusal is distinguishable from a budget pause.
    incremental.current=true;PoolLimits bounded=limits;bounded.max_entries=1;
    TransactionPool too_many(bounded);one={1,10000000};
    CHECK(too_many.Reconcile(ic,{}, {},detached,one).status==PoolStatus::Capacity);
    CHECK(!too_many.ReconcilePending());CHECK(!too_many.Enabled());
    std::cout<<"transaction pool tests passed\n";return 0;
} catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
