#ifndef LOTUS_V2_POOL_FIXTURES_H
#define LOTUS_V2_POOL_FIXTURES_H
#include "../transaction_pool.h"
#include "../signing.h"
#include "../commitment.h"
#include <stdexcept>
namespace pool_fixture {
using namespace lotus::v2;
inline void Check(bool b) { if(!b) throw std::runtime_error("pool fixture failure"); }
inline Output Native(uint64_t n) {Output o;o.value=n;o.branches={BranchLeaf(std::vector<uint8_t>{0x4e})};o.paths={{0}};return o;}
inline OrdinaryCandidateProfile Profile() {
    OrdinaryCandidateProfile p{TxProfile{32,32,8,512,8,8192,64},
        VmProfile{512,8,8192,32,32,65536,16,100000},VmCostProfile{},100,50000,2,100,10000000};
    p.vm_cost.max_invocation_cost=1000000;p.vm_cost.structural_byte_cost=1;
    for(auto&o:p.vm_cost.opcode)o={1,1,1};return p;
}
inline Transaction Spend(std::vector<Outpoint> ops,std::vector<Output> outputs) {
    Transaction t;t.outputs=std::move(outputs);
    for(const auto&op:ops) {Input i;i.flags=1;i.prev_txid=op.tx_id;i.prev_index=op.index;i.sequence=UINT32_MAX;i.witnesses={BranchWitness{{0x4e},{},{}}};t.inputs.push_back(i);}return t;
}
inline std::vector<uint8_t> Wire(const Transaction&t) {std::vector<uint8_t>w;std::string e;if(!EncodeTransaction(t,Profile().transaction,w,e))throw std::runtime_error(e);return w;}
inline Hash Id(const Transaction&t) {IdentityDigests i;std::string e;Check(ComputeIdentities(t,Profile().transaction,{},i,e));return i.txid;}
struct Fixture {
    DevelopmentUtxoView coins;bool current=true,error=false;size_t reads=0;
    Outpoint funding{{},0};
    Fixture() {funding.tx_id[0]=77;coins.emplace(funding,Coin{funding,Native(100000),90,49000,false});}
    PoolContext Context() {return PoolContext{{{},1},Profile(),{},[this](const Outpoint&o,Coin&c,std::string&e){++reads;if(error){e="disk error";return CoinReadResult::Error;}auto it=coins.find(o);if(it==coins.end())return CoinReadResult::Missing;c=it->second;return CoinReadResult::Found;},[this]{return current;},{1,1,1,1},{}};}
};
}
#endif
