// Copyright (c) 2026 The Lotus developers
#include "avalanche_peer_store.h"
#include <crypto/sha256.h>
#include <streams.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>
#include <set>
#include <atomic>
namespace lotus::v2::ava {
namespace {
using Bytes=std::vector<uint8_t>;
struct Reader {
    const Bytes &b; size_t p{};
    uint64_t number(size_t n) { if(n>b.size()-p) throw std::runtime_error("truncated"); uint64_t v=0; for(size_t i=0;i<n;++i) v|=uint64_t(b[p++])<<(8*i); return v; }
    void skip(uint64_t n) { if(n>b.size()-p) throw std::runtime_error("truncated"); p+=n; }
    uint64_t compact() { auto x=number(1); if(x<253)return x; auto n=x==253?2:x==254?4:8; auto v=number(n); if(v<(n==2?253:n==4?65536:0x100000000ULL)) throw std::runtime_error("noncanonical size"); return v; }
};
void put(Bytes &b,uint64_t v,size_t n) { for(size_t i=0;i<n;++i)b.push_back(v>>(8*i)); }
void append(Bytes &b,const auto &v) { b.insert(b.end(),v.begin(),v.end()); }
Hash digest(const Bytes &b) { Hash h; CSHA256().Write(b.data(),b.size()).Finalize(h.data()); return h; }
PeerStoreResult fail(PeerStoreCode c,const char *s) { return {c,s}; }
// Reject every symlink ancestor; all operations remain anchored to this directory
// even if a concurrent actor renames it or replaces its former pathname.
int openParent(const std::filesystem::path &path) {
    if(path.filename().empty() || path.filename()=="." || path.filename()=="..") { errno=EINVAL; return -1; }
    int fd=open(path.is_absolute()?"/":".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return -1;
    for(const auto &part:path.parent_path().relative_path()) {
        if(part==".")continue;
        if(part=="..") { close(fd);errno=EINVAL;return -1; }
        int next=openat(fd,part.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(fd);if(next<0)return -1;fd=next;
    }
    return fd;
}
struct ScopedFd { int fd; ~ScopedFd(){if(fd>=0)close(fd);} };

void scanProof(const Bytes &b,const PeerStoreLimits &l) {
    Reader r{b}; r.skip(16); auto key=r.compact(); if(key>65)throw std::runtime_error("master key bound"); r.skip(key);
    auto count=r.compact(); if(count>l.locks_per_proof || count>AVALANCHE_MAX_PROOF_STAKES)throw std::runtime_error("stake bound");
    for(uint64_t i=0;i<count;++i) { r.skip(48); key=r.compact(); if(key>65)throw std::runtime_error("stake key bound"); r.skip(key); r.skip(64); }
    auto payout=r.compact(); if(payout>l.payout_bytes)throw std::runtime_error("payout bound"); r.skip(payout); r.skip(64); if(r.p!=b.size())throw std::runtime_error("proof trailing bytes");
}
}
PeerStore::PeerStore(std::filesystem::path p,Profile profile,PeerStoreLimits limits):path_(std::move(p)),profile_(std::move(profile)),limits_(limits) {}
PeerStoreResult PeerStore::Load(std::vector<PersistedPeer> &out) const {
    out.clear(); if(poisoned_)return fail(PeerStoreCode::Poisoned,"peer store requires reopen"); if(limits_.payload_bytes>(1ULL<<30)||limits_.records>1000000||limits_.proof_bytes>(1ULL<<30)||limits_.locks_per_proof>AVALANCHE_MAX_PROOF_STAKES)return fail(PeerStoreCode::Resource,"invalid store limits"); ScopedFd parent{openParent(path_)}; if(parent.fd<0)return fail(PeerStoreCode::Io,"open peer directory"); int fd=::openat(parent.fd,path_.filename().c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC); if(fd<0)return fail(errno==ENOENT?PeerStoreCode::Missing:PeerStoreCode::Io,"open peer store");
    struct stat st{}; if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<140||uint64_t(st.st_size)>limits_.payload_bytes+140) { close(fd); return fail(PeerStoreCode::Resource,"peer store file bound"); }
    Bytes b; try { b.resize(st.st_size); } catch(const std::exception &) { close(fd);return fail(PeerStoreCode::Resource,"peer store allocation"); } size_t off=0; while(off<b.size()) { auto n=read(fd,b.data()+off,b.size()-off); if(n<=0) { close(fd);return fail(PeerStoreCode::Io,"read peer store"); } off+=n; } close(fd);
    try {
        Bytes body(b.begin(),b.end()-32); Hash expected; std::copy(b.end()-32,b.end(),expected.begin()); if(digest(body)!=expected)return fail(PeerStoreCode::Corrupt,"peer store checksum");
        Reader r{body}; if(r.number(4)!=0x41505632||r.number(4)!=1)return fail(PeerStoreCode::Corrupt,"peer store schema");
        for(const auto &h:{profile_.chain_id,profile_.genesis_id,profile_.validation_digest}) { if(body.size()-r.p<32)throw std::runtime_error("binding truncated"); if(!std::equal(h.begin(),h.end(),body.begin()+r.p))return fail(PeerStoreCode::ForeignProfile,"peer store binding"); r.skip(32); }
        auto count=r.number(4); if(count>limits_.records) return fail(PeerStoreCode::Resource,"peer count bound");
        std::vector<PersistedPeer> records; std::set<::avalanche::ProofId> ids;
        for(uint64_t i=0;i<count;++i) {
            auto size=r.number(4); if(size>limits_.proof_bytes||size>body.size()-r.p)throw std::runtime_error("proof size bound"); Bytes proof(body.begin()+r.p,body.begin()+r.p+size); r.skip(size); scanProof(proof,limits_);
            DataStream stream{proof}; ::avalanche::ProofRef ref; stream>>ref; if(!stream.empty()||!ids.insert(ref->getId()).second)throw std::runtime_error("duplicate proof");
            PersistedPeer peer; peer.envelope.proof=ref; auto locks=r.number(4); if(locks>limits_.locks_per_proof||locks!=ref->getStakes().size())throw std::runtime_error("lock count bound");
            for(uint64_t j=0;j<locks;++j) { if(body.size()-r.p<35)throw std::runtime_error("lock truncated"); Bytes lock(body.begin()+r.p,body.begin()+r.p+35); r.skip(35); if(lock[0]!=32||lock[33]!=0xbc||lock[34]!=0x4e)throw std::runtime_error("lock encoding"); peer.envelope.payment_locks.push_back(std::move(lock)); }
            auto flag=r.number(1); if(flag>1)throw std::runtime_error("finalized flag"); peer.finalized=flag; peer.registration_time=int64_t(r.number(8)); peer.next_conflict_time=int64_t(r.number(8)); records.push_back(std::move(peer));
        }
        if(r.p!=body.size())throw std::runtime_error("trailing bytes"); out=std::move(records); return {};
    } catch(const std::bad_alloc &) { return fail(PeerStoreCode::Resource,"peer store allocation"); } catch(const std::length_error &) { return fail(PeerStoreCode::Resource,"peer store allocation bound"); } catch(const std::exception &e) { return {PeerStoreCode::Corrupt,e.what()}; }
}
PeerStoreResult PeerStore::Save(const std::vector<PersistedPeer> &peers,Fault fault) {
    if(poisoned_)return fail(PeerStoreCode::Poisoned,"peer store requires reopen");
    if(limits_.payload_bytes>(1ULL<<30)||limits_.records>1000000||limits_.proof_bytes>(1ULL<<30)||limits_.locks_per_proof>AVALANCHE_MAX_PROOF_STAKES)return fail(PeerStoreCode::Resource,"invalid store limits");
    if(peers.size()>limits_.records)return fail(PeerStoreCode::Resource,"peer count bound");
    try {
    Bytes b; put(b,0x41505632,4);put(b,1,4);append(b,profile_.chain_id);append(b,profile_.genesis_id);append(b,profile_.validation_digest);put(b,peers.size(),4);
    try {
        std::set<::avalanche::ProofId> ids;
        for(const auto &p:peers) {
            if(!p.envelope.proof||!ids.insert(p.envelope.proof->getId()).second)throw std::runtime_error("null or duplicate proof");
            const auto &proof=*p.envelope.proof;
            if(proof.getStakes().size()>limits_.locks_per_proof||proof.getPayoutScript().size()>limits_.payout_bytes||GetSerializeSize(proof)>limits_.proof_bytes)throw std::runtime_error("proof bound");
            if(p.envelope.payment_locks.size()!=proof.getStakes().size())throw std::runtime_error("lock count");
            auto size=GetSerializeSize(proof); if(size+4+4+35*p.envelope.payment_locks.size()+17>limits_.payload_bytes || b.size()>limits_.payload_bytes-(size+4+4+35*p.envelope.payment_locks.size()+17))throw std::runtime_error("payload bound");
            DataStream stream; stream<<proof; put(b,size,4); b.insert(b.end(),reinterpret_cast<const uint8_t*>(stream.data()),reinterpret_cast<const uint8_t*>(stream.data())+stream.size()); put(b,p.envelope.payment_locks.size(),4);
            for(const auto &lock:p.envelope.payment_locks) { if(lock.size()!=35||lock[0]!=32||lock[33]!=0xbc||lock[34]!=0x4e)throw std::runtime_error("lock encoding"); append(b,lock); }
            put(b,p.finalized,1);put(b,uint64_t(p.registration_time),8);put(b,uint64_t(p.next_conflict_time),8);
        }
    } catch(const std::exception &e) {return {PeerStoreCode::Resource,e.what()};}
    append(b,digest(b));
    ScopedFd parent{openParent(path_)}; if(parent.fd<0)return fail(PeerStoreCode::Io,"open peer directory");
    static std::atomic<uint64_t> sequence{};
    std::string temporary; int fd=-1;
    for(unsigned attempt=0;attempt<100;++attempt) {
        temporary=path_.filename().string()+".tmp."+std::to_string(getpid())+"."+std::to_string(sequence.fetch_add(1));
        fd=openat(parent.fd,temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd>=0 || errno!=EEXIST)break;
    }
    if(fd<0)return fail(PeerStoreCode::Io,"create peer temporary");
    size_t off=0; bool good=true; while(off<b.size()) { auto n=write(fd,b.data()+off,b.size()-off); if(n<0&&errno==EINTR)continue; if(n<=0){good=false;break;} off+=n; }
    if(good)good=fsync(fd)==0; if(close(fd)!=0)good=false;
    if(!good||fault==Fault::BeforeReplace) { unlinkat(parent.fd,temporary.c_str(),0);return fail(PeerStoreCode::Io,"sync peer temporary"); }
    if(renameat(parent.fd,temporary.c_str(),parent.fd,path_.filename().c_str())) {unlinkat(parent.fd,temporary.c_str(),0);return fail(PeerStoreCode::Io,"replace peer store");}
    good=fault!=Fault::AfterReplace&&fsync(parent.fd)==0;
    if(!good){poisoned_=true;return fail(PeerStoreCode::Ambiguous,"peer replacement directory sync uncertain");} return {};
    } catch(const std::bad_alloc &) { return fail(PeerStoreCode::Resource,"peer store allocation"); }
      catch(const std::length_error &) { return fail(PeerStoreCode::Resource,"peer store allocation bound"); }
}
}
