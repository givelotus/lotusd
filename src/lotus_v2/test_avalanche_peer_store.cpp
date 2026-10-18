// Copyright (c) 2026 The Lotus developers
#include "avalanche_peer_store.h"
#include <avalanche/proofbuilder.h>
#include <key.h>
#include <stdexcept>
#define BOOST_REQUIRE(x) do { if(!(x)) throw std::runtime_error(#x); } while(0)
#define BOOST_CHECK(x) BOOST_REQUIRE(x)
#define BOOST_REQUIRE_EQUAL(x,y) BOOST_REQUIRE((x)==(y))
#define BOOST_CHECK_EQUAL(x,y) BOOST_REQUIRE_EQUAL(x,y)
#include <fstream>
#include <crypto/sha256.h>
#include <unistd.h>
#include <util/translation.h>
const std::function<std::string(const char *)> G_TRANSLATION_FUN{};
using namespace lotus::v2;
using namespace lotus::v2::ava;
int main() {
    ECC_Start();
    struct ECCCleanup { ~ECCCleanup(){ECC_Stop();} } ecc_cleanup;
    auto pattern=(std::filesystem::canonical(std::filesystem::temp_directory_path())/"lotus-ava-store-XXXXXX").string(); auto dir=mkdtemp(pattern.data()); BOOST_REQUIRE(dir);
    struct Cleanup { std::filesystem::path p; ~Cleanup(){std::filesystem::remove_all(p);} } cleanup{dir};
    auto path=cleanup.p/"peers";
    Profile profile; profile.chain_id[0]=1;profile.genesis_id[0]=2;profile.validation_digest[0]=3;
    CKey key;key.MakeNewKey(true); ::avalanche::ProofBuilder builder(1,2000,key,CScript()<<OP_RETURN);
    BOOST_REQUIRE(builder.addUTXO(COutPoint(TxId(uint256::ONE),0),::avalanche::PROOF_DUST_THRESHOLD,3,false,key));
    std::vector<uint8_t> lock{32};auto pub=key.GetPubKey();lock.insert(lock.end(),pub.begin()+1,pub.end());lock.insert(lock.end(),{0xbc,0x4e});
    PersistedPeer peer{{builder.build(),{lock}},true,123,456};
    PeerStore store(path,profile);std::vector<PersistedPeer> loaded;
    BOOST_CHECK(store.Load(loaded).code==PeerStoreCode::Missing);
    // Parent traversal rejects symlinks, including a pathname replaced after
    // construction. Existing destination data must survive rejected writes.
    auto intended=cleanup.p/"intended";auto outside=cleanup.p/"outside";
    std::filesystem::create_directory(intended);std::filesystem::create_directory(outside);
    PeerStore parent_replaced(intended/"peers",profile);
    std::filesystem::rename(intended,cleanup.p/"original");
    std::filesystem::create_directory_symlink(outside,intended);
    BOOST_CHECK(parent_replaced.Save({peer}).code==PeerStoreCode::Io);
    BOOST_CHECK(parent_replaced.Load(loaded).code==PeerStoreCode::Io);
    BOOST_CHECK(!std::filesystem::exists(outside/"peers"));
    BOOST_CHECK(!std::filesystem::exists(cleanup.p/"original"/"peers"));
    BOOST_REQUIRE(bool(store.Save({peer})));
    PeerStore restarted(path,profile);BOOST_REQUIRE(bool(restarted.Load(loaded)));BOOST_REQUIRE_EQUAL(loaded.size(),1U);
    BOOST_CHECK(loaded[0].envelope.proof->getId()==peer.envelope.proof->getId());BOOST_CHECK(loaded[0].envelope.payment_locks==peer.envelope.payment_locks);
    BOOST_CHECK(loaded[0].finalized);BOOST_CHECK_EQUAL(loaded[0].registration_time,123);BOOST_CHECK_EQUAL(loaded[0].next_conflict_time,456);
    BOOST_CHECK(store.Save({},PeerStore::Fault::BeforeReplace).code==PeerStoreCode::Io);BOOST_REQUIRE(bool(restarted.Load(loaded)));BOOST_CHECK_EQUAL(loaded.size(),1U);
    auto foreign=profile;foreign.validation_digest[0]++;PeerStore other(path,foreign);BOOST_CHECK(other.Load(loaded).code==PeerStoreCode::ForeignProfile);BOOST_CHECK(loaded.empty());
    PeerStoreLimits limits;limits.records=0;PeerStore capped(path,profile,limits);BOOST_CHECK(capped.Load(loaded).code==PeerStoreCode::Resource);BOOST_CHECK(capped.Save({peer}).code==PeerStoreCode::Resource);
    BOOST_CHECK(store.Save({},PeerStore::Fault::AfterReplace).code==PeerStoreCode::Ambiguous);BOOST_CHECK(store.Poisoned());BOOST_CHECK(store.Load(loaded).code==PeerStoreCode::Poisoned);BOOST_CHECK(loaded.empty());BOOST_CHECK(store.Save({peer}).code==PeerStoreCode::Poisoned);
    PeerStore fresh(path,profile);BOOST_REQUIRE(bool(fresh.Load(loaded)));BOOST_CHECK(loaded.empty());BOOST_REQUIRE(bool(fresh.Save({peer})));
    {std::fstream file(path,std::ios::binary|std::ios::in|std::ios::out);file.seekp(120);file.put('\xff');}
    BOOST_CHECK(fresh.Load(loaded).code==PeerStoreCode::Corrupt);BOOST_CHECK(loaded.empty());
    BOOST_REQUIRE(bool(fresh.Save({peer})));
    // Authenticated malicious nested count must be rejected before ABC allocates
    // the stake vector. The outer proof size remains a valid bounded frame.
    { std::ifstream input(path,std::ios::binary); std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
      const size_t stake_count=108+4+16+1+33;
      bytes.at(stake_count)=252;
      CSHA256().Write(bytes.data(),bytes.size()-32).Finalize(bytes.data()+bytes.size()-32);
      std::ofstream output(path,std::ios::binary|std::ios::trunc); output.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); }
    PeerStoreLimits proof_caps; proof_caps.locks_per_proof=1; PeerStore proof_capped(path,profile,proof_caps);
    BOOST_CHECK(proof_capped.Load(loaded).code==PeerStoreCode::Corrupt);BOOST_CHECK(loaded.empty());
    BOOST_REQUIRE(bool(fresh.Save({peer})));std::filesystem::resize_file(path,141);BOOST_CHECK(fresh.Load(loaded).code==PeerStoreCode::Corrupt);
}

