// Copyright (c) 2026 The Lotus developers
#include "avalanche_proof.h"
#include "avalanche_protocol.h"
#include "commitment.h"
#include <avalanche/proofbuilder.h>
#include <avalanche/delegationbuilder.h>
#include <avalanche/validation.h>
#include <hash.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>
#include <limits>
using namespace lotus::v2;
using namespace lotus::v2::ava;
BOOST_FIXTURE_TEST_SUITE(v2_avalanche_proof, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(native_coin_and_epoch_binding) {
    CKey key; key.MakeNewKey(true);
    ::avalanche::ProofBuilder builder(1, 2000, key, CScript() << OP_RETURN);
    const Amount amount = ::avalanche::PROOF_DUST_THRESHOLD;
    BOOST_REQUIRE(builder.addUTXO(COutPoint(TxId(uint256::ONE), 0), amount, 3, false, key));
    ProofEnvelope env{builder.build(), {}};
    std::vector<uint8_t> lock{0x20};
    auto pub = key.GetPubKey(); lock.insert(lock.end(), pub.begin()+1, pub.end());
    lock.insert(lock.end(), {0xbc,0x4e}); env.payment_locks.push_back(lock);
    lotus::v2::Coin coin{}; coin.outpoint.tx_id[0]=1; coin.creation_height=3;
    coin.output.value=amount/SATOSHI; coin.output.branches={BranchLeaf(lock)};
    coin.output.paths={{0}};
    Profile profile; profile.chain_id[0]=1; profile.genesis_id[0]=2; profile.validation_digest[0]=3;
    ChainSnapshot snapshot{}; snapshot.height=2018; snapshot.median_time_past=1999;
    auto live=snapshot;
    bool missing=false, change=false;
    CoinLookup lookup=[&](const Outpoint &point, std::optional<lotus::v2::Coin> &out, std::string &) {
        BOOST_CHECK(point == coin.outpoint);
        out=missing ? std::nullopt : std::optional<lotus::v2::Coin>{coin};
        if(change) ++live.generation;
        return true;
    };
    SnapshotReader reader=[&]{return live;};
    AdmittedProof admitted; std::string error;
    auto admit=[&]{return AdmitProof(profile,snapshot,lookup,env,admitted,reader,error);};
    BOOST_REQUIRE(admit());
    ::avalanche::ProofValidationState state;
    BOOST_CHECK(env.proof->verify(profile.stake_dust,state)); // exact upstream signature validator
    BOOST_CHECK_EQUAL(env.proof->getScore(), ::avalanche::Proof::amountToScore(amount));
    auto valid_proof=env.proof;
    auto signed_stakes=valid_proof->getStakes();
    auto bad_signature=signed_stakes[0].getSignature(); bad_signature[0]^=1;
    signed_stakes[0]=::avalanche::SignedStake(signed_stakes[0].getStake(),bad_signature);
    env.proof=::avalanche::ProofRef::make(valid_proof->getSequence(),
        valid_proof->getExpirationTime(),valid_proof->getMaster(),signed_stakes,
        valid_proof->getPayoutScript(),valid_proof->getSignature());
    BOOST_CHECK(!admit()); BOOST_CHECK_EQUAL(error,"invalid-stake-signature");
    env.proof=valid_proof;
    auto bad_master_signature=valid_proof->getSignature(); bad_master_signature[0]^=1;
    env.proof=::avalanche::ProofRef::make(valid_proof->getSequence(),
        valid_proof->getExpirationTime(),valid_proof->getMaster(),valid_proof->getStakes(),
        valid_proof->getPayoutScript(),bad_master_signature);
    BOOST_CHECK(!admit()); BOOST_CHECK_EQUAL(error,"invalid-proof-signature");
    env.proof=valid_proof;
    auto saved=coin;
    coin.output.flags=1; BOOST_CHECK(!admit()); coin=saved;
    coin.output.token_id[0]=1; BOOST_CHECK(!admit()); coin=saved;
    coin.output.paths={{0,0}}; BOOST_CHECK(!admit()); coin=saved;
    coin.output.branches[0][0]^=1; BOOST_CHECK(!admit()); coin=saved;
    coin.output.value++; BOOST_CHECK(!admit()); coin=saved;
    coin.output.value=std::numeric_limits<uint64_t>::max(); BOOST_CHECK(!admit()); coin=saved;
    coin.creation_height++; BOOST_CHECK(!admit()); coin=saved;
    coin.coinbase=true; BOOST_CHECK(!admit()); coin=saved;
    env.payment_locks[0][1]^=1; BOOST_CHECK(!admit()); env.payment_locks[0]=lock;
    missing=true; BOOST_CHECK(!admit()); missing=false;
    snapshot.height=2017; live=snapshot; BOOST_CHECK(!admit()); snapshot.height=2018;live=snapshot;
    snapshot.median_time_past=2000; live=snapshot; BOOST_CHECK(!admit()); snapshot.median_time_past=1999;live=snapshot;
    change=true; BOOST_CHECK(!admit()); BOOST_CHECK_EQUAL(error,"stale-chain-snapshot");
}
BOOST_AUTO_TEST_CASE(upstream_hello_and_response_signatures) {
    CKey master; master.MakeNewKey(true); CKey session; session.MakeNewKey(true);
    ::avalanche::ProofBuilder builder(1, 0, master, CScript() << OP_RETURN);
    BOOST_REQUIRE(builder.addUTXO(COutPoint(TxId(uint256::ONE),0), ::avalanche::PROOF_DUST_THRESHOLD,0,false,master));
    auto proof=builder.build();
    ::avalanche::DelegationBuilder db(*proof);
    BOOST_REQUIRE(db.addLevel(master,session.GetPubKey())); auto delegation=db.build();
    ConnectionTranscript t{1,2,3,4}; SchnorrSig sig{};
    BOOST_REQUIRE(session.SignSchnorr(HelloDigest(delegation,t),sig));
    BOOST_CHECK(HelloDigest(delegation,t)==(HashWriter{} << delegation.getId() << uint64_t(1) << uint64_t(2) << uint64_t(3) << uint64_t(4)).GetHash());
    AuthenticatedHello hello;std::string error;
    BOOST_REQUIRE(AuthenticateHello(delegation,sig,t,1024,hello,error));
    BOOST_CHECK(hello.proof_id==proof->getId()); BOOST_CHECK(hello.session_key==session.GetPubKey());
    ++t.sender_nonce; BOOST_CHECK(!AuthenticateHello(delegation,sig,t,1024,hello,error)); --t.sender_nonce;
    ++t.receiver_entropy; BOOST_CHECK(!AuthenticateHello(delegation,sig,t,1024,hello,error)); --t.receiver_entropy;
    BOOST_CHECK(!AuthenticateHello(delegation,sig,t,15,hello,error));
    sig[0]^=1; BOOST_CHECK(!AuthenticateHello(delegation,sig,t,1024,hello,error));
    ::avalanche::DelegationBuilder wrong(::avalanche::LimitedProofId{},master.GetPubKey());
    BOOST_CHECK(!AuthenticateHello(wrong.build(),sig,t,1024,hello,error));
    SignedResponse response{::avalanche::Response(7,100,{::avalanche::Vote(0,uint256::ONE)}),{}};
    BOOST_REQUIRE(session.SignSchnorr(ResponseDigest(response.response),response.signature));
    BOOST_CHECK(AuthenticateResponse(session.GetPubKey(),response,error));
    BOOST_CHECK(!AuthenticateResponse(master.GetPubKey(),response,error));
    response.response=::avalanche::Response(8,100,{}); BOOST_CHECK(!AuthenticateResponse(session.GetPubKey(),response,error));
}
BOOST_AUTO_TEST_SUITE_END()
