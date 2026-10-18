// Copyright (c) 2026 The Lotus developers
#include "avalanche_poll.h"
#include "commitment.h"
#include <avalanche/proofbuilder.h>
#include <avalanche/delegationbuilder.h>
#include <key.h>
#include <util/translation.h>
#include <iostream>
#include <stdexcept>
using namespace lotus::v2;
using namespace lotus::v2::ava;
const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (0)
int main() {
 ECC_Start();
 try {
  uint64_t saturated=UINT64_MAX-1;IncrementDiagnostic(saturated);CHECK(saturated==UINT64_MAX);IncrementDiagnostic(saturated);CHECK(saturated==UINT64_MAX);
  Profile profile; profile.chain_id[0]=1; profile.genesis_id[0]=2; profile.validation_digest[0]=3;
  ChainSnapshot snapshot; snapshot.tip[0]=4; snapshot.height=3000;
  Quorum quorum(profile); PollEngine engine(profile); std::string error;
  constexpr int64_t wall_seconds=1900000000;
  CKey key; key.MakeNewKey(true); auto pub=key.GetPubKey();
  std::vector<uint8_t> lock{0x20}; lock.insert(lock.end(),pub.begin()+1,pub.end()); lock.push_back(0xbc); lock.push_back(0x4e);
  Coin coin; coin.outpoint.tx_id[0]=9; coin.creation_height=1; coin.output.value=1000000000000ULL; coin.output.branches={BranchLeaf(lock)}; coin.output.paths={{0}};
  uint256 tx; std::copy(coin.outpoint.tx_id.begin(),coin.outpoint.tx_id.end(),tx.begin());
  ::avalanche::ProofBuilder builder(1,0,key,CScript{} << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20,1) << OP_EQUALVERIFY << OP_CHECKSIG);
  CHECK(builder.addUTXO(COutPoint(TxId(tx),0),int64_t(coin.output.value)*SATOSHI,1,false,key));
  ProofEnvelope envelope{builder.build(),{lock}};
  auto read=[&]{return snapshot;};
  CoinLookup lookup=[&](const Outpoint &point,std::optional<Coin> &out,std::string &){out=point==coin.outpoint?std::optional<Coin>(coin):std::nullopt;return true;};
  auto forged=envelope; forged.payment_locks[0][1]^=1;
  CHECK(!quorum.Register(forged,snapshot,lookup,0,read,error));
  if(!quorum.Register(envelope,snapshot,lookup,0,read,error)) throw std::runtime_error(error);
  auto saved=quorum.ExportPeers(); CHECK(saved.size()==1);
  Quorum restored(profile); CHECK(restored.RestorePeers(saved,snapshot,lookup,read,error));
  CHECK(restored.Vote(envelope.proof->getId())==0);
  std::vector<std::pair<::avalanche::ProofId,Status>> proof_batch{{envelope.proof->getId(),Status::Rejected}};
  CHECK(!restored.ApplyProofVotes(proof_batch,1,[](std::string &){return false;},error));
  CHECK(restored.Vote(envelope.proof->getId())==0);
  bool committed_invalid_batch=false; proof_batch.emplace_back(::avalanche::ProofId{},Status::Accepted);
  CHECK(!restored.ApplyProofVotes(proof_batch,1,[&](std::string &){committed_invalid_batch=true;return true;},error));
  CHECK(!committed_invalid_batch); CHECK(restored.Vote(envelope.proof->getId())==0);
  auto poisoned=saved; poisoned[0].envelope.payment_locks[0][1]^=1;
  Quorum rejected_restore(profile); CHECK(!rejected_restore.RestorePeers(poisoned,snapshot,lookup,read,error)); CHECK(rejected_restore.Proofs().empty());
  Quorum young(profile); snapshot.height=1;
  CHECK(!young.Register(envelope,snapshot,lookup,0,read,error)); CHECK(error=="immature-utxo");
  CHECK(young.Vote(envelope.proof->getId())==2); CHECK(!young.Pollable(envelope.proof->getId()));
  snapshot.height=3000; CHECK(young.Revalidate(snapshot,lookup,0,read,error)); CHECK(young.Vote(envelope.proof->getId())==0);
  snapshot.height=1; CHECK(young.Revalidate(snapshot,lookup,0,read,error)); CHECK(young.Vote(envelope.proof->getId())==2);
  snapshot.height=3000;
  // Maturing a preferred aggregate cannot bypass a finalized peer's cooldown.
  Quorum cooldown(profile); CHECK(cooldown.Register(envelope,snapshot,lookup,0,read,error));
  CHECK(cooldown.ApplyProofVote(envelope.proof->getId(),Status::Finalized,100,error));
  Coin recent=coin; recent.outpoint.tx_id[0]=10; recent.creation_height=2500;
  uint256 recent_tx; std::copy(recent.outpoint.tx_id.begin(),recent.outpoint.tx_id.end(),recent_tx.begin());
  ::avalanche::ProofBuilder replacement_builder(2,0,key,CScript{} << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20,1) << OP_EQUALVERIFY << OP_CHECKSIG);
  CHECK(replacement_builder.addUTXO(COutPoint(TxId(tx),0),int64_t(coin.output.value)*SATOSHI,1,false,key));
  CHECK(replacement_builder.addUTXO(COutPoint(TxId(recent_tx),0),int64_t(recent.output.value)*SATOSHI,2500,false,key));
  ProofEnvelope replacement{replacement_builder.build(),{lock,lock}};
  CoinLookup mixed=[&](const Outpoint &point,std::optional<Coin> &out,std::string &){out=point==coin.outpoint?std::optional<Coin>(coin):point==recent.outpoint?std::optional<Coin>(recent):std::nullopt;return true;};
  CHECK(!cooldown.Register(replacement,snapshot,mixed,101,read,error)); CHECK(error=="immature-utxo");
  CHECK(cooldown.Vote(replacement.proof->getId())==2);
  Quorum immature_preference(profile); CHECK(!immature_preference.Register(replacement,snapshot,mixed,101,read,error));
  ::avalanche::ProofBuilder preferred_builder(3,0,key,CScript{} << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20,1) << OP_EQUALVERIFY << OP_CHECKSIG);
  CHECK(preferred_builder.addUTXO(COutPoint(TxId(tx),0),int64_t(coin.output.value)*SATOSHI,1,false,key));
  CHECK(preferred_builder.addUTXO(COutPoint(TxId(recent_tx),0),int64_t(recent.output.value)*SATOSHI,2500,false,key));
  ProofEnvelope preferred{preferred_builder.build(),{lock,lock}};
  CHECK(!immature_preference.Register(preferred,snapshot,mixed,101,read,error));
  CHECK(immature_preference.Vote(replacement.proof->getId())==uint32_t(-1)); CHECK(immature_preference.Vote(preferred.proof->getId())==2);
  snapshot.height=5000; CHECK(cooldown.Revalidate(snapshot,mixed,102,read,error));
  CHECK(cooldown.Vote(envelope.proof->getId())==0); CHECK(cooldown.Vote(replacement.proof->getId())==uint32_t(-1));
  CHECK(cooldown.Register(replacement,snapshot,mixed,101+int64_t(profile.peer_replacement_cooldown_seconds),read,error));
  CHECK(cooldown.Vote(replacement.proof->getId())==0); CHECK(cooldown.Vote(envelope.proof->getId())==3);
  // Rejecting the preferred active proof evicts its older conflicting proof.
  // The later update for that initially known, now absent proof is skipped;
  // unrelated block work in the same atomic callback must still commit.
  std::vector<std::pair<::avalanche::ProofId,Status>> conflicting_batch{
   {replacement.proof->getId(),Status::Rejected},{envelope.proof->getId(),Status::Accepted}};
  auto one_record_profile=profile; one_record_profile.max_queries=1;
  PollEngine replacement_records(one_record_profile);
  PollItem old_record{ItemKind::Proof,{}}; std::copy(envelope.proof->getId().begin(),envelope.proof->getId().end(),old_record.id.begin());
  PollItem new_record{ItemKind::Proof,{}}; std::copy(replacement.proof->getId().begin(),replacement.proof->getId().end(),new_record.id.begin());
  CHECK(replacement_records.Reconcile(old_record,false,error));
  size_t block_batch_commits=0;
  CHECK(cooldown.ApplyProofVotes(conflicting_batch,100000,[&](std::string &){++block_batch_commits;return true;},error));
  CHECK(block_batch_commits==1); CHECK(cooldown.Vote(replacement.proof->getId())==3);
  CHECK(cooldown.Vote(envelope.proof->getId())==uint32_t(-1));
  CHECK(cooldown.ApplyProofVote(replacement.proof->getId(),Status::Accepted,100001,error));
  CHECK(!replacement_records.Reconcile(new_record,true,error)); CHECK(error=="vote-record-capacity");
  replacement_records.PruneProofs(cooldown);
  CHECK(replacement_records.Reconcile(new_record,true,error));
  snapshot.height=3000;
  auto bad_profile=profile; bad_profile.min_quorum_stake=MAX_MONEY+SATOSHI;
  bool invalid_constructor=false; try { Quorum invalid(bad_profile); } catch(const std::invalid_argument &) { invalid_constructor=true; } CHECK(invalid_constructor);
  auto delegation=::avalanche::DelegationBuilder(*envelope.proof).build();
  ConnectionTranscript transcript{1,2,3,4}; SchnorrSig hello;
  CHECK(key.SignSchnorr(HelloDigest(delegation,transcript),hello));
  for(int i=0;i<8;++i) { CHECK(quorum.Bind(i,delegation,hello,transcript,16,error)); quorum.SentProofInventory(i,snapshot); }
  CHECK(quorum.Established(snapshot));
  PollItem block{ItemKind::Block,{}}; block.id[0]=42;
  PollItem proof{ItemKind::Proof,{}}; std::copy(envelope.proof->getId().begin(),envelope.proof->getId().end(),proof.id.begin());
  CHECK(engine.Reconcile(block,true,error)); CHECK(engine.Reconcile(proof,true,error));
  OutgoingPoll poll; CHECK(engine.Next(quorum,snapshot,0,poll,error)); CHECK(poll.items.size()==2);
  SignedResponse response;
  ObserveBlock observe=[](const lotus::v2::Hash &,BlockObservation &state,std::string &){state.known=true;state.valid=true;state.active=true;return true;};
  CHECK(engine.Respond(poll,observe,quorum,key,response,error));
  auto bad=response; bad.signature[0]^=1;
  ApplyBlockUpdates apply=[&](const std::vector<BlockUpdate> &updates,std::string &){ for(const auto &update:updates) if(update.expected_tip!=snapshot.tip || update.expected_generation!=snapshot.generation) return false; return true; };
  CHECK(!engine.Receive(quorum,poll.node,bad,snapshot,1,wall_seconds,apply,error));
  CHECK(engine.Receive(quorum,poll.node,response,snapshot,1,wall_seconds,apply,error));
  CHECK(!engine.Receive(quorum,poll.node,response,snapshot,2,wall_seconds,apply,error));
  // A signed malformed response consumes the query and releases every slot.
  CHECK(engine.Next(quorum,snapshot,102,poll,error));
  response.response=::avalanche::Response(poll.round,100,{}); CHECK(key.SignSchnorr(ResponseDigest(response.response),response.signature));
  CHECK(!engine.Receive(quorum,poll.node,response,snapshot,103,wall_seconds,apply,error)); CHECK(error=="invalid-ava-response-size");
  CHECK(!engine.Receive(quorum,poll.node,response,snapshot,104,wall_seconds,apply,error)); CHECK(error=="unexpected-ava-response");
  // A real query expiry followed by a valid signed late response must not
  // disconnect its healthy node or advance the native vote confidence.
  PollEngine delayed(profile);CHECK(delayed.Reconcile(block,true,error));
  OutgoingPoll expired;CHECK(delayed.Next(quorum,snapshot,300,expired,error));
  SignedResponse late;CHECK(delayed.Respond(expired,observe,quorum,key,late,error));
  const auto confidence_before=delayed.Confidence(block);CHECK(confidence_before && *confidence_before==0);
  OutgoingPoll current;CHECK(delayed.Next(quorum,snapshot,10301,current,error));
  size_t late_applies=0;ApplyBlockUpdates late_apply=[&](const auto &,std::string &){++late_applies;return true;};
  CHECK(delayed.ReceiveResponse(quorum,expired.node,late,snapshot,10302,wall_seconds,late_apply,error)==PollReceiveResult::Ignored);
  CHECK(error=="unexpected-ava-response" && !late_applies && delayed.Confidence(block)==confidence_before && quorum.Node(expired.node));
  CHECK(delayed.ReceiveResponse(quorum,expired.node,late,snapshot,10303,wall_seconds,late_apply,error)==PollReceiveResult::Ignored);
  auto forged_late=late;forged_late.signature[0]^=1;
  CHECK(delayed.ReceiveResponse(quorum,expired.node,forged_late,snapshot,10304,wall_seconds,late_apply,error)==PollReceiveResult::Rejected);
  CHECK(delayed.Confidence(block)==confidence_before);
  SignedResponse mismatch_response;CHECK(delayed.Respond(current,observe,quorum,key,mismatch_response,error));
  auto wrong_votes=mismatch_response.response.GetVotes();wrong_votes[0]=::avalanche::Vote(0,uint256::ONE);
  mismatch_response.response=::avalanche::Response(current.round,100,std::move(wrong_votes));CHECK(key.SignSchnorr(ResponseDigest(mismatch_response.response),mismatch_response.signature));
  CHECK(delayed.ReceiveResponse(quorum,current.node,mismatch_response,snapshot,10305,wall_seconds,late_apply,error)==PollReceiveResult::Rejected);
  CHECK(error=="invalid-ava-response-content" && !late_applies && delayed.Confidence(block)==confidence_before);
  const auto delayed_stats=delayed.Diagnostics();
  CHECK(delayed_stats.queries_created==2 && delayed_stats.queries_expired==1 && delayed_stats.responses_matched==1);
  CHECK(delayed_stats.responses_applied==0 && delayed_stats.responses_ignored==2 && delayed_stats.responses_rejected==2 && delayed_stats.responses_local_failure==0);
  CHECK(delayed_stats.live_queries==0 && delayed_stats.live_records==1 && delayed.Diagnostics()==delayed_stats && delayed.Confidence(block)==confidence_before);
  CHECK(quorum.Node(expired.node) && delayed.Next(quorum,snapshot,10406,current,error));
  const auto queued_stats=delayed.Diagnostics();CHECK(queued_stats.queries_created==3 && queued_stats.live_queries==1);
  delayed.Disconnect(current.node);const auto cancelled_stats=delayed.Diagnostics();CHECK(cancelled_stats.queries_cancelled==1 && cancelled_stats.live_queries==0);
  CHECK(cancelled_stats.queries_created==cancelled_stats.responses_matched+cancelled_stats.queries_expired+cancelled_stats.queries_cancelled+cancelled_stats.live_queries);
  // Real upstream VoteRecord must finalize only after sustained diverse votes.
  size_t finalized=0;
  ApplyBlockUpdates finalize=[&](const std::vector<BlockUpdate> &updates,std::string &){
   for(const auto &update:updates) {
   CHECK(update.expected_tip==snapshot.tip); CHECK(update.expected_generation==snapshot.generation);
   if(update.status==Status::Finalized) ++finalized; } return true;
  };
  for(int64_t now=1000;now<1000000 && (finalized==0 || !quorum.ExportPeers().front().finalized);now+=101) {
   engine.PruneProofs(quorum); // Repeated proof cleanup preserves the block confidence.
   if(!engine.Next(quorum,snapshot,now,poll,error)) continue;
   CHECK(engine.Respond(poll,observe,quorum,key,response,error));
   CHECK(engine.Receive(quorum,poll.node,response,snapshot,now+1,wall_seconds,finalize,error));
  }
  CHECK(finalized==1); CHECK(!engine.Reconcile(block,true,error));
  auto finalized_peers=quorum.ExportPeers(); CHECK(finalized_peers.size()==1); CHECK(finalized_peers.front().finalized);
  // Query clocks near zero must never become proof replacement wall times.
  CHECK(finalized_peers.front().next_conflict_time==wall_seconds+int64_t(profile.peer_replacement_cooldown_seconds));
  PollEngine transactional(profile); PollItem second=block; second.id[0]++;
  CHECK(transactional.Reconcile(block,true,error)); CHECK(transactional.Reconcile(second,true,error));
  bool rejected_final=false; size_t batch_finalized=0;
  ApplyBlockUpdates atomic=[&](const std::vector<BlockUpdate> &updates,std::string &){
   size_t finals=0; for(const auto &update:updates) { CHECK(update.expected_tip==snapshot.tip); CHECK(update.expected_generation==snapshot.generation); finals+=update.status==Status::Finalized; }
   if(finals && !rejected_final) { rejected_final=true; return false; }
   batch_finalized+=finals; return true;
  };
  for(int64_t now=1000000;now<2000000 && batch_finalized<2;now+=101) {
   if(!transactional.Next(quorum,snapshot,now,poll,error)) continue;
   CHECK(transactional.Respond(poll,observe,quorum,key,response,error));
   const auto result=transactional.ReceiveResponse(quorum,poll.node,response,snapshot,now+1,wall_seconds,atomic,error);
   CHECK(result==PollReceiveResult::Applied || (result==PollReceiveResult::LocalFailure && rejected_final));
  }
  CHECK(rejected_final); CHECK(batch_finalized==2); CHECK(transactional.Diagnostics().responses_local_failure==1 && transactional.Diagnostics().responses_applied>0);
  // Ten inflight polls per inventory item, independently of peer capacity.
  for(int i=8;i<20;++i) { CHECK(quorum.Bind(i,delegation,hello,transcript,16,error)); }
  PollEngine bounded(profile); CHECK(bounded.Reconcile(block,true,error));
  for(int i=0;i<10;++i) CHECK(bounded.Next(quorum,snapshot,2000000,poll,error));
  CHECK(!bounded.Next(quorum,snapshot,2000000,poll,error));
  CHECK(bounded.Next(quorum,snapshot,2010001,poll,error));
  for(int i=7;i<20;++i) quorum.Disconnect(i);
  CHECK(!quorum.Established(snapshot));
  CHECK(engine.Respond(poll,observe,quorum,key,response,error));
  for(const auto &vote:response.response.GetVotes()) CHECK(vote.GetError()==uint32_t(-1));
  coin.output.value--; CHECK(quorum.Revalidate(snapshot,lookup,0,read,error)); CHECK(!quorum.Select(1000));
  std::cout<<"native Avalanche admission, quorum, typed polls, authentication and release checks passed\n";
 } catch(const std::exception &e) { std::cerr<<e.what()<<'\n'; ECC_Stop(); return 1; }
 ECC_Stop(); return 0;
}
