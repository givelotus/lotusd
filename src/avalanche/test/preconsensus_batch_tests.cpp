// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/preconsensus.h>

#include <avalanche/avalanche.h>
#include <avalanche/peermanager.h>
#include <avalanche/processor.h>
#include <avalanche/test/util.h>
#include <avalanche/voterecord.h>
#include <chainparams.h>
#include <config.h>
#include <common/args.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/chainstatemanager_args.h>
#include <policy/block/parkingpolicy.h>
#include <policy/block/preconsensus.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <streams.h>
#include <validation.h>
#include <validationinterface.h>
#include <future>

#include <test/util/net.h>
#include <test/util/logging.h>
#include <test/util/mining.h>
#include <pow/pow.h>
#include <logging.h>
#include <hash.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace avalanche;

namespace avalanche {
namespace {
    struct AvalancheTest {
        static void runEventLoop(Processor &p) { p.runEventLoop(); }
        static void updatedBlockTip(Processor &p) { p.updatedBlockTip(); }
        static size_t conflictedBatchCount(Processor &p) {
            LOCK(p.cs_mempoolBatches);
            return p.m_conflictedBatchIds.size();
        }
        static void activatePreconsensus(Processor &p, const CBlockIndex *tip) {
            LOCK(p.cs_finalizationTip);
            p.finalizationTip = tip;
        }
        static uint64_t getRound(const Processor &p) { return p.round; }
        static NodeId getPolledNode(Processor &p, uint64_t round) {
            auto queries = p.queries.getReadView();
            auto it = std::find_if(queries->begin(), queries->end(),
                                   [round](const auto &q) { return q.round == round; });
            BOOST_REQUIRE_MESSAGE(it != queries->end(), "No outstanding poll for round " << round);
            return it->nodeid;
        }

        static std::vector<CInv> getInvsForNextPoll(Processor &p) {
            auto r = p.voteRecords.getReadView();
            return p.getInvsForNextPoll(r, DEFAULT_AVALANCHE_MAX_ELEMENT_POLL,
                                        false, /*include_state_anchors=*/true, /*include_mempool_batches=*/true);
        }
    };
} // namespace
} // namespace avalanche

BOOST_AUTO_TEST_SUITE(preconsensus_batch_tests)

BOOST_FIXTURE_TEST_CASE(avaresponse_burst_preserves_individual_messages,
                        AvalancheTestingSetup) {
    LogInstance().EnableCategory(BCLog::NET);
    const CKey key = CKey::MakeCompressedKey();
    for (bool have_pubkey : {false, true}) {
        auto *node = new CNode(have_pubkey ? 901 : 900, nullptr, CAddress(),
                              0, 0, 0, CAddress(), "",
                              ConnectionType::OUTBOUND_FULL_RELAY, false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = PROTOCOL_VERSION;
        node->fSuccessfullyConnected = true;
        node->m_avalanche_enabled = true;
        if (have_pubkey) {
            LOCK(node->cs_avalanche_pubkey);
            node->m_avalanche_pubkey = key.GetPubKey();
        }
        m_connman->AddTestNode(*node);
        m_node.avalanche->setNodeMempoolBatchServices(node->GetId(), NODE_MERKLIX_EPOCH);
        constexpr int count = 5;
        for (int i = 0; i < count; ++i) {
            Response response(i, 0, {});
            HashWriter hash;
            hash << response;
            SchnorrSig sig;
            BOOST_REQUIRE(key.SignSchnorr(hash.GetHash(), sig));
            auto msg = NetMsg::Make(NetMsgType::AVARESPONSE, response, sig);
            if (have_pubkey && i == 2) msg.data.resize(1);
            BOOST_REQUIRE(m_connman->ReceiveMsgFrom(*node, msg));
        }
        node->fPauseSend = false;
        int no_pubkey_processed = 0;
        {
            DebugLogHelper log("invalid-ava-response-signature",
                [&](const std::string *line) {
                    if (line) ++no_pubkey_processed;
                    return false;
                });
            std::atomic<bool> interrupt{false};
            LOCK(NetEventsInterface::g_msgproc_mutex);
            m_node.peerman->ProcessMessages(config, node, interrupt);
        }
        if (have_pubkey) {
            // The malformed middle message must not discard either valid
            // prefix or suffix. Unsolicited valid responses reach registerVotes.
            BOOST_CHECK_EQUAL(node->m_avalanche_message_fault_counter, count - 1);
        } else {
            BOOST_CHECK_EQUAL(no_pubkey_processed, count);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(avalanche_defaults_keep_upstream_unparking,
                        BasicTestingSetup) {
    kernel::Notifications notifications;
    ChainstateManager::Options opts{.config = GetConfig(),
                                    .notifications = notifications};
    ArgsManager args;
    args.ForceSetArg("-avalanche", "1");
    BOOST_REQUIRE(!node::ApplyArgsManOptions(args, opts));
    BOOST_CHECK(!opts.automatic_unparking);
    args.ForceSetArg("-avalanche", "0");
    BOOST_REQUIRE(!node::ApplyArgsManOptions(args, opts));
    BOOST_CHECK(opts.automatic_unparking);
    args.ForceSetArg("-avalanche", "1");
    args.ForceSetArg("-automaticunparking", "1");
    BOOST_REQUIRE(!node::ApplyArgsManOptions(args, opts));
    BOOST_CHECK(opts.automatic_unparking);
}

// An Avalanche rejection parks the block. With Avalanche on, automatic
// unparking is off, so the parked tip must not come back merely because
// its own work exceeds the (zero) penalty of a fork at the tip. The batch
// retry tests below run with these same defaults.
BOOST_FIXTURE_TEST_CASE(avalanche_park_is_not_undone_by_work,
                        AvalancheTestChain100Setup) {
    auto &chainman = *m_node.chainman;
    auto &chainstate = chainman.ActiveChainstate();
    BOOST_REQUIRE(!chainman.m_options.automatic_unparking);
    CBlockIndex *tip = WITH_LOCK(cs_main, return chainman.ActiveTip());
    CBlockIndex *parent = tip->pprev;
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.ParkBlock(state, tip));
    BOOST_REQUIRE(chainstate.ActivateBestChain(state, nullptr,
                                               m_node.avalanche.get()));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveTip()), parent);
    WITH_LOCK(cs_main, BOOST_CHECK(tip->nStatus.isParked()));
    WITH_LOCK(cs_main, BOOST_CHECK(!tip->m_preconsensus_policy_parked));
}

BOOST_FIXTURE_TEST_CASE(work_unparking_preserves_finalized_ancestry,
                        AvalancheTestChain100Setup) {
    auto &chainman = *m_node.chainman;
    auto &chainstate = chainman.ActiveChainstate();
    CBlockIndex *tip = WITH_LOCK(cs_main, return chainman.ActiveTip());
    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainstate.AvalancheFinalizeBlock(tip, *m_node.avalanche));
    }
    CBlockIndex *parent = tip->pprev;
    // The competing branch has three blocks after the fork, enough to clear
    // the ordinary 1.5-block soft-park work penalty. Finality still wins.
    for (int i = 0; i < 3; ++i) {
        CBlock block = CreateBlock({}, CScript() << OP_TRUE, chainstate);
        block.hashPrevBlock = parent->GetBlockHash();
        createCoinbaseAndMerkleRoot(&block, parent, config.GetMaxBlockSize());
        block.nNonce = 0;
        while (!CheckProofOfWork(block.GetHash(), block.nBits,
                                config.GetChainParams().GetConsensus())) ++block.nNonce;
        BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(block),
            true, true, nullptr, m_node.avalanche.get()));
        parent = WITH_LOCK(cs_main,
            return chainman.m_blockman.LookupBlockIndex(block.GetHash()));
        BOOST_REQUIRE(parent);
    }
    BOOST_CHECK(parent->nChainWork > tip->nChainWork);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveTip()), tip);
    WITH_LOCK(cs_main, BOOST_CHECK(parent->nStatus.isOnParkedChain()));
}

BOOST_AUTO_TEST_CASE(batch_parking_compliant_sibling_arrival_orders) {
    for (bool compliantFirst : {false, true}) {
        AvalancheTestChain100Setup f;
        auto &chainman = *f.m_node.chainman;
        auto &chainstate = chainman.ActiveChainstate();
        auto &processor = *f.m_node.avalanche;
        const auto &config = f.config;
        f.setArg("-enablertt", "0");
        f.setArg("-avalanchestakingrewards", "0");
        CBlockIndex *tip = WITH_LOCK(cs_main, return chainman.ActiveTip());
        AvalancheTest::activatePreconsensus(processor, tip);
        auto proof = buildRandomProof(chainstate, MIN_VALID_PROOF_SCORE);
        BOOST_REQUIRE(processor.withPeerManager([&](avalanche::PeerManager &pm) {
            return pm.registerProof(proof);
        }));
        for (int i = 0; i < 8; ++i) {
            auto *node = new CNode(i + 1000, nullptr, CAddress(), 0, 0, 0,
                CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY, false);
            node->SetCommonVersion(PROTOCOL_VERSION);
            node->m_has_all_wanted_services = true;
            f.m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
            node->nVersion = PROTOCOL_VERSION;
            node->fSuccessfullyConnected = true;
            f.m_connman->AddTestNode(*node);
            processor.setNodeMempoolBatchServices(node->GetId(), NODE_MERKLIX_EPOCH);
            BOOST_REQUIRE(processor.withPeerManager([&](avalanche::PeerManager &pm) {
                return pm.addNode(node->GetId(), proof->getId(),
                                 DEFAULT_AVALANCHE_MAX_ELEMENT_POLL);
            }));
        }
        const CScript script = CScript() << ToByteVector(f.coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        const auto tx = f.CreateValidMempoolTransaction(f.m_coinbase_txns[0], 0,
            1, f.coinbaseKey, script, f.m_coinbase_txns[0]->vout[0].nValue, false);
        const auto ref = MakeTransactionRef(tx);
        CBlock compliant = f.CreateBlock({tx}, CScript() << OP_TRUE, chainstate);
        CBlock other = f.CreateBlock({}, CScript() << OP_TRUE, chainstate);
        {
            LOCK2(cs_main, f.m_node.mempool->cs);
            f.m_node.mempool->ConnectBlockReset(tip->GetBlockHash(),
                tip->nHeight + 1, tip->GetMedianTimePast());
            TestMemPoolEntryHelper entry;
            f.m_node.mempool->addUnchecked(entry.Fee(Amount::zero()).FromTx(ref));
        }
        MempoolBatchAnnouncement batch;
        batch.prev_block_hash = tip->GetBlockHash();
        batch.epoch_seq = 1;
        batch.tx_count = 1;
        batch.subtree_a_root = ComputeV2SubtreeARoot({ref});
        BOOST_REQUIRE(processor.registerMempoolBatch(batch, true));
        processor.finalizeMempoolBatch(batch.ComputeBatchId());
        // Hold queued tip callbacks so old-parent records remain present
        // until the competing ancestor is actually tried in both arrival orders.
        std::promise<void> callbacksBlocked, releaseCallbacks;
        const auto released = releaseCallbacks.get_future().share();
        struct ReleaseCallbacks {
            std::promise<void> &promise;
            ~ReleaseCallbacks() { promise.set_value(); }
        } releaseGuard{releaseCallbacks};
        f.m_node.validation_signals->CallFunctionInValidationInterfaceQueue(
            [&callbacksBlocked, released] {
                callbacksBlocked.set_value();
                released.wait();
            });
        callbacksBlocked.get_future().wait();
        auto submit = [&](const CBlock &block) {
            BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(block),
                true, true, nullptr, &processor));
        };
        if (compliantFirst) {
            submit(compliant);
            submit(other);
        } else {
            submit(other);
            BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveTip()), tip);
            submit(compliant);
        }
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()),
                          compliant.GetHash());
        // One additional block above the mismatching head supplies enough
        // work to exceed ABC's 1.5-block competing-branch threshold.
        CBlockIndex *otherIndex = WITH_LOCK(cs_main,
            return chainman.m_blockman.LookupBlockIndex(other.GetHash()));
        BOOST_REQUIRE(otherIndex);
        CBlock descendant = f.CreateBlock({}, CScript() << OP_TRUE, chainstate);
        descendant.hashPrevBlock = other.GetHash();
        createCoinbaseAndMerkleRoot(&descendant, otherIndex, config.GetMaxBlockSize());
        descendant.nNonce = 0;
        while (!CheckProofOfWork(descendant.GetHash(), descendant.nBits,
                                config.GetChainParams().GetConsensus())) ++descendant.nNonce;
        submit(descendant);
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()),
                          descendant.GetHash());
        WITH_LOCK(cs_main, BOOST_CHECK(!otherIndex->m_preconsensus_policy_parked));
    }
}

BOOST_FIXTURE_TEST_CASE(batch_tip_cleanup_removes_evicted_conflicts,
                        AvalancheTestChain100Setup) {
    auto &processor = *m_node.avalanche;
    const auto parent = WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash());
    for (size_t i = 0; i < Processor::MAX_MEMPOOL_BATCH_RECORDS + 2; ++i) {
        MempoolBatchAnnouncement batch;
        batch.prev_block_hash = parent;
        batch.epoch_seq = i < 2 ? 1 : uint32_t(i + 1);
        batch.tx_count = 1;
        batch.subtree_a_root = GetRandHash();
        BOOST_REQUIRE(processor.registerMempoolBatch(batch, false, false));
    }
    BOOST_CHECK_EQUAL(AvalancheTest::conflictedBatchCount(processor), 2U);
    const auto block = CreateAndProcessBlock({}, CScript() << OP_TRUE);
    BOOST_REQUIRE(WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash()) == block.GetHash());
    AvalancheTest::updatedBlockTip(processor);
    BOOST_CHECK_EQUAL(AvalancheTest::conflictedBatchCount(processor), 0U);
}

BOOST_FIXTURE_TEST_CASE(mempool_batch_serialization_and_id, BasicTestingSetup) {
    MempoolBatchAnnouncement batch;
    batch.prev_block_hash = BlockHash(uint256S(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"));
    batch.epoch_seq = 42;
    batch.parent_batch_id = uint256S(
        "1111111111111111111111111111111111111111111111111111111111111111");
    batch.subtree_a_root = uint256S(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    batch.utxo_root = uint256S(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    batch.tx_count = 128;
    batch.short_ids_hash = uint256S(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    // 1. Verify 168-byte wire format size and round-trip serialization
    DataStream ss{};
    ss << batch;
    BOOST_CHECK_EQUAL(ss.size(), MempoolBatchAnnouncement::SERIALIZED_SIZE);
    BOOST_CHECK_EQUAL(ss.size(), 168U);

    MempoolBatchAnnouncement deserialized;
    ss >> deserialized;
    BOOST_CHECK(deserialized == batch);
    BOOST_CHECK_EQUAL(deserialized.ComputeBatchId(), batch.ComputeBatchId());

    // 2. Verify the eCash tagged SHA256 identifier and field sensitivity
    const uint256 idOrig = batch.ComputeBatchId();
    BOOST_CHECK(!idOrig.IsNull());
    // Independent Python hashlib vector over explicit 168-byte LE serialization.
    BOOST_CHECK_EQUAL(idOrig.GetHex(),
        "f2550ec763722f0d511967da83bcfc5a4b5460f09a6001b17ed2ebcf85716f23");

    MempoolBatchAnnouncement modifiedEpoch = batch;
    modifiedEpoch.epoch_seq = 43;
    BOOST_CHECK(modifiedEpoch.ComputeBatchId() != idOrig);

    MempoolBatchAnnouncement modifiedTxCount = batch;
    modifiedTxCount.tx_count = 129;
    BOOST_CHECK(modifiedTxCount.ComputeBatchId() != idOrig);

    MempoolBatchAnnouncement zeroTxCount = batch;
    zeroTxCount.tx_count = 0;
    BOOST_CHECK(!zeroTxCount.IsValid());

    MempoolBatchAnnouncement modifiedSubtreeRoot = batch;
    modifiedSubtreeRoot.subtree_a_root = uint256S("01");
    BOOST_CHECK(modifiedSubtreeRoot.ComputeBatchId() != idOrig);

    // 3. Verify CInv wiring for MSG_AVA_MEMPOOL_BATCH
    CInv inv(MSG_AVA_MEMPOOL_BATCH, idOrig);
    BOOST_CHECK_EQUAL(inv.type, uint32_t(0x20000006));
    BOOST_CHECK(inv.IsMsgMempoolBatch());
    BOOST_CHECK_EQUAL(inv.GetKind(), uint32_t(MSG_AVA_MEMPOOL_BATCH));
    BOOST_CHECK_EQUAL(inv.GetMessageType(), NetMsgType::AVABATCH);
}

BOOST_FIXTURE_TEST_CASE(mempool_batch_voting_and_finalization,
                        AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    // Connect 8 avalanche nodes on a valid proof to establish quorum
    auto proof = buildRandomProof(active_chainstate, MIN_VALID_PROOF_SCORE);
    const ProofId &proofid = proof->getId();
    BOOST_CHECK(
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            return pm.registerProof(proof);
        }));

    std::array<CNode *, 8> nodes;
    for (size_t i = 0; i < nodes.size(); ++i) {
        CAddress addr;
        auto node =
            new CNode(static_cast<NodeId>(i + 1), /*sock=*/nullptr, addr, 0, 0,
                      0, CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY,
                      false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = 1;
        node->fSuccessfullyConnected = true;
        m_connman->AddTestNode(*node);
        m_node.avalanche->setNodeMempoolBatchServices(node->GetId(), NODE_MERKLIX_EPOCH);
        nodes[i] = node;
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            BOOST_CHECK(pm.addNode(node->GetId(), proofid,
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        });
    }
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());

    // Register a finalization callback
    bool callbackInvoked = false;
    MempoolBatchAnnouncement callbackBatch;
    m_node.avalanche->registerBatchFinalizedCallback(
        [&](const MempoolBatchAnnouncement &b) {
            callbackInvoked = true;
            callbackBatch = b;
        });

    // Register a MempoolBatchAnnouncement
    MempoolBatchAnnouncement batch;
    batch.prev_block_hash = chaintip->GetBlockHash();
    batch.epoch_seq = 1;
    batch.parent_batch_id = uint256::ZERO;
    batch.subtree_a_root = GetRandHash();
    batch.utxo_root = GetRandHash();
    batch.tx_count = 16;
    batch.short_ids_hash = GetRandHash();

    const uint256 batchId = batch.ComputeBatchId();
    BOOST_CHECK(!m_node.avalanche->isMempoolBatchKnown(batchId));
    BOOST_CHECK(
        m_node.avalanche->registerMempoolBatch(batch, /*locallyAccepted=*/true));
    BOOST_CHECK(m_node.avalanche->isMempoolBatchKnown(batchId));
    BOOST_CHECK(m_node.avalanche->isMempoolBatchLocallyAccepted(batchId));
    BOOST_CHECK(!m_node.avalanche->isMempoolBatchFinalized(batchId));

    // Verify the batch appears in the poll invs with MSG_AVA_MEMPOOL_BATCH
    auto invs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
    BOOST_REQUIRE_GE(invs.size(), 1U);
    const bool foundBatchInv = std::any_of(
        invs.begin(), invs.end(), [&](const CInv &inv) {
            return inv.type == uint32_t(MSG_AVA_MEMPOOL_BATCH) &&
                   inv.hash == batchId;
        });
    BOOST_CHECK(foundBatchInv);

    // Vote yes (0) across rounds until finalized
    size_t nextNodeIdx = 0;
    for (int roundIdx = 0;
         roundIdx < 200 && !m_node.avalanche->isMempoolBatchFinalized(batchId);
         ++roundIdx) {
        const uint64_t round =
            AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        const NodeId nodeid = nodes[nextNodeIdx++ % nodes.size()]->GetId();
        std::vector<Vote> votes;
        votes.reserve(polledInvs.size());
        for (const auto &polledInv : polledInvs) {
            votes.emplace_back(0, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp, updates,
                                                    disconnect, error));
    }

    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(batchId));
    BOOST_CHECK(callbackInvoked);
    BOOST_CHECK(callbackBatch == batch);

    MempoolBatchAnnouncement finalizedOut;
    BOOST_CHECK(m_node.avalanche->getFinalizedBatchForBlock(
        chaintip->GetBlockHash(), finalizedOut));
    BOOST_CHECK(finalizedOut == batch);
}

BOOST_FIXTURE_TEST_CASE(
    mempool_batch_untrusted_acceptance_and_preconsensus_policy,
    AvalancheTestChain100Setup) {
    gArgs.ForceSetArg("-avalanchepreconsensus", "1");

    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    // Establish 8-node quorum and finalize chaintip so
    // isPreconsensusActivated(chaintip) is true.
    auto proof = buildRandomProof(active_chainstate, MIN_VALID_PROOF_SCORE);
    const ProofId &proofid = proof->getId();
    std::array<CNode *, 8> nodes;
    m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
        BOOST_CHECK(pm.registerProof(proof));
    });
    for (size_t i = 0; i < nodes.size(); ++i) {
        CAddress addr;
        auto node =
            new CNode(static_cast<NodeId>(i + 10), /*sock=*/nullptr, addr, 0, 0,
                      0, CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY,
                      false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = 1;
        node->fSuccessfullyConnected = true;
        m_connman->AddTestNode(*node);
        m_node.avalanche->setNodeMempoolBatchServices(node->GetId(), NODE_MERKLIX_EPOCH);
        nodes[i] = node;
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            BOOST_CHECK(pm.addNode(node->GetId(), proofid,
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        });
    }
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());

    // Finalize chaintip via avalanche vote loop so hasFinalizedTip() is true.
    BOOST_CHECK(m_node.avalanche->addToReconcile(chaintip));
    size_t nextNodeIdx = 0;
    for (int roundIdx = 0;
         roundIdx < 200 && !m_node.avalanche->hasFinalizedTip(); ++roundIdx) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        const NodeId nodeid = nodes[nextNodeIdx++ % nodes.size()]->GetId();
        std::vector<Vote> votes;
        for (const auto &polledInv : polledInvs) {
            votes.emplace_back(0, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp, updates,
                                                    disconnect, error));
    }
    BOOST_CHECK(m_node.avalanche->hasFinalizedTip());
    BOOST_CHECK(m_node.avalanche->isPreconsensusActivated(chaintip));

    // 1. Untrusted peer-announced batch (locallyAccepted = false) must NOT be
    // marked locally accepted until setMempoolBatchAccepted(batchId, true) is
    // called, and re-registering an already-accepted batch with false must NOT
    // downgrade it.
    CMutableTransaction mtx1;
    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = COutPoint(TxId(GetRandHash()), 0);
    mtx1.vin[0].scriptSig = CScript() << OP_1;
    mtx1.vout.emplace_back(10 * COIN, CScript() << OP_TRUE);
    CTransactionRef tx1 = MakeTransactionRef(std::move(mtx1));

    CMutableTransaction mtx2;
    mtx2.nVersion = 2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout = COutPoint(TxId(GetRandHash()), 1);
    mtx2.vin[0].scriptSig = CScript() << OP_2;
    mtx2.vout.emplace_back(20 * COIN, CScript() << OP_TRUE);
    CTransactionRef tx2 = MakeTransactionRef(std::move(mtx2));

    MempoolBatchAnnouncement peerBatch;
    peerBatch.prev_block_hash = chaintip->GetBlockHash();
    peerBatch.epoch_seq = 7;
    peerBatch.parent_batch_id = uint256::ZERO;
    peerBatch.subtree_a_root = ComputeV2SubtreeARoot({tx1, tx2});
    peerBatch.utxo_root = GetRandHash();
    peerBatch.tx_count = 2;
    peerBatch.short_ids_hash = GetRandHash();
    const uint256 peerBatchId = peerBatch.ComputeBatchId();

    BOOST_CHECK(m_node.avalanche->registerMempoolBatch(
        peerBatch, /*locallyAccepted=*/false));
    BOOST_CHECK(m_node.avalanche->isMempoolBatchKnown(peerBatchId));
    BOOST_CHECK(!m_node.avalanche->isMempoolBatchLocallyAccepted(peerBatchId));
    BOOST_CHECK(
        !m_node.avalanche->isAccepted(MempoolBatchVoteItem(peerBatch)));

    // Promote to accepted after local verification
    BOOST_CHECK(m_node.avalanche->setMempoolBatchAccepted(peerBatchId, true));
    BOOST_CHECK(m_node.avalanche->isMempoolBatchLocallyAccepted(peerBatchId));
    BOOST_CHECK(
        m_node.avalanche->isAccepted(MempoolBatchVoteItem(peerBatch)));

    // Peer echoing the same batch with locallyAccepted=false must NOT downgrade
    // local acceptance.
    BOOST_CHECK(m_node.avalanche->registerMempoolBatch(
        peerBatch, /*locallyAccepted=*/false));
    BOOST_CHECK(m_node.avalanche->isMempoolBatchLocallyAccepted(peerBatchId));

    // Populate m_node.mempool with {tx1, tx2} anchored at chaintip so
    // finalizeMempoolBatch freezes the matching speculative overlay into L_1.
    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->clear();
        m_node.mempool->ConnectBlockReset(
            chaintip->GetBlockHash(), uint64_t(chaintip->nHeight + 1),
            uint64_t(chaintip->GetMedianTimePast()));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx2));
        BOOST_CHECK(
            m_node.mempool->GetOverlayManager().GetFrozenEpochs().empty());
    }

    // A smaller earlier batch for the same parent remains compliant even
    // after a larger batch is finalized. Unmined tx2 remains available.
    MempoolBatchAnnouncement earlierBatch = peerBatch;
    earlierBatch.epoch_seq = 6;
    earlierBatch.tx_count = 1;
    earlierBatch.subtree_a_root = ComputeV2SubtreeARoot({tx1});
    BOOST_REQUIRE(m_node.avalanche->registerMempoolBatch(earlierBatch, true));
    m_node.avalanche->finalizeMempoolBatch(earlierBatch.ComputeBatchId());

    // Finalize peerBatch -> freezes L_spec into L_1 (snapshot publication is added with its owning feature)
    m_node.avalanche->finalizeMempoolBatch(peerBatchId);
    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(peerBatchId));
    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK_EQUAL(
            m_node.mempool->GetOverlayManager().GetFrozenEpochs().size(), 1U);
    }

    // 2. PreConsensusPolicy enforcement against finalized MempoolBatchAnnouncement
    CMutableTransaction cbMtx;
    cbMtx.nVersion = 2;
    cbMtx.vin.resize(1);
    cbMtx.vin[0].prevout = COutPoint();
    cbMtx.vin[0].scriptSig = CScript() << int64_t(chaintip->nHeight + 1);
    cbMtx.vout.emplace_back(50 * COIN, CScript() << OP_TRUE);
    CTransactionRef cbTx = MakeTransactionRef(std::move(cbMtx));

    const BlockHash candidateHash(GetRandHash());
    CBlockIndex candidateIdx;
    candidateIdx.phashBlock = &candidateHash;
    candidateIdx.nHeight = chaintip->nHeight + 1;
    candidateIdx.pprev = chaintip;

    // 2a. Block omitting transactions from the finalized batch (only 1 non-cb tx
    // instead of batch.tx_count == 2) is parked by PreConsensusPolicy.
    {
        CBlock blockMissingTx;
        blockMissingTx.vtx = {cbTx, tx2};
        blockMissingTx.hashMerkleRoot = BlockMerkleRoot(blockMissingTx);

        LOCK(m_node.mempool->cs);
        BlockPolicyValidationState state;
        PreConsensusPolicy policy(*m_node.avalanche, candidateIdx,
                                  blockMissingTx, *m_node.mempool);
        ParkingPolicy &policy_ref = policy;
        BOOST_CHECK(!policy_ref(state));
        BOOST_CHECK(!state.IsValid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
                          "finalized-batch-mismatch");
    }

    // 2b. Block with enough transactions but wrong subtree_a_root is parked.
    {
        CMutableTransaction wrongMtx(*tx2);
        wrongMtx.vout[0].nValue = 19 * COIN;
        CTransactionRef wrongTx2 = MakeTransactionRef(std::move(wrongMtx));

        CBlock blockWrongRoot;
        blockWrongRoot.vtx = {cbTx, tx1, wrongTx2};
        blockWrongRoot.hashMerkleRoot = BlockMerkleRoot(blockWrongRoot);

        LOCK(m_node.mempool->cs);
        BlockPolicyValidationState state;
        PreConsensusPolicy policy(*m_node.avalanche, candidateIdx,
                                  blockWrongRoot, *m_node.mempool);
        ParkingPolicy &policy_ref = policy;
        BOOST_CHECK(!policy_ref(state));
        BOOST_CHECK(!state.IsValid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
                          "finalized-batch-mismatch");
    }

    // 2c. Block matching finalized batch subtree_a_root passes PreConsensusPolicy.
    {
        CBlock validBlock;
        validBlock.vtx = {cbTx, tx1, tx2};
        validBlock.hashMerkleRoot = BlockMerkleRoot(validBlock);
        BOOST_CHECK_EQUAL(
            ComputeV2SubtreeARoot({tx1, tx2}),
            peerBatch.subtree_a_root);

        LOCK(m_node.mempool->cs);
        BlockPolicyValidationState state;
        PreConsensusPolicy policy(*m_node.avalanche, candidateIdx, validBlock,
                                  *m_node.mempool);
        ParkingPolicy &policy_ref = policy;
        BOOST_CHECK(policy_ref(state));
        BOOST_CHECK(state.IsValid());
    }

    {
        CBlock olderMatch;
        olderMatch.vtx = {cbTx, tx1};
        olderMatch.hashMerkleRoot = BlockMerkleRoot(olderMatch);
        LOCK(m_node.mempool->cs);
        BlockPolicyValidationState state;
        PreConsensusPolicy policy(*m_node.avalanche, candidateIdx, olderMatch,
                                  *m_node.mempool);
        BOOST_CHECK(static_cast<ParkingPolicy &>(policy)(state));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(m_node.mempool->exists(tx2->GetId()));
    }

    // Duplicate identifiers are rejected by the policy boundary as well as
    // CheckBlock; they cannot escape as an uncaught recursive-root error.
    {
        CBlock duplicate;
        duplicate.vtx = {cbTx, tx1, tx1};
        LOCK(m_node.mempool->cs);
        BlockPolicyValidationState state;
        PreConsensusPolicy policy(*m_node.avalanche, candidateIdx, duplicate,
                                  *m_node.mempool);
        BOOST_CHECK(!static_cast<ParkingPolicy &>(policy)(state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "finalized-batch-mismatch");
    }

    setArg("-enablertt", "0");
    setArg("-avalanchestakingrewards", "0");
    // Integration: an otherwise-valid block at the current tip that misses
    // every finalized batch is parked once, then wins by existing work rules.
    // A batch-only grace requires a descendant before work retry. This is
    // work based: no elapsed-time rule or reconnect/repark loop exists.
    {
        {
            LOCK(m_node.mempool->cs);
            m_node.mempool->clear();
        }
        CBlock block = CreateBlock({}, CScript() << OP_TRUE, active_chainstate);
        int parks = 0, unparks = 0;
        DebugLogHelper parked("Park block because it violated a block policy:",
            [&](const std::string *line) {
                if (line && line->find("finalized-batch-mismatch") != std::string::npos)
                    ++parks;
                return false;
            });
        DebugLogHelper unparked("Unpark chain up to block", [&](const std::string *line) {
            if (line) ++unparks;
            return false;
        });
        BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(block),
            true, true, nullptr, m_node.avalanche.get()));
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveTip()), chaintip);
        BOOST_CHECK_EQUAL(parks, 1);
        BOOST_CHECK_EQUAL(unparks, 0);
        CBlockIndex *parkedIndex = WITH_LOCK(cs_main,
            return chainman.m_blockman.LookupBlockIndex(block.GetHash()));
        BOOST_REQUIRE(parkedIndex);
        CBlock child = CreateBlock({}, CScript() << OP_TRUE, active_chainstate);
        child.hashPrevBlock = block.GetHash();
        createCoinbaseAndMerkleRoot(&child, parkedIndex, config.GetMaxBlockSize());
        child.nNonce = 0;
        while (!CheckProofOfWork(child.GetHash(), child.nBits,
                                config.GetChainParams().GetConsensus())) ++child.nNonce;
        BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(child),
            true, true, nullptr, m_node.avalanche.get()));
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()),
                          child.GetHash());
        BOOST_CHECK_EQUAL(unparks, 1);
        WITH_LOCK(cs_main, BOOST_CHECK(!parkedIndex->m_preconsensus_policy_parked));
        BlockValidationState state;
        BOOST_REQUIRE(active_chainstate.ActivateBestChain(state, nullptr,
                                                          m_node.avalanche.get()));
        BOOST_CHECK_EQUAL(parks, 1);
        AvalancheTest::updatedBlockTip(*m_node.avalanche);
        BOOST_CHECK(m_node.avalanche->getFinalizedMempoolBatches(
            chaintip->GetBlockHash()).empty());
        // A delayed response cannot revive records for the connected parent.
        m_node.avalanche->finalizeMempoolBatch(peerBatchId);
        BOOST_CHECK(m_node.avalanche->getFinalizedMempoolBatches(
            chaintip->GetBlockHash()).empty());
    }

    // Real consensus connect of an older finalized set. The valid child is
    // finalized in a later superset but is not mined; it must remain in the
    // mempool and become eligible for the new parent's batches.
    {
        CBlockIndex *parentTip = WITH_LOCK(cs_main, return chainman.ActiveTip());
        const CScript script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        const CMutableTransaction parentTx = CreateValidMempoolTransaction(
            m_coinbase_txns[0], 0, 1, coinbaseKey, script,
            m_coinbase_txns[0]->vout[0].nValue, false);
        const auto parentRef = MakeTransactionRef(parentTx);
        const CMutableTransaction childTx = CreateValidMempoolTransaction(
            parentRef, 0, parentTip->nHeight + 1, coinbaseKey, script,
            parentTx.vout[0].nValue, false);
        const auto childRef = MakeTransactionRef(childTx);
        CBlock olderBlock = CreateBlock({parentTx}, CScript() << OP_TRUE, active_chainstate);
        {
            LOCK2(cs_main, m_node.mempool->cs);
            TestMemPoolEntryHelper entry;
            m_node.mempool->ConnectBlockReset(parentTip->GetBlockHash(),
                parentTip->nHeight + 1, parentTip->GetMedianTimePast());
            m_node.mempool->addUnchecked(entry.Fee(Amount::zero()).FromTx(parentRef));
            m_node.mempool->addUnchecked(entry.Fee(Amount::zero()).FromTx(childRef));
        }
        MempoolBatchAnnouncement small = peerBatch;
        small.prev_block_hash = parentTip->GetBlockHash();
        small.epoch_seq = 1;
        small.tx_count = 1;
        small.subtree_a_root = ComputeV2SubtreeARoot({parentRef});
        MempoolBatchAnnouncement large = small;
        large.epoch_seq = 2;
        large.tx_count = 2;
        large.subtree_a_root = ComputeV2SubtreeARoot({parentRef, childRef});
        BOOST_REQUIRE(m_node.avalanche->registerMempoolBatch(small, true));
        m_node.avalanche->finalizeMempoolBatch(small.ComputeBatchId());
        BOOST_REQUIRE(m_node.avalanche->registerMempoolBatch(large, true));
        m_node.avalanche->finalizeMempoolBatch(large.ComputeBatchId());
        BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(olderBlock),
            true, true, nullptr, m_node.avalanche.get()));
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()),
                          olderBlock.GetHash());
        {
            LOCK(m_node.mempool->cs);
            BOOST_CHECK(!m_node.mempool->exists(parentRef->GetId()));
            BOOST_CHECK(m_node.mempool->exists(childRef->GetId()));
        }
        AvalancheTest::updatedBlockTip(*m_node.avalanche);
        BOOST_CHECK(m_node.avalanche->getFinalizedMempoolBatches(
            parentTip->GetBlockHash()).empty());
        MempoolBatchAnnouncement next = small;
        next.prev_block_hash = olderBlock.GetHash();
        next.subtree_a_root = ComputeV2SubtreeARoot({childRef});
        BOOST_REQUIRE(m_node.avalanche->registerMempoolBatch(next, true));
        m_node.avalanche->finalizeMempoolBatch(next.ComputeBatchId());
        BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(next.ComputeBatchId()));
    }

    gArgs.ClearForcedArg("-avalanchepreconsensus");
}

BOOST_FIXTURE_TEST_CASE(batch_default_requires_normal_finalization_score,
                        AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    auto proof = buildRandomProof(active_chainstate, MIN_VALID_PROOF_SCORE);
    const ProofId &proofid = proof->getId();
    BOOST_CHECK(
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            return pm.registerProof(proof);
        }));

    std::array<CNode *, 8> nodes;
    for (size_t i = 0; i < nodes.size(); ++i) {
        CAddress addr;
        auto node =
            new CNode(static_cast<NodeId>(i + 100), /*sock=*/nullptr, addr, 0,
                      0, 0, CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY,
                      false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = 1;
        node->fSuccessfullyConnected = true;
        m_connman->AddTestNode(*node);
        m_node.avalanche->setNodeMempoolBatchServices(node->GetId(), NODE_MERKLIX_EPOCH);
        nodes[i] = node;
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            BOOST_CHECK(pm.addNode(node->GetId(), proofid,
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        });
    }
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());

    CMutableTransaction mtx1;
    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = COutPoint(TxId(GetRandHash()), 0);
    mtx1.vin[0].scriptSig = CScript() << OP_1;
    mtx1.vout.emplace_back(10 * COIN, CScript() << OP_TRUE);
    CTransactionRef tx1 = MakeTransactionRef(std::move(mtx1));

    CMutableTransaction mtx2;
    mtx2.nVersion = 2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout = COutPoint(TxId(GetRandHash()), 1);
    mtx2.vin[0].scriptSig = CScript() << OP_2;
    mtx2.vout.emplace_back(20 * COIN, CScript() << OP_TRUE);
    CTransactionRef tx2 = MakeTransactionRef(std::move(mtx2));

    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->clear();
        m_node.mempool->ConnectBlockReset(
            chaintip->GetBlockHash(), uint64_t(chaintip->nHeight + 1),
            uint64_t(chaintip->GetMedianTimePast()));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx2));
    }

    bool callbackInvoked = false;
    MempoolBatchAnnouncement callbackBatch;
    m_node.avalanche->registerBatchFinalizedCallback(
        [&](const MempoolBatchAnnouncement &b) {
            callbackInvoked = true;
            callbackBatch = b;
        });

    MempoolBatchAnnouncement batch;
    batch.prev_block_hash = chaintip->GetBlockHash();
    batch.epoch_seq = 1;
    batch.parent_batch_id = uint256::ZERO;
    batch.subtree_a_root = ComputeV2SubtreeARoot({tx1, tx2});
    batch.utxo_root = GetRandHash();
    batch.tx_count = 2;
    batch.short_ids_hash = GetRandHash();
    const uint256 batchId = batch.ComputeBatchId();

    BOOST_CHECK(
        m_node.avalanche->registerMempoolBatch(batch, /*locallyAccepted=*/true));
    BOOST_CHECK(!m_node.avalanche->hasMempoolBatchConflict(batchId));

    // One successful sample is not finality. Polling distinct peers must
    // accumulate the ordinary Avalanche finalization score before freezing.
    BOOST_CHECK_EQUAL(m_node.avalanche->getFastPathConfidenceThreshold(),
                      AVALANCHE_FINALIZATION_SCORE);
    int votesCast = 0;
    for (size_t i = 0;
         i < nodes.size() && !m_node.avalanche->isMempoolBatchFinalized(batchId);
         ++i) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        std::vector<Vote> votes;
        for (const auto &polledInv : polledInvs) {
            votes.emplace_back(0, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp,
                                                    updates, disconnect,
                                                    error));
        ++votesCast;
    }

    BOOST_CHECK_GE(votesCast, 7);
    BOOST_CHECK(!m_node.avalanche->isMempoolBatchFinalized(batchId));
    BOOST_CHECK(!callbackInvoked);
    BOOST_CHECK_EQUAL(
        m_node.avalanche->getAdaptiveEpochController()
            .getFastPathFinalizedCount(), 0U);
    for (int i = votesCast; i < 1024 &&
         !m_node.avalanche->isMempoolBatchFinalized(batchId); ++i) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        const auto invs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        std::vector<Vote> votes;
        for (const auto &inv : invs) votes.emplace_back(0, inv.hash);
        Response response(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_REQUIRE(m_node.avalanche->registerVotes(
            AvalancheTest::getPolledNode(*m_node.avalanche, round), response,
            updates, disconnect, error));
        ++votesCast;
    }
    BOOST_CHECK_GE(votesCast, AVALANCHE_FINALIZATION_SCORE);
    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(batchId));
    BOOST_CHECK(callbackInvoked);
    BOOST_CHECK(callbackBatch == batch);
    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK_EQUAL(
            m_node.mempool->GetOverlayManager().GetFrozenEpochs().size(), 1U);
    }
}

BOOST_FIXTURE_TEST_CASE(mysticeti_contention_fallback_to_metastable_snowball,
                        AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    auto proof = buildRandomProof(active_chainstate, MIN_VALID_PROOF_SCORE);
    const ProofId &proofid = proof->getId();
    BOOST_CHECK(
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            return pm.registerProof(proof);
        }));

    std::array<CNode *, 8> nodes;
    for (size_t i = 0; i < nodes.size(); ++i) {
        CAddress addr;
        auto node =
            new CNode(static_cast<NodeId>(i + 200), /*sock=*/nullptr, addr, 0,
                      0, 0, CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY,
                      false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = 1;
        node->fSuccessfullyConnected = true;
        m_connman->AddTestNode(*node);
        m_node.avalanche->setNodeMempoolBatchServices(node->GetId(), NODE_MERKLIX_EPOCH);
        nodes[i] = node;
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            BOOST_CHECK(pm.addNode(node->GetId(), proofid,
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        });
    }
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());

    // Case A: Two competing batches announced for the same (prev_block_hash,
    // epoch_seq = 1) must disable the 1-RTT fast path and require the full
    // metastable Snowball to finalize.
    MempoolBatchAnnouncement batchA;
    batchA.prev_block_hash = chaintip->GetBlockHash();
    batchA.epoch_seq = 1;
    batchA.parent_batch_id = uint256::ZERO;
    batchA.subtree_a_root = GetRandHash();
    batchA.utxo_root = GetRandHash();
    batchA.tx_count = 4;
    batchA.short_ids_hash = GetRandHash();
    const uint256 batchAId = batchA.ComputeBatchId();

    MempoolBatchAnnouncement batchB = batchA;
    batchB.subtree_a_root = GetRandHash();
    const uint256 batchBId = batchB.ComputeBatchId();
    BOOST_REQUIRE(batchAId != batchBId);

    BOOST_CHECK(m_node.avalanche->registerMempoolBatch(
        batchA, /*locallyAccepted=*/true));
    BOOST_CHECK(!m_node.avalanche->hasMempoolBatchConflict(batchAId));

    // Announcing competing batchB at the same (prev_block_hash, epoch_seq = 1)
    // immediately marks the epoch as conflicted.
    BOOST_CHECK(m_node.avalanche->registerMempoolBatch(
        batchB, /*locallyAccepted=*/false));
    BOOST_CHECK(m_node.avalanche->hasEpochConflict(chaintip->GetBlockHash(), 1));
    BOOST_CHECK(m_node.avalanche->hasMempoolBatchConflict(batchAId));
    BOOST_CHECK(m_node.avalanche->hasMempoolBatchConflict(batchBId));

    // After 7 unanimous 0 votes on batchA (confidence == 1), the 1-RTT fast
    // path must NOT finalize batchA because the epoch has contention.
    size_t nextNodeIdx = 0;
    int totalVotesA = 0;
    for (int i = 0; i < 7; ++i) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        const NodeId nodeid = nodes[nextNodeIdx++ % nodes.size()]->GetId();
        std::vector<Vote> votes;
        for (const auto &polledInv : polledInvs) {
            const uint32_t err = (polledInv.hash == batchAId) ? 0 : 1;
            votes.emplace_back(err, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp, updates,
                                                    disconnect, error));
        ++totalVotesA;
    }

    BOOST_CHECK(!m_node.avalanche->isMempoolBatchFinalized(batchAId));
    BOOST_CHECK_EQUAL(
        m_node.avalanche->getConfidence(MempoolBatchVoteItem(batchA)), 1);

    // Continue voting through the full metastable Snowball until finalized.
    for (int roundIdx = 0;
         roundIdx < 200 && !m_node.avalanche->isMempoolBatchFinalized(batchAId);
         ++roundIdx) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        const NodeId nodeid = nodes[nextNodeIdx++ % nodes.size()]->GetId();
        std::vector<Vote> votes;
        for (const auto &polledInv : polledInvs) {
            const uint32_t err = (polledInv.hash == batchAId) ? 0 : 1;
            votes.emplace_back(err, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp, updates,
                                                    disconnect, error));
        ++totalVotesA;
    }
    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(batchAId));
    BOOST_CHECK_GE(totalVotesA, int(AVALANCHE_FINALIZATION_SCORE));

    // Case B: Single batch announced at epoch_seq = 2, but a peer responds with
    // a non-zero error code in round 1 -> disables 1-RTT fast path for epoch 2.
    MempoolBatchAnnouncement batchC;
    batchC.prev_block_hash = chaintip->GetBlockHash();
    batchC.epoch_seq = 2;
    batchC.parent_batch_id = batchAId;
    batchC.subtree_a_root = GetRandHash();
    batchC.utxo_root = GetRandHash();
    batchC.tx_count = 8;
    batchC.short_ids_hash = GetRandHash();
    const uint256 batchCId = batchC.ComputeBatchId();

    BOOST_CHECK(m_node.avalanche->registerMempoolBatch(
        batchC, /*locallyAccepted=*/true));
    BOOST_CHECK(!m_node.avalanche->hasMempoolBatchConflict(batchCId));

    // First vote is non-zero (missing txs / inconclusive error = 1)
    {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        const NodeId nodeid = nodes[nextNodeIdx++ % nodes.size()]->GetId();
        std::vector<Vote> votes;
        for (const auto &polledInv : polledInvs) {
            votes.emplace_back(1, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp, updates,
                                                    disconnect, error));
    }
    BOOST_CHECK(m_node.avalanche->hasMempoolBatchConflict(batchCId));
    BOOST_CHECK(m_node.avalanche->hasEpochConflict(chaintip->GetBlockHash(), 2));

    // Next 7 votes are unanimous 0 -> confidence reaches 1, but fast-path must
    // remain disabled.
    for (int i = 0; i < 7; ++i) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        const NodeId nodeid = nodes[nextNodeIdx++ % nodes.size()]->GetId();
        std::vector<Vote> votes;
        for (const auto &polledInv : polledInvs) {
            votes.emplace_back(0, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp, updates,
                                                    disconnect, error));
    }
    BOOST_CHECK(!m_node.avalanche->isMempoolBatchFinalized(batchCId));
    BOOST_CHECK_EQUAL(
        m_node.avalanche->getConfidence(MempoolBatchVoteItem(batchC)), 1);
}

BOOST_FIXTURE_TEST_CASE(
    adaptive_epoch_controller_aimd_and_back_to_back_pipelining,
    AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    // 1. Verify AIMD settling window dynamics coupled to live peer RTT telemetry
    auto &ctrl = m_node.avalanche->getAdaptiveEpochController();
    ctrl.recordPollRtt(std::chrono::milliseconds(20));
    BOOST_CHECK_CLOSE(ctrl.getRttEwmaMs(), 20.0, 1e-3);
    BOOST_CHECK_CLOSE(ctrl.getSettlingWindowMs(), 20.0, 1e-3);

    // Simulated miss/conflict events multiplicatively back off tau_settle (2x)
    ctrl.recordMissOrConflict();
    BOOST_CHECK_CLOSE(ctrl.getSettlingWindowMs(), 40.0, 1e-3);
    BOOST_CHECK_GT(ctrl.getMissRateEwma(), 0.0);

    ctrl.recordMissOrConflict();
    BOOST_CHECK_CLOSE(ctrl.getSettlingWindowMs(), 80.0, 1e-3);

    // Clean 1-RTT fast-path finalizations additively shrink tau_settle back
    // toward the observed peer RTT EWMA (20ms).
    double prevWindow = ctrl.getSettlingWindowMs();
    for (int i = 0; i < 20; ++i) {
        ctrl.recordCleanFastPath();
        const double curWindow = ctrl.getSettlingWindowMs();
        BOOST_CHECK_LE(curWindow, prevWindow);
        BOOST_CHECK_GE(curWindow, ctrl.getRttEwmaMs());
        prevWindow = curWindow;
    }
    BOOST_CHECK_CLOSE(ctrl.getSettlingWindowMs(), ctrl.getRttEwmaMs(), 1.0);

    // 2. Verify event-driven back-to-back epoch batch pipelining upon finality
    auto proof = buildRandomProof(active_chainstate, MIN_VALID_PROOF_SCORE);
    const ProofId &proofid = proof->getId();
    BOOST_CHECK(
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            return pm.registerProof(proof);
        }));

    std::array<CNode *, 8> nodes;
    for (size_t i = 0; i < nodes.size(); ++i) {
        CAddress addr;
        auto node =
            new CNode(static_cast<NodeId>(i + 300), /*sock=*/nullptr, addr, 0,
                      0, 0, CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY,
                      false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = 1;
        node->fSuccessfullyConnected = true;
        m_connman->AddTestNode(*node);
        m_node.avalanche->setNodeMempoolBatchServices(node->GetId(), NODE_MERKLIX_EPOCH);
        nodes[i] = node;
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            BOOST_CHECK(pm.addNode(node->GetId(), proofid,
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        });
    }
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());

    auto makeDummyTx = [](int idx, Amount val) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(TxId(GetRandHash()), idx);
        mtx.vin[0].scriptSig = CScript() << int64_t(idx);
        mtx.vout.emplace_back(val, CScript() << OP_TRUE);
        return MakeTransactionRef(std::move(mtx));
    };

    CTransactionRef tx1 = makeDummyTx(1, 10 * COIN);
    CTransactionRef tx2 = makeDummyTx(2, 20 * COIN);
    CTransactionRef tx3 = makeDummyTx(3, 30 * COIN);
    CTransactionRef tx4 = makeDummyTx(4, 40 * COIN);

    ctrl.setMinBatchTxCount(2);
    ctrl.setAutoPipelineEnabled(true);

    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->clear();
        m_node.mempool->ConnectBlockReset(
            chaintip->GetBlockHash(), uint64_t(chaintip->nHeight + 1),
            uint64_t(chaintip->GetMedianTimePast()));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx2));
    }

    // Freeze and register Epoch 1 batch ({tx1, tx2})
    MempoolBatchAnnouncement batch1;
    BOOST_REQUIRE(m_node.avalanche->tryFreezeAndRegisterNextEpochBatch(
        chaintip->GetBlockHash(), &batch1));
    const uint256 batch1Id = batch1.ComputeBatchId();
    BOOST_CHECK_EQUAL(batch1.epoch_seq, 1U);
    BOOST_CHECK_EQUAL(batch1.parent_batch_id, uint256::ZERO);
    BOOST_CHECK_EQUAL(batch1.tx_count, 2U);
    BOOST_CHECK_EQUAL(batch1.subtree_a_root, ComputeV2SubtreeARoot({tx1, tx2}));

    // While Epoch 1 is in flight, add {tx3, tx4} to the speculative mempool tail
    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx3));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx4));
        BOOST_CHECK_EQUAL(
            m_node.mempool->GetOverlayManager().GetFrozenEpochs().size(), 1U);
    }

    // Finalize Epoch 1 at the normal score -> must automatically freeze
    // {tx1, tx2, tx3, tx4} into FrozenEpoch 2 and register Delta_2 for polling!
    size_t nextNodeIdx = 0;
    for (int i = 0;
         i < 2000 && !m_node.avalanche->isMempoolBatchFinalized(batch1Id); ++i) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        const NodeId nodeid = nodes[nextNodeIdx++ % nodes.size()]->GetId();
        std::vector<Vote> votes;
        for (const auto &polledInv : polledInvs) {
            votes.emplace_back(0, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp, updates,
                                                    disconnect, error));
    }

    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(batch1Id));
    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK_EQUAL(
            m_node.mempool->GetOverlayManager().GetFrozenEpochs().size(), 2U);
    }

    // Verify Delta_2 is immediately present in the next poll invs with
    // epoch_seq = 2 and parent_batch_id = batch1Id!
    auto nextPollInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
    uint256 batch2Id = uint256::ZERO;
    for (const auto &inv : nextPollInvs) {
        if (inv.IsMsgMempoolBatch() && inv.hash != batch1Id) {
            batch2Id = inv.hash;
            break;
        }
    }
    BOOST_REQUIRE(!batch2Id.IsNull());

    MempoolBatchAnnouncement batch2;
    BOOST_REQUIRE(m_node.avalanche->getMempoolBatch(batch2Id, batch2));
    BOOST_CHECK_EQUAL(batch2.epoch_seq, 2U);
    BOOST_CHECK_EQUAL(batch2.parent_batch_id, batch1Id);
    BOOST_CHECK_EQUAL(batch2.tx_count, 4U);
    BOOST_CHECK_EQUAL(batch2.subtree_a_root,
                      ComputeV2SubtreeARoot({tx1, tx2, tx3, tx4}));

    // Finalize Delta_2 at the normal score as well
    for (int i = 0;
         i < 2000 && !m_node.avalanche->isMempoolBatchFinalized(batch2Id); ++i) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        auto polledInvs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        const NodeId nodeid = nodes[nextNodeIdx++ % nodes.size()]->GetId();
        std::vector<Vote> votes;
        for (const auto &polledInv : polledInvs) {
            votes.emplace_back(0, polledInv.hash);
        }
        Response resp(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_CHECK(m_node.avalanche->registerVotes(AvalancheTest::getPolledNode(*m_node.avalanche, resp.getRound()), resp, updates,
                                                    disconnect, error));
    }
    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(batch2Id));

    const auto finalizedChain =
        m_node.avalanche->getFinalizedMempoolBatches(chaintip->GetBlockHash());
    BOOST_REQUIRE_EQUAL(finalizedChain.size(), 2U);
    BOOST_CHECK(finalizedChain[0] == batch1);
    BOOST_CHECK(finalizedChain[1] == batch2);
}

BOOST_AUTO_TEST_SUITE_END()
