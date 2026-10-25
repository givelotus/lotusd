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
#include <blockencodings.h>
#include <net/v2_protocol_handler.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/chainstatemanager_args.h>
#include <node/miner.h>
#include <node/snapshot.h>
#include <policy/block/parkingpolicy.h>
#include <policy/block/preconsensus.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <rpc/server.h>
#include <script/script.h>
#include <streams.h>
#include <univalue.h>
#include <validation.h>
#include <validationinterface.h>
#include <future>
#include <numeric>

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
                                        false, /*include_mempool_batches=*/true);
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

BOOST_FIXTURE_TEST_CASE(avaresponse_cross_peer_ready_turn,
                        AvalancheTestingSetup) {
    std::vector<CNode *> nodes;
    std::vector<CKey> keys;
    for (int i = 0; i < 7; ++i) {
        keys.push_back(CKey::MakeCompressedKey());
        auto *node = new CNode(950 + i, nullptr, CAddress(), 0, 0, 0,
                              CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY,
                              false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = PROTOCOL_VERSION;
        node->fSuccessfullyConnected = true;
        node->m_avalanche_enabled = true;
        WITH_LOCK(node->cs_avalanche_pubkey,
                  node->m_avalanche_pubkey = keys.back().GetPubKey());
        m_connman->AddTestNode(*node);
        Response response(i, 0, {});
        HashWriter hash;
        hash << response;
        SchnorrSig signature;
        BOOST_REQUIRE(keys.back().SignSchnorr(hash.GetHash(), signature));
        if (i == 1) signature[32] ^= 1;
        auto message = NetMsg::Make(NetMsgType::AVARESPONSE, response, signature);
        if (i == 5) message.data.resize(1);
        BOOST_REQUIRE(m_connman->ReceiveMsgFrom(*node, message));
        node->fPauseSend = false;
        nodes.push_back(node);
    }
    // Wrong-type and over-budget peeks must leave the head untouched.
    BOOST_CHECK(!nodes[0]->CopyIsolatedMessage(NetMsgType::PING, 65536));
    BOOST_CHECK(!nodes[0]->CopyIsolatedMessage(NetMsgType::AVARESPONSE, 1));
    std::atomic<bool> interrupt{false};
    LOCK(NetEventsInterface::g_msgproc_mutex);
    m_node.peerman->PrepareMessageTurn(nodes, interrupt);
    // A pre-pass must not consume votes or dequeue responses.
    for (auto *node : nodes) {
        BOOST_CHECK_EQUAL(node->m_avalanche_message_fault_counter, 0);
    }
    // Key changes between preverification and ordered consumption invalidate
    // the token; an earlier valid signature must never authorize a new key.
    WITH_LOCK(nodes[2]->cs_avalanche_pubkey,
              nodes[2]->m_avalanche_pubkey = keys[0].GetPubKey());
    nodes[3]->fDisconnect = true;
    for (auto *node : nodes) {
        m_node.peerman->ProcessMessages(config, node, interrupt);
    }
    // Valid responses reach registerVotes (unsolicited in this fixture);
    // invalid signatures, including rotated keys, must not reach it. One bad
    // peer must not suppress a valid peer before or after it in the batch.
    BOOST_CHECK_EQUAL(nodes[0]->m_avalanche_message_fault_counter, 1);
    BOOST_CHECK_EQUAL(nodes[1]->m_avalanche_message_fault_counter, 0);
    BOOST_CHECK_EQUAL(nodes[2]->m_avalanche_message_fault_counter, 0);
    BOOST_CHECK_EQUAL(nodes[3]->m_avalanche_message_fault_counter, 0);
    BOOST_CHECK_EQUAL(nodes[4]->m_avalanche_message_fault_counter, 1);
    BOOST_CHECK_EQUAL(nodes[5]->m_avalanche_message_fault_counter, 0);
    BOOST_CHECK_EQUAL(nodes[6]->m_avalanche_message_fault_counter, 1);
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

    // 2. Verify the native tagged BLAKE3 identifier and field sensitivity
    const uint256 idOrig = batch.ComputeBatchId();
    BOOST_CHECK(!idOrig.IsNull());
    // Independent Python blake3 vector over domain || NUL || 168-byte LE serialization.
    BOOST_CHECK_EQUAL(idOrig.GetHex(),
        "cf456a4b7889237c3adace3e092fa4186c2c8c00642735c13eb8d80c7d977d46");

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
        // The logger thread runs the callbacks: deliver queued lines first.
        LogInstance().Flush();
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
        // The logger thread runs the callbacks: deliver queued lines first.
        LogInstance().Flush();
        BOOST_CHECK_EQUAL(unparks, 1);
        WITH_LOCK(cs_main, BOOST_CHECK(!parkedIndex->m_preconsensus_policy_parked));
        BlockValidationState state;
        BOOST_REQUIRE(active_chainstate.ActivateBestChain(state, nullptr,
                                                          m_node.avalanche.get()));
        // The logger thread runs the callbacks: deliver queued lines first.
        LogInstance().Flush();
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

// ============================================================================
// 1. Two-Stage Snowball-Union (1. mempool -> 2. snowballed) with Stateful
//    Confidence + Consecutive Streak & Mixed Staking + Non-Staking Network
//    (2. snowballed -> 3. finalized)
// ============================================================================
BOOST_FIXTURE_TEST_CASE(
    snowball_union_two_stage_and_mixed_staking_nonstaking_lifecycle,
    AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    const BlockHash tipHash = chaintip->GetBlockHash();

    auto rpc = [&](const std::string &method, UniValue params = UniValue(UniValue::VARR)) {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = method;
        request.params = std::move(params);
        return tableRPC.execute(GlobalConfig{}, request);
    };

    auto makeTx = [](int idx, Amount val) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(TxId(GetRandHash()), idx);
        mtx.vin[0].scriptSig = CScript() << int64_t(idx);
        mtx.vout.emplace_back(val, CScript() << OP_TRUE);
        return MakeTransactionRef(std::move(mtx));
    };

    CTransactionRef tx1 = makeTx(1, 10 * COIN);
    CTransactionRef tx2 = makeTx(2, 20 * COIN);
    CTransactionRef tx3 = makeTx(3, 30 * COIN);
    CTransactionRef tx4 = makeTx(4, 40 * COIN);
    CTransactionRef tx5 = makeTx(5, 50 * COIN);

    // Create 3 additional peer mempools (2 staking peers + 1 non-staking peer)
    // to model a mixed network where each node starts with a partial subset:
    //   m_node.mempool (staking node 0): {tx1, tx2}
    //   peerPool1      (staking node 1): {tx2, tx3}
    //   peerPool2      (staking node 2): {tx3, tx4}
    //   nonStakingPool (non-staking 3):  {tx4, tx1}
    CTxMemPool peerPool1(config, CTxMemPool::Options{});
    CTxMemPool peerPool2(config, CTxMemPool::Options{});
    CTxMemPool nonStakingPool(config, CTxMemPool::Options{});

    auto initPoolWithTxs = [&](CTxMemPool &pool,
                               std::initializer_list<CTransactionRef> txs) {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, pool.cs);
        pool.clear();
        pool.ConnectBlockReset(tipHash, uint64_t(chaintip->nHeight + 1),
                               uint64_t(chaintip->GetMedianTimePast()));
        for (const auto &tx : txs) {
            pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
        }
    };

    initPoolWithTxs(*m_node.mempool, {tx1, tx2});
    initPoolWithTxs(peerPool1, {tx2, tx3});
    initPoolWithTxs(peerPool2, {tx3, tx4});
    initPoolWithTxs(nonStakingPool, {tx4, tx1});

    {
        LOCK(::cs_main);
        node::PublishChainTipSnapshot(chainman, m_node.mempool.get());
    }

    // Stage 0 check: all transactions in m_node.mempool start in state "mempool"
    for (const auto &tx : {tx1, tx2}) {
        UniValue p(UniValue::VARR);
        p.push_back(tx->GetId().ToString());
        const auto entryJson = rpc("getmempoolentry", std::move(p));
        BOOST_CHECK_EQUAL(entryJson["preconsensus_state"].get_str(), "mempool");
        BOOST_CHECK_EQUAL(entryJson["epoch_seq"].getInt<int>(), 0);

        UniValue rawP(UniValue::VARR);
        rawP.push_back(tx->GetId().ToString());
        rawP.push_back(true);
        const auto rawJson = rpc("getrawtransaction", std::move(rawP));
        BOOST_CHECK_EQUAL(rawJson["preconsensus_state"].get_str(), "mempool");
    }

    // Verify stateful Snowball root confidence is preserved across root changes:
    // Record 2 unchanged rounds on initial root R_init ({tx1, tx2}), then union
    // {tx3, tx4} to transition to R_full ({tx1, tx2, tx3, tx4}).
    const uint256 rootInit = ComputeV2SubtreeARoot({tx1, tx2});
    const uint256 rootFull = ComputeV2SubtreeARoot({tx1, tx2, tx3, tx4});
    constexpr uint32_t kBeta = 4;

    BOOST_CHECK(!m_node.avalanche->stepEpochSnowballReconciliation(
        tipHash, 1, /*changed_by_union=*/false, kBeta));
    BOOST_CHECK_EQUAL(
        m_node.avalanche->getEpochSnowballConfidence(tipHash, 1, rootInit), 1U);
    BOOST_CHECK_EQUAL(
        m_node.avalanche->getEpochSnowballConsecutiveRounds(tipHash, 1), 1U);

    BOOST_CHECK(!m_node.avalanche->stepEpochSnowballReconciliation(
        tipHash, 1, /*changed_by_union=*/false, kBeta));
    BOOST_CHECK_EQUAL(
        m_node.avalanche->getEpochSnowballConfidence(tipHash, 1, rootInit), 2U);
    BOOST_CHECK_EQUAL(
        m_node.avalanche->getEpochSnowballConsecutiveRounds(tipHash, 1), 2U);

    // Stage 1: Snowball-Union synchronization across all 4 nodes (staking and
    // non-staking) WITHOUT any voting messages!
    std::vector<CTxMemPool *> peerPools = {&peerPool1, &peerPool2,
                                           &nonStakingPool};
    bool crystallized = false;
    for (int r = 0; r < 10 && !crystallized; ++r) {
        // Also let peer pools reconcile with each other so the entire network
        // converges to the union {tx1, tx2, tx3, tx4}.
        {
            std::vector<std::tuple<CTransactionRef, int64_t, int64_t>> p1Txs;
            {
                LOCK(peerPool1.cs);
                p1Txs = peerPool1.GetActiveEpochTransactionsWithMetadata();
            }
            for (CTxMemPool *other : {&peerPool2, &nonStakingPool}) {
                LOCK(other->cs);
                for (const auto &[ptx, fee, sig] : p1Txs) {
                    other->UnionTransactionIntoActiveEpoch(ptx, fee, sig, 2, 3);
                }
            }
        }
        crystallized = m_node.avalanche->reconcileEpochWithPeerMempools(
            tipHash, peerPools, kBeta);

        // Stateful confidence on rootInit must never be zeroed out even after
        // the active root moved to rootFull!
        BOOST_CHECK_EQUAL(
            m_node.avalanche->getEpochSnowballConfidence(tipHash, 1, rootInit),
            2U);
    }

    BOOST_REQUIRE(crystallized);
    BOOST_CHECK(m_node.avalanche->isEpochSnowballed(tipHash, 1));
    BOOST_CHECK_GE(
        m_node.avalanche->getEpochSnowballConfidence(tipHash, 1, rootFull),
        kBeta);
    BOOST_CHECK_GE(
        m_node.avalanche->getEpochSnowballConsecutiveRounds(tipHash, 1),
        kBeta);

    // Non-staking node also crystallizes Epoch 1 via Snowball-Union
    {
        LOCK(nonStakingPool.cs);
        BOOST_REQUIRE_EQUAL(nonStakingPool.FreezeEpochBatch().GetLayerId(), 1U);
        BOOST_CHECK_EQUAL(nonStakingPool.MarkEpochSnowballed(1), 4U);
    }

    // Verify all 4 transactions on m_node.mempool are now in state "snowballed"
    // with epoch_seq == 1!
    for (const auto &tx : {tx1, tx2, tx3, tx4}) {
        UniValue p(UniValue::VARR);
        p.push_back(tx->GetId().ToString());
        const auto entryJson = rpc("getmempoolentry", std::move(p));
        BOOST_CHECK_EQUAL(entryJson["preconsensus_state"].get_str(),
                          "snowballed");
        BOOST_CHECK_EQUAL(entryJson["epoch_seq"].getInt<int>(), 1);

        UniValue rawP(UniValue::VARR);
        rawP.push_back(tx->GetId().ToString());
        rawP.push_back(true);
        const auto rawJson = rpc("getrawtransaction", std::move(rawP));
        BOOST_CHECK_EQUAL(rawJson["preconsensus_state"].get_str(),
                          "snowballed");
    }
    {
        const auto infoJson = rpc("getmempoolinfo");
        BOOST_CHECK_EQUAL(infoJson["snowballed_epochs"].getInt<int>(), 1);
        BOOST_CHECK_EQUAL(infoJson["snowballed_txs"].getInt<int>(), 4);
        BOOST_CHECK_EQUAL(infoJson["finalized_epochs"].getInt<int>(), 0);
        BOOST_CHECK_EQUAL(infoJson["finalized_txs"].getInt<int>(), 0);
    }

    // Verify Snowballed Lock: a late double-spend arriving after Epoch 1 is
    // snowballed cannot displace tx1 and returns REJECTED_EPOCH_LOCKED!
    {
        CMutableTransaction lateDoubleSpend(*tx1);
        lateDoubleSpend.vout[0].nValue = 9 * COIN;
        CTransactionRef lateDsRef =
            MakeTransactionRef(std::move(lateDoubleSpend));
        LOCK(m_node.mempool->cs);
        const auto outcome = m_node.mempool->UnionTransactionIntoActiveEpoch(
            lateDsRef, 5000, 1, 4, 4);
        BOOST_CHECK(outcome ==
                    lotus::v2::EpochUnionOutcome::REJECTED_EPOCH_LOCKED);
        BOOST_CHECK(m_node.mempool->exists(tx1->GetId()));
        BOOST_CHECK(!m_node.mempool->exists(lateDsRef->GetId()));
    }

    // Stage 2: Staking nodes vote on BatchId(1); non-staking nodes obey!
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
            new CNode(static_cast<NodeId>(i + 400), /*sock=*/nullptr, addr, 0,
                      0, 0, CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY,
                      false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = 1;
        node->fSuccessfullyConnected = true;
        m_connman->AddTestNode(*node);
        m_node.avalanche->setNodeMempoolBatchServices(node->GetId(),
                                                      NODE_MERKLIX_EPOCH);
        nodes[i] = node;
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            BOOST_CHECK(pm.addNode(node->GetId(), proofid,
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        });
    }
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());
    BOOST_CHECK(m_node.avalanche->hasBatchPollPeers());
    BOOST_CHECK_NE(m_node.avalanche->selectBatchPollPeer(), NO_NODE);

    // Retrieve the BatchId(1) registered when Epoch 1 snowballed
    auto invs = AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
    uint256 batch1Id = uint256::ZERO;
    for (const auto &inv : invs) {
        if (inv.IsMsgMempoolBatch()) {
            batch1Id = inv.hash;
            break;
        }
    }
    BOOST_REQUIRE(!batch1Id.IsNull());
    MempoolBatchAnnouncement batch1;
    BOOST_REQUIRE(m_node.avalanche->getMempoolBatch(batch1Id, batch1));
    BOOST_CHECK_EQUAL(batch1.epoch_seq, 1U);
    BOOST_CHECK_EQUAL(batch1.tx_count, 4U);
    BOOST_CHECK_EQUAL(batch1.subtree_a_root, rootFull);

    // Vote yes on BatchId(1) across staking quorum until finalized
    for (int i = 0;
         i < 2000 && !m_node.avalanche->isMempoolBatchFinalized(batch1Id); ++i) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        const auto polledInvs =
            AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        std::vector<Vote> votes;
        for (const auto &inv : polledInvs) {
            votes.emplace_back(0, inv.hash);
        }
        Response response(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_REQUIRE(m_node.avalanche->registerVotes(
            AvalancheTest::getPolledNode(*m_node.avalanche, round), response,
            updates, disconnect, error));
    }
    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(batch1Id));

    // Verify all 4 transactions on m_node.mempool are now in state "finalized"
    for (const auto &tx : {tx1, tx2, tx3, tx4}) {
        UniValue p(UniValue::VARR);
        p.push_back(tx->GetId().ToString());
        const auto entryJson = rpc("getmempoolentry", std::move(p));
        BOOST_CHECK_EQUAL(entryJson["preconsensus_state"].get_str(),
                          "finalized");
        BOOST_CHECK_EQUAL(entryJson["epoch_seq"].getInt<int>(), 1);
    }
    {
        const auto infoJson = rpc("getmempoolinfo");
        BOOST_CHECK_EQUAL(infoJson["finalized_epochs"].getInt<int>(), 1);
        BOOST_CHECK_EQUAL(infoJson["finalized_txs"].getInt<int>(), 4);
    }

    // Also test a late-joining non-staking node that initially had {tx1, tx2, tx5}
    // (missing {tx3, tx4} and holding extra tx5 for Epoch 2): it reconciles
    // against the staking quorum's finalized BatchId(1), adopts {tx1, tx2, tx3, tx4}
    // into FrozenEpoch 1 ("finalized"), and preserves extra tx5 in its
    // speculative layer ("mempool") for Epoch 2!
    CTxMemPool lateNonStakingPool(config, CTxMemPool::Options{});
    initPoolWithTxs(lateNonStakingPool, {tx1, tx2, tx5});
    {
        LOCK(lateNonStakingPool.cs);
        std::vector<std::tuple<CTransactionRef, int64_t, int64_t>> batchTxs = {
            {tx1, 1000, 1}, {tx2, 1000, 1}, {tx3, 1000, 1}, {tx4, 1000, 1}};
        BOOST_REQUIRE(lateNonStakingPool.ReconcileEpochBatchTransactions(
            tipHash, batch1.epoch_seq, batch1.subtree_a_root, batch1.utxo_root,
            batchTxs));
        BOOST_CHECK_EQUAL(lateNonStakingPool.MarkEpochFinalized(1), 4U);

        for (const auto &tx : {tx1, tx2, tx3, tx4}) {
            auto it = lateNonStakingPool.mapTx.find(tx->GetId());
            BOOST_REQUIRE(it != lateNonStakingPool.mapTx.end());
            BOOST_CHECK((*it)->GetPreconsensusState() ==
                        TxPreconsensusState::FINALIZED);
            BOOST_CHECK_EQUAL((*it)->GetEpochSeq(), 1U);
        }
        // Extra tx5 remains in speculative_layer_ in MEMPOOL state for Epoch 2!
        auto it5 = lateNonStakingPool.mapTx.find(tx5->GetId());
        BOOST_REQUIRE(it5 != lateNonStakingPool.mapTx.end());
        BOOST_CHECK((*it5)->GetPreconsensusState() ==
                    TxPreconsensusState::MEMPOOL);
        BOOST_CHECK_EQUAL((*it5)->GetEpochSeq(), 0U);
    }
}

// ============================================================================
// 2. Avalanche DAG Transitive Confidence Along parent_batch_id
// ============================================================================
BOOST_FIXTURE_TEST_CASE(
    avalanche_dag_transitive_confidence_along_parent_batch_id,
    AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    const BlockHash tipHash = chaintip->GetBlockHash();

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
            new CNode(static_cast<NodeId>(i + 500), /*sock=*/nullptr, addr, 0,
                      0, 0, CAddress(), "", ConnectionType::OUTBOUND_FULL_RELAY,
                      false);
        node->SetCommonVersion(PROTOCOL_VERSION);
        node->m_has_all_wanted_services = true;
        m_node.peerman->InitializeNode(config, *node, NODE_NETWORK);
        node->nVersion = 1;
        node->fSuccessfullyConnected = true;
        m_connman->AddTestNode(*node);
        m_node.avalanche->setNodeMempoolBatchServices(node->GetId(),
                                                      NODE_MERKLIX_EPOCH);
        nodes[i] = node;
        m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
            BOOST_CHECK(pm.addNode(node->GetId(), proofid,
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        });
    }
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());

    auto makeTx = [](int idx, Amount val) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(TxId(GetRandHash()), idx);
        mtx.vin[0].scriptSig = CScript() << int64_t(idx);
        mtx.vout.emplace_back(val, CScript() << OP_TRUE);
        return MakeTransactionRef(std::move(mtx));
    };

    CTransactionRef tx1 = makeTx(11, 10 * COIN);
    CTransactionRef tx2 = makeTx(12, 20 * COIN);
    CTransactionRef tx3 = makeTx(13, 30 * COIN);
    CTransactionRef tx4 = makeTx(14, 40 * COIN);

    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->clear();
        m_node.mempool->ConnectBlockReset(tipHash, uint64_t(chaintip->nHeight + 1),
                                          uint64_t(chaintip->GetMedianTimePast()));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx2));
        BOOST_REQUIRE_EQUAL(m_node.mempool->FreezeEpochBatch().GetLayerId(), 1U);
        m_node.mempool->MarkEpochSnowballed(1);

        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx3));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx4));
        BOOST_REQUIRE_EQUAL(m_node.mempool->FreezeEpochBatch().GetLayerId(), 2U);
        m_node.mempool->MarkEpochSnowballed(2);
    }

    // Register Epoch 1 (batch1) and child Epoch 2 (batch2, parent_batch_id = batch1Id)
    MempoolBatchAnnouncement batch1;
    batch1.prev_block_hash = tipHash;
    batch1.epoch_seq = 1;
    batch1.parent_batch_id = uint256::ZERO;
    batch1.subtree_a_root = ComputeV2SubtreeARoot({tx1, tx2});
    batch1.utxo_root = uint256::ZERO;
    batch1.tx_count = 2;
    batch1.short_ids_hash = GetRandHash();
    const uint256 batch1Id = batch1.ComputeBatchId();

    MempoolBatchAnnouncement batch2;
    batch2.prev_block_hash = tipHash;
    batch2.epoch_seq = 2;
    batch2.parent_batch_id = batch1Id;
    batch2.subtree_a_root = ComputeV2SubtreeARoot({tx1, tx2, tx3, tx4});
    batch2.utxo_root = uint256::ZERO;
    batch2.tx_count = 4;
    batch2.short_ids_hash = GetRandHash();
    const uint256 batch2Id = batch2.ComputeBatchId();

    BOOST_REQUIRE(m_node.avalanche->registerMempoolBatch(batch1, true));
    BOOST_REQUIRE(m_node.avalanche->registerMempoolBatch(batch2, true));

    // Only cast explicit votes on batch2Id in the response (omit batch1Id from
    // votes or vote yes on batch2Id when polled) and verify that positive votes
    // on batch2Id transitively advance confidence on ancestor batch1Id!
    for (int i = 0;
         i < 2000 && !m_node.avalanche->isMempoolBatchFinalized(batch2Id); ++i) {
        const uint64_t round = AvalancheTest::getRound(*m_node.avalanche);
        const auto polledInvs =
            AvalancheTest::getInvsForNextPoll(*m_node.avalanche);
        AvalancheTest::runEventLoop(*m_node.avalanche);
        std::vector<Vote> votes;
        for (const auto &inv : polledInvs) {
            // Even if the peer's vote on batch1 is inconclusive (-1), a yes (0)
            // vote on child batch2 transitively credits parent batch1!
            const uint32_t err = (inv.hash == batch2Id) ? 0 : uint32_t(-1);
            votes.emplace_back(err, inv.hash);
        }
        Response response(round, 0, votes);
        std::vector<VoteItemUpdate> updates;
        bool disconnect = false;
        std::string error;
        BOOST_REQUIRE(m_node.avalanche->registerVotes(
            AvalancheTest::getPolledNode(*m_node.avalanche, round), response,
            updates, disconnect, error));
    }

    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(batch2Id));
    BOOST_CHECK(m_node.avalanche->isMempoolBatchFinalized(batch1Id));

    // Both Epoch 1 ({tx1, tx2}) and Epoch 2 ({tx3, tx4}) transactions must be
    // marked FINALIZED!
    {
        LOCK(m_node.mempool->cs);
        for (const auto &tx : {tx1, tx2, tx3, tx4}) {
            auto it = m_node.mempool->mapTx.find(tx->GetId());
            BOOST_REQUIRE(it != m_node.mempool->mapTx.end());
            BOOST_CHECK((*it)->GetPreconsensusState() ==
                        TxPreconsensusState::FINALIZED);
        }
    }
}

// ============================================================================
// 3. Two-Phase Anti-Drip Poisoning Defense
// ============================================================================
BOOST_FIXTURE_TEST_CASE(two_phase_anti_drip_poisoning_defense,
                        AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    const BlockHash tipHash = chaintip->GetBlockHash();

    auto rpc = [&](const std::string &method, UniValue params = UniValue(UniValue::VARR)) {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = method;
        request.params = std::move(params);
        return tableRPC.execute(GlobalConfig{}, request);
    };

    auto makeTx = [](int idx, Amount val) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(TxId(GetRandHash()), idx);
        mtx.vin[0].scriptSig = CScript() << int64_t(idx);
        mtx.vout.emplace_back(val, CScript() << OP_TRUE);
        return MakeTransactionRef(std::move(mtx));
    };

    CTransactionRef tx1 = makeTx(21, 10 * COIN);
    CTransactionRef tx2 = makeTx(22, 20 * COIN);
    CTransactionRef tx3 = makeTx(23, 30 * COIN);
    CTransactionRef drip1 = makeTx(24, 40 * COIN);
    CTransactionRef drip2 = makeTx(25, 50 * COIN);
    CTransactionRef drip3 = makeTx(26, 60 * COIN);

    {
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->clear();
        m_node.mempool->ConnectBlockReset(tipHash, uint64_t(chaintip->nHeight + 1),
                                          uint64_t(chaintip->GetMedianTimePast()));
        m_node.mempool->GetOverlayManager().SetMaxUnrestrictedUnionRounds(3);

        // Phase 1 (rounds 1..3): unrestricted union admits transactions even
        // with single-peer support (1/4)
        BOOST_CHECK_EQUAL(
            m_node.mempool->GetOverlayManager().AdvanceUnionRound(), 1U);
        BOOST_CHECK(m_node.mempool->UnionTransactionIntoActiveEpoch(
                        tx1, 1000, 1, 1, 4) ==
                    lotus::v2::EpochUnionOutcome::ADMITTED);

        BOOST_CHECK_EQUAL(
            m_node.mempool->GetOverlayManager().AdvanceUnionRound(), 2U);
        BOOST_CHECK(m_node.mempool->UnionTransactionIntoActiveEpoch(
                        tx2, 1000, 1, 1, 4) ==
                    lotus::v2::EpochUnionOutcome::ADMITTED);

        BOOST_CHECK_EQUAL(
            m_node.mempool->GetOverlayManager().AdvanceUnionRound(), 3U);
        BOOST_CHECK(m_node.mempool->UnionTransactionIntoActiveEpoch(
                        tx3, 1000, 1, 1, 4) ==
                    lotus::v2::EpochUnionOutcome::ADMITTED);
    }

    const uint256 expectedEpoch1Root = ComputeV2SubtreeARoot({tx1, tx2, tx3});

    // Phase 2 (rounds 4..6 > R_cut = 3): adversary drips 1 new transaction per
    // round with support = 1 out of sample_size = 4 (1/4 < alpha_union = 1/2).
    // Each drip transaction MUST be deferred to Epoch E+1 so Epoch 1 root
    // remains stable and Snowball-Union converges without stalling!
    for (const auto &dripTx : {drip1, drip2, drip3}) {
        LOCK(m_node.mempool->cs);
        m_node.mempool->GetOverlayManager().AdvanceUnionRound();
        const auto outcome = m_node.mempool->UnionTransactionIntoActiveEpoch(
            dripTx, 1000, 1, /*peer_sample_support=*/1, /*peer_sample_size=*/4);
        BOOST_CHECK(outcome ==
                    lotus::v2::EpochUnionOutcome::DEFERRED_LATE_DRIP);

        // Active Epoch 1 SubtreeARoot must NOT be perturbed by late drips!
        uint256 curSubtreeA;
        std::memcpy(curSubtreeA.begin(),
                    m_node.mempool->GetOverlayManager()
                        .GetSpeculativeOverlay()
                        .GetSubtreeARoot()
                        .data(),
                    32);
        BOOST_CHECK_EQUAL(curSubtreeA, expectedEpoch1Root);
        BOOST_CHECK(!m_node.avalanche->stepEpochSnowballReconciliation(
            tipHash, 1, /*changed_by_union=*/false, /*beta=*/4));
    }

    // One more unchanged round crystallizes Epoch 1 despite the adversary's drip!
    BOOST_CHECK(m_node.avalanche->stepEpochSnowballReconciliation(
        tipHash, 1, /*changed_by_union=*/false, /*beta=*/4));
    BOOST_CHECK(m_node.avalanche->isEpochSnowballed(tipHash, 1));

    {
        const auto infoJson = rpc("getmempoolinfo");
        BOOST_CHECK_EQUAL(infoJson["late_drip_deferred_txs"].getInt<int>(), 3);
        BOOST_CHECK_EQUAL(infoJson["snowballed_epochs"].getInt<int>(), 1);
        BOOST_CHECK_EQUAL(infoJson["snowballed_txs"].getInt<int>(), 3);
    }

    // When Epoch 1 finalizes, ResolveEpochQuarantineWithBatchId promotes the
    // 3 deferred drip transactions into Epoch 2!
    const uint256 batch1Id = GetRandHash();
    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->MarkEpochFinalized(1);
        m_node.mempool->ResolveEpochQuarantineWithBatchId(batch1Id);
    }

    {
        const auto infoJson = rpc("getmempoolinfo");
        BOOST_CHECK_EQUAL(infoJson["late_drip_deferred_txs"].getInt<int>(), 0);
        BOOST_CHECK_EQUAL(infoJson["finalized_epochs"].getInt<int>(), 1);
        BOOST_CHECK_EQUAL(infoJson["finalized_txs"].getInt<int>(), 3);

        LOCK(m_node.mempool->cs);
        for (const auto &dripTx : {drip1, drip2, drip3}) {
            auto it = m_node.mempool->mapTx.find(dripTx->GetId());
            BOOST_REQUIRE(it != m_node.mempool->mapTx.end());
            BOOST_CHECK((*it)->GetPreconsensusState() ==
                        TxPreconsensusState::MEMPOOL);
            BOOST_CHECK_EQUAL((*it)->GetEpochSeq(), 0U);
            lotus::v2::Hash tid;
            std::memcpy(tid.data(), dripTx->GetId().begin(), 32);
            BOOST_CHECK(m_node.mempool->GetOverlayManager()
                            .GetSpeculativeOverlay()
                            .Contains(tid));
        }
    }
}

// ============================================================================
// 4. Option B Conflict Quarantine + BatchId(E) Resolution Across All Arrival
//    Orders (Triple Spends & Multi-Input Bridging Spends)
// ============================================================================
BOOST_FIXTURE_TEST_CASE(
    option_b_conflict_quarantine_and_batchid_resolution_all_orders,
    AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    const BlockHash tipHash = chaintip->GetBlockHash();

    auto makeTxSpending = [](std::initializer_list<COutPoint> prevouts,
                             Amount val, int salt) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        for (const auto &p : prevouts) {
            CTxIn in(p);
            in.scriptSig = CScript() << int64_t(salt);
            mtx.vin.push_back(std::move(in));
        }
        mtx.vout.emplace_back(val, CScript() << int64_t(salt) << OP_TRUE);
        return MakeTransactionRef(std::move(mtx));
    };

    const COutPoint uClean(TxId(GetRandHash()), 0);
    const COutPoint uShared(TxId(GetRandHash()), 1);
    CTransactionRef txClean = makeTxSpending({uClean}, 50 * COIN, 100);

    // Case A: Triple spends T1, T2, T3 spending the same UTXO uShared arriving
    // in all 6 permutations across 6 peer mempools.
    CTransactionRef t1 = makeTxSpending({uShared}, 10 * COIN, 1);
    CTransactionRef t2 = makeTxSpending({uShared}, 11 * COIN, 2);
    CTransactionRef t3 = makeTxSpending({uShared}, 12 * COIN, 3);
    std::array<CTransactionRef, 3> tripleTxs = {t1, t2, t3};
    std::array<size_t, 3> perm = {0, 1, 2};

    std::vector<std::unique_ptr<CTxMemPool>> pools;
    do {
        auto pool =
            std::make_unique<CTxMemPool>(config, CTxMemPool::Options{});
        LOCK2(cs_main, pool->cs);
        pool->ConnectBlockReset(tipHash, uint64_t(chaintip->nHeight + 1),
                                uint64_t(chaintip->GetMedianTimePast()));
        BOOST_CHECK(pool->UnionTransactionIntoActiveEpoch(txClean, 1000, 1) ==
                    lotus::v2::EpochUnionOutcome::ADMITTED);
        for (size_t idx : perm) {
            pool->UnionTransactionIntoActiveEpoch(tripleTxs[idx], 1000, 1);
        }
        // Every permutation must quarantine all 3 conflicting transactions and
        // leave only txClean in active Epoch 1!
        BOOST_CHECK_EQUAL(pool->GetQuarantinedConflictTxCount(), 3U);
        BOOST_CHECK_EQUAL(pool->GetOverlayManager()
                              .GetSpeculativeOverlay()
                              .GetTxCount(),
                          1U);
        uint256 subA;
        std::memcpy(subA.begin(),
                    pool->GetOverlayManager()
                        .GetSpeculativeOverlay()
                        .GetSubtreeARoot()
                        .data(),
                    32);
        BOOST_CHECK_EQUAL(subA, ComputeV2SubtreeARoot({txClean}));
        pools.push_back(std::move(pool));
    } while (std::next_permutation(perm.begin(), perm.end()));
    BOOST_REQUIRE_EQUAL(pools.size(), 6U);

    // Resolve quarantine across all 6 peers using the same finalized BatchId(1):
    // every peer must deterministically promote the exact same single winner
    // into Epoch 2 and evict the other 2 losers!
    const uint256 batch1Id = GetRandHash();
    TxId expectedWinnerId;
    for (size_t i = 0; i < pools.size(); ++i) {
        LOCK(pools[i]->cs);
        BOOST_REQUIRE_EQUAL(pools[i]->FreezeEpochBatch().GetLayerId(), 1U);
        pools[i]->MarkEpochFinalized(1);
        const auto res = pools[i]->ResolveEpochQuarantineWithBatchId(batch1Id);
        BOOST_REQUIRE_EQUAL(res.promoted_winners.size(), 1U);
        BOOST_CHECK_EQUAL(res.rejected_losers.size(), 2U);
        BOOST_CHECK_EQUAL(pools[i]->GetQuarantinedConflictTxCount(), 0U);
        BOOST_CHECK_EQUAL(pools[i]->GetQuarantineWinnersPromoted(), 1U);
        BOOST_CHECK_EQUAL(pools[i]->GetQuarantineLosersEvicted(), 2U);

        const auto winnerTx = std::static_pointer_cast<const CTransaction>(
            res.promoted_winners[0].tx_ref);
        BOOST_REQUIRE(winnerTx != nullptr);
        if (i == 0) {
            expectedWinnerId = winnerTx->GetId();
        } else {
            BOOST_CHECK_EQUAL(winnerTx->GetId(), expectedWinnerId);
        }
        BOOST_CHECK(pools[i]->exists(expectedWinnerId));
    }

    // Case B: Multi-input bridging conflict:
    //   b1 spends {u1}
    //   b2 spends {u1, u2} (bridges b1 and b3)
    //   b3 spends {u2}
    // Verify that even when b1 and b3 arrive first (disjoint) and b2 arrives
    // third, all 3 connected conflicting transactions {b1, b2, b3} are
    // quarantined out of Epoch 1, matching the arrival order where b2 arrives
    // first!
    const COutPoint u1(TxId(GetRandHash()), 10);
    const COutPoint u2(TxId(GetRandHash()), 20);
    CTransactionRef b1 = makeTxSpending({u1}, 10 * COIN, 11);
    CTransactionRef b2 = makeTxSpending({u1, u2}, 20 * COIN, 22);
    CTransactionRef b3 = makeTxSpending({u2}, 10 * COIN, 33);

    std::vector<std::array<CTransactionRef, 3>> bridgeOrders = {
        {b1, b3, b2}, // b1 and b3 admitted first, then b2 bridges them
        {b2, b1, b3}, // b2 admitted first, then b1 and b3 conflict with b2
        {b3, b2, b1},
    };
    const uint256 bridgeBatchId = GetRandHash();
    std::vector<TxId> canonicalWinners;

    for (size_t idx = 0; idx < bridgeOrders.size(); ++idx) {
        CTxMemPool pool(config, CTxMemPool::Options{});
        LOCK2(cs_main, pool.cs);
        pool.ConnectBlockReset(tipHash, uint64_t(chaintip->nHeight + 1),
                               uint64_t(chaintip->GetMedianTimePast()));
        pool.UnionTransactionIntoActiveEpoch(txClean, 1000, 1);
        for (const auto &tx : bridgeOrders[idx]) {
            pool.UnionTransactionIntoActiveEpoch(tx, 1000, 1);
        }
        BOOST_CHECK_EQUAL(pool.GetQuarantinedConflictTxCount(), 3U);
        BOOST_CHECK_EQUAL(
            pool.GetOverlayManager().GetSpeculativeOverlay().GetTxCount(), 1U);

        BOOST_REQUIRE_EQUAL(pool.FreezeEpochBatch().GetLayerId(), 1U);
        pool.MarkEpochFinalized(1);
        const auto res = pool.ResolveEpochQuarantineWithBatchId(bridgeBatchId);
        // Either b2 won alone (1 winner, 2 losers) OR {b1, b3} both won
        // because they are mutually compatible once b2 is evicted (2 winners, 1 loser)!
        BOOST_CHECK(res.promoted_winners.size() == 1U ||
                    res.promoted_winners.size() == 2U);
        BOOST_CHECK_EQUAL(
            res.promoted_winners.size() + res.rejected_losers.size(), 3U);

        std::vector<TxId> winners;
        for (const auto &w : res.promoted_winners) {
            const auto ptx =
                std::static_pointer_cast<const CTransaction>(w.tx_ref);
            winners.push_back(ptx->GetId());
        }
        std::sort(winners.begin(), winners.end());
        if (idx == 0) {
            canonicalWinners = winners;
        } else {
            BOOST_CHECK(winners == canonicalWinners);
        }
    }
}

// ============================================================================
// 5. Snapblock (SEALEDHEADER) Zero Failures Under Continuous Ingestion &
//    Full 4-State Lifecycle (mempool -> snowballed -> finalized -> confirmed)
// ============================================================================
BOOST_FIXTURE_TEST_CASE(
    snapblock_sealedheader_zero_failures_under_continuous_ingestion_and_4state_rpc,
    AvalancheTestChain100Setup) {
    // Advance 10 blocks so m_coinbase_txns[0..6] all satisfy COINBASE_MATURITY
    mineBlocks(10);
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    const BlockHash tipHash = chaintip->GetBlockHash();

    auto rpc = [&](const std::string &method, UniValue params = UniValue(UniValue::VARR)) {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = method;
        request.params = std::move(params);
        return tableRPC.execute(GlobalConfig{}, request);
    };

    const CScript script =
        CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Create 6 valid transactions spending mature coinbases:
    //   Epoch 1: {tx0, tx1, tx2, tx3} (4 transactions)
    //   Epoch 2 continuous tail: {tx4, tx5} (2 transactions)
    std::vector<CTransactionRef> epoch1Txs;
    std::vector<CTransactionRef> tailTxs;
    for (int i = 0; i < 6; ++i) {
        CMutableTransaction mtx = CreateValidMempoolTransaction(
            m_coinbase_txns[i], 0, i + 1, coinbaseKey, script,
            m_coinbase_txns[i]->vout[0].nValue - 1000 * SATOSHI, false);
        CTransactionRef ref = MakeTransactionRef(std::move(mtx));
        if (i < 4) {
            epoch1Txs.push_back(ref);
        } else {
            tailTxs.push_back(ref);
        }
    }

    // 1. Ingest Epoch 1 transactions ("mempool")
    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->clear();
        m_node.mempool->ConnectBlockReset(tipHash, uint64_t(chaintip->nHeight + 1),
                                          uint64_t(chaintip->GetMedianTimePast()));
        for (const auto &tx : epoch1Txs) {
            m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
        }
        node::PublishChainTipSnapshot(chainman, m_node.mempool.get());
    }

    // 2. Crystallize Epoch 1 via Snowball ("snowballed")
    for (int r = 0; r < 4; ++r) {
        m_node.avalanche->stepEpochSnowballReconciliation(
            tipHash, 1, /*changed_by_union=*/false, /*beta=*/4);
    }
    BOOST_CHECK(m_node.avalanche->isEpochSnowballed(tipHash, 1));

    // 3. Finalize Epoch 1 ("finalized")
    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK_EQUAL(m_node.mempool->MarkEpochFinalized(1), 4U);
    }

    // 4. Continuously ingest tail transactions {tx4, tx5} into speculative
    //    Epoch 2 ("mempool") AFTER Epoch 1 is finalized!
    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        for (const auto &tx : tailTxs) {
            m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
        }
        node::PublishMempoolSnapshot(*m_node.mempool);
    }

    // Verify mixed states in mempool before block mining:
    //   epoch1Txs -> "finalized" (epoch_seq = 1)
    //   tailTxs   -> "mempool"   (epoch_seq = 0)
    for (const auto &tx : epoch1Txs) {
        UniValue p(UniValue::VARR);
        p.push_back(tx->GetId().ToString());
        const auto e = rpc("getmempoolentry", std::move(p));
        BOOST_CHECK_EQUAL(e["preconsensus_state"].get_str(), "finalized");
        BOOST_CHECK_EQUAL(e["epoch_seq"].getInt<int>(), 1);
    }
    for (const auto &tx : tailTxs) {
        UniValue p(UniValue::VARR);
        p.push_back(tx->GetId().ToString());
        const auto e = rpc("getmempoolentry", std::move(p));
        BOOST_CHECK_EQUAL(e["preconsensus_state"].get_str(), "mempool");
        BOOST_CHECK_EQUAL(e["epoch_seq"].getInt<int>(), 0);
    }

    // 5. Construct a V2 block mining the frozen Epoch 1 transactions (or full
    //    speculative overlay) while continuous ingestion adds another unmined
    //    transaction to the receiver's speculative layer!
    CTransactionRef extraUnminedTx = [&]() {
        CMutableTransaction mtx = CreateValidMempoolTransaction(
            m_coinbase_txns[6], 0, 7, coinbaseKey, script,
            m_coinbase_txns[6]->vout[0].nValue - 1000 * SATOSHI, false);
        return MakeTransactionRef(std::move(mtx));
    }();

    // Build block containing Epoch 1 + tailTxs from the current speculative
    // overlay, then ingest extraUnminedTx into the receiver's mempool BEFORE
    // SEALEDHEADER arrives (simulating continuous tx arrival while block is in
    // flight)!
    std::vector<CMutableTransaction> blockMtxs;
    for (const auto &tx : epoch1Txs) blockMtxs.push_back(CMutableTransaction(*tx));
    for (const auto &tx : tailTxs) blockMtxs.push_back(CMutableTransaction(*tx));
    CBlock minedBlock = CreateBlock(blockMtxs, CScript() << OP_TRUE, active_chainstate);

    // Freeze Epoch 2 on the receiver before extraUnminedTx arrives, OR freeze
    // Epoch 1 only and test matching against FrozenEpoch!
    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        // Freeze {epoch1Txs + tailTxs} as FrozenEpoch 2, then add extraUnminedTx
        // into the live speculative layer for Epoch 3!
        BOOST_REQUIRE_EQUAL(m_node.mempool->FreezeEpochBatch().GetLayerId(), 2U);
        m_node.mempool->addUnchecked(
            entry.Fee(1000 * SATOSHI).FromTx(extraUnminedTx));
        m_node.mempool->FlushPendingOverlayAdds();
    }

    // Compute valid V2 state root and PoW for minedBlock
    {
        LOCK(cs_main);
        minedBlock.hashMerkleRoot = BlockMerkleRoot(minedBlock);
        minedBlock.hashStateRoot = ComputeV2BlockStateRoot(
            minedBlock, minedBlock.hashPrevBlock, minedBlock.nHeight,
            uint64_t(chaintip->GetMedianTimePast()), false);
        minedBlock.SetSize(::GetSerializeSize(minedBlock));
    }
    while (!CheckProofOfWork(minedBlock.GetHash(), minedBlock.nBits,
                             config.GetChainParams().GetConsensus())) {
        ++minedBlock.nNonce;
    }

    // 6. Deliver SEALEDHEADER over P2P and verify O(1) Merklix overlay fast-path
    //    reconstruction with ZERO snapblock_failures even though extraUnminedTx
    //    was already added to the receiver's speculative tail!
    CAddress addr;
    auto *peerNode = new CNode(777, /*sock=*/nullptr, addr, 0, 0, 0, CAddress(),
                               "", ConnectionType::OUTBOUND_FULL_RELAY, false);
    peerNode->SetCommonVersion(PROTOCOL_VERSION);
    peerNode->m_has_all_wanted_services = true;
    m_node.peerman->InitializeNode(config, *peerNode, NODE_NETWORK);
    peerNode->nVersion = PROTOCOL_VERSION;
    peerNode->fSuccessfullyConnected = true;
    m_connman->AddTestNode(*peerNode);

    SealedHeader sealed(minedBlock);
    DataStream ss{};
    ss << sealed;
    std::atomic<bool> interrupt{false};
    m_node.peerman->ProcessMessage(config, *peerNode, NetMsgType::SEALEDHEADER,
                                   ss, GetTime<std::chrono::microseconds>(),
                                   interrupt);

    // Verify block connected via SEALEDHEADER with 0 snapblock failures!
    BOOST_CHECK_EQUAL(
        WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()),
        minedBlock.GetHash());

    {
        LOCK(::cs_main);
        node::PublishChainTipSnapshot(chainman, m_node.mempool.get());
    }

    {
        const auto infoJson = rpc("getmempoolinfo");
        BOOST_CHECK_EQUAL(infoJson["snapblock_reconstructed"].getInt<int>(), 1);
        BOOST_CHECK_EQUAL(
            infoJson["snapblock_overlay_fastpath"].getInt<int>(), 1);
        BOOST_CHECK_EQUAL(infoJson["snapblock_failures"].getInt<int>(), 0);
    }

    // 7. Verify 4th lifecycle state ("confirmed") via getrawtransaction(..., true)
    //    for all mined transactions, while extraUnminedTx remains in "mempool"!
    for (const auto &tx : epoch1Txs) {
        UniValue rawP(UniValue::VARR);
        rawP.push_back(tx->GetId().ToString());
        rawP.push_back(true);
        rawP.push_back(minedBlock.GetHash().ToString());
        const auto rawJson = rpc("getrawtransaction", std::move(rawP));
        BOOST_CHECK_EQUAL(rawJson["preconsensus_state"].get_str(), "confirmed");
        BOOST_CHECK_GE(rawJson["confirmations"].getInt<int>(), 1);
    }
    {
        UniValue p(UniValue::VARR);
        p.push_back(extraUnminedTx->GetId().ToString());
        const auto e = rpc("getmempoolentry", std::move(p));
        BOOST_CHECK_EQUAL(e["preconsensus_state"].get_str(), "mempool");
    }
}

// ============================================================================
// 6. Numberless parent_base_root Self-Clocking Layer Promotion & Boundary Race
// ============================================================================
BOOST_FIXTURE_TEST_CASE(
    parent_base_root_self_clocking_layer_promotion_and_boundary_race,
    AvalancheTestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    const BlockHash tipHash = chaintip->GetBlockHash();

    auto rpc = [&](const std::string &method,
                   UniValue params = UniValue(UniValue::VARR)) {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = method;
        request.params = std::move(params);
        return tableRPC.execute(GlobalConfig{}, request);
    };

    auto makeTx = [](int idx, Amount val) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(TxId(GetRandHash()), idx);
        mtx.vin[0].scriptSig = CScript() << int64_t(idx);
        mtx.vout.emplace_back(val, CScript() << OP_TRUE);
        return MakeTransactionRef(std::move(mtx));
    };

    CTransactionRef tx1 = makeTx(61, 10 * COIN);
    CTransactionRef tx2 = makeTx(62, 20 * COIN);
    CTransactionRef tx3 = makeTx(63, 30 * COIN);
    CTransactionRef tx4 = makeTx(64, 40 * COIN);

    const uint256 emptyRoot = []() {
        uint256 out;
        const auto h = lotus::v2::EmptyTxRoot();
        std::memcpy(out.begin(), h.data(), 32);
        return out;
    }();
    const uint256 rootR1 = ComputeV2SubtreeARoot({tx1, tx2});
    const uint256 rootR2 = ComputeV2SubtreeARoot({tx1, tx2, tx3, tx4});

    // Peer A (aheadPeerPool) and Peer B (m_node.mempool) both start at
    // parent_base_root = EmptyTxRoot() with Layer 1 candidate R_1 = {tx1, tx2}.
    CTxMemPool aheadPeerPool(config, CTxMemPool::Options{});
    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, aheadPeerPool.cs);
        aheadPeerPool.clear();
        aheadPeerPool.ConnectBlockReset(
            tipHash, uint64_t(chaintip->nHeight + 1),
            uint64_t(chaintip->GetMedianTimePast()));
        aheadPeerPool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));
        aheadPeerPool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx2));
        BOOST_CHECK_EQUAL(aheadPeerPool.GetParentBaseRoot(), emptyRoot);
        BOOST_CHECK_EQUAL(aheadPeerPool.GetActiveSketchRoot(), rootR1);

        // Stage {tx3, tx4} into Peer A's IncomingMempool while Layer 1 (R_1)
        // is snowballing: verify R_1's ActiveSketchRoot is NOT perturbed!
        BOOST_CHECK(aheadPeerPool.StageIncomingTransaction(tx3, 1000, 1));
        BOOST_CHECK(aheadPeerPool.StageIncomingTransaction(tx4, 1000, 1));
        BOOST_CHECK_EQUAL(
            aheadPeerPool.GetOverlayManager().GetIncomingMempoolTxCount(), 2U);
        BOOST_CHECK_EQUAL(aheadPeerPool.GetActiveSketchRoot(), rootR1);
    }

    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->clear();
        m_node.mempool->ConnectBlockReset(
            tipHash, uint64_t(chaintip->nHeight + 1),
            uint64_t(chaintip->GetMedianTimePast()));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx2));
        BOOST_CHECK_EQUAL(m_node.mempool->GetParentBaseRoot(), emptyRoot);
        BOOST_CHECK_EQUAL(m_node.mempool->GetActiveSketchRoot(), rootR1);
    }

    // Peer B (m_node) completes beta - 1 = 3 unchanged rounds on R_1 (beta = 4)
    constexpr uint32_t kBeta = 4;
    for (uint32_t r = 0; r < kBeta - 1; ++r) {
        BOOST_CHECK(!m_node.avalanche->stepEpochSnowballReconciliation(
            tipHash, 1, /*treeChangedInRound=*/false, kBeta));
    }
    BOOST_CHECK(!m_node.avalanche->isEpochSnowballed(tipHash, 1));

    // Meanwhile, Peer A finishes its 4th round on R_1 one tick ahead of Peer B!
    // Freezing R_1 on Peer A folds R_1 into CrystallizedBase (parent_base_root = R_1)
    // and automatically promotes Peer A's IncomingMempool ({tx3, tx4}) into
    // Peer A's new ActiveSketchLayer (active_sketch_root = R_2)!
    {
        LOCK(aheadPeerPool.cs);
        BOOST_CHECK_EQUAL(aheadPeerPool.MarkEpochSnowballed(1), 2U);
        BOOST_CHECK_EQUAL(aheadPeerPool.GetParentBaseRoot(), rootR1);
        BOOST_CHECK_EQUAL(aheadPeerPool.GetActiveSketchRoot(), rootR2);
        BOOST_CHECK_EQUAL(
            aheadPeerPool.GetOverlayManager().GetIncomingMempoolTxCount(), 0U);
        BOOST_CHECK_EQUAL(
            aheadPeerPool.GetOverlayManager().GetActiveLayerDeltaTxCount(), 2U);
    }

    // Verify Boundary Race Classification on Peer B:
    // Peer B sees Peer A's parent_base_root == Peer B's active_sketch_root (R_1),
    // which classifies as PEER_AHEAD_CONFIRMS_LOCAL!
    {
        uint256 peerParentBase;
        uint256 peerActiveSketch;
        {
            LOCK(aheadPeerPool.cs);
            peerParentBase = aheadPeerPool.GetParentBaseRoot();
            peerActiveSketch = aheadPeerPool.GetActiveSketchRoot();
        }
        LOCK(m_node.mempool->cs);
        BOOST_CHECK(m_node.mempool->ClassifyPeerLayerSketch(
                        peerParentBase, peerActiveSketch) ==
                    lotus::v2::LayerSyncRelation::PEER_AHEAD_CONFIRMS_LOCAL);
    }

    // Now Peer B reconciles with Peer A via numberless reconcileEpochWithPeerMempools:
    // 1. Peer B counts Peer A's parent_base_root == R_1 as confirming R_1
    //    WITHOUT mixing {tx3, tx4} into Layer 1 (R_1)!
    // 2. Peer B completes its 4th round on R_1, crystallizing Layer 1 (R_1)
    //    with exact root R_1 ({tx1, tx2} in state "snowballed", epoch_seq = 1)
    //    and promoting Peer B's parent_base_root to R_1!
    // 3. Peer B immediately adopts Peer A's Layer 2 delta ({tx3, tx4}) into
    //    Peer B's newly promoted ActiveSketchLayer anchored on R_1!
    std::vector<CTxMemPool *> sampledPeers = {&aheadPeerPool};
    MempoolBatchAnnouncement batch1;
    BOOST_REQUIRE(m_node.avalanche->reconcileEpochWithPeerMempools(
        tipHash, sampledPeers, kBeta, /*autoRegisterBatch=*/true, &batch1));
    BOOST_CHECK(m_node.avalanche->isEpochSnowballed(tipHash, 1));
    BOOST_CHECK_EQUAL(batch1.epoch_seq, 1U);
    BOOST_CHECK_EQUAL(batch1.tx_count, 2U);
    BOOST_CHECK_EQUAL(batch1.subtree_a_root, rootR1);

    {
        LOCK(m_node.mempool->cs);
        BOOST_CHECK_EQUAL(m_node.mempool->GetParentBaseRoot(), rootR1);
        BOOST_CHECK_EQUAL(m_node.mempool->GetActiveSketchRoot(), rootR2);
        BOOST_CHECK_GT(m_node.mempool->GetLastLayerConvergenceMs(), 0U);
    }

    // Verify tx1, tx2 are "snowballed" (epoch_seq = 1) and tx3, tx4 are
    // "mempool" (epoch_seq = 0) in Layer 2!
    for (const auto &tx : {tx1, tx2}) {
        UniValue p(UniValue::VARR);
        p.push_back(tx->GetId().ToString());
        const auto e = rpc("getmempoolentry", std::move(p));
        BOOST_CHECK_EQUAL(e["preconsensus_state"].get_str(), "snowballed");
        BOOST_CHECK_EQUAL(e["epoch_seq"].getInt<int>(), 1);
    }
    for (const auto &tx : {tx3, tx4}) {
        UniValue p(UniValue::VARR);
        p.push_back(tx->GetId().ToString());
        const auto e = rpc("getmempoolentry", std::move(p));
        BOOST_CHECK_EQUAL(e["preconsensus_state"].get_str(), "mempool");
        BOOST_CHECK_EQUAL(e["epoch_seq"].getInt<int>(), 0);
    }

    const auto infoJson = rpc("getmempoolinfo");
    BOOST_CHECK_GT(infoJson["last_layer_convergence_ms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
