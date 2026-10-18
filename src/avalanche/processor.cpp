// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/processor.h>

#include <avalanche/avalanche.h>
#include <avalanche/delegationbuilder.h>
#include <avalanche/peermanager.h>
#include <avalanche/proofcomparator.h>
#include <avalanche/validation.h>
#include <avalanche/voterecord.h>
#include <chain.h>
#include <common/args.h>
#include <consensus/activation.h>
#include <key_io.h> // For DecodeSecret
#include <net.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <node/metrics.h>
#include <policy/block/stakingrewards.h>
#include <scheduler.h>
#include <txmempool.h>
#include <util/bitmanip.h>
#include <util/moneystr.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>

#include <chrono>
#include <limits>
#include <tuple>

/**
 * Run the avalanche event loop every 10ms.
 */
static constexpr std::chrono::milliseconds AVALANCHE_TIME_STEP{10};

static const std::string AVAPEERS_FILE_NAME{"avapeers.dat"};

namespace avalanche {
static uint256 GetVoteItemId(const AnyVoteItem &item) {
    return std::visit(variant::overloaded{
                          [](const ProofRef &proof) {
                              uint256 id = proof->getId();
                              return id;
                          },
                          [](const CBlockIndex *pindex) {
                              uint256 hash = pindex->GetBlockHash();
                              return hash;
                          },
                          [](const StakeContenderId &contenderId) {
                              return uint256(contenderId);
                          },
                          [](const TreasuryContenderId &contenderId) {
                              return uint256(contenderId);
                          },
                          [](const MempoolBatchVoteItem &batch) {
                              return batch.GetId();
                          },
                          [](const CTransactionRef &tx) {
                              uint256 id = tx->GetId();
                              return id;
                          },
                      },
                      item);
}

static bool VerifyProof(const Amount &stakeUtxoDustThreshold,
                        const Proof &proof, bilingual_str &error) {
    ProofValidationState proof_state;

    if (!proof.verify(stakeUtxoDustThreshold, proof_state)) {
        switch (proof_state.GetResult()) {
            case ProofValidationResult::NO_STAKE:
                error = _("The avalanche proof has no stake.");
                return false;
            case ProofValidationResult::DUST_THRESHOLD:
                error = _("The avalanche proof stake is too low.");
                return false;
            case ProofValidationResult::DUPLICATE_STAKE:
                error = _("The avalanche proof has duplicated stake.");
                return false;
            case ProofValidationResult::INVALID_STAKE_SIGNATURE:
                error = _("The avalanche proof has invalid stake signatures.");
                return false;
            case ProofValidationResult::TOO_MANY_UTXOS:
                error = strprintf(
                    _("The avalanche proof has too many utxos (max: %u)."),
                    AVALANCHE_MAX_PROOF_STAKES);
                return false;
            default:
                error = _("The avalanche proof is invalid.");
                return false;
        }
    }

    return true;
}

static bool VerifyDelegation(const Delegation &dg,
                             const CPubKey &expectedPubKey,
                             bilingual_str &error) {
    DelegationState dg_state;

    CPubKey auth;
    if (!dg.verify(dg_state, auth)) {
        switch (dg_state.GetResult()) {
            case avalanche::DelegationResult::INVALID_SIGNATURE:
                error = _("The avalanche delegation has invalid signatures.");
                return false;
            case avalanche::DelegationResult::TOO_MANY_LEVELS:
                error = _(
                    "The avalanche delegation has too many delegation levels.");
                return false;
            default:
                error = _("The avalanche delegation is invalid.");
                return false;
        }
    }

    if (auth != expectedPubKey) {
        error = _(
            "The avalanche delegation does not match the expected public key.");
        return false;
    }

    return true;
}

struct Processor::PeerData {
    ProofRef proof;
    Delegation delegation;

    mutable Mutex cs_proofState;
    ProofRegistrationState proofState GUARDED_BY(cs_proofState);
};

class Processor::NotificationsHandler
    : public interfaces::Chain::Notifications {
    Processor *m_processor;

public:
    NotificationsHandler(Processor *p) : m_processor(p) {}

    void updatedBlockTip() override { m_processor->updatedBlockTip(); }

    void transactionAddedToMempool(const CTransactionRef &tx,
                                   uint64_t mempool_sequence) override {
        m_processor->transactionAddedToMempool(tx);
    }
};

Processor::Processor(Config avaconfigIn, interfaces::Chain &chain,
                     CConnman *connmanIn, ChainstateManager &chainmanIn,
                     CTxMemPool *mempoolIn, CScheduler &scheduler,
                     std::unique_ptr<PeerData> peerDataIn, CKey sessionKeyIn,
                     uint32_t minQuorumTotalScoreIn,
                     double minQuorumConnectedScoreRatioIn,
                     int64_t minAvaproofsNodeCountIn, size_t minQuorumNodesIn,
                     uint64_t minQuorumSupplyPermilleIn,
                     uint32_t staleVoteThresholdIn, uint32_t staleVoteFactorIn,
                     Amount stakeUtxoDustThreshold, bool preConsensus,
                     bool stakingPreConsensus, size_t maxElementPoll)
    : avaconfig(std::move(avaconfigIn)), connman(connmanIn),
      chainman(chainmanIn), mempool(mempoolIn), round(0),
      peerManager(std::make_unique<PeerManager>(
          stakeUtxoDustThreshold, chainman, stakingPreConsensus,
          peerDataIn ? peerDataIn->proof : ProofRef())),
      peerData(std::move(peerDataIn)), sessionKey(std::move(sessionKeyIn)),
      minQuorumScore(minQuorumTotalScoreIn),
      minQuorumConnectedScoreRatio(minQuorumConnectedScoreRatioIn),
      minQuorumNodes(minQuorumNodesIn),
      minQuorumSupplyPermille(minQuorumSupplyPermilleIn),
      minAvaproofsNodeCount(minAvaproofsNodeCountIn),
      staleVoteThreshold(staleVoteThresholdIn),
      staleVoteFactor(staleVoteFactorIn), m_preConsensus(preConsensus),
      m_stakingPreConsensus(stakingPreConsensus),
      m_maxElementPoll(maxElementPoll) {
    {
        LOCK(cs_main);
        if (const CBlockIndex *tip = chainman.ActiveTip()) {
            LOCK(cs_activeTipHash);
            m_activeTipHash = tip->GetBlockHash();
        }
    }
    // Make sure we get notified of chain state changes.
    chainNotificationsHandler =
        chain.handleNotifications(std::make_shared<NotificationsHandler>(this));

    scheduler.scheduleEvery(
        [this]() -> bool {
            std::unordered_set<ProofRef, SaltedProofHasher> registeredProofs;
            WITH_LOCK(cs_peerManager,
                      peerManager->cleanupDanglingProofs(registeredProofs));
            for (const auto &proof : registeredProofs) {
                LogDebug(BCLog::AVALANCHE,
                         "Promoting previously dangling proof %s\n",
                         proof->getId().ToString());
                reconcileOrFinalize(proof);
            }
            return true;
        },
        5min);

    if (!gArgs.GetBoolArg("-persistavapeers", DEFAULT_PERSIST_AVAPEERS)) {
        return;
    }

    std::unordered_set<ProofRef, SaltedProofHasher> registeredProofs;

    // Attempt to load the peer file if it exists.
    const fs::path dumpPath = gArgs.GetDataDirNet() / AVAPEERS_FILE_NAME;
    WITH_LOCK(cs_peerManager, return peerManager->loadPeersFromFile(
                                  dumpPath, registeredProofs));

    // We just loaded the previous finalization status, but make sure to trigger
    // another round of vote for these proofs to avoid issue if the network
    // status changed since the peers file was dumped.
    for (const auto &proof : registeredProofs) {
        addToReconcile(proof);
    }

    LogDebug(BCLog::AVALANCHE, "Loaded %d peers from the %s file\n",
             registeredProofs.size(), PathToString(dumpPath));
}

Processor::~Processor() {
    chainNotificationsHandler->disconnect();
    chainNotificationsHandler.reset();
    stopEventLoop();

    if (!gArgs.GetBoolArg("-persistavapeers", DEFAULT_PERSIST_AVAPEERS)) {
        return;
    }

    LOCK(cs_peerManager);
    // Discard the status output: if it fails we want to continue normally.
    peerManager->dumpPeersToFile(gArgs.GetDataDirNet() / AVAPEERS_FILE_NAME);
}

std::unique_ptr<Processor>
Processor::MakeProcessor(const ArgsManager &argsman, interfaces::Chain &chain,
                         CConnman *connman, ChainstateManager &chainman,
                         CTxMemPool *mempool, CScheduler &scheduler,
                         bilingual_str &error) {
    std::unique_ptr<PeerData> peerData;
    CKey masterKey;
    CKey sessionKey;

    Amount stakeUtxoDustThreshold = PROOF_DUST_THRESHOLD;
    if (argsman.IsArgSet("-avaproofstakeutxodustthreshold") &&
        !ParseMoney(argsman.GetArg("-avaproofstakeutxodustthreshold", ""),
                    stakeUtxoDustThreshold)) {
        error = _("The avalanche stake utxo dust threshold amount is invalid.");
        return nullptr;
    }

    if (argsman.IsArgSet("-avasessionkey")) {
        sessionKey = DecodeSecret(argsman.GetArg("-avasessionkey", ""));
        if (!sessionKey.IsValid()) {
            error = _("The avalanche session key is invalid.");
            return nullptr;
        }
    } else {
        // Pick a random key for the session.
        sessionKey.MakeNewKey(true);
    }

    if (argsman.IsArgSet("-avaproof")) {
        if (!argsman.IsArgSet("-avamasterkey")) {
            error = _(
                "The avalanche master key is missing for the avalanche proof.");
            return nullptr;
        }

        masterKey = DecodeSecret(argsman.GetArg("-avamasterkey", ""));
        if (!masterKey.IsValid()) {
            error = _("The avalanche master key is invalid.");
            return nullptr;
        }

        auto proof = RCUPtr<Proof>::make();
        if (!Proof::FromHex(*proof, argsman.GetArg("-avaproof", ""), error)) {
            // error is set by FromHex
            return nullptr;
        }

        peerData = std::make_unique<PeerData>();
        peerData->proof = proof;
        if (!VerifyProof(stakeUtxoDustThreshold, *peerData->proof, error)) {
            // error is set by VerifyProof
            return nullptr;
        }

        std::unique_ptr<DelegationBuilder> dgb;
        const CPubKey &masterPubKey = masterKey.GetPubKey();

        if (argsman.IsArgSet("-avadelegation")) {
            Delegation dg;
            if (!Delegation::FromHex(dg, argsman.GetArg("-avadelegation", ""),
                                     error)) {
                // error is set by FromHex()
                return nullptr;
            }

            if (dg.getProofId() != peerData->proof->getId()) {
                error = _("The delegation does not match the proof.");
                return nullptr;
            }

            if (masterPubKey != dg.getDelegatedPubkey()) {
                error = _(
                    "The master key does not match the delegation public key.");
                return nullptr;
            }

            dgb = std::make_unique<DelegationBuilder>(dg);
        } else {
            if (masterPubKey != peerData->proof->getMaster()) {
                error =
                    _("The master key does not match the proof public key.");
                return nullptr;
            }

            dgb = std::make_unique<DelegationBuilder>(*peerData->proof);
        }

        // Generate the delegation to the session key.
        const CPubKey sessionPubKey = sessionKey.GetPubKey();
        if (sessionPubKey != masterPubKey) {
            if (!dgb->addLevel(masterKey, sessionPubKey)) {
                error = _("Failed to generate a delegation for this session.");
                return nullptr;
            }
        }
        peerData->delegation = dgb->build();

        if (!VerifyDelegation(peerData->delegation, sessionPubKey, error)) {
            // error is set by VerifyDelegation
            return nullptr;
        }
    }

    const auto queryTimeoutDuration =
        std::chrono::milliseconds(argsman.GetIntArg(
            "-avatimeout", AVALANCHE_DEFAULT_QUERY_TIMEOUT.count()));

    // Determine quorum parameters
    Amount minQuorumStake = AVALANCHE_DEFAULT_MIN_QUORUM_STAKE;
    if (argsman.IsArgSet("-avaminquorumstake") &&
        !ParseMoney(argsman.GetArg("-avaminquorumstake", ""), minQuorumStake)) {
        error = _("The avalanche min quorum stake amount is invalid.");
        return nullptr;
    }

    if (!MoneyRange(minQuorumStake)) {
        error = _("The avalanche min quorum stake amount is out of range.");
        return nullptr;
    }

    double minQuorumConnectedStakeRatio =
        AVALANCHE_DEFAULT_MIN_QUORUM_CONNECTED_STAKE_RATIO;
    if (argsman.IsArgSet("-avaminquorumconnectedstakeratio")) {
        // Parse the parameter with a precision of 0.000001.
        int64_t megaMinRatio;
        if (!ParseFixedPoint(
                argsman.GetArg("-avaminquorumconnectedstakeratio", ""), 6,
                &megaMinRatio)) {
            error =
                _("The avalanche min quorum connected stake ratio is invalid.");
            return nullptr;
        }
        minQuorumConnectedStakeRatio = double(megaMinRatio) / 1000000;
    }

    if (minQuorumConnectedStakeRatio < 0 || minQuorumConnectedStakeRatio > 1) {
        error = _(
            "The avalanche min quorum connected stake ratio is out of range.");
        return nullptr;
    }

    int64_t minAvaproofsNodeCount =
        argsman.GetIntArg("-avaminavaproofsnodecount",
                          AVALANCHE_DEFAULT_MIN_AVAPROOFS_NODE_COUNT);
    if (minAvaproofsNodeCount < 0) {
        error = _("The minimum number of node that sent avaproofs message "
                  "should be non-negative");
        return nullptr;
    }

    int64_t minQuorumNodes = argsman.GetIntArg(
        "-avaminquorumnodes", AVALANCHE_DEFAULT_MIN_QUORUM_NODES);
    if (minQuorumNodes < 0) {
        error = _("The minimum number of quorum nodes should be non-negative");
        return nullptr;
    }

    int64_t minQuorumSupplyPermille = argsman.GetIntArg(
        "-avaminquorumsupplypermille",
        AVALANCHE_DEFAULT_MIN_QUORUM_SUPPLY_PERMILLE);
    if (minQuorumSupplyPermille < 0 || minQuorumSupplyPermille > 1000) {
        error = _(
            "The avalanche min quorum supply permille must be between 0 and 1000");
        return nullptr;
    }

    // Determine voting parameters
    int64_t staleVoteThreshold = argsman.GetIntArg(
        "-avastalevotethreshold", AVALANCHE_VOTE_STALE_THRESHOLD);
    if (staleVoteThreshold < AVALANCHE_VOTE_STALE_MIN_THRESHOLD) {
        error = strprintf(_("The avalanche stale vote threshold must be "
                            "greater than or equal to %d"),
                          AVALANCHE_VOTE_STALE_MIN_THRESHOLD);
        return nullptr;
    }
    if (staleVoteThreshold > std::numeric_limits<uint32_t>::max()) {
        error = strprintf(_("The avalanche stale vote threshold must be less "
                            "than or equal to %d"),
                          std::numeric_limits<uint32_t>::max());
        return nullptr;
    }

    int64_t staleVoteFactor =
        argsman.GetIntArg("-avastalevotefactor", AVALANCHE_VOTE_STALE_FACTOR);
    if (staleVoteFactor <= 0) {
        error = _("The avalanche stale vote factor must be greater than 0");
        return nullptr;
    }
    if (staleVoteFactor > std::numeric_limits<uint32_t>::max()) {
        error = strprintf(_("The avalanche stale vote factor must be less than "
                            "or equal to %d"),
                          std::numeric_limits<uint32_t>::max());
        return nullptr;
    }

    Config avaconfig(queryTimeoutDuration);

    int64_t maxElementPoll = argsman.GetIntArg(
        "-avamaxelementpoll", DEFAULT_AVALANCHE_MAX_ELEMENT_POLL);
    if (maxElementPoll < int64_t{AVALANCHE_MAX_ELEMENT_POLL_LEGACY} ||
        maxElementPoll > std::numeric_limits<uint32_t>::max()) {
        error = strprintf(
            _("The -avamaxelementpoll value must be between %d and %d"),
            AVALANCHE_MAX_ELEMENT_POLL_LEGACY,
            std::numeric_limits<uint32_t>::max());
        return nullptr;
    }

    // We can't use std::make_unique with a private constructor
    return std::unique_ptr<Processor>(new Processor(
        std::move(avaconfig), chain, connman, chainman, mempool, scheduler,
        std::move(peerData), std::move(sessionKey),
        Proof::amountToScore(minQuorumStake), minQuorumConnectedStakeRatio,
        minAvaproofsNodeCount, minQuorumNodes, minQuorumSupplyPermille,
        staleVoteThreshold, staleVoteFactor,
        stakeUtxoDustThreshold,
        argsman.GetBoolArg("-avalanchepreconsensus",
                           DEFAULT_AVALANCHE_PRECONSENSUS),
        argsman.GetBoolArg("-avalanchestakingpreconsensus",
                           DEFAULT_AVALANCHE_STAKING_PRECONSENSUS),
        // This is safe because we ensure size_t is >= 32 bits in assumptions.h
        static_cast<size_t>(maxElementPoll)));
}

static bool isNull(const AnyVoteItem &item) {
    return item.valueless_by_exception() ||
           std::visit(variant::overloaded{
                          [](const StakeContenderId &contenderId) {
                              return contenderId == uint256::ZERO;
                          },
                          [](const TreasuryContenderId &contenderId) {
                              return contenderId == uint256::ZERO;
                          },
                          [](const MempoolBatchVoteItem &batch) {
                              return batch.isNull();
                          },
                          [](const auto &item) { return item == nullptr; },
                      },
                      item);
};

/** A new vote record, timestamped when metrics are on */
static VoteRecord NewVoteRecord(bool accepted) {
    VoteRecord vr(accepted);
    if (node::GetNodeMetrics()) {
        vr.addedTime = std::chrono::steady_clock::now();
    }
    return vr;
}

/** Label index (node::metric_labels::AvalancheItemTypes) of an item */
static size_t MetricItemType(const AnyVoteItem &item) {
    static_assert(std::variant_size_v<AnyVoteItem> == 6,
                  "update AvalancheItemTypes() in node/metrics.cpp");
    return item.index();
}

bool Processor::addToReconcile(const AnyVoteItem &item) {
    if (isNull(item)) {
        return false;
    }

    if (!isWorthPolling(item)) {
        return false;
    }

    // getLocalAcceptance() takes the voteRecords read lock, so we can't inline
    // the calls or we get a deadlock.
    const bool accepted = getLocalAcceptance(item);

    return voteRecords.getWriteView()
        ->insert(std::make_pair(item, NewVoteRecord(accepted)))
        .second;
}

bool Processor::reconcileOrFinalize(const ProofRef &proof) {
    if (!proof) {
        return false;
    }

    if (isRecentlyFinalized(proof->getId())) {
        PeerId peerid;
        LOCK(cs_peerManager);
        if (peerManager->forPeer(proof->getId(), [&](const Peer &peer) {
                peerid = peer.peerid;
                return true;
            })) {
            return peerManager->setFinalized(peerid);
        }
    }

    return addToReconcile(proof);
}

bool Processor::isAccepted(const AnyVoteItem &item) const {
    if (isNull(item)) {
        return false;
    }

    auto r = voteRecords.getReadView();
    auto it = r->find(item);
    if (it == r.end()) {
        return false;
    }

    return it->second.isAccepted();
}

int Processor::getConfidence(const AnyVoteItem &item) const {
    if (isNull(item)) {
        return -1;
    }

    auto r = voteRecords.getReadView();
    auto it = r->find(item);
    if (it == r.end()) {
        return -1;
    }

    return it->second.getConfidence();
}

bool Processor::isPolled(const AnyVoteItem &item) const {
    if (isNull(item)) {
        return false;
    }

    auto r = voteRecords.getReadView();
    auto it = r->find(item);
    return it != r.end();
}

bool Processor::isRecentlyFinalized(const uint256 &itemId) const {
    return WITH_LOCK(cs_finalizedItems, return finalizedItems.contains(itemId));
}

void Processor::setRecentlyFinalized(const uint256 &itemId) {
    WITH_LOCK(cs_finalizedItems, finalizedItems.insert(itemId));
}

void Processor::clearFinalizedItems() {
    LOCK(cs_finalizedItems);
    finalizedItems.reset();
}

namespace {
    /**
     * When using TCP, we need to sign all messages as the transport layer is
     * not secure.
     */
    class TCPResponse {
        Response response;
        SchnorrSig sig;

    public:
        TCPResponse(Response responseIn, const CKey &key)
            : response(std::move(responseIn)) {
            HashWriter hasher{};
            hasher << response;
            const uint256 hash = hasher.GetHash();

            // Now let's sign!
            if (!key.SignSchnorr(hash, sig)) {
                sig.fill(0);
            }
        }

        // serialization support
        SERIALIZE_METHODS(TCPResponse, obj) {
            READWRITE(obj.response, obj.sig);
        }
    };
} // namespace

void Processor::sendResponse(CNode *pfrom, Response response) const {
    connman->PushMessage(
        pfrom, NetMsg::Make(NetMsgType::AVARESPONSE,
                            TCPResponse(std::move(response), sessionKey)));
}

bool Processor::registerVotes(NodeId nodeid, const Response &response,
                              std::vector<VoteItemUpdate> &updates,
                              bool &disconnect, std::string &error) {
    disconnect = false;
    updates.clear();

    // Save the time at which we can query again.
    WITH_LOCK(cs_peerManager,
              peerManager->updateNextRequestTimeForResponse(nodeid, response));

    std::vector<CInv> invs;
    SteadyMilliseconds queryTimeout{};

    {
        // Check that the query exists. There is a possibility that it has been
        // deleted if the query timed out, so we don't disconnect for poor
        // networking over time.
        // Disconnecting has to be handled at callsite to avoid DoS.
        auto w = queries.getWriteView();
        auto it = w->find(std::make_tuple(nodeid, response.getRound()));
        if (it == w.end()) {
            error = "unexpected-ava-response";
            return false;
        }

        queryTimeout = it->timeout;
        invs = std::move(it->invs);
        w->erase(it);
    }

    const auto now = Now<SteadyMilliseconds>();
    const auto sentTime = queryTimeout - avaconfig.queryTimeoutDuration;
    if (now >= sentTime) {
        m_adaptiveEpochController.recordPollRtt(now - sentTime);
    }

    // Verify that the request and the vote are consistent.
    const std::vector<Vote> &votes = response.GetVotes();
    size_t size = invs.size();
    if (auto *metrics{node::GetNodeMetrics()}) {
        for (const Vote &v : votes) {
            metrics->avalanche_votes_received.Add(
                node::AvalancheVoteSeries(v.GetError()));
        }
    }
    if (votes.size() != size) {
        disconnect = true;
        error = "invalid-ava-response-size";
        clearInflightRequests(invs);
        return false;
    }

    for (size_t i = 0; i < size; i++) {
        if (invs[i].hash != votes[i].GetHash()) {
            disconnect = true;
            error = "invalid-ava-response-content";
            clearInflightRequests(invs);
            return false;
        }
    }

    // Opt-in debug observation for transport experiments. Only matched,
    // content-consistent responses reach here; the caller verified signatures.
    // This measures dispatch-to-processing latency, including local queues,
    // rather than claiming a pure wire RTT. No payload or key material is logged.
    if (now >= sentTime) {
        LogDebug(BCLog::AVALANCHE,
                 "poll_rtt peer=%d round=%u rtt_ms=%d\n", nodeid,
                 response.getRound(), (now - sentTime).count());
    }

    std::map<AnyVoteItem, Vote, VoteMapComparator> responseItems;

    // At this stage we are certain that invs[i] matches votes[i], so we can use
    // the inv type to retrieve what is being voted on.
    for (size_t i = 0; i < size; i++) {
        auto item = getVoteItemFromInv(invs[i]);

        if (isNull(item)) {
            // This should not happen, but just in case...
            continue;
        }

        if (!isWorthPolling(item)) {
            // There is no point polling this item.
            continue;
        }

        responseItems.insert(std::make_pair(std::move(item), votes[i]));
    }

    auto *const metrics{node::GetNodeMetrics()};
    const auto countItem{
        [&](const AnyVoteItem &item, node::AvalancheItemOutcome outcome) {
            if (metrics) {
                const std::array<size_t, 2> idx{MetricItemType(item),
                                                size_t(outcome)};
                metrics->avalanche_items.Add(
                    metrics->avalanche_items.SeriesIndex(idx));
            }
        }};

    {
        auto voteRecordsWriteView = voteRecords.getWriteView();

        // Register votes.
        for (const auto &p : responseItems) {
            auto item = p.first;
            const Vote &v = p.second;

            auto it = voteRecordsWriteView->find(item);
            if (it == voteRecordsWriteView.end()) {
                // We are not voting on that item anymore.
                continue;
            }

            const bool isBatchItem =
                std::holds_alternative<const MempoolBatchVoteItem>(item);
            if (isBatchItem && v.GetError() != 0) {
                const auto &batchItem =
                    std::get<const MempoolBatchVoteItem>(item);
                markMempoolBatchConflict(batchItem.GetId());
                m_adaptiveEpochController.recordMissOrConflict();
            }

            auto &vr = it->second;
            const bool voteRegistered = vr.registerVote(nodeid, v.GetError());

            // A confidence increment is not a stake-weighted supermajority
            // certificate. Batches use the same finalization score as every
            // other Avalanche item; the adaptive scheduler changes cadence,
            // never the safety threshold.

            if (!voteRegistered) {
                if (vr.isStale(staleVoteThreshold, staleVoteFactor)) {
                    countItem(item, node::AvalancheItemOutcome::STALE);
                    updates.emplace_back(std::move(item), VoteStatus::Stale);

                    // Just drop stale votes. If we see this item again, we'll
                    // do a new vote.
                    voteRecordsWriteView->erase(it);
                }
                // This vote did not provide any extra information, move on.
                continue;
            }

            if (!vr.hasFinalized()) {
                // This item has not been finalized, so we have nothing more to
                // do.
                updates.emplace_back(std::move(item), vr.isAccepted()
                                                          ? VoteStatus::Accepted
                                                          : VoteStatus::Rejected);
                continue;
            }

            if (isBatchItem && vr.isAccepted() &&
                !hasMempoolBatchConflict(
                    std::get<const MempoolBatchVoteItem>(item).GetId())) {
                // Clean normal finalizations recover the cadence after a
                // backoff too. This legacy counter name is not fast finality.
                m_adaptiveEpochController.recordCleanFastPath();
            }

            // We just finalized a vote. If it is valid, then let the caller
            // know. Either way, remove the item from the map.
            countItem(item, vr.isAccepted()
                                ? node::AvalancheItemOutcome::FINALIZED
                                : node::AvalancheItemOutcome::INVALIDATED);
            if (metrics && vr.isAccepted() &&
                vr.addedTime != std::chrono::steady_clock::time_point{}) {
                metrics->avalanche_finalization_seconds.RecordDuration(
                    std::chrono::steady_clock::now() - vr.addedTime,
                    MetricItemType(item));
            }
            updates.emplace_back(std::move(item), vr.isAccepted()
                                                      ? VoteStatus::Finalized
                                                      : VoteStatus::Invalid);
            voteRecordsWriteView->erase(it);
        }
    }

    // FIXME This doesn't belong here as it has nothing to do with vote
    // registration.
    for (const auto &update : updates) {
        const auto &item = update.getVoteItem();
        const VoteStatus status = update.getStatus();

        if (std::holds_alternative<const TreasuryContenderId>(item)) {
            const auto &contenderId = std::get<const TreasuryContenderId>(item);
            if (status == VoteStatus::Accepted) {
                acceptTreasuryContender(contenderId);
            } else if (status == VoteStatus::Finalized) {
                finalizeTreasuryContender(contenderId);
                setRecentlyFinalized(contenderId);
            } else if (status == VoteStatus::Rejected ||
                       status == VoteStatus::Invalid) {
                rejectTreasuryContender(contenderId);
            }
            continue;
        }

        // Treasury handles provisional decisions above. Other item kinds
        // update finalized state only after the vote has actually finalized.
        if (status != VoteStatus::Finalized && status != VoteStatus::Invalid) {
            continue;
        }

        if (const auto *batch = std::get_if<const MempoolBatchVoteItem>(&item)) {
            if (update.getStatus() == VoteStatus::Finalized) {
                finalizeMempoolBatch(batch->GetId());
            } else {
                markMempoolBatchConflict(batch->GetId());
            }
            continue;
        }

        if (!std::holds_alternative<const CBlockIndex *>(item)) {
            continue;
        }

        if (status == VoteStatus::Invalid) {
            // Track invalidated blocks. Other invalidated types are not
            // tracked because they may be rejected for transient reasons
            // (ex: immature proofs or orphaned txs) With blocks this is not
            // the case. A rejected block will not be mined on. To prevent
            // reorgs, invalidated blocks should never be polled again.
            LOCK(cs_invalidatedBlocks);
            invalidatedBlocks.insert(GetVoteItemId(item));
            continue;
        }

        // At this point the block index can only be finalized
        const CBlockIndex *pindex = std::get<const CBlockIndex *>(item);
        LOCK(cs_finalizationTip);
        if (finalizationTip &&
            finalizationTip->GetAncestor(pindex->nHeight) == pindex) {
            continue;
        }

        finalizationTip = pindex;
    }

    return true;
}

CPubKey Processor::getSessionPubKey() const {
    return sessionKey.GetPubKey();
}

bool Processor::sendHelloInternal(CNode *pfrom) {
    AssertLockHeld(cs_delayedAvahelloNodeIds);

    Delegation delegation;
    if (peerData) {
        if (!canShareLocalProof()) {
            if (!delayedAvahelloNodeIds.emplace(pfrom->GetId()).second) {
                // Nothing to do
                return false;
            }
        } else {
            delegation = peerData->delegation;
        }
    }

    HashWriter hasher{};
    hasher << delegation.getId();
    hasher << pfrom->GetLocalNonce();
    hasher << pfrom->nRemoteHostNonce;
    hasher << pfrom->GetLocalExtraEntropy();
    hasher << pfrom->nRemoteExtraEntropy;

    // Now let's sign!
    SchnorrSig sig;
    if (!sessionKey.SignSchnorr(hasher.GetHash(), sig)) {
        return false;
    }

    connman->PushMessage(
        pfrom, NetMsg::Make(NetMsgType::AVAHELLO,
                            Hello(delegation, sig, m_maxElementPoll)));

    return delegation.getLimitedProofId() != uint256::ZERO;
}

bool Processor::sendHello(CNode *pfrom) {
    return WITH_LOCK(cs_delayedAvahelloNodeIds,
                     return sendHelloInternal(pfrom));
}

void Processor::sendDelayedAvahello() {
    LOCK(cs_delayedAvahelloNodeIds);

    auto it = delayedAvahelloNodeIds.begin();
    while (it != delayedAvahelloNodeIds.end()) {
        if (connman->ForNode(*it, [&](CNode *pnode) EXCLUSIVE_LOCKS_REQUIRED(
                                      cs_delayedAvahelloNodeIds) {
                return sendHelloInternal(pnode);
            })) {
            // Our proof has been announced to this node
            it = delayedAvahelloNodeIds.erase(it);
        } else {
            ++it;
        }
    }
}

ProofRef Processor::getLocalProof() const {
    return peerData ? peerData->proof : ProofRef();
}

ProofRegistrationState Processor::getLocalProofRegistrationState() const {
    AssertLockNotHeld(cs_peerManager);

    ProofRegistrationState state;
    if (!peerData) {
        return state;
    }

    if (peerData->proof) {
        LOCK(cs_peerManager);

        const ProofId &proofid = peerData->proof->getId();

        if (peerManager->isInConflictingPool(proofid)) {
            state.Invalid(ProofRegistrationResult::CONFLICTING,
                          "conflicting-utxos");
            return state;
        }

        if (peerManager->isInvalid(proofid)) {
            // If proof is invalid but verifies valid, it's been rejected by
            // avalanche
            state.Invalid(ProofRegistrationResult::INVALID,
                          "avalanche-invalidated");
            return state;
        }
    }

    return WITH_LOCK(peerData->cs_proofState, return peerData->proofState);
}

bool Processor::startEventLoop(CScheduler &scheduler) {
    return eventLoop.startEventLoop(
        scheduler, [this]() { this->runEventLoop(); }, AVALANCHE_TIME_STEP);
}

bool Processor::stopEventLoop() {
    return eventLoop.stopEventLoop();
}

void Processor::avaproofsSent(NodeId nodeid) {
    AssertLockNotHeld(cs_main);

    if (chainman.IsInitialBlockDownload()) {
        // Before IBD is complete there is no way to make sure a proof is valid
        // or not, e.g. it can be spent in a block we don't know yet. In order
        // to increase confidence that our proof set is similar to other nodes
        // on the network, the messages received during IBD are not accounted.
        return;
    }

    LOCK(cs_peerManager);
    if (peerManager->latchAvaproofsSent(nodeid)) {
        avaproofsNodeCounter++;
    }
}

/*
 * Returns a bool indicating whether we have a usable Avalanche quorum enabling
 * us to take decisions based on polls.
 */
bool Processor::isQuorumLatched() const {
    return quorumIsEstablished.load() &&
           peerManager->getQuorumMetrics().nodeCount >= minQuorumNodes;
}

Processor::QuorumFigures Processor::getQuorumFigures() const {
    const auto quorum{peerManager->getQuorumMetrics()};
    return {quorum.nodeCount, quorum.totalScore, quorum.connectedScore};
}

bool Processor::isQuorumEstablished() const NO_THREAD_SAFETY_ANALYSIS {
    const auto quorum = peerManager->getQuorumMetrics();
    if (quorum.nodeCount < minQuorumNodes) {
        // Keep upstream's unlatched eight-node eligibility rule.
        return false;
    }

    /*
     * The following parameters can naturally go temporarly below the threshold
     * under normal circumstances, like during a proof replacement with a lower
     * stake amount, or the discovery of a new proofs for which we don't have a
     * node yet.
     * In order to prevent our node from starting and stopping the polls
     * spuriously on such event, the quorum establishement is latched. The only
     * parameters that should not latched is the minimum node count, as this
     * would cause the poll to be inconclusive anyway and should not happen
     * under normal circumstances.
     */
    if (quorumIsEstablished) {
        return true;
    }

    // Don't do Avalanche while node is IBD'ing
    if (chainman.IsInitialBlockDownload()) {
        return false;
    }

    if (avaproofsNodeCounter < minAvaproofsNodeCount) {
        return false;
    }

    auto localProof = getLocalProof();

    // Read all peer metrics from the same published generation. Separate
    // independent atomic reads could mix pre- and post-update quorum state.
    const uint32_t totalPeersScore = quorum.totalScore;
    uint32_t connectedPeersScore = quorum.connectedScore;
    if (localProof && quorum.localProofHasNoNode) {
        connectedPeersScore += localProof->getScore();
    }

    // Ensure enough is being staked overall
    if (totalPeersScore < minQuorumScore) {
        return false;
    }

    // Ensure we have connected score for enough of the overall score
    uint32_t minConnectedScore =
        std::round(double(totalPeersScore) * minQuorumConnectedScoreRatio);
    if (connectedPeersScore < minConnectedScore) {
        return false;
    }

    if (minQuorumSupplyPermille > 0) {
        const BlockHash tipHash = WITH_LOCK(cs_activeTipHash, return m_activeTipHash);
        const uint64_t supply = GetV2BlockCirculatingSupply(tipHash);
        if (supply > 0 && uint64_t(std::max<int64_t>(0, quorum.totalStakedSatoshis)) * 1000 <
                              supply * minQuorumSupplyPermille) return false;
    }

    quorumIsEstablished.store(true);
    return true;
}

bool Processor::isQuorumEstablished() NO_THREAD_SAFETY_ANALYSIS {
    AssertLockNotHeld(cs_main);

    const bool wasEstablished = quorumIsEstablished.load();
    if (!std::as_const(*this).isQuorumEstablished()) {
        return false;
    }

    if (!wasEstablished) {
        // Attempt to compute the staking rewards winner now so we don't have to
        // wait for a block if we already have all the prerequisites.
        const CBlockIndex *pprev =
            WITH_LOCK(cs_main, return chainman.ActiveTip());
        bool computedRewards = false;
        if (pprev &&
            IsStakingRewardsActivated(chainman.GetConsensus(), pprev)) {
            computedRewards = computeStakingReward(pprev);
        }
        if (pprev && isStakingPreconsensusActivated(pprev) &&
            !computedRewards) {
            // It's possible to have quorum shortly after startup if peers were
            // loaded from disk, but staking rewards may not be ready yet. In
            // this case, we can still promote and poll for contenders.
            promoteAndPollStakeContenders(pprev);
        }
    }

    return true;
}

bool Processor::canShareLocalProof() {
    // The flag is latched
    if (m_canShareLocalProof) {
        return true;
    }

    // Don't share our proof if we don't have any inbound connection.
    // This is a best effort measure to prevent advertising a proof if we have
    // limited network connectivity.
    m_canShareLocalProof = connman->GetNodeCount(ConnectionDirection::In) > 0;

    return m_canShareLocalProof;
}

bool Processor::computeStakingReward(const CBlockIndex *pindex) {
    if (!pindex) {
        return false;
    }

    // If the quorum is not established there is no point picking a winner that
    // will be rejected.
    if (!isQuorumEstablished()) {
        return false;
    }

    {
        LOCK(cs_stakingRewards);
        if (stakingRewards.count(pindex->GetBlockHash()) > 0) {
            return true;
        }
    }

    StakingReward _stakingRewards;
    _stakingRewards.blockheight = pindex->nHeight;

    bool rewardsInserted = false;
    if (WITH_LOCK(cs_peerManager, return peerManager->selectStakingRewardWinner(
                                      pindex, _stakingRewards.winners))) {
        {
            LOCK(cs_stakingRewards);
            rewardsInserted =
                stakingRewards
                    .emplace(pindex->GetBlockHash(), std::move(_stakingRewards))
                    .second;
        }

        if (isStakingPreconsensusActivated(pindex)) {
            promoteAndPollStakeContenders(pindex);
        }
    }

    return rewardsInserted;
}

bool Processor::eraseStakingRewardWinner(const BlockHash &prevBlockHash) {
    LOCK(cs_stakingRewards);
    return stakingRewards.erase(prevBlockHash) > 0;
}

void Processor::cleanupStakingRewards(const int minHeight) {
    // Avoid cs_main => cs_peerManager reverse order locking
    AssertLockNotHeld(::cs_main);
    AssertLockNotHeld(cs_stakingRewards);
    AssertLockNotHeld(cs_peerManager);

    {
        LOCK(cs_stakingRewards);
        // std::erase_if is only defined since C++20
        for (auto it = stakingRewards.begin(); it != stakingRewards.end();) {
            if (it->second.blockheight < minHeight) {
                it = stakingRewards.erase(it);
            } else {
                ++it;
            }
        }
    }

    WITH_LOCK(cs_peerManager,
              return peerManager->cleanupStakeContenders(minHeight));
}

bool Processor::getStakingRewardWinners(
    const BlockHash &prevBlockHash,
    std::vector<std::pair<ProofId, CScript>> &winners) const {
    LOCK(cs_stakingRewards);
    auto it = stakingRewards.find(prevBlockHash);
    if (it == stakingRewards.end()) {
        return false;
    }

    winners = it->second.winners;
    return true;
}

bool Processor::getStakingRewardWinners(const BlockHash &prevBlockHash,
                                        std::vector<CScript> &payouts) const {
    std::vector<std::pair<ProofId, CScript>> winners;
    if (!getStakingRewardWinners(prevBlockHash, winners)) {
        return false;
    }

    payouts.clear();
    payouts.reserve(winners.size());
    for (auto &winner : winners) {
        payouts.push_back(std::move(winner.second));
    }

    return true;
}

bool Processor::setStakingRewardWinners(const CBlockIndex *pprev,
                                        const std::vector<CScript> &payouts) {
    assert(pprev);

    StakingReward stakingReward;
    stakingReward.blockheight = pprev->nHeight;

    stakingReward.winners.reserve(payouts.size());
    for (const CScript &payout : payouts) {
        stakingReward.winners.push_back({ProofId(), payout});
    }

    if (isStakingPreconsensusActivated(pprev)) {
        LOCK(cs_peerManager);
        peerManager->setStakeContenderWinners(pprev, payouts);
    }

    LOCK(cs_stakingRewards);
    return stakingRewards.insert_or_assign(pprev->GetBlockHash(), stakingReward)
        .second;
}

bool Processor::setStakingRewardWinners(
    const CBlockIndex *pprev,
    const std::vector<std::pair<ProofId, CScript>> &winners) {
    assert(pprev);

    StakingReward stakingReward;
    stakingReward.blockheight = pprev->nHeight;
    stakingReward.winners = winners;

    LOCK(cs_stakingRewards);
    return stakingRewards.insert_or_assign(pprev->GetBlockHash(), stakingReward)
        .second;
}

void Processor::FinalizeNode(const ::Config &config, const CNode &node) {
    AssertLockNotHeld(cs_main);

    const NodeId nodeid = node.GetId();
    WITH_LOCK(cs_batchPollPeers, batchPollPeers.erase(nodeid));
    WITH_LOCK(cs_peerManager, peerManager->removeNode(nodeid));
    WITH_LOCK(cs_delayedAvahelloNodeIds, delayedAvahelloNodeIds.erase(nodeid));
}

int Processor::getStakeContenderStatus(
    const StakeContenderId &contenderId) const {
    AssertLockNotHeld(cs_peerManager);
    AssertLockNotHeld(cs_stakingRewards);

    BlockHash prevblockhash;
    int status =
        WITH_LOCK(cs_peerManager, return peerManager->getStakeContenderStatus(
                                      contenderId, prevblockhash));

    if (status != -1) {
        std::vector<std::pair<ProofId, CScript>> winners;
        getStakingRewardWinners(prevblockhash, winners);
        if (winners.size() == 0) {
            // If we have not selected a local staking rewards winner yet,
            // indicate this contender is pending to avoid convergence issues.
            return -2;
        }
    }

    return status;
}

void Processor::acceptStakeContender(const StakeContenderId &contenderId) {
    LOCK(cs_peerManager);
    peerManager->acceptStakeContender(contenderId);
}

void Processor::finalizeStakeContender(const StakeContenderId &contenderId) {
    AssertLockNotHeld(cs_main);

    BlockHash prevblockhash;
    std::vector<std::pair<ProofId, CScript>> winners;
    {
        LOCK(cs_peerManager);
        peerManager->finalizeStakeContender(contenderId, prevblockhash,
                                            winners);
    }

    // Set staking rewards to include newly finalized contender
    if (winners.size() > 0) {
        const CBlockIndex *block = WITH_LOCK(
            cs_main,
            return chainman.m_blockman.LookupBlockIndex(prevblockhash));
        if (block) {
            setStakingRewardWinners(block, winners);
        }
    }
}

void Processor::rejectStakeContender(const StakeContenderId &contenderId) {
    LOCK(cs_peerManager);
    peerManager->rejectStakeContender(contenderId);
}

void Processor::setNodeMempoolBatchServices(NodeId nodeid, ServiceFlags services) {
    LOCK(cs_batchPollPeers);
    if (services & NODE_MERKLIX_EPOCH) batchPollPeers.insert(nodeid);
    else batchPollPeers.erase(nodeid);
}

bool Processor::nodeSupportsMempoolBatch(NodeId nodeid) const {
    LOCK(cs_batchPollPeers);
    return batchPollPeers.count(nodeid) != 0;
}

void Processor::promoteAndPollStakeContenders(const CBlockIndex *pprev) {
    assert(pprev);

    if (!isQuorumEstablished()) {
        // Avoid growing the contender cache before it's possible to clean it up
        // (by finalizing blocks).
        return;
    }

    {
        LOCK(cs_peerManager);
        peerManager->promoteStakeContendersToBlock(pprev);
    }

    // If staking rewards have not been computed yet, we will try again when
    // they have been.
    std::vector<StakeContenderId> pollableContenders;
    if (setContenderStatusForLocalWinners(pprev, pollableContenders)) {
        for (const StakeContenderId &contender : pollableContenders) {
            addToReconcile(contender);
        }
    }
}

bool Processor::setContenderStatusForLocalWinners(
    const CBlockIndex *pindex,
    std::vector<StakeContenderId> &pollableContenders) {
    const BlockHash prevblockhash = pindex->GetBlockHash();
    std::vector<std::pair<ProofId, CScript>> winners;
    getStakingRewardWinners(prevblockhash, winners);

    LOCK(cs_peerManager);
    return peerManager->setContenderStatusForLocalWinners(
        pindex, winners, AVALANCHE_CONTENDER_MAX_POLLABLE, pollableContenders);
}

void Processor::AdaptiveEpochController::recordPollRtt(
    std::chrono::milliseconds rtt) {
    recordPollRttMs(static_cast<double>(rtt.count()));
}

void Processor::AdaptiveEpochController::recordPollRttMs(double rttMs) {
    LOCK(m_cs);
    const double clampedRtt = std::max(0.1, rttMs);
    if (m_rttSampleCount == 0) {
        m_rttEwmaMs = clampedRtt;
        if (m_settlingWindowMs <= 0.0) {
            m_settlingWindowMs = clampedRtt;
        }
    } else {
        m_rttEwmaMs =
            (1.0 - m_ewmaAlpha) * m_rttEwmaMs + m_ewmaAlpha * clampedRtt;
        if (m_settlingWindowMs < m_rttEwmaMs) {
            m_settlingWindowMs = m_rttEwmaMs;
        }
    }
    ++m_rttSampleCount;
}

void Processor::AdaptiveEpochController::recordCleanFastPath() {
    LOCK(m_cs);
    ++m_fastPathFinalizedCount;
    m_missRateEwma = (1.0 - m_ewmaAlpha) * m_missRateEwma;

    const double floorMs = std::max(0.1, m_rttEwmaMs);
    if (m_settlingWindowMs > floorMs) {
        const double delta = std::max(floorMs * m_ewmaAlpha,
                                      (m_settlingWindowMs - floorMs) * 0.25);
        m_settlingWindowMs = std::max(floorMs, m_settlingWindowMs - delta);
    } else {
        m_settlingWindowMs = floorMs;
    }
}

void Processor::AdaptiveEpochController::recordMissOrConflict() {
    LOCK(m_cs);
    ++m_conflictOrMissCount;
    m_missRateEwma = (1.0 - m_ewmaAlpha) * m_missRateEwma + m_ewmaAlpha * 1.0;

    const double baseMs = std::max({0.1, m_settlingWindowMs, m_rttEwmaMs});
    const double maxWindowMs =
        static_cast<double>(AVALANCHE_DEFAULT_QUERY_TIMEOUT.count());
    m_settlingWindowMs = std::min(maxWindowMs, 2.0 * baseMs);
}

void Processor::AdaptiveEpochController::recordBatchFrozen(
    SteadyMilliseconds now) {
    LOCK(m_cs);
    m_lastFreezeTime = now;
}

bool Processor::AdaptiveEpochController::shouldPipelineNextBatch(
    size_t unfrozenTailTxCount, SteadyMilliseconds now) const {
    LOCK(m_cs);
    if (!m_autoPipelineEnabled || unfrozenTailTxCount == 0) {
        return false;
    }
    if (unfrozenTailTxCount >= m_minBatchTxCount) {
        return true;
    }
    if (m_lastFreezeTime.time_since_epoch().count() == 0) {
        return true;
    }
    const double elapsedMs =
        static_cast<double>((now - m_lastFreezeTime).count());
    return elapsedMs >= m_settlingWindowMs;
}

double Processor::AdaptiveEpochController::getRttEwmaMs() const {
    LOCK(m_cs);
    return m_rttEwmaMs;
}

double Processor::AdaptiveEpochController::getMissRateEwma() const {
    LOCK(m_cs);
    return m_missRateEwma;
}

double Processor::AdaptiveEpochController::getSettlingWindowMs() const {
    LOCK(m_cs);
    return m_settlingWindowMs;
}

std::chrono::milliseconds
Processor::AdaptiveEpochController::getSettlingWindow() const {
    LOCK(m_cs);
    return std::chrono::milliseconds(
        static_cast<int64_t>(std::llround(m_settlingWindowMs)));
}

void Processor::AdaptiveEpochController::setMinBatchTxCount(size_t minTxs) {
    LOCK(m_cs);
    m_minBatchTxCount = std::max<size_t>(1, minTxs);
}

size_t Processor::AdaptiveEpochController::getMinBatchTxCount() const {
    LOCK(m_cs);
    return m_minBatchTxCount;
}

void Processor::AdaptiveEpochController::setAutoPipelineEnabled(bool enabled) {
    LOCK(m_cs);
    m_autoPipelineEnabled = enabled;
}

bool Processor::AdaptiveEpochController::isAutoPipelineEnabled() const {
    LOCK(m_cs);
    return m_autoPipelineEnabled;
}

uint64_t Processor::AdaptiveEpochController::getRttSampleCount() const {
    LOCK(m_cs);
    return m_rttSampleCount;
}

uint64_t Processor::AdaptiveEpochController::getFastPathFinalizedCount() const {
    LOCK(m_cs);
    return m_fastPathFinalizedCount;
}

uint64_t Processor::AdaptiveEpochController::getConflictOrMissCount() const {
    LOCK(m_cs);
    return m_conflictOrMissCount;
}

bool Processor::registerMempoolBatch(const MempoolBatchAnnouncement &batch,
                                     bool accepted, bool reconcile) {
    if (!batch.IsValid()) {
        return false;
    }

    const uint256 batchId = batch.ComputeBatchId();
    bool slotConflictDetected = false;
    {
        LOCK(cs_mempoolBatches);
        const bool isNew =
            m_mempoolBatches.find(batchId) == m_mempoolBatches.end();
        if (isNew && m_mempoolBatches.size() >= MAX_MEMPOOL_BATCH_RECORDS) {
            // Evict the oldest unfinalized batch record first; fall back to the
            // oldest record if all tracked records are finalized.
            auto evictIt = m_mempoolBatchOrder.begin();
            for (auto it = m_mempoolBatchOrder.begin();
                 it != m_mempoolBatchOrder.end(); ++it) {
                auto mapIt = m_mempoolBatches.find(*it);
                if (mapIt == m_mempoolBatches.end()) {
                    evictIt = it;
                    break;
                }
                const auto finIt = m_finalizedMempoolBatches.find(
                    mapIt->second.prev_block_hash);
                const bool isFin =
                    finIt != m_finalizedMempoolBatches.end() &&
                    std::any_of(finIt->second.begin(), finIt->second.end(),
                                [&](const MempoolBatchAnnouncement &b) {
                                    return b.ComputeBatchId() == *it;
                                });
                if (!isFin) {
                    evictIt = it;
                    break;
                }
            }
            if (evictIt != m_mempoolBatchOrder.end()) {
                const uint256 evictId = *evictIt;
                m_mempoolBatchOrder.erase(evictIt);
                m_mempoolBatches.erase(evictId);
                m_acceptedMempoolBatches.erase(evictId);
            }
        }

        auto &epochMap = m_epochBatchBySlot[batch.prev_block_hash];
        auto slotIt = epochMap.find(batch.epoch_seq);
        if (slotIt == epochMap.end()) {
            epochMap.emplace(batch.epoch_seq, batchId);
        } else if (slotIt->second != batchId) {
            m_conflictedBatchEpochs[batch.prev_block_hash].insert(
                batch.epoch_seq);
            m_conflictedBatchIds.insert(slotIt->second);
            m_conflictedBatchIds.insert(batchId);
            slotConflictDetected = true;
        }
        if (m_conflictedBatchEpochs[batch.prev_block_hash].count(
                batch.epoch_seq) > 0) {
            m_conflictedBatchIds.insert(batchId);
        }

        m_mempoolBatches.insert_or_assign(batchId, batch);
        if (isNew) {
            m_mempoolBatchOrder.push_back(batchId);
        }
        // Preserve existing local acceptance if a peer echoes a batch we
        // already locally verified/accepted.
        if (accepted) {
            m_acceptedMempoolBatches.insert(batchId);
        }
    }

    if (slotConflictDetected) {
        m_adaptiveEpochController.recordMissOrConflict();
    }

    if (reconcile) {
        const MempoolBatchVoteItem item(batch);
        if (!isPolled(item)) {
            return addToReconcile(item);
        }
        if (accepted) {
            auto w = voteRecords.getWriteView();
            auto it = w->find(item);
            if (it != w.end() && it->second.getConfidence() == 0) {
                VoteRecord vr(true);
                vr.addedTime = it->second.addedTime;
                w->erase(it);
                w->insert(std::make_pair(item, vr));
            }
        }
    }
    return true;
}

bool Processor::setMempoolBatchAccepted(const uint256 &batchId, bool accepted) {
    {
        LOCK(cs_mempoolBatches);
        if (m_mempoolBatches.find(batchId) == m_mempoolBatches.end()) {
            return false;
        }
        if (accepted) {
            m_acceptedMempoolBatches.insert(batchId);
        } else {
            m_acceptedMempoolBatches.erase(batchId);
        }
    }

    const MempoolBatchVoteItem item(batchId);
    auto w = voteRecords.getWriteView();
    auto it = w->find(item);
    if (it != w.end() && it->second.getConfidence() == 0) {
        VoteRecord vr(accepted);
        vr.addedTime = it->second.addedTime;
        w->erase(it);
        w->insert(std::make_pair(item, vr));
    }
    return true;
}

bool Processor::getMempoolBatch(const uint256 &batchId,
                                MempoolBatchAnnouncement &outBatch) const {
    LOCK(cs_mempoolBatches);
    auto it = m_mempoolBatches.find(batchId);
    if (it == m_mempoolBatches.end()) {
        return false;
    }
    outBatch = it->second;
    return true;
}

bool Processor::isMempoolBatchKnown(const uint256 &batchId) const {
    LOCK(cs_mempoolBatches);
    return m_mempoolBatches.find(batchId) != m_mempoolBatches.end();
}

bool Processor::isMempoolBatchLocallyAccepted(const uint256 &batchId) const {
    LOCK(cs_mempoolBatches);
    return m_acceptedMempoolBatches.find(batchId) !=
           m_acceptedMempoolBatches.end();
}

bool Processor::isMempoolBatchFinalized(const uint256 &batchId) const {
    LOCK(cs_mempoolBatches);
    auto it = m_mempoolBatches.find(batchId);
    if (it == m_mempoolBatches.end()) {
        return false;
    }
    auto finIt = m_finalizedMempoolBatches.find(it->second.prev_block_hash);
    if (finIt == m_finalizedMempoolBatches.end()) {
        return false;
    }
    return std::any_of(finIt->second.begin(), finIt->second.end(),
                       [&](const MempoolBatchAnnouncement &b) {
                           return b.ComputeBatchId() == batchId;
                       });
}

bool Processor::hasMempoolBatchConflict(const uint256 &batchId) const {
    LOCK(cs_mempoolBatches);
    if (m_conflictedBatchIds.find(batchId) != m_conflictedBatchIds.end()) {
        return true;
    }
    auto it = m_mempoolBatches.find(batchId);
    if (it == m_mempoolBatches.end()) {
        return false;
    }
    auto epochIt = m_conflictedBatchEpochs.find(it->second.prev_block_hash);
    return epochIt != m_conflictedBatchEpochs.end() &&
           epochIt->second.count(it->second.epoch_seq) > 0;
}

bool Processor::hasEpochConflict(const BlockHash &prevBlockHash,
                                 uint32_t epochSeq) const {
    LOCK(cs_mempoolBatches);
    auto epochIt = m_conflictedBatchEpochs.find(prevBlockHash);
    return epochIt != m_conflictedBatchEpochs.end() &&
           epochIt->second.count(epochSeq) > 0;
}

void Processor::markMempoolBatchConflict(const uint256 &batchId) {
    LOCK(cs_mempoolBatches);
    m_conflictedBatchIds.insert(batchId);
    auto it = m_mempoolBatches.find(batchId);
    if (it != m_mempoolBatches.end()) {
        m_conflictedBatchEpochs[it->second.prev_block_hash].insert(
            it->second.epoch_seq);
    }
}

namespace {
MempoolBatchAnnouncement BuildBatchAnnouncementFromLayer(
    const BlockHash &prevBlockHash, uint32_t epochSeq,
    const uint256 &parentBatchId, const lotus::v2::MempoolOverlayLayer &layer) {
    MempoolBatchAnnouncement batch;
    batch.prev_block_hash = prevBlockHash;
    batch.epoch_seq = epochSeq;
    batch.parent_batch_id = parentBatchId;
    const auto subA = layer.GetSubtreeARoot();
    const auto utxoRoot = layer.GetUtxoRootDigest();
    std::memcpy(batch.subtree_a_root.begin(), subA.data(), 32);
    std::memcpy(batch.utxo_root.begin(), utxoRoot.data(), 32);
    batch.tx_count = static_cast<uint32_t>(layer.GetTxCount());

    HashWriter hasher{};
    for (const auto &[txId, _] : layer.GetOrderedTxs()) {
        hasher.write(std::as_bytes(std::span{txId}));
    }
    batch.short_ids_hash = hasher.GetHash();
    return batch;
}
} // namespace

void Processor::finalizeMempoolBatch(const uint256 &batchId) {
    MempoolBatchFinalizedCallback cb;
    MempoolBatchAnnouncement batch;
    bool newlyFinalized = false;

    {
        LOCK(cs_mempoolBatches);
        auto it = m_mempoolBatches.find(batchId);
        if (it == m_mempoolBatches.end()) {
            return;
        }
        batch = it->second;
        if (m_mempoolBatchParent &&
            batch.prev_block_hash != *m_mempoolBatchParent) {
            return;
        }
        m_acceptedMempoolBatches.insert(batchId);

        auto &vec = m_finalizedMempoolBatches[batch.prev_block_hash];
        const bool alreadyPresent = std::any_of(
            vec.begin(), vec.end(), [&](const MempoolBatchAnnouncement &b) {
                return b.ComputeBatchId() == batchId;
            });
        if (!alreadyPresent) {
            vec.push_back(batch);
            std::sort(vec.begin(), vec.end(),
                      [](const MempoolBatchAnnouncement &a,
                         const MempoolBatchAnnouncement &b) {
                          return a.epoch_seq < b.epoch_seq;
                      });
            newlyFinalized = true;
            cb = m_onMempoolBatchFinalized;
        }
    }

    if (newlyFinalized) {
        std::optional<MempoolBatchAnnouncement> pipelinedNextBatch;
        if (mempool) {
            LOCK(mempool->cs);
            lotus::v2::Hash target_root{};
            std::memcpy(target_root.data(), batch.subtree_a_root.begin(), 32);
            auto &overlay_mgr = mempool->GetOverlayManager();
            lotus::v2::Hash expectedParentBlock{};
            std::memcpy(expectedParentBlock.data(), batch.prev_block_hash.begin(), 32);
            bool already_frozen = false;
            for (const auto &frozen_layer : overlay_mgr.GetFrozenEpochs()) {
                if (frozen_layer.GetSubtreeARoot() == target_root) {
                    already_frozen = true;
                    break;
                }
            }
            if (!already_frozen &&
                overlay_mgr.GetSpeculativeOverlay().GetParentBlockId() == expectedParentBlock &&
                overlay_mgr.GetSpeculativeOverlay().GetSubtreeARoot() ==
                    target_root) {
                mempool->FreezeEpochBatch();
            }

            // Event-driven back-to-back pipelining: if the speculative overlay
            // has accumulated additional transactions beyond this finalized
            // batch and the adaptive controller allows pipelining, freeze and
            // announce Delta_{e+1} immediately.
            const auto &specOverlay = overlay_mgr.GetSpeculativeOverlay();
            if (specOverlay.GetParentBlockId() == expectedParentBlock &&
                specOverlay.GetTxCount() > batch.tx_count &&
                specOverlay.GetSubtreeARoot() != target_root) {
                const size_t tailTxCount =
                    specOverlay.GetTxCount() - batch.tx_count;
                const auto now = Now<SteadyMilliseconds>();
                if (m_adaptiveEpochController.shouldPipelineNextBatch(
                        tailTxCount, now)) {
                    const auto &nextLayer = mempool->FreezeEpochBatch();
                    pipelinedNextBatch = BuildBatchAnnouncementFromLayer(
                        batch.prev_block_hash, batch.epoch_seq + 1, batchId,
                        nextLayer);
                    m_adaptiveEpochController.recordBatchFrozen(now);
                }
            }

        }
        if (pipelinedNextBatch.has_value()) {
            registerMempoolBatch(*pipelinedNextBatch, /*accepted=*/true,
                                 /*reconcile=*/true);
        }
        const bool currentParent = WITH_LOCK(cs_mempoolBatches,
            return !m_mempoolBatchParent ||
                   *m_mempoolBatchParent == batch.prev_block_hash);
        if (cb && currentParent) {
            cb(batch);
        }
    }
}

bool Processor::tryFreezeAndRegisterNextEpochBatch(
    const BlockHash &prevBlockHash, MempoolBatchAnnouncement *outBatch,
    bool force) {
    if (!mempool) {
        return false;
    }

    uint32_t nextEpochSeq = 1;
    uint256 parentBatchId = uint256::ZERO;
    size_t baselineTxCount = 0;
    {
        LOCK(cs_mempoolBatches);
        auto finIt = m_finalizedMempoolBatches.find(prevBlockHash);
        if (finIt != m_finalizedMempoolBatches.end() &&
            !finIt->second.empty()) {
            const auto &lastFin = finIt->second.back();
            nextEpochSeq = lastFin.epoch_seq + 1;
            parentBatchId = lastFin.ComputeBatchId();
            baselineTxCount = lastFin.tx_count;
        }
    }

    std::optional<MempoolBatchAnnouncement> createdBatch;
    {
        LOCK(mempool->cs);
        auto &overlay_mgr = mempool->GetOverlayManager();
        const auto &specOverlay = overlay_mgr.GetSpeculativeOverlay();
        lotus::v2::Hash expectedParentBlock{};
        std::memcpy(expectedParentBlock.data(), prevBlockHash.begin(), 32);
        if (specOverlay.GetParentBlockId() != expectedParentBlock ||
            specOverlay.GetTxCount() <= baselineTxCount) {
            return false;
        }
        const size_t tailTxCount = specOverlay.GetTxCount() - baselineTxCount;
        const auto now = Now<SteadyMilliseconds>();
        if (!force && !m_adaptiveEpochController.shouldPipelineNextBatch(
                          tailTxCount, now)) {
            return false;
        }
        const auto &frozenLayer = mempool->FreezeEpochBatch();
        createdBatch = BuildBatchAnnouncementFromLayer(
            prevBlockHash, nextEpochSeq, parentBatchId, frozenLayer);
        m_adaptiveEpochController.recordBatchFrozen(now);
    }

    if (!registerMempoolBatch(*createdBatch, /*accepted=*/true,
                              /*reconcile=*/true)) {
        return false;
    }
    if (outBatch != nullptr) {
        *outBatch = *createdBatch;
    }
    return true;
}

void Processor::rejectMempoolBatch(const uint256 &batchId) {
    LOCK(cs_mempoolBatches);
    m_acceptedMempoolBatches.erase(batchId);
}

std::vector<MempoolBatchAnnouncement>
Processor::getFinalizedMempoolBatches(const BlockHash &prevBlockHash) const {
    LOCK(cs_mempoolBatches);
    auto it = m_finalizedMempoolBatches.find(prevBlockHash);
    if (it == m_finalizedMempoolBatches.end()) {
        return {};
    }
    return it->second;
}

bool Processor::getFinalizedBatchForBlock(
    const BlockHash &prevBlockHash, MempoolBatchAnnouncement &outBatch) const {
    LOCK(cs_mempoolBatches);
    auto it = m_finalizedMempoolBatches.find(prevBlockHash);
    if (it == m_finalizedMempoolBatches.end() || it->second.empty()) {
        return false;
    }
    outBatch = it->second.back();
    return true;
}

void Processor::setMempoolBatchFinalizedCallback(
    MempoolBatchFinalizedCallback cb) {
    LOCK(cs_mempoolBatches);
    m_onMempoolBatchFinalized = std::move(cb);
}

bool Processor::addTreasuryContender(const BlockHash &prevBlockHash,
                                     const std::vector<CTxOut> &outputs,
                                     bool isLocalWinner,
                                     TreasuryContenderId *outContenderId) {
    TreasuryContenderId cid;
    {
        LOCK(cs_treasury);
        if (!m_treasuryContenderCache.add(prevBlockHash, outputs, &cid)) {
            if (outContenderId) {
                *outContenderId = TreasuryContenderId();
            }
            return false;
        }
        if (outContenderId) {
            *outContenderId = cid;
        }
        if (isLocalWinner) {
            m_treasuryContenderCache.setLocalWinner(cid);
        }
    }

    return addToReconcile(cid);
}

TreasuryContenderId
Processor::addTreasuryContender(const BlockHash &prevBlockHash,
                                const std::vector<CTxOut> &outputs,
                                Amount totalReward) {
    TreasuryContenderId cid;
    {
        LOCK(cs_treasury);
        cid = m_treasuryContenderCache.add(prevBlockHash, outputs, totalReward);
    }
    addToReconcile(cid);
    return cid;
}

TreasuryContenderId Processor::registerDefaultTreasuryContender(
    const CBlockIndex *pindexPrev, Amount blockSubsidy,
    TreasuryContenderId *outContenderId) {
    if (!pindexPrev) {
        if (outContenderId) {
            *outContenderId = TreasuryContenderId();
        }
        return TreasuryContenderId();
    }
    return registerDefaultTreasuryContender(pindexPrev->GetBlockHash(),
                                            pindexPrev->nHeight, blockSubsidy,
                                            outContenderId);
}

TreasuryContenderId Processor::registerDefaultTreasuryContender(
    const BlockHash &prevBlockHash, int blockHeight, Amount blockSubsidy,
    TreasuryContenderId *outContenderId) {
    TreasuryContenderId cid;
    {
        LOCK(cs_treasury);
        cid = m_treasuryContenderCache.registerDefaultTreasuryContender(
            prevBlockHash, blockHeight, blockSubsidy, outContenderId);
    }
    if (!cid.IsNull()) {
        if (!isPolled(cid)) {
            addToReconcile(cid);
        } else {
            auto w = voteRecords.getWriteView();
            auto it = w->find(cid);
            if (it != w.end() && it->second.getConfidence() == 0) {
                w->erase(it);
                w->insert(std::make_pair(cid, VoteRecord(true)));
            }
        }
    }
    return cid;
}

void Processor::cleanupTreasuryContenders(const int minHeight) {
    LOCK(cs_treasury);
    m_treasuryContenderCache.cleanup(minHeight);
}

void Processor::cleanupTreasuryContenders(const BlockHash &keepBlockHash) {
    LOCK(cs_treasury);
    m_treasuryContenderCache.cleanup(keepBlockHash);
}

int Processor::getTreasuryContenderStatus(
    const TreasuryContenderId &contenderId) const {
    LOCK(cs_treasury);
    return m_treasuryContenderCache.getVoteStatus(contenderId);
}

bool Processor::getTreasuryContenderOutputs(
    const TreasuryContenderId &contenderId,
    std::vector<CTxOut> &outputs) const {
    LOCK(cs_treasury);
    return m_treasuryContenderCache.getOutputs(contenderId, outputs);
}

bool Processor::acceptTreasuryContender(
    const TreasuryContenderId &contenderId) {
    LOCK(cs_treasury);
    return m_treasuryContenderCache.accept(contenderId);
}

bool Processor::finalizeTreasuryContender(
    const TreasuryContenderId &contenderId) {
    LOCK(cs_treasury);
    return m_treasuryContenderCache.finalize(contenderId);
}

bool Processor::rejectTreasuryContender(
    const TreasuryContenderId &contenderId) {
    LOCK(cs_treasury);
    return m_treasuryContenderCache.reject(contenderId);
}

bool Processor::getTreasuryRewardWinner(const BlockHash &prevBlockHash,
                                        std::vector<CTxOut> &outputs) const {
    LOCK(cs_treasury);
    return m_treasuryContenderCache.getWinner(prevBlockHash, outputs);
}

bool Processor::setTreasuryRewardWinner(const BlockHash &prevBlockHash,
                                        const std::vector<CTxOut> &outputs) {
    LOCK(cs_treasury);
    TreasuryContenderId cid;
    if (!m_treasuryContenderCache.add(prevBlockHash, outputs, &cid)) {
        return false;
    }
    return m_treasuryContenderCache.finalize(cid);
}

void Processor::updatedBlockTip() {
    const bool registerLocalProof = canShareLocalProof();
    auto registerProofs = [&]() {
        LOCK(cs_peerManager);

        auto registeredProofs = peerManager->updatedBlockTip();

        ProofRegistrationState localProofState;
        if (peerData && peerData->proof && registerLocalProof) {
            if (peerManager->registerProof(peerData->proof, localProofState)) {
                registeredProofs.insert(peerData->proof);
            }

            if (localProofState.GetResult() ==
                ProofRegistrationResult::ALREADY_REGISTERED) {
                // If our proof already exists, that's fine but we don't want to
                // erase the state with a duplicated proof status, so let's
                // retrieve the proper state. It also means we are able to
                // update the status should the proof move from one pool to the
                // other.
                const ProofId &localProofId = peerData->proof->getId();
                if (peerManager->isImmature(localProofId)) {
                    localProofState.Invalid(ProofRegistrationResult::IMMATURE,
                                            "immature-proof");
                }
                if (peerManager->isInConflictingPool(localProofId)) {
                    localProofState.Invalid(
                        ProofRegistrationResult::CONFLICTING,
                        "conflicting-utxos");
                }
                if (peerManager->isBoundToPeer(localProofId)) {
                    localProofState = ProofRegistrationState();
                }
            }

            WITH_LOCK(peerData->cs_proofState,
                      peerData->proofState = std::move(localProofState));
        }

        return registeredProofs;
    };

    auto registeredProofs = registerProofs();
    for (const auto &proof : registeredProofs) {
        reconcileOrFinalize(proof);
    }

    const CBlockIndex *activeTip =
        WITH_LOCK(cs_main, return chainman.ActiveTip());
    if (activeTip) {
        {
            LOCK(cs_mempoolBatches);
            m_mempoolBatchParent = activeTip->GetBlockHash();
            std::erase_if(m_finalizedMempoolBatches, [&](const auto &entry) {
                return entry.first != *m_mempoolBatchParent;
            });
            std::erase_if(m_mempoolBatches, [&](const auto &entry) {
                if (entry.second.prev_block_hash == *m_mempoolBatchParent) return false;
                m_acceptedMempoolBatches.erase(entry.first);
                m_conflictedBatchIds.erase(entry.first);
                return true;
            });
            std::erase_if(m_mempoolBatchOrder, [&](const auto &id) {
                return !m_mempoolBatches.contains(id);
            });
            std::erase_if(m_conflictedBatchIds, [&](const auto &id) {
                return !m_mempoolBatches.contains(id);
            });
            std::erase_if(m_epochBatchBySlot, [&](const auto &entry) {
                return entry.first != *m_mempoolBatchParent;
            });
            std::erase_if(m_conflictedBatchEpochs, [&](const auto &entry) {
                return entry.first != *m_mempoolBatchParent;
            });
        }
        WITH_LOCK(cs_activeTipHash,
                  m_activeTipHash = activeTip->GetBlockHash());
    }
    if (activeTip && isStakingPreconsensusActivated(activeTip)) {
        promoteAndPollStakeContenders(activeTip);
    }
    if (activeTip && IsTreasuryActivated(chainman.GetConsensus(), activeTip) &&
        (gArgs.IsArgSet("-avalanchetreasuryaddress") ||
         gArgs.GetBoolArg("-avalanchedefaulttreasury", false) ||
         gArgs.GetBoolArg("-avalancheusedefaulttreasury", false))) {
        const Amount nextBlockSubsidy =
            GetBlockSubsidy(activeTip->nHeight + 1, chainman.GetConsensus());
        registerDefaultTreasuryContender(activeTip, nextBlockSubsidy);
    }
}

void Processor::transactionAddedToMempool(const CTransactionRef &tx) {
    // Activation depends on the configured gate and finalized tip, not the
    // active chain tip. Do not serialize notifications behind chain validation.
    if (isPreconsensusActivated(nullptr)) {
        addToReconcile(tx);
    }
}

void Processor::runEventLoop() {
    // Don't poll if quorum hasn't been established yet
    if (!isQuorumEstablished()) {
        return;
    }

    // First things first, check if we have requests that timed out and clear
    // them.
    clearTimedoutRequests();

    clearInvsNotWorthPolling();

    NodeId nodeid{NO_NODE};
    do {
        std::vector<CInv> invs;

        {
            // Build a unique pointer to the read view of vote records.
            // This is so we can release the lock immediately after we have
            // gathered the invs to poll and avoid a lock inversion with the
            // peer manager lock.
            auto voteRecordsReadView =
                std::make_unique<decltype(voteRecords.getReadView())>(
                    voteRecords.getReadView());

            LOCK(cs_peerManager);

            // Make sure there is at least one suitable node to query before
            // gathering invs.
            // Classify pollable work once. Skip capability-ineligible nodes
            // within the selected weighted proof without fake queries, slot
            // reservations, or changes to ordinary poll cooldowns.
            bool regular = false, batches = false;
            for (const auto &[item, record] : *voteRecordsReadView) {
                if (!record.shouldPoll()) continue;
                if (std::holds_alternative<const MempoolBatchVoteItem>(item)) batches = true;
                else regular = true;
            }
            // No peer is needed when no item can be polled. Passing an
            // always-false capability predicate to selectNode would falsely
            // report a peer shortage and keep requesting every peer's address.
            if (!regular && !batches) {
                return;
            }
            nodeid = peerManager->selectNode([&](NodeId id) {
                return regular || (batches && nodeSupportsMempoolBatch(id));
            });
            if (nodeid == NO_NODE) {
                return;
            }

            size_t max_elements = AVALANCHE_MAX_ELEMENT_POLL_LEGACY;
            peerManager->forNode(nodeid, [&max_elements](const Node &node) {
                max_elements = node.maxElements;
                return true;
            });

            invs = getInvsForNextPoll(*voteRecordsReadView, max_elements,
                                      /*forPoll=*/true, nodeSupportsMempoolBatch(nodeid));
            if (invs.empty()) {
                return;
            }

            // Release the read lock on vote records
            voteRecordsReadView.reset();

            /**
             * If we lost contact to that node, then we remove it from nodeids,
             * but never add the request to queries, which ensures bad nodes get
             * cleaned up over time. Keep a copy of invs for inflight rollback
             * if the send fails (registerPoll already ran during gather).
             */
            bool hasSent = connman->ForNode(
                nodeid, [this, invs](CNode *pnode) EXCLUSIVE_LOCKS_REQUIRED(
                            cs_peerManager) mutable {
                    uint64_t current_round = round++;

                    {
                        // Compute the time at which this requests times out.
                        auto timeout = Now<SteadyMilliseconds>() +
                                       avaconfig.queryTimeoutDuration;
                        // Register the query.
                        queries.getWriteView()->insert(
                            {pnode->GetId(), current_round, timeout, invs});
                        // Set the timeout.
                        peerManager->updateNextRequestTimeForPoll(
                            pnode->GetId(), timeout, current_round);
                    }

                    pnode->invsPolled(invs.size());
                    if (auto *metrics{node::GetNodeMetrics()}) {
                        metrics->avalanche_polls_sent.Inc();
                        metrics->avalanche_poll_items_sent.Add(0, invs.size());
                    }

                    // Send the query to the node.
                    connman->PushMessage(
                        pnode,
                        NetMsg::Make(NetMsgType::AVAPOLL,
                                     Poll(current_round, std::move(invs))));
                    return true;
                });

            // Success!
            if (hasSent) {
                return;
            }

            // This node is obsolete, delete it.
            peerManager->removeNode(nodeid);
        }

        // Roll back inflight counters for the polls that were never dispatched.
        // Done after releasing cs_peerManager to avoid lock inversion with
        // voteRecords.
        clearInflightRequests(invs);
    } while (nodeid != NO_NODE);
}

void Processor::clearInvsNotWorthPolling() {
    auto w = voteRecords.getWriteView();
    for (auto it = w->begin(); it != w->end();) {
        if (!isWorthPolling(it->first)) {
            it = w->erase(it);
        } else {
            ++it;
        }
    }
}

void Processor::clearTimedoutRequests() {
    auto now = Now<SteadyMilliseconds>();
    std::map<CInv, uint8_t> timedout_items{};

    {
        // Clear expired requests.
        auto w = queries.getWriteView();
        auto it = w->get<query_timeout>().begin();
        while (it != w->get<query_timeout>().end() && it->timeout < now) {
            for (const auto &i : it->invs) {
                timedout_items[i]++;
            }

            w->get<query_timeout>().erase(it++);
        }
    }

    clearInflightRequests(timedout_items);
}

void Processor::clearInflightRequests(const std::vector<CInv> &invs) {
    std::map<CInv, uint8_t> counts;
    for (const CInv &inv : invs) {
        counts[inv]++;
    }
    clearInflightRequests(counts);
}

void Processor::clearInflightRequests(
    const std::map<CInv, uint8_t> &inflightRequests) {
    if (inflightRequests.empty()) {
        return;
    }

    auto voteRecordsReadView = voteRecords.getReadView();
    for (const auto &inflightRequest : inflightRequests) {
        auto item = getVoteItemFromInv(inflightRequest.first);

        if (isNull(item)) {
            continue;
        }

        auto it = voteRecordsReadView->find(item);
        if (it == voteRecordsReadView.end()) {
            continue;
        }

        it->second.clearInflightRequest(inflightRequest.second);
    }
}

std::vector<CInv> Processor::getInvsForNextPoll(
    RWCollection<VoteMap>::ReadView &voteRecordsReadView, size_t max_elements,
    bool forPoll, bool include_mempool_batches) const {
    std::vector<CInv> invs;

    auto buildInvFromVoteItem = variant::overloaded{
        [](const ProofRef &proof) {
            return CInv(MSG_AVA_PROOF, proof->getId());
        },
        [](const CBlockIndex *pindex) {
            return CInv(MSG_BLOCK, pindex->GetBlockHash());
        },
        [](const StakeContenderId &contenderId) {
            return CInv(MSG_AVA_STAKE_CONTENDER, contenderId);
        },
        [](const MempoolBatchVoteItem &batch) { return CInv(MSG_AVA_MEMPOOL_BATCH, batch.GetId()); },
        [](const TreasuryContenderId &contenderId) {
            return CInv(MSG_AVA_TREASURY_CONTENDER, contenderId);
        },
        [](const CTransactionRef &tx) { return CInv(MSG_TX, tx->GetId()); },
    };

    for (const auto &[item, voteRecord] : voteRecordsReadView) {
        if (invs.size() >= max_elements) {
            // Make sure we do not produce more invs than specified by the
            // protocol.
            return invs;
        }

        if (!include_mempool_batches &&
            std::holds_alternative<const MempoolBatchVoteItem>(item)) {
            continue;
        }

        const bool shouldPoll =
            forPoll ? voteRecord.registerPoll() : voteRecord.shouldPoll();

        if (!shouldPoll) {
            continue;
        }

        invs.emplace_back(std::visit(buildInvFromVoteItem, item));
    }

    return invs;
}

AnyVoteItem Processor::getVoteItemFromInv(const CInv &inv) const {
    if (inv.IsMsgBlk()) {
        return WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(
                                      BlockHash(inv.hash)));
    }

    if (inv.IsMsgProof()) {
        return WITH_LOCK(cs_peerManager,
                         return peerManager->getProof(ProofId(inv.hash)));
    }

    if (inv.IsMsgStakeContender()) {
        return StakeContenderId(inv.hash);
    }

    if (inv.IsMsgTreasuryContender()) {
        return TreasuryContenderId(inv.hash);
    }

    if (inv.IsMsgMempoolBatch()) {
        MempoolBatchAnnouncement batch;
        if (getMempoolBatch(inv.hash, batch)) {
            return MempoolBatchVoteItem(batch);
        }
        return {nullptr};
    }



    if (mempool && inv.IsMsgTx()) {
        LOCK(mempool->cs);
        if (CTransactionRef tx = mempool->get(TxId(inv.hash))) {
            return tx;
        }
        if (CTransactionRef tx = mempool->withConflicting(
                [&inv](const TxConflicting &conflicting) {
                    return conflicting.GetTx(TxId(inv.hash));
                })) {
            return tx;
        }
    }

    return {nullptr};
}

bool Processor::IsWorthPolling::operator()(const CBlockIndex *pindex) const {
    AssertLockNotHeld(cs_main);

    LOCK(cs_main);

    if (pindex->nStatus.isInvalid()) {
        // No point polling invalid blocks.
        return false;
    }

    if (WITH_LOCK(processor.cs_finalizationTip,
                  return processor.finalizationTip &&
                         processor.finalizationTip->GetAncestor(
                             pindex->nHeight) == pindex)) {
        // There is no point polling blocks that are ancestor of a block that
        // has been accepted by the network.
        return false;
    }

    if (WITH_LOCK(processor.cs_invalidatedBlocks,
                  return processor.invalidatedBlocks.contains(
                      pindex->GetBlockHash()))) {
        // Blocks invalidated by Avalanche should not be polled twice.
        return false;
    }

    return true;
}

bool Processor::IsWorthPolling::operator()(const ProofRef &proof) const {
    // Avoid lock order issues cs_main -> cs_peerManager
    AssertLockNotHeld(::cs_main);
    AssertLockNotHeld(processor.cs_peerManager);

    const ProofId &proofid = proof->getId();

    LOCK(processor.cs_peerManager);

    // No point polling immature or discarded proofs
    return processor.peerManager->isBoundToPeer(proofid) ||
           processor.peerManager->isInConflictingPool(proofid);
}

bool Processor::IsWorthPolling::operator()(
    const StakeContenderId &contenderId) const {
    AssertLockNotHeld(processor.cs_peerManager);
    AssertLockNotHeld(processor.cs_stakingRewards);

    // Only worth polling for contenders that we know about
    return processor.getStakeContenderStatus(contenderId) != -1;
}

bool Processor::IsWorthPolling::operator()(
    const MempoolBatchVoteItem &batch) const {
    AssertLockNotHeld(processor.cs_mempoolBatches);
    return processor.isMempoolBatchKnown(batch.GetId());
}

bool Processor::IsWorthPolling::operator()(
    const TreasuryContenderId &contenderId) const {
    AssertLockNotHeld(processor.cs_treasury);
    return processor.getTreasuryContenderStatus(contenderId) != -1;
}



bool Processor::IsWorthPolling::operator()(const CTransactionRef &tx) const {
    if (!processor.mempool) {
        return false;
    }

    AssertLockNotHeld(processor.mempool->cs);
    return WITH_LOCK(processor.mempool->cs,
                     return processor.mempool->isWorthPolling(tx));
}

bool Processor::isWorthPolling(const AnyVoteItem &item) const {
    return !isRecentlyFinalized(GetVoteItemId(item)) &&
           std::visit(IsWorthPolling(*this), item);
}

bool Processor::GetLocalAcceptance::operator()(
    const CBlockIndex *pindex) const {
    AssertLockNotHeld(cs_main);

    return WITH_LOCK(cs_main,
                     return processor.chainman.ActiveChain().Contains(pindex));
}

bool Processor::GetLocalAcceptance::operator()(const ProofRef &proof) const {
    AssertLockNotHeld(processor.cs_peerManager);

    return WITH_LOCK(
        processor.cs_peerManager,
        return processor.peerManager->isBoundToPeer(proof->getId()));
}

bool Processor::GetLocalAcceptance::operator()(
    const StakeContenderId &contenderId) const {
    AssertLockNotHeld(processor.cs_peerManager);
    AssertLockNotHeld(processor.cs_stakingRewards);

    return processor.getStakeContenderStatus(contenderId) == 0;
}

bool Processor::GetLocalAcceptance::operator()(
    const MempoolBatchVoteItem &batch) const {
    AssertLockNotHeld(processor.cs_mempoolBatches);
    return processor.isMempoolBatchLocallyAccepted(batch.GetId());
}

bool Processor::GetLocalAcceptance::operator()(
    const TreasuryContenderId &contenderId) const {
    AssertLockNotHeld(processor.cs_treasury);
    return processor.getTreasuryContenderStatus(contenderId) == 0;
}



bool Processor::GetLocalAcceptance::operator()(
    const CTransactionRef &tx) const {
    if (!processor.mempool) {
        return false;
    }

    AssertLockNotHeld(processor.mempool->cs);

    return WITH_LOCK(processor.mempool->cs,
                     return processor.mempool->exists(tx->GetId()));
}

bool Processor::isPreconsensusActivated(const CBlockIndex *pprev) const {
    // Require at least one avalanche-finalized block so we rely on a finalized
    // utxo set.
    return m_preConsensus && hasFinalizedTip();
}

bool Processor::isStakingPreconsensusActivated(const CBlockIndex *pprev) const {
    return m_stakingPreConsensus;
}

} // namespace avalanche
