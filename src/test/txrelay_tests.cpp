// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Nucleation relay: fixed relay tick and the transaction announcement path.

#include <net_processing.h>

#include <config.h>
#include <common/args.h>
#include <lotus_v2/commitment.h>
#include <net.h>
#include <net/txrelay_index.h>
#include <node/snapshot.h>

#include <net/v2_protocol_handler.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <script/standard.h>
#include <stdexcept>
#include <streams.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/net.h>
#include <test/util/admission.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <future>
#include <thread>
#include <map>
#include <memory>
#include <set>
#include <vector>

using namespace std::chrono_literals;

namespace {

CService MakeTestIp(uint32_t i) {
    struct in_addr s;
    s.s_addr = i;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

/** A standalone transaction (unfunded inputs are fine for addUnchecked) */
CTransactionRef MakeTx(FastRandomContext &rng,
                       const std::vector<COutPoint> &prevouts = {}) {
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    if (prevouts.empty()) {
        mtx.vin.emplace_back(COutPoint(TxId(rng.rand256()), 0));
    } else {
        for (const auto &prevout : prevouts) {
            mtx.vin.emplace_back(prevout);
        }
    }
    mtx.vin[0].scriptSig = CScript() << std::vector<uint8_t>(32, 0x42);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 10000 * SATOSHI;
    mtx.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_TRUE));
    return MakeTransactionRef(std::move(mtx));
}

/** Transaction announcements one peer was sent */
struct Sent {
    std::vector<TxId> inv_txids;
    std::vector<TxId> shorttx_txids;
    //! invshort announcements: (epoch_id, short id)
    std::vector<std::pair<uint256, uint64_t>> short_ids;
    //! getshorttx requests
    std::vector<lotus::v2::net::ShortTxRequest> short_requests;
    //! merklixsync summaries
    std::vector<lotus::v2::net::MerklixSyncSummary> summaries;
    size_t Total() const {
        return inv_txids.size() + shorttx_txids.size() + short_ids.size();
    }
};

/** A PeerManager with full-relay peers, driven by a mocked relay tick clock */
struct RelayHarness {
    const Config &config;
    std::unique_ptr<ConnmanTestMsg> connman;
    std::unique_ptr<PeerManager> peerman;
    //! Owned by connman (deleted by ClearTestNodes)
    std::vector<CNode *> nodes;

    RelayHarness(node::NodeContext &node_ctx, PeerManager::Options peer_opts)
        : config{node_ctx.chainman->GetConfig()} {
        connman = std::make_unique<ConnmanTestMsg>(config, 123, 456,
                                                   *node_ctx.addrman);
        peer_opts.deterministic_rng = true;
        peerman = PeerManager::make(*connman, *node_ctx.addrman, nullptr,
                                    *node_ctx.chainman, *node_ctx.mempool,
                                    nullptr, peer_opts);
        CConnman::Options opts;
        opts.m_msgproc = {peerman.get()};
        opts.nSendBufferMaxSize = 16 * 1024 * 1024;
        connman->Init(opts);
    }

    ~RelayHarness() {
        for (CNode *node : nodes) {
            peerman->FinalizeNode(config, *node);
        }
        connman->ClearTestNodes();
    }

    CNode &AddPeer(ConnectionType type = ConnectionType::OUTBOUND_FULL_RELAY)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        const NodeId id = NodeId(500 + nodes.size());
        CAddress addr(MakeTestIp(0x0a000001 + uint32_t(nodes.size())),
                      NODE_NONE);
        nodes.push_back(new CNode(id, nullptr, addr, 0, 0, 0, CAddress(), "",
                                  type, type == ConnectionType::INBOUND));
        CNode &node = *nodes.back();
        connman->Handshake(node, true, NODE_NETWORK, NODE_NETWORK,
                           PROTOCOL_VERSION, true);
        connman->AddTestNode(node);
        return node;
    }

    /** Run SendMessages for every peer and collect what each was sent */
    std::map<NodeId, Sent> SendAll()
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        std::map<NodeId, Sent> out;
        for (auto &node : nodes) {
            BOOST_CHECK(peerman->SendMessages(config, node));
            out[node->GetId()] = Drain(*node);
        }
        return out;
    }

    Sent Drain(CNode &node) {
        Sent sent;
        V1TransportDeserializer deserializer(config, node.GetId());
        LOCK(node.cs_vSend);
        for (const auto &chunk : node.vSendMsg) {
            Span<const uint8_t> bytes{chunk};
            while (!bytes.empty()) {
                BOOST_REQUIRE_GE(deserializer.Read(config, bytes), 0);
                if (!deserializer.Complete()) {
                    continue;
                }
                bool rejected = false;
                auto msg = deserializer.GetMessage(0us, rejected);
                BOOST_CHECK(!rejected);
                if (msg.m_type == NetMsgType::INV) {
                    std::vector<CInv> invs;
                    msg.m_recv >> invs;
                    for (const auto &inv : invs) {
                        if (inv.IsMsgTx()) {
                            sent.inv_txids.emplace_back(inv.hash);
                        }
                    }
                } else if (msg.m_type == NetMsgType::INVSHORT) {
                    uint256 epoch_id;
                    std::vector<uint64_t> ids;
                    msg.m_recv >> epoch_id >> ids;
                    for (const uint64_t id : ids) {
                        sent.short_ids.emplace_back(epoch_id, id);
                    }
                } else if (msg.m_type == NetMsgType::MERKLIXSYNC) {
                    lotus::v2::net::MerklixSyncSummary summary;
                    msg.m_recv >> summary;
                    sent.summaries.push_back(std::move(summary));
                } else if (msg.m_type == NetMsgType::GETSHORTTX) {
                    lotus::v2::net::ShortTxRequest req;
                    msg.m_recv >> req;
                    sent.short_requests.push_back(std::move(req));
                } else if (msg.m_type == NetMsgType::SHORTTX) {
                    lotus::v2::net::ShortTxResponse response;
                    msg.m_recv >> response;
                    for (const auto &tx : response.txs) {
                        sent.shorttx_txids.push_back(tx->GetId());
                    }
                }
            }
        }
        node.vSendMsg.clear();
        return sent;
    }
};

/** Mock the relay tick clock (MockableSteadyClock) for one test */
struct MockTick {
    explicit MockTick(std::chrono::milliseconds start) { Set(start); }
    ~MockTick() { MockableSteadyClock::ClearMockTime(); }
    void Set(std::chrono::milliseconds t) {
        MockableSteadyClock::SetMockTime(t);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(txrelay_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(burst_precompute_preserves_receive_slots) {
    FastRandomContext rng;
    std::vector<CTransactionRef> txs;
    for (size_t i = 0; i < 24; ++i) txs.push_back(MakeTx(rng));
    // Repeated bodies, a null slot and a malformed member must not shift
    // results onto a different transaction or suppress subsequent work.
    txs[2] = txs[0];
    txs[7].reset();
    CMutableTransaction duplicate_inputs(*txs[11]);
    duplicate_inputs.vin.push_back(duplicate_inputs.vin.front());
    txs[11] = MakeTransactionRef(std::move(duplicate_inputs));
    const auto checks = PrecomputeTxRelayBatch(txs);
    BOOST_REQUIRE_EQUAL(checks.size(), txs.size());
    for (size_t i = 0; i < txs.size(); ++i) {
        const auto &check = checks[i];
        BOOST_CHECK_EQUAL(check.regular_tx_checked, bool(txs[i]));
        if (txs[i]) {
            BOOST_CHECK(check.txid == txs[i]->GetId());
            BOOST_CHECK_EQUAL(check.regular_tx_valid, i != 11);
        }
        // Precomputation cannot manufacture a reusable script verdict.
        BOOST_CHECK(check.spent_outputs.empty());
        BOOST_CHECK(!check.standard.ran);
        BOOST_CHECK(!check.consensus.ran);
    }
    BOOST_CHECK_EQUAL(checks[11].regular_tx_state.GetRejectReason(),
                      "bad-txns-inputs-duplicate");
    BOOST_CHECK(PrecomputeTxRelayBatch({}).empty());
    const auto one = PrecomputeTxRelayBatch({txs[0]});
    BOOST_REQUIRE_EQUAL(one.size(), 1U);
    BOOST_CHECK(one[0].regular_tx_valid);
}

BOOST_FIXTURE_TEST_CASE(burst_precompute_keeps_signature_verification,
                        TestChain100Setup) {
    auto wallet = admission_test::MakeWallet();
    admission_test::FundWallet(*this, wallet, 8);
    std::vector<CTransactionRef> txs;
    for (const auto &output : wallet.outputs) {
        txs.push_back(admission_test::SignedSpend(wallet, {output}, 1, true));
    }
    CMutableTransaction bad_signature(*txs[3]);
    bad_signature.vin[0].scriptSig[5] ^= 1;
    txs[3] = MakeTransactionRef(std::move(bad_signature));
    const auto checks = PrecomputeTxRelayBatch(txs);
    BOOST_REQUIRE_EQUAL(checks.size(), txs.size());
    LOCK(cs_main);
    for (size_t i = 0; i < txs.size(); ++i) {
        BOOST_REQUIRE(checks[i].regular_tx_valid);
        const auto ordinary = m_node.chainman->ProcessTransaction(
            txs[i], /*test_accept=*/true);
        const auto staged = m_node.chainman->ProcessTransaction(
            txs[i], /*test_accept=*/true, {}, &checks[i]);
        BOOST_CHECK(ordinary.m_result_type == staged.m_result_type);
        BOOST_CHECK_EQUAL(ordinary.m_state.GetRejectReason(),
                          staged.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(staged.m_state.IsValid(), i != 3);
        // Even a valid regular result from another slot is advisory only.
        const auto mismatched = m_node.chainman->ProcessTransaction(
            txs[i], /*test_accept=*/true, {}, &checks[(i + 1) % checks.size()]);
        BOOST_CHECK(mismatched.m_result_type == ordinary.m_result_type);
        BOOST_CHECK_EQUAL(mismatched.m_state.GetRejectReason(),
                          ordinary.m_state.GetRejectReason());
    }
    LOCK(m_node.mempool->cs);
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}

BOOST_AUTO_TEST_CASE(relay_tick_alignment) {
    constexpr auto tick{std::chrono::microseconds{10ms}};
    // Strictly after now, on a multiple of the tick.
    BOOST_CHECK(NextRelayTick(0us, tick) == 10ms);
    BOOST_CHECK(NextRelayTick(1us, tick) == 10ms);
    BOOST_CHECK(NextRelayTick(9999us, tick) == 10ms);
    BOOST_CHECK(NextRelayTick(10ms, tick) == 20ms);
    BOOST_CHECK(NextRelayTick(10001us, tick) == 20ms);
    BOOST_CHECK(NextRelayTick(123'456'789us, tick) == 123'460ms);
    // Two peers that sent at different times within the same tick next
    // send at the same boundary.
    BOOST_CHECK(NextRelayTick(20'001us, tick) == NextRelayTick(29'999us, tick));
    for (int64_t t = 0; t < 100'000; t += 777) {
        const auto next{NextRelayTick(std::chrono::microseconds{t}, tick)};
        BOOST_CHECK(next > std::chrono::microseconds{t});
        BOOST_CHECK(next - std::chrono::microseconds{t} <= tick);
        BOOST_CHECK_EQUAL(next.count() % tick.count(), 0);
    }
    // A non-positive tick sends immediately.
    BOOST_CHECK(NextRelayTick(5us, 0us) == 5us);
}

BOOST_AUTO_TEST_CASE(peers_share_one_relay_tick) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    MockTick clock{1'000'001ms};
    PeerManager::Options opts;
    opts.txrelay_tick = 10ms;
    RelayHarness h{m_node, opts};
    CNode &outbound = h.AddPeer(ConnectionType::OUTBOUND_FULL_RELAY);
    // The first SendMessages after the handshake makes a peer relay-ready.
    BOOST_CHECK(h.peerman->SendMessages(h.config, &outbound));
    h.Drain(outbound);
    clock.Set(1'000'004ms);
    CNode &inbound = h.AddPeer(ConnectionType::INBOUND);
    BOOST_CHECK(h.peerman->SendMessages(h.config, &inbound));
    h.Drain(inbound);

    FastRandomContext rng{true};
    std::vector<CTransactionRef> txs;
    TestMemPoolEntryHelper entry;
    for (int i = 0; i < 5; ++i) {
        txs.push_back(MakeTx(rng));
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->addUnchecked(entry.FromTx(txs.back()));
    }
    h.peerman->RelayTransactionBatch(txs);

    // Within the tick: nothing yet, for either peer.
    clock.Set(1'000'009ms);
    for (const auto &[id, sent] : h.SendAll()) {
        BOOST_CHECK_EQUAL(sent.Total(), 0U);
    }
    // At the shared boundary both peers announce everything.
    clock.Set(1'000'010ms);
    for (const auto &[id, sent] : h.SendAll()) {
        BOOST_CHECK_EQUAL(sent.Total(), txs.size());
    }
    // Nothing is announced twice.
    clock.Set(1'000'020ms);
    for (const auto &[id, sent] : h.SendAll()) {
        BOOST_CHECK_EQUAL(sent.Total(), 0U);
    }

    // A transaction queued just after a boundary waits for the next one.
    auto late{MakeTx(rng)};
    {
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->addUnchecked(entry.FromTx(late));
    }
    clock.Set(1'000'021ms);
    h.peerman->RelayTransaction(late->GetId());
    for (const auto &[id, sent] : h.SendAll()) {
        BOOST_CHECK_EQUAL(sent.Total(), 0U);
    }
    clock.Set(1'000'030ms);
    for (const auto &[id, sent] : h.SendAll()) {
        BOOST_REQUIRE_EQUAL(sent.inv_txids.size(), 1U);
        BOOST_CHECK(sent.inv_txids[0] == late->GetId());
    }
}

BOOST_AUTO_TEST_CASE(fanout_formula) {
    // clamp(max(min, ceil(pct x n)), min, max)
    BOOST_CHECK_EQUAL(TxRelayFanout(0, 8, 0.25, 32), 8U);
    BOOST_CHECK_EQUAL(TxRelayFanout(4, 8, 0.25, 32), 8U);  // n < min
    BOOST_CHECK_EQUAL(TxRelayFanout(32, 8, 0.25, 32), 8U); // pct x n == min
    BOOST_CHECK_EQUAL(TxRelayFanout(33, 8, 0.25, 32), 9U); // ceil
    BOOST_CHECK_EQUAL(TxRelayFanout(40, 8, 0.25, 32), 10U);
    BOOST_CHECK_EQUAL(TxRelayFanout(128, 8, 0.25, 32), 32U); // == max
    BOOST_CHECK_EQUAL(TxRelayFanout(129, 8, 0.25, 32), 32U); // capped
    BOOST_CHECK_EQUAL(TxRelayFanout(5000, 8, 0.25, 32), 32U);
    // Floating point: 0.1 x 30 must stay 3, not become 4.
    BOOST_CHECK_EQUAL(TxRelayFanout(30, 1, 0.1, 100), 3U);
    // Fixed fan-out (pct 0), flooding (pct 1 with a large max).
    BOOST_CHECK_EQUAL(TxRelayFanout(50, 2, 0.0, 2), 2U);
    BOOST_CHECK_EQUAL(TxRelayFanout(50, 1, 1.0, 1000), 50U);
    // A max below the min is raised to the min.
    BOOST_CHECK_EQUAL(TxRelayFanout(50, 8, 0.25, 4), 8U);
}

namespace {
/** Peers (by id) that were sent an announcement for txid */
std::set<NodeId> SentTo(const std::map<NodeId, Sent> &sent, const TxId &txid) {
    std::set<NodeId> out;
    for (const auto &[id, s] : sent) {
        if (std::find(s.inv_txids.begin(), s.inv_txids.end(), txid) !=
                s.inv_txids.end() ||
            std::find(s.shorttx_txids.begin(), s.shorttx_txids.end(), txid) !=
                s.shorttx_txids.end()) {
            out.insert(id);
        }
    }
    return out;
}

void AddToMempool(node::NodeContext &node, const CTransactionRef &tx,
                  bool local = false) {
    TestMemPoolEntryHelper entry;
    LOCK2(cs_main, node.mempool->cs);
    node.mempool->addUnchecked(entry.FromTx(tx));
    if (local) {
        node.mempool->AddUnbroadcastTx(tx->GetId());
    }
}
} // namespace

BOOST_AUTO_TEST_CASE(fanout_selection) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    MockTick clock{3'000'000ms};
    RelayHarness h{m_node, PeerManager::Options{}};
    for (int i = 0; i < 40; ++i) {
        h.AddPeer(i % 2 ? ConnectionType::INBOUND
                        : ConnectionType::OUTBOUND_FULL_RELAY);
    }
    h.SendAll();
    const size_t k{TxRelayFanout(40, DEFAULT_TXRELAY_FANOUT_MIN,
                                 DEFAULT_TXRELAY_FANOUT_PCT,
                                 DEFAULT_TXRELAY_FANOUT_MAX)};
    BOOST_REQUIRE_EQUAL(k, 10U);
    FastRandomContext rng{true};
    auto ms{3'000'000ms};

    // Relayed transactions go to exactly k peers each, picked at random.
    std::set<NodeId> reached;
    for (int i = 0; i < 20; ++i) {
        auto tx{MakeTx(rng)};
        AddToMempool(m_node, tx);
        h.peerman->RelayTransaction(tx->GetId());
        clock.Set(ms += 10ms);
        const auto to{SentTo(h.SendAll(), tx->GetId())};
        BOOST_CHECK_EQUAL(to.size(), k);
        reached.insert(to.begin(), to.end());
    }
    BOOST_CHECK_GT(reached.size(), 30U);

    // A transaction this node originated goes to every peer.
    auto local_tx{MakeTx(rng)};
    AddToMempool(m_node, local_tx, /*local=*/true);
    h.peerman->RelayTransaction(local_tx->GetId());
    clock.Set(ms += 10ms);
    BOOST_CHECK_EQUAL(SentTo(h.SendAll(), local_tx->GetId()).size(), 40U);

    // Peers known to have it are not candidates; fewer than k candidates
    // all get it.
    auto known_tx{MakeTx(rng)};
    AddToMempool(m_node, known_tx);
    for (size_t i = 0; i < 35; ++i) {
        h.peerman->MarkPeerKnownTx(h.nodes[i]->GetId(), known_tx->GetId());
    }
    h.peerman->RelayTransaction(known_tx->GetId());
    clock.Set(ms += 10ms);
    const auto to_unknown{SentTo(h.SendAll(), known_tx->GetId())};
    BOOST_CHECK_EQUAL(to_unknown.size(), 5U);
    for (size_t i = 35; i < 40; ++i) {
        BOOST_CHECK(to_unknown.count(h.nodes[i]->GetId()));
    }

    // A child is announced to (at least) every peer its parent went to.
    for (int round = 0; round < 5; ++round) {
        auto parent{MakeTx(rng)};
        AddToMempool(m_node, parent);
        h.peerman->RelayTransaction(parent->GetId());
        clock.Set(ms += 10ms);
        const auto parent_to{SentTo(h.SendAll(), parent->GetId())};
        BOOST_CHECK_EQUAL(parent_to.size(), k);
        auto child{MakeTx(rng, {COutPoint(parent->GetId(), 0)})};
        AddToMempool(m_node, child);
        h.peerman->RelayTransaction(child->GetId());
        clock.Set(ms += 10ms);
        const auto child_to{SentTo(h.SendAll(), child->GetId())};
        BOOST_CHECK_GE(child_to.size(), k);
        for (const NodeId id : parent_to) {
            BOOST_CHECK(child_to.count(id));
        }
    }
}

BOOST_AUTO_TEST_CASE(per_tick_rate_budget) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    MockTick clock{4'000'000ms};
    PeerManager::Options opts;
    opts.txrelay_rate_max = 1000; // x 10 ms = 10 per tick
    RelayHarness h{m_node, opts};
    CNode &peer = h.AddPeer();
    h.SendAll();
    FastRandomContext rng{true};
    std::vector<CTransactionRef> txs;
    for (int i = 0; i < 25; ++i) {
        txs.push_back(MakeTx(rng));
        AddToMempool(m_node, txs.back());
    }
    h.peerman->RelayTransactionBatch(txs);
    size_t total{0};
    for (const size_t expect : {10U, 10U, 5U, 0U}) {
        clock.Set(4'000'000ms +
                  10ms * (1 + total / 10 + (expect == 0 ? 1 : 0)));
        const size_t n{h.SendAll()[peer.GetId()].Total()};
        BOOST_CHECK_EQUAL(n, expect);
        total += n;
    }
    BOOST_CHECK_EQUAL(total, 25U);
}

BOOST_AUTO_TEST_CASE(shortid_index_epochs_and_collisions) {
    using txrelay::TxRelayIndex;
    FastRandomContext rng{true};
    const auto key1{txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 100)};
    const auto key2{txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 101)};
    const auto key3{txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 102)};
    BOOST_CHECK(key1.k0 != key2.k0 || key1.k1 != key2.k1);
    // Deterministic: every node derives the same key for the same tip.
    BOOST_CHECK(txrelay::MakeEpochKey(BlockHash{key1.epoch_id}, 100) == key1);

    // Request keys round-trip and never parse under another epoch.
    const uint64_t sid{0x0123456789abcdefULL};
    const uint256 rkey{txrelay::ShortIdRequestKey(key1.epoch_id, sid)};
    BOOST_CHECK(txrelay::ParseShortIdRequestKey(rkey, key1.epoch_id) == sid);
    BOOST_CHECK(!txrelay::ParseShortIdRequestKey(rkey, key2.epoch_id));
    BOOST_CHECK(!txrelay::ParseShortIdRequestKey(rng.rand256(), key1.epoch_id));

    TxRelayIndex index;
    BOOST_CHECK(!index.Current());
    std::vector<std::pair<TxId, std::chrono::microseconds>> mempool;
    for (int i = 0; i < 50; ++i) {
        mempool.emplace_back(TxId{rng.rand256()},
                             std::chrono::microseconds{i * 1'000'000});
    }
    index.SetEpoch(key1, [&] { return mempool; });
    BOOST_CHECK(index.Current() == key1);
    BOOST_CHECK_EQUAL(index.Size(), 50U);
    const TxId &a{mempool[0].first};
    std::vector<TxId> out;
    BOOST_CHECK(index.Find(key1.epoch_id, index.ShortId(key1, a), &out) ==
                TxRelayIndex::Lookup::HAVE);
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    BOOST_CHECK(out[0] == a);
    BOOST_CHECK(index.Find(key2.epoch_id, 1) ==
                TxRelayIndex::Lookup::UNKNOWN_EPOCH);

    // A new epoch re-keys; the previous one stays readable, an older one
    // is dropped.
    index.Remove(a);
    BOOST_CHECK(index.Find(key1.epoch_id, index.ShortId(key1, a)) ==
                TxRelayIndex::Lookup::MISSING);
    index.SetEpoch(key2, [&] {
        return TxRelayIndex::Snapshot{mempool.begin() + 1, mempool.end()};
    });
    BOOST_CHECK(index.Current() == key2);
    BOOST_CHECK(index.FindEpoch(key1.epoch_id) == key1);
    const TxId &b{mempool[1].first};
    BOOST_CHECK(index.Find(key1.epoch_id, index.ShortId(key1, b)) ==
                TxRelayIndex::Lookup::HAVE);
    BOOST_CHECK(index.Find(key2.epoch_id, index.ShortId(key2, b)) ==
                TxRelayIndex::Lookup::HAVE);
    // Removal affects only the current epoch.
    index.Remove(b);
    BOOST_CHECK(index.Find(key1.epoch_id, index.ShortId(key1, b)) ==
                TxRelayIndex::Lookup::HAVE);
    index.SetEpoch(key3, [] { return TxRelayIndex::Snapshot{}; });
    BOOST_CHECK(!index.FindEpoch(key1.epoch_id));
    BOOST_CHECK(index.FindEpoch(key2.epoch_id));

    // Window: transactions admitted since a time, still indexed.
    TxRelayIndex window_index;
    window_index.SetEpoch(key1, [&] { return mempool; });
    const auto recent{
        window_index.AdmittedSince(std::chrono::microseconds{40'000'000})};
    BOOST_CHECK_EQUAL(recent.size(), 10U);
    window_index.Remove(mempool[45].first);
    window_index.Add(TxId{rng.rand256()},
                     std::chrono::microseconds{60'000'000});
    BOOST_CHECK_EQUAL(
        window_index.AdmittedSince(std::chrono::microseconds{40'000'000})
            .size(),
        10U);
    window_index.PruneWindow(std::chrono::microseconds{45'000'000});
    BOOST_CHECK_EQUAL(
        window_index.AdmittedSince(std::chrono::microseconds{0}).size(), 5U);

    // Collisions (forced with 4-bit ids): both are kept under the id and
    // counted.
    TxRelayIndex narrow{4};
    narrow.SetEpoch(key1, [&] { return mempool; });
    BOOST_CHECK_GT(narrow.Collisions(), 30U);
    size_t total{0};
    for (uint64_t id = 1; id < 16; ++id) {
        std::vector<TxId> under;
        narrow.Find(key1.epoch_id, id, &under);
        total += under.size();
    }
    BOOST_CHECK_EQUAL(total, 50U);
}

namespace {
std::vector<TxId>
PinnedWindowIds(const txrelay::TxRelayIndex::WindowTree &tree) {
    std::vector<TxId> ids;
    tree.forEachLeaf([&](const auto &entry) {
        ids.push_back(entry->txid);
        return true;
    });
    return ids;
}
} // namespace

BOOST_AUTO_TEST_CASE(recon_window_pinned_index_matches_scan) {
    using Index = txrelay::TxRelayIndex;
    using Clock = Index::Clock;
    FastRandomContext rng{true};
    Index index;
    auto epoch = txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 1);
    std::vector<TxId> ids;
    std::set<TxId> active;
    Index::Snapshot initial;
    for (int i = 0; i < 6000; ++i) {
        ids.emplace_back(rng.rand256());
        active.insert(ids.back());
        initial.emplace_back(ids.back(), Clock{i});
    }
    index.SetEpoch(epoch, [&] { return initial; });
    auto check = [&](Clock since, Clock until) {
        auto expected = index.AdmittedSince(since, until);
        std::sort(expected.begin(), expected.end());
        const auto pinned = index.PinAdmittedSince(since, until);
        const auto actual = PinnedWindowIds(*pinned);
        BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(),
                                      expected.begin(), expected.end());
        return pinned;
    };
    const auto old = check(Clock{0}, Clock{6000});
    const auto old_ids = PinnedWindowIds(*old);
    Clock now{6000};
    for (int step = 0; step < 500; ++step) {
        const auto &id = ids[rng.randrange(ids.size())];
        if (step % 3 == 0) {
            index.Remove(id);
            active.erase(id);
        } else {
            index.Add(id, now);
            active.insert(id);
        }
        now += Clock{int64_t(rng.randrange(4))};
        check(Clock{step / 3}, now - Clock{100});
        if (step % 37 == 0) {
            index.PruneWindow(Clock{step / 4});
            check(Clock{0}, now); // Backwards cutoff rebuild.
        }
        if (step % 53 == 0) {
            epoch = txrelay::MakeEpochKey(BlockHash{rng.rand256()}, step + 2);
            Index::Snapshot live;
            for (const auto &txid : active)
                live.emplace_back(txid, now);
            index.SetEpoch(epoch, [&] { return live; });
            check(Clock{0}, now + Clock{1});
        }
    }
    const auto still_old = PinnedWindowIds(*old);
    BOOST_CHECK_EQUAL_COLLECTIONS(still_old.begin(), still_old.end(),
                                  old_ids.begin(), old_ids.end());
    check(now, now);
    check(now, Clock{0});
    // Preserve legacy reverse-scan semantics on backwards admission time.
    index.Add(TxId{rng.rand256()}, Clock{-1});
    check(Clock{0}, now + Clock{1});
    index.PruneWindow(now + Clock{10});
    check(Clock{-10}, now + Clock{10});
    // After the inverted edge is pruned, normal incremental queries resume.
    index.Add(TxId{rng.rand256()}, now + Clock{11});
    check(now, now + Clock{12});
}

BOOST_AUTO_TEST_CASE(recon_window_cap_follows_live_membership) {
    using Index = txrelay::TxRelayIndex;
    using Clock = Index::Clock;
    FastRandomContext rng{true};
    Index index;
    const auto epoch = txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 1);
    Index::Snapshot initial;
    for (int i = 0; i < 7000; ++i)
        initial.emplace_back(TxId{rng.rand256()}, Clock{i});
    index.SetEpoch(epoch, [&] { return initial; });
    auto expected = index.AdmittedSince(Clock{0}, Clock{7000});
    std::sort(expected.begin(), expected.end());
    // Lagging removal callbacks: low IDs must not consume the cap before
    // filtering by the current live mempool view.
    std::set<TxId> live(expected.begin() + 1500, expected.end());
    expected.erase(expected.begin(), expected.begin() + 1500);
    expected.resize(4096);
    const auto pinned = index.PinAdmittedSince(Clock{0}, Clock{7000});
    // Force real short-id collisions too; pinning must retain every full ID.
    Index colliding{4};
    colliding.SetEpoch(epoch, [&] {
        return Index::Snapshot(initial.begin(), initial.begin() + 50);
    });
    auto collision_expected = colliding.AdmittedSince(Clock{0}, Clock{7000});
    std::sort(collision_expected.begin(), collision_expected.end());
    const auto collision_actual =
        PinnedWindowIds(*colliding.PinAdmittedSince(Clock{0}, Clock{7000}));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        collision_actual.begin(), collision_actual.end(),
        collision_expected.begin(), collision_expected.end());
    node::MempoolSnapshotTree live_builder;
    for (const auto &id : live) {
        node::MempoolEntrySnapshot entry{};
        entry.txid = id;
        BOOST_REQUIRE(live_builder.insert(
            RCUPtr<node::ImmutableMempoolEntry>::make(std::move(entry))));
    }
    const auto live_view = std::make_shared<const node::MempoolSnapshotTree>(
        std::move(live_builder));
    node::MempoolSnapshotTree next_live(
        *live_view, node::MempoolSnapshotTree::ImmutableSnapshotTag{});
    std::promise<void> start_writer, first_mutation;
    auto start = start_writer.get_future();
    auto mutated = first_mutation.get_future();
    std::thread writer([&] {
        start.wait();
        for (size_t i = 0; i < 64; ++i) {
            index.Remove(expected[i]);
            next_live.remove(Uint256RadixKey(expected[i]));
            if (i == 0) first_mutation.set_value();
        }
        // Signal above happens before TLS teardown, which itself can wait
        // for the reader's RCU section. Join only after traversal completes.
    });
    std::vector<TxId> actual;
    bool started{false};
    bool mutation_observed{false};
    pinned->forEachLeaf([&](const auto &candidate) {
        if (!started) {
            started = true;
            start_writer.set_value();
            mutation_observed =
                mutated.wait_for(1s) == std::future_status::ready;
            // A regression must release this guard before joining a writer
            // that could itself be blocked by an incorrect grace-period wait.
            if (!mutation_observed) return false;
        }
        const auto entry =
            live_view->getWithinReadSection(Uint256RadixKey(candidate->txid));
        if (entry) actual.push_back(candidate->txid);
        return actual.size() < 4096;
    });
    if (!started) start_writer.set_value();
    writer.join();
    BOOST_CHECK(started);
    BOOST_CHECK(mutation_observed);
    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(),
                                  expected.begin(), expected.end());
    auto roots_and_buckets = [&](const std::vector<TxId> &selected) {
        std::vector<lotus::v2::TxIdentityPair> pairs;
        std::array<std::pair<uint32_t, uint64_t>, 16> buckets{};
        for (const auto &id : selected) {
            lotus::v2::TxIdentityPair pair{};
            std::copy(id.begin(), id.end(), pair.tx_id.begin());
            std::copy(id.begin(), id.end(), pair.tx_hash.begin());
            pairs.push_back(pair);
            auto &bucket = buckets[lotus::v2::net::GetMerklixBucketIndex(id)];
            ++bucket.first;
            bucket.second ^= index.ShortId(epoch, id);
        }
        return std::make_pair(lotus::v2::BuildTxSubtreeA(pairs), buckets);
    };
    BOOST_CHECK(roots_and_buckets(actual) == roots_and_buckets(expected));
}

BOOST_AUTO_TEST_CASE(shortid_epoch_rebuild_preserves_mutations) {
    using txrelay::TxRelayIndex;
    FastRandomContext rng{true};
    const auto key1{txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 100)};
    const auto key2{txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 101)};
    const auto key3{txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 102)};
    const TxId removed{rng.rand256()}, retained{rng.rand256()},
        added{rng.rand256()};
    const TxRelayIndex::Clock time{1'000'000};
    const TxRelayIndex::Snapshot stale{{removed, time}, {retained, time}};
    TxRelayIndex index;
    index.SetEpoch(key1, [&] { return stale; });
    index.SetEpoch(key2, [&] {
        // Deliberately mutate after taking a stale snapshot: these events
        // must also survive the index being built outside its mutex.
        index.Add(added, time);
        index.Remove(removed);
        return stale;
    });
    BOOST_CHECK(index.Current() == key2);
    BOOST_CHECK_EQUAL(index.Size(), 2U);
    BOOST_CHECK(index.Find(key2.epoch_id, index.ShortId(key2, added)) ==
                TxRelayIndex::Lookup::HAVE);
    BOOST_CHECK(index.Find(key2.epoch_id, index.ShortId(key2, removed)) ==
                TxRelayIndex::Lookup::MISSING);
    BOOST_CHECK(index.Find(key2.epoch_id, index.ShortId(key2, retained)) ==
                TxRelayIndex::Lookup::HAVE);

    // A journal overflow abandons one bounded attempt, keeping the complete
    // current epoch; the next update can retry without an internal spin.
    index.SetEpoch(key3, [&] {
        for (size_t i = 0; i < 65'537; ++i) {
            index.Add(added, time);
        }
        return stale;
    });
    BOOST_CHECK(index.Current() == key2);
    index.SetEpoch(key3, [&] {
        return TxRelayIndex::Snapshot{{retained, time}, {added, time}};
    });
    BOOST_CHECK(index.Current() == key3);
    BOOST_CHECK_EQUAL(index.Size(), 2U);

    // Snapshot failure must stop journaling and allow a later rebuild.
    BOOST_CHECK_THROW(index.SetEpoch(key1,
                                     []() -> TxRelayIndex::Snapshot {
                                         throw std::runtime_error(
                                             "snapshot failure");
                                     }),
                      std::runtime_error);
    BOOST_CHECK(index.Current() == key3);
    index.SetEpoch(key1, [&] {
        return TxRelayIndex::Snapshot{{retained, time}, {added, time}};
    });
    BOOST_CHECK(index.Current() == key1);

    TxRelayIndex initial;
    initial.SetEpoch(key1, [&] {
        initial.Add(added, time);
        return stale;
    });
    BOOST_CHECK_EQUAL(initial.Size(), 3U);
    BOOST_CHECK_EQUAL(initial.AdmittedSince(TxRelayIndex::Clock{0}).size(), 3U);
}

BOOST_AUTO_TEST_CASE(invshort_negotiation_and_announcements) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    MockTick clock{5'000'000ms};
    auto &chainman{static_cast<TestChainstateManager &>(*m_node.chainman)};
    chainman.JumpOutOfIbd();
    RelayHarness h{m_node, PeerManager::Options{}};
    CNode &stock = h.AddPeer();
    CNode &nucleation = h.AddPeer();
    // Our sendinvshort went out after verack (to both peers).
    // Only the second peer offers short ids.
    {
        DataStream offer{};
        offer << txrelay::SENDINVSHORT_VERSION
              << uint64_t{txrelay::TXRELAY_INVSHORT | (1ULL << 40)};
        std::atomic<bool> interrupt{false};
        h.peerman->ProcessMessage(h.config, nucleation,
                                  NetMsgType::SENDINVSHORT, offer, 0us,
                                  interrupt);
    }
    h.SendAll();

    FastRandomContext rng{true};
    auto tx{MakeTx(rng)};
    AddToMempool(m_node, tx);
    h.peerman->RelayTransaction(tx->GetId());
    clock.Set(5'000'010ms);
    auto sent{h.SendAll()};
    // The stock peer gets an ordinary INV, the other a short id under the
    // current tip's epoch key.
    BOOST_REQUIRE_EQUAL(sent[stock.GetId()].inv_txids.size(), 1U);
    BOOST_CHECK(sent[stock.GetId()].short_ids.empty());
    BOOST_CHECK(sent[nucleation.GetId()].inv_txids.empty());
    BOOST_REQUIRE_EQUAL(sent[nucleation.GetId()].short_ids.size(), 1U);
    const auto [epoch_id, sid] = sent[nucleation.GetId()].short_ids[0];
    const auto tip{WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    const auto key{txrelay::MakeEpochKey(tip->GetBlockHash(), tip->nHeight)};
    BOOST_CHECK(epoch_id == key.epoch_id);
    BOOST_CHECK_EQUAL(sid,
                      txrelay::ComputeShortId(key.k0, key.k1, tx->GetId()));
    // 8 bytes on the wire, against 36 for an INV entry.
    BOOST_CHECK_EQUAL(sizeof(sid), 8U);

    // Announcements back: a short id we have marks the peer as knowing it
    // (no request); one we lack is requested by getshorttx under its epoch.
    auto missing{MakeTx(rng)};
    {
        DataStream ann{};
        ann << key.epoch_id
            << std::vector<uint64_t>{
                   sid,
                   txrelay::ComputeShortId(key.k0, key.k1, missing->GetId())};
        std::atomic<bool> interrupt{false};
        h.peerman->ProcessMessage(h.config, nucleation, NetMsgType::INVSHORT,
                                  ann, 0us, interrupt);
    }
    sent = h.SendAll();
    BOOST_REQUIRE_EQUAL(sent[nucleation.GetId()].short_requests.size(), 1U);
    const auto &req{sent[nucleation.GetId()].short_requests[0]};
    BOOST_CHECK(req.context_id == key.epoch_id);
    BOOST_CHECK_EQUAL(req.salt_k0, key.k0);
    BOOST_CHECK_EQUAL(req.salt_k1, key.k1);
    BOOST_REQUIRE_EQUAL(req.short_ids.size(), 1U);
    BOOST_CHECK_EQUAL(req.short_ids[0], txrelay::ComputeShortId(
                                            key.k0, key.k1, missing->GetId()));
    // Not requested twice while in flight.
    sent = h.SendAll();
    BOOST_CHECK(sent[nucleation.GetId()].short_requests.empty());

    // The peer serves our short ids from the index (getshorttx under the
    // relay epoch), answering with the body.
    {
        lotus::v2::net::ShortTxRequest ask;
        ask.scope = uint8_t(lotus::v2::net::ReconScope::LIVE_MEMPOOL);
        ask.context_id = key.epoch_id;
        ask.salt_k0 = key.k0;
        ask.salt_k1 = key.k1;
        ask.short_ids = {sid};
        DataStream ss{};
        ss << ask;
        std::atomic<bool> interrupt{false};
        h.peerman->ProcessMessage(h.config, nucleation, NetMsgType::GETSHORTTX,
                                  ss, 0us, interrupt);
    }
    sent = h.SendAll();
    BOOST_REQUIRE_EQUAL(sent[nucleation.GetId()].shorttx_txids.size(), 1U);
    BOOST_CHECK(sent[nucleation.GetId()].shorttx_txids[0] == tx->GetId());

    // Without negotiation, invshort is ignored (no request).
    {
        DataStream ann{};
        ann << key.epoch_id << std::vector<uint64_t>{12345};
        std::atomic<bool> interrupt{false};
        h.peerman->ProcessMessage(h.config, stock, NetMsgType::INVSHORT, ann,
                                  0us, interrupt);
    }
    sent = h.SendAll();
    BOOST_CHECK(sent[stock.GetId()].short_requests.empty());
    chainman.ResetIbd();
}

BOOST_AUTO_TEST_CASE(shorttx_fetch_publishes_unbroadcast_batch) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    MockTick clock{5'500'000ms};
    auto &chainman{static_cast<TestChainstateManager &>(*m_node.chainman)};
    chainman.JumpOutOfIbd();
    RelayHarness h{m_node, PeerManager::Options{}};
    CNode &peer = h.AddPeer();
    std::atomic<bool> interrupt{false};
    DataStream offer{};
    offer << txrelay::SENDINVSHORT_VERSION << uint64_t{txrelay::TXRELAY_INVSHORT};
    h.peerman->ProcessMessage(h.config, peer, NetMsgType::SENDINVSHORT,
                              offer, 0us, interrupt);
    h.SendAll();

    FastRandomContext rng{true};
    std::vector<CTransactionRef> txs;
    for (size_t i = 0; i < 3; ++i) {
        txs.push_back(MakeTx(rng));
        AddToMempool(m_node, txs.back(), /*local=*/true);
        h.peerman->RelayTransaction(txs.back()->GetId());
    }
    clock.Set(5'500'010ms);
    h.SendAll();
    const auto tip{WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    const auto key{txrelay::MakeEpochKey(tip->GetBlockHash(), tip->nHeight)};
    lotus::v2::net::ShortTxRequest ask;
    ask.scope = uint8_t(lotus::v2::net::ReconScope::LIVE_MEMPOOL);
    ask.context_id = key.epoch_id;
    ask.salt_k0 = key.k0;
    ask.salt_k1 = key.k1;
    for (const auto &tx : txs) {
        ask.short_ids.push_back(txrelay::ComputeShortId(key.k0, key.k1, tx->GetId()));
    }
    const auto before{node::GetGlobalSnapshotPublisher().Load()};
    BOOST_REQUIRE(before && before->entry_tree);
    BOOST_REQUIRE_EQUAL(before->unbroadcast_count, txs.size());
    const auto publications{node::GetGlobalSnapshotPublisher().PublicationCount()};
    auto fetch = [&] {
        DataStream request{};
        request << ask;
        h.peerman->ProcessMessage(h.config, peer, NetMsgType::GETSHORTTX,
                                  request, 0us, interrupt);
        return h.Drain(peer).shorttx_txids;
    };
    const auto fetched{fetch()};
    BOOST_REQUIRE_EQUAL(fetched.size(), txs.size());
    const auto after{node::GetGlobalSnapshotPublisher().Load()};
    BOOST_REQUIRE(after && after->entry_tree);
    // Clearing unbroadcast publishes one snapshot. Tip, size, and
    // transactions_updated are unchanged, so InitMiningTemplate shares the
    // previous generation's template instead of allocating a new id.
    BOOST_CHECK(after.get() != before.get());
    BOOST_CHECK_EQUAL(node::GetGlobalSnapshotPublisher().PublicationCount(),
                      publications + 1);
    BOOST_CHECK_EQUAL(after->transactions_updated, before->transactions_updated);
    BOOST_CHECK(after->mining == before->mining);
    BOOST_CHECK_EQUAL(after->GetMiningTemplate().template_id,
                      before->GetMiningTemplate().template_id);
    BOOST_CHECK_EQUAL(after->unbroadcast_count, 0U);
    BOOST_CHECK_EQUAL(after->mempool_size, before->mempool_size);
    for (size_t i = 0; i < txs.size(); ++i) {
        BOOST_CHECK(fetched[i] == txs[i]->GetId());
        const auto old_entry{before->entry_tree->get(Uint256RadixKey(txs[i]->GetId()))};
        const auto new_entry{after->entry_tree->get(Uint256RadixKey(txs[i]->GetId()))};
        BOOST_REQUIRE(old_entry && new_entry);
        BOOST_CHECK(old_entry->entry.unbroadcast);
        BOOST_CHECK(!new_entry->entry.unbroadcast);
    }
    // Fetching the same bodies again must not publish an unchanged snapshot.
    BOOST_CHECK(fetch() == fetched);
    BOOST_CHECK(node::GetGlobalSnapshotPublisher().Load().get() == after.get());
    BOOST_CHECK_EQUAL(node::GetGlobalSnapshotPublisher().PublicationCount(),
                      publications + 1);
    chainman.ResetIbd();
}

BOOST_AUTO_TEST_CASE(reconciliation_round_robin) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto &chainman{static_cast<TestChainstateManager &>(*m_node.chainman)};
    chainman.JumpOutOfIbd();
    MockTick clock{6'000'000ms};
    PeerManager::Options opts;
    opts.txrecon_interval = 250ms;
    RelayHarness h{m_node, opts};
    // Three peers: two negotiate reconciliation, one only short ids.
    std::vector<CNode *> peers;
    const uint64_t flags[]{txrelay::TXRELAY_INVSHORT | txrelay::TXRELAY_RECON,
                           txrelay::TXRELAY_INVSHORT,
                           txrelay::TXRELAY_INVSHORT | txrelay::TXRELAY_RECON};
    for (const uint64_t f : flags) {
        CNode &node{h.AddPeer()};
        DataStream offer{};
        offer << txrelay::SENDINVSHORT_VERSION << f;
        std::atomic<bool> interrupt{false};
        h.peerman->ProcessMessage(h.config, node, NetMsgType::SENDINVSHORT,
                                  offer, 0us, interrupt);
        peers.push_back(&node);
    }
    FastRandomContext rng{true};
    auto tx{MakeTx(rng)};
    const auto t0{GetTime<std::chrono::seconds>()};
    SetMockTime(t0);
    AddToMempool(m_node, tx);
    h.peerman->RelayTransaction(tx->GetId());
    // The newest two intervals are left out of the summary: be past them.
    SetMockTime(t0 + 1s);

    // One round per interval, alternating between the two that negotiated.
    std::vector<NodeId> order;
    auto ms{6'000'000ms};
    for (int round = 0; round < 6; ++round) {
        clock.Set(ms += 250ms);
        auto sent{h.SendAll()};
        for (const auto &[id, s] : sent) {
            BOOST_CHECK_LE(s.summaries.size(), 1U);
            if (!s.summaries.empty()) {
                order.push_back(id);
                const auto &summary{s.summaries[0]};
                BOOST_CHECK_EQUAL(
                    summary.scope,
                    uint8_t(lotus::v2::net::ReconScope::LIVE_MEMPOOL));
                // The window holds the relayed transaction.
                uint32_t count{0};
                for (const auto &b : summary.buckets) {
                    count += b.count;
                }
                BOOST_CHECK_EQUAL(count, 1U);
            }
        }
        // Within the interval: no second round.
        clock.Set(ms + 100ms);
        for (const auto &[id, s] : h.SendAll()) {
            BOOST_CHECK(s.summaries.empty());
        }
    }
    BOOST_REQUIRE_EQUAL(order.size(), 6U);
    for (size_t i = 0; i < order.size(); ++i) {
        BOOST_CHECK_EQUAL(order[i], peers[i % 2 ? 2 : 0]->GetId());
    }
    SetMockTime(0);
    chainman.ResetIbd();
}

BOOST_AUTO_TEST_CASE(stock_peer_does_not_support_private_relay) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    MockTick clock{8'000'000ms};
    struct ResetArgs {
        ~ResetArgs() { gArgs.ClearForcedArg("-highbandwidthtx"); }
    } reset_args;
    gArgs.ForceSetArg("-highbandwidthtx", "1");
    PeerManager::Options opts;
    opts.txrelay_push_hb = true;
    RelayHarness h{m_node, opts};
    CNode &stock{h.AddPeer()};
    // Ordinary Bitcoin compact-block negotiation does not negotiate Lotus
    // sealed headers or unsolicited shorttx messages.
    stock.m_bip152_highbandwidth_to = true;
    stock.m_bip152_highbandwidth_from = true;
    BOOST_CHECK(!h.peerman->GetV2ProtocolHandler()
                     ->IsHighBandwidthShortTxPeer(stock.GetId()));
    h.SendAll();
    FastRandomContext rng{true};
    std::vector<CTransactionRef> txs;
    for (int i = 0; i < 20; ++i) {
        txs.push_back(MakeTx(rng));
        AddToMempool(m_node, txs.back());
    }
    h.peerman->RelayTransactionBatch(txs);
    clock.Set(8'000'010ms);
    const Sent sent{h.SendAll()[stock.GetId()]};
    BOOST_CHECK(sent.shorttx_txids.empty());
    BOOST_CHECK_EQUAL(sent.inv_txids.size(), 20U);
}

BOOST_AUTO_TEST_CASE(private_relay_requires_explicit_remote_offer) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    struct ResetArgs {
        ~ResetArgs() { gArgs.ClearForcedArg("-highbandwidthtx"); }
    } reset_args;
    gArgs.ForceSetArg("-highbandwidthtx", "1");
    MockTick clock{9'000'000ms};
    PeerManager::Options opts;
    opts.txrelay_push_hb = true;
    RelayHarness h{m_node, opts};
    CNode &stock{h.AddPeer()};
    CNode &short_only{h.AddPeer()};
    CNode &capable{h.AddPeer()};
    CNode &block_only{h.AddPeer(ConnectionType::BLOCK_RELAY)};
    auto offer = [&](CNode &node, uint64_t flags) {
        DataStream message{};
        message << txrelay::SENDINVSHORT_VERSION << flags;
        std::atomic<bool> interrupt{false};
        h.peerman->ProcessMessage(h.config, node, NetMsgType::SENDINVSHORT,
                                  message, 0us, interrupt);
    };
    offer(short_only, txrelay::TXRELAY_INVSHORT | (1ULL << 40));
    offer(capable, txrelay::TXRELAY_HIGH_BANDWIDTH | (1ULL << 40));
    offer(block_only, txrelay::TXRELAY_HIGH_BANDWIDTH);
    auto *handler{h.peerman->GetV2ProtocolHandler()};
    BOOST_CHECK(!handler->IsHighBandwidthShortTxPeer(stock.GetId()));
    BOOST_CHECK(!handler->IsHighBandwidthShortTxPeer(short_only.GetId()));
    BOOST_CHECK(handler->IsHighBandwidthShortTxPeer(capable.GetId()));
    BOOST_CHECK(!handler->IsHighBandwidthShortTxPeer(block_only.GetId()));
    h.SendAll();
    FastRandomContext rng{true};
    std::vector<CTransactionRef> txs;
    for (int i = 0; i < 20; ++i) {
        txs.push_back(MakeTx(rng));
        AddToMempool(m_node, txs.back());
    }
    h.peerman->RelayTransactionBatch(txs);
    clock.Set(9'000'010ms);
    auto sent{h.SendAll()};
    BOOST_CHECK_EQUAL(sent[stock.GetId()].inv_txids.size(), 20U);
    BOOST_CHECK(sent[stock.GetId()].shorttx_txids.empty());
    BOOST_CHECK_EQUAL(sent[short_only.GetId()].short_ids.size(), 20U);
    BOOST_CHECK(sent[short_only.GetId()].shorttx_txids.empty());
    BOOST_CHECK_EQUAL(sent[capable.GetId()].shorttx_txids.size(), 20U);
    BOOST_CHECK_EQUAL(sent[block_only.GetId()].Total(), 0U);
    // Unknown flags neither enable the private path nor preserve an earlier
    // offer when its explicit high-bandwidth bit is removed.
    offer(capable, uint64_t{1} << 40);
    BOOST_CHECK(!handler->IsHighBandwidthShortTxPeer(capable.GetId()));
    offer(capable, txrelay::TXRELAY_HIGH_BANDWIDTH);
    BOOST_CHECK(handler->IsHighBandwidthShortTxPeer(capable.GetId()));
    // FinalizeNode cleanup is checked by the sealed-header integration test;
    // another connection to the same implementation still needs its own offer.
    CNode &reconnected{h.AddPeer()};
    BOOST_CHECK(!handler->IsHighBandwidthShortTxPeer(reconnected.GetId()));
}

BOOST_AUTO_TEST_CASE(private_relay_local_willingness_and_disabled_shortids) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    struct ResetArgs {
        ~ResetArgs() { gArgs.ClearForcedArg("-highbandwidthtx"); }
    } reset_args;
    for (const bool willing : {false, true}) {
        gArgs.ForceSetArg("-highbandwidthtx", willing ? "1" : "0");
        PeerManager::Options opts;
        opts.txrelay_shortids = false;
        RelayHarness h{m_node, opts};
        CNode &peer{h.AddPeer()};
        DataStream offer{};
        offer << txrelay::SENDINVSHORT_VERSION
              << uint64_t{txrelay::TXRELAY_HIGH_BANDWIDTH};
        std::atomic<bool> interrupt{false};
        h.peerman->ProcessMessage(h.config, peer, NetMsgType::SENDINVSHORT,
                                  offer, 0us, interrupt);
        BOOST_CHECK_EQUAL(h.peerman->GetV2ProtocolHandler()
                              ->IsHighBandwidthShortTxPeer(peer.GetId()),
                          willing);
    }
}

BOOST_AUTO_TEST_CASE(no_body_push_by_default) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    struct ResetArgs {
        ~ResetArgs() { gArgs.ClearForcedArg("-highbandwidthtx"); }
    } reset_args;
    gArgs.ForceSetArg("-highbandwidthtx", "1");
    FastRandomContext rng{true};
    for (const bool push : {false, true}) {
        MockTick clock{7'000'000ms};
        PeerManager::Options opts;
        opts.txrelay_push_hb = push;
        RelayHarness h{m_node, opts};
        CNode &peer{h.AddPeer()};
        DataStream offer{};
        offer << txrelay::SENDINVSHORT_VERSION
              << uint64_t{txrelay::TXRELAY_HIGH_BANDWIDTH};
        std::atomic<bool> interrupt{false};
        h.peerman->ProcessMessage(h.config, peer, NetMsgType::SENDINVSHORT,
                                  offer, 0us, interrupt);
        h.SendAll();
        std::vector<CTransactionRef> txs;
        for (int i = 0; i < 20; ++i) {
            txs.push_back(MakeTx(rng));
            AddToMempool(m_node, txs.back());
        }
        h.peerman->RelayTransactionBatch(txs);
        clock.Set(7'000'010ms);
        const Sent sent{h.SendAll()[peer.GetId()]};
        // A high-bandwidth peer gets bodies only with -txrelaypushhb.
        BOOST_CHECK_EQUAL(sent.shorttx_txids.size(), push ? 20U : 0U);
        BOOST_CHECK_EQUAL(sent.inv_txids.size(), push ? 0U : 20U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
