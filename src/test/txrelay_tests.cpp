// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Nucleation relay: fixed relay tick and the transaction announcement path.

#include <net_processing.h>

#include <config.h>
#include <net.h>
#include <net/v2_protocol_handler.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <script/standard.h>
#include <streams.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
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
    size_t Total() const { return inv_txids.size() + shorttx_txids.size(); }
};

/** A PeerManager with full-relay peers, driven by a mocked relay tick clock */
struct RelayHarness {
    const Config &config;
    std::unique_ptr<ConnmanTestMsg> connman;
    std::unique_ptr<PeerManager> peerman;
    std::vector<std::unique_ptr<CNode>> nodes;

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
        for (auto &node : nodes) {
            peerman->FinalizeNode(config, *node);
        }
    }

    CNode &AddPeer(ConnectionType type = ConnectionType::OUTBOUND_FULL_RELAY)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        const NodeId id = NodeId(500 + nodes.size());
        CAddress addr(MakeTestIp(0x0a000001 + uint32_t(nodes.size())),
                      NODE_NONE);
        nodes.push_back(
            std::make_unique<CNode>(id, nullptr, addr, 0, 0, 0, CAddress(), "",
                                    type, type == ConnectionType::INBOUND));
        CNode &node = *nodes.back();
        connman->Handshake(node, true, NODE_NETWORK, NODE_NETWORK,
                           PROTOCOL_VERSION, true);
        return node;
    }

    /** Run SendMessages for every peer and collect what each was sent */
    std::map<NodeId, Sent> SendAll()
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        std::map<NodeId, Sent> out;
        for (auto &node : nodes) {
            BOOST_CHECK(peerman->SendMessages(config, node.get()));
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

BOOST_AUTO_TEST_SUITE_END()
