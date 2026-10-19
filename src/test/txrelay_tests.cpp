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

#include <chrono>
#include <map>
#include <memory>
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

BOOST_AUTO_TEST_SUITE_END()
