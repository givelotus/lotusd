// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests of the WebSocket subscription handler (port of chronik-http ws.rs,
// which has no Rust unit tests; its behaviour is covered by the Chronik
// functional tests). Uses a fake WsSession and a manually run executor.

#include <chronik/native/codec/hex.h>
#include <chronik/native/proto.h>
#include <chronik/native/subs.h>
#include <chronik/native/subscription_limits.h>
#include <chronik/native/ws.h>

#include <core/ws/ws_handler.h>
#include <test/fake_host.h>
#include <test/test_sha256.h>

#include <boost/test/unit_test.hpp>

#include <deque>
#include <mutex>

using namespace chronik::native;
namespace th = chronik::native::testhost;

namespace {

class FakeSession final : public WsSession {
public:
    void SendBinary(Bytes msg) override {
        std::lock_guard lock(mutex);
        sent.push_back(std::move(msg));
    }
    void Close() override { closed = true; }
    const std::string &PeerIp() const override { return ip; }
    void NotifyActivity() override { ++activity; }

    std::vector<proto::WsMsg> Take() {
        std::lock_guard lock(mutex);
        std::vector<proto::WsMsg> out;
        for (const Bytes &b : sent) {
            proto::WsMsg msg;
            BOOST_REQUIRE(msg.ParseFromArray(b.data(), int(b.size())));
            out.push_back(msg);
        }
        sent.clear();
        return out;
    }

    std::mutex mutex;
    std::vector<Bytes> sent;
    std::string ip = "10.0.0.1";
    bool closed = false;
    int activity = 0;
};

struct Executor {
    std::deque<std::function<void()>> tasks;
    SerialExecutor Post() {
        return [this](std::function<void()> fn) {
            tasks.push_back(std::move(fn));
        };
    }
    size_t RunAll() {
        size_t n = 0;
        while (!tasks.empty()) {
            auto fn = std::move(tasks.front());
            tasks.pop_front();
            fn();
            ++n;
        }
        return n;
    }
};

Sha256Fn TestSha() {
    return [](ByteView data, uint8_t out[32]) {
        chronik::native::test::TestSha256(data, out);
    };
}

struct WsEnv {
    std::shared_ptr<SubsHub> hub = std::make_shared<SubsHub>(TestSha());
    std::shared_ptr<SubscriptionLimiter> limiter;
    std::shared_ptr<FakeSession> session = std::make_shared<FakeSession>();
    Executor exec;
    std::vector<std::string> logs;
    std::unique_ptr<WsHandler> handler;

    explicit WsEnv(size_t max_subs = 1000, size_t max_per_ip = 1000,
                   WsHandlerSettings settings = {})
        : limiter(SubscriptionLimiter::Create(max_subs, max_per_ip)) {
        handler = MakeChronikWsHandler(
            session, hub, limiter, settings, exec.Post(),
            [this](std::string_view msg, bool) { logs.emplace_back(msg); });
    }
    void Send(const proto::WsSub &sub) {
        const std::string s = sub.SerializeAsString();
        handler->OnBinary(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(s.data()), s.size()));
        exec.RunAll();
    }
    std::vector<proto::WsMsg> Publish(const std::function<void(Subs &)> &f) {
        {
            auto subs = hub->Write();
            f(*subs);
        }
        exec.RunAll();
        return session->Take();
    }
    size_t ClientCount() const {
        return limiter->ClientCount(SubscriptionClientKey::Ip(session->ip));
    }
};

proto::WsSub SubBlocks(bool unsub = false) {
    proto::WsSub sub;
    sub.set_is_unsub(unsub);
    sub.mutable_blocks();
    return sub;
}
proto::WsSub SubTxs(bool unsub = false) {
    proto::WsSub sub;
    sub.set_is_unsub(unsub);
    sub.mutable_txs();
    return sub;
}
proto::WsSub SubTxId(const TxId &txid, bool unsub = false) {
    proto::WsSub sub;
    sub.set_is_unsub(unsub);
    sub.mutable_txid()->set_txid(HashToHex(txid));
    return sub;
}
proto::WsSub SubScript(const std::string &type, const Bytes &payload,
                       bool unsub = false) {
    proto::WsSub sub;
    sub.set_is_unsub(unsub);
    sub.mutable_script()->set_script_type(type);
    sub.mutable_script()->set_payload(
        std::string(payload.begin(), payload.end()));
    return sub;
}
proto::WsSub SubLokad(const std::array<uint8_t, 4> &id, bool unsub = false) {
    proto::WsSub sub;
    sub.set_is_unsub(unsub);
    sub.mutable_lokad_id()->set_lokad_id(std::string(id.begin(), id.end()));
    return sub;
}

BlockMsg MakeBlockMsg(uint8_t n, BlockMsgType type = BlockMsgType::Connected) {
    BlockMsg msg;
    msg.msg_type = type;
    msg.hash.b.fill(n);
    msg.height = n;
    msg.timestamp = 1000 + n;
    return msg;
}

Tx MakeTx(uint8_t n, Bytes script) {
    Tx tx;
    tx.txid.b.fill(n);
    TxInput in;
    in.prev_out.txid.b.fill(uint8_t(n + 100));
    in.coin = Coin{TxOutput{1000, th::P2pkh(0x99)}, 1, false};
    tx.inputs.push_back(in);
    tx.outputs.push_back(TxOutput{900, std::move(script)});
    return tx;
}

std::string HashStr(const Hash32 &h) {
    return std::string(h.b.begin(), h.b.end());
}

Bytes Payload20(uint8_t id) { return Bytes(20, id); }

} // namespace

BOOST_AUTO_TEST_SUITE(ws_handler_tests)

BOOST_AUTO_TEST_CASE(block_messages) {
    WsEnv env;
    env.Send(SubBlocks());
    BOOST_CHECK(env.session->Take().empty());
    BOOST_CHECK_EQUAL(env.ClientCount(), 1u);
    auto msgs = env.Publish(
        [](Subs &subs) { subs.BroadcastBlockMsg(MakeBlockMsg(7)); });
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_REQUIRE(msgs[0].has_block());
    BOOST_CHECK_EQUAL(msgs[0].block().msg_type(), proto::BLK_CONNECTED);
    BOOST_CHECK(msgs[0].block().block_hash() == std::string(32, '\x07'));
    BOOST_CHECK_EQUAL(msgs[0].block().block_height(), 7);
    BOOST_CHECK_EQUAL(msgs[0].block().block_timestamp(), 1007);
    BOOST_CHECK(!msgs[0].block().has_coinbase_data());

    // Disconnected with coinbase data
    BlockMsg disconnected = MakeBlockMsg(8, BlockMsgType::Disconnected);
    Tx cb;
    TxInput in;
    in.prev_out.out_idx = 0xffffffff;
    in.script = {0x01, 0x02};
    cb.inputs.push_back(in);
    cb.outputs.push_back(TxOutput{5000, th::P2pkh(1)});
    disconnected.coinbase_tx = std::make_shared<const Tx>(cb);
    msgs = env.Publish(
        [&](Subs &subs) { subs.BroadcastBlockMsg(disconnected); });
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK_EQUAL(msgs[0].block().msg_type(), proto::BLK_DISCONNECTED);
    BOOST_REQUIRE(msgs[0].block().has_coinbase_data());
    BOOST_CHECK(msgs[0].block().coinbase_data().coinbase_scriptsig() ==
                std::string("\x01\x02"));
    BOOST_REQUIRE_EQUAL(
        msgs[0].block().coinbase_data().coinbase_outputs_size(), 1);
    BOOST_CHECK_EQUAL(
        msgs[0].block().coinbase_data().coinbase_outputs(0).sats(), 5000);

    // Finalized / invalidated types
    msgs = env.Publish([](Subs &subs) {
        subs.BroadcastBlockMsg(MakeBlockMsg(9, BlockMsgType::Finalized));
        subs.BroadcastBlockMsg(MakeBlockMsg(9, BlockMsgType::Invalidated));
    });
    BOOST_REQUIRE_EQUAL(msgs.size(), 2u);
    BOOST_CHECK_EQUAL(msgs[0].block().msg_type(), proto::BLK_FINALIZED);
    BOOST_CHECK_EQUAL(msgs[1].block().msg_type(), proto::BLK_INVALIDATED);

    // Multiple subs to blocks are silently ignored (one slot)
    env.Send(SubBlocks());
    BOOST_CHECK_EQUAL(env.ClientCount(), 1u);
    // Unsubscribe: no more messages, slot released
    env.Send(SubBlocks(true));
    BOOST_CHECK_EQUAL(env.ClientCount(), 0u);
    msgs = env.Publish(
        [](Subs &subs) { subs.BroadcastBlockMsg(MakeBlockMsg(10)); });
    BOOST_CHECK(msgs.empty());
    // Unsubscribing again is a no-op
    env.Send(SubBlocks(true));
    BOOST_CHECK_EQUAL(env.ClientCount(), 0u);
}

BOOST_AUTO_TEST_CASE(dedup_identical_consecutive_messages) {
    WsEnv env;
    env.Send(SubBlocks());
    const int activity_before = env.session->activity;
    auto msgs = env.Publish([](Subs &subs) {
        subs.BroadcastBlockMsg(MakeBlockMsg(1));
        subs.BroadcastBlockMsg(MakeBlockMsg(1));
        subs.BroadcastBlockMsg(MakeBlockMsg(2));
        subs.BroadcastBlockMsg(MakeBlockMsg(1));
    });
    BOOST_REQUIRE_EQUAL(msgs.size(), 3u);
    BOOST_CHECK_EQUAL(msgs[0].block().block_height(), 1);
    BOOST_CHECK_EQUAL(msgs[1].block().block_height(), 2);
    BOOST_CHECK_EQUAL(msgs[2].block().block_height(), 1);
    // The deduplicated message only counts as activity
    BOOST_CHECK_EQUAL(env.session->activity - activity_before, 1);
}

BOOST_AUTO_TEST_CASE(biased_order_blocks_txs_txids_scripts_lokad) {
    WsEnv env;
    const Tx tx = MakeTx(5, th::LokadOpReturn({'A', 'B', 'C', 'D'}));
    const Tx script_tx = MakeTx(6, th::P2pkh(0x11));
    env.Send(SubLokad({'A', 'B', 'C', 'D'}));
    env.Send(SubScript("p2pkh", Payload20(0x11)));
    env.Send(SubTxId(tx.txid));
    env.Send(SubTxs());
    env.Send(SubBlocks());
    BOOST_CHECK_EQUAL(env.ClientCount(), 5u);
    const int activity_before = env.session->activity;
    auto msgs = env.Publish([&](Subs &subs) {
        // published in "reverse" priority order
        subs.HandleTxEvent(script_tx, TxMsgType::Confirmed());
        subs.HandleTxEvent(tx, TxMsgType::AddedToMempool());
        subs.BroadcastBlockMsg(MakeBlockMsg(3));
    });
    // blocks; txs (script_tx, tx); txids (tx: identical to the previous
    // message, deduplicated); scripts (script_tx); lokad_ids (tx)
    BOOST_REQUIRE_EQUAL(msgs.size(), 5u);
    BOOST_CHECK(msgs[0].has_block());
    BOOST_CHECK(msgs[1].tx().txid() == HashStr(script_tx.txid));
    BOOST_CHECK_EQUAL(msgs[1].tx().msg_type(), proto::TX_CONFIRMED);
    BOOST_CHECK(msgs[2].tx().txid() == HashStr(tx.txid));
    BOOST_CHECK_EQUAL(msgs[2].tx().msg_type(), proto::TX_ADDED_TO_MEMPOOL);
    BOOST_CHECK(msgs[3].tx().txid() == HashStr(script_tx.txid));
    BOOST_CHECK(msgs[4].tx().txid() == HashStr(tx.txid));
    BOOST_CHECK_EQUAL(env.session->activity - activity_before, 1);
}

BOOST_AUTO_TEST_CASE(tx_message_types) {
    WsEnv env;
    env.Send(SubTxs());
    const Tx tx = MakeTx(1, th::P2pkh(1));
    auto msgs = env.Publish([&](Subs &subs) {
        subs.BroadcastTxMsg(tx.txid, TxMsgType::RemovedFromMempool());
        subs.BroadcastTxMsg(
            tx.txid, TxMsgType::Finalized(TxFinalizationReason::PreConsensus));
        subs.BroadcastTxMsg(
            tx.txid, TxMsgType::Finalized(TxFinalizationReason::PostConsensus));
        subs.BroadcastTxMsg(tx.txid, TxMsgType::Invalidated());
    });
    BOOST_REQUIRE_EQUAL(msgs.size(), 4u);
    BOOST_CHECK_EQUAL(msgs[0].tx().msg_type(), proto::TX_REMOVED_FROM_MEMPOOL);
    BOOST_CHECK(!msgs[0].tx().has_finalization_reason());
    BOOST_CHECK_EQUAL(msgs[1].tx().msg_type(), proto::TX_FINALIZED);
    BOOST_CHECK_EQUAL(msgs[1].tx().finalization_reason().finalization_type(),
                      proto::TX_FINALIZATION_REASON_PRE_CONSENSUS);
    BOOST_CHECK_EQUAL(msgs[2].tx().finalization_reason().finalization_type(),
                      proto::TX_FINALIZATION_REASON_POST_CONSENSUS);
    BOOST_CHECK_EQUAL(msgs[3].tx().msg_type(), proto::TX_INVALIDATED);
}

BOOST_AUTO_TEST_CASE(lagged_gives_nothing) {
    WsEnv env;
    env.Send(SubTxs());
    const int activity_before = env.session->activity;
    auto msgs = env.Publish([](Subs &subs) {
        for (uint32_t i = 0; i < TXS_CHANNEL_CAPACITY + 5; ++i) {
            TxId txid;
            txid.b[0] = uint8_t(i);
            subs.BroadcastTxMsg(txid, TxMsgType::Confirmed());
        }
    });
    // The oldest 5 were dropped; the lag itself sends nothing
    BOOST_REQUIRE_EQUAL(msgs.size(), TXS_CHANNEL_CAPACITY);
    BOOST_CHECK_EQUAL(uint8_t(msgs[0].tx().txid()[0]), 5);
    BOOST_CHECK_EQUAL(env.session->activity - activity_before, 1);
}

BOOST_AUTO_TEST_CASE(script_token_lokad_subscriptions) {
    WsEnv env;
    env.Send(SubScript("p2pkh", Payload20(0x22)));
    BOOST_CHECK(env.session->Take().empty());
    const Tx tx = MakeTx(3, th::P2pkh(0x22));
    auto msgs = env.Publish(
        [&](Subs &subs) { subs.HandleTxEvent(tx, TxMsgType::Confirmed()); });
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].tx().txid() == HashStr(tx.txid));
    // Unrelated script: nothing
    msgs = env.Publish([&](Subs &subs) {
        subs.HandleTxEvent(MakeTx(4, th::P2pkh(0x23)), TxMsgType::Confirmed());
    });
    BOOST_CHECK(msgs.empty());
    // Unsubscribe
    env.Send(SubScript("p2pkh", Payload20(0x22), true));
    msgs = env.Publish(
        [&](Subs &subs) { subs.HandleTxEvent(tx, TxMsgType::Confirmed()); });
    BOOST_CHECK(msgs.empty());
    BOOST_CHECK_EQUAL(env.ClientCount(), 0u);

    // LOKAD ID
    env.Send(SubLokad({'X', 'Y', 'Z', 'W'}));
    const Tx lokad_tx = MakeTx(5, th::LokadOpReturn({'X', 'Y', 'Z', 'W'}));
    msgs = env.Publish([&](Subs &subs) {
        subs.HandleTxEvent(lokad_tx, TxMsgType::AddedToMempool());
    });
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].tx().txid() == HashStr(lokad_tx.txid));

    // Token ID (subscribing works without a token index; no events)
    proto::WsSub token_sub;
    token_sub.mutable_token_id()->set_token_id(std::string(64, 'a'));
    env.Send(token_sub);
    BOOST_CHECK(env.session->Take().empty());
    BOOST_CHECK_EQUAL(env.ClientCount(), 2u);
    token_sub.set_is_unsub(true);
    env.Send(token_sub);
    BOOST_CHECK_EQUAL(env.ClientCount(), 1u);
}

BOOST_AUTO_TEST_CASE(errors) {
    WsHandlerSettings settings;
    settings.subscription_max_script_size = 25;
    settings.subscription_max_plugin_size = 4;
    WsEnv env(1000, 1000, settings);
    const auto error_of = [&](const proto::WsSub &sub) -> std::string {
        env.Send(sub);
        auto msgs = env.session->Take();
        BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
        BOOST_REQUIRE(msgs[0].has_error());
        return msgs[0].error().msg();
    };
    // Missing sub_type
    BOOST_CHECK_EQUAL(error_of(proto::WsSub()),
                      "400: Missing sub_type in WsSub message");
    // Script too large (p2pkh is 25 bytes, "other" with 26 bytes isn't)
    BOOST_CHECK_EQUAL(error_of(SubScript("other", Bytes(26, 0x51))),
                      WsScriptTooLargeMessage(26, 25));
    BOOST_CHECK_EQUAL(env.ClientCount(), 0u);
    env.Send(SubScript("p2pkh", Payload20(1)));
    BOOST_CHECK(env.session->Take().empty());
    // ... unsubscribing from a too large script is fine
    env.Send(SubScript("other", Bytes(26, 0x51), true));
    BOOST_CHECK(env.session->Take().empty());
    // Invalid payload / script type are 400 errors
    BOOST_CHECK(error_of(SubScript("p2pkh", Bytes(3, 0)))
                    .starts_with("400: Invalid payload for P2PKH: "));
    BOOST_CHECK(error_of(SubScript("foo", Bytes(20, 0))).starts_with("400: "));
    // Plugins: group too large, else not loaded
    proto::WsSub plugin;
    plugin.mutable_plugin()->set_plugin_name("plg");
    plugin.mutable_plugin()->set_group("12345");
    BOOST_CHECK_EQUAL(error_of(plugin), WsPluginGroupTooLargeMessage(5, 4));
    plugin.set_is_unsub(true);
    BOOST_CHECK_EQUAL(error_of(plugin), "404: Plugin \"plg\" not loaded");
    plugin.set_is_unsub(false);
    plugin.mutable_plugin()->set_group("1234");
    BOOST_CHECK_EQUAL(error_of(plugin), "404: Plugin \"plg\" not loaded");
    // Text message: unprefixed error -> 500
    env.handler->OnText();
    auto msgs = env.session->Take();
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK_EQUAL(msgs[0].error().msg(), "Unknown error, contact admins");
    // Undecodable protobuf
    const uint8_t garbage[] = {0xff, 0xff, 0xff};
    env.handler->OnBinary(garbage);
    msgs = env.session->Take();
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK(msgs[0].has_error());
    // Errors are never deduplicated
    error_of(proto::WsSub());
    error_of(proto::WsSub());
}

BOOST_AUTO_TEST_CASE(subscription_limits) {
    WsEnv env(1000, 2);
    env.Send(SubBlocks());
    env.Send(SubTxs());
    const proto::WsSub third = SubTxId(TxId{});
    env.Send(third);
    auto msgs = env.session->Take();
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK_EQUAL(msgs[0].error().msg(),
                      WsSubscriptionLimitErrorMessage(SubscriptionLimitError{
                          SubscriptionLimitError::Kind::PerClient, 2}));
    // Releasing one makes room again
    env.Send(SubTxs(true));
    env.Send(third);
    BOOST_CHECK(env.session->Take().empty());
    BOOST_CHECK_EQUAL(env.ClientCount(), 2u);

    // A second session from the same IP shares the per-IP limit
    auto session2 = std::make_shared<FakeSession>();
    auto handler2 = MakeChronikWsHandler(session2, env.hub, env.limiter, {},
                                         env.exec.Post());
    const std::string s = SubBlocks().SerializeAsString();
    handler2->OnBinary(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t *>(s.data()), s.size()));
    BOOST_REQUIRE_EQUAL(session2->Take().size(), 1u);
    handler2->OnClosed();

    // Global limit
    WsEnv global(1, 10);
    global.Send(SubBlocks());
    global.Send(SubTxs());
    msgs = global.session->Take();
    BOOST_REQUIRE_EQUAL(msgs.size(), 1u);
    BOOST_CHECK_EQUAL(msgs[0].error().msg(),
                      WsSubscriptionLimitErrorMessage(SubscriptionLimitError{
                          SubscriptionLimitError::Kind::Global, 1}));
}

BOOST_AUTO_TEST_CASE(close_releases_everything) {
    WsEnv env;
    const Tx tx = MakeTx(9, th::P2pkh(0x33));
    env.Send(SubBlocks());
    env.Send(SubTxId(tx.txid));
    env.Send(SubScript("p2pkh", Payload20(0x33)));
    env.Send(SubLokad({'Q', 'Q', 'Q', 'Q'}));
    BOOST_CHECK_EQUAL(env.ClientCount(), 4u);
    // Queue a message, then close before the drain runs
    {
        auto subs = env.hub->Write();
        subs->BroadcastBlockMsg(MakeBlockMsg(1));
    }
    env.handler->OnClosed();
    env.exec.RunAll();
    BOOST_CHECK(env.session->Take().empty());
    BOOST_CHECK_EQUAL(env.ClientCount(), 0u);
    BOOST_CHECK_EQUAL(env.limiter->Total(), 0u);
    // A new subscriber of the same member still works after the cleanup
    auto rx = env.hub->Write()->SubsTxId().SubscribeToMember(
        ByteView(tx.txid.b.data(), 32));
    {
        auto subs = env.hub->Write();
        subs->HandleTxEvent(tx, TxMsgType::Confirmed());
    }
    BOOST_CHECK_EQUAL(rx.Len(), 1u);
    // Events after close are ignored; OnClosed is idempotent
    env.handler->OnClosed();
    env.Send(SubBlocks());
    BOOST_CHECK(env.session->Take().empty());
    BOOST_CHECK_EQUAL(env.limiter->Total(), 0u);
}

BOOST_AUTO_TEST_CASE(destroy_without_close_releases) {
    WsEnv env;
    env.Send(SubBlocks());
    env.Send(SubTxId(TxId{}));
    BOOST_CHECK_EQUAL(env.limiter->Total(), 2u);
    env.handler.reset();
    BOOST_CHECK_EQUAL(env.limiter->Total(), 0u);
    // Nothing reaches the session any more
    {
        auto subs = env.hub->Write();
        subs->BroadcastBlockMsg(MakeBlockMsg(1));
    }
    env.exec.RunAll();
    BOOST_CHECK(env.session->Take().empty());
}

BOOST_AUTO_TEST_CASE(drain_is_coalesced) {
    WsEnv env;
    env.Send(SubTxs());
    {
        auto subs = env.hub->Write();
        for (uint8_t i = 0; i < 10; ++i) {
            TxId txid;
            txid.b[0] = i;
            subs->BroadcastTxMsg(txid, TxMsgType::Confirmed());
        }
    }
    // Ten wakers, but only one drain was posted
    BOOST_CHECK_EQUAL(env.exec.tasks.size(), 1u);
    env.exec.RunAll();
    BOOST_CHECK_EQUAL(env.session->Take().size(), 10u);
}

BOOST_AUTO_TEST_CASE(debug_logs) {
    WsEnv env;
    env.Send(SubBlocks());
    env.Send(SubTxs());
    env.Send(SubLokad({0x01, 0x02, 0x03, 0x04}));
    env.Send(SubLokad({0x01, 0x02, 0x03, 0x04}, true));
    env.Send(SubBlocks(true));
    const std::vector<std::string> expected = {
        "WS subscribe to blocks\n",
        "WS subscribe to all txs\n",
        "WS subscribe to LOKAD ID 01020304\n",
        "WS unsubscribe from LOKAD ID 01020304\n",
        "WS unsubscribe from blocks\n",
    };
    BOOST_CHECK(env.logs == expected);
}

BOOST_AUTO_TEST_CASE(optional_connection_observer_balances_close_and_destruction) {
    int64_t active = 0;
    WsHandlerSettings settings;
    settings.observe_connections = [&](int32_t delta) {
        active += delta;
        throw 1;
    };
    {
        WsEnv env(1000, 1000, settings);
        BOOST_CHECK_EQUAL(active, 1);
        env.handler->OnClosed();
        env.handler->OnClosed();
        BOOST_CHECK_EQUAL(active, 0);
    }
    BOOST_CHECK_EQUAL(active, 0);
    {
        WsEnv env(1000, 1000, settings);
        BOOST_CHECK_EQUAL(active, 1);
    }
    BOOST_CHECK_EQUAL(active, 0);
}

BOOST_AUTO_TEST_SUITE_END()
