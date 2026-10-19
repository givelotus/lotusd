// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// subs.rs / subs_group.rs have no Rust #[test]s. These tests pin the tokio
// broadcast semantics the port reproduces (ring buffer per receiver, drop
// oldest on overflow, Lagged once, Closed after drain) and the group
// fan-out/dedup/unsubscribe behavior of SubsGroup and Subs.

#include <chronik/native/subs.h>

#include <test/test_sha256.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <thread>

using namespace chronik::native;
using namespace std::chrono_literals;

namespace {

Sha256Fn TestSha() {
    return [](ByteView d, uint8_t out[32]) { test::TestSha256(d, out); };
}

TxId MakeTxId(uint8_t n) {
    TxId t;
    t.b.fill(n);
    t.b[31] = 0xee;
    return t;
}

TxMsg Msg(uint8_t n, TxMsgType type = TxMsgType::AddedToMempool()) {
    return TxMsg{type, MakeTxId(n)};
}

Bytes P2pkh(uint8_t n) {
    Bytes s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) {
        s.push_back(n);
    }
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

Bytes OpReturnLokad(char a, char b, char c, char d) {
    return Bytes{0x6a, 0x04, uint8_t(a), uint8_t(b), uint8_t(c), uint8_t(d)};
}

TxInput InputWithCoin(const Bytes &script, uint8_t prev = 1) {
    TxInput in;
    in.prev_out = {MakeTxId(prev), 0};
    in.coin = Coin{TxOutput{1000, script}, 1, false};
    return in;
}

TxInput InputWithoutCoin(uint8_t prev = 2) {
    TxInput in;
    in.prev_out = {MakeTxId(prev), 0};
    return in;
}

Tx MakeTx(uint8_t n, std::vector<TxInput> inputs,
          std::vector<Bytes> output_scripts) {
    Tx tx;
    tx.txid = MakeTxId(n);
    tx.version = 1;
    tx.inputs = std::move(inputs);
    for (auto &s : output_scripts) {
        tx.outputs.push_back(TxOutput{546, std::move(s)});
    }
    return tx;
}

template <typename T> std::optional<T> Next(BroadcastReceiver<T> &r) {
    auto res = r.TryRecv();
    if (res.status != RecvStatus::Message) {
        return std::nullopt;
    }
    return res.msg;
}

template <typename T> size_t Drain(BroadcastReceiver<T> &r) {
    size_t n = 0;
    while (r.TryRecv().status == RecvStatus::Message) {
        ++n;
    }
    return n;
}

} // namespace

BOOST_AUTO_TEST_SUITE(subs_tests)

// ---- BroadcastSender / BroadcastReceiver (tokio broadcast) ----

BOOST_AUTO_TEST_CASE(broadcast_capacity_rounds_to_power_of_two) {
    BOOST_CHECK_EQUAL(BroadcastSender<int>(1).Capacity(), 1u);
    BOOST_CHECK_EQUAL(BroadcastSender<int>(3).Capacity(), 4u);
    BOOST_CHECK_EQUAL(BroadcastSender<int>(16).Capacity(), 16u);
    BOOST_CHECK_EQUAL(BroadcastSender<int>(17).Capacity(), 32u);
    BOOST_CHECK_EQUAL(BLOCK_CHANNEL_CAPACITY, 16u);
    BOOST_CHECK_EQUAL(TXS_CHANNEL_CAPACITY, 32u);
    BOOST_CHECK_EQUAL(GROUP_CHANNEL_CAPACITY, 16u);
}

BOOST_AUTO_TEST_CASE(broadcast_send_without_receivers_fails) {
    BroadcastSender<int> tx(4);
    BOOST_CHECK_EQUAL(tx.ReceiverCount(), 0u);
    BOOST_CHECK(!tx.Send(1));
    auto rx = tx.Subscribe();
    BOOST_CHECK_EQUAL(tx.ReceiverCount(), 1u);
    // Messages sent before subscribing are never seen
    BOOST_CHECK(rx.TryRecv().status == RecvStatus::Empty);
    BOOST_CHECK(tx.Send(2));
    auto rx2 = tx.Subscribe();
    BOOST_CHECK(tx.Send(3));
    BOOST_CHECK_EQUAL(*Next(rx), 2);
    BOOST_CHECK_EQUAL(*Next(rx), 3);
    BOOST_CHECK(rx.TryRecv().status == RecvStatus::Empty);
    BOOST_CHECK_EQUAL(*Next(rx2), 3);
    BOOST_CHECK(rx2.TryRecv().status == RecvStatus::Empty);
}

BOOST_AUTO_TEST_CASE(broadcast_overflow_drops_oldest) {
    BroadcastSender<int> tx(16);
    auto rx = tx.Subscribe();
    for (int i = 0; i < 20; ++i) {
        BOOST_CHECK(tx.Send(i));
    }
    BOOST_CHECK_EQUAL(rx.Len(), 16u);
    // tokio: Lagged(4) once, then the oldest retained message
    auto r = rx.TryRecv();
    BOOST_CHECK(r.status == RecvStatus::Lagged);
    BOOST_CHECK_EQUAL(r.lagged, 4u);
    BOOST_CHECK(!r.msg);
    for (int i = 4; i < 20; ++i) {
        auto m = rx.TryRecv();
        BOOST_REQUIRE(m.status == RecvStatus::Message);
        BOOST_CHECK_EQUAL(*m.msg, i);
    }
    BOOST_CHECK(rx.TryRecv().status == RecvStatus::Empty);
}

BOOST_AUTO_TEST_CASE(broadcast_overflow_exactly_capacity_is_lossless) {
    BroadcastSender<int> tx(4);
    auto rx = tx.Subscribe();
    for (int i = 0; i < 4; ++i) {
        tx.Send(i);
    }
    for (int i = 0; i < 4; ++i) {
        BOOST_CHECK_EQUAL(*Next(rx), i);
    }
    // Interleaved reads: never lags while the reader keeps up
    for (int i = 0; i < 100; ++i) {
        tx.Send(i);
        BOOST_CHECK_EQUAL(*Next(rx), i);
    }
}

BOOST_AUTO_TEST_CASE(broadcast_lag_then_more_lag) {
    BroadcastSender<int> tx(2);
    auto rx = tx.Subscribe();
    for (int i = 0; i < 5; ++i) {
        tx.Send(i); // keeps 3, 4; lagged 3
    }
    auto r = rx.TryRecv();
    BOOST_CHECK(r.status == RecvStatus::Lagged);
    BOOST_CHECK_EQUAL(r.lagged, 3u);
    BOOST_CHECK_EQUAL(*Next(rx), 3);
    tx.Send(5);
    tx.Send(6); // drops 4
    r = rx.TryRecv();
    BOOST_CHECK(r.status == RecvStatus::Lagged);
    BOOST_CHECK_EQUAL(r.lagged, 1u);
    BOOST_CHECK_EQUAL(*Next(rx), 5);
    BOOST_CHECK_EQUAL(*Next(rx), 6);
}

BOOST_AUTO_TEST_CASE(broadcast_receivers_lag_independently) {
    BroadcastSender<int> tx(4);
    auto slow = tx.Subscribe();
    auto fast = tx.Subscribe();
    for (int i = 0; i < 10; ++i) {
        tx.Send(i);
        BOOST_CHECK_EQUAL(*Next(fast), i);
    }
    auto r = slow.TryRecv();
    BOOST_CHECK(r.status == RecvStatus::Lagged);
    BOOST_CHECK_EQUAL(r.lagged, 6u);
    BOOST_CHECK_EQUAL(*Next(slow), 6);
}

BOOST_AUTO_TEST_CASE(broadcast_receiver_drop_and_move) {
    BroadcastSender<int> tx(4);
    {
        auto rx = tx.Subscribe();
        BOOST_CHECK_EQUAL(tx.ReceiverCount(), 1u);
        BroadcastReceiver<int> moved = std::move(rx);
        BOOST_CHECK(!rx.Valid());
        BOOST_CHECK(moved.Valid());
        BOOST_CHECK_EQUAL(tx.ReceiverCount(), 1u);
        tx.Send(7);
        BOOST_CHECK_EQUAL(*Next(moved), 7);
        BOOST_CHECK(rx.TryRecv().status == RecvStatus::Closed);
    }
    BOOST_CHECK_EQUAL(tx.ReceiverCount(), 0u);
    BOOST_CHECK(!tx.Send(8));
}

BOOST_AUTO_TEST_CASE(broadcast_closed_after_drain) {
    auto tx = std::make_unique<BroadcastSender<int>>(4);
    auto rx = tx->Subscribe();
    int wakes = 0;
    rx.SetWaker([&] { ++wakes; });
    tx->Send(1);
    tx->Send(2);
    BOOST_CHECK_EQUAL(wakes, 2);
    tx.reset();
    BOOST_CHECK_EQUAL(wakes, 3); // woken on close
    BOOST_CHECK_EQUAL(*Next(rx), 1);
    BOOST_CHECK_EQUAL(*Next(rx), 2);
    BOOST_CHECK(rx.TryRecv().status == RecvStatus::Closed);
}

BOOST_AUTO_TEST_CASE(broadcast_wakers_deferred) {
    BroadcastSender<int> tx(4);
    auto rx = tx.Subscribe();
    int wakes = 0;
    rx.SetWaker([&] {
        // Must not be called under the channel lock: receiving works here
        BOOST_CHECK(rx.TryRecv().status == RecvStatus::Message);
        ++wakes;
    });
    WakerList deferred;
    tx.Send(1, &deferred);
    BOOST_CHECK_EQUAL(wakes, 0);
    BOOST_CHECK_EQUAL(deferred.size(), 1u);
    InvokeWakers(deferred);
    BOOST_CHECK_EQUAL(wakes, 1);
    BOOST_CHECK(deferred.empty());
    tx.Send(2); // immediate
    BOOST_CHECK_EQUAL(wakes, 2);
    rx.SetWaker({});
    tx.Send(3);
    BOOST_CHECK_EQUAL(wakes, 2);
}

BOOST_AUTO_TEST_CASE(broadcast_recv_for_cross_thread) {
    BroadcastSender<int> tx(4);
    auto rx = tx.Subscribe();
    BOOST_CHECK(rx.RecvFor(10ms).status == RecvStatus::Empty);
    std::thread t([&] {
        std::this_thread::sleep_for(20ms);
        tx.Send(42);
    });
    auto r = rx.RecvFor(5s);
    t.join();
    BOOST_REQUIRE(r.status == RecvStatus::Message);
    BOOST_CHECK_EQUAL(*r.msg, 42);
}

BOOST_AUTO_TEST_CASE(broadcast_concurrent_send_recv) {
    BroadcastSender<int> tx(32);
    auto rx = tx.Subscribe();
    constexpr int N = 20000;
    std::thread t([&] {
        for (int i = 0; i < N; ++i) {
            tx.Send(i);
        }
    });
    int last = -1;
    uint64_t received = 0, lagged = 0;
    while (last < N - 1) {
        auto r = rx.RecvFor(5s);
        if (r.status == RecvStatus::Lagged) {
            lagged += r.lagged;
        } else if (r.status == RecvStatus::Message) {
            BOOST_REQUIRE(*r.msg > last); // order preserved, oldest dropped
            last = *r.msg;
            ++received;
        } else {
            BOOST_FAIL("unexpected status");
        }
    }
    t.join();
    BOOST_CHECK_EQUAL(received + lagged, uint64_t(N));
}

// ---- messages ----

BOOST_AUTO_TEST_CASE(msg_equality) {
    BOOST_CHECK(TxMsgType::Finalized(TxFinalizationReason::PreConsensus) !=
                TxMsgType::Finalized(TxFinalizationReason::PostConsensus));
    BOOST_CHECK(TxMsgType::Confirmed() == TxMsgType::Confirmed());
    BOOST_CHECK(TxMsgType::Confirmed() != TxMsgType::Invalidated());
    BOOST_CHECK(Msg(1) == Msg(1));
    BOOST_CHECK(Msg(1) != Msg(2));

    BlockMsg a{BlockMsgType::Disconnected, MakeTxId(3), 7, 1234, nullptr};
    BlockMsg b = a;
    BOOST_CHECK(a == b);
    b.coinbase_tx = std::make_shared<Tx>(MakeTx(9, {}, {P2pkh(1)}));
    BOOST_CHECK(!(a == b));
    a.coinbase_tx = std::make_shared<Tx>(MakeTx(9, {}, {P2pkh(1)}));
    BOOST_CHECK(a == b);
    a.coinbase_tx = std::make_shared<Tx>(MakeTx(9, {}, {P2pkh(2)}));
    BOOST_CHECK(!(a == b));
}

// ---- group kinds ----

BOOST_AUTO_TEST_CASE(kind_txid) {
    TxIdSubsGroupKind kind;
    const TxId txid = MakeTxId(5);
    const auto be = txid.Reversed();
    BOOST_CHECK(kind.SerMember(txid.b) == Bytes(be.begin(), be.end()));
    BOOST_CHECK(!kind.IsHashMemberSupported());
    std::vector<SubsMember> members;
    kind.TxMembers(MakeTx(5, {InputWithCoin(P2pkh(1))}, {P2pkh(2)}), {}, members);
    BOOST_REQUIRE_EQUAL(members.size(), 1u);
    BOOST_CHECK(members[0].ser == Bytes(be.begin(), be.end()));
    BOOST_CHECK(!members[0].hash);
}

BOOST_AUTO_TEST_CASE(kind_script) {
    ScriptSubsGroupKind kind(TestSha());
    BOOST_CHECK(kind.IsHashMemberSupported());
    // Compressed P2PKH: 0x00 || hash160
    Bytes expected{0x00};
    for (int i = 0; i < 20; ++i) {
        expected.push_back(0x11);
    }
    BOOST_CHECK(kind.SerMember(P2pkh(0x11)) == expected);
    // scripthash = SHA-256 reversed
    uint8_t digest[32];
    const Bytes s = P2pkh(0x11);
    test::TestSha256(s, digest);
    const auto h = kind.HashMember(s);
    for (size_t i = 0; i < 32; ++i) {
        BOOST_CHECK_EQUAL(h[i], digest[31 - i]);
    }

    // Inputs stop at the first input without a coin; OP_RETURN outputs skip.
    const Tx tx =
        MakeTx(1,
               {InputWithCoin(P2pkh(1)), InputWithoutCoin(),
                InputWithCoin(P2pkh(3))},
               {OpReturnLokad('S', 'L', 'P', 0), P2pkh(4), Bytes{}, P2pkh(1)});
    std::vector<SubsMember> members;
    kind.TxMembers(tx, {}, members);
    BOOST_REQUIRE_EQUAL(members.size(), 4u);
    BOOST_CHECK(members[0].ser == kind.SerMember(P2pkh(1)));
    BOOST_CHECK(members[1].ser == kind.SerMember(P2pkh(4)));
    BOOST_CHECK(members[2].ser == kind.SerMember(Bytes{}));
    BOOST_CHECK(members[3].ser == kind.SerMember(P2pkh(1)));
    for (const auto &m : members) {
        BOOST_CHECK(m.hash);
    }
    BOOST_CHECK(*members[1].hash == kind.HashMember(P2pkh(4)));
}

BOOST_AUTO_TEST_CASE(kind_token_id) {
    TokenIdSubsGroupKind kind;
    const Tx tx = MakeTx(1, {InputWithCoin(P2pkh(1)), InputWithCoin(P2pkh(2))},
                         {P2pkh(3), P2pkh(4)});
    std::vector<SubsMember> members;
    kind.TxMembers(tx, {}, members); // no aux
    BOOST_CHECK(members.empty());

    TokenIdSubsAux aux;
    const token::TokenId t1{MakeTxId(0x41)}, t2{MakeTxId(0x42)};
    aux.txs[tx.txid] = {{std::nullopt, t1}, {t2, std::nullopt}};
    kind.TxMembers(tx, SubsAux{&aux}, members);
    BOOST_REQUIRE_EQUAL(members.size(), 2u);
    const auto be1 = t1.ToBeBytes(), be2 = t2.ToBeBytes();
    BOOST_CHECK(members[0].ser == Bytes(be1.begin(), be1.end()));
    BOOST_CHECK(members[1].ser == Bytes(be2.begin(), be2.end()));
    BOOST_CHECK(kind.SerMember(t1.txid.b) == members[0].ser);

    members.clear();
    kind.TxMembers(MakeTx(2, {}, {}), SubsAux{&aux}, members);
    BOOST_CHECK(members.empty());
}

BOOST_AUTO_TEST_CASE(kind_lokad_id) {
    LokadIdSubsGroupKind kind;
    const Tx tx = MakeTx(1, {InputWithCoin(P2pkh(1))},
                         {OpReturnLokad('S', 'L', 'P', '2'), P2pkh(4)});
    std::vector<SubsMember> members;
    kind.TxMembers(tx, {}, members);
    BOOST_REQUIRE_GE(members.size(), 1u);
    BOOST_CHECK(members[0].ser == (Bytes{'S', 'L', 'P', '2'}));
    BOOST_CHECK(kind.SerMember(Bytes{'a', 'b', 'c', 'd'}) ==
                (Bytes{'a', 'b', 'c', 'd'}));
}

// ---- SubsGroup ----

BOOST_AUTO_TEST_CASE(group_subscribe_shares_channel) {
    SubsGroup group(std::make_unique<TxIdSubsGroupKind>());
    BOOST_CHECK(group.IsEmpty());
    const TxId txid = MakeTxId(1);
    auto r1 = group.SubscribeToMember(txid.b);
    auto r2 = group.SubscribeToMember(txid.b);
    BOOST_CHECK_EQUAL(group.NumChannels(), 1u);
    group.HandleTxEvent(MakeTx(1, {}, {}), {}, TxMsgType::AddedToMempool());
    group.HandleTxEvent(MakeTx(2, {}, {}), {}, TxMsgType::AddedToMempool());
    BOOST_CHECK(*Next(r1) == Msg(1));
    BOOST_CHECK(*Next(r2) == Msg(1));
    BOOST_CHECK(r1.TryRecv().status == RecvStatus::Empty);
}

BOOST_AUTO_TEST_CASE(group_clean_unsubscribe) {
    SubsGroup group(std::make_unique<TxIdSubsGroupKind>());
    const TxId txid = MakeTxId(1);
    auto r1 = group.SubscribeToMember(txid.b);
    {
        auto r2 = group.SubscribeToMember(txid.b);
        // Receivers left: unsubscribe keeps the channel
        group.UnsubscribeFromMember(txid.b);
        BOOST_CHECK_EQUAL(group.NumChannels(), 1u);
    }
    group.UnsubscribeFromMember(txid.b);
    BOOST_CHECK_EQUAL(group.NumChannels(), 1u);
    r1 = BroadcastReceiver<TxMsg>();
    group.UnsubscribeFromMember(txid.b);
    BOOST_CHECK(group.IsEmpty());
    // Unknown member: no-op
    group.UnsubscribeFromMember(MakeTxId(9).b);
    BOOST_CHECK(group.IsEmpty());
}

BOOST_AUTO_TEST_CASE(group_unclean_unsubscribe) {
    SubsGroup group(std::make_unique<TxIdSubsGroupKind>());
    {
        auto r = group.SubscribeToMember(MakeTxId(1).b);
    }
    BOOST_CHECK_EQUAL(group.NumChannels(), 1u);
    // Sending to a channel without receivers removes it
    group.HandleTxEvent(MakeTx(1, {}, {}), {}, TxMsgType::Confirmed());
    BOOST_CHECK(group.IsEmpty());
}

BOOST_AUTO_TEST_CASE(group_notifies_member_once_per_tx) {
    SubsGroup group(std::make_unique<ScriptSubsGroupKind>(TestSha()));
    auto r = group.SubscribeToMember(P2pkh(1));
    auto other = group.SubscribeToMember(P2pkh(2));
    const Tx tx = MakeTx(7,
                         {InputWithCoin(P2pkh(1)), InputWithCoin(P2pkh(1))},
                         {P2pkh(1), P2pkh(1), P2pkh(3)});
    group.HandleTxEvent(tx, {}, TxMsgType::AddedToMempool());
    BOOST_CHECK(*Next(r) == Msg(7));
    BOOST_CHECK(r.TryRecv().status == RecvStatus::Empty);
    BOOST_CHECK(other.TryRecv().status == RecvStatus::Empty);
}

BOOST_AUTO_TEST_CASE(group_scripthash_member) {
    ScriptSubsGroupKind kind(TestSha());
    const auto hash = kind.HashMember(P2pkh(1));
    SubsGroup group(std::make_unique<ScriptSubsGroupKind>(TestSha()));
    auto by_hash = group.SubscribeToHashMember(hash);
    auto by_script = group.SubscribeToMember(P2pkh(1));
    BOOST_CHECK_EQUAL(group.NumChannels(), 2u);
    const Tx tx = MakeTx(3, {InputWithCoin(P2pkh(1))}, {P2pkh(1)});
    group.HandleTxEvent(tx, {}, TxMsgType::RemovedFromMempool());
    BOOST_CHECK(*Next(by_hash) == Msg(3, TxMsgType::RemovedFromMempool()));
    BOOST_CHECK(by_hash.TryRecv().status == RecvStatus::Empty);
    BOOST_CHECK(*Next(by_script) == Msg(3, TxMsgType::RemovedFromMempool()));
    BOOST_CHECK(by_script.TryRecv().status == RecvStatus::Empty);

    by_hash = BroadcastReceiver<TxMsg>();
    group.UnsubscribeFromHashMember(hash);
    BOOST_CHECK_EQUAL(group.NumChannels(), 1u);
}

BOOST_AUTO_TEST_CASE(group_ring_buffer_overflow) {
    SubsGroup sgroup(std::make_unique<ScriptSubsGroupKind>(TestSha()));
    auto r = sgroup.SubscribeToMember(P2pkh(1));
    for (uint8_t i = 0; i < 20; ++i) {
        sgroup.HandleTxEvent(MakeTx(i, {}, {P2pkh(1)}), {},
                             TxMsgType::AddedToMempool());
    }
    auto res = r.TryRecv();
    BOOST_CHECK(res.status == RecvStatus::Lagged);
    BOOST_CHECK_EQUAL(res.lagged, 20u - GROUP_CHANNEL_CAPACITY);
    for (uint8_t i = 4; i < 20; ++i) {
        BOOST_CHECK(*Next(r) == Msg(i));
    }
    BOOST_CHECK(r.TryRecv().status == RecvStatus::Empty);
}

BOOST_AUTO_TEST_CASE(group_token_id_with_aux) {
    SubsGroup group(std::make_unique<TokenIdSubsGroupKind>());
    const token::TokenId token{MakeTxId(0x55)};
    auto r = group.SubscribeToMember(token.txid.b);
    const Tx tx = MakeTx(1, {InputWithCoin(P2pkh(1))}, {P2pkh(2), P2pkh(3)});
    TokenIdSubsAux aux;
    aux.txs[tx.txid] = {{token}, {token, token}};
    group.HandleTxEvent(tx, {}, TxMsgType::AddedToMempool()); // no aux
    BOOST_CHECK(r.TryRecv().status == RecvStatus::Empty);
    group.HandleTxEvent(tx, SubsAux{&aux}, TxMsgType::AddedToMempool());
    BOOST_CHECK(*Next(r) == Msg(1));
    BOOST_CHECK(r.TryRecv().status == RecvStatus::Empty);
}

// ---- Subs ----

BOOST_AUTO_TEST_CASE(subs_block_msgs) {
    Subs subs(TestSha());
    BlockMsg msg{BlockMsgType::Connected, MakeTxId(1), 1, 100, nullptr};
    subs.BroadcastBlockMsg(msg); // no receiver: dropped
    auto r = subs.SubToBlockMsgs();
    msg.height = 2;
    subs.BroadcastBlockMsg(msg);
    auto got = Next(r);
    BOOST_REQUIRE(got);
    BOOST_CHECK_EQUAL(got->height, 2);
    BOOST_CHECK(r.TryRecv().status == RecvStatus::Empty);
    for (int i = 0; i < 17; ++i) {
        msg.height = 10 + i;
        subs.BroadcastBlockMsg(msg);
    }
    auto res = r.TryRecv();
    BOOST_CHECK(res.status == RecvStatus::Lagged);
    BOOST_CHECK_EQUAL(res.lagged, 1u);
    BOOST_CHECK_EQUAL(Next(r)->height, 11);
}

BOOST_AUTO_TEST_CASE(subs_tx_event_fans_out) {
    Subs subs(TestSha());
    auto all = subs.SubToTxMsgs();
    auto by_txid = subs.SubsTxId().SubscribeToMember(MakeTxId(1).b);
    auto by_script = subs.SubsScript().SubscribeToMember(P2pkh(9));
    auto by_lokad = subs.SubsLokadId().SubscribeToMember(Bytes{'S', 'L', 'P', 0});
    const Tx tx = MakeTx(1, {InputWithCoin(P2pkh(9))},
                         {OpReturnLokad('S', 'L', 'P', 0), P2pkh(2)});
    subs.HandleTxEvent(tx, TxMsgType::Finalized(TxFinalizationReason::PreConsensus));
    const TxMsg expected =
        Msg(1, TxMsgType::Finalized(TxFinalizationReason::PreConsensus));
    BOOST_CHECK(*Next(all) == expected);
    BOOST_CHECK(*Next(by_txid) == expected);
    BOOST_CHECK(*Next(by_script) == expected);
    BOOST_CHECK(*Next(by_lokad) == expected);

    subs.HandleTxEvent(MakeTx(2, {}, {P2pkh(3)}), TxMsgType::AddedToMempool());
    BOOST_CHECK(*Next(all) == Msg(2));
    BOOST_CHECK(by_txid.TryRecv().status == RecvStatus::Empty);
    BOOST_CHECK(by_script.TryRecv().status == RecvStatus::Empty);
}

BOOST_AUTO_TEST_CASE(subs_block_tx_events_short_circuit) {
    Subs subs(TestSha());
    auto all = subs.SubToTxMsgs();
    std::vector<Tx> txs{MakeTx(1, {}, {P2pkh(1)}), MakeTx(2, {}, {P2pkh(2)})};
    // Rust quirk preserved: with no GROUP subscriptions, nothing is sent,
    // not even to all-tx subscribers.
    subs.HandleBlockTxEvents(txs, TxMsgType::Confirmed());
    BOOST_CHECK(all.TryRecv().status == RecvStatus::Empty);

    auto by_txid = subs.SubsTxId().SubscribeToMember(MakeTxId(2).b);
    subs.HandleBlockTxEvents(txs, TxMsgType::Confirmed());
    BOOST_CHECK(*Next(all) == Msg(1, TxMsgType::Confirmed()));
    BOOST_CHECK(*Next(all) == Msg(2, TxMsgType::Confirmed()));
    BOOST_CHECK(all.TryRecv().status == RecvStatus::Empty);
    BOOST_CHECK(*Next(by_txid) == Msg(2, TxMsgType::Confirmed()));

    // TxRef overload
    std::vector<TxRef> refs{std::make_shared<Tx>(txs[1])};
    subs.HandleBlockTxEvents(refs, TxMsgType::Finalized(
                                       TxFinalizationReason::PostConsensus));
    BOOST_CHECK(*Next(all) ==
                Msg(2, TxMsgType::Finalized(TxFinalizationReason::PostConsensus)));
    BOOST_CHECK(*Next(by_txid) ==
                Msg(2, TxMsgType::Finalized(TxFinalizationReason::PostConsensus)));
}

BOOST_AUTO_TEST_CASE(subs_token_id_aux) {
    Subs subs(TestSha());
    const token::TokenId token{MakeTxId(0x77)};
    auto r = subs.SubsTokenId().SubscribeToMember(token.txid.b);
    const Tx tx = MakeTx(4, {}, {P2pkh(1)});
    TokenIdSubsAux aux;
    aux.txs[tx.txid] = {{}, {token}};
    subs.HandleTxEvent(tx, TxMsgType::AddedToMempool(), SubsAux{&aux});
    BOOST_CHECK(*Next(r) == Msg(4));
}

BOOST_AUTO_TEST_CASE(subs_txs_overflow_capacity_32) {
    Subs subs(TestSha());
    auto all = subs.SubToTxMsgs();
    for (uint8_t i = 0; i < 40; ++i) {
        subs.BroadcastTxMsg(MakeTxId(i), TxMsgType::AddedToMempool());
    }
    auto res = all.TryRecv();
    BOOST_CHECK(res.status == RecvStatus::Lagged);
    BOOST_CHECK_EQUAL(res.lagged, 8u);
    BOOST_CHECK(*Next(all) == Msg(8));
    BOOST_CHECK_EQUAL(Drain(all), 31u);
}

BOOST_AUTO_TEST_CASE(hub_wakers_run_after_unlock) {
    SubsHub hub(TestSha());
    BroadcastReceiver<TxMsg> r = hub.Write()->SubToTxMsgs();
    std::atomic<int> wakes{0};
    r.SetWaker([&] {
        // Taking the hub lock from a waker must not deadlock
        auto subs = hub.Write();
        (void)subs;
        ++wakes;
    });
    {
        auto subs = hub.Write();
        subs->BroadcastTxMsg(MakeTxId(1), TxMsgType::AddedToMempool());
        subs->BroadcastTxMsg(MakeTxId(2), TxMsgType::AddedToMempool());
        BOOST_CHECK_EQUAL(wakes.load(), 0);
        BOOST_CHECK_EQUAL(subs->PendingWakers().size(), 2u);
    }
    BOOST_CHECK_EQUAL(wakes.load(), 2);
    BOOST_CHECK(*Next(r) == Msg(1));
    BOOST_CHECK(*Next(r) == Msg(2));
}

BOOST_AUTO_TEST_CASE(hub_concurrent_publish_and_subscribe) {
    SubsHub hub(TestSha());
    std::atomic<bool> stop{false};
    std::thread writer([&] {
        uint8_t n = 0;
        while (!stop) {
            auto subs = hub.Write();
            subs->HandleTxEvent(MakeTx(n++, {}, {P2pkh(1)}),
                                TxMsgType::AddedToMempool());
        }
    });
    for (int i = 0; i < 200; ++i) {
        BroadcastReceiver<TxMsg> r;
        {
            auto subs = hub.Write();
            r = subs->SubsScript().SubscribeToMember(P2pkh(1));
        }
        auto res = r.RecvFor(5s);
        BOOST_REQUIRE(res.status == RecvStatus::Message ||
                      res.status == RecvStatus::Lagged);
        r = BroadcastReceiver<TxMsg>();
        hub.Write()->SubsScript().UnsubscribeFromMember(P2pkh(1));
    }
    stop = true;
    writer.join();
}

BOOST_AUTO_TEST_SUITE_END()
