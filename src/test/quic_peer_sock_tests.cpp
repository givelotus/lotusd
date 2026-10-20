// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <crypto/common.h>
#include <net_quic/quic_peer_sock.h>
#include <protocol.h>
#include <test/util/setup_common.h>

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

namespace {
std::vector<uint8_t> Message(const char *type, size_t payload = 0) {
    std::vector<uint8_t> msg(CMessageHeader::HEADER_SIZE + payload, 0);
    std::memcpy(msg.data() + CMessageHeader::MESSAGE_START_SIZE, type,
                std::strlen(type));
    WriteLE32(msg.data() + CMessageHeader::MESSAGE_SIZE_OFFSET, payload);
    return msg;
}
struct Peer {
    std::shared_ptr<QuicPeerChannel> channel;
    std::unique_ptr<QuicPeerSock> sock;
    explicit Peer(uint64_t receive_limit = QuicPeerChannel::RX_QUEUE_LIMIT) {
        int fds[2];
        BOOST_REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        channel = std::make_shared<QuicPeerChannel>(
            fds[1], std::make_shared<QuicTransportInfo>(), [] {},
            receive_limit);
        sock = std::make_unique<QuicPeerSock>(fds[0], channel, false);
    }
    void Receive(StreamClass cls, const std::vector<uint8_t> &msg) {
        BOOST_REQUIRE(channel->PushRx({cls, quic_frame::FLAG_RAW, msg,
                                       quic_frame::HEADER_SIZE + msg.size()}));
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(quic_peer_sock_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(configured_receive_threshold_and_frame_cap) {
    Peer p{40};
    p.Receive(StreamClass::CONTROL, Message("version"));
    BOOST_CHECK(p.channel->RxHasRoom());
    p.Receive(StreamClass::CONTROL, Message("verack"));
    BOOST_CHECK(!p.channel->RxHasRoom());
    BOOST_REQUIRE(p.channel->PopRx(true));
    BOOST_CHECK(p.channel->RxHasRoom());
    BOOST_CHECK(p.channel->credit_wanted);
    Peer small{0};
    BOOST_CHECK(small.channel->RxHasRoom());
    small.Receive(StreamClass::CONTROL, Message("version"));
    BOOST_CHECK(!small.channel->RxHasRoom());
    BOOST_REQUIRE(small.channel->PopRx(true));
    BOOST_CHECK(small.channel->RxHasRoom());

    Peer bounded;
    for (size_t i{0}; i < QuicPeerChannel::MAX_PENDING_RX_FRAMES; ++i) {
        BOOST_REQUIRE(
            bounded.channel->PushRx({StreamClass::CONTROL, 0, {}, 5}));
    }
    BOOST_CHECK(!bounded.channel->PushRx({StreamClass::CONTROL, 0, {}, 5}));
    BOOST_CHECK_EQUAL(bounded.channel->RxBuffered(),
                      5 * QuicPeerChannel::MAX_PENDING_RX_FRAMES);
}

BOOST_AUTO_TEST_CASE(large_frame_followed_by_fragmented_frame) {
    StreamFramer encoder{false};
    const auto first{Message("block", 1024 * 1024)};
    const auto second{Message("ping", 8)};
    auto bytes{encoder.Encode(StreamClass::BLOCK, first)};
    const auto tail{encoder.Encode(StreamClass::CONTROL, second)};
    bytes.insert(bytes.end(), tail.begin(), tail.begin() + 2);
    FrameReassembler reassembler;
    std::vector<FrameReassembler::Frame> frames;
    BOOST_REQUIRE(reassembler.Feed(bytes, frames));
    BOOST_REQUIRE_EQUAL(frames.size(), 1U);
    BOOST_CHECK(frames[0].body == first);
    BOOST_CHECK_EQUAL(reassembler.Buffered(), 2U);
    BOOST_REQUIRE(reassembler.Feed(Span{tail}.subspan(2), frames));
    BOOST_REQUIRE_EQUAL(frames.size(), 2U);
    BOOST_CHECK(frames[1].body == second);
    BOOST_CHECK_EQUAL(reassembler.Buffered(), 0U);
}

BOOST_AUTO_TEST_CASE(frame_roundtrips_and_fragmentation) {
    StreamFramer encoder, decoder;
    for (const auto cls : ALL_STREAM_CLASSES) {
        for (const size_t size :
             {size_t{24}, size_t{1024}, size_t{65536}, size_t{1024}}) {
            std::vector<uint8_t> input(size, 0x42);
            const auto encoded{encoder.Encode(cls, input)};
            FrameReassembler reassembler;
            std::vector<FrameReassembler::Frame> frames;
            for (const auto byte : encoded) {
                BOOST_REQUIRE(reassembler.Feed({&byte, 1}, frames));
            }
            BOOST_REQUIRE_EQUAL(frames.size(), 1);
            BOOST_CHECK_EQUAL(reassembler.Buffered(), 0);
            BOOST_CHECK_EQUAL(frames[0].wire_size, encoded.size());
            BOOST_CHECK_EQUAL(frames[0].flags,
                              size < 64      ? quic_frame::FLAG_RAW
                              : size < 65536 ? quic_frame::FLAG_STREAM
                                             : quic_frame::FLAG_INDEPENDENT);
            std::vector<uint8_t> output;
            std::string error;
            BOOST_REQUIRE(decoder.Decode(cls, frames[0].flags, frames[0].body,
                                         output, error));
            BOOST_CHECK(output == input);
        }
    }
}

BOOST_AUTO_TEST_CASE(reject_invalid_frames) {
    FrameReassembler reassembler;
    std::vector<FrameReassembler::Frame> frames;
    uint8_t length[4]{};
    BOOST_CHECK(!reassembler.Feed(length, frames));
    FrameReassembler oversized;
    WriteLE32(length, static_cast<uint32_t>(quic_frame::MaxFrameLength() + 1));
    BOOST_CHECK(!oversized.Feed(length, frames));
    StreamFramer decoder;
    std::vector<uint8_t> output;
    std::string error;
    BOOST_CHECK(!decoder.Decode(StreamClass::CONTROL, 3, {}, output, error));
    BOOST_CHECK(!decoder.Decode(
        StreamClass::CONTROL, quic_frame::FLAG_INDEPENDENT, {}, output, error));
}

BOOST_AUTO_TEST_CASE(handshake_order_and_eof) {
    Peer p;
    const auto tx{Message("tx", 10)};
    const auto version{Message("version")};
    const auto verack{Message("verack")};
    p.Receive(StreamClass::TX_BODY, tx);
    BOOST_CHECK(!p.sock->HasBufferedRecv());
    p.Receive(StreamClass::CONTROL, version);
    p.Receive(StreamClass::CONTROL, verack);
    for (const auto &expected : {version, verack, tx}) {
        std::vector<uint8_t> actual(expected.size());
        BOOST_REQUIRE_EQUAL(p.sock->Recv(actual.data(), actual.size(), 0),
                            expected.size());
        BOOST_CHECK(actual == expected);
    }
    uint8_t byte;
    BOOST_CHECK_EQUAL(p.sock->Recv(&byte, 1, 0), -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    p.channel->MarkClosed();
    BOOST_CHECK_EQUAL(p.sock->Recv(&byte, 1, 0), 0);
}

BOOST_AUTO_TEST_CASE(coalesce_split_inventory_and_backpressure) {
    Peer p;
    auto inv{Message("inv", 1 + 2 * 36)};
    auto *payload{inv.data() + CMessageHeader::HEADER_SIZE};
    payload[0] = 2;
    WriteLE32(payload + 1, MSG_TX);
    WriteLE32(payload + 37, MSG_BLOCK);
    BOOST_REQUIRE_EQUAL(p.sock->Send(inv.data(), 7, 0), 7);
    BOOST_CHECK(p.channel->TakeTx(StreamClass::TX_ANNOUNCE).empty());
    BOOST_REQUIRE_EQUAL(p.sock->Send(inv.data() + 7, inv.size() - 7, 0),
                        inv.size() - 7);
    BOOST_CHECK_EQUAL(p.channel->TakeTx(StreamClass::TX_ANNOUNCE).size(), 1);
    BOOST_CHECK_EQUAL(p.channel->TakeTx(StreamClass::BLOCK).size(), 1);
    BOOST_CHECK_EQUAL(p.channel->Info()->splits.load(), 1);
    const auto ping{Message("ping", 8)};
    p.channel->SetEngineUnsent(StreamClass::CONTROL,
                               QuicPeerChannel::MAX_PENDING_SEND + 1);
    BOOST_CHECK_EQUAL(p.sock->Send(ping.data(), ping.size(), 0), -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    BOOST_CHECK(p.sock->SendBlockedByTransport());
    // Simulate the engine's drain and notification.
    p.channel->SetEngineUnsent(StreamClass::CONTROL, 0);
    p.channel->send_blocked = false;
    p.channel->Notify();
    BOOST_REQUIRE_EQUAL(p.sock->Send(ping.data(), ping.size(), 0), ping.size());
    BOOST_CHECK_EQUAL(p.channel->TakeTx(StreamClass::CONTROL).size(), 1);
}

BOOST_AUTO_TEST_CASE(reject_inconsistent_message_length) {
    Peer p;
    auto msg{Message("version")};
    WriteLE32(msg.data() + CMessageHeader::MESSAGE_SIZE_OFFSET, 100);
    p.Receive(StreamClass::CONTROL, msg);
    uint8_t byte;
    BOOST_CHECK_EQUAL(p.sock->Recv(&byte, 1, 0), -1);
    BOOST_CHECK_EQUAL(errno, ECONNRESET);
}

BOOST_AUTO_TEST_CASE(notification_after_socket_destruction) {
    Peer p;
    p.sock.reset();
    BOOST_CHECK(p.channel->SockGone());
    // A late engine notification must not terminate the process with SIGPIPE.
    p.channel->Notify();
}

BOOST_AUTO_TEST_SUITE_END()
