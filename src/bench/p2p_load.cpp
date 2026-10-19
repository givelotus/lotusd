// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see COPYING.
// Load-only peers: production socket/dialer/TLS/WebSocket/p2p-v2 transport.
#include <chrono>
#include <config.h>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <net.h>
#include <net_websocket_dialer.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <node/protocol_version.h>
#include <protocol.h>
#include <random.h>
#include <streams.h>
#include <sys/resource.h>
#include <thread>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/translation.h>

const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;
using Clock = std::chrono::steady_clock;
static int64_t Now() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               Clock::now().time_since_epoch())
        .count();
}
struct Peer {
    std::shared_ptr<Sock> sock;
    std::unique_ptr<P2PV2TransportDeserializer> rx;
    std::vector<uint8_t> tx;
    size_t sent{0};
    bool ready{false};
    uint64_t blocks{0}, bytes{0};
    int64_t first{0}, last{0}, request{0};
    std::vector<std::pair<std::string, int64_t>> messages;
};
static void Send(Peer &p, const Config &cfg, CSerializedNetMsg msg) {
    std::vector<uint8_t> header;
    P2PV2TransportSerializer{}.prepareForTransport(cfg, msg, header);
    p.tx.insert(p.tx.end(), header.begin(), header.end());
    p.tx.insert(p.tx.end(), msg.data.begin(), msg.data.end());
}
static double Cpu(const rusage &u) {
    return u.ru_utime.tv_sec + u.ru_utime.tv_usec / 1e6 + u.ru_stime.tv_sec +
           u.ru_stime.tv_usec / 1e6;
}
int main(int argc, char **argv) {
    try {
        if (argc != 8)
            throw std::runtime_error(
                "usage: p2p-load URL PEERS THREADS SECONDS BLOCK_HASH_FILE "
                "READY_FILE JSON_OUTPUT");
        LogInstance().m_print_to_console = true;
        LogInstance().EnableCategory(BCLog::NET);
        LogInstance().StartLogging();
        SelectParams(ChainType::REGTEST);
        GlobalConfig cfg;
        cfg.SetMaxBlockSize(128000000);
        const auto url = ParseWebSocketURL(argv[1]);
        if (!url) throw std::runtime_error("invalid URL");
        const size_t count = std::stoul(argv[2]), threads = std::stoul(argv[3]);
        const double seconds = std::stod(argv[4]);
        if (!count || !threads || threads > count || threads > 16 ||
            count > 1000 || seconds <= 0)
            throw std::runtime_error("invalid load bounds");
        std::vector<CInv> requests;
        std::ifstream hashes(argv[5]);
        std::string hash;
        while (hashes >> hash)
            requests.emplace_back(MSG_BLOCK, uint256S(hash));
        if (!StartP2PWebSocketDialer({}, {}, P2P_WS_PROTOCOL_V2))
            throw std::runtime_error("dialer start failed");
        CThreadInterrupt interrupt;
        std::vector<Peer> peers(count);
        const int64_t start = Now();
        for (size_t i = 0; i < count; ++i) {
            auto tcp =
                ConnectDirectly(LookupNumeric(url->host, url->port), true);
            if (!tcp)
                throw std::runtime_error("TCP dial failed at peer " +
                                         std::to_string(i));
            auto ws = GetWebSocketDialer()(std::move(tcp), *url, interrupt);
            if (!ws || ws->info->compression != P2PWebSocketCompression::P2P_V2)
                throw std::runtime_error("p2p-v2 upgrade failed");
            auto &p = peers[i];
            p.sock = std::move(ws->sock);
            p.rx = std::make_unique<P2PV2TransportDeserializer>(cfg, i);
            Send(p, cfg,
                 NetMsg::Make(NetMsgType::VERSION, PROTOCOL_VERSION,
                              uint64_t(NODE_NETWORK), int64_t(time(nullptr)),
                              uint64_t(0), WithParams(CNetAddr::V1, CService{}),
                              uint64_t(NODE_NETWORK),
                              WithParams(CNetAddr::V1, CService{}),
                              uint64_t(i + start),
                              std::string("/load-only:0.1/"), int32_t(0), true,
                              uint64_t(i)));
        }
        std::atomic<size_t> ready{0}, finished{0};
        std::atomic<bool> failed{false};
        std::mutex error_mutex;
        std::string error;
        rusage cpu_start{}, cpu_end{};
        getrusage(RUSAGE_SELF, &cpu_start);
        std::vector<std::thread> workers;
        for (size_t t = 0; t < threads; ++t)
            workers.emplace_back([&, t] {
                try {
                    std::vector<uint8_t> buf(256 * 1024);
                    const int64_t deadline = Now() + int64_t(seconds * 1e6);
                    while (Now() < deadline && !failed && finished < count) {
                        Sock::EventsPerSock events;
                        bool buffered = false;
                        for (size_t i = t; i < count; i += threads) {
                            auto &p = peers[i];
                            buffered |= p.sock->HasBufferedRecv();
                            Sock::Event wanted =
                                Sock::RECV | p.sock->PendingEvents();
                            if (p.sent < p.tx.size()) wanted |= Sock::SEND;
                            events.emplace(p.sock, Sock::Events{wanted});
                        }
                        if (!peers[t].sock->WaitMany(
                                std::chrono::milliseconds{buffered ? 0 : 10},
                                events))
                            throw std::runtime_error("poll failed");
                        for (size_t i = t; i < count; i += threads) {
                            auto &p = peers[i];
                            const auto occurred = events.at(p.sock).occurred;
                            if (!p.sock->FlushPending())
                                throw std::runtime_error("flush failed");
                            if (p.sent < p.tx.size()) {
                                const auto n = p.sock->Send(
                                    p.tx.data() + p.sent, p.tx.size() - p.sent,
                                    MSG_NOSIGNAL);
                                if (n > 0)
                                    p.sent += n;
                                else if (n < 0 && errno != EAGAIN &&
                                         errno != EWOULDBLOCK)
                                    throw std::runtime_error("send failed");
                                if (p.sent == p.tx.size()) {
                                    p.tx.clear();
                                    p.sent = 0;
                                }
                            }
                            if (!(occurred & Sock::RECV) &&
                                !p.sock->HasBufferedRecv())
                                continue;
                            const auto n = p.sock->Recv(buf.data(), buf.size(),
                                                        MSG_DONTWAIT);
                            if (!n) throw std::runtime_error("peer EOF");
                            if (n < 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK)
                                    continue;
                                throw std::runtime_error(
                                    "receive failed peer " + std::to_string(i) +
                                    ": " + std::strerror(errno));
                            }
                            Span<const uint8_t> bytes{buf.data(), size_t(n)};
                            while (!bytes.empty()) {
                                if (p.rx->Read(cfg, bytes) < 0)
                                    throw std::runtime_error(
                                        "invalid p2p-v2 frame");
                                if (!p.rx->Complete()) continue;
                                bool reject = false;
                                auto m = p.rx->GetMessage(
                                    std::chrono::microseconds(Now()), reject);
                                if (reject)
                                    throw std::runtime_error("invalid command");
                                p.messages.emplace_back(m.m_type, Now());
                                if (m.m_type == NetMsgType::VERSION)
                                    Send(p, cfg,
                                         NetMsg::Make(NetMsgType::VERACK));
                                if (m.m_type == NetMsgType::VERACK &&
                                    !p.ready) {
                                    p.ready = true;
                                    ++ready;
                                    if (!requests.empty()) {
                                        p.request = Now();
                                        Send(p, cfg,
                                             NetMsg::Make(NetMsgType::GETDATA,
                                                          requests));
                                    }
                                }
                                if (m.m_type == NetMsgType::PING) {
                                    uint64_t nonce;
                                    m.m_recv >> nonce;
                                    Send(p, cfg,
                                         NetMsg::Make(NetMsgType::PONG, nonce));
                                }
                                if (m.m_type == NetMsgType::INV &&
                                    requests.empty()) {
                                    std::vector<CInv> inv;
                                    m.m_recv >> inv;
                                    std::vector<CInv> blocks;
                                    for (const auto &v : inv)
                                        if (v.type == MSG_BLOCK)
                                            blocks.push_back(v);
                                    if (!blocks.empty())
                                        Send(p, cfg,
                                             NetMsg::Make(NetMsgType::GETDATA,
                                                          blocks));
                                }
                                if (m.m_type == NetMsgType::BLOCK) {
                                    ++p.blocks;
                                    p.bytes += m.m_message_size;
                                    if (!p.first) p.first = Now();
                                    p.last = Now();
                                    if (p.blocks == (requests.empty()
                                                         ? 1
                                                         : requests.size()))
                                        ++finished;
                                }
                            }
                        }
                        if (ready == count) {
                            static std::atomic<bool> written{false};
                            if (!written.exchange(true))
                                std::ofstream(argv[6]) << Now() << "\n";
                        }
                    }
                } catch (const std::exception &e) {
                    std::lock_guard<std::mutex> lock(error_mutex);
                    error = e.what();
                    failed = true;
                }
            });
        for (auto &w : workers)
            w.join();
        getrusage(RUSAGE_SELF, &cpu_end);
        UniValue out(UniValue::VOBJ), rows(UniValue::VARR);
        out.pushKV("status",
                   failed ? "failed" : (finished == count ? "ok" : "timeout"));
        out.pushKV("error", error);
        out.pushKV("clock", "steady_clock_us");
        out.pushKV("start_us", start);
        out.pushKV("end_us", Now());
        out.pushKV("ready_peers", uint64_t(ready));
        out.pushKV("client_cpu_seconds", Cpu(cpu_end) - Cpu(cpu_start));
        out.pushKV("threads", uint64_t(threads));
        for (size_t i = 0; i < count; ++i) {
            UniValue r(UniValue::VOBJ);
            r.pushKV("peer", uint64_t(i));
            r.pushKV("blocks", peers[i].blocks);
            r.pushKV("bytes", peers[i].bytes);
            r.pushKV("first_us", peers[i].first);
            r.pushKV("last_us", peers[i].last);
            r.pushKV("request_us", peers[i].request);
            UniValue events(UniValue::VARR);
            for (const auto &event : peers[i].messages) {
                UniValue e(UniValue::VOBJ);
                e.pushKV("type", event.first);
                e.pushKV("at_us", event.second);
                events.push_back(e);
            }
            r.pushKV("messages", events);
            rows.push_back(r);
        }
        out.pushKV("peers", rows);
        std::ofstream(argv[7]) << out.write(2) << "\n";
        StopP2PWebSocketDialer();
        return failed || finished != count ? 1 : 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
