// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config/bitcoin-config.h>

#ifdef ENABLE_HTTP2

#include <http2_server.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace http = boost::beast::http;

/**
 * Arbitrary client bytes into the server side of the HTTP/2 adapter, with a
 * real nghttp2 session behind it. Between chunks, the "application" answers
 * requests (large and small bodies, HEAD), accepts or refuses extended
 * CONNECTs, echoes and consumes tunnel bytes, resets streams and shuts down,
 * all chosen by the input, so that the adapter's state handling is
 * exercised alongside nghttp2's parser.
 */
FUZZ_TARGET(http2_server) {
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    http2::Limits limits;
    limits.max_concurrent_streams = fdp.ConsumeIntegralInRange<uint32_t>(1, 8);
    limits.max_header_list_size =
        fdp.ConsumeIntegralInRange<uint32_t>(64, 16384);
    limits.max_body_size = fdp.ConsumeIntegralInRange<uint64_t>(0, 100000);
    limits.max_continuations = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    limits.reset_burst = fdp.ConsumeIntegralInRange<uint64_t>(1, 50);
    limits.enable_connect_protocol = fdp.ConsumeBool();
    limits.stream_window = fdp.ConsumeIntegralInRange<uint32_t>(65535, 1 << 20);

    std::vector<std::pair<int32_t, bool>> requests; // id, is HEAD
    std::vector<int32_t> connects;
    std::vector<std::pair<int32_t, size_t>> tunnel_bytes;
    std::set<int32_t> open;

    http2::ServerSession::Handlers handlers;
    handlers.on_request = [&](int32_t id, http2::Request &&req) {
        // What the HTTP server reads from every request.
        (void)req.method();
        (void)req.target();
        (void)req.body().size();
        for (const auto &f : req) {
            (void)f.name_string();
            (void)f.value();
        }
        requests.emplace_back(id, req.method() == http::verb::head);
        open.insert(id);
    };
    handlers.on_connect = [&](int32_t id, http2::Request &&req,
                              std::string protocol) {
        assert(!protocol.empty());
        (void)req.target();
        connects.push_back(id);
        open.insert(id);
    };
    handlers.on_tunnel_data = [&](int32_t id, std::string_view data) {
        tunnel_bytes.emplace_back(id, data.size());
    };
    handlers.on_tunnel_eof = [&](int32_t id) { (void)id; };
    handlers.on_stream_close = [&](int32_t id, uint32_t) { open.erase(id); };

    http2::ServerSession session{limits, std::move(handlers)};

    // Usually start with the client connection preface, so that the input
    // reaches frame processing.
    if (fdp.ConsumeBool()) {
        static const std::string PREFACE{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        if (!session.Receive({reinterpret_cast<const uint8_t *>(PREFACE.data()),
                              PREFACE.size()})) {
            return;
        }
    }

    LIMITED_WHILE(fdp.remaining_bytes() > 0, 10000) {
        const std::vector<uint8_t> chunk{
            ConsumeRandomLengthByteVector(fdp, 4096)};
        const bool alive{session.Receive(chunk)};

        // The application's turn.
        for (const auto &[id, head] : requests) {
            if (!fdp.ConsumeBool()) {
                continue;
            }
            http2::Response res{http::status::ok, 11};
            res.set(http::field::content_type, "application/json");
            res.set(http::field::connection, "close");
            res.body() =
                std::string(fdp.ConsumeIntegralInRange<size_t>(0, 20000), 'x');
            res.prepare_payload();
            session.SubmitResponse(id, std::move(res), head);
        }
        requests.clear();
        for (const int32_t id : connects) {
            if (fdp.ConsumeBool()) {
                session.AcceptTunnel(
                    id, 200, {{"sec-websocket-protocol", "p2p-zstd-v1"}});
            } else {
                session.SubmitResponse(
                    id, http2::Response{http::status::not_found, 11});
            }
        }
        connects.clear();
        for (const auto &[id, n] : tunnel_bytes) {
            if (fdp.ConsumeBool()) {
                session.TunnelConsumed(id, n);
            }
            if (fdp.ConsumeBool()) {
                session.TunnelSend(id, std::string(n, 'e'));
            }
            if (fdp.ConsumeBool()) {
                session.TunnelEnd(id);
            }
            (void)session.TunnelQueued(id);
        }
        tunnel_bytes.clear();
        if (!open.empty() && fdp.ConsumeIntegralInRange<int>(0, 15) == 0) {
            session.Reset(*open.begin(), 8 /* CANCEL */);
        }
        if (fdp.ConsumeIntegralInRange<int>(0, 63) == 0) {
            session.Shutdown();
        }
        (void)session.IncompleteRequests();
        (void)session.IncompleteRequestsSince(std::chrono::steady_clock::now());

        http2::Output out;
        if (!session.Collect(out,
                             fdp.ConsumeIntegralInRange<size_t>(1, 1 << 20))) {
            break;
        }
        (void)out.Buffers();
        if (!alive || (!session.WantsRead() && !session.WantsWrite())) {
            break;
        }
    }
}

#endif // ENABLE_HTTP2
