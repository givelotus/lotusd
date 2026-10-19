// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_websocket_codec.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <vector>

FUZZ_TARGET(websocket_codec) {
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const auto role{provider.ConsumeBool() ? WebSocketCodec::Role::CLIENT
                                           : WebSocketCodec::Role::SERVER};
    const auto compression{provider.PickValueInArray(
        {P2PWebSocketCompression::NONE, P2PWebSocketCompression::ZSTD,
         P2PWebSocketCompression::ZSTD_DICT})};

    // Arbitrary wire input must never crash, and must be consumed in
    // order without exceeding the input.
    {
        WebSocketCodec codec{role, compression};
        std::vector<uint8_t> wire;
        std::vector<uint8_t> plain, reply;
        while (provider.remaining_bytes() > 0 && !codec.PeerClosed()) {
            const auto chunk{ConsumeRandomLengthByteVector(provider, 4096)};
            wire.insert(wire.end(), chunk.begin(), chunk.end());
            const auto result{codec.Decode(wire, plain, reply)};
            assert(result.consumed <= wire.size());
            if (result.error) {
                break;
            }
            wire.erase(wire.begin(), wire.begin() + result.consumed);
            if (plain.size() > (1 << 20)) {
                plain.clear();
            }
        }
    }

    // Round trip: what one side encodes, the other side decodes exactly,
    // however the wire bytes are split.
    {
        FuzzedDataProvider rt{buffer.data(), buffer.size()};
        const auto peer_role{role == WebSocketCodec::Role::CLIENT
                                 ? WebSocketCodec::Role::SERVER
                                 : WebSocketCodec::Role::CLIENT};
        WebSocketCodec sender{role, compression}, receiver{peer_role,
                                                           compression};
        std::vector<uint8_t> sent, wire, plain, reply;
        for (int i = 0; i < 8 && rt.remaining_bytes() > 0; ++i) {
            const auto msg{ConsumeRandomLengthByteVector(rt, 2048)};
            sent.insert(sent.end(), msg.begin(), msg.end());
            sender.EncodeMessage(msg, wire);
        }
        size_t fed{0};
        std::vector<uint8_t> pending;
        while (fed < wire.size()) {
            const size_t n{std::min<size_t>(
                wire.size() - fed, 1 + rt.ConsumeIntegralInRange<size_t>(0, 64))};
            pending.insert(pending.end(), wire.begin() + fed,
                           wire.begin() + fed + n);
            fed += n;
            const auto result{receiver.Decode(pending, plain, reply)};
            assert(!result.error);
            pending.erase(pending.begin(), pending.begin() + result.consumed);
        }
        assert(pending.empty());
        assert(plain == sent);
    }
}
