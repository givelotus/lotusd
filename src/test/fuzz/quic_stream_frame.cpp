// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_quic/quic_peer_sock.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

FUZZ_TARGET(quic_stream_frame) {
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    StreamFramer decoder;
    const StreamClass cls{
        ALL_STREAM_CLASSES[provider.ConsumeIntegralInRange<size_t>(
            0, NUM_STREAM_CLASSES - 1)]};
    const uint8_t flags{provider.ConsumeIntegral<uint8_t>()};
    const auto body{ConsumeRandomLengthByteVector(provider, 65536)};
    std::vector<uint8_t> output;
    std::string error;
    (void)decoder.Decode(cls, flags, body, output, error);
    FrameReassembler frames;
    std::vector<FrameReassembler::Frame> complete;
    (void)frames.Feed(body, complete);
}
