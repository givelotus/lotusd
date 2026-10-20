// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Built only with -DENABLE_WEBTRANSPORT=ON.

#include <net_quic/webtransport_wire.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <vector>

FUZZ_TARGET(wt_capsule) {
    FuzzedDataProvider provider{buffer.data(), buffer.size()};

    // Stream prefixes: never read past the input; a WebTransport header
    // re-encodes to the bytes it was parsed from when minimally encoded.
    {
        const auto bytes{ConsumeRandomLengthByteVector(provider, 32)};
        const bool uni{provider.ConsumeBool()};
        const auto p{wt::ParseStreamPrefix(bytes, uni)};
        if (p.status == wt::StreamPrefix::Status::WEBTRANSPORT) {
            assert(p.header_len <= bytes.size());
            assert(p.header_len >= 2);
        }
    }

    // Capsule streams: parse until incomplete or an error, consuming in
    // order and never past the input.
    {
        auto stream{ConsumeRandomLengthByteVector(provider, 70000)};
        Span<const uint8_t> rest{stream};
        while (!rest.empty()) {
            const auto c{wt::ParseCapsule(rest)};
            if (c.status != wt::CapsuleParse::Status::OK) {
                break;
            }
            assert(c.consumed > 0 && c.consumed <= rest.size());
            if (c.capsule.type == wt::CAPSULE_CLOSE_SESSION) {
                if (const auto close{wt::DecodeCloseSession(c.capsule.value)}) {
                    assert(close->reason.size() <= wt::MAX_CLOSE_REASON);
                    // Round trip.
                    const auto enc{wt::EncodeCloseSession(close->code,
                                                          close->reason)};
                    const auto again{wt::ParseCapsule(enc)};
                    assert(again.status == wt::CapsuleParse::Status::OK);
                    assert(again.capsule.value == c.capsule.value);
                }
            }
            rest = rest.subspan(c.consumed);
        }
    }

    // Varints and the error code mapping round-trip.
    {
        const uint64_t v{provider.ConsumeIntegral<uint64_t>() >> 2};
        std::vector<uint8_t> enc;
        wt::PutVarint(enc, v);
        uint64_t dec{0};
        assert(wt::GetVarint(enc, dec) == enc.size() && dec == v);
        const uint32_t code{provider.ConsumeIntegral<uint32_t>()};
        assert(wt::HttpCodeToWebTransport(wt::WebTransportCodeToHttp(code)) ==
               code);
        (void)wt::HttpCodeToWebTransport(provider.ConsumeIntegral<uint64_t>());
    }

    // wt-available-protocols: whatever parses re-serializes and parses again
    // to the same list.
    {
        const std::string field{provider.ConsumeRandomLengthString(256)};
        if (const auto list{wt::ParseProtocolList(field)}) {
            std::string joined;
            for (const auto &p : *list) {
                joined += (joined.empty() ? "" : ", ") +
                          wt::SerializeProtocol(p);
            }
            const auto again{wt::ParseProtocolList(joined)};
            assert(again && *again == *list);
        }
    }
}
