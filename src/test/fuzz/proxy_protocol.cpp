// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <proxy_protocol.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <string>
#include <vector>

FUZZ_TARGET(proxy_protocol) {
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    // v2: a header with a valid signature and arbitrary rest, or raw bytes.
    std::vector<uint8_t> v2;
    if (fdp.ConsumeBool()) {
        v2.assign(std::begin(proxy_protocol::V2_SIGNATURE),
                  std::end(proxy_protocol::V2_SIGNATURE));
    }
    const auto rest{fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(
        0, proxy_protocol::V2_MAX_PAYLOAD + 64))};
    v2.insert(v2.end(), rest.begin(), rest.end());
    if (const auto len{proxy_protocol::V2PayloadSize(v2)}) {
        assert(*len <= proxy_protocol::V2_MAX_PAYLOAD);
        if (v2.size() >= proxy_protocol::V2_FIXED_SIZE + *len) {
            v2.resize(proxy_protocol::V2_FIXED_SIZE + *len);
            if (const auto h{proxy_protocol::ParseV2(v2)}; h && h->source) {
                assert(h->source->IsIPv4() || h->source->IsIPv6());
            }
        }
    }
    (void)proxy_protocol::ParseV2(v2);

    // v1
    std::string line{fdp.ConsumeBool() ? "PROXY " : ""};
    line += fdp.ConsumeRandomLengthString(proxy_protocol::V1_MAX_LINE + 8);
    if (fdp.ConsumeBool()) {
        line += "\r\n";
    }
    if (const auto h{proxy_protocol::ParseV1(line)}; h && h->source) {
        assert(h->source->IsIPv4() || h->source->IsIPv6());
    }

    // X-Forwarded-For with arbitrary fields and trust.
    const CService peer{ConsumeService(fdp)};
    std::vector<std::string> fields;
    while (fields.size() < 4 && fdp.ConsumeBool()) {
        fields.push_back(fdp.ConsumeRandomLengthString(128));
    }
    const std::vector<std::string_view> views(fields.begin(), fields.end());
    const bool trust_all{fdp.ConsumeBool()};
    (void)proxy_protocol::ResolveForwardedClient(
        peer, views, [&](const CNetAddr &a) { return trust_all || a == peer; });
}
