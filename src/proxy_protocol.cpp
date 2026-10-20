// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <proxy_protocol.h>

#include <netbase.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <cstring>
#include <string>

namespace proxy_protocol {

std::optional<size_t> V2PayloadSize(Span<const uint8_t> fixed) {
    if (fixed.size() < V2_FIXED_SIZE ||
        std::memcmp(fixed.data(), V2_SIGNATURE, sizeof(V2_SIGNATURE)) != 0 ||
        (fixed[12] & 0xF0) != 0x20) {
        return std::nullopt;
    }
    const size_t len{(size_t(fixed[14]) << 8) | fixed[15]};
    if (len > V2_MAX_PAYLOAD) {
        return std::nullopt;
    }
    return len;
}

/** Whether v2 TLVs say the client used TLS (PP2_TYPE_SSL, PP2_CLIENT_SSL) */
static bool ClientUsedTLS(Span<const uint8_t> tlvs) {
    static constexpr uint8_t PP2_TYPE_SSL{0x20};
    static constexpr uint8_t PP2_CLIENT_SSL{0x01};
    while (tlvs.size() >= 3) {
        const uint8_t type{tlvs[0]};
        const size_t len{size_t(tlvs[1]) << 8 | tlvs[2]};
        if (tlvs.size() < 3 + len) {
            // Truncated: believe none of it.
            return false;
        }
        if (type == PP2_TYPE_SSL && len >= 1 && (tlvs[3] & PP2_CLIENT_SSL)) {
            return true;
        }
        tlvs = tlvs.subspan(3 + len);
    }
    return false;
}

std::optional<Header> ParseV2(Span<const uint8_t> header) {
    const auto len{V2PayloadSize(header)};
    if (!len || header.size() != V2_FIXED_SIZE + *len) {
        return std::nullopt;
    }
    const uint8_t command{uint8_t(header[12] & 0x0F)};
    const uint8_t family{header[13]};
    const Span<const uint8_t> addrs{header.subspan(V2_FIXED_SIZE)};
    if (command == 0x0) {
        // LOCAL: the proxy's own connection (e.g. a health check).
        return Header{};
    }
    if (command != 0x1) {
        return std::nullopt;
    }
    // TCP over IPv4 (0x11) or IPv6 (0x21); anything else carries no usable
    // client address.
    if (family == 0x11 && addrs.size() >= 12) {
        in_addr a;
        std::memcpy(&a, addrs.data(), 4);
        const uint16_t port{uint16_t((addrs[8] << 8) | addrs[9])};
        return Header{CService{a, port}, ClientUsedTLS(addrs.subspan(12))};
    }
    if (family == 0x21 && addrs.size() >= 36) {
        in6_addr a;
        std::memcpy(&a, addrs.data(), 16);
        const uint16_t port{uint16_t((addrs[32] << 8) | addrs[33])};
        return Header{CService{a, port}, ClientUsedTLS(addrs.subspan(36))};
    }
    return Header{};
}

std::optional<Header> ParseV1(std::string_view line) {
    if (line.size() > V1_MAX_LINE || !line.ends_with("\r\n") ||
        !line.starts_with("PROXY ")) {
        return std::nullopt;
    }
    line.remove_suffix(2);
    const auto fields{util::SplitString(line, ' ')};
    if (fields.size() >= 2 && fields[1] == "UNKNOWN") {
        // The proxy could not tell (e.g. its own health check).
        return Header{};
    }
    if (fields.size() != 6 || (fields[1] != "TCP4" && fields[1] != "TCP6")) {
        return std::nullopt;
    }
    const auto port{ToIntegral<uint16_t>(fields[4])};
    const auto source{LookupHost(fields[2], /*fAllowLookup=*/false)};
    if (!port || !source || (fields[1] == "TCP4") != source->IsIPv4()) {
        return std::nullopt;
    }
    return Header{CService{*source, *port}};
}

CService ResolveForwardedClient(
    const CService &peer, const std::vector<std::string_view> &forwarded,
    const std::function<bool(const CNetAddr &)> &trusted) {
    std::vector<std::string> hops;
    for (const std::string_view field : forwarded) {
        for (const std::string &hop : util::SplitString(field, ',')) {
            hops.emplace_back(util::TrimStringView(hop));
        }
    }
    CService current{peer};
    while (trusted(current) && !hops.empty()) {
        std::string hop{std::move(hops.back())};
        hops.pop_back();
        // An entry may carry a port ("a.b.c.d:p", "[v6]:p") or not ("v6").
        uint16_t port{0};
        std::string host;
        if (!SplitHostPort(hop, port, host)) {
            break;
        }
        const auto next{LookupHost(host, /*fAllowLookup=*/false)};
        if (!next || !next->IsValid()) {
            break;
        }
        current = CService{*next, port};
    }
    return current;
}

} // namespace proxy_protocol
