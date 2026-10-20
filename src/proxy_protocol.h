// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PROXY_PROTOCOL_H
#define BITCOIN_PROXY_PROTOCOL_H

#include <netaddress.h>
#include <span.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <vector>

/**
 * Client addresses behind load balancers and reverse proxies.
 *
 * A node behind one or more proxies sees their addresses, not the client's.
 * Proxies in trusted subnets (-trustedproxy) can tell it the real one: a
 * PROXY protocol header at the start of the connection (layer-4 balancers
 * such as AWS NLB, HAProxy), and X-Forwarded-For on each HTTP request
 * (HTTP proxies such as AWS ALB, nginx). Nothing from an untrusted peer is
 * believed.
 */
namespace proxy_protocol {

//! PROXY protocol v2 signature (the first 12 bytes of a v2 header)
inline constexpr uint8_t V2_SIGNATURE[12]{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
                                          0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
//! Size of the fixed part of a v2 header (signature, command, family, length)
inline constexpr size_t V2_FIXED_SIZE{16};
//! Largest v2 address block accepted (addresses plus TLVs)
inline constexpr size_t V2_MAX_PAYLOAD{1024};
//! Longest v1 header line, CRLF included (from the specification)
inline constexpr size_t V1_MAX_LINE{107};

struct Header {
    //! The client, or std::nullopt for LOCAL/UNKNOWN (health checks from the
    //! proxy itself): keep the connection's own peer address.
    std::optional<CService> source;
    //! The client reached the proxy over TLS: a v2 PP2_TYPE_SSL TLV with
    //! PP2_CLIENT_SSL set (v1 headers cannot say).
    bool client_tls{false};
};

/**
 * Length of the address block of a v2 header, from its fixed 16 bytes, or
 * std::nullopt if they are not a valid v2 header.
 */
std::optional<size_t> V2PayloadSize(Span<const uint8_t> fixed);

/** Parse a whole v2 header (fixed part and address block) */
std::optional<Header> ParseV2(Span<const uint8_t> header);

/** Parse a v1 header line ("PROXY TCP4 <src> <dst> <sport> <dport>\r\n") */
std::optional<Header> ParseV1(std::string_view line);

/**
 * The client of an HTTP request: starting from the connection's peer, while
 * the current address is a trusted proxy, step to the next X-Forwarded-For
 * hop from the right. Stops at the first untrusted address (the client), or
 * at an entry that is not an address.
 *
 * @param peer       The connection's peer (after any PROXY header)
 * @param forwarded  The values of every X-Forwarded-For field, in order
 * @param trusted    Whether an address is a trusted proxy
 */
CService ResolveForwardedClient(
    const CService &peer, const std::vector<std::string_view> &forwarded,
    const std::function<bool(const CNetAddr &)> &trusted);

} // namespace proxy_protocol

#endif // BITCOIN_PROXY_PROTOCOL_H
