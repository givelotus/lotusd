// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CORE_SERVICE_BIND_PARSE_H
#define CHRONIK_NATIVE_CORE_SERVICE_BIND_PARSE_H

#include <chronik/native/transport/beast_listener.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * Port of chronik-lib bridge.rs parse_socket_addr: "ip:port" / "[ipv6]:port"
 * (Rust SocketAddr) or a bare "ip" (Rust IpAddr) with the default port.
 */
namespace chronik::native {

/** Rust Ipv4Addr::from_str (strict dotted quad, no leading zeros). */
std::optional<std::string> ParseRustIpv4(std::string_view s);
/** Rust Ipv6Addr::from_str; returns the canonical display form. */
std::optional<std::string> ParseRustIpv6(std::string_view s);

/**
 * Throws ChronikError "Invalid Chronik host address {host:?}: invalid IP
 * address syntax" (InvalidChronikHost).
 */
ListenerBind ParseChronikHost(const std::string &host, uint16_t default_port);

/** Rust `{:?}` of a Vec<SocketAddr>, e.g. "[127.0.0.1:8331, [::1]:8331]". */
std::string DebugSocketAddrs(const std::vector<ListenerBind> &binds);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_CORE_SERVICE_BIND_PARSE_H
