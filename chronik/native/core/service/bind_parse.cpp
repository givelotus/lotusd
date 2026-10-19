// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core/service/bind_parse.h>

#include <chronik/native/error.h>
#include <chronik/native/http.h>

#include <arpa/inet.h>

#include <array>
#include <cstdio>

namespace chronik::native {

namespace {

bool IsDigit(char c) { return c >= '0' && c <= '9'; }

/** Rust net parser read_number(10, max_digits, allow_zero_prefix). */
std::optional<uint64_t> ReadDecimal(std::string_view s, size_t &pos,
                                    std::optional<size_t> max_digits,
                                    bool allow_zero_prefix, uint64_t max) {
    const size_t start = pos;
    uint64_t value = 0;
    size_t digits = 0;
    while (pos < s.size() && IsDigit(s[pos])) {
        if (max_digits && digits == *max_digits) {
            return std::nullopt;
        }
        if (digits == 1 && !allow_zero_prefix && s[start] == '0') {
            return std::nullopt;
        }
        value = value * 10 + uint64_t(s[pos] - '0');
        if (value > max) {
            return std::nullopt;
        }
        ++digits;
        ++pos;
    }
    if (digits == 0) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::array<uint8_t, 4>> ParseV4(std::string_view s,
                                              size_t &pos) {
    std::array<uint8_t, 4> out{};
    for (size_t i = 0; i < 4; ++i) {
        if (i > 0) {
            if (pos >= s.size() || s[pos] != '.') {
                return std::nullopt;
            }
            ++pos;
        }
        auto octet = ReadDecimal(s, pos, 3, false, 255);
        if (!octet) {
            return std::nullopt;
        }
        out[i] = uint8_t(*octet);
    }
    return out;
}

std::string FormatV4(const std::array<uint8_t, 4> &a) {
    return std::to_string(a[0]) + "." + std::to_string(a[1]) + "." +
           std::to_string(a[2]) + "." + std::to_string(a[3]);
}

/** Rust Ipv6Addr Display (RFC 5952). */
std::string FormatV6(const std::array<uint8_t, 16> &b) {
    std::array<uint16_t, 8> g{};
    for (size_t i = 0; i < 8; ++i) {
        g[i] = uint16_t(b[2 * i] << 8 | b[2 * i + 1]);
    }
    // IPv4-mapped
    if (g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 &&
        g[5] == 0xffff) {
        return "::ffff:" + FormatV4({b[12], b[13], b[14], b[15]});
    }
    // Longest run of zero groups (len > 1), first on ties
    size_t best_start = 8, best_len = 0;
    for (size_t i = 0; i < 8;) {
        if (g[i] != 0) {
            ++i;
            continue;
        }
        size_t j = i;
        while (j < 8 && g[j] == 0) {
            ++j;
        }
        if (j - i > best_len) {
            best_start = i;
            best_len = j - i;
        }
        i = j;
    }
    if (best_len < 2) {
        best_start = 8;
        best_len = 0;
    }
    std::string out;
    char buf[8];
    for (size_t i = 0; i < 8; ++i) {
        if (i == best_start) {
            out += "::";
            i += best_len - 1;
            continue;
        }
        if (!out.empty() && out.back() != ':') {
            out += ":";
        }
        std::snprintf(buf, sizeof(buf), "%x", g[i]);
        out += buf;
    }
    return out;
}

[[noreturn]] void ThrowInvalidHost(const std::string &host) {
    throw ChronikError("Invalid Chronik host address " + RustDebugStr(host) +
                       ": invalid IP address syntax");
}

} // namespace

std::optional<std::string> ParseRustIpv4(std::string_view s) {
    size_t pos = 0;
    auto v4 = ParseV4(s, pos);
    if (!v4 || pos != s.size()) {
        return std::nullopt;
    }
    return FormatV4(*v4);
}

std::optional<std::string> ParseRustIpv6(std::string_view s) {
    // Rust only accepts hex digits, ':' and '.' (embedded IPv4)
    for (char c : s) {
        const bool ok = IsDigit(c) || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F') || c == ':' || c == '.';
        if (!ok) {
            return std::nullopt;
        }
    }
    std::array<uint8_t, 16> bytes{};
    const std::string str(s);
    if (inet_pton(AF_INET6, str.c_str(), bytes.data()) != 1) {
        return std::nullopt;
    }
    return FormatV6(bytes);
}

ListenerBind ParseChronikHost(const std::string &host, uint16_t default_port) {
    const std::string_view s = host;
    // SocketAddr: "a.b.c.d:port"
    {
        size_t pos = 0;
        auto v4 = ParseV4(s, pos);
        if (v4 && pos < s.size() && s[pos] == ':') {
            ++pos;
            auto port = ReadDecimal(s, pos, std::nullopt, true, 0xffff);
            if (port && pos == s.size()) {
                return {FormatV4(*v4), uint16_t(*port)};
            }
        }
    }
    // SocketAddr: "[v6]:port"
    if (!s.empty() && s[0] == '[') {
        const size_t close = s.find(']');
        if (close != std::string_view::npos) {
            auto v6 = ParseRustIpv6(s.substr(1, close - 1));
            size_t pos = close + 1;
            if (v6 && pos < s.size() && s[pos] == ':') {
                ++pos;
                auto port = ReadDecimal(s, pos, std::nullopt, true, 0xffff);
                if (port && pos == s.size()) {
                    return {*v6, uint16_t(*port)};
                }
            }
        }
    }
    // IpAddr with the default port
    if (auto v4 = ParseRustIpv4(s)) {
        return {*v4, default_port};
    }
    if (auto v6 = ParseRustIpv6(s)) {
        return {*v6, default_port};
    }
    ThrowInvalidHost(host);
}

std::string DebugSocketAddrs(const std::vector<ListenerBind> &binds) {
    std::string out = "[";
    for (size_t i = 0; i < binds.size(); ++i) {
        if (i > 0) {
            out += ", ";
        }
        out += FormatSocketAddr(binds[i].ip, binds[i].port);
    }
    out += "]";
    return out;
}

} // namespace chronik::native
