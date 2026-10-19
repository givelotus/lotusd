// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/http/util.h>

#include <ext/lotus_v2/service/service.h>

namespace chronik::native::lotus_v2::http {

namespace detail {

std::string Hex(const uint8_t *data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += kHex[data[i] >> 4];
        out += kHex[data[i] & 0xf];
    }
    return out;
}

int HexDigit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool IsLowerHex(std::string_view s) {
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::optional<Bytes> HexDecode(std::string_view s) {
    if (s.size() % 2 != 0) {
        return std::nullopt;
    }
    Bytes out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = HexDigit(s[i]);
        const int lo = HexDigit(s[i + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.push_back(uint8_t(hi * 16 + lo));
    }
    return out;
}

std::optional<uint64_t> CanonicalU64(std::string_view s) {
    if (s.empty() || (s.size() > 1 && s[0] == '0')) {
        return std::nullopt;
    }
    uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        const uint64_t d = uint64_t(c - '0');
        if (v > (UINT64_MAX - d) / 10) {
            return std::nullopt;
        }
        v = v * 10 + d;
    }
    return v;
}

HttpResponse JsonResponse(int status, std::string body, bool no_store) {
    HttpResponse resp;
    resp.status = status;
    resp.headers.emplace_back("content-type", "application/json");
    if (no_store) {
        resp.headers.emplace_back("cache-control", "no-store");
    }
    resp.body.assign(body.begin(), body.end());
    return resp;
}

} // namespace detail

V2HttpState MakeV2HttpState(const V2Service &service,
                            query_branches::Sha256Fn sha256) {
    V2HttpState state;
    state.index_error = service.IndexError();
    state.service_epoch = service.ServiceEpoch();
    state.db = service.SharedDatabase();
    std::shared_ptr<Authority> authority = service.GetAuthority();
    state.node_anchor = [authority] { return authority->Observe(); };
    state.sha256 = std::move(sha256);
    return state;
}

} // namespace chronik::native::lotus_v2::http
