// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <walletpwa/session.h>

#include <crypto/sha256.h>
#include <random.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>

namespace walletpwa {

Hash HashSecret(std::string_view secret) {
    Hash out;
    CSHA256()
        .Write(reinterpret_cast<const uint8_t *>(secret.data()), secret.size())
        .Finalize(out.data());
    return out;
}

std::string NewSecret() {
    std::array<uint8_t, 32> bytes;
    GetStrongRandBytes(bytes);
    return HexStr(bytes);
}

bool SecretsEqual(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    uint8_t diff{0};
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

static bool HashesEqual(const Hash &a, const Hash &b) {
    uint8_t diff{0};
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

static bool IsLowerHexSecret(std::string_view s) {
    return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

static std::optional<uint16_t> DefaultPort(std::string_view scheme) {
    if (scheme == "http") {
        return 80;
    }
    if (scheme == "https") {
        return 443;
    }
    return std::nullopt;
}

std::string Authority::Normalized(std::string_view scheme) const {
    if (!port || port == DefaultPort(scheme)) {
        return host;
    }
    return host + ":" + util::ToString(*port);
}

static bool IsRegNameChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
           c == '.' || c == '_';
}

std::optional<Authority> ParseAuthority(std::string_view in) {
    const std::string s{ToLower(in)};
    if (s.empty() || s.size() > 255) {
        return std::nullopt;
    }
    Authority out;
    std::string_view rest{s};
    if (rest.front() == '[') {
        const size_t close{rest.find(']')};
        if (close == std::string_view::npos || close < 3) {
            return std::nullopt;
        }
        const std::string_view addr{rest.substr(1, close - 1)};
        if (!std::all_of(addr.begin(), addr.end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                       c == ':' || c == '.';
            })) {
            return std::nullopt;
        }
        out.host = std::string{rest.substr(0, close + 1)};
        rest.remove_prefix(close + 1);
    } else {
        const size_t colon{rest.find(':')};
        const std::string_view name{rest.substr(0, colon)};
        if (name.empty() ||
            !std::all_of(name.begin(), name.end(), IsRegNameChar)) {
            return std::nullopt;
        }
        out.host = std::string{name};
        rest.remove_prefix(name.size());
    }
    if (rest.empty()) {
        return out;
    }
    if (rest.front() != ':' || rest.size() < 2 || rest.size() > 6) {
        return std::nullopt;
    }
    rest.remove_prefix(1);
    uint16_t port{0};
    if (!std::all_of(rest.begin(), rest.end(), IsDigit) ||
        !ParseUInt16(rest, &port) || port == 0) {
        return std::nullopt;
    }
    out.port = port;
    return out;
}

std::optional<Origin> ParseOrigin(std::string_view in) {
    const size_t sep{in.find("://")};
    if (sep == std::string_view::npos) {
        return std::nullopt;
    }
    Origin out;
    out.scheme = ToLower(in.substr(0, sep));
    if (!DefaultPort(out.scheme)) {
        return std::nullopt;
    }
    auto authority{ParseAuthority(in.substr(sep + 3))};
    if (!authority) {
        return std::nullopt;
    }
    out.authority = std::move(*authority);
    return out;
}

bool IsLoopbackHost(std::string_view host) {
    if (host == "localhost" || host == "[::1]") {
        return true;
    }
    // A dotted-quad literal in 127.0.0.0/8
    int octets{0};
    size_t pos{0};
    while (pos <= host.size()) {
        const size_t dot{std::min(host.find('.', pos), host.size())};
        const std::string_view part{host.substr(pos, dot - pos)};
        uint8_t value{0};
        if (part.empty() || part.size() > 3 ||
            !std::all_of(part.begin(), part.end(), IsDigit) ||
            !ParseUInt8(part, &value)) {
            return false;
        }
        if (octets == 0 && value != 127) {
            return false;
        }
        ++octets;
        pos = dot + 1;
    }
    return octets == 4;
}

bool OriginPolicy::Allows(std::string_view scheme,
                          const std::optional<std::string> &host,
                          const std::optional<std::string> &origin,
                          bool require_origin, std::string &reason) const {
    std::optional<Authority> authority;
    if (host) {
        authority = ParseAuthority(*host);
    }
    if (!authority) {
        reason = "missing or malformed Host";
        return false;
    }
    const bool loopback{IsLoopbackHost(authority->host)};
    if (!loopback) {
        const bool listed{
            std::any_of(m_extra.begin(), m_extra.end(), [&](const Origin &o) {
                return o.authority.host == authority->host &&
                       o.authority.Normalized(o.scheme) ==
                           authority->Normalized(o.scheme);
            })};
        if (!listed) {
            reason = "Host not allowed";
            return false;
        }
    }
    if (!origin) {
        if (require_origin) {
            reason = "missing Origin";
            return false;
        }
        return true;
    }
    const auto parsed{ParseOrigin(*origin)};
    if (!parsed) {
        reason = "malformed Origin";
        return false;
    }
    const std::string own{std::string{scheme} + "://" +
                          authority->Normalized(scheme)};
    if (parsed->Normalized() != own) {
        reason = "Origin does not match Host";
        return false;
    }
    if (!loopback &&
        std::none_of(m_extra.begin(), m_extra.end(),
                     [&](const Origin &o) { return o.Normalized() == own; })) {
        reason = "Origin not allowed";
        return false;
    }
    return true;
}

std::string CookieName(uint16_t rpcport) {
    return "nodewallet_" + util::ToString(rpcport);
}

static std::string_view Trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

std::optional<std::string> GetCookie(std::string_view header,
                                     std::string_view name) {
    while (!header.empty()) {
        const size_t semi{std::min(header.find(';'), header.size())};
        const std::string_view part{header.substr(0, semi)};
        header.remove_prefix(std::min(semi + 1, header.size()));
        const size_t eq{part.find('=')};
        if (eq == std::string_view::npos) {
            continue;
        }
        if (Trim(part.substr(0, eq)) == name) {
            std::string_view value{Trim(part.substr(eq + 1))};
            if (value.size() >= 2 && value.front() == '"' &&
                value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }
            return std::string{value};
        }
    }
    return std::nullopt;
}

bool IsJsonContentType(std::string_view content_type) {
    const std::string type{ToLower(Trim(content_type.substr(
        0, std::min(content_type.find(';'), content_type.size()))))};
    return type == "application/json";
}

std::string LoginTokens::Mint(const std::string &user, int64_t now,
                              int64_t &expires) {
    std::string token{NewSecret()};
    expires = now + TOKEN_LIFETIME_SECONDS;
    m_tokens.push_back({HashSecret(token), expires, user});
    while (m_tokens.size() > MAX_LOGIN_TOKENS) {
        m_tokens.pop_front();
    }
    return token;
}

std::optional<std::string> LoginTokens::Consume(std::string_view token,
                                                int64_t now) {
    if (!IsLowerHexSecret(token)) {
        return std::nullopt;
    }
    const Hash hash{HashSecret(token)};
    // Compare against every stored hash, so that timing does not tell which
    // (if any) matched.
    std::optional<size_t> found;
    for (size_t i = 0; i < m_tokens.size(); ++i) {
        if (HashesEqual(m_tokens[i].hash, hash)) {
            found = i;
        }
    }
    if (!found) {
        return std::nullopt;
    }
    Entry entry{std::move(m_tokens[*found])};
    m_tokens.erase(m_tokens.begin() + *found);
    if (now >= entry.expires) {
        return std::nullopt;
    }
    return std::move(entry.user);
}

SessionStore::NewSession SessionStore::Create(const std::string &user,
                                              int64_t now) {
    NewSession out{NewSecret(), {user, NewSecret(), now, now}};
    while (m_sessions.size() >= MAX_SESSIONS) {
        auto lru{std::min_element(m_sessions.begin(), m_sessions.end(),
                                  [](const auto &a, const auto &b) {
                                      return a.second.last_used <
                                             b.second.last_used;
                                  })};
        m_sessions.erase(lru);
    }
    m_sessions.emplace(HashSecret(out.id), out.session);
    return out;
}

std::optional<SessionStore::Session> SessionStore::Lookup(std::string_view id,
                                                          int64_t now) {
    if (!IsLowerHexSecret(id)) {
        return std::nullopt;
    }
    // The map is keyed by a hash of the id, so lookups leak nothing useful.
    auto it{m_sessions.find(HashSecret(id))};
    if (it == m_sessions.end()) {
        return std::nullopt;
    }
    Session &s{it->second};
    if (now - s.last_used >= SESSION_IDLE_SECONDS ||
        now - s.created >= SESSION_ABSOLUTE_SECONDS) {
        m_sessions.erase(it);
        return std::nullopt;
    }
    s.last_used = std::max(s.last_used, now);
    return s;
}

bool SessionStore::Remove(std::string_view id) {
    if (!IsLowerHexSecret(id)) {
        return false;
    }
    return m_sessions.erase(HashSecret(id)) > 0;
}

} // namespace walletpwa
