// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLETPWA_SESSION_H
#define BITCOIN_WALLETPWA_SESSION_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * Browser sessions for the wallet PWA: one-time login tokens, session
 * cookies, CSRF tokens and the Origin/Host policy. Everything here is pure
 * (times are passed in, nothing global), so it is unit-testable; the HTTP glue
 * is in walletpwa/http.cpp.
 */
namespace walletpwa {

//! Lifetime of a one-time login token
static constexpr int64_t TOKEN_LIFETIME_SECONDS{120};
//! Outstanding login tokens; minting another evicts the oldest
static constexpr size_t MAX_LOGIN_TOKENS{16};
//! Sessions; creating another evicts the least recently used
static constexpr size_t MAX_SESSIONS{64};
//! A session not used for this long expires
static constexpr int64_t SESSION_IDLE_SECONDS{7 * 24 * 60 * 60};
//! A session expires this long after it was created, used or not
static constexpr int64_t SESSION_ABSOLUTE_SECONDS{30 * 24 * 60 * 60};
//! Largest accepted POST /auth/session body
static constexpr size_t MAX_LOGIN_BODY_SIZE{4096};

using Hash = std::array<uint8_t, 32>;

/** SHA-256 of a string */
Hash HashSecret(std::string_view secret);

/** 32 bytes from GetStrongRandBytes, as 64 lowercase hex characters */
std::string NewSecret();

/** Constant-time comparison of two strings (time depends on sizes only) */
bool SecretsEqual(std::string_view a, std::string_view b);

/** "host[:port]", the host lower-cased (IPv6 kept in brackets) */
struct Authority {
    std::string host;
    std::optional<uint16_t> port;

    /** host, plus ":port" unless the port is the scheme's default */
    std::string Normalized(std::string_view scheme) const;
};

/** Parse a Host header value or an origin's authority. */
std::optional<Authority> ParseAuthority(std::string_view in);

/** "http(s)://host[:port]", nothing else (no path, user info or query) */
struct Origin {
    std::string scheme;
    Authority authority;

    std::string Normalized() const {
        return scheme + "://" + authority.Normalized(scheme);
    }
};

/** Parse an Origin header or a -walletpwaorigin value. */
std::optional<Origin> ParseOrigin(std::string_view in);

/** 127.0.0.0/8 as a dotted-quad literal, [::1], or localhost */
bool IsLoopbackHost(std::string_view host);

/**
 * The origin policy for /auth/ endpoints and session-authenticated requests:
 *
 * 1. Host must name a loopback host (any port), or the host:port of one of
 *    the extra origins. This defends against DNS rebinding.
 * 2. Origin, when present, must equal scheme://Host after normalization; if
 *    Host is not a loopback host, Origin must also be one of the extra
 *    origins. A required Origin must be present.
 */
class OriginPolicy {
public:
    OriginPolicy() = default;
    explicit OriginPolicy(std::vector<Origin> extra)
        : m_extra(std::move(extra)) {}

    /**
     * @param scheme  "http" or "https", as the client sees it
     * @param host    the Host header, if any
     * @param origin  the Origin header, if any
     * @param require_origin  whether a missing Origin is a violation
     * @param[out] reason  a short, value-free reason on failure
     */
    bool Allows(std::string_view scheme, const std::optional<std::string> &host,
                const std::optional<std::string> &origin, bool require_origin,
                std::string &reason) const;

    const std::vector<Origin> &Extra() const { return m_extra; }

private:
    std::vector<Origin> m_extra;
};

/** Name of the session cookie for a node whose -rpcport is `rpcport` */
std::string CookieName(uint16_t rpcport);

/** The value of cookie `name` in a Cookie header (the first one wins). */
std::optional<std::string> GetCookie(std::string_view header,
                                     std::string_view name);

/** Whether a Content-Type is application/json (parameters allowed) */
bool IsJsonContentType(std::string_view content_type);

/** One-time login tokens, stored only as hashes. */
class LoginTokens {
public:
    /** Mint a token for `user`; returns it, and its expiry in *expires. */
    std::string Mint(const std::string &user, int64_t now, int64_t &expires);
    /**
     * Use a token. Returns the user it was minted for, if it is outstanding
     * and unexpired. A token can be used once, even if it had expired.
     */
    std::optional<std::string> Consume(std::string_view token, int64_t now);
    size_t Size() const { return m_tokens.size(); }
    void Clear() { m_tokens.clear(); }

private:
    struct Entry {
        Hash hash;
        int64_t expires;
        std::string user;
    };
    std::deque<Entry> m_tokens;
};

/** In-memory browser sessions, keyed by the hash of the session id. */
class SessionStore {
public:
    struct Session {
        std::string user;
        std::string csrf;
        int64_t created;
        int64_t last_used;

        /** When the session expires if it keeps being used */
        int64_t Expires() const { return created + SESSION_ABSOLUTE_SECONDS; }
    };
    struct NewSession {
        std::string id;
        Session session;
    };

    /** Create a session, evicting the least recently used one if full. */
    NewSession Create(const std::string &user, int64_t now);
    /** Find a live session by its id and mark it used. */
    std::optional<Session> Lookup(std::string_view id, int64_t now);
    /** Delete a session; returns whether it existed. */
    bool Remove(std::string_view id);
    size_t Size() const { return m_sessions.size(); }
    void Clear() { m_sessions.clear(); }

private:
    std::map<Hash, Session> m_sessions;
};

} // namespace walletpwa

#endif // BITCOIN_WALLETPWA_SESSION_H
