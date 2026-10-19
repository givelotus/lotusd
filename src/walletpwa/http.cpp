// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <walletpwa/http.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <httpserver.h>
#include <logging.h>
#include <netaddress.h>
#include <rpc/protocol.h>
#include <sync.h>
#include <util/fs.h>
#include <util/time.h>
#include <walletinitinterface.h>
#include <walletpwa/assets.h>
#include <walletpwa/serve.h>
#include <walletpwa/session.h>

#include <univalue.h>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <vector>

namespace walletpwa {

//! Delay before answering a failed login, as for RPC (brute-force deterrent)
static constexpr std::chrono::milliseconds LOGIN_FAILURE_DELAY{250};
static const std::string AUTH_SESSION_PATH{"/auth/session"};
static const std::string AUTH_LOGOUT_PATH{"/auth/logout"};
static const std::string WALLET_PATH{"/wallet"};
static const std::string WALLET_PREFIX{"/wallet/"};

namespace {
    struct State {
        bool enabled{false};
        std::optional<fs::path> dir;
        OriginPolicy policy;
        uint16_t rpcport{0};
        std::string cookie_name;
        CredentialCheck check_credentials;
        LoginTokens tokens;
        SessionStore sessions;
    };
} // namespace

static GlobalMutex g_state_mutex;
static State g_state GUARDED_BY(g_state_mutex);

static int64_t Now() {
    return GetTime<std::chrono::seconds>().count();
}

static std::optional<std::string> Header(const HTTPRequest *req,
                                         const std::string &name) {
    auto [present, value] = req->GetHeader(name);
    if (!present) {
        return std::nullopt;
    }
    return value;
}

static std::optional<std::vector<Origin>> ParseOrigins(const ArgsManager &args,
                                                       std::string &error) {
    std::vector<Origin> origins;
    for (const std::string &value : args.GetArgs("-walletpwaorigin")) {
        auto origin{ParseOrigin(value)};
        // Only scheme://host[:port]: ParseOrigin refuses anything more.
        if (!origin) {
            error = strprintf("Invalid -walletpwaorigin '%s' (expected "
                              "scheme://host[:port], e.g. "
                              "https://node.example.org)",
                              value);
            return std::nullopt;
        }
        origins.push_back(std::move(*origin));
    }
    return origins;
}

std::optional<std::string> CheckWalletPwaArgs(const ArgsManager &args) {
    std::string error;
    if (!ParseOrigins(args, error)) {
        return error;
    }
    if (args.IsArgSet("-walletpwadir")) {
        const fs::path dir{args.GetPathArg("-walletpwadir")};
        std::error_code ec;
        if (dir.empty() || !std::filesystem::is_directory(dir, ec)) {
            return strprintf("-walletpwadir '%s' is not a directory",
                             fs::PathToString(dir));
        }
    }
    if (args.GetBoolArg("-gui", DEFAULT_GUI)) {
        if (!args.GetBoolArg("-walletpwa", DEFAULT_WALLET_PWA)) {
            return std::string{"-gui needs the wallet UI, but -walletpwa=0"};
        }
        if (!WalletPwaHasApp(args)) {
            return std::string{
                "-gui needs the wallet UI, but this node was built without "
                "it; use -walletpwadir=<dir> or a release build"};
        }
    }
    return std::nullopt;
}

bool WalletPwaHasApp(const ArgsManager &args) {
    return args.IsArgSet("-walletpwadir") || !EmbeddedBundle().empty();
}

bool WalletPwaEnabled() {
    LOCK(g_state_mutex);
    return g_state.enabled;
}

uint16_t WalletPwaRpcPort() {
    LOCK(g_state_mutex);
    return g_state.rpcport;
}

std::string ServedAppVersion() {
    LOCK(g_state_mutex);
    if (g_state.dir) {
        return "dev";
    }
    return std::string{EmbeddedBundleVersion()};
}

static void WriteJson(HTTPRequest *req, int status, const UniValue &body) {
    req->WriteHeader("Content-Type", "application/json");
    req->WriteHeader("Cache-Control", "no-store");
    req->WriteHeader("X-Content-Type-Options", "nosniff");
    req->WriteReply(status, body.write() + "\n");
}

static void WriteError(HTTPRequest *req, int status, const std::string &msg) {
    UniValue body{UniValue::VOBJ};
    body.pushKV("error", msg);
    WriteJson(req, status, body);
}

/** The origin policy for a request; logs violations, without values. */
static bool OriginAllowed(const HTTPRequest *req, bool require_origin)
    EXCLUSIVE_LOCKS_REQUIRED(g_state_mutex) {
    std::string reason;
    if (g_state.policy.Allows(req->GetScheme(), Header(req, "host"),
                              Header(req, "origin"), require_origin, reason)) {
        return true;
    }
    LogDebug(BCLog::HTTP, "Wallet PWA request from %s refused: %s\n",
             req->GetPeer().ToStringAddrPort(), reason);
    return false;
}

/** The session named by the request's cookie, marked used */
static std::optional<SessionStore::Session>
CookieSession(const HTTPRequest *req, std::string *id_out = nullptr)
    EXCLUSIVE_LOCKS_REQUIRED(g_state_mutex) {
    const auto cookies{Header(req, "cookie")};
    if (!cookies) {
        return std::nullopt;
    }
    auto id{GetCookie(*cookies, g_state.cookie_name)};
    if (!id) {
        return std::nullopt;
    }
    auto session{g_state.sessions.Lookup(*id, Now())};
    if (session && id_out) {
        *id_out = std::move(*id);
    }
    return session;
}

static bool CsrfMatches(const HTTPRequest *req,
                        const SessionStore::Session &session) {
    const auto token{Header(req, "x-csrf-token")};
    return token && SecretsEqual(*token, session.csrf);
}

static UniValue SessionJson(const SessionStore::Session &session) {
    UniValue body{UniValue::VOBJ};
    body.pushKV("csrf", session.csrf);
    body.pushKV("user", session.user);
    body.pushKV("expires", session.Expires());
    return body;
}

bool MaybeServeWalletPwa(HTTPRequest *req) {
    const std::string uri{req->GetURI()};
    if (req->GetRequestMethod() != HTTPRequest::GET ||
        uri.compare(0, WALLET_PREFIX.size(), WALLET_PREFIX) != 0) {
        return false;
    }
    std::optional<fs::path> dir;
    {
        LOCK(g_state_mutex);
        if (!g_state.enabled) {
            req->WriteReply(HTTP_NOT_FOUND);
            return true;
        }
        dir = g_state.dir;
    }
    const std::string_view raw{
        std::string_view{uri}.substr(WALLET_PREFIX.size())};
    AssetReply reply;
    if (dir) {
        reply = ServeFromDirectory(*dir, raw);
    } else if (!EmbeddedBundle().empty()) {
        reply =
            ServeAsset(EmbeddedBundle(), raw, Header(req, "accept-encoding"),
                       Header(req, "if-none-match"));
    } else {
        reply = NoBundleReply();
    }
    for (const auto &[name, value] : reply.headers) {
        req->WriteHeader(name, value);
    }
    req->WriteReply(reply.status, std::move(reply.body));
    return true;
}

std::optional<std::string> AuthorizeWalletPwaSession(HTTPRequest *req) {
    std::optional<std::string> user;
    {
        LOCK(g_state_mutex);
        if (!g_state.enabled || !OriginAllowed(req, /*require_origin=*/true)) {
            return std::nullopt;
        }
        const auto content_type{Header(req, "content-type")};
        if (!content_type || !IsJsonContentType(*content_type)) {
            return std::nullopt;
        }
        const auto session{CookieSession(req)};
        if (!session || !CsrfMatches(req, *session)) {
            return std::nullopt;
        }
        user = session->user;
    }
    req->WriteHeader("Cache-Control", "no-store");
    return user;
}

std::optional<LoginToken> MintLoginToken(const std::string &user) {
    LOCK(g_state_mutex);
    if (!g_state.enabled) {
        return std::nullopt;
    }
    LoginToken out;
    out.token = g_state.tokens.Mint(user, Now(), out.expires);
    return out;
}

/** /wallet/<path> in a build without wallet support */
static bool HandleWalletPrefix(Config &, HTTPRequest *req,
                               const std::string &) {
    if (MaybeServeWalletPwa(req)) {
        return true;
    }
    req->WriteReply(HTTP_NOT_FOUND);
    return false;
}

/** GET /wallet: redirect to the app */
static bool HandleWalletRoot(Config &, HTTPRequest *req, const std::string &) {
    if (!WalletPwaEnabled() || req->GetRequestMethod() != HTTPRequest::GET) {
        req->WriteReply(HTTP_NOT_FOUND);
        return false;
    }
    req->WriteHeader("Location", WALLET_PREFIX);
    req->WriteReply(308);
    return true;
}

static void GetSession(HTTPRequest *req) {
    std::optional<SessionStore::Session> session;
    {
        LOCK(g_state_mutex);
        if (!OriginAllowed(req, /*require_origin=*/false)) {
            WriteError(req, HTTP_FORBIDDEN, "origin not allowed");
            return;
        }
        session = CookieSession(req);
    }
    if (!session) {
        WriteError(req, HTTP_UNAUTHORIZED, "login required");
        return;
    }
    UniValue body{SessionJson(*session)};
    body.pushKV("pwa_version", ServedAppVersion());
    WriteJson(req, HTTP_OK, body);
}

/** POST /auth/session: log in with a one-time token or RPC credentials */
static boost::asio::awaitable<void>
PostSession(HTTPRequest *req, boost::asio::any_io_executor executor) {
    CredentialCheck check;
    {
        LOCK(g_state_mutex);
        if (!OriginAllowed(req, /*require_origin=*/true)) {
            WriteError(req, HTTP_FORBIDDEN, "origin not allowed");
            co_return;
        }
        check = g_state.check_credentials;
    }
    const auto content_type{Header(req, "content-type")};
    if (!content_type || !IsJsonContentType(*content_type)) {
        WriteError(req, 415, "JSON required");
        co_return;
    }
    const bool https{req->GetScheme() == "https"};
    if (!https && !req->GetPeer().IsLocal()) {
        LogDebug(BCLog::HTTP,
                 "Wallet PWA login from %s refused: not HTTPS or loopback\n",
                 req->GetPeer().ToStringAddrPort());
        WriteError(req, HTTP_FORBIDDEN,
                   "wallet sessions need HTTPS or a loopback connection");
        co_return;
    }
    const std::string body{req->ReadBody()};
    UniValue request;
    if (body.size() > MAX_LOGIN_BODY_SIZE) {
        WriteError(req, 413, "request too large");
        co_return;
    }
    if (!request.read(body) || !request.isObject()) {
        WriteError(req, HTTP_BAD_REQUEST, "bad request");
        co_return;
    }

    std::optional<std::string> user;
    const UniValue &token{request.find_value("token")};
    const UniValue &name{request.find_value("user")};
    const UniValue &password{request.find_value("password")};
    if (token.isStr()) {
        LOCK(g_state_mutex);
        user = g_state.tokens.Consume(token.get_str(), Now());
    } else if (name.isStr() && password.isStr() && check) {
        std::string checked_user;
        if (check(name.get_str() + ":" + password.get_str(), checked_user)) {
            user = checked_user;
        }
    }
    if (!user) {
        LogPrintf("Wallet PWA login failed from %s\n",
                  req->GetPeer().ToStringAddrPort());
        boost::asio::steady_timer delay{executor, LOGIN_FAILURE_DELAY};
        boost::system::error_code ec;
        co_await delay.async_wait(
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        WriteError(req, HTTP_UNAUTHORIZED, "login failed");
        co_return;
    }

    SessionStore::NewSession created;
    std::string cookie_name;
    {
        LOCK(g_state_mutex);
        created = g_state.sessions.Create(*user, Now());
        cookie_name = g_state.cookie_name;
    }
    LogPrintf("Wallet PWA session created for RPC user %s from %s\n", *user,
              req->GetPeer().ToStringAddrPort());
    req->WriteHeader(
        "Set-Cookie",
        strprintf("%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s",
                  cookie_name, created.id, SESSION_ABSOLUTE_SECONDS,
                  https ? "; Secure" : ""));
    WriteJson(req, HTTP_OK, SessionJson(created.session));
}

static boost::asio::awaitable<bool>
HandleAuthSession(Config &, HTTPRequest *req, const std::string &,
                  boost::asio::any_io_executor executor) {
    if (!WalletPwaEnabled()) {
        req->WriteReply(HTTP_NOT_FOUND);
        co_return false;
    }
    switch (req->GetRequestMethod()) {
        case HTTPRequest::GET:
            GetSession(req);
            co_return true;
        case HTTPRequest::POST:
            co_await PostSession(req, std::move(executor));
            co_return true;
        default:
            WriteError(req, HTTP_BAD_METHOD, "method not allowed");
            co_return false;
    }
}

/** POST /auth/logout: delete the session */
static bool HandleAuthLogout(Config &, HTTPRequest *req, const std::string &) {
    if (!WalletPwaEnabled()) {
        req->WriteReply(HTTP_NOT_FOUND);
        return false;
    }
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        WriteError(req, HTTP_BAD_METHOD, "method not allowed");
        return false;
    }
    std::string cookie_name;
    {
        LOCK(g_state_mutex);
        if (!OriginAllowed(req, /*require_origin=*/true)) {
            WriteError(req, HTTP_FORBIDDEN, "origin not allowed");
            return false;
        }
        std::string id;
        const auto session{CookieSession(req, &id)};
        if (!session || !CsrfMatches(req, *session)) {
            WriteError(req, HTTP_UNAUTHORIZED, "login required");
            return false;
        }
        g_state.sessions.Remove(id);
        cookie_name = g_state.cookie_name;
        LogPrintf("Wallet PWA session of RPC user %s logged out from %s\n",
                  session->user, req->GetPeer().ToStringAddrPort());
    }
    req->WriteHeader("Set-Cookie", cookie_name + "=; Max-Age=0; Path=/");
    req->WriteHeader("Cache-Control", "no-store");
    req->WriteReply(204);
    return true;
}

void StartWalletPwa(const ArgsManager &args, CredentialCheck check) {
    std::string error;
    auto origins{ParseOrigins(args, error)};
    {
        LOCK(g_state_mutex);
        g_state.enabled = args.GetBoolArg("-walletpwa", DEFAULT_WALLET_PWA);
        g_state.dir.reset();
        if (args.IsArgSet("-walletpwadir")) {
            g_state.dir = fs::absolute(args.GetPathArg("-walletpwadir"));
        }
        // Checked by CheckWalletPwaArgs at startup.
        g_state.policy = OriginPolicy{origins.value_or(std::vector<Origin>{})};
        g_state.rpcport = static_cast<uint16_t>(
            args.GetIntArg("-rpcport", BaseParams().RPCPort()));
        g_state.cookie_name = CookieName(g_state.rpcport);
        g_state.check_credentials = std::move(check);
        g_state.tokens.Clear();
        g_state.sessions.Clear();
    }
    if (!g_wallet_init_interface.HasWalletSupport()) {
        // StartHTTPRPC registers /wallet/ only for multi-wallet RPC; the
        // app's node views work without a wallet too.
        RegisterHTTPHandler(WALLET_PREFIX, false, HandleWalletPrefix);
    }
    RegisterHTTPHandler(WALLET_PATH, true, HandleWalletRoot);
    RegisterHTTPAsyncHandler(AUTH_SESSION_PATH, true, HandleAuthSession);
    RegisterHTTPHandler(AUTH_LOGOUT_PATH, true, HandleAuthLogout);
    if (WalletPwaEnabled()) {
        const std::string source{
            args.IsArgSet("-walletpwadir")
                ? "-walletpwadir"
                : (EmbeddedBundle().empty()
                       ? "none (built without a bundle)"
                       : strprintf("embedded bundle %s",
                                   std::string{EmbeddedBundleVersion()}))};
        LogPrintf("Wallet UI served at /wallet/ (app: %s)\n", source);
    }
}

void StopWalletPwa() {
    if (!g_wallet_init_interface.HasWalletSupport()) {
        UnregisterHTTPHandler(WALLET_PREFIX, false);
    }
    UnregisterHTTPHandler(WALLET_PATH, true);
    UnregisterHTTPHandler(AUTH_SESSION_PATH, true);
    UnregisterHTTPHandler(AUTH_LOGOUT_PATH, true);
    LOCK(g_state_mutex);
    g_state.enabled = false;
    g_state.check_credentials = nullptr;
    g_state.tokens.Clear();
    g_state.sessions.Clear();
}

} // namespace walletpwa
