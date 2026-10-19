// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLETPWA_HTTP_H
#define BITCOIN_WALLETPWA_HTTP_H

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

class ArgsManager;
class HTTPRequest;

/**
 * The wallet PWA on the node's HTTP server: GET /wallet/<path> (the app files),
 * /auth/session and /auth/logout (browser sessions), and session
 * authorization of JSON-RPC requests. See doc/wallet-pwa.md.
 */
namespace walletpwa {

static constexpr bool DEFAULT_WALLET_PWA{true};
static constexpr bool DEFAULT_GUI{false};

/** Checks "user:password" against the RPC credentials; sets the user. */
using CredentialCheck =
    std::function<bool(const std::string &user_colon_pass, std::string &user)>;

/** Validate the -walletpwa* and -gui options; returns an error, if any. */
std::optional<std::string> CheckWalletPwaArgs(const ArgsManager &args);

/**
 * Read the options and register /wallet, /auth/session and /auth/logout.
 * Call after StartHTTPRPC (which routes GET /wallet/<path> here) and before
 * StartHTTPServer.
 */
void StartWalletPwa(const ArgsManager &args, CredentialCheck check);

/** Unregister the handlers and forget every token and session. */
void StopWalletPwa();

/** Whether -walletpwa is on (after StartWalletPwa) */
bool WalletPwaEnabled();

/** Whether there is an app to serve: an embedded bundle or -walletpwadir */
bool WalletPwaHasApp(const ArgsManager &args);

/**
 * Serve GET /wallet/<path>. Returns true, having replied, only for GET
 * requests under /wallet/; anything else is left to JSON-RPC.
 */
bool MaybeServeWalletPwa(HTTPRequest *req);

/**
 * Authorize a JSON-RPC request without an Authorization header by its
 * browser session: -walletpwa is on, the session cookie names a live
 * session, Origin is present and passes the origin policy, X-CSRF-Token is
 * the session's, and the body is application/json. Returns the session's
 * RPC user (so -rpcwhitelist applies as usual), or nullopt.
 */
std::optional<std::string> AuthorizeWalletPwaSession(HTTPRequest *req);

struct LoginToken {
    std::string token;
    int64_t expires;
};

/** Mint a one-time login token for an RPC user; nullopt if disabled. */
std::optional<LoginToken> MintLoginToken(const std::string &user);

/** The node's -rpcport, which names the session cookie */
uint16_t WalletPwaRpcPort();

/** Version of the app being served: the bundle's, "dev" or "" */
std::string ServedAppVersion();

} // namespace walletpwa

#endif // BITCOIN_WALLETPWA_HTTP_H
