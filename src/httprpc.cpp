// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httprpc.h>

#include <common/args.h>
#include <config.h>
#include <crypto/hmac_sha256.h>
#include <logging.h>
#include <node/context.h>
#include <node/mining_pool.h>
#include <rpc/async_waiter.h>
#include <rpc/protocol.h>
#include <rpc/server_util.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>
#include <walletinitinterface.h>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstdio>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

using util::SplitString;
using util::TrimStringView;

/** WWW-Authenticate to present with 401 Unauthorized response */
static const char *WWW_AUTH_HEADER_DATA = "Basic realm=\"jsonrpc\"";

/** RPC auth failure delay to make brute-forcing expensive */
static const int64_t RPC_AUTH_BRUTE_FORCE_DELAY = 250;

/**
 * Simple one-shot callback timer to be used by the RPC mechanism to e.g.
 * re-lock the wallet.
 */
class HTTPRPCTimer : public RPCTimerBase {
public:
    HTTPRPCTimer(struct event_base *eventBase, std::function<void()> &func,
                 int64_t millis)
        : ev(eventBase, false, func) {
        struct timeval tv;
        tv.tv_sec = millis / 1000;
        tv.tv_usec = (millis % 1000) * 1000;
        ev.trigger(&tv);
    }

private:
    HTTPEvent ev;
};

class HTTPRPCTimerInterface : public RPCTimerInterface {
public:
    explicit HTTPRPCTimerInterface(struct event_base *_base) : base(_base) {}

    const char *Name() override { return "HTTP"; }

    RPCTimerBase *NewTimer(std::function<void()> &func,
                           int64_t millis) override {
        return new HTTPRPCTimer(base, func, millis);
    }

private:
    struct event_base *base;
};

/* Pre-base64-encoded authentication token */
static std::string strRPCUserColonPass;
/* Pre-base64-encoded authentication token */
static std::string strRPCCORSDomain;
/* Stored RPC timer interface (for unregistration) */
static std::unique_ptr<HTTPRPCTimerInterface> httpRPCTimerInterface;
/* List of -rpcauth values */
static std::vector<std::vector<std::string>> g_rpcauth;
/* RPC Auth Whitelist */
static std::map<std::string, std::set<std::string>> g_rpc_whitelist;
static bool g_rpc_whitelist_default = false;

static void JSONErrorReply(HTTPRequest *req, const UniValue &objError,
                           const UniValue &id) {
    // Send error reply from json-rpc error object.
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = objError.find_value("code").getInt<int>();

    if (code == RPC_INVALID_REQUEST) {
        nStatus = HTTP_BAD_REQUEST;
    } else if (code == RPC_METHOD_NOT_FOUND) {
        nStatus = HTTP_NOT_FOUND;
    }

    std::string strReply = JSONRPCReply(NullUniValue, objError, id);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(nStatus, strReply);
}

/*
 * This function checks username and password against -rpcauth entries from
 * config file.
 */
static bool multiUserAuthorized(std::string strUserPass) {
    if (strUserPass.find(':') == std::string::npos) {
        return false;
    }
    std::string strUser = strUserPass.substr(0, strUserPass.find(':'));
    std::string strPass = strUserPass.substr(strUserPass.find(':') + 1);

    for (const auto &vFields : g_rpcauth) {
        std::string strName = vFields[0];
        if (!TimingResistantEqual(strName, strUser)) {
            continue;
        }

        std::string strSalt = vFields[1];
        std::string strHash = vFields[2];

        static const unsigned int KEY_SIZE = 32;
        uint8_t out[KEY_SIZE];

        CHMAC_SHA256(reinterpret_cast<const uint8_t *>(strSalt.data()),
                     strSalt.size())
            .Write(reinterpret_cast<const uint8_t *>(strPass.data()),
                   strPass.size())
            .Finalize(out);
        std::vector<uint8_t> hexvec(out, out + KEY_SIZE);
        std::string strHashFromPass = HexStr(hexvec);

        if (TimingResistantEqual(strHashFromPass, strHash)) {
            return true;
        }
    }
    return false;
}

bool CheckRPCCredentials(const std::string &strUserPass,
                         std::string &strAuthUsernameOut) {
    // Belt-and-suspenders measure if InitRPCAuthentication was not called.
    if (strRPCUserColonPass.empty()) {
        return false;
    }

    if (strUserPass.find(':') != std::string::npos) {
        strAuthUsernameOut = strUserPass.substr(0, strUserPass.find(':'));
    }

    // Check if authorized under single-user field
    if (TimingResistantEqual(strUserPass, strRPCUserColonPass)) {
        return true;
    }
    return multiUserAuthorized(strUserPass);
}

static bool RPCAuthorized(const std::string &strAuth,
                          std::string &strAuthUsernameOut) {
    if (strAuth.substr(0, 6) != "Basic ") {
        return false;
    }

    std::string_view strUserPass64 =
        TrimStringView(std::string_view{strAuth}.substr(6));
    auto userpass_data = DecodeBase64(strUserPass64);
    std::string strUserPass;
    if (!userpass_data) {
        return false;
    }
    strUserPass.assign(userpass_data->begin(), userpass_data->end());
    return CheckRPCCredentials(strUserPass, strAuthUsernameOut);
}

/**
 * Reply 401 to a request without (valid) credentials. Requests from the
 * wallet PWA (they carry X-CSRF-Token) get no WWW-Authenticate, so that the
 * browser does not prompt for a password: the app shows its login screen.
 */
static void ReplyUnauthorized(HTTPRequest *req) {
    if (!req->GetHeader("x-csrf-token").first) {
        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
    }
    req->WriteReply(HTTP_UNAUTHORIZED);
}

static bool checkCORS(HTTPRequest *req) {
    // https://www.w3.org/TR/cors/#resource-requests

    // 1. If the Origin header is not present terminate this set of steps.
    // The request is outside the scope of this specification.
    std::pair<bool, std::string> origin = req->GetHeader("origin");
    if (!origin.first) {
        return false;
    }

    // 2. If the value of the Origin header is not a case-sensitive match for
    // any of the values in list of origins do not set any additional headers
    // and terminate this set of steps.
    // Note: Always matching is acceptable since the list of origins can be
    // unbounded.
    if (origin.second != strRPCCORSDomain) {
        return false;
    }

    if (req->GetRequestMethod() == HTTPRequest::OPTIONS) {
        // 6.2 Preflight Request
        // In response to a preflight request the resource indicates which
        // methods and headers (other than simple methods and simple
        // headers) it is willing to handle and whether it supports
        // credentials.
        // Resources must use the following set of steps to determine which
        // additional headers to use in the response:

        // 3. Let method be the value as result of parsing the
        // Access-Control-Request-Method header.
        // If there is no Access-Control-Request-Method header or if parsing
        // failed, do not set any additional headers and terminate this set
        // of steps. The request is outside the scope of this specification.
        std::pair<bool, std::string> method =
            req->GetHeader("access-control-request-method");
        if (!method.first) {
            return false;
        }

        // 4. Let header field-names be the values as result of parsing
        // the Access-Control-Request-Headers headers.
        // If there are no Access-Control-Request-Headers headers let header
        // field-names be the empty list.
        // If parsing failed do not set any additional headers and terminate
        // this set of steps. The request is outside the scope of this
        // specification.
        std::pair<bool, std::string> header_field_names =
            req->GetHeader("access-control-request-headers");

        // 5. If method is not a case-sensitive match for any of the
        // values in list of methods do not set any additional headers
        // and terminate this set of steps.
        // Note: Always matching is acceptable since the list of methods
        // can be unbounded.
        if (method.second != "POST") {
            return false;
        }

        // 6. If any of the header field-names is not a ASCII case-
        // insensitive match for any of the values in list of headers do not
        // set any additional headers and terminate this set of steps.
        // Note: Always matching is acceptable since the list of headers can
        // be unbounded.
        const std::string &list_of_headers = "authorization,content-type";

        // 7. If the resource supports credentials add a single
        // Access-Control-Allow-Origin header, with the value of the Origin
        // header as value, and add a single
        // Access-Control-Allow-Credentials header with the case-sensitive
        // string "true" as value.
        req->WriteHeader("Access-Control-Allow-Origin", origin.second);
        req->WriteHeader("Access-Control-Allow-Credentials", "true");

        // 8. Optionally add a single Access-Control-Max-Age header with as
        // value the amount of seconds the user agent is allowed to cache
        // the result of the request.

        // 9. If method is a simple method this step may be skipped.
        // Add one or more Access-Control-Allow-Methods headers consisting
        // of (a subset of) the list of methods.
        // If a method is a simple method it does not need to be listed, but
        // this is not prohibited.
        // Note: Since the list of methods can be unbounded, simply
        // returning the method indicated by
        // Access-Control-Request-Method (if supported) can be enough.
        req->WriteHeader("Access-Control-Allow-Methods", method.second);

        // 10. If each of the header field-names is a simple header and none
        // is Content-Type, this step may be skipped.
        // Add one or more Access-Control-Allow-Headers headers consisting
        // of (a subset of) the list of headers.
        req->WriteHeader("Access-Control-Allow-Headers",
                         header_field_names.first ? header_field_names.second
                                                  : list_of_headers);
        req->WriteReply(HTTP_OK);
        return true;
    }

    // 6.1 Simple Cross-Origin Request, Actual Request, and Redirects
    // In response to a simple cross-origin request or actual request the
    // resource indicates whether or not to share the response.
    // If the resource has been relocated, it indicates whether to share its
    // new URL.
    // Resources must use the following set of steps to determine which
    // additional headers to use in the response:

    // 3. If the resource supports credentials add a single
    // Access-Control-Allow-Origin header, with the value of the Origin
    // header as value, and add a single Access-Control-Allow-Credentials
    // header with the case-sensitive string "true" as value.
    req->WriteHeader("Access-Control-Allow-Origin", origin.second);
    req->WriteHeader("Access-Control-Allow-Credentials", "true");

    // 4. If the list of exposed headers is not empty add one or more
    // Access-Control-Expose-Headers headers, with as values the header
    // field names given in the list of exposed headers.
    req->WriteHeader("Access-Control-Expose-Headers", "WWW-Authenticate");

    return false;
}

bool HTTPRPCRequestProcessor::ProcessHTTPRequest(HTTPRequest *req) {
    // First, check and/or set CORS headers
    if (checkCORS(req)) {
        return true;
    }

    // JSONRPC handles only POST
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_BAD_METHOD,
                        "JSONRPC server handles only POST requests");
        return false;
    }
    // Check authorization
    std::pair<bool, std::string> authHeader = req->GetHeader("authorization");
    JSONRPCRequest jreq;
    jreq.context = context;
    jreq.peerAddr = req->GetPeer().ToStringAddrPort();
    if (!authHeader.first) {
        // Without Basic credentials, only a wallet PWA browser session
        // (cookie, Origin and CSRF token) can authorize the request.
        auto user{walletpwa::AuthorizeWalletPwaSession(req)};
        if (!user) {
            ReplyUnauthorized(req);
            return false;
        }
        jreq.authUser = std::move(*user);
    } else if (!RPCAuthorized(authHeader.second, jreq.authUser)) {
        LogInfoEvent(BCLog::ALL, "rpc_authentication_failed",
                     "ThreadRPCServer incorrect password attempt from {addr}")
            .Field(BCLog::LogField::Addr, jreq.peerAddr);

        /**
         * Deter brute-forcing.
         * If this results in a DoS the user really shouldn't have their RPC
         * port exposed.
         */
        UninterruptibleSleep(
            std::chrono::milliseconds{RPC_AUTH_BRUTE_FORCE_DELAY});

        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    try {
        // Parse request
        UniValue valRequest;
        if (!valRequest.read(req->ReadBody())) {
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");
        }

        // Set the URI
        jreq.URI = req->GetURI();

        std::string strReply;
        bool user_has_whitelist = g_rpc_whitelist.count(jreq.authUser);
        if (!user_has_whitelist && g_rpc_whitelist_default) {
            LogInfoEvent(BCLog::ALL, "rpc_access_denied",
                         "RPC User {rpc_user} not allowed to call any methods")
                .Field(BCLog::LogField::RpcUser, jreq.authUser);
            req->WriteReply(HTTP_FORBIDDEN);
            return false;

            // singleton request
        } else if (valRequest.isObject()) {
            jreq.parse(valRequest);
            if (user_has_whitelist &&
                !g_rpc_whitelist[jreq.authUser].count(jreq.strMethod)) {
                LogInfoEvent(BCLog::ALL, "rpc_method_access_denied",
                             "RPC User {rpc_user} not allowed to call method "
                             "{original_method}")
                    .Field(BCLog::LogField::RpcUser, jreq.authUser)
                    .Field(BCLog::LogField::OriginalMethod, jreq.strMethod);
                req->WriteReply(HTTP_FORBIDDEN);
                return false;
            }
            UniValue result = rpcServer.ExecuteCommand(config, jreq);

            // Send reply
            strReply = JSONRPCReply(result, NullUniValue, jreq.id);

            // array of requests
        } else if (valRequest.isArray()) {
            if (user_has_whitelist) {
                for (unsigned int reqIdx = 0; reqIdx < valRequest.size();
                     reqIdx++) {
                    if (!valRequest[reqIdx].isObject()) {
                        throw JSONRPCError(RPC_INVALID_REQUEST,
                                           "Invalid Request object");
                    } else {
                        const UniValue &request = valRequest[reqIdx].get_obj();
                        // Parse method
                        std::string strMethod =
                            request.find_value("method").get_str();
                        if (!g_rpc_whitelist[jreq.authUser].count(strMethod)) {
                            LogInfoEvent(BCLog::ALL, "rpc_method_access_denied",
                                         "RPC User {rpc_user} not allowed to "
                                         "call method {original_method}")
                                .Field(BCLog::LogField::RpcUser, jreq.authUser)
                                .Field(BCLog::LogField::OriginalMethod,
                                       strMethod);
                            req->WriteReply(HTTP_FORBIDDEN);
                            return false;
                        }
                    }
                }
            }
            strReply = JSONRPCExecBatch(config, rpcServer, jreq,
                                        valRequest.get_array());
        } else {
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");
        }

        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, std::move(strReply));
    } catch (const UniValue &objError) {
        JSONErrorReply(req, objError, jreq.id);
        return false;
    } catch (const std::exception &e) {
        JSONErrorReply(req, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        return false;
    }
    return true;
}

boost::asio::awaitable<bool>
HTTPRPCRequestProcessor::ProcessHTTPRequestAsync(
    HTTPRequest *req, boost::asio::any_io_executor executor) {
    if (checkCORS(req)) {
        co_return true;
    }

    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_BAD_METHOD,
                        "JSONRPC server handles only POST requests");
        co_return false;
    }

    std::pair<bool, std::string> authHeader = req->GetHeader("authorization");
    JSONRPCRequest jreq;
    jreq.context = context;
    jreq.peerAddr = req->GetPeer().ToStringAddrPort();
    if (!authHeader.first) {
        // Without Basic credentials, only a wallet PWA browser session
        // (cookie, Origin and CSRF token) can authorize the request.
        auto user{walletpwa::AuthorizeWalletPwaSession(req)};
        if (!user) {
            ReplyUnauthorized(req);
            co_return false;
        }
        jreq.authUser = std::move(*user);
    } else if (!RPCAuthorized(authHeader.second, jreq.authUser)) {
        LogInfoEvent(BCLog::ALL, "rpc_authentication_failed",
                     "ThreadRPCServer incorrect password attempt from {addr}")
            .Field(BCLog::LogField::Addr, jreq.peerAddr);

        boost::asio::steady_timer delay_timer(
            executor, std::chrono::milliseconds{RPC_AUTH_BRUTE_FORCE_DELAY});
        boost::system::error_code ec;
        co_await delay_timer.async_wait(
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));

        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        co_return false;
    }

    try {
        UniValue valRequest;
        if (!valRequest.read(req->ReadBody())) {
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");
        }

        jreq.URI = req->GetURI();

        std::string strReply;
        bool user_has_whitelist = g_rpc_whitelist.count(jreq.authUser);
        if (!user_has_whitelist && g_rpc_whitelist_default) {
            LogInfoEvent(BCLog::ALL, "rpc_access_denied",
                         "RPC User {rpc_user} not allowed to call any methods")
                .Field(BCLog::LogField::RpcUser, jreq.authUser);
            req->WriteReply(HTTP_FORBIDDEN);
            co_return false;
        } else if (valRequest.isObject()) {
            jreq.parse(valRequest);
            if (user_has_whitelist &&
                !g_rpc_whitelist[jreq.authUser].count(jreq.strMethod)) {
                LogInfoEvent(BCLog::ALL, "rpc_method_access_denied",
                             "RPC User {rpc_user} not allowed to call method "
                             "{original_method}")
                    .Field(BCLog::LogField::RpcUser, jreq.authUser)
                    .Field(BCLog::LogField::OriginalMethod, jreq.strMethod);
                req->WriteReply(HTTP_FORBIDDEN);
                co_return false;
            }
            UniValue result = co_await rpcServer.ExecuteCommandAsync(
                config, jreq, std::move(executor));

            strReply = JSONRPCReply(result, NullUniValue, jreq.id);
        } else if (valRequest.isArray()) {
            if (user_has_whitelist) {
                for (unsigned int reqIdx = 0; reqIdx < valRequest.size();
                     reqIdx++) {
                    if (!valRequest[reqIdx].isObject()) {
                        throw JSONRPCError(RPC_INVALID_REQUEST,
                                           "Invalid Request object");
                    } else {
                        const UniValue &request = valRequest[reqIdx].get_obj();
                        std::string strMethod =
                            request.find_value("method").get_str();
                        if (!g_rpc_whitelist[jreq.authUser].count(strMethod)) {
                            LogInfoEvent(BCLog::ALL, "rpc_method_access_denied",
                                         "RPC User {rpc_user} not allowed to "
                                         "call method {original_method}")
                                .Field(BCLog::LogField::RpcUser, jreq.authUser)
                                .Field(BCLog::LogField::OriginalMethod,
                                       strMethod);
                            req->WriteReply(HTTP_FORBIDDEN);
                            co_return false;
                        }
                    }
                }
            }
            strReply = co_await JSONRPCExecBatchAsync(
                config, rpcServer, jreq, valRequest.get_array(),
                std::move(executor));
        } else {
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");
        }

        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strReply);
    } catch (const UniValue &objError) {
        JSONErrorReply(req, objError, jreq.id);
        co_return false;
    } catch (const std::exception &e) {
        JSONErrorReply(req, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        co_return false;
    }
    co_return true;
}

static bool InitRPCAuthentication() {
    if (gArgs.GetArg("-rpcpassword", "") == "") {
        LogInfoEvent(BCLog::ALL, "rpc_cookie_auth_enabled",
                     "Using random cookie authentication.");
        if (!GenerateAuthCookie(&strRPCUserColonPass)) {
            return false;
        }
    } else {
        LogInfoEvent(BCLog::ALL, "rpc_password_options_deprecated",
                     "Config options rpcuser and rpcpassword will soon be "
                     "deprecated. Locally-run instances may remove rpcuser to "
                     "use cookie-based auth, or may be replaced with rpcauth. "
                     "Please see share/rpcauth for rpcauth auth generation.");
        strRPCUserColonPass = gArgs.GetArg("-rpcuser", "") + ":" +
                              gArgs.GetArg("-rpcpassword", "");
    }

    strRPCCORSDomain = gArgs.GetArg("-rpccorsdomain", "");

    if (gArgs.GetArg("-rpcauth", "") != "") {
        LogInfoEvent(BCLog::ALL, "rpc_rpcauth_enabled",
                     "Using rpcauth authentication.");
        for (const std::string &rpcauth : gArgs.GetArgs("-rpcauth")) {
            std::vector<std::string> fields{SplitString(rpcauth, ':')};
            const std::vector<std::string> salt_hmac{
                SplitString(fields.back(), '$')};
            if (fields.size() == 2 && salt_hmac.size() == 2) {
                fields.pop_back();
                fields.insert(fields.end(), salt_hmac.begin(), salt_hmac.end());
                g_rpcauth.push_back(fields);
            } else {
                LogInfoEvent(BCLog::ALL, "rpc_rpcauth_invalid",
                             "Invalid -rpcauth argument.");
                return false;
            }
        }
    }

    g_rpc_whitelist_default = gArgs.GetBoolArg("-rpcwhitelistdefault",
                                               gArgs.IsArgSet("-rpcwhitelist"));
    for (const std::string &strRPCWhitelist : gArgs.GetArgs("-rpcwhitelist")) {
        auto pos = strRPCWhitelist.find(':');
        std::string strUser = strRPCWhitelist.substr(0, pos);
        bool intersect = g_rpc_whitelist.count(strUser);
        std::set<std::string> &whitelist = g_rpc_whitelist[strUser];
        if (pos != std::string::npos) {
            std::string strWhitelist = strRPCWhitelist.substr(pos + 1);
            std::vector<std::string> whitelist_split =
                SplitString(strWhitelist, ", ");
            std::set<std::string> new_whitelist{
                std::make_move_iterator(whitelist_split.begin()),
                std::make_move_iterator(whitelist_split.end())};
            if (intersect) {
                std::set<std::string> tmp_whitelist;
                std::set_intersection(
                    new_whitelist.begin(), new_whitelist.end(),
                    whitelist.begin(), whitelist.end(),
                    std::inserter(tmp_whitelist, tmp_whitelist.end()));
                new_whitelist = std::move(tmp_whitelist);
            }
            whitelist = std::move(new_whitelist);
        }
    }

    return true;
}

static void WritePoolCORSHeaders(HTTPRequest *req) {
    req->WriteHeader("Access-Control-Allow-Origin", "*");
    req->WriteHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    req->WriteHeader("Access-Control-Allow-Headers",
                     "Content-Type, Authorization, Accept");
    req->WriteHeader("Cache-Control", "no-cache");
}

static std::string UrlDecodeParam(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            const int hi = HexDigit(input[i + 1]);
            const int lo = HexDigit(input[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        } else if (input[i] == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(input[i]);
    }
    return out;
}

static std::map<std::string, std::string>
ParseURIQueryParams(std::string_view uri) {
    std::map<std::string, std::string> params;
    const size_t qpos = uri.find('?');
    if (qpos == std::string_view::npos || qpos + 1 >= uri.size()) {
        return params;
    }
    const std::string_view query = uri.substr(qpos + 1);
    size_t start = 0;
    while (start < query.size()) {
        size_t amp = query.find('&', start);
        if (amp == std::string_view::npos) {
            amp = query.size();
        }
        const std::string_view pair = query.substr(start, amp - start);
        if (!pair.empty()) {
            const size_t eq = pair.find('=');
            if (eq == std::string_view::npos) {
                params[UrlDecodeParam(pair)] = "1";
            } else {
                params[UrlDecodeParam(pair.substr(0, eq))] =
                    UrlDecodeParam(pair.substr(eq + 1));
            }
        }
        start = amp + 1;
    }
    return params;
}

static bool ParseUint64FromUniValue(const UniValue &val, uint64_t &out) {
    if (val.isNum()) {
        out = val.getInt<uint64_t>();
        return true;
    }
    if (!val.isStr()) {
        return false;
    }
    std::string s{TrimStringView(val.get_str())};
    if (s.empty()) {
        return false;
    }
    int base = 10;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
        s = s.substr(2);
        base = 16;
    } else {
        for (char c : s) {
            if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                base = 16;
                break;
            }
        }
    }
    char *endptr = nullptr;
    errno = 0;
    const unsigned long long parsed =
        std::strtoull(s.c_str(), &endptr, base);
    if (errno != 0 || endptr == s.c_str() || *endptr != '\0') {
        return false;
    }
    out = static_cast<uint64_t>(parsed);
    return true;
}

static boost::asio::awaitable<bool> HandlePoolJobsHTTPAsync(
    Config &config, const std::any &context, HTTPRequest *req,
    boost::asio::any_io_executor executor) {
    WritePoolCORSHeaders(req);
    if (req->GetRequestMethod() == HTTPRequest::OPTIONS) {
        req->WriteReply(HTTP_OK);
        co_return true;
    }
    if (req->GetRequestMethod() != HTTPRequest::GET) {
        req->WriteReply(HTTP_BAD_METHOD,
                        "Pool jobs endpoint supports GET and OPTIONS");
        co_return false;
    }

    try {
        node::NodeContext &node = EnsureAnyNodeContext(context);
        auto pool = node::GetMiningPool(node);
        const bool disabled =
            node.args &&
            !node.args->GetBoolArg(
                "-miningpool", lotus::v2::node::DEFAULT_MINING_POOL_ENABLED);
        if (disabled || !pool || !pool->IsEnabled()) {
            req->WriteReply(HTTP_SERVICE_UNAVAILABLE,
                            disabled
                                ? "{\"error\":\"mining-pool-disabled\"}\n"
                                : "{\"error\":\"mining-pool-unavailable\"}\n");
            co_return false;
        }

        const auto qparams = ParseURIQueryParams(req->GetURI());
        std::string worker_id = "default";
        if (auto it = qparams.find("worker"); it != qparams.end() && !it->second.empty()) {
            worker_id = it->second;
        } else if (auto it2 = qparams.find("worker_id");
                   it2 != qparams.end() && !it2->second.empty()) {
            worker_id = it2->second;
        }

        bool longpoll = false;
        if (auto it = qparams.find("longpoll"); it != qparams.end()) {
            longpoll = (it->second == "1" || it->second == "true");
        }
        int64_t timeout_ms = 15000;
        if (auto it = qparams.find("timeout_ms"); it != qparams.end()) {
            timeout_ms = std::clamp<int64_t>(std::atoll(it->second.c_str()), 10, 60000);
        }

        if (longpoll && node.chainman) {
            BlockHash watched_tip;
            {
                LOCK(cs_main);
                if (const CBlockIndex *tip = node.chainman->ActiveTip()) {
                    watched_tip = tip->GetBlockHash();
                }
            }
            const auto deadline =
                std::chrono::steady_clock::now() +
                std::chrono::milliseconds(timeout_ms);
            co_await GetRPCBlockChangeWaiter().WaitUntilDeadline(
                executor, deadline, [&node, &watched_tip]() {
                    LOCK(cs_main);
                    const CBlockIndex *tip =
                        node.chainman ? node.chainman->ActiveTip() : nullptr;
                    return !tip || tip->GetBlockHash() != watched_tip ||
                           !IsRPCRunning();
                });
        }

        const UniValue job_json =
            pool->GetMiningJobJSON(config, node, worker_id);

        bool use_sse = false;
        const auto accept_hdr = req->GetHeader("Accept");
        const auto accept_hdr_lower = req->GetHeader("accept");
        if ((accept_hdr.first &&
             accept_hdr.second.find("text/event-stream") !=
                 std::string::npos) ||
            (accept_hdr_lower.first &&
             accept_hdr_lower.second.find("text/event-stream") !=
                 std::string::npos)) {
            use_sse = true;
        }
        if (auto it = qparams.find("sse");
            it != qparams.end() && (it->second == "1" || it->second == "true")) {
            use_sse = true;
        }
        if (auto it = qparams.find("format");
            it != qparams.end() && it->second == "sse") {
            use_sse = true;
        }

        if (use_sse) {
            req->WriteHeader("Content-Type",
                             "text/event-stream; charset=utf-8");
            req->WriteReply(
                HTTP_OK,
                lotus::v2::node::MiningPoolManager::FormatSSEJobEvent(
                    job_json));
        } else {
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, job_json.write() + "\n");
        }
        co_return true;
    } catch (const std::exception &e) {
        req->WriteHeader("Content-Type", "application/json");
        UniValue err(UniValue::VOBJ);
        err.pushKV("error", e.what());
        req->WriteReply(HTTP_INTERNAL_SERVER_ERROR, err.write() + "\n");
        co_return false;
    }
}

static boost::asio::awaitable<bool> HandlePoolSubmitHTTPAsync(
    Config &config, const std::any &context, HTTPRequest *req) {
    WritePoolCORSHeaders(req);
    if (req->GetRequestMethod() == HTTPRequest::OPTIONS) {
        req->WriteReply(HTTP_OK);
        co_return true;
    }
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_BAD_METHOD,
                        "Pool submit endpoint supports POST and OPTIONS");
        co_return false;
    }

    try {
        node::NodeContext &node = EnsureAnyNodeContext(context);
        auto pool = node::GetMiningPool(node);
        const bool disabled =
            node.args &&
            !node.args->GetBoolArg(
                "-miningpool", lotus::v2::node::DEFAULT_MINING_POOL_ENABLED);
        if (disabled || !pool || !pool->IsEnabled()) {
            req->WriteReply(HTTP_SERVICE_UNAVAILABLE,
                            disabled
                                ? "{\"error\":\"mining-pool-disabled\"}\n"
                                : "{\"error\":\"mining-pool-unavailable\"}\n");
            co_return false;
        }

        UniValue body;
        if (!body.read(req->ReadBody()) || !body.isObject()) {
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_BAD_REQUEST,
                            "{\"accepted\":false,\"reason\":\"invalid-json\"}\n");
            co_return false;
        }

        uint64_t job_id = 0;
        if (!ParseUint64FromUniValue(body.find_value("job_id"), job_id)) {
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_BAD_REQUEST,
                            "{\"accepted\":false,\"reason\":\"invalid-job-id\"}\n");
            co_return false;
        }

        std::string worker_id = "default";
        if (const UniValue &w = body.find_value("worker"); w.isStr()) {
            worker_id = w.get_str();
        } else if (const UniValue &wid = body.find_value("worker_id");
                   wid.isStr()) {
            worker_id = wid.get_str();
        }

        uint64_t nonce = 0;
        if (!ParseUint64FromUniValue(body.find_value("nonce"), nonce)) {
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_BAD_REQUEST,
                            "{\"accepted\":false,\"reason\":\"invalid-nonce\"}\n");
            co_return false;
        }

        std::optional<uint64_t> ntime_opt;
        uint64_t parsed_time = 0;
        if (ParseUint64FromUniValue(body.find_value("time"), parsed_time) ||
            ParseUint64FromUniValue(body.find_value("ntime"), parsed_time)) {
            ntime_opt = parsed_time;
        }

        const auto res = pool->SubmitShare(config, node, job_id, worker_id,
                                           ntime_opt, nonce);
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, res.ToUniValue().write() + "\n");
        co_return true;
    } catch (const std::exception &e) {
        req->WriteHeader("Content-Type", "application/json");
        UniValue err(UniValue::VOBJ);
        err.pushKV("accepted", false);
        err.pushKV("reason", e.what());
        req->WriteReply(HTTP_INTERNAL_SERVER_ERROR, err.write() + "\n");
        co_return false;
    }
}

static boost::asio::awaitable<bool> HandlePoolStatsHTTPAsync(
    const std::any &context, HTTPRequest *req) {
    WritePoolCORSHeaders(req);
    if (req->GetRequestMethod() == HTTPRequest::OPTIONS) {
        req->WriteReply(HTTP_OK);
        co_return true;
    }
    if (req->GetRequestMethod() != HTTPRequest::GET) {
        req->WriteReply(HTTP_BAD_METHOD,
                        "Pool stats endpoint supports GET and OPTIONS");
        co_return false;
    }

    try {
        node::NodeContext &node = EnsureAnyNodeContext(context);
        auto pool = node::GetMiningPool(node);
        const bool disabled =
            node.args &&
            !node.args->GetBoolArg(
                "-miningpool", lotus::v2::node::DEFAULT_MINING_POOL_ENABLED);
        if (disabled || !pool || !pool->IsEnabled()) {
            req->WriteReply(HTTP_SERVICE_UNAVAILABLE,
                            disabled
                                ? "{\"error\":\"mining-pool-disabled\"}\n"
                                : "{\"error\":\"mining-pool-unavailable\"}\n");
            co_return false;
        }

        const auto qparams = ParseURIQueryParams(req->GetURI());
        std::string worker_id;
        if (auto it = qparams.find("worker"); it != qparams.end()) {
            worker_id = it->second;
        } else if (auto it2 = qparams.find("worker_id"); it2 != qparams.end()) {
            worker_id = it2->second;
        }

        req->WriteHeader("Content-Type", "application/json");
        if (!worker_id.empty()) {
            const UniValue stats = pool->GetWorkerStatsJSON(worker_id);
            req->WriteReply(HTTP_OK, stats.write() + "\n");
        } else {
            const UniValue info = pool->GetPoolInfoJSON();
            req->WriteReply(HTTP_OK, info.write() + "\n");
        }
        co_return true;
    } catch (const std::exception &e) {
        req->WriteHeader("Content-Type", "application/json");
        UniValue err(UniValue::VOBJ);
        err.pushKV("error", e.what());
        req->WriteReply(HTTP_INTERNAL_SERVER_ERROR, err.write() + "\n");
        co_return false;
    }
}

bool StartHTTPRPC(HTTPRPCRequestProcessor &httpRPCRequestProcessor) {
    LogEvent(BCLog::RPC, "rpc_http_started", "Starting HTTP RPC server");
    if (!InitRPCAuthentication()) {
        return false;
    }

    HTTPAsyncRequestHandler rpcFunction =
        [&httpRPCRequestProcessor](
            Config &, HTTPRequest *req, const std::string &,
            boost::asio::any_io_executor executor) -> boost::asio::awaitable<bool> {
        // GET /wallet/<path> is the wallet PWA; everything else is JSON-RPC.
        if (walletpwa::MaybeServeWalletPwa(req)) {
            co_return true;
        }
        co_return co_await HTTPRPCRequestProcessor::DelegateHTTPRequestAsync(
            &httpRPCRequestProcessor, req, std::move(executor));
    };
    RegisterHTTPAsyncHandler("/", true, rpcFunction);
    if (g_wallet_init_interface.HasWalletSupport()) {
        RegisterHTTPAsyncHandler("/wallet/", false, rpcFunction);
    }

    RegisterHTTPAsyncHandler(
        "/pool/jobs", true,
        [&httpRPCRequestProcessor](
            Config &cfg, HTTPRequest *req, const std::string &,
            boost::asio::any_io_executor executor)
            -> boost::asio::awaitable<bool> {
            co_return co_await HandlePoolJobsHTTPAsync(
                cfg, httpRPCRequestProcessor.context, req, std::move(executor));
        });
    RegisterHTTPAsyncHandler(
        "/pool/submit", true,
        [&httpRPCRequestProcessor](
            Config &cfg, HTTPRequest *req, const std::string &,
            boost::asio::any_io_executor) -> boost::asio::awaitable<bool> {
            co_return co_await HandlePoolSubmitHTTPAsync(
                cfg, httpRPCRequestProcessor.context, req);
        });
    RegisterHTTPAsyncHandler(
        "/pool/stats", true,
        [&httpRPCRequestProcessor](
            Config &, HTTPRequest *req, const std::string &,
            boost::asio::any_io_executor) -> boost::asio::awaitable<bool> {
            co_return co_await HandlePoolStatsHTTPAsync(
                httpRPCRequestProcessor.context, req);
        });

    struct event_base *eventBase = EventBase();
    assert(eventBase);
    httpRPCTimerInterface = std::make_unique<HTTPRPCTimerInterface>(eventBase);
    RPCSetTimerInterface(httpRPCTimerInterface.get());
    return true;
}

void InterruptHTTPRPC() {
    LogEvent(BCLog::RPC, "rpc_http_interrupting",
             "Interrupting HTTP RPC server");
}

void StopHTTPRPC() {
    LogEvent(BCLog::RPC, "rpc_http_stopping", "Stopping HTTP RPC server");
    UnregisterHTTPHandler("/", true);
    if (g_wallet_init_interface.HasWalletSupport()) {
        UnregisterHTTPHandler("/wallet/", false);
    }
    UnregisterHTTPHandler("/pool/jobs", true);
    UnregisterHTTPHandler("/pool/submit", true);
    UnregisterHTTPHandler("/pool/stats", true);
    if (httpRPCTimerInterface) {
        RPCUnsetTimerInterface(httpRPCTimerInterface.get());
        httpRPCTimerInterface.reset();
    }
}
