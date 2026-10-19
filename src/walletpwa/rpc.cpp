// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <util/string.h>
#include <walletpwa/assets.h>
#include <walletpwa/http.h>
#include <walletpwa/session.h>

#include <univalue.h>

#include <string>

static RPCHelpMan getwalletpwaurl() {
    return RPCHelpMan{
        "getwalletpwaurl",
        "Returns a one-time login link to the node's wallet UI (served at "
        "/wallet/). The link is valid once, for " +
            util::ToString(walletpwa::TOKEN_LIFETIME_SECONDS) +
            " seconds, and logs the browser in as the calling RPC user.\n",
        {
            {"base", RPCArg::Type::STR,
             RPCArg::DefaultHint{"http://127.0.0.1:<rpcport>"},
             "The scheme://host[:port] the browser reaches the node at"},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR, "url", "The login link"},
                {RPCResult::Type::NUM_TIME, "expires",
                 "When the link expires, in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::STR, "pwa_version",
                 "Version of the embedded wallet UI, empty if the node was "
                 "built without one"},
            }},
        RPCExamples{
            HelpExampleCli("getwalletpwaurl", "") +
            HelpExampleCli("getwalletpwaurl", "\"https://node.example.org\"") +
            HelpExampleRpc("getwalletpwaurl", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            std::string base{strprintf("http://127.0.0.1:%u",
                                       walletpwa::WalletPwaRpcPort())};
            if (!request.params[0].isNull()) {
                const auto origin{
                    walletpwa::ParseOrigin(request.params[0].get_str())};
                if (!origin) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       "base must be scheme://host[:port]");
                }
                base = origin->Normalized();
            }
            const auto token{walletpwa::MintLoginToken(request.authUser)};
            if (!token) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "The wallet UI is disabled (-walletpwa=0)");
            }
            UniValue result{UniValue::VOBJ};
            result.pushKV("url", base + "/wallet/#/login/" + token->token);
            result.pushKV("expires", token->expires);
            result.pushKV("pwa_version",
                          std::string{walletpwa::EmbeddedBundleVersion()});
            return result;
        },
    };
}

void RegisterWalletPwaRPCCommands(CRPCTable &t) {
    // clang-format off
    static const CRPCCommand commands[] = {
        //  category            actor (function)
        //  ------------------  ----------------------
        { "util",               getwalletpwaurl,         },
    };
    // clang-format on
    for (const auto &c : commands) {
        t.appendCommand(c.name, &c);
    }
}
