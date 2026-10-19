// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <walletpwa/launch.h>

#include <common/args.h>
#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/threadnames.h>
#include <walletpwa/http.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <thread>

#ifdef WIN32
#include <io.h>
#include <shellapi.h>
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

namespace walletpwa {

std::string LaunchAuthority(const ArgsManager &args, uint16_t rpcport) {
    const std::string fallback{strprintf("127.0.0.1:%u", rpcport)};
    // -rpcbind is ignored (localhost is bound) without -rpcallowip.
    if (!args.IsArgSet("-rpcallowip")) {
        return fallback;
    }
    std::optional<std::string> first;
    for (const std::string &bind : args.GetArgs("-rpcbind")) {
        uint16_t port{rpcport};
        std::string host;
        if (!SplitHostPort(bind, port, host)) {
            continue;
        }
        const auto addr{LookupHost(host, /*fAllowLookup=*/false)};
        if (!addr) {
            continue;
        }
        if (addr->IsBindAny()) {
            return strprintf("127.0.0.1:%u", port);
        }
        if (addr->IsLocal()) {
            return strprintf("%s:%u", addr->IsIPv6() ? "[::1]" : "127.0.0.1",
                             port);
        }
        if (!first) {
            first = strprintf(addr->IsIPv6() ? "[%s]:%u" : "%s:%u",
                              addr->ToStringAddr(), port);
        }
    }
    return first.value_or(fallback);
}

/** Open a URL in the default browser, without a shell and without waiting */
static void OpenBrowser(const std::string &url) {
#ifdef WIN32
    std::wstring wide(url.begin(), url.end());
    const auto result{reinterpret_cast<intptr_t>(ShellExecuteW(
        nullptr, L"open", wide.c_str(), nullptr, nullptr, SW_SHOWNORMAL))};
    if (result <= 32) {
        LogPrintf("Could not open a browser for the wallet UI; open the URL "
                  "above or run `getwalletpwaurl`\n");
    }
#else
#ifdef __APPLE__
    const char *opener{"open"};
#else
    const char *opener{"xdg-open"};
    if (!std::getenv("DISPLAY") && !std::getenv("WAYLAND_DISPLAY")) {
        LogPrintf("No desktop session; open the URL above or run "
                  "`getwalletpwaurl`\n");
        return;
    }
#endif
    std::string arg0{opener};
    std::string arg1{url};
    char *argv[]{arg0.data(), arg1.data(), nullptr};
    pid_t pid;
    if (posix_spawnp(&pid, opener, nullptr, nullptr, argv, environ) != 0) {
        LogPrintf("Could not start %s to open the wallet UI; open the URL "
                  "above or run `getwalletpwaurl`\n",
                  opener);
        return;
    }
    // Reap the opener when it exits, without holding up startup.
    std::thread([pid] {
        util::ThreadRename("walletpwaopen");
        int status;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
    }).detach();
#endif
}

static bool StdoutIsTerminal() {
#ifdef WIN32
    return _isatty(_fileno(stdout));
#else
    return isatty(fileno(stdout));
#endif
}

void LaunchWalletPwa(const ArgsManager &args) {
    // The token stores only the user name; it never needs the password.
    const std::string user{args.GetArg("-rpcpassword", "").empty()
                               ? std::string{"__cookie__"}
                               : args.GetArg("-rpcuser", "")};
    const auto token{MintLoginToken(user)};
    if (!token) {
        return;
    }
    // Always http: the listener also serves plain HTTP, and loopback is a
    // secure context for browsers.
    const std::string url{strprintf("http://%s/wallet/#/login/%s",
                                    LaunchAuthority(args, WalletPwaRpcPort()),
                                    token->token)};
    if (StdoutIsTerminal() && !args.GetBoolArg("-daemon", false)) {
        // Never written to debug.log: it carries a login token.
        tfm::format(std::cout, "Wallet: %s\n", url);
        std::cout.flush();
    }
    LogPrintf("Opening the wallet UI in the default browser\n");
    OpenBrowser(url);
}

} // namespace walletpwa
