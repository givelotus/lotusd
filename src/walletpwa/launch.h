// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLETPWA_LAUNCH_H
#define BITCOIN_WALLETPWA_LAUNCH_H

#include <cstdint>
#include <string>

class ArgsManager;

namespace walletpwa {

/**
 * Host part of the wallet URL -gui opens: 127.0.0.1, unless every -rpcbind
 * is a non-loopback, non-wildcard address, then the first of them (bracketed
 * if IPv6, with its port if it has one). Returns "host:port".
 */
std::string LaunchAuthority(const ArgsManager &args, uint16_t rpcport);

/**
 * -gui: mint a one-time login token, print the wallet URL (to a terminal
 * only, never to debug.log) and open it in the default browser. Failing to
 * open a browser is logged, not an error.
 */
void LaunchWalletPwa(const ArgsManager &args);

} // namespace walletpwa

#endif // BITCOIN_WALLETPWA_LAUNCH_H
