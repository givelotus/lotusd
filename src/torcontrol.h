// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Functionality for communicating with Tor.
 */
#ifndef BITCOIN_TORCONTROL_H
#define BITCOIN_TORCONTROL_H

#include <netaddress.h>

#include <optional>
#include <string>

extern const std::string DEFAULT_TOR_CONTROL;
static const bool DEFAULT_LISTEN_ONION = true;

void StartTorControl(CService onion_service_target);
void InterruptTorControl();
void StopTorControl();

CService DefaultOnionServiceTarget();

/**
 * Parse a Tor control port address: a numeric IPv4 or IPv6 address with an
 * optional port, written as "1.2.3.4", "1.2.3.4:9051", "[::1]", "[::1]:9051"
 * or "::1". Host names are rejected. A missing port gives port 0; a given port
 * must be in 1-65535. These are the forms libevent's
 * evutil_parse_sockaddr_port accepts.
 */
std::optional<CService> ParseTorControlAddress(const std::string &address);

#endif // BITCOIN_TORCONTROL_H
