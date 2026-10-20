// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_NODE_WEBTRANSPORT_H
#define BITCOIN_NET_QUIC_NODE_WEBTRANSPORT_H

// The node's P2P over WebTransport service (built with
// -DENABLE_WEBTRANSPORT=ON): reads the -p2pwebtransport* options and runs
// the QUIC engine. No QUIC library header is included.

#include <util/translation.h>

class ArgsManager;
class QuicEngine;

/** Start the QUIC engine per -p2pwebtransport*; false + error on failure */
bool StartNodeWebTransport(const ArgsManager &args, bilingual_str &error);
/** Stop it (idempotent); call after CConnman::Stop() */
void StopNodeWebTransport();
/** The running engine, or nullptr */
QuicEngine *GetNodeQuicEngine();

#endif // BITCOIN_NET_QUIC_NODE_WEBTRANSPORT_H
