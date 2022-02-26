// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_ACTIVATION_H
#define BITCOIN_CONSENSUS_ACTIVATION_H

class CBlockIndex;

namespace Consensus {
struct Params;
}

/** Check if December 21st, 2021 protocol upgrade has activated. */
bool IsExodusEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev);

/** Check if June 21st, 2022 protocol upgrade has activated. */
bool IsLeviticusEnabled(const Consensus::Params &params,
                        const CBlockIndex *pindexPrev);

#endif // BITCOIN_CONSENSUS_ACTIVATION_H
