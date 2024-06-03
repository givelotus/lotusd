// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_ACTIVATION_H
#define BITCOIN_CONSENSUS_ACTIVATION_H

#include <cstdint>

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

/** Check if December 21st, 2022 protocol upgrade has activated. */
bool IsNumbersEnabled(const Consensus::Params &params,
                      const int64_t nMedianTimePast);
bool IsNumbersEnabled(const Consensus::Params &params,
                      const CBlockIndex *pindexPrev);

/** Check if June 21st, 2023 protocol upgrade has activated. */
bool IsDeuteronomyEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev);

/** Check if December 22nd, 2023 protocol upgrade has activated. */
bool IsJoshuaEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev);

/** Check if June 20th, 2024 protocol upgrade has activated. */
bool IsJudgesEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev);

#endif // BITCOIN_CONSENSUS_ACTIVATION_H
