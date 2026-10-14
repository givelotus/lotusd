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

/** Check if May 15th, 2023 protocol upgrade has activated. */
bool IsWellingtonEnabled(const Consensus::Params &params, int32_t nHeight);
/** Check if May 15th, 2023 protocol upgrade has activated. */
bool IsWellingtonEnabled(const Consensus::Params &params,
                         const CBlockIndex *pindexPrev);

/** Check if Nov 15th, 2023 protocol upgrade has activated. */
bool IsCowperthwaiteEnabled(const Consensus::Params &params, int32_t nHeight);
bool IsCowperthwaiteEnabled(const Consensus::Params &params,
                            const CBlockIndex *pindexPrev);

/** Check if December 21st, 2021 protocol upgrade has activated. */
bool IsExodusEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev);

/** Check if 2022-06-21T09:14:00.000Z protocol upgrade has activated. */
bool IsLeviticusEnabled(const Consensus::Params &params,
                        const CBlockIndex *pindexPrev);

/** Check if 2022-12-21T21:48:00.000Z protocol upgrade has activated. */
bool IsNumbersEnabled(const Consensus::Params &params,
                      const int64_t nMedianTimePast);
bool IsNumbersEnabled(const Consensus::Params &params,
                      const CBlockIndex *pindexPrev);

/** Check if 2023-06-21T14:58:00.000Z protocol upgrade has activated. */
bool IsDeuteronomyEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev);

/** Check if 2023-12-22T03:27:00.000Z protocol upgrade has activated. */
bool IsJoshuaEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev);

/** Check if 2024-06-20T20:51:00.000Z protocol upgrade has activated. */
bool IsJudgesEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev);

/** Check if 2024-12-21T09:20:00.000Z protocol upgrade has activated. */
bool IsRuthEnabled(const Consensus::Params &params,
                   const CBlockIndex *pindexPrev);

/** Check if 2025-06-21T02:42:00.000Z protocol upgrade has activated. */
bool IsFirstSamuelEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev);

/** Check if 2025-12-21T15:03:00.000Z protocol upgrade has activated. */
bool IsSecondSamuelEnabled(const Consensus::Params &params,
                           const CBlockIndex *pindexPrev);

/** Check if 2026-06-21T08:24:00.000Z protocol upgrade has activated. */
bool IsFirstKingsEnabled(const Consensus::Params &params,
                         const CBlockIndex *pindexPrev);

#endif // BITCOIN_CONSENSUS_ACTIVATION_H
