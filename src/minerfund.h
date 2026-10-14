// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINERFUND_H
#define BITCOIN_MINERFUND_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/standard.h>

#include <vector>

class CBlockIndex;

namespace Consensus {
struct Params;
} // namespace Consensus

std::vector<CTxOut> GetMinerFundRequiredOutputs(const Consensus::Params &params,
                                                const CBlockIndex *pindexPrev,
                                                const Amount &blockReward);

/**
 * Returns false if there is an invalid miner fund. True otherwise.
 */
bool CheckMinerFund(const Consensus::Params &params,
                    const std::vector<CTxOut> &coinbaseTxOut,
                    const Amount &blockReward, const CBlockIndex *pprev);

#endif // BITCOIN_MINERFUND_H
