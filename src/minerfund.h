// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINERFUND_H
#define BITCOIN_MINERFUND_H

#include <amount.h>
#include <primitives/transaction.h>
#include <script/standard.h>

#include <vector>

class CBlockIndex;

namespace Consensus {
struct Params;
}

std::vector<CTxOut> GetMinerFundRequiredOutputs(const Consensus::Params &params,
                                                const CBlockIndex *pindexPrev,
                                                const Amount &blockReward);

#endif // BITCOIN_MINERFUND_H
