// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/activation.h>

#include <chain.h>
#include <common/args.h>
#include <consensus/params.h>

bool IsWellingtonEnabled(const Consensus::Params &params, int32_t nHeight) {
    return nHeight >= params.wellingtonHeight;
}

bool IsWellingtonEnabled(const Consensus::Params &params,
                         const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsWellingtonEnabled(params, pindexPrev->nHeight);
}

bool IsCowperthwaiteEnabled(const Consensus::Params &params, int32_t nHeight) {
    return nHeight >= params.cowperthwaiteHeight;
}

bool IsCowperthwaiteEnabled(const Consensus::Params &params,
                            const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsCowperthwaiteEnabled(params, pindexPrev->nHeight);
}

bool IsObolenskyEnabled(const Consensus::Params &params,
                        int64_t nMedianTimePast) {
    return nMedianTimePast >= gArgs.GetIntArg("-obolenskyactivationtime",
                                              params.obolenskyActivationTime);
}

bool IsObolenskyEnabled(const Consensus::Params &params,
                        const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsObolenskyEnabled(params, pindexPrev->GetMedianTimePast());
}

bool IsExodusEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetIntArg("-exodusactivationtime", params.exodusActivationTime);
}

bool IsLeviticusEnabled(const Consensus::Params &params,
                        const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetIntArg("-leviticusactivationtime", params.leviticusActivationTime);
}
