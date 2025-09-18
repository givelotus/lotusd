// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/activation.h>

#include <chain.h>
#include <consensus/params.h>
#include <util/system.h>

bool IsExodusEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetArg("-exodusactivationtime", params.exodusActivationTime);
}

bool IsLeviticusEnabled(const Consensus::Params &params,
                        const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetArg("-leviticusactivationtime",
                        params.leviticusActivationTime);
}

bool IsNumbersEnabled(const Consensus::Params &params,
                      const int64_t nMedianTimePast) {
    return nMedianTimePast >=
           gArgs.GetArg("-numbersactivationtime", params.numbersActivationTime);
}

bool IsNumbersEnabled(const Consensus::Params &params,
                      const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsNumbersEnabled(params, pindexPrev->GetMedianTimePast());
}

bool IsDeuteronomyEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetArg("-deuteronomyactivationtime",
                        params.deuteronomyActivationTime);
}

bool IsJoshuaEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetArg("-joshuaactivationtime", params.joshuaActivationTime);
}

bool IsJudgesEnabled(const Consensus::Params &params,

const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetArg("-judgesactivationtime", params.judgesActivationTime);
}

bool IsRuthEnabled(const Consensus::Params &params,
                   const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }
    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetArg("-ruthactivationtime", params.ruthActivationTime);
}

bool IsFirstSamuelEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }
    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetArg("-firstsamuelactivationtime",
                        params.firstSamuelActivationTime);
}
