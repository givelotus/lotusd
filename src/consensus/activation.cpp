// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/activation.h>

#include <chain.h>
#include <common/args.h>
#include <consensus/params.h>

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

bool IsNumbersEnabled(const Consensus::Params &params,
                      const int64_t nMedianTimePast) {
    return nMedianTimePast >=
           gArgs.GetIntArg("-numbersactivationtime", params.numbersActivationTime);
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
           gArgs.GetIntArg("-deuteronomyactivationtime", params.deuteronomyActivationTime);
}

bool IsJoshuaEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetIntArg("-joshuaactivationtime", params.joshuaActivationTime);
}

bool IsJudgesEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetIntArg("-judgesactivationtime", params.judgesActivationTime);
}

bool IsRuthEnabled(const Consensus::Params &params,
                   const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetIntArg("-ruthactivationtime", params.ruthActivationTime);
}

bool IsFirstSamuelEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetIntArg("-firstsamuelactivationtime",
                           params.firstSamuelActivationTime);
}

bool IsSecondSamuelEnabled(const Consensus::Params &params,
                           const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetIntArg("-secondsamuelactivationtime",
                           params.secondSamuelActivationTime);
}

bool IsFirstKingsEnabled(const Consensus::Params &params,
                         const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetIntArg("-firstkingsactivationtime",
                           params.firstKingsActivationTime);
}
