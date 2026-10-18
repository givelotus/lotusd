// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/activation.h>

#include <chain.h>
#include <common/args.h>
#include <consensus/params.h>

bool IsUAHFenabled(const Consensus::Params &params, int nHeight) {
    return true;
}

bool IsUAHFenabled(const Consensus::Params &params,
                   const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsUAHFenabled(params, pindexPrev->nHeight);
}

bool IsDAAEnabled(const Consensus::Params &params, int nHeight) {
    return true;
}

bool IsDAAEnabled(const Consensus::Params &params,
                  const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsDAAEnabled(params, pindexPrev->nHeight);
}

bool IsMagneticAnomalyEnabled(const Consensus::Params &params,
                              int32_t nHeight) {
    return true;
}

bool IsMagneticAnomalyEnabled(const Consensus::Params &params,
                              const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsMagneticAnomalyEnabled(params, pindexPrev->nHeight);
}

static bool IsGravitonEnabled(const Consensus::Params &params,
                              int32_t nHeight) {
    return true;
}

bool IsGravitonEnabled(const Consensus::Params &params,
                       const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsGravitonEnabled(params, pindexPrev->nHeight);
}

static bool IsPhononEnabled(const Consensus::Params &params, int32_t nHeight) {
    return true;
}

bool IsPhononEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsPhononEnabled(params, pindexPrev->nHeight);
}

static bool IsAxionEnabled(const Consensus::Params &params, int32_t nHeight) {
    return true;
}

bool IsAxionEnabled(const Consensus::Params &params,
                    const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsAxionEnabled(params, pindexPrev->nHeight);
}

bool IsWellingtonEnabled(const Consensus::Params &params, int32_t nHeight) {
    return true;
}

bool IsWellingtonEnabled(const Consensus::Params &params,
                         const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsWellingtonEnabled(params, pindexPrev->nHeight);
}

bool IsCowperthwaiteEnabled(const Consensus::Params &params, int32_t nHeight) {
    return true;
}

bool IsCowperthwaiteEnabled(const Consensus::Params &params,
                            const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsCowperthwaiteEnabled(params, pindexPrev->nHeight);
}

bool IsMengerEnabled(const Consensus::Params &params, int64_t nMedianTimePast) {
    return true;
}

bool IsMengerEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return true;
    }

    return IsMengerEnabled(params, pindexPrev->GetMedianTimePast());
}
