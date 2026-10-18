// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/system.h>
#include <consensus/activation.h>
#include <consensus/params.h>
#include <pow/aserti32d.h>
#include <pow/daa.h>
#include <pow/eda.h>
#include <pow/grasberg.h>
#include <primitives/blockhash.h>

uint32_t GetNextWorkRequired(const CBlockIndex *pindexPrev,
                             const CBlockHeader *pblock,
                             const CChainParams &chainParams) {
    // GetNextWorkRequired should never be called on the genesis block
    assert(pindexPrev != nullptr);

    const Consensus::Params &params = chainParams.GetConsensus();

    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting) {
        return pindexPrev->nBits;
    }

    // ASERT requires an anchor block which has one parent.
    // The Genesis block has no parent. Therefore, the block after Genesis
    // will be our anchor block. We assign it minimum difficulty.
    if (!pindexPrev->pprev) {
        const uint32_t nProofOfWorkLimit =
            UintToArith256(params.powLimit).GetCompact();
        return nProofOfWorkLimit;
    }

    // All blocks after genesis+1 adjust difficulty based on the genesis
    // block timestamp as anchor.
    return GetNextASERTWorkRequired(pindexPrev, pblock, params);
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params &params,
                                   int64_t height, uint32_t old_nbits,
                                   uint32_t new_nbits) {
    if (params.fPowAllowMinDifficultyBlocks) {
        return true;
    }

    // Keeping the same difficulty as the prev block is always permitted,
    // assuming the initial difficulty was valid, so bail out early.
    // The initial difficulty is valid because we start from the genesis block
    // and we stop calling this function as soon as it returns false.
    // This avoids further computation for most blocks prior to the BCH fork.
    if (old_nbits == new_nbits) {
        return true;
    }

    arith_uint256 observed_new_target;
    // Check [0, powLimit] range.
    if (!NBitsToTarget(params, new_nbits, observed_new_target)) {
        return false;
    }

    // ASERT allows any difficulty transition.
    return true;
}

bool CheckProofOfWork(const BlockHash &hash, uint32_t nBits,
                      const Consensus::Params &params) {
    arith_uint256 bnTarget;
    if (!NBitsToTarget(params, nBits, bnTarget)) {
        return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    return true;
}

bool NBitsToTarget(const Consensus::Params &params, uint32_t nBits,
                   arith_uint256 &target) {
    bool fNegative;
    bool fOverflow;

    target.SetCompact(nBits, &fNegative, &fOverflow);

    return !(fNegative || target == 0 || fOverflow ||
             target > UintToArith256(params.powLimit));
}
