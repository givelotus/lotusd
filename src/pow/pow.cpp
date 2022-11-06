// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/activation.h>
#include <consensus/params.h>
#include <pow/aserti32d.h>
#include <primitives/blockhash.h>
#include <util/system.h>

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
    // will be our anchor block.
    // We assign it minimum difficulty.
    if (!pindexPrev->pprev) {
        const uint32_t nProofOfWorkLimit =
            UintToArith256(params.powLimit).GetCompact();
        return nProofOfWorkLimit;
    }

    // TODO: Remove other difficulty adjustment algorithms (EDA, DAA, Grasberg).

    // All blocks after that will adjust their difficulty based on the
    // timestamp of the Genesis block.
    return GetNextASERTWorkRequired(pindexPrev, pblock, params);
}

bool CheckProofOfWork(const BlockHash &hash, uint32_t nBits,
                      const Consensus::Params &params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow ||
        bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    return true;
}

bool IsEpochBlockHash(const BlockHash &hash, const uint32_t nBits) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    const uint32_t nSize = nBits >> 24;
    const uint32_t nWord = nBits & 0x007f'ffff;

    assert(EPOCH_NUM_BLOCKS > 0x100); // otherwise we might build invalid nWord
    // Shift by 8 first to retain some precision, ...
    const uint32_t nWordEpoch = (nWord << 8) / EPOCH_NUM_BLOCKS;
    // ... and adjust nSize accordingly.
    const uint32_t nSizeEpoch = nSize - 1;
    // Build new epoch nBits.
    const uint32_t nBitsEpoch = (nSizeEpoch << 24) | nWordEpoch;

    bnTarget.SetCompact(nBitsEpoch, &fNegative, &fOverflow);

    // Check if proof of work is sufficient to be an epoch hash
    return UintToArith256(hash) <= bnTarget;
}

bool IsEpochBlock(const Consensus::Params &params, const CBlockIndex *pindex) {
    // Old epoch block mechanism, rolls over every 5040 blocks
    if (!IsLeviticusEnabled(params, pindex)) {
        return (pindex->nHeight + 1) % EPOCH_NUM_BLOCKS == 0;
    }

    // New PoW-based epoch block hash, requires 5040x PoW
    return IsEpochBlockHash(pindex->GetBlockHash(), pindex->nBits);
}

uint256 GetNextEpochBlockHash(const Consensus::Params &params,
                              const CBlockIndex *pindex) {
    if (IsEpochBlock(params, pindex)) {
        return pindex->GetBlockHash();
    }
    return pindex->hashEpochBlock;
}
