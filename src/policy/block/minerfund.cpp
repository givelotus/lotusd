// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/block/minerfund.h>

#include <blockindex.h>
#include <consensus/activation.h>
#include <minerfund.h>

bool MinerFundPolicy::operator()(BlockPolicyValidationState &state) {
    if (!m_blockIndex.pprev) {
        return true;
    }

    assert(m_block.vtx.size());
    if (!CheckMinerFund(m_consensusParams, m_block.vtx[0]->vout, m_blockReward,
                        m_blockIndex.pprev)) {
        return state.Invalid(BlockPolicyValidationResult::POLICY_VIOLATION,
                             "policy-bad-miner-fund",
                             strprintf("Block %s violates miner fund policy",
                                       m_blockIndex.GetBlockHash().ToString()));
    }
    return true;
}
