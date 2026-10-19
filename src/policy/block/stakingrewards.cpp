// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/block/stakingrewards.h>

#include <primitives/v2_outputs.h>

#include <avalanche/avalanche.h>
#include <avalanche/processor.h>
#include <blockindex.h>
#include <common/args.h>
#include <consensus/activation.h>
#include <consensus/amount.h>
#include <logging.h>
#include <primitives/block.h>

#include <vector>

bool StakingRewardsPolicy::operator()(BlockPolicyValidationState &state) {
    if (!IsStakingRewardsActivated(m_consensusParams, m_blockIndex.pprev) ||
        !m_avalanche.isQuorumEstablished()) {
        return true;
    }

    assert(m_block.vtx.size());

    const BlockHash blockhash = m_blockIndex.GetBlockHash();

    std::vector<CScript> winners;
    if (!m_avalanche.getStakingRewardWinners(m_blockIndex.pprev->GetBlockHash(),
                                             winners)) {
        LogDebug(BCLog::AVALANCHE,
                 "Staking rewards for block %s: not ready yet\n",
                 blockhash.ToString());
        return true;
    }

    const Amount required = GetStakingRewardsAmount(m_blockReward);
    for (auto &o : m_block.vtx[0]->vout) {
        if (o.nValue < required) {
            // This output doesn't qualify because its amount is too low.
            continue;
        }

        auto it = std::find_if(
            winners.begin(), winners.end(), [&](const CScript &winner) {
                return CoinbaseOutputPaysScript(o, winner);
            });
        if (it != winners.end()) {
            if (it != winners.begin()) {
                LogDebug(BCLog::AVALANCHE,
                         "Staking rewards for block %s: selected winner is "
                         "flaky, accepting an alternative one\n",
                         blockhash.ToString());
            }

            return true;
        }
    }

    LogDebug(BCLog::AVALANCHE,
             "Staking rewards for block %s: payout script mismatch!\n",
             blockhash.ToString());

    return state.Invalid(BlockPolicyValidationResult::POLICY_VIOLATION,
                         "policy-bad-staking-reward",
                         strprintf("Block %s violates staking reward policy",
                                   m_blockIndex.GetBlockHash().ToString()));
}

Amount GetStakingRewardsAmount(const Amount &coinbaseValue) {
    return STAKING_REWARD_RATIO * coinbaseValue / 100;
}

bool IsStakingRewardsActivated(const Consensus::Params &params,
                               const CBlockIndex *pprev) {
    return pprev != nullptr &&
           gArgs.GetBoolArg("-avalanchestakingrewards",
                            params.enableStakingRewards);
}
