// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <minerfund.h>

#include <chainparams.h>
#include <consensus/activation.h>
#include <key_io.h> // For DecodeDestination
#include <util/system.h>
#include <validation.h> // For VersionBitsBlockState

static const CTxOut BuildOutput(const std::string &dest, const Amount amount) {
    const auto mainNetParams = CreateChainParams(CBaseChainParams::MAIN);
    const CScript script =
        GetScriptForDestination(DecodeDestination(dest, *mainNetParams));
    return {amount, script};
}

const CTxOut BuildRandomOutput(const std::vector<std::string> &addressList,
                               uint64_t slot, Amount shareAmount,
                               uint256 epochBlockHash) {
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << slot;
    hasher << epochBlockHash;
    uint256 hash = hasher.GetSHA256();
    uint64_t weakHash = hash.GetUint64(0);
    // Note: There is modulo bias here, but it is being ignored as the random
    // domain is much much larger than injected range. Thus, the effect is
    // small.
    return BuildOutput(addressList[weakHash % addressList.size()], shareAmount);
}

std::vector<CTxOut> GetMinerFundRequiredOutputs(const Consensus::Params &params,
                                                const bool enableMinerFund,
                                                const CBlockIndex *pindexPrev,
                                                const Amount &blockReward) {
    if (!enableMinerFund) {
        return {};
    }

    const auto epochBlockHash = Hash(pindexPrev->hashEpochBlock);
    const auto numPayoutAddressSets = params.payoutAddressSets.size();
    // Plus 1 for Foundation output
    const Amount shareAmount =
        blockReward / (int64_t(2 * (numPayoutAddressSets)));
    std::vector<CTxOut> minerFundOutputs;
    minerFundOutputs.reserve(numPayoutAddressSets);

    for (const auto &addressSet : params.payoutAddressSets) {
        minerFundOutputs.emplace_back(BuildRandomOutput(
            addressSet, minerFundOutputs.size(), shareAmount, epochBlockHash));
    }

    return minerFundOutputs;
}
