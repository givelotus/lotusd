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

static const CTxOut BurnOutput(const Amount amount) {
    std::vector<uint8_t> burnPayload = {
        200, 225, 246, 229, 160, 237, 229, 242, 227, 249, 160, 239, 238,
        160, 237, 229, 172, 160, 225, 160, 243, 233, 238, 238, 229, 242};
    return {amount, CScript() << OP_RETURN << burnPayload};
}

std::vector<CTxOut> GetMinerFundRequiredOutputs(const Consensus::Params &params,
                                                const bool enableMinerFund,
                                                const CBlockIndex *pindexPrev,
                                                const Amount &blockReward) {
    if (!enableMinerFund) {
        return {};
    }
    const Amount shareAmount = blockReward / 26;

    return {
        // Bitcoin ABC
        BuildOutput("pqnqv9lt7e5vjyp0w88zf2af0l92l8rxdgnlxww9j9", shareAmount),
        // Stamp
        BuildOutput("qqrad726sy24klmsd4dus5gxl0rhgz0rdcjnagpmve", shareAmount),
        // Tobias
        BuildOutput("qzafzyamh8rgszacw73gg2vly8gnxe099qx6fqrdfd", shareAmount),
        // Burn the remaining shares
        BurnOutput(10 * shareAmount),
    };
}
