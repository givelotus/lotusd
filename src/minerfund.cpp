// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <minerfund.h>

#include <cashaddrenc.h> // For DecodeCashAddrContent
#include <chainparams.h>
#include <consensus/activation.h>
#include <key_io.h> // For DecodeDestination

static const CTxOut BuildOutput(const std::string &address,
                                const Amount amount) {
    const std::unique_ptr<CChainParams> mainNetParams =
        CreateChainParams(CBaseChainParams::MAIN);
    CTxDestination dest = DecodeDestination(address, *mainNetParams);
    if (!IsValidDestination(dest)) {
        // Try the ecash cashaddr prefix.
        dest = DecodeCashAddrDestination(
            DecodeCashAddrContent(address, "bitcoincash"));
    }
    const CScript script = GetScriptForDestination(dest);
    return {amount, script};
}

static const std::vector<std::string> &
GetPayoutAddresses(const Consensus::Params &params,
                   const CBlockIndex *pindexPrev) {
    if (IsExodusEnabled(params, pindexPrev)) {
        return params.coinbasePayoutAddresses.exodus;
    }
    return params.coinbasePayoutAddresses.genesis;
}

std::vector<CTxOut> GetMinerFundRequiredOutputs(const Consensus::Params &params,
                                                const bool enableMinerFund,
                                                const CBlockIndex *pindexPrev,
                                                const Amount &blockReward) {
    if (!enableMinerFund) {
        return {};
    }

    const std::vector<std::string> &addresses =
        GetPayoutAddresses(params, pindexPrev);
    const size_t numAddresses = addresses.size();
    std::vector<CTxOut> minerFundOutputs;
    const Amount shareAmount = blockReward / (int64_t(2 * numAddresses));
    minerFundOutputs.reserve(numAddresses);
    for (const std::string &address : addresses) {
        minerFundOutputs.emplace_back(BuildOutput(address, shareAmount));
    }

    return minerFundOutputs;
}
