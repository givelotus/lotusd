// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <minerfund.h>

#include <blockindex.h>
#include <cashaddrenc.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/activation.h>
#include <consensus/amount.h>
#include <currencyunit.h>
#include <key_io.h> // For DecodeDestination
#include <primitives/transaction.h>

static const CTxOut BuildOutput(const std::string &destStr,
                                const Amount amount) {
    const ArgsManager unused_argsman{};
    const auto mainNetParams =
        CreateChainParams(unused_argsman, ChainType::MAIN);
    CTxDestination dest = DecodeDestination(destStr, *mainNetParams);
    if (!IsValidDestination(dest)) {
        dest = DecodeCashAddrDestination(
            DecodeCashAddrContent(destStr, "bitcoincash"));
    }
    const CScript script = GetScriptForDestination(dest);
    return {amount, script};
}

std::vector<CTxOut> GetMinerFundRequiredOutputs(const Consensus::Params &params,
                                                const bool enableMinerFund,
                                                const CBlockIndex *pindexPrev,
                                                const Amount &blockReward) {
    if (!enableMinerFund) {
        return {};
    }

    const std::vector<std::string> &addresses =
        params.coinbasePayoutAddresses.genesis;

    const size_t numAddresses = addresses.size();
    std::vector<CTxOut> minerFundOutputs;
    const Amount shareAmount = blockReward / (int64_t(2 * numAddresses));
    minerFundOutputs.reserve(numAddresses);
    for (const std::string &address : addresses) {
        minerFundOutputs.emplace_back(BuildOutput(address, shareAmount));
    }

    return minerFundOutputs;
}

bool CheckMinerFund(const Consensus::Params &params,
                    const bool enableMinerFund,
                    const std::vector<CTxOut> &coinbaseTxOut,
                    const Amount &blockReward, const CBlockIndex *pprev) {
    const std::vector<CTxOut> requiredOutputs =
        GetMinerFundRequiredOutputs(params, enableMinerFund, pprev, blockReward);
    if (requiredOutputs.empty()) {
        return true;
    }
    auto nextRequiredOutput = requiredOutputs.begin();
    for (const CTxOut &o : coinbaseTxOut) {
        if (o == *nextRequiredOutput) {
            nextRequiredOutput++;
            if (nextRequiredOutput == requiredOutputs.end()) {
                return true;
            }
        }
    }
    return false;
}
