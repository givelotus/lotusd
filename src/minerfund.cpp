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

static const std::vector<CTxOut>
BuildOutputsCycling(const std::vector<std::string> &addresses,
                    const CBlockIndex *pindexPrev, const Amount blockReward) {
    const size_t numAddresses = addresses.size();
    const Amount shareAmount = blockReward / 2;
    const auto blockHeight = pindexPrev->nHeight + 1;
    const auto addressIndx = blockHeight % numAddresses;
    const auto address = addresses[addressIndx];
    return std::vector<CTxOut>({BuildOutput(address, shareAmount)});
}

static const std::vector<CTxOut>
BuildOutputsFanOut(const std::vector<std::string> &addresses,
                   const CBlockIndex *pindexPrev, const Amount blockReward) {
    const size_t numAddresses = addresses.size();
    std::vector<CTxOut> minerFundOutputs;
    const Amount shareAmount = blockReward / (int64_t(2 * numAddresses));
    minerFundOutputs.reserve(numAddresses);
    for (const std::string &address : addresses) {
        minerFundOutputs.emplace_back(BuildOutput(address, shareAmount));
    }
    return minerFundOutputs;
}

std::vector<CTxOut> GetMinerFundRequiredOutputs(const Consensus::Params &params,
                                                const bool enableMinerFund,
                                                const CBlockIndex *pindexPrev,
                                                const Amount &blockReward) {
    if (!enableMinerFund) {
        return {};
    }

    if (IsFirstKingsEnabled(params, pindexPrev)) {
        return BuildOutputsCycling(params.coinbasePayoutAddresses.firstKings,
                                   pindexPrev, blockReward);
    }

    if (IsSecondSamuelEnabled(params, pindexPrev)) {
        return BuildOutputsCycling(params.coinbasePayoutAddresses.secondSamuel,
                                   pindexPrev, blockReward);
    }

    if (IsFirstSamuelEnabled(params, pindexPrev)) {
        return BuildOutputsCycling(params.coinbasePayoutAddresses.firstSamuel,
                                   pindexPrev, blockReward);
    }

    if (IsRuthEnabled(params, pindexPrev)) {
        return BuildOutputsCycling(params.coinbasePayoutAddresses.ruth,
                                   pindexPrev, blockReward);
    }

    if (IsJudgesEnabled(params, pindexPrev)) {
        return BuildOutputsCycling(params.coinbasePayoutAddresses.judges,
                                   pindexPrev, blockReward);
    }

    if (IsJoshuaEnabled(params, pindexPrev)) {
        return BuildOutputsCycling(params.coinbasePayoutAddresses.joshua,
                                   pindexPrev, blockReward);
    }

    if (IsDeuteronomyEnabled(params, pindexPrev)) {
        return BuildOutputsCycling(params.coinbasePayoutAddresses.deuteronomy,
                                   pindexPrev, blockReward);
    }

    if (IsNumbersEnabled(params, pindexPrev)) {
        return BuildOutputsCycling(params.coinbasePayoutAddresses.numbers,
                                   pindexPrev, blockReward);
    }

    if (IsLeviticusEnabled(params, pindexPrev)) {
        return BuildOutputsFanOut(params.coinbasePayoutAddresses.leviticus,
                                  pindexPrev, blockReward);
    }

    if (IsExodusEnabled(params, pindexPrev)) {
        return BuildOutputsFanOut(params.coinbasePayoutAddresses.exodus,
                                  pindexPrev, blockReward);
    }

    return BuildOutputsFanOut(params.coinbasePayoutAddresses.genesis,
                              pindexPrev, blockReward);
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
