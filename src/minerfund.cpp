// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <minerfund.h>

#include <cashaddrenc.h> // For DecodeCashAddrContent
#include <chain.h>       // For CBlockIndex class
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
