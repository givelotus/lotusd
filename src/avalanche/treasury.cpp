// Copyright (c) 2024-2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/treasury.h>

#include <primitives/v2_outputs.h>

#include <avalanche/processor.h>
#include <blockindex.h>
#include <cashaddrenc.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <key_io.h>
#include <logging.h>
#include <lotus_v2/vendor/blake3/blake3.h>
#include <primitives/block.h>
#include <script/script.h>
#include <script/standard.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>

namespace avalanche {

namespace {

CTxDestination TryDecodeAnyDestination(const std::string &addrStr) {
    // 1. Try active chainparams first
    CTxDestination dest = DecodeDestination(addrStr, Params());
    if (IsValidDestination(dest)) {
        return dest;
    }

    // 2. If addrStr has an explicit prefix:payload, try CashAddr decoding with
    // that prefix directly (supports lotus:, ecash:, bitcoincash:, bchreg:, etc.)
    const size_t colonPos = addrStr.find(':');
    if (colonPos != std::string::npos && colonPos > 0) {
        const std::string prefix = ToLower(addrStr.substr(0, colonPos));
        const CashAddrContent content = DecodeCashAddrContent(addrStr, prefix);
        dest = DecodeCashAddrDestination(content);
        if (IsValidDestination(dest)) {
            return dest;
        }
    } else {
        // Prefixless CashAddr: try common prefixes
        for (const char *prefix : {"lotus", "ecash", "bitcoincash", "bchreg",
                                   "ecregtest", "bchtest", "ectest"}) {
            const CashAddrContent content =
                DecodeCashAddrContent(addrStr, prefix);
            dest = DecodeCashAddrDestination(content);
            if (IsValidDestination(dest)) {
                return dest;
            }
        }
    }

    // 3. Try Mainnet / Testnet / Regtest chainparams (both ecash and bitcoincash)
    for (const ChainType ct :
         {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        for (const bool ecashOpt : {false, true}) {
            CChainParams::ChainOptions opts{};
            opts.ecash = ecashOpt;
            std::unique_ptr<const CChainParams> cp;
            switch (ct) {
                case ChainType::MAIN:
                    cp = CChainParams::Main(opts);
                    break;
                case ChainType::TESTNET:
                    cp = CChainParams::TestNet(opts);
                    break;
                case ChainType::REGTEST:
                    cp = CChainParams::RegTest(opts);
                    break;
            }
            if (cp) {
                dest = DecodeDestination(addrStr, *cp);
                if (IsValidDestination(dest)) {
                    return dest;
                }
            }
        }
    }

    return CNoDestination{};
}

bool IsDefaultTreasuryExplicitlyDisabled() {
    if (gArgs.IsArgSet("-avalanchedefaulttreasury") &&
        !gArgs.GetBoolArg("-avalanchedefaulttreasury", true)) {
        return true;
    }
    if (gArgs.IsArgSet("-avalancheusedefaulttreasury") &&
        !gArgs.GetBoolArg("-avalancheusedefaulttreasury", true)) {
        return true;
    }
    return false;
}

bool IsDefaultTreasuryExplicitlyEnabled() {
    if (IsDefaultTreasuryExplicitlyDisabled()) {
        return false;
    }
    if (gArgs.IsArgSet("-avalanchetreasuryaddress") &&
        !gArgs.GetArgs("-avalanchetreasuryaddress").empty()) {
        return true;
    }
    if (gArgs.IsArgSet("-avalanchedefaulttreasury") &&
        gArgs.GetBoolArg("-avalanchedefaulttreasury", false)) {
        return true;
    }
    if (gArgs.IsArgSet("-avalancheusedefaulttreasury") &&
        gArgs.GetBoolArg("-avalancheusedefaulttreasury", false)) {
        return true;
    }
    return false;
}

} // namespace

bool IsValidTreasuryOutputs(const std::vector<CTxOut> &outputs,
                            std::optional<Amount> expectedTotalReward) {
    if (outputs.empty() || outputs.size() > MAX_TREASURY_OUTPUTS) {
        return false;
    }
    if (expectedTotalReward.has_value() &&
        (!MoneyRange(*expectedTotalReward) ||
         *expectedTotalReward <= Amount::zero())) {
        return false;
    }

    Amount sum = Amount::zero();
    for (const CTxOut &out : outputs) {
        if (!MoneyRange(out.nValue) || out.nValue <= Amount::zero()) {
            return false;
        }
        if (out.scriptPubKey.empty() ||
            out.scriptPubKey.size() > MAX_SCRIPT_SIZE) {
            return false;
        }
        if (!MoneyRange(sum + out.nValue)) {
            return false;
        }
        sum += out.nValue;
    }

    if (expectedTotalReward.has_value() && sum != *expectedTotalReward) {
        return false;
    }
    return true;
}

std::vector<CTxOut> ComputeProportionalTreasuryOutputs(
    const std::vector<std::pair<CScript, uint32_t>> &templateEntries,
    Amount totalTreasuryReward) {
    if (templateEntries.empty() ||
        templateEntries.size() > MAX_TREASURY_OUTPUTS ||
        !MoneyRange(totalTreasuryReward) ||
        totalTreasuryReward <= Amount::zero()) {
        return {};
    }

    uint64_t totalWeight = 0;
    for (const auto &[script, weight] : templateEntries) {
        if (script.empty() || script.size() > MAX_SCRIPT_SIZE || weight == 0) {
            return {};
        }
        totalWeight += weight;
    }
    if (totalWeight == 0) {
        return {};
    }

    const int64_t totalSats = totalTreasuryReward / SATOSHI;
    if (totalSats < static_cast<int64_t>(templateEntries.size())) {
        return {};
    }

    std::vector<CTxOut> outputs;
    outputs.reserve(templateEntries.size());

    int64_t allocatedSats = 0;
    for (const auto &[script, weight] : templateEntries) {
        const int64_t shareSats = static_cast<int64_t>(
            (static_cast<__uint128_t>(totalSats) * weight) / totalWeight);
        allocatedSats += shareSats;
        outputs.emplace_back(shareSats * SATOSHI, script);
    }

    const int64_t remainderSats = totalSats - allocatedSats;
    outputs[0].nValue += remainderSats * SATOSHI;

    if (!IsValidTreasuryOutputs(outputs, totalTreasuryReward)) {
        return {};
    }
    return outputs;
}

bool ParseTreasuryAddressEntry(const std::string &entry, CScript &scriptOut,
                               uint32_t &weightOut) {
    const std::string trimmed = util::TrimString(entry);
    if (trimmed.empty()) {
        return false;
    }

    std::string targetStr = trimmed;
    weightOut = DEFAULT_TREASURY_OUTPUT_WEIGHT;

    const size_t lastColon = trimmed.rfind(':');
    if (lastColon != std::string::npos && lastColon > 0 &&
        lastColon + 1 < trimmed.size()) {
        const std::string suffix = trimmed.substr(lastColon + 1);
        const bool allDigits =
            !suffix.empty() && suffix.size() <= 10 &&
            std::all_of(suffix.begin(), suffix.end(),
                        [](char c) { return c >= '0' && c <= '9'; });
        if (allDigits) {
            uint64_t parsedWeight = 0;
            for (char c : suffix) {
                parsedWeight = parsedWeight * 10 + static_cast<uint64_t>(c - '0');
            }
            if (parsedWeight == 0 ||
                parsedWeight > std::numeric_limits<uint32_t>::max()) {
                return false;
            }
            weightOut = static_cast<uint32_t>(parsedWeight);
            targetStr = util::TrimString(trimmed.substr(0, lastColon));
            if (targetStr.empty()) {
                return false;
            }
        }
    }

    const CTxDestination dest = TryDecodeAnyDestination(targetStr);
    if (IsValidDestination(dest)) {
        scriptOut = GetScriptForDestination(dest);
        return !scriptOut.empty() && scriptOut.size() <= MAX_SCRIPT_SIZE;
    }

    if (IsHex(targetStr) && (targetStr.size() % 2 == 0)) {
        const std::vector<uint8_t> raw = ParseHex(targetStr);
        scriptOut = CScript(raw.begin(), raw.end());
        return !scriptOut.empty() && scriptOut.size() <= MAX_SCRIPT_SIZE;
    }

    return false;
}

bool ParseTreasuryAddressArgs(
    const std::vector<std::string> &rawArgs,
    std::vector<std::pair<CScript, uint32_t>> &templateOut) {
    templateOut.clear();
    for (const std::string &rawArg : rawArgs) {
        for (const std::string &tokenRaw : util::SplitString(rawArg, ',')) {
            const std::string token = util::TrimString(tokenRaw);
            if (token.empty()) {
                continue;
            }
            CScript script;
            uint32_t weight = 0;
            if (!ParseTreasuryAddressEntry(token, script, weight)) {
                templateOut.clear();
                return false;
            }
            templateOut.emplace_back(std::move(script), weight);
        }
    }
    if (templateOut.empty() || templateOut.size() > MAX_TREASURY_OUTPUTS) {
        templateOut.clear();
        return false;
    }
    return true;
}

std::vector<std::pair<CScript, uint32_t>>
GetDefaultTreasuryTemplate(const Consensus::Params &params) {
    if (gArgs.IsArgSet("-avalanchetreasuryaddress")) {
        const auto rawArgs = gArgs.GetArgs("-avalanchetreasuryaddress");
        std::vector<std::pair<CScript, uint32_t>> parsed;
        if (!rawArgs.empty() && ParseTreasuryAddressArgs(rawArgs, parsed)) {
            return parsed;
        }
    }
    return params.defaultTreasuryOutputs;
}

TreasuryContenderId
TreasuryContenderId::ComputeId(const BlockHash &prevblockhash,
                               const std::vector<CTxOut> &outputs) {
    static constexpr const char *kDomainTag = "lotus.v2.ava.treasury_contender";
    uint8_t key[BLAKE3_KEY_LEN]{};
    std::memcpy(key, kDomainTag,
                std::min(std::strlen(kDomainTag), size_t(BLAKE3_KEY_LEN)));

    DataStream ss{};
    ss << prevblockhash;
    WriteCompactSize(ss, outputs.size());
    for (const CTxOut &out : outputs) {
        ss << out;
    }

    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, key);
    blake3_hasher_update(&hasher, UCharCast(ss.data()), ss.size());

    uint256 result;
    blake3_hasher_finalize(&hasher, result.begin(), BLAKE3_OUT_LEN);
    return TreasuryContenderId(result);
}

void TreasuryContenderCache::eraseTrackedBlock(const BlockHash &blockhash) {
    auto &mwHashView = manualWinners.get<by_treasury_prevblockhash>();
    auto [mwBegin, mwEnd] = mwHashView.equal_range(blockhash);
    mwHashView.erase(mwBegin, mwEnd);

    auto &cHashView = contenders.get<by_treasury_prevblockhash>();
    auto [cBegin, cEnd] = cHashView.equal_range(blockhash);
    cHashView.erase(cBegin, cEnd);

    m_blockOrder.erase(
        std::remove(m_blockOrder.begin(), m_blockOrder.end(), blockhash),
        m_blockOrder.end());
}

void TreasuryContenderCache::trackBlockInOrder(const BlockHash &prevblockhash,
                                               size_t maxTrackedBlocks) {
    if (std::find(m_blockOrder.begin(), m_blockOrder.end(), prevblockhash) !=
        m_blockOrder.end()) {
        return;
    }
    while (maxTrackedBlocks > 0 && m_blockOrder.size() >= maxTrackedBlocks) {
        const BlockHash oldest = m_blockOrder.front();
        m_blockOrder.pop_front();
        eraseTrackedBlock(oldest);
    }
    m_blockOrder.push_back(prevblockhash);
}

void TreasuryContenderCache::cleanupBounded(size_t maxTrackedBlocks) {
    while (m_blockOrder.size() > maxTrackedBlocks) {
        const BlockHash oldest = m_blockOrder.front();
        m_blockOrder.pop_front();
        eraseTrackedBlock(oldest);
    }
}

void TreasuryContenderCache::cleanup(const int requestedMinHeight) {
    std::set<BlockHash> hashesToErase;
    auto &mwHeightView = manualWinners.get<by_treasury_blockheight>();
    for (auto it = mwHeightView.begin();
         it != mwHeightView.lower_bound(requestedMinHeight); ++it) {
        if (it->blockheight > 0) {
            hashesToErase.insert(it->prevblockhash);
        }
    }

    auto &cHeightView = contenders.get<by_treasury_blockheight>();
    for (auto it = cHeightView.begin();
         it != cHeightView.lower_bound(requestedMinHeight); ++it) {
        if (it->blockheight > 0) {
            hashesToErase.insert(it->prevblockhash);
        }
    }

    for (const auto &blockhash : hashesToErase) {
        eraseTrackedBlock(blockhash);
    }
    cleanupBounded(MAX_TRACKED_TREASURY_BLOCKS);
}

void TreasuryContenderCache::cleanup(const BlockHash &keepBlockHash) {
    for (auto it = manualWinners.begin(); it != manualWinners.end();) {
        if (it->prevblockhash != keepBlockHash) {
            it = manualWinners.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = contenders.begin(); it != contenders.end();) {
        if (it->prevblockhash != keepBlockHash) {
            it = contenders.erase(it);
        } else {
            ++it;
        }
    }
    m_blockOrder.erase(
        std::remove_if(m_blockOrder.begin(), m_blockOrder.end(),
                       [&](const BlockHash &h) { return h != keepBlockHash; }),
        m_blockOrder.end());
}

TreasuryContenderId TreasuryContenderCache::registerDefaultTreasuryContender(
    const CBlockIndex *pindexPrev, Amount blockSubsidy,
    TreasuryContenderId *outContenderId) {
    if (!pindexPrev) {
        if (outContenderId) {
            *outContenderId = TreasuryContenderId();
        }
        return TreasuryContenderId();
    }
    return registerDefaultTreasuryContender(pindexPrev->GetBlockHash(),
                                            pindexPrev->nHeight, blockSubsidy,
                                            outContenderId);
}

TreasuryContenderId TreasuryContenderCache::registerDefaultTreasuryContender(
    const BlockHash &prevblockhash, int blockheight, Amount blockSubsidy,
    TreasuryContenderId *outContenderId) {
    if (prevblockhash.IsNull() || IsDefaultTreasuryExplicitlyDisabled()) {
        if (outContenderId) {
            *outContenderId = TreasuryContenderId();
        }
        return TreasuryContenderId();
    }

    std::vector<std::pair<CScript, uint32_t>> templateEntries;
    if (gArgs.IsArgSet("-avalanchetreasuryaddress")) {
        const auto rawArgs = gArgs.GetArgs("-avalanchetreasuryaddress");
        if (!ParseTreasuryAddressArgs(rawArgs, templateEntries)) {
            if (outContenderId) {
                *outContenderId = TreasuryContenderId();
            }
            return TreasuryContenderId();
        }
    } else if (!defaultTreasuryOutputs.empty()) {
        templateEntries = defaultTreasuryOutputs;
    } else {
        templateEntries = Params().GetConsensus().defaultTreasuryOutputs;
    }

    const Amount treasuryReward = GetTreasuryRewardsAmount(blockSubsidy);
    const std::vector<CTxOut> outputs =
        ComputeProportionalTreasuryOutputs(templateEntries, treasuryReward);
    if (outputs.empty()) {
        if (outContenderId) {
            *outContenderId = TreasuryContenderId();
        }
        return TreasuryContenderId();
    }

    m_defaultTreasuryReward = treasuryReward;
    const TreasuryContenderId cid(prevblockhash, outputs);
    add(prevblockhash, blockheight, outputs,
        TreasuryContenderStatus::TREASURY_ACCEPTED);
    accept(cid);
    if (outContenderId) {
        *outContenderId = cid;
    }
    return cid;
}

bool TreasuryContenderCache::add(const CBlockIndex *pindex,
                                 const std::vector<CTxOut> &outputs,
                                 uint8_t status) {
    if (!pindex) {
        return false;
    }
    return add(pindex->GetBlockHash(), pindex->nHeight, outputs, status);
}

bool TreasuryContenderCache::add(const BlockHash &prevblockhash,
                                 int blockheight,
                                 const std::vector<CTxOut> &outputs,
                                 uint8_t status) {
    if (prevblockhash.IsNull() || !IsValidTreasuryOutputs(outputs)) {
        return false;
    }
    trackBlockInOrder(prevblockhash, MAX_TRACKED_TREASURY_BLOCKS);
    return contenders
        .emplace(prevblockhash, blockheight, outputs, status)
        .second;
}

TreasuryContenderId TreasuryContenderCache::add(
    const BlockHash &prevblockhash, const std::vector<CTxOut> &outputs,
    Amount totalReward) {
    if (prevblockhash.IsNull() ||
        !IsValidTreasuryOutputs(outputs, totalReward)) {
        return TreasuryContenderId();
    }
    TreasuryContenderId cid(prevblockhash, outputs);
    add(prevblockhash, 0, outputs, TreasuryContenderStatus::TREASURY_UNKNOWN);
    return cid;
}

bool TreasuryContenderCache::add(const BlockHash &prevblockhash,
                                 const std::vector<CTxOut> &outputs,
                                 TreasuryContenderId *outContenderId) {
    if (prevblockhash.IsNull() || !IsValidTreasuryOutputs(outputs)) {
        if (outContenderId) {
            *outContenderId = TreasuryContenderId();
        }
        return false;
    }
    TreasuryContenderId cid(prevblockhash, outputs);
    if (outContenderId) {
        *outContenderId = cid;
    }
    return add(prevblockhash, 0, outputs,
               TreasuryContenderStatus::TREASURY_UNKNOWN);
}

bool TreasuryContenderCache::setWinner(const CBlockIndex *pindex,
                                       const std::vector<CTxOut> &outputs) {
    if (!pindex) {
        return false;
    }
    return setWinner(pindex->GetBlockHash(), pindex->nHeight, outputs);
}

bool TreasuryContenderCache::setWinner(const BlockHash &prevblockhash,
                                       int blockheight,
                                       const std::vector<CTxOut> &outputs) {
    if (prevblockhash.IsNull() || !IsValidTreasuryOutputs(outputs)) {
        return false;
    }
    trackBlockInOrder(prevblockhash, MAX_TRACKED_TREASURY_BLOCKS);
    auto &view = manualWinners.get<by_treasury_prevblockhash>();
    auto it = view.find(prevblockhash);
    if (it == view.end()) {
        return manualWinners
            .emplace(prevblockhash, blockheight, outputs)
            .second;
    }
    return manualWinners.replace(
        it, ManualTreasuryWinner(prevblockhash, blockheight, outputs));
}

bool TreasuryContenderCache::accept(const TreasuryContenderId &contenderId) {
    auto &view = contenders.get<by_treasurycontenderid>();
    auto it = view.find(contenderId);
    if (it == view.end()) {
        return false;
    }
    return contenders.modify(it, [](TreasuryContenderEntry &entry) {
        entry.status |= TreasuryContenderStatus::TREASURY_ACCEPTED;
    });
}

bool TreasuryContenderCache::finalize(const TreasuryContenderId &contenderId) {
    auto &view = contenders.get<by_treasurycontenderid>();
    auto it = view.find(contenderId);
    if (it == view.end()) {
        return false;
    }
    return contenders.modify(it, [](TreasuryContenderEntry &entry) {
        entry.status |= TreasuryContenderStatus::TREASURY_ACCEPTED |
                        TreasuryContenderStatus::TREASURY_IN_WINNER_SET;
    });
}

bool TreasuryContenderCache::reject(const TreasuryContenderId &contenderId) {
    auto &view = contenders.get<by_treasurycontenderid>();
    auto it = view.find(contenderId);
    if (it == view.end()) {
        return false;
    }
    return contenders.modify(it, [](TreasuryContenderEntry &entry) {
        entry.status &= ~TreasuryContenderStatus::TREASURY_ACCEPTED;
    });
}

std::optional<TreasuryContenderEntry> TreasuryContenderCache::getContender(
    const TreasuryContenderId &contenderId) const {
    auto &view = contenders.get<by_treasurycontenderid>();
    auto it = view.find(contenderId);
    if (it == view.end()) {
        return std::nullopt;
    }
    return *it;
}

bool TreasuryContenderCache::getOutputs(const TreasuryContenderId &contenderId,
                                        std::vector<CTxOut> &outputs) const {
    auto entry = getContender(contenderId);
    if (!entry) {
        return false;
    }
    outputs = entry->outputs;
    return true;
}

int TreasuryContenderCache::getVoteStatus(
    const TreasuryContenderId &contenderId, BlockHash &prevblockhashout) const {
    auto &view = contenders.get<by_treasurycontenderid>();
    auto it = view.find(contenderId);
    if (it == view.end()) {
        return -1;
    }

    prevblockhashout = it->prevblockhash;
    if (it->isAccepted()) {
        return 0;
    }

    auto &mwView = manualWinners.get<by_treasury_prevblockhash>();
    auto mwIt = mwView.find(it->prevblockhash);
    if (mwIt != manualWinners.end() && mwIt->outputs == it->outputs) {
        return 0;
    }

    return 1;
}

size_t TreasuryContenderCache::getPollableContenders(
    const BlockHash &prevblockhash, size_t maxPollable,
    std::vector<TreasuryContenderId> &pollableContenders) const {
    std::vector<const TreasuryContenderEntry *> ranked;
    auto &view = contenders.get<by_treasury_prevblockhash>();
    auto [begin, end] = view.equal_range(prevblockhash);
    for (auto it = begin; it != end; ++it) {
        ranked.push_back(&(*it));
    }

    std::sort(ranked.begin(), ranked.end(),
              [](const TreasuryContenderEntry *lhs,
                 const TreasuryContenderEntry *rhs) {
                  if (lhs->isAccepted() != rhs->isAccepted()) {
                      return lhs->isAccepted();
                  }
                  return lhs->getTreasuryContenderId() <
                         rhs->getTreasuryContenderId();
              });

    const size_t numPollable = std::min(ranked.size(), maxPollable);
    pollableContenders.clear();
    pollableContenders.reserve(numPollable);
    for (size_t i = 0; i < numPollable; ++i) {
        pollableContenders.push_back(ranked[i]->getTreasuryContenderId());
    }
    return pollableContenders.size();
}

bool TreasuryContenderCache::getWinner(const BlockHash &prevblockhash,
                                       std::vector<CTxOut> &outputs) const {
    outputs.clear();
    if (prevblockhash.IsNull()) {
        return false;
    }

    auto &mwView = manualWinners.get<by_treasury_prevblockhash>();
    auto mwIt = mwView.find(prevblockhash);
    if (mwIt != manualWinners.end() && !mwIt->outputs.empty()) {
        outputs = mwIt->outputs;
        return true;
    }

    std::vector<const TreasuryContenderEntry *> winners;
    auto &view = contenders.get<by_treasury_prevblockhash>();
    auto [begin, end] = view.equal_range(prevblockhash);
    for (auto it = begin; it != end; ++it) {
        if (it->isInWinnerSet() || it->isAccepted()) {
            winners.push_back(&(*it));
        }
    }

    if (!winners.empty()) {
        std::sort(winners.begin(), winners.end(),
                  [](const TreasuryContenderEntry *lhs,
                     const TreasuryContenderEntry *rhs) {
                      if (lhs->isInWinnerSet() != rhs->isInWinnerSet()) {
                          return lhs->isInWinnerSet();
                      }
                      if (lhs->isAccepted() != rhs->isAccepted()) {
                          return lhs->isAccepted();
                      }
                      return lhs->getTreasuryContenderId() <
                             rhs->getTreasuryContenderId();
                  });

        outputs = winners.front()->outputs;
        return !outputs.empty();
    }

    if (IsDefaultTreasuryExplicitlyDisabled()) {
        return false;
    }

    if (!defaultTreasuryOutputs.empty() || IsDefaultTreasuryExplicitlyEnabled()) {
        std::vector<std::pair<CScript, uint32_t>> activeTemplate;
        if (gArgs.IsArgSet("-avalanchetreasuryaddress")) {
            const auto rawArgs = gArgs.GetArgs("-avalanchetreasuryaddress");
            if (!ParseTreasuryAddressArgs(rawArgs, activeTemplate)) {
                return false;
            }
        } else if (!defaultTreasuryOutputs.empty()) {
            activeTemplate = defaultTreasuryOutputs;
        } else {
            activeTemplate = Params().GetConsensus().defaultTreasuryOutputs;
        }

        Amount totalTreasuryReward = m_defaultTreasuryReward;
        if (totalTreasuryReward <= Amount::zero()) {
            if (begin != end && begin->GetTotalValue() > Amount::zero()) {
                totalTreasuryReward = begin->GetTotalValue();
            } else {
                totalTreasuryReward = GetTreasuryRewardsAmount(
                    GetBlockSubsidy(1, Params().GetConsensus()));
            }
        }

        outputs = ComputeProportionalTreasuryOutputs(activeTemplate,
                                                     totalTreasuryReward);
        return !outputs.empty();
    }

    return false;
}

} // namespace avalanche

bool TreasuryPolicy::operator()(BlockPolicyValidationState &state) {
    if (!m_blockIndex.pprev || !m_avalanche.isQuorumEstablished() ||
        !IsTreasuryActivated(m_consensusParams, m_blockIndex.pprev)) {
        return true;
    }

    std::vector<CTxOut> winnerOutputs;
    if (!m_avalanche.getTreasuryRewardWinner(m_blockIndex.pprev->GetBlockHash(),
                                             winnerOutputs) ||
        winnerOutputs.empty()) {
        // No local treasury winner has been finalized for this block yet.
        return true;
    }

    const Amount minTreasuryReward = GetTreasuryRewardsAmount(m_blockSubsidy);
    Amount matchedValue = Amount::zero();
    std::vector<bool> used(m_block.vtx[0]->vout.size(), false);

    for (const CTxOut &expected : winnerOutputs) {
        bool found = false;
        for (size_t i = 0; i < m_block.vtx[0]->vout.size(); ++i) {
            if (used[i]) {
                continue;
            }
            const CTxOut &candidate = m_block.vtx[0]->vout[i];
            if (CoinbaseOutputPaysScript(candidate, expected.scriptPubKey)) {
                if (expected.nValue <= Amount::zero() ||
                    candidate.nValue >= expected.nValue) {
                    used[i] = true;
                    matchedValue += candidate.nValue;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            LogPrintf("Block %s violates treasury reward policy: missing "
                      "treasury output\n",
                      m_blockIndex.GetBlockHash().ToString());
            return state.Invalid(
                BlockPolicyValidationResult::POLICY_VIOLATION,
                "bad-cb-treasury-reward",
                strprintf("Block %s violates treasury reward policy",
                          m_blockIndex.GetBlockHash().ToString()));
        }
    }

    if (matchedValue < minTreasuryReward) {
        LogPrintf("Block %s violates treasury reward policy: insufficient "
                  "treasury payout\n",
                  m_blockIndex.GetBlockHash().ToString());
        return state.Invalid(
            BlockPolicyValidationResult::POLICY_VIOLATION,
            "bad-cb-treasury-reward",
            strprintf("Block %s violates treasury reward policy",
                      m_blockIndex.GetBlockHash().ToString()));
    }

    return true;
}

bool IsTreasuryActivated(const Consensus::Params &params,
                         const CBlockIndex *pprev) {
    if (pprev == nullptr) {
        return false;
    }

    if (gArgs.IsArgSet("-avalanchetreasury")) {
        return gArgs.GetBoolArg("-avalanchetreasury", true);
    }
    if (gArgs.IsArgSet("-avalanchestakingrewards")) {
        return gArgs.GetBoolArg("-avalanchestakingrewards", true);
    }

    return true;
}

Amount GetTreasuryRewardsAmount(const Amount &coinbaseSubsidy) {
    return avalanche::TREASURY_REWARD_RATIO * coinbaseSubsidy / 100;
}
