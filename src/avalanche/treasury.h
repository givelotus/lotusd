// Copyright (c) 2024-2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AVALANCHE_TREASURY_H
#define BITCOIN_AVALANCHE_TREASURY_H

#include <consensus/amount.h>
#include <policy/block/parkingpolicy.h>
#include <primitives/blockhash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/hasher.h>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include <cstdint>
#include <deque>
#include <optional>
#include <vector>

class CBlock;
class CBlockIndex;

namespace Consensus {
struct Params;
} // namespace Consensus

namespace avalanche {

class Processor;

/**
 * Percentage of the block subsidy allocated to the treasury.
 */
static constexpr int TREASURY_REWARD_RATIO = 25;

/**
 * Maximum number of outputs permitted in a single treasury payout proposal.
 */
static constexpr size_t MAX_TREASURY_OUTPUTS = 64;

/**
 * Maximum number of distinct prevblockhash entries tracked in
 * TreasuryContenderCache.
 */
static constexpr size_t MAX_TRACKED_TREASURY_BLOCKS = 128;

/**
 * Default weight assigned to an -avalanchetreasuryaddress=<addr> entry when no
 * explicit :weight suffix is provided.
 */
static constexpr uint32_t DEFAULT_TREASURY_OUTPUT_WEIGHT = 100;

/**
 * Validate treasury proposal outputs and optional expected total reward.
 */
bool IsValidTreasuryOutputs(
    const std::vector<CTxOut> &outputs,
    std::optional<Amount> expectedTotalReward = std::nullopt);

/**
 * Deterministically split totalTreasuryReward across 1..64 weighted
 * (scriptPubKey, weight) entries, placing any integer division remainder of
 * 1..63 satoshis onto the first output so the sum is 100% equal to
 * totalTreasuryReward.
 */
std::vector<CTxOut> ComputeProportionalTreasuryOutputs(
    const std::vector<std::pair<CScript, uint32_t>> &templateEntries,
    Amount totalTreasuryReward);

/**
 * Parse a single `<addr[:weight]>` or `<hex_script[:weight]>` entry.
 */
bool ParseTreasuryAddressEntry(const std::string &entry, CScript &scriptOut,
                               uint32_t &weightOut);

/**
 * Parse repeatable or comma-separated `-avalanchetreasuryaddress` values into a
 * weighted treasury template.
 */
bool ParseTreasuryAddressArgs(
    const std::vector<std::string> &rawArgs,
    std::vector<std::pair<CScript, uint32_t>> &templateOut);

/**
 * Resolve the active treasury payout template: `-avalanchetreasuryaddress` CLI
 * / config override if set, otherwise `params.defaultTreasuryOutputs`.
 */
std::vector<std::pair<CScript, uint32_t>>
GetDefaultTreasuryTemplate(const Consensus::Params &params);

/**
 * TreasuryContenderId identifies a treasury payout proposal for the block
 * extending prev_finalized_block_hash.
 * Computed via BLAKE3_keyed("lotus.v2.ava.treasury_contender",
 *                           prev_finalized_block_hash || CompactSize(outputs.size()) || serialized_outputs).
 */
struct TreasuryContenderId : public uint256 {
    constexpr TreasuryContenderId() : uint256() {}
    constexpr explicit TreasuryContenderId(const uint256 &b) : uint256(b) {}
    TreasuryContenderId(const BlockHash &prevblockhash,
                        const std::vector<CTxOut> &outputs)
        : uint256(ComputeId(prevblockhash, outputs)) {}

    explicit constexpr operator bool() const { return !IsNull(); }

    static TreasuryContenderId ComputeId(const BlockHash &prevblockhash,
                                         const std::vector<CTxOut> &outputs);

    static TreasuryContenderId fromHex(const std::string &str) {
        return TreasuryContenderId(uint256S(str));
    }
};

enum TreasuryContenderStatus : uint8_t {
    TREASURY_UNKNOWN = 0,
    TREASURY_ACCEPTED = (1 << 0),
    TREASURY_IN_WINNER_SET = (1 << 1),
};

struct TreasuryContenderEntry {
    BlockHash prevblockhash{};
    int blockheight{0};
    std::vector<CTxOut> outputs;
    TreasuryContenderId contenderId{};
    uint8_t status{TreasuryContenderStatus::TREASURY_UNKNOWN};

    TreasuryContenderEntry() = default;
    TreasuryContenderEntry(const BlockHash &_prevblockhash, int _blockheight,
                           const std::vector<CTxOut> &_outputs,
                           uint8_t _status = TreasuryContenderStatus::TREASURY_UNKNOWN)
        : prevblockhash(_prevblockhash), blockheight(_blockheight),
          outputs(_outputs),
          contenderId(TreasuryContenderId(_prevblockhash, _outputs)),
          status(_status) {}

    SERIALIZE_METHODS(TreasuryContenderEntry, obj) {
        READWRITE(obj.prevblockhash, obj.outputs);
        SER_READ(obj, obj.contenderId = TreasuryContenderId(obj.prevblockhash,
                                                            obj.outputs));
    }

    const TreasuryContenderId &getTreasuryContenderId() const {
        return contenderId;
    }
    bool isAccepted() const {
        return status & TreasuryContenderStatus::TREASURY_ACCEPTED;
    }
    bool isInWinnerSet() const {
        return status & TreasuryContenderStatus::TREASURY_IN_WINNER_SET;
    }
    Amount GetTotalValue() const {
        Amount total = Amount::zero();
        for (const auto &out : outputs) {
            total += out.nValue;
        }
        return total;
    }
};

struct ManualTreasuryWinner {
    BlockHash prevblockhash;
    int blockheight;
    std::vector<CTxOut> outputs;

    ManualTreasuryWinner(const BlockHash &_prevblockhash, int _blockheight,
                         const std::vector<CTxOut> &_outputs)
        : prevblockhash(_prevblockhash), blockheight(_blockheight),
          outputs(_outputs) {}
};

struct treasurycontenderid_index {
    using result_type = TreasuryContenderId;
    result_type operator()(const TreasuryContenderEntry &entry) const {
        return entry.getTreasuryContenderId();
    }
};

struct by_treasurycontenderid;
struct by_treasury_prevblockhash;
struct by_treasury_blockheight;

namespace bmi = boost::multi_index;

class TreasuryContenderCache {
    using ContenderSet = bmi::multi_index_container<
        TreasuryContenderEntry,
        bmi::indexed_by<
            bmi::hashed_unique<bmi::tag<by_treasurycontenderid>,
                               treasurycontenderid_index, SaltedUint256Hasher>,
            bmi::hashed_non_unique<
                bmi::tag<by_treasury_prevblockhash>,
                bmi::member<TreasuryContenderEntry, BlockHash,
                            &TreasuryContenderEntry::prevblockhash>,
                SaltedUint256Hasher>,
            bmi::ordered_non_unique<
                bmi::tag<by_treasury_blockheight>,
                bmi::member<TreasuryContenderEntry, int,
                            &TreasuryContenderEntry::blockheight>>>>;

    ContenderSet contenders;

    using ManualWinnersSet = bmi::multi_index_container<
        ManualTreasuryWinner,
        bmi::indexed_by<
            bmi::hashed_unique<bmi::tag<by_treasury_prevblockhash>,
                               bmi::member<ManualTreasuryWinner, BlockHash,
                                           &ManualTreasuryWinner::prevblockhash>,
                               SaltedUint256Hasher>,
            bmi::ordered_unique<
                bmi::tag<by_treasury_blockheight>,
                bmi::member<ManualTreasuryWinner, int,
                            &ManualTreasuryWinner::blockheight>>>>;

    ManualWinnersSet manualWinners;
    std::deque<BlockHash> m_blockOrder;
    std::vector<std::pair<CScript, uint32_t>> defaultTreasuryOutputs;
    Amount m_defaultTreasuryReward{Amount::zero()};

    void trackBlockInOrder(const BlockHash &prevblockhash,
                           size_t maxTrackedBlocks = MAX_TRACKED_TREASURY_BLOCKS);
    void eraseTrackedBlock(const BlockHash &blockhash);

public:
    TreasuryContenderCache() = default;

    void setDefaultTreasuryOutputs(
        const std::vector<std::pair<CScript, uint32_t>> &entries,
        Amount defaultReward = Amount::zero()) {
        defaultTreasuryOutputs = entries;
        if (defaultReward > Amount::zero()) {
            m_defaultTreasuryReward = defaultReward;
        }
    }

    const std::vector<std::pair<CScript, uint32_t>> &
    getDefaultTreasuryOutputs() const {
        return defaultTreasuryOutputs;
    }

    TreasuryContenderId registerDefaultTreasuryContender(
        const CBlockIndex *pindexPrev, Amount blockSubsidy,
        TreasuryContenderId *outContenderId = nullptr);

    TreasuryContenderId registerDefaultTreasuryContender(
        const BlockHash &prevblockhash, int blockheight, Amount blockSubsidy,
        TreasuryContenderId *outContenderId = nullptr);

    TreasuryContenderId registerDefaultTreasuryContender(
        const BlockHash &prevblockhash, Amount blockSubsidy,
        TreasuryContenderId *outContenderId = nullptr) {
        return registerDefaultTreasuryContender(prevblockhash, 0, blockSubsidy,
                                                outContenderId);
    }

    void cleanup(const int requestedMinHeight);
    void cleanup(const BlockHash &keepBlockHash);
    void cleanupBounded(size_t maxTrackedBlocks = MAX_TRACKED_TREASURY_BLOCKS);

    size_t getTrackedBlockCount() const { return m_blockOrder.size(); }

    bool isEmpty() const {
        return (contenders.size() + manualWinners.size()) == 0;
    }

    bool add(const CBlockIndex *pindex, const std::vector<CTxOut> &outputs,
             uint8_t status = TreasuryContenderStatus::TREASURY_UNKNOWN);

    bool add(const BlockHash &prevblockhash, int blockheight,
             const std::vector<CTxOut> &outputs,
             uint8_t status = TreasuryContenderStatus::TREASURY_UNKNOWN);

    TreasuryContenderId add(const BlockHash &prevblockhash,
                            const std::vector<CTxOut> &outputs,
                            Amount totalReward);

    bool add(const BlockHash &prevblockhash,
             const std::vector<CTxOut> &outputs,
             TreasuryContenderId *outContenderId = nullptr);

    bool setLocalWinner(const TreasuryContenderId &contenderId) {
        return accept(contenderId);
    }

    bool setWinner(const CBlockIndex *pindex,
                   const std::vector<CTxOut> &outputs);
    bool setWinner(const BlockHash &prevblockhash, int blockheight,
                   const std::vector<CTxOut> &outputs);

    bool accept(const TreasuryContenderId &contenderId);
    bool finalize(const TreasuryContenderId &contenderId);
    bool reject(const TreasuryContenderId &contenderId);

    std::optional<TreasuryContenderEntry>
    getContender(const TreasuryContenderId &contenderId) const;

    bool getOutputs(const TreasuryContenderId &contenderId,
                    std::vector<CTxOut> &outputs) const;

    /**
     * Get contender acceptance state for avalanche voting.
     * Returns 0 for accepted, 1 for rejected, and -1 for not in cache.
     */
    int getVoteStatus(const TreasuryContenderId &contenderId,
                      BlockHash &prevblockhashout) const;
    int getVoteStatus(const TreasuryContenderId &contenderId) const {
        BlockHash dummy;
        return getVoteStatus(contenderId, dummy);
    }

    size_t getPollableContenders(
        const BlockHash &prevblockhash, size_t maxPollable,
        std::vector<TreasuryContenderId> &pollableContenders) const;

    bool getWinner(const BlockHash &prevblockhash,
                   std::vector<CTxOut> &outputs) const;
};

} // namespace avalanche

class TreasuryPolicy : public ParkingPolicy {
private:
    const avalanche::Processor &m_avalanche;
    const CBlock &m_block;
    const Amount m_blockSubsidy;
    const CBlockIndex &m_blockIndex;
    const Consensus::Params &m_consensusParams;

public:
    TreasuryPolicy(const avalanche::Processor &avalanche,
                   const Consensus::Params &consensusParams,
                   BlockPolicyValidationState &,
                   const CBlockIndex *pindexNew, const CBlock &block,
                   const Amount &blockSubsidy)
        : m_avalanche(avalanche), m_block(block), m_blockSubsidy(blockSubsidy),
          m_blockIndex(*pindexNew), m_consensusParams(consensusParams) {}

    TreasuryPolicy(const avalanche::Processor &avalanche,
                   const CBlockIndex &blockIndex, const CBlock &block,
                   const Consensus::Params &consensusParams,
                   const Amount &blockSubsidy)
        : m_avalanche(avalanche), m_block(block), m_blockSubsidy(blockSubsidy),
          m_blockIndex(blockIndex), m_consensusParams(consensusParams) {}

    TreasuryPolicy(const avalanche::Processor &avalanche,
                   const Consensus::Params &consensusParams,
                   const CBlockIndex &blockIndex, const CBlock &block,
                   const Amount &blockSubsidy)
        : m_avalanche(avalanche), m_block(block), m_blockSubsidy(blockSubsidy),
          m_blockIndex(blockIndex), m_consensusParams(consensusParams) {}

    virtual ~TreasuryPolicy() = default;

    bool operator()(BlockPolicyValidationState &state) override;
};

bool IsTreasuryActivated(const Consensus::Params &params,
                         const CBlockIndex *pprev);

Amount GetTreasuryRewardsAmount(const Amount &coinbaseSubsidy);

#endif // BITCOIN_AVALANCHE_TREASURY_H
