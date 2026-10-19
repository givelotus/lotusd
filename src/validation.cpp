// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <kernel/chain.h>
#include <kernel/chainparams.h>
#include <kernel/coinstats.h>
#include <kernel/disconnected_transactions.h>
#include <kernel/mempool_entry.h>

#include <arith_uint256.h>
#include <avalanche/avalanche.h>
#include <avalanche/processor.h>
#include <blockvalidity.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <checkqueue.h>
#include <common/args.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <hash.h>
#include <kernel/notifications_interface.h>
#include <logging.h>
#include <logging/timer.h>
#include <logging/values.h>
#include <minerfund.h>
#include <node/blockstorage.h>
#include <node/metrics.h>
#include <node/snapshot.h>
#include <node/utxo_snapshot.h>
#include <policy/block/minerfund.h>
#include <policy/block/parkingpolicy.h>
#include <policy/block/preconsensus.h>
#include <policy/block/rtt.h>
#include <policy/block/stakingrewards.h>
#include <policy/block/treasury.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <lotus_v2/fast_sync.h>
#include <lotus_v2/fee_hysteresis.h>
#include <lotus_v2/tagged_hash.h>
#include <lotus_v2/vm.h>
#include <random.h>
#include <reverse_iterator.h>
#include <rpc/async_waiter.h>
#include <script/script.h>
#include <script/scriptcache.h>
#include <script/sigcache.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/moneystr.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <deque>
#include <numeric>
#include <optional>
#include <string>
#include <thread>
#include <tuple>

using kernel::CCoinsStats;
using kernel::CoinStatsHashType;
using kernel::ComputeUTXOStats;
using kernel::Notifications;

using fsbridge::FopenFn;
using node::BlockManager;
using node::BlockMap;
using node::SnapshotMetadata;

/**
 * Time window to wait between writing blocks/block index and chainstate to
 * disk.
 * Randomize writing time inside the window to prevent a situation where the
 * network over time settles into a few cohorts of synchronized writers.
 */
static constexpr auto DATABASE_WRITE_INTERVAL_MIN{50min};
static constexpr auto DATABASE_WRITE_INTERVAL_MAX{70min};
const std::vector<std::string> CHECKLEVEL_DOC{
    "level 0 reads the blocks from disk",
    "level 1 verifies block validity",
    "level 2 verifies undo data",
    "level 3 checks disconnection of tip blocks",
    "level 4 tries to reconnect the blocks",
    "each level includes the checks of the previous levels",
};
/**
 * The number of blocks to keep below the deepest prune lock.
 * There is nothing special about this number. It is higher than what we
 * expect to see in regular mainnet reorgs, but not so high that it would
 * noticeably interfere with the pruning mechanism.
 * */
static constexpr int PRUNE_LOCK_BUFFER{10};

static constexpr uint64_t HEADERS_TIME_VERSION{1};

GlobalMutex g_best_block_mutex;
std::condition_variable g_best_block_cv;
const CBlockIndex *g_best_block;

BlockValidationOptions::BlockValidationOptions(const Config &config)
    : excessiveBlockSize(config.GetMaxBlockSize()), checkPoW(true),
      checkMerkleRoot(true) {}

const CBlockIndex *
Chainstate::FindForkInGlobalIndex(const CBlockLocator &locator) const {
    AssertLockHeld(cs_main);

    // Find the latest block common to locator and chain - we expect that
    // locator.vHave is sorted descending by height.
    for (const BlockHash &hash : locator.vHave) {
        const CBlockIndex *pindex{m_blockman.LookupBlockIndex(hash)};
        if (pindex) {
            if (m_chain.Contains(pindex)) {
                return pindex;
            }
            if (pindex->GetAncestor(m_chain.Height()) == m_chain.Tip()) {
                return m_chain.Tip();
            }
        }
    }
    return m_chain.Genesis();
}

static uint32_t GetNextBlockScriptFlags(const CBlockIndex *pindex,
                                        const ChainstateManager &chainman);

namespace {
/**
 * A helper which calculates heights of inputs of a given transaction.
 *
 * @param[in] tip    The current chain tip. If an input belongs to a mempool
 *                   transaction, we assume it will be confirmed in the next
 *                   block.
 * @param[in] coins  Any CCoinsView that provides access to the relevant coins.
 * @param[in] tx     The transaction being evaluated.
 *
 * @returns A vector of input heights or nullopt, in case of an error.
 */
std::optional<std::vector<int>> CalculatePrevHeights(const CBlockIndex &tip,
                                                     const CCoinsView &coins,
                                                     const CTransaction &tx) {
    std::vector<int> prev_heights;
    prev_heights.resize(tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (tx.vin[i].nFlags == 3) {
            prev_heights[i] = 0;
            continue;
        }
        if (auto coin{coins.GetCoin(tx.vin[i].prevout)}) {
            // Assume all mempool transaction confirm in the next block.
            prev_heights[i] = coin->GetHeight() == MEMPOOL_HEIGHT
                                  ? tip.nHeight + 1
                                  : coin->GetHeight();
        } else {
            LogInfoEvent(
                BCLog::ALL, "transaction_input_missing",
                "ERROR: {source_function}: Missing input {input_index} in transaction '{tx_hash}'")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::InputIndex, i)
                .Field(BCLog::LogField::TxHash, tx.GetHash());
            return std::nullopt;
        }
    }
    return prev_heights;
}
} // namespace

std::optional<LockPoints> CalculateLockPointsAtTip(CBlockIndex *tip,
                                                   const CCoinsView &coins_view,
                                                   const CTransaction &tx) {
    assert(tip);
    auto prev_heights{CalculatePrevHeights(*tip, coins_view, tx)};
    if (!prev_heights.has_value()) {
        return std::nullopt;
    }

    CBlockIndex next_tip;
    next_tip.pprev = tip;
    // When SequenceLocks() is called within ConnectBlock(), the height
    // of the block *being* evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than
    // active_chainstate.m_chain.Height()
    next_tip.nHeight = tip->nHeight + 1;
    const auto [min_height, min_time] = CalculateSequenceLocks(
        tx, STANDARD_LOCKTIME_VERIFY_FLAGS, prev_heights.value(), next_tip);

    return LockPoints{min_height, min_time};
}

bool CheckSequenceLocksAtTip(CBlockIndex *tip, const LockPoints &lock_points) {
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocksAtTip() uses active_chainstate.m_chain.Height()+1 to
    // evaluate height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being* evaluated is what is
    // used. Thus if we want to know if a transaction can be part of the *next*
    // block, we need to use one more than active_chainstate.m_chain.Height()
    index.nHeight = tip->nHeight + 1;

    return EvaluateSequenceLocks(index, {lock_points.height, lock_points.time});
}

// Command-line argument "-replayprotectionactivationtime=<timestamp>" will
// cause the node to switch to replay protected SigHash ForkID value when the
// median timestamp of the previous 11 blocks is greater than or equal to
// <timestamp>. Defaults to the pre-defined timestamp when not set.
static bool
IsReplayProtectionEnabled(const Consensus::Params &params,
                          const CBlockIndex *pindexPrev,
                          const std::optional<int64_t> activation_time) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return pindexPrev->GetMedianTimePast() >=
           activation_time.value_or(0xffffffff);
}

namespace {
bool CheckInputScriptsReusing(
    const CTransaction &tx, TxValidationState &state,
    const CCoinsViewCache &inputs, const uint32_t flags, bool sigCacheStore,
    bool scriptCacheStore, const PrecomputedAdmissionChecks *precomputed,
    const ScriptCheckOutcome *outcome, ValidationCache &validation_cache,
    int &nSigChecksOut) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
} // namespace

/**
 * Checks to avoid mempool polluting consensus critical paths since cached
 * signature and script validity results will be reused if we validate this
 * transaction again during block validation.
 */
static bool CheckInputsFromMempoolAndCache(
    const CTransaction &tx, TxValidationState &state,
    const CCoinsViewCache &view, const CTxMemPool &pool, const uint32_t flags,
    const PrecomputedTransactionData &txdata, ValidationCache &validation_cache,
    int &nSigChecksOut, CCoinsViewCache &coins_tip,
    const PrecomputedAdmissionChecks *precomputed)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs) {
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn &txin : tx.vin) {
        if (txin.nFlags == 3) {
            continue;
        }
        const Coin &coin = view.AccessCoin(txin.prevout);

        // This coin was checked in PreChecks and MemPoolAccept
        // has been holding cs_main since then.
        Assume(!coin.IsSpent());
        if (coin.IsSpent()) {
            return false;
        }

        // If the Coin is available, there are 2 possibilities:
        // it is available in our current ChainstateActive UTXO set,
        // or it's a UTXO provided by a transaction in our mempool.
        // Ensure the scriptPubKeys in Coins from CoinsView are correct.
        const CTransactionRef &txFrom = pool.get(txin.prevout.GetTxId());
        if (txFrom) {
            assert(txFrom->GetId() == txin.prevout.GetTxId());
            assert(txFrom->vout.size() > txin.prevout.GetN());
            assert(txFrom->vout[txin.prevout.GetN()] == coin.GetTxOut());
        } else {
            const Coin &coinFromUTXOSet = coins_tip.AccessCoin(txin.prevout);
            assert(!coinFromUTXOSet.IsSpent());
            assert(coinFromUTXOSet.GetTxOut() == coin.GetTxOut());
        }
    }

    // Call CheckInputScripts() to cache signature and script validity against
    // current tip consensus rules.
    if (precomputed != nullptr) {
        return CheckInputScriptsReusing(
            tx, state, view, flags, /*sigCacheStore=*/true,
            /*scriptCacheStore=*/true, precomputed, &precomputed->consensus,
            validation_cache, nSigChecksOut);
    }
    return CheckInputScripts(tx, state, view, flags, /*sigCacheStore=*/true,
                             /*scriptCacheStore=*/true, txdata,
                             validation_cache, nSigChecksOut);
}

namespace {

struct ParallelTxScriptError {
    TxValidationResult result{TxValidationResult::TX_CONSENSUS};
    ScriptError script_err{ScriptError::UNKNOWN};
    std::string reject_reason;
    std::string debug_message;
};

/**
 * Run every input script of tx against the outputs it spends, reporting a
 * failure exactly as CheckInputScripts does (including the mandatory-flags
 * recheck that distinguishes TX_NOT_STANDARD from TX_CONSENSUS). Takes no
 * locks. spent_output(i) returns the output spent by input i.
 */
template <typename SpentOutput>
std::optional<ParallelTxScriptError>
VerifyTxScriptsAgainst(const CTransaction &tx, SpentOutput &&spent_output,
                       const uint32_t flags, bool sigCacheStore,
                       const PrecomputedTransactionData &txdata,
                       SignatureCache &signature_cache, int &nSigChecksOut,
                       TxSigCheckLimiter &txLimitSigChecks,
                       CheckInputsLimiter *pBlockLimitSigChecks,
                       lotus::v2::BatchSigCollector *sig_collector) {
    assert(!tx.IsCoinBase());

    int nSigChecksTotal = 0;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        const CTxOut &prev_txout = spent_output(i);

        CScriptCheck check(prev_txout, tx, signature_cache, i, flags,
                           sigCacheStore, txdata, &txLimitSigChecks,
                           pBlockLimitSigChecks, /*resolvedCoins=*/nullptr,
                           sig_collector);
        if (auto result = check(); result.has_value()) {
            uint32_t mandatoryFlags =
                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS;
            if (flags != mandatoryFlags) {
                CScriptCheck check2(prev_txout, tx, signature_cache, i,
                                    mandatoryFlags, sigCacheStore, txdata,
                                    nullptr, nullptr, nullptr);
                auto mandatory_result = check2();
                if (!mandatory_result.has_value()) {
                    return ParallelTxScriptError{
                        TxValidationResult::TX_NOT_STANDARD, result->first,
                        strprintf("non-mandatory-script-verify-flag (%s)",
                                  ScriptErrorString(result->first)),
                        result->second};
                }
                result = mandatory_result;
            }
            return ParallelTxScriptError{
                TxValidationResult::TX_CONSENSUS, result->first,
                strprintf("mandatory-script-verify-flag-failed (%s)",
                          ScriptErrorString(result->first)),
                result->second};
        }
        nSigChecksTotal += check.GetScriptExecutionMetrics().nSigChecks;
    }
    nSigChecksOut = nSigChecksTotal;
    return std::nullopt;
}

// Per-transaction V2 post-check over the effects recorded by every input's
// invocations: claims fit their outputs and every HAS_STATE output was
// authorized. Returns the reject reason on failure.
std::optional<std::string>
FinalizeV2TransactionEffects(const CTransaction &tx,
                             const lotus::v2::VmTransactionEffects &effects) {
    if (tx.nVersion != 7) return std::nullopt;
    std::vector<lotus::v2::Output> outputs;
    outputs.reserve(tx.vout.size());
    for (const CTxOut &out : tx.vout) outputs.push_back(out.ToV2Output());
    std::string error;
    if (!lotus::v2::FinalizeVmTransactionEffects(outputs, effects, error))
        return error;
    return std::nullopt;
}

std::optional<ParallelTxScriptError> VerifyTxScriptsFromResolvedCoins(
    const CTransaction &tx, const std::vector<Coin> &resolved_inputs,
    const uint32_t flags, bool sigCacheStore,
    const PrecomputedTransactionData &txdata, SignatureCache &signature_cache,
    int &nSigChecksOut, TxSigCheckLimiter &txLimitSigChecks,
    CheckInputsLimiter *pBlockLimitSigChecks,
    lotus::v2::BatchSigCollector *sig_collector,
    bool consensus_only = false) {
    assert(!tx.IsCoinBase());
    assert(resolved_inputs.size() == tx.vin.size());

    lotus::v2::VmTransactionEffects v2_effects;
    auto finalize = [&]() -> std::optional<ParallelTxScriptError> {
        if (auto reason = FinalizeV2TransactionEffects(tx, v2_effects)) {
            ParallelTxScriptError err;
            err.reject_reason = *reason;
            err.debug_message = "V2 transaction effects post-check";
            return err;
        }
        return std::nullopt;
    };

    if (tx.nVersion == 7 && !tx.vin.empty() && tx.vin.size() <= 16) {
        static const lotus::v2::Hash kOpTrueBranchLeaf =
            lotus::v2::BranchLeaf(std::array<uint8_t, 1>{0x4e});
        bool fast_ok = true;
        bool has_schnorr = false;
        std::array<lotus::v2::Hash, 16> leaf_hashes{};
        std::array<lotus::v2::Hash, 16> coin_leaves{};
        std::array<bool, 16> is_schnorr_in{};
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const CTxIn &in = tx.vin[i];
            if (in.nFlags != 1 || in.nPathIndex != 0 ||
                in.vWitnesses.size() != 1 ||
                !in.vWitnesses[0].siblings.empty() ||
                resolved_inputs[i].IsSpent()) {
                fast_ok = false;
                break;
            }
            const CTxOut &prev_out = resolved_inputs[i].GetTxOut();
            if ((prev_out.nFlags & 0x02U) != 0 ||
                prev_out.scriptPubKey.size() != 45 ||
                prev_out.scriptPubKey[0] != 0x00 ||
                prev_out.scriptPubKey[9] != 0x01 ||
                prev_out.scriptPubKey[42] != 0x01 ||
                prev_out.scriptPubKey[43] != 0x01 ||
                prev_out.scriptPubKey[44] != 0x00) {
                fast_ok = false;
                break;
            }
            const uint8_t *expected_branch = prev_out.scriptPubKey.data() + 10;
            const auto &w = in.vWitnesses[0];
            if (w.script.size() == 1 && w.script[0] == 0x4e &&
                w.arguments.empty()) {
                if (std::memcmp(expected_branch, kOpTrueBranchLeaf.data(),
                                32) != 0) {
                    fast_ok = false;
                    break;
                }
                leaf_hashes[i] = kOpTrueBranchLeaf;
                is_schnorr_in[i] = false;
            } else if (w.script.size() == 34 && w.script[0] == 0x20 &&
                       w.script[33] == 0xbb && w.arguments.size() == 1 &&
                       (w.arguments[0].size() == 64 ||
                        (w.arguments[0].size() == 65 &&
                         w.arguments[0][64] == 0))) {
                leaf_hashes[i] = lotus::v2::BranchLeaf(w.script);
                if (std::memcmp(expected_branch, leaf_hashes[i].data(), 32) !=
                    0) {
                    fast_ok = false;
                    break;
                }
                has_schnorr = true;
                is_schnorr_in[i] = true;
            } else {
                fast_ok = false;
                break;
            }
        }
        if (fast_ok) {
            // Fast-path scripts record no effects, but the post-check still
            // applies (a HAS_STATE output is then unauthorized).
            if (auto err = finalize()) return err;
            if (!has_schnorr) {
                nSigChecksOut = 0;
                return std::nullopt;
            }
            for (size_t i = 0; i < tx.vin.size(); ++i) {
                const CTxOut &prev_out = resolved_inputs[i].GetTxOut();
                coin_leaves[i] = lotus::v2::CoinEntryLeaf(
                    std::span<const uint8_t>(prev_out.scriptPubKey.data(), 45));
            }
            const lotus::v2::Hash coins_root = lotus::v2::IndexedTreeRoot(
                std::span<const lotus::v2::Hash>(coin_leaves.data(),
                                                 tx.vin.size()));
            std::array<uint8_t, 138> preimage{};
            const auto &chain_id = GetActiveV2ChainId();
            std::memcpy(preimage.data(), chain_id.data(), 32);
            preimage[32] = 0; // mode == 0
            std::memcpy(preimage.data() + 33, tx.GetId().begin(), 32);
            std::memcpy(preimage.data() + 65, coins_root.data(), 32);
            preimage[97] = 1; // invocation.kind == 1
            // preimage[102..105] = 0 (branch_index == 0)
            lotus::v2::BatchSigCollector staged_sigs;
            bool sigs_ok = true;
            for (size_t i = 0; i < tx.vin.size(); ++i) {
                if (!is_schnorr_in[i]) {
                    continue;
                }
                for (size_t b = 0; b < 4; ++b) {
                    preimage[98 + b] = static_cast<uint8_t>(i >> (8 * b));
                }
                std::memcpy(preimage.data() + 106, leaf_hashes[i].data(), 32);
                const lotus::v2::Hash msg = lotus::v2::TaggedHash(
                    lotus::v2::HashDomain::Sighash, preimage);
                const auto &w = tx.vin[i].vWitnesses[0];
                const std::span<const uint8_t> pubkey(w.script.data() + 1, 32);
                const std::span<const uint8_t> sig64(w.arguments[0].data(), 64);
                if (sig_collector != nullptr) {
                    lotus::v2::BatchSigCollector *target =
                        (tx.vin.size() == 1) ? sig_collector : &staged_sigs;
                    if (!target->Add(pubkey, sig64, msg)) {
                        sigs_ok = false;
                        break;
                    }
                } else {
                    if (lotus::v2::VerifyBip340Signature(
                            pubkey, sig64, msg, false) !=
                        lotus::v2::SignatureStatus::Valid) {
                        sigs_ok = false;
                        break;
                    }
                }
            }
            if (sigs_ok) {
                if (sig_collector != nullptr && tx.vin.size() > 1) {
                    sig_collector->Merge(std::move(staged_sigs));
                }
                nSigChecksOut = 0;
                return std::nullopt;
            }
        }
    }

    const bool has_v2_input = std::any_of(
        tx.vin.begin(), tx.vin.end(),
        [](const CTxIn &in) { return in.nFlags == 1 || in.nFlags == 3; });
    std::shared_ptr<CScriptCheck::V2ResolvedCoins> v2_resolved_coins;
    if (has_v2_input) {
        v2_resolved_coins =
            std::make_shared<CScriptCheck::V2ResolvedCoins>(tx.vin.size());
        for (size_t j = 0; j < tx.vin.size(); ++j) {
            if (tx.vin[j].nFlags == 3) {
                (*v2_resolved_coins)[j] = std::nullopt;
                continue;
            }
            assert(!resolved_inputs[j].IsSpent());
            (*v2_resolved_coins)[j] =
                resolved_inputs[j].GetTxOut().ToV2Output();
        }
    }

    static const CTxOut kEmptyTxOut{};
    int nSigChecksTotal = 0;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        if (tx.vin[i].nFlags != 3) {
            assert(!resolved_inputs[i].IsSpent());
        }
        const CTxOut &prev_txout =
            (tx.vin[i].nFlags == 3 ||
             (v2_resolved_coins && tx.vin[i].nFlags == 1))
                ? kEmptyTxOut
                : resolved_inputs[i].GetTxOut();

        CScriptCheck check(prev_txout, tx, signature_cache, i, flags,
                           sigCacheStore, txdata, &txLimitSigChecks,
                           pBlockLimitSigChecks, v2_resolved_coins,
                           sig_collector);
        check.SetV2Effects(&v2_effects);
        if (auto result = check(); result.has_value()) {
            uint32_t mandatoryFlags =
                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS;
            // Block flags are consensus requirements. The policy fallback is
            // only meaningful for mempool checks that add standardness flags.
            if (!consensus_only && flags != mandatoryFlags) {
                CScriptCheck check2(prev_txout, tx, signature_cache, i,
                                    mandatoryFlags, sigCacheStore, txdata,
                                    nullptr, nullptr, v2_resolved_coins,
                                    nullptr);
                auto mandatory_result = check2();
                if (!mandatory_result.has_value()) {
                    return ParallelTxScriptError{
                        TxValidationResult::TX_NOT_STANDARD, result->first,
                        strprintf("non-mandatory-script-verify-flag (%s)",
                                  ScriptErrorString(result->first)),
                        result->second};
                }
                result = mandatory_result;
            }
            return ParallelTxScriptError{
                TxValidationResult::TX_CONSENSUS, result->first,
                strprintf("mandatory-script-verify-flag-failed (%s)",
                          ScriptErrorString(result->first)),
                result->second};
        }
        nSigChecksTotal += check.GetScriptExecutionMetrics().nSigChecks;
    }
    if (auto err = finalize()) return err;
    nSigChecksOut = nSigChecksTotal;
    return std::nullopt;
}

/** Whether every input of tx spends, in view, exactly the given outputs. */
bool SpentOutputsMatch(const CTransaction &tx, const CCoinsViewCache &view,
                       const std::vector<CTxOut> &spent_outputs) {
    if (tx.nVersion == 7 || spent_outputs.size() != tx.vin.size()) {
        return false;
    }
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const Coin &coin = view.AccessCoin(tx.vin[i].prevout);
        if (coin.IsSpent() || !(coin.GetTxOut() == spent_outputs[i])) {
            return false;
        }
    }
    return true;
}

/**
 * CheckInputScripts, but when `outcome` was computed for these flags and for
 * exactly the outputs `inputs` provides, reuse it instead of executing the
 * scripts again. The script execution cache is consulted and updated exactly
 * as CheckInputScripts would, so the verdict, sigcheck count and cache state
 * are the same either way.
 */
bool CheckInputScriptsReusing(
    const CTransaction &tx, TxValidationState &state,
    const CCoinsViewCache &inputs, const uint32_t flags, bool sigCacheStore,
    bool scriptCacheStore, const PrecomputedAdmissionChecks *precomputed,
    const ScriptCheckOutcome *outcome, ValidationCache &validation_cache,
    int &nSigChecksOut) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);
    if (tx.nVersion == 7 || precomputed == nullptr || outcome == nullptr || !outcome->ran ||
        outcome->flags != flags ||
        !SpentOutputsMatch(tx, inputs, precomputed->spent_outputs)) {
        return CheckInputScripts(tx, state, inputs, flags, sigCacheStore,
                                 scriptCacheStore, tx.GetPrecomputedData(),
                                 validation_cache, nSigChecksOut);
    }
    ScriptCacheKey hashCacheEntry(
        tx, flags, validation_cache.ScriptExecutionCacheHasher());
    ScriptCacheElement elem(hashCacheEntry, 0);
    const bool found_in_cache = validation_cache.m_script_execution_cache.get(
        elem, /*erase=*/!scriptCacheStore);
    nSigChecksOut = elem.nSigChecks;
    if (found_in_cache) {
        TxSigCheckLimiter txLimitSigChecks;
        if (!txLimitSigChecks.consume_and_check(nSigChecksOut)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "too-many-sigchecks");
        }
        return true;
    }
    if (outcome->error_result.has_value()) {
        return state.Invalid(*outcome->error_result, outcome->error_reason,
                             outcome->error_debug);
    }
    nSigChecksOut = outcome->sigchecks;
    if (scriptCacheStore) {
        validation_cache.m_script_execution_cache.insert(
            ScriptCacheElement{hashCacheEntry, outcome->sigchecks});
    }
    return true;
}



struct BatchTxIdIndexSlot {
    TxId txid;
    size_t index{0};
    bool occupied{false};
};

std::optional<LockPoints> CalculateLockPointsFromResolvedCoins(
    CBlockIndex *tip, const CTransaction &tx,
    const std::vector<Coin> &resolved_inputs) {
    assert(tip);
    std::vector<int> prev_heights(tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (tx.vin[i].nFlags == 3) {
            prev_heights[i] = 0;
            continue;
        }
        if (resolved_inputs[i].IsSpent()) {
            return std::nullopt;
        }
        prev_heights[i] = resolved_inputs[i].GetHeight() == MEMPOOL_HEIGHT
                              ? tip->nHeight + 1
                              : resolved_inputs[i].GetHeight();
    }
    CBlockIndex next_tip;
    next_tip.pprev = tip;
    next_tip.nHeight = tip->nHeight + 1;
    const auto [min_height, min_time] = CalculateSequenceLocks(
        tx, STANDARD_LOCKTIME_VERIFY_FLAGS, prev_heights, next_tip);
    return LockPoints{min_height, min_time};
}

static inline bool ExtractTokenIdAndValueFast(const CTxOut &txout,
                                              uint256 &tok_id,
                                              uint64_t &val) {
    if (!txout.vBranches.empty()) {
        if ((txout.nFlags & 0x01U) == 0) {
            return false;
        }
        tok_id = txout.tokenId;
        val = static_cast<uint64_t>(
            std::max<int64_t>(0, txout.nValue / SATOSHI));
        return true;
    }
    if (txout.scriptPubKey.size() >= 43) {
        const uint8_t flags0 = txout.scriptPubKey[0];
        const bool maybe_token =
            ((flags0 & 0x01U) != 0 && (flags0 & 0xfcU) == 0) ||
            (flags0 == 0x6a && txout.scriptPubKey.size() >= 44 &&
             (txout.scriptPubKey[1] & 0x01U) != 0 &&
             (txout.scriptPubKey[1] & 0xfcU) == 0);
        if (!maybe_token) {
            return false;
        }
        const lotus::v2::Output v2out = txout.ToV2Output();
        if (v2out.HasToken()) {
            std::memcpy(tok_id.begin(), v2out.token_id.data(), 32);
            val = v2out.value;
            return true;
        }
    }
    return false;
}

bool CheckTxInputsFromResolvedCoins(const CTransaction &tx,
                                    TxValidationState &state,
                                    const std::vector<Coin> &resolved_inputs,
                                    int nSpendHeight, Amount &txfee) {
    Amount nValueIn = Amount::zero();
    std::map<uint256, std::pair<__uint128_t, __uint128_t>> tokenTotals;
    bool has_authority_input = false;
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto &in = tx.vin[i];
        if (in.nFlags == 3) {
            has_authority_input = true;
            continue;
        }
        const Coin &coin = resolved_inputs[i];
        if (coin.IsSpent()) {
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS,
                                 "bad-txns-inputs-missingorspent",
                                 strprintf("%s: inputs missing/spent", __func__));
        }
        if (coin.IsCoinBase() &&
            nSpendHeight - coin.GetHeight() < COINBASE_MATURITY) {
            return state.Invalid(
                TxValidationResult::TX_PREMATURE_SPEND,
                "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d",
                          nSpendHeight - coin.GetHeight()));
        }
        const CTxOut &prev_txout = coin.GetTxOut();
        uint256 tok_id;
        uint64_t tok_val = 0;
        if (ExtractTokenIdAndValueFast(prev_txout, tok_id, tok_val)) {
            if (prev_txout.nValue < Amount::zero()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-inputvalues-outofrange");
            }
            tokenTotals[tok_id].first += tok_val;
            continue;
        }
        nValueIn += prev_txout.nValue;
        if (!MoneyRange(prev_txout.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-inputvalues-outofrange");
        }
    }

    for (const auto &out : tx.vout) {
        uint256 tok_id;
        uint64_t tok_val = 0;
        if (ExtractTokenIdAndValueFast(out, tok_id, tok_val)) {
            if (out.nValue < Amount::zero()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-vout-negative");
            }
            tokenTotals[tok_id].second += tok_val;
        }
    }

    if (!tokenTotals.empty() || has_authority_input) {
        std::set<uint256> positiveTokenDeltas;
        for (const auto &[tokenId, totals] : tokenTotals) {
            if (totals.second > totals.first) {
                positiveTokenDeltas.insert(tokenId);
            }
        }
        for (const auto &in : tx.vin) {
            if (in.nFlags != 3) {
                continue;
            }
            if (positiveTokenDeltas.erase(uint256(in.prevout.GetTxId())) != 1) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "bad-txns-mint-without-positive-delta");
            }
        }
        if (!positiveTokenDeltas.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "bad-txns-token-inflation");
        }
    }

    const Amount value_out = tx.GetValueOut();
    if (nValueIn < value_out) {
        return state.Invalid(
            TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn),
                      FormatMoney(value_out)));
    }

    const Amount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;
    return true;
}

bool AreInputsStandardFromResolvedCoins(
    const CTransaction &tx, const std::vector<Coin> &resolved_inputs) {
    if (tx.IsCoinBase()) {
        return true;
    }
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (tx.vin[i].nFlags == 3) {
            continue;
        }
        const CTxOut &prev = resolved_inputs[i].GetTxOut();
        std::vector<std::vector<uint8_t>> vSolutions;
        if (Solver(prev.scriptPubKey, vSolutions) == TxoutType::NONSTANDARD) {
            return false;
        }
    }
    return true;
}

class MemPoolAccept {
public:
    MemPoolAccept(CTxMemPool &mempool, Chainstate &active_chainstate)
        : m_pool(mempool), m_view(&m_dummy),
          m_viewmempool(&active_chainstate.CoinsTip(), m_pool),
          m_active_chainstate(active_chainstate) {}

    // We put the arguments we're handed into a struct, so we can pass them
    // around easier.
    struct ATMPArgs {
        const Config &m_config;
        const int64_t m_accept_time;
        const bool m_bypass_limits;
        /*
         * Return any outpoints which were not previously present in the coins
         * cache, but were added as a result of validating the tx for mempool
         * acceptance. This allows the caller to optionally remove the cache
         * additions if the associated transaction ends up being rejected by
         * the mempool.
         */
        std::vector<COutPoint> &m_coins_to_uncache;
        const bool m_test_accept;
        const unsigned int m_heightOverride;
        /**
         * When true, the mempool will not be trimmed when any transactions are
         * submitted in Finalize(). Instead, limits should be enforced at the
         * end to ensure the package is not partially submitted.
         */
        const bool m_package_submission;
        /**
         * When true, use package feerates instead of individual transaction
         * feerates for fee-based policies such as mempool min fee and min relay
         * fee.
         */
        const bool m_package_feerates;
        MempoolAdmissionLimits m_limits{};

        /** Parameters for single transaction mempool validation. */
        static ATMPArgs SingleAccept(const Config &config, int64_t accept_time,
                                     bool bypass_limits,
                                     std::vector<COutPoint> &coins_to_uncache,
                                     bool test_accept,
                                     unsigned int heightOverride) {
            return ATMPArgs{
                config,
                accept_time,
                bypass_limits,
                coins_to_uncache,
                test_accept,
                heightOverride,
                /*package_submission=*/false,
                /*package_feerates=*/false,
            };
        }

        /**
         * Parameters for test package mempool validation through
         * testmempoolaccept.
         */
        static ATMPArgs
        PackageTestAccept(const Config &config, int64_t accept_time,
                          std::vector<COutPoint> &coins_to_uncache) {
            return ATMPArgs{
                config,
                accept_time,
                /*bypass_limits=*/false,
                coins_to_uncache,
                /*test_accept=*/true,
                /*height_override=*/0,
                // not submitting to mempool
                /*package_submission=*/false,
                /*package_feerates=*/false,
            };
        }

        /** Parameters for child-with-unconfirmed-parents package validation. */
        static ATMPArgs
        PackageChildWithParents(const Config &config, int64_t accept_time,
                                std::vector<COutPoint> &coins_to_uncache) {
            return ATMPArgs{
                config,
                accept_time,
                /*bypass_limits=*/false,
                coins_to_uncache,
                /*test_accept=*/false,
                /*height_override=*/0,
                /*package_submission=*/true,
                /*package_feerates=*/true,
            };
        }

        /** Parameters for all-or-nothing batch validation/submission (testrawtxbatch / submitrawtxbatch). */
        static ATMPArgs
        RawTxBatch(const Config &config, int64_t accept_time,
                   std::vector<COutPoint> &coins_to_uncache, bool test_accept) {
            return ATMPArgs{
                config,
                accept_time,
                /*bypass_limits=*/false,
                coins_to_uncache,
                /*test_accept=*/test_accept,
                /*height_override=*/0,
                /*package_submission=*/!test_accept,
                /*package_feerates=*/false,
            };
        }

        /** Parameters for a single transaction within a package. */
        static ATMPArgs SingleInPackageAccept(const ATMPArgs &package_args) {
            return ATMPArgs{
                /*config=*/package_args.m_config,
                /*accept_time=*/package_args.m_accept_time,
                /*bypass_limits=*/false,
                /*coins_to_uncache=*/package_args.m_coins_to_uncache,
                /*test_accept=*/package_args.m_test_accept,
                /*height_override=*/package_args.m_heightOverride,
                // do not LimitMempoolSize in Finalize()
                /*package_submission=*/true,
                // only 1 transaction
                /*package_feerates=*/false,
            };
        }

    private:
        // Private ctor to avoid exposing details to clients and allowing the
        // possibility of mixing up the order of the arguments. Use static
        // functions above instead.
        ATMPArgs(const Config &config, int64_t accept_time, bool bypass_limits,
                 std::vector<COutPoint> &coins_to_uncache, bool test_accept,
                 unsigned int height_override, bool package_submission,
                 bool package_feerates)
            : m_config{config}, m_accept_time{accept_time},
              m_bypass_limits{bypass_limits},
              m_coins_to_uncache{coins_to_uncache}, m_test_accept{test_accept},
              m_heightOverride{height_override},
              m_package_submission{package_submission},
              m_package_feerates(package_feerates) {}
    };

    // Single transaction acceptance
    MempoolAcceptResult AcceptSingleTransaction(
        const CTransactionRef &ptx, ATMPArgs &args,
        const PrecomputedAdmissionChecks *precomputed = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Multiple transaction acceptance. Transactions may or may not be
     * interdependent, but must not conflict with each other, and the
     * transactions cannot already be in the mempool. Parents must come
     * before children if any dependencies exist.
     */
    PackageMempoolAcceptResult
    AcceptMultipleTransactions(const std::vector<CTransactionRef> &txns,
                               ATMPArgs &args)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * All-or-nothing batch validation and single-pass commit for
     * testrawtxbatch and submitrawtxbatch.
     */
    PackageMempoolAcceptResult
    AcceptRawTxBatch(
        const std::vector<CTransactionRef> &txns, ATMPArgs &args,
        const CFeeRate &max_raw_tx_fee_rate,
        const std::vector<PrecomputedBatchTxData> *precomputed_batch = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Submission of a subpackage.
     * If subpackage size == 1, calls AcceptSingleTransaction() with adjusted
     * ATMPArgs to avoid package policy restrictions like no CPFP carve out
     * (PackageMempoolChecks), and creates a PackageMempoolAcceptResult wrapping
     * the result.
     *
     * If subpackage size > 1, calls AcceptMultipleTransactions() with the
     * provided ATMPArgs.
     *
     * Also cleans up all non-chainstate coins from m_view at the end.
     */
    PackageMempoolAcceptResult
    AcceptSubPackage(const std::vector<CTransactionRef> &subpackage,
                     ATMPArgs &args)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    /**
     * Package (more specific than just multiple transactions) acceptance.
     * Package must be a child with all of its unconfirmed parents, and
     * topologically sorted.
     */
    PackageMempoolAcceptResult AcceptPackage(const Package &package,
                                             ATMPArgs &args)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    // All the intermediate state that gets passed between the various levels
    // of checking a given transaction.
    struct Workspace {
        Workspace(const CTransactionRef &ptx,
                  const uint32_t next_block_script_verify_flags)
            : m_ptx(ptx),
              m_next_block_script_verify_flags(next_block_script_verify_flags) {
        }
        /**
         * Mempool entry constructed for this transaction.
         * Constructed in PreChecks() but not inserted into the mempool until
         * Finalize().
         */
        std::unique_ptr<CTxMemPoolEntry> m_entry;

        /**
         * Virtual size of the transaction as used by the mempool, calculated
         * using serialized size of the transaction and sigchecks.
         */
        int64_t m_vsize;
        /**
         * Fees paid by this transaction: total input amounts subtracted by
         * total output amounts.
         */
        Amount m_base_fees;

        /**
         * Base fees + any fee delta set by the user with
         * prioritisetransaction.
         */
        Amount m_modified_fees;

        /**
         * If we're doing package validation (i.e. m_package_feerates=true), the
         * "effective" package feerate of this transaction is the total fees
         * divided by the total size of transactions (which may include its
         * ancestors and/or descendants).
         */
        CFeeRate m_package_feerate{Amount::zero()};

        const CTransactionRef &m_ptx;
        TxValidationState m_state;
        /**
         * A temporary cache containing serialized transaction data for
         * signature verification.
         * Reused across PreChecks and ConsensusScriptChecks.
         */
        bool m_regular_tx_checked{false};
        bool m_regular_tx_valid{false};
        TxValidationState m_regular_tx_state;

        // ABC specific flags that are used in both PreChecks and
        // ConsensusScriptChecks
        const uint32_t m_next_block_script_verify_flags;
        int m_sig_checks_standard{0};

        // Pre-resolved input coins and lock points captured during Pass 1 of
        // batch validation so Pass 2 can validate scripts/signatures in parallel.
        std::vector<Coin> m_resolved_inputs;
        std::vector<int32_t> m_batch_parent_indices;
        bool m_has_mempool_parents{true};
        std::optional<LockPoints> m_lock_points;

        // Advisory legacy checks; native admission remains authoritative.
        const PrecomputedAdmissionChecks *m_precomputed{nullptr};
    };

    // Run the policy checks on a given transaction, excluding any script
    // checks. Looks up inputs, calculates feerate, considers replacement,
    // evaluates package limits, etc. As this function can be invoked for "free"
    // by a peer, only tests that are fast should be done here (to avoid CPU
    // DoS).
    bool PreChecks(ATMPArgs &args, Workspace &ws,
                   bool defer_script_checks = false)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    bool PreChecksBatch(ATMPArgs &args, Workspace &ws, size_t ws_idx,
                        const std::vector<CTransactionRef> &txns,
                        const std::vector<BatchTxIdIndexSlot> &txid_table,
                        size_t txid_mask, bool mempool_nonempty)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    bool FinalizeDeferredPreChecks(ATMPArgs &args, Workspace &ws)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Re-run the script checks, using consensus flags, and try to cache the
    // result in the scriptcache. This should be done after
    // PolicyScriptChecks(). This requires that all inputs either be in our
    // utxo set or in the mempool.
    bool ConsensusScriptChecks(const ATMPArgs &args, Workspace &ws)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Try to add the transaction to the mempool, removing any conflicts first.
    // Returns true if the transaction is in the mempool after any size
    // limiting is performed, false otherwise.
    bool Finalize(const ATMPArgs &args, Workspace &ws,
                  std::vector<ValidationSignals::MempoolAddedBatchItem>
                      *batch_signals = nullptr,
                  const std::vector<CTxMemPool::txiter> *batch_iters = nullptr,
                  CTxMemPool::txiter *out_iter = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Submit all transactions to the mempool and call ConsensusScriptChecks to
    // add to the script cache - should only be called after successful
    // validation of all transactions in the package.
    // Does not call LimitMempoolSize(), so mempool max_size_bytes may be
    // temporarily exceeded.
    bool SubmitPackage(const ATMPArgs &args, std::vector<Workspace> &workspaces,
                       PackageValidationState &package_state,
                       std::map<TxId, MempoolAcceptResult> &results,
                       bool scripts_already_verified = false)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Compare a package's feerate against minimum allowed.
    bool CheckFeeRate(size_t package_size, size_t package_vsize,
                      Amount package_fee, TxValidationState &state)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_pool.cs) {
        AssertLockHeld(::cs_main);
        AssertLockHeld(m_pool.cs);

        const Amount mempoolRejectFee =
            m_pool.GetMinFee().GetFee(package_vsize);

        if (mempoolRejectFee > Amount::zero() &&
            package_fee < mempoolRejectFee) {
            return state.Invalid(
                TxValidationResult::TX_PACKAGE_RECONSIDERABLE,
                "mempool min fee not met",
                strprintf("%d < %d", package_fee, mempoolRejectFee));
        }

        // Do not change this to use virtualsize without coordinating a network
        // policy upgrade.
        if (package_fee <
            m_pool.m_opts.min_relay_feerate.GetFee(package_size)) {
            return state.Invalid(
                TxValidationResult::TX_PACKAGE_RECONSIDERABLE,
                "min relay fee not met",
                strprintf(
                    "%d < %d", package_fee,
                    m_pool.m_opts.min_relay_feerate.GetFee(package_size)));
        }

        return true;
    }

public:
    std::vector<bool>
    PrepareStaged(const std::vector<CTransactionRef> &txs,
                  std::vector<PrecomputedAdmissionChecks> &checks,
                  std::vector<std::vector<COutPoint>> &fetched,
                  uint32_t script_flags, const MempoolAdmissionLimits &limits)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    ValidationCache &GetValidationCache() {
        return m_active_chainstate.m_chainman.m_validation_cache;
    }

private:
    CTxMemPool &m_pool;
    CCoinsViewCache m_view;
    CCoinsViewMemPool m_viewmempool;
    CCoinsView m_dummy;

    Chainstate &m_active_chainstate;
};

bool MemPoolAccept::PreChecks(ATMPArgs &args, Workspace &ws,
                              bool defer_script_checks) {
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction &tx = *ws.m_ptx;
    const TxId &txid = ws.m_ptx->GetId();

    LogDebug(BCLog::TXPACKAGES, "tx-admission-precheck txid=%s\n",
             txid.ToString());

    // Copy/alias what we need out of args
    std::vector<COutPoint> &coins_to_uncache = args.m_coins_to_uncache;

    // Alias what we need out of ws
    TxValidationState &state = ws.m_state;
    // Coinbase is only valid in a block, not as a loose transaction.
    if (ws.m_regular_tx_checked) {
        if (!ws.m_regular_tx_valid) {
            state = ws.m_regular_tx_state;
            return false;
        }
    } else if (!CheckRegularTransaction(tx, state)) {
        // state filled in by CheckRegularTransaction.
        return false;
    }

    const bool is_v2_native_tx =
        std::any_of(tx.vin.begin(), tx.vin.end(), [](const CTxIn &in) {
            return in.nFlags != 0 && !in.vWitnesses.empty();
        });

    // Rather not work on nonstandard transactions (unless -testnet)
    std::string reason;
    if (m_pool.m_opts.require_standard && !is_v2_native_tx &&
        !IsStandardTx(tx, m_pool.m_opts.max_datacarrier_bytes,
                      m_pool.m_opts.permit_bare_multisig,
                      m_pool.m_opts.dust_relay_feerate, reason)) {
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, reason);
    }

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    TxValidationState ctxState;
    if (!ContextualCheckTransactionForCurrentBlock(
            *Assert(m_active_chainstate.m_chain.Tip()),
            args.m_config.GetChainParams().GetConsensus(), tx, ctxState)) {
        // We copy the state from a dummy to ensure we don't increase the
        // ban score of peer for transaction that could be valid in the future.
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND,
                             ctxState.GetRejectReason(),
                             ctxState.GetDebugMessage());
    }

    // Is it already in the memory pool?
    if (m_pool.exists(txid)) {
        return state.Invalid(TxValidationResult::TX_DUPLICATE,
                             "txn-already-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    for (const CTxIn &txin : tx.vin) {
        if (txin.nFlags == 3) {
            continue;
        }
        if (const auto ptxConflicting = m_pool.GetConflictTx(txin.prevout)) {
            if (m_pool.isAvalancheFinalizedPreConsensus(
                    ptxConflicting->GetId())) {
                return state.Invalid(TxValidationResult::TX_CONFLICT,
                                     "finalized-tx-conflict");
            }

            return state.Invalid(
                TxValidationResult::TX_AVALANCHE_RECONSIDERABLE,
                "txn-mempool-conflict");
        }
    }

    m_view.SetBackend(m_viewmempool);

    const CCoinsViewCache &coins_cache = m_active_chainstate.CoinsTip();
    // Do all inputs exist?
    for (const CTxIn &txin : tx.vin) {
        if (txin.nFlags == 3) {
            continue;
        }
        if (!coins_cache.HaveCoinInCache(txin.prevout)) {
            coins_to_uncache.push_back(txin.prevout);
        }

        // Note: this call may add txin.prevout to the coins cache
        // (coins_cache.cacheCoins) by way of FetchCoin(). It should be
        // removed later (via coins_to_uncache) if this tx turns out to be
        // invalid.
        if (!m_view.HaveCoin(txin.prevout)) {
            // Are inputs missing because we already have the tx?
            for (size_t out = 0; out < tx.vout.size(); out++) {
                // Optimistically just do efficient check of cache for
                // outputs.
                if (coins_cache.HaveCoinInCache(COutPoint(txid, out))) {
                    return state.Invalid(TxValidationResult::TX_DUPLICATE,
                                         "txn-already-known");
                }
            }

            // Otherwise assume this might be an orphan tx for which we just
            // haven't seen parents yet.
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS,
                                 "bad-txns-inputs-missingorspent");
        }
    }

    // Bring the best block into scope.
    m_view.GetBestBlock();

    // we have all inputs cached now, so switch back to dummy (to protect
    // against bugs where we pull more inputs from disk that miss being
    // added to coins_to_uncache)
    m_view.SetBackend(m_dummy);

    assert(m_active_chainstate.m_blockman.LookupBlockIndex(
               m_view.GetBestBlock()) == m_active_chainstate.m_chain.Tip());

    // Only accept BIP68 sequence locked transactions that can be mined in
    // the next block; we don't want our mempool filled up with transactions
    // that can't be mined yet.
    // Pass in m_view which has all of the relevant inputs cached. Note that,
    // since m_view's backend was removed, it no longer pulls coins from the
    // mempool.
    const std::optional<LockPoints> lock_points{CalculateLockPointsAtTip(
        m_active_chainstate.m_chain.Tip(), m_view, tx)};
    if (!lock_points.has_value() ||
        !CheckSequenceLocksAtTip(m_active_chainstate.m_chain.Tip(),
                                 *lock_points)) {
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND,
                             "non-BIP68-final");
    }

    // The mempool holds txs for the next block, so pass height+1 to
    // CheckTxInputs
    if (!Consensus::CheckTxInputs(tx, state, m_view,
                                  m_active_chainstate.m_chain.Height() + 1,
                                  ws.m_base_fees)) {
        // state filled in by CheckTxInputs
        return false;
    }

    // Check for non-standard pay-to-script-hash in inputs
    if (m_pool.m_opts.require_standard && !is_v2_native_tx &&
        !AreInputsStandard(tx, m_view, ws.m_next_block_script_verify_flags)) {
        return state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD,
                             "bad-txns-nonstandard-inputs");
    }

    // ws.m_modified_fess includes any fee deltas from PrioritiseTransaction
    ws.m_modified_fees = ws.m_base_fees;
    m_pool.ApplyDelta(txid, ws.m_modified_fees);
    ws.m_lock_points = lock_points;

    if (defer_script_checks) {
        ws.m_resolved_inputs.resize(tx.vin.size());
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            if (tx.vin[i].nFlags == 3) {
                ws.m_resolved_inputs[i] =
                    Coin(CTxOut(Amount::zero(), CScript()), 1, false);
            } else {
                ws.m_resolved_inputs[i] = m_view.AccessCoin(tx.vin[i].prevout);
            }
        }
        return true;
    }

    // Validate input scripts against standard script flags.
    const uint32_t scriptVerifyFlags =
        ws.m_next_block_script_verify_flags | STANDARD_SCRIPT_VERIFY_FLAGS;
    if (!CheckInputScriptsReusing(
            tx, state, m_view, scriptVerifyFlags, /*sigCacheStore=*/true,
            /*scriptCacheStore=*/false, ws.m_precomputed,
            ws.m_precomputed ? &ws.m_precomputed->standard : nullptr,
            GetValidationCache(), ws.m_sig_checks_standard)) {
        // State filled in by CheckInputScripts
        return false;
    }

    return FinalizeDeferredPreChecks(args, ws);
}

bool MemPoolAccept::PreChecksBatch(
    ATMPArgs &args, Workspace &ws, size_t ws_idx,
    const std::vector<CTransactionRef> &txns,
    const std::vector<BatchTxIdIndexSlot> &txid_table, size_t txid_mask,
    bool mempool_nonempty) {
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction &tx = *ws.m_ptx;
    const TxId &txid = ws.m_ptx->GetId();
    std::vector<COutPoint> &coins_to_uncache = args.m_coins_to_uncache;
    TxValidationState &state = ws.m_state;

    if (ws.m_regular_tx_checked) {
        if (!ws.m_regular_tx_valid) {
            state = ws.m_regular_tx_state;
            return false;
        }
    } else if (!CheckRegularTransaction(tx, state)) {
        return false;
    }

    const bool is_v2_native_tx =
        std::any_of(tx.vin.begin(), tx.vin.end(), [](const CTxIn &in) {
            return in.nFlags != 0 && !in.vWitnesses.empty();
        });

    std::string reason;
    if (m_pool.m_opts.require_standard && !is_v2_native_tx &&
        !IsStandardTx(tx, m_pool.m_opts.max_datacarrier_bytes,
                      m_pool.m_opts.permit_bare_multisig,
                      m_pool.m_opts.dust_relay_feerate, reason)) {
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, reason);
    }

    CBlockIndex *const tip = Assert(m_active_chainstate.m_chain.Tip());
    TxValidationState ctxState;
    if (!ContextualCheckTransactionForCurrentBlock(
            *tip, args.m_config.GetChainParams().GetConsensus(), tx,
            ctxState)) {
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND,
                             ctxState.GetRejectReason(),
                             ctxState.GetDebugMessage());
    }

    if (mempool_nonempty) {
        if (m_pool.mapTx.find(txid) != m_pool.mapTx.end()) {
            return state.Invalid(TxValidationResult::TX_DUPLICATE,
                                 "txn-already-in-mempool");
        }
        for (const CTxIn &txin : tx.vin) {
            if (txin.nFlags == 3) {
                continue;
            }
            if (const auto ptxConflicting =
                    m_pool.GetConflictTx(txin.prevout)) {
                if (m_pool.isAvalancheFinalizedPreConsensus(
                        ptxConflicting->GetId())) {
                    return state.Invalid(TxValidationResult::TX_CONFLICT,
                                         "finalized-tx-conflict");
                }
                return state.Invalid(
                    TxValidationResult::TX_AVALANCHE_RECONSIDERABLE,
                    "txn-mempool-conflict");
            }
        }
    }

    ws.m_resolved_inputs.resize(tx.vin.size());
    ws.m_batch_parent_indices.assign(tx.vin.size(), -1);
    ws.m_has_mempool_parents = false;
    const CCoinsViewCache &coins_cache = m_active_chainstate.CoinsTip();

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const CTxIn &txin = tx.vin[i];
        if (txin.nFlags == 3) {
            ws.m_resolved_inputs[i] =
                Coin(CTxOut(Amount::zero(), CScript()), 1, false);
            continue;
        }
        bool resolved = false;
        if (!txid_table.empty()) {
            const TxId &prev_txid = txin.prevout.GetTxId();
            size_t tslot = prev_txid.GetUint64(0) & txid_mask;
            while (txid_table[tslot].occupied) {
                if (txid_table[tslot].txid == prev_txid) {
                    const size_t parent_idx = txid_table[tslot].index;
                    if (parent_idx < ws_idx) {
                        const CTransaction &parent_tx = *txns[parent_idx];
                        const uint32_t n = txin.prevout.GetN();
                        if (n < parent_tx.vout.size() &&
                            !parent_tx.vout[n].IsNull()) {
                            ws.m_resolved_inputs[i] =
                                Coin(parent_tx.vout[n], MEMPOOL_HEIGHT, false);
                            ws.m_batch_parent_indices[i] =
                                static_cast<int32_t>(parent_idx);
                            ws.m_has_mempool_parents = true;
                            resolved = true;
                        }
                    }
                    break;
                }
                tslot = (tslot + 1) & txid_mask;
            }
        }
        if (!resolved && mempool_nonempty) {
            auto mit = m_pool.mapTx.find(txin.prevout.GetTxId());
            if (mit != m_pool.mapTx.end()) {
                const CTransaction &ptx = (*mit)->GetTx();
                const uint32_t n = txin.prevout.GetN();
                if (n < ptx.vout.size() && !ptx.vout[n].IsNull()) {
                    ws.m_resolved_inputs[i] =
                        Coin(ptx.vout[n], MEMPOOL_HEIGHT, false);
                    ws.m_has_mempool_parents = true;
                    resolved = true;
                }
            }
        }
        if (!resolved) {
            if (!coins_cache.HaveCoinInCache(txin.prevout)) {
                coins_to_uncache.push_back(txin.prevout);
            }
            const Coin &coin = coins_cache.AccessCoin(txin.prevout);
            if (!coin.IsSpent()) {
                ws.m_resolved_inputs[i] = coin;
                resolved = true;
            }
        }
        if (!resolved) {
            for (size_t out = 0; out < tx.vout.size(); out++) {
                if (coins_cache.HaveCoinInCache(COutPoint(txid, out))) {
                    return state.Invalid(TxValidationResult::TX_DUPLICATE,
                                         "txn-already-known");
                }
            }
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS,
                                 "bad-txns-inputs-missingorspent");
        }
    }

    const std::optional<LockPoints> lock_points{
        CalculateLockPointsFromResolvedCoins(tip, tx, ws.m_resolved_inputs)};
    if (!lock_points.has_value() ||
        !CheckSequenceLocksAtTip(tip, *lock_points)) {
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND,
                             "non-BIP68-final");
    }

    if (!CheckTxInputsFromResolvedCoins(tx, state, ws.m_resolved_inputs,
                                        tip->nHeight + 1, ws.m_base_fees)) {
        return false;
    }

    if (m_pool.m_opts.require_standard && !is_v2_native_tx &&
        !AreInputsStandardFromResolvedCoins(tx, ws.m_resolved_inputs)) {
        return state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD,
                             "bad-txns-nonstandard-inputs");
    }

    ws.m_modified_fees = ws.m_base_fees;
    if (!m_pool.mapDeltas.empty()) {
        m_pool.ApplyDelta(txid, ws.m_modified_fees);
    }
    ws.m_lock_points = lock_points;
    return true;
}

bool MemPoolAccept::FinalizeDeferredPreChecks(ATMPArgs &args, Workspace &ws) {
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransactionRef &ptx = ws.m_ptx;
    const CTransaction &tx = *ws.m_ptx;
    const int64_t nAcceptTime = args.m_accept_time;
    const bool bypass_limits = args.m_bypass_limits;
    const unsigned int heightOverride = args.m_heightOverride;
    TxValidationState &state = ws.m_state;
    const unsigned int nSize = tx.GetTotalSize();

    ws.m_entry = std::make_unique<CTxMemPoolEntry>(
        ptx, ws.m_base_fees, nAcceptTime,
        heightOverride ? heightOverride : m_active_chainstate.m_chain.Height(),
        ws.m_sig_checks_standard, ws.m_lock_points.value());

    ws.m_vsize = ws.m_entry->GetTxVirtualSize();

    // No individual transactions are allowed below the min relay feerate except
    // from disconnected blocks. This requirement, unlike CheckFeeRate, cannot
    // be bypassed using m_package_feerates because, while a tx could be package
    // CPFP'd when entering the mempool, we do not have a DoS-resistant method
    // of ensuring the tx remains bumped. For example, the fee-bumping child
    // could disappear due to a replacement.
    if (!bypass_limits &&
        ws.m_modified_fees <
            m_pool.m_opts.min_relay_feerate.GetFee(ws.m_ptx->GetTotalSize())) {
        // Even though this is a fee-related failure, this result is
        // TX_MEMPOOL_POLICY, not TX_PACKAGE_RECONSIDERABLE, because it cannot
        // be bypassed using package validation.
        return state.Invalid(
            TxValidationResult::TX_MEMPOOL_POLICY, "min relay fee not met",
            strprintf("%d < %d", ws.m_modified_fees,
                      m_pool.m_opts.min_relay_feerate.GetFee(nSize)));
    }
    // No individual transactions are allowed below the mempool min feerate
    // except from disconnected blocks and transactions in a package. Package
    // transactions will be checked using package feerate later.
    if (!bypass_limits && !args.m_package_feerates &&
        !CheckFeeRate(nSize, ws.m_vsize, ws.m_modified_fees, state)) {
        return false;
    }

    return true;
}

bool MemPoolAccept::ConsensusScriptChecks(const ATMPArgs &args, Workspace &ws) {
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction &tx = *ws.m_ptx;
    const TxId &txid = tx.GetId();
    TxValidationState &state = ws.m_state;

    // Check again against the next block's script verification flags
    // to cache our script execution flags.
    //
    // This is also useful in case of bugs in the standard flags that cause
    // transactions to pass as valid when they're actually invalid. For
    // instance the STRICTENC flag was incorrectly allowing certain CHECKSIG
    // NOT scripts to pass, even though they were invalid.
    //
    // There is a similar check in CreateNewBlock() to prevent creating
    // invalid blocks (using TestBlockValidity), however allowing such
    // transactions into the mempool can be exploited as a DoS attack.
    int nSigChecksConsensus;
    if (!CheckInputsFromMempoolAndCache(
            tx, state, m_view, m_pool, ws.m_next_block_script_verify_flags,
            tx.GetPrecomputedData(), GetValidationCache(), nSigChecksConsensus,
            m_active_chainstate.CoinsTip(), ws.m_precomputed)) {
        // This can occur under some circumstances, if the node receives an
        // unrequested tx which is invalid due to new consensus rules not
        // being activated yet (during IBD).
        LogInfoEvent(BCLog::ALL, "script_validation_flags_inconsistent",
                     "BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block but not STANDARD flags {txid}, {reason}")
            .Field(BCLog::LogField::TxId, txid)
            .Field(BCLog::LogField::Reason, state);
        return Assume(false);
    }

    if (ws.m_sig_checks_standard != nSigChecksConsensus) {
        // We can't accept this transaction as we've used the standard count
        // for the mempool/mining, but the consensus count will be enforced
        // in validation (we don't want to produce bad block templates).
        LogErrorEvent(
            BCLog::ALL, "script_sigchecks_inconsistent",
            "{source_function}: BUG! PLEASE REPORT THIS! SigChecks count differed between standard and consensus flags in {txid}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::TxId, txid);
        return false;
    }
    return true;
}

bool MemPoolAccept::Finalize(
    const ATMPArgs &args, Workspace &ws,
    std::vector<ValidationSignals::MempoolAddedBatchItem> *batch_signals,
    const std::vector<CTxMemPool::txiter> *batch_iters,
    CTxMemPool::txiter *out_iter) {
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const TxId &txid = ws.m_ptx->GetId();
    TxValidationState &state = ws.m_state;
    const bool bypass_limits = args.m_bypass_limits;

    // Store transaction in memory
    CTxMemPoolEntry *pentry = ws.m_entry.release();
    auto entry = CTxMemPoolEntryRef::acquire(pentry);
    CTxMemPool::txiter it = m_pool.addUnchecked(
        entry, ws.m_has_mempool_parents,
        ws.m_batch_parent_indices.empty() ? nullptr
                                          : &ws.m_batch_parent_indices,
        batch_iters);
    if (out_iter != nullptr) {
        *out_iter = it;
    }
    if (m_pool.m_opts.signals) {
        std::shared_ptr<const std::vector<Coin>> spent_coins_ptr;
        if (!ws.m_resolved_inputs.empty()) {
            spent_coins_ptr = std::make_shared<const std::vector<Coin>>(
                std::move(ws.m_resolved_inputs));
        } else {
            auto spentCoins = GetSpentCoins(ws.m_ptx, m_view);
            Assume(spentCoins.has_value());
            if (spentCoins.has_value()) {
                spent_coins_ptr = std::make_shared<const std::vector<Coin>>(
                    std::move(*spentCoins));
            }
        }
        const uint64_t seq = m_pool.GetAndIncrementSequence();
        if (batch_signals != nullptr) {
            batch_signals->push_back(ValidationSignals::MempoolAddedBatchItem{
                ws.m_ptx, std::move(spent_coins_ptr), seq});
        } else {
            m_pool.m_opts.signals->TransactionAddedToMempool(
                ws.m_ptx, std::move(spent_coins_ptr), seq);
        }
    }

    // Trim mempool and check if tx was trimmed.
    // If we are validating a package, don't trim here because we could evict a
    // previous transaction in the package. LimitMempoolSize() should be called
    // at the very end to make sure the mempool is still within limits and
    // package submission happens atomically.
    if (!args.m_package_submission && !bypass_limits) {
        m_pool.LimitSize(m_active_chainstate.CoinsTip());
        if (!m_pool.exists(txid)) {
            // The tx no longer meets our (new) mempool minimum feerate but
            // could be reconsidered in a package.
            return state.Invalid(TxValidationResult::TX_PACKAGE_RECONSIDERABLE,
                                 "mempool full");
        }
    }
    return true;
}

bool MemPoolAccept::SubmitPackage(
    const ATMPArgs &args, std::vector<Workspace> &workspaces,
    PackageValidationState &package_state,
    std::map<TxId, MempoolAcceptResult> &results,
    bool scripts_already_verified) {
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    CTxMemPool::ScopedSnapshotDefer snap_defer(m_pool);
    const CBlockIndex *tip = m_active_chainstate.m_chain.Tip();
    if (tip) {
        m_pool.SyncMerklixOverlayToTip(
            tip->GetBlockHash(), static_cast<uint64_t>(tip->nHeight + 1),
            static_cast<uint64_t>(tip->GetMedianTimePast()));
    }
    // Sanity check: none of the transactions should be in the mempool.
    assert(std::all_of(
        workspaces.cbegin(), workspaces.cend(),
        [this](const auto &ws) { return !m_pool.exists(ws.m_ptx->GetId()); }));

    bool all_submitted = true;
    std::vector<ValidationSignals::MempoolAddedBatchItem> batch_signals;
    if (m_pool.m_opts.signals && workspaces.size() > 1) {
        batch_signals.reserve(workspaces.size());
    }
    auto *batch_signals_ptr =
        (m_pool.m_opts.signals && workspaces.size() > 1) ? &batch_signals
                                                         : nullptr;
    std::vector<CTxMemPool::txiter> batch_iters(workspaces.size());
    // ConsensusScriptChecks adds to the script cache and is therefore
    // consensus-critical; CheckInputsFromMempoolAndCache asserts that
    // transactions only spend coins available from the mempool or UTXO set.
    // Submit each transaction to the mempool immediately after calling
    // ConsensusScriptChecks to make the outputs available for subsequent
    // transactions.
    for (size_t idx = 0; idx < workspaces.size(); ++idx) {
        Workspace &ws = workspaces[idx];
        if (!scripts_already_verified && !ConsensusScriptChecks(args, ws)) {
            results.emplace(ws.m_ptx->GetId(),
                            MempoolAcceptResult::Failure(ws.m_state));
            // Since PreChecks() passed, this should never fail.
            all_submitted = false;
            package_state.Invalid(
                PackageValidationResult::PCKG_MEMPOOL_ERROR,
                strprintf("BUG! PolicyScriptChecks succeeded but "
                          "ConsensusScriptChecks failed: %s",
                          ws.m_ptx->GetId().ToString()));
        }

        // If we call LimitMempoolSize() for each individual Finalize(), the
        // mempool will not take the transaction's descendant feerate into
        // account because it hasn't seen them yet. Also, we risk evicting a
        // transaction that a subsequent package transaction depends on.
        // Instead, allow the mempool to temporarily bypass limits, the maximum
        // package size) while submitting transactions individually and then
        // trim at the very end.
        if (!Finalize(args, ws, batch_signals_ptr, &batch_iters,
                      &batch_iters[idx])) {
            results.emplace(ws.m_ptx->GetId(),
                            MempoolAcceptResult::Failure(ws.m_state));
            // Since LimitMempoolSize() won't be called, this should never fail.
            all_submitted = false;
            package_state.Invalid(PackageValidationResult::PCKG_MEMPOOL_ERROR,
                                  strprintf("BUG! Adding to mempool failed: %s",
                                            ws.m_ptx->GetId().ToString()));
        }
    }

    if (batch_signals_ptr != nullptr && !batch_signals.empty()) {
        m_pool.m_opts.signals->TransactionsAddedToMempoolBatch(
            std::move(batch_signals));
    }

    // It may or may not be the case that all the transactions made it into the
    // mempool. Regardless, make sure we haven't exceeded max mempool size.
    m_pool.LimitSize(m_active_chainstate.CoinsTip());

    std::vector<TxId> all_package_txids;
    if (args.m_package_feerates) {
        all_package_txids.reserve(workspaces.size());
        std::transform(workspaces.cbegin(), workspaces.cend(),
                       std::back_inserter(all_package_txids),
                       [](const auto &ws) { return ws.m_ptx->GetId(); });
    }

    // Add successful results. The returned results may change later if
    // LimitMempoolSize() evicts them.
    for (Workspace &ws : workspaces) {
        const auto effective_feerate =
            args.m_package_feerates
                ? ws.m_package_feerate
                : CFeeRate{ws.m_modified_fees,
                           static_cast<uint32_t>(ws.m_vsize)};
        const auto effective_feerate_txids =
            args.m_package_feerates ? all_package_txids
                                    : std::vector<TxId>({ws.m_ptx->GetId()});
        results.emplace(ws.m_ptx->GetId(),
                        MempoolAcceptResult::Success(ws.m_vsize, ws.m_base_fees,
                                                     effective_feerate,
                                                     effective_feerate_txids));
    }
    return all_submitted;
}

MempoolAcceptResult MemPoolAccept::AcceptSingleTransaction(
    const CTransactionRef &ptx, ATMPArgs &args,
    const PrecomputedAdmissionChecks *precomputed) {
    AssertLockHeld(cs_main);
    // mempool "read lock" (held through
    // m_pool.m_opts.signals->TransactionAddedToMempool())
    LOCK(m_pool.cs);

    const CBlockIndex *tip = m_active_chainstate.m_chain.Tip();

    Workspace ws(ptx,
                 GetNextBlockScriptFlags(tip, m_active_chainstate.m_chainman));
    if (precomputed != nullptr && precomputed->txid == ptx->GetId()) {
        ws.m_precomputed = precomputed;
        // CheckRegularTransaction is context-free: its result for this
        // transaction holds whenever it was computed.
        if (precomputed->regular_tx_checked) {
            ws.m_regular_tx_checked = true;
            ws.m_regular_tx_valid = precomputed->regular_tx_valid;
            ws.m_regular_tx_state = precomputed->regular_tx_state;
        }
    }

    const std::vector<TxId> single_txid{ws.m_ptx->GetId()};

    // Perform the inexpensive checks first and avoid hashing and signature
    // verification unless those checks pass, to mitigate CPU exhaustion
    // denial-of-service attacks.
    if (!PreChecks(args, ws)) {
        if (ws.m_state.GetResult() ==
            TxValidationResult::TX_PACKAGE_RECONSIDERABLE) {
            // Failed for fee reasons. Provide the effective feerate and which
            // tx was included.
            return MempoolAcceptResult::FeeFailure(
                ws.m_state, CFeeRate(ws.m_modified_fees, ws.m_vsize),
                single_txid);
        }
        return MempoolAcceptResult::Failure(ws.m_state);
    }

    if (args.m_limits.max_fee > Amount::zero() && ws.m_base_fees > args.m_limits.max_fee) {
        ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "max-fee-exceeded");
        return MempoolAcceptResult::Failure(ws.m_state);
    }
    if (args.m_limits.rpc_fee_hysteresis) {
        const auto now = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
        const auto &controller = lotus::v2::GetGlobalFeeHysteresisController();
        const uint64_t rate = controller.GetRpcAdmissionRatePerKCu(now);
        const uint64_t required = lotus::v2::FeeHysteresisController::ComputeFeeForCu(ws.m_vsize, rate);
        if (rate > controller.GetConsensusFloorPerKCu() &&
            uint64_t(std::max<int64_t>(0, ws.m_base_fees / SATOSHI)) < required) {
            // Only rejection diagnostics need the wider coherent policy view.
            const auto info = controller.GetFeeRateInfo(now);
            const uint64_t recommended = std::max(required,
                lotus::v2::FeeHysteresisController::ComputeFeeForCu(
                    ws.m_vsize, info.recommended_sdk_feerate_per_kcu));
            ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY,
                "rpc-fee-hysteresis-insufficient",
                strprintf("required_fee_sats=%u, required_rate_per_kcu=%u, "
                          "recommended_sdk_feerate_per_kcu=%u, recommended_sdk_fee_sats=%u",
                          required, rate, info.recommended_sdk_feerate_per_kcu,
                          recommended));
            return MempoolAcceptResult::Failure(ws.m_state);
        }
    }

    if (!ConsensusScriptChecks(args, ws)) {
        return MempoolAcceptResult::Failure(ws.m_state);
    }

    const TxId txid = ptx->GetId();

    // Mempool sanity check -- in our new mempool no tx can be added if its
    // outputs are already spent in the mempool (that is, no children before
    // parents allowed; the mempool must be consistent at all times).
    //
    // This means that on reorg, the disconnectpool *must* always import
    // the existing mempool tx's, clear the mempool, and then re-add
    // remaining tx's in topological order via this function. Our new mempool
    // has fast adds, so this is ok.
    if (auto it = m_pool.mapNextTx.lower_bound(COutPoint{txid, 0});
        it != m_pool.mapNextTx.end() && it->first->GetTxId() == txid) {
        LogInfoEvent(
            BCLog::ALL, "mempool_child_before_parent",
            "{source_function}: BUG! PLEASE REPORT THIS! Attempt to add txid {txid}, but its outputs are already spent in the mempool")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::TxId, txid);
        ws.m_state.Invalid(TxValidationResult::TX_CHILD_BEFORE_PARENT,
                           "txn-child-before-parent");
        return MempoolAcceptResult::Failure(ws.m_state);
    }

    const CFeeRate effective_feerate{ws.m_modified_fees,
                                     static_cast<uint32_t>(ws.m_vsize)};
    // Tx was accepted, but not added
    if (args.m_test_accept) {
        return MempoolAcceptResult::Success(ws.m_vsize, ws.m_base_fees,
                                            effective_feerate, single_txid);
    }

    if (tip) {
        m_pool.SyncMerklixOverlayToTip(
            tip->GetBlockHash(), static_cast<uint64_t>(tip->nHeight + 1),
            static_cast<uint64_t>(tip->GetMedianTimePast()));
    }

    if (!Finalize(args, ws)) {
        // The only possible failure reason is fee-related (mempool full).
        // Failed for fee reasons. Provide the effective feerate and which txns
        // were included.
        Assume(ws.m_state.GetResult() ==
               TxValidationResult::TX_PACKAGE_RECONSIDERABLE);
        return MempoolAcceptResult::FeeFailure(
            ws.m_state, CFeeRate(ws.m_modified_fees, ws.m_vsize), single_txid);
    }

    return MempoolAcceptResult::Success(ws.m_vsize, ws.m_base_fees,
                                        effective_feerate, single_txid);
}

PackageMempoolAcceptResult MemPoolAccept::AcceptMultipleTransactions(
    const std::vector<CTransactionRef> &txns, ATMPArgs &args) {
    AssertLockHeld(cs_main);

    // These context-free package limits can be done before taking the mempool
    // lock.
    PackageValidationState package_state;
    if (!CheckPackage(txns, package_state)) {
        return PackageMempoolAcceptResult(package_state, {});
    }

    std::vector<Workspace> workspaces{};
    workspaces.reserve(txns.size());
    std::transform(
        txns.cbegin(), txns.cend(), std::back_inserter(workspaces),
        [this](const auto &tx) {
            return Workspace(
                tx, GetNextBlockScriptFlags(m_active_chainstate.m_chain.Tip(),
                                            m_active_chainstate.m_chainman));
        });
    std::map<TxId, MempoolAcceptResult> results;

    LOCK(m_pool.cs);

    // Do all PreChecks first and fail fast to avoid running expensive script
    // checks when unnecessary.
    std::vector<TxId> valid_txids;
    for (Workspace &ws : workspaces) {
        if (!PreChecks(args, ws)) {
            package_state.Invalid(PackageValidationResult::PCKG_TX,
                                  "transaction failed");
            // Exit early to avoid doing pointless work. Update the failed tx
            // result; the rest are unfinished.
            results.emplace(ws.m_ptx->GetId(),
                            MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state,
                                              std::move(results));
        }
        // Make the coins created by this transaction available for subsequent
        // transactions in the package to spend.
        m_viewmempool.PackageAddTransaction(ws.m_ptx);
        valid_txids.push_back(ws.m_ptx->GetId());
    }

    // Transactions must meet two minimum feerates: the mempool minimum fee and
    // min relay fee. For transactions consisting of exactly one child and its
    // parents, it suffices to use the package feerate
    // (total modified fees / total size or vsize) to check this requirement.
    // Note that this is an aggregate feerate; this function has not checked
    // that there are transactions too low feerate to pay for themselves, or
    // that the child transactions are higher feerate than their parents. Using
    // aggregate feerate may allow "parents pay for child" behavior and permit
    // a child that is below mempool minimum feerate. To avoid these behaviors,
    // callers of AcceptMultipleTransactions need to restrict txns topology
    // (e.g. to ancestor sets) and check the feerates of individuals and
    // subsets.
    const auto m_total_size = std::accumulate(
        workspaces.cbegin(), workspaces.cend(), int64_t{0},
        [](int64_t sum, auto &ws) { return sum + ws.m_ptx->GetTotalSize(); });
    const auto m_total_vsize =
        std::accumulate(workspaces.cbegin(), workspaces.cend(), int64_t{0},
                        [](int64_t sum, auto &ws) { return sum + ws.m_vsize; });
    const auto m_total_modified_fees = std::accumulate(
        workspaces.cbegin(), workspaces.cend(), Amount::zero(),
        [](Amount sum, auto &ws) { return sum + ws.m_modified_fees; });
    const CFeeRate package_feerate(m_total_modified_fees, m_total_vsize);
    std::vector<TxId> all_package_txids;
    all_package_txids.reserve(workspaces.size());
    std::transform(workspaces.cbegin(), workspaces.cend(),
                   std::back_inserter(all_package_txids),
                   [](const auto &ws) { return ws.m_ptx->GetId(); });
    TxValidationState placeholder_state;
    if (args.m_package_feerates &&
        !CheckFeeRate(m_total_size, m_total_vsize, m_total_modified_fees,
                      placeholder_state)) {
        package_state.Invalid(PackageValidationResult::PCKG_TX,
                              "transaction failed");
        return PackageMempoolAcceptResult(
            package_state, {{workspaces.back().m_ptx->GetId(),
                             MempoolAcceptResult::FeeFailure(
                                 placeholder_state,
                                 CFeeRate(m_total_modified_fees, m_total_vsize),
                                 all_package_txids)}});
    }

    for (Workspace &ws : workspaces) {
        ws.m_package_feerate = package_feerate;
        const TxId &ws_txid = ws.m_ptx->GetId();
        if (args.m_test_accept &&
            std::find(valid_txids.begin(), valid_txids.end(), ws_txid) !=
                valid_txids.end()) {
            const auto effective_feerate =
                args.m_package_feerates
                    ? ws.m_package_feerate
                    : CFeeRate{ws.m_modified_fees,
                               static_cast<uint32_t>(ws.m_vsize)};
            const auto effective_feerate_txids =
                args.m_package_feerates ? all_package_txids
                                        : std::vector<TxId>{ws.m_ptx->GetId()};
            // When test_accept=true, transactions that pass PreChecks
            // are valid because there are no further mempool checks (passing
            // PreChecks implies passing ConsensusScriptChecks).
            results.emplace(ws_txid,
                            MempoolAcceptResult::Success(
                                ws.m_vsize, ws.m_base_fees, effective_feerate,
                                effective_feerate_txids));
        }
    }

    if (args.m_test_accept) {
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }

    if (!SubmitPackage(args, workspaces, package_state, results)) {
        // PackageValidationState filled in by SubmitPackage().
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }

    return PackageMempoolAcceptResult(package_state, std::move(results));
}

namespace {
class ParallelScriptWorkerPool {
public:
    static ParallelScriptWorkerPool &Instance() {
        static ParallelScriptWorkerPool pool;
        return pool;
    }

    template <typename Fn>
    void Run(size_t num_workers, Fn &&fn) {
        if (num_workers <= 1) {
            fn(0);
            return;
        }
        std::unique_lock<std::mutex> dispatch_lock(m_dispatch_mutex);
        RunLocked(dispatch_lock, num_workers, std::forward<Fn>(fn));
    }

    /**
     * As Run, but returns false without running anything if another caller
     * is using the pool (e.g. ConnectBlock's script checks), instead of
     * waiting for it. Must not be called from a pool task.
     */
    template <typename Fn> bool TryRun(size_t num_workers, Fn &&fn) {
        if (num_workers <= 1) {
            fn(0);
            return true;
        }
        std::unique_lock<std::mutex> dispatch_lock(m_dispatch_mutex,
                                                   std::try_to_lock);
        if (!dispatch_lock.owns_lock()) {
            return false;
        }
        RunLocked(dispatch_lock, num_workers, std::forward<Fn>(fn));
        return true;
    }

private:
    template <typename Fn>
    void RunLocked(std::unique_lock<std::mutex> &dispatch_lock,
                   size_t num_workers, Fn &&fn) {
        std::function<void(size_t)> task_fn(std::forward<Fn>(fn));
        EnsureWorkers(num_workers - 1);
        const size_t active = std::min(num_workers - 1, m_threads.size());
        if (active == 0) {
            dispatch_lock.unlock();
            task_fn(0);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_task = &task_fn;
            m_active_workers = active;
            m_remaining.store(active, std::memory_order_release);
            ++m_generation;
        }
        m_cv_start.notify_all();
        task_fn(0);
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv_done.wait(lock, [this]() {
                return m_remaining.load(std::memory_order_acquire) == 0;
            });
            m_task = nullptr;
        }
    }

    ParallelScriptWorkerPool() = default;
    ~ParallelScriptWorkerPool() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stop = true;
            ++m_generation;
        }
        m_cv_start.notify_all();
        for (auto &t : m_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    void EnsureWorkers(size_t count) {
        while (m_threads.size() < count) {
            const size_t worker_id = m_threads.size() + 1;
            m_threads.emplace_back([this, worker_id]() {
                uint64_t seen_gen = 0;
                while (true) {
                    const std::function<void(size_t)> *fn = nullptr;
                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv_start.wait(lock, [this, &seen_gen]() {
                            return m_stop || m_generation != seen_gen;
                        });
                        if (m_stop) {
                            return;
                        }
                        seen_gen = m_generation;
                        if (worker_id <= m_active_workers) {
                            fn = m_task;
                        }
                    }
                    if (fn != nullptr) {
                        (*fn)(worker_id);
                        if (m_remaining.fetch_sub(
                                1, std::memory_order_acq_rel) == 1) {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            m_cv_done.notify_one();
                        }
                    }
                }
            });
        }
    }

    std::mutex m_dispatch_mutex;
    std::mutex m_mutex;
    std::condition_variable m_cv_start;
    std::condition_variable m_cv_done;
    std::vector<std::thread> m_threads;
    const std::function<void(size_t)> *m_task{nullptr};
    size_t m_active_workers{0};
    std::atomic<size_t> m_remaining{0};
    uint64_t m_generation{0};
    bool m_stop{false};
};
} // namespace

PackageMempoolAcceptResult MemPoolAccept::AcceptRawTxBatch(
    const std::vector<CTransactionRef> &txns, ATMPArgs &args,
    const CFeeRate &max_raw_tx_fee_rate,
    const std::vector<PrecomputedBatchTxData> *precomputed_batch) {
    AssertLockHeld(cs_main);

    PackageValidationState package_state;
    const size_t batch_count = txns.size();
    if (batch_count > MAX_RAWTX_BATCH_COUNT) {
        package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                              "package-too-many-transactions");
        return PackageMempoolAcceptResult(package_state, {});
    }

    std::vector<BatchTxIdIndexSlot> txid_table;
    size_t txid_mask = 0;

    if (batch_count > 1) {
        const int64_t total_size = std::accumulate(
            txns.cbegin(), txns.cend(), int64_t{0},
            [](int64_t sum, const auto &tx) {
                return sum + GetVirtualTransactionSize(*tx);
            });
        if (total_size > int64_t(MAX_RAWTX_BATCH_SIZE_KB) * 1000) {
            package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                                  "package-too-large");
            return PackageMempoolAcceptResult(package_state, {});
        }

        size_t txid_cap = 16;
        while (txid_cap < batch_count * 2) {
            txid_cap <<= 1;
        }
        txid_mask = txid_cap - 1;
        txid_table.resize(txid_cap);
        size_t total_inputs = 0;
        for (size_t i = 0; i < batch_count; ++i) {
            const TxId &id = txns[i]->GetId();
            total_inputs += txns[i]->vin.size();
            size_t slot = id.GetUint64(0) & txid_mask;
            while (txid_table[slot].occupied) {
                if (txid_table[slot].txid == id) {
                    package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                                          "package-contains-duplicates");
                    return PackageMempoolAcceptResult(package_state, {});
                }
                slot = (slot + 1) & txid_mask;
            }
            txid_table[slot].txid = id;
            txid_table[slot].index = i;
            txid_table[slot].occupied = true;
        }

        size_t in_cap = 16;
        while (in_cap < (total_inputs + 1) * 2) {
            in_cap <<= 1;
        }
        const size_t in_mask = in_cap - 1;
        struct OutpointSlot {
            COutPoint outpoint;
            bool occupied{false};
        };
        std::vector<OutpointSlot> inputs_seen(in_cap);
        for (size_t i = 0; i < batch_count; ++i) {
            const auto &tx = txns[i];
            for (const auto &input : tx->vin) {
                if (input.nFlags == 3) {
                    continue;
                }
                const TxId &prev_txid = input.prevout.GetTxId();
                size_t tslot = prev_txid.GetUint64(0) & txid_mask;
                while (txid_table[tslot].occupied) {
                    if (txid_table[tslot].txid == prev_txid) {
                        if (txid_table[tslot].index >= i) {
                            package_state.Invalid(
                                PackageValidationResult::PCKG_POLICY,
                                "package-not-sorted");
                            return PackageMempoolAcceptResult(package_state,
                                                              {});
                        }
                        break;
                    }
                    tslot = (tslot + 1) & txid_mask;
                }

                const uint64_t ohash =
                    prev_txid.GetUint64(0) ^
                    (static_cast<uint64_t>(input.prevout.GetN()) *
                     0x9e3779b97f4a7c15ULL);
                size_t islot = static_cast<size_t>(ohash) & in_mask;
                while (inputs_seen[islot].occupied) {
                    if (inputs_seen[islot].outpoint == input.prevout) {
                        package_state.Invalid(
                            PackageValidationResult::PCKG_POLICY,
                            "conflict-in-package");
                        return PackageMempoolAcceptResult(package_state, {});
                    }
                    islot = (islot + 1) & in_mask;
                }
                inputs_seen[islot].outpoint = input.prevout;
                inputs_seen[islot].occupied = true;
            }
        }
    }

    const uint32_t script_flags = GetNextBlockScriptFlags(
        m_active_chainstate.m_chain.Tip(), m_active_chainstate.m_chainman);
    std::vector<Workspace> workspaces;
    workspaces.reserve(txns.size());
    for (size_t i = 0; i < txns.size(); ++i) {
        Workspace &ws = workspaces.emplace_back(txns[i], script_flags);
        if (precomputed_batch != nullptr && i < precomputed_batch->size()) {
            const PrecomputedBatchTxData &pre = (*precomputed_batch)[i];
            if (pre.regular_tx_checked) {
                ws.m_regular_tx_checked = true;
                ws.m_regular_tx_valid = pre.regular_tx_valid;
                ws.m_regular_tx_state = pre.regular_tx_state;
            }
        }
    }

    std::map<TxId, MempoolAcceptResult> results;
    LOCK(m_pool.cs);
    CTxMemPool::ScopedSnapshotDefer snap_defer(m_pool);

    auto cleanup_views = []() {};

    // Prefetch only uncached disk UTXO pages in sorted key order before Pass 1.
    if (txns.size() >= 8) {
        CCoinsViewCache &coins_tip = m_active_chainstate.CoinsTip();
        std::vector<COutPoint> batch_outpoints;
        batch_outpoints.reserve(txns.size() * 2);
        for (const auto &tx : txns) {
            for (const auto &in : tx->vin) {
                if (in.nFlags != 3 && !coins_tip.HaveCoinInCache(in.prevout)) {
                    batch_outpoints.push_back(in.prevout);
                }
            }
        }
        if (!batch_outpoints.empty()) {
            coins_tip.PrefetchOutpointsAsync(batch_outpoints);
        }
    }

    const bool mempool_nonempty = !m_pool.mapTx.empty();

    // Pass 1: Single-wave UTXO dependency resolution & fast policy/input checks.
    for (size_t ws_idx = 0; ws_idx < workspaces.size(); ++ws_idx) {
        Workspace &ws = workspaces[ws_idx];
        if (!PreChecksBatch(args, ws, ws_idx, txns, txid_table, txid_mask,
                            mempool_nonempty)) {
            package_state.Invalid(PackageValidationResult::PCKG_TX,
                                  "transaction failed");
            results.emplace(ws.m_ptx->GetId(),
                            MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state,
                                              std::move(results));
        }
    }

    // Pass 2: Static UTXO Dependency-Graph Multi-Core Parallel Script & Batch
    // Signature Validation using the pre-resolved coins captured in Pass 1.
    ValidationCache &val_cache = GetValidationCache();
    std::vector<size_t> uncached_ws_indices;
    uncached_ws_indices.reserve(workspaces.size());
    for (size_t idx = 0; idx < workspaces.size(); ++idx) {
        Workspace &ws = workspaces[idx];
        const CTransaction &tx = *ws.m_ptx;
        const uint32_t scriptVerifyFlags =
            ws.m_next_block_script_verify_flags | STANDARD_SCRIPT_VERIFY_FLAGS;
        ScriptCacheKey hashCacheEntry(
            tx, scriptVerifyFlags, val_cache.ScriptExecutionCacheHasher());
        ScriptCacheElement elem(hashCacheEntry, 0);
        if (val_cache.m_script_execution_cache.get(elem, /*erase=*/true)) {
            TxSigCheckLimiter txLimiter;
            if (!txLimiter.consume_and_check(elem.nSigChecks)) {
                ws.m_state.Invalid(TxValidationResult::TX_CONSENSUS,
                                   "too-many-sigchecks");
                package_state.Invalid(PackageValidationResult::PCKG_TX,
                                      "transaction failed");
                results.emplace(ws.m_ptx->GetId(),
                                MempoolAcceptResult::Failure(ws.m_state));
                cleanup_views();
                return PackageMempoolAcceptResult(package_state,
                                                  std::move(results));
            }
            ws.m_sig_checks_standard = elem.nSigChecks;

        } else {
            uncached_ws_indices.push_back(idx);
        }
    }

    if (!uncached_ws_indices.empty()) {
        const size_t n_uncached = uncached_ws_indices.size();
        const unsigned int hw_threads =
            std::max(1u, std::thread::hardware_concurrency());
        const size_t num_workers =
            (n_uncached >= 2)
                ? std::min<size_t>(n_uncached, static_cast<size_t>(hw_threads))
                : 1;
        std::vector<std::optional<ParallelTxScriptError>> ws_errors(n_uncached);
        std::vector<lotus::v2::BatchSigCollector> worker_collectors(
            num_workers);
        std::atomic<size_t> next_k{0};
        std::atomic<size_t> min_failed_k{n_uncached};

        auto worker_fn = [&](size_t tid) {
            lotus::v2::BatchSigCollector &local_sigs = worker_collectors[tid];
            while (true) {
                const size_t k = next_k.fetch_add(1, std::memory_order_relaxed);
                if (k >= n_uncached ||
                    k > min_failed_k.load(std::memory_order_relaxed)) {
                    break;
                }
                Workspace &ws = workspaces[uncached_ws_indices[k]];
                const CTransaction &tx = *ws.m_ptx;
                const uint32_t scriptVerifyFlags =
                    ws.m_next_block_script_verify_flags |
                    STANDARD_SCRIPT_VERIFY_FLAGS;

                TxSigCheckLimiter txLimiter;
                auto err = VerifyTxScriptsFromResolvedCoins(
                    tx, ws.m_resolved_inputs, scriptVerifyFlags,
                    /*sigCacheStore=*/true, tx.GetPrecomputedData(),
                    val_cache.m_signature_cache, ws.m_sig_checks_standard,
                    txLimiter, nullptr, &local_sigs);
                if (err.has_value()) {
                    ws_errors[k] = std::move(err);
                    size_t prev = min_failed_k.load(std::memory_order_relaxed);
                    while (k < prev &&
                           !min_failed_k.compare_exchange_weak(
                               prev, k, std::memory_order_relaxed)) {
                    }
                }
            }
        };

        ParallelScriptWorkerPool::Instance().Run(num_workers, worker_fn);

        for (size_t k = 0; k < n_uncached; ++k) {
            if (ws_errors[k].has_value()) {
                Workspace &ws = workspaces[uncached_ws_indices[k]];
                ws.m_state.Invalid(ws_errors[k]->result,
                                   ws_errors[k]->reject_reason,
                                   ws_errors[k]->debug_message);
                package_state.Invalid(PackageValidationResult::PCKG_TX,
                                      "transaction failed");
                results.emplace(ws.m_ptx->GetId(),
                                MempoolAcceptResult::Failure(ws.m_state));
                cleanup_views();
                return PackageMempoolAcceptResult(package_state,
                                                  std::move(results));
            }
        }

        lotus::v2::BatchSigCollector combined_sigs;
        for (auto &wc : worker_collectors) {
            combined_sigs.Merge(std::move(wc));
        }
        if (!combined_sigs.Empty()) {
            if (!combined_sigs.VerifyAll()) {
                for (size_t k = 0; k < n_uncached; ++k) {
                    Workspace &ws = workspaces[uncached_ws_indices[k]];
                    const CTransaction &tx = *ws.m_ptx;
                    const uint32_t scriptVerifyFlags =
                        ws.m_next_block_script_verify_flags |
                        STANDARD_SCRIPT_VERIFY_FLAGS;
                    TxSigCheckLimiter txLimiter;
                    int dummy_sigchecks = 0;
                    auto err = VerifyTxScriptsFromResolvedCoins(
                        tx, ws.m_resolved_inputs, scriptVerifyFlags,
                        /*sigCacheStore=*/false, tx.GetPrecomputedData(),
                        val_cache.m_signature_cache, dummy_sigchecks, txLimiter,
                        nullptr, nullptr);
                    if (err.has_value()) {
                        ws.m_state.Invalid(err->result, err->reject_reason,
                                           err->debug_message);
                        package_state.Invalid(PackageValidationResult::PCKG_TX,
                                              "transaction failed");
                        results.emplace(
                            ws.m_ptx->GetId(),
                            MempoolAcceptResult::Failure(ws.m_state));
                        cleanup_views();
                        return PackageMempoolAcceptResult(package_state,
                                                          std::move(results));
                    }
                }
            } else {
                val_cache.m_signature_cache.SetBatch(combined_sigs);
            }
        }
    }

    for (Workspace &ws : workspaces) {
        if (!FinalizeDeferredPreChecks(args, ws)) {
            package_state.Invalid(PackageValidationResult::PCKG_TX,
                                  "transaction failed");
            results.emplace(ws.m_ptx->GetId(),
                            MempoolAcceptResult::Failure(ws.m_state));
            cleanup_views();
            return PackageMempoolAcceptResult(package_state,
                                              std::move(results));
        }

        const Amount max_raw_tx_fee =
            max_raw_tx_fee_rate.GetFee(ws.m_vsize);
        if (max_raw_tx_fee != Amount::zero() &&
            ws.m_base_fees > max_raw_tx_fee) {
            package_state.Invalid(PackageValidationResult::PCKG_TX,
                                  "max-fee-exceeded");
            ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY,
                               "max-fee-exceeded");
            results.emplace(ws.m_ptx->GetId(),
                            MempoolAcceptResult::Failure(ws.m_state));
            cleanup_views();
            return PackageMempoolAcceptResult(package_state,
                                              std::move(results));
        }

        // Pure V7 inputs execute the same fixed VM profile under policy and
        // consensus flags. Legacy/mixed compatibility inputs must earn the
        // exact consensus-flags cache entry independently.
        const auto &tx = *ws.m_ptx;
        const bool native_only = tx.nVersion == 7 &&
            std::all_of(tx.vin.begin(), tx.vin.end(), [](const auto &in) {
                return in.nFlags == 1 || in.nFlags == 3;
            });
        if (!native_only) {
            TxSigCheckLimiter limiter;
            int consensus_sigchecks = 0;
            const auto error = VerifyTxScriptsFromResolvedCoins(tx, ws.m_resolved_inputs,
                ws.m_next_block_script_verify_flags, true, tx.GetPrecomputedData(),
                val_cache.m_signature_cache, consensus_sigchecks, limiter, nullptr, nullptr);
            if (error || consensus_sigchecks != ws.m_sig_checks_standard) {
                ws.m_state.Invalid(TxValidationResult::TX_CONSENSUS,
                    error ? error->reject_reason : "inconsistent-consensus-sigchecks");
                package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
                results.emplace(tx.GetId(), MempoolAcceptResult::Failure(ws.m_state));
                cleanup_views();
                return PackageMempoolAcceptResult(package_state, std::move(results));
            }
        }
        if (!args.m_test_accept) {
            ScriptCacheKey consensusKey(
                *ws.m_ptx, ws.m_next_block_script_verify_flags,
                val_cache.ScriptExecutionCacheHasher());
            val_cache.m_script_execution_cache.insert(
                ScriptCacheElement{consensusKey, ws.m_sig_checks_standard});
        }
    }

    // Reserve the whole batch before SubmitPackage can insert entries and
    // subsequently trim individual members to satisfy the pool limit.
    std::vector<const CTxMemPoolEntry *> staged_entries;
    staged_entries.reserve(workspaces.size());
    for (const Workspace &ws : workspaces) {
        staged_entries.push_back(ws.m_entry.get());
    }
    if (!m_pool.CanFitRawTxBatch(staged_entries)) {
        package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                              "mempool full");
        cleanup_views();
        return PackageMempoolAcceptResult(package_state, {});
    }

    if (args.m_test_accept) {
        for (Workspace &ws : workspaces) {
            const TxId &ws_txid = ws.m_ptx->GetId();
            const CFeeRate effective_feerate{
                ws.m_modified_fees, static_cast<uint32_t>(ws.m_vsize)};
            results.emplace(ws_txid,
                            MempoolAcceptResult::Success(
                                ws.m_vsize, ws.m_base_fees, effective_feerate,
                                std::vector<TxId>{ws_txid}));
        }
        cleanup_views();
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }

    SubmitPackage(args, workspaces, package_state, results,
                  /*scripts_already_verified=*/true);
    cleanup_views();
    return PackageMempoolAcceptResult(package_state, std::move(results));
}

PackageMempoolAcceptResult
MemPoolAccept::AcceptSubPackage(const std::vector<CTransactionRef> &subpackage,
                                ATMPArgs &args) {
    AssertLockHeld(::cs_main);
    AssertLockHeld(m_pool.cs);

    auto result = [&]() EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_pool.cs) {
        if (subpackage.size() > 1) {
            return AcceptMultipleTransactions(subpackage, args);
        }
        const auto &tx = subpackage.front();
        ATMPArgs single_args = ATMPArgs::SingleInPackageAccept(args);
        const auto single_res = AcceptSingleTransaction(tx, single_args);
        PackageValidationState package_state_wrapped;
        if (single_res.m_result_type !=
            MempoolAcceptResult::ResultType::VALID) {
            package_state_wrapped.Invalid(PackageValidationResult::PCKG_TX,
                                          "transaction failed");
        }
        return PackageMempoolAcceptResult(package_state_wrapped,
                                          {{tx->GetId(), single_res}});
    }();

    // Clean up m_view and m_viewmempool so that other subpackage evaluations
    // don't have access to coins they shouldn't. Keep some coins in order to
    // minimize re-fetching coins from the UTXO set.
    //
    // There are 3 kinds of coins in m_view:
    // (1) Temporary coins from the transactions in subpackage, constructed by
    //     m_viewmempool.
    // (2) Mempool coins from transactions in the mempool, constructed by
    //     m_viewmempool.
    // (3) Confirmed coins fetched from our current UTXO set.
    //
    // (1) Temporary coins need to be removed, regardless of whether the
    // transaction was submitted. If the transaction was submitted to the
    // mempool, m_viewmempool will be able to fetch them from there. If it
    // wasn't submitted to mempool, it is incorrect to keep them - future calls
    // may try to spend those coins that don't actually exist.
    // (2) Mempool coins also need to be removed. If the mempool contents have
    // changed as a result of submitting or replacing transactions, coins
    // previously fetched from mempool may now be spent or nonexistent. Those
    // coins need to be deleted from m_view.
    // (3) Confirmed coins don't need to be removed. The chainstate has not
    // changed (we are holding cs_main and no blocks have been processed) so the
    // confirmed tx cannot disappear like a mempool tx can. The coin may now be
    // spent after we submitted a tx to mempool, but we have already checked
    // that the package does not have 2 transactions spending the same coin.
    // Keeping them in m_view is an optimization to not re-fetch confirmed coins
    // if we later look up inputs for this transaction again.
    for (const auto &outpoint : m_viewmempool.GetNonBaseCoins()) {
        // In addition to resetting m_viewmempool, we also need to manually
        // delete these coins from m_view because it caches copies of the coins
        // it fetched from m_viewmempool previously.
        m_view.Uncache(outpoint);
    }
    // This deletes the temporary and mempool coins.
    m_viewmempool.Reset();
    return result;
}

PackageMempoolAcceptResult MemPoolAccept::AcceptPackage(const Package &package,
                                                        ATMPArgs &args) {
    AssertLockHeld(cs_main);
    // Used if returning a PackageMempoolAcceptResult directly from this
    // function.
    PackageValidationState package_state_quit_early;

    // Check that the package is well-formed. If it isn't, we won't try to
    // validate any of the transactions and thus won't return any
    // MempoolAcceptResults, just a package-wide error.

    // Context-free package checks.
    if (!CheckPackage(package, package_state_quit_early)) {
        return PackageMempoolAcceptResult(package_state_quit_early, {});
    }

    // All transactions in the package must be a parent of the last transaction.
    // This is just an opportunity for us to fail fast on a context-free check
    // without taking the mempool lock.
    if (!IsChildWithParents(package)) {
        package_state_quit_early.Invalid(PackageValidationResult::PCKG_POLICY,
                                         "package-not-child-with-parents");
        return PackageMempoolAcceptResult(package_state_quit_early, {});
    }

    // IsChildWithParents() guarantees the package is > 1 transactions.
    assert(package.size() > 1);
    // The package must be 1 child with all of its unconfirmed parents. The
    // package is expected to be sorted, so the last transaction is the child.
    const auto &child = package.back();
    std::unordered_set<TxId, SaltedTxIdHasher> unconfirmed_parent_txids;
    std::transform(
        package.cbegin(), package.cend() - 1,
        std::inserter(unconfirmed_parent_txids, unconfirmed_parent_txids.end()),
        [](const auto &tx) { return tx->GetId(); });

    // All child inputs must refer to a preceding package transaction or a
    // confirmed UTXO. The only way to verify this is to look up the child's
    // inputs in our current coins view (not including mempool), and enforce
    // that all parents not present in the package be available at chain tip.
    // Since this check can bring new coins into the coins cache, keep track of
    // these coins and uncache them if we don't end up submitting this package
    // to the mempool.
    const CCoinsViewCache &coins_tip_cache = m_active_chainstate.CoinsTip();
    for (const auto &input : child->vin) {
        if (input.nFlags == 3) {
            continue;
        }
        if (!coins_tip_cache.HaveCoinInCache(input.prevout)) {
            args.m_coins_to_uncache.push_back(input.prevout);
        }
    }
    // Using the MemPoolAccept m_view cache allows us to look up these same
    // coins faster later. This should be connecting directly to CoinsTip, not
    // to m_viewmempool, because we specifically require inputs to be confirmed
    // if they aren't in the package.
    m_view.SetBackend(m_active_chainstate.CoinsTip());
    const auto package_or_confirmed = [this, &unconfirmed_parent_txids](
                                          const auto &input) {
        return input.nFlags == 3 ||
               unconfirmed_parent_txids.count(input.prevout.GetTxId()) > 0 ||
               m_view.HaveCoin(input.prevout);
    };
    if (!std::all_of(child->vin.begin(), child->vin.end(),
                     package_or_confirmed)) {
        package_state_quit_early.Invalid(
            PackageValidationResult::PCKG_POLICY,
            "package-not-child-with-unconfirmed-parents");
        return PackageMempoolAcceptResult(package_state_quit_early, {});
    }
    // Protect against bugs where we pull more inputs from disk that miss being
    // added to coins_to_uncache. The backend will be connected again when
    // needed in PreChecks.
    m_view.SetBackend(m_dummy);

    LOCK(m_pool.cs);
    // Stores results from which we will create the returned
    // PackageMempoolAcceptResult. A result may be changed if a mempool
    // transaction is evicted later due to LimitMempoolSize().
    std::map<TxId, MempoolAcceptResult> results_final;
    // Results from individual validation which will be returned if no other
    // result is available for this transaction. "Nonfinal" because if a
    // transaction fails by itself but succeeds later (i.e. when evaluated with
    // a fee-bumping child), the result in this map may be discarded.
    std::map<TxId, MempoolAcceptResult> individual_results_nonfinal;
    bool quit_early{false};
    std::vector<CTransactionRef> txns_package_eval;
    for (const auto &tx : package) {
        const auto &txid = tx->GetId();
        // An already confirmed tx is treated as one not in mempool, because all
        // we know is that the inputs aren't available.
        if (m_pool.exists(txid)) {
            // Exact transaction already exists in the mempool.
            // Node operators are free to set their mempool policies however
            // they please, nodes may receive transactions in different orders,
            // and malicious counterparties may try to take advantage of policy
            // differences to pin or delay propagation of transactions. As such,
            // it's possible for some package transaction(s) to already be in
            // the mempool, and we don't want to reject the entire package in
            // that case (as that could be a censorship vector). De-duplicate
            // the transactions that are already in the mempool, and only call
            // AcceptMultipleTransactions() with the new transactions. This
            // ensures we don't double-count transaction counts and sizes when
            // checking ancestor/descendant limits, or double-count transaction
            // fees for fee-related policy.
            auto iter = m_pool.GetIter(txid);
            assert(iter != std::nullopt);
            results_final.emplace(txid, MempoolAcceptResult::MempoolTx(
                                            (*iter.value())->GetTxSize(),
                                            (*iter.value())->GetFee()));
        } else {
            // Transaction does not already exist in the mempool.
            // Try submitting the transaction on its own.
            const auto single_package_res = AcceptSubPackage({tx}, args);
            const auto &single_res = single_package_res.m_tx_results.at(txid);
            if (single_res.m_result_type ==
                MempoolAcceptResult::ResultType::VALID) {
                // The transaction succeeded on its own and is now in the
                // mempool. Don't include it in package validation, because its
                // fees should only be "used" once.
                assert(m_pool.exists(txid));
                results_final.emplace(txid, single_res);
            } else if (single_res.m_state.GetResult() !=
                           TxValidationResult::TX_PACKAGE_RECONSIDERABLE &&
                       single_res.m_state.GetResult() !=
                           TxValidationResult::TX_MISSING_INPUTS) {
                // Package validation policy only differs from individual policy
                // in its evaluation of feerate. For example, if a transaction
                // fails here due to violation of a consensus rule, the result
                // will not change when it is submitted as part of a package. To
                // minimize the amount of repeated work, unless the transaction
                // fails due to feerate or missing inputs (its parent is a
                // previous transaction in the package that failed due to
                // feerate), don't run package validation. Note that this
                // decision might not make sense if different types of packages
                // are allowed in the future.  Continue individually validating
                // the rest of the transactions, because some of them may still
                // be valid.
                quit_early = true;
                package_state_quit_early.Invalid(
                    PackageValidationResult::PCKG_TX, "transaction failed");
                individual_results_nonfinal.emplace(txid, single_res);
            } else {
                individual_results_nonfinal.emplace(txid, single_res);
                txns_package_eval.push_back(tx);
            }
        }
    }

    auto multi_submission_result =
        quit_early || txns_package_eval.empty()
            ? PackageMempoolAcceptResult(package_state_quit_early, {})
            : AcceptSubPackage(txns_package_eval, args);
    PackageValidationState &package_state_final =
        multi_submission_result.m_state;

    // Make sure we haven't exceeded max mempool size.
    // Package transactions that were submitted to mempool or already in mempool
    // may be evicted.
    m_pool.LimitSize(m_active_chainstate.CoinsTip());

    for (const auto &tx : package) {
        const auto &txid = tx->GetId();
        if (multi_submission_result.m_tx_results.count(txid) > 0) {
            // We shouldn't have re-submitted if the tx result was already in
            // results_final.
            Assume(results_final.count(txid) == 0);
            // If it was submitted, check to see if the tx is still in the
            // mempool. It could have been evicted due to LimitMempoolSize()
            // above.
            const auto &txresult =
                multi_submission_result.m_tx_results.at(txid);
            if (txresult.m_result_type ==
                    MempoolAcceptResult::ResultType::VALID &&
                !m_pool.exists(txid)) {
                package_state_final.Invalid(PackageValidationResult::PCKG_TX,
                                            "transaction failed");
                TxValidationState mempool_full_state;
                mempool_full_state.Invalid(
                    TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
                results_final.emplace(
                    txid, MempoolAcceptResult::Failure(mempool_full_state));
            } else {
                results_final.emplace(txid, txresult);
            }
        } else if (const auto final_it{results_final.find(txid)};
                   final_it != results_final.end()) {
            // Already-in-mempool transaction. Check to see if it's still there,
            // as it could have been evicted when LimitMempoolSize() was called.
            Assume(final_it->second.m_result_type !=
                   MempoolAcceptResult::ResultType::INVALID);
            Assume(individual_results_nonfinal.count(txid) == 0);
            if (!m_pool.exists(tx->GetId())) {
                package_state_final.Invalid(PackageValidationResult::PCKG_TX,
                                            "transaction failed");
                TxValidationState mempool_full_state;
                mempool_full_state.Invalid(
                    TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
                // Replace the previous result.
                results_final.erase(txid);
                results_final.emplace(
                    txid, MempoolAcceptResult::Failure(mempool_full_state));
            }
        } else if (const auto non_final_it{
                       individual_results_nonfinal.find(txid)};
                   non_final_it != individual_results_nonfinal.end()) {
            Assume(non_final_it->second.m_result_type ==
                   MempoolAcceptResult::ResultType::INVALID);
            // Interesting result from previous processing.
            results_final.emplace(txid, non_final_it->second);
        }
    }
    Assume(results_final.size() == package.size());
    return PackageMempoolAcceptResult(package_state_final,
                                      std::move(results_final));
}
} // namespace

namespace {
std::atomic<uint64_t> g_mempool_admission_attempts{0};

/** Count a final (not test) mempool admission result in the metrics */
void RecordMempoolAdmission(const MempoolAcceptResult &result) {
    auto *metrics{node::GetNodeMetrics()};
    if (!metrics) {
        return;
    }
    switch (result.m_result_type) {
        case MempoolAcceptResult::ResultType::VALID: {
            metrics->mempool_accepted.Inc();
            if (result.m_vsize && *result.m_vsize > 0 && result.m_base_fees) {
                const int64_t sats{*result.m_base_fees / SATOSHI};
                metrics->mempool_accepted_fee_rate.Record(
                    uint64_t(std::max<int64_t>(0, sats)) * 1000 /
                    uint64_t(*result.m_vsize));
            }
            break;
        }
        case MempoolAcceptResult::ResultType::MEMPOOL_ENTRY:
            metrics->mempool_rejected.Add(node::MempoolRejectSeries(
                int(TxValidationResult::TX_DUPLICATE)));
            break;
        case MempoolAcceptResult::ResultType::INVALID:
            metrics->mempool_rejected.Add(
                node::MempoolRejectSeries(int(result.m_state.GetResult())));
            break;
    }
}

void RecordMempoolAdmissions(const PackageMempoolAcceptResult &result) {
    if (!node::GetNodeMetrics()) {
        return;
    }
    for (const auto &[txid, tx_result] : result.m_tx_results) {
        RecordMempoolAdmission(tx_result);
    }
}
} // namespace
uint64_t GetMempoolAdmissionAttempts() noexcept {
    return g_mempool_admission_attempts.load(std::memory_order_relaxed);
}

MempoolAcceptResult
AcceptToMemoryPool(Chainstate &active_chainstate, const CTransactionRef &tx,
                   int64_t accept_time, bool bypass_limits, bool test_accept,
                   unsigned int heightOverride,
                   const MempoolAdmissionLimits &limits,
                   const PrecomputedAdmissionChecks *precomputed) {
    AssertLockHeld(::cs_main);
    g_mempool_admission_attempts.fetch_add(1, std::memory_order_relaxed);
    assert(active_chainstate.GetMempool() != nullptr);
    CTxMemPool &pool{*active_chainstate.GetMempool()};

    std::vector<COutPoint> coins_to_uncache;
    auto args = MemPoolAccept::ATMPArgs::SingleAccept(
        active_chainstate.m_chainman.GetConfig(), accept_time, bypass_limits,
        coins_to_uncache, test_accept, heightOverride);
    args.m_limits = limits;
    MempoolAcceptResult result = MemPoolAccept(pool, active_chainstate)
                                     .AcceptSingleTransaction(tx, args, precomputed);
    if (!test_accept) {
        RecordMempoolAdmission(result);
    }
    if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        // Remove coins that were not present in the coins cache before calling
        // ATMPW; this is to prevent memory DoS in case we receive a large
        // number of invalid transactions that attempt to overrun the in-memory
        // coins cache
        // (`CCoinsViewCache::cacheCoins`).

        for (const COutPoint &outpoint : coins_to_uncache) {
            active_chainstate.CoinsTip().Uncache(outpoint);
        }
    }

    // After we've (potentially) uncached entries, ensure our coins cache is
    // still within its size limits
    BlockValidationState stateDummy;
    active_chainstate.FlushStateToDisk(stateDummy, FlushStateMode::PERIODIC);
    return result;
}

PackageMempoolAcceptResult ProcessNewPackage(Chainstate &active_chainstate,
                                             CTxMemPool &pool,
                                             const Package &package,
                                             bool test_accept) {
    AssertLockHeld(cs_main);
    assert(!package.empty());
    assert(std::all_of(package.cbegin(), package.cend(),
                       [](const auto &tx) { return tx != nullptr; }));

    const Config &config = active_chainstate.m_chainman.GetConfig();

    std::vector<COutPoint> coins_to_uncache;
    auto result = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        if (test_accept) {
            auto args = MemPoolAccept::ATMPArgs::PackageTestAccept(
                config, GetTime(), coins_to_uncache);
            return MemPoolAccept(pool, active_chainstate)
                .AcceptMultipleTransactions(package, args);
        } else {
            auto args = MemPoolAccept::ATMPArgs::PackageChildWithParents(
                config, GetTime(), coins_to_uncache);
            return MemPoolAccept(pool, active_chainstate)
                .AcceptPackage(package, args);
        }
    }();
    if (!test_accept) {
        RecordMempoolAdmissions(result);
    }

    // Uncache coins pertaining to transactions that were not submitted to the
    // mempool.
    if (test_accept || result.m_state.IsInvalid()) {
        for (const COutPoint &hashTx : coins_to_uncache) {
            active_chainstate.CoinsTip().Uncache(hashTx);
        }
    }
    // Ensure the coins cache is still within limits.
    BlockValidationState state_dummy;
    active_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    return result;
}

uint32_t GetMempoolScriptFlags(const Chainstate &active_chainstate) {
    AssertLockHeld(cs_main);
    return GetNextBlockScriptFlags(active_chainstate.m_chain.Tip(),
                                   active_chainstate.m_chainman);
}

void ComputeAdmissionChecks(const CTransaction &tx,
                            uint32_t next_block_script_flags,
                            ValidationCache &validation_cache,
                            PrecomputedAdmissionChecks &out) {
    out.standard = {};
    out.consensus = {};
    out.txid = tx.GetId();
    out.regular_tx_checked = true;
    out.regular_tx_valid = CheckRegularTransaction(tx, out.regular_tx_state);
    // Native deferred records and structural inputs require the existing
    // authoritative native verifier, not a legacy spent-output outcome.
    if (tx.nVersion == 7 || !out.regular_tx_valid || tx.IsCoinBase() ||
        out.spent_outputs.size() != tx.vin.size()) {
        return;
    }
    const PrecomputedTransactionData &txdata = tx.GetPrecomputedData();
    auto run = [&](ScriptCheckOutcome &outcome, uint32_t flags) {
        outcome.flags = flags;
        outcome.ran = true;
        TxSigCheckLimiter tx_limit_sigchecks;
        int sigchecks = 0;
        auto error = VerifyTxScriptsAgainst(
            tx,
            [&](size_t i) -> const CTxOut & { return out.spent_outputs[i]; },
            flags, /*sigCacheStore=*/true, txdata,
            validation_cache.m_signature_cache, sigchecks, tx_limit_sigchecks,
            /*pBlockLimitSigChecks=*/nullptr, /*sig_collector=*/nullptr);
        if (error.has_value()) {
            outcome.error_result = error->result;
            outcome.error_reason = std::move(error->reject_reason);
            outcome.error_debug = std::move(error->debug_message);
            outcome.sigchecks = 0;
        } else {
            outcome.sigchecks = sigchecks;
        }
    };
    // Same order as admission: policy flags first, consensus flags only for
    // a transaction that passes them.
    run(out.standard, next_block_script_flags | STANDARD_SCRIPT_VERIFY_FLAGS);
    if (!out.standard.error_result.has_value()) {
        run(out.consensus, next_block_script_flags);
    }
}

void PrecomputeSingleTxData(const CTransaction &tx,
                            PrecomputedBatchTxData &out) {
    out.regular_tx_checked = true;
    out.regular_tx_valid = CheckRegularTransaction(tx, out.regular_tx_state);
    if (out.regular_tx_valid) {
        (void)tx.GetPrecomputedData();
    }
}

PackageMempoolAcceptResult
ProcessRawTxBatch(
    Chainstate &active_chainstate, CTxMemPool &pool,
    const Package &package, bool test_accept,
    const CFeeRate &max_raw_tx_fee_rate,
    const std::vector<PrecomputedBatchTxData> *precomputed_batch) {
    AssertLockHeld(cs_main);
    assert(!package.empty());
    assert(std::all_of(package.cbegin(), package.cend(),
                       [](const auto &tx) { return tx != nullptr; }));

    const Config &config = active_chainstate.m_chainman.GetConfig();
    std::vector<COutPoint> coins_to_uncache;
    auto args = MemPoolAccept::ATMPArgs::RawTxBatch(
        config, GetTime(), coins_to_uncache, test_accept);
    PackageMempoolAcceptResult result =
        MemPoolAccept(pool, active_chainstate)
            .AcceptRawTxBatch(package, args, max_raw_tx_fee_rate,
                              precomputed_batch);
    if (!test_accept) {
        RecordMempoolAdmissions(result);
    }

    if (test_accept || result.m_state.IsInvalid()) {
        for (const COutPoint &hashTx : coins_to_uncache) {
            active_chainstate.CoinsTip().Uncache(hashTx);
        }
    }
    BlockValidationState state_dummy;
    active_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    return result;
}

std::vector<bool>
MemPoolAccept::PrepareStaged(const std::vector<CTransactionRef> &txs,
                             std::vector<PrecomputedAdmissionChecks> &checks,
                             std::vector<std::vector<COutPoint>> &fetched,
                             uint32_t script_flags,
                             const MempoolAdmissionLimits &limits) {
    AssertLockHeld(cs_main);
    LOCK(m_pool.cs);
    const size_t n = txs.size();
    std::vector<bool> verify(n, false);
    // Reuse the ordinary deferred PreChecks: reject cheap invalid
    // work before it consumes script workers. Phase C still repeats
    // every check and produces the authoritative verdict.
    size_t table_size = 1;
    while (table_size < n * 2) {
        table_size *= 2;
    }
    std::vector<BatchTxIdIndexSlot> table(table_size);
    for (size_t i = 0; i < n; ++i) {
        const auto &id = txs[i]->GetId();
        size_t slot = id.GetUint64(0) & (table_size - 1);
        while (table[slot].occupied && table[slot].txid != id) {
            slot = (slot + 1) & (table_size - 1);
        }
        if (!table[slot].occupied) {
            table[slot] = {id, i, true};
        }
    }
    std::unordered_set<COutPoint, SaltedOutpointHasher> claimed;
    for (size_t i = 0; i < n; ++i) {
        const auto &tx = txs[i];
        // Native deferred/structural inputs use authoritative Phase C only.
        if (tx->nVersion == 7) {
            continue;
        }
        if (std::any_of(tx->vin.begin(), tx->vin.end(), [&](const auto &input) {
                return !claimed.insert(input.prevout).second;
            })) {
            continue;
        }
        auto args =
            ATMPArgs::SingleAccept(m_active_chainstate.m_chainman.GetConfig(),
                                   GetTime(), false, fetched[i], false, 0);
        Workspace ws(tx, script_flags);
        if (!PreChecksBatch(args, ws, i, txs, table, table_size - 1,
                            /*mempool_nonempty=*/m_pool.size() != 0)) {
            continue;
        }
        // Serialized-size relay minimum is independent of script
        // sigchecks. The exact virtual-size minimum, fee limits and
        // package policy are evaluated again at commit time.
        if (ws.m_modified_fees <
                m_pool.m_opts.min_relay_feerate.GetFee(tx->GetTotalSize()) ||
            (limits.max_fee > Amount::zero() &&
             ws.m_base_fees > limits.max_fee)) {
            continue;
        }
        auto &spent = checks[i].spent_outputs;
        spent.reserve(ws.m_resolved_inputs.size());
        for (const auto &coin : ws.m_resolved_inputs) {
            spent.push_back(coin.GetTxOut());
        }
        verify[i] = true;
    }
    return verify;
}

PrecomputedAdmissionChecks
PrecomputeMempoolAdmission(ChainstateManager &chainman,
                           const CTransactionRef &tx,
                           const MempoolAdmissionLimits &limits) {
    AssertLockNotHeld(cs_main);
    // Native scripts deliberately use authoritative admission only. Do not
    // acquire staging locks or allocate spent-output tables for a skipped tx.
    if (tx->nVersion == 7) {
        PrecomputedAdmissionChecks checks;
        return checks;
    }
    std::vector<PrecomputedAdmissionChecks> checks(1);
    std::vector<std::vector<COutPoint>> fetched(1);
    bool verify = false;
    uint32_t flags = 0;
    {
        const auto waiting = SteadyClock::now();
        LOCK(cs_main);
        node::AdmissionLockTimer timer(waiting);
        auto &chainstate = chainman.ActiveChainstate();
        if (auto *pool = chainstate.GetMempool()) {
            flags = GetMempoolScriptFlags(chainstate);
            verify =
                MemPoolAccept(*pool, chainstate)
                    .PrepareStaged({tx}, checks, fetched, flags, limits)[0];
            // No admission owns these cache entries yet. Retain only copied
            // outputs across the unlocked phase, including for invalid work.
            for (const auto &outpoint : fetched[0]) {
                chainstate.CoinsTip().Uncache(outpoint);
            }
        }
    }
    if (verify) {
        const auto start = SteadyClock::now();
        ComputeAdmissionChecks(*tx, flags, chainman.m_validation_cache,
                               checks[0]);
        if (auto *metrics = node::GetNodeMetrics()) {
            metrics->mempool_admission_verify_seconds.RecordDuration(
                SteadyClock::now() - start);
        }
    }
    return std::move(checks[0]);
}

std::vector<std::optional<MempoolAcceptResult>> AcceptToMemoryPoolStaged(
    ChainstateManager &chainman, const std::vector<CTransactionRef> &txs,
    const StagedAdmissionOptions &options, StagedAdmissionStats *stats) {
    AssertLockNotHeld(cs_main);
    const size_t n = txs.size();
    std::vector<std::optional<MempoolAcceptResult>> results(n);
    if (n == 0) {
        return results;
    }
    StagedAdmissionStats local;
    std::vector<PrecomputedAdmissionChecks> checks(n);
    std::vector<bool> verify(n, false);
    // Coins phase A brought into the coins cache, per transaction, so they
    // can be evicted again if that transaction is not admitted (as
    // AcceptToMemoryPool does for the coins it fetches).
    std::vector<std::vector<COutPoint>> fetched(n);
    uint32_t script_flags = 0;

    // Native entries are never eligible for legacy advisory precomputation.
    // Mixed batches retain ordinary staging; every batch still runs Phase C.
    const bool has_legacy = std::any_of(txs.begin(), txs.end(),
        [](const auto &tx) { return tx->nVersion != 7; });
    // Phase A: resolve spent outputs under the locks only when useful.
    if (has_legacy) {
        const auto start = SteadyClock::now();
        LOCK(cs_main);
        const auto acquired = SteadyClock::now();
        local.lock_wait += acquired - start;
        Chainstate &chainstate = chainman.ActiveChainstate();
        CTxMemPool *pool = chainstate.GetMempool();
        if (pool != nullptr) {
            script_flags = GetMempoolScriptFlags(chainstate);
            verify = MemPoolAccept(*pool, chainstate)
                         .PrepareStaged(txs, checks, fetched, script_flags,
                                        options.limits);
        }
        local.resolve_locked = SteadyClock::now() - acquired;
    }

    // Phase B: context-free and script checks, no locks held.
    std::vector<size_t> work;
    work.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        if (verify[i]) {
            work.push_back(i);
        }
    }
    local.precomputed = work.size();
    if (!work.empty()) {
        const auto start = SteadyClock::now();
        ValidationCache &validation_cache = chainman.m_validation_cache;
        std::atomic<size_t> next{0};
        const size_t threads =
            std::clamp<size_t>(options.script_threads, 1, work.size());
        ParallelScriptWorkerPool::Instance().Run(threads, [&](size_t) {
            for (size_t k = next.fetch_add(1, std::memory_order_relaxed);
                 k < work.size();
                 k = next.fetch_add(1, std::memory_order_relaxed)) {
                const size_t i = work[k];
                ComputeAdmissionChecks(*txs[i], script_flags, validation_cache,
                                       checks[i]);
            }
        });
        local.verify_unlocked = SteadyClock::now() - start;
    }

    if (options.test_between_phases) {
        options.test_between_phases();
    }

    // Phase C: ordinary admission, in order, reusing matching checks.
    {
        const auto start = SteadyClock::now();
        LOCK(cs_main);
        const auto acquired = SteadyClock::now();
        local.lock_wait += acquired - start;
        Chainstate &chainstate = chainman.ActiveChainstate();
        CTxMemPool *pool = chainstate.GetMempool();
        // Publish one mempool snapshot for the whole batch.
        std::optional<CTxMemPool::ScopedSnapshotDefer> defer;
        if (pool != nullptr) {
            LOCK(pool->cs);
            defer.emplace(*pool);
        }
        for (size_t i = 0; i < n; ++i) {
            if (options.skip_at_commit && options.skip_at_commit(txs[i])) {
                continue;
            }
            results[i].emplace(chainman.ProcessTransaction(
                txs[i], /*test_accept=*/false, options.limits,
                verify[i] ? &checks[i] : nullptr));
        }
        for (size_t i = 0; i < n; ++i) {
            if (!results[i] || results[i]->m_result_type !=
                                   MempoolAcceptResult::ResultType::VALID) {
                for (const COutPoint &outpoint : fetched[i]) {
                    chainstate.CoinsTip().Uncache(outpoint);
                }
            }
        }
        if (pool != nullptr) {
            LOCK(pool->cs);
            defer.reset();
        }
        local.commit_locked = SteadyClock::now() - acquired;
    }
    if (auto *metrics = node::GetNodeMetrics()) {
        metrics->mempool_admission_lock_hold_seconds.RecordDuration(
            local.resolve_locked + local.commit_locked);
        metrics->mempool_admission_lock_wait_seconds.RecordDuration(
            local.lock_wait);
        metrics->mempool_admission_verify_seconds.RecordDuration(
            local.verify_unlocked);
    }
    if (stats != nullptr) {
        *stats = local;
    }
    return results;
}

Amount GetBlockSubsidy(int nHeight, const Consensus::Params &consensusParams) {
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64) {
        return Amount::zero();
    }

    Amount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 blocks which will occur
    // approximately every 4 years.
    return ((nSubsidy / SATOSHI) >> halvings) * SATOSHI;
}

CoinsViews::CoinsViews(DBParams db_params, CoinsViewOptions options)
    : m_dbview{std::move(db_params), std::move(options)},
      m_catcherview(&m_dbview) {}

void CoinsViews::InitCache() {
    AssertLockHeld(::cs_main);
    m_cacheview = std::make_unique<CCoinsViewCache>(&m_catcherview);
    if (auto *metrics{node::GetNodeMetrics()}) {
        m_cacheview->SetLookupMetric(&metrics->utxo_cache_lookups);
    }
    m_connect_block_view = std::make_unique<CCoinsViewCache>(&*m_cacheview);
}

Chainstate::Chainstate(CTxMemPool *mempool, BlockManager &blockman,
                       ChainstateManager &chainman,
                       std::optional<BlockHash> from_snapshot_blockhash)
    : m_mempool(mempool), m_blockman(blockman), m_chainman(chainman),
      m_from_snapshot_blockhash(from_snapshot_blockhash) {}

const CBlockIndex *Chainstate::SnapshotBase() {
    if (!m_from_snapshot_blockhash) {
        return m_fast_sync_pivot_base;
    }
    if (!m_cached_snapshot_base) {
        m_cached_snapshot_base = Assert(
            m_chainman.m_blockman.LookupBlockIndex(*m_from_snapshot_blockhash));
    }
    return m_cached_snapshot_base;
}

bool Chainstate::IsSnapSyncEnabled() const {
    AssertLockHeld(::cs_main);
    const bool snap =
        m_snapsync_enabled_override.value_or(gArgs.GetBoolArg("-snapsync", true));
    const bool rev = m_reversesync_enabled_override.value_or(
        gArgs.GetBoolArg("-reversesync", true));
    return snap && rev;
}

bool Chainstate::IsReverseSyncEnabled() const {
    AssertLockHeld(::cs_main);
    return IsSnapSyncEnabled();
}

static bool ContextualCheckBlock(const CBlock &block, BlockValidationState &state,
                                 const ChainstateManager &chainman,
                                 const CBlockIndex *pindexPrev);

bool Chainstate::ActivateVerifiedFastSyncPivot(
    CBlockIndex *pindex_pivot,
    const std::vector<lotus::v2::Coin> &coins,
    const lotus::v2::MonetaryState &monetary_state,
    std::string &error) {
    AssertLockHeld(::cs_main);
    if (!IsSnapSyncEnabled()) { error = "snapsync disabled"; return false; }
    if (!pindex_pivot || !HasCoinsViews()) {
        error = "Missing pivot or coins view";
        return false;
    }
    lotus::v2::UtxoSet verified;
    std::vector<std::pair<COutPoint, ::Coin>> installed;
    installed.reserve(coins.size());
    for (const auto &coin : coins) {
        if (coin.creation_height > static_cast<uint64_t>(pindex_pivot->nHeight) ||
            !verified.Insert(coin)) {
            error = "Invalid or duplicate pivot coin";
            return false;
        }
        uint256 txid;
        std::copy(coin.outpoint.tx_id.begin(), coin.outpoint.tx_id.end(), txid.begin());
        installed.emplace_back(COutPoint{TxId{txid}, coin.outpoint.index},
            ::Coin{CTxOut::FromV2Output(coin.output), uint32_t(coin.creation_height),
                   coin.coinbase, coin.fee_per_output, coin.expiration_height});
    }
    const auto root = lotus::v2::StateRoot(GetActiveV2ChainId(),
        pindex_pivot->nHeight, verified.Root(), monetary_state);
    if (root != pindex_pivot->GetBlockHeader().ToV2Header().state_root) {
        error = "Pivot state does not match authenticated header";
        return false;
    }
    const BlockHash pivot_hash = pindex_pivot->GetBlockHash();
    // Persist the authenticated native snapshot before publishing the atomic
    // chainstate marker. An interruption before the marker leaves an unused
    // snapshot; after it, startup can reconstruct provisional history.
    if (!ImportV2BlockStateCoinsAndMonetary(pivot_hash, coins, monetary_state, true)) {
        error = "Failed to persist authenticated pivot state";
        return false;
    }
    uint256 marker_root;
    std::copy(root.begin(), root.end(), marker_root.begin());
    CoinsDB().InstallFastSyncSnapshot(pivot_hash, marker_root, installed);
    m_coins_views->InitCache();

    if (!pindex_pivot->IsValid(BlockValidity::SCRIPTS) ||
        !pindex_pivot->HaveNumChainTxs()) {
        m_fast_sync_pivot_base = pindex_pivot;
        if (!pindex_pivot->HaveNumChainTxs()) {
            pindex_pivot->m_chain_tx_count =
                static_cast<unsigned int>(pindex_pivot->nHeight + 1);
            m_blockman.m_dirty_blockindex.insert(pindex_pivot);
        }
    }

    if (m_chain.Tip() != pindex_pivot) {
        m_chain.SetTip(*pindex_pivot);
        setBlockIndexCandidates.insert(pindex_pivot);
        PruneBlockIndexCandidates();
        if (m_mempool) {
            LOCK(m_mempool->cs);
            m_mempool->ConnectBlockReset(
                pivot_hash, static_cast<uint64_t>(pindex_pivot->nHeight + 1),
                static_cast<uint64_t>(pindex_pivot->GetMedianTimePast()));
        }
        UpdateTip(pindex_pivot);
    } else if (m_mempool) {
        LOCK(m_mempool->cs);
        m_mempool->ConnectBlockReset(
            pivot_hash, static_cast<uint64_t>(pindex_pivot->nHeight + 1),
            static_cast<uint64_t>(pindex_pivot->GetMedianTimePast()));
    }

    ActivateFastSyncPivot(pindex_pivot->nHeight);
    node::PublishChainTipSnapshot(m_chainman, m_mempool);
    return true;
}

bool Chainstate::PeelFastSyncBlock(
    const BlockHash &block_hash,
    const lotus::v2::BlockUndoMessage &undo_msg,
    const CBlock *optional_block,
    FastSyncPeelResult &result_out,
    std::string &err_out) {
    AssertLockHeld(::cs_main);
    if (!IsReverseSyncEnabled()) { err_out = "reverse sync disabled"; return false; }
    if (!IsFastSyncActive()) {
        err_out = "Fast-sync reverse peeling is not active";
        return false;
    }

    CBlockIndex *pindex = m_blockman.LookupBlockIndex(block_hash);
    if (!pindex || pindex->nHeight <= 0 || !pindex->pprev) {
        err_out = "Valid non-genesis block not found";
        return false;
    }
    if (pindex->nHeight != GetEarliestVerifiedHeight()) {
        err_out = strprintf(
            "Block height %d does not match earliest_verified_height %d",
            pindex->nHeight, GetEarliestVerifiedHeight());
        return false;
    }

    lotus::v2::Hash expected_block_id{};
    std::memcpy(expected_block_id.data(), block_hash.begin(), 32);
    if (undo_msg.block_id != expected_block_id) {
        err_out = "BLOCKUNDO block_id mismatch";
        return false;
    }

    lotus::v2::MonetaryState parent_mon_state{};
    try {
        parent_mon_state = lotus::v2::DecodeMonetaryState(
            std::vector<uint8_t>(undo_msg.parent_monetary_state.begin(),
                                 undo_msg.parent_monetary_state.end()));
    } catch (const std::exception &e) {
        err_out = strprintf("Invalid parent_monetary_state: %s", e.what());
        return false;
    }

    CBlock disk_block;
    const CBlock *block_ptr = optional_block;
    if (block_ptr) {
        if (block_ptr->GetHash() != block_hash) {
            err_out = "Provided block hash does not match target block_hash";
            return false;
        }
    } else {
        if (!m_blockman.ReadBlock(disk_block, *pindex)) {
            err_out = "Failed to read block";
            return false;
        }
        block_ptr = &disk_block;
    }
    const CBlock &block = *block_ptr;
    BlockValidationState blk_state;
    if (!CheckBlock(*block_ptr, blk_state,
            m_chainman.GetConsensus(),
            BlockValidationOptions(m_chainman.GetConfig()))) {
        err_out = strprintf("Invalid block in reverse peel: %s",
                blk_state.ToString());
        return false;
    }

    BlockValidationState contextual_state;
    if (!ContextualCheckBlock(block, contextual_state, m_chainman, pindex->pprev)) {
        err_out = "Invalid peeled block context: " + contextual_state.ToString();
        return false;
    }

    std::vector<lotus::v2::Coin> current_coins;
    lotus::v2::MonetaryState current_mon_state{};
    if (!GetV2BlockStateCoinsAndMonetary(
            block_hash, static_cast<uint64_t>(pindex->nHeight), current_coins,
            current_mon_state)) {
        err_out = "Current block V2 state not found";
        return false;
    }
    lotus::v2::UtxoSet current_utxo;
    for (const auto &c : current_coins) {
        if (!current_utxo.Insert(c)) {
            err_out = "Failed to populate current UTXO set";
            return false;
        }
    }

    const uint64_t height = static_cast<uint64_t>(pindex->nHeight);
    const uint64_t parent_mtp =
        static_cast<uint64_t>(pindex->pprev->GetMedianTimePast());

    struct V2OutpointLess {
        bool operator()(const lotus::v2::Outpoint &a,
                        const lotus::v2::Outpoint &b) const {
            if (a.tx_id != b.tx_id) {
                return a.tx_id < b.tx_id;
            }
            return a.index < b.index;
        }
    };

    std::map<lotus::v2::Outpoint, lotus::v2::Coin, V2OutpointLess>
        created_coins;
    std::map<lotus::v2::Outpoint, size_t, V2OutpointLess> created_tx_index;
    for (size_t tx_i = 0; tx_i < block.vtx.size(); ++tx_i) {
        const CTransaction &tx = *block.vtx[tx_i];
        lotus::v2::Hash txid{};
        std::memcpy(txid.data(), tx.GetId().begin(), 32);
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            if (tx.vout[j].scriptPubKey.IsUnspendable()) {
                continue;
            }
            const lotus::v2::Output v2out = tx.vout[j].ToV2Output();
            if (!v2out.IsBurn()) {
                const lotus::v2::Outpoint op{txid, static_cast<uint32_t>(j)};
                lotus::v2::Coin coin{op, v2out, height, parent_mtp,
                                     tx.IsCoinBase()};
                created_coins.emplace(op, std::move(coin));
                created_tx_index.emplace(op, tx_i);
            }
        }
    }

    std::set<lotus::v2::Outpoint, V2OutpointLess> all_spent;
    std::set<lotus::v2::Outpoint, V2OutpointLess> intra_spent;
    std::vector<lotus::v2::Outpoint> prior_spent_order;
    for (size_t tx_i = 0; tx_i < block.vtx.size(); ++tx_i) {
        const CTransaction &tx = *block.vtx[tx_i];
        if (tx.IsCoinBase()) {
            continue;
        }
        for (const auto &txin : tx.vin) {
            if (txin.nFlags == 3) {
                continue;
            }
            lotus::v2::Outpoint op{};
            std::memcpy(op.tx_id.data(), txin.prevout.GetTxId().begin(), 32);
            op.index = txin.prevout.GetN();
            if (!all_spent.insert(op).second) {
                err_out = "Duplicate input outpoint in block";
                return false;
            }
            auto it_created = created_tx_index.find(op);
            if (it_created != created_tx_index.end()) {
                if (it_created->second == tx_i) {
                    err_out = "Invalid intra-block self-spend";
                    return false;
                }
                intra_spent.insert(op);
            } else {
                prior_spent_order.push_back(op);
            }
        }
    }

    if (undo_msg.prior_spent_coins.size() != prior_spent_order.size()) {
        err_out =
            "BLOCKUNDO prior_spent_coins count does not match prior_spent";
        return false;
    }
    for (size_t i = 0; i < undo_msg.prior_spent_coins.size(); ++i) {
        const auto &coin = undo_msg.prior_spent_coins[i];
        std::vector<uint8_t> encoded_coin;
        if (!(coin.outpoint == prior_spent_order[i]) ||
            !lotus::v2::EncodeCoin(coin, encoded_coin) ||
            coin.output.IsBurn() || coin.creation_height >= height) {
            err_out = "Invalid coin in BLOCKUNDO prior_spent_coins";
            return false;
        }
    }

    // Reconstruct paid lifetime metadata from actual input values, including
    // intra-block parents that appear later in CTOR order.
    std::map<lotus::v2::Outpoint, const lotus::v2::Coin *, V2OutpointLess> prior_coins;
    for (const auto &coin : undo_msg.prior_spent_coins) prior_coins.emplace(coin.outpoint, &coin);
    for (const auto &transaction : block.vtx) {
        uint64_t input_value = 0, output_value = 0;
        size_t spendable_outputs = 0;
        if (!transaction->IsCoinBase()) {
            for (const auto &input : transaction->vin) {
                if (input.nFlags == 3) continue;
                lotus::v2::Outpoint op{};
                std::copy_n(input.prevout.GetTxId().begin(), 32, op.tx_id.begin());
                op.index = input.prevout.GetN();
                const auto created = created_coins.find(op);
                const auto prior = prior_coins.find(op);
                const auto *coin = created != created_coins.end() ? &created->second :
                                   prior != prior_coins.end() ? prior->second : nullptr;
                if (!coin) { err_out = "Missing input for peeled fee metadata"; return false; }
                if (!coin->output.HasToken()) input_value += coin->output.value;
            }
        }
        for (const auto &output : transaction->vout) {
            if (output.scriptPubKey.IsUnspendable()) continue;
            const auto native = output.ToV2Output();
            if (!native.HasToken()) output_value += native.value;
            if (!native.IsBurn()) ++spendable_outputs;
        }
        const auto fee_share = transaction->IsCoinBase() ? 0 :
            lotus::v2::ComputeTxFeePerSpendableOutput(
                input_value >= output_value ? input_value - output_value : 0, spendable_outputs);
        lotus::v2::Hash id{};
        std::copy_n(transaction->GetId().begin(), 32, id.begin());
        for (size_t index = 0; index < transaction->vout.size(); ++index) {
            const auto created = created_coins.find({id, uint32_t(index)});
            if (created == created_coins.end()) continue;
            created->second.fee_per_output = fee_share;
            created->second.expiration_height = lotus::v2::ComputeUtxoExpirationHeight(
                height, created->second.coinbase, fee_share);
        }
    }

    std::map<lotus::v2::Outpoint, lotus::v2::Coin, V2OutpointLess> current_view;
    for (const auto &c : current_utxo.Coins()) {
        current_view.emplace(c.outpoint, c);
    }
    lotus::v2::UtxoSet parent_utxo = current_utxo;
    for (const auto &intra_op : intra_spent) {
        if (current_view.count(intra_op) > 0) {
            err_out = "Intra-block spent coin present in end-of-block UTXO";
            return false;
        }
    }
    size_t net_outputs_removed = 0;
    for (const auto &[op, expected_coin] : created_coins) {
        if (intra_spent.count(op) > 0) {
            continue;
        }
        const auto it_actual = current_view.find(op);
        std::vector<uint8_t> b1, b2;
        if (it_actual == current_view.end() ||
            !lotus::v2::EncodeCoin(it_actual->second, b1) ||
            !lotus::v2::EncodeCoin(expected_coin, b2) || b1 != b2) {
            err_out = "Net block output missing or mismatched in UTXO_h";
            return false;
        }
        if (!parent_utxo.Erase(op)) {
            err_out = "Failed to remove net block output";
            return false;
        }
        ++net_outputs_removed;
    }
    for (const auto &coin : undo_msg.prior_spent_coins) {
        if (current_view.count(coin.outpoint) > 0 ||
            !parent_utxo.Insert(coin)) {
            err_out = "Failed to restore prior-block spent coin";
            return false;
        }
    }
    for (const auto &coin : undo_msg.expired_swept_coins) {
        std::vector<uint8_t> encoded_coin;
        if (current_view.count(coin.outpoint) > 0 ||
            !lotus::v2::EncodeCoin(coin, encoded_coin) ||
            coin.output.IsBurn() ||
            !lotus::v2::IsUtxoExpired(coin, height) ||
            !parent_utxo.Insert(coin)) {
            err_out = "Failed to restore expired swept coin";
            return false;
        }
    }

    CBlockIndex *parent_index = pindex->pprev;
    const lotus::v2::Header parent_hdr =
        parent_index->GetBlockHeader().ToV2Header();
    const lotus::v2::Hash expected_parent_state_root = lotus::v2::StateRoot(
        GetActiveV2ChainId(), static_cast<uint64_t>(parent_index->nHeight),
        parent_utxo.Root(), parent_mon_state);
    if (expected_parent_state_root != parent_hdr.state_root) {
        err_out = "Peeled parent StateRoot mismatch against parent header";
        return false;
    }

    const lotus::v2::MonetaryState expected_current_mon =
        AdvanceV2BlockMonetaryState(block, parent_mon_state);
    if (lotus::v2::EncodeMonetaryState(expected_current_mon) !=
        lotus::v2::EncodeMonetaryState(current_mon_state)) {
        err_out = "Forward monetary transition mismatch from parent state";
        return false;
    }

    // Forward-verify all transaction inputs, sequence locks, fees, scripts,
    // and locally construct CBlockUndo from the StateRoot-authenticated parent
    // coins before persisting rev*.dat.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache parent_view(&coins_dummy);
        parent_view.SetBestBlock(parent_index->GetBlockHash());
        for (const auto &sc : undo_msg.prior_spent_coins) {
            const COutPoint outp(TxId(uint256(Span<const uint8_t>(
                                     sc.outpoint.tx_id.data(), 32))),
                                 sc.outpoint.index);
            parent_view.AddCoin(
                outp,
                Coin(CTxOut::FromV2Output(sc.output),
                     static_cast<uint32_t>(sc.creation_height), sc.coinbase,
                     sc.fee_per_output, sc.expiration_height),
                /*possible_overwrite=*/false);
        }
        for (const auto &ec : undo_msg.expired_swept_coins) {
            const COutPoint outp(TxId(uint256(Span<const uint8_t>(
                                     ec.outpoint.tx_id.data(), 32))),
                                 ec.outpoint.index);
            parent_view.AddCoin(
                outp,
                Coin(CTxOut::FromV2Output(ec.output),
                     static_cast<uint32_t>(ec.creation_height), ec.coinbase,
                     ec.fee_per_output, ec.expiration_height),
                /*possible_overwrite=*/false);
        }
        try {
            for (const auto &ptx : block.vtx) {
                AddCoins(parent_view, *ptx, pindex->nHeight);
            }
        } catch (const std::logic_error &) {
            err_out = "Duplicate transaction output overwrite in peeled block";
            return false;
        }

        const Consensus::Params &consensusParams =
            m_chainman.GetParams().GetConsensus();
        int nLockTimeFlags = 0;
        if (DeploymentActiveAt(*pindex, consensusParams,
                               Consensus::DEPLOYMENT_CSV)) {
            nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
        }
        const uint32_t script_flags =
            GetNextBlockScriptFlags(parent_index, m_chainman);
        const bool fEnforceSigCheck =
            (script_flags & SCRIPT_ENFORCE_SIGCHECKS) != 0;
        CheckInputsLimiter sigchecks_block_limiter(
            GetMaxBlockSigChecksCount(DEFAULT_MAX_BLOCK_SIZE));

        CBlockUndo blockundo;
        if (!block.vtx.empty()) {
            blockundo.vtxundo.resize(block.vtx.size() - 1);
        }
        Amount nFees = Amount::zero();
        std::vector<int> prevheights;
        size_t tx_undo_idx = 0;

        for (const auto &ptx : block.vtx) {
            const CTransaction &tx = *ptx;
            if (tx.IsCoinBase()) {
                continue;
            }
            Amount txfee = Amount::zero();
            TxValidationState tx_state;
            if (!Consensus::CheckTxInputs(tx, tx_state, parent_view,
                                          pindex->nHeight, txfee)) {
                err_out = "Forward input check failed on peeled block: " +
                          tx_state.ToString();
                return false;
            }
            nFees += txfee;
            if (!MoneyRange(nFees)) {
                err_out = "Accumulated fee out of range in peeled block";
                return false;
            }

            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); ++j) {
                prevheights[j] =
                    (tx.vin[j].nFlags == 3 ||
                     (tx.vin[j].nSequence &
                      CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG))
                        ? 0
                        : parent_view.AccessCoin(tx.vin[j].prevout).GetHeight();
            }
            if (!SequenceLocks(tx, nLockTimeFlags, prevheights, *pindex)) {
                err_out = "Non-BIP68-final transaction in peeled block";
                return false;
            }

            PrecomputedTransactionData txdata(tx);
            TxSigCheckLimiter tx_sigcheck_limiter =
                fEnforceSigCheck ? TxSigCheckLimiter()
                                 : TxSigCheckLimiter::getDisabled();
            int nSigChecksTx = 0;
            if (!CheckInputScripts(tx, tx_state, parent_view, script_flags,
                                   /*cacheSigStore=*/false,
                                   /*cacheFullScriptStore=*/false, txdata,
                                   m_chainman.m_validation_cache, nSigChecksTx,
                                   tx_sigcheck_limiter, &sigchecks_block_limiter,
                                   /*pvChecks=*/nullptr)) {
                err_out = "Forward script verification failed on peeled block: " +
                          tx_state.ToString();
                return false;
            }

            SpendCoins(parent_view, tx, blockundo.vtxundo.at(tx_undo_idx),
                       pindex->nHeight);
            ++tx_undo_idx;
        }

        auto swept_peeled = parent_view.SweepExpiredCoins(height);
        blockundo.vexpired.reserve(swept_peeled.size());
        for (auto &[op, coin] : swept_peeled) {
            blockundo.vexpired.push_back(ExpiredCoinUndo{op, std::move(coin)});
        }
        const uint64_t bounty_atoms = lotus::v2::ComputeCleaningCrewBounty(
            swept_peeled.size(),
            static_cast<uint64_t>(std::max<int64_t>(0, nFees / SATOSHI)));
        const Amount cleaningBounty =
            static_cast<int64_t>(bounty_atoms) * SATOSHI;

        const Amount blockReward =
            nFees + GetBlockSubsidy(pindex->nHeight, consensusParams) +
            cleaningBounty;
        if (!block.vtx.empty() && block.vtx[0]->GetValueOut() > blockReward) {
            err_out = "Coinbase pays too much in peeled block";
            return false;
        }

        if (!pindex->nStatus.hasUndo()) {
            BlockValidationState undo_state;
            if (!m_blockman.WriteBlockUndo(blockundo, undo_state, *pindex)) {
                err_out = "Failed to write local CBlockUndo for peeled block";
                return false;
            }
        }
    }

    if (!ImportV2BlockStateCoinsAndMonetary(parent_index->GetBlockHash(),
                                          parent_utxo.Coins(), parent_mon_state,
                                          /*is_tip=*/false)) {
        err_out = "Failed to persist authenticated peeled parent state";
        return false;
    }
    // Update block storage and CBlockIndex accounting for the peeled block
    // and step m_fast_sync_pivot_base / m_chain_tx_count backwards.
    if (!pindex->nStatus.hasData()) {
        FlatFilePos blockPos = m_blockman.WriteBlock(block, pindex->nHeight);
        if (blockPos.IsNull()) {
            err_out = "Failed to store reverse-verified block";
            return false;
        }
        pindex->nFile = blockPos.nFile;
        pindex->nDataPos = blockPos.nPos;
        pindex->nSize = ::GetSerializeSize(block);
        pindex->nStatus = pindex->nStatus.withData();
    }
    if (pindex->nTx == 0) {
        pindex->nTx = block.vtx.size();
    }
    pindex->RaiseValidity(BlockValidity::TRANSACTIONS);
    // Parent commitments authenticate the reconstruction; complete execution
    // provenance is established only after peeling reaches genesis.
    m_blockman.m_dirty_blockindex.insert(pindex);
    // Publish progress only after the historical body/index and authenticated
    // predecessor snapshot exist. An interrupted earlier attempt can be replayed.
    if (!m_blockman.FlushBlockFile(pindex->nFile, false, false)) {
        err_out = "Failed to flush reverse-verified block";
        return false;
    }
    m_blockman.WriteBlockIndexDB();
    if (parent_index->nHeight > 0) {
        uint256 root;
        const auto parent_root = parent_index->GetBlockHeader().ToV2Header().state_root;
        std::copy(parent_root.begin(), parent_root.end(), root.begin());
        CoinsDB().SetFastSyncProgress(parent_index->GetBlockHash(), root);
    }
    if (!RecordReversePeeledBlock(parent_index->nHeight)) {
        err_out = "Failed to update earliest_verified_height";
        return false;
    }

    if (parent_index->nHeight == 0) {
        m_fast_sync_pivot_base = nullptr;
        for (int h_idx = 1; h_idx <= m_chain.Height(); ++h_idx) {
            CBlockIndex *blk = m_chain[h_idx];
            if (blk && blk->nTx > 0 && blk->pprev &&
                blk->pprev->m_chain_tx_count > 0) {
                blk->m_chain_tx_count =
                    blk->pprev->m_chain_tx_count + blk->nTx;
                blk->RaiseValidity(BlockValidity::SCRIPTS);
                m_blockman.m_dirty_blockindex.insert(blk);
            }
        }
        m_blockman.WriteBlockIndexDB();
        CoinsDB().ClearFastSyncSnapshot();
    }

    node::PublishChainTipSnapshot(m_chainman, m_mempool);

    result_out.peeled_blockhash = block_hash;
    result_out.parent_blockhash = parent_index->GetBlockHash();
    result_out.parent_height = parent_index->nHeight;
    result_out.earliest_verified_height = GetEarliestVerifiedHeight();
    result_out.fast_sync_active = IsFastSyncActive();
    result_out.intra_block_spends = intra_spent.size();
    result_out.prior_spends_restored = undo_msg.prior_spent_coins.size();
    result_out.net_outputs_removed = net_outputs_removed;
    err_out.clear();
    return true;
}

void Chainstate::InitCoinsDB(size_t cache_size_bytes, bool in_memory,
                             bool should_wipe, std::string leveldb_name) {
    if (m_from_snapshot_blockhash) {
        leveldb_name += node::SNAPSHOT_CHAINSTATE_SUFFIX;
    }

    SetV2StatePersistDir(
        in_memory ? std::string{}
                  : fs::PathToString(m_chainman.m_options.datadir / "v2_state"));
    const CBlock &genesis = m_chainman.GetParams().GenesisBlock();
    RecordV2BlockState(genesis, genesis.GetHash(), BlockHash(), 0, 0);

    m_coins_views = std::make_unique<CoinsViews>(
        DBParams{.path = m_chainman.m_options.datadir / leveldb_name,
                 .cache_bytes = cache_size_bytes,
                 .memory_only = in_memory,
                 .wipe_data = should_wipe,
                 .obfuscate = true,
                 .options = m_chainman.m_options.coins_db},
        m_chainman.m_options.coins_view);
}

void Chainstate::InitCoinsCache(size_t cache_size_bytes) {
    AssertLockHeld(::cs_main);
    assert(m_coins_views != nullptr);
    m_coinstip_cache_size_bytes = cache_size_bytes;
    m_coins_views->InitCache();
}

// Note that though this is marked const, we may end up modifying
// `m_cached_finished_ibd`, which is a performance-related implementation
// detail. This function must be marked `const` so that `CValidationInterface`
// clients (which are given a `const Chainstate*`) can call it.
//
bool ChainstateManager::IsInitialBlockDownload() const {
    // Optimization: pre-test latch before taking the lock.
    if (m_cached_finished_ibd.load(std::memory_order_relaxed)) {
        return false;
    }

    LOCK(cs_main);
    if (m_cached_finished_ibd.load(std::memory_order_relaxed)) {
        return false;
    }
    if (m_blockman.LoadingBlocks()) {
        return true;
    }
    CChain &chain{ActiveChain()};
    if (chain.Tip() == nullptr) {
        return true;
    }
    if (chain.Tip()->nChainWork < MinimumChainWork()) {
        return true;
    }
    if (chain.Tip()->Time() < Now<NodeSeconds>() - m_options.max_tip_age) {
        return true;
    }
    LogInfoEvent(BCLog::ALL, "initial_download_finished",
                 "Leaving InitialBlockDownload (latching to false)");
    m_cached_finished_ibd.store(true, std::memory_order_relaxed);
    if (auto *metrics{node::GetNodeMetrics()}) {
        metrics->initial_block_download.Set(0);
    }
    return false;
}

void Chainstate::CheckForkWarningConditions() {
    AssertLockHeld(cs_main);

    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial
    // sync)
    // Also not applicable to the background chainstate
    if (m_chainman.IsInitialBlockDownload() ||
        this->GetRole() == ChainstateRole::BACKGROUND) {
        return;
    }

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one
    // mines it) of our head, or if it is back on the active chain, drop it
    if (m_best_fork_tip && (m_chain.Height() - m_best_fork_tip->nHeight >= 72 ||
                            m_chain.Contains(m_best_fork_tip))) {
        m_best_fork_tip = nullptr;
    }

    if (m_best_fork_tip ||
        (m_chainman.m_best_invalid &&
         m_chainman.m_best_invalid->nChainWork >
             m_chain.Tip()->nChainWork + (GetBlockProof(*m_chain.Tip()) * 6))) {
        if (!GetfLargeWorkForkFound() && m_best_fork_base) {
            std::string warning =
                std::string("'Warning: Large-work fork detected, forking after "
                            "block ") +
                m_best_fork_base->phashBlock->ToString() + std::string("'");
            m_chainman.GetNotifications().warning(warning);
        }

        if (m_best_fork_tip && m_best_fork_base) {
            LogInfoEvent(BCLog::ALL, "chain_large_fork_detected",
                     "{source_function}: Warning: Large fork found\n  forking the chain at height {fork_base_height} ({fork_base_hash})\n  lasting to height {fork_tip_height} ({fork_tip_hash}).\nChain state database corruption likely.")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::ForkBaseHeight, m_best_fork_base->nHeight)
            .Field(BCLog::LogField::ForkBaseHash, m_best_fork_base->GetBlockHash())
            .Field(BCLog::LogField::ForkTipHeight, m_best_fork_tip->nHeight)
            .Field(BCLog::LogField::ForkTipHash, m_best_fork_tip->GetBlockHash());
            SetfLargeWorkForkFound(true);
        } else {
            LogInfoEvent(BCLog::ALL, "chain_large_invalid_fork_detected",
                     "{source_function}: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.")
            .Field(BCLog::LogField::SourceFunction, __func__);
            SetfLargeWorkInvalidChainFound(true);
        }
    } else {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

void Chainstate::CheckForkWarningConditionsOnNewFork(
    CBlockIndex *pindexNewForkTip) {
    AssertLockHeld(cs_main);

    // If we are on a fork that is sufficiently large, set a warning flag.
    const CBlockIndex *pfork = m_chain.FindFork(pindexNewForkTip);

    // We define a condition where we should warn the user about as a fork of at
    // least 7 blocks with a tip within 72 blocks (+/- 12 hours if no one mines
    // it) of ours. We use 7 blocks rather arbitrarily as it represents just
    // under 10% of sustained network hash rate operating on the fork, or a
    // chain that is entirely longer than ours and invalid (note that this
    // should be detected by both). We define it this way because it allows us
    // to only store the highest fork tip (+ base) which meets the 7-block
    // condition and from this always have the most-likely-to-cause-warning fork
    if (pfork &&
        (!m_best_fork_tip ||
         pindexNewForkTip->nHeight > m_best_fork_tip->nHeight) &&
        pindexNewForkTip->nChainWork - pfork->nChainWork >
            (GetBlockProof(*pfork) * 7) &&
        m_chain.Height() - pindexNewForkTip->nHeight < 72) {
        m_best_fork_tip = pindexNewForkTip;
        m_best_fork_base = pfork;
    }

    CheckForkWarningConditions();
}

// Called both upon regular invalid block discovery *and* InvalidateBlock
void Chainstate::InvalidChainFound(CBlockIndex *pindexNew) {
    AssertLockHeld(cs_main);
    if (!m_chainman.m_best_invalid ||
        pindexNew->nChainWork > m_chainman.m_best_invalid->nChainWork) {
        m_chainman.m_best_invalid = pindexNew;
    }
    SetBlockFailureFlags(pindexNew);
    if (m_chainman.m_best_header != nullptr &&
        m_chainman.m_best_header->GetAncestor(pindexNew->nHeight) ==
            pindexNew) {
        m_chainman.RecalculateBestHeader();
    }

    // If the invalid chain found is supposed to be finalized, we need to move
    // back the finalization point.
    if (IsBlockAvalancheFinalized(pindexNew)) {
        LOCK(cs_avalancheFinalizedBlockIndex);
        m_avalancheFinalizedBlockIndex = pindexNew->pprev;
    }

    LogInfoEvent(BCLog::ALL, "chain_invalid_block",
                     "{source_function}: invalid block={block_hash}  height={height}  log2_work={log2_work:f}  date={block_time}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::BlockHash, pindexNew->GetBlockHash())
            .Field(BCLog::LogField::Height, pindexNew->nHeight)
            .Field(BCLog::LogField::Log2Work, log(pindexNew->nChainWork.getdouble()) / log(2.0))
            .Field(BCLog::LogField::BlockTime, FormatISO8601DateTime(pindexNew->GetBlockTime()));
    CBlockIndex *tip = m_chain.Tip();
    assert(tip);
    LogInfoEvent(BCLog::ALL, "chain_invalid_current_best",
                     "{source_function}:  current best={block_hash}  height={height}  log2_work={log2_work:f}  date={block_time}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::BlockHash, tip->GetBlockHash())
            .Field(BCLog::LogField::Height, m_chain.Height())
            .Field(BCLog::LogField::Log2Work, log(tip->nChainWork.getdouble()) / log(2.0))
            .Field(BCLog::LogField::BlockTime, FormatISO8601DateTime(tip->GetBlockTime()));
}

// Same as InvalidChainFound, above, except not called directly from
// InvalidateBlock, which does its own setBlockIndexCandidates management.
void Chainstate::InvalidBlockFound(CBlockIndex *pindex,
                                   const BlockValidationState &state) {
    AssertLockHeld(cs_main);
    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
        if (auto *metrics{node::GetNodeMetrics()}) {
            metrics->blocks_invalid.Add(/*validation=*/0);
        }
        pindex->nStatus = pindex->nStatus.withFailed();
        m_chainman.m_failed_blocks.insert(pindex);
        m_blockman.m_dirty_blockindex.insert(pindex);
        InvalidChainFound(pindex);
    }
}

void SpendCoins(CCoinsViewCache &view, const CTransaction &tx, CTxUndo &txundo,
                int nHeight) {
    // Mark inputs spent.
    if (tx.IsCoinBase()) {
        return;
    }

    txundo.vprevout.reserve(tx.vin.size());
    for (const CTxIn &txin : tx.vin) {
        if (txin.nFlags == 3) {
            txundo.vprevout.emplace_back(CTxOut(Amount::zero(), CScript()), 1,
                                         false);
            continue;
        }
        txundo.vprevout.emplace_back();
        bool is_spent = view.SpendCoin(txin.prevout, &txundo.vprevout.back());
        assert(is_spent);
    }
}

void UpdateCoins(CCoinsViewCache &view, const CTransaction &tx, CTxUndo &txundo,
                 int nHeight) {
    SpendCoins(view, tx, txundo, nHeight);
    AddCoins(view, tx, nHeight);
}

std::optional<std::vector<Coin>>
GetSpentCoins(const CTransactionRef &ptx, const CCoinsViewCache &coins_view) {
    std::vector<Coin> spent_coins;
    spent_coins.reserve(ptx->vin.size());
    for (const CTxIn &input : ptx->vin) {
        if (input.nFlags == 3) {
            spent_coins.emplace_back(CTxOut(Amount::zero(), CScript()), 1,
                                     false);
            continue;
        }
        auto coin{coins_view.GetCoin(input.prevout)};
        if (!coin.has_value()) {
            return std::nullopt;
        }
        spent_coins.push_back(std::move(*coin));
    }
    return spent_coins;
}

std::optional<std::pair<ScriptError, std::string>> CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    ScriptError error{ScriptError::UNKNOWN};
    auto make_debug_str = [&]() {
        return strprintf("input %i of %s, spending %s:%i", nIn,
                         ptxTo->GetId().ToString(),
                         ptxTo->vin[nIn].prevout.GetTxId().ToString(),
                         ptxTo->vin[nIn].prevout.GetN());
    };
    if (ptxTo->vin[nIn].nFlags == 1 || ptxTo->vin[nIn].nFlags == 3) {
        if (ptxTo->vin[nIn].vWitnesses.empty()) {
            return std::make_pair(ScriptError::EVAL_FALSE, make_debug_str());
        }
        if (!m_resolved_coins && ptxTo->nVersion == 7 &&
            ptxTo->vin[nIn].nFlags == 1 && ptxTo->vin[nIn].nPathIndex == 0 &&
            ptxTo->vin[nIn].vWitnesses.size() == 1 &&
            ptxTo->vin[nIn].vWitnesses[0].siblings.empty() &&
            ptxTo->vin[nIn].vWitnesses[0].script.size() == 1 &&
            ptxTo->vin[nIn].vWitnesses[0].script[0] == 0x4e &&
            ptxTo->vin[nIn].vWitnesses[0].arguments.empty() &&
            (m_tx_out.nFlags & 0x02U) == 0) {
            static const lotus::v2::Hash kOpTrueBranchLeaf =
                lotus::v2::BranchLeaf(std::array<uint8_t, 1>{0x4e});
            if (m_tx_out.nFlags == 0 && m_tx_out.vBranches.size() == 1 &&
                m_tx_out.vPaths.size() == 1 &&
                m_tx_out.vPaths[0].size() == 1 &&
                m_tx_out.vPaths[0][0] == 0 &&
                m_tx_out.vBranches[0] == kOpTrueBranchLeaf) {
                return std::nullopt;
            }
            if (m_tx_out.scriptPubKey.size() == 45 &&
                m_tx_out.scriptPubKey[0] == 0x00 &&
                m_tx_out.scriptPubKey[9] == 0x01 &&
                m_tx_out.scriptPubKey[42] == 0x01 &&
                m_tx_out.scriptPubKey[43] == 0x01 &&
                m_tx_out.scriptPubKey[44] == 0x00 &&
                std::memcmp(m_tx_out.scriptPubKey.data() + 10,
                            kOpTrueBranchLeaf.data(), 32) == 0) {
                return std::nullopt;
            }
        }

        static constexpr lotus::v2::VmProfile kDefaultVmProfile{
            10000, 65535, 8192, 1000, 1000, 65536, 64, 1000000};
        static const lotus::v2::VmCostProfile kDefaultVmCost = []() {
            lotus::v2::VmCostProfile c{};
            c.max_invocation_cost = 1000000;
            c.structural_byte_cost = 1;
            for (auto &op : c.opcode) {
                op.base = 1;
            }
            return c;
        }();

        struct CachedPreparedVm {
            const CTransaction *tx_ptr{nullptr};
            TxHash tx_hash{};
            std::weak_ptr<const V2ResolvedCoins> resolved_wp;
            lotus::v2::Transaction v2tx;
            lotus::v2::PreparedVmTransaction prepared_vm;
            lotus::v2::SigningPreparationStatus status{
                lotus::v2::SigningPreparationStatus::InvalidWitness};
        };
        thread_local CachedPreparedVm tl_cache;

        lotus::v2::ResolvedCoins fallback_resolved;
        const lotus::v2::Transaction *v2tx_ptr = nullptr;
        lotus::v2::PreparedVmTransaction *prepared_vm_ptr = nullptr;
        lotus::v2::Transaction local_v2tx;
        lotus::v2::PreparedVmTransaction local_prepared_vm;

        auto extract_known_v2_ids = [&](lotus::v2::IdentityDigests &ids) {
            std::memcpy(ids.txid.data(), ptxTo->GetId().begin(), 32);
            std::memcpy(ids.txhash.data(), ptxTo->GetHash().begin(), 32);
            std::memcpy(ids.outputs_root.data(),
                        ptxTo->GetOutputsHash().begin(), 32);
            if (ptxTo->nVersion != 7) {
                ids.txid[0] ^= uint8_t(ptxTo->nVersion & 0xffU);
                ids.txhash[0] ^= uint8_t(ptxTo->nVersion & 0xffU);
            }
        };

        if (m_resolved_coins) {
            if (tl_cache.tx_ptr != ptxTo ||
                tl_cache.tx_hash != ptxTo->GetHash() ||
                tl_cache.resolved_wp.lock() != m_resolved_coins) {
                tl_cache.tx_ptr = ptxTo;
                tl_cache.tx_hash = ptxTo->GetHash();
                tl_cache.resolved_wp = m_resolved_coins;
                tl_cache.v2tx = ptxTo->ToV2Transaction();
                lotus::v2::IdentityDigests precomputed_ids{};
                extract_known_v2_ids(precomputed_ids);
                std::string prep_err;
                tl_cache.status = tl_cache.prepared_vm.PrepareChecked(
                    tl_cache.v2tx, lotus::v2::DefaultTxProfile,
                    GetActiveV2ChainId(), *m_resolved_coins, kDefaultVmCost,
                    prep_err, &precomputed_ids);
            }
            if (tl_cache.status != lotus::v2::SigningPreparationStatus::Ready) {
                return std::make_pair(ScriptError::EVAL_FALSE,
                                      make_debug_str());
            }
            v2tx_ptr = &tl_cache.v2tx;
            prepared_vm_ptr = &tl_cache.prepared_vm;
        } else {
            local_v2tx = ptxTo->ToV2Transaction();
            fallback_resolved.resize(local_v2tx.inputs.size());
            if (ptxTo->vin[nIn].nFlags == 1 && nIn < fallback_resolved.size()) {
                fallback_resolved[nIn] = m_tx_out.ToV2Output();
            }
            lotus::v2::IdentityDigests precomputed_ids{};
            extract_known_v2_ids(precomputed_ids);
            std::string prep_err;
            if (local_prepared_vm.PrepareChecked(
                    local_v2tx, lotus::v2::DefaultTxProfile,
                    GetActiveV2ChainId(), fallback_resolved, kDefaultVmCost,
                    prep_err, &precomputed_ids) !=
                lotus::v2::SigningPreparationStatus::Ready) {
                return std::make_pair(ScriptError::EVAL_FALSE,
                                      make_debug_str());
            }
            v2tx_ptr = &local_v2tx;
            prepared_vm_ptr = &local_prepared_vm;
        }

        const lotus::v2::Transaction &v2tx = *v2tx_ptr;
        lotus::v2::PreparedVmTransaction &prepared_vm = *prepared_vm_ptr;
        const lotus::v2::ResolvedCoins &resolved =
            m_resolved_coins ? *m_resolved_coins : fallback_resolved;

        if (ptxTo->vin[nIn].nFlags == 1) {
            if (nIn >= resolved.size() || !resolved[nIn].has_value()) {
                return std::make_pair(ScriptError::EVAL_FALSE,
                                      make_debug_str());
            }
            const lotus::v2::Output &v2out = *resolved[nIn];
            if (ptxTo->vin[nIn].nPathIndex >= v2out.paths.size()) {
                return std::make_pair(ScriptError::EVAL_FALSE,
                                      make_debug_str());
            }
            const auto &path = v2out.paths[ptxTo->vin[nIn].nPathIndex];
            if (path.size() != ptxTo->vin[nIn].vWitnesses.size()) {
                return std::make_pair(ScriptError::EVAL_FALSE,
                                      make_debug_str());
            }
            for (size_t j = 0; j < path.size(); ++j) {
                const auto &w = ptxTo->vin[nIn].vWitnesses[j];
                auto ctx = prepared_vm.Invocation(nIn, j, {}, m_sig_collector);
                ctx.effects = m_v2_effects;
                const lotus::v2::VmChargedResult vm_res =
                    lotus::v2::EvaluateVmCharged(
                        w.script, w.arguments, kDefaultVmProfile,
                        prepared_vm.Cost(),
                        static_cast<uint16_t>(v2tx.inputs.size()),
                        static_cast<uint16_t>(v2tx.outputs.size()), &ctx);
                if ((vm_res.invocation.status != lotus::v2::VmStatus::Success &&
                     vm_res.invocation.status !=
                         lotus::v2::VmStatus::AutomaticSuccess) ||
                    !vm_res.charged) {
                    return std::make_pair(ScriptError::EVAL_FALSE,
                                          make_debug_str());
                }
            }
            return std::nullopt;
        }

        // Mint input (nFlags == 3)
        if (ptxTo->vin[nIn].vWitnesses.size() != 1) {
            return std::make_pair(ScriptError::EVAL_FALSE, make_debug_str());
        }
        const lotus::v2::Hash32 &token_id = v2tx.inputs[nIn].prev_txid;
        __uint128_t in_tokens = 0;
        __uint128_t out_tokens = 0;
        for (const auto &rc : resolved) {
            if (rc.has_value() && rc->HasToken() && rc->token_id == token_id) {
                in_tokens += rc->value;
            }
        }
        for (const auto &out : v2tx.outputs) {
            if (out.HasToken() && out.token_id == token_id) {
                out_tokens += out.value;
            }
        }
        if (out_tokens <= in_tokens) {
            return std::make_pair(ScriptError::EVAL_FALSE, make_debug_str());
        }
        const __uint128_t amount = out_tokens - in_tokens;
        lotus::v2::PositiveDelta delta{};
        for (size_t b = 0; b < delta.size(); ++b) {
            delta[b] = static_cast<uint8_t>(amount >> (8 * b));
        }
        const auto &w = ptxTo->vin[nIn].vWitnesses[0];
        auto ctx = prepared_vm.Invocation(nIn, 0, delta, m_sig_collector);
        ctx.effects = m_v2_effects;
        const lotus::v2::VmChargedResult vm_res =
            lotus::v2::EvaluateVmCharged(
                w.script, w.arguments, kDefaultVmProfile, prepared_vm.Cost(),
                static_cast<uint16_t>(v2tx.inputs.size()),
                static_cast<uint16_t>(v2tx.outputs.size()), &ctx);
        if ((vm_res.invocation.status != lotus::v2::VmStatus::Success &&
             vm_res.invocation.status !=
                 lotus::v2::VmStatus::AutomaticSuccess) ||
            !vm_res.charged) {
            return std::make_pair(ScriptError::EVAL_FALSE, make_debug_str());
        }
        return std::nullopt;
    }
    if (!VerifyScript(scriptSig, m_tx_out.scriptPubKey, nFlags,
                      CachingTransactionSignatureChecker(
                          ptxTo, nIn, m_tx_out.nValue, cacheStore,
                          *m_signature_cache, txdata,
                          ((nFlags & SCRIPT_VERIFY_NULLFAIL) != 0)
                              ? m_sig_collector
                              : nullptr),
                      metrics, &error)) {
        return std::make_pair(error, make_debug_str());
    }
    if ((pTxLimitSigChecks &&
         !pTxLimitSigChecks->consume_and_check(metrics.nSigChecks)) ||
        (pBlockLimitSigChecks &&
         !pBlockLimitSigChecks->consume_and_check(metrics.nSigChecks))) {
        // we can't assign a meaningful script error (since the script
        // succeeded), but remove the ScriptError::OK which could be
        // misinterpreted.
        return std::make_pair(ScriptError::SIGCHECKS_LIMIT_EXCEEDED,
                              make_debug_str());
    }
    return std::nullopt;
}

ValidationCache::ValidationCache(const size_t script_execution_cache_bytes,
                                 const size_t signature_cache_bytes)
    : m_signature_cache{signature_cache_bytes} {
    // Setup the salted hasher
    uint256 nonce = GetRandHash();
    // We want the nonce to be 64 bytes long to force the hasher to process
    // this chunk, which makes later hash computations more efficient. We
    // just write our 32-byte entropy twice to fill the 64 bytes.
    m_script_execution_cache_hasher.Write(nonce.begin(), 32);
    m_script_execution_cache_hasher.Write(nonce.begin(), 32);

    const auto [num_elems, approx_size_bytes] =
        m_script_execution_cache.setup_bytes(script_execution_cache_bytes);
    LogInfoEvent(
        BCLog::ALL, "script_execution_cache_initialized",
        "Using {cache_allocated_mib} MiB out of {cache_requested_mib} MiB requested for script execution cache, able to store {cache_capacity} elements")
        .Field(BCLog::LogField::CacheAllocatedMiB, approx_size_bytes >> 20)
        .Field(BCLog::LogField::CacheRequestedMiB,
               script_execution_cache_bytes >> 20)
        .Field(BCLog::LogField::CacheCapacity, num_elems);
}

bool CheckInputScripts(const CTransaction &tx, TxValidationState &state,
                       const CCoinsViewCache &inputs, const uint32_t flags,
                       bool sigCacheStore, bool scriptCacheStore,
                       const PrecomputedTransactionData &txdata,
                       ValidationCache &validation_cache, int &nSigChecksOut,
                       TxSigCheckLimiter &txLimitSigChecks,
                       CheckInputsLimiter *pBlockLimitSigChecks,
                       std::vector<CScriptCheck> *pvChecks) {
    AssertLockHeld(cs_main);
    assert(!tx.IsCoinBase());

    if (pvChecks) {
        pvChecks->reserve(tx.vin.size());
    }

    // First check if script executions have been cached with the same flags.
    // Note that this assumes that the inputs provided are correct (ie that the
    // transaction hash which is in tx's prevouts properly commits to the
    // scriptPubKey in the inputs view of that transaction).
    ScriptCacheKey hashCacheEntry(
        tx, flags, validation_cache.ScriptExecutionCacheHasher());
    ScriptCacheElement elem(hashCacheEntry, 0);
    bool found_in_cache = validation_cache.m_script_execution_cache.get(
        elem, /*erase=*/!scriptCacheStore);
    node::CountValidationCacheLookup(/*script_execution=*/true, found_in_cache);
    nSigChecksOut = elem.nSigChecks;
    if (found_in_cache) {
        if (!txLimitSigChecks.consume_and_check(nSigChecksOut) ||
            (pBlockLimitSigChecks &&
             !pBlockLimitSigChecks->consume_and_check(nSigChecksOut))) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "too-many-sigchecks");
        }
        return true;
    }

    int nSigChecksTotal = 0;
    lotus::v2::VmTransactionEffects v2_effects;

    const bool has_v2_input = std::any_of(
        tx.vin.begin(), tx.vin.end(),
        [](const CTxIn &in) { return in.nFlags == 1 || in.nFlags == 3; });
    std::shared_ptr<CScriptCheck::V2ResolvedCoins> resolved_coins;
    if (has_v2_input) {
        resolved_coins =
            std::make_shared<CScriptCheck::V2ResolvedCoins>(tx.vin.size());
        for (size_t j = 0; j < tx.vin.size(); ++j) {
            if (tx.vin[j].nFlags == 3) {
                (*resolved_coins)[j] = std::nullopt;
                continue;
            }
            const Coin &c = inputs.AccessCoin(tx.vin[j].prevout);
            assert(!c.IsSpent());
            (*resolved_coins)[j] = c.GetTxOut().ToV2Output();
        }
    }

    for (size_t i = 0; i < tx.vin.size(); i++) {
        CTxOut prev_txout;
        if (tx.vin[i].nFlags != 3) {
            const COutPoint &prevout = tx.vin[i].prevout;
            const Coin &coin = inputs.AccessCoin(prevout);
            assert(!coin.IsSpent());
            prev_txout = coin.GetTxOut();
        }

        // We very carefully only pass in things to CScriptCheck which are
        // clearly committed to by tx's hash. This provides a sanity
        // check that our caching is not introducing consensus failures through
        // additional data in, eg, the coins being spent being checked as a part
        // of CScriptCheck.

        // Verify signature
        CScriptCheck check(prev_txout, tx, validation_cache.m_signature_cache,
                           i, flags, sigCacheStore, txdata, &txLimitSigChecks,
                           pBlockLimitSigChecks, resolved_coins);
        check.SetV2Effects(&v2_effects);

        // If pvChecks is not null, defer the check execution to the caller.
        // A V2 transaction is one check unit: its inputs run here and the
        // transaction-scoped effects are finalized below, so it is never
        // deferred.
        if (pvChecks && tx.nVersion != 7) {
            pvChecks->push_back(std::move(check));
            continue;
        }

        if (auto result = check(); result.has_value()) {
            // Compute flags without the optional standardness flags.
            // This differs from MANDATORY_SCRIPT_VERIFY_FLAGS as it contains
            // additional upgrade flags (see AcceptToMemoryPoolWorker variable
            // extraFlags).
            uint32_t mandatoryFlags =
                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS;
            if (flags != mandatoryFlags) {
                // Check whether the failure was caused by a non-mandatory
                // script verification check. If so, ensure we return
                // NOT_STANDARD instead of CONSENSUS to avoid downstream users
                // splitting the network between upgraded and non-upgraded nodes
                // by banning CONSENSUS-failing data providers.
                CScriptCheck check2(prev_txout, tx,
                                    validation_cache.m_signature_cache, i,
                                    mandatoryFlags, sigCacheStore, txdata,
                                    nullptr, nullptr, resolved_coins);
                auto mandatory_result = check2();
                if (!mandatory_result.has_value()) {
                    return state.Invalid(
                        TxValidationResult::TX_NOT_STANDARD,
                        strprintf("non-mandatory-script-verify-flag (%s)",
                                  ScriptErrorString(result->first)),
                        result->second);
                }
                // If the second check failed, it failed due to a mandatory
                // script verification flag, but the first check might have
                // failed on a non-mandatory script verification flag.
                //
                // Avoid reporting a mandatory script check failure with a
                // non-mandatory error string by reporting the error from the
                // second check.
                result = mandatory_result;
            }

            // MANDATORY flag failures correspond to
            // TxValidationResult::TX_CONSENSUS.
            return state.Invalid(
                TxValidationResult::TX_CONSENSUS,
                strprintf("mandatory-script-verify-flag-failed (%s)",
                          ScriptErrorString(result->first)),
                result->second);
        }

        nSigChecksTotal += check.GetScriptExecutionMetrics().nSigChecks;
    }

    if (auto reason = FinalizeV2TransactionEffects(tx, v2_effects)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, *reason);
    }

    nSigChecksOut = nSigChecksTotal;

    if (scriptCacheStore && !pvChecks) {
        // We executed all of the provided scripts, and were told to cache the
        // result. Do so now.
        validation_cache.m_script_execution_cache.insert(
            ScriptCacheElement{hashCacheEntry, nSigChecksTotal});
    }

    return true;
}

bool FatalError(Notifications &notifications, BlockValidationState &state,
                const std::string &strMessage,
                const bilingual_str &userMessage) {
    notifications.fatalError(strMessage, userMessage);
    return state.Error(strMessage);
}

/** Restore the UTXO in a Coin at a given COutPoint. */
DisconnectResult UndoCoinSpend(Coin &&undo, CCoinsViewCache &view,
                               const COutPoint &out) {
    bool fClean = true;

    if (view.HaveCoin(out)) {
        // Overwriting transaction output.
        fClean = false;
    }

    if (undo.GetHeight() == 0) {
        // Missing undo metadata (height and coinbase). Older versions included
        // this information only in undo records for the last spend of a
        // transactions' outputs. This implies that it must be present for some
        // other output of the same tx.
        const Coin &alternate = AccessByTxid(view, out.GetTxId());
        if (alternate.IsSpent()) {
            // Adding output for transaction without known metadata
            return DisconnectResult::FAILED;
        }

        // This is somewhat ugly, but hopefully utility is limited. This is only
        // useful when working from legacy on disck data. In any case, putting
        // the correct information in there doesn't hurt.
        const_cast<Coin &>(undo) = Coin(undo.GetTxOut(), alternate.GetHeight(),
                                        alternate.IsCoinBase());
    }

    // If the coin already exists as an unspent coin in the cache, then the
    // possible_overwrite parameter to AddCoin must be set to true. We have
    // already checked whether an unspent coin exists above using HaveCoin, so
    // we don't need to guess. When fClean is false, an unspent coin already
    // existed and it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DisconnectResult::OK : DisconnectResult::UNCLEAN;
}

/**
 * Undo the effects of this block (with given index) on the UTXO set represented
 * by coins. When FAILED is returned, view is left in an indeterminate state.
 */
DisconnectResult Chainstate::DisconnectBlock(const CBlock &block,
                                             const CBlockIndex *pindex,
                                             CCoinsViewCache &view) {
    AssertLockHeld(::cs_main);
    CBlockUndo blockUndo;
    if (!m_blockman.ReadBlockUndo(blockUndo, *pindex)) {
        LogErrorEvent(BCLog::ALL, "disconnect_undo_read_failed",
                      "DisconnectBlock(): failure reading undo data");
        return DisconnectResult::FAILED;
    }

    return ApplyBlockUndo(std::move(blockUndo), block, pindex, view);
}

DisconnectResult ApplyBlockUndo(CBlockUndo &&blockUndo, const CBlock &block,
                                const CBlockIndex *pindex,
                                CCoinsViewCache &view) {
    bool fClean = true;

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        LogErrorEvent(BCLog::ALL, "disconnect_block_undo_inconsistent",
                      "DisconnectBlock(): block and undo data inconsistent");
        return DisconnectResult::FAILED;
    }

    // First, restore inputs.
    for (size_t i = 1; i < block.vtx.size(); i++) {
        const CTransaction &tx = *(block.vtx[i]);
        CTxUndo &txundo = blockUndo.vtxundo[i - 1];
        if (txundo.vprevout.size() != tx.vin.size()) {
            LogErrorEvent(
                BCLog::ALL, "disconnect_transaction_undo_inconsistent",
                "DisconnectBlock(): transaction and undo data inconsistent");
            return DisconnectResult::FAILED;
        }

        for (size_t j = 0; j < tx.vin.size(); j++) {
            if (tx.vin[j].nFlags == 3) {
                continue;
            }
            const COutPoint &out = tx.vin[j].prevout;
            DisconnectResult res =
                UndoCoinSpend(std::move(txundo.vprevout[j]), view, out);
            if (res == DisconnectResult::FAILED) {
                return DisconnectResult::FAILED;
            }
            fClean = fClean && res != DisconnectResult::UNCLEAN;
        }
        // At this point, all of txundo.vprevout should have been moved out.
    }

    for (size_t i = 0; i < blockUndo.vexpired.size(); ++i) {
        ExpiredCoinUndo &exp_undo = blockUndo.vexpired[i];
        DisconnectResult res = UndoCoinSpend(
            std::move(exp_undo.coin), view, exp_undo.outpoint);
        if (res == DisconnectResult::FAILED) {
            return DisconnectResult::FAILED;
        }
        fClean = fClean && res != DisconnectResult::UNCLEAN;
    }

    // Second, revert created outputs.
    for (const auto &ptx : block.vtx) {
        const CTransaction &tx = *ptx;
        const TxId &txid = tx.GetId();
        const bool is_coinbase = tx.IsCoinBase();

        // Check that all outputs are available and match the outputs in the
        // block itself exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (tx.vout[o].scriptPubKey.IsUnspendable()) {
                continue;
            }

            COutPoint out(txid, o);
            Coin coin;
            bool is_spent = view.SpendCoin(out, &coin);
            if (!is_spent || tx.vout[o] != coin.GetTxOut() ||
                uint32_t(pindex->nHeight) != coin.GetHeight() ||
                is_coinbase != coin.IsCoinBase()) {
                // transaction output mismatch
                fClean = false;
            }
        }
    }

    // Move best block pointer to previous block.
    view.SetBestBlock(block.hashPrevBlock);

    return fClean ? DisconnectResult::OK : DisconnectResult::UNCLEAN;
}

// Returns the script flags which should be checked for the block after
// the given block.
static uint32_t GetNextBlockScriptFlags(const CBlockIndex *pindex,
                                        const ChainstateManager &chainman) {
    const Consensus::Params &consensusparams = chainman.GetConsensus();

    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG |
                     SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                     SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                     SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID |
                     SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLFAIL |
                     SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_CLEANSTACK |
                     SCRIPT_ENABLE_SCHNORR_MULTISIG |
                     SCRIPT_VERIFY_MINIMALDATA | SCRIPT_ENFORCE_SIGCHECKS;

    // We make sure this node will have replay protection during the next hard
    // fork.
    if (IsReplayProtectionEnabled(
            consensusparams, pindex,
            chainman.m_options.replay_protection_activation_time)) {
        flags |= SCRIPT_ENABLE_REPLAY_PROTECTION;
    }

    return flags;
}

/**
 * Apply the effects of this block (with given index) on the UTXO set
 * represented by coins. Validity checks that depend on the UTXO set are also
 * done; ConnectBlock() can fail if those validity checks fail (among other
 * reasons).
 */
bool Chainstate::ConnectBlock(const CBlock &block, BlockValidationState &state,
                              CBlockIndex *pindex, CCoinsViewCache &view,
                              BlockValidationOptions options, Amount *blockFees,
                              bool fJustCheck) {
    AssertLockHeld(cs_main);
    assert(pindex);

    const BlockHash block_hash{block.GetHash()};
    assert(*pindex->phashBlock == block_hash);

    const auto time_start{SteadyClock::now()};

    const CChainParams &params{m_chainman.GetParams()};
    const Consensus::Params &consensusParams = params.GetConsensus();

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific.
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // m_adjusted_time_callback() to go backward).
    if (!fJustCheck &&
        !CheckBlock(block, state, consensusParams,
                    options.withCheckPoW(!fJustCheck)
                        .withCheckMerkleRoot(!fJustCheck))) {
        if (state.GetResult() == BlockValidationResult::BLOCK_MUTATED) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having
            // hardware problems.
            return FatalError(m_chainman.GetNotifications(), state,
                              "Corrupt block found indicating potential "
                              "hardware failure; shutting down");
        }
        LogErrorEvent(BCLog::ALL, "chain_check_block_failed",
                      "{source_function}: Consensus::CheckBlock: {reason}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state);
        return false;
    }

    // Verify that the view's current state corresponds to the previous block
    BlockHash hashPrevBlock =
        pindex->pprev == nullptr ? BlockHash() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    m_chainman.num_blocks_total++;

    // Special case for the genesis block, skipping connection of its
    // transactions (its coinbase is unspendable)
    if (block_hash == consensusParams.hashGenesisBlock) {
        RecordV2BlockState(block, block_hash, BlockHash(), 0, 0);
        if (!fJustCheck) {
            view.SetBestBlock(pindex->GetBlockHash());
        }

        return true;
    }

    bool fScriptChecks = true;
    if (!m_chainman.AssumedValidBlock().IsNull()) {
        // We've been configured with the hash of a block which has been
        // externally verified to have a valid history. A suitable default value
        // is included with the software and updated from time to time. Because
        // validity relative to a piece of software is an objective fact these
        // defaults can be easily reviewed. This setting doesn't force the
        // selection of any particular chain but makes validating some faster by
        // effectively caching the result of part of the verification.
        BlockMap::const_iterator it{
            m_blockman.m_block_index.find(m_chainman.AssumedValidBlock())};
        if (it != m_blockman.m_block_index.end()) {
            if (it->second.GetAncestor(pindex->nHeight) == pindex &&
                m_chainman.m_best_header->GetAncestor(pindex->nHeight) ==
                    pindex &&
                m_chainman.m_best_header->nChainWork >=
                    m_chainman.MinimumChainWork()) {
                // This block is a member of the assumed verified chain and an
                // ancestor of the best header.
                // Script verification is skipped when connecting blocks under
                // the assumevalid block. Assuming the assumevalid block is
                // valid this is safe because block merkle hashes are still
                // computed and checked, Of course, if an assumed valid block is
                // invalid due to false scriptSigs this optimization would allow
                // an invalid chain to be accepted.
                // The equivalent time check discourages hash power from
                // extorting the network via DOS attack into accepting an
                // invalid block through telling users they must manually set
                // assumevalid. Requiring a software change or burying the
                // invalid block, regardless of the setting, makes it hard to
                // hide the implication of the demand. This also avoids having
                // release candidates that are hardly doing any signature
                // verification at all in testing without having to artificially
                // set the default assumed verified block further back. The test
                // against the minimum chain work prevents the skipping when
                // denied access to any chain at least as good as the expected
                // chain.
                fScriptChecks = (GetBlockProofEquivalentTime(
                                     *m_chainman.m_best_header, *pindex,
                                     *m_chainman.m_best_header,
                                     consensusParams) <= 60 * 60 * 24 * 5);
            }
        }
    }

    const auto time_1{SteadyClock::now()};
    m_chainman.time_check += time_1 - time_start;
    LogDebug(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_1 - time_start),
             Ticks<SecondsDouble>(m_chainman.time_check),
             Ticks<MillisecondsDouble>(m_chainman.time_check) /
                 m_chainman.num_blocks_total);

    // Do not allow blocks that contain transactions which 'overwrite' older
    // transactions, unless those are already completely spent. If such
    // overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance --
    // even after being sent to another address.
    // See BIP30, CVE-2012-1909, and http://r6.ca/blog/20120206T005236Z.html
    // for more information. This rule was originally applied to all blocks
    // with a timestamp after March 15, 2012, 0:00 UTC. Now that the whole
    // chain is irreversibly beyond that time it is applied to all blocks
    // except the two in the chain that violate it. This prevents exploiting
    // the issue against nodes during their initial block download.
    bool fEnforceBIP30 = !((pindex->nHeight == 91842 &&
                            pindex->GetBlockHash() ==
                                uint256S("0x00000000000a4d0a398161ffc163c503763"
                                         "b1f4360639393e0e4c8e300e0caec")) ||
                           (pindex->nHeight == 91880 &&
                            pindex->GetBlockHash() ==
                                uint256S("0x00000000000743f190a18c5577a3c2d2a1f"
                                         "610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate
    // coinbases and thus other than starting with the 2 existing duplicate
    // coinbase pairs, not possible to create overwriting txs. But by the time
    // BIP34 activated, in each of the existing pairs the duplicate coinbase had
    // overwritten the first before the first had been spent. Since those
    // coinbases are sufficiently buried it's no longer possible to create
    // further duplicate transactions descending from the known pairs either. If
    // we're on the known chain at height greater than where BIP34 activated, we
    // can save the db accesses needed for the BIP30 check.

    // BIP34 requires that a block at height X (block X) has its coinbase
    // scriptSig start with a CScriptNum of X (indicated height X).  The above
    // logic of no longer requiring BIP30 once BIP34 activates is flawed in the
    // case that there is a block X before the BIP34 height of 227,931 which has
    // an indicated height Y where Y is greater than X.  The coinbase for block
    // X would also be a valid coinbase for block Y, which could be a BIP30
    // violation.  An exhaustive search of all mainnet coinbases before the
    // BIP34 height which have an indicated height greater than the block height
    // reveals many occurrences. The 3 lowest indicated heights found are
    // 209,921, 490,897, and 1,983,702 and thus coinbases for blocks at these 3
    // heights would be the first opportunity for BIP30 to be violated.

    // The search reveals a great many blocks which have an indicated height
    // greater than 1,983,702, so we simply remove the optimization to skip
    // BIP30 checking for blocks at height 1,983,702 or higher.  Before we reach
    // that block in another 25 years or so, we should take advantage of a
    // future consensus change to do a new and improved version of BIP34 that
    // will actually prevent ever creating any duplicate coinbases in the
    // future.
    static constexpr int BIP34_IMPLIES_BIP30_LIMIT = 1983702;

    // There is no potential to create a duplicate coinbase at block 209,921
    // because this is still before the BIP34 height and so explicit BIP30
    // checking is still active.

    // The final case is block 176,684 which has an indicated height of
    // 490,897. Unfortunately, this issue was not discovered until about 2 weeks
    // before block 490,897 so there was not much opportunity to address this
    // case other than to carefully analyze it and determine it would not be a
    // problem. Block 490,897 was, in fact, mined with a different coinbase than
    // block 176,684, but it is important to note that even if it hadn't been or
    // is remined on an alternate fork with a duplicate coinbase, we would still
    // not run into a BIP30 violation.  This is because the coinbase for 176,684
    // is spent in block 185,956 in transaction
    // d4f7fbbf92f4a3014a230b2dc70b8058d02eb36ac06b4a0736d9d60eaa9e8781.  This
    // spending transaction can't be duplicated because it also spends coinbase
    // 0328dd85c331237f18e781d692c92de57649529bd5edf1d01036daea32ffde29.  This
    // coinbase has an indicated height of over 4.2 billion, and wouldn't be
    // duplicatable until that height, and it's currently impossible to create a
    // chain that long. Nevertheless we may wish to consider a future soft fork
    // which retroactively prevents block 490,897 from creating a duplicate
    // coinbase. The two historical BIP30 violations often provide a confusing
    // edge case when manipulating the UTXO and it would be simpler not to have
    // another edge case to deal with.

    // testnet3 has no blocks before the BIP34 height with indicated heights
    // post BIP34 before approximately height 486,000,000 and presumably will
    // be reset before it reaches block 1,983,702 and starts doing unnecessary
    // BIP30 checking again.
    assert(pindex->pprev);
    CBlockIndex *pindexBIP34height =
        pindex->pprev->GetAncestor(consensusParams.BIP34Height);
    // Only continue to enforce if we're below BIP34 activation height or the
    // block hash at that height doesn't correspond.
    fEnforceBIP30 =
        fEnforceBIP30 &&
        (!pindexBIP34height ||
         !(pindexBIP34height->GetBlockHash() == consensusParams.BIP34Hash));

    // Lotus V2 coinbases (nVersion == 7, nFlags == 2) commit to
    // COutPoint(TxId(hashPrevBlock), pindex->nHeight) in vin[0].prevout from
    // height 1, guaranteeing unique coinbase TxIDs without LevelDB cache-miss
    // lookups on every output. AddCoins below still enforces !possible_overwrite.
    const bool fV2UniqueCoinbase =
        !block.vtx.empty() && block.vtx[0]->nVersion == 7 &&
        !block.vtx[0]->vin.empty() && block.vtx[0]->vin[0].nFlags == 2 &&
        block.vtx[0]->vin[0].prevout ==
            COutPoint(TxId(hashPrevBlock),
                      static_cast<uint32_t>(pindex->nHeight));

    // TODO: Remove BIP30 checking from block height 1,983,702 on, once we have
    // a consensus change that ensures coinbases at those heights can not
    // duplicate earlier coinbases.
    if (!fV2UniqueCoinbase &&
        (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT)) {
        for (const auto &tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetId(), o))) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                         "bad-txns-BIP30",
                                         "tried to overwrite transaction");
                }
            }
        }
    }

    // Enforce BIP68 (sequence locks).
    int nLockTimeFlags = 0;
    if (DeploymentActiveAt(*pindex, consensusParams,
                           Consensus::DEPLOYMENT_CSV)) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    const uint32_t flags = GetNextBlockScriptFlags(pindex->pprev, m_chainman);

    const auto time_2{SteadyClock::now()};
    m_chainman.time_forks += time_2 - time_1;
    LogDebug(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<SecondsDouble>(m_chainman.time_forks),
             Ticks<MillisecondsDouble>(m_chainman.time_forks) /
                 m_chainman.num_blocks_total);

    // Deterministic process-crash coverage pauses inside the real connection,
    // rather than inferring an in-flight operation from asynchronous logs.
    // Parameter interaction rejects this hidden option outside regtest.
    if (!fJustCheck && params.GetChainType() == ChainType::REGTEST &&
        gArgs.GetIntArg("-testblockconnectpauseheight", -1) == pindex->nHeight) {
        LogInfo("Pausing block connection at test height %d\n",
                pindex->nHeight);
        LogInstance().Flush();
        while (!m_chainman.m_interrupt) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return state.Error("Block connection interrupted during test pause");
    }

    std::vector<int> prevheights;
    Amount nFees = Amount::zero();
    int nInputs = 0;

    // Limit the total executed signature operations in the block, a consensus
    // rule. Tracking during the CPU-consuming part (validation of uncached
    // inputs) is per-input atomic and validation in each thread stops very
    // quickly after the limit is exceeded, so an adversary cannot cause us to
    // exceed the limit by much at all.
    CheckInputsLimiter nSigChecksBlockLimiter(
        GetMaxBlockSigChecksCount(options.getExcessiveBlockSize()));

    std::vector<TxSigCheckLimiter> nSigChecksTxLimiters;
    nSigChecksTxLimiters.resize(block.vtx.size() - 1);

    CBlockUndo blockundo;
    blockundo.vtxundo.resize(block.vtx.size() - 1);

    std::optional<CCheckQueueControl<CScriptCheck>> control;
    if (fScriptChecks) {
        control.emplace(m_chainman.GetCheckQueue());
    }

    view.Reserve(block.vtx.size() * 2 + 16);

    // Add all outputs
    try {
        for (const auto &ptx : block.vtx) {
            AddCoins(view, *ptx, pindex->nHeight);
        }
    } catch (const std::logic_error &e) {
        // This error will be thrown from AddCoin if we try to connect a block
        // containing duplicate transactions. Such a thing should normally be
        // caught early nowadays (due to ContextualCheckBlock's CTOR
        // enforcement) however some edge cases can escape that:
        // - ContextualCheckBlock does not get re-run after saving the block to
        // disk, and older versions may have saved a weird block.
        // - its checks are not applied to pre-CTOR chains, which we might visit
        // with checkpointing off.
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "tx-duplicate", "tried to overwrite transaction");
    }

    if (block.vtx.size() > 8) {
        std::vector<COutPoint> block_spent_outpoints;
        block_spent_outpoints.reserve(block.vtx.size() * 2);
        for (size_t i = 1; i < block.vtx.size(); ++i) {
            for (const auto &in : block.vtx[i]->vin) {
                if (in.nFlags != 3 && !view.HaveCoinInCache(in.prevout)) {
                    block_spent_outpoints.push_back(in.prevout);
                }
            }
        }
        if (!block_spent_outpoints.empty()) {
            view.PrefetchOutpointsAsync(block_spent_outpoints);
        }
    }

    struct PendingBlockTxCheck {
        size_t tx_index;
        ScriptCacheKey cache_key;
    };
    std::vector<PendingBlockTxCheck> pending_script_txs;
    std::vector<int> prevalidated_overlay_sigchecks;
    uint256 expectedStateRoot;
    bool used_overlay_state_root = false;
    if (m_mempool && !block.vtx.empty() && pindex->pprev != nullptr) {
        TRY_LOCK(m_mempool->cs, lock_mempool);
        if (lock_mempool) {
            lotus::v2::Hash prev_id{};
            std::memcpy(prev_id.data(), hashPrevBlock.begin(), 32);
            const auto &mgr = m_mempool->GetMerklixOverlay();
            const auto &spec = mgr.GetSpeculativeOverlay();
            std::shared_ptr<const lotus::v2::SmtNode> base_utxo;
            lotus::v2::MonetaryState base_mon{};
            const bool has_snap =
                GetV2BlockStateSnapshot(hashPrevBlock, base_utxo, base_mon);
            if (mgr.IsAnchoredAt(
                    prev_id, uint64_t(pindex->nHeight),
                    uint64_t(pindex->pprev->GetMedianTimePast())) &&
                (has_snap || pindex->nHeight <= 1) &&
                spec.GetBaseUtxoRoot() == base_utxo &&
                block.vtx.size() == spec.GetTxCount() + 1 &&
                !block.hashMerkleRoot.IsNull() &&
                block.hashMerkleRoot ==
                    ComputeV2TxRootFromSubtreeA(*block.vtx[0],
                                                spec.GetSubtreeARoot())) {
                const BlockHash block_hash = pindex->GetBlockHash();
                try {
                    expectedStateRoot = ComputeV2StateRootFromOverlay(
                        *block.vtx[0], spec, block.nBits, uint64_t(pindex->nHeight),
                        uint64_t(pindex->pprev->GetMedianTimePast()), false,
                        &block_hash, &block.hashStateRoot);
                } catch (const V2StateCacheError &error) {
                    return state.Error(error.what());
                }
                used_overlay_state_root = true;

                if (!fJustCheck && fScriptChecks && block.vtx.size() > 1 &&
                    pindex->pprev->pprev != nullptr &&
                    GetNextBlockScriptFlags(pindex->pprev, m_chainman) ==
                        GetNextBlockScriptFlags(pindex->pprev->pprev,
                                                m_chainman)) {
                    const auto &ordered = spec.GetOrderedTxs();
                    if (ordered.size() == block.vtx.size() - 1) {
                        std::vector<int> sigchecks;
                        sigchecks.reserve(ordered.size());
                        size_t idx = 1;
                        bool all_match = true;
                        for (const auto &[_, oentry] : ordered) {
                            if (block.vtx[idx].get() != oentry.tx_ref.get() ||
                                oentry.sigchecks < 0) {
                                all_match = false;
                                break;
                            }
                            const auto entry = m_mempool->mapTx.find(block.vtx[idx]->GetId());
                            ScriptCacheKey cached_key(*block.vtx[idx], flags,
                                m_chainman.m_validation_cache.ScriptExecutionCacheHasher());
                            ScriptCacheElement cached(cached_key, 0);
                            if (entry == m_mempool->mapTx.end() ||
                                (*entry)->GetSharedTx().get() != block.vtx[idx].get() ||
                                !m_chainman.m_validation_cache.m_script_execution_cache.get(cached, false) ||
                                cached.nSigChecks != oentry.sigchecks) {
                                all_match = false;
                                break;
                            }
                            sigchecks.push_back(int(oentry.sigchecks));
                            ++idx;
                        }
                        if (all_match) {
                            prevalidated_overlay_sigchecks =
                                std::move(sigchecks);
                        }
                    }
                }
            }
        }
    }
    if (fScriptChecks && block.vtx.size() > 1 &&
        prevalidated_overlay_sigchecks.empty()) {
        pending_script_txs.reserve(block.vtx.size() - 1);
    }

    size_t txIndex = 0;
    // nSigChecksRet may be accurate (found in cache) or 0 (checks were
    // deferred into Pass 2).
    int nSigChecksRet = 0;
    const bool fCacheResults = fJustCheck;
    const bool fEnforceSigCheck = flags & SCRIPT_ENFORCE_SIGCHECKS;
    for (const auto &ptx : block.vtx) {
        const CTransaction &tx = *ptx;
        const bool isCoinBase = tx.IsCoinBase();
        nInputs += tx.vin.size();

        // The following checks do not apply to the coinbase.
        if (isCoinBase) {
            continue;
        }

        // Spend inputs in a single CCoinsViewCache lookup per input, capturing
        // the spent Coin into blockundo.vtxundo[txIndex].vprevout for
        // CheckTxInputsFromSpentCoins, BIP68 prevheights, and Pass 2 parallel
        // script verification.
        CTxUndo &txundo = blockundo.vtxundo.at(txIndex);
        txundo.vprevout.resize(tx.vin.size());
        prevheights.resize(tx.vin.size());
        bool inputs_ok = true;
        for (size_t j = 0; j < tx.vin.size(); j++) {
            if (tx.vin[j].nFlags == 3) {
                prevheights[j] = 0;
                continue;
            }
            if (!view.SpendCoin(tx.vin[j].prevout, &txundo.vprevout[j])) {
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              "bad-txns-inputs-missingorspent",
                              "CheckTxInputs: inputs missing/spent in "
                              "transaction " +
                                  tx.GetId().ToString());
                inputs_ok = false;
                break;
            }
            prevheights[j] =
                (tx.vin[j].nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
                    ? 0
                    : txundo.vprevout[j].GetHeight();
        }
        if (!inputs_ok) {
            break;
        }

        {
            Amount txfee = Amount::zero();
            TxValidationState tx_state;
            if (!Consensus::CheckTxInputsFromSpentCoins(
                    tx, txundo.vprevout, tx_state, pindex->nHeight, txfee)) {
                // Any transaction validation failure in ConnectBlock is a block
                // consensus failure.
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              tx_state.GetRejectReason(),
                              tx_state.GetDebugMessage() + " in transaction " +
                                  tx.GetId().ToString());
                break;
            }
            if (!isCoinBase && txfee > Amount::zero()) {
                size_t spendable_outputs = 0;
                for (const auto &out : tx.vout) {
                    if (!out.scriptPubKey.IsUnspendable() &&
                        (out.nFlags & 0x02) == 0) {
                        ++spendable_outputs;
                    }
                }
                const uint64_t fee_per_output =
                    lotus::v2::ComputeTxFeePerSpendableOutput(
                        static_cast<uint64_t>(txfee / SATOSHI),
                        spendable_outputs);
                const uint64_t exp_height =
                    lotus::v2::ComputeUtxoExpirationHeight(
                        static_cast<uint64_t>(std::max(0, pindex->nHeight)),
                        false, fee_per_output);
                const TxId txid = tx.GetId();
                for (size_t o = 0; o < tx.vout.size(); ++o) {
                    view.UpdateCoinFeeLifespan(COutPoint(txid, o),
                                               fee_per_output, exp_height);
                }
            }
            nFees += txfee;
        }

        if (!MoneyRange(nFees)) {
            state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                          "bad-txns-accumulated-fee-outofrange",
                          "accumulated fee in the block out of range");
            break;
        }

        // Check that transaction is BIP68 final. BIP68 lock checks (as
        // opposed to nLockTime checks) must be in ConnectBlock because they
        // require the UTXO set.
        if (!SequenceLocks(tx, nLockTimeFlags, prevheights, *pindex)) {
            state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                          "bad-txns-nonfinal",
                          "contains a non-BIP68-final transaction " +
                              tx.GetHash().ToString());
            break;
        }

        if (!fEnforceSigCheck) {
            // Historically, there has been transactions with a very high
            // sigcheck count, so we need to disable this check for such
            // transactions.
            nSigChecksTxLimiters[txIndex] = TxSigCheckLimiter::getDisabled();
        }

        if (fScriptChecks) {
            if (!prevalidated_overlay_sigchecks.empty()) {
                nSigChecksRet = prevalidated_overlay_sigchecks[txIndex];
                if (!nSigChecksTxLimiters[txIndex].consume_and_check(
                        nSigChecksRet) ||
                    !nSigChecksBlockLimiter.consume_and_check(nSigChecksRet)) {
                    state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "too-many-sigchecks", "");
                    break;
                }
            } else {
                ScriptCacheKey hashCacheEntry(
                    tx, flags,
                    m_chainman.m_validation_cache.ScriptExecutionCacheHasher());
                ScriptCacheElement elem(hashCacheEntry, 0);
                const bool script_cache_hit{
                    m_chainman.m_validation_cache.m_script_execution_cache.get(
                        elem, /*erase=*/!fCacheResults)};
                node::CountValidationCacheLookup(/*script_execution=*/true,
                                                 script_cache_hit);
                if (script_cache_hit) {
                    nSigChecksRet = elem.nSigChecks;
                    if (!nSigChecksTxLimiters[txIndex].consume_and_check(
                            nSigChecksRet) ||
                        !nSigChecksBlockLimiter.consume_and_check(
                            nSigChecksRet)) {
                        state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                      "too-many-sigchecks", "");
                        break;
                    }
                } else {
                    nSigChecksRet = 0;
                    pending_script_txs.push_back({txIndex, hashCacheEntry});
                }
            }
        }

        txIndex++;
    }
    const auto time_3{SteadyClock::now()};
    m_chainman.time_connect += time_3 - time_2;
    LogDebug(BCLog::BENCH,
             "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) "
             "[%.2fs (%.2fms/blk)]\n",
             (unsigned)block.vtx.size(),
             Ticks<MillisecondsDouble>(time_3 - time_2),
             Ticks<MillisecondsDouble>(time_3 - time_2) / block.vtx.size(),
             nInputs <= 1
                 ? 0
                 : Ticks<MillisecondsDouble>(time_3 - time_2) / (nInputs - 1),
             Ticks<SecondsDouble>(m_chainman.time_connect),
             Ticks<MillisecondsDouble>(m_chainman.time_connect) /
                 m_chainman.num_blocks_total);

    Amount cleaningBounty = Amount::zero();
    if (state.IsValid()) {
        auto swept = view.SweepExpiredCoins(
            static_cast<uint64_t>(std::max(0, pindex->nHeight)));
        blockundo.vexpired.reserve(swept.size());
        for (auto &[op, coin] : swept) {
            blockundo.vexpired.push_back(ExpiredCoinUndo{op, std::move(coin)});
        }
        const uint64_t bounty_atoms = lotus::v2::ComputeCleaningCrewBounty(
            swept.size(),
            static_cast<uint64_t>(std::max<int64_t>(0, nFees / SATOSHI)));
        cleaningBounty = static_cast<int64_t>(bounty_atoms) * SATOSHI;
    }

    const Amount blockReward =
        nFees + GetBlockSubsidy(pindex->nHeight, consensusParams) +
        cleaningBounty;
    if (block.vtx[0]->GetValueOut() > blockReward && state.IsValid()) {
        state.Invalid(
            BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-amount",
            strprintf("coinbase pays too much (actual=%d vs limit=%d)",
                      block.vtx[0]->GetValueOut(), blockReward));
    }

    if (blockFees) {
        *blockFees = nFees;
    }

    // Pass 2: Static UTXO Dependency-Graph Multi-Core Parallel Script, VM &
    // Batch Schnorr Signature Verification using blockundo.vtxundo[txIndex].
    if (fScriptChecks && state.IsValid() && !pending_script_txs.empty()) {
        const size_t n_pending = pending_script_txs.size();
        const unsigned int hw_threads =
            std::max(1u, std::thread::hardware_concurrency());
        const size_t num_workers =
            (n_pending >= 2)
                ? std::min<size_t>(n_pending, static_cast<size_t>(hw_threads))
                : 1;
        std::vector<std::optional<ParallelTxScriptError>> tx_errors(n_pending);
        std::vector<int> tx_sigchecks(n_pending, 0);
        std::vector<lotus::v2::BatchSigCollector> worker_collectors(
            num_workers);
        std::atomic<size_t> next_k{0};
        std::atomic<size_t> min_failed_k{n_pending};

        auto worker_fn = [&](size_t tid) {
            lotus::v2::BatchSigCollector &local_sigs = worker_collectors[tid];
            while (true) {
                const size_t k = next_k.fetch_add(1, std::memory_order_relaxed);
                if (k >= n_pending ||
                    k > min_failed_k.load(std::memory_order_relaxed)) {
                    break;
                }
                const size_t t_idx = pending_script_txs[k].tx_index;
                const CTransaction &tx = *block.vtx[t_idx + 1];
                const std::vector<Coin> &resolved_inputs =
                    blockundo.vtxundo[t_idx].vprevout;
                const PrecomputedTransactionData &txdata = tx.GetPrecomputedData();
                auto err = VerifyTxScriptsFromResolvedCoins(
                    tx, resolved_inputs, flags, fCacheResults, txdata,
                    m_chainman.m_validation_cache.m_signature_cache,
                    tx_sigchecks[k], nSigChecksTxLimiters[t_idx],
                    &nSigChecksBlockLimiter, &local_sigs, /*consensus_only=*/true);
                if (err.has_value()) {
                    tx_errors[k] = std::move(err);
                    size_t prev = min_failed_k.load(std::memory_order_relaxed);
                    while (k < prev &&
                           !min_failed_k.compare_exchange_weak(
                               prev, k, std::memory_order_relaxed)) {
                    }
                }
            }
        };

        if (auto *metrics{node::GetNodeMetrics()}; metrics && !fJustCheck) {
            metrics->script_check_transactions.Record(n_pending);
            metrics->script_check_workers.Record(num_workers);
        }
        ParallelScriptWorkerPool::Instance().Run(num_workers, worker_fn);

        for (size_t k = 0; k < n_pending; ++k) {
            if (tx_errors[k].has_value()) {
                state.Invalid(
                    BlockValidationResult::BLOCK_CONSENSUS,
                    strprintf("mandatory-script-verify-flag-failed (%s)",
                              ScriptErrorString(tx_errors[k]->script_err)),
                    tx_errors[k]->debug_message);
                break;
            }
        }

        if (state.IsValid()) {
            lotus::v2::BatchSigCollector combined_sigs;
            for (const auto &wc : worker_collectors) {
                combined_sigs.Merge(wc);
            }
            if (!combined_sigs.Empty() && !combined_sigs.VerifyAll()) {
                for (size_t k = 0; k < n_pending; ++k) {
                    const size_t t_idx = pending_script_txs[k].tx_index;
                    const CTransaction &tx = *block.vtx[t_idx + 1];
                    const std::vector<Coin> &resolved_inputs =
                        blockundo.vtxundo[t_idx].vprevout;
                    const PrecomputedTransactionData &txdata = tx.GetPrecomputedData();
                    int dummy_sigchecks = 0;
                    TxSigCheckLimiter dummy_tx_limiter =
                        TxSigCheckLimiter::getDisabled();
                    TxSigCheckLimiter dummy_block_limiter =
                        TxSigCheckLimiter::getDisabled();
                    auto err = VerifyTxScriptsFromResolvedCoins(
                        tx, resolved_inputs, flags, /*cache_results=*/false,
                        txdata,
                        m_chainman.m_validation_cache.m_signature_cache,
                        dummy_sigchecks, dummy_tx_limiter,
                        &dummy_block_limiter, /*sig_collector=*/nullptr,
                        /*consensus_only=*/true);
                    if (err.has_value()) {
                        state.Invalid(
                            BlockValidationResult::BLOCK_CONSENSUS,
                            strprintf(
                                "mandatory-script-verify-flag-failed (%s)",
                                ScriptErrorString(err->script_err)),
                            err->debug_message);
                        break;
                    }
                }
                if (state.IsValid()) {
                    state.Invalid(
                        BlockValidationResult::BLOCK_CONSENSUS,
                        strprintf("mandatory-script-verify-flag-failed (%s)",
                                  ScriptErrorString(ScriptError::EVAL_FALSE)),
                        "V2 batch signature verification failed");
                }
            } else if (fCacheResults) {
                for (const auto &litem : combined_sigs.LegacyItems()) {
                    if (litem.store_in_cache) {
                        uint256 entry;
                        std::memcpy(entry.begin(), litem.cache_entry.data(), 32);
                        m_chainman.m_validation_cache.m_signature_cache.Set(
                            entry);
                    }
                }
            }
        }

        if (state.IsValid() && fCacheResults) {
            for (size_t k = 0; k < n_pending; ++k) {
                m_chainman.m_validation_cache.m_script_execution_cache.insert(
                    ScriptCacheElement{pending_script_txs[k].cache_key,
                                       tx_sigchecks[k]});
            }
        }
    }
    if (control) {
        (void)control->Complete();
    }
    if (!state.IsValid()) {
        LogInfoEvent(BCLog::ALL, "block_validation_error",
                     "Block validation error: {reason}")
            .Field(BCLog::LogField::Reason, state);
        return false;
    }
    const auto time_4{SteadyClock::now()};
    m_chainman.time_verify += time_4 - time_2;
    LogDebug(
        BCLog::BENCH,
        "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n",
        nInputs - 1, Ticks<MillisecondsDouble>(time_4 - time_2),
        nInputs <= 1
            ? 0
            : Ticks<MillisecondsDouble>(time_4 - time_2) / (nInputs - 1),
        Ticks<SecondsDouble>(m_chainman.time_verify),
        Ticks<MillisecondsDouble>(m_chainman.time_verify) /
            m_chainman.num_blocks_total);

    if (!used_overlay_state_root) {
        try {
            expectedStateRoot = ComputeV2BlockStateRoot(
                block, hashPrevBlock, uint64_t(pindex->nHeight),
                uint64_t(pindex->pprev->GetMedianTimePast()), false);
        } catch (const V2StateCacheError &error) {
            return state.Error(error.what());
        }
    }
    const bool requireStateRoot =
        !block.hashStateRoot.IsNull() ||
        !consensusParams.allowNullStateRoot ||
        gArgs.GetBoolArg("-strictstateroot", false);
    if (block.nHeaderVersion == lotus::v2::kHeaderVersion &&
        requireStateRoot &&
        block.hashStateRoot != expectedStateRoot) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-blk-stateroot", "hashStateRoot mismatch");
    }

    if (fJustCheck) {
        return true;
    }

    // Publish only after the declared root has passed the active validation
    // policy. Min-difficulty networks may explicitly allow a zero commitment
    // (testnet/regtest unless -strictstateroot); the state remains keyed by the real serialized header hash, never a synthesized one.
    try {
        if (used_overlay_state_root && m_mempool) {
            LOCK(m_mempool->cs);
            const auto &overlay = m_mempool->GetMerklixOverlay().GetSpeculativeOverlay();
            const auto hash = pindex->GetBlockHash();
            const auto recorded = ComputeV2StateRootFromOverlay(
                *block.vtx[0], overlay, block.nBits, uint64_t(pindex->nHeight),
                uint64_t(pindex->pprev->GetMedianTimePast()), true, &hash,
                &expectedStateRoot);
            if (recorded != expectedStateRoot)
                return state.Error("V2 overlay changed before state publication");
        } else {
            RecordV2BlockState(block, pindex->GetBlockHash(), hashPrevBlock,
                uint64_t(pindex->nHeight), uint64_t(pindex->pprev->GetMedianTimePast()),
                !requireStateRoot);
        }
    } catch (const V2StateCacheError &error) {
        return state.Error(error.what());
    }

    if (!m_blockman.WriteBlockUndo(blockundo, state, *pindex)) {
        return false;
    }

    if (!pindex->IsValid(BlockValidity::SCRIPTS)) {
        pindex->RaiseValidity(BlockValidity::SCRIPTS);
        m_blockman.m_dirty_blockindex.insert(pindex);
    }

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    const auto time_5{SteadyClock::now()};
    m_chainman.time_index += time_5 - time_4;
    node::RecordBlockStage(node::BlockStage::CHECK, time_1 - time_start);
    node::RecordBlockStage(node::BlockStage::FORKS, time_2 - time_1);
    node::RecordBlockStage(node::BlockStage::CONNECT, time_3 - time_2);
    node::RecordBlockStage(node::BlockStage::VERIFY, time_4 - time_3);
    node::RecordBlockStage(node::BlockStage::INDEX, time_5 - time_4);
    LogDebug(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_5 - time_4),
             Ticks<SecondsDouble>(m_chainman.time_index),
             Ticks<MillisecondsDouble>(m_chainman.time_index) /
                 m_chainman.num_blocks_total);

    TRACE6(validation, block_connected, block_hash.data(), pindex->nHeight,
           block.vtx.size(), nInputs, nSigChecksRet,
           // in microseconds (µs)
           time_5 - time_start);

    return true;
}

CoinsCacheSizeState Chainstate::GetCoinsCacheSizeState() {
    AssertLockHeld(::cs_main);
    return this->GetCoinsCacheSizeState(
        m_coinstip_cache_size_bytes,
        m_mempool ? m_mempool->m_opts.max_size_bytes : 0);
}

CoinsCacheSizeState
Chainstate::GetCoinsCacheSizeState(size_t max_coins_cache_size_bytes,
                                   size_t max_mempool_size_bytes) {
    AssertLockHeld(::cs_main);
    int64_t nMempoolUsage = m_mempool ? m_mempool->DynamicMemoryUsage() : 0;
    int64_t cacheSize = CoinsTip().DynamicMemoryUsage();
    int64_t nTotalSpace =
        max_coins_cache_size_bytes +
        std::max<int64_t>(int64_t(max_mempool_size_bytes) - nMempoolUsage, 0);

    //! No need to periodic flush if at least this much space still available.
    static constexpr int64_t MAX_BLOCK_COINSDB_USAGE_BYTES =
        10 * 1024 * 1024; // 10MB
    int64_t large_threshold = std::max(
        (9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE_BYTES);

    if (cacheSize > nTotalSpace) {
        LogInfoEvent(
            BCLog::ALL, "coins_cache_budget_exceeded",
            "Cache size ({cache_size_bytes}) exceeds total space ({cache_budget_bytes})")
            .Field(BCLog::LogField::CacheSizeBytes, cacheSize)
            .Field(BCLog::LogField::CacheBudgetBytes, nTotalSpace);
        return CoinsCacheSizeState::CRITICAL;
    } else if (cacheSize > large_threshold) {
        return CoinsCacheSizeState::LARGE;
    }
    return CoinsCacheSizeState::OK;
}

bool Chainstate::FlushStateToDisk(BlockValidationState &state,
                                  FlushStateMode mode, int nManualPruneHeight) {
    LOCK(cs_main);
    assert(this->CanFlushToDisk());
    std::set<int> setFilesToPrune;
    bool full_flush_completed = false;

    [[maybe_unused]] const size_t coins_count{CoinsTip().GetCacheSize()};
    [[maybe_unused]] const size_t coins_mem_usage{
        CoinsTip().DynamicMemoryUsage()};
    auto *const metrics{node::GetNodeMetrics()};
    if (metrics && this == &m_chainman.ActiveChainstate()) {
        metrics->utxo_cache_entries.Set(double(coins_count));
        metrics->utxo_cache_bytes.Set(double(coins_mem_usage));
    }

    try {
        {
            bool fFlushForPrune = false;

            CoinsCacheSizeState cache_state = GetCoinsCacheSizeState();
            LOCK(m_blockman.cs_LastBlockFile);
            if (m_blockman.IsPruneMode() &&
                (m_blockman.m_check_for_pruning || nManualPruneHeight > 0) &&
                m_chainman.m_blockman.m_blockfiles_indexed) {
                // Make sure we don't prune any of the prune locks bestblocks.
                // Pruning is height-based.
                int last_prune{m_chain.Height()};
                // prune lock that actually was the limiting factor, only used
                // for logging
                std::optional<std::string> limiting_lock;

                for (const auto &prune_lock : m_blockman.m_prune_locks) {
                    if (prune_lock.second.height_first ==
                        std::numeric_limits<int>::max()) {
                        continue;
                    }
                    // Remove the buffer and one additional block here to get
                    // actual height that is outside of the buffer
                    const int lock_height{prune_lock.second.height_first -
                                          PRUNE_LOCK_BUFFER - 1};
                    last_prune = std::max(1, std::min(last_prune, lock_height));
                    if (last_prune == lock_height) {
                        limiting_lock = prune_lock.first;
                    }
                }

                if (limiting_lock) {
                    LogDebug(BCLog::PRUNE, "%s limited pruning to height %d\n",
                             limiting_lock.value(), last_prune);
                }

                if (nManualPruneHeight > 0) {
                    LOG_TIME_MILLIS_WITH_CATEGORY(
                        "find files to prune (manual)", BCLog::BENCH);
                    m_blockman.FindFilesToPruneManual(
                        setFilesToPrune,
                        std::min(last_prune, nManualPruneHeight), *this,
                        m_chainman);
                } else {
                    LOG_TIME_MILLIS_WITH_CATEGORY("find files to prune",
                                                  BCLog::BENCH);
                    m_blockman.FindFilesToPrune(setFilesToPrune, last_prune,
                                                *this, m_chainman);
                    m_blockman.m_check_for_pruning = false;
                }
                if (!setFilesToPrune.empty()) {
                    fFlushForPrune = true;
                    if (!m_blockman.m_have_pruned) {
                        m_blockman.m_block_tree_db->WriteFlag(
                            "prunedblockfiles", true);
                        m_blockman.m_have_pruned = true;
                    }
                }
            }
            const auto nNow{NodeClock::now()};
            // The cache is large and we're within 10% and 10 MiB of the limit,
            // but we have time now (not in the middle of a block processing).
            bool fCacheLarge = mode == FlushStateMode::PERIODIC &&
                               cache_state >= CoinsCacheSizeState::LARGE;
            // The cache is over the limit, we have to write now.
            bool fCacheCritical = mode == FlushStateMode::IF_NEEDED &&
                                  cache_state >= CoinsCacheSizeState::CRITICAL;
            // It's been a while since we wrote the block index  and chain
            // state to disk. Do this frequently, so we don't need to
            // redownload or reindex after a crash.
            bool fPeriodicWrite =
                mode == FlushStateMode::PERIODIC && nNow >= m_next_write;
            // Combine all conditions that result in a write to disk.
            bool should_write = (mode == FlushStateMode::ALWAYS) ||
                                fCacheLarge || fCacheCritical ||
                                fPeriodicWrite || fFlushForPrune;
            // Write blocks, block index and best chain related state to disk.
            if (should_write) {
                // Ensure we can write block index
                if (!CheckDiskSpace(m_blockman.m_opts.blocks_dir)) {
                    return FatalError(m_chainman.GetNotifications(), state,
                                      "Disk space is too low!",
                                      _("Disk space is too low!"));
                }

                {
                    LOG_TIME_MILLIS_WITH_CATEGORY(
                        "write block and undo data to disk", BCLog::BENCH);

                    // First make sure all block and undo data is flushed to
                    // disk.
                    if (!m_blockman.FlushChainstateBlockFile(
                            m_chain.Height())) {
                        return FatalError(m_chainman.GetNotifications(), state,
                                          "Failed to flush block file",
                                          _("Failed to flush block file"));
                    }
                }
                // Then update all block file information (which may refer to
                // block and undo files).
                {
                    LOG_TIME_MILLIS_WITH_CATEGORY("write block index to disk",
                                                  BCLog::BENCH);

                    m_blockman.WriteBlockIndexDB();
                }

                // Finally remove any pruned files
                if (fFlushForPrune) {
                    LOG_TIME_MILLIS_WITH_CATEGORY("unlink pruned files",
                                                  BCLog::BENCH);

                    m_blockman.UnlinkPrunedFiles(setFilesToPrune);
                    node::PublishChainTipSnapshot(m_chainman, m_mempool);
                }

                if (!CoinsTip().GetBestBlock().IsNull()) {
                    // Typical Coin structures on disk are around 48 bytes in
                    // size. Pushing a new one to the database can cause it to
                    // be written twice (once in the log, and once in the
                    // tables). This is already an overestimation, as most will
                    // delete an existing entry or overwrite one. Still, use a
                    // conservative safety factor of 2.
                    if (!CheckDiskSpace(m_chainman.m_options.datadir,
                                        48 * 2 * 2 *
                                            CoinsTip().GetDirtyCount())) {
                        return FatalError(m_chainman.GetNotifications(), state,
                                          "Disk space is too low!",
                                          _("Disk space is too low!"));
                    }

                    // Flush the chainstate (which may refer to block index
                    // entries).
                    const auto empty_cache{(mode == FlushStateMode::ALWAYS) ||
                                           fCacheLarge || fCacheCritical};
                    // Recovery and the next block also need the native parent
                    // snapshot. Publish it before any partial coins batch can
                    // advance DB_HEAD_BLOCKS or terminate through fault injection.
                    if (!FlushV2BlockStatesToDisk()) {
                        throw std::runtime_error(
                            "Unable to persist native block states before coins flush");
                    }
                    const auto flush_start{SteadyClock::now()};
                    empty_cache ? CoinsTip().Flush() : CoinsTip().Sync();
                    full_flush_completed = true;
                    if (metrics) {
                        metrics->utxo_flush_seconds.RecordDuration(
                            SteadyClock::now() - flush_start,
                            empty_cache ? 0 : 1);
                    }
                    TRACE5(utxocache, flush,
                           int64_t{Ticks<std::chrono::microseconds>(
                               SteadyClock::now() - nNow)},
                           uint32_t(mode), coins_count,
                           uint64_t(coins_mem_usage), fFlushForPrune);
                }
            }

            if (should_write || m_next_write == NodeClock::time_point::max()) {
                constexpr auto range{DATABASE_WRITE_INTERVAL_MAX -
                                     DATABASE_WRITE_INTERVAL_MIN};
                m_next_write = FastRandomContext().rand_uniform_delay(
                    NodeClock::now() + DATABASE_WRITE_INTERVAL_MIN, range);
            }
        }

        if (full_flush_completed && m_chainman.m_options.signals) {
            // Update best block in wallet (so we can detect restored wallets).
            m_chainman.m_options.signals->ChainStateFlushed(
                this->GetRole(), m_chain.GetLocator());
        }
    } catch (const std::runtime_error &e) {
        return FatalError(m_chainman.GetNotifications(), state,
                          std::string("System error while flushing: ") +
                              e.what());
    }
    return true;
}

void Chainstate::ForceFlushStateToDisk() {
    BlockValidationState state;
    if (!this->FlushStateToDisk(state, FlushStateMode::ALWAYS)) {
        LogInfoEvent(BCLog::ALL, "chainstate_flush_failed",
                     "{source_function}: failed to flush state ({reason})")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state);
    }
}

void Chainstate::PruneAndFlush() {
    BlockValidationState state;
    m_blockman.m_check_for_pruning = true;
    if (!this->FlushStateToDisk(state, FlushStateMode::NONE)) {
        LogInfoEvent(BCLog::ALL, "chainstate_flush_failed",
                     "{source_function}: failed to flush state ({reason})")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state);
    }
}

static void UpdateTipLog(const CCoinsViewCache &coins_tip,
                         const CBlockIndex *tip, const CChainParams &params,
                         const std::string &func_name,
                         const std::string &prefix)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    AssertLockHeld(::cs_main);

    // Preserve unrestricted progress reporting during IBD; ring-full policy
    // remains the same as other Info events.
    LogInfoEventNoRateLimit(
        BCLog::LogFlags::ALL, "chain_tip_updated",
        "{log_prefix}{source_function}: new best={block_hash} height={height} "
        "version=0x{version:08x} log2_work={log2_work:f} tx={chain_tx_count} "
        "date='{block_time}' progress={verification_progress:f} "
        "cache={utxo_cache_mib:.1f}MiB({utxo_cache_coins}txo)")
        .Field(BCLog::LogField::LogPrefix, prefix)
        .Field(BCLog::LogField::SourceFunction, func_name)
        .Field(BCLog::LogField::BlockHash, tip->GetBlockHash())
        .Field(BCLog::LogField::Height, tip->nHeight)
        .Field(BCLog::LogField::Version, uint32_t(tip->nHeaderVersion))
        .Field(BCLog::LogField::Log2Work,
               log(tip->nChainWork.getdouble()) / log(2.0))
        .Field(BCLog::LogField::ChainTxCount, tip->GetChainTxCount())
        .Field(BCLog::LogField::BlockTime,
               FormatISO8601DateTime(tip->GetBlockTime()))
        .Field(BCLog::LogField::VerificationProgress,
               GuessVerificationProgress(params.TxData(), tip))
        .Field(BCLog::LogField::UTXOCacheMiB,
               coins_tip.DynamicMemoryUsage() * (1.0 / (1 << 20)))
        .Field(BCLog::LogField::UTXOCacheCoins, coins_tip.GetCacheSize())
        .Field(BCLog::LogField::UTXOCacheBytes, coins_tip.DynamicMemoryUsage())
        .Field(BCLog::LogField::BlockTimeSeconds, tip->GetBlockTime())
        .Field(BCLog::LogField::ChainstateRole,
               prefix.empty() ? BCLog::LogStatic("active")
                              : BCLog::LogStatic("background"));
}

static void SyncAdaptiveCapacityTip(const CBlockIndex *tip)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    auto &controller = lotus::v2::GetGlobalFeeHysteresisController();
    const bool available = controller.HasCompleteAdaptiveHistory();
    controller.SyncActiveTip(tip, TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now()));
    if (available && !controller.HasCompleteAdaptiveHistory()) {
        LogWarning("Adaptive capacity history unavailable (missing ancestor block size); "
                   "using configured baseline capacity. Complete ancestry and restart to reconstruct.\n");
    }
}

void Chainstate::UpdateTip(const CBlockIndex *pindexNew) {
    AssertLockHeld(::cs_main);
    const auto &coins_tip = CoinsTip();

    const CChainParams &params{m_chainman.GetParams()};

    // The remainder of the function isn't relevant if we are not acting on
    // the active chainstate, so return if need be.
    if (this != &m_chainman.ActiveChainstate()) {
        // Only log every so often so that we don't bury log messages at the
        // tip.
        constexpr int BACKGROUND_LOG_INTERVAL = 2000;
        if (pindexNew->nHeight % BACKGROUND_LOG_INTERVAL == 0) {
            UpdateTipLog(coins_tip, pindexNew, params, __func__,
                         "[background validation] ");
        }
        return;
    }

    SyncAdaptiveCapacityTip(pindexNew);

    // New best block
    if (m_mempool) {
        m_mempool->AddTransactionsUpdated(1);
    }

    {
        LOCK(g_best_block_mutex);
        g_best_block = pindexNew;
        g_best_block_cv.notify_all();
    }
    node::SetTipMetrics(pindexNew->nHeight, pindexNew->GetBlockTime());

    node::PublishChainTipSnapshot(m_chainman, m_mempool);
    GetRPCBlockChangeWaiter().NotifyAll();

    UpdateTipLog(coins_tip, pindexNew, params, __func__, "");
}

/**
 * Disconnect m_chain's tip.
 * After calling, the mempool will be in an inconsistent state, with
 * transactions from disconnected blocks being added to disconnectpool. You
 * should make the mempool consistent again by calling updateMempoolForReorg.
 * with cs_main held.
 *
 * If disconnectpool is nullptr, then no disconnected transactions are added to
 * disconnectpool (note that the caller is responsible for mempool consistency
 * in any case).
 */
bool Chainstate::DisconnectTip(BlockValidationState &state,
                               DisconnectedBlockTransactions *disconnectpool) {
    AssertLockHeld(cs_main);
    if (m_mempool) {
        AssertLockHeld(m_mempool->cs);
    }

    CBlockIndex *pindexDelete = m_chain.Tip();

    assert(pindexDelete);
    assert(pindexDelete->pprev);

    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock &block = *pblock;
    if (!m_blockman.ReadBlock(block, *pindexDelete)) {
        LogErrorEvent(BCLog::ALL, "disconnect_tip_read_failed",
                      "DisconnectTip(): Failed to read block");
        return false;
    }

    // Apply the block atomically to the chain state.
    const auto time_start{SteadyClock::now()};
    {
        CCoinsViewCache view(&CoinsTip());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view) !=
            DisconnectResult::OK) {
            LogErrorEvent(
                BCLog::ALL, "chain_disconnect_block_failed",
                "DisconnectTip(): DisconnectBlock {block_hash} failed")
                .Field(BCLog::LogField::BlockHash,
                       pindexDelete->GetBlockHash());
            return false;
        }

        // local CCoinsViewCache goes out of scope
        view.Flush(/*reallocate_cache=*/false);
    }
    LogDebug(BCLog::BENCH, "- Disconnect block: %.2fms\n",
             Ticks<MillisecondsDouble>(SteadyClock::now() - time_start));

    {
        // Prune locks that began at or after the tip should be moved backward
        // so they get a chance to reorg
        const int max_height_first{pindexDelete->nHeight - 1};
        for (auto &prune_lock : m_blockman.m_prune_locks) {
            if (prune_lock.second.height_first <= max_height_first) {
                continue;
            }

            prune_lock.second.height_first = max_height_first;
            LogDebug(BCLog::PRUNE, "%s prune lock moved back to %d\n",
                     prune_lock.first, max_height_first);
        }
    }

    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FlushStateMode::IF_NEEDED)) {
        return false;
    }

    if (m_mempool) {
        CTxMemPool::ScopedSnapshotDefer snap_defer(*m_mempool);
        // If this block is deactivating a fork, we move all mempool
        // transactions in front of disconnectpool for reprocessing in a future
        // updateMempoolForReorg call
        if (pindexDelete->pprev != nullptr &&
            GetNextBlockScriptFlags(pindexDelete, m_chainman) !=
                GetNextBlockScriptFlags(pindexDelete->pprev, m_chainman)) {
            LogEvent(BCLog::MEMPOOL, "mempool_upgrade_rewind",
                     "Disconnecting mempool due to rewind of upgrade block");
            if (disconnectpool) {
                disconnectpool->importMempool(*m_mempool);
            }
            m_mempool->clear();
        }

        if (disconnectpool) {
            disconnectpool->addForBlock(block.vtx, *m_mempool);
        }
        m_mempool->ConnectBlockReset(
            pindexDelete->pprev->GetBlockHash(),
            static_cast<uint64_t>(pindexDelete->pprev->nHeight + 1),
            static_cast<uint64_t>(pindexDelete->pprev->GetMedianTimePast()));
        snap_defer.CancelFlush();
    }

    m_chain.SetTip(*pindexDelete->pprev);

    UpdateTip(pindexDelete->pprev);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    if (m_chainman.m_options.signals) {
        m_chainman.m_options.signals->BlockDisconnected(pblock, pindexDelete);
    }
    return true;
}

/**
 * Connect a new block to m_chain. pblock is either nullptr or a pointer to
 * a CBlock corresponding to pindexNew, to bypass loading it again from disk.
 */
bool Chainstate::ConnectTip(BlockValidationState &state,
                            BlockPolicyValidationState &blockPolicyState,
                            CBlockIndex *pindexNew,
                            const std::shared_ptr<const CBlock> &pblock,
                            DisconnectedBlockTransactions &disconnectpool,
                            const avalanche::Processor *const avalanche,
                            const ChainstateRole chainstate_role) {
    AssertLockHeld(cs_main);
    if (m_mempool) {
        AssertLockHeld(m_mempool->cs);
    }

    const Consensus::Params &consensusParams = m_chainman.GetConsensus();

    assert(pindexNew->pprev == m_chain.Tip());
    // Read block from disk.
    const auto time_1{SteadyClock::now()};
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!m_blockman.ReadBlock(*pblockNew, *pindexNew)) {
            return FatalError(m_chainman.GetNotifications(), state,
                              "Failed to read block");
        }
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }

    const CBlock &blockConnecting = *pthisBlock;

    // Apply the block atomically to the chain state.
    const auto time_2{SteadyClock::now()};
    SteadyClock::time_point time_3;
    // When adding aggregate statistics in the future, keep in mind that
    // num_blocks_total may be zero until the ConnectBlock() call below.
    LogDebug(BCLog::BENCH, "  - Load block from disk: %.2fms\n",
             Ticks<MillisecondsDouble>(time_2 - time_1));
    {
        Amount blockFees{Amount::zero()};
        CCoinsViewCache &view{*m_coins_views->m_connect_block_view};
        const auto reset_guard{view.CreateResetGuard()};
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view,
                               BlockValidationOptions(m_chainman.GetConfig()),
                               &blockFees);
        if (auto *metrics{node::GetNodeMetrics()}; metrics && rv) {
            metrics->block_connect_seconds.RecordDuration(SteadyClock::now() -
                                                          time_2);
        }
        if (m_chainman.m_options.signals) {
            m_chainman.m_options.signals->BlockChecked(blockConnecting, state);
        }
        if (!rv) {
            if (state.IsInvalid()) {
                InvalidBlockFound(pindexNew, state);
            }

            LogErrorEvent(
                BCLog::ALL, "chain_connect_block_failed",
                "{source_function}: ConnectBlock {block_hash} failed, {reason}")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::BlockHash, pindexNew->GetBlockHash())
                .Field(BCLog::LogField::Reason, state);
            return false;
        }

        /**
         * The block is valid by consensus rules so now we check if the block
         * passes all block policy checks. If not, then park the block and bail.
         *
         * We check block parking policies before flushing changes to the UTXO
         * set. This allows us to avoid rewinding everything immediately after.
         *
         * Only check block parking policies the first time the block is
         * connected. Avalanche voting can override the parking decision made by
         * these policies.
         */
        const BlockHash blockhash = pindexNew->GetBlockHash();
        if (!m_chainman.IsInitialBlockDownload() &&
            !m_filterParkingPoliciesApplied.contains(blockhash)) {
            m_filterParkingPoliciesApplied.insert(blockhash);

            const Amount blockSubsidy =
                GetBlockSubsidy(pindexNew->nHeight, consensusParams);
            const Amount blockReward = blockFees + blockSubsidy;

            std::vector<std::unique_ptr<ParkingPolicy>> parkingPolicies;
            parkingPolicies.emplace_back(std::make_unique<MinerFundPolicy>(
                consensusParams, *pindexNew, blockConnecting, blockReward));

            if (avalanche) {
                // Only enable the RTT policy if the node already finalized a
                // block. This is because it's very possible that new blocks
                // will be parked after a node restart (but after IBD) if the
                // node is behind by a few blocks. We want to make sure that the
                // node will be able to switch back to the right tip in this
                // case.
                if (avalanche->hasFinalizedTip()) {
                    // Special case for testnet, don't reject blocks mined with
                    // the min difficulty
                    if (!consensusParams.fPowAllowMinDifficultyBlocks ||
                        (blockConnecting.GetBlockTime() <=
                         pindexNew->pprev->GetBlockTime() +
                             2 * consensusParams.nPowTargetSpacing)) {
                        parkingPolicies.emplace_back(
                            std::make_unique<RTTPolicy>(consensusParams,
                                                        *pindexNew));
                    }
                }

                if (avalanche->isQuorumEstablished()) {
                    parkingPolicies.emplace_back(
                        std::make_unique<StakingRewardsPolicy>(
                            *avalanche, consensusParams, *pindexNew,
                            blockConnecting, blockSubsidy));

                    parkingPolicies.emplace_back(
                        std::make_unique<TreasuryPolicy>(
                            *avalanche, consensusParams, *pindexNew,
                            blockConnecting, blockSubsidy));

                    if (m_mempool) {
                        parkingPolicies.emplace_back(
                            std::make_unique<PreConsensusPolicy>(
                                *avalanche, *pindexNew, blockConnecting,
                                m_mempool, &disconnectpool));
                    }
                }
            }

            // If any block policy is violated, bail on the first one found
            if (std::find_if_not(parkingPolicies.begin(), parkingPolicies.end(),
                                 [&](const auto &policy) {
                                     bool ret = (*policy)(blockPolicyState);
                                     if (!ret) {
                                         LogInfoEvent(
                                             BCLog::ALL, "block_parked_policy",
                                             "Park block because it violated a block policy: {reason}")
                                             .Field(
                                                 BCLog::LogField::Reason,
                                                 blockPolicyState.ToString());
                                     }
                                     return ret;
                                 }) != parkingPolicies.end()) {
                node::CountParkedBlock(node::BlockParkReason::POLICY);
                pindexNew->nStatus = pindexNew->nStatus.withParked();
                pindexNew->m_preconsensus_policy_parked =
                    blockPolicyState.GetRejectReason() == "finalized-batch-mismatch";
                m_blockman.m_dirty_blockindex.insert(pindexNew);
                return false;
            }
        }

        time_3 = SteadyClock::now();
        m_chainman.time_connect_total += time_3 - time_2;
        assert(m_chainman.num_blocks_total > 0);
        LogDebug(BCLog::BENCH,
                 "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n",
                 Ticks<MillisecondsDouble>(time_3 - time_2),
                 Ticks<SecondsDouble>(m_chainman.time_connect_total),
                 Ticks<MillisecondsDouble>(m_chainman.time_connect_total) /
                     m_chainman.num_blocks_total);
        // No need to reallocate since it only has capacity for 1 block
        view.Flush(/*reallocate_cache=*/false);
    }

    const auto time_4{SteadyClock::now()};
    m_chainman.time_flush += time_4 - time_3;
    LogDebug(BCLog::BENCH, "  - Flush: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_4 - time_3),
             Ticks<SecondsDouble>(m_chainman.time_flush),
             Ticks<MillisecondsDouble>(m_chainman.time_flush) /
                 m_chainman.num_blocks_total);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FlushStateMode::IF_NEEDED)) {
        return false;
    }
    const auto time_5{SteadyClock::now()};
    m_chainman.time_chainstate += time_5 - time_4;
    LogDebug(BCLog::BENCH,
             "  - Writing chainstate: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_5 - time_4),
             Ticks<SecondsDouble>(m_chainman.time_chainstate),
             Ticks<MillisecondsDouble>(m_chainman.time_chainstate) /
                 m_chainman.num_blocks_total);
    // Remove conflicting transactions from the mempool.
    if (m_mempool) {
        CTxMemPool::ScopedSnapshotDefer snap_defer(*m_mempool);
        disconnectpool.removeForBlock(blockConnecting.vtx, *m_mempool);

        // If this block is activating a fork, we move all mempool transactions
        // in front of disconnectpool for reprocessing in a future
        // updateMempoolForReorg call
        if (pindexNew->pprev != nullptr &&
            GetNextBlockScriptFlags(pindexNew, m_chainman) !=
                GetNextBlockScriptFlags(pindexNew->pprev, m_chainman)) {
            LogEvent(
                BCLog::MEMPOOL, "mempool_upgrade_accepted",
                "Disconnecting mempool due to acceptance of upgrade block");
            disconnectpool.importMempool(*m_mempool);
        }
        m_mempool->ConnectBlockReset(
            pindexNew->GetBlockHash(),
            static_cast<uint64_t>(pindexNew->nHeight + 1),
            static_cast<uint64_t>(pindexNew->GetMedianTimePast()));
        snap_defer.CancelFlush();
    }

    // Update m_chain & related variables.
    m_chain.SetTip(*pindexNew);
    UpdateTip(pindexNew);

    const auto time_6{SteadyClock::now()};
    m_chainman.time_post_connect += time_6 - time_5;
    node::RecordBlockStage(node::BlockStage::LOAD, time_2 - time_1);
    node::RecordBlockStage(node::BlockStage::FLUSH, time_4 - time_3);
    node::RecordBlockStage(node::BlockStage::CHAINSTATE, time_5 - time_4);
    node::RecordBlockStage(node::BlockStage::POST_CONNECT, time_6 - time_5);
    m_chainman.time_total += time_6 - time_1;
    LogDebug(BCLog::BENCH,
             "  - Connect postprocess: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_6 - time_5),
             Ticks<SecondsDouble>(m_chainman.time_post_connect),
             Ticks<MillisecondsDouble>(m_chainman.time_post_connect) /
                 m_chainman.num_blocks_total);
    LogDebug(BCLog::BENCH, "- Connect block: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_6 - time_1),
             Ticks<SecondsDouble>(m_chainman.time_total),
             Ticks<MillisecondsDouble>(m_chainman.time_total) /
                 m_chainman.num_blocks_total);

    // If we are the background validation chainstate, check to see if we are
    // done validating the snapshot (i.e. our tip has reached the snapshot's
    // base block).
    if (this != &m_chainman.ActiveChainstate()) {
        // This call may set `m_disabled`, which is referenced immediately
        // afterwards in ActivateBestChain, so that we stop connecting blocks
        // past the snapshot base.
        m_chainman.MaybeCompleteSnapshotValidation();
    }

    if (m_chainman.m_options.signals) {
        m_chainman.m_options.signals->BlockConnected(chainstate_role,
                                                     pthisBlock, pindexNew);
    }
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't known to be
 * invalid (it's however far from certain to be valid).
 */
CBlockIndex *Chainstate::FindMostWorkChain(
    std::vector<const CBlockIndex *> &blocksToReconcile, bool fAutoUnpark) {
    AssertLockHeld(::cs_main);
    do {
        CBlockIndex *pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex *, CBlockIndexWorkComparator>::reverse_iterator
                it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend()) {
                return nullptr;
            }
            pindexNew = *it;
        }

        // Work-based retry is only for soft policy parks. It must never
        // override Avalanche-finalized ancestry, regardless of chain work.
        bool conflictsFinalizedAncestry = false;
        // If this block will cause an avalanche finalized block to be reorged,
        // then we park it.
        {
            LOCK(cs_avalancheFinalizedBlockIndex);
            if (m_avalancheFinalizedBlockIndex &&
                !AreOnTheSameFork(pindexNew, m_avalancheFinalizedBlockIndex)) {
                conflictsFinalizedAncestry = true;
                LogInfoEvent(
                    BCLog::ALL, "block_parked_before_finalized_tip",
                    "Park block {block_hash} because it forks prior to the avalanche finalized chaintip.")
                    .Field(BCLog::LogField::BlockHash,
                           pindexNew->GetBlockHash());
                node::CountParkedBlock(
                    node::BlockParkReason::FINALIZATION_CONFLICT);
                pindexNew->nStatus = pindexNew->nStatus.withParked();
                m_blockman.m_dirty_blockindex.insert(pindexNew);
            }
        }

        const CBlockIndex *pindexFork = m_chain.FindFork(pindexNew);

        // A finalized-batch mismatch is a temporary work penalty, even when
        // general automatic unparking is off (the Avalanche default). It only
        // applies when every park on the candidate's path is such a park, so
        // Avalanche rejections and other parks stay parked as upstream.
        bool fBatchRetryOnly = false;
        if (!fAutoUnpark) {
            bool sawBatchPark = false;
            bool sawOtherPark = false;
            for (const CBlockIndex *p = pindexNew; p && p != pindexFork;
                 p = p->pprev) {
                if (p->nStatus.isParked()) {
                    if (p->m_preconsensus_policy_parked) {
                        sawBatchPark = true;
                    } else {
                        sawOtherPark = true;
                    }
                }
            }
            fBatchRetryOnly = sawBatchPark && !sawOtherPark;
        }

        // Check whether all blocks on the path between the currently active
        // chain and the candidate are valid. Just going until the active chain
        // is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool hasValidAncestor = true;
        while (hasValidAncestor && pindexTest && pindexTest != pindexFork) {
            assert(pindexTest->HaveNumChainTxs() || pindexTest->nHeight == 0);

            // If this is a parked chain, but it has enough PoW, clear the park
            // state.
            bool fParkedChain = pindexTest->nStatus.isOnParkedChain();
            if ((fAutoUnpark || fBatchRetryOnly) && fParkedChain &&
                !conflictsFinalizedAncestry) {
                const CBlockIndex *pindexTip = m_chain.Tip();

                // During initialization, pindexTip and/or pindexFork may be
                // null. In this case, we just ignore the fact that the chain is
                // parked.
                if (!pindexTip || !pindexFork) {
                    UnparkBlock(pindexTest);
                    continue;
                }

                // A parked chain can be unparked if it has twice as much PoW
                // accumulated as the main chain has since the fork block.
                CBlockIndex const *pindexExtraPow = pindexTip;
                arith_uint256 requiredWork = pindexTip->nChainWork;
                switch (pindexTip->nHeight - pindexFork->nHeight) {
                    // Limit the penality for depth 1, 2 and 3 to half a block
                    // worth of work to ensure we don't fork accidentally.
                    case 3:
                    case 2:
                        pindexExtraPow = pindexExtraPow->pprev;
                    // FALLTHROUGH
                    case 1: {
                        const arith_uint256 deltaWork =
                            pindexExtraPow->nChainWork - pindexFork->nChainWork;
                        requiredWork += (deltaWork >> 1);
                        break;
                    }
                    default:
                        requiredWork +=
                            pindexExtraPow->nChainWork - pindexFork->nChainWork;
                        break;
                }

                // A batch-mismatching head needs one more block of work;
                // otherwise fork==tip would undo the policy in this same call.
                if (pindexTest->m_preconsensus_policy_parked) {
                    requiredWork = std::max(requiredWork, pindexTest->nChainWork);
                }
                if (pindexNew->nChainWork > requiredWork) {
                    // We have enough, clear the parked state.
                    LogInfoEvent(
                        BCLog::ALL, "chain_unparked_by_work",
                        "Unpark chain up to block {block_hash} as it has accumulated enough PoW.")
                        .Field(BCLog::LogField::BlockHash,
                               pindexNew->GetBlockHash());
                    fParkedChain = false;
                    UnparkBlock(pindexTest);
                }
            }

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted. Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fInvalidChain = pindexTest->nStatus.isInvalid();
            bool fMissingData = !pindexTest->nStatus.hasData();
            if (!(fInvalidChain || fParkedChain || fMissingData)) {
                // The current block is acceptable, move to the parent, up to
                // the fork point.
                pindexTest = pindexTest->pprev;
                continue;
            }

            // Candidate chain is not usable (either invalid or parked or
            // missing data)
            hasValidAncestor = false;
            setBlockIndexCandidates.erase(pindexTest);

            if (fInvalidChain && (m_chainman.m_best_invalid == nullptr ||
                                  pindexNew->nChainWork >
                                      m_chainman.m_best_invalid->nChainWork)) {
                m_chainman.m_best_invalid = pindexNew;
            }

            if (fParkedChain && (m_chainman.m_best_parked == nullptr ||
                                 pindexNew->nChainWork >
                                     m_chainman.m_best_parked->nChainWork)) {
                m_chainman.m_best_parked = pindexNew;
            }

            LogPrintf("Considered switching to better tip %s but that chain "
                      "contains a%s%s%s block.\n",
                      pindexNew->GetBlockHash().ToString(),
                      fInvalidChain ? "n invalid" : "",
                      fParkedChain ? " parked" : "",
                      fMissingData ? " missing-data" : "");

            CBlockIndex *pindexFailed = pindexNew;
            // Remove the entire chain from the set.
            while (pindexTest != pindexFailed) {
                if (fInvalidChain || fParkedChain) {
                    pindexFailed->nStatus =
                        pindexFailed->nStatus.withFailedParent(fInvalidChain)
                            .withParkedParent(fParkedChain);
                    m_blockman.m_dirty_blockindex.insert(pindexFailed);
                } else if (fMissingData) {
                    // If we're missing data, then add back to
                    // m_blocks_unlinked, so that if the block arrives in the
                    // future we can try adding to setBlockIndexCandidates
                    // again.
                    m_blockman.m_blocks_unlinked.insert(
                        std::make_pair(pindexFailed->pprev, pindexFailed));
                }
                setBlockIndexCandidates.erase(pindexFailed);
                pindexFailed = pindexFailed->pprev;
            }

            if (fInvalidChain || fParkedChain) {
                // We discovered a new chain tip that is either parked or
                // invalid, we may want to warn.
                CheckForkWarningConditionsOnNewFork(pindexNew);
            }
        }

        blocksToReconcile.push_back(pindexNew);

        // We found a candidate that has valid ancestors. This is our guy.
        if (hasValidAncestor) {
            return pindexNew;
        }
    } while (true);
}

/**
 * Delete all entries in setBlockIndexCandidates that are worse than the current
 * tip.
 */
void Chainstate::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to
    // return to it later in case a reorganization to a better block fails.
    auto it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() &&
           setBlockIndexCandidates.value_comp()(*it, m_chain.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }

    // Either the current tip or a successor of it we're working towards is left
    // in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to
 * pindexMostWork.
 *
 * @returns true unless a system error occurred
 */
bool Chainstate::ActivateBestChainStep(
    BlockValidationState &state, CBlockIndex *pindexMostWork,
    const std::shared_ptr<const CBlock> &pblock, bool &fInvalidFound,
    const avalanche::Processor *const avalanche,
    const ChainstateRole chainstate_role) {
    AssertLockHeld(cs_main);
    if (m_mempool) {
        AssertLockHeld(m_mempool->cs);
    }

    const CBlockIndex *pindexOldTip = m_chain.Tip();
    const CBlockIndex *pindexFork = m_chain.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (m_chain.Tip() && m_chain.Tip() != pindexFork) {
        if (m_mempool && !fBlocksDisconnected) {
            // Import and clear mempool; we must do this to preserve
            // topological ordering in the mempool index. This is ok since
            // inserts into the mempool are very fast now in our new
            // implementation.
            disconnectpool.importMempool(*m_mempool);
        }

        if (!DisconnectTip(state, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            if (m_mempool) {
                disconnectpool.updateMempoolForReorg(*this, false, *m_mempool);
            }

            // If we're unable to disconnect a block during normal operation,
            // then that is a failure of our local system -- we should abort
            // rather than stay on a less work chain.
            FatalError(m_chainman.GetNotifications(), state,
                       "Failed to disconnect block; see debug.log for details");
            return false;
        }

        fBlocksDisconnected = true;
    }
    if (fBlocksDisconnected && pindexOldTip) {
        if (auto *metrics{node::GetNodeMetrics()}) {
            metrics->chain_reorgs.Inc();
            metrics->chain_reorg_depth.Record(
                uint64_t(pindexOldTip->nHeight -
                         (pindexFork ? pindexFork->nHeight : -1)));
        }
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex *> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the
        // best tip, as we likely only need a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }

        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex *pindexConnect : reverse_iterate(vpindexToConnect)) {
            BlockPolicyValidationState blockPolicyState;
            if (!ConnectTip(state, blockPolicyState, pindexConnect,
                            pindexConnect == pindexMostWork
                                ? pblock
                                : std::shared_ptr<const CBlock>(),
                            disconnectpool, avalanche, chainstate_role)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (state.GetResult() !=
                        BlockValidationResult::BLOCK_MUTATED) {
                        InvalidChainFound(vpindexToConnect.front());
                    }
                    state = BlockValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                }

                if (blockPolicyState.IsInvalid()) {
                    // The block violates a policy rule.
                    CBlockIndex *pindexParkedDescendant = pindexMostWork;
                    while (pindexParkedDescendant &&
                           pindexParkedDescendant != pindexConnect) {
                        pindexParkedDescendant->nStatus =
                            pindexParkedDescendant->nStatus.withParkedParent();
                        m_blockman.m_dirty_blockindex.insert(
                            pindexParkedDescendant);
                        setBlockIndexCandidates.erase(pindexParkedDescendant);
                        pindexParkedDescendant = pindexParkedDescendant->pprev;
                    }
                    // A descendant may already supply the batch-policy grace
                    // work when its ancestor is parked for the first time.
                    // Let FindMostWorkChain apply the ordinary work/finality
                    // checks instead of losing that candidate until new data.
                    if (pindexConnect->m_preconsensus_policy_parked &&
                        pindexMostWork != pindexConnect) {
                        TryAddBlockIndexCandidate(pindexMostWork);
                    }
                    fContinue = false;
                    break;
                }

                // A system error occurred (disk space, database error, ...).
                // Make the mempool consistent with the current tip, just in
                // case any observers try to use it before shutdown.
                if (m_mempool) {
                    disconnectpool.updateMempoolForReorg(*this, false,
                                                         *m_mempool);
                }
                return false;
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip ||
                    m_chain.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return
                    // temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (m_mempool) {
        if (fBlocksDisconnected || !disconnectpool.isEmpty()) {
            // If any blocks were disconnected, we need to update the mempool
            // even if disconnectpool is empty. The disconnectpool may also be
            // non-empty if the mempool was imported due to new validation rules
            // being in effect.
            LogEvent(BCLog::MEMPOOL, "mempool_reorg_update",
                     "Updating mempool due to reorganization or rules "
                     "upgrade/downgrade");
            disconnectpool.updateMempoolForReorg(*this, true, *m_mempool);
        }

        m_mempool->check(this->CoinsTip(), this->m_chain.Height() + 1);
    }

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound) {
        CheckForkWarningConditionsOnNewFork(pindexMostWork);
    } else {
        CheckForkWarningConditions();
    }

    return true;
}

static SynchronizationState GetSynchronizationState(bool init,
                                                    bool blockfiles_indexed) {
    if (!init) {
        return SynchronizationState::POST_INIT;
    }
    if (!blockfiles_indexed) {
        return SynchronizationState::INIT_REINDEX;
    }
    return SynchronizationState::INIT_DOWNLOAD;
}

bool ChainstateManager::NotifyHeaderTip() {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    CBlockIndex *pindexHeader = nullptr;
    {
        LOCK(GetMutex());
        pindexHeader = m_best_header;

        if (pindexHeader != m_last_notified_header) {
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            m_last_notified_header = pindexHeader;
        }
    }

    // Send block tip changed notifications without the lock held
    if (fNotify) {
        GetNotifications().headerTip(
            GetSynchronizationState(fInitialBlockDownload,
                                    m_blockman.m_blockfiles_indexed),
            pindexHeader->nHeight, pindexHeader->nTime, false);
    }
    return fNotify;
}

static void LimitValidationInterfaceQueue(ValidationSignals &signals)
    LOCKS_EXCLUDED(cs_main) {
    AssertLockNotHeld(cs_main);

    if (signals.CallbacksPending() > 10) {
        signals.SyncWithValidationInterfaceQueue();
    }
}

bool Chainstate::ActivateBestChain(BlockValidationState &state,
                                   std::shared_ptr<const CBlock> pblock,
                                   avalanche::Processor *const avalanche) {
    AssertLockNotHeld(m_chainstate_mutex);

    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(::cs_main);

    // ABC maintains a fair degree of expensive-to-calculate internal state
    // because this function periodically releases cs_main so that it does not
    // lock up other threads for too long during large connects - and to allow
    // for e.g. the callback queue to drain we use m_chainstate_mutex to enforce
    // mutual exclusion so that only one caller may execute this function at a
    // time
    LOCK(m_chainstate_mutex);

    // Belt-and-suspenders check that we aren't attempting to advance the
    // background chainstate past the snapshot base block.
    if (WITH_LOCK(::cs_main, return m_disabled)) {
        LogInfoEvent(
            BCLog::ALL, "disabled_chainstate_advance_refused",
            "m_disabled is set - this chainstate should not be in operation. Please report this as a bug. {bug_report_url}")
            .Field(BCLog::LogField::BugReportURL, PACKAGE_BUGREPORT);
        return false;
    }

    CBlockIndex *pindexMostWork = nullptr;
    CBlockIndex *pindexNewTip = nullptr;
    bool exited_ibd{false};
    do {
        // Block until the validation queue drains. This should largely
        // never happen in normal operation, however may happen during
        // reindex, causing memory blowup if we run too far ahead.
        // Note that if a validationinterface callback ends up calling
        // ActivateBestChain this may lead to a deadlock! We should
        // probably have a DEBUG_LOCKORDER test for this in the future.
        if (m_chainman.m_options.signals) {
            LimitValidationInterfaceQueue(*m_chainman.m_options.signals);
        }

        std::vector<const CBlockIndex *> blocksToReconcile;
        bool blocks_connected = false;

        {
            LOCK(cs_main);
            // Lock transaction pool for at least as long as it takes for
            // updateMempoolForReorg to be executed if needed
            LOCK(MempoolMutex());
            const bool was_in_ibd = m_chainman.IsInitialBlockDownload();
            CBlockIndex *starting_tip = m_chain.Tip();
            do {
                // We absolutely may not unlock cs_main until we've made forward
                // progress (with the exception of shutdown due to hardware
                // issues, low disk space, etc).

                if (pindexMostWork == nullptr) {
                    pindexMostWork = FindMostWorkChain(
                        blocksToReconcile,
                        m_chainman.m_options.automatic_unparking);
                }

                // Whether we have anything to do at all.
                if (pindexMostWork == nullptr ||
                    pindexMostWork == m_chain.Tip()) {
                    break;
                }

                bool fInvalidFound = false;
                std::shared_ptr<const CBlock> nullBlockPtr;
                // BlockConnected signals must be sent for the original role;
                // in case snapshot validation is completed during
                // ActivateBestChainStep, the result of GetRole() changes from
                // BACKGROUND to NORMAL.
                const ChainstateRole chainstate_role{this->GetRole()};
                if (!ActivateBestChainStep(
                        state, pindexMostWork,
                        pblock && pblock->GetHash() ==
                                      pindexMostWork->GetBlockHash()
                            ? pblock
                            : nullBlockPtr,
                        fInvalidFound, avalanche, chainstate_role)) {
                    // A system error occurred
                    return false;
                }
                blocks_connected = true;

                if (fInvalidFound ||
                    (pindexMostWork &&
                     pindexMostWork->nStatus.isOnParkedChain())) {
                    // Wipe cache, we may need another branch now.
                    pindexMostWork = nullptr;
                }

                pindexNewTip = m_chain.Tip();

                // This will have been toggled in
                // ActivateBestChainStep -> ConnectTip ->
                // MaybeCompleteSnapshotValidation, if at all, so we should
                // catch it here.
                //
                // Break this do-while to ensure we don't advance past the base
                // snapshot.
                if (m_disabled) {
                    break;
                }
            } while (!m_chain.Tip() ||
                     (starting_tip && CBlockIndexWorkComparator()(
                                          m_chain.Tip(), starting_tip)));

            // Check the index once we're done with the above loop, since
            // we're going to release cs_main soon. If the index is in a bad
            // state now, then it's better to know immediately rather than
            // randomly have it cause a problem in a race.
            m_chainman.CheckBlockIndex();

            if (blocks_connected) {
                const CBlockIndex *pindexFork = m_chain.FindFork(starting_tip);
                bool still_in_ibd = m_chainman.IsInitialBlockDownload();

                if (was_in_ibd && !still_in_ibd) {
                    // Active chainstate has exited IBD
                    exited_ibd = true;
                }

                // Notify external listeners about the new tip.
                // Enqueue while holding cs_main to ensure that UpdatedBlockTip
                // is called in the order in which blocks are connected
                if (this == &m_chainman.ActiveChainstate() &&
                    pindexFork != pindexNewTip) {
                    // Notify ValidationInterface subscribers
                    if (m_chainman.m_options.signals) {
                        m_chainman.m_options.signals->UpdatedBlockTip(
                            pindexNewTip, pindexFork, still_in_ibd);
                    }

                    // Always notify the UI if a new block tip was connected
                    if (kernel::IsInterrupted(
                            m_chainman.GetNotifications().blockTip(
                                GetSynchronizationState(
                                    still_in_ibd,
                                    m_chainman.m_blockman.m_blockfiles_indexed),
                                *pindexNewTip))) {
                        // Just breaking and returning success for now. This
                        // could be changed to bubble up the kernel::Interrupted
                        // value to the caller so the caller could distinguish
                        // between completed and interrupted operations.
                        break;
                    }
                }
            }
        }
        // When we reach this point, we switched to a new tip (stored in
        // pindexNewTip).
        if (avalanche) {
            const CBlockIndex *pfinalized =
                WITH_LOCK(cs_avalancheFinalizedBlockIndex,
                          return m_avalancheFinalizedBlockIndex);
            for (const CBlockIndex *pindex : blocksToReconcile) {
                avalanche->addToReconcile(pindex);

                // Compute staking rewards for all blocks with more chainwork to
                // just after the finalized block. We could stop at the fork
                // point, but this is more robust.
                if (blocks_connected) {
                    const CBlockIndex *pindexTest = pindex;
                    while (pindexTest && pindexTest != pfinalized) {
                        if (pindexTest->nHeight < pindex->nHeight - 3) {
                            // Only compute up to some max depth
                            break;
                        }
                        avalanche->computeStakingReward(pindexTest);
                        pindexTest = pindexTest->pprev;
                    }
                }
            }
        }

        if (!blocks_connected) {
            return true;
        }

        if (exited_ibd) {
            // If a background chainstate is in use, we may need to rebalance
            // our allocation of caches once a chainstate exits initial block
            // download.
            LOCK(::cs_main);
            m_chainman.MaybeRebalanceCaches();
        }

        if (WITH_LOCK(::cs_main, return m_disabled)) {
            // Background chainstate has reached the snapshot base block, so
            // exit.

            // Restart indexes to resume indexing for all blocks unique to the
            // snapshot chain. This resumes indexing "in order" from where the
            // indexing on the background validation chain left off.
            //
            // This cannot be done while holding cs_main (within
            // MaybeCompleteSnapshotValidation) or a cs_main deadlock will
            // occur.
            if (m_chainman.snapshot_download_completed) {
                m_chainman.snapshot_download_completed();
            }
            break;
        }

        // We check interrupt only after giving ActivateBestChainStep a chance
        // to run once so that we never interrupt before connecting the genesis
        // block during LoadChainTip(). Previously this caused an assert()
        // failure during interrupt in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (m_chainman.m_interrupt) {
            break;
        }
    } while (pindexNewTip != pindexMostWork);

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FlushStateMode::PERIODIC)) {
        return false;
    }

    return true;
}

bool Chainstate::PreciousBlock(BlockValidationState &state, CBlockIndex *pindex,
                               avalanche::Processor *const avalanche) {
    AssertLockNotHeld(m_chainstate_mutex);
    AssertLockNotHeld(::cs_main);
    {
        LOCK(cs_main);
        if (pindex->nChainWork < m_chain.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        }

        if (m_chain.Tip()->nChainWork > m_chainman.nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the
            // counter.
            m_chainman.nBlockReverseSequenceId = -1;
        }

        m_chainman.nLastPreciousChainwork = m_chain.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = m_chainman.nBlockReverseSequenceId;
        if (m_chainman.nBlockReverseSequenceId >
            std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            m_chainman.nBlockReverseSequenceId--;
        }

        // In case this was parked, unpark it.
        UnparkBlock(pindex);

        // Make sure it is added to the candidate list if appropriate.
        if (pindex->IsValid(BlockValidity::TRANSACTIONS) &&
            pindex->HaveNumChainTxs()) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, /*pblock=*/nullptr, avalanche);
}

namespace {
// Leverage RAII to run a functor at scope end
template <typename Func> struct Defer {
    Func func;
    Defer(Func &&f) : func(std::move(f)) {}
    ~Defer() { func(); }
};
} // namespace

bool Chainstate::UnwindBlock(BlockValidationState &state, CBlockIndex *pindex,
                             bool invalidate) {
    // Genesis block can't be invalidated or parked
    assert(pindex);
    if (pindex->nHeight == 0) {
        return false;
    }

    CBlockIndex *to_mark_failed_or_parked = pindex;
    bool pindex_was_in_chain = false;
    int disconnected = 0;

    // We do not allow ActivateBestChain() to run while UnwindBlock() is
    // running, as that could cause the tip to change while we disconnect
    // blocks. (Note for backport of Core PR16849: we acquire
    // LOCK(m_chainstate_mutex) in the Park, Invalidate and FinalizeBlock
    // functions due to differences in our code)
    AssertLockHeld(m_chainstate_mutex);

    // We'll be acquiring and releasing cs_main below, to allow the validation
    // callbacks to run. However, we should keep the block index in a
    // consistent state as we disconnect blocks -- in particular we need to
    // add equal-work blocks to setBlockIndexCandidates as we disconnect.
    // To avoid walking the block index repeatedly in search of candidates,
    // build a map once so that we can look up candidate blocks by chain
    // work as we go.
    std::multimap<const arith_uint256, CBlockIndex *> candidate_blocks_by_work;

    {
        LOCK(cs_main);
        for (auto &entry : m_blockman.m_block_index) {
            CBlockIndex *candidate = &entry.second;
            // We don't need to put anything in our active chain into the
            // multimap, because those candidates will be found and considered
            // as we disconnect.
            // Instead, consider only non-active-chain blocks that have at
            // least as much work as where we expect the new tip to end up.
            if (!m_chain.Contains(candidate) &&
                !CBlockIndexWorkComparator()(candidate, pindex->pprev) &&
                candidate->IsValid(BlockValidity::TRANSACTIONS) &&
                candidate->HaveNumChainTxs()) {
                candidate_blocks_by_work.insert(
                    std::make_pair(candidate->nChainWork, candidate));
            }
        }
    }

    {
        LOCK(cs_main);
        // Lock for as long as disconnectpool is in scope to make sure
        // UpdateMempoolForReorg is called after DisconnectTip without unlocking
        // in between
        LOCK(MempoolMutex());

        constexpr int maxDisconnectPoolBlocks = 10;
        bool ret = false;
        DisconnectedBlockTransactions disconnectpool;
        // After 10 blocks this becomes nullptr, so that DisconnectTip will
        // stop giving us unwound block txs if we are doing a deep unwind.
        DisconnectedBlockTransactions *optDisconnectPool = &disconnectpool;

        // Disable thread safety analysis because we can't require m_mempool->cs
        // as m_mempool can be null. We keep the runtime analysis though.
        Defer deferred([&]() NO_THREAD_SAFETY_ANALYSIS {
            AssertLockHeld(cs_main);
            if (m_mempool && !disconnectpool.isEmpty()) {
                AssertLockHeld(m_mempool->cs);
                // DisconnectTip will add transactions to disconnectpool.
                // When all unwinding is done and we are on a new tip, we must
                // add all transactions back to the mempool against the new tip.
                disconnectpool.updateMempoolForReorg(*this,
                                                     /* fAddToMempool = */ ret,
                                                     *m_mempool);
            }
        });

        // Disconnect (descendants of) pindex, and mark them invalid.
        while (true) {
            if (m_chainman.m_interrupt) {
                break;
            }

            // Make sure the queue of validation callbacks doesn't grow
            // unboundedly.
            // FIXME this commented code is a regression and could cause OOM if
            // a very old block is invalidated via the invalidateblock RPC.
            // This can be uncommented if the main signals are moved away from
            // cs_main or this code is refactored so that cs_main can be
            // released at this point.
            //
            // LimitValidationInterfaceQueue();

            if (!m_chain.Contains(pindex)) {
                break;
            }

            if (m_mempool && disconnected == 0) {
                // On first iteration, we grab all the mempool txs to preserve
                // topological ordering. This has the side-effect of temporarily
                // clearing the mempool, but we will re-add later in
                // updateMempoolForReorg() (above). This technique guarantees
                // mempool consistency as well as ensures that our topological
                // entry_id index is always correct.
                disconnectpool.importMempool(*m_mempool);
            }

            pindex_was_in_chain = true;
            CBlockIndex *invalid_walk_tip = m_chain.Tip();

            // ActivateBestChain considers blocks already in m_chain
            // unconditionally valid already, so force disconnect away from it.

            ret = DisconnectTip(state, optDisconnectPool);
            ++disconnected;

            if (optDisconnectPool && disconnected > maxDisconnectPoolBlocks) {
                // Stop using the disconnect pool after 10 blocks. After 10
                // blocks we no longer add block tx's to the disconnectpool.
                // However, when this scope ends we will reconcile what's
                // in the pool with the new tip (in the deferred d'tor above).
                optDisconnectPool = nullptr;
            }

            if (!ret) {
                return false;
            }

            assert(invalid_walk_tip->pprev == m_chain.Tip());

            // We immediately mark the disconnected blocks as invalid.
            // This prevents a case where pruned nodes may fail to
            // invalidateblock and be left unable to start as they have no tip
            // candidates (as there are no blocks that meet the "have data and
            // are not invalid per nStatus" criteria for inclusion in
            // setBlockIndexCandidates).

            invalid_walk_tip->nStatus =
                invalidate ? invalid_walk_tip->nStatus.withFailed()
                           : invalid_walk_tip->nStatus.withParked();

            m_blockman.m_dirty_blockindex.insert(invalid_walk_tip);
            setBlockIndexCandidates.insert(invalid_walk_tip->pprev);

            if (invalid_walk_tip == to_mark_failed_or_parked->pprev &&
                (invalidate ? to_mark_failed_or_parked->nStatus.hasFailed()
                            : to_mark_failed_or_parked->nStatus.isParked())) {
                // We only want to mark the last disconnected block as
                // Failed (or Parked); its children need to be FailedParent (or
                // ParkedParent) instead.
                to_mark_failed_or_parked->nStatus =
                    (invalidate
                         ? to_mark_failed_or_parked->nStatus.withFailed(false)
                               .withFailedParent()
                         : to_mark_failed_or_parked->nStatus.withParked(false)
                               .withParkedParent());

                m_blockman.m_dirty_blockindex.insert(to_mark_failed_or_parked);
            }

            // Add any equal or more work headers to setBlockIndexCandidates
            auto candidate_it = candidate_blocks_by_work.lower_bound(
                invalid_walk_tip->pprev->nChainWork);
            while (candidate_it != candidate_blocks_by_work.end()) {
                if (!CBlockIndexWorkComparator()(candidate_it->second,
                                                 invalid_walk_tip->pprev)) {
                    setBlockIndexCandidates.insert(candidate_it->second);
                    candidate_it = candidate_blocks_by_work.erase(candidate_it);
                } else {
                    ++candidate_it;
                }
            }

            // Track the last disconnected block, so we can correct its
            // FailedParent (or ParkedParent) status in future iterations, or,
            // if it's the last one, call InvalidChainFound on it.
            to_mark_failed_or_parked = invalid_walk_tip;
        }
    }

    m_chainman.CheckBlockIndex();

    {
        LOCK(cs_main);
        if (m_chain.Contains(to_mark_failed_or_parked)) {
            // If the to-be-marked invalid block is in the active chain,
            // something is interfering and we can't proceed.
            return false;
        }

        // Mark pindex (or the last disconnected block) as invalid (or parked),
        // even when it never was in the main chain.
        to_mark_failed_or_parked->nStatus =
            invalidate ? to_mark_failed_or_parked->nStatus.withFailed()
                       : to_mark_failed_or_parked->nStatus.withParked();
        m_blockman.m_dirty_blockindex.insert(to_mark_failed_or_parked);
        if (invalidate) {
            m_chainman.m_failed_blocks.insert(to_mark_failed_or_parked);
        }

        // If any new blocks somehow arrived while we were disconnecting
        // (above), then the pre-calculation of what should go into
        // setBlockIndexCandidates may have missed entries. This would
        // technically be an inconsistency in the block index, but if we clean
        // it up here, this should be an essentially unobservable error.
        // Loop back over all block index entries and add any missing entries
        // to setBlockIndexCandidates.
        for (auto &[_, block_index] : m_blockman.m_block_index) {
            if (block_index.IsValid(BlockValidity::TRANSACTIONS) &&
                block_index.HaveNumChainTxs() &&
                !setBlockIndexCandidates.value_comp()(&block_index,
                                                      m_chain.Tip())) {
                setBlockIndexCandidates.insert(&block_index);
            }
        }

        if (invalidate) {
            InvalidChainFound(to_mark_failed_or_parked);
        }
    }

    // Only notify about a new block tip if the active chain was modified.
    if (pindex_was_in_chain) {
        // Ignoring return value for now, this could be changed to bubble up
        // kernel::Interrupted value to the caller so the caller could
        // distinguish between completed and interrupted operations. It might
        // also make sense for the blockTip notification to have an enum
        // parameter indicating the source of the tip change so hooks can
        // distinguish user-initiated invalidateblock changes from other
        // changes.
        (void)m_chainman.GetNotifications().blockTip(
            GetSynchronizationState(m_chainman.IsInitialBlockDownload(),
                                    m_chainman.m_blockman.m_blockfiles_indexed),
            *to_mark_failed_or_parked->pprev);
    }
    return true;
}

bool Chainstate::InvalidateBlock(BlockValidationState &state,
                                 CBlockIndex *pindex) {
    AssertLockNotHeld(m_chainstate_mutex);
    AssertLockNotHeld(::cs_main);
    // See 'Note for backport of Core PR16849' in Chainstate::UnwindBlock
    LOCK(m_chainstate_mutex);

    if (auto *metrics{node::GetNodeMetrics()}) {
        metrics->blocks_invalid.Add(/*invalidateblock=*/1);
    }
    return UnwindBlock(state, pindex, true);
}

bool Chainstate::ParkBlock(BlockValidationState &state, CBlockIndex *pindex) {
    AssertLockNotHeld(m_chainstate_mutex);
    AssertLockNotHeld(::cs_main);
    // See 'Note for backport of Core PR16849' in Chainstate::UnwindBlock
    LOCK(m_chainstate_mutex);

    node::CountParkedBlock(node::BlockParkReason::REQUESTED);
    return UnwindBlock(state, pindex, false);
}

template <typename F>
bool Chainstate::UpdateFlagsForBlock(CBlockIndex *pindexBase,
                                     CBlockIndex *pindex, F f) {
    BlockStatus newStatus = f(pindex->nStatus);
    if (pindex->nStatus != newStatus &&
        (!pindexBase ||
         pindex->GetAncestor(pindexBase->nHeight) == pindexBase)) {
        pindex->nStatus = newStatus;
        if (!newStatus.isOnParkedChain()) {
            pindex->m_preconsensus_policy_parked = false;
        }
        m_blockman.m_dirty_blockindex.insert(pindex);
        if (newStatus.isValid()) {
            m_chainman.m_failed_blocks.erase(pindex);
        }

        if (pindex->IsValid(BlockValidity::TRANSACTIONS) &&
            pindex->HaveNumChainTxs() &&
            setBlockIndexCandidates.value_comp()(m_chain.Tip(), pindex)) {
            setBlockIndexCandidates.insert(pindex);
        }
        return true;
    }
    return false;
}

template <typename F, typename C, typename AC>
void Chainstate::UpdateFlags(CBlockIndex *pindex, CBlockIndex *&pindexReset,
                             F f, C fChild, AC fAncestorWasChanged) {
    AssertLockHeld(cs_main);

    // Update the current block and ancestors; while we're doing this, identify
    // which was the deepest ancestor we changed.
    CBlockIndex *pindexDeepestChanged = pindex;
    for (auto pindexAncestor = pindex; pindexAncestor != nullptr;
         pindexAncestor = pindexAncestor->pprev) {
        if (UpdateFlagsForBlock(nullptr, pindexAncestor, f)) {
            pindexDeepestChanged = pindexAncestor;
        }
    }

    if (pindexReset &&
        pindexReset->GetAncestor(pindexDeepestChanged->nHeight) ==
            pindexDeepestChanged) {
        // reset pindexReset if it had a modified ancestor.
        pindexReset = nullptr;
    }

    // Update all blocks under modified blocks.
    for (auto &[_, block_index] : m_blockman.m_block_index) {
        UpdateFlagsForBlock(pindex, &block_index, fChild);
        UpdateFlagsForBlock(pindexDeepestChanged, &block_index,
                            fAncestorWasChanged);
    }
}

void Chainstate::SetBlockFailureFlags(CBlockIndex *invalid_block) {
    AssertLockHeld(cs_main);

    for (auto &[_, block_index] : m_blockman.m_block_index) {
        if (block_index.GetAncestor(invalid_block->nHeight) == invalid_block &&
            !block_index.nStatus.isInvalid()) {
            block_index.nStatus = block_index.nStatus.withFailedParent();
        }
    }
}

void Chainstate::ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    UpdateFlags(
        pindex, m_chainman.m_best_invalid,
        [](const BlockStatus status) {
            return status.withClearedFailureFlags();
        },
        [](const BlockStatus status) {
            return status.withClearedFailureFlags();
        },
        [](const BlockStatus status) {
            return status.withFailedParent(false);
        });
}

void Chainstate::TryAddBlockIndexCandidate(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);
    // The block only is a candidate for the most-work-chain if it has the same
    // or more work than our current tip.
    if (m_chain.Tip() != nullptr &&
        setBlockIndexCandidates.value_comp()(pindex, m_chain.Tip())) {
        return;
    }

    bool is_active_chainstate = this == &m_chainman.ActiveChainstate();
    if (is_active_chainstate) {
        // The active chainstate should always add entries that have more
        // work than the tip.
        setBlockIndexCandidates.insert(pindex);
    } else if (!m_disabled) {
        // For the background chainstate, we only consider connecting blocks
        // towards the snapshot base (which can't be nullptr or else we'll
        // never make progress).
        const CBlockIndex *snapshot_base{
            Assert(m_chainman.GetSnapshotBaseBlock())};
        if (snapshot_base->GetAncestor(pindex->nHeight) == pindex) {
            setBlockIndexCandidates.insert(pindex);
        }
    }
}

void Chainstate::UnparkBlockImpl(CBlockIndex *pindex, bool fClearChildren) {
    AssertLockHeld(cs_main);
    pindex->m_preconsensus_policy_parked = false;

    UpdateFlags(
        pindex, m_chainman.m_best_parked,
        [](const BlockStatus status) {
            return status.withClearedParkedFlags();
        },
        [fClearChildren](const BlockStatus status) {
            return fClearChildren ? status.withClearedParkedFlags()
                                  : status.withParkedParent(false);
        },
        [](const BlockStatus status) {
            return status.withParkedParent(false);
        });
}

void Chainstate::UnparkBlockAndChildren(CBlockIndex *pindex) {
    return UnparkBlockImpl(pindex, true);
}

void Chainstate::UnparkBlock(CBlockIndex *pindex) {
    return UnparkBlockImpl(pindex, false);
}

bool Chainstate::AvalancheFinalizeBlock(CBlockIndex *pindex,
                                        avalanche::Processor &avalanche) {
    AssertLockHeld(::cs_main);
    AssertLockNotHeld(cs_avalancheFinalizedBlockIndex);

    if (!pindex) {
        return false;
    }

    if (!m_chain.Contains(pindex)) {
        LogDebug(BCLog::AVALANCHE,
                 "The block to mark finalized by avalanche is not on the "
                 "active chain: %s\n",
                 pindex->GetBlockHash().ToString());
        return false;
    }

    if (IsBlockAvalancheFinalized(pindex)) {
        return true;
    }

    {
        LOCK(cs_avalancheFinalizedBlockIndex);
        m_avalancheFinalizedBlockIndex = pindex;
    }
    node::PublishChainTipSnapshot(m_chainman, m_mempool);

    if (m_chainman.m_options.signals) {
        m_chainman.m_options.signals->BlockFinalized(pindex);
    }

    return true;
}

void Chainstate::ClearAvalancheFinalizedBlock() {
    {
        LOCK(cs_avalancheFinalizedBlockIndex);
        m_avalancheFinalizedBlockIndex = nullptr;
    }
    LOCK(::cs_main);
    node::PublishChainTipSnapshot(m_chainman, m_mempool);
}

bool Chainstate::IsBlockAvalancheFinalized(const CBlockIndex *pindex) const {
    LOCK(cs_avalancheFinalizedBlockIndex);
    return pindex && m_avalancheFinalizedBlockIndex &&
           m_avalancheFinalizedBlockIndex->GetAncestor(pindex->nHeight) ==
               pindex;
}

/**
 * Mark a block as having its data received and checked (up to
 * BLOCK_VALID_TRANSACTIONS).
 */
void ChainstateManager::ReceivedBlockTransactions(const CBlock &block,
                                                  CBlockIndex *pindexNew,
                                                  const FlatFilePos &pos) {
    pindexNew->nTx = block.vtx.size();
    // Typically nChainTX will be 0 at this point, but it can be nonzero if this
    // is a pruned block which is being downloaded again, or if this is an
    // assumeutxo snapshot block which has a hardcoded m_chain_tx_count value
    // from the snapshot metadata. If the pindex is not the snapshot block and
    // the m_chain_tx_count value is not zero, assert that value is actually
    // correct.
    auto prev_tx_sum = [](CBlockIndex &block) {
        return block.nTx + (block.pprev ? block.pprev->m_chain_tx_count : 0);
    };
    if (!Assume(pindexNew->m_chain_tx_count == 0 ||
                pindexNew->m_chain_tx_count == prev_tx_sum(*pindexNew) ||
                pindexNew == GetSnapshotBaseBlock())) {
        LogInfoEvent(
            BCLog::ALL, "block_chain_tx_count_unexpected",
            "Internal bug detected: block {height} has unexpected m_chain_tx_count {chain_tx_count} that should be {expected_chain_tx_count}. Please report this issue here: {bug_report_url}")
            .Field(BCLog::LogField::Height, pindexNew->nHeight)
            .Field(BCLog::LogField::ChainTxCount, pindexNew->m_chain_tx_count)
            .Field(BCLog::LogField::ExpectedChainTxCount,
                   prev_tx_sum(*pindexNew))
            .Field(BCLog::LogField::BugReportURL, PACKAGE_BUGREPORT);
        pindexNew->m_chain_tx_count = 0;
    }
    pindexNew->nSize = ::GetSerializeSize(block);
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus = pindexNew->nStatus.withData();
    pindexNew->RaiseValidity(BlockValidity::TRANSACTIONS);
    m_blockman.m_dirty_blockindex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->HaveNumChainTxs()) {
        // If pindexNew is the genesis block or all parents are
        // BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex *> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to
        // be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            // Before setting m_chain_tx_count, assert that it is 0 or already
            // set to the correct value. This assert will fail after receiving
            // the assumeutxo snapshot block if assumeutxo snapshot metadata has
            // an incorrect hardcoded AssumeutxoData::m_chain_tx_count value.
            if (!Assume(pindex->m_chain_tx_count == 0 ||
                        pindex->m_chain_tx_count == prev_tx_sum(*pindex) ||
                        pindex == GetSnapshotBaseBlock())) {
                LogInfoEvent(
                    BCLog::ALL, "block_chain_tx_count_unexpected",
                    "Internal bug detected: block {height} has unexpected m_chain_tx_count {chain_tx_count} that should be {expected_chain_tx_count}. Please report this issue here: {bug_report_url}")
                    .Field(BCLog::LogField::Height, pindex->nHeight)
                    .Field(BCLog::LogField::ChainTxCount,
                           pindex->m_chain_tx_count)
                    .Field(BCLog::LogField::ExpectedChainTxCount,
                           prev_tx_sum(*pindex))
                    .Field(BCLog::LogField::BugReportURL, PACKAGE_BUGREPORT);
            }
            const bool was_fast_sync_base =
                (m_active_chainstate &&
                 pindex == m_active_chainstate->FastSyncPivotBase());
            pindex->m_chain_tx_count = prev_tx_sum(*pindex);
            if (was_fast_sync_base) {
                for (int h = pindex->nHeight + 1; h <= ActiveChain().Height();
                     ++h) {
                    CBlockIndex *desc = ActiveChain()[h];
                    if (desc && desc->nTx > 0 && desc->pprev) {
                        desc->m_chain_tx_count =
                            desc->nTx + desc->pprev->m_chain_tx_count;
                        m_blockman.m_dirty_blockindex.insert(desc);
                    }
                }
            }
            if (pindex->nSequenceId == 0) {
                // We assign a sequence is when transaction are received to
                // prevent a miner from being able to broadcast a block but not
                // its content. However, a sequence id may have been set
                // manually, for instance via PreciousBlock, in which case, we
                // don't need to assign one.
                pindex->nSequenceId = nBlockSequenceId++;
            }
            for (Chainstate *c : GetAll()) {
                c->TryAddBlockIndexCandidate(pindex);
            }

            std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
                      std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
                range = m_blockman.m_blocks_unlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator it =
                    range.first;
                queue.push_back(it->second);
                range.first++;
                m_blockman.m_blocks_unlinked.erase(it);
            }
        }
    } else if (pindexNew->pprev &&
               pindexNew->pprev->IsValid(BlockValidity::TREE)) {
        m_blockman.m_blocks_unlinked.insert(
            std::make_pair(pindexNew->pprev, pindexNew));
    }
}

/**
 * Return true if the provided block header is valid.
 * Only verify PoW if blockValidationOptions is configured to do so.
 * This allows validation of headers on which the PoW hasn't been done.
 * For example: to validate template handed to mining software.
 * Do not call this for any check that depends on the context.
 * For context-dependent calls, see ContextualCheckBlockHeader.
 */
static bool CheckBlockHeader(const CBlockHeader &block,
                             BlockValidationState &state,
                             const Consensus::Params &params,
                             BlockValidationOptions validationOptions) {
    // Check proof of work matches claimed amount
    if (validationOptions.shouldValidatePoW() &&
        !CheckProofOfWork(block.GetHash(), block.nBits, params)) {
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER,
                             "high-hash", "proof of work failed");
    }

    if (block.nHeaderVersion != lotus::v2::kHeaderVersion) {
        LogPrintf("ERROR: expected block version %u but got %u\n",
                  lotus::v2::kHeaderVersion, block.nHeaderVersion);
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER,
                             "bad-blk-version", "block version must be 2");
    }

    // Check if claimed size is excessive
    if (block.GetSize() > validationOptions.getExcessiveBlockSize()) {
        LogPrintf(
            "ERROR: block has excessive size %u, which is above the limit %u\n",
            block.GetSize(), validationOptions.getExcessiveBlockSize());
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-blk-size",
                             "block header has excessive claimed size");
    }

    return true;
}

void RunOnValidationWorkers(size_t max_threads, size_t n_tasks,
                            const std::function<void(size_t)> &fn) {
    std::atomic<size_t> next{0};
    auto work = [&](size_t) {
        for (size_t i;
             (i = next.fetch_add(1, std::memory_order_relaxed)) < n_tasks;) {
            fn(i);
        }
    };
    const size_t threads{std::min(max_threads, n_tasks)};
    // Never wait for the pool: while ConnectBlock (or a mempool batch) uses
    // it, do the work on this thread, as before.
    if (!ParallelScriptWorkerPool::Instance().TryRun(threads, work)) {
        work(0);
    }
}

uint256 ValidationBlockMerkleRoot(const CBlock &block, bool *mutated,
                                  size_t /*min_parallel_txs*/, size_t /*threads*/) {
    // Preserve native TransactionRoot and duplicate-TxId detection. Parallel
    // native hashing is a separate optimization, not SHA256D chunk reuse.
    return BlockMerkleRoot(block, mutated);
}

static bool CheckMerkleRoot(const CBlock &block, BlockValidationState &state) {
    if (block.m_checked_merkle_root) {
        return true;
    }

    bool mutated;
    uint256 merkle_root = BlockMerkleRoot(block, &mutated);

    // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
    // of transactions in a block without affecting the merkle root of a block,
    // while still invalidating it.
    if (mutated) {
        return state.Invalid(
            /*result=*/BlockValidationResult::BLOCK_MUTATED,
            /*reject_reason=*/"bad-txns-duplicate",
            /*debug_message=*/"duplicate transaction");
    }

    if (block.hashMerkleRoot != merkle_root) {
        return state.Invalid(
            /*result=*/BlockValidationResult::BLOCK_MUTATED,
            /*reject_reason=*/"bad-txnmrklroot",
            /*debug_message=*/"hashMerkleRoot mismatch");
    }

    block.m_checked_merkle_root = true;
    return true;
}

bool CheckBlock(const CBlock &block, BlockValidationState &state,
                const Consensus::Params &params,
                BlockValidationOptions validationOptions) {
    // These are checks that are independent of context.
    if (block.fChecked) {
        return true;
    }

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, params, validationOptions)) {
        return false;
    }

    // Check the merkle root.
    if (validationOptions.shouldValidateMerkleRoot() &&
        !CheckMerkleRoot(block, state)) {
        return false;
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // First transaction must be coinbase.
    if (block.vtx.empty()) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-cb-missing", "first tx is not coinbase");
    }

    // Size limits.
    auto nMaxBlockSize = validationOptions.getExcessiveBlockSize();
    if (!block.IsNull() && nMaxBlockSize >= DEFAULT_MAX_BLOCK_SIZE &&
        !gArgs.IsArgSet("-excessiveblocksize") &&
        gArgs.GetBoolArg("-adaptiveblocksize", true)) {
        nMaxBlockSize = std::max(
            nMaxBlockSize, lotus::v2::DEFAULT_ADAPTIVE_MAX_BLOCK_CEILING);
    }

    // Bail early if there is no way this block is of reasonable size.
    if ((block.vtx.size() * MIN_TRANSACTION_SIZE) > nMaxBlockSize) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-blk-size-mismatch", "size limits failed");
    }

    auto currentBlockSize = ::GetSerializeSize(block);
    if (currentBlockSize != block.GetSize()) {
        LogPrintf("ERROR: block size mismatch: claims to have size %u, but "
                  "has %u\n",
                  block.GetSize(), currentBlockSize);
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-blk-size-mismatch",
                             "block does not have the size it claims to have");
    }

    // And a valid coinbase.
    TxValidationState tx_state;
    if (!CheckCoinbase(*block.vtx[0], tx_state)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             tx_state.GetRejectReason(),
                             strprintf("Coinbase check failed (txid %s) %s",
                                       block.vtx[0]->GetId().ToString(),
                                       tx_state.GetDebugMessage()));
    }

    // Check transactions for regularity, skipping the first. Note that this
    // is the first time we check that all after the first are !IsCoinBase.
    for (size_t i = 1; i < block.vtx.size(); i++) {
        auto *tx = block.vtx[i].get();
        if (!CheckRegularTransaction(*tx, tx_state)) {
            return state.Invalid(
                BlockValidationResult::BLOCK_CONSENSUS,
                tx_state.GetRejectReason(),
                strprintf("Transaction check failed (txid %s) %s",
                          tx->GetId().ToString(), tx_state.GetDebugMessage()));
        }
    }

    if (validationOptions.shouldValidatePoW() &&
        validationOptions.shouldValidateMerkleRoot()) {
        block.fChecked = true;
    }

    return true;
}

bool HasValidProofOfWork(const std::vector<CBlockHeader> &headers,
                         const Consensus::Params &consensusParams) {
    return std::all_of(headers.cbegin(), headers.cend(),
                       [&](const auto &header) {
                           return CheckProofOfWork(
                               header.GetHash(), header.nBits, consensusParams);
                       });
}

bool IsBlockMutated(const CBlock &block) {
    BlockValidationState state;
    if (!CheckMerkleRoot(block, state)) {
        LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Debug,
                      "Block mutated: %s\n", state.ToString());
        return true;
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        // Consider the block mutated if any transaction is 64 bytes in size
        // (see 3.1 in "Weaknesses in Bitcoin’s Merkle Root Construction":
        // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/attachments/20190225/a27d8837/attachment-0001.pdf).
        //
        // Note: This is not a consensus change as this only applies to blocks
        // that don't have a coinbase transaction and would therefore already be
        // invalid.
        return std::any_of(block.vtx.begin(), block.vtx.end(),
                           [](auto &tx) { return GetSerializeSize(tx) == 64; });
    } else {
        // Theoretically it is still possible for a block with a 64 byte
        // coinbase transaction to be mutated but we neglect that possibility
        // here as it requires at least 224 bits of work.
    }

    return false;
}

arith_uint256
CalculateClaimedHeadersWork(const std::vector<CBlockHeader> &headers) {
    arith_uint256 total_work{0};
    for (const CBlockHeader &header : headers) {
        CBlockIndex dummy(header);
        total_work += GetBlockProof(dummy);
    }
    return total_work;
}

/**
 * Context-dependent validity checks.
 * By "context", we mean only the previous block headers, but not the UTXO
 * set; UTXO-related validity checks are done in ConnectBlock().
 * NOTE: This function is not currently invoked by ConnectBlock(), so we
 * should consider upgrade issues if we change which consensus rules are
 * enforced in this function (eg by adding a new consensus rule). See comment
 * in ConnectBlock().
 * Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlockHeader(
    const CBlockHeader &block, BlockValidationState &state,
    BlockManager &blockman, ChainstateManager &chainman,
    const CBlockIndex *pindexPrev, NodeClock::time_point now,
    const std::optional<CCheckpointData> &test_checkpoints = std::nullopt)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    AssertLockHeld(::cs_main);
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;

    const CChainParams &params = chainman.GetParams();

    // Check proof of work
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, params)) {
        LogPrintf("bad bits after height: %d\n", pindexPrev->nHeight);
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER,
                             "bad-diffbits", "incorrect proof of work");
    }

    // Check against checkpoints
    if (chainman.m_options.checkpoints_enabled) {
        const CCheckpointData &checkpoints =
            test_checkpoints ? test_checkpoints.value() : params.Checkpoints();

        // Check that the block chain matches the known block chain up to a
        // checkpoint.
        if (!Checkpoints::CheckBlock(checkpoints, nHeight, block.GetHash())) {
            LogDebug(BCLog::VALIDATION,
                     "ERROR: %s: rejected by checkpoint lock-in at %d\n",
                     __func__, nHeight);
            return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT,
                                 "checkpoint mismatch");
        }

        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's
        // in our BlockIndex().

        const CBlockIndex *pcheckpoint =
            blockman.GetLastCheckpoint(checkpoints);
        if (pcheckpoint && nHeight < pcheckpoint->nHeight) {
            LogDebug(BCLog::VALIDATION,
                     "ERROR: %s: forked chain older than last checkpoint "
                     "(height %d)\n",
                     __func__, nHeight);
            return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT,
                                 "bad-fork-prior-to-checkpoint");
        }
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast()) {
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER,
                             "time-too-old", "block's timestamp is too early");
    }

    if (block.nHeight != uint64_t(pindexPrev->nHeight + 1)) {
        LogPrintf("ERROR: expected block height %d but got %u\n",
                  pindexPrev->nHeight + 1, block.nHeight);
        return state.Invalid(
            BlockValidationResult::BLOCK_INVALID_HEADER, "bad-blk-height",
            "block height is not one higher than previous block");
    }

    // Check timestamp
    if (block.Time() > now + std::chrono::seconds{MAX_FUTURE_BLOCK_TIME}) {
        return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE,
                             "time-too-new",
                             "block timestamp too far in the future");
    }

    return true;
}

/**
 * NOTE: This function is not currently invoked by ConnectBlock(), so we
 * should consider upgrade issues if we change which consensus rules are
 * enforced in this function (eg by adding a new consensus rule). See comment
 * in ConnectBlock().
 * Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock &block,
                                 BlockValidationState &state,
                                 const ChainstateManager &chainman,
                                 const CBlockIndex *pindexPrev) {
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Always enforce BIP113 (Median Time Past) from genesis.
    const int64_t nMedianTimePast =
        pindexPrev == nullptr ? 0 : pindexPrev->GetMedianTimePast();

    const int64_t nLockTimeCutoff = nMedianTimePast;

    const Consensus::Params params = chainman.GetConsensus();

    // Check transactions:
    // - canonical ordering
    // - ensure they are finalized
    // - check they have the minimum size
    const CTransaction *prevTx = nullptr;
    for (const auto &ptx : block.vtx) {
        const CTransaction &tx = *ptx;
        if (prevTx && (tx.GetId() <= prevTx->GetId())) {
            if (tx.GetId() == prevTx->GetId()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "tx-duplicate",
                                     strprintf("Duplicated transaction %s",
                                               tx.GetId().ToString()));
            }

            return state.Invalid(
                BlockValidationResult::BLOCK_CONSENSUS, "tx-ordering",
                strprintf("Transaction order is invalid (%s < %s)",
                          tx.GetId().ToString(),
                          prevTx->GetId().ToString()));
        }

        if (prevTx || !tx.IsCoinBase()) {
            prevTx = &tx;
        }

        TxValidationState tx_state;
        if (!ContextualCheckTransaction(params, tx, tx_state, nHeight,
                                        nLockTimeCutoff)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                 tx_state.GetRejectReason(),
                                 tx_state.GetDebugMessage());
        }
    }

    // Enforce rule that the coinbase commits to parent block and height
    if (nHeight >= 1) {
        if (block.vtx[0]->vin[0].nFlags == 2 &&
            !block.vtx[0]->vin[0].prevout.IsNull() && pindexPrev != nullptr) {
            lotus::v2::Hash32 parent_id{};
            std::memcpy(parent_id.data(),
                        pindexPrev->GetBlockHash().begin(), 32);
            std::string cb_err;
            if (!lotus::v2::CheckCoinbaseContext(
                    block.vtx[0]->ToV2Transaction(), parent_id,
                    uint64_t(nHeight), cb_err)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "bad-cb-height", cb_err);
            }
        } else {
            CScript expect = CScript() << nHeight;
            if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
                !std::equal(expect.begin(), expect.end(),
                            block.vtx[0]->vin[0].scriptSig.begin())) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "bad-cb-height",
                                     "block height mismatch in coinbase");
            }
        }
    }

    return true;
}

/**
 * If the provided block header is valid, add it to the block index.
 *
 * Returns true if the block is successfully added to the block index.
 */
bool ChainstateManager::AcceptBlockHeader(
    const CBlockHeader &block, BlockValidationState &state,
    CBlockIndex **ppindex, bool min_pow_checked,
    const std::optional<CCheckpointData> &test_checkpoints) {
    AssertLockHeld(cs_main);
    const Config &config = this->GetConfig();
    const CChainParams &chainparams = config.GetChainParams();

    // Check for duplicate
    BlockHash hash = block.GetHash();
    BlockMap::iterator miSelf{m_blockman.m_block_index.find(hash)};
    if (hash != chainparams.GetConsensus().hashGenesisBlock) {
        if (miSelf != m_blockman.m_block_index.end()) {
            // Block header is already known.
            CBlockIndex *pindex = &(miSelf->second);
            if (ppindex) {
                *ppindex = pindex;
            }

            if (pindex->nStatus.isInvalid()) {
                LogDebug(BCLog::VALIDATION, "%s: block %s is marked invalid\n",
                         __func__, hash.ToString());
                return state.Invalid(
                    BlockValidationResult::BLOCK_CACHED_INVALID, "duplicate");
            }

            return true;
        }

        if (!CheckBlockHeader(block, state, chainparams.GetConsensus(),
                              BlockValidationOptions(config))) {
            LogDebug(BCLog::VALIDATION,
                     "%s: Consensus::CheckBlockHeader: %s, %s\n", __func__,
                     hash.ToString(), state.ToString());
            return false;
        }

        // Get prev block index
        BlockMap::iterator mi{
            m_blockman.m_block_index.find(block.hashPrevBlock)};
        if (mi == m_blockman.m_block_index.end()) {
            LogDebug(BCLog::VALIDATION,
                     "header %s has prev block not found: %s\n",
                     hash.ToString(), block.hashPrevBlock.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV,
                                 "prev-blk-not-found");
        }

        CBlockIndex *pindexPrev = &((*mi).second);
        assert(pindexPrev);
        if (pindexPrev->nStatus.isInvalid()) {
            LogDebug(BCLog::VALIDATION,
                     "header %s has prev block invalid: %s\n", hash.ToString(),
                     block.hashPrevBlock.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV,
                                 "bad-prevblk");
        }

        if (!ContextualCheckBlockHeader(
                block, state, m_blockman, *this, pindexPrev,
                m_options.adjusted_time_callback(), test_checkpoints)) {
            LogDebug(BCLog::VALIDATION,
                     "%s: Consensus::ContextualCheckBlockHeader: %s, %s\n",
                     __func__, hash.ToString(), state.ToString());
            return false;
        }

        /* Determine if this block descends from any block which has been found
         * invalid (m_failed_blocks), then mark pindexPrev and any blocks
         * between them as failed. For example:
         *
         *                D3
         *              /
         *      B2 - C2
         *    /         \
         *  A             D2 - E2 - F2
         *    \
         *      B1 - C1 - D1 - E1
         *
         * In the case that we attempted to reorg from E1 to F2, only to find
         * C2 to be invalid, we would mark D2, E2, and F2 as BLOCK_FAILED_CHILD
         * but NOT D3 (it was not in any of our candidate sets at the time).
         *
         * In any case D3 will also be marked as BLOCK_FAILED_CHILD at restart
         * in LoadBlockIndex.
         */
        if (!pindexPrev->IsValid(BlockValidity::SCRIPTS)) {
            // The above does not mean "invalid": it checks if the previous
            // block hasn't been validated up to BlockValidity::SCRIPTS. This is
            // a performance optimization, in the common case of adding a new
            // block to the tip, we don't need to iterate over the failed blocks
            // list.
            for (const CBlockIndex *failedit : m_failed_blocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    assert(failedit->nStatus.hasFailed());
                    CBlockIndex *invalid_walk = pindexPrev;
                    while (invalid_walk != failedit) {
                        invalid_walk->nStatus =
                            invalid_walk->nStatus.withFailedParent();
                        m_blockman.m_dirty_blockindex.insert(invalid_walk);
                        invalid_walk = invalid_walk->pprev;
                    }
                    LogDebug(BCLog::VALIDATION,
                             "header %s has prev block invalid: %s\n",
                             hash.ToString(), block.hashPrevBlock.ToString());
                    return state.Invalid(
                        BlockValidationResult::BLOCK_INVALID_PREV,
                        "bad-prevblk");
                }
            }
        }
    }
    if (!min_pow_checked) {
        LogDebug(BCLog::VALIDATION,
                 "%s: not adding new block header %s, missing anti-dos "
                 "proof-of-work validation\n",
                 __func__, hash.ToString());
        return state.Invalid(BlockValidationResult::BLOCK_HEADER_LOW_WORK,
                             "too-little-chainwork");
    }
    const CBlockIndex *prev_best_header = m_best_header;
    CBlockIndex *pindex{m_blockman.AddToBlockIndex(block, m_best_header)};
    if (m_best_header != prev_best_header && m_active_chainstate) {
        node::PublishChainTipSnapshot(*this, m_active_chainstate->GetMempool());
    }

    if (ppindex) {
        *ppindex = pindex;
    }

    // Since this is the earliest point at which we have determined that a
    // header is both new and valid, log here.
    //
    // These messages are valuable for detecting potential selfish mining
    // behavior; if multiple displacing headers are seen near simultaneously
    // across many nodes in the network, this might be an indication of selfish
    // mining. Having this log by default when not in IBD ensures broad
    // availability of this data in case investigation is merited.
    const auto msg = strprintf("Saw new header hash=%s height=%d",
                               hash.ToString(), pindex->nHeight);

    if (IsInitialBlockDownload()) {
        LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Debug, "%s\n", msg);
    } else {
        LogPrintf("%s\n", msg);
    }

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ChainstateManager::ProcessNewBlockHeaders(
    const std::vector<CBlockHeader> &headers, bool min_pow_checked,
    BlockValidationState &state, const CBlockIndex **ppindex,
    const std::optional<CCheckpointData> &test_checkpoints) {
    AssertLockNotHeld(cs_main);
    {
        LOCK(cs_main);
        for (const CBlockHeader &header : headers) {
            // Use a temp pindex instead of ppindex to avoid a const_cast
            CBlockIndex *pindex = nullptr;
            bool accepted = AcceptBlockHeader(
                header, state, &pindex, min_pow_checked, test_checkpoints);
            CheckBlockIndex();

            if (!accepted) {
                return false;
            }

            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }

    if (NotifyHeaderTip()) {
        if (IsInitialBlockDownload() && ppindex && *ppindex) {
            const CBlockIndex &last_accepted{**ppindex};
            int64_t blocks_left{(NodeClock::now() - last_accepted.Time()) /
                                GetConsensus().PowTargetSpacing()};
            blocks_left = std::max<int64_t>(0, blocks_left);
            const double progress{100.0 * last_accepted.nHeight /
                                  (last_accepted.nHeight + blocks_left)};
            LogInfoEvent(BCLog::ALL, "chain_headers_sync_progress",
                     "Synchronizing blockheaders, height: {height} (~{header_progress_percent:.2f}%)")
            .Field(BCLog::LogField::Height, last_accepted.nHeight)
            .Field(BCLog::LogField::HeaderProgressPercent, progress);
        }
    }
    return true;
}

void ChainstateManager::ReportHeadersPresync(const arith_uint256 &work,
                                             int64_t height,
                                             int64_t timestamp) {
    AssertLockNotHeld(cs_main);
    {
        LOCK(cs_main);
        // Don't report headers presync progress if we already have a
        // post-minchainwork header chain.
        // This means we lose reporting for potentially legimate, but unlikely,
        // deep reorgs, but prevent attackers that spam low-work headers from
        // filling our logs.
        if (m_best_header->nChainWork >=
            UintToArith256(GetConsensus().nMinimumChainWork)) {
            return;
        }
        // Rate limit headers presync updates to 4 per second, as these are not
        // subject to DoS protection.
        auto now = Now<SteadyMilliseconds>();
        if (now < m_last_presync_update + 250ms) {
            return;
        }
        m_last_presync_update = now;
    }
    bool initial_download = IsInitialBlockDownload();
    GetNotifications().headerTip(
        GetSynchronizationState(initial_download,
                                m_blockman.m_blockfiles_indexed),
        height, timestamp, /*presync=*/true);
    if (initial_download) {
        int64_t blocks_left{
            (NodeClock::now() - NodeSeconds{std::chrono::seconds{timestamp}}) /
            GetConsensus().PowTargetSpacing()};
        blocks_left = std::max<int64_t>(0, blocks_left);
        const double progress{100.0 * height / (height + blocks_left)};
        LogInfoEvent(BCLog::ALL, "chain_headers_presync_progress",
                     "Pre-synchronizing blockheaders, height: {height} (~{header_progress_percent:.2f}%)")
            .Field(BCLog::LogField::Height, height)
            .Field(BCLog::LogField::HeaderProgressPercent, progress);
    }
}

bool ChainstateManager::AcceptBlock(const std::shared_ptr<const CBlock> &pblock,
                                    BlockValidationState &state,
                                    bool fRequested, const FlatFilePos *dbp,
                                    bool *fNewBlock, bool min_pow_checked) {
    AssertLockHeld(cs_main);

    const CBlock &block = *pblock;
    if (fNewBlock) {
        *fNewBlock = false;
    }

    CBlockIndex *pindex = nullptr;

    bool accepted_header{
        AcceptBlockHeader(block, state, &pindex, min_pow_checked)};
    CheckBlockIndex();

    if (!accepted_header) {
        return false;
    }

    // Check all requested blocks that we do not already have for validity and
    // save them to disk. Skip processing of unrequested blocks as an anti-DoS
    // measure, unless the blocks have more work than the active chain tip, and
    // aren't too far ahead of it, so are likely to be attached soon.
    bool fAlreadyHave = pindex->nStatus.hasData();

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) {
        return true;
    }

    // Compare block header timestamps and received times of the block and the
    // chaintip.  If they have the same chain height, use these diffs as a
    // tie-breaker, attempting to pick the more honestly-mined block.
    int64_t newBlockTimeDiff = std::llabs(pindex->GetReceivedTimeDiff());
    int64_t chainTipTimeDiff =
        ActiveTip() ? std::llabs(ActiveTip()->GetReceivedTimeDiff()) : 0;

    bool isSameHeight =
        ActiveTip() && (pindex->nChainWork == ActiveTip()->nChainWork);
    if (isSameHeight) {
        LogInfoEvent(BCLog::ALL, "chain_tip_received_time_difference",
                     "Chain tip timestamp-to-received-time difference: hash={block_hash}, diff={received_time_difference_seconds}")
            .Field(BCLog::LogField::BlockHash, ActiveTip()->GetBlockHash())
            .Field(BCLog::LogField::ReceivedTimeDifferenceSeconds, chainTipTimeDiff);
        LogInfoEvent(BCLog::ALL, "chain_block_received_time_difference",
                     "New block timestamp-to-received-time difference: hash={block_hash}, diff={received_time_difference_seconds}")
            .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash())
            .Field(BCLog::LogField::ReceivedTimeDifferenceSeconds, newBlockTimeDiff);
    }

    bool fHasMoreOrSameWork =
        (ActiveTip() ? pindex->nChainWork >= ActiveTip()->nChainWork : true);

    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead{pindex->nHeight >
                      ActiveHeight() + int(MIN_BLOCKS_TO_KEEP)};

    // TODO: Decouple this function from the block download logic by removing
    // fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.
    // Note that this would break the getblockfrompeer RPC

    // If we didn't ask for it:
    if (!fRequested) {
        // This is a previously-processed block that was pruned.
        if (pindex->nTx != 0) {
            return true;
        }

        // Don't process less-work chains.
        if (!fHasMoreOrSameWork) {
            return true;
        }

        // Block height is too high.
        if (fTooFarAhead) {
            return true;
        }

        // Protect against DoS attacks from low-work chains.
        // If our tip is behind, a peer could try to send us
        // low-work blocks on a fake chain that we would never
        // request; don't process these.
        if (pindex->nChainWork < MinimumChainWork()) {
            return true;
        }
    }

    if (!CheckBlock(block, state,
                    m_options.config.GetChainParams().GetConsensus(),
                    BlockValidationOptions(m_options.config)) ||
        !ContextualCheckBlock(block, state, *this, pindex->pprev)) {
        if (state.IsInvalid() &&
            state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
            pindex->nStatus = pindex->nStatus.withFailed();
            m_blockman.m_dirty_blockindex.insert(pindex);
        }

        LogErrorEvent(BCLog::ALL, "chain_contextual_block_failed",
                      "{source_function}: {reason} (block {block_hash})")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state)
            .Field(BCLog::LogField::BlockHash, block.GetHash());
        return false;
    }

    // If connecting the new block would require rewinding more than one block
    // from the active chain (i.e., a "deep reorg"), then mark the new block as
    // parked. If it has enough work then it will be automatically unparked
    // later, during FindMostWorkChain. We mark the block as parked at the very
    // last minute so we can make sure everything is ready to be reorged if
    // needed.
    if (m_options.park_deep_reorg) {
        // Blocks that are below the snapshot height can't cause reorgs, as the
        // active tip is at least thousands of blocks higher. Don't park them,
        // they will most likely connect on the tip of the background chain.
        std::optional<int> snapshot_base_height = GetSnapshotBaseHeight();
        const bool is_background_block =
            ActiveChain().Contains(pindex) ||
            (snapshot_base_height && BackgroundSyncInProgress() &&
             pindex->nHeight <= snapshot_base_height);
        const CBlockIndex *pindexFork = ActiveChain().FindFork(pindex);
        if (!is_background_block && pindexFork &&
            pindexFork->nHeight + 1 < ActiveHeight()) {
            LogInfoEvent(
                BCLog::ALL, "block_parked_deep_reorg",
                "Park block {block_hash} as it would cause a deep reorg.")
                .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash());
            node::CountParkedBlock(node::BlockParkReason::DEEP_REORG);
            pindex->nStatus = pindex->nStatus.withParked();
            m_blockman.m_dirty_blockindex.insert(pindex);
        }
    }

    // Header is valid/has work and the merkle tree is good.
    // Relay now, but if it does not build on our best tip, let the
    // SendMessages loop relay it.
    if (!IsInitialBlockDownload() && ActiveTip() == pindex->pprev &&
        m_options.signals) {
        m_options.signals->NewPoWValidBlock(pindex, pblock);
    }

    // Write block to history file
    if (fNewBlock) {
        *fNewBlock = true;
    }
    try {
        FlatFilePos blockPos{};
        if (dbp) {
            blockPos = *dbp;
            m_blockman.UpdateBlockInfo(block, pindex->nHeight, blockPos);
        } else {
            blockPos = m_blockman.WriteBlock(block, pindex->nHeight);
            if (blockPos.IsNull()) {
                state.Error(strprintf(
                    "%s: Failed to find position to write new block to disk",
                    __func__));
                return false;
            }
        }
        ReceivedBlockTransactions(block, pindex, blockPos);
    } catch (const std::runtime_error &e) {
        return FatalError(GetNotifications(), state,
                          std::string("System error: ") + e.what());
    }

    // TODO: FlushStateToDisk() handles flushing of both block and chainstate
    // data, so we should move this to ChainstateManager so that we can be more
    // intelligent about how we flush.
    // For now, since FlushStateMode::NONE is used, all that can happen is that
    // the block files may be pruned, so we can just call this on one
    // chainstate (particularly if we haven't implemented pruning with
    // background validation yet).
    ActiveChainstate().FlushStateToDisk(state, FlushStateMode::NONE);

    CheckBlockIndex();

    return true;
}

bool ChainstateManager::ProcessNewBlock(
    const std::shared_ptr<const CBlock> &block, bool force_processing,
    bool min_pow_checked, bool *new_block,
    avalanche::Processor *const avalanche) {
    AssertLockNotHeld(cs_main);

    {
        if (new_block) {
            *new_block = false;
        }

        BlockValidationState state;

        // CheckBlock() does not support multi-threaded block validation
        // because CBlock::fChecked can cause data race.
        // Therefore, the following critical section must include the
        // CheckBlock() call as well.
        LOCK(cs_main);

        // Usually already started when the block arrived (net_processing);
        // this covers the other sources (RPC, -loadblock). Deduplicated.
        PrefetchBlockCoinsLocked(block);

        // Skipping AcceptBlock() for CheckBlock() failures means that we will
        // never mark a block as invalid if CheckBlock() fails.  This is
        // protective against consensus failure if there are any unknown form
        // s of block malleability that cause CheckBlock() to fail; see e.g.
        // CVE-2012-2459 and
        // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-February/016697.html.
        // Because CheckBlock() is not very expensive, the anti-DoS benefits of
        // caching failure (of a definitely-invalid block) are not substantial.
        bool ret = CheckBlock(*block, state, this->GetConsensus(),
                              BlockValidationOptions(this->GetConfig()));
        if (ret) {
            // Store to disk
            ret = AcceptBlock(block, state, force_processing, nullptr,
                              new_block, min_pow_checked);
        }

        if (!ret) {
            if (m_options.signals) {
                m_options.signals->BlockChecked(*block, state);
            }
            LogErrorEvent(BCLog::ALL, "chain_accept_block_failed",
                          "{source_function}: AcceptBlock FAILED ({reason})")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Reason, state);
            return false;
        }
    }

    NotifyHeaderTip();

    // Only used to report errors, not invalidity - ignore it
    BlockValidationState state;
    if (!ActiveChainstate().ActivateBestChain(state, block, avalanche)) {
        LogErrorEvent(BCLog::ALL, "chain_activate_best_failed",
                      "{source_function}: ActivateBestChain failed ({reason})")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state);
        return false;
    }

    Chainstate *bg_chain{WITH_LOCK(cs_main, return BackgroundSyncInProgress()
                                                       ? m_ibd_chainstate.get()
                                                       : nullptr)};
    BlockValidationState bg_state;
    if (bg_chain && !bg_chain->ActivateBestChain(bg_state, block)) {
        LogErrorEvent(
            BCLog::ALL, "chain_background_activate_best_failed",
            "{source_function}: [background] ActivateBestChain failed ({reason})")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, bg_state);
        return false;
    }

    return true;
}

MempoolAcceptResult ChainstateManager::ProcessTransaction(
    const CTransactionRef &tx, bool test_accept,
    const MempoolAdmissionLimits &limits,
    const PrecomputedAdmissionChecks *precomputed) {
    AssertLockHeld(cs_main);
    Chainstate &active_chainstate = ActiveChainstate();
    if (!active_chainstate.GetMempool()) {
        TxValidationState state;
        state.Invalid(TxValidationResult::TX_NO_MEMPOOL, "no-mempool");
        return MempoolAcceptResult::Failure(state);
    }
    auto result = AcceptToMemoryPool(active_chainstate, tx, GetTime(),
                                     /*bypass_limits=*/false, test_accept, 0,
                                     limits, precomputed);
    active_chainstate.GetMempool()->check(
        active_chainstate.CoinsTip(), active_chainstate.m_chain.Height() + 1);
    return result;
}

bool TestBlockValidity(
    BlockValidationState &state, const CChainParams &params,
    Chainstate &chainstate, const CBlock &block, CBlockIndex *pindexPrev,
    const std::function<NodeClock::time_point()> &adjusted_time_callback,
    BlockValidationOptions validationOptions) {
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainstate.m_chain.Tip());
    CCoinsViewCache viewNew(&chainstate.CoinsTip());
    BlockHash block_hash(block.GetHash());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;
    indexDummy.phashBlock = &block_hash;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainstate.m_blockman,
                                    chainstate.m_chainman, pindexPrev,
                                    adjusted_time_callback())) {
        LogErrorEvent(
            BCLog::ALL, "chain_contextual_header_check_failed",
            "{source_function}: Consensus::ContextualCheckBlockHeader: {reason}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state);
        return false;
    }

    if (!CheckBlock(block, state, params.GetConsensus(), validationOptions)) {
        LogErrorEvent(BCLog::ALL, "chain_check_block_failed",
                      "{source_function}: Consensus::CheckBlock: {reason}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state);
        return false;
    }

    if (!ContextualCheckBlock(block, state, chainstate.m_chainman,
                              pindexPrev)) {
        LogErrorEvent(
            BCLog::ALL, "chain_contextual_block_check_failed",
            "{source_function}: Consensus::ContextualCheckBlock: {reason}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state);
        return false;
    }

    if (!chainstate.ConnectBlock(block, state, &indexDummy, viewNew,
                                 validationOptions, nullptr, true)) {
        return false;
    }

    assert(state.IsValid());
    return true;
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(Chainstate &active_chainstate,
                           int nManualPruneHeight) {
    BlockValidationState state;
    if (active_chainstate.FlushStateToDisk(state, FlushStateMode::NONE,
                                           nManualPruneHeight)) {
        LogInfoEvent(BCLog::ALL, "chainstate_flush_failed",
                     "{source_function}: failed to flush state ({reason})")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Reason, state);
    }
}

bool Chainstate::LoadChainTip() {
    AssertLockHeld(cs_main);
    const CCoinsViewCache &coins_cache = CoinsTip();
    // Never called when the coins view is empty
    assert(!coins_cache.GetBestBlock().IsNull());
    if (const auto marker = CoinsDB().GetFastSyncSnapshot()) {
        auto *pivot = m_blockman.LookupBlockIndex(marker->first);
        if (!pivot) return false;
        const auto root = pivot->GetBlockHeader().ToV2Header().state_root;
        if (!std::equal(root.begin(), root.end(), marker->second.begin())) return false;
        std::vector<lotus::v2::Coin> coins;
        lotus::v2::MonetaryState monetary;
        if (!GetV2BlockStateCoinsAndMonetary(marker->first, pivot->nHeight, coins, monetary))
            return false;
        lotus::v2::UtxoSet verified;
        for (const auto &coin : coins) if (!verified.Insert(coin)) return false;
        if (lotus::v2::StateRoot(GetActiveV2ChainId(), pivot->nHeight,
                               verified.Root(), monetary) != root) return false;
        CBlockIndex *live_tip =
            m_blockman.LookupBlockIndex(coins_cache.GetBestBlock());
        if (!live_tip || live_tip->GetAncestor(pivot->nHeight) != pivot) return false;
        const auto progress = CoinsDB().GetFastSyncProgress();
        if (!progress) return false;
        CBlockIndex *frontier = m_blockman.LookupBlockIndex(progress->first);
        if (!frontier || frontier->nHeight <= 0 ||
            frontier->nHeight > pivot->nHeight ||
            pivot->GetAncestor(frontier->nHeight) != frontier) return false;
        const auto frontier_root = frontier->GetBlockHeader().ToV2Header().state_root;
        if (!std::equal(frontier_root.begin(), frontier_root.end(), progress->second.begin()))
            return false;
        if (!GetV2BlockStateCoinsAndMonetary(progress->first, frontier->nHeight,
                                           coins, monetary)) return false;
        lotus::v2::UtxoSet verified_frontier;
        for (const auto &coin : coins) if (!verified_frontier.Insert(coin)) return false;
        if (lotus::v2::StateRoot(GetActiveV2ChainId(), frontier->nHeight,
                                verified_frontier.Root(), monetary) != frontier_root)
            return false;
        m_fast_sync_pivot_base = pivot;
        ActivateFastSyncPivot(frontier->nHeight);
        // Block-index loading cannot derive transaction counts through missing
        // pre-pivot bodies. Restore the same provisional estimate installed at
        // activation, then link downloaded descendants for normal validation.
        if (!pivot->HaveNumChainTxs()) pivot->m_chain_tx_count = pivot->nHeight + 1;
        // A process interruption can leave durable block/index descendants
        // ahead of the last UTXO flush. Rebuild candidates for all downloaded
        // descendants of the authenticated pivot so ActivateBestChain can
        // reconnect them using normal validation, rather than losing that work.
        auto descendants = m_blockman.GetAllBlockIndices();
        std::sort(descendants.begin(), descendants.end(),
                  CBlockIndexHeightOnlyComparator());
        for (CBlockIndex *descendant : descendants) {
            if (descendant->nHeight < pivot->nHeight ||
                descendant->GetAncestor(pivot->nHeight) != pivot) continue;
            if (descendant != pivot) {
                if (!descendant->nTx || !descendant->IsValid(BlockValidity::TRANSACTIONS) ||
                    !descendant->pprev->HaveNumChainTxs()) continue;
                descendant->m_chain_tx_count = descendant->pprev->m_chain_tx_count + descendant->nTx;
            }
            auto range = m_blockman.m_blocks_unlinked.equal_range(descendant->pprev);
            for (auto it = range.first; it != range.second;) {
                if (it->second == descendant) it = m_blockman.m_blocks_unlinked.erase(it);
                else ++it;
            }
            TryAddBlockIndexCandidate(descendant);
        }
        if (!live_tip->HaveNumChainTxs() ||
            (live_tip != pivot && !live_tip->IsValid(BlockValidity::SCRIPTS))) return false;
        setBlockIndexCandidates.insert(live_tip);
    }
    const CBlockIndex *tip = m_chain.Tip();

    if (tip && tip->GetBlockHash() == coins_cache.GetBestBlock()) {
        return true;
    }

    // Load pointer to end of best chain
    CBlockIndex *pindex =
        m_blockman.LookupBlockIndex(coins_cache.GetBestBlock());
    if (!pindex) {
        return false;
    }
    m_chain.SetTip(*pindex);
    PruneBlockIndexCandidates();

    tip = m_chain.Tip();
    if (this == &m_chainman.ActiveChainstate()) {
        SyncAdaptiveCapacityTip(tip);
    }
    LogInfoEvent(
        BCLog::ALL, "chainstate_best_chain_loaded",
        "Loaded best chain: hashBestChain={block_hash} height={height} date={block_time} progress={verification_progress:f}")
        .Field(BCLog::LogField::BlockHash, tip->GetBlockHash())
        .Field(BCLog::LogField::Height, m_chain.Height())
        .Field(BCLog::LogField::BlockTime,
               FormatISO8601DateTime(tip->GetBlockTime()))
        .Field(BCLog::LogField::VerificationProgress,
               GuessVerificationProgress(m_chainman.GetParams().TxData(), tip));
    return true;
}

CVerifyDB::CVerifyDB(Notifications &notifications)
    : m_notifications{notifications} {
    m_notifications.progress(_("Verifying blocks…"), 0, false);
}

CVerifyDB::~CVerifyDB() {
    m_notifications.progress(bilingual_str{}, 100, false);
}

VerifyDBResult CVerifyDB::VerifyDB(Chainstate &chainstate,
                                   CCoinsView &coinsview, int nCheckLevel,
                                   int nCheckDepth) {
    AssertLockHeld(cs_main);

    const Config &config = chainstate.m_chainman.GetConfig();
    const CChainParams &params = config.GetChainParams();
    const Consensus::Params &consensusParams = params.GetConsensus();

    if (chainstate.m_chain.Tip() == nullptr ||
        chainstate.m_chain.Tip()->pprev == nullptr) {
        return VerifyDBResult::SUCCESS;
    }

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainstate.m_chain.Height()) {
        nCheckDepth = chainstate.m_chain.Height();
    }

    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogInfoEvent(BCLog::ALL, "chain_verification_parameters",
                     "Verifying last {verification_depth} blocks at level {verification_level}")
            .Field(BCLog::LogField::VerificationDepth, nCheckDepth)
            .Field(BCLog::LogField::VerificationLevel, nCheckLevel);

    CCoinsViewCache coins(&coinsview);
    CBlockIndex *pindex;
    CBlockIndex *pindexFailure = nullptr;
    int nGoodTransactions = 0;
    BlockValidationState state;
    int reportDone = 0;
    bool skipped_no_block_data{false};
    bool skipped_l3_checks{false};
    LogInfoEvent(BCLog::ALL, "chain_verification_started",
                 "Verification progress: 0%");

    const bool is_snapshot_cs{chainstate.m_from_snapshot_blockhash.has_value() ||
                              chainstate.FastSyncPivotBase() != nullptr};

    for (pindex = chainstate.m_chain.Tip(); pindex && pindex->pprev;
         pindex = pindex->pprev) {
        const int percentageDone = std::max(
            1, std::min(99, (int)(((double)(chainstate.m_chain.Height() -
                                            pindex->nHeight)) /
                                  (double)nCheckDepth *
                                  (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone / 10) {
            // report every 10% step
            LogInfoEvent(BCLog::ALL, "chain_verification_progress",
                     "Verification progress: {progress_percent}%")
            .Field(BCLog::LogField::ProgressPercent, percentageDone);
            reportDone = percentageDone / 10;
        }

        m_notifications.progress(_("Verifying blocks…"), percentageDone, false);
        if (pindex->nHeight <= chainstate.m_chain.Height() - nCheckDepth) {
            break;
        }

        if ((chainstate.m_blockman.IsPruneMode() || is_snapshot_cs) &&
            (!pindex->nStatus.hasData() ||
             (chainstate.FastSyncPivotBase() != nullptr &&
              pindex->nHeight <= chainstate.FastSyncPivotBase()->nHeight))) {
            // If pruning or running under an assumeutxo snapshot or fast-sync
            // pivot, only go back as far as we have connected block/undo data.
            LogInfoEvent(BCLog::ALL, "chain_verification_no_data",
                     "VerifyDB(): block verification stopping at height {height} (no data). This could be due to pruning or use of an assumeutxo snapshot.")
            .Field(BCLog::LogField::Height, pindex->nHeight);
            skipped_no_block_data = true;
            break;
        }

        CBlock block;

        // check level 0: read from disk
        if (!chainstate.m_blockman.ReadBlock(block, *pindex)) {
            LogInfoEvent(BCLog::ALL, "chain_verification_read_failed",
                     "Verification error: ReadBlock failed at {height}, hash={block_hash}")
            .Field(BCLog::LogField::Height, pindex->nHeight)
            .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash());
            return VerifyDBResult::CORRUPTED_BLOCK_DB;
        }

        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, consensusParams,
                                            BlockValidationOptions(config))) {
            LogInfoEvent(BCLog::ALL, "chain_verification_bad_block",
                     "Verification error: found bad block at {height}, hash={block_hash} ({reason})")
            .Field(BCLog::LogField::Height, pindex->nHeight)
            .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash())
            .Field(BCLog::LogField::Reason, state);
            return VerifyDBResult::CORRUPTED_BLOCK_DB;
        }

        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!chainstate.m_blockman.ReadBlockUndo(undo, *pindex)) {
                    LogInfoEvent(BCLog::ALL, "chain_verification_undo_failed",
                     "Verification error: found bad undo data at {height}, hash={block_hash}")
            .Field(BCLog::LogField::Height, pindex->nHeight)
            .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash());
                    return VerifyDBResult::CORRUPTED_BLOCK_DB;
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only
        // disconnect of tip blocks
        size_t curr_coins_usage = coins.DynamicMemoryUsage() +
                                  chainstate.CoinsTip().DynamicMemoryUsage();

        if (nCheckLevel >= 3) {
            if (curr_coins_usage <= chainstate.m_coinstip_cache_size_bytes) {
                assert(coins.GetBestBlock() == pindex->GetBlockHash());
                DisconnectResult res =
                    chainstate.DisconnectBlock(block, pindex, coins);
                if (res == DisconnectResult::FAILED) {
                    LogInfoEvent(BCLog::ALL, "chain_verification_disconnect_failed",
                     "Verification error: irrecoverable inconsistency in block data at {height}, hash={block_hash}")
            .Field(BCLog::LogField::Height, pindex->nHeight)
            .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash());
                    return VerifyDBResult::CORRUPTED_BLOCK_DB;
                }
                if (res == DisconnectResult::UNCLEAN) {
                    nGoodTransactions = 0;
                    pindexFailure = pindex;
                } else {
                    nGoodTransactions += block.vtx.size();
                }
            } else {
                skipped_l3_checks = true;
            }
        }

        if (chainstate.m_chainman.m_interrupt) {
            return VerifyDBResult::INTERRUPTED;
        }
    }

    if (pindexFailure) {
        LogInfoEvent(BCLog::ALL, "chain_verification_inconsistent_coins",
                     "Verification error: coin database inconsistencies found (last {verification_depth} blocks, {count} good transactions before that)")
            .Field(BCLog::LogField::VerificationDepth, chainstate.m_chain.Height() - pindexFailure->nHeight + 1)
            .Field(BCLog::LogField::Count, nGoodTransactions);
        return VerifyDBResult::CORRUPTED_BLOCK_DB;
    }
    if (skipped_l3_checks) {
        LogInfoEvent(BCLog::ALL, "chain_verification_cache_limited",
                     "Skipped verification of level >=3 (insufficient database "
                     "cache size). Consider increasing -dbcache.");
    }

    // store block count as we move pindex at check level >= 4
    int block_count = chainstate.m_chain.Height() - pindex->nHeight;

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4 && !skipped_l3_checks) {
        while (pindex != chainstate.m_chain.Tip()) {
            const int percentageDone = std::max(
                1, std::min(99, 100 - int(double(chainstate.m_chain.Height() -
                                                 pindex->nHeight) /
                                          double(nCheckDepth) * 50)));
            if (reportDone < percentageDone / 10) {
                // report every 10% step
                LogInfoEvent(BCLog::ALL, "chain_verification_progress",
                     "Verification progress: {progress_percent}%")
            .Field(BCLog::LogField::ProgressPercent, percentageDone);
                reportDone = percentageDone / 10;
            }
            m_notifications.progress(_("Verifying blocks…"), percentageDone,
                                     false);
            pindex = chainstate.m_chain.Next(pindex);
            CBlock block;
            if (!chainstate.m_blockman.ReadBlock(block, *pindex)) {
                LogInfoEvent(BCLog::ALL, "chain_verification_reconnect_read_failed",
                     "Verification error: ReadBlock failed at {height}, hash={block_hash}")
            .Field(BCLog::LogField::Height, pindex->nHeight)
            .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash());
                return VerifyDBResult::CORRUPTED_BLOCK_DB;
            }
            if (!chainstate.ConnectBlock(block, state, pindex, coins,
                                         BlockValidationOptions(config))) {
                LogInfoEvent(BCLog::ALL, "chain_verification_unconnectable_block",
                     "Verification error: found unconnectable block at {height}, hash={block_hash} ({reason})")
            .Field(BCLog::LogField::Height, pindex->nHeight)
            .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash())
            .Field(BCLog::LogField::Reason, state);
                return VerifyDBResult::CORRUPTED_BLOCK_DB;
            }
            if (chainstate.m_chainman.m_interrupt) {
                return VerifyDBResult::INTERRUPTED;
            }
        }
    }

    LogInfoEvent(BCLog::ALL, "chain_verification_completed",
                     "Verification: No coin database inconsistencies in last {verification_depth} blocks ({count} transactions)")
            .Field(BCLog::LogField::VerificationDepth, block_count)
            .Field(BCLog::LogField::Count, nGoodTransactions);

    if (skipped_l3_checks) {
        return VerifyDBResult::SKIPPED_L3_CHECKS;
    }
    if (skipped_no_block_data) {
        return VerifyDBResult::SKIPPED_MISSING_BLOCKS;
    }
    return VerifyDBResult::SUCCESS;
}

/**
 * Apply the effects of a block on the utxo cache, ignoring that it may already
 * have been applied.
 */
bool Chainstate::RollforwardBlock(const CBlockIndex *pindex,
                                  CCoinsViewCache &view) {
    AssertLockHeld(cs_main);
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!m_blockman.ReadBlock(block, *pindex)) {
        LogErrorEvent(BCLog::ALL, "chain_replay_read_failed",
            "ReplayBlock(): ReadBlock failed at {height}, hash={block_hash}")
            .Field(BCLog::LogField::Height, pindex->nHeight)
            .Field(BCLog::LogField::BlockHash, pindex->GetBlockHash());
        return false;
    }

    // A partially flushed coins view cannot supply authoritative input values:
    // some inputs may already be spent, including inputs created in this block.
    // The durable undo record preserves the accepted block's original inputs.
    CBlockUndo undo;
    if (!m_blockman.ReadBlockUndo(undo, *pindex) || block.vtx.empty() ||
        undo.vtxundo.size() != block.vtx.size() - 1) {
        LogError("ReplayBlock(): missing or inconsistent undo at %d, hash=%s\n",
                 pindex->nHeight, pindex->GetBlockHash().ToString());
        return false;
    }
    std::vector<uint64_t> fee_shares(block.vtx.size(), 0);
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        const CTransaction &tx = *block.vtx[i];
        const auto &spent = undo.vtxundo[i - 1].vprevout;
        Amount fee = Amount::zero();
        TxValidationState state;
        if (spent.size() != tx.vin.size() ||
            !Consensus::CheckTxInputsFromSpentCoins(
                tx, spent, state, pindex->nHeight, fee)) {
            LogError("ReplayBlock(): inconsistent transaction undo at %d, "
                     "hash=%s, tx=%s\n", pindex->nHeight,
                     pindex->GetBlockHash().ToString(), tx.GetId().ToString());
            return false;
        }
        size_t spendable_outputs = 0;
        for (const auto &out : tx.vout) {
            if (!out.scriptPubKey.IsUnspendable() && (out.nFlags & 0x02) == 0) {
                ++spendable_outputs;
            }
        }
        fee_shares[i] = lotus::v2::ComputeTxFeePerSpendableOutput(
            static_cast<uint64_t>(fee / SATOSHI), spendable_outputs);
    }

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const CTransaction &tx = *block.vtx[i];
        // Reapply full Coin metadata as well as output values. Both operations
        // are idempotent, regardless of which entries reached disk before crash.
        AddCoins(view, tx, pindex->nHeight, /*check=*/true);
        if (fee_shares[i] != 0) {
            const uint64_t expiration = lotus::v2::ComputeUtxoExpirationHeight(
                static_cast<uint64_t>(pindex->nHeight), false, fee_shares[i]);
            const TxId txid = tx.GetId();
            for (size_t output = 0; output < tx.vout.size(); ++output) {
                view.UpdateCoinFeeLifespan(COutPoint(txid, output),
                                          fee_shares[i], expiration);
            }
        }
    }

    for (const CTransactionRef &tx : block.vtx) {
        if (tx->IsCoinBase()) {
            continue;
        }
        for (const CTxIn &txin : tx->vin) {
            if (txin.nFlags != 3) {
                view.SpendCoin(txin.prevout);
            }
        }
    }
    // Expiration removals belong to the same committed block transition, even
    // when the block has no ordinary spends. Replaying them is idempotent too.
    for (const auto &expired : undo.vexpired) {
        view.SpendCoin(expired.outpoint);
    }

    return true;
}

bool Chainstate::ReplayBlocks() {
    LOCK(cs_main);

    CCoinsView &db = this->CoinsDB();
    CCoinsViewCache cache(&db);

    std::vector<BlockHash> hashHeads = db.GetHeadBlocks();
    if (hashHeads.empty()) {
        // We're already in a consistent state.
        return true;
    }
    if (hashHeads.size() != 2) {
        LogErrorEvent(BCLog::ALL, "replay_state_unknown",
                      "ReplayBlocks(): unknown inconsistent state");
        return false;
    }

    m_chainman.GetNotifications().progress(_("Replaying blocks…"), 0, false);
    LogInfoEvent(BCLog::ALL, "chain_replay_started", "Replaying blocks");

    // Old tip during the interrupted flush.
    const CBlockIndex *pindexOld = nullptr;
    // New tip during the interrupted flush.
    const CBlockIndex *pindexNew;
    // Latest block common to both the old and the new tip.
    const CBlockIndex *pindexFork = nullptr;

    if (m_blockman.m_block_index.count(hashHeads[0]) == 0) {
        LogErrorEvent(
            BCLog::ALL, "replay_target_unknown",
            "ReplayBlocks(): reorganization to unknown block requested");
        return false;
    }

    pindexNew = &(m_blockman.m_block_index[hashHeads[0]]);

    if (!hashHeads[1].IsNull()) {
        // The old tip is allowed to be 0, indicating it's the first flush.
        if (m_blockman.m_block_index.count(hashHeads[1]) == 0) {
            LogErrorEvent(
                BCLog::ALL, "replay_source_unknown",
                "ReplayBlocks(): reorganization from unknown block requested");
            return false;
        }

        pindexOld = &(m_blockman.m_block_index[hashHeads[1]]);
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) {
            // Never disconnect the genesis block.
            CBlock block;
            if (!m_blockman.ReadBlock(block, *pindexOld)) {
                LogErrorEvent(BCLog::ALL, "chain_rollback_read_failed",
                    "RollbackBlock(): ReadBlock() failed at {height}, hash={block_hash}")
                    .Field(BCLog::LogField::Height, pindexOld->nHeight)
                    .Field(BCLog::LogField::BlockHash, pindexOld->GetBlockHash());
                return false;
            }

            LogInfoEvent(BCLog::ALL, "chain_replay_rolling_back",
                "Rolling back {block_hash} ({height})")
                .Field(BCLog::LogField::BlockHash, pindexOld->GetBlockHash())
                .Field(BCLog::LogField::Height, pindexOld->nHeight);
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache);
            if (res == DisconnectResult::FAILED) {
                LogErrorEvent(BCLog::ALL, "chain_rollback_disconnect_failed",
                    "RollbackBlock(): DisconnectBlock failed at {height}, hash={block_hash}")
                    .Field(BCLog::LogField::Height, pindexOld->nHeight)
                    .Field(BCLog::LogField::BlockHash, pindexOld->GetBlockHash());
                return false;
            }

            // If DisconnectResult::UNCLEAN is returned, it means a non-existing
            // UTXO was deleted, or an existing UTXO was overwritten. It
            // corresponds to cases where the block-to-be-disconnect never had
            // all its operations applied to the UTXO set. However, as both
            // writing a UTXO and deleting a UTXO are idempotent operations, the
            // result is still a version of the UTXO set with the effects of
            // that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight;
         ++nHeight) {
        const CBlockIndex &pindex{*Assert(pindexNew->GetAncestor(nHeight))};
        LogInfoEvent(BCLog::ALL, "chain_replay_rolling_forward",
            "Rolling forward {block_hash} ({height})")
            .Field(BCLog::LogField::BlockHash, pindex.GetBlockHash())
            .Field(BCLog::LogField::Height, nHeight);
        m_chainman.GetNotifications().progress(
            _("Replaying blocks…"),
            (int)((nHeight - nForkHeight) * 100.0 /
                  (pindexNew->nHeight - nForkHeight)),
            false);
        if (!RollforwardBlock(&pindex, cache)) {
            return false;
        }
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    // local CCoinsViewCache goes out of scope
    cache.Flush(/*reallocate_cache=*/false);
    m_chainman.GetNotifications().progress(bilingual_str{}, 100, false);
    return true;
}

// May NOT be used after any connections are up as much of the peer-processing
// logic assumes a consistent block index state
void Chainstate::ClearBlockIndexCandidates() {
    AssertLockHeld(::cs_main);
    m_best_fork_tip = nullptr;
    m_best_fork_base = nullptr;
    setBlockIndexCandidates.clear();
}

bool ChainstateManager::DumpRecentHeadersTime(const fs::path &filePath) const {
    AssertLockHeld(cs_main);

    if (!m_options.store_recent_headers_time) {
        return false;
    }

    // Dump enough headers for RTT computation, with a few extras in case a
    // reorg occurs.
    const uint64_t numHeaders{20};

    try {
        const fs::path filePathTmp = filePath + ".new";
        FILE *filestr = fsbridge::fopen(filePathTmp, "wb");
        if (!filestr) {
            return false;
        }

        AutoFile file{filestr};
        file << HEADERS_TIME_VERSION;
        file << numHeaders;

        const CBlockIndex *index = ActiveTip();
        bool missingIndex{false};
        for (uint64_t i = 0; i < numHeaders; i++) {
            if (!index) {
                LogInfoEvent(
                    BCLog::ALL, "header_times_dump_index_missing",
                    "Missing block index, stopping the headers time dumping after {count} blocks.")
                    .Field(BCLog::LogField::Count, i);
                missingIndex = true;
                break;
            }

            file << index->GetBlockHash();
            file << index->GetHeaderReceivedTime();

            index = index->pprev;
        }

        if (!FileCommit(file.Get())) {
            throw std::runtime_error(strprintf("Failed to commit to file %s",
                                               PathToString(filePathTmp)));
        }
        file.fclose();

        if (missingIndex) {
            fs::remove(filePathTmp);
            return false;
        }

        if (!RenameOver(filePathTmp, filePath)) {
            throw std::runtime_error(strprintf("Rename failed from %s to %s",
                                               PathToString(filePathTmp),
                                               PathToString(filePath)));
        }
    } catch (const std::exception &e) {
        LogInfoEvent(BCLog::ALL, "header_times_dump_failed",
                     "Failed to dump the headers time: {error}.")
            .Field(BCLog::LogField::Error, e.what());
        return false;
    }

    LogInfoEvent(BCLog::ALL, "header_times_dumped",
                 "Successfully dumped the last {count} headers time to {path}.")
        .Field(BCLog::LogField::Count, numHeaders)
        .Field(BCLog::LogField::Path, PathToString(filePath));

    return true;
}

bool ChainstateManager::LoadRecentHeadersTime(const fs::path &filePath) {
    AssertLockHeld(cs_main);

    if (!m_options.store_recent_headers_time) {
        return false;
    }

    FILE *filestr = fsbridge::fopen(filePath, "rb");
    AutoFile file{filestr};
    if (file.IsNull()) {
        LogInfoEvent(BCLog::ALL, "header_times_read_failed",
                     "Failed to open header times from disk, skipping.");
        return false;
    }

    try {
        uint64_t version;
        file >> version;

        if (version != HEADERS_TIME_VERSION) {
            LogInfoEvent(BCLog::ALL, "header_times_version_unsupported",
                         "Unsupported header times file version, skipping.");
            return false;
        }

        uint64_t numBlocks;
        file >> numBlocks;

        for (uint64_t i = 0; i < numBlocks; i++) {
            BlockHash blockHash;
            int64_t receiveTime;

            file >> blockHash;
            file >> receiveTime;

            CBlockIndex *index = m_blockman.LookupBlockIndex(blockHash);
            if (!index) {
                LogInfoEvent(
                    BCLog::ALL, "header_times_load_index_missing",
                    "Missing index for block {block_hash}, stopping the headers time loading after {count} blocks.")
                    .Field(BCLog::LogField::BlockHash, blockHash)
                    .Field(BCLog::LogField::Count, i);
                return false;
            }

            index->nTimeReceived = receiveTime;
        }
    } catch (const std::exception &e) {
        LogInfoEvent(
            BCLog::ALL, "header_times_load_failed",
            "Failed to read the headers time file data on disk: {error}.")
            .Field(BCLog::LogField::Error, e.what());
        return false;
    }

    return true;
}

bool ChainstateManager::LoadBlockIndex() {
    AssertLockHeld(cs_main);
    // Load block index from databases
    if (m_blockman.m_blockfiles_indexed) {
        bool ret{m_blockman.LoadBlockIndexDB(SnapshotBlockhash())};
        if (!ret) {
            return false;
        }

        m_blockman.ScanAndUnlinkAlreadyPrunedFiles();

        std::vector<CBlockIndex *> vSortedByHeight{
            m_blockman.GetAllBlockIndices()};
        std::sort(vSortedByHeight.begin(), vSortedByHeight.end(),
                  CBlockIndexHeightOnlyComparator());

        for (CBlockIndex *pindex : vSortedByHeight) {
            if (m_interrupt) {
                return false;
            }
            // If we have an assumeutxo-based chainstate, then the snapshot
            // block will be a candidate for the tip, but it may not be
            // VALID_TRANSACTIONS (eg if we haven't yet downloaded the block),
            // so we special-case the snapshot block as a potential candidate
            // here.
            if (pindex == GetSnapshotBaseBlock() ||
                (pindex->IsValid(BlockValidity::TRANSACTIONS) &&
                 (pindex->HaveNumChainTxs() || pindex->pprev == nullptr))) {
                for (Chainstate *chainstate : GetAll()) {
                    chainstate->TryAddBlockIndexCandidate(pindex);
                }
            }

            if (pindex->nStatus.isInvalid() &&
                (!m_best_invalid ||
                 pindex->nChainWork > m_best_invalid->nChainWork)) {
                m_best_invalid = pindex;
            }

            if (pindex->nStatus.isOnParkedChain() &&
                (!m_best_parked ||
                 pindex->nChainWork > m_best_parked->nChainWork)) {
                m_best_parked = pindex;
            }

            if (pindex->IsValid(BlockValidity::TREE) &&
                (m_best_header == nullptr ||
                 CBlockIndexWorkComparator()(m_best_header, pindex))) {
                m_best_header = pindex;
            }
        }
    }
    if (m_active_chainstate) {
        node::PublishChainTipSnapshot(*this, m_active_chainstate->GetMempool());
    }
    return true;
}

bool Chainstate::LoadGenesisBlock() {
    LOCK(cs_main);

    const CChainParams &params{m_chainman.GetParams()};

    // Check whether we're already initialized by checking for genesis in
    // m_blockman.m_block_index. Note that we can't use m_chain here, since it
    // is set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (m_blockman.m_block_index.count(params.GenesisBlock().GetHash())) {
        return true;
    }

    try {
        const CBlock &block = params.GenesisBlock();
        FlatFilePos blockPos{m_blockman.WriteBlock(block, 0)};
        if (blockPos.IsNull()) {
            LogError("%s: writing genesis block to disk failed\n", __func__);
            return false;
        }
        CBlockIndex *pindex =
            m_blockman.AddToBlockIndex(block, m_chainman.m_best_header);
        m_chainman.ReceivedBlockTransactions(block, pindex, blockPos);
    } catch (const std::runtime_error &e) {
        LogError("%s: failed to write genesis block: %s\n", __func__, e.what());
        return false;
    }

    return true;
}

void ChainstateManager::LoadExternalBlockFile(
    AutoFile &file_in, FlatFilePos *dbp,
    std::multimap<BlockHash, FlatFilePos> *blocks_with_unknown_parent,
    avalanche::Processor *const avalanche) {
    // Either both should be specified (-reindex), or neither (-loadblock).
    assert(!dbp == !blocks_with_unknown_parent);

    int64_t nStart = GetTimeMillis();
    const CChainParams &params{GetParams()};

    int nLoaded = 0;
    try {
        // Make sure we have at least 2*MAX_TX_SIZE space in the buffer
        // so any transaction can fit in there.
        BufferedFile blkdat{file_in, 2 * MAX_TX_SIZE, MAX_TX_SIZE + 8};
        // nRewind indicates where to resume scanning in case something goes
        // wrong, such as a block fails to deserialize.
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            if (m_interrupt) {
                return;
            }

            blkdat.SetPos(nRewind);
            // Start one byte further next time, in case of failure.
            nRewind++;
            // Remove former limit.
            blkdat.SetLimit();
            unsigned int nSize = 0;
            try {
                // Locate a header.
                uint8_t buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(std::byte(params.DiskMagic()[0]));
                nRewind = blkdat.GetPos() + 1;
                blkdat >> buf;
                if (memcmp(buf, params.DiskMagic().data(),
                           CMessageHeader::MESSAGE_START_SIZE)) {
                    continue;
                }

                // Read size.
                blkdat >> nSize;
                if (nSize < lotus::v2::HEADER_SIZE) {
                    continue;
                }
            } catch (const std::exception &) {
                // No valid block header found; don't complain.
                // (this happens at the end of every blk.dat file)
                break;
            }

            try {
                // read block header
                const uint64_t nBlockPos{blkdat.GetPos()};
                if (dbp) {
                    dbp->nPos = nBlockPos;
                }
                blkdat.SetLimit(nBlockPos + nSize);
                CBlockHeader header;
                blkdat >> header;
                const BlockHash hash{header.GetHash()};
                // Skip the rest of this block (this may read from disk
                // into memory); position to the marker before the next block,
                // but it's still possible to rewind to the start of the
                // current block (without a disk read).
                nRewind = nBlockPos + nSize;
                blkdat.SkipTo(nRewind);

                // needs to remain available after the cs_main lock is released
                // to avoid duplicate reads from disk
                std::shared_ptr<CBlock> pblock{};

                {
                    LOCK(cs_main);
                    // detect out of order blocks, and store them for later
                    if (hash != params.GetConsensus().hashGenesisBlock &&
                        !m_blockman.LookupBlockIndex(header.hashPrevBlock)) {
                        LogDebug(
                            BCLog::REINDEX,
                            "%s: Out of order block %s, parent %s not known\n",
                            __func__, hash.ToString(),
                            header.hashPrevBlock.ToString());
                        if (dbp && blocks_with_unknown_parent) {
                            blocks_with_unknown_parent->emplace(
                                header.hashPrevBlock, *dbp);
                        }
                        continue;
                    }

                    // process in case the block isn't known yet
                    const CBlockIndex *pindex =
                        m_blockman.LookupBlockIndex(hash);
                    if (!pindex || !pindex->nStatus.hasData()) {
                        // This block can be processed immediately; rewind to
                        // its start, read and deserialize it.
                        blkdat.SetPos(nBlockPos);
                        pblock = std::make_shared<CBlock>();
                        blkdat >> *pblock;
                        nRewind = blkdat.GetPos();

                        BlockValidationState state;
                        if (AcceptBlock(pblock, state, true, dbp, nullptr,
                                        true)) {
                            nLoaded++;
                        }
                        if (state.IsError()) {
                            break;
                        }
                    } else if (hash != params.GetConsensus().hashGenesisBlock &&
                               pindex->nHeight % 1000 == 0) {
                        LogDebug(
                            BCLog::REINDEX,
                            "Block Import: already had block %s at height %d\n",
                            hash.ToString(), pindex->nHeight);
                    }
                }

                // Activate the genesis block so normal node progress can
                // continue. During first -reindex, this will only connect
                // Genesis since ActivateBestChain only connects blocks which
                // are in the block tree db, which only contains blocks whose
                // parents are in it.
                // But do this only if genesis isn't activated yet, to avoid
                // connecting many blocks without assumevalid in the case of a
                // continuation of a reindex that was interrupted by the user.
                if (hash == params.GetConsensus().hashGenesisBlock &&
                    WITH_LOCK(::cs_main, return ActiveHeight()) == -1) {
                    BlockValidationState state;
                    if (!ActiveChainstate().ActivateBestChain(state, nullptr,
                                                              avalanche)) {
                        break;
                    }
                }

                if (m_blockman.IsPruneMode() &&
                    m_blockman.m_blockfiles_indexed && pblock) {
                    // Must update the tip for pruning to work while importing
                    // with -loadblock. This is a tradeoff to conserve disk
                    // space at the expense of time spent updating the tip to be
                    // able to prune. Otherwise, ActivateBestChain won't be
                    // called by the import process until after all of the block
                    // files are loaded. ActivateBestChain can be called by
                    // concurrent network message processing, but that is not
                    // reliable for the purpose of pruning while importing.
                    bool activation_failure = false;
                    for (auto c : GetAll()) {
                        BlockValidationState state;
                        if (!c->ActivateBestChain(state, pblock, avalanche)) {
                            LogDebug(BCLog::REINDEX,
                                     "failed to activate chain (%s)\n",
                                     state.ToString());
                            activation_failure = true;
                            break;
                        }
                    }
                    if (activation_failure) {
                        break;
                    }
                }

                NotifyHeaderTip();

                if (!blocks_with_unknown_parent) {
                    continue;
                }

                // Recursively process earlier encountered successors of this
                // block
                std::deque<BlockHash> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    BlockHash head = queue.front();
                    queue.pop_front();
                    auto range = blocks_with_unknown_parent->equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<BlockHash, FlatFilePos>::iterator it =
                            range.first;
                        std::shared_ptr<CBlock> pblockrecursive =
                            std::make_shared<CBlock>();
                        if (m_blockman.ReadBlock(*pblockrecursive,
                                                 it->second)) {
                            LogDebug(
                                BCLog::REINDEX,
                                "%s: Processing out of order child %s of %s\n",
                                __func__, pblockrecursive->GetHash().ToString(),
                                head.ToString());
                            LOCK(cs_main);
                            BlockValidationState dummy;
                            if (AcceptBlock(pblockrecursive, dummy, true,
                                            &it->second, nullptr, true)) {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        blocks_with_unknown_parent->erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception &e) {
                // Historical bugs added extra data to the block files that does
                // not deserialize cleanly. Commonly this data is between
                // readable blocks, but it does not really matter. Such data is
                // not fatal to the import process. The code that reads the
                // block files deals with invalid data by simply ignoring it. It
                // continues to search for the next {4 byte magic message start
                // bytes + 4 byte length + block} that does deserialize cleanly
                // and passes all of the other block validation checks dealing
                // with POW and the merkle root, etc... We merely note with this
                // informational log message when unexpected data is
                // encountered. We could also be experiencing a storage system
                // read error, or a read of a previous bad write. These are
                // possible, but less likely scenarios. We don't have enough
                // information to tell a difference here. The reindex process is
                // not the place to attempt to clean and/or compact the block
                // files. If so desired, a studious node operator may use
                // knowledge of the fact that the block files are not entirely
                // pristine in order to prepare a set of pristine, and perhaps
                // ordered, block files for later reindexing.
                LogDebug(BCLog::REINDEX,
                         "%s: unexpected data at file offset 0x%x - %s. "
                         "continuing\n",
                         __func__, (nRewind - 1), e.what());
            }
        }
    } catch (const std::runtime_error &e) {
        GetNotifications().fatalError(std::string("System error: ") + e.what());
    }

    LogInfoEvent(
        BCLog::ALL, "block_file_external_import_completed",
        "Loaded {imported_block_count} blocks from external file in {elapsed_milliseconds}ms")
        .Field(BCLog::LogField::ImportedBlockCount, nLoaded)
        .Field(BCLog::LogField::ElapsedMilliseconds, GetTimeMillis() - nStart);
}

bool ChainstateManager::ShouldCheckBlockIndex() const {
    // Assert to verify Flatten() has been called.
    if (!*Assert(m_options.check_block_index)) {
        return false;
    }
    if (FastRandomContext().randrange(*m_options.check_block_index) >= 1) {
        return false;
    }
    return true;
}

void ChainstateManager::CheckBlockIndex() {
    if (!ShouldCheckBlockIndex()) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex
    // before ActivateBestChain, so we have the genesis block in
    // m_blockman.m_block_index but no active chain. (A few of the tests when
    // iterating the block tree require that m_chain has been initialized.)
    if (ActiveChain().Height() < 0) {
        assert(m_blockman.m_block_index.size() <= 1);
        return;
    }

    // Build forward-pointing data structure for the entire block tree.
    // For performance reasons, indexes of the best header chain are stored in
    // a vector (within CChain).
    // All remaining blocks are stored in a multimap.
    // The best header chain can differ from the active chain: E.g. its entries
    // may belong to blocks that are not yet validated.
    CChain best_hdr_chain;
    assert(m_best_header);
    best_hdr_chain.SetTip(*m_best_header);

    std::multimap<CBlockIndex *, CBlockIndex *> forward;
    for (auto &[_, block_index] : m_blockman.m_block_index) {
        // Only save indexes in forward that are not part of the best header
        // chain.
        if (!best_hdr_chain.Contains(&block_index)) {
            // Only genesis, which must be part of the best header chain,
            // can have a nullptr parent.
            assert(block_index.pprev);
            forward.emplace(block_index.pprev, &block_index);
        }
    }
    assert(forward.size() + best_hdr_chain.Height() + 1 ==
           m_blockman.m_block_index.size());

    CBlockIndex *pindex = best_hdr_chain[0];
    assert(pindex);
    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    // Oldest ancestor of pindex which is invalid.
    CBlockIndex *pindexFirstInvalid = nullptr;
    // Oldest ancestor of pindex which is parked.
    CBlockIndex *pindexFirstParked = nullptr;
    // Oldest ancestor of pindex which does not have data available, since
    // assumeutxo snapshot if used.
    CBlockIndex *pindexFirstMissing = nullptr;
    // Oldest ancestor of pindex for which nTx == 0, since assumeutxo snapshot
    // if used..
    CBlockIndex *pindexFirstNeverProcessed = nullptr;
    // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE
    // (regardless of being valid or not).
    CBlockIndex *pindexFirstNotTreeValid = nullptr;
    // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS
    // (regardless of being valid or not), since assumeutxo snapshot if used.
    CBlockIndex *pindexFirstNotTransactionsValid = nullptr;
    // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN
    // (regardless of being valid or not), since assumeutxo snapshot if used.
    CBlockIndex *pindexFirstNotChainValid = nullptr;
    // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS
    // (regardless of being valid or not), since assumeutxo snapshot if used.
    CBlockIndex *pindexFirstNotScriptsValid = nullptr;

    // After checking an assumeutxo snapshot block, reset pindexFirst pointers
    // to earlier blocks that have not been downloaded or validated yet, so
    // checks for later blocks can assume the earlier blocks were validated and
    // be stricter, testing for more requirements.
    const CBlockIndex *snap_base{GetSnapshotBaseBlock()};
    CBlockIndex *snap_first_missing{}, *snap_first_notx{}, *snap_first_notv{},
        *snap_first_nocv{}, *snap_first_nosv{};
    auto snap_update_firsts = [&] {
        if (pindex == snap_base) {
            std::swap(snap_first_missing, pindexFirstMissing);
            std::swap(snap_first_notx, pindexFirstNeverProcessed);
            std::swap(snap_first_notv, pindexFirstNotTransactionsValid);
            std::swap(snap_first_nocv, pindexFirstNotChainValid);
            std::swap(snap_first_nosv, pindexFirstNotScriptsValid);
        }
    };

    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus.hasFailed()) {
            pindexFirstInvalid = pindex;
        }
        if (pindexFirstParked == nullptr && pindex->nStatus.isParked()) {
            pindexFirstParked = pindex;
        }
        if (pindexFirstMissing == nullptr && !pindex->nStatus.hasData()) {
            pindexFirstMissing = pindex;
        }
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) {
            pindexFirstNeverProcessed = pindex;
        }
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr &&
            pindex->nStatus.getValidity() < BlockValidity::TREE) {
            pindexFirstNotTreeValid = pindex;
        }
        if (pindex->pprev != nullptr) {
            if (pindexFirstNotTransactionsValid == nullptr &&
                pindex->nStatus.getValidity() < BlockValidity::TRANSACTIONS) {
                pindexFirstNotTransactionsValid = pindex;
            }
            if (pindexFirstNotChainValid == nullptr &&
                pindex->nStatus.getValidity() < BlockValidity::CHAIN) {
                pindexFirstNotChainValid = pindex;
            }
            if (pindexFirstNotScriptsValid == nullptr &&
                pindex->nStatus.getValidity() < BlockValidity::SCRIPTS) {
                pindexFirstNotScriptsValid = pindex;
            }
        }

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            // Genesis block's hash must match.
            assert(pindex->GetBlockHash() == GetConsensus().hashGenesisBlock);
            for (auto c : GetAll()) {
                if (c->m_chain.Genesis() != nullptr) {
                    // The chain's genesis block must be this block.
                    assert(pindex == c->m_chain.Genesis());
                }
            }
        }
        if (!pindex->HaveNumChainTxs()) {
            // nSequenceId can't be set positive for blocks that aren't linked
            // (negative is used for preciousblock)
            assert(pindex->nSequenceId <= 0);
        }
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or
        // not pruning has occurred). HAVE_DATA is only equivalent to nTx > 0
        // (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!m_blockman.m_have_pruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx
            // > 0
            assert(pindex->nStatus.hasData() == (pindex->nTx > 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else if (pindex->nStatus.hasData()) {
            // If we have pruned, then we can only say that HAVE_DATA implies
            // nTx > 0
            assert(pindex->nTx > 0);
        }
        if (pindex->nStatus.hasUndo()) {
            assert(pindex->nStatus.hasData());
        }
        if (snap_base && snap_base->GetAncestor(pindex->nHeight) == pindex) {
            // Assumed-valid blocks should connect to the main chain.
            assert(pindex->nStatus.getValidity() >= BlockValidity::TREE);
        }
        // There should only be an nTx value if we have
        // actually seen a block's transactions.
        // This is pruning-independent.
        assert((pindex->nStatus.getValidity() >= BlockValidity::TRANSACTIONS) ==
               (pindex->nTx > 0));
        // All parents having had data (at some point) is equivalent to all
        // parents being VALID_TRANSACTIONS, which is equivalent to
        // HaveNumChainTxs().
        assert((pindexFirstNeverProcessed == nullptr || pindex == snap_base) ==
               (pindex->HaveNumChainTxs()));
        assert((pindexFirstNotTransactionsValid == nullptr ||
                pindex == snap_base) == (pindex->HaveNumChainTxs()));
        // nHeight must be consistent.
        assert(pindex->nHeight == nHeight);
        // For every block except the genesis block, the chainwork must be
        // larger than the parent's.
        assert(pindex->pprev == nullptr ||
               pindex->nChainWork >= pindex->pprev->nChainWork);
        // The pskip pointer must point back for all but the first 2 blocks.
        assert(nHeight < 2 ||
               (pindex->pskip && (pindex->pskip->nHeight < nHeight)));
        // All m_blockman.m_block_index entries must at least be TREE valid
        assert(pindexFirstNotTreeValid == nullptr);
        if (pindex->nStatus.getValidity() >= BlockValidity::TREE) {
            // TREE valid implies all parents are TREE valid
            assert(pindexFirstNotTreeValid == nullptr);
        }
        if (pindex->nStatus.getValidity() >= BlockValidity::CHAIN) {
            // CHAIN valid implies all parents are CHAIN valid
            assert(pindexFirstNotChainValid == nullptr);
        }
        if (pindex->nStatus.getValidity() >= BlockValidity::SCRIPTS) {
            // SCRIPTS valid implies all parents are SCRIPTS valid
            assert(pindexFirstNotScriptsValid == nullptr);
        }
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            // The failed mask cannot be set for blocks without invalid parents.
            assert(!pindex->nStatus.isInvalid());
        }
        if (pindexFirstParked == nullptr) {
            // Checks for not-parked blocks.
            // The parked mask cannot be set for blocks without parked parents.
            // (i.e., hasParkedParent only if an ancestor is properly parked).
            assert(!pindex->nStatus.isOnParkedChain());
        }
        // Make sure m_chain_tx_count sum is correctly computed.
        if (!pindex->pprev) {
            // If no previous block, nTx and m_chain_tx_count must be the same.
            assert(pindex->m_chain_tx_count == pindex->nTx);
        } else if (pindex->pprev->m_chain_tx_count > 0 && pindex->nTx > 0) {
            // If previous m_chain_tx_count is set and number of transactions in
            // block is known, sum must be set.
            assert(pindex->m_chain_tx_count ==
                   pindex->nTx + pindex->pprev->m_chain_tx_count);
        } else {
            // Otherwise m_chain_tx_count should only be set if this is a
            // snapshot block, and must be set if it is.
            assert((pindex->m_chain_tx_count != 0) == (pindex == snap_base));
        }

        // Chainstate-specific checks on setBlockIndexCandidates
        for (auto c : GetAll()) {
            if (c->m_chain.Tip() == nullptr) {
                continue;
            }
            // Two main factors determine whether pindex is a candidate in
            // setBlockIndexCandidates:
            //
            // - If pindex has less work than the chain tip, it should not be a
            //   candidate, and this will be asserted below. Otherwise it is a
            //   potential candidate.
            //
            // - If pindex or one of its parent blocks back to the genesis block
            //   or an assumeutxo snapshot never downloaded transactions
            //   (pindexFirstNeverProcessed is non-null), it should not be a
            //   candidate, and this will be asserted below. The only exception
            //   is if pindex itself is an assumeutxo snapshot block. Then it is
            //   also a potential candidate.
            if (!CBlockIndexWorkComparator()(pindex, c->m_chain.Tip()) &&
                (pindexFirstNeverProcessed == nullptr || pindex == snap_base)) {
                // If pindex was detected as invalid (pindexFirstInvalid is
                // non-null), it is not required to be in
                // setBlockIndexCandidates.
                if (pindexFirstInvalid == nullptr) {
                    // If this chainstate is the active chainstate, pindex
                    // must be in setBlockIndexCandidates. Otherwise, this
                    // chainstate is a background validation chainstate, and
                    // pindex only needs to be added if it is an ancestor of
                    // the snapshot that is being validated.
                    if (c == &ActiveChainstate() ||
                        GetSnapshotBaseBlock()->GetAncestor(pindex->nHeight) ==
                            pindex) {
                        // If pindex and all its parents back to the genesis
                        // block or an assumeutxo snapshot block downloaded
                        // transactions, transactions, and the transactions were
                        // not pruned (pindexFirstMissing is null), it is a
                        // potential candidate or was parked. The check excludes
                        // pruned blocks, because if any blocks were pruned
                        // between pindex the current chain tip, pindex will
                        // only temporarily be added to setBlockIndexCandidates,
                        // before being moved to m_blocks_unlinked. This check
                        // could be improved to verify that if all blocks
                        // between the chain tip and pindex have data, pindex
                        // must be a candidate.
                        if (pindexFirstMissing == nullptr) {
                            assert(pindex->nStatus.isOnParkedChain() ||
                                   c->setBlockIndexCandidates.count(pindex));
                        }
                        // If pindex is the chain tip, it also is a potential
                        // candidate.
                        //
                        // If the chainstate was loaded from a snapshot and
                        // pindex is the base of the snapshot, pindex is also a
                        // potential candidate.
                        if (pindex == c->m_chain.Tip() ||
                            pindex == c->SnapshotBase()) {
                            assert(c->setBlockIndexCandidates.count(pindex));
                        }
                    }
                    // If some parent is missing, then it could be that this
                    // block was in setBlockIndexCandidates but had to be
                    // removed because of the missing data. In this case it must
                    // be in m_blocks_unlinked -- see test below.
                }
            } else {
                // If this block sorts worse than the current tip or some
                // ancestor's block has never been seen, it cannot be in
                // setBlockIndexCandidates.
                assert(c->setBlockIndexCandidates.count(pindex) == 0);
            }
        }
        // Check whether this block is in m_blocks_unlinked.
        std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
                  std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
            rangeUnlinked =
                m_blockman.m_blocks_unlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && pindex->nStatus.hasData() &&
            pindex != snap_base &&
            pindexFirstNeverProcessed != nullptr &&
            pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never
            // received, and has no invalid parents, it must be in
            // m_blocks_unlinked.
            assert(foundInUnlinked);
        }
        if (!pindex->nStatus.hasData()) {
            // Can't be in m_blocks_unlinked if we don't HAVE_DATA
            assert(!foundInUnlinked);
        }
        if (pindexFirstMissing == nullptr) {
            // We aren't missing data for any parent -- cannot be in
            // m_blocks_unlinked.
            assert(!foundInUnlinked);
        }
        if (pindex->pprev && pindex->nStatus.hasData() &&
            pindexFirstNeverProcessed == nullptr &&
            pindexFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents
            // at some point, but we're currently missing data for some parent.
            assert(m_blockman.m_have_pruned);
            // This block may have entered m_blocks_unlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between m_chain and the
            //    tip.
            // So if this block is itself better than any m_chain.Tip() and it
            // wasn't in setBlockIndexCandidates, then it must be in
            // m_blocks_unlinked.
            for (auto c : GetAll()) {
                const bool is_active = c == &ActiveChainstate();
                if (!CBlockIndexWorkComparator()(pindex, c->m_chain.Tip()) &&
                    c->setBlockIndexCandidates.count(pindex) == 0) {
                    if (pindexFirstInvalid == nullptr) {
                        if (is_active ||
                            snap_base->GetAncestor(pindex->nHeight) == pindex) {
                            assert(foundInUnlinked);
                        }
                    }
                }
            }
        }
        // Perhaps too slow
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash());
        // End: actual consistency checks.

        // Try descending into the first subnode. Always process forks first and
        // the best header chain after.
        snap_update_firsts();
        std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
                  std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
            range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode not part of the best header chain was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        } else if (best_hdr_chain.Contains(pindex)) {
            // Descend further into best header chain.
            nHeight++;
            pindex = best_hdr_chain[nHeight];
            if (!pindex) {
                // we are finished, since the best header chain is always
                // processed last
                break;
            }
            continue;
        }
        // This is a leaf node. Move upwards until we reach a node of which we
        // have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            snap_update_firsts();
            // If pindex was the first with a certain property, unset the
            // corresponding variable.
            if (pindex == pindexFirstInvalid) {
                pindexFirstInvalid = nullptr;
            }
            if (pindex == pindexFirstParked) {
                pindexFirstParked = nullptr;
            }
            if (pindex == pindexFirstMissing) {
                pindexFirstMissing = nullptr;
            }
            if (pindex == pindexFirstNeverProcessed) {
                pindexFirstNeverProcessed = nullptr;
            }
            if (pindex == pindexFirstNotTreeValid) {
                pindexFirstNotTreeValid = nullptr;
            }
            if (pindex == pindexFirstNotTransactionsValid) {
                pindexFirstNotTransactionsValid = nullptr;
            }
            if (pindex == pindexFirstNotChainValid) {
                pindexFirstNotChainValid = nullptr;
            }
            if (pindex == pindexFirstNotScriptsValid) {
                pindexFirstNotScriptsValid = nullptr;
            }
            // Find our parent.
            CBlockIndex *pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
                      std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
                rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                // Our parent must have at least the node we're coming from as
                // child.
                assert(rangePar.first != rangePar.second);
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to a sibling not part of the best header chain.
                pindex = rangePar.first->second;
                break;
            } else if (pindexPar == best_hdr_chain[nHeight - 1]) {
                // Move to pindex's sibling on the best-chain, if it has one.
                pindex = best_hdr_chain[nHeight];
                // There will not be a next block if (and only if) parent block
                // is the best header.
                assert((pindex == nullptr) ==
                       (pindexPar == best_hdr_chain.Tip()));
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire block index.
    assert(nNodes == forward.size() + best_hdr_chain.Height() + 1);
}

std::string Chainstate::ToString() {
    AssertLockHeld(::cs_main);
    CBlockIndex *tip = m_chain.Tip();
    return strprintf("Chainstate [%s] @ height %d (%s)",
                     m_from_snapshot_blockhash ? "snapshot" : "ibd",
                     tip ? tip->nHeight : -1,
                     tip ? tip->GetBlockHash().ToString() : "null");
}

bool Chainstate::ResizeCoinsCaches(size_t coinstip_size, size_t coinsdb_size) {
    AssertLockHeld(::cs_main);
    if (coinstip_size == m_coinstip_cache_size_bytes &&
        coinsdb_size == m_coinsdb_cache_size_bytes) {
        // Cache sizes are unchanged, no need to continue.
        return true;
    }
    size_t old_coinstip_size = m_coinstip_cache_size_bytes;
    m_coinstip_cache_size_bytes = coinstip_size;
    m_coinsdb_cache_size_bytes = coinsdb_size;
    CoinsDB().ResizeCache(coinsdb_size);

    LogInfoEvent(
        BCLog::ALL, "coins_database_cache_resized",
        "[{chainstate_description}] resized coinsdb cache to {database_cache_mib:.1f} MiB")
        .Field(BCLog::LogField::ChainstateDescription, this->ToString())
        .Field(BCLog::LogField::DatabaseCacheMiB,
               coinsdb_size * (1.0 / 1024 / 1024));
    LogInfoEvent(
        BCLog::ALL, "coins_tip_cache_resized",
        "[{chainstate_description}] resized coinstip cache to {coins_tip_cache_budget_mib:.1f} MiB")
        .Field(BCLog::LogField::ChainstateDescription, this->ToString())
        .Field(BCLog::LogField::CoinsTipCacheBudgetMiB,
               coinstip_size * (1.0 / 1024 / 1024));

    BlockValidationState state;
    bool ret;

    if (coinstip_size > old_coinstip_size) {
        // Likely no need to flush if cache sizes have grown.
        ret = FlushStateToDisk(state, FlushStateMode::IF_NEEDED);
    } else {
        // Otherwise, flush state to disk and deallocate the in-memory coins
        // map.
        ret = FlushStateToDisk(state, FlushStateMode::ALWAYS);
    }
    return ret;
}

//! Guess how far we are in the verification process at the given block index
//! require cs_main if pindex has not been validated yet (because the chain's
//! transaction count might be unset) This conditional lock requirement might be
//! confusing, see: https://github.com/bitcoin/bitcoin/issues/15994
double GuessVerificationProgress(const ChainTxData &data,
                                 const CBlockIndex *pindex) {
    if (pindex == nullptr) {
        return 0.0;
    }
    if (pindex->m_chain_tx_count == 0) {
        LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Debug,
                      "Block %d has unset m_chain_tx_count. Unable to "
                      "estimate verification progress.\n",
                      pindex->nHeight);
        return 0.0;
    }

    int64_t nNow = time(nullptr);

    double fTxTotal;
    if (pindex->GetChainTxCount() <= data.tx_count) {
        fTxTotal = data.tx_count + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->GetChainTxCount() +
                   (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return std::min<double>(pindex->GetChainTxCount() / fTxTotal, 1.0);
}

std::optional<BlockHash> ChainstateManager::SnapshotBlockhash() const {
    LOCK(::cs_main);
    if (m_active_chainstate && m_active_chainstate->m_from_snapshot_blockhash) {
        // If a snapshot chainstate exists, it will always be our active.
        return m_active_chainstate->m_from_snapshot_blockhash;
    }
    return std::nullopt;
}

std::vector<Chainstate *> ChainstateManager::GetAll() {
    LOCK(::cs_main);
    std::vector<Chainstate *> out;

    for (Chainstate *pchainstate :
         {m_ibd_chainstate.get(), m_snapshot_chainstate.get()}) {
        if (this->IsUsable(pchainstate)) {
            out.push_back(pchainstate);
        }
    }

    return out;
}

// Startup/reset switches can select a chainstate before it has a loaded tip.
// Retire its previous RPC generation rather than publishing an unready view.
static void InvalidateChainstateRpcSnapshot(const ChainstateManager &chainman) {
    auto &publisher = node::GetGlobalSnapshotPublisher();
    const auto current = publisher.Load();
    if (current && current->chainman_ptr == &chainman) {
        publisher.Publish(std::make_shared<const node::ChainAndMempoolSnapshot>());
    }
}

Chainstate &ChainstateManager::InitializeChainstate(CTxMemPool *mempool) {
    AssertLockHeld(::cs_main);
    assert(!m_ibd_chainstate);
    assert(!m_active_chainstate);

    m_ibd_chainstate = std::make_unique<Chainstate>(mempool, m_blockman, *this);
    m_active_chainstate = m_ibd_chainstate.get();
    InvalidateChainstateRpcSnapshot(*this);
    return *m_active_chainstate;
}

[[nodiscard]] static bool DeleteCoinsDBFromDisk(const fs::path &db_path,
                                                bool is_snapshot)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    AssertLockHeld(::cs_main);

    if (is_snapshot) {
        fs::path base_blockhash_path =
            db_path / node::SNAPSHOT_BLOCKHASH_FILENAME;

        try {
            const bool existed{fs::remove(base_blockhash_path)};
            if (!existed) {
                LogInfoEvent(
                    BCLog::ALL, "snapshot_cleanup_base_hash_missing",
                    "[snapshot] snapshot chainstate dir being removed lacks {path} file")
                    .Field(BCLog::LogField::Path,
                           fs::PathToString(node::SNAPSHOT_BLOCKHASH_FILENAME));
            }
        } catch (const fs::filesystem_error &e) {
            LogWarning("[snapshot] failed to remove file %s: %s\n",
                       fs::PathToString(base_blockhash_path),
                       e.code().message());
        }
    }

    std::string path_str = fs::PathToString(db_path);
    LogInfoEvent(BCLog::ALL, "snapshot_database_directory_removing",
                 "Removing leveldb dir at {directory}")
        .Field(BCLog::LogField::Directory, path_str);

    // We have to destruct before this call leveldb::DB in order to release the
    // db lock, otherwise `DestroyDB` will fail. See `leveldb::~DBImpl()`.
    const bool destroyed = dbwrapper::DestroyDB(path_str, {}).ok();

    if (!destroyed) {
        LogInfoEvent(BCLog::ALL, "snapshot_database_directory_removal_failed",
                     "error: leveldb DestroyDB call failed on {directory}")
            .Field(BCLog::LogField::Directory, path_str);
    }

    // Datadir should be removed from filesystem; otherwise initialization may
    // detect it on subsequent statups and get confused.
    //
    // If the base_blockhash_path removal above fails in the case of snapshot
    // chainstates, this will return false since leveldb won't remove a
    // non-empty directory.
    return destroyed && !fs::exists(db_path);
}

util::Result<CBlockIndex *> ChainstateManager::ActivateSnapshot(
    AutoFile &coins_file, const SnapshotMetadata &metadata, bool in_memory) {
    BlockHash base_blockhash = metadata.m_base_blockhash;

    if (this->SnapshotBlockhash()) {
        return util::Error{Untranslated(
            "Can't activate a snapshot-based chainstate more than once")};
    }

    CBlockIndex *snapshot_start_block{};

    {
        LOCK(::cs_main);

        if (!GetParams().AssumeutxoForBlockhash(base_blockhash).has_value()) {
            auto available_heights = GetParams().GetAvailableSnapshotHeights();
            std::string heights_formatted =
                util::Join(available_heights, ", ",
                           [&](const auto &i) { return util::ToString(i); });
            return util::Error{strprintf(
                Untranslated("assumeutxo block hash in snapshot metadata not "
                             "recognized (hash: %s). The following "
                             "snapshot heights are available: %s."),
                base_blockhash.ToString(), heights_formatted)};
        }

        snapshot_start_block = m_blockman.LookupBlockIndex(base_blockhash);
        if (!snapshot_start_block) {
            return util::Error{strprintf(
                Untranslated("The base block header (%s) must appear in the "
                             "headers chain. Make sure all headers are "
                             "syncing, and call loadtxoutset again."),
                base_blockhash.ToString())};
        }

        if (snapshot_start_block->nStatus.isInvalid()) {
            return util::Error{strprintf(
                Untranslated(
                    "The base block header (%s) is part of an invalid chain"),
                base_blockhash.ToString())};
        }

        if (!m_best_header ||
            m_best_header->GetAncestor(snapshot_start_block->nHeight) !=
                snapshot_start_block) {
            return util::Error{Untranslated(
                "A forked headers-chain with more work than the chain with the "
                "snapshot base block header exists. Please proceed to sync "
                "without AssumeUtxo.")};
        }

        auto mempool{m_active_chainstate->GetMempool()};
        if (mempool && mempool->size() > 0) {
            return util::Error{Untranslated(
                "Can't activate a snapshot when mempool not empty.")};
        }
    }

    int64_t current_coinsdb_cache_size{0};
    int64_t current_coinstip_cache_size{0};

    // Cache percentages to allocate to each chainstate.
    //
    // These particular percentages don't matter so much since they will only be
    // relevant during snapshot activation; caches are rebalanced at the
    // conclusion of this function. We want to give (essentially) all available
    // cache capacity to the snapshot to aid the bulk load later in this
    // function.
    static constexpr double IBD_CACHE_PERC = 0.01;
    static constexpr double SNAPSHOT_CACHE_PERC = 0.99;

    {
        LOCK(::cs_main);
        // Resize the coins caches to ensure we're not exceeding memory limits.
        //
        // Allocate the majority of the cache to the incoming snapshot
        // chainstate, since (optimistically) getting to its tip will be the top
        // priority. We'll need to call `MaybeRebalanceCaches()` once we're done
        // with this function to ensure the right allocation (including the
        // possibility that no snapshot was activated and that we should restore
        // the active chainstate caches to their original size).
        //
        current_coinsdb_cache_size =
            this->ActiveChainstate().m_coinsdb_cache_size_bytes;
        current_coinstip_cache_size =
            this->ActiveChainstate().m_coinstip_cache_size_bytes;

        // Temporarily resize the active coins cache to make room for the
        // newly-created snapshot chain.
        this->ActiveChainstate().ResizeCoinsCaches(
            static_cast<size_t>(current_coinstip_cache_size * IBD_CACHE_PERC),
            static_cast<size_t>(current_coinsdb_cache_size * IBD_CACHE_PERC));
    }

    auto snapshot_chainstate =
        WITH_LOCK(::cs_main, return std::make_unique<Chainstate>(
                                 /* mempool */ nullptr, m_blockman, *this,
                                 base_blockhash));

    {
        LOCK(::cs_main);
        snapshot_chainstate->InitCoinsDB(
            static_cast<size_t>(current_coinsdb_cache_size *
                                SNAPSHOT_CACHE_PERC),
            in_memory, false, "chainstate");
        snapshot_chainstate->InitCoinsCache(static_cast<size_t>(
            current_coinstip_cache_size * SNAPSHOT_CACHE_PERC));
    }

    auto cleanup_bad_snapshot =
        [&](bilingual_str &&reason) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            this->MaybeRebalanceCaches();

            // PopulateAndValidateSnapshot can return (in error) before the
            // leveldb datadir has been created, so only attempt removal if we
            // got that far.
            if (auto snapshot_datadir =
                    node::FindSnapshotChainstateDir(m_options.datadir)) {
                // We have to destruct leveldb::DB in order to release the db
                // lock, otherwise DestroyDB() (in DeleteCoinsDBFromDisk()) will
                // fail. See `leveldb::~DBImpl()`. Destructing the chainstate
                // (and so resetting the coinsviews object) does this.
                snapshot_chainstate.reset();
                bool removed = DeleteCoinsDBFromDisk(*snapshot_datadir,
                                                     /*is_snapshot=*/true);
                if (!removed) {
                    GetNotifications().fatalError(strprintf(
                        "Failed to remove snapshot chainstate dir (%s). "
                        "Manually remove it before restarting.\n",
                        fs::PathToString(*snapshot_datadir)));
                }
            }
            return util::Error{std::move(reason)};
        };

    if (!this->PopulateAndValidateSnapshot(*snapshot_chainstate, coins_file,
                                           metadata)) {
        LOCK(::cs_main);
        return cleanup_bad_snapshot(Untranslated("population failed"));
    }

    // cs_main required for rest of snapshot activation.
    LOCK(::cs_main);

    // Do a final check to ensure that the snapshot chainstate is actually a
    // more work chain than the active chainstate; a user could have loaded a
    // snapshot very late in the IBD process, and we wouldn't want to load a
    // useless chainstate.
    if (!CBlockIndexWorkComparator()(ActiveTip(),
                                     snapshot_chainstate->m_chain.Tip())) {
        return cleanup_bad_snapshot(
            Untranslated("work does not exceed active chainstate"));
    }
    // If not in-memory, persist the base blockhash for use during subsequent
    // initialization.
    if (!in_memory) {
        if (!node::WriteSnapshotBaseBlockhash(*snapshot_chainstate)) {
            return cleanup_bad_snapshot(
                Untranslated("could not write base blockhash"));
        }
    }

    assert(!m_snapshot_chainstate);
    m_snapshot_chainstate.swap(snapshot_chainstate);
    const bool chaintip_loaded = m_snapshot_chainstate->LoadChainTip();
    assert(chaintip_loaded);

    // Transfer possession of the mempool to the snapshot chainstate.
    // Mempool is empty at this point because we're still in IBD.
    Assert(!m_active_chainstate->m_mempool ||
           m_active_chainstate->m_mempool->size() == 0);
    Assert(!m_snapshot_chainstate->m_mempool);
    m_snapshot_chainstate->m_mempool = m_active_chainstate->m_mempool;
    m_active_chainstate->m_mempool = nullptr;
    m_active_chainstate = m_snapshot_chainstate.get();
    m_blockman.m_snapshot_height = this->GetSnapshotBaseHeight();

    LogInfoEvent(BCLog::ALL, "snapshot_activated",
                 "[snapshot] successfully activated snapshot {block_hash}")
        .Field(BCLog::LogField::BlockHash, base_blockhash);
    LogInfoEvent(BCLog::ALL, "snapshot_activated_cache",
                 "[snapshot] ({snapshot_cache_mb:.2f} MB)")
        .Field(BCLog::LogField::SnapshotCacheMB,
               m_snapshot_chainstate->CoinsTip().DynamicMemoryUsage() /
                   (1000 * 1000));

    this->MaybeRebalanceCaches();
    // The manager identity is unchanged, but RPC readers must observe the
    // newly active snapshot before loadtxoutset returns.
    node::PublishChainTipSnapshot(*this, m_active_chainstate->m_mempool);
    return snapshot_start_block;
}

static void FlushSnapshotToDisk(CCoinsViewCache &coins_cache,
                                bool snapshot_loaded) {
    LOG_TIME_MILLIS_WITH_CATEGORY_MSG_ONCE(
        strprintf("%s (%.2f MB)",
                  snapshot_loaded ? "saving snapshot chainstate"
                                  : "flushing coins cache",
                  coins_cache.DynamicMemoryUsage() / (1000 * 1000)),
        BCLog::LogFlags::ALL);

    coins_cache.Flush();
}

struct StopHashingException : public std::exception {
    const char *what() const noexcept override {
        return "ComputeUTXOStats interrupted by shutdown.";
    }
};

static void SnapshotUTXOHashBreakpoint(const util::SignalInterrupt &interrupt) {
    if (interrupt) {
        throw StopHashingException();
    }
}

bool ChainstateManager::PopulateAndValidateSnapshot(
    Chainstate &snapshot_chainstate, AutoFile &coins_file,
    const SnapshotMetadata &metadata) {
    // It's okay to release cs_main before we're done using `coins_cache`
    // because we know that nothing else will be referencing the newly created
    // snapshot_chainstate yet.
    CCoinsViewCache &coins_cache =
        *WITH_LOCK(::cs_main, return &snapshot_chainstate.CoinsTip());

    BlockHash base_blockhash = metadata.m_base_blockhash;

    CBlockIndex *snapshot_start_block = WITH_LOCK(
        ::cs_main, return m_blockman.LookupBlockIndex(base_blockhash));

    if (!snapshot_start_block) {
        // Needed for ComputeUTXOStats to determine the
        // height and to avoid a crash when base_blockhash.IsNull()
        LogInfoEvent(
            BCLog::ALL, "snapshot_start_header_missing",
            "[snapshot] Did not find snapshot start blockheader {block_hash}")
            .Field(BCLog::LogField::BlockHash, base_blockhash);
        return false;
    }

    int base_height = snapshot_start_block->nHeight;
    const auto &maybe_au_data = GetParams().AssumeutxoForHeight(base_height);

    if (!maybe_au_data) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_load_height_unrecognized",
            "[snapshot] assumeutxo height in snapshot metadata not recognized ({height}) - refusing to load snapshot")
            .Field(BCLog::LogField::Height, base_height);
        return false;
    }

    const AssumeutxoData &au_data = *maybe_au_data;

    // This work comparison is a duplicate check with the one performed later in
    // ActivateSnapshot(), but is done so that we avoid doing the long work of
    // staging a snapshot that isn't actually usable.
    if (WITH_LOCK(::cs_main, return !CBlockIndexWorkComparator()(
                                 ActiveTip(), snapshot_start_block))) {
        LogInfoEvent(BCLog::ALL, "snapshot_activation_insufficient_work",
                     "[snapshot] activation failed - work does not exceed "
                     "active chainstate");
        return false;
    }

    const uint64_t coins_count = metadata.m_coins_count;
    uint64_t coins_left = metadata.m_coins_count;

    LogInfoEvent(BCLog::ALL, "snapshot_coins_loading",
                 "[snapshot] loading {count} coins from snapshot {block_hash}")
        .Field(BCLog::LogField::Count, coins_left)
        .Field(BCLog::LogField::BlockHash, base_blockhash);
    int64_t coins_processed{0};

    while (coins_left > 0) {
        try {
            TxId txid;
            coins_file >> txid;
            size_t coins_per_txid{0};
            coins_per_txid = ReadCompactSize(coins_file);

            if (coins_per_txid > coins_left) {
                LogInfoEvent(BCLog::ALL, "snapshot_coins_count_mismatch",
                             "[snapshot] mismatch in coins count in snapshot "
                             "metadata and actual snapshot data");
                return false;
            }

            for (size_t i = 0; i < coins_per_txid; i++) {
                Coin coin;
                COutPoint outpoint{
                    txid, static_cast<uint32_t>(ReadCompactSize(coins_file))};
                coins_file >> coin;
                // Avoid integer wrap-around in coinstats.cpp:ApplyHash
                if (coin.GetHeight() > uint32_t(base_height) ||
                    outpoint.GetN() >=
                        std::numeric_limits<decltype(outpoint.GetN())>::max()) {
                    LogInfoEvent(
                        BCLog::ALL, "snapshot_coin_bounds_invalid",
                        "[snapshot] bad snapshot data after deserializing {count} coins")
                        .Field(BCLog::LogField::Count,
                               coins_count - coins_left);
                    return false;
                }
                if (!MoneyRange(coin.GetTxOut().nValue)) {
                    LogInfoEvent(
                        BCLog::ALL, "snapshot_coin_value_invalid",
                        "[snapshot] bad snapshot data after deserializing {count} coins - bad tx out value")
                        .Field(BCLog::LogField::Count,
                               coins_count - coins_left);
                    return false;
                }
                coins_cache.EmplaceCoinInternalDANGER(std::move(outpoint),
                                                      std::move(coin));

                --coins_left;
                ++coins_processed;

                if (coins_processed % 1000000 == 0) {
                    LogInfoEvent(
                        BCLog::ALL, "snapshot_coins_load_progress",
                        "[snapshot] {snapshot_coins_processed} coins loaded ({snapshot_progress_percent:.2f}%, {snapshot_cache_mb:.2f} MB)")
                        .Field(BCLog::LogField::SnapshotCoinsProcessed,
                               coins_processed)
                        .Field(BCLog::LogField::SnapshotProgressPercent,
                               static_cast<float>(coins_processed) * 100 /
                                   static_cast<float>(coins_count))
                        .Field(BCLog::LogField::SnapshotCacheMB,
                               coins_cache.DynamicMemoryUsage() /
                                   (1000 * 1000));
                }

                // Batch write and flush (if we need to) every so often.
                //
                // If our average Coin size is roughly 41 bytes, checking every
                // 120,000 coins means <5MB of memory imprecision.
                if (coins_processed % 120000 == 0) {
                    if (m_interrupt) {
                        return false;
                    }

                    const auto snapshot_cache_state = WITH_LOCK(
                        ::cs_main,
                        return snapshot_chainstate.GetCoinsCacheSizeState());

                    if (snapshot_cache_state >= CoinsCacheSizeState::CRITICAL) {
                        // This is a hack - we don't know what the actual best
                        // block is, but that doesn't matter for the purposes of
                        // flushing the cache here. We'll set this to its
                        // correct value (`base_blockhash`) below after the
                        // coins are loaded.
                        coins_cache.SetBestBlock(BlockHash{GetRandHash()});

                        // No need to acquire cs_main since this chainstate
                        // isn't being used yet.
                        FlushSnapshotToDisk(coins_cache,
                                            /*snapshot_loaded=*/false);
                    }
                }
            }
        } catch (const std::ios_base::failure &) {
            LogInfoEvent(
                BCLog::ALL, "snapshot_coin_stream_invalid",
                "[snapshot] bad snapshot format or truncated snapshot after deserializing {snapshot_coins_processed} coins")
                .Field(BCLog::LogField::SnapshotCoinsProcessed,
                       coins_processed);
            return false;
        }
    }

    // Important that we set this. This and the coins_cache accesses above are
    // sort of a layer violation, but either we reach into the innards of
    // CCoinsViewCache here or we have to invert some of the Chainstate to
    // embed them in a snapshot-activation-specific CCoinsViewCache bulk load
    // method.
    coins_cache.SetBestBlock(base_blockhash);

    bool out_of_coins{false};
    try {
        std::byte left_over_byte;
        coins_file >> left_over_byte;
    } catch (const std::ios_base::failure &) {
        // We expect an exception since we should be out of coins.
        out_of_coins = true;
    }
    if (!out_of_coins) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_coins_remaining",
            "[snapshot] bad snapshot - coins left over after deserializing {count} coins")
            .Field(BCLog::LogField::Count, coins_count);
        return false;
    }

    LogInfoEvent(
        BCLog::ALL, "snapshot_coins_loaded",
        "[snapshot] loaded {count} ({snapshot_cache_mb:.2f} MB) coins from snapshot {block_hash}")
        .Field(BCLog::LogField::Count, coins_count)
        .Field(BCLog::LogField::SnapshotCacheMB,
               coins_cache.DynamicMemoryUsage() / (1000 * 1000))
        .Field(BCLog::LogField::BlockHash, base_blockhash);

    // No need to acquire cs_main since this chainstate isn't being used yet.
    FlushSnapshotToDisk(coins_cache, /*snapshot_loaded=*/true);

    assert(coins_cache.GetBestBlock() == base_blockhash);

    // As above, okay to immediately release cs_main here since no other context
    // knows about the snapshot_chainstate.
    CCoinsViewDB *snapshot_coinsdb =
        WITH_LOCK(::cs_main, return &snapshot_chainstate.CoinsDB());

    std::optional<CCoinsStats> maybe_stats;

    try {
        maybe_stats = ComputeUTXOStats(
            CoinStatsHashType::HASH_SERIALIZED, snapshot_coinsdb, m_blockman,
            [&interrupt = m_interrupt] {
                SnapshotUTXOHashBreakpoint(interrupt);
            });
    } catch (StopHashingException const &) {
        return false;
    }
    if (!maybe_stats.has_value()) {
        LogInfoEvent(BCLog::ALL, "snapshot_coins_stats_failed",
                     "[snapshot] failed to generate coins stats");
        return false;
    }

    // Assert that the deserialized chainstate contents match the expected
    // assumeutxo value.
    if (AssumeutxoHash{maybe_stats->hashSerialized} !=
        au_data.hash_serialized) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_content_hash_mismatch",
            "[snapshot] bad snapshot content hash: expected {expected_snapshot_hash}, got {snapshot_hash}")
            .Field(BCLog::LogField::ExpectedSnapshotHash,
                   uint256{Span{au_data.hash_serialized.data(),
                                au_data.hash_serialized.size()}})
            .Field(BCLog::LogField::SnapshotHash, maybe_stats->hashSerialized);
        return false;
    }

    // The verified legacy coin set alone is not enough to execute a native
    // successor: native SMT leaves also bind creation MTP, and monetary history
    // is not carried in the legacy snapshot file. Authenticate both against the
    // already trusted anchor header before publishing any native state.
    if (!au_data.native_monetary_state) {
        LogPrintf("[snapshot] missing native monetary anchor state\n");
        return false;
    }
    std::vector<lotus::v2::Coin> native_coins;
    native_coins.reserve(maybe_stats->coins_count);
    lotus::v2::UtxoSet verified_native;
    std::unique_ptr<CCoinsViewCursor> cursor{snapshot_coinsdb->Cursor()};
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin)) {
            LogPrintf("[snapshot] unable to read native anchor coins\n");
            return false;
        }
        const CBlockIndex *creation =
            snapshot_start_block->GetAncestor(coin.GetHeight());
        if (!creation) {
            LogPrintf("[snapshot] missing creation header for native coin\n");
            return false;
        }
        lotus::v2::Outpoint native_outpoint{};
        std::copy_n(outpoint.GetTxId().begin(), 32, native_outpoint.tx_id.begin());
        native_outpoint.index = outpoint.GetN();
        lotus::v2::Coin native_coin{
            native_outpoint, coin.GetTxOut().ToV2Output(), coin.GetHeight(),
            creation->pprev ? uint64_t(creation->pprev->GetMedianTimePast()) : 0,
            coin.IsCoinBase(), coin.GetFeePerOutput(), coin.GetExpirationHeight()};
        if (!verified_native.Insert(native_coin)) {
            LogPrintf("[snapshot] invalid native anchor coin\n");
            return false;
        }
        native_coins.push_back(std::move(native_coin));
        cursor->Next();
    }
    const auto native_root = lotus::v2::StateRoot(
        GetActiveV2ChainId(), base_height, verified_native.Root(),
        *au_data.native_monetary_state);
    if (native_root != snapshot_start_block->GetBlockHeader().ToV2Header().state_root) {
        LogPrintf("[snapshot] native anchor state does not match header\n");
        return false;
    }
    if (!ImportV2BlockStateCoinsAndMonetary(
            base_blockhash, native_coins, *au_data.native_monetary_state)) {
        LogPrintf("[snapshot] failed to persist native anchor state\n");
        return false;
    }

    snapshot_chainstate.m_chain.SetTip(*snapshot_start_block);

    // The remainder of this function requires modifying data protected by
    // cs_main.
    LOCK(::cs_main);

    // Fake various pieces of CBlockIndex state:
    CBlockIndex *index = nullptr;

    // Don't make any modifications to the genesis block since it shouldn't be
    // necessary, and since the genesis block doesn't have normal flags like
    // BLOCK_VALID_SCRIPTS set.
    constexpr int AFTER_GENESIS_START{1};

    for (int i = AFTER_GENESIS_START; i <= snapshot_chainstate.m_chain.Height();
         ++i) {
        index = snapshot_chainstate.m_chain[i];

        m_blockman.m_dirty_blockindex.insert(index);
        // Changes to the block index will be flushed to disk after this call
        // returns in `ActivateSnapshot()`, when `MaybeRebalanceCaches()` is
        // called, since we've added a snapshot chainstate and therefore will
        // have to downsize the IBD chainstate, which will result in a call to
        // `FlushStateToDisk(ALWAYS)`.
    }

    assert(index);
    assert(index == snapshot_start_block);
    index->m_chain_tx_count = au_data.m_chain_tx_count;
    snapshot_chainstate.setBlockIndexCandidates.insert(snapshot_start_block);

    LogInfoEvent(BCLog::ALL, "snapshot_cache_validated",
                 "[snapshot] validated snapshot ({snapshot_cache_mb:.2f} MB)")
        .Field(BCLog::LogField::SnapshotCacheMB,
               coins_cache.DynamicMemoryUsage() / (1000 * 1000));
    return true;
}

// Currently, this function holds cs_main for its duration, which could be for
// multiple minutes due to the ComputeUTXOStats call. This hold is necessary
// because we need to avoid advancing the background validation chainstate
// farther than the snapshot base block - and this function is also invoked
// from within ConnectTip, i.e. from within ActivateBestChain, so cs_main is
// held anyway.
//
// Eventually (TODO), we could somehow separate this function's runtime from
// maintenance of the active chain, but that will either require
//
//  (i) setting `m_disabled` immediately and ensuring all chainstate accesses go
//      through IsUsable() checks, or
//
//  (ii) giving each chainstate its own lock instead of using cs_main for
//  everything.
SnapshotCompletionResult ChainstateManager::MaybeCompleteSnapshotValidation() {
    AssertLockHeld(cs_main);
    if (m_ibd_chainstate.get() == &this->ActiveChainstate() ||
        !this->IsUsable(m_snapshot_chainstate.get()) ||
        !this->IsUsable(m_ibd_chainstate.get()) ||
        !m_ibd_chainstate->m_chain.Tip()) {
        // Nothing to do - this function only applies to the background
        // validation chainstate.
        return SnapshotCompletionResult::SKIPPED;
    }
    const int snapshot_tip_height = this->ActiveHeight();
    const int snapshot_base_height = *Assert(this->GetSnapshotBaseHeight());
    const CBlockIndex &index_new = *Assert(m_ibd_chainstate->m_chain.Tip());

    if (index_new.nHeight < snapshot_base_height) {
        // Background IBD not complete yet.
        return SnapshotCompletionResult::SKIPPED;
    }

    assert(SnapshotBlockhash());
    BlockHash snapshot_blockhash = *Assert(SnapshotBlockhash());

    auto handle_invalid_snapshot = [&]() EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        bilingual_str user_error = strprintf(
            _("%s failed to validate the -assumeutxo snapshot state. "
              "This indicates a hardware problem, or a bug in the software, or "
              "a bad software modification that allowed an invalid snapshot to "
              "be loaded. As a result of this, the node will shut down and "
              "stop using any state that was built on the snapshot, resetting "
              "the chain height from %d to %d. On the next restart, the node "
              "will resume syncing from %d without using any snapshot data. "
              "Please report this incident to %s, including how you obtained "
              "the snapshot. The invalid snapshot chainstate will be left on "
              "disk in case it is helpful in diagnosing the issue that caused "
              "this error."),
            PACKAGE_NAME, snapshot_tip_height, snapshot_base_height,
            snapshot_base_height, PACKAGE_BUGREPORT);

        LogPrintf("[snapshot] !!! %s\n", user_error.original);
        LogInfoEvent(BCLog::ALL, "snapshot_validation_reverting",
                     "[snapshot] deleting snapshot, reverting to validated "
                     "chain, and stopping node");

        m_active_chainstate = m_ibd_chainstate.get();
        InvalidateChainstateRpcSnapshot(*this);
        m_snapshot_chainstate->m_disabled = true;
        assert(!this->IsUsable(m_snapshot_chainstate.get()));
        assert(this->IsUsable(m_ibd_chainstate.get()));

        auto rename_result = m_snapshot_chainstate->InvalidateCoinsDBOnDisk();
        if (!rename_result) {
            user_error = strprintf(Untranslated("%s\n%s"), user_error,
                                   util::ErrorString(rename_result));
        }

        GetNotifications().fatalError(user_error.original, user_error);
    };

    if (index_new.GetBlockHash() != snapshot_blockhash) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_base_block_mismatch",
            "[snapshot] supposed base block {block_index_description} does not match the snapshot base block {expected_block_hash} (height {height}). Snapshot is not valid.")
            .Field(BCLog::LogField::BlockIndexDescription, index_new.ToString())
            .Field(BCLog::LogField::ExpectedBlockHash, snapshot_blockhash)
            .Field(BCLog::LogField::Height, snapshot_base_height)
            .Field(BCLog::LogField::BlockHash, index_new.GetBlockHash());
        handle_invalid_snapshot();
        return SnapshotCompletionResult::BASE_BLOCKHASH_MISMATCH;
    }

    assert(index_new.nHeight == snapshot_base_height);

    int curr_height = m_ibd_chainstate->m_chain.Height();

    assert(snapshot_base_height == curr_height);
    assert(snapshot_base_height == index_new.nHeight);
    assert(this->IsUsable(m_snapshot_chainstate.get()));
    assert(this->GetAll().size() == 2);

    CCoinsViewDB &ibd_coins_db = m_ibd_chainstate->CoinsDB();
    m_ibd_chainstate->ForceFlushStateToDisk();

    const auto &maybe_au_data =
        this->GetParams().AssumeutxoForHeight(curr_height);
    if (!maybe_au_data) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_validation_height_unrecognized",
            "[snapshot] assumeutxo data not found for height ({height}) - refusing to validate snapshot")
            .Field(BCLog::LogField::Height, curr_height);
        handle_invalid_snapshot();
        return SnapshotCompletionResult::MISSING_CHAINPARAMS;
    }

    const AssumeutxoData &au_data = *maybe_au_data;
    std::optional<CCoinsStats> maybe_ibd_stats;
    LogInfoEvent(BCLog::ALL, "snapshot_background_stats_started",
                 "[snapshot] computing UTXO stats for background chainstate to "
                 "validate snapshot - this could take a few minutes");
    try {
        maybe_ibd_stats =
            ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, &ibd_coins_db,
                             m_blockman, [&interrupt = m_interrupt] {
                                 SnapshotUTXOHashBreakpoint(interrupt);
                             });
    } catch (StopHashingException const &) {
        return SnapshotCompletionResult::STATS_FAILED;
    }

    if (!maybe_ibd_stats) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_validation_stats_failed",
            "[snapshot] failed to generate stats for validation coins db");
        // While this isn't a problem with the snapshot per se, this condition
        // prevents us from validating the snapshot, so we should shut down and
        // let the user handle the issue manually.
        handle_invalid_snapshot();
        return SnapshotCompletionResult::STATS_FAILED;
    }
    const auto &ibd_stats = *maybe_ibd_stats;

    // Compare the background validation chainstate's UTXO set hash against the
    // hard-coded assumeutxo hash we expect.
    //
    // TODO: For belt-and-suspenders, we could cache the UTXO set
    // hash for the snapshot when it's loaded in its chainstate's leveldb. We
    // could then reference that here for an additional check.
    if (AssumeutxoHash{ibd_stats.hashSerialized} != au_data.hash_serialized) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_validation_hash_mismatch",
            "[snapshot] hash mismatch: actual={snapshot_hash}, expected={expected_snapshot_hash}")
            .Field(BCLog::LogField::SnapshotHash, ibd_stats.hashSerialized)
            .Field(BCLog::LogField::ExpectedSnapshotHash,
                   uint256{Span{au_data.hash_serialized.data(),
                                au_data.hash_serialized.size()}});
        handle_invalid_snapshot();
        return SnapshotCompletionResult::HASH_MISMATCH;
    }

    LogInfoEvent(
        BCLog::ALL, "snapshot_fully_validated",
        "[snapshot] snapshot beginning at {block_hash} has been fully validated")
        .Field(BCLog::LogField::BlockHash, snapshot_blockhash);

    m_ibd_chainstate->m_disabled = true;
    this->MaybeRebalanceCaches();

    return SnapshotCompletionResult::SUCCESS;
}

Chainstate &ChainstateManager::ActiveChainstate() const {
    LOCK(::cs_main);
    assert(m_active_chainstate);
    return *m_active_chainstate;
}

const CBlockIndex *ChainstateManager::GetAvalancheFinalizedTip() const {
    auto &active_chainstate = ActiveChainstate();
    LOCK(active_chainstate.cs_avalancheFinalizedBlockIndex);
    return active_chainstate.m_avalancheFinalizedBlockIndex;
}

bool ChainstateManager::IsSnapshotActive() const {
    LOCK(::cs_main);
    return m_snapshot_chainstate &&
           m_active_chainstate == m_snapshot_chainstate.get();
}
void ChainstateManager::MaybeRebalanceCaches() {
    AssertLockHeld(::cs_main);
    bool ibd_usable = this->IsUsable(m_ibd_chainstate.get());
    bool snapshot_usable = this->IsUsable(m_snapshot_chainstate.get());
    assert(ibd_usable || snapshot_usable);

    if (ibd_usable && !snapshot_usable) {
        // Allocate everything to the IBD chainstate. This will always happen
        // when we are not using a snapshot.
        m_ibd_chainstate->ResizeCoinsCaches(m_total_coinstip_cache,
                                            m_total_coinsdb_cache);
    } else if (snapshot_usable && !ibd_usable) {
        // If background validation has completed and snapshot is our active
        // chain...
        LogInfoEvent(
            BCLog::ALL, "snapshot_cache_allocated",
            "[snapshot] allocating all cache to the snapshot chainstate");
        // Allocate everything to the snapshot chainstate.
        m_snapshot_chainstate->ResizeCoinsCaches(m_total_coinstip_cache,
                                                 m_total_coinsdb_cache);
    } else if (ibd_usable && snapshot_usable) {
        // If both chainstates exist, determine who needs more cache based on
        // IBD status.
        //
        // Note: shrink caches first so that we don't inadvertently overwhelm
        // available memory.
        if (IsInitialBlockDownload()) {
            m_ibd_chainstate->ResizeCoinsCaches(m_total_coinstip_cache * 0.05,
                                                m_total_coinsdb_cache * 0.05);
            m_snapshot_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.95, m_total_coinsdb_cache * 0.95);
        } else {
            m_snapshot_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.05, m_total_coinsdb_cache * 0.05);
            m_ibd_chainstate->ResizeCoinsCaches(m_total_coinstip_cache * 0.95,
                                                m_total_coinsdb_cache * 0.95);
        }
    }
}

void ChainstateManager::ResetChainstates() {
    InvalidateChainstateRpcSnapshot(*this);
    m_ibd_chainstate.reset();
    m_snapshot_chainstate.reset();
    m_active_chainstate = nullptr;
}

/**
 * Apply default chain params to nullopt members.
 * This helps to avoid coding errors around the accidental use of the compare
 * operators that accept nullopt, thus ignoring the intended default value.
 */
static ChainstateManager::Options &&Flatten(ChainstateManager::Options &&opts) {
    if (!opts.check_block_index.has_value()) {
        opts.check_block_index =
            opts.config.GetChainParams().DefaultConsistencyChecks();
    }

    if (!opts.minimum_chain_work.has_value()) {
        opts.minimum_chain_work = UintToArith256(
            opts.config.GetChainParams().GetConsensus().nMinimumChainWork);
    }
    if (!opts.assumed_valid_block.has_value()) {
        opts.assumed_valid_block =
            opts.config.GetChainParams().GetConsensus().defaultAssumeValid;
    }
    Assert(opts.adjusted_time_callback);
    return std::move(opts);
}

ChainstateManager::ChainstateManager(
    const util::SignalInterrupt &interrupt, Options options,
    node::BlockManager::Options blockman_options)
    : m_script_check_queue{
          /*batch_size=*/128,
          std::clamp(options.worker_threads_num, 0, MAX_SCRIPTCHECK_THREADS)},
      m_interrupt{interrupt}, m_options{Flatten(std::move(options))},
      m_blockman{interrupt, std::move(blockman_options)},
      m_validation_cache{m_options.script_execution_cache_bytes,
                         m_options.signature_cache_bytes},
      m_block_prefetcher{std::make_unique<node::BlockPrefetcher>(
          node::BlockPrefetcher::Options{
              .threads = size_t(std::clamp(m_options.block_prefetch_threads, 0,
                                           node::MAX_BLOCK_PREFETCH_THREADS)),
          })} {}

void ChainstateManager::PrefetchBlockCoins(
    const std::shared_ptr<const CBlock> &block) {
    if (!m_block_prefetcher->Enabled() || !block ||
        block->vtx.size() < m_block_prefetcher->GetOptions().min_txs) {
        return;
    }
    LOCK(::cs_main);
    PrefetchBlockCoinsLocked(block);
}

void ChainstateManager::PrefetchBlockCoinsLocked(
    const std::shared_ptr<const CBlock> &block) {
    AssertLockHeld(::cs_main);
    if (!m_block_prefetcher->Enabled() || !block ||
        block->vtx.size() < m_block_prefetcher->GetOptions().min_txs) {
        return;
    }
    // Reading coins costs disk I/O: only for blocks whose header has real
    // proof of work (which also makes a junk block expensive to send).
    if (!CheckProofOfWork(block->GetHash(), block->nBits, GetConsensus())) {
        return;
    }
    Chainstate *chainstate{m_active_chainstate};
    if (!chainstate || !chainstate->HasCoinsViews()) {
        return;
    }
    m_block_prefetcher->Start(block,
                              chainstate->CoinsDB().GetBackgroundHandle());
}

bool ChainstateManager::DetectSnapshotChainstate(CTxMemPool *mempool) {
    assert(!m_snapshot_chainstate);
    std::optional<fs::path> path =
        node::FindSnapshotChainstateDir(m_options.datadir);
    if (!path) {
        return false;
    }
    std::optional<BlockHash> base_blockhash =
        node::ReadSnapshotBaseBlockhash(*path);
    if (!base_blockhash) {
        return false;
    }
    LogInfoEvent(
        BCLog::ALL, "snapshot_chainstate_detected",
        "[snapshot] detected active snapshot chainstate ({directory}) - loading")
        .Field(BCLog::LogField::Directory, fs::PathToString(*path));

    this->ActivateExistingSnapshot(*base_blockhash);
    return true;
}

Chainstate &
ChainstateManager::ActivateExistingSnapshot(BlockHash base_blockhash) {
    assert(!m_snapshot_chainstate);
    m_snapshot_chainstate = std::make_unique<Chainstate>(nullptr, m_blockman,
                                                         *this, base_blockhash);
    LogInfoEvent(
        BCLog::ALL, "snapshot_active_chainstate_switching",
        "[snapshot] switching active chainstate to {chainstate_description}")
        .Field(BCLog::LogField::ChainstateDescription,
               m_snapshot_chainstate->ToString());

    // Mempool is empty at this point because we're still in IBD.
    Assert(m_active_chainstate->m_mempool->size() == 0);
    Assert(!m_snapshot_chainstate->m_mempool);
    m_snapshot_chainstate->m_mempool = m_active_chainstate->m_mempool;
    m_active_chainstate->m_mempool = nullptr;
    m_active_chainstate = m_snapshot_chainstate.get();
    InvalidateChainstateRpcSnapshot(*this);
    return *m_snapshot_chainstate;
}

static fs::path GetSnapshotCoinsDBPath(Chainstate &cs)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    AssertLockHeld(::cs_main);
    // Should never be called on a non-snapshot chainstate.
    assert(cs.m_from_snapshot_blockhash);
    auto storage_path_maybe = cs.CoinsDB().StoragePath();
    // Should never be called with a non-existent storage path.
    assert(storage_path_maybe);
    return *storage_path_maybe;
}

util::Result<void> Chainstate::InvalidateCoinsDBOnDisk() {
    fs::path snapshot_datadir = GetSnapshotCoinsDBPath(*this);

    // Coins views no longer usable.
    m_coins_views.reset();

    auto invalid_path = snapshot_datadir + "_INVALID";
    std::string dbpath = fs::PathToString(snapshot_datadir);
    std::string target = fs::PathToString(invalid_path);
    LogInfoEvent(
        BCLog::ALL, "snapshot_invalid_directory_renaming",
        "[snapshot] renaming snapshot datadir {source_path} to {destination_path}")
        .Field(BCLog::LogField::SourcePath, dbpath)
        .Field(BCLog::LogField::DestinationPath, target);

    // The invalid snapshot datadir is simply moved and not deleted because we
    // may want to do forensics later during issue investigation. The user is
    // instructed accordingly in MaybeCompleteSnapshotValidation().
    try {
        fs::rename(snapshot_datadir, invalid_path);
    } catch (const fs::filesystem_error &e) {
        auto src_str = fs::PathToString(snapshot_datadir);
        auto dest_str = fs::PathToString(invalid_path);

        LogInfoEvent(
            BCLog::ALL, "snapshot_invalid_directory_rename_failed",
            "{source_function}: error renaming file '{source_path}' -> '{destination_path}': {error}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::SourcePath, src_str)
            .Field(BCLog::LogField::DestinationPath, dest_str)
            .Field(BCLog::LogField::Error, e.what());
        return util::Error{strprintf(_("Rename of '%s' -> '%s' failed. "
                                       "You should resolve this by manually "
                                       "moving or deleting the invalid "
                                       "snapshot directory %s, otherwise you "
                                       "will encounter the same error again "
                                       "on the next startup."),
                                     src_str, dest_str, src_str)};
    }
    return {};
}

bool ChainstateManager::DeleteSnapshotChainstate() {
    AssertLockHeld(::cs_main);
    Assert(m_snapshot_chainstate);
    Assert(m_ibd_chainstate);

    fs::path snapshot_datadir =
        Assert(node::FindSnapshotChainstateDir(m_options.datadir)).value();
    if (!DeleteCoinsDBFromDisk(snapshot_datadir, /*is_snapshot=*/true)) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_directory_removal_required",
            "Deletion of {directory} failed. Please remove it manually to continue reindexing.")
            .Field(BCLog::LogField::Directory,
                   fs::PathToString(snapshot_datadir));
        return false;
    }
    m_active_chainstate = m_ibd_chainstate.get();
    m_active_chainstate->m_mempool = m_snapshot_chainstate->m_mempool;
    m_snapshot_chainstate.reset();
    node::PublishChainTipSnapshot(*this, m_active_chainstate->m_mempool);
    return true;
}

ChainstateRole Chainstate::GetRole() const {
    if (m_chainman.GetAll().size() <= 1) {
        return ChainstateRole::NORMAL;
    }
    return (this != &m_chainman.ActiveChainstate())
               ? ChainstateRole::BACKGROUND
               : ChainstateRole::ASSUMEDVALID;
}
const CBlockIndex *ChainstateManager::GetSnapshotBaseBlock() const {
    return m_active_chainstate ? m_active_chainstate->SnapshotBase() : nullptr;
}

std::optional<int> ChainstateManager::GetSnapshotBaseHeight() const {
    const CBlockIndex *base = this->GetSnapshotBaseBlock();
    return base ? std::make_optional(base->nHeight) : std::nullopt;
}

void ChainstateManager::RecalculateBestHeader() {
    AssertLockHeld(cs_main);
    const CBlockIndex *prev_best_header = m_best_header;
    m_best_header = ActiveChain().Tip();
    for (auto &entry : m_blockman.m_block_index) {
        if (!(entry.second.nStatus.isInvalid()) &&
            m_best_header->nChainWork < entry.second.nChainWork) {
            m_best_header = &entry.second;
        }
    }
    if (m_best_header != prev_best_header && m_active_chainstate) {
        node::PublishChainTipSnapshot(*this, m_active_chainstate->GetMempool());
    }
}

bool ChainstateManager::ValidatedSnapshotCleanup() {
    AssertLockHeld(::cs_main);
    auto get_storage_path = [](auto &chainstate) EXCLUSIVE_LOCKS_REQUIRED(
                                ::cs_main) -> std::optional<fs::path> {
        if (!(chainstate && chainstate->HasCoinsViews())) {
            return {};
        }
        return chainstate->CoinsDB().StoragePath();
    };
    std::optional<fs::path> ibd_chainstate_path_maybe =
        get_storage_path(m_ibd_chainstate);
    std::optional<fs::path> snapshot_chainstate_path_maybe =
        get_storage_path(m_snapshot_chainstate);

    if (!this->IsSnapshotValidated()) {
        // No need to clean up.
        return false;
    }
    // If either path doesn't exist, that means at least one of the chainstates
    // is in-memory, in which case we can't do on-disk cleanup. You'd better be
    // in a unittest!
    if (!ibd_chainstate_path_maybe || !snapshot_chainstate_path_maybe) {
        LogInfoEvent(BCLog::ALL, "snapshot_cleanup_in_memory",
                     "[snapshot] snapshot chainstate cleanup cannot happen "
                     "with in-memory chainstates. You are testing, right?");
        return false;
    }

    const auto &snapshot_chainstate_path = *snapshot_chainstate_path_maybe;
    const auto &ibd_chainstate_path = *ibd_chainstate_path_maybe;

    // Since we're going to be moving around the underlying leveldb filesystem
    // content for each chainstate, make sure that the chainstates (and their
    // constituent CoinsViews members) have been destructed first.
    //
    // The caller of this method will be responsible for reinitializing
    // chainstates if they want to continue operation.
    this->ResetChainstates();

    // No chainstates should be considered usable.
    assert(this->GetAll().size() == 0);

    LogInfoEvent(
        BCLog::ALL, "snapshot_background_directory_deleting",
        "[snapshot] deleting background chainstate directory (now unnecessary) ({directory})")
        .Field(BCLog::LogField::Directory,
               fs::PathToString(ibd_chainstate_path));

    fs::path tmp_old{ibd_chainstate_path + "_todelete"};

    auto rename_failed_abort = [this](fs::path p_old, fs::path p_new,
                                      const fs::filesystem_error &err) {
        LogInfoEvent(
            BCLog::ALL, "snapshot_background_directory_rename_failed",
            "Error renaming path ({source_path}) -> ({destination_path}): {error}")
            .Field(BCLog::LogField::SourcePath, fs::PathToString(p_old))
            .Field(BCLog::LogField::DestinationPath, fs::PathToString(p_new))
            .Field(BCLog::LogField::Error, err.what());
        GetNotifications().fatalError(strprintf(
            "Rename of '%s' -> '%s' failed. "
            "Cannot clean up the background chainstate leveldb directory.",
            fs::PathToString(p_old), fs::PathToString(p_new)));
    };

    try {
        fs::rename(ibd_chainstate_path, tmp_old);
    } catch (const fs::filesystem_error &e) {
        rename_failed_abort(ibd_chainstate_path, tmp_old, e);
        throw;
    }

    LogInfoEvent(
        BCLog::ALL, "snapshot_directory_promoting",
        "[snapshot] moving snapshot chainstate ({source_path}) to default chainstate directory ({destination_path})")
        .Field(BCLog::LogField::SourcePath,
               fs::PathToString(snapshot_chainstate_path))
        .Field(BCLog::LogField::DestinationPath,
               fs::PathToString(ibd_chainstate_path));

    try {
        fs::rename(snapshot_chainstate_path, ibd_chainstate_path);
    } catch (const fs::filesystem_error &e) {
        rename_failed_abort(snapshot_chainstate_path, ibd_chainstate_path, e);
        throw;
    }

    if (!DeleteCoinsDBFromDisk(tmp_old, /*is_snapshot=*/false)) {
        // No need to FatalError because once the unneeded bg chainstate data is
        // moved, it will not interfere with subsequent initialization.
        LogInfoEvent(
            BCLog::ALL, "snapshot_background_directory_removal_required",
            "Deletion of {directory} failed. Please remove it manually, as the directory is now unnecessary.")
            .Field(BCLog::LogField::Directory, fs::PathToString(tmp_old));
    } else {
        LogInfoEvent(
            BCLog::ALL, "snapshot_background_directory_deleted",
            "[snapshot] deleted background chainstate directory ({directory})")
            .Field(BCLog::LogField::Directory,
                   fs::PathToString(ibd_chainstate_path));
    }
    return true;
}

Chainstate &ChainstateManager::GetChainstateForIndexing() {
    // We can't always return `m_ibd_chainstate` because after background
    // validation has completed,
    // `m_snapshot_chainstate == m_active_chainstate`, but it can be indexed.
    return (this->GetAll().size() > 1) ? *m_ibd_chainstate
                                       : *m_active_chainstate;
}

std::pair<int, int>
ChainstateManager::GetPruneRange(const Chainstate &chainstate,
                                 int last_height_can_prune) {
    if (chainstate.m_chain.Height() <= 0) {
        return {0, 0};
    }
    int prune_start{0};

    if (this->GetAll().size() > 1 &&
        m_snapshot_chainstate.get() == &chainstate) {
        // Leave the blocks in the background IBD chain alone if we're pruning
        // the snapshot chain.
        prune_start = *Assert(GetSnapshotBaseHeight()) + 1;
    }

    int max_prune = std::max<int>(0, chainstate.m_chain.Height() -
                                         static_cast<int>(MIN_BLOCKS_TO_KEEP));

    // last block to prune is the lesser of (caller-specified height,
    // MIN_BLOCKS_TO_KEEP from the tip)
    //
    // While you might be tempted to prune the background chainstate more
    // aggressively (i.e. fewer MIN_BLOCKS_TO_KEEP), this won't work with index
    // building - specifically blockfilterindex requires undo data, and if
    // we don't maintain this trailing window, we hit indexing failures.
    int prune_end = std::min(last_height_can_prune, max_prune);

    return {prune_start, prune_end};
}
