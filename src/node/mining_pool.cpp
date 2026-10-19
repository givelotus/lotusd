// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mining_pool.h>

#include <arith_uint256.h>
#include <avalanche/avalanche.h>
#include <avalanche/processor.h>
#include <avalanche/treasury.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key_io.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/header.h>
#include <minerfund.h>
#include <node/context.h>
#include <node/miner.h>
#include <node/snapshot.h>
#include <policy/block/stakingrewards.h>
#include <policy/block/treasury.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <streams.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace lotus::v2::node {

UniValue ShareSubmissionResult::ToUniValue() const {
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("accepted", accepted);
    obj.pushKV("reason", reason.empty() ? (accepted ? "accepted" : "rejected")
                                        : reason);
    obj.pushKV("block_found", block_found);
    if (block_found && !block_hash.IsNull()) {
        obj.pushKV("block_hash", block_hash.GetHex());
    } else {
        obj.pushKV("block_hash", NullUniValue);
    }
    if (!share_hash.IsNull()) {
        obj.pushKV("share_hash", share_hash.GetHex());
    }
    if (!share_target.IsNull()) {
        obj.pushKV("share_target", share_target.GetHex());
    }
    obj.pushKV("accepted_shares", accepted_shares);
    obj.pushKV("rejected_shares", rejected_shares);
    obj.pushKV("newsletter_credits_usd_cents", newsletter_credits_usd_cents);
    obj.pushKV("subscription_unlocked", subscription_unlocked);
    return obj;
}

MiningPoolManager::MiningPoolManager() = default;

void MiningPoolManager::Configure(const ArgsManager &args,
                                  const Config &config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_enabled = args.GetBoolArg("-miningpool", DEFAULT_MINING_POOL_ENABLED);
    m_pool_address_arg = args.GetArg("-pooladdress", "");
    const int64_t window = args.GetIntArg(
        "-poolpplnswindow", static_cast<int64_t>(DEFAULT_POOL_PPLNS_WINDOW));
    m_pplns_window_size =
        static_cast<size_t>(std::max<int64_t>(1, window));
    const int64_t spacing = args.GetIntArg(
        "-pooltargetspacing", DEFAULT_POOL_TARGET_SPACING_SEC);
    m_target_spacing_sec = std::max<int64_t>(1, spacing);
    m_fallback_payout_script.clear();
    m_configured = true;
}

void MiningPoolManager::Reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_next_job_id = 1;
    m_next_nonce_prefix = 1;
    for (auto &job : m_jobs) {
        job = PoolJob{};
    }
    m_workers.clear();
    m_pplns_window.clear();
    m_total_accepted_shares = 0;
    m_total_rejected_shares = 0;
    m_blocks_found = 0;
    m_total_work = 0.0;
}

bool MiningPoolManager::IsEnabled(const ArgsManager *args) const {
    if (args && args->IsArgSet("-miningpool")) {
        return args->GetBoolArg("-miningpool", DEFAULT_MINING_POOL_ENABLED);
    }
    if (gArgs.IsArgSet("-miningpool")) {
        return gArgs.GetBoolArg("-miningpool", DEFAULT_MINING_POOL_ENABLED);
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_enabled;
}

void MiningPoolManager::SetTargetSpacingSec(int64_t spacing_sec) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_target_spacing_sec = std::max<int64_t>(1, spacing_sec);
}

void MiningPoolManager::SetPPLNSWindowSize(size_t window_size) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pplns_window_size = std::max<size_t>(1, window_size);
    while (m_pplns_window.size() > m_pplns_window_size) {
        m_pplns_window.pop_front();
    }
}

void MiningPoolManager::SetWorkerShareTarget(const std::string &worker_id,
                                             const uint256 &target,
                                             const Config &config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    PoolWorker &worker = GetOrCreateWorkerLocked(worker_id, config);
    worker.share_target = target;
}

CScript MiningPoolManager::GetFallbackPayoutScriptLocked(
    const Config &config) const {
    if (!m_fallback_payout_script.empty()) {
        return m_fallback_payout_script;
    }
    std::string addr = m_pool_address_arg;
    if (addr.empty() && gArgs.IsArgSet("-pooladdress")) {
        addr = gArgs.GetArg("-pooladdress", "");
    }
    if (!addr.empty()) {
        CTxDestination dest =
            DecodeDestination(addr, config.GetChainParams());
        if (IsValidDestination(dest)) {
            return GetScriptForDestination(dest);
        }
        if (addr.size() >= 2 && (addr.size() % 2 == 0) && IsHex(addr)) {
            const auto raw = ParseHex(addr);
            return CScript(raw.begin(), raw.end());
        }
    }
    throw std::runtime_error("Native pool payout provider is unavailable at this prefix");
}

CScript MiningPoolManager::ResolveWorkerPayoutScriptLocked(
    const std::string &worker_id, const Config &config,
    bool &is_newsletter_out) const {
    if (worker_id.rfind("sub:", 0) == 0) {
        is_newsletter_out = true;
        return GetFallbackPayoutScriptLocked(config);
    }
    is_newsletter_out = false;
    if (worker_id.empty() || worker_id == "default") {
        return GetFallbackPayoutScriptLocked(config);
    }

    // 1. Direct Lotus address
    CTxDestination dest =
        DecodeDestination(worker_id, config.GetChainParams());
    if (IsValidDestination(dest)) {
        return GetScriptForDestination(dest);
    }

    // 2. Address.worker_name format
    const size_t dot_pos = worker_id.find('.');
    if (dot_pos != std::string::npos && dot_pos > 0) {
        const std::string addr_part = worker_id.substr(0, dot_pos);
        dest = DecodeDestination(addr_part, config.GetChainParams());
        if (IsValidDestination(dest)) {
            return GetScriptForDestination(dest);
        }
    }

    // 3. Raw scriptPubKey hex
    if (worker_id.size() >= 4 && (worker_id.size() % 2 == 0) &&
        IsHex(worker_id)) {
        const auto raw = ParseHex(worker_id);
        return CScript(raw.begin(), raw.end());
    }

    throw std::runtime_error("Native pool payout provider is unavailable at this prefix");
}

uint256 MiningPoolManager::GetInitialShareTarget(
    const Consensus::Params &params) {
    if (params.fPowNoRetargeting) {
        // On regtest, network powLimit is 0x7fffff... (50% of hash space).
        // Set initial share_target to 0xbfffff... (75% of hash space) so:
        // - [0x00.., 0x7f..] meets both share_target and network_target
        // - (0x7f.., 0xbf..] meets share_target only (share without block)
        // - (0xbf.., 0xff..] exceeds share_target ("high-hash" rejection)
        uint256 target;
        std::memset(target.begin(), 0xff, 32);
        *(target.begin() + 31) = 0xbf;
        return target;
    }
    return params.powLimit;
}

double MiningPoolManager::ComputeShareDifficulty(const uint256 &share_target,
                                                 const uint256 &pow_limit) {
    const double target_d = UintToArith256(share_target).getdouble();
    const double limit_d = UintToArith256(pow_limit).getdouble();
    if (target_d <= 0.0 || limit_d <= 0.0) {
        return 1.0;
    }
    return std::max(0.1, limit_d / target_d);
}

PoolWorker &MiningPoolManager::GetOrCreateWorkerLocked(
    const std::string &worker_id, const Config &config) {
    const std::string key = worker_id.empty() ? "default" : worker_id;
    auto it = m_workers.find(key);
    if (it != m_workers.end()) {
        return it->second;
    }

    PoolWorker worker;
    worker.worker_id = key;
    worker.nonce_prefix = (m_next_nonce_prefix & 0x00FFFFFFU);
    if (worker.nonce_prefix == 0) {
        m_next_nonce_prefix = 1;
        worker.nonce_prefix = 1;
    }
    ++m_next_nonce_prefix;
    worker.payout_script = ResolveWorkerPayoutScriptLocked(
        key, config, worker.is_newsletter_subscriber);
    worker.share_target =
        GetInitialShareTarget(config.GetChainParams().GetConsensus());

    auto [inserted_it, _] = m_workers.emplace(key, std::move(worker));
    return inserted_it->second;
}

void MiningPoolManager::UpdateVarDiffLocked(PoolWorker &worker, int64_t now_ms,
                                            const Consensus::Params &params) {
    const int64_t target_spacing_sec =
        gArgs.IsArgSet("-pooltargetspacing")
            ? std::max<int64_t>(
                  1, gArgs.GetIntArg("-pooltargetspacing",
                                     DEFAULT_POOL_TARGET_SPACING_SEC))
            : m_target_spacing_sec;
    const int64_t target_ms = std::max<int64_t>(100, target_spacing_sec * 1000);

    if (worker.last_share_time_ms <= 0) {
        worker.last_share_time_ms = now_ms;
        return;
    }

    const int64_t elapsed_ms =
        std::max<int64_t>(1, now_ms - worker.last_share_time_ms);
    worker.last_share_time_ms = now_ms;

    worker.recent_share_intervals_ms.push_back(elapsed_ms);
    while (worker.recent_share_intervals_ms.size() > 8) {
        worker.recent_share_intervals_ms.pop_front();
    }

    int64_t sum_ms = 0;
    for (int64_t v : worker.recent_share_intervals_ms) {
        sum_ms += v;
    }
    const int64_t avg_ms =
        sum_ms / static_cast<int64_t>(worker.recent_share_intervals_ms.size());

    arith_uint256 bn_target = UintToArith256(worker.share_target);
    const arith_uint256 bn_max_target =
        UintToArith256(GetInitialShareTarget(params));
    // Floor at powLimit >> 6 on regtest so rapid test bursts remain fast to mine
    arith_uint256 bn_min_target = UintToArith256(params.powLimit);
    bn_min_target >>= (params.fPowNoRetargeting ? 6 : 32);
    if (bn_min_target == 0) {
        bn_min_target = 1;
    }

    if (avg_ms < (target_ms * 4) / 5) {
        // Shares arriving faster than target spacing -> tighten target (higher diff)
        const int64_t factor_num =
            std::clamp<int64_t>((avg_ms * 100) / target_ms, 85, 95);
        bn_target = (bn_target / 100) * static_cast<uint32_t>(factor_num);
        if (bn_target < bn_min_target) {
            bn_target = bn_min_target;
        }
        worker.share_target = ArithToUint256(bn_target);
    } else if (avg_ms > (target_ms * 5) / 4) {
        // Shares arriving slower than target spacing -> loosen target (lower diff)
        const int64_t factor_num =
            std::clamp<int64_t>((avg_ms * 100) / target_ms, 115, 200);
        arith_uint256 next_target =
            (bn_target / 100) * static_cast<uint32_t>(factor_num);
        if (next_target <= bn_target) {
            next_target = bn_target + (bn_target >> 2);
        }
        if (next_target > bn_max_target) {
            next_target = bn_max_target;
        }
        worker.share_target = ArithToUint256(next_target);
    }
}

double MiningPoolManager::EstimateWorkerHashrateLocked(
    const PoolWorker &worker, const Consensus::Params &params) const {
    if (worker.accepted_shares == 0) {
        return 0.0;
    }
    int64_t avg_ms = m_target_spacing_sec * 1000;
    if (!worker.recent_share_intervals_ms.empty()) {
        int64_t sum = 0;
        for (int64_t v : worker.recent_share_intervals_ms) {
            sum += v;
        }
        avg_ms = std::max<int64_t>(
            1, sum / static_cast<int64_t>(
                         worker.recent_share_intervals_ms.size()));
    }
    const double target_d = UintToArith256(worker.share_target).getdouble();
    const double max_256 = std::ldexp(1.0, 256);
    const double expected_hashes_per_share =
        target_d > 0.0 ? std::max(1.0, max_256 / target_d) : 1.0;
    return (expected_hashes_per_share * 1000.0) / static_cast<double>(avg_ms);
}

double MiningPoolManager::ComputeWorkerPPLNSWeightLocked(
    const std::string &worker_id) const {
    double weight = 0.0;
    for (const auto &share : m_pplns_window) {
        if (share.worker_id == worker_id) {
            weight += share.weight;
        }
    }
    return weight;
}

UniValue MiningPoolManager::GetMiningJobJSON(const Config &config,
                                             ::node::NodeContext &node,
                                             const std::string &worker_id,
                                             PoolJob *out_job,
                                             PoolWorker *out_worker) {
    // Removed only by the later explicit native payout provider.
    throw std::runtime_error("Native pool payout provider is unavailable at this prefix");
    ChainstateManager *chainman_ptr = node.chainman.get();
    if (!chainman_ptr) {
        throw std::runtime_error("ChainstateManager not initialized");
    }
    ChainstateManager &chainman = *chainman_ptr;
    const CChainParams &chainparams = config.GetChainParams();
    const Consensus::Params &consensusParams = chainparams.GetConsensus();

    ::node::SnapshotPublisher &publisher =
        node.snapshot_publisher ? *node.snapshot_publisher
                                : ::node::GetGlobalSnapshotPublisher();

    auto snap = publisher.Load();
    {
        LOCK(cs_main);
        const CBlockIndex *tip = chainman.ActiveTip();
        const BlockHash tip_hash = tip ? tip->GetBlockHash() : BlockHash();
        if (!snap || !snap->chain_valid || snap->chainman_ptr != &chainman ||
            !snap->mining_template.template_valid ||
            snap->best_block_hash != tip_hash) {
            ::node::PublishChainTipSnapshot(chainman, node.mempool.get());
            snap = publisher.Load();
        }
    }

    if (!snap || !snap->chain_valid || !snap->mining_template.template_valid) {
        throw std::runtime_error("Mining template snapshot unavailable");
    }

    // A valid snapshot can still carry a deferred, empty template stub.
    // Materialize this pinned snapshot before reading its selection or reward.
    snap->EnsureMiningTemplate();
    const ::node::MiningTemplateSnapshot &tmpl = snap->mining_template;
    tmpl.EnsureRoots();

    const int64_t adjustedTime =
        TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    const int64_t curtime =
        std::max<int64_t>(tmpl.min_time, adjustedTime);
    uint32_t nBits = tmpl.nBits;
    if (!consensusParams.fPowNoRetargeting &&
        consensusParams.fPowAllowMinDifficultyBlocks && snap->height >= 1 &&
        curtime > snap->time + 2 * consensusParams.nPowTargetSpacing) {
        nBits = UintToArith256(consensusParams.powLimit).GetCompact();
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (gArgs.IsArgSet("-poolpplnswindow")) {
        m_pplns_window_size = static_cast<size_t>(std::max<int64_t>(
            1, gArgs.GetIntArg("-poolpplnswindow",
                               static_cast<int64_t>(DEFAULT_POOL_PPLNS_WINDOW))));
    }
    PoolWorker &worker = GetOrCreateWorkerLocked(worker_id, config);
    const CScript fallback_script = GetFallbackPayoutScriptLocked(config);

    const Amount blockReward = tmpl.block_reward;
    const auto minerFundWhitelist = GetMinerFundWhitelist(consensusParams);
    const Amount minerFundAmount =
        !minerFundWhitelist.empty()
            ? GetMinerFundAmount(consensusParams, blockReward, nullptr)
            : Amount::zero();

    std::vector<CScript> stakingRewardsPayoutScripts;
    Amount stakingRewardsAmount = Amount::zero();
    if (node.avalanche &&
        gArgs.GetBoolArg("-avalanchestakingrewards",
                         consensusParams.enableStakingRewards)) {
        if (node.avalanche->getStakingRewardWinners(
                tmpl.prev_block_hash, stakingRewardsPayoutScripts) &&
            !stakingRewardsPayoutScripts.empty()) {
            stakingRewardsAmount = GetStakingRewardsAmount(blockReward);
        } else {
            stakingRewardsPayoutScripts.clear();
        }
    }

    const Amount minerSlice =
        std::max(Amount::zero(),
                 blockReward - minerFundAmount - stakingRewardsAmount);

    // Aggregate PPLNS payout weights by scriptPubKey in order of appearance
    std::vector<std::pair<CScript, double>> pplns_payouts;
    double total_weight = 0.0;
    for (const PPLNSShare &share : m_pplns_window) {
        if (share.weight <= 0.0) {
            continue;
        }
        const CScript &script = share.is_newsletter_subscriber
                                    ? fallback_script
                                    : share.payout_script;
        auto it = std::find_if(
            pplns_payouts.begin(), pplns_payouts.end(),
            [&script](const auto &entry) { return entry.first == script; });
        if (it != pplns_payouts.end()) {
            it->second += share.weight;
        } else {
            pplns_payouts.emplace_back(script, share.weight);
        }
        total_weight += share.weight;
    }

    // A pool is a mainnet feature: its coinbase is always a V2 coinbase.
    CMutableTransaction coinbaseTx = ::node::CreateCoinbaseShell(
        7, tmpl.prev_block_hash, int(tmpl.next_height));

    if (pplns_payouts.empty() || total_weight <= 0.0) {
        const CScript &recipient =
            worker.is_newsletter_subscriber ? fallback_script
                                            : worker.payout_script;
        coinbaseTx.vout.emplace_back(minerSlice, recipient);
    } else {
        const int64_t total_miner_sats = minerSlice / SATOSHI;
        int64_t allocated_sats = 0;
        for (size_t i = 0; i < pplns_payouts.size(); ++i) {
            int64_t sats = 0;
            if (i + 1 < pplns_payouts.size()) {
                sats = static_cast<int64_t>(std::llround(
                    (static_cast<double>(total_miner_sats) *
                     pplns_payouts[i].second) /
                    total_weight));
                sats = std::clamp<int64_t>(
                    sats, 0, total_miner_sats - allocated_sats);
            } else {
                sats = std::max<int64_t>(0, total_miner_sats - allocated_sats);
            }
            allocated_sats += sats;
            if (sats > 0) {
                coinbaseTx.vout.emplace_back(sats * SATOSHI,
                                             pplns_payouts[i].first);
            }
        }
        if (coinbaseTx.vout.empty()) {
            coinbaseTx.vout.emplace_back(minerSlice, fallback_script);
        }
    }

    if (!minerFundWhitelist.empty() && minerFundAmount > Amount::zero()) {
        coinbaseTx.vout.emplace_back(
            minerFundAmount,
            GetScriptForDestination(*minerFundWhitelist.begin()));
    }
    if (!stakingRewardsPayoutScripts.empty() &&
        stakingRewardsAmount > Amount::zero()) {
        coinbaseTx.vout.emplace_back(stakingRewardsAmount,
                                     stakingRewardsPayoutScripts[0]);
    }

    // The payees by script; the coinbase pays each the V0-leaf V2 output
    // over its script.
    const std::vector<CTxOut> payouts = coinbaseTx.vout;
    ::node::SetCoinbaseOutputs(coinbaseTx, payouts);
    ::node::PadCoinbaseToMinSize(coinbaseTx);
    uint64_t coinbaseSize = ::GetSerializeSize(coinbaseTx);

    CTransactionRef coinbaseRef = MakeTransactionRef(std::move(coinbaseTx));

    // O(1) Merkle root from cached Subtree A root (2 BLAKE3 hashes)
    const uint256 hashMerkleRoot =
        ComputeV2TxRootFromSubtreeA(*coinbaseRef, tmpl.subtree_a_root);

    // O(1) State root from cached V2 base state (~27 BLAKE3 hashes)
    const uint256 hashStateRoot = ComputeV2StateRootFromTemplate(
        tmpl.v2_base_state, *coinbaseRef, nBits);

    uint64_t non_cb_size = tmpl.non_cb_serialized_size;
    if (non_cb_size == 0 && !tmpl.non_coinbase_txs.empty()) {
        for (const auto &tx : tmpl.non_coinbase_txs) {
            non_cb_size += ::GetSerializeSize(*tx);
        }
    }
    const uint64_t blocksize =
        lotus::v2::HEADER_SIZE +
        GetSizeOfCompactSize(1 + tmpl.non_coinbase_txs.size()) + coinbaseSize +
        non_cb_size;

    CBlockHeader candidate_header;
    candidate_header.hashPrevBlock = tmpl.prev_block_hash;
    candidate_header.nBits = nBits;
    candidate_header.SetBlockTime(static_cast<uint64_t>(curtime));
    candidate_header.nNonce =
        static_cast<uint64_t>(worker.nonce_prefix) << 40;
    candidate_header.nHeaderVersion = tmpl.nHeaderVersion;
    candidate_header.SetSize(blocksize);
    candidate_header.nHeight = static_cast<uint64_t>(tmpl.next_height);
    candidate_header.hashMerkleRoot = hashMerkleRoot;
    candidate_header.hashStateRoot = hashStateRoot;

    lotus::v2::Hash pow_limit_bytes{};
    std::memcpy(pow_limit_bytes.data(), consensusParams.powLimit.begin(), 32);
    lotus::v2::Hash v2_target_bytes{};
    lotus::v2::DecodeTarget(nBits, pow_limit_bytes, v2_target_bytes);
    uint256 network_target;
    std::memcpy(network_target.begin(), v2_target_bytes.data(), 32);

    const lotus::v2::Hash body_hash_bytes = lotus::v2::BodyHash(
        GetActiveV2ChainId(), candidate_header.ToV2Header());
    uint256 body_hash_u256;
    std::memcpy(body_hash_u256.begin(), body_hash_bytes.data(), 32);

    const uint64_t job_id = m_next_job_id++;
    PoolJob &job_slot = m_jobs[job_id % POOL_JOB_RING_SIZE];
    job_slot = PoolJob{};
    job_slot.job_id = job_id;
    job_slot.template_id = tmpl.template_id;
    job_slot.header_134 = candidate_header;
    job_slot.coinbase_tx = coinbaseRef;
    job_slot.template_txs = tmpl.non_coinbase_txs;
    job_slot.subtree_a_root = tmpl.subtree_a_root;
    job_slot.body_hash = body_hash_bytes;
    job_slot.parent_id = tmpl.prev_block_hash;
    job_slot.nBits = nBits;
    job_slot.network_target = network_target;
    job_slot.created_time = curtime;
    job_slot.block_size = blocksize;
    job_slot.block_reward = blockReward;
    job_slot.block_sealed = false;

    if (out_job) {
        *out_job = job_slot;
    }
    if (out_worker) {
        *out_worker = worker;
    }

    DataStream ss_header{};
    ss_header << candidate_header;
    const std::string header_hex = HexStr(ss_header);

    UniValue coinbase_outputs(UniValue::VARR);
    for (const auto &out : payouts) {
        UniValue out_obj(UniValue::VOBJ);
        out_obj.pushKV("value_sats", int64_t(out.nValue / SATOSHI));
        out_obj.pushKV("script_hex", HexStr(out.scriptPubKey));
        coinbase_outputs.push_back(std::move(out_obj));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("job_id", strprintf("%llu", static_cast<unsigned long long>(job_id)));
    result.pushKV("job_id_num", job_id);
    result.pushKV("protocol", "v2");
    result.pushKV("worker_id", worker.worker_id);
    result.pushKV("height", int64_t(tmpl.next_height));
    result.pushKV("prev_block_hash", tmpl.prev_block_hash.GetHex());
    result.pushKV("header_hex", header_hex);
    result.pushKV("header", header_hex);
    result.pushKV("body_hash", HexStr(body_hash_bytes));
    result.pushKV("chain_id", HexStr(GetActiveV2ChainId()));
    result.pushKV("bits", strprintf("%08x", nBits));
    result.pushKV("time", static_cast<uint64_t>(curtime));
    result.pushKV("nonce_prefix", static_cast<uint64_t>(worker.nonce_prefix));
    result.pushKV("nonce_prefix_hex",
                  strprintf("%06x", worker.nonce_prefix));
    result.pushKV("share_target", worker.share_target.GetHex());
    result.pushKV("network_target", network_target.GetHex());
    result.pushKV("target", worker.share_target.GetHex());
    result.pushKV("coinbase_tx_hex", EncodeHexTx(*coinbaseRef));
    result.pushKV("coinbase_outputs", std::move(coinbase_outputs));
    return result;
}

std::string MiningPoolManager::FormatSSEJobEvent(const UniValue &job_json) {
    return "event: job\ndata: " + job_json.write() + "\n\n";
}

ShareSubmissionResult MiningPoolManager::SubmitShare(
    const Config &config, ::node::NodeContext &node, uint64_t job_id,
    const std::string &worker_id, std::optional<uint64_t> nTime,
    uint64_t nNonce) {
    ShareSubmissionResult result;
    result.reason = "native-payout-provider-unavailable";
    return result;
    const Consensus::Params &consensusParams =
        config.GetChainParams().GetConsensus();

    std::shared_ptr<CBlock> candidate_block;
    BlockHash candidate_pow_hash;
    std::string resolved_worker_key;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        PoolWorker &worker = GetOrCreateWorkerLocked(worker_id, config);
        resolved_worker_key = worker.worker_id;
        result.share_target = worker.share_target;

        if (job_id == 0) {
            ++worker.rejected_shares;
            ++m_total_rejected_shares;
            result.accepted = false;
            result.reason = "job-not-found";
            result.accepted_shares = worker.accepted_shares;
            result.rejected_shares = worker.rejected_shares;
            return result;
        }

        PoolJob &job = m_jobs[job_id % POOL_JOB_RING_SIZE];
        if (job.job_id != job_id) {
            ++worker.rejected_shares;
            ++m_total_rejected_shares;
            result.accepted = false;
            result.reason = "job-not-found";
            result.accepted_shares = worker.accepted_shares;
            result.rejected_shares = worker.rejected_shares;
            return result;
        }

        // Reject duplicate nonces on the same job
        if (job.submitted_nonces.count(nNonce) > 0) {
            ++worker.rejected_shares;
            ++m_total_rejected_shares;
            result.accepted = false;
            result.reason = "duplicate-share";
            result.accepted_shares = worker.accepted_shares;
            result.rejected_shares = worker.rejected_shares;
            return result;
        }

        // Validate 24-bit nonce prefix (accept worker's assigned prefix or unprefixed 0)
        const uint32_t upper24 =
            static_cast<uint32_t>((nNonce >> 40) & 0x00FFFFFFULL);
        if (upper24 != 0 && upper24 != worker.nonce_prefix) {
            ++worker.rejected_shares;
            ++m_total_rejected_shares;
            result.accepted = false;
            result.reason = "nonce-prefix-mismatch";
            result.accepted_shares = worker.accepted_shares;
            result.rejected_shares = worker.rejected_shares;
            return result;
        }

        CBlockHeader header = job.header_134;
        if (nTime.has_value()) {
            header.SetBlockTime(*nTime);
        }
        header.nNonce = nNonce;

        const BlockHash pow_hash = header.GetHash();
        result.share_hash = pow_hash;

        lotus::v2::Hash pow_bytes{};
        std::memcpy(pow_bytes.data(), pow_hash.begin(), 32);
        lotus::v2::Hash share_target_bytes{};
        std::memcpy(share_target_bytes.data(), worker.share_target.begin(), 32);

        if (!lotus::v2::MeetsTarget(pow_bytes, share_target_bytes)) {
            ++worker.rejected_shares;
            ++m_total_rejected_shares;
            result.accepted = false;
            result.reason = "high-hash";
            result.accepted_shares = worker.accepted_shares;
            result.rejected_shares = worker.rejected_shares;
            return result;
        }

        // Valid share! Record nonce and update PPLNS + vardiff + newsletter credits
        job.submitted_nonces.insert(nNonce);

        const double share_diff =
            ComputeShareDifficulty(worker.share_target, consensusParams.powLimit);

        PPLNSShare pplns_entry;
        pplns_entry.worker_id = worker.worker_id;
        pplns_entry.payout_script = worker.payout_script;
        pplns_entry.weight = share_diff;
        pplns_entry.is_newsletter_subscriber = worker.is_newsletter_subscriber;
        m_pplns_window.push_back(std::move(pplns_entry));
        while (m_pplns_window.size() > m_pplns_window_size) {
            m_pplns_window.pop_front();
        }

        ++worker.accepted_shares;
        ++m_total_accepted_shares;
        worker.cumulative_work += share_diff;
        m_total_work += share_diff;

        if (worker.is_newsletter_subscriber) {
            worker.newsletter_credits_usd_cents += 25.0 * share_diff;
        }

        const int64_t now_ms =
            TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
        UpdateVarDiffLocked(worker, now_ms, consensusParams);

        result.accepted = true;
        result.reason = "accepted";
        result.share_target = worker.share_target;
        result.accepted_shares = worker.accepted_shares;
        result.rejected_shares = worker.rejected_shares;
        result.newsletter_credits_usd_cents =
            worker.newsletter_credits_usd_cents;
        result.subscription_unlocked =
            worker.is_newsletter_subscriber &&
            (worker.newsletter_credits_usd_cents >= 25.0 ||
             worker.accepted_shares > 0);

        // Check if this share ALSO satisfies the full network target
        if (!job.block_sealed &&
            CheckProofOfWork(pow_hash, header.nBits, consensusParams)) {
            candidate_block = std::make_shared<CBlock>(header);
            candidate_block->vtx.reserve(1 + job.template_txs.size());
            candidate_block->vtx.push_back(job.coinbase_tx);
            candidate_block->vtx.insert(candidate_block->vtx.end(),
                                        job.template_txs.begin(),
                                        job.template_txs.end());
            candidate_block->m_checked_merkle_root = true;
            candidate_pow_hash = pow_hash;
            job.block_sealed = true;
        }
    }

    // Submit candidate block outside m_mutex to avoid lock-order inversion with cs_main
    if (candidate_block && node.chainman) {
        ChainstateManager &chainman = *node.chainman;
        bool should_submit = false;
        {
            LOCK(cs_main);
            const CBlockIndex *tip = chainman.ActiveTip();
            if (tip &&
                tip->GetBlockHash() == candidate_block->hashPrevBlock) {
                should_submit = true;
            }
        }
        if (should_submit) {
            bool new_block = false;
            const bool processed = chainman.ProcessNewBlock(
                candidate_block, /*force_processing=*/true,
                /*min_pow_checked=*/true, &new_block, node.avalanche.get());
            if (chainman.m_options.signals) {
                chainman.m_options.signals
                    ->SyncWithValidationInterfaceQueue();
            }
            bool block_valid = false;
            {
                LOCK(cs_main);
                const CBlockIndex *pindex =
                    chainman.m_blockman.LookupBlockIndex(candidate_pow_hash);
                if (processed && pindex && !pindex->nStatus.isInvalid()) {
                    block_valid = true;
                }
            }
            if (block_valid) {
                std::lock_guard<std::mutex> lock(m_mutex);
                ++m_blocks_found;
                auto it = m_workers.find(resolved_worker_key);
                if (it != m_workers.end()) {
                    ++it->second.blocks_found;
                }
                result.block_found = true;
                result.block_hash = candidate_pow_hash;
            }
        }
    }

    return result;
}

UniValue MiningPoolManager::GetPoolInfoJSON() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    const Consensus::Params &consensusParams =
        GetConfig().GetChainParams().GetConsensus();

    double pool_hashrate = 0.0;
    for (const auto &[_, worker] : m_workers) {
        pool_hashrate += EstimateWorkerHashrateLocked(worker, consensusParams);
    }

    const bool enabled =
        gArgs.IsArgSet("-miningpool")
            ? gArgs.GetBoolArg("-miningpool", DEFAULT_MINING_POOL_ENABLED)
            : m_enabled;
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("enabled", enabled);
    obj.pushKV("payout_ready", false);
    obj.pushKV("payout_error", "native-payout-provider-unavailable");
    obj.pushKV("active_workers", static_cast<uint64_t>(m_workers.size()));
    obj.pushKV("pool_hashrate", pool_hashrate);
    obj.pushKV("blocks_found", m_blocks_found);
    obj.pushKV("total_accepted_shares", m_total_accepted_shares);
    obj.pushKV("total_rejected_shares", m_total_rejected_shares);
    obj.pushKV("total_work", m_total_work);
    obj.pushKV("pplns_window_shares",
               static_cast<uint64_t>(m_pplns_window.size()));
    obj.pushKV("pplns_window_max",
               static_cast<uint64_t>(m_pplns_window_size));
    obj.pushKV("target_spacing_sec", m_target_spacing_sec);
    return obj;
}

UniValue MiningPoolManager::GetWorkerStatsJSON(
    const std::string &worker_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    const Consensus::Params &consensusParams =
        GetConfig().GetChainParams().GetConsensus();

    double pool_hashrate = 0.0;
    for (const auto &[_, w] : m_workers) {
        pool_hashrate += EstimateWorkerHashrateLocked(w, consensusParams);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("active_workers", static_cast<uint64_t>(m_workers.size()));
    obj.pushKV("pool_hashrate", pool_hashrate);
    obj.pushKV("blocks_found", m_blocks_found);
    obj.pushKV("pplns_window_shares",
               static_cast<uint64_t>(m_pplns_window.size()));

    const std::string key = worker_id.empty() ? "default" : worker_id;
    auto it = m_workers.find(key);
    if (it == m_workers.end()) {
        const bool is_sub = (key.rfind("sub:", 0) == 0);
        obj.pushKV("worker_id", key);
        obj.pushKV("nonce_prefix", uint64_t(0));
        obj.pushKV("share_target",
                   GetInitialShareTarget(consensusParams).GetHex());
        obj.pushKV("accepted_shares", uint64_t(0));
        obj.pushKV("rejected_shares", uint64_t(0));
        obj.pushKV("worker_blocks_found", uint64_t(0));
        obj.pushKV("cumulative_work", 0.0);
        obj.pushKV("estimated_hashrate", 0.0);
        obj.pushKV("pplns_weight", 0.0);
        obj.pushKV("is_newsletter_subscriber", is_sub);
        obj.pushKV("newsletter_credits_usd_cents", 0.0);
        obj.pushKV("subscription_unlocked", false);
        return obj;
    }

    const PoolWorker &w = it->second;
    const double est_hashrate =
        EstimateWorkerHashrateLocked(w, consensusParams);
    const double pplns_weight = ComputeWorkerPPLNSWeightLocked(w.worker_id);
    const bool unlocked =
        w.is_newsletter_subscriber &&
        (w.newsletter_credits_usd_cents >= 25.0 || w.accepted_shares > 0);

    obj.pushKV("worker_id", w.worker_id);
    obj.pushKV("nonce_prefix", static_cast<uint64_t>(w.nonce_prefix));
    obj.pushKV("nonce_prefix_hex", strprintf("%06x", w.nonce_prefix));
    obj.pushKV("share_target", w.share_target.GetHex());
    obj.pushKV("accepted_shares", w.accepted_shares);
    obj.pushKV("rejected_shares", w.rejected_shares);
    obj.pushKV("worker_blocks_found", w.blocks_found);
    obj.pushKV("cumulative_work", w.cumulative_work);
    obj.pushKV("estimated_hashrate", est_hashrate);
    obj.pushKV("pplns_weight", pplns_weight);
    obj.pushKV("is_newsletter_subscriber", w.is_newsletter_subscriber);
    obj.pushKV("newsletter_credits_usd_cents", w.newsletter_credits_usd_cents);
    obj.pushKV("subscription_unlocked", unlocked);
    return obj;
}

std::shared_ptr<MiningPoolManager> GetGlobalMiningPoolPtr() {
    static auto g_pool = std::make_shared<MiningPoolManager>();
    return g_pool;
}

MiningPoolManager &GetGlobalMiningPool() {
    return *GetGlobalMiningPoolPtr();
}

} // namespace lotus::v2::node
