// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/v2_outputs.h>
#include <node/mining_pool.h>

#include <arith_uint256.h>
#include <base58.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <config.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key.h>
#include <key_io.h>
#include <lotus_v2/header.h>
#include <lotus_v2/address.h>
#include <lotus_v2/output.h>
#include <node/context.h>
#include <node/snapshot.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <future>
#include <limits>
#include <string>
#include <thread>

namespace {

std::string NativeAddress(const CKey &key) {
    const auto pubkey = key.GetPubKey();
    return lotus::v2::EncodeKeyHashAddress(
        lotus::v2::AddressNetwork::REGTEST,
        lotus::v2::NativeKeyHash(std::span<const uint8_t, 32>(pubkey.data() + 1, 32)));
}

lotus::v2::Hash32 AddressRoot(const std::string &address) {
    std::string error;
    return lotus::v2::DecodeAddress(address, error)->BranchRoot();
}

bool OutputPaysAddress(const UniValue &output, const std::string &address) {
    return output.find_value("branch_root").get_str() == HexStr(AddressRoot(address));
}

bool HashMeetsTarget(const BlockHash &pow_hash, const uint256 &target) {
    lotus::v2::Hash pow_bytes{};
    std::memcpy(pow_bytes.data(), pow_hash.begin(), 32);
    lotus::v2::Hash target_bytes{};
    std::memcpy(target_bytes.data(), target.begin(), 32);
    return lotus::v2::MeetsTarget(pow_bytes, target_bytes);
}

/**
 * Find a 64-bit nonce with the given 24-bit upper prefix whose V2 PoW hash
 * satisfies:
 *   - require_above_network_target == true:  network_target < hash <= share_target
 *   - require_above_network_target == false: hash <= network_target && hash <= share_target
 */
uint64_t FindShareNonce(CBlockHeader header, uint32_t nonce_prefix,
                        const uint256 &share_target,
                        const uint256 &network_target,
                        bool require_above_network_target,
                        uint64_t start_local_nonce = 1) {
    const uint64_t base = static_cast<uint64_t>(nonce_prefix) << 40;
    for (uint64_t local = start_local_nonce; local < start_local_nonce + 100000;
         ++local) {
        const uint64_t candidate = base | local;
        header.nNonce = candidate;
        const BlockHash h = header.GetHash();
        const bool meets_share = HashMeetsTarget(h, share_target);
        const bool meets_net = HashMeetsTarget(h, network_target);
        if (require_above_network_target) {
            if (meets_share && !meets_net) {
                return candidate;
            }
        } else {
            if (meets_share && meets_net) {
                return candidate;
            }
        }
    }
    BOOST_FAIL("Failed to find matching nonce in search range");
    return 0;
}

/**
 * Find a 64-bit nonce with the given 24-bit upper prefix whose V2 PoW hash
 * exceeds share_target (i.e. a high-hash invalid share).
 */
uint64_t FindHighHashNonce(CBlockHeader header, uint32_t nonce_prefix,
                           const uint256 &share_target,
                           uint64_t start_local_nonce = 1) {
    const uint64_t base = static_cast<uint64_t>(nonce_prefix) << 40;
    for (uint64_t local = start_local_nonce; local < start_local_nonce + 100000;
         ++local) {
        const uint64_t candidate = base | local;
        header.nNonce = candidate;
        const BlockHash h = header.GetHash();
        if (!HashMeetsTarget(h, share_target)) {
            return candidate;
        }
    }
    BOOST_FAIL("Failed to find high-hash nonce in search range");
    return 0;
}

} // namespace

struct MiningPoolTestSetup : TestChain100Setup {
    MiningPoolTestSetup() {
        m_node.args->ForceSetArg("-pooladdress", NativeAddress(coinbaseKey));
        auto pool = std::make_shared<node::MiningPoolManager>();
        pool->Configure(*m_node.args, GetConfig());
        std::atomic_store(&m_node.mining_pool, std::move(pool));
    }
    ~MiningPoolTestSetup() { node::StopMiningPool(m_node); }
};

BOOST_FIXTURE_TEST_SUITE(mining_pool_tests, MiningPoolTestSetup)

BOOST_AUTO_TEST_CASE(operator_commission_exact_percent_parser) {
    using Pool = node::MiningPoolManager;
    for (const auto &[text, bps] : std::vector<std::pair<std::string, int>>{
        {"0", 0}, {"0.00", 0}, {"0.01", 1}, {"1.2", 120}, {"1.25", 125},
        {"99.99", 9999}, {"100", 10000}, {"100.00", 10000}})
        BOOST_CHECK_EQUAL(Pool::ParseOperatorFeePercent(text), bps);
    for (const auto *text : {"", "-1", "100.01", "101", "nan", "1e1", "+1",
                             ".5", "1.", "0.001", "1.2.3", "1%", " 1", "1 "})
        BOOST_CHECK_THROW(Pool::ParseOperatorFeePercent(text), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(operator_commission_integer_rounding) {
    using Pool = node::MiningPoolManager;
    for (const uint16_t bps : {0, 1, 125, 9999, 10000}) {
        for (const int64_t amount : {0LL, 1LL, 79LL, 80LL, 9999LL, 10000LL,
                                    10001LL, 5000000000LL}) {
            const auto fee = Pool::OperatorCommission(amount * SATOSHI, bps);
            BOOST_CHECK_EQUAL(fee / SATOSHI, (amount * bps) / 10000);
            BOOST_CHECK(fee >= Amount::zero());
            BOOST_CHECK(fee <= amount * SATOSHI);
            BOOST_CHECK_EQUAL(((amount * SATOSHI - fee) + fee) / SATOSHI, amount);
        }
    }
    const int64_t huge = std::numeric_limits<int64_t>::max();
    BOOST_CHECK_EQUAL(Pool::OperatorCommission(huge * SATOSHI, 10000) / SATOSHI, huge);
    BOOST_CHECK_THROW(Pool::OperatorCommission(-SATOSHI, 100), std::invalid_argument);
    BOOST_CHECK_THROW(Pool::OperatorCommission(SATOSHI, 10001), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(operator_commission_jobs_conserve_and_freeze) {
    const Config &config = GetConfig();
    CKey worker_key;
    worker_key.MakeNewKey(true);
    const auto worker_address = NativeAddress(worker_key);
    const auto operator_address = NativeAddress(coinbaseKey);
    for (const auto &[percent, bps] : std::vector<std::pair<std::string, int>>{
            {"0", 0}, {"0.01", 1}, {"1.25", 125}, {"100", 10000}}) {
        ArgsManager args;
        args.ForceSetArg("-pooladdress", operator_address);
        args.ForceSetArg("-poolfeepercent", percent);
        node::MiningPoolManager pool;
        pool.Configure(args, config);
        lotus::v2::node::PoolJob cached;
        const auto job = pool.GetMiningJobJSON(config, m_node, worker_address, &cached);
        BOOST_CHECK_EQUAL(job.find_value("operator_fee_bps").getInt<int>(), bps);
        const auto fee = node::MiningPoolManager::OperatorCommission(cached.block_reward, bps);
        BOOST_CHECK_EQUAL(cached.operator_commission / SATOSHI, fee / SATOSHI);
        BOOST_CHECK_EQUAL(cached.worker_reward / SATOSHI,
                          (cached.block_reward - fee) / SATOSHI);
        Amount total = Amount::zero(), worker_paid = Amount::zero(), operator_paid = Amount::zero();
        for (const auto &output : cached.coinbase_tx->vout) {
            BOOST_CHECK(!output.IsLegacy());
            total += output.nValue;
            if (output.vBranches == std::vector<lotus::v2::Hash32>{AddressRoot(worker_address)})
                worker_paid += output.nValue;
            else if (output.vBranches == std::vector<lotus::v2::Hash32>{AddressRoot(operator_address)})
                operator_paid += output.nValue;
            else BOOST_FAIL("Unexpected recipient");
        }
        BOOST_CHECK(total == cached.block_reward);
        BOOST_CHECK(operator_paid == fee);
        BOOST_CHECK(worker_paid == cached.worker_reward);
        const auto wire_before = EncodeHexTx(*cached.coinbase_tx);
        args.ForceSetArg("-poolfeepercent", "50");
        BOOST_CHECK_THROW(pool.Configure(args, config), std::logic_error);
        BOOST_CHECK_EQUAL(pool.GetPoolInfoJSON().find_value("operator_fee_bps").getInt<int>(), bps);
        BOOST_CHECK_EQUAL(EncodeHexTx(*cached.coinbase_tx), wire_before);
    }
    for (const auto &address : {std::string(), std::string("invalid"),
             EncodeDestination(PKHash(coinbaseKey.GetPubKey()), config)}) {
        ArgsManager args;
        args.ForceSetArg("-poolfeepercent", "1.25");
        args.ForceSetArg("-pooladdress", address);
        node::MiningPoolManager pool;
        pool.Configure(args, config);
        BOOST_CHECK(!pool.GetPoolInfoJSON().find_value("payout_ready").get_bool());
        BOOST_CHECK_THROW(pool.GetMiningJobJSON(config, m_node, worker_address), std::runtime_error);
    }
    for (const auto *invalid : {"-1", "100.01", "1.234", "NaN"}) {
        ArgsManager args;
        args.ForceSetArg("-poolfeepercent", invalid);
        node::MiningPoolManager pool;
        BOOST_CHECK_THROW(pool.Configure(args, config), std::invalid_argument);
    }
}

BOOST_AUTO_TEST_CASE(operator_commission_preserves_multi_worker_pplns_remainder) {
    const Config &config = GetConfig();
    ArgsManager args;
    const auto operator_address = NativeAddress(coinbaseKey);
    args.ForceSetArg("-pooladdress", operator_address);
    args.ForceSetArg("-poolfeepercent", "1.25");
    node::MiningPoolManager pool;
    pool.Configure(args, config);
    CKey a, b;
    a.MakeNewKey(true);
    b.MakeNewKey(true);
    const auto address_a = NativeAddress(a), address_b = NativeAddress(b);
    for (const auto &[address, count] :
         std::vector<std::pair<std::string, int>>{{address_a, 3}, {address_b, 1}}) {
        lotus::v2::node::PoolJob cached;
        lotus::v2::node::PoolWorker worker;
        pool.GetMiningJobJSON(config, m_node, address, &cached, &worker);
        uint64_t cursor = 1;
        for (int i = 0; i < count; ++i) {
            pool.SetWorkerShareTarget(address, worker.share_target, config);
            const auto nonce = FindShareNonce(cached.header_134, worker.nonce_prefix,
                worker.share_target, cached.network_target, true, cursor);
            cursor = (nonce & 0xFFFFFFFFFFULL) + 1;
            const auto result = pool.SubmitShare(config, m_node, cached.job_id,
                                                address, std::nullopt, nonce);
            BOOST_REQUIRE(result.accepted);
            BOOST_CHECK(!result.block_found);
        }
    }
    lotus::v2::node::PoolJob final_job;
    pool.GetMiningJobJSON(config, m_node, address_a, &final_job);
    Amount paid_a = Amount::zero(), paid_b = Amount::zero(), paid_operator = Amount::zero();
    for (const auto &output : final_job.coinbase_tx->vout) {
        const auto &root = output.vBranches.at(0);
        if (root == AddressRoot(address_a)) paid_a += output.nValue;
        else if (root == AddressRoot(address_b)) paid_b += output.nValue;
        else if (root == AddressRoot(operator_address)) paid_operator += output.nValue;
        else BOOST_FAIL("Unexpected PPLNS recipient");
    }
    BOOST_CHECK(paid_operator == final_job.operator_commission);
    BOOST_CHECK(paid_a + paid_b == final_job.worker_reward);
    BOOST_CHECK(paid_a + paid_b + paid_operator == final_job.block_reward);
    BOOST_CHECK_LE(std::abs((paid_a - 3 * paid_b) / SATOSHI), 2);
}

BOOST_AUTO_TEST_CASE(native_payout_configuration_failclosed) {
    const Config &config = GetConfig();
    for (const auto &address : {std::string(), std::string("invalid"),
             EncodeDestination(PKHash(coinbaseKey.GetPubKey()), config),
             lotus::v2::EncodeAddress(lotus::v2::AddressNetwork::MAINNET, {})}) {
        ArgsManager args;
        args.ForceSetArg("-pooladdress", address);
        node::MiningPoolManager pool;
        pool.Configure(args, config);
        BOOST_CHECK(pool.IsEnabled());
        BOOST_CHECK(!pool.GetPoolInfoJSON().find_value("payout_ready").get_bool());
        BOOST_CHECK_THROW(pool.GetMiningJobJSON(config, m_node, "default"), std::runtime_error);
        BOOST_CHECK_EQUAL(pool.GetPoolInfoJSON().find_value("active_workers").getInt<int>(), 0);
    }
    auto pool = node::GetMiningPool(m_node);
    const auto job = pool->GetMiningJobJSON(config, m_node, "default");
    BOOST_CHECK_THROW(pool->Configure(*m_node.args, config), std::logic_error);
    for (const auto &invalid_worker : {
            EncodeDestination(PKHash(coinbaseKey.GetPubKey()), config),
            EncodeBase58Check(std::vector<uint8_t>(21, 0)),
            std::string("rxpi1broken"), std::string("xpi1broken"),
            std::string("RXPI1BROKEN"), std::string("rXpi1broken"), std::string("51")}) {
        BOOST_CHECK_THROW(pool->GetMiningJobJSON(config, m_node, invalid_worker), std::runtime_error);
    }
    BOOST_CHECK(OutputPaysAddress(job.find_value("coinbase_outputs")[0], NativeAddress(coinbaseKey)));
}

BOOST_AUTO_TEST_CASE(job_generation_nonce_prefix_and_vardiff) {
    const Config &config = GetConfig();
    auto pool_ptr = node::GetMiningPool(m_node);
    auto &pool = *pool_ptr;
    pool.Reset();
    pool.Configure(*m_node.args, config);

    // 1. Generate jobs via RPC getminingjob for two distinct workers
    JSONRPCRequest req1;
    req1.context = &m_node;
    req1.strMethod = "getminingjob";
    req1.params = UniValue(UniValue::VARR);
    req1.params.push_back("worker_alpha");
    const UniValue job1 = tableRPC.execute(config, req1);

    JSONRPCRequest req2;
    req2.context = &m_node;
    req2.strMethod = "getminingjob";
    req2.params = UniValue(UniValue::VARR);
    req2.params.push_back("worker_beta");
    const UniValue job2 = tableRPC.execute(config, req2);

    BOOST_CHECK_EQUAL(job1.find_value("protocol").get_str(), "v2");
    BOOST_CHECK_EQUAL(job1.find_value("height").getInt<int>(), 101);
    BOOST_CHECK_EQUAL(job1.find_value("header_hex").get_str().size(),
                      lotus::v2::HEADER_SIZE * 2);
    BOOST_CHECK_EQUAL(job1.find_value("body_hash").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(job1.find_value("chain_id").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(job1.find_value("share_target").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(job1.find_value("network_target").get_str().size(), 64U);

    // Verify SSE event formatting
    const std::string sse_frame =
        lotus::v2::node::MiningPoolManager::FormatSSEJobEvent(job1);
    BOOST_CHECK(sse_frame.rfind("event: job\ndata: ", 0) == 0);
    BOOST_CHECK(sse_frame.substr(sse_frame.size() - 2) == "\n\n");

    // 2. Verify unique 24-bit nonce_prefix assignment
    const uint32_t prefix1 =
        job1.find_value("nonce_prefix").getInt<uint32_t>();
    const uint32_t prefix2 =
        job2.find_value("nonce_prefix").getInt<uint32_t>();
    BOOST_CHECK_EQUAL(prefix1, 1U);
    BOOST_CHECK_EQUAL(prefix2, 2U);

    CBlockHeader hdr1;
    BOOST_REQUIRE(
        DecodeHexBlockHeader(hdr1, job1.find_value("header_hex").get_str()));
    BOOST_CHECK_EQUAL(hdr1.nNonce, static_cast<uint64_t>(prefix1) << 40);

    // 3. Test automatic vardiff tightening on rapid share arrivals (< target_spacing)
    const uint64_t job1_id = job1.find_value("job_id_num").getInt<uint64_t>();
    const uint256 initial_target =
        uint256S(job1.find_value("share_target").get_str());
    const uint256 net_target =
        uint256S(job1.find_value("network_target").get_str());

    uint64_t local_cursor = 1;
    uint256 current_target = initial_target;
    for (int i = 0; i < 3; ++i) {
        const uint64_t share_nonce =
            FindShareNonce(hdr1, prefix1, current_target, net_target,
                           /*require_above_network_target=*/true, local_cursor);
        local_cursor = (share_nonce & 0xFFFFFFFFFFULL) + 1;
        auto res = pool.SubmitShare(config, m_node, job1_id, "worker_alpha",
                                    std::nullopt, share_nonce);
        BOOST_CHECK(res.accepted);
        BOOST_CHECK(!res.block_found);
        current_target = res.share_target;
    }

    // Because 3 shares arrived within 0ms (< 5000ms target spacing), vardiff
    // must have tightened (decreased) worker_alpha's share_target.
    BOOST_CHECK(UintToArith256(current_target) <
                UintToArith256(initial_target));
    const uint256 tightened_target = current_target;

    // 4. Advance mocktime by +30s (> 5s target spacing) and verify vardiff loosens
    for (int i = 0; i < 4; ++i) {
        SetMockTime(GetTime() + 30);
        // Ensure current_target is above net_target or find any valid share
        const bool can_stay_above_net =
            UintToArith256(current_target) > UintToArith256(net_target);
        if (!can_stay_above_net) {
            pool.SetWorkerShareTarget("worker_alpha", initial_target, config);
            current_target = initial_target;
        }
        const uint64_t slow_nonce =
            FindShareNonce(hdr1, prefix1, current_target, net_target,
                           /*require_above_network_target=*/true, local_cursor);
        local_cursor = (slow_nonce & 0xFFFFFFFFFFULL) + 1;
        auto res = pool.SubmitShare(config, m_node, job1_id, "worker_alpha",
                                    std::nullopt, slow_nonce);
        BOOST_CHECK(res.accepted);
        current_target = res.share_target;
    }
    BOOST_CHECK(UintToArith256(current_target) >
                UintToArith256(tightened_target));
}

BOOST_AUTO_TEST_CASE(share_validation_accept_duplicate_and_high_hash) {
    const Config &config = GetConfig();
    auto pool_ptr = node::GetMiningPool(m_node);
    auto &pool = *pool_ptr;
    pool.Reset();
    pool.Configure(*m_node.args, config);

    const UniValue job =
        pool.GetMiningJobJSON(config, m_node, "validator_worker");
    const std::string job_id_str = job.find_value("job_id").get_str();
    const uint32_t prefix =
        job.find_value("nonce_prefix").getInt<uint32_t>();
    const uint256 share_target =
        uint256S(job.find_value("share_target").get_str());
    const uint256 net_target =
        uint256S(job.find_value("network_target").get_str());

    CBlockHeader hdr;
    BOOST_REQUIRE(
        DecodeHexBlockHeader(hdr, job.find_value("header_hex").get_str()));

    // 1. Valid share -> accepted
    const uint64_t valid_nonce =
        FindShareNonce(hdr, prefix, share_target, net_target,
                       /*require_above_network_target=*/true, 1);

    JSONRPCRequest submit_req;
    submit_req.context = &m_node;
    submit_req.strMethod = "submitminingshare";
    submit_req.params = UniValue(UniValue::VARR);
    submit_req.params.push_back(job_id_str);
    submit_req.params.push_back("validator_worker");
    submit_req.params.push_back(valid_nonce);

    const UniValue res_valid = tableRPC.execute(config, submit_req);
    BOOST_CHECK_EQUAL(res_valid.find_value("accepted").get_bool(), true);
    BOOST_CHECK_EQUAL(res_valid.find_value("accepted_shares").getInt<uint64_t>(),
                      1U);

    // 2. Duplicate share (same job_id + nonce) -> rejected with "duplicate-share"
    const UniValue res_dup = tableRPC.execute(config, submit_req);
    BOOST_CHECK_EQUAL(res_dup.find_value("accepted").get_bool(), false);
    BOOST_CHECK_EQUAL(res_dup.find_value("reason").get_str(),
                      "duplicate-share");
    BOOST_CHECK_EQUAL(res_dup.find_value("rejected_shares").getInt<uint64_t>(),
                      1U);

    // 3. High-hash share -> rejected with "high-hash"
    const uint256 updated_target =
        uint256S(res_valid.find_value("share_target").get_str());
    const uint64_t high_hash_nonce =
        FindHighHashNonce(hdr, prefix, updated_target, 5000);

    JSONRPCRequest high_req;
    high_req.context = &m_node;
    high_req.strMethod = "submitminingshare";
    high_req.params = UniValue(UniValue::VARR);
    high_req.params.push_back(job_id_str);
    high_req.params.push_back("validator_worker");
    high_req.params.push_back(high_hash_nonce);

    const UniValue res_high = tableRPC.execute(config, high_req);
    BOOST_CHECK_EQUAL(res_high.find_value("accepted").get_bool(), false);
    BOOST_CHECK_EQUAL(res_high.find_value("reason").get_str(), "high-hash");
    BOOST_CHECK_EQUAL(res_high.find_value("rejected_shares").getInt<uint64_t>(),
                      2U);

    // 4. Nonce prefix mismatch -> rejected with "nonce-prefix-mismatch"
    const uint64_t wrong_prefix_nonce =
        (static_cast<uint64_t>(prefix + 99) << 40) | 42ULL;
    JSONRPCRequest prefix_req;
    prefix_req.context = &m_node;
    prefix_req.strMethod = "submitminingshare";
    prefix_req.params = UniValue(UniValue::VARR);
    prefix_req.params.push_back(job_id_str);
    prefix_req.params.push_back("validator_worker");
    prefix_req.params.push_back(wrong_prefix_nonce);

    const UniValue res_prefix = tableRPC.execute(config, prefix_req);
    BOOST_CHECK_EQUAL(res_prefix.find_value("accepted").get_bool(), false);
    BOOST_CHECK_EQUAL(res_prefix.find_value("reason").get_str(),
                      "nonce-prefix-mismatch");
}

// Exercise the real job builder and the cached coinbase used by SubmitShare,
// rather than fabricating a transaction that bypasses pool payout assembly.
BOOST_AUTO_TEST_CASE(coinbase_outputs_survive_wire_round_trip) {
    const Config &config = GetConfig();
    auto pool_ptr = node::GetMiningPool(m_node);
    auto &pool = *pool_ptr;
    pool.Reset();
    const auto payout = AddressRoot(NativeAddress(coinbaseKey));
    pool.Configure(*m_node.args, config);
    lotus::v2::node::PoolJob cached;
    const UniValue job = pool.GetMiningJobJSON(config, m_node, "sub:wire", &cached);
    BOOST_REQUIRE(cached.coinbase_tx);
    const CTransaction &coinbase = *cached.coinbase_tx;
    DataStream stream;
    stream << coinbase;
    const auto serialized = HexStr(stream);
    const CTransaction decoded(deserialize, stream);
    BOOST_CHECK_EQUAL(decoded.GetId(), coinbase.GetId());
    BOOST_CHECK_EQUAL(decoded.GetHash(), coinbase.GetHash());
    BOOST_REQUIRE_EQUAL(decoded.vout.size(), coinbase.vout.size());
    BOOST_REQUIRE(!coinbase.vout.empty());
    BOOST_CHECK(coinbase.vout[0].vBranches == std::vector<lotus::v2::Hash32>{payout});
    BOOST_CHECK(decoded.vout[0].vBranches == std::vector<lotus::v2::Hash32>{payout});
    BOOST_CHECK_EQUAL(job.find_value("coinbase_tx_hex").get_str(), EncodeHexTx(coinbase));
    for (size_t i = 0; i < coinbase.vout.size(); ++i) {
        BOOST_CHECK(decoded.vout[i].scriptPubKey == coinbase.vout[i].scriptPubKey);
        BOOST_CHECK(decoded.vout[i] == coinbase.vout[i]);
        BOOST_CHECK(decoded.vout[i].ToV2Output() == coinbase.vout[i].ToV2Output());
    }
    DataStream reencoded;
    reencoded << decoded;
    BOOST_CHECK_EQUAL(HexStr(reencoded), serialized);
}

BOOST_AUTO_TEST_CASE(newsletter_subscriber_worker_credits_and_routing) {
    const Config &config = GetConfig();
    auto pool_ptr = node::GetMiningPool(m_node);
    auto &pool = *pool_ptr;
    pool.Reset();

    // Configure -pooladdress to a known pool operator destination
    CKey poolKey;
    poolKey.MakeNewKey(true);
    const std::string poolAddr = NativeAddress(poolKey);
    m_node.args->ForceSetArg("-pooladdress", poolAddr);
    pool.Configure(*m_node.args, config);

    const UniValue job = pool.GetMiningJobJSON(config, m_node, "sub:alice");
    const uint64_t job_id = job.find_value("job_id_num").getInt<uint64_t>();
    const uint32_t prefix =
        job.find_value("nonce_prefix").getInt<uint32_t>();
    const uint256 share_target =
        uint256S(job.find_value("share_target").get_str());
    const uint256 net_target =
        uint256S(job.find_value("network_target").get_str());

    // Verify that sub:alice's coinbase payout is routed to -pooladdress
    const UniValue &cb_outs = job.find_value("coinbase_outputs");
    BOOST_REQUIRE(cb_outs.isArray() && cb_outs.size() >= 1);
    BOOST_CHECK(OutputPaysAddress(cb_outs[0], poolAddr));

    CBlockHeader hdr;
    BOOST_REQUIRE(
        DecodeHexBlockHeader(hdr, job.find_value("header_hex").get_str()));

    uint64_t cursor = 1;
    for (int i = 0; i < 2; ++i) {
        SetMockTime(GetTime() + 5);
        const uint64_t nonce =
            FindShareNonce(hdr, prefix, share_target, net_target,
                           /*require_above_network_target=*/true, cursor);
        cursor = (nonce & 0xFFFFFFFFFFULL) + 1;
        const auto res = pool.SubmitShare(config, m_node, job_id, "sub:alice",
                                          std::nullopt, nonce);
        BOOST_CHECK(res.accepted);
    }

    // Query getpoolworker("sub:alice") via RPC
    JSONRPCRequest wreq;
    wreq.context = &m_node;
    wreq.strMethod = "getpoolworker";
    wreq.params = UniValue(UniValue::VARR);
    wreq.params.push_back("sub:alice");
    const UniValue wstats = tableRPC.execute(config, wreq);

    BOOST_CHECK_EQUAL(wstats.find_value("worker_id").get_str(), "sub:alice");
    BOOST_CHECK_EQUAL(
        wstats.find_value("is_newsletter_subscriber").get_bool(), true);
    BOOST_CHECK_EQUAL(
        wstats.find_value("accepted_shares").getInt<uint64_t>(), 2U);
    BOOST_CHECK_GT(wstats.find_value("cumulative_work").get_real(), 0.0);
    BOOST_CHECK_GT(wstats.find_value("pplns_weight").get_real(), 0.0);
    BOOST_CHECK_GT(
        wstats.find_value("newsletter_credits_usd_cents").get_real(), 0.0);
    BOOST_CHECK_EQUAL(
        wstats.find_value("subscription_unlocked").get_bool(), true);
}

BOOST_AUTO_TEST_CASE(pplns_multi_worker_coinbase_splitting_and_block_discovery) {
    const Config &config = GetConfig();
    const Consensus::Params &consensusParams =
        config.GetChainParams().GetConsensus();
    auto pool_ptr = node::GetMiningPool(m_node);
    auto &pool = *pool_ptr;
    pool.Reset();
    pool.Configure(*m_node.args, config);

    // Create two distinct miner addresses for PPLNS reward splitting
    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    const std::string addrA =
        NativeAddress(keyA);
    const std::string addrB =
        NativeAddress(keyB);

    const UniValue jobA = pool.GetMiningJobJSON(config, m_node, addrA);
    const UniValue jobB = pool.GetMiningJobJSON(config, m_node, addrB);

    const uint64_t jobA_id = jobA.find_value("job_id_num").getInt<uint64_t>();
    const uint64_t jobB_id = jobB.find_value("job_id_num").getInt<uint64_t>();
    const uint32_t prefixA = jobA.find_value("nonce_prefix").getInt<uint32_t>();
    const uint32_t prefixB = jobB.find_value("nonce_prefix").getInt<uint32_t>();
    const uint256 share_target =
        uint256S(jobA.find_value("share_target").get_str());
    const uint256 net_target =
        uint256S(jobA.find_value("network_target").get_str());

    CBlockHeader hdrA, hdrB;
    BOOST_REQUIRE(
        DecodeHexBlockHeader(hdrA, jobA.find_value("header_hex").get_str()));
    BOOST_REQUIRE(
        DecodeHexBlockHeader(hdrB, jobB.find_value("header_hex").get_str()));

    // Miner A submits 3 shares spaced by 5s (keeping share_target constant at initial)
    uint64_t cursorA = 1;
    for (int i = 0; i < 3; ++i) {
        SetMockTime(GetTime() + 5);
        pool.SetWorkerShareTarget(addrA, share_target, config);
        const uint64_t nonceA =
            FindShareNonce(hdrA, prefixA, share_target, net_target,
                           /*require_above_network_target=*/true, cursorA);
        cursorA = (nonceA & 0xFFFFFFFFFFULL) + 1;
        const auto resA = pool.SubmitShare(config, m_node, jobA_id, addrA,
                                           std::nullopt, nonceA);
        BOOST_REQUIRE(resA.accepted);
        BOOST_REQUIRE(!resA.block_found);
    }

    // Miner B submits 1 share with the same share_target
    SetMockTime(GetTime() + 5);
    pool.SetWorkerShareTarget(addrB, share_target, config);
    const uint64_t nonceB =
        FindShareNonce(hdrB, prefixB, share_target, net_target,
                       /*require_above_network_target=*/true, 1);
    const auto resB = pool.SubmitShare(config, m_node, jobB_id, addrB,
                                       std::nullopt, nonceB);
    BOOST_REQUIRE(resB.accepted);
    BOOST_REQUIRE(!resB.block_found);

    // Generate a new mining job and verify 75% / 25% PPLNS coinbase output split
    const UniValue split_job = pool.GetMiningJobJSON(config, m_node, addrA);
    const UniValue &outputs = split_job.find_value("coinbase_outputs");
    BOOST_REQUIRE(outputs.isArray());
    BOOST_REQUIRE_GE(outputs.size(), 2U);

    int64_t satsA = 0;
    int64_t satsB = 0;
    int64_t totalPayout = 0;
    for (size_t i = 0; i < outputs.size(); ++i) {
        const int64_t val = outputs[i].find_value("value_sats").getInt<int64_t>();
        totalPayout += val;
        if (OutputPaysAddress(outputs[i], addrA)) {
            satsA += val;
        } else if (OutputPaysAddress(outputs[i], addrB)) {
            satsB += val;
        }
    }
    BOOST_CHECK_GT(satsA, 0);
    BOOST_CHECK_GT(satsB, 0);
    BOOST_CHECK_EQUAL(satsA, 3 * satsB);
    BOOST_CHECK_EQUAL(satsA + satsB, totalPayout);

    // 5. Full block discovery: solve a network-target nonce on split_job and submit
    CBlockHeader split_hdr;
    BOOST_REQUIRE(DecodeHexBlockHeader(
        split_hdr, split_job.find_value("header_hex").get_str()));
    const uint64_t split_job_id =
        split_job.find_value("job_id_num").getInt<uint64_t>();
    const uint256 split_share_target =
        uint256S(split_job.find_value("share_target").get_str());
    const uint256 split_net_target =
        uint256S(split_job.find_value("network_target").get_str());

    const uint64_t block_nonce =
        FindShareNonce(split_hdr, prefixA, split_share_target, split_net_target,
                       /*require_above_network_target=*/false, 1);
    split_hdr.nNonce = block_nonce;
    const BlockHash expected_block_hash = split_hdr.GetHash();
    BOOST_REQUIRE(CheckProofOfWork(expected_block_hash, split_hdr.nBits,
                                   consensusParams));

    JSONRPCRequest solve_req;
    solve_req.context = &m_node;
    solve_req.strMethod = "submitminingshare";
    solve_req.params = UniValue(UniValue::VARR);
    solve_req.params.push_back(split_job_id);
    solve_req.params.push_back(addrA);
    solve_req.params.push_back(block_nonce);

    const UniValue solve_res = tableRPC.execute(config, solve_req);
    BOOST_CHECK_EQUAL(solve_res.find_value("accepted").get_bool(), true);
    BOOST_CHECK_EQUAL(solve_res.find_value("block_found").get_bool(), true);
    BOOST_CHECK_EQUAL(solve_res.find_value("block_hash").get_str(),
                      expected_block_hash.GetHex());

    // Verify the block was sealed and connected to the active regtest chain
    {
        LOCK(cs_main);
        const CBlockIndex *tip = m_node.chainman->ActiveTip();
        BOOST_REQUIRE(tip != nullptr);
        BOOST_CHECK_EQUAL(tip->nHeight, 101);
        BOOST_CHECK_EQUAL(tip->GetBlockHash(), expected_block_hash);
    }

    // Verify getpoolinfo reflects the newly discovered block
    JSONRPCRequest info_req;
    info_req.context = &m_node;
    info_req.strMethod = "getpoolinfo";
    info_req.params = UniValue(UniValue::VARR);
    const UniValue pool_info = tableRPC.execute(config, info_req);
    BOOST_CHECK_EQUAL(pool_info.find_value("blocks_found").getInt<uint64_t>(),
                      1U);
    BOOST_CHECK_EQUAL(
        pool_info.find_value("pplns_window_shares").getInt<uint64_t>(), 5U);
}

// Startup publication is per node. Neither an RPC-disabled nor an explicitly
// pool-disabled node instantiates the service; restarting creates fresh state.
BOOST_AUTO_TEST_CASE(node_owned_runtime_activation_and_isolation) {
    const Config &config = GetConfig();
    ArgsManager args_a, args_b;
    node::NodeContext a, b;
    a.args = &args_a;
    b.args = &args_b;
    node::StartMiningPool(a, config);
    BOOST_CHECK(!node::GetMiningPool(a));
    args_a.ForceSetArg("-server", "1");
    args_a.ForceSetArg("-miningpool", "0");
    node::StartMiningPool(a, config);
    BOOST_CHECK(!node::GetMiningPool(a));

    JSONRPCRequest request;
    request.context = &a;
    request.strMethod = "getpoolinfo";
    request.params = UniValue(UniValue::VARR);
    BOOST_CHECK_EXCEPTION(
        tableRPC.execute(config, request), UniValue, [](const UniValue &error) {
            return error.find_value("code").getInt<int>() == RPC_MISC_ERROR &&
                   error.find_value("message").get_str() ==
                       "Built-in mining pool is disabled";
        });
    args_a.ForceSetArg("-miningpool", "1");
    BOOST_CHECK_EXCEPTION(tableRPC.execute(config, request), UniValue,
                          [](const UniValue &error) {
                              return error.find_value("message").get_str() ==
                                     "Built-in mining pool is unavailable";
                          });
    args_a.ForceSetArg("-pooladdress", NativeAddress(coinbaseKey));
    args_b.ForceSetArg("-pooladdress", NativeAddress(coinbaseKey));
    args_b.ForceSetArg("-server", "1");
    args_b.ForceSetArg("-poolpplnswindow", "17");
    node::StartMiningPool(a, config);
    node::StartMiningPool(b,
                          config); // Default on, without explicit -miningpool.
    auto pa = node::GetMiningPool(a), pb = node::GetMiningPool(b);
    BOOST_REQUIRE(pa);
    BOOST_REQUIRE(pb);
    BOOST_CHECK(pa != pb);
    pa->SetWorkerShareTarget("isolated", uint256S("1234"), config);
    pa->SetPPLNSWindowSize(9);
    BOOST_CHECK_EQUAL(
        pa->GetPoolInfoJSON().find_value("active_workers").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        pb->GetPoolInfoJSON().find_value("active_workers").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(
        pb->GetPoolInfoJSON().find_value("pplns_window_max").getInt<int>(), 17);
    BOOST_CHECK_EQUAL(tableRPC.execute(config, request)
                          .find_value("pplns_window_max")
                          .getInt<int>(),
                      9);
    BOOST_CHECK_THROW(node::StartMiningPool(a, config), std::logic_error);
    node::InterruptMiningPool(a);
    BOOST_CHECK(!pa->IsEnabled());
    BOOST_CHECK(pb->IsEnabled());
    node::StopMiningPool(a);
    node::StopMiningPool(a); // Partial startup/shutdown is idempotent.
    BOOST_CHECK(!node::GetMiningPool(a));
    node::StartMiningPool(a, config);
    BOOST_CHECK(node::GetMiningPool(a) != pa);
    BOOST_CHECK_EQUAL(node::GetMiningPool(a)
                          ->GetPoolInfoJSON()
                          .find_value("active_workers")
                          .getInt<int>(),
                      0);
    BOOST_CHECK_EQUAL(node::GetMiningPool(a)
                          ->GetPoolInfoJSON()
                          .find_value("pplns_window_max")
                          .getInt<int>(),
                      1000);
}

BOOST_AUTO_TEST_CASE(concurrent_jobs_shares_configuration_and_stats) {
    const Config &config = GetConfig();
    auto pool = node::GetMiningPool(m_node);
    const auto job = pool->GetMiningJobJSON(config, m_node, "concurrent");
    CBlockHeader header;
    BOOST_REQUIRE(
        DecodeHexBlockHeader(header, job.find_value("header_hex").get_str()));
    const auto share_target =
        uint256S(job.find_value("share_target").get_str());
    const auto net_target =
        uint256S(job.find_value("network_target").get_str());
    const auto nonce = FindShareNonce(
        header, job.find_value("nonce_prefix").getInt<uint32_t>(), share_target,
        net_target, true);
    const auto job_id = job.find_value("job_id_num").getInt<uint64_t>();
    std::atomic<bool> go{false};
    std::atomic<int> accepted{0}, duplicate{0}, errors{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            while (!go.load())
                std::this_thread::yield();
            try {
                auto result = pool->SubmitShare(
                    config, m_node, job_id, "concurrent", std::nullopt, nonce);
                if (result.accepted)
                    ++accepted;
                else if (result.reason == "duplicate-share")
                    ++duplicate;
                else
                    ++errors;
            } catch (...) {
                ++errors;
            }
        });
    }
    threads.emplace_back([&] {
        while (!go.load())
            std::this_thread::yield();
        try {
            for (int i = 0; i < 20; ++i) {
                pool->GetMiningJobJSON(config, m_node, "concurrent");
                pool->GetWorkerStatsJSON("concurrent");
                pool->GetPoolInfoJSON();
            }
        } catch (...) {
            ++errors;
        }
    });
    threads.emplace_back([&] {
        while (!go.load())
            std::this_thread::yield();
        try {
            ArgsManager local;
            local.ForceSetArg("-poolpplnswindow", "1000");
            for (int i = 0; i < 20; ++i) {
                try {
                    pool->Configure(local, config);
                    ++errors;
                } catch (const std::logic_error &error) {
                    if (std::string(error.what()) !=
                        "Mining pool configuration is frozen after first use") ++errors;
                }
                pool->SetTargetSpacingSec(5);
                pool->SetPPLNSWindowSize(1000);
            }
        } catch (...) {
            ++errors;
        }
    });
    go = true;
    for (auto &thread : threads)
        thread.join();
    BOOST_CHECK_EQUAL(errors.load(), 0);
    BOOST_CHECK_EQUAL(accepted.load(), 1);
    BOOST_CHECK_EQUAL(duplicate.load(), 7);
    BOOST_CHECK_EQUAL(pool->GetPoolInfoJSON()
                          .find_value("total_accepted_shares")
                          .getInt<int>(),
                      1);
    BOOST_CHECK_EQUAL(
        pool->GetPoolInfoJSON().find_value("pplns_window_shares").getInt<int>(),
        1);
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(),
                          100); // Share is deliberately not a block.
    }
}

BOOST_AUTO_TEST_CASE(concurrent_block_candidates_claim_submission_once) {
    const Config &config = GetConfig();
    auto pool = node::GetMiningPool(m_node);
    const auto job = pool->GetMiningJobJSON(config, m_node, "block-claim");
    CBlockHeader header;
    BOOST_REQUIRE(
        DecodeHexBlockHeader(header, job.find_value("header_hex").get_str()));
    const auto share_target =
        uint256S(job.find_value("share_target").get_str());
    const auto net_target =
        uint256S(job.find_value("network_target").get_str());
    const auto prefix = job.find_value("nonce_prefix").getInt<uint32_t>();
    const auto first_nonce =
        FindShareNonce(header, prefix, share_target, net_target, false);
    const auto second_nonce =
        FindShareNonce(header, prefix, share_target, net_target, false,
                       (first_nonce & 0xFFFFFFFFFFULL) + 1);
    const auto job_id = job.find_value("job_id_num").getInt<uint64_t>();
    std::future<lotus::v2::node::ShareSubmissionResult> first, second;
    {
        LOCK(cs_main);
        first = std::async(std::launch::async, [&] {
            return pool->SubmitShare(config, m_node, job_id, "block-claim",
                                     std::nullopt, first_nonce);
        });
        second = std::async(std::launch::async, [&] {
            return pool->SubmitShare(config, m_node, job_id, "block-claim",
                                     std::nullopt, second_nonce);
        });
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while ((pool->GetPoolInfoJSON()
                        .find_value("total_accepted_shares")
                        .getInt<int>() < 2 ||
                pool->GetPoolInfoJSON()
                        .find_value("active_operations")
                        .getInt<int>() != 1) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        BOOST_CHECK_EQUAL(pool->GetPoolInfoJSON()
                              .find_value("total_accepted_shares")
                              .getInt<int>(),
                          2);
        // Both shares are accounted for, but only the claimed block waits on
        // cs_main.
        BOOST_CHECK_EQUAL(pool->GetPoolInfoJSON()
                              .find_value("active_operations")
                              .getInt<int>(),
                          1);
        BOOST_CHECK_EQUAL(
            pool->GetPoolInfoJSON().find_value("blocks_found").getInt<int>(),
            0);
    }
    const auto a = first.get(), b = second.get();
    BOOST_CHECK(a.accepted);
    BOOST_CHECK(b.accepted);
    BOOST_CHECK_EQUAL(int(a.block_found) + int(b.block_found), 1);
    BOOST_CHECK_EQUAL(
        pool->GetPoolInfoJSON().find_value("blocks_found").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        pool->GetPoolInfoJSON().find_value("pplns_window_shares").getInt<int>(),
        2);
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(), 101);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                          a.block_found ? a.block_hash : b.block_hash);
    }
}

// Hold cs_main so a real job request remains in flight. Stop must wait for it,
// while new requests are rejected, without acquiring cs_main under the pool
// lock.
BOOST_AUTO_TEST_CASE(shutdown_drains_node_dependent_work) {
    const Config &config = GetConfig();
    auto pool = node::GetMiningPool(m_node);
    std::future<UniValue> job;
    std::future<void> stop;
    {
        LOCK(cs_main);
        job = std::async(std::launch::async, [&] {
            return pool->GetMiningJobJSON(config, m_node, "draining");
        });
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (pool->GetPoolInfoJSON()
                       .find_value("active_operations")
                       .getInt<int>() == 0 &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        BOOST_CHECK_EQUAL(pool->GetPoolInfoJSON()
                              .find_value("active_operations")
                              .getInt<int>(),
                          1);
        BOOST_CHECK_THROW(pool->Reset(), std::logic_error);
        node::InterruptMiningPool(m_node);
        stop = std::async(std::launch::async,
                          [&] { node::StopMiningPool(m_node); });
        BOOST_CHECK(stop.wait_for(std::chrono::milliseconds(50)) ==
                    std::future_status::timeout);
        BOOST_CHECK_THROW(pool->GetMiningJobJSON(config, m_node, "late"),
                          std::runtime_error);
    }
    BOOST_CHECK(!job.get().isNull());
    stop.get();
    BOOST_CHECK(!node::GetMiningPool(m_node));
    BOOST_CHECK(!pool->IsEnabled());
    BOOST_CHECK_EQUAL(
        pool->GetPoolInfoJSON().find_value("active_operations").getInt<int>(),
        0);
    BOOST_CHECK_THROW(
        pool->SubmitShare(config, m_node, 1, "late", std::nullopt, 0),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
