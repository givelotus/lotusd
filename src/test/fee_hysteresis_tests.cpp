// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <boost/test/unit_test.hpp>
#include <chrono>
#include <future>
#include <vector>
#include <limits>
#include <lotus_v2/fee_hysteresis.h>
#include <test/util/setup_common.h>
#include <thread>
#include <util/time.h>

namespace lotus::v2 {
struct FeePolicyTestAccess {
    static std::unique_lock<std::mutex>
    Lock(FeeHysteresisController &controller) {
        return std::unique_lock<std::mutex>(controller.mutex_);
    }
};
} // namespace lotus::v2

namespace {
bool WaitForBacklog(lotus::v2::FeeHysteresisController &controller,
                    uint64_t bytes) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(3);
    do {
        if (controller.GetFeeRateInfo(0).mempool_backlog_bytes == bytes)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(fee_hysteresis_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(rolling_floor_cushion_and_reset) {
    lotus::v2::FeeHysteresisController ctrl;
    ctrl.SetRpcAdmissionRatePerKCu(4000, 1);
    ctrl.SetRpcAdmissionRatePerKCu(8000, 1000);
    BOOST_CHECK_EQUAL(ctrl.GetRpcAdmissionRatePerKCu(1000), 8000U);
    BOOST_CHECK_EQUAL(ctrl.GetP2pRelayRatePerKCu(1000), 1000U);
    BOOST_CHECK_EQUAL(ctrl.GetP2pRelayRatePerKCu(31001), 6800U);
    BOOST_CHECK_EQUAL(ctrl.GetRecommendedSdkRatePerKCu(31001), 8400U);
    BOOST_CHECK_EQUAL(
        ctrl.GetFeeRateInfo(31001).recommended_sdk_feerate_per_kcu, 8400U);
    BOOST_CHECK(ctrl.EvaluateTransactionFee(lotus::v2::FeeTier::RpcAdmission,
                                            100, 800, 31001)
                    .accepted);
    BOOST_CHECK(!ctrl.EvaluateTransactionFee(lotus::v2::FeeTier::RpcAdmission,
                                             100, 799, 31001)
                     .accepted);
    ctrl.Reset(32000);
    BOOST_CHECK_EQUAL(ctrl.GetRpcAdmissionRatePerKCu(32000), 1000U);
    BOOST_CHECK_EQUAL(ctrl.ComputeFeeForCu(1, 1), 1U);
}
BOOST_AUTO_TEST_CASE(large_congestion_and_cushion_saturate_without_wrapping) {
    const auto maximum = std::numeric_limits<uint64_t>::max();
    lotus::v2::FeeHysteresisController ctrl;
    const uint64_t target = uint64_t{1} << 32;
    BOOST_CHECK_EQUAL(
        ctrl.UpdateCongestion((uint64_t{1} << 63) + target, target, 0),
        maximum);
    lotus::v2::FeeHysteresisConfig config;
    config.sdk_cushion_permille = maximum;
    lotus::v2::FeeHysteresisController large_cushion(config);
    BOOST_CHECK_EQUAL(large_cushion.GetRecommendedSdkRatePerKCu(0), maximum);
    BOOST_CHECK_EQUAL(
        large_cushion.GetFeeRateInfo(0).recommended_sdk_feerate_per_kcu,
        maximum);
    BOOST_CHECK_EQUAL(ctrl.ComputeFeeForCu(maximum, maximum), maximum);
}
BOOST_AUTO_TEST_CASE(admission_scalar_read_does_not_wait_for_calculation) {
    lotus::v2::FeeHysteresisController controller;
    controller.SetRpcAdmissionRatePerKCu(123456789012345ULL, 0);
    auto held = lotus::v2::FeePolicyTestAccess::Lock(controller);
    auto reader = std::async(std::launch::async, [&] {
        return controller.GetRpcAdmissionRatePerKCu(1);
    });
    const auto status = reader.wait_for(std::chrono::milliseconds(500));
    held.unlock();
    BOOST_CHECK(status == std::future_status::ready);
    BOOST_CHECK_EQUAL(reader.get(), 123456789012345ULL);
}

BOOST_AUTO_TEST_CASE(worker_backlog_trace_matches_synchronous_local_policy) {
    lotus::v2::FeeHysteresisController controller, reference;
    lotus::v2::FeePolicyWorker worker(controller);
    const int64_t now =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    worker.Start();
    for (const uint64_t bytes :
         {40'000'000ULL, 70'000'000ULL, 1'000'000ULL, 0ULL}) {
        reference.RecordMempoolBacklog(bytes, now);
        worker.RecordBacklog(bytes, now);
        BOOST_REQUIRE(WaitForBacklog(controller, bytes));
        const auto info = controller.GetFeeRateInfo(now);
        const auto expected = reference.GetFeeRateInfo(now);
        BOOST_CHECK_EQUAL(controller.GetRpcAdmissionRatePerKCu(now),
                          expected.rpc_admission_feerate_per_kcu);
        BOOST_CHECK_EQUAL(info.recommended_sdk_feerate_per_kcu,
                          expected.recommended_sdk_feerate_per_kcu);
        BOOST_CHECK_EQUAL(info.p2p_relay_feerate_per_kcu,
                          expected.p2p_relay_feerate_per_kcu);
        BOOST_CHECK_EQUAL(info.adaptive_max_block_size,
                          expected.adaptive_max_block_size);
    }
    worker.Stop();
    BOOST_CHECK_EQUAL(worker.Failures(), 0);
}

BOOST_AUTO_TEST_CASE(queue_overflow_retains_latest_absolute_backlog_without_drift) {
    lotus::v2::FeeHysteresisController controller, reference;
    lotus::v2::FeePolicyWorker worker(controller);
    const int64_t now =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    // No consumer yet: exercise deterministic overflow, including removals and
    // clear.
    for (unsigned i = 0; i < 4096; ++i)
        worker.RecordBacklog(80'000'000 - i, now);
    worker.RecordBacklog(0, now);
    BOOST_CHECK_GT(worker.DroppedSamples(), 0);
    worker.Start();
    // The constructor's zero view is insufficient: wait for the queued high
    // samples and final zero to be applied by stopping/joining the worker.
    worker.Stop();
    BOOST_CHECK_EQUAL(controller.GetMempoolBacklogBytes(), 0);
    BOOST_CHECK_EQUAL(controller.GetRpcAdmissionRatePerKCu(now), 1000);
    BOOST_CHECK_EQUAL(worker.Failures(), 0);
}

BOOST_AUTO_TEST_CASE(old_generation_samples_do_not_repopulate_reorg_history) {
    lotus::v2::FeeHysteresisController controller, reference;
    lotus::v2::FeePolicyWorker worker(controller);
    const int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    // This low sample would wrongly lower P2P hysteresis if allowed to survive
    // the reset. The reset's own floor sample is deliberately outside its window.
    worker.RecordBacklog(0, now);
    controller.Reset(now - 31'001);
    reference.Reset(now - 31'001);
    worker.RecordBacklog(100'000'000, now);
    reference.RecordMempoolBacklog(100'000'000, now);
    worker.Start();
    worker.Stop();
    BOOST_CHECK_EQUAL(controller.GetMempoolBacklogBytes(), 100'000'000);
    BOOST_CHECK_EQUAL(controller.GetRpcAdmissionRatePerKCu(now), reference.GetRpcAdmissionRatePerKCu(now));
    BOOST_CHECK_EQUAL(controller.GetP2pRelayRatePerKCu(now), reference.GetP2pRelayRatePerKCu(now));
}

BOOST_AUTO_TEST_CASE(reset_without_new_producer_does_not_restore_old_backlog) {
    lotus::v2::FeeHysteresisController controller;
    lotus::v2::FeePolicyWorker worker(controller);
    const int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    worker.RecordBacklog(100'000'000, now);
    controller.Reset(now);
    worker.Start();
    worker.Stop();
    BOOST_CHECK_EQUAL(controller.GetMempoolBacklogBytes(), 0);
    BOOST_CHECK_EQUAL(controller.GetRpcAdmissionRatePerKCu(now), 1000);
}

BOOST_AUTO_TEST_CASE(concurrent_producers_and_repeated_worker_shutdown) {
    lotus::v2::FeeHysteresisController controller;
    lotus::v2::FeePolicyWorker worker(controller);
    const int64_t now =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    worker.Start();
    std::vector<std::thread> producers;
    for (unsigned i = 0; i < 4; ++i)
        producers.emplace_back([&, i] {
            for (unsigned n = 0; n < 4096; ++n)
                worker.RecordBacklog(40'000'000 + i * 4096 + n, now);
        });
    for (auto &producer : producers)
        producer.join();
    worker.RecordBacklog(123, now);
    BOOST_REQUIRE(WaitForBacklog(controller, 123));
    worker.Stop();
    worker.Stop();
    worker.Start();
    worker.RecordBacklog(0, now);
    BOOST_REQUIRE(WaitForBacklog(controller, 0));
    worker.Stop();
    BOOST_CHECK_EQUAL(worker.Failures(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
