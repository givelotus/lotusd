// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <lotus_v2/fee_hysteresis.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>
#include <limits>
BOOST_FIXTURE_TEST_SUITE(fee_hysteresis_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(rolling_floor_cushion_and_reset) {
    lotus::v2::FeeHysteresisController ctrl;
    ctrl.SetRpcAdmissionRatePerKCu(4000, 1);
    ctrl.SetRpcAdmissionRatePerKCu(8000, 1000);
    BOOST_CHECK_EQUAL(ctrl.GetRpcAdmissionRatePerKCu(1000), 8000U);
    BOOST_CHECK_EQUAL(ctrl.GetP2pRelayRatePerKCu(1000), 1000U);
    BOOST_CHECK_EQUAL(ctrl.GetP2pRelayRatePerKCu(31001), 6800U);
    BOOST_CHECK_EQUAL(ctrl.GetRecommendedSdkRatePerKCu(31001), 8400U);
    BOOST_CHECK_EQUAL(ctrl.GetFeeRateInfo(31001).recommended_sdk_feerate_per_kcu, 8400U);
    BOOST_CHECK(ctrl.EvaluateTransactionFee(lotus::v2::FeeTier::RpcAdmission, 100, 800, 31001).accepted);
    BOOST_CHECK(!ctrl.EvaluateTransactionFee(lotus::v2::FeeTier::RpcAdmission, 100, 799, 31001).accepted);
    ctrl.Reset(32000);
    BOOST_CHECK_EQUAL(ctrl.GetRpcAdmissionRatePerKCu(32000), 1000U);
    BOOST_CHECK_EQUAL(ctrl.ComputeFeeForCu(1, 1), 1U);
}
BOOST_AUTO_TEST_CASE(large_congestion_and_cushion_saturate_without_wrapping) {
    const auto maximum = std::numeric_limits<uint64_t>::max();
    lotus::v2::FeeHysteresisController ctrl;
    const uint64_t target = uint64_t{1} << 32;
    BOOST_CHECK_EQUAL(ctrl.UpdateCongestion((uint64_t{1} << 63) + target, target, 0), maximum);
    lotus::v2::FeeHysteresisConfig config;
    config.sdk_cushion_permille = maximum;
    lotus::v2::FeeHysteresisController large_cushion(config);
    BOOST_CHECK_EQUAL(large_cushion.GetRecommendedSdkRatePerKCu(0), maximum);
    BOOST_CHECK_EQUAL(large_cushion.GetFeeRateInfo(0).recommended_sdk_feerate_per_kcu, maximum);
    BOOST_CHECK_EQUAL(ctrl.ComputeFeeForCu(maximum, maximum), maximum);
}
BOOST_AUTO_TEST_SUITE_END()
