// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockindex.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>

namespace {
// Height from which Lotus 8.3.4 stopped checking the height of a coinbase
// whose first output does not carry the "logos" prefix.
constexpr int LOOSENED_FROM_HEIGHT = 1018000;

const std::vector<uint8_t> VANITY_PREFIX{'F', 'R', 'B', 'T', 'C'};

// A block at nHeight whose parent has the given median time past.
struct TestBlock {
    CBlockIndex prev;
    CBlock block;

    TestBlock(int nHeight, int64_t prevMedianTimePast,
              const CScript &firstOutput) {
        // With no ancestors, the parent's median time past is its own time.
        prev.nHeight = nHeight - 1;
        prev.nTime = prevMedianTimePast;

        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout = COutPoint();
        coinbase.vin[0].scriptSig = CScript() << std::vector<uint8_t>(80);
        coinbase.vout.resize(2);
        coinbase.vout[0].scriptPubKey = firstOutput;
        coinbase.vout[1].scriptPubKey = CScript() << OP_TRUE;
        block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    }

    bool Check(BlockValidationState &state) const {
        return ContextualCheckCoinbaseHeight(block, state, &prev);
    }

    bool Check() const {
        BlockValidationState state;
        return Check(state);
    }
};

CScript Canonical(int nHeight) {
    return CScript() << OP_RETURN << COINBASE_PREFIX << nHeight;
}

CScript Vanity(int nHeight) {
    return CScript() << OP_RETURN << VANITY_PREFIX << nHeight;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(coinbase_height_tests, BasicTestingSetup)

// Median time past well before the 2026-12-21 network upgrade.
static constexpr int64_t EARLY_MTP = 1780000000;

BOOST_AUTO_TEST_CASE(canonical_coinbase_accepted) {
    for (const int h : {20000, LOOSENED_FROM_HEIGHT - 1, LOOSENED_FROM_HEIGHT,
                        LOOSENED_FROM_HEIGHT + 400000}) {
        BOOST_CHECK(TestBlock(h, EARLY_MTP, Canonical(h)).Check());
        // Data after the height is allowed.
        BOOST_CHECK(TestBlock(h, EARLY_MTP,
                              Canonical(h) << std::vector<uint8_t>{1, 2, 3})
                        .Check());
    }
}

BOOST_AUTO_TEST_CASE(wrong_height_rejected) {
    const int h = LOOSENED_FROM_HEIGHT + 1;
    BlockValidationState state;
    BOOST_CHECK(!TestBlock(h, EARLY_MTP, Canonical(h - 1)).Check(state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-height");
}

// The height commitment is required at every height. Lotus 8.3.4 stopped
// checking coinbases without the "logos" prefix from height 1018000, which left
// their txids free to repeat an earlier coinbase; that exemption is gone.
BOOST_AUTO_TEST_CASE(vanity_prefix_rejected) {
    for (const int h : {LOOSENED_FROM_HEIGHT - 1, LOOSENED_FROM_HEIGHT,
                        LOOSENED_FROM_HEIGHT + 400000}) {
        for (const int committed : {h, 1}) {
            BlockValidationState state;
            BOOST_CHECK(
                !TestBlock(h, EARLY_MTP, Vanity(committed)).Check(state));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-height");
        }
    }
}

// Below height 20000 the old rule did not check the height; it does now.
BOOST_AUTO_TEST_CASE(low_heights_checked) {
    const int h = 100;
    BOOST_CHECK(!TestBlock(h, EARLY_MTP, Canonical(h - 1)).Check());
    BOOST_CHECK(TestBlock(h, EARLY_MTP, Canonical(h)).Check());
}

BOOST_AUTO_TEST_CASE(malformed_coinbase_rejected) {
    const int h = LOOSENED_FROM_HEIGHT + 400000;

    BOOST_CHECK(!TestBlock(h, EARLY_MTP, CScript() << OP_TRUE).Check());
    BOOST_CHECK(!TestBlock(h, EARLY_MTP, CScript()).Check());
    BOOST_CHECK(
        !TestBlock(h, EARLY_MTP, CScript() << OP_RETURN << COINBASE_PREFIX)
             .Check());
    // Canonical prefix, wrong height.
    BOOST_CHECK(!TestBlock(h, EARLY_MTP, Canonical(h - 1)).Check());
}

// The 2nd Kings activation time itself is unchanged; the coinbase rule no
// longer depends on it.
BOOST_AUTO_TEST_CASE(second_kings_activation_time) {
    BOOST_CHECK_EQUAL(Params().GetConsensus().secondKingsActivationTime,
                      1797886200);
}

BOOST_AUTO_TEST_SUITE_END()
