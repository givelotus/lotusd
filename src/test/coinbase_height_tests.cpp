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
        return ContextualCheckCoinbaseHeight(block, state, Params().GetConsensus(),
                                             &prev);
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

BOOST_AUTO_TEST_CASE(vanity_prefix_before_loosening_rejected) {
    const int h = LOOSENED_FROM_HEIGHT - 1;
    BlockValidationState state;
    BOOST_CHECK(!TestBlock(h, EARLY_MTP, Vanity(h)).Check(state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-height");
}

// From height 1018000 until the 2026-12-21 upgrade, a coinbase without the
// "logos" prefix is accepted without any height check, so its height does not
// have to be committed and two such coinbases can share a txid. The network
// accepted blocks like this, so they stay valid.
BOOST_AUTO_TEST_CASE(vanity_prefix_after_loosening_accepted) {
    const int h = LOOSENED_FROM_HEIGHT;
    BOOST_CHECK(TestBlock(h, EARLY_MTP, Vanity(h)).Check());
    BOOST_CHECK(TestBlock(h, EARLY_MTP, Vanity(1)).Check());
}

BOOST_AUTO_TEST_SUITE_END()
