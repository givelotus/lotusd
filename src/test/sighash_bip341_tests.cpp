// Copyright (c) 2012-2019 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <hash.h>
#include <script/script.h>
#include <script/standard.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sighash_bip341_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(prepare_spent_outputs) {
    LOCK(cs_main);
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);

    CMutableTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_1));
    txFrom.vout[0].nValue = 1000 * SATOSHI;

    AddCoins(coins, CTransaction(txFrom), 0);

    CMutableTransaction txTo;
    txTo.vin.resize(1);
    txTo.vin[0].prevout = COutPoint(txFrom.GetId(), 0);
    txTo.vout.resize(1);
    txTo.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_2));
    txTo.vout[0].nValue = 3000 * SATOSHI;

    PrecomputedTransactionData txdata =
        PrecomputedTransactionData::FromCoinsView(txTo, coins);
    BOOST_CHECK(txdata.m_spent_outputs == txFrom.vout);
}

BOOST_AUTO_TEST_SUITE_END()
