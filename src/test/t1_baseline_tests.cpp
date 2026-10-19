// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Golden values pinned before the legacy bridge (T1) changes transaction
// formats. Later commits change these only where their plan says so, and
// say why in the test that changes.

#include <chainparams.h>
#include <coins.h>
#include <hash.h>
#include <lotus_v2/sparse_state.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(t1_baseline_tests, BasicTestingSetup)

namespace {
/** A pure v7 transaction: one OP_TRUE spend, one V0-leaf output. */
lotus::v2::Transaction PureV7Fixture() {
    lotus::v2::Transaction tx;
    tx.lock = 0;
    lotus::v2::Input in;
    in.prev_txid.fill(0x11);
    in.prev_index = 3;
    in.sequence = 0xffffffff;
    in.flags = 1;
    in.witnesses.push_back({{0x4e}, {}, {}});
    tx.inputs.push_back(in);
    lotus::v2::Output out;
    out.value = 12345;
    out.branches.push_back(lotus::v2::BranchLeaf(std::vector<uint8_t>{0x4e}));
    out.paths.push_back({0});
    tx.outputs.push_back(out);
    return tx;
}

/** A legacy (eCash-format) version 2 P2PKH spend. */
CMutableTransaction LegacyFixture() {
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(
        COutPoint(TxId(uint256S("0000000000000000000000000000000000000000000"
                                "000000000000000000001")),
                  1),
        CScript() << std::vector<uint8_t>(72, 0x30)
                  << std::vector<uint8_t>(33, 0x02),
        0xfffffffe);
    mtx.vout.emplace_back(
        4999 * COIN / 100,
        CScript() << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0xab)
                  << OP_EQUALVERIFY << OP_CHECKSIG);
    mtx.nLockTime = 100;
    return mtx;
}

const std::string kLegacyBytes =
    "0200000001010000000000000000000000000000000000000000000000000000000000"
    "0000010000006b48303030303030303030303030303030303030303030303030303030"
    "3030303030303030303030303030303030303030303030303030303030303030303030"
    "3030303030303030303021020202020202020202020202020202020202020202020202"
    "020202020202020202feffffff01c0aff629010000001976a914ababababababababab"
    "ababababababababababab88ac64000000";

std::string LegacyBytes(const CMutableTransaction &mtx) {
    // The eCash grammar, written field by field so this does not depend on
    // the transaction serializer under test.
    DataStream s{};
    s << mtx.nVersion;
    WriteCompactSize(s, mtx.vin.size());
    for (const CTxIn &in : mtx.vin) s << in.prevout << in.scriptSig << in.nSequence;
    WriteCompactSize(s, mtx.vout.size());
    for (const CTxOut &out : mtx.vout) s << out.nValue << out.scriptPubKey;
    s << mtx.nLockTime;
    return HexStr(s);
}
} // namespace

BOOST_AUTO_TEST_CASE(regtest_genesis) {
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const CBlock &genesis = params->GenesisBlock();
    BOOST_TEST_MESSAGE("regtest genesis " << genesis.GetHash().GetHex()
                                          << " merkle "
                                          << genesis.hashMerkleRoot.GetHex());
    BOOST_CHECK_EQUAL(genesis.GetHash().GetHex(), "078419172a86430dea899ecec3abd6c4ad8b56fbadc617aacd5b71d1a9038cb6");
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.GetHex(), "ab7a9a3a45e6decf448edff44e2904ba8531902e11e5bc8a7bf8833661220aca");
}

BOOST_AUTO_TEST_CASE(pure_v7_identities) {
    const CTransaction tx(CMutableTransaction::FromV2Transaction(PureV7Fixture()));
    BOOST_TEST_MESSAGE("v7 txid " << tx.GetId().GetHex() << " txhash "
                                  << tx.GetHash().GetHex());
    BOOST_CHECK_EQUAL(tx.GetId().GetHex(), "de22c4a6b33f539a56a5f6c4edfa74ccc6a56f0639e8f8b520be511b61f9e442");
    BOOST_CHECK_EQUAL(tx.GetHash().GetHex(), "8c9ea1119c2f9cb5d80c99647d4589124fd4bf6bdf7461629f4777f3c52c348c");
}

BOOST_AUTO_TEST_CASE(legacy_serialization_and_sha256d) {
    const CMutableTransaction mtx = LegacyFixture();
    const std::string bytes = LegacyBytes(mtx);
    const uint256 sha256d = Hash(ParseHex(bytes));
    BOOST_TEST_MESSAGE("legacy bytes " << bytes << " sha256d "
                                       << sha256d.GetHex());
    BOOST_CHECK_EQUAL(bytes, kLegacyBytes);
    // The node writes a version 2 transaction in the same grammar.
    DataStream node_bytes{};
    node_bytes << mtx;
    BOOST_CHECK_EQUAL(HexStr(node_bytes), kLegacyBytes);
    BOOST_CHECK_EQUAL(sha256d.GetHex(), "1a9706df1ec40d24c122884a6b651d541a247a71f150691ad2dda1ddd532c368");
}

BOOST_AUTO_TEST_CASE(legacy_state_coin_encoding) {
    lotus::v2::Coin coin;
    coin.outpoint.tx_id.fill(0x22);
    coin.outpoint.index = 1;
    coin.output.value = 5000;
    const CMutableTransaction mtx = LegacyFixture();
    coin.output.legacy_script.emplace(mtx.vout[0].scriptPubKey.begin(),
                                      mtx.vout[0].scriptPubKey.end());
    coin.creation_height = 7;
    coin.creation_parent_mtp = 1'700'000'000;
    coin.coinbase = true;
    std::vector<uint8_t> encoded;
    BOOST_REQUIRE(lotus::v2::EncodeCoin(coin, encoded));
    BOOST_TEST_MESSAGE("legacy state coin " << HexStr(encoded));
    // The record ends with the coin provenance trailer of this stack's coin
    // format (native_coin_provenance_tests).
    BOOST_CHECK_EQUAL(HexStr(encoded), "222222222222222222222222222222222222222222222222222222222222222201000000238088130000000000001976a914abababababababababababababababababababab88ac070000000000000000f15365000000000102000000000000000007cd400100000000");
}

BOOST_AUTO_TEST_CASE(coin_serialization) {
    const CMutableTransaction mtx = LegacyFixture();
    const Coin coin(mtx.vout[0], 4096, true);
    DataStream s{};
    s << coin;
    BOOST_TEST_MESSAGE("coin " << HexStr(s));
    // This stack's coins-database record: format magic, the compressed
    // height/coinbase code and output, then the coin provenance fields.
    BOOST_CHECK_EQUAL(HexStr(s), "58504932bf0181de4500abababababababababababababababababababab000000000000000000dd400100000000");
}

BOOST_AUTO_TEST_SUITE_END()
