// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <merkleblock.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(merkleblock_tests, BasicTestingSetup)

static uint256 ExpectedPartialMerkleRoot(const CBlock &block) {
    std::vector<uint256> leaves;
    leaves.reserve(block.vtx.size());
    for (const auto &tx : block.vtx) {
        leaves.push_back(tx->GetId());
    }
    return ComputeMerkleRoot(std::move(leaves));
}

/**
 * Create a CMerkleBlock using a list of txids which will be found in the
 * given block.
 */
BOOST_AUTO_TEST_CASE(merkleblock_construct_from_txids_found) {
    CBlock block = getBlock13b8a();

    std::set<TxId> txids;

    // Last txn in block.
    TxId txid1(uint256S("0x27fbcc889495538e02d451319c18d5d3543419125fa16e8ee56949bed3be67e3"));

    // Second txn in block.
    TxId txid2(uint256S("0xe580c0745af200f5a82548f4d7074c05fca53e62cd41c5fd4cc84b685c27b6d0"));

    txids.insert(txid1);
    txids.insert(txid2);

    CMerkleBlock merkleBlock(block, txids);

    BOOST_CHECK_EQUAL(merkleBlock.header.GetHash().GetHex(),
                      block.GetHash().GetHex());

    // vMatchedTxn is only used when bloom filter is specified.
    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 0U);

    std::vector<uint256> vMatched;
    std::vector<size_t> vIndex;

    BOOST_CHECK_EQUAL(merkleBlock.txn.ExtractMatches(vMatched, vIndex).GetHex(),
                      ExpectedPartialMerkleRoot(block).GetHex());
    BOOST_CHECK_EQUAL(vMatched.size(), 2U);

    // Ordered by occurrence in depth-first tree traversal.
    BOOST_CHECK_EQUAL(vMatched[0].ToString(), txid2.ToString());
    BOOST_CHECK_EQUAL(vIndex[0], 1U);

    BOOST_CHECK_EQUAL(vMatched[1].ToString(), txid1.ToString());
    BOOST_CHECK_EQUAL(vIndex[1], 8U);
}

/**
 * Create a CMerkleBlock using a list of txids which will not be found in the
 * given block.
 */
BOOST_AUTO_TEST_CASE(merkleblock_construct_from_txids_not_found) {
    CBlock block = getBlock13b8a();

    std::set<TxId> txids2;
    txids2.insert(TxId(uint256S(
        "0xc0ffee00003bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20")));
    CMerkleBlock merkleBlock(block, txids2);

    BOOST_CHECK_EQUAL(merkleBlock.header.GetHash().GetHex(),
                      block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 0U);

    std::vector<uint256> vMatched;
    std::vector<size_t> vIndex;

    BOOST_CHECK_EQUAL(merkleBlock.txn.ExtractMatches(vMatched, vIndex).GetHex(),
                      ExpectedPartialMerkleRoot(block).GetHex());
    BOOST_CHECK_EQUAL(vMatched.size(), 0U);
    BOOST_CHECK_EQUAL(vIndex.size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
