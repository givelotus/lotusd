// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <lotus_v2/commitment.h>
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
    // Lotus V2 transaction ids commit to the active chain id, so take them
    // from the block instead of hard-coding them.
    const TxId txid1 = block.vtx.back()->GetId();

    // Second txn in block.
    const TxId txid2 = block.vtx[1]->GetId();

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

BOOST_AUTO_TEST_CASE(merkleblock_verify_native_body_authentication) {
    CBlock multi_block = getBlock13b8a();
    multi_block.hashMerkleRoot = BlockMerkleRoot(multi_block);
    const BlockHash multi_hash = multi_block.GetHash();
    const CBlockHeader multi_header = multi_block.GetBlockHeader();
    const uint32_t multi_ntx = static_cast<uint32_t>(multi_block.vtx.size());
    BOOST_REQUIRE_GT(multi_ntx, 1U);

    // 1. Genuine multi-tx proof succeeds.
    const TxId target_txid = multi_block.vtx[1]->GetId();
    CMerkleBlock valid_multi_proof(multi_block, std::set<TxId>{target_txid});
    std::vector<uint256> matched;
    BOOST_CHECK(VerifyMerkleBlockAgainstAuthenticatedBlock(
                    valid_multi_proof, multi_block, multi_hash, multi_header,
                    multi_ntx, matched) == MerkleBlockVerifyResult::VALID);
    BOOST_REQUIRE_EQUAL(matched.size(), 1U);
    BOOST_CHECK_EQUAL(matched[0], uint256(target_txid));

    // 2. Genuine 1-transaction (coinbase-only) native block proof succeeds.
    CBlock single_block = multi_block;
    single_block.vtx.resize(1);
    single_block.hashMerkleRoot = BlockMerkleRoot(single_block);
    const BlockHash single_hash = single_block.GetHash();
    const CBlockHeader single_header = single_block.GetBlockHeader();
    const TxId cb_txid = single_block.vtx[0]->GetId();
    BOOST_CHECK(single_block.hashMerkleRoot != uint256(cb_txid));

    CMerkleBlock valid_single_proof(single_block, std::set<TxId>{cb_txid});
    BOOST_CHECK(VerifyMerkleBlockAgainstAuthenticatedBlock(
                    valid_single_proof, single_block, single_hash,
                    single_header, 1U,
                    matched) == MerkleBlockVerifyResult::VALID);
    BOOST_REQUIRE_EQUAL(matched.size(), 1U);
    BOOST_CHECK_EQUAL(matched[0], uint256(cb_txid));

    // 3. Forged 1-tx proof claiming an arbitrary fake TxId with authentic header
    // and matching nTransactions=1 must be rejected.
    const uint256 fake_txid = uint256S(
        "0xdeadbeef00000000000000000000000000000000000000000000000000000001");
    CMerkleBlock forged_fake_leaf;
    forged_fake_leaf.header = single_header;
    forged_fake_leaf.txn = CPartialMerkleTree({fake_txid}, {true});
    BOOST_CHECK(VerifyMerkleBlockAgainstAuthenticatedBlock(
                    forged_fake_leaf, single_block, single_hash, single_header,
                    1U, matched) == MerkleBlockVerifyResult::INVALID_PROOF);
    BOOST_CHECK(matched.empty());

    // 4. Forged 1-tx proof setting sole leaf equal to native header.hashMerkleRoot
    // must be rejected (defeats naive proof_legacy_root == header.hashMerkleRoot).
    CMerkleBlock forged_root_as_leaf;
    forged_root_as_leaf.header = single_header;
    forged_root_as_leaf.txn =
        CPartialMerkleTree({single_header.hashMerkleRoot}, {true});
    BOOST_CHECK(VerifyMerkleBlockAgainstAuthenticatedBlock(
                    forged_root_as_leaf, single_block, single_hash,
                    single_header, 1U,
                    matched) == MerkleBlockVerifyResult::INVALID_PROOF);
    BOOST_CHECK(matched.empty());

    // 5. Forged multi-tx proof with real nTransactions but altered leaf hash
    // must be rejected.
    std::vector<uint256> forged_leaves;
    std::vector<bool> forged_match(multi_block.vtx.size(), false);
    for (size_t i = 0; i < multi_block.vtx.size(); ++i) {
        forged_leaves.push_back(i == 1 ? fake_txid
                                       : uint256(multi_block.vtx[i]->GetId()));
    }
    forged_match[1] = true;
    CMerkleBlock forged_multi_proof;
    forged_multi_proof.header = multi_header;
    forged_multi_proof.txn = CPartialMerkleTree(forged_leaves, forged_match);
    BOOST_CHECK_EQUAL(forged_multi_proof.txn.GetNumTransactions(), multi_ntx);
    BOOST_CHECK(VerifyMerkleBlockAgainstAuthenticatedBlock(
                    forged_multi_proof, multi_block, multi_hash, multi_header,
                    multi_ntx,
                    matched) == MerkleBlockVerifyResult::INVALID_PROOF);
    BOOST_CHECK(matched.empty());

    // 6. Native witness/body binding: mutating witness arguments on a V2
    // transaction keeps TxId and legacy ComputeMerkleRoot unchanged, but changes
    // TxHash and native BlockMerkleRoot -> must fail with CORRUPT_BLOCK.
    auto make_v2_tx = [&](uint8_t witness_arg_byte) {
        CMutableTransaction mtx;
        mtx.nVersion = 7;
        mtx.nLockTime = 0;
        mtx.nV2Lock = 0;
        CTxIn input(COutPoint(multi_block.vtx[0]->GetId(), 0));
        input.nFlags = 1;
        input.nPathIndex = 0;
        lotus::v2::BranchWitness witness;
        witness.script = {0x4e};
        witness.arguments = {{witness_arg_byte}};
        input.vWitnesses = {witness};
        mtx.vin.push_back(std::move(input));
        lotus::v2::Output output;
        output.value = 1000;
        output.branches = {lotus::v2::BranchLeaf(std::vector<uint8_t>{0x4e})};
        output.paths = {{0}};
        mtx.vout.push_back(CTxOut::FromV2Output(output));
        return MakeTransactionRef(std::move(mtx));
    };
    CBlock v2_block = single_block;
    v2_block.vtx.push_back(make_v2_tx(0x01));
    v2_block.hashMerkleRoot = BlockMerkleRoot(v2_block);
    const BlockHash v2_hash = v2_block.GetHash();
    const CBlockHeader v2_header = v2_block.GetBlockHeader();
    const TxId v2_txid = v2_block.vtx[1]->GetId();
    CMerkleBlock valid_v2_proof(v2_block, std::set<TxId>{v2_txid});
    BOOST_CHECK(VerifyMerkleBlockAgainstAuthenticatedBlock(
                    valid_v2_proof, v2_block, v2_hash, v2_header, 2U,
                    matched) == MerkleBlockVerifyResult::VALID);

    CBlock witness_mutated_block = v2_block;
    witness_mutated_block.vtx[1] = make_v2_tx(0x02);
    BOOST_CHECK_EQUAL(witness_mutated_block.vtx[1]->GetId(), v2_txid);
    BOOST_CHECK(witness_mutated_block.vtx[1]->GetHash() !=
                v2_block.vtx[1]->GetHash());
    BOOST_CHECK_EQUAL(ExpectedPartialMerkleRoot(witness_mutated_block),
                      ExpectedPartialMerkleRoot(v2_block));
    BOOST_CHECK(VerifyMerkleBlockAgainstAuthenticatedBlock(
                    valid_v2_proof, witness_mutated_block, v2_hash, v2_header,
                    2U, matched) == MerkleBlockVerifyResult::CORRUPT_BLOCK);
    BOOST_CHECK(matched.empty());
}

BOOST_AUTO_TEST_SUITE_END()
