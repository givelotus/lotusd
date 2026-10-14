// Copyright (c) 2011-2019 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <chainparams.h>
#include <common/system.h>
#include <config.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>

#include <test/lcg.h>
#include <test/util/setup_common.h>

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

// Whether to check all possible nBits in the block subsidy test (takes ~20s)
#define IS_CHECK_SUBSIDY_EXHAUSTIVE 0

static double ApproxTarget(const uint32_t nBits) {
    const uint32_t exp = nBits >> 24;
    double factor = exp > 3 ? pow(256, exp - 3) : 1.0 / pow(256, 3 - exp);
    return (nBits & 0xff'ff'ff) * factor;
}

static void TestBlockSubsidyLogarithmic(const Consensus::Params &params) {
    const std::vector<std::pair<uint32_t, Amount>> test_cases = {
        {0x1c100000, 1 * SUBSIDY},
        {0x1c0fffff, 1 * SUBSIDY + 359 * SATOSHI},
        {0x1c080000, 2 * SUBSIDY},
        {0x1c07ffff, 2 * SUBSIDY + 717 * SATOSHI},
        {0x1c040000, 3 * SUBSIDY},
        {0x1c03ffff, 3 * SUBSIDY + 1432 * SATOSHI},
        {0x1c020000, 4 * SUBSIDY},
        {0x1c01ffff, 4 * SUBSIDY + 2864 * SATOSHI},
        {0x1c010000, 5 * SUBSIDY},
        {0x1c00ffff, 5 * SUBSIDY + 5725 * SATOSHI},
        {0x1c008000, 6 * SUBSIDY},
        {0x1b7fffff, 6 * SUBSIDY + 47 * SATOSHI},
        {0x1b400000, 7 * SUBSIDY},
        {0x1b3fffff, 7 * SUBSIDY + 92 * SATOSHI},
        {0x1b200000, 8 * SUBSIDY},
        {0x1b1fffff, 8 * SUBSIDY + 181 * SATOSHI},
        {0x1b100000, 9 * SUBSIDY},
        {0x1b0fffff, 9 * SUBSIDY + 359 * SATOSHI},
        {0x1b080000, 10 * SUBSIDY},
        {0x1b07ffff, 10 * SUBSIDY + 717 * SATOSHI},
        {0x1b040000, 11 * SUBSIDY},
        {0x1b03ffff, 11 * SUBSIDY + 1432 * SATOSHI},
        {0x1b020000, 12 * SUBSIDY},
        {0x1b01ffff, 12 * SUBSIDY + 2864 * SATOSHI},
        {0x1b010000, 13 * SUBSIDY},
        {0x1b00ffff, 13 * SUBSIDY + 5725 * SATOSHI},
        {0x1b008000, 14 * SUBSIDY},
        {0x1a7fffff, 14 * SUBSIDY + 47 * SATOSHI},
        {0x1a400000, 15 * SUBSIDY},
        {0x1a3fffff, 15 * SUBSIDY + 92 * SATOSHI},
        {0x1a200000, 16 * SUBSIDY},
        {0x18200000, 32 * SUBSIDY},
        {0x14200000, 64 * SUBSIDY},
        {0x0c200000, 128 * SUBSIDY},
        {0x01010000, 221 * SUBSIDY}, // Max possible difficulty
        {0x1b04864c, int64_t(2'813'774'771) * SATOSHI},  // block 100000 on BTC
        {0x1a05db8b, int64_t(4'796'920'144) * SATOSHI},  // block 200000 on BTC
        {0x1900896c, int64_t(7'773'358'358) * SATOSHI},  // block 300000 on BTC
        {0x1806b99f, int64_t(8'905'116'497) * SATOSHI},  // block 400000 on BTC
        {0x18009645, int64_t(9'819'833'738) * SATOSHI},  // block 500000 on BTC
        {0x1715a35c, int64_t(10'546'769'112) * SATOSHI}, // block 600000 on BTC
        {0x170bef93, int64_t(10'769'920'772) * SATOSHI}, // block 680603 on BTC
        {0x1000ffff, int64_t(26'260'005'725) * SATOSHI},
        {0x0500ffff, int64_t(49'140'005'725) * SATOSHI},
        {0x0300ffff, int64_t(53'300'005'725) * SATOSHI},
        {0x1c100001, 1 * SUBSIDY}, // for testnet
        {0x1d00ffff, 1 * SUBSIDY}, // for testnet
    };
    for (const auto &pair : test_cases) {
        const Amount subsidy = GetBlockSubsidy(pair.first, params);
        BOOST_CHECK_MESSAGE(pair.second == subsidy,
                            "Subsidy test failed: "
                                << std::dec << pair.second << " != " << subsidy
                                << " for 0x" << std::hex << pair.first);
    }
#if IS_CHECK_SUBSIDY_EXHAUSTIVE
    std::vector<uint32_t> test_mantissa_cases(257); // +1 for the rng one
    std::iota(test_mantissa_cases.begin(), test_mantissa_cases.end() - 1, 0);
#else
    std::vector<uint32_t> test_mantissa_cases = {0x00, 0x01, 0x80,
                                                 0xfe, 0xff, 0};
#endif
    MMIXLinearCongruentialGenerator lcg;
    // check nBits exhaustively
    for (uint32_t exp = 0x1c; exp >= 0x01; --exp) {
        double max_rel_error = 0;
        uint32_t max_rel_error_nBits;
        double max_abs_error = 0;
        uint32_t max_abs_error_nBits;
        for (uint32_t mantissa_upper = 0x7f'ff00; mantissa_upper >= 0x8000;
             mantissa_upper -= 0x100) {
            test_mantissa_cases.back() = lcg.next() & 0xff; // last is random
            for (uint32_t mantissa_lower : test_mantissa_cases) {
                uint32_t mantissa = mantissa_upper | mantissa_lower;
                if (exp == 0x1c && mantissa > 0x100000) {
                    continue;
                }
                if (exp == 0x01 && mantissa < 0x10000) {
                    continue;
                }
                uint32_t nBits = (exp << 24) | mantissa;
                double approx_target = ApproxTarget(nBits);
                double approx_max_target = ApproxTarget(0x1c100000);
                double approx_log_difficulty =
                    log2(approx_max_target) - log2(approx_target);
                double approx_subsidy =
                    (SUBSIDY / SATOSHI) * (approx_log_difficulty + 1);
                double actual_subsidy =
                    GetBlockSubsidy(nBits, params) / SATOSHI;
                double abs_error = abs(actual_subsidy - approx_subsidy);
                double rel_error = abs_error / approx_subsidy;
                if (abs_error > max_abs_error) {
                    max_abs_error = abs_error;
                    max_abs_error_nBits = nBits;
                }
                if (rel_error > max_rel_error) {
                    max_rel_error = rel_error;
                    max_rel_error_nBits = nBits;
                }
            }
        }
        constexpr double MAX_EXPECTED_ABS_ERROR = 5.39298629760743;
        BOOST_CHECK_MESSAGE(
            max_abs_error < MAX_EXPECTED_ABS_ERROR,
            strprintf("Subsidy approximation failed, absolute error too large: "
                      "%.16f >= %.16f, for nBits = %08x",
                      max_abs_error, MAX_EXPECTED_ABS_ERROR,
                      max_abs_error_nBits));
        constexpr double MAX_EXPECTED_REL_ERROR = 0.00000001573502;
        BOOST_CHECK_MESSAGE(
            max_rel_error < MAX_EXPECTED_REL_ERROR,
            strprintf("Subsidy approximation failed, relative error too large: "
                      "%.16f >= %.16f, for nBits = %08x",
                      max_rel_error, MAX_EXPECTED_REL_ERROR,
                      max_rel_error_nBits));
    }
}

/**
 * Make sure the block subsidy is constant.
 */
static void TestBlockSubsidyConstant(const Consensus::Params &consensusParams) {
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x1d00ffff, consensusParams));
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x1d008000, consensusParams));
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x1e7fffff, consensusParams));
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1c2a1115, consensusParams)); // block 50000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1b04864c, consensusParams)); // block 100000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1a05db8b, consensusParams)); // block 200000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1900896c, consensusParams)); // block 300000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1806b99f, consensusParams)); // block 400000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x18009645, consensusParams)); // block 500000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1715a35c, consensusParams)); // block 600000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x170bef93, consensusParams)); // block 680603 on BTC
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x1000ffff, consensusParams));
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x0500ffff, consensusParams));
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x0300ffff, consensusParams));
}

BOOST_AUTO_TEST_CASE(block_subsidy_test) {
    TestBlockSubsidyLogarithmic(
        CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus());
    TestBlockSubsidyLogarithmic(
        CreateChainParams(*m_node.args, ChainType::TESTNET)->GetConsensus());
    TestBlockSubsidyConstant(
        CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus());
}

static CBlock makeLargeDummyBlock(const size_t num_tx) {
    CBlock block;
    block.vtx.reserve(num_tx);

    CTransaction tx;
    for (size_t i = 0; i < num_tx; i++) {
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    return block;
}

/**
 * Test that LoadExternalBlockFile works with the buffer size set below the
 * size of a large block. Currently, LoadExternalBlockFile has the buffer size
 * for BufferedFile set to 2 * MAX_TX_SIZE. Test with a value of
 * 10 * MAX_TX_SIZE.
 */
BOOST_AUTO_TEST_CASE(validation_load_external_block_file) {
    fs::path tmpfile_name = gArgs.GetDataDirNet() / "block.dat";

    FILE *fp = fopen(fs::PathToString(tmpfile_name).c_str(), "wb+");

    BOOST_CHECK(fp != nullptr);

    const CChainParams &chainparams = m_node.chainman->GetParams();

    // serialization format is:
    // message start magic, size of block, block

    size_t nwritten = fwrite(std::begin(chainparams.DiskMagic()),
                             CMessageHeader::MESSAGE_START_SIZE, 1, fp);

    BOOST_CHECK_EQUAL(nwritten, 1UL);

    CTransaction empty_tx;
    size_t empty_tx_size = GetSerializeSize(empty_tx);

    size_t num_tx = (10 * MAX_TX_SIZE) / empty_tx_size;

    CBlock block = makeLargeDummyBlock(num_tx);

    BOOST_CHECK(GetSerializeSize(block) > 2 * MAX_TX_SIZE);

    unsigned int size = GetSerializeSize(block);
    AutoFile outs{fp};
    outs << size;
    outs << block;

    BOOST_CHECK_NO_THROW({ m_node.chainman->LoadExternalBlockFile(outs, 0); });
}

//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo) {
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the
    // contents of chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    const auto out110 = *params->AssumeutxoForHeight(110);
    BOOST_CHECK_EQUAL(
        out110.hash_serialized.ToString(),
        "d754ca97ef24c5132f8d2147c19310b7a6bd136766430304735a73372fe36213");
    BOOST_CHECK_EQUAL(out110.nChainTx, 111U);

    const auto out110_2 = *params->AssumeutxoForBlockhash(BlockHash{uint256S(
        "0x47cfb2b77860d250060e78d3248bb050928765453cbcbdbc121e3c48b99a376c")});
    BOOST_CHECK_EQUAL(
        out110_2.hash_serialized.ToString(),
        "d754ca97ef24c5132f8d2147c19310b7a6bd136766430304735a73372fe36213");
    BOOST_CHECK_EQUAL(out110_2.nChainTx, 111U);
}

BOOST_AUTO_TEST_CASE(block_malleation) {
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock &block) {
        bool mutated{IsBlockMutated(block)};
        block.fChecked = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock &block) {
        return !is_mutated(block);
    };

    // Test utilities to create coinbase transactions
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(38);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block));
        block.hashMerkleRoot = block.vtx[0]->GetHash();
        BOOST_CHECK(is_not_mutated(block));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        {
            block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
            BOOST_CHECK(is_mutated(block));
            HashWriter hasher;
            hasher << block.vtx[0]->GetId();
            hasher << block.vtx[1]->GetId();
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_not_mutated(block));
        }

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            BOOST_CHECK(is_mutated(block));
            HashWriter hasher;
            hasher << block.vtx[0]->GetId();
            hasher << block.vtx[1]->GetId();
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(block.vtx.back()) == 64);
        }
        BOOST_CHECK(is_not_mutated(block));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_siz(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000"));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000"));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(
            tx3,
            "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc1"
            "0032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06"));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher << tx1.GetId();
            hasher << tx2.GetId();
            assert(hasher.GetHash() == tx3.GetHash());
            // Verify that tx3 is 64 bytes in size.
            assert(GetSerializeSize(tx3) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block));
    }
}

BOOST_AUTO_TEST_SUITE_END()
