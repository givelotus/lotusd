// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <consensus/merkle.h>
#include <lotus_v2/blocksnap.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>

#include <cassert>
#include <vector>

static void MerkleRoot(benchmark::Bench &bench) {
    FastRandomContext rng{/*fDeterministic=*/true};

    std::vector<uint256> hashes{};
    hashes.resize(9001);
    for (auto &item : hashes) {
        item = rng.rand256();
    }

    const uint256 expected_root{uint256S(
        "d8d4dfd014a533bc3941b8663fa6e7f3a8707af124f713164d75b0c3179ecb08")};
    for (bool mutate : {false, true}) {
        bench.name(mutate ? "MerkleRootWithMutation" : "MerkleRoot")
            .batch(hashes.size())
            .unit("leaf")
            .run([&] {
                std::vector<uint256> leaves;
                leaves.reserve((hashes.size() + 1) &
                               ~1ULL); // capacity rounded up to even
                for (size_t s = 0; s < hashes.size(); s++) {
                    leaves.push_back(hashes[s]);
                }

                bool mutated{false};
                const uint256 root{ComputeMerkleRoot(
                    std::move(leaves), mutate ? &mutated : nullptr)};
                assert(root == expected_root);
            });
    }
}

static void SealedBlockMerkleSpine(benchmark::Bench &bench) {
    FastRandomContext rng{/*fDeterministic=*/true};

    CMutableTransaction cb_mtx;
    cb_mtx.vin.resize(1);
    cb_mtx.vin[0].scriptSig = CScript() << OP_0;
    cb_mtx.vout.resize(1);
    cb_mtx.vout[0].nValue = 100 * SATOSHI;
    CTransactionRef cb_tx = MakeTransactionRef(std::move(cb_mtx));

    std::vector<CTransactionRef> non_cb_txs;
    non_cb_txs.reserve(9000);
    for (size_t i = 0; i < 9000; ++i) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(TxId(rng.rand256()), uint32_t(i));
        mtx.vout.resize(1);
        non_cb_txs.push_back(MakeTransactionRef(std::move(mtx)));
    }
    uint256 null_root;
    std::vector<uint256> branch;
    lotus::v2::ComputeNullMerkleRootAndBranch(non_cb_txs, null_root, branch);

    lotus::v2::SealedBlock sb;
    sb.header.nVersion = 1;
    sb.header.nBits = 0x207fffff;
    sb.tx_coinbase = cb_tx;
    sb.coinbase_merkle_branch = branch;
    sb.header.hashMerkleRoot =
        lotus::v2::ComputeMerkleRootFromBranch(cb_tx->GetId(), branch, 0);

    bench.name("SealedBlockMerkleSpine")
        .batch(9001)
        .unit("leaf")
        .run([&] {
            const bool ok = sb.VerifyMerkleSpine(null_root);
            assert(ok);
            ankerl::nanobench::doNotOptimizeAway(ok);
        });
}

BENCHMARK(MerkleRoot);
BENCHMARK(SealedBlockMerkleSpine);
