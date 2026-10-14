// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <consensus/merkle.h>
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
    bench.name("MerkleRoot")
        .batch(hashes.size())
        .unit("leaf")
        .run([&] {
            std::vector<uint256> leaves;
            leaves.reserve((hashes.size() + 1) &
                           ~1ULL); // capacity rounded up to even
            for (size_t s = 0; s < hashes.size(); s++) {
                leaves.push_back(hashes[s]);
            }

            size_t num_layers{0};
            const uint256 root{ComputeMerkleRoot(std::move(leaves), num_layers)};
            leaves[num_layers] = root;
        });
}

BENCHMARK(MerkleRoot);
