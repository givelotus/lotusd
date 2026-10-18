// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <coins.h>
#include <dbwrapper.h>
#include <policy/policy.h>
#include <random.h>
#include <script/signingprovider.h>
#include <test/util/transaction_utils.h>

#include <cassert>
#include <vector>

// Microbenchmark for simple accesses to a CCoinsViewCache database. Note from
// laanwj, "replicating the actual usage patterns of the client is hard though,
// many times micro-benchmarks of the database showed completely different
// characteristics than e.g. reindex timings. But that's not a requirement of
// every benchmark."
// (https://github.com/bitcoin/bitcoin/issues/7883#issuecomment-224807484)
static void CCoinsCaching(benchmark::Bench &bench) {
    ECC_Start();

    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(
        keystore, coins, {{11 * COIN, 50 * COIN, 21 * COIN, 22 * COIN}});

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout = COutPoint(dummyTransactions[0].GetId(), 1);
    t1.vin[0].scriptSig << std::vector<uint8_t>(65, 0);
    t1.vin[1].prevout = COutPoint(dummyTransactions[1].GetId(), 0);
    t1.vin[1].scriptSig << std::vector<uint8_t>(65, 0)
                        << std::vector<uint8_t>(33, 4);
    t1.vin[2].prevout = COutPoint(dummyTransactions[1].GetId(), 1);
    t1.vin[2].scriptSig << std::vector<uint8_t>(65, 0)
                        << std::vector<uint8_t>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90 * COIN;
    t1.vout[0].scriptPubKey << OP_1;

    // Benchmark.
    bench.run([&] {
        CTransaction t(t1);
        bool success =
            AreInputsStandard(t, coins, STANDARD_SCRIPT_VERIFY_FLAGS);
        assert(success);
    });
    ECC_Stop();
}

static void CDBWrapperMdbxRead1000(benchmark::Bench &bench) {
    FastRandomContext rng{/*fDeterministic=*/true};
    DBParams params{};
    params.path = fs::path("bench_mdbx");
    params.cache_bytes = 16 << 20;
    params.memory_only = true;
    CDBWrapper db(params);

    std::vector<uint256> keys(1000);
    CDBBatch batch(db);
    for (size_t i = 0; i < keys.size(); ++i) {
        keys[i] = rng.rand256();
        batch.Write(keys[i], uint64_t(i + 1));
    }
    db.WriteBatch(batch);

    bench.name("CDBWrapperMdbxRead1000")
        .batch(keys.size())
        .unit("op")
        .run([&] {
            uint64_t sum = 0;
            for (const uint256 &k : keys) {
                uint64_t v = 0;
                const bool ok = db.Read(k, v);
                assert(ok);
                sum += v;
            }
            ankerl::nanobench::doNotOptimizeAway(sum);
        });
}

BENCHMARK(CCoinsCaching);
BENCHMARK(CDBWrapperMdbxRead1000);
