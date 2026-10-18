// Copyright (c) 2016-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <hash.h>
#include <key.h>
#include <lotus_v2/signing.h>
#if defined(HAVE_CONSENSUS_LIB)
#include <script/bitcoinconsensus.h>
#endif
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <tinyformat.h>

#include <array>
#include <cstring>

static void VerifyNestedIfScript(benchmark::Bench &bench) {
    std::vector<std::vector<uint8_t>> stack;
    CScript script;
    for (int i = 0; i < 100; ++i) {
        script << OP_1 << OP_IF;
    }
    for (int i = 0; i < 1000; ++i) {
        script << OP_1;
    }
    for (int i = 0; i < 100; ++i) {
        script << OP_ENDIF;
    }
    bench.run([&] {
        auto stack_copy = stack;
        ScriptExecutionMetrics metrics = {};
        ScriptError error;
        bool ret = EvalScript(stack_copy, script, 0, BaseSignatureChecker(),
                              metrics, &error);
        assert(ret);
    });
}

static void VerifySchnorrIndividual64(benchmark::Bench &bench) {
    BasicTestingSetup test_setup;
    constexpr size_t N = 64;
    std::vector<CPubKey> pubkeys(N);
    std::vector<uint256> msgs(N);
    std::vector<std::vector<uint8_t>> sigs(N);
    for (size_t i = 0; i < N; ++i) {
        CKey k;
        k.MakeNewKey(true);
        pubkeys[i] = k.GetPubKey();
        msgs[i] = Hash(strprintf("bench schnorr msg %zu", i));
        bool ok = k.SignSchnorr(msgs[i], sigs[i]);
        assert(ok);
    }
    bench.batch(N).unit("sig").run([&] {
        for (size_t i = 0; i < N; ++i) {
            bool ok = pubkeys[i].VerifySchnorr(msgs[i], sigs[i]);
            assert(ok);
        }
    });
}

static void VerifySchnorrBatch64(benchmark::Bench &bench) {
    BasicTestingSetup test_setup;
    constexpr size_t N = 64;
    lotus::v2::BatchSigCollector collector;
    for (size_t i = 0; i < N; ++i) {
        CKey k;
        k.MakeNewKey(true);
        CPubKey pk = k.GetPubKey();
        uint256 msg = Hash(strprintf("bench schnorr msg %zu", i));
        std::vector<uint8_t> sig;
        bool ok = k.SignSchnorr(msg, sig);
        assert(ok);
        collector.AddLegacySchnorr(
            std::span<const uint8_t>(pk.data(), pk.size()),
            std::span<const uint8_t>(sig.data(), sig.size()), msg.begin());
    }
    bench.batch(N).unit("sig").run([&] {
        bool ok = collector.VerifyAll();
        assert(ok);
    });
}

static void SigCacheTlsHit(benchmark::Bench &bench) {
    BasicTestingSetup test_setup;
    SignatureCache sigcache{DEFAULT_SIGNATURE_CACHE_BYTES};
    CKey k;
    k.MakeNewKey(true);
    CPubKey pk = k.GetPubKey();
    uint256 msg = Hash(std::string("tls sigcache bench"));
    std::vector<uint8_t> sig;
    bool ok = k.SignSchnorr(msg, sig);
    assert(ok);
    uint256 entry;
    sigcache.ComputeEntry(entry, msg, sig, pk);
    sigcache.Set(entry);
    bench.unit("lookup").run([&] {
        bool hit = sigcache.Get(entry, /*erase=*/false);
        assert(hit);
    });
}

BENCHMARK(VerifyNestedIfScript);
BENCHMARK(VerifySchnorrIndividual64);
BENCHMARK(VerifySchnorrBatch64);
BENCHMARK(SigCacheTlsHit);
