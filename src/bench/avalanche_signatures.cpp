// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/protocol.h>
#include <bench/bench.h>
#include <hash.h>
#include <key.h>
#include <lotus_v2/signing.h>
#include <streams.h>

#include <array>
#include <stdexcept>

namespace {
struct SignedResponse {
    CPubKey key;
    uint256 hash;
    SchnorrSig signature;
    DataStream bytes;
};

void AvalancheSignatures(benchmark::Bench &bench, bool multiple_keys,
                         bool batch, bool include_prepass,
                         size_t batch_size = 32, size_t key_reuse = 1) {
    ECC_Start();
    constexpr size_t COUNT = 32;
    std::array<SignedResponse, COUNT> responses;
    CKey key = CKey::MakeCompressedKey();
    for (size_t i = 0; i < COUNT; ++i) {
        if (multiple_keys && i % key_reuse == 0) {
            key = CKey::MakeCompressedKey();
        }
        auto &item = responses[i];
        item.key = key.GetPubKey();
        avalanche::Response response(i, 0, std::vector<avalanche::Vote>(16));
        HashWriter hash;
        hash << response;
        item.hash = hash.GetHash();
        if (!key.SignSchnorr(item.hash, item.signature)) {
            throw std::runtime_error("Schnorr benchmark signing failed");
        }
        item.bytes << response << item.signature;
    }
    bench.batch(COUNT).unit("signature").run([&] {
        lotus::v2::BatchSigCollector collector;
        collector.Reserve(COUNT);
        for (const auto &item : responses) {
            uint256 hash = item.hash;
            SchnorrSig signature = item.signature;
            if (include_prepass) {
                // Includes the bounded queue-head copy and duplicate parse;
                // the normal consumer subsequently parses once in all cases.
                DataStream copied{Span{item.bytes.data(), item.bytes.size()}};
                avalanche::Response response;
                HashVerifier verifier(copied);
                verifier >> response;
                hash = verifier.GetHash();
                copied >> signature;
            }
            const bool valid = batch
                ? collector.AddLegacySchnorr(
                    std::span<const uint8_t>{item.key.data(), item.key.size()},
                    std::span<const uint8_t>{signature.data(), signature.size()},
                    hash.begin())
                : item.key.VerifySchnorr(hash, signature);
            if (!valid) throw std::runtime_error("Schnorr benchmark invalid item");
            if (batch && collector.Size() == batch_size) {
                // Use the same automatic worker threshold as production.
                if (!collector.VerifyAll()) {
                    throw std::runtime_error("Schnorr benchmark invalid batch");
                }
                collector.Clear();
            }
        }
    });
    ECC_Stop();
}
} // namespace

static void AvaSameKeyIndividual(benchmark::Bench &b) {
    AvalancheSignatures(b, false, false, false);
}
static void AvaSameKeyBatch(benchmark::Bench &b) {
    AvalancheSignatures(b, false, true, false);
}
static void AvaCrossPeerIndividual(benchmark::Bench &b) {
    AvalancheSignatures(b, true, false, false);
}
static void AvaCrossPeerBatch(benchmark::Bench &b) {
    AvalancheSignatures(b, true, true, false);
}
static void AvaCrossPeerBatchPrepass(benchmark::Bench &b) {
    AvalancheSignatures(b, true, true, true);
}
// Matched workload: eight peers, four responses/key, identical payload shape.
// This control measures crypto grouping only: production intentionally retains
// contiguous per-peer burst handling rather than copying/reordering it.
static void AvaEightPeerBatches(benchmark::Bench &b) {
    AvalancheSignatures(b, true, true, false, 4, 4);
}
static void AvaEightPeerCombined(benchmark::Bench &b) {
    AvalancheSignatures(b, true, true, false, 32, 4);
}
BENCHMARK(AvaEightPeerBatches);
BENCHMARK(AvaEightPeerCombined);
BENCHMARK(AvaSameKeyIndividual);
BENCHMARK(AvaSameKeyBatch);
BENCHMARK(AvaCrossPeerIndividual);
BENCHMARK(AvaCrossPeerBatch);
BENCHMARK(AvaCrossPeerBatchPrepass);
