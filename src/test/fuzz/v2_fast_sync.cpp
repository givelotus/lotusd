// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/fast_sync.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void FuzzFastSyncCodecs(FuzzedDataProvider &fuzzed_data_provider) {
    const std::vector<uint8_t> raw =
        fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>();

    {
        lotus::v2::GetUtxoRootsRequest req{};
        std::string err;
        if (lotus::v2::DecodeGetUtxoRootsRequest(raw, req, err)) {
            const std::vector<uint8_t> reencoded =
                lotus::v2::EncodeGetUtxoRootsRequest(req);
            Assert(reencoded == raw);
        }
    }

    {
        lotus::v2::UtxoRootsMessage msg{};
        std::string err;
        if (lotus::v2::DecodeUtxoRootsMessage(raw, msg, err)) {
            const std::vector<uint8_t> reencoded =
                lotus::v2::EncodeUtxoRootsMessage(msg);
            Assert(reencoded == raw);
            std::string fold_err;
            (void)lotus::v2::FoldDepth8ShardRoots(msg.shards, &fold_err);
        }
    }

    {
        lotus::v2::GetUtxoShardRequest req{};
        std::string err;
        if (lotus::v2::DecodeGetUtxoShardRequest(raw, req, err)) {
            std::vector<uint8_t> reencoded;
            std::string enc_err;
            Assert(lotus::v2::EncodeGetUtxoShardRequest(req, reencoded,
                                                        enc_err));
            Assert(reencoded == raw);
        }
    }

    {
        lotus::v2::UtxoShardMessage msg{};
        std::string err;
        if (lotus::v2::DecodeUtxoShardMessage(raw, msg, err)) {
            std::vector<uint8_t> reencoded;
            std::string enc_err;
            if (lotus::v2::EncodeUtxoShardMessage(msg, reencoded, enc_err)) {
                Assert(reencoded == raw);
            }
        }
    }

    {
        lotus::v2::GetBlockUndoRequest req{};
        std::string err;
        if (lotus::v2::DecodeGetBlockUndoRequest(raw, req, err)) {
            const std::vector<uint8_t> reencoded =
                lotus::v2::EncodeGetBlockUndoRequest(req);
            Assert(reencoded == raw);
        }
    }

    {
        lotus::v2::BlockUndoMessage msg{};
        std::string err;
        if (lotus::v2::DecodeBlockUndoMessage(raw, msg, err)) {
            std::vector<uint8_t> reencoded;
            std::string enc_err;
            if (lotus::v2::EncodeBlockUndoMessage(msg, reencoded, enc_err)) {
                Assert(reencoded == raw);
            }
        }
    }
}

void FuzzFastSyncShardVerify(FuzzedDataProvider &fuzzed_data_provider) {
    lotus::v2::ShardRootEntry expected_d8{};
    expected_d8.cardinality_tag =
        fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 3);
    if (expected_d8.cardinality_tag == 0 &&
        fuzzed_data_provider.ConsumeBool()) {
        expected_d8.subtree_root = lotus::v2::EmptyUtxoRoot();
    } else {
        const auto root_bytes = fuzzed_data_provider.ConsumeBytes<uint8_t>(32);
        std::copy(root_bytes.begin(), root_bytes.end(),
                  expected_d8.subtree_root.begin());
    }

    const uint64_t pivot_height =
        fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(0, 1000000);
    const std::vector<uint8_t> raw =
        fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>();

    lotus::v2::UtxoShardMessage shard{};
    std::string err;
    if (lotus::v2::DecodeUtxoShardMessage(raw, shard, err)) {
        lotus::v2::ShardRootEntry computed_sub{};
        (void)lotus::v2::VerifyAndBuildUtxoShard(expected_d8, pivot_height,
                                                 shard, &computed_sub, err);
    }
}

} // namespace

FUZZ_TARGET(v2_fast_sync_codecs) {
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FuzzFastSyncCodecs(fuzzed_data_provider);
}

FUZZ_TARGET(v2_fast_sync_shard_verify) {
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FuzzFastSyncShardVerify(fuzzed_data_provider);
}

FUZZ_TARGET(v2_fast_sync) {
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    if (fuzzed_data_provider.ConsumeBool()) {
        FuzzFastSyncCodecs(fuzzed_data_provider);
    } else {
        FuzzFastSyncShardVerify(fuzzed_data_provider);
    }
}
