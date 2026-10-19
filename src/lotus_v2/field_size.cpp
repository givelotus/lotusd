// Copyright (c) 2026 The Lotus developers
#include "field_size.h"

#include <utility>

namespace lotus::v2 {
namespace {

void AccumulatePaths(const std::vector<std::vector<uint8_t>> &paths,
                     std::vector<size_t> &sizes) {
    for (size_t slot = 0; slot < paths.size(); ++slot) {
        const size_t encoded = PathSerializedSize(paths[slot]);
        if (sizes.size() <= slot) sizes.resize(slot + 1, 0);
        if (encoded > sizes[slot]) sizes[slot] = encoded;
    }
}

} // namespace

bool OutputSerializedSize(const Output &output, size_t &size,
                          std::string &error) {
    return ComputeOutputSerializedSize(output, size, error);
}

bool DeriveFieldSizes(const VmExecutionContext &context,
                      std::map<uint8_t, std::vector<size_t>> &field_sizes,
                      std::string &error) {
    std::vector<size_t> outputs;
    outputs.reserve(context.tx.outputs.size());
    for (const Output &output : context.tx.outputs) {
        size_t size = 0;
        if (!OutputSerializedSize(output, size, error)) {
            field_sizes.clear();
            return false;
        }
        outputs.push_back(size);
    }
    std::vector<size_t> coins(context.tx.inputs.size(), 0);
    std::vector<size_t> coin_paths;
    std::vector<size_t> output_paths;
    for (size_t i = 0; i < context.tx.inputs.size(); ++i) {
        if (i >= context.resolved.size() || !context.resolved[i]) continue;
        const Output &coin = *context.resolved[i];
        size_t size = 0;
        if (!ComputeCoinOutputSerializedSize(coin, size, error)) {
            field_sizes.clear();
            return false;
        }
        coins[i] = size;
        AccumulatePaths(coin.paths, coin_paths);
    }
    for (const Output &output : context.tx.outputs)
        AccumulatePaths(output.paths, output_paths);
    field_sizes.clear();
    field_sizes.emplace(0xdb, std::move(coin_paths));
    field_sizes.emplace(0xdc, std::move(coins));
    field_sizes.emplace(0xe6, std::move(output_paths));
    field_sizes.emplace(0xe7, std::move(outputs));
    error.clear();
    return true;
}

} // namespace lotus::v2
