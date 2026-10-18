// Copyright (c) 2026 The Lotus developers
#include "chronik_explorer.h"
#include "block_wire.h"
#include <algorithm>
namespace lotus::v2 {
bool MakeChronikExplorerFacts(const Transaction &tx, const TxProfile &profile,
                              std::span<const uint8_t> source,
                              std::vector<uint8_t> &wire,
                              std::vector<ChronikFullInput> &inputs,
                              std::string &error) {
    std::vector<uint8_t> encoded;
    if (!EncodeTransaction(tx, profile, encoded, error)) return false;
    if (encoded.size() != source.size() ||
        !std::equal(encoded.begin(), encoded.end(), source.begin())) {
        error = "Chronik exact transaction frame mismatch";
        return false;
    }
    // The checked native encoder bounds all counts before building descriptors.
    // Advance with subtraction checks so even an inconsistent caller cannot
    // export an overflowing or out-of-frame range.
    size_t position = 0;
    auto advance = [&](size_t size) {
        if (size > source.size() - position) return false;
        position += size;
        return true;
    };
    auto payload = [&](size_t size, ChronikWireRange &range) {
        if (!advance(CompactSizeWidth(size))) return false;
        range = {position, size};
        return advance(size);
    };
    std::vector<ChronikFullInput> facts;
    if (!advance(16)) {
        error = "Chronik transaction location bounds";
        return false;
    }
    for (const auto &input : tx.inputs) {
        ChronikFullInput fact;
        fact.prev_txid = input.prev_txid;
        fact.prev_index = input.prev_index;
        fact.sequence = input.sequence;
        fact.flags = input.flags;
        fact.path_index = input.path_index;
        fact.has_coinbase_data = input.has_coinbase_data;
        if (!advance(41)) goto bounds;
        if (input.flags == 1) {
            if (!advance(CompactSizeWidth(input.path_index)) ||
                !advance(CompactSizeWidth(input.witnesses.size()))) goto bounds;
        } else if (input.flags == 2) {
            if (!advance(1) ||
                (input.has_coinbase_data &&
                 !payload(input.coinbase_data.size(), fact.coinbase_data)))
                goto bounds;
        }
        for (const auto &witness : input.witnesses) {
            ChronikWitness w;
            if (!payload(witness.script.size(), w.script)) goto bounds;
            w.siblings_count = uint32_t(witness.siblings.size());
            w.siblings_table.offset = position;
            if (!advance(CompactSizeWidth(witness.siblings.size())) ||
                !advance(witness.siblings.size() * 32)) goto bounds;
            w.siblings_table.length = position - w.siblings_table.offset;
            w.arguments_count = uint32_t(witness.arguments.size());
            w.arguments_table.offset = position;
            if (!advance(CompactSizeWidth(witness.arguments.size()))) goto bounds;
            for (const auto &argument : witness.arguments) {
                ChronikWireRange ignored;
                if (!payload(argument.size(), ignored)) goto bounds;
            }
            w.arguments_table.length = position - w.arguments_table.offset;
            fact.witnesses.push_back(std::move(w));
        }
        facts.push_back(std::move(fact));
    }
    // Independently account for the output tail, retaining native branch/path
    // order in the output wires produced by the existing converter.
    for (const auto &output : tx.outputs) {
        std::vector<uint8_t> bytes;
        if (!EncodeOutput(output, bytes, error)) return false;
        if (!advance(bytes.size())) goto bounds;
    }
    if (position != source.size()) goto bounds;
    wire = std::move(encoded);
    inputs = std::move(facts);
    error.clear();
    return true;
bounds:
    error = "Chronik transaction location bounds";
    return false;
}
} // namespace lotus::v2
