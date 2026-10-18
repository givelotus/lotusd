// Copyright (c) 2026 The Lotus developers
#include "block_cost.h"
#include "block_wire.h"
#include <limits>
#include <stdexcept>
namespace lotus::v2 {
namespace {
    using Int = MonetaryInteger;
    void Require(bool v, const char *why) {
        if (!v) throw std::invalid_argument(why);
    }
    void Profile(const BlockCostProfile &p) {
        Require(p.hash_base && p.hash_byte && p.resolve_byte &&
                    p.asset_comparison,
                "nonpositive block cost schedule");
    }
    Int HashCost(const Int &bytes, const BlockCostProfile &p) {
        return p.hash_base + (bytes + 64) * p.hash_byte;
    }
    Int Tree(size_t n, const BlockCostProfile &p) {
        // At most 2*n internal digests, even with odd-layer padding; empty root
        // and single-leaf cases are conservatively charged as well.
        return Int(2) * std::max<size_t>(n, 1) * HashCost(66, p);
    }
    uint64_t Narrow(const Int &v) {
        Require(v >= 0 && v <= std::numeric_limits<uint64_t>::max(),
                "transaction linear cost width");
        return v.convert_to<uint64_t>();
    }
    Int StateKey(const Coin &coin, const BlockCostProfile &p) {
        std::vector<uint8_t> raw;
        Require(EncodeCoin(coin, raw), "cost coin encoding");
        return HashCost(36, p) +
               HashCost(1 + 32 + CompactSizeWidth(raw.size()) + raw.size(), p) +
               Int(27) * HashCost(67, p);
    }
} // namespace
TransactionCosts AuthenticatedTransactionCostsResolved(const Transaction &tx,
                                               const TxProfile &profile,
                                               const std::vector<Coin> &resolved_spends,
                                               uint64_t height, uint64_t mtp,
                                               VmCostUnits invocation,
                                               const BlockCostProfile &p,
                                               const uint64_t *precomputed_wire_bytes) {
    Profile(p);
    std::string error;
    Int total = 0;
    if (precomputed_wire_bytes != nullptr) {
        Require(!tx.inputs.empty() && !tx.outputs.empty(),
                "cost transaction encoding");
        total = *precomputed_wire_bytes;
    } else {
        std::vector<uint8_t> raw;
        Require(EncodeTransaction(tx, profile, raw, error),
                "cost transaction encoding");
        total = raw.size();
    }
    Int vm = static_cast<uint64_t>(invocation >> 64);
    vm <<= 64;
    vm += static_cast<uint64_t>(invocation);
    total += vm;
    // All identity and signing commitments are charged even when cached/lazy.
    total += 2 * HashCost(112, p);
    size_t spends = 0;
    for (const auto &input : tx.inputs) {
        std::vector<uint8_t> core, full;
        Require(EncodeInputCore(input, profile, core, error) &&
                    EncodeInputFull(input, profile, full, error),
                "cost input encoding");
        total += HashCost(core.size(), p) + HashCost(full.size(), p);
        for (const auto &w : input.witnesses)
            total += HashCost(1 + CompactSizeWidth(w.script.size()) +
                                  w.script.size(),
                              p) +
                     Int(w.siblings.size()) * HashCost(65, p);
        if (input.flags == 1) {
            Require(spends < resolved_spends.size(), "cost unresolved coin");
            const Coin &coin_record = resolved_spends[spends++];
            Require(coin_record.outpoint == Outpoint{input.prev_txid, input.prev_index},
                    "cost resolved outpoint mismatch");
            std::vector<uint8_t> output, coin;
            Require(EncodeOutput(coin_record.output, output, error) &&
                        EncodeCoin(coin_record, coin),
                    "cost resolved encoding");
            total += Int(coin.size()) * p.resolve_byte;
            total +=
                HashCost(CompactSizeWidth(output.size()) + output.size(), p);
            total += HashCost(core.size() + CompactSizeWidth(output.size()) +
                                  output.size(),
                              p);
            // Path selection and matching is bounded by the frozen 16x16 caps.
            total += Int(256) * p.asset_comparison;
            total += StateKey(coin_record, p);
        } else if (input.flags == 3)
            total += HashCost(0, p); // absent resolved CoinEntry
    }
    Require(spends == resolved_spends.size(), "cost extra resolved coin");
    const bool coinbase = tx.inputs.front().flags == 2;
    total += (coinbase ? 2 : 3) * Tree(tx.inputs.size(), p) +
             Tree(tx.outputs.size(), p);
    for (size_t j = 0; j < tx.outputs.size(); ++j) {
        const auto &output = tx.outputs[j];
        std::vector<uint8_t> bytes;
        Require(EncodeOutput(output, bytes, error), "cost output encoding");
        total += HashCost(CompactSizeWidth(bytes.size()) + bytes.size(), p);
        if (!output.IsBurn()) {
            Coin coin;
            coin.output = output;
            coin.outpoint.index = j;
            coin.creation_height = height;
            coin.creation_parent_mtp = mtp;
            coin.coinbase = tx.inputs.front().flags == 2;
            total += StateKey(coin, p);
        }
    }
    // Covers native/token additions, ordered asset-map/mint/path lookups and
    // comparisons. Deliberately conservative development cost, not calibration.
    Int records = tx.inputs.size() + tx.outputs.size();
    total += (records * records + records + spends) * p.asset_comparison;
    uint64_t result = Narrow(total);
    return {result, result};
}
TransactionCosts AuthenticatedTransactionCosts(
    const Transaction &tx, const TxProfile &profile,
    const DevelopmentUtxoView &view, uint64_t height, uint64_t mtp,
    VmCostUnits invocation, const BlockCostProfile &p) {
    std::vector<Coin> resolved;
    for (const auto &input : tx.inputs) {
        if (input.flags != 1) continue;
        const auto found = view.find(Outpoint{input.prev_txid, input.prev_index});
        Require(found != view.end(), "cost unresolved coin");
        resolved.push_back(found->second);
    }
    return AuthenticatedTransactionCostsResolved(tx, profile, resolved, height,
                                                 mtp, invocation, p);
}
MonetaryInteger AuthenticatedEnvelopeCost(uint64_t frames, uint32_t count,
                                          const BlockCostProfile &p) {
    Profile(p);
    Require(count > 0, "empty block cost");
    Int cost = Int(134) + 4 + frames;
    // Block-wide ordered TxID uniqueness lookup, independent of live outputs.
    cost += (Int(count) * count + count) * p.asset_comparison;
    // Ordered transaction-tree: n leaves, n-1 interior nodes, count wrapper.
    cost += (Int(2) * count - 1) * HashCost(65, p) + HashCost(37, p);
    // StateRoot plus header body/work/block-ID domains.
    cost +=
        HashCost(130, p) + HashCost(116, p) + HashCost(50, p) + HashCost(64, p);
    Require(cost < (Int(1) << 128), "envelope cost width");
    return cost;
}
} // namespace lotus::v2
