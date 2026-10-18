// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_BLOCK_COST_H
#define LOTUS_V2_BLOCK_COST_H
#include "monetary.h"
namespace lotus::v2 {
// Explicit development schedule, never launch defaults. Hash charges reserve
// 64 domain bytes per digest, plus base and payload bytes. State update charges
// conservatively cover 27 collapsed sparse-tree levels per key. Asset lookup uses
// a conservative quadratic comparison bound; no expected hash-table bound.
// This is an abstract development schedule, not calibrated/frozen P05 costs.
// Oracle view copying/rebuilding and repeated checks of authenticated ancestor
// headers are bookkeeping outside this model. Their implementation overhead
// remains an uncalibrated measurement gap, not a resource-safety claim.
struct BlockCostProfile {
    uint64_t hash_base;
    uint64_t hash_byte;
    uint64_t resolve_byte;
    uint64_t asset_comparison;
};
struct TransactionCosts {
    uint64_t account_linear = 0;
    uint64_t enforce_linear = 0;
};
// Genesis allocation only: authenticated VM charge is shared by both views.
// Extensions must supply separate authenticated accounting/execution engines
// before they can use this acceptance boundary (no caller cost override).
TransactionCosts
AuthenticatedTransactionCosts(const Transaction &tx, const TxProfile &profile,
                              const DevelopmentUtxoView &view, uint64_t height,
                              uint64_t parent_mtp, VmCostUnits invocation_cost,
                              const BlockCostProfile &cost);
// Same arithmetic over the validated transaction's resolved spends, in input
// order with mint/coinbase inputs omitted. This avoids backend reads or a
// complete UTXO map in the persistent connector. Reject mismatched records.
TransactionCosts AuthenticatedTransactionCostsResolved(
    const Transaction &tx, const TxProfile &profile,
    const std::vector<Coin> &resolved_spends, uint64_t height,
    uint64_t parent_mtp, VmCostUnits invocation_cost,
    const BlockCostProfile &cost,
    const uint64_t *precomputed_wire_bytes = nullptr);
MonetaryInteger AuthenticatedEnvelopeCost(uint64_t frame_prefix_bytes,
                                          uint32_t count,
                                          const BlockCostProfile &cost);
} // namespace lotus::v2
#endif
