// Copyright (c) 2026 The Lotus developers
// Standalone ordinary-block connect/disconnect model. Not lotusd ConnectTip,
// not a disk chainstate, and not mining, ASERT, or coinbase consensus.
#ifndef LOTUS_V2_BLOCK_H
#define LOTUS_V2_BLOCK_H

#include "block_cost.h"
#include "block_wire.h"
#include "header_context.h"
#include "incremental_utxo.h"
#include "monetary.h"

#include <array>
#include <string>
#include <vector>

namespace lotus::v2 {

// Parent header plus the monetary record committed at that header. The child
// block header and PoW are not represented. A leading development-profile
// coinbase is a candidate that feeds the existing AdvanceMonetary fields.
// Its input names the parent BlockId and the candidate height. It is not a
// frozen mainnet entitlement, not ConnectTip, and not a block accepted by
// lotusd.
struct OrdinaryParentContext {
    Header header;
    ChainId chain_id{};
    MonetaryState monetary{};
};

// One UTXO change, in application order. created=false is a coin removed by
// a spend; created=true is a coin inserted for a non-burn output.
struct OrdinaryUndoStep {
    bool created = false;
    Coin coin;
};

struct OrdinaryBlockUndo {
    std::vector<OrdinaryUndoStep> steps;
    MonetaryState prior_monetary{};
    Hash prior_utxo_root{};
    std::array<uint8_t, 56> prior_monetary_bytes{};
};

// monetary is AdvanceMonetary's result for this block and the parent work
// integer. With no coinbase, the existing coinbase fields stay zero. A
// development coinbase fills those fields and does not freeze a mainnet
// entitlement or choose a new work value.
struct OrdinaryBlockConnected {
    Hash utxo_root{};
    Hash state_root{};
    std::array<uint8_t, 56> monetary_bytes{};
    MonetaryTransition monetary{};
    OrdinaryBlockUndo undo;
    VmCostUnits invocation_cost{};
};

// Apply transactions in order. The running invocation-cost sum rejects when
// it exceeds profile.max_total_invocation_cost; equal to the cap is accepted.
// Any rejection leaves the view, incremental root, and monetary bytes as
// they were. profile.candidate_height must be parent.header.height+1 and
// profile.parent_mtp must be parent.header.time. The parent state_root must
// already commit the supplied UTXO root and monetary record.
// This does not accept a block and is not ConnectTip.
bool ConnectOrdinaryBlock(const std::vector<Transaction> &transactions,
                          const OrdinaryParentContext &parent,
                          const OrdinaryCandidateProfile &profile,
                          const MonetaryProfile &monetary_profile,
                          DevelopmentUtxoView &view, IncrementalUtxoSet &utxo,
                          MonetaryState &monetary,
                          OrdinaryBlockConnected &connected,
                          std::string &error);

// Complete, in-memory framed-block acceptance under the genesis allocation.
// Atomic across all header, framing, VM, monetary and state checks. No stores
// are written. History's oldest entry must be authenticated by the caller.
// Staging copies/rebuilds the in-memory oracle view; this is not a production
// storage algorithm or a bound on implementation resource use.
// This remains an isolated candidate boundary, not lotusd ConnectTip.
bool ConnectCompleteBlock(const std::vector<uint8_t> &wire,
                          const OrdinaryParentContext &parent,
                          const std::vector<Header> &history,
                          const HeaderChainProfile &header_profile,
                          const OrdinaryCandidateProfile &ordinary_profile,
                          const MonetaryProfile &monetary_profile,
                          const BlockCostProfile &cost_profile,
                          DevelopmentUtxoView &view, IncrementalUtxoSet &utxo,
                          MonetaryState &monetary,
                          OrdinaryBlockConnected &connected,
                          std::string &error);

// Reverse undo.steps, then restore the prior monetary record. Success leaves
// the incremental UTXO root and the 56-byte monetary record byte-for-byte.
bool DisconnectOrdinaryBlock(const OrdinaryBlockUndo &undo,
                             DevelopmentUtxoView &view,
                             IncrementalUtxoSet &utxo, MonetaryState &monetary,
                             std::string &error);

// In-memory coin image plus the 56-byte monetary record. Same process only.
// Not a database, snapshot trust model, or undo log. Reload rebuilds the
// incremental root from the encoded coins.
bool WriteInMemorySnapshot(const DevelopmentUtxoView &view,
                           const MonetaryState &monetary,
                           std::vector<uint8_t> &bytes, std::string &error);
bool LoadInMemorySnapshot(const std::vector<uint8_t> &bytes,
                          DevelopmentUtxoView &view, IncrementalUtxoSet &utxo,
                          MonetaryState &monetary, std::string &error);

} // namespace lotus::v2
#endif
