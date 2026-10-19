// Candidate Lotus V2 transaction framing.
#ifndef LOTUS_V2_TRANSACTION_H
#define LOTUS_V2_TRANSACTION_H

#include "output.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lotus::v2 {

// Consensus caps on a V2 transaction (decision I-6, 2026-10-19). The wire
// format counts inputs and outputs with u16 (65,535), but consensus accepts
// at most 256 of each, so `TXINPUTCOUNT ENUMERATE` and `TXOUTPUTCOUNT
// ENUMERATE` (bound 0..256) always cover the whole transaction. Profiles may
// only tighten these caps. They are validation rules only: transaction
// identity (ComputeTransactionIdentities) never depends on them.
constexpr size_t MAX_TX_INPUTS = 256;
constexpr size_t MAX_TX_OUTPUTS = 256;
// Wire-format bounds: the header counts inputs and outputs with u16.
constexpr size_t MAX_WIRE_TX_INPUTS = 65535;
constexpr size_t MAX_WIRE_TX_OUTPUTS = 65535;

struct TxProfile {
    size_t max_inputs;
    size_t max_outputs;
    size_t max_mints;
    size_t max_script_bytes;
    size_t max_arguments;
    size_t max_argument_bytes;
    size_t max_branch_proof_depth;
};

struct BranchWitness {
    std::vector<uint8_t> script;
    std::vector<Hash32> siblings;
    std::vector<std::vector<uint8_t>> arguments;
    bool operator==(const BranchWitness &other) const = default;
};

struct Input {
    Hash32 prev_txid{};
    uint32_t prev_index = 0;
    uint32_t sequence = 0;
    uint8_t flags = 0;      // 1 spend, 2 coinbase, 3 mint
    uint8_t path_index = 0; // meaningful only for spend
    std::vector<BranchWitness> witnesses;
    bool has_coinbase_data = false;
    std::vector<uint8_t> coinbase_data;
};

struct Transaction {
    uint64_t lock = 0;
    std::vector<Input> inputs;
    std::vector<Output> outputs;
};

// The profile is required and caller-selected; no production limits are
// implied. Success consumes exactly the supplied frame and clears error.
// Failure leaves the result unchanged. Mint-root membership and spend-path
// resolution are later contextual/crypto checks, outside this framing-only
// codec.
bool DecodeTransaction(const std::vector<uint8_t> &frame,
                       const TxProfile &profile, Transaction &result,
                       std::string &error);
bool EncodeTransaction(const Transaction &tx, const TxProfile &profile,
                       std::vector<uint8_t> &result, std::string &error);
bool EncodeInputCore(const Input &input, const TxProfile &profile,
                     std::vector<uint8_t> &result, std::string &error);
bool EncodeInputFull(const Input &input, const TxProfile &profile,
                     std::vector<uint8_t> &result, std::string &error);
bool CheckCoinbaseContext(const Transaction &tx, const Hash32 &parent_block_id,
                          uint64_t height, std::string &error);

inline constexpr TxProfile DefaultTxProfile{
    MAX_TX_INPUTS, MAX_TX_OUTPUTS, MAX_TX_INPUTS, 10000, 65535, 8192, 64};

// Computes TxId/TxHash from the transaction's content. Input and output counts
// are bounded only by the wire format (MAX_WIRE_TX_*); the profile's
// max_inputs, max_outputs and max_mints are ignored, so a transaction over the
// consensus caps keeps the identity of its bytes and is rejected by validation
// instead. The profile's witness caps still apply.
bool ComputeTransactionIdentities(const Transaction &tx,
                                  const TxProfile &profile,
                                  const Hash32 &chain_id, Hash32 &txid,
                                  Hash32 &txhash, std::string &error,
                                  Hash32 *outputs_root_out = nullptr);

} // namespace lotus::v2

#endif
