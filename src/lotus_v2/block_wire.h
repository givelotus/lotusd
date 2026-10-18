// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_BLOCK_WIRE_H
#define LOTUS_V2_BLOCK_WIRE_H
#include "commitment.h"
#include "header.h"
#include "signing.h"
#include "transaction.h"
#include <string>
#include <vector>
namespace lotus::v2 {
struct FramedBlock {
    Header header;
    std::vector<Transaction> transactions;
    std::vector<uint64_t> frame_prefix_bytes;
    std::vector<uint64_t> transaction_bytes;
    std::vector<IdentityDigests> transaction_identities;
    uint64_t wire_bytes = 0;
};
// Structural codec only; no contextual header/state/monetary acceptance.
// Count is bounded by remaining bytes before allocation; every CS is shortest.
// Decode requires first-and-only coinbase, unique TxIDs and exact consumption.
bool DecodeBlockWire(const std::vector<uint8_t> &wire, const TxProfile &profile,
                     const ChainId &chain_id, FramedBlock &out,
                     std::string &error);
bool EncodeBlockWire(const Header &header, const std::vector<Transaction> &txs,
                     const TxProfile &profile, std::vector<uint8_t> &out,
                     std::string &error);
bool CompleteTransactionRoot(const std::vector<Transaction> &txs,
                             const TxProfile &profile, const ChainId &chain_id,
                             Hash &out, std::string &error);
uint64_t CompactSizeWidth(uint64_t value);
} // namespace lotus::v2
#endif
