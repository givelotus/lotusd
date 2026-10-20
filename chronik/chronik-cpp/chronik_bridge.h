// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHRONIK_CPP_CHRONIK_BRIDGE_H
#define BITCOIN_CHRONIK_CPP_CHRONIK_BRIDGE_H

#include <node/context.h>
#include <threadsafety.h>
#include <txmempool.h>

#include <memory>
#include <optional>
#include <rust/cxx.h>
#include <vector>

class CBlock;
class CBlockIndex;
class CBlockUndo;
class Coin;
class Config;
class CTransaction;

namespace Consensus {
struct Params;
} // namespace Consensus

class uint256;

namespace chronik_bridge {

struct BlockInfo;
struct V2FeeRateInfo;
struct Block;
struct Tx;
struct OutPoint;
struct WrappedBlockHash;
struct RawBlockHeader;

class block_index_not_found : public std::exception {
public:
    const char *what() const noexcept override {
        return "CBlockIndex not found";
    }
};

class invalid_block_range : public std::exception {
public:
    const char *what() const noexcept override {
        return "Invalid block range requested";
    }
};

void log_print(const rust::Str logging_function, const rust::Str source_file,
               const uint32_t source_line, const rust::Str msg,
               bool should_ratelimit);

void log_print_chronik(const rust::Str logging_function,
                       const rust::Str source_file, const uint32_t source_line,
                       const rust::Str msg);

/**
 * Bridge to bitcoind to access the node.
 */
class ChronikBridge {
    const node::NodeContext &m_node;

public:
    ChronikBridge(const node::NodeContext &node);

    const CBlockIndex &get_chain_tip() const;

    const CBlockIndex &lookup_block_index(std::array<uint8_t, 32> hash) const;

    const CBlockIndex &lookup_block_index_by_height(int height) const;

    rust::Vec<RawBlockHeader> get_block_headers_by_range(int start,
                                                         int end) const;
    rust::Vec<WrappedBlockHash> get_block_hashes_by_range(int start,
                                                          int end) const;

    std::unique_ptr<CBlock> load_block(const CBlockIndex &bindex) const;

    std::unique_ptr<CBlockUndo>
    load_block_undo(const CBlockIndex &bindex) const;

    Tx load_tx(uint32_t file_num, uint32_t data_pos, uint32_t undo_pos) const;

    rust::Vec<uint8_t> load_raw_tx(uint32_t file_num, uint32_t data_pos) const;

    /**
     * Read the transaction serialized at a block-file position (C++ only, for
     * the V2 index, which stores positions instead of transactions).
     */
    std::shared_ptr<const CTransaction> read_tx_from_disk(uint32_t file_num,
                                                         uint32_t data_pos) const;

    bool is_avalanche_finalized_preconsensus(
        const std::array<uint8_t, 32> &txid) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_node.mempool->cs);

    const CBlockIndex &find_fork(const CBlockIndex &index) const;

    void decode_raw_tx(rust::Slice<const uint8_t> raw_tx, Tx &tx) const;

    void lookup_spent_coins(Tx &, rust::Vec<OutPoint> &not_found,
                            rust::Vec<OutPoint> &coins_to_uncache) const;
    void uncache_coins(rust::Slice<const OutPoint>) const;

    std::array<uint8_t, 32> broadcast_tx(rust::Slice<const uint8_t> raw_tx,
                                         int64_t max_fee) const;

    void fatal_error(const rust::Str msg, const rust::Str user_msg) const;

    bool shutdown_requested() const;

    WrappedBlockHash get_genesis_hash() const;

    int64_t estimate_feerate_sats_per_kb() const;

    int64_t min_relay_feerate_sats_per_kb() const;

    bool get_feerate_info(std::array<uint8_t, 32> mempool_txid,
                          int64_t &modified_fee_rate_sats_per_kb,
                          uint32_t &virtual_size_bytes) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_node.mempool->cs);

    void sync_with_validation_interface_queue() const;
};

std::unique_ptr<ChronikBridge> make_bridge(const node::NodeContext &node);

/**
 * Description of a Lotus V2 3-branch Taproot-style output (`key_branch`,
 * optional `script_branch`, optional `data_branch`, and optional `token_id` /
 * `AssetId`) for bridging into Chronik's indexer.
 */
struct V2ThreeBranchOutputDesc {
    int64_t sats{0};
    std::array<uint8_t, 32> key_branch{};
    std::optional<std::array<uint8_t, 32>> script_branch{};
    std::optional<std::array<uint8_t, 32>> data_branch{};
    std::optional<std::array<uint8_t, 32>> token_id{};
    bool is_burn{false};
};

rust::Vec<uint8_t>
encode_v2_three_branch_output_script(const V2ThreeBranchOutputDesc &desc);

Tx bridge_tx(const CTransaction &tx, const std::vector<Coin> &spent_coins);

Block bridge_block(const CBlock &block, const CBlockUndo &block_undo,
                   const CBlockIndex &bindex);

BlockInfo get_block_info(const CBlockIndex &index);

rust::Vec<uint8_t> get_block_header(const CBlockIndex &index);

const CBlockIndex &get_block_ancestor(const CBlockIndex &index, int32_t height);

rust::Vec<uint8_t> compress_script(rust::Slice<const uint8_t> script);

rust::Vec<uint8_t> decompress_script(rust::Slice<const uint8_t> compressed);

int64_t calc_fee(size_t num_bytes, int64_t sats_fee_per_kb);

int64_t default_max_raw_tx_fee_rate_per_kb();

V2FeeRateInfo get_v2_fee_rate_info();

bool init_error(const rust::Str msg);

rust::String client_name();

rust::String format_full_version();

/** Count a Chronik HTTP request in the node's metrics (no-op without) */
void metrics_chronik_request(rust::Str route, uint16_t status, uint64_t nanos);
/** Add delta to the open Chronik WebSocket connections metric */
void metrics_chronik_ws_connections(int32_t delta);
/** Add delta to the active Chronik WebSocket subscriptions metric */
void metrics_chronik_ws_subscriptions(int32_t delta);

} // namespace chronik_bridge

#endif // BITCOIN_CHRONIK_CPP_CHRONIK_BRIDGE_H
