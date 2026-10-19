// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer query/blocks.rs (QueryBlocks).

#include <core/query/query.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/index/block_stats.h>
#include <chronik/native/merkle.h>

namespace chronik::native::query {

namespace {

[[noreturn]] void BlockNotFound(std::string_view what) {
    throw ChronikError("404: Block not found: " + std::string(what));
}

proto::BlockInfo MakeBlockInfoProto(const Avalanche &avalanche,
                                    const index::DbBlock &db_block,
                                    const index::BlockStats &block_stats) {
    proto::BlockInfo info;
    info.set_hash(HashStr(db_block.hash));
    info.set_prev_hash(HashStr(db_block.prev_hash));
    info.set_height(db_block.height);
    info.set_n_bits(db_block.n_bits);
    info.set_timestamp(db_block.timestamp);
    info.set_is_final(avalanche.IsFinalHeight(db_block.height));
    info.set_block_size(block_stats.block_size);
    info.set_num_txs(block_stats.num_txs);
    info.set_num_inputs(block_stats.num_inputs);
    info.set_num_outputs(block_stats.num_outputs);
    info.set_sum_input_sats(block_stats.sum_input_sats);
    info.set_sum_coinbase_output_sats(block_stats.sum_coinbase_output_sats);
    info.set_sum_normal_output_sats(block_stats.sum_normal_output_sats);
    info.set_sum_burned_sats(block_stats.sum_burned_sats);
    return info;
}

[[noreturn]] void MissingBlockStats(BlockHeight height) {
    throw ChronikError(
        "500: Inconsistent DB: Missing block stats for height " +
        std::to_string(height));
}

std::optional<index::DbBlock>
LookupDbBlock(const index::BlockReader &reader,
              std::string_view hash_or_height) {
    const HashOrHeight parsed = ParseHashOrHeight(hash_or_height);
    return parsed.is_hash ? reader.ByHash(parsed.hash)
                          : reader.ByHeight(parsed.height);
}

/**
 * Check that the start and end heights are consistent for a range of
 * blocks, and return the number of blocks.
 */
size_t CheckRangeBoundaries(BlockHeight start_height,
                            BlockHeight end_height) {
    if (start_height < 0) {
        throw ChronikError("400: Invalid block start height: " +
                           std::to_string(start_height));
    }
    if (end_height < start_height) {
        throw ChronikError("400: Invalid block end height: " +
                           std::to_string(end_height));
    }
    return size_t(end_height) - size_t(start_height) + 1;
}

void CheckNumBlocks(size_t num_blocks) {
    if (num_blocks > MAX_BLOCKS_PAGE_SIZE) {
        throw ChronikError(
            "400: Blocks page size too large, may not be above " +
            std::to_string(MAX_BLOCKS_PAGE_SIZE) + " but got " +
            std::to_string(num_blocks));
    }
}

/** QueryBlocks::merkle_root_and_branch (locked snapshot). */
std::pair<std::string, std::vector<std::string>>
MerkleRootAndBranch(const IndexerSnapshot &snap, BlockHeight block_height,
                    BlockHeight checkpoint_height) {
    std::string root;
    std::vector<std::string> branch;
    if (checkpoint_height > 0) {
        if (block_height > checkpoint_height) {
            throw ChronikError("400: Invalid checkpoint height " +
                               std::to_string(checkpoint_height) +
                               ", may not be below queried header height " +
                               std::to_string(block_height));
        }
        const size_t length = size_t(checkpoint_height) + 1;
        const size_t index = size_t(block_height);
        const index::BlockReader block_reader(snap.Store(), snap.Txn());
        const BlockHeight tip_height = block_reader.Height();
        if (checkpoint_height > tip_height) {
            throw ChronikError("400: Invalid checkpoint height " +
                               std::to_string(checkpoint_height) +
                               ", must be <= chain height " +
                               std::to_string(tip_height));
        }
        const auto [root_hash, branch_hashes] =
            snap.WithMerkleTree([&](MerkleTree &tree) {
                return tree.MerkleRootAndBranch(
                    length, index, [&](size_t start, size_t count) {
                        const auto hashes = block_reader.HashesByRange(
                            BlockHeight(start), count);
                        if (hashes.size() != count) {
                            const size_t missing = start + hashes.size();
                            BlockNotFound(std::to_string(missing));
                        }
                        std::vector<Hash32> out;
                        out.reserve(hashes.size());
                        for (const auto &hash : hashes) {
                            out.push_back(Hash32::FromBytes(hash));
                        }
                        return out;
                    });
            });
        root = HashStr(root_hash);
        for (const Hash32 &hash : branch_hashes) {
            branch.push_back(HashStr(hash));
        }
    }
    return {std::move(root), std::move(branch)};
}

} // namespace

proto::Block BlockByHashOrHeight(const IndexerSnapshot &snap,
                                 std::string_view hash_or_height) {
    const index::BlockReader db_blocks(snap.Store(), snap.Txn());
    const index::BlockStatsReader block_stats_reader(snap.Store(), snap.Txn());
    const std::optional<index::DbBlock> db_block =
        LookupDbBlock(db_blocks, hash_or_height);
    if (!db_block) {
        BlockNotFound(hash_or_height);
    }
    const std::optional<index::BlockStats> block_stats =
        block_stats_reader.ByHeight(db_block->height);
    if (!block_stats) {
        MissingBlockStats(db_block->height);
    }
    proto::Block block;
    *block.mutable_block_info() =
        MakeBlockInfoProto(snap.GetAvalanche(), *db_block, *block_stats);
    return block;
}

proto::Blocks BlocksByRange(const IndexerSnapshot &snap,
                            BlockHeight start_height,
                            BlockHeight end_height) {
    const size_t num_blocks = CheckRangeBoundaries(start_height, end_height);
    CheckNumBlocks(num_blocks);
    const index::BlockReader block_reader(snap.Store(), snap.Txn());
    const index::BlockStatsReader block_stats_reader(snap.Store(), snap.Txn());
    const Avalanche avalanche = snap.GetAvalanche();
    proto::Blocks blocks;
    for (int64_t height = start_height; height <= end_height; ++height) {
        const BlockHeight block_height = BlockHeight(height);
        const std::optional<index::DbBlock> block =
            block_reader.ByHeight(block_height);
        if (!block) {
            break;
        }
        const std::optional<index::BlockStats> block_stats =
            block_stats_reader.ByHeight(block_height);
        if (!block_stats) {
            MissingBlockStats(block_height);
        }
        *blocks.add_blocks() =
            MakeBlockInfoProto(avalanche, *block, *block_stats);
    }
    return blocks;
}

TxPagePlan PlanBlockTxs(const IndexerSnapshot &snap,
                        std::string_view hash_or_height,
                        size_t request_page_num, size_t request_page_size) {
    if (request_page_size < MIN_BLOCK_TXS_PAGE_SIZE) {
        throw ChronikError("400: Requested block tx page size " +
                           std::to_string(request_page_size) +
                           " is too small, minimum is " +
                           std::to_string(MIN_BLOCK_TXS_PAGE_SIZE));
    }
    if (request_page_size > MAX_BLOCK_TXS_PAGE_SIZE) {
        throw ChronikError("400: Requested block tx page size " +
                           std::to_string(request_page_size) +
                           " is too big, maximum is " +
                           std::to_string(MAX_BLOCK_TXS_PAGE_SIZE));
    }
    const index::BlockReader block_reader(snap.Store(), snap.Txn());
    const index::TxReader tx_reader(snap.Store(), snap.Txn());
    const std::optional<index::DbBlock> db_block =
        LookupDbBlock(block_reader, hash_or_height);
    if (!db_block) {
        BlockNotFound(hash_or_height);
    }
    const auto tx_range = tx_reader.BlockTxNumRange(db_block->height);
    if (!tx_range) {
        throw ChronikError("500: Inconsistent DB: Block " +
                           std::to_string(db_block->height) + " has no txs");
    }
    const auto [range_start, range_end] = *tx_range;
    const uint64_t tx_offset =
        request_page_num > SIZE_MAX / request_page_size
            ? SIZE_MAX
            : request_page_num * request_page_size;
    const auto sat_add = [](uint64_t a, uint64_t b) {
        return a > UINT64_MAX - b ? UINT64_MAX : a + b;
    };
    const uint64_t page_tx_num_start =
        std::min(sat_add(range_start, tx_offset), range_end);
    const uint64_t page_tx_num_end = std::min(
        sat_add(page_tx_num_start, request_page_size), range_end);

    TxPagePlan plan;
    try {
        for (TxNum tx_num = page_tx_num_start; tx_num < page_tx_num_end;
             ++tx_num) {
            const std::optional<index::BlockTx> db_tx =
                tx_reader.TxByTxNum(tx_num);
            if (!db_tx) {
                throw ChronikError("500: Inconsistent DB: block " +
                                   HashToHex(db_block->hash) +
                                   " has missing tx_num " +
                                   std::to_string(tx_num));
            }
            DbTxJob job;
            job.tx_num = tx_num;
            job.entry = db_tx->entry;
            job.block = *db_block;
            job.mempool_spent = CopyMempoolSpent(snap, db_tx->entry.txid);
            plan.jobs.emplace_back(std::move(job));
        }
    } catch (...) {
        plan.deferred = std::current_exception();
    }
    const size_t total_num_txs = size_t(range_end - range_start);
    plan.num_txs = uint32_t(total_num_txs);
    plan.num_pages = uint32_t((total_num_txs + request_page_size - 1) /
                              request_page_size);
    return plan;
}

proto::BlockHeader BlockHeader(const IndexerImpl &indexer, const Host &host,
                               std::string_view hash_or_height,
                               int32_t checkpoint_height) {
    const HashOrHeight parsed = ParseHashOrHeight(hash_or_height);
    const std::optional<BlockInfo> block_index =
        parsed.is_hash ? host.LookupBlock(parsed.hash)
                       : host.ActiveAtHeight(parsed.height);
    if (!block_index) {
        BlockNotFound(hash_or_height);
    }
    const BlockHeight block_height = block_index->height;
    std::pair<std::string, std::vector<std::string>> root_branch;
    if (checkpoint_height > 0) {
        IndexerSnapshot snap = indexer.Snapshot();
        root_branch =
            MerkleRootAndBranch(snap, block_height, checkpoint_height);
    }
    proto::BlockHeader header;
    header.set_raw_header(BytesStr(host.RawHeader(*block_index)));
    header.set_root(std::move(root_branch.first));
    for (std::string &hash : root_branch.second) {
        header.add_branch(std::move(hash));
    }
    return header;
}

proto::BlockHeaders BlockHeadersByRange(const IndexerImpl &indexer,
                                        const Host &host,
                                        BlockHeight start_height,
                                        BlockHeight end_height,
                                        int32_t checkpoint_height,
                                        bool check_num_blocks) {
    const size_t num_blocks = CheckRangeBoundaries(start_height, end_height);
    if (check_num_blocks) {
        CheckNumBlocks(num_blocks);
    }
    std::pair<std::string, std::vector<std::string>> root_branch;
    if (checkpoint_height > 0) {
        IndexerSnapshot snap = indexer.Snapshot();
        root_branch = MerkleRootAndBranch(snap, end_height, checkpoint_height);
    }
    const std::vector<Bytes> headers =
        host.RawHeadersByRange(start_height, end_height);
    proto::BlockHeaders result;
    for (size_t i = 0; i < headers.size(); ++i) {
        proto::BlockHeader *header = result.add_headers();
        header->set_raw_header(BytesStr(headers[i]));
        if (i + 1 == headers.size()) {
            header->set_root(root_branch.first);
            for (const std::string &hash : root_branch.second) {
                header->add_branch(hash);
            }
        }
    }
    return result;
}

} // namespace chronik::native::query
