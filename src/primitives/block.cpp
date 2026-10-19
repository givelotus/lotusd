// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <core_memusage.h>
#include <hash.h>
#include <lotus_v2/candidate_state_key.h>
#include <stdexcept>
#include <lotus_v2/commitment.h>
#include <lotus_v2/mempool_overlay.h>
#include <lotus_v2/monetary.h>
#include <lotus_v2/sparse_state.h>
#include <lotus_v2/tagged_hash.h>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <tinyformat.h>
#include <unordered_map>
#include <unordered_set>

namespace {
// Startup-selected process domain, immutable while node worker threads run.
lotus::v2::ChainId g_active_v2_chain_id{};
// Explicit temporary construction scopes affect only their calling thread.
thread_local const lotus::v2::ChainId *g_scoped_v2_chain_id{nullptr};
std::mutex g_v2_utxo_mutex;
std::mutex g_v2_state_io_mutex;
std::string g_v2_state_persist_dir;
uint64_t g_v2_state_directory_generation = 0;

using lotus::v2::SmtErase;
using lotus::v2::SmtInsert;
using lotus::v2::SmtKeyBit;
using lotus::v2::SmtNode;
using lotus::v2::SmtRoot;

struct V2BlockStateSnapshot {
    std::shared_ptr<const SmtNode> utxo_root;
    lotus::v2::MonetaryState mon_state;
    BlockHash parent_hash{};
    std::vector<lotus::v2::Outpoint> erased_outpoints;
    std::vector<lotus::v2::Coin> inserted_coins;
    uint64_t circulating_supply{0};
    bool persisted_to_disk{false};
};

struct CandidateV2StateCacheEntry {
    bool valid{false};
    BlockHash hashPrevBlock{};
    lotus::v2::Hash parent_utxo_digest{};
    lotus::v2::MonetaryState parent_mon_state{};
    uint64_t nHeight{0};
    uint64_t nParentMtp{0};
    uint32_t nBits{0};
    size_t tx_count{0};
    lotus::v2::Hash transaction_commitment{};
    V2BlockStateSnapshot snapshot{};
};

constexpr size_t kMaxCachedV2StateSnapshots = 64;
std::map<BlockHash, V2BlockStateSnapshot> g_v2_state_snapshots;
std::list<BlockHash> g_v2_state_lru;
std::map<BlockHash, std::list<BlockHash>::iterator> g_v2_state_lru_pos;
std::array<CandidateV2StateCacheEntry, 8> g_v2_candidate_cache{};
size_t g_v2_candidate_cache_pos = 0;
uint64_t g_latest_v2_circulating_supply = 0;

bool SaveV2BlockStateToDiskLocked(std::unique_lock<std::mutex> &lock, const BlockHash &blockHash,
                                  const V2BlockStateSnapshot &snap);

bool FlushV2BlockStatesToDiskLocked(std::unique_lock<std::mutex> &lock) {
    if (g_v2_state_persist_dir.empty()) return true;
    const std::string directory = g_v2_state_persist_dir;
    const auto generation = g_v2_state_directory_generation;
    std::vector<std::pair<BlockHash, V2BlockStateSnapshot>> pending;
    for (const auto &bh : g_v2_state_lru) {
        auto it = g_v2_state_snapshots.find(bh);
        if (it != g_v2_state_snapshots.end() && !it->second.persisted_to_disk)
            pending.emplace_back(bh, it->second);
    }
    bool all_written = true;
    for (const auto &[bh, snapshot] : pending) {
        if (generation != g_v2_state_directory_generation) return false;
        const bool written = SaveV2BlockStateToDiskLocked(lock, bh, snapshot);
        auto it = g_v2_state_snapshots.find(bh);
        if (written && generation == g_v2_state_directory_generation &&
            it != g_v2_state_snapshots.end() &&
            it->second.utxo_root == snapshot.utxo_root &&
            it->second.circulating_supply == snapshot.circulating_supply &&
            lotus::v2::EncodeMonetaryState(it->second.mon_state) ==
                lotus::v2::EncodeMonetaryState(snapshot.mon_state)) {
            it->second.persisted_to_disk = true;
        } else {
            all_written = false;
        }
    }
    return all_written;
}

void TouchV2StateLruLocked(std::unique_lock<std::mutex> &, const BlockHash &blockHash) {
    auto it = g_v2_state_lru_pos.find(blockHash);
    if (it != g_v2_state_lru_pos.end()) g_v2_state_lru.erase(it->second);
    g_v2_state_lru.push_back(blockHash);
    g_v2_state_lru_pos[blockHash] = std::prev(g_v2_state_lru.end());
}

bool CacheV2BlockStateLocked(std::unique_lock<std::mutex> &lock, const BlockHash &blockHash,
                             V2BlockStateSnapshot &&snap) {
    // Make room before publication. Failed persistence must neither lose the
    // oldest state nor permit an unbounded stream of new cached hashes.
    const auto generation = g_v2_state_directory_generation;
    const size_t max_entries = g_v2_state_persist_dir.empty() ? 256 : kMaxCachedV2StateSnapshots;
    while (!g_v2_state_snapshots.count(blockHash) &&
           g_v2_state_snapshots.size() >= max_entries) {
        if (g_v2_state_lru.empty()) return false;
        const BlockHash oldest = g_v2_state_lru.front();
        const auto found = g_v2_state_snapshots.find(oldest);
        if (found == g_v2_state_snapshots.end()) return false;
        const V2BlockStateSnapshot snapshot = found->second;
        const bool written = g_v2_state_persist_dir.empty() || snapshot.persisted_to_disk ||
            SaveV2BlockStateToDiskLocked(lock, oldest, snapshot);
        // An old eviction pass cannot walk a replacement directory/cache.
        if (!written || generation != g_v2_state_directory_generation) return false;
        const auto current = g_v2_state_snapshots.find(oldest);
        if (current == g_v2_state_snapshots.end() ||
            current->second.utxo_root != snapshot.utxo_root ||
            current->second.circulating_supply != snapshot.circulating_supply ||
            lotus::v2::EncodeMonetaryState(current->second.mon_state) !=
                lotus::v2::EncodeMonetaryState(snapshot.mon_state)) return false;
        g_v2_state_snapshots.erase(current);
        auto position = g_v2_state_lru_pos.find(oldest);
        if (position != g_v2_state_lru_pos.end()) {
            g_v2_state_lru.erase(position->second);
            g_v2_state_lru_pos.erase(position);
        }
    }
    g_v2_state_snapshots[blockHash] = std::move(snap);
    TouchV2StateLruLocked(lock, blockHash);
    return true;
}

constexpr uint64_t kDeltaSnapshotMagic = 0xFFFFFFFFFFFFFFFEULL;

constexpr lotus::v2::MonetaryProfile kDefaultMonetaryProfile{
    2, 16, 2, 4, 32, 60, 2, 2000, 3, 1000, 200, lotus::v2::Hash{2}};

lotus::v2::MonetaryState InitialV2MonetaryState() {
    return lotus::v2::GetInitialV2MonetaryState();
}



bool WriteV2BlockStateFile(const std::string &directory, const BlockHash &blockHash,
                                  const V2BlockStateSnapshot &snap) {
    if (directory.empty()) {
        return false;
    }
    std::error_code ec;
    const std::filesystem::path dir(directory);
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;
    const std::string hex_hash = blockHash.GetHex();
    const std::filesystem::path final_path = dir / (hex_hash + ".bin");
    const std::filesystem::path tmp_path = dir / (hex_hash + ".bin.tmp");

    std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        std::filesystem::create_directories(dir, ec);
        out.open(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }
    }

    // Stream block state deltas in bounded 64 KiB chunks so large blocks never
    // allocate a massive contiguous buffer while avoiding per-field write calls.
    constexpr size_t kStreamChunkBytes = 64 * 1024;
    std::vector<uint8_t> buf;
    buf.reserve(kStreamChunkBytes + 1024);

    auto flush_chunk = [&]() -> bool {
        if (buf.empty()) {
            return true;
        }
        out.write(reinterpret_cast<const char *>(buf.data()),
                  static_cast<std::streamsize>(buf.size()));
        buf.clear();
        return static_cast<bool>(out);
    };
    auto append_u32_le = [&buf](uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
        buf.push_back(static_cast<uint8_t>(v >> 16));
        buf.push_back(static_cast<uint8_t>(v >> 24));
    };
    auto append_u64_le = [&buf](uint64_t v) {
        for (unsigned i = 0; i < 8; ++i) {
            buf.push_back(static_cast<uint8_t>(v >> (8 * i)));
        }
    };

    const auto mon_bytes = lotus::v2::EncodeMonetaryState(snap.mon_state);
    buf.insert(buf.end(), mon_bytes.begin(), mon_bytes.end());
    append_u64_le(kDeltaSnapshotMagic);
    buf.insert(buf.end(), snap.parent_hash.begin(),
               snap.parent_hash.begin() + 32);
    append_u32_le(static_cast<uint32_t>(snap.erased_outpoints.size()));
    for (const auto &op : snap.erased_outpoints) {
        buf.insert(buf.end(), op.tx_id.begin(), op.tx_id.end());
        append_u32_le(op.index);
        if (buf.size() >= kStreamChunkBytes && !flush_chunk()) {
            out.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }
    append_u32_le(static_cast<uint32_t>(snap.inserted_coins.size()));
    std::vector<uint8_t> encoded;
    encoded.reserve(128);
    for (const auto &coin : snap.inserted_coins) {
        encoded.clear();
        if (!lotus::v2::EncodeCoin(coin, encoded)) {
            out.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
        append_u32_le(static_cast<uint32_t>(encoded.size()));
        buf.insert(buf.end(), encoded.begin(), encoded.end());
        if (buf.size() >= kStreamChunkBytes && !flush_chunk()) {
            out.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }
    if (!flush_chunk()) {
        out.close();
        std::filesystem::remove(tmp_path, ec);
        return false;
    }
    out.close();
    if (!out) {
        std::filesystem::remove(tmp_path, ec);
        return false;
    }
    std::filesystem::rename(tmp_path, final_path, ec);
    return !ec;
}

bool SaveV2BlockStateToDiskLocked(std::unique_lock<std::mutex> &lock,
                                  const BlockHash &blockHash,
                                  const V2BlockStateSnapshot &snap) {
    // Copy immutable tree ownership and the delta before releasing the cache
    // lock: callers may evict or replace the map entry during file I/O.
    const V2BlockStateSnapshot snapshot = snap;
    const std::string directory = g_v2_state_persist_dir;
    bool written = false;
    lock.unlock();
    try {
        {
            std::lock_guard<std::mutex> io_lock(g_v2_state_io_mutex);
            written = WriteV2BlockStateFile(directory, blockHash, snapshot);
        }
    } catch (...) {
        lock.lock();
        throw;
    }
    lock.lock();
    return written;
}

struct RawDiskDeltaSnapshot {
    BlockHash block_hash{};
    lotus::v2::MonetaryState mon_state{};
    bool is_delta{false};
    BlockHash parent_hash{};
    std::vector<lotus::v2::Outpoint> erased_outpoints;
    std::vector<lotus::v2::Coin> inserted_coins;
};

bool ReadRawDiskSnapshotFile(const std::string &directory, const BlockHash &blockHash,
                             RawDiskDeltaSnapshot &out) {
    if (directory.empty()) {
        return false;
    }
    const std::filesystem::path path =
        std::filesystem::path(directory) /
        (blockHash.GetHex() + ".bin");
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    out.block_hash = blockHash;
    std::vector<uint8_t> mon_bytes(56);
    if (!in.read(reinterpret_cast<char *>(mon_bytes.data()), 56)) {
        return false;
    }
    try {
        out.mon_state = lotus::v2::DecodeMonetaryState(mon_bytes);
    } catch (...) {
        return false;
    }
    uint8_t count_buf[8]{};
    if (!in.read(reinterpret_cast<char *>(count_buf), 8)) {
        return false;
    }
    uint64_t count = 0;
    for (unsigned i = 0; i < 8; ++i) {
        count |= uint64_t(count_buf[i]) << (8 * i);
    }
    if (count == kDeltaSnapshotMagic) {
        out.is_delta = true;
        uint256 parent_raw;
        if (!in.read(reinterpret_cast<char *>(parent_raw.begin()), 32)) {
            return false;
        }
        out.parent_hash = BlockHash{parent_raw};
        uint8_t erased_buf[4]{};
        if (!in.read(reinterpret_cast<char *>(erased_buf), 4)) {
            return false;
        }
        uint32_t erased_count = 0;
        for (unsigned i = 0; i < 4; ++i) {
            erased_count |= uint32_t(erased_buf[i]) << (8 * i);
        }
        if (erased_count > 1000000) {
            return false;
        }
        out.erased_outpoints.clear();
        out.erased_outpoints.reserve(erased_count);
        for (uint32_t c = 0; c < erased_count; ++c) {
            lotus::v2::Outpoint op{};
            if (!in.read(reinterpret_cast<char *>(op.tx_id.data()), 32)) {
                return false;
            }
            uint8_t idx_buf[4]{};
            if (!in.read(reinterpret_cast<char *>(idx_buf), 4)) {
                return false;
            }
            op.index = 0;
            for (unsigned i = 0; i < 4; ++i) {
                op.index |= uint32_t(idx_buf[i]) << (8 * i);
            }
            out.erased_outpoints.push_back(op);
        }
        uint8_t inserted_buf[4]{};
        if (!in.read(reinterpret_cast<char *>(inserted_buf), 4)) {
            return false;
        }
        uint32_t inserted_count = 0;
        for (unsigned i = 0; i < 4; ++i) {
            inserted_count |= uint32_t(inserted_buf[i]) << (8 * i);
        }
        if (inserted_count > 1000000) {
            return false;
        }
        out.inserted_coins.clear();
        out.inserted_coins.reserve(inserted_count);
        for (uint32_t c = 0; c < inserted_count; ++c) {
            uint8_t len_buf[4]{};
            if (!in.read(reinterpret_cast<char *>(len_buf), 4)) {
                return false;
            }
            uint32_t len = 0;
            for (unsigned i = 0; i < 4; ++i) {
                len |= uint32_t(len_buf[i]) << (8 * i);
            }
            if (len == 0 || len > lotus::v2::MAX_COIN_BYTES) {
                return false;
            }
            std::vector<uint8_t> encoded(len);
            if (!in.read(reinterpret_cast<char *>(encoded.data()), len)) {
                return false;
            }
            lotus::v2::Coin coin;
            if (!lotus::v2::DecodeCoinBytes(encoded, coin)) {
                return false;
            }
            out.inserted_coins.push_back(std::move(coin));
        }
        return true;
    }
    if (count > 1000000) {
        return false;
    }
    out.is_delta = false;
    out.parent_hash = BlockHash{};
    out.erased_outpoints.clear();
    out.inserted_coins.clear();
    out.inserted_coins.reserve(count);
    for (uint64_t c = 0; c < count; ++c) {
        uint8_t len_buf[4]{};
        if (!in.read(reinterpret_cast<char *>(len_buf), 4)) {
            return false;
        }
        uint32_t len = 0;
        for (unsigned i = 0; i < 4; ++i) {
            len |= uint32_t(len_buf[i]) << (8 * i);
        }
        if (len == 0 || len > lotus::v2::MAX_COIN_BYTES) {
            return false;
        }
        std::vector<uint8_t> encoded(len);
        if (!in.read(reinterpret_cast<char *>(encoded.data()), len)) {
            return false;
        }
        lotus::v2::Coin coin;
        if (!lotus::v2::DecodeCoinBytes(encoded, coin)) {
            return false;
        }
        out.inserted_coins.push_back(std::move(coin));
    }
    return true;
}

bool LoadV2BlockStateFromDiskLocked(std::unique_lock<std::mutex> &lock, const BlockHash &blockHash,
                                    V2BlockStateSnapshot &snap) {
    const auto generation = g_v2_state_directory_generation;
    std::vector<RawDiskDeltaSnapshot> chain;
    BlockHash cur = blockHash;
    std::shared_ptr<const lotus::v2::SmtNode> base_root{};

    while (!cur.IsNull()) {
        auto it = g_v2_state_snapshots.find(cur);
        if (it != g_v2_state_snapshots.end()) {
            base_root = it->second.utxo_root;
            break;
        }
        RawDiskDeltaSnapshot raw;
        const std::string directory = g_v2_state_persist_dir;
        bool read = false;
        lock.unlock();
        try {
            {
                std::lock_guard<std::mutex> io_lock(g_v2_state_io_mutex);
                read = ReadRawDiskSnapshotFile(directory, cur, raw);
            }
        } catch (...) {
            lock.lock();
            throw;
        }
        lock.lock();
        // A concurrent network/datadir reset invalidates this load, rather than
        // publishing an old directory's tree into the new cache generation.
        if (generation != g_v2_state_directory_generation) return false;
        if (!read) {
            if (chain.empty()) {
                return false;
            }
            // Reached unpersisted genesis ancestor; base UTXO tree is empty.
            base_root.reset();
            break;
        }
        const bool is_delta = raw.is_delta;
        const BlockHash next_parent = raw.parent_hash;
        chain.push_back(std::move(raw));
        if (!is_delta) {
            base_root.reset();
            break;
        }
        cur = next_parent;
    }

    std::shared_ptr<const lotus::v2::SmtNode> running_root = base_root;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        if (!it->is_delta) {
            running_root.reset();
        }
        if (it->erased_outpoints.size() + it->inserted_coins.size() >= 32) {
            lotus::v2::SmtBatchUpdateParallel(
                running_root, it->erased_outpoints, it->inserted_coins);
        } else {
            for (const auto &op : it->erased_outpoints) {
                SmtErase(running_root, op);
            }
            for (const auto &coin : it->inserted_coins) {
                SmtInsert(running_root, coin);
            }
        }
        V2BlockStateSnapshot built;
        built.utxo_root = running_root;
        built.mon_state = it->mon_state;
        built.parent_hash = it->parent_hash;
        built.erased_outpoints = std::move(it->erased_outpoints);
        built.inserted_coins = std::move(it->inserted_coins);
        built.circulating_supply =
            running_root ? running_root->total_value : 0;
        // These states came from complete files, so their cache eviction does
        // not need to rewrite them. Keep only the nearest bounded window: a
        // deep rewind can then reuse its reconstructed parents instead of
        // replaying the whole delta history again for every disconnected tip.
        built.persisted_to_disk = true;
        if (it + 1 == chain.rend()) {
            snap = built;
        }
        if (static_cast<size_t>(chain.rend() - it) <= kMaxCachedV2StateSnapshots &&
            !CacheV2BlockStateLocked(lock, it->block_hash, std::move(built))) {
            throw V2StateCacheError("Unable to cache reconstructed V2 state");
        }
    }
    return true;
}

lotus::v2::MonetaryState
AdvanceV2MonetaryStateForBlock(const lotus::v2::MonetaryState &parent_mon_state,
                               uint32_t nBits,
                               const lotus::v2::MonetaryInteger &block_cost) {
    lotus::v2::Hash pow_limit{};
    pow_limit.fill(0xff);
    lotus::v2::Hash target_hash{};
    lotus::v2::MonetaryInteger work = 2;
    if (lotus::v2::DecodeTarget(nBits, pow_limit, target_hash)) {
        lotus::v2::MonetaryInteger target_int = 0;
        for (size_t i = target_hash.size(); i > 0; --i) {
            target_int <<= 8;
            target_int += target_hash[i - 1];
        }
        work = (lotus::v2::MonetaryInteger(1) << 256) / (target_int + 1);
        if (work == 0) {
            work = 1;
        }
    }
    const lotus::v2::MonetaryInteger capped_cost =
        (lotus::v2::RequiredBlockBurn(block_cost,
                                      parent_mon_state.ema_block_cost,
                                      kDefaultMonetaryProfile) >
         parent_mon_state.tail_subsidy)
            ? lotus::v2::MonetaryInteger(kDefaultMonetaryProfile.ema_min)
            : block_cost;
    const lotus::v2::MonetaryTransition transition = lotus::v2::AdvanceMonetary(
        kDefaultMonetaryProfile, parent_mon_state, work, {},
        /*coinbase_native_outputs=*/0, /*coinbase_native_burn=*/0,
        /*coinbase_bytes=*/0, /*tx_frame_prefix_bytes=*/0, capped_cost,
        capped_cost);
    return transition.state;
}

bool MonetaryStatesEqual(const lotus::v2::MonetaryState &a,
                         const lotus::v2::MonetaryState &b) noexcept {
    return a.bootstrap_reserve == b.bootstrap_reserve &&
           a.tail_subsidy == b.tail_subsidy && a.prev_work == b.prev_work &&
           a.ema_block_cost == b.ema_block_cost;
}

V2BlockStateSnapshot BuildNextV2BlockState(const CBlock &block,
                                           const BlockHash &hashPrevBlock,
                                           uint64_t nHeight,
                                           uint64_t nParentMtp) {
    V2BlockStateSnapshot state{{}, InitialV2MonetaryState(), hashPrevBlock, {}, {}, 0};
    if (nHeight == 0) {
        return state;
    }

    // Commit every byte of both identities, in block order. The previous
    // two-word mixer ignored 24 bytes of each identity and was not binding.
    lotus::v2::CandidateStateHasher candidate_hasher(std::span<const uint8_t, 32>(hashPrevBlock.begin(), 32));
    for (const auto &ptx : block.vtx) {
        candidate_hasher.Add(std::span<const uint8_t, 32>(ptx->GetId().begin(), 32),
                             std::span<const uint8_t, 32>(ptx->GetHash().begin(), 32));
    }
    const auto transaction_commitment = candidate_hasher.Finalize();

    lotus::v2::Hash parent_utxo_digest{};
    lotus::v2::MonetaryState parent_mon_state{};
    {
        std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
        if (!hashPrevBlock.IsNull()) {
            auto it = g_v2_state_snapshots.find(hashPrevBlock);
            if (it != g_v2_state_snapshots.end()) {
                state.utxo_root = it->second.utxo_root;
                state.mon_state = it->second.mon_state;
                state.circulating_supply = it->second.circulating_supply;
            } else if (LoadV2BlockStateFromDiskLocked(lock, hashPrevBlock, state)) {
                V2BlockStateSnapshot cached = state;
                CacheV2BlockStateLocked(lock, hashPrevBlock, std::move(cached));
                state.parent_hash = hashPrevBlock;
                state.erased_outpoints.clear();
                state.inserted_coins.clear();
            }
        }
        // Loading the parent may mark its snapshot persisted. This derived
        // child has not been written and must still be persisted on eviction.
        state.persisted_to_disk = false;
        parent_utxo_digest = SmtRoot(state.utxo_root);
        parent_mon_state = state.mon_state;

        for (const auto &entry : g_v2_candidate_cache) {
            if (entry.valid && entry.hashPrevBlock == hashPrevBlock &&
                entry.nHeight == nHeight && entry.nParentMtp == nParentMtp &&
                entry.nBits == block.nBits &&
                entry.tx_count == block.vtx.size() &&
                entry.transaction_commitment == transaction_commitment &&
                entry.parent_utxo_digest == parent_utxo_digest &&
                MonetaryStatesEqual(entry.parent_mon_state, parent_mon_state)) {
                return entry.snapshot;
            }
        }
    }

    std::vector<uint64_t> tx_linear_costs;
    tx_linear_costs.reserve(block.vtx.size());
    std::unordered_set<lotus::v2::Outpoint, lotus::v2::OutpointHasher>
        block_spent;
    block_spent.reserve(block.vtx.size() * 2);
    std::vector<lotus::v2::Outpoint> ordered_spent;
    ordered_spent.reserve(block.vtx.size() * 2);
    std::unordered_map<lotus::v2::Outpoint, lotus::v2::Coin,
                       lotus::v2::OutpointHasher>
        block_created;
    block_created.reserve(block.vtx.size() * 2);
    std::vector<lotus::v2::Coin> ordered_created;
    ordered_created.reserve(block.vtx.size() * 2);

    // CTOR may place a child before its parent. Fee lookup must include all
    // block-created values, while the coalesced state update stays unchanged.
    for (const auto &transaction : block.vtx) {
        lotus::v2::Hash id{};
        std::copy_n(transaction->GetId().begin(), 32, id.begin());
        for (size_t index = 0; index < transaction->vout.size(); ++index) {
            if (transaction->vout[index].scriptPubKey.IsUnspendable()) continue;
            const auto output = transaction->vout[index].ToV2Output();
            if (!output.IsBurn()) {
                const lotus::v2::Outpoint outpoint{id, uint32_t(index)};
                block_created.emplace(outpoint, lotus::v2::Coin{outpoint, output});
            }
        }
    }
    for (const auto &ptx : block.vtx) {
        const CTransaction &tx = *ptx;
        const uint64_t linear_cost =
            uint64_t(tx.GetTotalSize()) +
            uint64_t(tx.vin.size() * 64 + tx.vout.size() * 64);
        tx_linear_costs.push_back(linear_cost);
        uint64_t resolved_in_value = 0;
        bool all_inputs_resolved = !tx.IsCoinBase();
        if (!tx.IsCoinBase()) {
            for (const auto &txin : tx.vin) {
                if (txin.nFlags != 3) {
                    lotus::v2::Outpoint op{};
                    std::memcpy(op.tx_id.data(), txin.prevout.GetTxId().begin(),
                                32);
                    op.index = txin.prevout.GetN();
                    if (all_inputs_resolved) {
                        auto it_bc = block_created.find(op);
                        if (it_bc != block_created.end()) {
                            if (!it_bc->second.output.HasToken()) {
                                resolved_in_value += it_bc->second.output.value;
                            }
                        } else if (auto found =
                                       lotus::v2::SmtFind(state.utxo_root, op)) {
                            if (!found->output.HasToken()) {
                                resolved_in_value += found->output.value;
                            }
                        } else {
                            all_inputs_resolved = false;
                        }
                    }
                    block_spent.insert(op);
                    ordered_spent.push_back(op);
                }
            }
        }
        size_t spendable_outputs = 0;
        uint64_t native_out_value = 0;
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            if (tx.vout[j].scriptPubKey.IsUnspendable()) {
                continue;
            }
            const lotus::v2::Output v2out = tx.vout[j].ToV2Output();
            if (!v2out.HasToken()) {
                native_out_value += v2out.value;
            }
            if (!v2out.IsBurn()) {
                ++spendable_outputs;
            }
        }
        const uint64_t tx_fee_atoms =
            (all_inputs_resolved && resolved_in_value >= native_out_value)
                ? (resolved_in_value - native_out_value)
                : 0;
        const uint64_t fee_per_output =
            tx.IsCoinBase() ? 0
                            : lotus::v2::ComputeTxFeePerSpendableOutput(
                                  tx_fee_atoms, spendable_outputs);
        const uint64_t exp_height = lotus::v2::ComputeUtxoExpirationHeight(
            nHeight, tx.IsCoinBase(), fee_per_output);

        lotus::v2::Hash txid{};
        std::memcpy(txid.data(), tx.GetId().begin(), 32);
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            if (tx.vout[j].scriptPubKey.IsUnspendable()) {
                continue;
            }
            const lotus::v2::Output v2out = tx.vout[j].ToV2Output();
            if (!v2out.IsBurn()) {
                lotus::v2::Coin coin{
                    {txid, static_cast<uint32_t>(j)},
                    v2out,
                    nHeight,
                    nParentMtp,
                    tx.IsCoinBase(),
                    fee_per_output,
                    exp_height};
                block_created[coin.outpoint] = coin;
                ordered_created.push_back(std::move(coin));
            }
        }
    }

    // Apply base-chain erasures first, then surviving block creations so that
    // intra-block CTOR parent-child spends (even when child TxId < parent TxId)
    // elide cleanly and produce identical UTXO roots to topological execution.
    for (const auto &op : ordered_spent) {
        if (block_created.find(op) == block_created.end()) {
            state.erased_outpoints.push_back(op);
        }
    }
    for (auto &coin : ordered_created) {
        if (block_spent.find(coin.outpoint) == block_spent.end()) {
            state.inserted_coins.push_back(std::move(coin));
        }
    }
    if (state.erased_outpoints.size() + state.inserted_coins.size() >= 32) {
        lotus::v2::SmtBatchUpdateParallel(state.utxo_root,
                                          state.erased_outpoints,
                                          state.inserted_coins);
    } else {
        for (const auto &op : state.erased_outpoints) {
            SmtErase(state.utxo_root, op);
        }
        for (const auto &coin : state.inserted_coins) {
            SmtInsert(state.utxo_root, coin);
        }
    }

    // C17a deterministic block-level expiry sweep (capped at MAX_EXPIRY_SWEEPS_PER_BLOCK).
    if (state.utxo_root &&
        state.utxo_root->min_expiration_height <= nHeight) {
        const auto expired_coins =
            lotus::v2::SmtCollectExpired(state.utxo_root, nHeight);
        for (const auto &exp_coin : expired_coins) {
            SmtErase(state.utxo_root, exp_coin.outpoint);
            state.erased_outpoints.push_back(exp_coin.outpoint);
        }
    }

    const lotus::v2::MonetaryInteger envelope_cost =
        138 + uint64_t(block.vtx.size()) * 64;
    const lotus::v2::MonetaryInteger block_cost = lotus::v2::BlockEffectiveCost(
        envelope_cost, tx_linear_costs, kDefaultMonetaryProfile);
    state.mon_state = AdvanceV2MonetaryStateForBlock(state.mon_state,
                                                     block.nBits, block_cost);
    state.circulating_supply =
        state.utxo_root ? state.utxo_root->total_value : 0;

    {
        std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
        auto &slot =
            g_v2_candidate_cache[g_v2_candidate_cache_pos++ %
                                 g_v2_candidate_cache.size()];
        slot.valid = true;
        slot.hashPrevBlock = hashPrevBlock;
        slot.parent_utxo_digest = parent_utxo_digest;
        slot.parent_mon_state = parent_mon_state;
        slot.nHeight = nHeight;
        slot.nParentMtp = nParentMtp;
        slot.nBits = block.nBits;
        slot.tx_count = block.vtx.size();
        slot.transaction_commitment = transaction_commitment;
        slot.snapshot = state;
    }

    return state;
}

void ExtractOverlayTxData(
    const CTransaction &tx,
    uint64_t nHeight,
    uint64_t nParentMtp,
    int64_t fee_sats,
    lotus::v2::Hash &tx_id,
    lotus::v2::Hash &tx_hash,
    uint64_t &linear_cost,
    std::vector<lotus::v2::Outpoint> &spent_outpoints,
    std::vector<lotus::v2::Coin> &created_coins) {
    std::memcpy(tx_id.data(), tx.GetId().begin(), 32);
    std::memcpy(tx_hash.data(), tx.GetHash().begin(), 32);
    linear_cost = uint64_t(tx.GetTotalSize()) +
                  uint64_t(tx.vin.size() * 64 + tx.vout.size() * 64);

    spent_outpoints.clear();
    if (!tx.IsCoinBase()) {
        spent_outpoints.reserve(tx.vin.size());
        for (const auto &txin : tx.vin) {
            if (txin.nFlags != 3) {
                lotus::v2::Outpoint op{};
                std::memcpy(op.tx_id.data(), txin.prevout.GetTxId().begin(),
                            32);
                op.index = txin.prevout.GetN();
                spent_outpoints.push_back(op);
            }
        }
    }

    created_coins.clear();
    created_coins.reserve(tx.vout.size());
    size_t spendable_outputs = 0;
    for (const auto &output : tx.vout) {
        if (!output.scriptPubKey.IsUnspendable() &&
            !output.ToV2Output().IsBurn()) ++spendable_outputs;
    }
    const uint64_t fee_share = tx.IsCoinBase() ? 0 :
        lotus::v2::ComputeTxFeePerSpendableOutput(
            fee_sats > 0 ? static_cast<uint64_t>(fee_sats) : 0,
            spendable_outputs);
    const uint64_t exp_height = lotus::v2::ComputeUtxoExpirationHeight(
        nHeight, tx.IsCoinBase(), fee_share);
    for (size_t j = 0; j < tx.vout.size(); ++j) {
        if (tx.vout[j].scriptPubKey.IsUnspendable()) {
            continue;
        }
        const lotus::v2::Output v2out = tx.vout[j].ToV2Output();
        if (!v2out.IsBurn()) {
            lotus::v2::Coin coin{
                {tx_id, static_cast<uint32_t>(j)},
                v2out,
                nHeight,
                nParentMtp,
                tx.IsCoinBase(),
                fee_share,
                exp_height};
            created_coins.push_back(std::move(coin));
        }
    }
}

void CollectSmtCoins(const std::shared_ptr<const SmtNode> &node,
                     std::vector<lotus::v2::Coin> &out) {
    if (!node) {
        return;
    }
    if (node->IsLeaf()) {
        out.push_back(*node->coin);
        return;
    }
    CollectSmtCoins(node->child[0], out);
    CollectSmtCoins(node->child[1], out);
}
} // namespace

ScopedV2ChainId::ScopedV2ChainId(const lotus::v2::ChainId &chain_id) noexcept
    : m_chain_id(chain_id), m_previous(g_scoped_v2_chain_id) {
    g_scoped_v2_chain_id = &m_chain_id;
}

ScopedV2ChainId::~ScopedV2ChainId() noexcept {
    assert(g_scoped_v2_chain_id == &m_chain_id);
    g_scoped_v2_chain_id = m_previous;
}

const lotus::v2::ChainId &GetActiveV2ChainId() {
    return g_scoped_v2_chain_id ? *g_scoped_v2_chain_id : g_active_v2_chain_id;
}

void SetActiveV2ChainId(const lotus::v2::ChainId &chain_id) {
    g_active_v2_chain_id = chain_id;
}

void SetV2StatePersistDir(const std::string &dir_path) {
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    if (g_v2_state_persist_dir != dir_path) {
        FlushV2BlockStatesToDiskLocked(lock);
        g_v2_state_persist_dir = dir_path;
        ++g_v2_state_directory_generation;
        g_v2_state_snapshots.clear();
        g_v2_state_lru.clear();
        g_v2_state_lru_pos.clear();
        for (auto &slot : g_v2_candidate_cache) {
            slot.valid = false;
        }
    }
}

bool FlushV2BlockStatesToDisk() {
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    return FlushV2BlockStatesToDiskLocked(lock);
}

bool GetV2BlockStateSnapshot(
    const BlockHash &blockHash,
    std::shared_ptr<const lotus::v2::SmtNode> &utxo_root_out,
    lotus::v2::MonetaryState &mon_state_out) {
    if (blockHash.IsNull()) {
        utxo_root_out.reset();
        mon_state_out = InitialV2MonetaryState();
        return true;
    }
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    auto it = g_v2_state_snapshots.find(blockHash);
    if (it != g_v2_state_snapshots.end()) {
        utxo_root_out = it->second.utxo_root;
        mon_state_out = it->second.mon_state;
        TouchV2StateLruLocked(lock, blockHash);
        return true;
    }
    V2BlockStateSnapshot loaded{{}, InitialV2MonetaryState(), BlockHash(), {}, {}};
    if (LoadV2BlockStateFromDiskLocked(lock, blockHash, loaded)) {
        loaded.persisted_to_disk = true;
        utxo_root_out = loaded.utxo_root;
        mon_state_out = loaded.mon_state;
        CacheV2BlockStateLocked(lock, blockHash, std::move(loaded));
        return true;
    }
    utxo_root_out.reset();
    mon_state_out = InitialV2MonetaryState();
    return false;
}

uint256 ComputeV2BlockStateRoot(const CBlock &block,
                                const BlockHash &hashPrevBlock,
                                uint64_t nHeight,
                                uint64_t nParentMtp,
                                bool record) {
    V2BlockStateSnapshot next_state =
        BuildNextV2BlockState(block, hashPrevBlock, nHeight, nParentMtp);
    const lotus::v2::Hash utxo_root = SmtRoot(next_state.utxo_root);
    const lotus::v2::Hash sroot = lotus::v2::StateRoot(
        GetActiveV2ChainId(), nHeight, utxo_root, next_state.mon_state);
    uint256 out;
    std::memcpy(out.begin(), sroot.data(), 32);
    // Return the computed root to the validation caller even on mismatch: peer
    // input must be rejected through BlockValidationState, not an exception.
    // Only a header that actually commits this state may publish a snapshot.
    if (record && block.hashStateRoot == out) {
        CBlockHeader hdr = block.GetBlockHeader();
        const BlockHash blockHash = hdr.GetHash();
        std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
        const auto supply = next_state.circulating_supply;
        if (!CacheV2BlockStateLocked(lock, blockHash, std::move(next_state)))
            throw V2StateCacheError("Unable to persist evicted V2 state");
        g_latest_v2_circulating_supply = supply;
    }
    return out;
}

void RecordV2BlockState(const CBlock &block,
                        const BlockHash &blockHash,
                        const BlockHash &hashPrevBlock,
                        uint64_t nHeight,
                        uint64_t nParentMtp) {
    RecordV2BlockState(block, blockHash, hashPrevBlock, nHeight, nParentMtp, false);
}

void RecordV2BlockState(const CBlock &block,
                        const BlockHash &blockHash,
                        const BlockHash &hashPrevBlock,
                        uint64_t nHeight,
                        uint64_t nParentMtp,
                        bool allow_uncommitted_state_root) {
    V2BlockStateSnapshot next_state =
        BuildNextV2BlockState(block, hashPrevBlock, nHeight, nParentMtp);
    const auto state_root = lotus::v2::StateRoot(
        GetActiveV2ChainId(), nHeight, SmtRoot(next_state.utxo_root), next_state.mon_state);
    if (std::memcmp(state_root.data(), block.hashStateRoot.begin(), 32) != 0 &&
        !(allow_uncommitted_state_root && block.hashStateRoot.IsNull())) {
        throw std::invalid_argument("V2 block header state root mismatch");
    }
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    const auto supply = next_state.circulating_supply;
    if (!CacheV2BlockStateLocked(lock, blockHash, std::move(next_state)))
        throw V2StateCacheError("Unable to persist evicted V2 state");
    g_latest_v2_circulating_supply = supply;
}

uint64_t GetV2BlockCirculatingSupply(const BlockHash &blockHash) {
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    if (blockHash.IsNull()) {
        return g_latest_v2_circulating_supply;
    }
    auto it = g_v2_state_snapshots.find(blockHash);
    if (it != g_v2_state_snapshots.end()) {
        return it->second.circulating_supply;
    }
    V2BlockStateSnapshot snap;
    if (LoadV2BlockStateFromDiskLocked(lock, blockHash, snap)) {
        snap.persisted_to_disk = true;
        const uint64_t supply = snap.circulating_supply;
        if (CacheV2BlockStateLocked(lock, blockHash, std::move(snap)))
            g_latest_v2_circulating_supply = supply;
        return supply;
    }
    return g_latest_v2_circulating_supply;
}

void SetV2BlockCirculatingSupplyForTest(const BlockHash &blockHash,
                                        uint64_t circulating_supply) {
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    if (!blockHash.IsNull()) {
        V2BlockStateSnapshot snap;
        const auto it = g_v2_state_snapshots.find(blockHash);
        if (it != g_v2_state_snapshots.end()) snap = it->second;
        if (snap.mon_state.tail_subsidy == 0) snap.mon_state = InitialV2MonetaryState();
        snap.circulating_supply = circulating_supply;
        if (!CacheV2BlockStateLocked(lock, blockHash, std::move(snap)))
            throw V2StateCacheError("Unable to persist evicted V2 state");
    }
    g_latest_v2_circulating_supply = circulating_supply;
}

uint256 ComputeV2TxRootFromSubtreeA(const CTransaction &coinbase_tx,
                                    const lotus::v2::Hash &subtree_a_root) {
    std::array<uint8_t, 65> cb_buf{};
    cb_buf[0] = 0x00;
    std::memcpy(cb_buf.data() + 1, coinbase_tx.GetId().begin(), 32);
    std::memcpy(cb_buf.data() + 33, coinbase_tx.GetHash().begin(), 32);
    const lotus::v2::Hash cb_leaf =
        lotus::v2::TaggedHash(lotus::v2::HashDomain::TxRoot, cb_buf);

    std::array<uint8_t, 65> top{};
    top[0] = 0x03;
    std::memcpy(top.data() + 1, cb_leaf.data(), 32);
    std::memcpy(top.data() + 33, subtree_a_root.data(), 32);
    const lotus::v2::Hash tx_root =
        lotus::v2::TaggedHash(lotus::v2::HashDomain::TxRoot, top);

    uint256 out;
    std::memcpy(out.begin(), tx_root.data(), 32);
    return out;
}

uint256 ComputeV2StateRootFromOverlay(
    const CTransaction &coinbase_tx,
    const lotus::v2::MempoolOverlayLayer &overlay,
    uint32_t nBits, uint64_t nHeight, uint64_t nParentMtp,
    bool record, const BlockHash *pBlockHash) {
    return ComputeV2StateRootFromOverlay(coinbase_tx, overlay, nBits, nHeight,
                                       nParentMtp, record, pBlockHash, nullptr);
}

uint256 ComputeV2StateRootFromOverlay(
    const CTransaction &coinbase_tx,
    const lotus::v2::MempoolOverlayLayer &overlay,
    uint32_t nBits,
    uint64_t nHeight,
    uint64_t nParentMtp,
    bool record,
    const BlockHash *pBlockHash,
    const uint256 *declared_state_root) {
    if (nHeight == 0) {
        const lotus::v2::Hash utxo_root = lotus::v2::EmptyUtxoRoot();
        const lotus::v2::MonetaryState mon_state = InitialV2MonetaryState();
        const lotus::v2::Hash sroot = lotus::v2::StateRoot(
            GetActiveV2ChainId(), 0, utxo_root, mon_state);
        uint256 out;
        std::memcpy(out.begin(), sroot.data(), 32);
        return out;
    }

    lotus::v2::Hash cb_txid{};
    std::memcpy(cb_txid.data(), coinbase_tx.GetId().begin(), 32);
    std::shared_ptr<const SmtNode> final_utxo_root = overlay.GetUtxoRoot();
    std::vector<lotus::v2::Coin> cb_coins;
    for (size_t j = 0; j < coinbase_tx.vout.size(); ++j) {
        if (coinbase_tx.vout[j].scriptPubKey.IsUnspendable()) {
            continue;
        }
        const lotus::v2::Output v2out = coinbase_tx.vout[j].ToV2Output();
        if (!v2out.IsBurn()) {
            lotus::v2::Coin coin{
                {cb_txid, static_cast<uint32_t>(j)},
                v2out,
                nHeight,
                nParentMtp,
                true};
            SmtInsert(final_utxo_root, coin);
            if (record) {
                cb_coins.push_back(std::move(coin));
            }
        }
    }
    const lotus::v2::Hash utxo_digest = SmtRoot(final_utxo_root);

    const uint64_t cb_linear_cost =
        coinbase_tx.GetTotalSize() +
        uint64_t(coinbase_tx.vin.size() * 64 + coinbase_tx.vout.size() * 64);
    const uint64_t cb_eff_cost = lotus::v2::TransactionEffectiveCost(
        cb_linear_cost, kDefaultMonetaryProfile);
    const lotus::v2::MonetaryInteger envelope_cost =
        138 + uint64_t(1 + overlay.GetTxCount()) * 64;
    const lotus::v2::MonetaryInteger block_cost =
        envelope_cost + lotus::v2::MonetaryInteger(cb_eff_cost) +
        lotus::v2::MonetaryInteger(overlay.GetSumNonCbEffectiveCost());

    const lotus::v2::MonetaryState next_mon_state =
        AdvanceV2MonetaryStateForBlock(overlay.GetBaseMonetaryState(), nBits,
                                       block_cost);

    const lotus::v2::Hash sroot = lotus::v2::StateRoot(
        GetActiveV2ChainId(), nHeight, utxo_digest, next_mon_state);
    uint256 out;
    std::memcpy(out.begin(), sroot.data(), 32);

    if (record && pBlockHash != nullptr && declared_state_root != nullptr &&
        *declared_state_root == out) {
        uint256 parent_raw;
        std::memcpy(parent_raw.begin(), overlay.GetParentBlockId().data(), 32);
        V2BlockStateSnapshot next_state;
        next_state.utxo_root = std::move(final_utxo_root);
        next_state.mon_state = next_mon_state;
        next_state.parent_hash = BlockHash{parent_raw};
        next_state.erased_outpoints = overlay.GetNetErasedOutpoints();
        next_state.inserted_coins = overlay.GetNetInsertedCoins();
        for (auto &c : cb_coins) {
            next_state.inserted_coins.push_back(std::move(c));
        }
        next_state.circulating_supply =
            next_state.utxo_root ? next_state.utxo_root->total_value : 0;
        std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
        const auto supply = next_state.circulating_supply;
        if (!CacheV2BlockStateLocked(lock, *pBlockHash, std::move(next_state)))
            throw V2StateCacheError("Unable to persist evicted V2 state");
        g_latest_v2_circulating_supply = supply;
    }

    return out;
}

namespace {
//! Retained-body charge for pinned reconciliation views; matches the former
//! full-mempool snapshot capture charge max(serialized, recursive usage).
uint32_t OverlayPayloadBytes(const CTransactionRef &ptx) {
    const size_t bytes = std::max<size_t>(GetSerializeSize(*ptx),
                                          RecursiveDynamicUsage(ptx));
    return static_cast<uint32_t>(
        std::min<size_t>(bytes, std::numeric_limits<uint32_t>::max()));
}
} // namespace

bool AddTransactionToOverlay(lotus::v2::MempoolOverlayLayer &overlay,
                             const CTransactionRef &ptx,
                             int64_t fee_sats,
                             int64_t sigchecks) {
    if (!ptx || ptx->IsCoinBase()) {
        return false;
    }
    lotus::v2::Hash tx_id{};
    lotus::v2::Hash tx_hash{};
    uint64_t linear_cost = 0;
    std::vector<lotus::v2::Outpoint> spent;
    std::vector<lotus::v2::Coin> created;
    ExtractOverlayTxData(*ptx, overlay.GetHeight(), overlay.GetParentMtp(),
                         fee_sats, tx_id, tx_hash, linear_cost, spent, created);
    return overlay.AddTransaction(tx_id, tx_hash, linear_cost, spent, created,
                                  fee_sats, sigchecks, ptx,
                                  OverlayPayloadBytes(ptx));
}

bool AddTransactionToOverlay(lotus::v2::MerklixOverlayManager &manager,
                             const CTransactionRef &ptx,
                             int64_t fee_sats,
                             int64_t sigchecks) {
    return AddTransactionToOverlay(manager.GetSpeculativeOverlay(), ptx,
                                   fee_sats, sigchecks);
}

size_t AddTransactionsToOverlayBatch(
    lotus::v2::MempoolOverlayLayer &overlay,
    std::span<const std::tuple<CTransactionRef, int64_t, int64_t>> txs) {
    if (txs.empty()) {
        return 0;
    }
    if (txs.size() == 1) {
        const auto &[ptx, fee_sats, sigchecks] = txs[0];
        return AddTransactionToOverlay(overlay, ptx, fee_sats, sigchecks) ? 1 : 0;
    }

    const uint64_t nHeight = overlay.GetHeight();
    const uint64_t nParentMtp = overlay.GetParentMtp();
    std::vector<lotus::v2::OverlayTxEntry> entries(txs.size());

    auto extract_range = [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
            const auto &[ptx, fee_sats, sigchecks] = txs[i];
            if (!ptx || ptx->IsCoinBase()) {
                continue;
            }
            auto &e = entries[i];
            ExtractOverlayTxData(*ptx, nHeight, nParentMtp, fee_sats, e.tx_id, e.tx_hash,
                                 e.linear_cost, e.spent_outpoints,
                                 e.created_coins);
            e.fee_sats = fee_sats;
            e.sigchecks = sigchecks;
            e.tx_ref = ptx;
            e.payload_bytes = OverlayPayloadBytes(ptx);
        }
    };

    if (txs.size() >= 64) {
        const unsigned hw = std::thread::hardware_concurrency();
        const size_t num_workers = std::min<size_t>(
            std::max<unsigned>(1, hw == 0 ? 4 : hw),
            (txs.size() + 31) / 32);
        if (num_workers <= 1) {
            extract_range(0, txs.size());
        } else {
            const size_t chunk = (txs.size() + num_workers - 1) / num_workers;
            std::vector<std::thread> workers;
            workers.reserve(num_workers - 1);
            for (size_t w = 1; w < num_workers; ++w) {
                const size_t begin = w * chunk;
                if (begin >= txs.size()) {
                    break;
                }
                const size_t end = std::min(txs.size(), begin + chunk);
                workers.emplace_back(extract_range, begin, end);
            }
            extract_range(0, std::min(txs.size(), chunk));
            for (auto &t : workers) {
                t.join();
            }
        }
    } else {
        extract_range(0, txs.size());
    }

    size_t write_idx = 0;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].tx_ref) {
            if (write_idx != i) {
                entries[write_idx] = std::move(entries[i]);
            }
            ++write_idx;
        }
    }
    entries.resize(write_idx);

    return overlay.AddTransactionBatch(entries);
}

size_t AddTransactionsToOverlayBatch(
    lotus::v2::MerklixOverlayManager &manager,
    std::span<const std::tuple<CTransactionRef, int64_t, int64_t>> txs) {
    return AddTransactionsToOverlayBatch(manager.GetSpeculativeOverlay(), txs);
}

bool RemoveTransactionFromOverlay(lotus::v2::MempoolOverlayLayer &overlay,
                                  const CTransaction &tx) {
    lotus::v2::Hash tx_id{};
    std::memcpy(tx_id.data(), tx.GetId().begin(), 32);
    return overlay.RemoveTransaction(tx_id);
}

bool RemoveTransactionFromOverlay(lotus::v2::MerklixOverlayManager &manager,
                                  const CTransaction &tx) {
    return RemoveTransactionFromOverlay(manager.GetSpeculativeOverlay(), tx);
}

V2TemplateBaseState BuildV2TemplateBaseState(
    std::span<const CTransactionRef> non_coinbase_txs,
    const BlockHash &hashPrevBlock,
    uint64_t nHeight,
    uint64_t nParentMtp) {
    V2TemplateBaseState base{};
    base.mon_state = InitialV2MonetaryState();
    base.height = nHeight;
    base.parent_mtp = nParentMtp;
    base.non_cb_tx_count = non_coinbase_txs.size();
    if (nHeight == 0) {
        return base;
    }
    if (!hashPrevBlock.IsNull()) {
        std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
        auto it = g_v2_state_snapshots.find(hashPrevBlock);
        if (it != g_v2_state_snapshots.end()) {
            base.utxo_root = it->second.utxo_root;
            base.mon_state = it->second.mon_state;
        } else {
            V2BlockStateSnapshot disk_state{};
            if (LoadV2BlockStateFromDiskLocked(lock, hashPrevBlock, disk_state)) {
                base.utxo_root = disk_state.utxo_root;
                base.mon_state = disk_state.mon_state;
                CacheV2BlockStateLocked(lock, hashPrevBlock, std::move(disk_state));
            }
        }
    }
    for (const auto &ptx : non_coinbase_txs) {
        const CTransaction &tx = *ptx;
        const uint64_t linear_cost =
            ::GetSerializeSize(tx) +
            uint64_t(tx.vin.size() * 64 + tx.vout.size() * 64);
        base.sum_non_cb_effective_cost +=
            lotus::v2::TransactionEffectiveCost(linear_cost,
                                                kDefaultMonetaryProfile);
        if (!tx.IsCoinBase()) {
            for (const auto &txin : tx.vin) {
                if (txin.nFlags != 3) {
                    lotus::v2::Outpoint op{};
                    std::memcpy(op.tx_id.data(), txin.prevout.GetTxId().begin(),
                                32);
                    op.index = txin.prevout.GetN();
                    SmtErase(base.utxo_root, op);
                }
            }
        }
        lotus::v2::Hash txid{};
        std::memcpy(txid.data(), tx.GetId().begin(), 32);
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            if (tx.vout[j].scriptPubKey.IsUnspendable()) {
                continue;
            }
            const lotus::v2::Output v2out = tx.vout[j].ToV2Output();
            if (!v2out.IsBurn()) {
                lotus::v2::Coin coin{
                    {txid, static_cast<uint32_t>(j)},
                    v2out,
                    nHeight,
                    nParentMtp,
                    tx.IsCoinBase()};
                SmtInsert(base.utxo_root, coin);
            }
        }
    }
    return base;
}

uint256 ComputeV2StateRootFromTemplate(
    const V2TemplateBaseState &base_state,
    const CTransaction &coinbase_tx,
    uint32_t nBits) {
    lotus::v2::MonetaryState mon_state = base_state.mon_state;
    lotus::v2::Hash utxo_root_hash{};
    if (base_state.height > 0) {
        lotus::v2::Hash txid{};
        std::memcpy(txid.data(), coinbase_tx.GetId().begin(), 32);
        if (base_state.utxo_arena) {
            std::vector<lotus::v2::Coin> cb_coins;
            cb_coins.reserve(coinbase_tx.vout.size());
            for (size_t j = 0; j < coinbase_tx.vout.size(); ++j) {
                if (coinbase_tx.vout[j].scriptPubKey.IsUnspendable()) {
                    continue;
                }
                const lotus::v2::Output v2out =
                    coinbase_tx.vout[j].ToV2Output();
                if (!v2out.IsBurn()) {
                    cb_coins.push_back(lotus::v2::Coin{
                        {txid, static_cast<uint32_t>(j)},
                        v2out,
                        base_state.height,
                        base_state.parent_mtp,
                        true});
                }
            }
            utxo_root_hash =
                base_state.utxo_arena->RootDigestWithExtraCoins(cb_coins);
        } else {
            std::shared_ptr<const SmtNode> utxo_root = base_state.utxo_root;
            for (size_t j = 0; j < coinbase_tx.vout.size(); ++j) {
                if (coinbase_tx.vout[j].scriptPubKey.IsUnspendable()) {
                    continue;
                }
                const lotus::v2::Output v2out =
                    coinbase_tx.vout[j].ToV2Output();
                if (!v2out.IsBurn()) {
                    lotus::v2::Coin coin{
                        {txid, static_cast<uint32_t>(j)},
                        v2out,
                        base_state.height,
                        base_state.parent_mtp,
                        true};
                    SmtInsert(utxo_root, coin);
                }
            }
            utxo_root_hash = SmtRoot(utxo_root);
        }
        const uint64_t cb_linear_cost =
            ::GetSerializeSize(coinbase_tx) +
            uint64_t(coinbase_tx.vin.size() * 64 + coinbase_tx.vout.size() * 64);
        const lotus::v2::MonetaryInteger cb_effective_cost =
            lotus::v2::TransactionEffectiveCost(cb_linear_cost,
                                                kDefaultMonetaryProfile);
        const lotus::v2::MonetaryInteger envelope_cost =
            138 + uint64_t(1 + base_state.non_cb_tx_count) * 64;
        const lotus::v2::MonetaryInteger block_cost =
            envelope_cost + cb_effective_cost +
            base_state.sum_non_cb_effective_cost;

        mon_state = AdvanceV2MonetaryStateForBlock(mon_state, nBits, block_cost);
    } else {
        utxo_root_hash = base_state.utxo_arena
                             ? base_state.utxo_arena->RootDigest()
                             : SmtRoot(base_state.utxo_root);
    }
    const lotus::v2::Hash sroot = lotus::v2::StateRoot(
        GetActiveV2ChainId(), base_state.height, utxo_root_hash, mon_state);
    uint256 out;
    std::memcpy(out.begin(), sroot.data(), 32);
    return out;
}

bool GetV2BlockStateCoinsAndMonetary(
    const BlockHash &blockHash,
    uint64_t nHeight,
    std::vector<lotus::v2::Coin> &coins_out,
    lotus::v2::MonetaryState &monetary_out) {
    coins_out.clear();
    if (nHeight == 0) {
        monetary_out = InitialV2MonetaryState();
        return true;
    }
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    V2BlockStateSnapshot snapshot;
    auto it = g_v2_state_snapshots.find(blockHash);
    if (it == g_v2_state_snapshots.end()) {
        V2BlockStateSnapshot loaded;
        if (!LoadV2BlockStateFromDiskLocked(lock, blockHash, loaded)) {
            return false;
        }
        loaded.persisted_to_disk = true;
        snapshot = loaded;
        CacheV2BlockStateLocked(lock, blockHash, std::move(loaded));
    } else {
        snapshot = it->second;
        TouchV2StateLruLocked(lock, blockHash);
    }
    monetary_out = snapshot.mon_state;
    CollectSmtCoins(snapshot.utxo_root, coins_out);
    std::sort(coins_out.begin(), coins_out.end(),
              [](const lotus::v2::Coin &a, const lotus::v2::Coin &b) {
                  if (a.outpoint.tx_id != b.outpoint.tx_id) {
                      return a.outpoint.tx_id < b.outpoint.tx_id;
                  }
                  return a.outpoint.index < b.outpoint.index;
              });
    return true;
}

bool ImportV2BlockStateCoinsAndMonetary(
    const BlockHash &blockHash,
    const std::vector<lotus::v2::Coin> &coins,
    const lotus::v2::MonetaryState &monetary_state,
    bool is_tip) {
    V2BlockStateSnapshot snap{{}, monetary_state, BlockHash{}, {}, {}};
    snap.inserted_coins.reserve(coins.size());
    if (coins.size() >= 32) {
        std::vector<lotus::v2::Outpoint> empty_erased;
        SmtBatchUpdateParallel(snap.utxo_root, empty_erased, coins);
        snap.inserted_coins = coins;
    } else {
        for (const auto &coin : coins) {
            SmtInsert(snap.utxo_root, coin);
            snap.inserted_coins.push_back(coin);
        }
    }
    snap.circulating_supply =
        snap.utxo_root ? snap.utxo_root->total_value : 0;
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    const auto generation = g_v2_state_directory_generation;
    const bool persist = !g_v2_state_persist_dir.empty();
    const bool written = !persist || SaveV2BlockStateToDiskLocked(lock, blockHash, snap);
    if (!written || generation != g_v2_state_directory_generation)
        return false;
    snap.persisted_to_disk = persist;
    const auto supply = snap.circulating_supply;
    if (!CacheV2BlockStateLocked(lock, blockHash, std::move(snap))) return false;
    if (is_tip || g_latest_v2_circulating_supply == 0)
        g_latest_v2_circulating_supply = supply;
    return true;
}

lotus::v2::MonetaryState AdvanceV2BlockMonetaryState(
    const CBlock &block,
    const lotus::v2::MonetaryState &parent_mon_state) {
    std::vector<uint64_t> tx_linear_costs;
    tx_linear_costs.reserve(block.vtx.size());
    for (const auto &ptx : block.vtx) {
        const CTransaction &tx = *ptx;
        const uint64_t linear_cost =
            ::GetSerializeSize(tx) +
            uint64_t(tx.vin.size() * 64 + tx.vout.size() * 64);
        tx_linear_costs.push_back(linear_cost);
    }
    lotus::v2::Hash pow_limit{};
    pow_limit.fill(0xff);
    lotus::v2::Hash target_hash{};
    lotus::v2::MonetaryInteger work = 2;
    if (lotus::v2::DecodeTarget(block.nBits, pow_limit, target_hash)) {
        lotus::v2::MonetaryInteger target_int = 0;
        for (size_t i = target_hash.size(); i > 0; --i) {
            target_int <<= 8;
            target_int += target_hash[i - 1];
        }
        work = (lotus::v2::MonetaryInteger(1) << 256) / (target_int + 1);
        if (work == 0) {
            work = 1;
        }
    }
    const lotus::v2::MonetaryInteger envelope_cost =
        138 + uint64_t(block.vtx.size()) * 64;
    const lotus::v2::MonetaryInteger block_cost = lotus::v2::BlockEffectiveCost(
        envelope_cost, tx_linear_costs, kDefaultMonetaryProfile);
    const lotus::v2::MonetaryInteger capped_cost =
        (lotus::v2::RequiredBlockBurn(block_cost,
                                      parent_mon_state.ema_block_cost,
                                      kDefaultMonetaryProfile) >
         parent_mon_state.tail_subsidy)
            ? lotus::v2::MonetaryInteger(kDefaultMonetaryProfile.ema_min)
            : block_cost;
    const lotus::v2::MonetaryTransition transition = lotus::v2::AdvanceMonetary(
        kDefaultMonetaryProfile, parent_mon_state, work, {},
        /*coinbase_native_outputs=*/0, /*coinbase_native_burn=*/0,
        /*coinbase_bytes=*/0, /*tx_frame_prefix_bytes=*/0, capped_cost,
        capped_cost);
    return transition.state;
}

std::shared_ptr<const SmtNode> GetV2BlockUtxoRoot(const BlockHash &blockHash,
                                                  bool *found_out) {
    if (blockHash.IsNull()) {
        if (found_out) {
            *found_out = false;
        }
        return nullptr;
    }
    std::unique_lock<std::mutex> lock(g_v2_utxo_mutex);
    auto it = g_v2_state_snapshots.find(blockHash);
    if (it != g_v2_state_snapshots.end()) {
        if (found_out) {
            *found_out = true;
        }
        return it->second.utxo_root;
    }
    V2BlockStateSnapshot disk_state{};
    if (LoadV2BlockStateFromDiskLocked(lock, blockHash, disk_state)) {
        auto root = disk_state.utxo_root;
        CacheV2BlockStateLocked(lock, blockHash, std::move(disk_state));
        if (found_out) {
            *found_out = true;
        }
        return root;
    }
    if (found_out) {
        *found_out = false;
    }
    return nullptr;
}

std::optional<CTxOut> LookupV2SmtCoin(const std::shared_ptr<const SmtNode> &root,
                                      const COutPoint &outpoint,
                                      uint32_t *height_out,
                                      bool *coinbase_out) {
    if (!root) {
        return std::nullopt;
    }
    lotus::v2::Outpoint op{};
    std::memcpy(op.tx_id.data(), outpoint.GetTxId().begin(), 32);
    op.index = outpoint.GetN();
    const lotus::v2::Hash key = lotus::v2::OutpointKey(op);
    std::shared_ptr<const SmtNode> node = root;
    unsigned depth = 0;
    while (node && !node->IsLeaf() && depth < 256) {
        node = node->child[SmtKeyBit(key, depth++)];
    }
    if (!node || !node->IsLeaf() || node->key != key || !node->coin ||
        node->coin->outpoint != op) {
        return std::nullopt;
    }
    if (height_out) {
        *height_out = static_cast<uint32_t>(node->coin->creation_height);
    }
    if (coinbase_out) {
        *coinbase_out = node->coin->coinbase;
    }
    return CTxOut::FromV2Output(node->coin->output);
}

lotus::v2::Header CBlockHeader::ToV2Header() const {
    lotus::v2::Header h;
    std::memcpy(h.prev_id.data(), hashPrevBlock.begin(), 32);
    h.bits = nBits;
    h.time = static_cast<uint64_t>(GetBlockTime());
    h.nonce = nNonce;
    h.version = nHeaderVersion;
    h.size = nSize;
    h.height = nHeight;
    std::memcpy(h.tx_root.data(), hashMerkleRoot.begin(), 32);
    std::memcpy(h.state_root.data(), hashStateRoot.begin(), 32);
    return h;
}

CBlockHeader CBlockHeader::FromV2Header(const lotus::v2::Header &h) {
    CBlockHeader hdr;
    std::memcpy(hdr.hashPrevBlock.begin(), h.prev_id.data(), 32);
    hdr.nBits = h.bits;
    hdr.SetBlockTime(h.time);
    hdr.nNonce = h.nonce;
    hdr.nHeaderVersion = h.version;
    hdr.nSize = h.size;
    hdr.nHeight = h.height;
    std::memcpy(hdr.hashMerkleRoot.begin(), h.tx_root.data(), 32);
    std::memcpy(hdr.hashStateRoot.begin(), h.state_root.data(), 32);
    return hdr;
}

BlockHash CBlockHeader::GetHash() const {
    const lotus::v2::Header h = ToV2Header();
    lotus::v2::Hash id{};
    lotus::v2::BlockId(GetActiveV2ChainId(), h, id);
    uint256 out;
    std::memcpy(out.begin(), id.data(), 32);
    return BlockHash{out};
}

std::string CBlock::ToString() const {
    std::stringstream s;
    s << strprintf(
        "CBlock(hash=%s, hashPrevBlock=%s, bits=0x%08x, time=%u, "
        "nonce=%u, headerversion=%u, size=%u, height=%u, "
        "hashMerkleRoot=%s, hashStateRoot=%s, vtx=%u)\n",
        GetHash().ToString(), hashPrevBlock.ToString(), nBits, GetBlockTime(),
        nNonce, nHeaderVersion, GetSize(), nHeight, hashMerkleRoot.ToString(),
        hashStateRoot.ToString(), vtx.size());
    for (const auto &tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
