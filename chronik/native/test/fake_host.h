// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TEST_FAKE_HOST_H
#define CHRONIK_NATIVE_TEST_FAKE_HOST_H

#include <chronik/native/error.h>
#include <chronik/native/host.h>
#include <chronik/native/types.h>

#include <test/test_sha256.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/**
 * An in-memory node for indexer/service tests: a block tree with an active
 * chain, a coin-tracking block generator, LoadTx by (file, data_pos), a
 * ShutdownRequested toggle (or countdown) and log capture.
 */
namespace chronik::native::testhost {

/** P2PKH script with a 1-byte key id (distinct scripts => distinct groups). */
inline Bytes P2pkh(uint8_t id) {
    Bytes s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) {
        s.push_back(id);
    }
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

/** OP_RETURN <4-byte LOKAD ID> <payload> */
inline Bytes LokadOpReturn(const std::array<uint8_t, 4> &lokad,
                           uint8_t payload = 0) {
    return Bytes{0x6a, 0x04, lokad[0], lokad[1], lokad[2], lokad[3],
                 0x01,  payload};
}

class FakeHost final : public Host {
public:
    FakeHost() {
        m_caps.network = "regtest";
        m_caps.default_http_port = 18442;
        m_caps.client_name = "fakehost";
    }

    HostCapabilities &Caps() { return m_caps; }

    // ---- chain construction ----

    /** Hash32 from a tag and counter (via the test SHA-256). */
    Hash32 MakeHash(uint8_t tag) {
        const uint64_t n = m_counter++;
        uint8_t data[9] = {tag};
        for (int i = 0; i < 8; ++i) {
            data[1 + i] = uint8_t(n >> (8 * i));
        }
        Hash32 h;
        test::TestSha256(ByteView(data, sizeof(data)), h.b.data());
        return h;
    }

    /** UTXOs of the active chain up to and including `height`. */
    std::map<OutPoint, Coin> UtxosAt(int32_t height) const {
        std::map<OutPoint, Coin> utxos;
        for (int32_t h = 0; h <= height && h < int32_t(m_active.size()); ++h) {
            const Block &block = m_blocks.at(m_active[h]);
            for (const BlockTx &btx : block.txs) {
                const Tx &tx = *btx.tx;
                if (!tx.is_coinbase()) {
                    for (const TxInput &in : tx.inputs) {
                        utxos.erase(in.prev_out);
                    }
                }
                for (uint32_t i = 0; i < tx.outputs.size(); ++i) {
                    if (!tx.outputs[i].script.empty() &&
                        tx.outputs[i].script[0] == 0x6a) {
                        continue; // unspendable
                    }
                    utxos[OutPoint{tx.txid, i}] =
                        Coin{tx.outputs[i], h, tx.is_coinbase()};
                }
            }
        }
        return utxos;
    }

    /** Coinbase paying `script`. */
    Tx MakeCoinbase(int32_t height, const Bytes &script) {
        Tx tx;
        tx.version = 1;
        TxInput in;
        in.prev_out.out_idx = 0xffffffff;
        in.script = {0x03, uint8_t(height), uint8_t(height >> 8),
                     uint8_t(height >> 16), uint8_t(m_counter)};
        in.sequence = 0xffffffff;
        in.coin = Coin{};
        tx.inputs.push_back(in);
        tx.outputs.push_back(TxOutput{5000, script});
        tx.txid = MakeHash('t');
        tx.wire_size = 100;
        return tx;
    }

    /** Tx spending `spent` (with their coins) to `outputs`. */
    Tx MakeSpend(const std::vector<std::pair<OutPoint, Coin>> &spent,
                 std::vector<TxOutput> outputs) {
        Tx tx;
        tx.version = 2;
        for (const auto &[op, coin] : spent) {
            TxInput in;
            in.prev_out = op;
            in.script = {0x01, 0x51};
            in.sequence = 0xfffffffe;
            in.coin = coin;
            tx.inputs.push_back(in);
        }
        tx.outputs = std::move(outputs);
        tx.txid = MakeHash('t');
        tx.wire_size = uint32_t(10 + 40 * tx.inputs.size() +
                                30 * tx.outputs.size());
        return tx;
    }

    /**
     * New block on top of the active block at `parent_height` (-1: genesis)
     * with the given txs (the coinbase is prepended). Not connected to the
     * active chain; use SetActive/Extend.
     */
    Block MakeBlock(int32_t parent_height, std::vector<Tx> txs,
                    uint8_t cb_script_id = 0xcb) {
        Block block;
        block.info.hash = MakeHash('b');
        if (parent_height >= 0) {
            block.info.prev_hash = m_active.at(parent_height);
        }
        block.info.height = parent_height + 1;
        block.info.n_bits = 0x207fffff;
        block.info.timestamp = 1'600'000'000 + block.info.height * 120;
        block.info.file_num = 0;
        block.info.data_pos = m_next_pos++;
        block.info.undo_pos = m_next_pos++;
        txs.insert(txs.begin(),
                   MakeCoinbase(block.info.height, P2pkh(cb_script_id)));
        uint64_t size = 80;
        for (Tx &tx : txs) {
            BlockTx btx;
            btx.data_pos = m_next_pos++;
            btx.undo_pos = tx.is_coinbase() ? 0 : m_next_pos++;
            size += tx.wire_size;
            btx.tx = std::make_shared<const Tx>(std::move(tx));
            block.txs.push_back(btx);
        }
        block.info.size = size;
        return block;
    }

    /** Register a block (any branch) and its txs for LoadBlock/LoadTx. */
    void AddBlock(const Block &block) {
        m_blocks[block.info.hash] = block;
        for (const BlockTx &btx : block.txs) {
            m_txs[{block.info.file_num, btx.data_pos}] = *btx.tx;
        }
    }

    /** Make `block` the active tip (its parent must be at height-1). */
    void Extend(const Block &block) {
        AddBlock(block);
        m_active.resize(size_t(block.info.height));
        m_active.push_back(block.info.hash);
    }

    /** Truncate the active chain to `height` (blocks stay known). */
    void TruncateActive(int32_t height) {
        m_active.resize(size_t(height + 1));
    }

    /**
     * Random block on top of the active block at `parent_height`, spending
     * random UTXOs of that chain (with dependent in-block spends), with
     * random P2PKH and LOKAD OP_RETURN outputs.
     */
    Block RandomBlock(std::mt19937_64 &rng, int32_t parent_height) {
        std::map<OutPoint, Coin> utxos = UtxosAt(parent_height);
        std::vector<Tx> txs;
        const int num_txs = int(rng() % 5);
        for (int i = 0; i < num_txs && !utxos.empty(); ++i) {
            std::vector<std::pair<OutPoint, Coin>> spent;
            const int num_inputs = 1 + int(rng() % 3);
            for (int j = 0; j < num_inputs && !utxos.empty(); ++j) {
                auto it = utxos.begin();
                std::advance(it, rng() % utxos.size());
                spent.push_back(*it);
                utxos.erase(it);
            }
            std::vector<TxOutput> outputs;
            const int num_outputs = 1 + int(rng() % 3);
            for (int j = 0; j < num_outputs; ++j) {
                outputs.push_back(
                    TxOutput{int64_t(100 + rng() % 1000),
                             P2pkh(uint8_t(rng() % 6))});
            }
            if (rng() % 3 == 0) {
                outputs.push_back(TxOutput{
                    0, LokadOpReturn({'T', 'E', 'S', uint8_t('0' + rng() % 3)},
                                     uint8_t(rng()))});
            }
            Tx tx = MakeSpend(spent, std::move(outputs));
            // in-block descendants may spend these outputs
            for (uint32_t k = 0; k < tx.outputs.size(); ++k) {
                if (tx.outputs[k].script[0] != 0x6a) {
                    utxos[OutPoint{tx.txid, k}] =
                        Coin{tx.outputs[k], parent_height + 1, false};
                }
            }
            txs.push_back(std::move(tx));
        }
        return MakeBlock(parent_height, std::move(txs),
                         uint8_t(0xc0 + rng() % 4));
    }

    int32_t TipHeight() const { return int32_t(m_active.size()) - 1; }
    const Block &ActiveBlock(int32_t height) const {
        return m_blocks.at(m_active.at(height));
    }
    const Block &GetBlock(const BlockHash &hash) const {
        return m_blocks.at(hash);
    }

    // ---- process controls ----

    void SetShutdown(bool v) { m_shutdown_after = v ? 0 : -1; }
    /** Shutdown becomes requested after `n` more ShutdownRequested calls. */
    void ShutdownAfter(int64_t n) { m_shutdown_after = n; }

    std::vector<std::pair<LogLevel, std::string>> Logs() const {
        std::lock_guard lock(m_log_mutex);
        return m_logs;
    }
    std::vector<std::string> LogLines(std::optional<LogLevel> level = {}) const {
        std::vector<std::string> out;
        for (const auto &[l, msg] : Logs()) {
            if (!level || *level == l) {
                out.push_back(msg);
            }
        }
        return out;
    }
    bool HasLog(std::string_view needle) const {
        for (const auto &[l, msg] : Logs()) {
            if (msg.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
    void ClearLogs() {
        std::lock_guard lock(m_log_mutex);
        m_logs.clear();
    }
    std::vector<std::pair<std::string, std::string>> FatalErrors() const {
        std::lock_guard lock(m_log_mutex);
        return m_fatal;
    }

    // ---- Host ----

    const HostCapabilities &Capabilities() const override { return m_caps; }
    std::optional<BlockInfo> ActiveTip() const override {
        if (m_active.empty()) {
            return std::nullopt;
        }
        return m_blocks.at(m_active.back()).info;
    }
    std::optional<BlockInfo> LookupBlock(const BlockHash &hash) const override {
        auto it = m_blocks.find(hash);
        if (it == m_blocks.end()) {
            return std::nullopt;
        }
        return it->second.info;
    }
    std::optional<BlockInfo> ActiveAtHeight(int32_t height) const override {
        if (height < 0 || height >= int32_t(m_active.size())) {
            return std::nullopt;
        }
        return m_blocks.at(m_active[height]).info;
    }
    std::optional<BlockInfo> FindFork(const BlockHash &hash) const override {
        auto it = m_blocks.find(hash);
        while (it != m_blocks.end()) {
            const BlockInfo &info = it->second.info;
            if (info.height < int32_t(m_active.size()) &&
                m_active[info.height] == info.hash) {
                return info;
            }
            if (info.height == 0) {
                return std::nullopt;
            }
            it = m_blocks.find(info.prev_hash);
        }
        return std::nullopt;
    }
    BlockHash GenesisHash() const override {
        return m_active.empty() ? BlockHash{} : m_active[0];
    }
    Bytes RawHeader(const BlockInfo &info) const override {
        Bytes out(80, 0);
        std::copy(info.hash.b.begin(), info.hash.b.end(), out.begin());
        return out;
    }
    std::vector<Bytes> RawHeadersByRange(int32_t start,
                                         int32_t end) const override {
        std::vector<Bytes> out;
        for (int32_t h = start; h <= end; ++h) {
            if (auto info = ActiveAtHeight(h)) {
                out.push_back(RawHeader(*info));
            }
        }
        return out;
    }
    Block LoadBlock(const BlockInfo &info) const override {
        ++m_load_block_calls;
        auto it = m_blocks.find(info.hash);
        if (it == m_blocks.end()) {
            throw ChronikError("Block not found in FakeHost");
        }
        return it->second;
    }
    Tx LoadTx(uint32_t file_num, uint32_t data_pos,
              uint32_t /*undo_pos*/) const override {
        auto it = m_txs.find({file_num, data_pos});
        if (it == m_txs.end()) {
            throw ChronikError("Tx not found in FakeHost");
        }
        return it->second;
    }
    Bytes LoadRawTx(uint32_t, uint32_t) const override {
        throw ChronikError("LoadRawTx not supported by FakeHost");
    }
    DecodedTx DecodeRawTx(std::span<const uint8_t>) const override {
        return DecodedTx{false, {}, "unsupported"};
    }
    SpentCoinLookup LookupSpentCoins(Tx &) const override { return {}; }
    void UncacheCoins(std::span<const OutPoint>) const override {}
    BroadcastResult Broadcast(std::span<const uint8_t>,
                              int64_t) const override {
        return BroadcastResult{false, {}, "unsupported"};
    }
    int64_t CalcMaxFee(size_t) const override { return 0; }
    std::optional<FeeRateInfo> MempoolFeeRate(const TxId &) const override {
        return std::nullopt;
    }
    int64_t EstimateFeeRateSatsPerKb() const override { return 1000; }
    int64_t MinRelayFeeRateSatsPerKb() const override { return 1000; }
    std::optional<bool> IsFinalizedPreConsensus(const TxId &) const override {
        return std::nullopt;
    }
    void SyncWithIndexer() const override {}
    bool ShutdownRequested() const override {
        int64_t n = m_shutdown_after.load();
        if (n < 0) {
            return false;
        }
        if (n == 0) {
            return true;
        }
        m_shutdown_after.store(n - 1);
        return false;
    }
    void FatalError(std::string_view log_msg,
                    std::string_view user_msg) const override {
        std::lock_guard lock(m_log_mutex);
        m_fatal.emplace_back(std::string(log_msg), std::string(user_msg));
    }
    void Log(LogLevel level, std::string_view msg) const override {
        std::lock_guard lock(m_log_mutex);
        m_logs.emplace_back(level, std::string(msg));
    }
    std::string FormatFullVersion() const override { return "v0.0.0-test"; }
    void Sha256(std::span<const uint8_t> data, uint8_t out[32]) const override {
        test::TestSha256(ByteView(data.data(), data.size()), out);
    }

    mutable std::atomic<int> m_load_block_calls{0};

private:
    HostCapabilities m_caps;
    std::vector<BlockHash> m_active;
    std::unordered_map<BlockHash, Block, Hash32Hasher> m_blocks;
    std::map<std::pair<uint32_t, uint32_t>, Tx> m_txs;
    uint64_t m_counter = 1;
    uint32_t m_next_pos = 1;
    mutable std::atomic<int64_t> m_shutdown_after{-1};
    mutable std::mutex m_log_mutex;
    mutable std::vector<std::pair<LogLevel, std::string>> m_logs;
    mutable std::vector<std::pair<std::string, std::string>> m_fatal;
};

} // namespace chronik::native::testhost

#endif // CHRONIK_NATIVE_TEST_FAKE_HOST_H
