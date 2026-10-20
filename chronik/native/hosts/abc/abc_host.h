// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_HOSTS_ABC_ABC_HOST_H
#define CHRONIK_NATIVE_HOSTS_ABC_ABC_HOST_H

#include <chronik/native/host.h>
#include <hosts/common/flat_file_reader.h>

#include <cstdint>
#include <memory>
#include <vector>

class CBlock;
class CBlockIndex;
class CBlockUndo;
class CTransaction;
class Coin;
namespace node {
struct NodeContext;
} // namespace node

namespace chronik::native::abc {

/** Port of the BridgeTx/BridgeBlock conversions of chronik_bridge.cpp. */
Tx ConvertTx(bool is_coinbase, const CTransaction &tx,
             const std::vector<::Coin> &spent_coins);
Block ConvertBlock(const CBlock &block, const CBlockUndo &block_undo,
                   const CBlockIndex &bindex);
BlockInfo ConvertBlockInfo(const CBlockIndex &bindex);
/** Serialized header bytes of a block index entry. */
Bytes SerializeHeader(const CBlockIndex &bindex);

/**
 * chronik::native::Host for the ABC/eCash node, a port of ChronikBridge
 * (chronik/chronik-cpp/chronik_bridge.cpp).
 */
class AbcHost final : public Host {
public:
    AbcHost(const node::NodeContext &node, HostCapabilities caps);
    ~AbcHost() override;

    const HostCapabilities &Capabilities() const override { return m_caps; }

    std::optional<BlockInfo> ActiveTip() const override;
    std::optional<BlockInfo> LookupBlock(const BlockHash &) const override;
    std::optional<BlockInfo> ActiveAtHeight(int32_t height) const override;
    std::optional<BlockInfo> FindFork(const BlockHash &) const override;
    BlockHash GenesisHash() const override;
    Bytes RawHeader(const BlockInfo &) const override;
    std::vector<Bytes> RawHeadersByRange(int32_t start,
                                         int32_t end) const override;

    Block LoadBlock(const BlockInfo &) const override;
    Tx LoadTx(uint32_t file_num, uint32_t data_pos,
              uint32_t undo_pos) const override;
    Bytes LoadRawTx(uint32_t file_num, uint32_t data_pos) const override;

    DecodedTx DecodeRawTx(std::span<const uint8_t> raw) const override;
    SpentCoinLookup LookupSpentCoins(Tx &tx) const override;
    void UncacheCoins(std::span<const OutPoint>) const override;
    BroadcastResult Broadcast(std::span<const uint8_t> raw,
                              int64_t max_fee_sats) const override;
    int64_t CalcMaxFee(size_t tx_size) const override;
    std::optional<FeeRateInfo> MempoolFeeRate(const TxId &) const override;
    int64_t EstimateFeeRateSatsPerKb() const override;
    int64_t MinRelayFeeRateSatsPerKb() const override;
    std::optional<bool> IsFinalizedPreConsensus(const TxId &) const override;
    void SyncWithIndexer() const override;

    bool ShutdownRequested() const override;
    void FatalError(std::string_view log_msg,
                    std::string_view user_msg) const override;
    void Log(LogLevel level, std::string_view msg) const override;
    std::string FormatFullVersion() const override;
    void Sha256(std::span<const uint8_t>, uint8_t out[32]) const override;

    /** Load the undo data of a block; nullopt if it can't be read. */
    std::unique_ptr<CBlockUndo> LoadBlockUndo(const CBlockIndex &) const;
    const CBlockIndex *LookupIndex(const BlockHash &) const;

    /** Counters of the blk/rev descriptor cache used by LoadTx/LoadRawTx. */
    hosts::FlatFileCacheStats FileCacheStats() const;

private:
    const node::NodeContext &m_node;
    HostCapabilities m_caps;
    /**
     * Read-only descriptors of complete blk/rev files, read with pread.
     * Files the node may still append to are read through BlockManager as
     * before; pruned files are dropped before the node deletes them.
     */
    std::unique_ptr<hosts::FlatFileReadCache> m_file_cache;
    uint64_t m_unlink_callback;
};

} // namespace chronik::native::abc

#endif // CHRONIK_NATIVE_HOSTS_ABC_ABC_HOST_H
