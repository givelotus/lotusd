// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_HOST_H
#define CHRONIK_NATIVE_HOST_H

#include <chronik/native/types.h>

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace chronik::native {

/** error = "<TransactionError>: <msg>" */
struct BroadcastResult {
    bool ok{};
    TxId txid;
    std::string error;
};
struct FeeRateInfo {
    int64_t sats_per_kb{};
    uint32_t vsize{};
};
/** Spent coins NOT resolved */
struct DecodedTx {
    bool ok{};
    Tx tx;
    std::string error;
};
enum class LogLevel { Info, InfoNoRateLimit, Debug };

struct SpentCoinLookup {
    std::vector<OutPoint> not_found;
    std::vector<OutPoint> to_uncache;
};

/**
 * Everything the indexer core needs from the node. Thread rules:
 *  - Every method is callable from any Chronik thread (writer, query pool,
 *    init).
 *  - The core NEVER calls a Host method while holding its exclusive state
 *    lock.
 *  - Methods may take host locks (cs_main, mempool.cs) internally and must
 *    not call back into Chronik.
 * Errors: return values for expected misses; throw std::runtime_error for I/O
 * corruption (the core maps it to FatalError on the writer, 500 on queries).
 */
class Host {
public:
    virtual ~Host() = default;
    virtual const HostCapabilities &Capabilities() const = 0;

    // ---- chain view (validated/active chainstate only) ----
    virtual std::optional<BlockInfo> ActiveTip() const = 0;
    /** Any branch */
    virtual std::optional<BlockInfo> LookupBlock(const BlockHash &) const = 0;
    virtual std::optional<BlockInfo> ActiveAtHeight(int32_t height) const = 0;
    /** Last common active ancestor */
    virtual std::optional<BlockInfo> FindFork(const BlockHash &) const = 0;
    virtual BlockHash GenesisHash() const = 0;
    /**
     * Exact raw header bytes (80 ABC/BCHN/Core, 160 Lotus V1, 134 Lotus V2,
     * variable Doged AuxPoW).
     */
    virtual Bytes RawHeader(const BlockInfo &) const = 0;
    /** Batch form; returns a prefix if the range runs past the active tip. */
    virtual std::vector<Bytes> RawHeadersByRange(int32_t start,
                                                 int32_t end) const = 0;

    // ---- immutable block storage (no cs_main needed by contract) ----
    /**
     * Load + decode block, spent coins from undo, per-tx data_pos/undo_pos
     * (host computes first-tx offset: header size [+ vMetadata] +
     * CompactSize(n_tx), witness-aware sizes).
     */
    virtual Block LoadBlock(const BlockInfo &) const = 0;
    virtual Tx LoadTx(uint32_t file_num, uint32_t data_pos,
                      uint32_t undo_pos) const = 0;
    virtual Bytes LoadRawTx(uint32_t file_num, uint32_t data_pos) const = 0;

    // ---- mempool / relay ----
    /** Accepts trailing bytes, like Rust TxMut::deser */
    virtual DecodedTx DecodeRawTx(std::span<const uint8_t> raw) const = 0;
    /** Fill inputs[i].coin from CoinsTip+mempool view (broadcast checks). */
    virtual SpentCoinLookup LookupSpentCoins(Tx &tx) const = 0;
    virtual void UncacheCoins(std::span<const OutPoint>) const = 0;
    virtual BroadcastResult Broadcast(std::span<const uint8_t> raw,
                                      int64_t max_fee_sats) const = 0;
    /** Host default max raw-tx fee for a tx of this size */
    virtual int64_t CalcMaxFee(size_t tx_size) const = 0;
    virtual std::optional<FeeRateInfo> MempoolFeeRate(const TxId &) const = 0;
    virtual int64_t EstimateFeeRateSatsPerKb() const = 0;
    virtual int64_t MinRelayFeeRateSatsPerKb() const = 0;
    /** nullopt <=> capability absent (Core/BCHN); core reports false. */
    virtual std::optional<bool>
    IsFinalizedPreConsensus(const TxId &) const = 0;
    /**
     * Waits until every event already published by the node has been applied
     * by Chronik.
     */
    virtual void SyncWithIndexer() const = 0;

    // ---- process ----
    virtual bool ShutdownRequested() const = 0;
    virtual void FatalError(std::string_view log_msg,
                            std::string_view user_msg) const = 0;
    /**
     * Info: rate-limited node log (Rust `log!`); InfoNoRateLimit: Rust
     * `log_no_ratelimit!`; Debug: only with -debug=chronik (`log_chronik!`).
     */
    virtual void Log(LogLevel level, std::string_view msg) const = 0;
    virtual std::string FormatFullVersion() const = 0;
    /** scripthash, key hashing */
    virtual void Sha256(std::span<const uint8_t>, uint8_t out[32]) const = 0;
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_HOST_H
