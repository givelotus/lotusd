// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the conversions and node accessors of
// chronik/chronik-cpp/chronik_bridge.cpp to the native Host interface.

#include <hosts/abc/abc_host.h>

#include <chronik/native/tx/legacy_tx.h>

#include <blockindex.h>
#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <common/messages.h>
#include <crypto/sha256.h>
#include <feerate.h>
#include <logging.h>
#include <lotus_v2/fee_hysteresis.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/transaction.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <shutdown.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <txmempool.h>
#include <undo.h>
#include <util/fs.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cstring>
#include <set>
#include <source_location>
#include <stdexcept>

using common::TransactionErrorString;
using node::TransactionError;

namespace chronik::native::abc {

namespace {

/** Deserialization stream over a hosts::FlatFileCursor. */
class CursorStream {
public:
    explicit CursorStream(hosts::FlatFileCursor &cursor) : m_cursor{cursor} {}

    void read(Span<std::byte> dst) {
        m_cursor.Read(
            std::span(reinterpret_cast<uint8_t *>(dst.data()), dst.size()));
    }
    void ignore(size_t num_bytes) { m_cursor.Skip(num_bytes); }

    template <typename T> CursorStream &operator>>(T &&obj) {
        ::Unserialize(*this, obj);
        return *this;
    }

private:
    hosts::FlatFileCursor &m_cursor;
};

/**
 * Deserialize obj at pos of a cached file. False if the file isn't cached
 * (the node may still append to it) or the read fails: the caller then
 * reads through BlockManager, which also reports any error.
 */
template <typename T>
bool ReadCached(hosts::FlatFileReadCache &cache, hosts::FlatFileKind kind,
                uint32_t file_num, uint32_t pos, T &obj) {
    std::shared_ptr<const hosts::CachedFlatFile> file =
        cache.Acquire(kind, file_num);
    if (!file) {
        return false;
    }
    try {
        hosts::FlatFileCursor cursor(std::move(file), pos);
        CursorStream stream{cursor};
        stream >> obj;
        return true;
    } catch (const std::exception &) {
        obj = T{};
        return false;
    }
}

Hash32 ToHash(const uint256 &h) {
    Hash32 out;
    std::memcpy(out.b.data(), h.begin(), 32);
    return out;
}

uint256 FromHash(const Hash32 &h) {
    uint256 out;
    std::memcpy(out.begin(), h.b.data(), 32);
    return out;
}

TxOutput ConvertOutput(const CTxOut &output) {
    return TxOutput{
        .sats = output.nValue / Amount::satoshi(),
        .script = Bytes(output.scriptPubKey.begin(), output.scriptPubKey.end()),
    };
}

Coin ConvertCoin(const ::Coin &coin) {
    const int32_t height =
        coin.GetHeight() == 0x7fff'ffff ? -1 : int32_t(coin.GetHeight());
    return Coin{
        .output = ConvertOutput(coin.GetTxOut()),
        .height = height,
        .is_coinbase = coin.IsCoinBase(),
    };
}

size_t GetFirstBlockTxOffset(const CBlock &block, size_t block_data_pos) {
    return block_data_pos + ::GetSerializeSize(CBlockHeader()) +
           GetSizeOfCompactSize(block.vtx.size());
}

size_t GetFirstUndoOffset(const CBlock &block, size_t block_undo_pos) {
    // -1 because coinbase txs don't have undo data.
    return block_undo_pos + GetSizeOfCompactSize(block.vtx.size() - 1);
}

} // namespace

Tx ConvertTx(bool is_coinbase, const CTransaction &tx,
             const std::vector<::Coin> &spent_coins) {
    Tx out;
    out.txid = ToHash(tx.GetId());
    out.version = int32_t(tx.nVersion);
    out.inputs.reserve(tx.vin.size());
    for (size_t idx = 0; idx < tx.vin.size(); ++idx) {
        const CTxIn &input = tx.vin[idx];
        TxInput in;
        in.prev_out.txid = ToHash(input.prevout.GetTxId());
        in.prev_out.out_idx = input.prevout.GetN();
        in.script = Bytes(input.scriptSig.begin(), input.scriptSig.end());
        in.sequence = input.nSequence;
        if (!is_coinbase) {
            if (idx >= spent_coins.size()) {
                throw std::runtime_error("Missing coin for input");
            }
            in.coin = ConvertCoin(spent_coins[idx]);
        } else {
            // The Rust bridge passes an empty coin for coinbase inputs.
            in.coin = Coin{};
        }
        out.inputs.push_back(std::move(in));
    }
    out.outputs.reserve(tx.vout.size());
    for (const CTxOut &output : tx.vout) {
        out.outputs.push_back(ConvertOutput(output));
    }
    out.locktime = tx.nLockTime;
    out.wire_size = uint32_t(::GetSerializeSize(tx));
    return out;
}

BlockInfo ConvertBlockInfo(const CBlockIndex &bindex) {
    BlockInfo info;
    info.hash = ToHash(bindex.GetBlockHash());
    if (bindex.pprev) {
        info.prev_hash = ToHash(bindex.pprev->GetBlockHash());
    }
    info.height = bindex.nHeight;
    info.n_bits = bindex.nBits;
    info.timestamp = bindex.GetBlockTime();
    info.file_num = uint32_t(bindex.nFile);
    info.data_pos = bindex.nDataPos;
    info.undo_pos = bindex.nUndoPos;
    return info;
}

Block ConvertBlock(const CBlock &block, const CBlockUndo &block_undo,
                   const CBlockIndex &bindex) {
    AssertLockNotHeld(::cs_main);
    Block out;
    {
        LOCK(::cs_main);
        out.info = ConvertBlockInfo(bindex);
    }
    // Like the Rust bridge, the block's own header fields are authoritative.
    out.info.hash = ToHash(block.GetHash());
    out.info.prev_hash = ToHash(block.hashPrevBlock);
    out.info.n_bits = block.nBits;
    out.info.timestamp = block.GetBlockTime();
    out.info.size = ::GetSerializeSize(block);

    size_t data_pos = GetFirstBlockTxOffset(block, out.info.data_pos);
    size_t undo_pos = 0;
    // Set undo offset; for the genesis block leave it at 0
    if (bindex.nHeight > 0) {
        undo_pos = GetFirstUndoOffset(block, out.info.undo_pos);
    }

    static const std::vector<::Coin> NO_COINS;
    out.txs.reserve(block.vtx.size());
    for (size_t tx_idx = 0; tx_idx < block.vtx.size(); ++tx_idx) {
        const bool is_coinbase = tx_idx == 0;
        const CTransaction &tx = *block.vtx[tx_idx];
        if (!is_coinbase && tx_idx - 1 >= block_undo.vtxundo.size()) {
            throw std::runtime_error("Missing undo data for tx");
        }
        const std::vector<::Coin> &spent_coins =
            is_coinbase ? NO_COINS : block_undo.vtxundo[tx_idx - 1].vprevout;
        BlockTx btx;
        btx.tx = std::make_shared<const Tx>(
            ConvertTx(is_coinbase, tx, spent_coins));
        btx.data_pos = uint32_t(data_pos);
        btx.undo_pos = uint32_t(is_coinbase ? 0 : undo_pos);
        out.txs.push_back(std::move(btx));

        data_pos += ::GetSerializeSize(tx);
        if (!is_coinbase) {
            undo_pos += ::GetSerializeSize(block_undo.vtxundo[tx_idx - 1]);
        }
    }
    return out;
}

Bytes SerializeHeader(const CBlockIndex &bindex) {
    DataStream ser_header{};
    ser_header << bindex.GetBlockHeader();
    const auto span = MakeUCharSpan(ser_header);
    return Bytes(span.begin(), span.end());
}

AbcHost::AbcHost(const node::NodeContext &node, HostCapabilities caps)
    : m_node{node}, m_caps{std::move(caps)} {
    Assert(m_node.chainman);
    Assert(m_node.mempool);
    node::BlockManager &blockman = m_node.chainman->m_blockman;
    m_file_cache = std::make_unique<hosts::FlatFileReadCache>(
        hosts::FlatFileReadCache::Hooks{
            .file_path =
                [&blockman](hosts::FlatFileKind kind, uint32_t file_num) {
                    const FlatFilePos pos(int(file_num), 0);
                    return fs::PathToString(
                        kind == hosts::FlatFileKind::BLOCK
                            ? blockman.GetBlockPosFilename(pos)
                            : blockman.GetUndoPosFilename(pos));
                },
            // rev N is cached once blk N is complete: undo data can still be
            // appended to it (a reorg connecting blocks stored in blk N), but
            // pread reads the file's current contents and the bytes of
            // undo data already written never change.
            .may_append =
                [&blockman](hosts::FlatFileKind, uint32_t file_num) {
                    return blockman.MayAppendToBlockFile(int(file_num));
                },
        });
    m_unlink_callback = blockman.RegisterUnlinkFilesCallback(
        [cache = m_file_cache.get()](const std::set<int> &files) {
            for (const int file_num : files) {
                cache->Invalidate(uint32_t(file_num));
            }
        });
}

AbcHost::~AbcHost() {
    m_node.chainman->m_blockman.UnregisterUnlinkFilesCallback(
        m_unlink_callback);
}

hosts::FlatFileCacheStats AbcHost::FileCacheStats() const {
    return m_file_cache->Stats();
}

const CBlockIndex *AbcHost::LookupIndex(const BlockHash &hash) const {
    ::BlockHash block_hash{FromHash(hash)};
    return WITH_LOCK(
        cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(block_hash));
}

std::optional<BlockInfo> AbcHost::ActiveTip() const {
    LOCK(cs_main);
    const CBlockIndex *tip = m_node.chainman->ActiveTip();
    if (!tip) {
        return std::nullopt;
    }
    return ConvertBlockInfo(*tip);
}

std::optional<BlockInfo> AbcHost::LookupBlock(const BlockHash &hash) const {
    LOCK(cs_main);
    const CBlockIndex *pindex =
        m_node.chainman->m_blockman.LookupBlockIndex(::BlockHash{FromHash(hash)});
    if (!pindex) {
        return std::nullopt;
    }
    return ConvertBlockInfo(*pindex);
}

std::optional<BlockInfo> AbcHost::ActiveAtHeight(int32_t height) const {
    LOCK(cs_main);
    const CBlockIndex *pindex =
        m_node.chainman->GetChainstateForIndexing().m_chain[height];
    if (!pindex) {
        return std::nullopt;
    }
    return ConvertBlockInfo(*pindex);
}

std::optional<BlockInfo> AbcHost::FindFork(const BlockHash &hash) const {
    LOCK(cs_main);
    const CBlockIndex *pindex =
        m_node.chainman->m_blockman.LookupBlockIndex(::BlockHash{FromHash(hash)});
    if (!pindex) {
        return std::nullopt;
    }
    const CBlockIndex *fork =
        m_node.chainman->GetChainstateForIndexing().m_chain.FindFork(pindex);
    if (!fork) {
        return std::nullopt;
    }
    return ConvertBlockInfo(*fork);
}

BlockHash AbcHost::GenesisHash() const {
    return ToHash(m_node.chainman->GetParams().GenesisBlock().GetHash());
}

Bytes AbcHost::RawHeader(const BlockInfo &info) const {
    LOCK(cs_main);
    const CBlockIndex *pindex = m_node.chainman->m_blockman.LookupBlockIndex(
        ::BlockHash{FromHash(info.hash)});
    if (!pindex) {
        throw std::runtime_error("Block index not found");
    }
    return SerializeHeader(*pindex);
}

std::vector<Bytes> AbcHost::RawHeadersByRange(int32_t start,
                                              int32_t end) const {
    std::vector<Bytes> headers;
    if (start < 0 || end < start) {
        return headers;
    }
    LOCK(cs_main);
    for (int32_t height = start; height <= end; ++height) {
        const CBlockIndex *pindex =
            m_node.chainman->GetChainstateForIndexing().m_chain[height];
        if (!pindex) {
            // Partial results allowed: following heights don't exist either.
            break;
        }
        headers.push_back(SerializeHeader(*pindex));
    }
    return headers;
}

std::unique_ptr<CBlockUndo>
AbcHost::LoadBlockUndo(const CBlockIndex &bindex) const {
    auto block_undo = std::make_unique<CBlockUndo>();
    // Genesis block doesn't have undo data
    if (bindex.nHeight > 0) {
        if (!m_node.chainman->m_blockman.ReadBlockUndo(*block_undo, bindex)) {
            return nullptr;
        }
    }
    return block_undo;
}

Block AbcHost::LoadBlock(const BlockInfo &info) const {
    const CBlockIndex *pindex = LookupIndex(info.hash);
    if (!pindex) {
        throw std::runtime_error("Block index not found");
    }
    CBlock block;
    if (!m_node.chainman->m_blockman.ReadBlock(block, *pindex)) {
        throw std::runtime_error("Reading block data failed");
    }
    std::unique_ptr<CBlockUndo> undo = LoadBlockUndo(*pindex);
    if (!undo) {
        throw std::runtime_error("Reading block undo data failed");
    }
    return ConvertBlock(block, *undo, *pindex);
}

Tx AbcHost::LoadTx(uint32_t file_num, uint32_t data_pos,
                   uint32_t undo_pos) const {
    CMutableTransaction tx;
    CTxUndo txundo{};
    const bool is_coinbase = undo_pos == 0;
    if (!ReadCached(*m_file_cache, hosts::FlatFileKind::BLOCK, file_num,
                    data_pos, tx) &&
        !m_node.chainman->m_blockman.ReadTxFromDisk(
            tx, FlatFilePos(file_num, data_pos))) {
        throw std::runtime_error("Reading tx data from disk failed");
    }
    if (!is_coinbase) {
        if (!ReadCached(*m_file_cache, hosts::FlatFileKind::UNDO, file_num,
                        undo_pos, txundo) &&
            !m_node.chainman->m_blockman.ReadTxUndoFromDisk(
                txundo, FlatFilePos(file_num, undo_pos))) {
            throw std::runtime_error("Reading tx undo data from disk failed");
        }
    }
    return ConvertTx(is_coinbase, CTransaction(std::move(tx)), txundo.vprevout);
}

Bytes AbcHost::LoadRawTx(uint32_t file_num, uint32_t data_pos) const {
    CMutableTransaction tx;
    if (!ReadCached(*m_file_cache, hosts::FlatFileKind::BLOCK, file_num,
                    data_pos, tx) &&
        !m_node.chainman->m_blockman.ReadTxFromDisk(
            tx, FlatFilePos(file_num, data_pos))) {
        throw std::runtime_error("Reading tx data from disk failed");
    }
    DataStream raw_tx{};
    raw_tx << tx;
    const auto span = MakeUCharSpan(raw_tx);
    return Bytes(span.begin(), span.end());
}

DecodedTx AbcHost::DecodeRawTx(std::span<const uint8_t> raw) const {
    // Same decoder and error texts as the Rust Chronik (TxMut::deser), which
    // also accepts trailing bytes. The txid is that of the decoded fields.
    LegacyTxDecodeResult decoded = DecodeLegacyTx(raw);
    DecodedTx out;
    if (decoded.error) {
        out.error = *decoded.error;
        return out;
    }
    const Bytes ser = SerializeLegacyTx(decoded.tx);
    DataStream stream{MakeByteSpan(ser)};
    CMutableTransaction mtx;
    stream >> mtx;
    out.ok = true;
    out.tx = std::move(decoded.tx);
    out.tx.txid = ToHash(CTransaction(mtx).GetId());
    out.tx.raw = Bytes(raw.begin(), raw.end());
    return out;
}

SpentCoinLookup AbcHost::LookupSpentCoins(Tx &tx) const {
    SpentCoinLookup result;
    LOCK(cs_main);
    CCoinsViewCache &coins_cache =
        m_node.chainman->GetChainstateForIndexing().CoinsTip();
    CCoinsViewMemPool coin_view(&coins_cache, *m_node.mempool);
    for (TxInput &input : tx.inputs) {
        const COutPoint outpoint(::TxId(FromHash(input.prev_out.txid)),
                                 input.prev_out.out_idx);
        // Remember if coin was already cached
        const bool had_cached = coins_cache.HaveCoinInCache(outpoint);
        std::optional<::Coin> coin{coin_view.GetCoin(outpoint)};
        if (!coin) {
            result.not_found.push_back(input.prev_out);
            continue;
        }
        if (!had_cached) {
            result.to_uncache.push_back(input.prev_out);
        }
        input.coin = ConvertCoin(*coin);
    }
    return result;
}

void AbcHost::UncacheCoins(std::span<const OutPoint> outpoints) const {
    LOCK(cs_main);
    CCoinsViewCache &coins_cache =
        m_node.chainman->GetChainstateForIndexing().CoinsTip();
    for (const OutPoint &outpoint : outpoints) {
        coins_cache.Uncache(
            COutPoint(::TxId(FromHash(outpoint.txid)), outpoint.out_idx));
    }
}

BroadcastResult AbcHost::Broadcast(std::span<const uint8_t> raw,
                                   int64_t max_fee_sats) const {
    BroadcastResult result;
    try {
        DataStream stream{MakeByteSpan(raw)};
        CMutableTransaction tx;
        stream >> tx;
        CTransactionRef tx_ref = MakeTransactionRef(tx);
        std::string err_str;
        // wait_callback is false because this would deadlock; the core calls
        // SyncWithIndexer() after broadcasting instead.
        TransactionError error = node::BroadcastTransaction(
            m_node, tx_ref, err_str, max_fee_sats * Amount::satoshi(),
            /*relay=*/true, /*wait_callback=*/false);
        if (error != TransactionError::OK) {
            bilingual_str tx_error_msg = TransactionErrorString(error);
            result.error =
                err_str.empty()
                    ? tx_error_msg.original
                    : strprintf("%s: %s", tx_error_msg.original, err_str);
            return result;
        }
        result.ok = true;
        result.txid = ToHash(tx_ref->GetId());
    } catch (const std::exception &e) {
        result.error = e.what();
    }
    return result;
}

int64_t AbcHost::CalcMaxFee(size_t tx_size) const {
    const int64_t rate =
        node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK() / SATOSHI;
    return CFeeRate(rate * SATOSHI).GetFee(tx_size) / SATOSHI;
}

std::optional<FeeRateInfo> AbcHost::MempoolFeeRate(const TxId &txid) const {
    if (!m_node.mempool) {
        return std::nullopt;
    }
    AssertLockNotHeld(m_node.mempool->cs);
    LOCK(m_node.mempool->cs);
    auto iter = m_node.mempool->GetIter(::TxId{FromHash(txid)});
    if (!iter) {
        return std::nullopt;
    }
    return FeeRateInfo{
        .sats_per_kb =
            (**iter)->GetModifiedFeeRate().GetFeePerK() / Amount::satoshi(),
        .vsize = uint32_t((**iter)->GetTxVirtualSize()),
    };
}

int64_t AbcHost::EstimateFeeRateSatsPerKb() const {
    if (!m_node.mempool) {
        return -1;
    }
    const int64_t now_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    const lotus::v2::FeeRateInfo fee_info =
        lotus::v2::GetGlobalFeeHysteresisController().GetFeeRateInfo(now_ms);
    const int64_t hysteresis_rate =
        fee_info.rpc_admission_feerate_per_kcu >
                fee_info.consensus_floor_per_kcu
            ? static_cast<int64_t>(std::min<uint64_t>(
                  fee_info.recommended_sdk_feerate_per_kcu, INT64_MAX))
            : static_cast<int64_t>(std::min<uint64_t>(
                  fee_info.rpc_admission_feerate_per_kcu, INT64_MAX));
    const Amount fee_rate_sats_per_k =
        m_node.mempool->estimateFee().GetFeePerK();
    return std::max<int64_t>(fee_rate_sats_per_k / Amount::satoshi(),
                             hysteresis_rate);
}

int64_t AbcHost::MinRelayFeeRateSatsPerKb() const {
    if (!m_node.mempool) {
        return -1;
    }
    const int64_t now_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    const uint64_t rpc_rate_per_kcu =
        lotus::v2::GetGlobalFeeHysteresisController().GetRpcAdmissionRatePerKCu(
            now_ms);
    const int64_t base_relay =
        m_node.mempool->m_opts.min_relay_feerate.GetFeePerK() /
        Amount::satoshi();
    return std::max<int64_t>(
        base_relay,
        static_cast<int64_t>(std::min<uint64_t>(rpc_rate_per_kcu, INT64_MAX)));
}

std::optional<bool>
AbcHost::IsFinalizedPreConsensus(const TxId &txid) const {
    if (!m_node.mempool) {
        return false;
    }
    AssertLockNotHeld(m_node.mempool->cs);
    return WITH_LOCK(m_node.mempool->cs,
                     return m_node.mempool->isAvalancheFinalizedPreConsensus(
                         ::TxId{FromHash(txid)}));
}

void AbcHost::SyncWithIndexer() const {
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

bool AbcHost::ShutdownRequested() const {
    return ::ShutdownRequested();
}

void AbcHost::FatalError(std::string_view log_msg,
                         std::string_view user_msg) const {
    m_node.chainman->GetNotifications().fatalError(
        std::string(log_msg), Untranslated(std::string(user_msg)));
}

void AbcHost::Log(LogLevel level, std::string_view msg) const {
    // All Chronik call sites share this source location, so rate limiting
    // applies a single quota to rate-limited Chronik logs, as in Rust.
    switch (level) {
        case LogLevel::Debug:
            if (!LogInstance().WillLogCategory(BCLog::CHRONIK)) {
                return;
            }
            [[fallthrough]];
        case LogLevel::InfoNoRateLimit:
            LogInstance().LogPrintStr(std::string(msg),
                                      std::source_location::current(),
                                      BCLog::LogFlags::NONE,
                                      BCLog::Level::Info,
                                      /*site=*/nullptr);
            return;
        case LogLevel::Info: {
            // One quota for every rate-limited Chronik log, as the Rust
            // bridge's log_print.
            static constinit BCLog::LogSiteLimit site_limit;
            LogInstance().LogPrintStr(std::string(msg),
                                      std::source_location::current(),
                                      BCLog::LogFlags::NONE,
                                      BCLog::Level::Info, &site_limit);
            return;
        }
    }
}

std::string AbcHost::FormatFullVersion() const {
    return ::FormatFullVersion();
}

void AbcHost::Sha256(std::span<const uint8_t> data, uint8_t out[32]) const {
    CSHA256().Write(data.data(), data.size()).Finalize(out);
}

} // namespace chronik::native::abc
