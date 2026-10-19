// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockindex.h>
#include <chainparams.h>
#include <chronik-bridge/src/ffi.rs.h>
#include <chronik-cpp/chronik_bridge.h>
#include <chronik-cpp/util/collection.h>
#include <chronik-cpp/util/hash.h>
#include <clientversion.h>
#include <common/messages.h>
#include <compressor.h>
#include <config.h>
#include <feerate.h>
#include <logging.h>
#include <lotus_v2/fee_hysteresis.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/metrics.h>
#include <node/transaction.h>
#include <node/ui_interface.h>
#include <shutdown.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <undo.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <optional>

using common::TransactionErrorString;
using node::TransactionError;

chronik_bridge::OutPoint BridgeOutPoint(const COutPoint &outpoint) {
    return {
        .txid = chronik::util::HashToArray(outpoint.GetTxId()),
        .out_idx = outpoint.GetN(),
    };
}

template <typename TxOutT>
rust::Vec<uint8_t> BridgeTxOutputScript(const TxOutT &output) {
    if constexpr (requires {
                      output.vBranches;
                      output.nFlags;
                      output.tokenId;
                      output.vPaths;
                  }) {
        if (output.scriptPubKey.size() <= 1 && !output.vBranches.empty()) {
            uint8_t flags = output.nFlags & 0x07;
            const bool has_token = !output.tokenId.IsNull() || (flags & 1) != 0;
            if (has_token) {
                flags |= 1;
            }
            const bool is_burn = (flags & 2) != 0;
            std::vector<uint8_t> out;
            out.push_back(flags);
            const uint64_t val = static_cast<uint64_t>(
                std::max<int64_t>(0, output.nValue / Amount::satoshi()));
            for (int i = 0; i < 8; ++i) {
                out.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xff));
            }
            if (has_token) {
                out.insert(out.end(), output.tokenId.begin(),
                           output.tokenId.end());
            }
            if constexpr (requires { output.stateRoot; }) {
                if (flags & 0x04) {
                    out.insert(out.end(), output.stateRoot.begin(),
                               output.stateRoot.end());
                }
            } else {
                flags &= 0x03;
                out[0] = flags;
            }
            out.push_back(static_cast<uint8_t>(output.vBranches.size()));
            for (const auto &branch : output.vBranches) {
                out.insert(out.end(), branch.begin(), branch.end());
            }
            if (is_burn) {
                out.push_back(0);
            } else if (!output.vPaths.empty()) {
                out.push_back(static_cast<uint8_t>(output.vPaths.size()));
                for (const auto &path : output.vPaths) {
                    out.push_back(static_cast<uint8_t>(path.size()));
                    out.insert(out.end(), path.begin(), path.end());
                }
            } else {
                out.push_back(static_cast<uint8_t>(output.vBranches.size()));
                for (size_t idx = 0; idx < output.vBranches.size(); ++idx) {
                    out.push_back(1);
                    out.push_back(static_cast<uint8_t>(idx));
                }
            }
            return chronik::util::ToRustVec<uint8_t>(out);
        }
    }
    return chronik::util::ToRustVec<uint8_t>(output.scriptPubKey);
}

template <typename TxInT>
rust::Vec<uint8_t> BridgeTxInputScript(const TxInT &input) {
    if constexpr (requires {
                      input.vCoinbaseData;
                      input.vWitnesses;
                      input.nFlags;
                  }) {
        if (input.scriptSig.empty()) {
            if (input.nFlags == 2 && !input.vCoinbaseData.empty()) {
                return chronik::util::ToRustVec<uint8_t>(input.vCoinbaseData);
            }
            if (!input.vWitnesses.empty() &&
                !input.vWitnesses[0].script.empty()) {
                return chronik::util::ToRustVec<uint8_t>(
                    input.vWitnesses[0].script);
            }
        }
    }
    return chronik::util::ToRustVec<uint8_t>(input.scriptSig);
}

chronik_bridge::TxOutput BridgeTxOutput(const CTxOut &output) {
    return {
        .sats = output.nValue / Amount::satoshi(),
        .script = BridgeTxOutputScript(output),
    };
}

chronik_bridge::Coin BridgeCoin(const Coin &coin) {
    const int32_t nHeight =
        coin.GetHeight() == 0x7fff'ffff ? -1 : coin.GetHeight();
    return {
        .output = BridgeTxOutput(coin.GetTxOut()),
        .height = nHeight,
        .is_coinbase = coin.IsCoinBase(),
    };
}

rust::Vec<chronik_bridge::TxInput>
BridgeTxInputs(bool isCoinbase, Span<const CTxIn> inputs,
               const std::vector<Coin> &spent_coins) {
    rust::Vec<chronik_bridge::TxInput> bridged_inputs;
    bridged_inputs.reserve(inputs.size());
    for (size_t idx = 0; idx < inputs.size(); ++idx) {
        const CTxIn &input = inputs[idx];
        if (!isCoinbase && input.nFlags == 3) {
            continue;
        }
        chronik_bridge::Coin bridge_coin{}; // empty coin
        if (!isCoinbase) {
            if (idx >= spent_coins.size()) {
                throw std::runtime_error("Missing coin for input");
            }
            bridge_coin = BridgeCoin(spent_coins[idx]);
        }
        bridged_inputs.push_back({
            .prev_out = BridgeOutPoint(input.prevout),
            .script = BridgeTxInputScript(input),
            .sequence = input.nSequence,
            .coin = std::move(bridge_coin),
        });
    }
    return bridged_inputs;
}

rust::Vec<chronik_bridge::TxOutput>
BridgeTxOutputs(Span<const CTxOut> outputs) {
    rust::Vec<chronik_bridge::TxOutput> bridged_outputs;
    bridged_outputs.reserve(outputs.size());
    for (const CTxOut &output : outputs) {
        bridged_outputs.push_back(BridgeTxOutput(output));
    }
    return bridged_outputs;
}

chronik_bridge::Tx BridgeTx(bool isCoinbase, const CTransaction &tx,
                            const std::vector<Coin> &spent_coins) {
    return {
        .txid = chronik::util::HashToArray(tx.GetId()),
        .version = tx.nVersion,
        .inputs = BridgeTxInputs(isCoinbase, tx.vin, spent_coins),
        .outputs = BridgeTxOutputs(tx.vout),
        .locktime = tx.nLockTime,
    };
}

chronik_bridge::BlockTx BridgeBlockTx(bool isCoinbase, const CTransaction &tx,
                                      const std::vector<Coin> &spent_coins,
                                      size_t data_pos, size_t undo_pos) {
    return {.tx = BridgeTx(isCoinbase, tx, spent_coins),
            .data_pos = uint32_t(data_pos),
            .undo_pos = uint32_t(isCoinbase ? 0 : undo_pos)};
}

inline size_t GetFirstBlockTxOffset(const CBlock &block,
                                    const size_t block_data_pos) {
    return block_data_pos + ::GetSerializeSize(CBlockHeader()) +
           GetSizeOfCompactSize(block.vtx.size());
}

inline size_t GetFirstUndoOffset(const CBlock &block,
                                 const size_t block_undo_pos) {
    // We have to -1 here, because coinbase txs don't have undo data.
    return block_undo_pos + GetSizeOfCompactSize(block.vtx.size() - 1);
}

chronik_bridge::Block BridgeBlock(const CBlock &block,
                                  const CBlockUndo &block_undo,
                                  const CBlockIndex &bindex)
    EXCLUSIVE_LOCKS_REQUIRED(!::cs_main) {
    AssertLockNotHeld(::cs_main);

    uint32_t block_file_num{0};
    uint32_t block_data_pos{0};
    uint32_t block_undo_pos{0};
    {
        LOCK(::cs_main);
        block_file_num = uint32_t(bindex.nFile);
        block_data_pos = bindex.nDataPos;
        block_undo_pos = bindex.nUndoPos;
    }

    size_t data_pos = GetFirstBlockTxOffset(block, block_data_pos);
    size_t undo_pos = 0;

    // Set undo offset; for the genesis block leave it at 0
    if (bindex.nHeight > 0) {
        undo_pos = GetFirstUndoOffset(block, block_undo_pos);
    }

    rust::Vec<chronik_bridge::BlockTx> bridged_txs;
    for (size_t tx_idx = 0; tx_idx < block.vtx.size(); ++tx_idx) {
        const bool isCoinbase = tx_idx == 0;
        const CTransaction &tx = *block.vtx[tx_idx];
        if (!isCoinbase && tx_idx - 1 >= block_undo.vtxundo.size()) {
            throw std::runtime_error("Missing undo data for tx");
        }
        const std::vector<Coin> &spent_coins =
            isCoinbase ? std::vector<Coin>()
                       : block_undo.vtxundo[tx_idx - 1].vprevout;
        bridged_txs.push_back(
            BridgeBlockTx(isCoinbase, tx, spent_coins, data_pos, undo_pos));

        // advance data_pos and undo_pos positions
        data_pos += ::GetSerializeSize(tx);
        if (!isCoinbase) {
            undo_pos += ::GetSerializeSize(block_undo.vtxundo[tx_idx - 1]);
        }
    }

    return {.hash = chronik::util::HashToArray(block.GetHash()),
            .prev_hash = chronik::util::HashToArray(block.hashPrevBlock),
            .n_bits = block.nBits,
            .timestamp = block.GetBlockTime(),
            .height = bindex.nHeight,
            .file_num = block_file_num,
            .data_pos = block_data_pos,
            .undo_pos = block_undo_pos,
            .size = ::GetSerializeSize(block),
            .txs = bridged_txs};
}

namespace chronik_bridge {

void log_print(const rust::Str logging_function, const rust::Str source_file,
               const uint32_t source_line, const rust::Str msg,
               bool should_ratelimit) {
    // All Chronik Rust call sites share this C++ source_location, so rate
    // limiting applies a single hourly quota to rate-limited Chronik logs.
    // Pass should_ratelimit=false for high-volume expected paths (e.g. IBD /
    // reindex progress).
    static constinit BCLog::LogSiteLimit site_limit;
    LogInstance().LogPrintStr(std::string(msg), std::source_location::current(),
                              BCLog::LogFlags::NONE, BCLog::Level::Info,
                              should_ratelimit ? &site_limit : nullptr);
}

void log_print_chronik(const rust::Str logging_function,
                       const rust::Str source_file, const uint32_t source_line,
                       const rust::Str msg) {
    // Never rate-limited: -debug=chronik is opt-in, like other debug
    // categories.
    if (LogInstance().WillLogCategory(BCLog::CHRONIK)) {
        log_print(logging_function, source_file, source_line, msg,
                  /*should_ratelimit=*/false);
    }
}

ChronikBridge::ChronikBridge(const node::NodeContext &node) : m_node{node} {
    // This class relies on these two members not being nullptr
    Assert(m_node.chainman);
    Assert(m_node.mempool);
}

const CBlockIndex &ChronikBridge::get_chain_tip() const {
    const CBlockIndex *tip =
        WITH_LOCK(cs_main, return m_node.chainman->ActiveTip());
    if (tip == nullptr) {
        throw block_index_not_found();
    }
    return *tip;
}

const CBlockIndex &
ChronikBridge::lookup_block_index(std::array<uint8_t, 32> hash) const {
    BlockHash block_hash{chronik::util::ArrayToHash(hash)};
    const CBlockIndex *pindex = WITH_LOCK(
        cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(block_hash));
    if (!pindex) {
        throw block_index_not_found();
    }
    return *pindex;
}

const CBlockIndex &
ChronikBridge::lookup_block_index_by_height(int height) const {
    // The boundary check is performed in the CChain::operator[](int nHeight)
    // method, a nullptr is returned if height is out of bounds.
    const CBlockIndex *pindex = WITH_LOCK(
        cs_main,
        return m_node.chainman->GetChainstateForIndexing().m_chain[height]);
    if (!pindex) {
        throw block_index_not_found();
    }
    return *pindex;
}

rust::Vec<RawBlockHeader>
ChronikBridge::get_block_headers_by_range(int start, int end) const {
    if (start < 0 || end < start) {
        throw invalid_block_range();
    }
    LOCK(cs_main);
    std::vector<RawBlockHeader> headers;
    for (int height = start; height <= end; height++) {
        const CBlockIndex *pindex =
            m_node.chainman->GetChainstateForIndexing().m_chain[height];
        if (!pindex) {
            // We allow partial results or empty result.
            // We can assume that if a block height does not exist the following
            // ones also will not exist.
            return chronik::util::ToRustVec<RawBlockHeader>(headers);
        }
        headers.push_back({.data = get_block_header(*pindex)});
    }
    return chronik::util::ToRustVec<RawBlockHeader>(headers);
}

rust::Vec<WrappedBlockHash>
ChronikBridge::get_block_hashes_by_range(int start, int end) const {
    if (start < 0 || end < start) {
        throw invalid_block_range();
    }
    LOCK(cs_main);
    std::vector<WrappedBlockHash> block_hashes;
    for (int height = start; height <= end; height++) {
        const CBlockIndex *pindex =
            m_node.chainman->GetChainstateForIndexing().m_chain[height];
        if (!pindex) {
            throw block_index_not_found();
        }
        block_hashes.push_back(
            {.data = chronik::util::HashToArray(pindex->GetBlockHash())});
    }
    return chronik::util::ToRustVec<WrappedBlockHash>(block_hashes);
}

std::unique_ptr<CBlock>
ChronikBridge::load_block(const CBlockIndex &bindex) const {
    CBlock block;
    if (!m_node.chainman->m_blockman.ReadBlock(block, bindex)) {
        throw std::runtime_error("Reading block data failed");
    }
    return std::make_unique<CBlock>(std::move(block));
}

std::unique_ptr<CBlockUndo>
ChronikBridge::load_block_undo(const CBlockIndex &bindex) const {
    CBlockUndo block_undo;
    // Read undo data (genesis block doesn't have undo data)
    if (bindex.nHeight > 0) {
        if (!m_node.chainman->m_blockman.ReadBlockUndo(block_undo, bindex)) {
            throw std::runtime_error("Reading block undo data failed");
        }
    }
    return std::make_unique<CBlockUndo>(std::move(block_undo));
}

Tx ChronikBridge::load_tx(uint32_t file_num, uint32_t data_pos,
                          uint32_t undo_pos) const {
    CMutableTransaction tx;
    CTxUndo txundo{};
    const bool isCoinbase = undo_pos == 0;
    if (!m_node.chainman->m_blockman.ReadTxFromDisk(
            tx, FlatFilePos(file_num, data_pos))) {
        throw std::runtime_error("Reading tx data from disk failed");
    }
    if (!isCoinbase) {
        if (!m_node.chainman->m_blockman.ReadTxUndoFromDisk(
                txundo, FlatFilePos(file_num, undo_pos))) {
            throw std::runtime_error("Reading tx undo data from disk failed");
        }
    }
    return BridgeTx(isCoinbase, CTransaction(std::move(tx)), txundo.vprevout);
}

std::shared_ptr<const CTransaction>
ChronikBridge::read_tx_from_disk(uint32_t file_num, uint32_t data_pos) const {
    CMutableTransaction tx;
    if (!m_node.chainman->m_blockman.ReadTxFromDisk(
            tx, FlatFilePos(file_num, data_pos))) {
        throw std::runtime_error("Reading tx data from disk failed");
    }
    return std::make_shared<const CTransaction>(std::move(tx));
}

rust::Vec<uint8_t> ChronikBridge::load_raw_tx(uint32_t file_num,
                                              uint32_t data_pos) const {
    CMutableTransaction tx;
    if (!m_node.chainman->m_blockman.ReadTxFromDisk(
            tx, FlatFilePos(file_num, data_pos))) {
        throw std::runtime_error("Reading tx data from disk failed");
    }
    DataStream raw_tx{};
    raw_tx << tx;
    return chronik::util::ToRustVec<uint8_t>(MakeUCharSpan(raw_tx));
}

bool ChronikBridge::is_avalanche_finalized_preconsensus(
    const std::array<uint8_t, 32> &mempool_txid) const {
    if (!m_node.mempool) {
        return false;
    }

    AssertLockNotHeld(m_node.mempool->cs);

    TxId txid{chronik::util::ArrayToHash(mempool_txid)};
    return WITH_LOCK(
        m_node.mempool->cs,
        return m_node.mempool->isAvalancheFinalizedPreConsensus(txid));
}

Tx bridge_tx(const CTransaction &tx, const std::vector<::Coin> &spent_coins) {
    return BridgeTx(spent_coins.empty() && tx.IsCoinBase(), tx, spent_coins);
}

const CBlockIndex &ChronikBridge::find_fork(const CBlockIndex &index) const {
    const CBlockIndex *fork = WITH_LOCK(
        cs_main,
        return m_node.chainman->GetChainstateForIndexing().m_chain.FindFork(
            &index));
    if (!fork) {
        throw block_index_not_found();
    }
    return *fork;
}

void ChronikBridge::decode_raw_tx(rust::Slice<const uint8_t> raw_tx,
                                  Tx &tx) const {
    std::optional<CMutableTransaction> node_tx;
    try {
        DataStream stream{chronik::util::FromRustSlice(raw_tx)};
        CMutableTransaction mtx;
        stream >> mtx;
        node_tx = std::move(mtx);
    } catch (const std::exception &e) {
        // A v7 frame has no legacy interpretation. Reject malformed native
        // bytes instead of constructing a different transaction from defaults.
        if (raw_tx.size() >= 4 && raw_tx[0] == 7 && raw_tx[1] == 0 &&
            raw_tx[2] == 0 && raw_tx[3] == 0) {
            throw std::runtime_error(e.what());
        }
    }
    if (node_tx) {
        // A native V2 tx has no legacy-shaped fields: take the node's
        // inputs, outputs and identity, as indexed once it is broadcast.
        const CTransaction ctx{std::move(*node_tx)};
        const bool is_coinbase = ctx.IsCoinBase();
        rust::Vec<TxInput> inputs;
        inputs.reserve(ctx.vin.size());
        for (const CTxIn &input : ctx.vin) {
            if (!is_coinbase && input.nFlags == 3) {
                continue;
            }
            inputs.push_back({
                .prev_out = BridgeOutPoint(input.prevout),
                .script = BridgeTxInputScript(input),
                .sequence = input.nSequence,
                .coin = {},
            });
        }
        tx.txid = chronik::util::HashToArray(ctx.GetId());
        tx.version = ctx.nVersion;
        tx.inputs = std::move(inputs);
        tx.outputs = BridgeTxOutputs(ctx.vout);
        tx.locktime = ctx.nLockTime;
        return;
    }
    CMutableTransaction mtx;
    mtx.nVersion = tx.version;
    mtx.nLockTime = tx.locktime;
    mtx.vin.reserve(tx.inputs.size());
    for (const TxInput &in : tx.inputs) {
        mtx.vin.emplace_back(
            COutPoint(TxId(chronik::util::ArrayToHash(in.prev_out.txid)),
                      in.prev_out.out_idx),
            CScript(in.script.data(), in.script.data() + in.script.size()),
            in.sequence);
    }
    mtx.vout.reserve(tx.outputs.size());
    for (const TxOutput &out : tx.outputs) {
        mtx.vout.emplace_back(
            out.sats * SATOSHI,
            CScript(out.script.data(), out.script.data() + out.script.size()));
    }
    tx.txid = chronik::util::HashToArray(CTransaction(mtx).GetId());
}

void ChronikBridge::lookup_spent_coins(
    Tx &tx, rust::Vec<OutPoint> &not_found,
    rust::Vec<OutPoint> &coins_to_uncache) const {
    not_found.clear();
    coins_to_uncache.clear();
    LOCK(cs_main);
    CCoinsViewCache &coins_cache =
        m_node.chainman->GetChainstateForIndexing().CoinsTip();
    CCoinsViewMemPool coin_view(&coins_cache, *m_node.mempool);
    for (TxInput &input : tx.inputs) {
        TxId txid = TxId(chronik::util::ArrayToHash(input.prev_out.txid));
        COutPoint outpoint = COutPoint(txid, input.prev_out.out_idx);

        // Remember if coin was already cached
        const bool had_cached = coins_cache.HaveCoinInCache(outpoint);

        std::optional<::Coin> coin{coin_view.GetCoin(outpoint)};
        if (!coin) {
            not_found.push_back(input.prev_out);
            continue;
        }

        if (!had_cached) {
            // Only add if previously uncached.
            // We don't check if the prev_out is now cached (which wouldn't be
            // the case for a mempool UTXO), as uncaching an outpoint is cheap,
            // so we save one extra cache lookup here.
            coins_to_uncache.push_back(input.prev_out);
        }
        input.coin = BridgeCoin(std::move(*coin));
    }
}

void ChronikBridge::uncache_coins(
    rust::Slice<const OutPoint> coins_to_uncache) const {
    LOCK(cs_main);
    CCoinsViewCache &coins_cache =
        m_node.chainman->GetChainstateForIndexing().CoinsTip();
    for (const OutPoint &outpoint : coins_to_uncache) {
        TxId txid = TxId(chronik::util::ArrayToHash(outpoint.txid));
        coins_cache.Uncache(COutPoint(txid, outpoint.out_idx));
    }
}

std::array<uint8_t, 32>
ChronikBridge::broadcast_tx(rust::Slice<const uint8_t> raw_tx,
                            int64_t max_fee) const {
    std::vector<uint8_t> vec = chronik::util::FromRustSlice(raw_tx);
    DataStream stream{vec};
    CMutableTransaction tx;
    stream >> tx;
    CTransactionRef tx_ref = MakeTransactionRef(tx);
    std::string err_str;
    // wait_callback is false because this would cause a deadlock. Instead we
    // explicitly call SyncWithValidationInterfaceQueue() after broadcasting
    // the transaction to ensure that the transaction is fully processed before
    // we return.
    TransactionError error = node::BroadcastTransaction(
        m_node, tx_ref, err_str, max_fee * Amount::satoshi(), /*relay=*/true,
        /*wait_callback=*/false);
    if (error != TransactionError::OK) {
        bilingual_str txErrorMsg = TransactionErrorString(error);
        if (err_str.empty()) {
            throw std::runtime_error(txErrorMsg.original.c_str());
        } else {
            std::string msg = strprintf("%s: %s", txErrorMsg.original, err_str);
            throw std::runtime_error(msg.c_str());
        }
    }
    return chronik::util::HashToArray(tx_ref->GetId());
}

void ChronikBridge::fatal_error(const rust::Str msg,
                                const rust::Str user_msg) const {
    m_node.chainman->GetNotifications().fatalError(
        std::string(msg), Untranslated(std::string(user_msg)));
}

bool ChronikBridge::shutdown_requested() const {
    return ShutdownRequested();
}

WrappedBlockHash ChronikBridge::get_genesis_hash() const {
    const CBlock &genesis = m_node.chainman->GetParams().GenesisBlock();
    return WrappedBlockHash{.data =
                                chronik::util::HashToArray(genesis.GetHash())};
}

int64_t ChronikBridge::estimate_feerate_sats_per_kb() const {
    if (!m_node.mempool) {
        return -1;
    }

    const int64_t mempool_sats_per_kb =
        m_node.mempool->estimateFee().GetFeePerK() / Amount::satoshi();
    const int64_t now_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    const auto fee_info =
        lotus::v2::GetGlobalFeeHysteresisController().GetFeeRateInfo(now_ms);
    const int64_t hysteresis_sats_per_kb = static_cast<int64_t>(
        fee_info.rpc_admission_feerate_per_kcu >
                fee_info.consensus_floor_per_kcu
            ? std::min<uint64_t>(fee_info.recommended_sdk_feerate_per_kcu, INT64_MAX)
            : std::min<uint64_t>(fee_info.rpc_admission_feerate_per_kcu, INT64_MAX));
    return std::max(mempool_sats_per_kb, hysteresis_sats_per_kb);
}

int64_t ChronikBridge::min_relay_feerate_sats_per_kb() const {
    if (!m_node.mempool) {
        return -1;
    }

    const int64_t base_relay_sats_per_kb =
        m_node.mempool->m_opts.min_relay_feerate.GetFeePerK() /
        Amount::satoshi();
    const int64_t now_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    const int64_t rpc_admission_sats_per_kb = static_cast<int64_t>(
        std::min<uint64_t>(lotus::v2::GetGlobalFeeHysteresisController()
            .GetRpcAdmissionRatePerKCu(now_ms), INT64_MAX));
    return std::max(base_relay_sats_per_kb, rpc_admission_sats_per_kb);
}

bool ChronikBridge::get_feerate_info(std::array<uint8_t, 32> mempool_txid,
                                     int64_t &modified_fee_rate_sats_per_kb,
                                     uint32_t &virtual_size_bytes) const {
    TxId txid{chronik::util::ArrayToHash(mempool_txid)};

    if (!m_node.mempool) {
        return false;
    }

    AssertLockNotHeld(m_node.mempool->cs);
    LOCK(m_node.mempool->cs);

    auto iter = m_node.mempool->GetIter(txid);
    if (!iter) {
        return false;
    }

    modified_fee_rate_sats_per_kb =
        (**iter)->GetModifiedFeeRate().GetFeePerK() / Amount::satoshi();
    virtual_size_bytes = (**iter)->GetTxVirtualSize();

    return true;
}

void ChronikBridge::sync_with_validation_interface_queue() const {
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

std::unique_ptr<ChronikBridge> make_bridge(const node::NodeContext &node) {
    return std::make_unique<ChronikBridge>(node);
}

rust::Vec<uint8_t>
encode_v2_three_branch_output_script(const V2ThreeBranchOutputDesc &desc) {
    std::vector<std::array<uint8_t, 32>> branches;
    branches.reserve(3);
    branches.push_back(desc.key_branch);
    if (desc.script_branch && *desc.script_branch != desc.key_branch) {
        branches.push_back(*desc.script_branch);
    }
    if (desc.data_branch && *desc.data_branch != desc.key_branch &&
        (!desc.script_branch || *desc.data_branch != *desc.script_branch)) {
        branches.push_back(*desc.data_branch);
    }

    uint8_t flags = 0;
    const std::array<uint8_t, 32> zero_hash{};
    const bool has_token = desc.token_id && *desc.token_id != zero_hash;
    if (has_token) {
        flags |= 1;
    }
    if (desc.is_burn) {
        flags |= 2;
    }

    std::vector<uint8_t> out;
    out.push_back(flags);
    const uint64_t val = static_cast<uint64_t>(desc.sats);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xff));
    }
    if (has_token) {
        out.insert(out.end(), desc.token_id->begin(), desc.token_id->end());
    }
    out.push_back(static_cast<uint8_t>(branches.size()));
    for (const auto &branch : branches) {
        out.insert(out.end(), branch.begin(), branch.end());
    }
    if (desc.is_burn) {
        out.push_back(0);
    } else {
        out.push_back(static_cast<uint8_t>(branches.size()));
        for (size_t idx = 0; idx < branches.size(); ++idx) {
            out.push_back(1);
            out.push_back(static_cast<uint8_t>(idx));
        }
    }
    return chronik::util::ToRustVec<uint8_t>(out);
}

chronik_bridge::Block bridge_block(const CBlock &block,
                                   const CBlockUndo &block_undo,
                                   const CBlockIndex &bindex)
    EXCLUSIVE_LOCKS_REQUIRED(!::cs_main) {
    return BridgeBlock(block, block_undo, bindex);
}

BlockInfo get_block_info(const CBlockIndex &bindex) {
    return {
        .hash = chronik::util::HashToArray(bindex.GetBlockHash()),
        .height = bindex.nHeight,
    };
}

rust::Vec<uint8_t> get_block_header(const CBlockIndex &index) {
    DataStream ser_header{};
    ser_header << index.GetBlockHeader();
    return chronik::util::ToRustVec<uint8_t>(MakeUCharSpan(ser_header));
}

const CBlockIndex &get_block_ancestor(const CBlockIndex &index,
                                      int32_t height) {
    const CBlockIndex *pindex = index.GetAncestor(height);
    if (!pindex) {
        throw block_index_not_found();
    }
    return *pindex;
}

rust::Vec<uint8_t> compress_script(rust::Slice<const uint8_t> bytecode) {
    std::vector<uint8_t> vec = chronik::util::FromRustSlice(bytecode);
    CScript script{vec.begin(), vec.end()};
    DataStream compressed{};
    compressed << Using<ScriptCompression>(script);
    return chronik::util::ToRustVec<uint8_t>(MakeUCharSpan(compressed));
}

rust::Vec<uint8_t> decompress_script(rust::Slice<const uint8_t> compressed) {
    std::vector<uint8_t> vec = chronik::util::FromRustSlice(compressed);
    DataStream stream{vec};
    CScript script;
    stream >> Using<ScriptCompression>(script);
    return chronik::util::ToRustVec<uint8_t>(script);
}

int64_t calc_fee(size_t num_bytes, int64_t sats_fee_per_kb) {
    return CFeeRate(sats_fee_per_kb * SATOSHI).GetFee(num_bytes) / SATOSHI;
}

int64_t default_max_raw_tx_fee_rate_per_kb() {
    return node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK() / SATOSHI;
}

V2FeeRateInfo get_v2_fee_rate_info() {
    const int64_t now_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    const lotus::v2::FeeRateInfo info =
        lotus::v2::GetGlobalFeeHysteresisController().GetFeeRateInfo(now_ms);
    return V2FeeRateInfo{
        .consensus_floor_per_kcu = info.consensus_floor_per_kcu,
        .p2p_relay_feerate_per_kcu = info.p2p_relay_feerate_per_kcu,
        .rpc_admission_feerate_per_kcu = info.rpc_admission_feerate_per_kcu,
        .recommended_sdk_feerate_per_kcu = info.recommended_sdk_feerate_per_kcu,
        .marginal_burn_feerate_per_kcu = info.marginal_burn_feerate_per_kcu,
        .hysteresis_window_ms = info.hysteresis_window_ms,
        .hysteresis_discount_permille = info.hysteresis_discount_permille,
        .ema_block_size_bytes = info.ema_block_size_bytes,
        .adaptive_target_block_size = info.adaptive_target_block_size,
        .adaptive_max_block_size = info.adaptive_max_block_size,
        .adaptive_max_generated_block_size =
            info.adaptive_max_generated_block_size,
        .mempool_backlog_bytes = info.mempool_backlog_bytes,
    };
}

bool init_error(const rust::Str msg) {
    return InitError(Untranslated(std::string(msg)));
}

rust::String client_name() {
    return CLIENT_NAME;
}

void metrics_chronik_request(rust::Str route, uint16_t status, uint64_t nanos) {
    node::RecordChronikRequest(std::string_view{route.data(), route.size()},
                               status, nanos);
}

void metrics_chronik_ws_connections(int32_t delta) {
    if (auto *m{node::GetNodeMetrics()}) {
        m->chronik_ws_connections.Add(delta);
    }
}

void metrics_chronik_ws_subscriptions(int32_t delta) {
    if (auto *m{node::GetNodeMetrics()}) {
        m->chronik_ws_subscriptions.Add(delta);
    }
}

rust::String format_full_version() {
    return FormatFullVersion();
}

} // namespace chronik_bridge
