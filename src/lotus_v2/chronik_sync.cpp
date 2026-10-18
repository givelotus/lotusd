// Copyright (c) 2026 The Lotus developers
#include "chronik_sync.h"
#include "signing.h"
#include <algorithm>
#include <exception>
namespace lotus::v2 {
bool MakeChronikBlock(const std::vector<uint8_t> &wire, const ChainId &chain,
                      const TxProfile &profile, const ChronikAnchor &anchor,
                      ChronikBlock &out, std::string &error) {
    FramedBlock decoded;
    Hash id{}, root{};
    if (!DecodeBlockWire(wire, profile, chain, decoded, error) ||
        !BlockId(chain, decoded.header, id) || id != anchor.block_id ||
        decoded.header.height != anchor.height ||
        !CompleteTransactionRoot(decoded.transactions, profile, chain, root,
                                 error) ||
        root != decoded.header.tx_root) {
        error = "Chronik connected body authentication";
        return false;
    }
    ChronikBlock block;
    block.anchor = anchor;
    std::copy_n(wire.begin(), HEADER_SIZE, block.header_wire.begin());
    size_t frame_position = HEADER_SIZE + 4;
    block.parent = {decoded.header.prev_id,
                    anchor.height ? anchor.height - 1 : 0};
    for (size_t n = 0; n < decoded.transactions.size(); ++n) {
        const auto &tx = decoded.transactions[n];
        IdentityDigests identity;
        if (n > UINT32_MAX || tx.inputs.size() > UINT32_MAX ||
            !ComputeIdentities(tx, profile, chain, identity, error))
            return false;
        ChronikTransaction record;
        record.txid = identity.txid;
        record.txhash = identity.txhash;
        record.index = uint32_t(n);
        record.lock = tx.lock;
        const auto prefix = decoded.frame_prefix_bytes[n];
        if ((prefix != 1 && prefix != 3 && prefix != 5 && prefix != 9) ||
            prefix > wire.size() - frame_position) {
            error = "Chronik transaction prefix bounds";
            return false;
        }
        // DecodeBlockWire already checked the canonical enclosing length.
        // Its recorded prefix width locates that validated length without
        // decoding any transaction a second time or retaining another frame.
        uint64_t frame_size = prefix == 1 ? wire[frame_position] : 0;
        if (prefix != 1)
            for (size_t i = 1; i < prefix; ++i)
                frame_size |= uint64_t(wire[frame_position + i]) << (8 * (i - 1));
        frame_position += size_t(prefix);
        if (frame_size > wire.size() - frame_position) {
            error = "Chronik transaction frame bounds";
            return false;
        }
        if (!MakeChronikExplorerFacts(
                tx, profile,
                std::span<const uint8_t>(wire).subspan(frame_position,
                                                     size_t(frame_size)),
                record.wire, record.full_inputs, error))
            return false;
        frame_position += size_t(frame_size);
        for (size_t i = 0; i < tx.inputs.size(); ++i)
            if (tx.inputs[i].flags == 1)
                record.inputs.push_back({tx.inputs[i].prev_txid,
                                         tx.inputs[i].prev_index, uint32_t(i)});
        for (const auto &output : tx.outputs) {
            std::vector<uint8_t> bytes;
            if (!EncodeOutput(output, bytes, error)) return false;
            record.outputs.push_back(std::move(bytes));
        }
        block.transactions.push_back(std::move(record));
    }
    if (frame_position != wire.size()) {
        error = "Chronik block frame consumption";
        return false;
    }
    out = std::move(block);
    error.clear();
    return true;
}
ChronikSync::ChronikSync(DevelopmentRuntime &runtime, ChronikSink &sink,
                         ChainId chain, TxProfile profile, uint64_t max_bytes)
    : runtime_(runtime), sink_(sink), chain_(chain), profile_(profile),
      max_bytes_(max_bytes) {}
ChronikSyncResult ChronikSync::Step(std::string &error) {
    error.clear();
    try {
        const auto snapshot = runtime_.Snapshot();
        if (!max_bytes_ || !snapshot.chain || snapshot.reopen_required ||
            snapshot.execution_paused || snapshot.chain->pending_journal ||
            snapshot.chain->pending_receipt ||
            snapshot.chain->pending_propagation) {
            return ChronikSyncResult::Unavailable;
        }
        const auto indexed = sink_.Checkpoint();
        const auto tip = snapshot.chain->stable_tip;
        std::optional<Header> next;
        DiskStateError failure;
        auto headers = [&](std::span<const Hash> locator, const Hash &stop,
                           std::vector<Header> &out) {
            const auto result =
                runtime_.ReadHeaders(tip, locator, stop, 1, 1, out, failure);
            if (result != ChainIndexResult::Complete) {
                error = failure.message.empty()
                            ? "Chronik active header lookup unavailable"
                            : failure.message;
                return false;
            }
            return true;
        };
        std::vector<Header> found;
        if (indexed) {
            // The explicit-stop query checks membership via the active height
            // index. A missing checkpoint is divergent, never a catchup
            // locator.
            if (!headers({}, indexed->block_id, found))
                return ChronikSyncResult::Error;
            if (found.empty()) {
                if (!indexed->height) {
                    error = "Chronik genesis checkpoint mismatch";
                    return ChronikSyncResult::Error;
                }
                sink_.Disconnect(*indexed);
                return ChronikSyncResult::Progress;
            }
            if (found.front().height != indexed->height) {
                error = "Chronik checkpoint height mismatch";
                return ChronikSyncResult::Error;
            }
            if (indexed->block_id == tip) return ChronikSyncResult::Ready;
            const std::array<Hash, 1> locator{indexed->block_id};
            if (!headers(locator, {}, found)) return ChronikSyncResult::Error;
            if (found.size() != 1 ||
                found.front().prev_id != indexed->block_id ||
                indexed->height == UINT64_MAX ||
                found.front().height != indexed->height + 1) {
                error = "Chronik active child unavailable";
                return ChronikSyncResult::Error;
            }
            next = found.front();
        } else {
            // Unknown locator falls back to anchored genesis and returns its
            // first child, avoiding a tip-to-genesis walk even on fresh sync.
            const std::array<Hash, 1> locator{Hash{}};
            if (!headers(locator, {}, found)) return ChronikSyncResult::Error;
            const auto genesis = found.empty() ? tip : found.front().prev_id;
            std::optional<IndexedHeader> header;
            if (runtime_.ReadHeader(genesis, header, error) !=
                    DevelopmentRuntimeResult::Progress ||
                !header || header->stage != HeaderStage::Connected ||
                header->header.height != 0) {
                error = "Chronik authoritative genesis unavailable";
                return ChronikSyncResult::Error;
            }
            next = header->header;
        }
        ChronikAnchor anchor;
        anchor.height = next->height;
        if (!BlockId(chain_, *next, anchor.block_id))
            return ChronikSyncResult::Error;
        std::vector<uint8_t> wire;
        ChronikBlock block;
        if (runtime_.ReadConnectedBody(anchor.block_id, max_bytes_, wire,
                                       error) !=
                DevelopmentRuntimeResult::Progress ||
            !MakeChronikBlock(wire, chain_, profile_, anchor, block, error))
            return ChronikSyncResult::Error;
        if (indexed)
            sink_.Connect(block);
        else
            sink_.Initialize(block);
        return ChronikSyncResult::Progress;
    } catch (const std::exception &e) {
        error = e.what();
        return ChronikSyncResult::Error;
    }
}
} // namespace lotus::v2

#ifdef LOTUS_V2_CHRONIK_CXX
namespace lotus::v2 {
namespace {
    chronik_v2::Anchor BridgeAnchor(const ChronikAnchor &a) {
        chronik_v2::Anchor out;
        out.block_id = a.block_id;
        out.height = a.height;
        return out;
    }
    chronik_v2::NativeBlock BridgeBlock(const ChronikBlock &b) {
        chronik_v2::NativeBlock out;
        out.anchor = BridgeAnchor(b.anchor);
        out.parent = BridgeAnchor(b.parent);
        out.header_wire = b.header_wire;
        for (const auto &tx : b.transactions) {
            chronik_v2::NativeTx record;
            record.txid = tx.txid;
            record.txhash = tx.txhash;
            record.index = tx.index;
            record.lock = tx.lock;
            for (const auto byte : tx.wire) record.wire.push_back(byte);
            for (const auto &input : tx.full_inputs) {
                chronik_v2::NativeFullInput i;
                i.prev_txid = input.prev_txid;
                i.prev_index = input.prev_index;
                i.sequence = input.sequence;
                i.flags = input.flags;
                i.path_index = input.path_index;
                i.has_coinbase_data = input.has_coinbase_data;
                i.coinbase_data = {input.coinbase_data.offset,
                                   input.coinbase_data.length};
                for (const auto &witness : input.witnesses) {
                    chronik_v2::NativeWitness w;
                    w.script = {witness.script.offset, witness.script.length};
                    w.siblings_table = {witness.siblings_table.offset,
                                        witness.siblings_table.length};
                    w.siblings_count = witness.siblings_count;
                    w.arguments_table = {witness.arguments_table.offset,
                                         witness.arguments_table.length};
                    w.arguments_count = witness.arguments_count;
                    i.witnesses.push_back(std::move(w));
                }
                record.full_inputs.push_back(std::move(i));
            }
            for (const auto &input : tx.inputs) {
                chronik_v2::Input i;
                i.txid = input.txid;
                i.out_idx = input.out_idx;
                i.input_index = input.input_index;
                record.inputs.push_back(std::move(i));
            }
            for (const auto &wire : tx.outputs) {
                chronik_v2::NativeOutput output;
                for (const auto byte : wire)
                    output.wire.push_back(byte);
                record.outputs.push_back(std::move(output));
            }
            out.transactions.push_back(std::move(record));
        }
        return out;
    }
} // namespace
std::optional<ChronikAnchor> CxxChronikSink::Checkpoint() {
    const auto status = service_.status(BridgeAnchor({}));
    if (!status.initialized) return std::nullopt;
    return ChronikAnchor{status.indexed.block_id, status.indexed.height};
}
void CxxChronikSink::Initialize(const ChronikBlock &b) {
    auto genesis = BridgeBlock(b);
    // The index ABI uses a self-parented checkpoint for genesis; the native
    // block header correctly retains its all-zero predecessor.
    genesis.parent = genesis.anchor;
    service_.initialize_genesis(std::move(genesis));
}
void CxxChronikSink::Connect(const ChronikBlock &b) {
    service_.connect_block(BridgeBlock(b));
}
void CxxChronikSink::Disconnect(const ChronikAnchor &a) {
    service_.disconnect_block(BridgeAnchor(a));
}
} // namespace lotus::v2
#endif
