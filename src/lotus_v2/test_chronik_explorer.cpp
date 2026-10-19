// Copyright (c) 2026 The Lotus developers
#include "chronik_sync.h"
#include "signing.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace lotus::v2;
namespace {
void Check(bool ok, const std::string &message) {
    if (!ok) throw std::runtime_error(message);
}
Hash H(uint8_t byte) { Hash h{}; h.fill(byte); return h; }
std::vector<uint8_t> Slice(const std::vector<uint8_t> &wire,
                           ChronikWireRange range) {
    Check(range.offset <= wire.size() &&
              range.length <= wire.size() - range.offset, "range bounds");
    return {wire.begin() + range.offset,
            wire.begin() + range.offset + range.length};
}
Output Pay() {
    Output o;
    o.value = UINT64_MAX;
    for (uint8_t n = 1; n <= 16; ++n) o.branches.push_back(H(n));
    for (uint8_t n = 0; n < 16; ++n) o.paths.push_back({n});
    return o;
}
Transaction Coinbase(bool present) {
    Transaction tx;
    Input i;
    i.flags = 2;
    i.prev_index = UINT32_MAX;
    i.sequence = UINT32_MAX;
    i.has_coinbase_data = present;
    if (present) i.coinbase_data.assign(8192, 0xab);
    tx.inputs.push_back(i);
    tx.outputs.push_back(Pay());
    return tx;
}
ChronikBlock Convert(std::vector<Transaction> txs, const TxProfile &profile,
                     const ChainId &chain, std::vector<uint8_t> &wire,
                     Header &header) {
    std::string error;
    Check(CompleteTransactionRoot(txs, profile, chain, header.tx_root, error), error);
    header.size = HEADER_SIZE + 4;
    for (const auto &tx : txs) {
        std::vector<uint8_t> encoded;
        Check(EncodeTransaction(tx, profile, encoded, error), error);
        header.size += CompactSizeWidth(encoded.size()) + encoded.size();
    }
    Check(EncodeBlockWire(header, txs, profile, wire, error), error);
    ChronikAnchor anchor{{}, header.height};
    Check(BlockId(chain, header, anchor.block_id), "native block id");
    ChronikBlock converted;
    Check(MakeChronikBlock(wire, chain, profile, anchor, converted, error), error);
    Check(std::equal(converted.header_wire.begin(), converted.header_wire.end(),
                     wire.begin()), "exact 134-byte source header");
    Header parsed;
    Check(ParseHeader(converted.header_wire.data(), 134, parsed), "header parse");
    Check(parsed.tx_root == header.tx_root && parsed.height == header.height &&
              parsed.prev_id == header.prev_id && parsed.size == wire.size() &&
              parsed.time == header.time && parsed.bits == header.bits &&
              parsed.nonce == header.nonce && parsed.version == header.version &&
              parsed.state_root == header.state_root, "all exact header fields");
    std::vector<TxIdentityPair> pairs;
    for (size_t n = 0; n < txs.size(); ++n) {
        const auto &record = converted.transactions[n];
        std::vector<uint8_t> encoded;
        Check(EncodeTransaction(txs[n], profile, encoded, error), error);
        Check(record.wire == encoded && record.index == n &&
                  record.lock == txs[n].lock, "exact complete frame/ordinal/lock");
        IdentityDigests identity;
        Check(ComputeIdentities(txs[n], profile, chain, identity, error), error);
        Check(record.txid == identity.txid && record.txhash == identity.txhash &&
                  record.txid != record.txhash, "distinct native identities");
        pairs.push_back({record.txhash, record.txid});
        for (size_t out = 0; out < txs[n].outputs.size(); ++out) {
            Output o;
            Check(DecodeOutput(record.outputs[out], o, error), error);
            Check(o.branches == txs[n].outputs[out].branches &&
                      o.paths == txs[n].outputs[out].paths &&
                      o.value == txs[n].outputs[out].value &&
                      o.flags == txs[n].outputs[out].flags &&
                      (!o.HasToken() || o.token_id == txs[n].outputs[out].token_id),
                  "all ordered branches/paths and output fields");
        }
    }
    Hash root;
    Check(TransactionRoot(pairs, root) && root == header.tx_root,
          "ordered native transaction root parity");
    if (pairs.size() > 1) {
        std::reverse(pairs.begin(), pairs.end());
        Check(TransactionRoot(pairs, root) && root != header.tx_root,
              "transaction order bound by root");
    }
    auto sentinel = converted;
    auto changed = wire;
    changed.back() ^= 1;
    Check(!MakeChronikBlock(changed, chain, profile, anchor, converted, error) &&
              converted.header_wire == sentinel.header_wire &&
              converted.transactions.back().wire == sentinel.transactions.back().wire,
          "changed authenticated frame rejected atomically");
    ++anchor.height;
    Check(!MakeChronikBlock(wire, chain, profile, anchor, converted, error),
          "anchor height authenticated");
    return sentinel;
}
} // namespace
int main() {
    try {
        const TxProfile profile{256, 256, 256, 65536, 65535, 8192, 64};
        const ChainId chain = H(0x55);
        Header h;
        h.bits = 0x207fffff;
        h.time = MAX_TIME;
        h.nonce = UINT64_MAX;
        h.version = UINT32_MAX;
        h.state_root = H(0x99);
        std::vector<uint8_t> block_wire;
        for (const bool present : {false, true}) {
            const auto block = Convert({Coinbase(present)}, profile, chain, block_wire, h);
            Check(block.parent.block_id == Hash{} && block.parent.height == 0,
                  "native genesis retains zero predecessor");
            const auto &tx = block.transactions.front();
            const auto &input = tx.full_inputs.front();
            Check(input.flags == 2 && input.prev_index == UINT32_MAX &&
                      input.sequence == UINT32_MAX && input.path_index == 0 &&
                      input.has_coinbase_data == present && input.witnesses.empty(),
                  "coinbase core selectors");
            Check(present ? input.coinbase_data == ChronikWireRange{61, 8192}
                          : input.coinbase_data == ChronikWireRange{},
                  "coinbase exact payload offset and absence");
            if (present) Check(Slice(tx.wire, input.coinbase_data) ==
                                   std::vector<uint8_t>(8192, 0xab), "coinbase bytes");
        }
        Transaction tx;
        tx.lock = (UINT64_MAX & ~uint64_t{255}) | 2;
        Input mint;
        mint.flags = 3;
        mint.prev_txid = H(0xa1);
        mint.sequence = UINT32_MAX;
        BranchWitness m;
        m.script = {0x11};
        m.siblings = {H(0xa2)};
        m.arguments = {{0x12}, {}};
        mint.witnesses = {m};
        Input spend;
        spend.flags = 1;
        spend.prev_txid = H(0xb1);
        spend.prev_index = UINT32_MAX;
        spend.sequence = UINT32_MAX;
        spend.path_index = 15;
        BranchWitness w;
        w.script.assign(32768, 0x22);
        w.siblings.assign(64, H(0xb2));
        w.arguments.assign(253, std::vector<uint8_t>(253, 0x33));
        spend.witnesses = {w, BranchWitness{}};
        tx.inputs = {mint, spend};
        tx.outputs = {Pay()};
        auto token = Pay();
        token.flags = 1;
        token.token_id = mint.prev_txid;
        tx.outputs.push_back(token);
        Output burn;
        burn.flags = 3;
        burn.value = 7;
        burn.token_id = mint.prev_txid;
        burn.branches = {H(0xdd)};
        tx.outputs.push_back(burn);
        h.prev_id = H(0xcc);
        h.height = UINT64_MAX;
        const auto block = Convert({Coinbase(false), tx}, profile, chain, block_wire, h);
        Check(block.parent.height == UINT64_MAX - 1 &&
                  block.parent.block_id == h.prev_id, "maximum parent height");
        const auto &record = block.transactions[1];
        Check(record.inputs.size() == 1 && record.inputs[0].input_index == 1 &&
                  record.full_inputs.size() == 2 && record.full_inputs[0].flags == 3 &&
                  record.full_inputs[1].flags == 1 &&
                  record.full_inputs[1].path_index == 15 &&
                  record.full_inputs[1].prev_index == UINT32_MAX,
              "mint selector plus nonzero spend ordinal");
        const auto &mw = record.full_inputs[0].witnesses[0];
        Check(mw.script == ChronikWireRange{58, 1} &&
                  mw.siblings_table == ChronikWireRange{59, 33} &&
                  mw.arguments_table == ChronikWireRange{92, 4} &&
                  mw.siblings_count == 1 && mw.arguments_count == 2,
              "exact mint witness table framing offsets");
        Check(Slice(record.wire, mw.arguments_table) ==
                  std::vector<uint8_t>({2, 1, 0x12, 0}), "mint arguments bytes");
        const auto &sw = record.full_inputs[1].witnesses[0];
        Check(sw.script == ChronikWireRange{142, 32768} &&
                  sw.siblings_table == ChronikWireRange{32910, 2049} &&
                  sw.arguments_table == ChronikWireRange{34959, 64771} &&
                  sw.siblings_count == 64 && sw.arguments_count == 253,
              "chunk crossing payload and multi-byte argument framing");
        Check(Slice(record.wire, sw.script) == w.script, "full script byte parity");
        const auto siblings = Slice(record.wire, sw.siblings_table);
        Check(siblings.front() == 64 && siblings.size() == 2049 &&
                  std::all_of(siblings.begin() + 1, siblings.end(),
                              [](uint8_t b) { return b == 0xb2; }), "proof table bytes");
        const auto args = Slice(record.wire, sw.arguments_table);
        Check(args[0] == 253 && args[1] == 253 && args[2] == 0 &&
                  args[3] == 253 && args[4] == 253 && args[5] == 0,
              "canonical arguments count/element prefixes");
        const auto &empty = record.full_inputs[1].witnesses[1];
        Check(empty.script.length == 0 && empty.script.offset == 99731 &&
                  empty.siblings_table == ChronikWireRange{99731, 1} &&
                  empty.arguments_table == ChronikWireRange{99732, 1},
              "empty script preserves offset and empty tables preserve framing");
        std::string error;
        std::vector<uint8_t> kept{0xee};
        std::vector<ChronikFullInput> facts(1);
        for (size_t cut : {size_t(0), size_t(16), record.wire.size() - 1}) {
            Check(!MakeChronikExplorerFacts(tx, profile,
                    std::span<const uint8_t>(record.wire).first(cut), kept, facts, error) &&
                      kept == std::vector<uint8_t>{0xee} && facts.size() == 1,
                  "short exact frame refuses partial facts");
        }
        auto strict = profile;
        strict.max_arguments = 252;
        Check(!MakeChronikExplorerFacts(tx, strict, record.wire, kept, facts, error),
              "profile count cap before descriptor vectors");
        auto malformed = record.wire;
        malformed.push_back(0);
        Check(!MakeChronikExplorerFacts(tx, profile, malformed, kept, facts, error),
              "extra source bytes refused");
        std::cout << "chronik explorer producer checks passed\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
