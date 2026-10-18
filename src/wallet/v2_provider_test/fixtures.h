// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_PROVIDER_TEST_FIXTURES_H
#define LOTUS_V2_PROVIDER_TEST_FIXTURES_H
// Minimal authenticated disk fixture copied from v2_wallet_tests.cpp at
// eaecdb04b. Direct metadata/coin commits isolate provider verification; no
// complete-block acceptance or network-chain claim is made by this fixture.
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <lotus_v2/block_wire.h>
#include <lotus_v2/incremental_utxo.h>
#include <stdexcept>
#include <wallet/v2_payment.h>
namespace provider_fixture {
using namespace lotus::v2;
using V2Hash = lotus::v2::Hash;
using namespace lotus::v2::wallet;
unsigned checks = 0;
void Check(bool value, const std::string &why) {
    ++checks;
    if (!value) throw std::runtime_error(why);
}
void Success(Result result, const std::string &error) {
    Check(result == Result::Success, "wallet operation: " + error);
}
std::vector<uint8_t> PaymentScript(const V2Hash &owner) {
    std::vector<uint8_t> script{0x20};
    script.insert(script.end(), owner.begin(), owner.end());
    script.insert(script.end(), {0xbc, 0x4e});
    return script;
}
std::vector<uint8_t> File(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), {}};
}
// Synthetic authenticated store fixture isolates wallet behavior. Append
// commits directly through DiskStateTransaction; this is not complete block
// acceptance. The separate compiler pilot must supply actual complete-block
// acceptance.
struct Chain {
    ChainProfile profile;
    DiskStateStore store;
    std::vector<Header> history;
    MonetaryState money{9, 200, {}, 4};
    std::string path;
    explicit Chain(const std::string &directory) : path(directory) {
        auto &hp = profile.header;
        hp.chain_id[0] = 71;
        hp.version = 2;
        hp.genesis_time = 1000;
        hp.genesis_bits = 0x207fffff;
        hp.pow_limit.fill(255);
        hp.half_life_seconds = 172800;
        hp.spacing_seconds = 120;
        auto &op = profile.ordinary;
        op.transaction = {32, 32, 8, 512, 8, 8192, 64};
        op.vm = {512, 8, 8192, 32, 32, 65536, 16, 1000000};
        op.coinbase_maturity = 2;
        op.dust_limit = 1;
        op.max_total_invocation_cost = 1000000;
        op.vm_cost.max_invocation_cost = 1000000;
        op.vm_cost.structural_byte_cost = 1;
        for (auto &cost : op.vm_cost.opcode)
            cost.base = 1;
        profile.monetary = {.boot_shift = 1, .tx_knee_shift = 1,
                            .ema_shift = 1000, .ema_min = 1,
                            .linear_shift = 1, .quad_shift = 1,
                            .tail_min = 1, .tail_max = 10000000,
                            .dust_limit = 10000000, .min_fee_per_kb = 1000,
                            .genesis_tail = money.tail_subsidy,
                            .genesis_work = {}};
        profile.costs = {1, 1, 1, 1};
        money.prev_work[0] = 2;
        profile.monetary.genesis_work = money.prev_work;
        Check(AbsoluteTail(profile.monetary, 2) == money.tail_subsidy,
              "valid monetary genesis anchors");
        Header genesis;
        genesis.version = hp.version;
        genesis.time = hp.genesis_time;
        genesis.bits = hp.genesis_bits;
        genesis.state_root = StateRoot(hp.chain_id, 0, EmptyUtxoRoot(), money);
        auto cb = Coinbase({}, 0, Burn());
        std::string error;
        Check(CompleteTransactionRoot({cb}, op.transaction, hp.chain_id,
                                      genesis.tx_root, error),
              error);
        std::vector<uint8_t> txbytes;
        Check(EncodeTransaction(cb, op.transaction, txbytes, error), error);
        genesis.size =
            HEADER_SIZE + 4 + CompactSizeWidth(txbytes.size()) + txbytes.size();
        Mine(genesis);
        Check(BlockId(hp.chain_id, genesis, hp.genesis_id), "genesis ID");
        history = {genesis};
        DiskStateOptions options;
        options.identity = hp.chain_id;
        options.profile_digest = profile.Binding().validation_digest;
        DiskStateError failure;
        Check(DiskStateStore::Open(path, options, {}, store, failure),
              failure.message);
        DiskStateTransaction tx;
        Check(store.Begin(tx, failure), failure.message);
        auto metadata = Metadata(genesis, {cb});
        Check(tx.Commit(metadata, failure), failure.message);
    }
    static Output Burn() {
        Output out;
        out.flags = 2;
        out.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
        return out;
    }
    static Transaction Coinbase(const V2Hash &previous, uint64_t height,
                                const Output &out) {
        Input input;
        input.flags = 2;
        input.prev_txid = previous;
        input.prev_index = uint32_t(height);
        input.sequence = UINT32_MAX;
        return {0, {input}, {out}};
    }
    void Mine(Header &header) {
        V2Hash target, id;
        Check(DecodeTarget(header.bits, profile.header.pow_limit, target),
              "target");
        for (header.nonce = 0;; ++header.nonce) {
            Check(BlockId(profile.header.chain_id, header, id), "block ID");
            if (MeetsTarget(id, target)) break;
        }
    }
    DiskStateMetadata Metadata(const Header &header,
                               const std::vector<Transaction> &transactions) {
        std::string error;
        std::vector<uint8_t> wire;
        Check(EncodeBlockWire(header, transactions,
                              profile.ordinary.transaction, wire, error),
              error);
        DiskStateMetadata metadata;
        Check(BlockId(profile.header.chain_id, header, metadata.tip), "tip ID");
        metadata.header.assign(wire.begin(), wire.begin() + HEADER_SIZE);
        auto encoded = EncodeMonetaryState(money);
        metadata.monetary.assign(encoded.begin(), encoded.end());
        metadata.auxiliary = EncodeDiskChainContext(history, wire);
        return metadata;
    }
    Outpoint Append(const Output &funding,
                    const std::optional<Transaction> &payment = {}) {
        Header header;
        header.version = profile.header.version;
        header.bits = profile.header.genesis_bits;
        header.time = history.front().time + 120;
        header.height = history.front().height + 1;
        header.prev_id = store.Metadata().tip;
        std::vector<Transaction> transactions{
            Coinbase(header.prev_id, header.height, funding)};
        if (payment) transactions.push_back(*payment);
        auto mtp = ParentMedianTime(profile.header, history.front(), history);
        Check(mtp.has_value(), "fixture parent MTP");
        DiskStateTransaction tx;
        DiskStateError failure;
        Check(store.Begin(tx, failure), failure.message);
        std::string error;
        Outpoint first;
        for (size_t n = 0; n < transactions.size(); ++n) {
            const auto &transaction = transactions[n];
            if (n)
                for (const auto &input : transaction.inputs)
                    Check(
                        tx.Erase({input.prev_txid, input.prev_index}, failure),
                        failure.message);
            IdentityDigests ids;
            Check(ComputeIdentities(transaction, profile.ordinary.transaction,
                                    profile.header.chain_id, ids, error),
                  error);
            if (!n) first = {ids.txid, 0};
            for (size_t i = 0; i < transaction.outputs.size(); ++i)
                if (!transaction.outputs[i].IsBurn())
                    Check(tx.Insert({{ids.txid, uint32_t(i)},
                                     transaction.outputs[i],
                                     header.height,
                                     *mtp,
                                     n == 0},
                                    failure),
                          failure.message);
        }
        header.state_root =
            StateRoot(profile.header.chain_id, header.height, tx.Root(), money);
        Check(CompleteTransactionRoot(
                  transactions, profile.ordinary.transaction,
                  profile.header.chain_id, header.tx_root, error),
              error);
        uint64_t size = HEADER_SIZE + 4;
        for (const auto &transaction : transactions) {
            std::vector<uint8_t> bytes;
            Check(EncodeTransaction(transaction, profile.ordinary.transaction,
                                    bytes, error),
                  error);
            size += CompactSizeWidth(bytes.size()) + bytes.size();
        }
        header.size = size;
        Mine(header);
        history.insert(history.begin(), header);
        if (history.size() > 11) history.resize(11);
        Check(tx.Commit(Metadata(header, transactions), failure),
              failure.message);
        return first;
    }
    void Disconnect() {
        DiskStateError error;
        Check(store.Disconnect(store.Metadata().tip, error), error.message);
        std::vector<uint8_t> body;
        std::string detail;
        Check(ReadDiskChainContext(store.Metadata(), profile.header, history,
                                   body, detail),
              detail);
    }
};
} // namespace provider_fixture
#endif
