// Copyright (c) 2026 The Lotus developers
#include "chronik_sync.h"
#include "development_runtime_test/fixtures.h"
#include <iostream>
using namespace lotus::v2;
using namespace runtime_fixture;
DevelopmentRuntimeConfig Config(Home &home) {
    DevelopmentRuntimeConfig config;
    config.directory = home.path;
    config.genesis_wire = Bytes(genesis_wire);
    config.profiles = home.p;
    config.initial_money = DecodeMonetaryState(Bytes(initial_money));
    config.storage.cache_bytes = 1024;
    config.storage.write_buffer_bytes = 64 << 10;
    config.storage.recovery = DiskRecoveryOptions{32 << 20, 4 << 20};
    config.storage.candidates = CandidateStoreOptions{64, 64, 8};
    config.storage.env = home.env;
    config.bodies = {3, 1 << 20, 3 << 20, 3, 3 << 20, 64};
    config.initial_body_epoch = 1;
    config.initial_context_generation = 1;
    return config;
}

struct Sink : ChronikSink {
    std::vector<ChronikBlock> chain;
    size_t disconnects{};
    bool fail{};
    std::optional<ChronikAnchor> Checkpoint() override {
        if (fail) throw std::runtime_error("sink failure");
        return chain.empty() ? std::nullopt
                             : std::optional(chain.back().anchor);
    }
    void Initialize(const ChronikBlock &b) override {
        Check(chain.empty() && b.anchor.height == 0, "genesis");
        chain.push_back(b);
    }
    void Connect(const ChronikBlock &b) override {
        Check(!chain.empty() && b.parent == chain.back().anchor,
              "parent exact");
        chain.push_back(b);
    }
    void Disconnect(const ChronikAnchor &a) override {
        Check(chain.back().anchor == a && a.height > 0, "disconnect exact");
        chain.pop_back();
        ++disconnects;
    }
};
size_t Run(Home &home, Sink &sink) {
    home.store = {};
    std::unique_ptr<DevelopmentRuntime> runtime;
    std::string error;
    Check(DevelopmentRuntime::Open(Config(home), runtime, error), error);
    ChronikSync sync(*runtime, sink, home.p.header.chain_id,
                     home.p.ordinary.transaction, 1 << 20);
    size_t count{};
    for (;;) {
        const auto result = sync.Step(error);
        Check(result == ChronikSyncResult::Progress ||
                  result == ChronikSyncResult::Ready,
              error);
        Check(++count < 100, "bounded progress");
        if (result == ChronikSyncResult::Ready) break;
    }
    const auto original = runtime->Snapshot();
    sink.fail = true;
    Check(sync.Step(error) == ChronikSyncResult::Error,
          "index error unavailable");
    Check(runtime->Snapshot().chain->stable_tip == original.chain->stable_tip,
          "consensus untouched");
    sink.fail = false;
    return count;
}
int main() {
    try {
        Sink sink;
        Home source;
        for (size_t n : {0, 1, 2, 3}) {
            source.Connect(n);
            source.Open();
        }
        Check(Run(source, sink) == 6,
              "linear initial catchup: 5 indexed blocks plus readiness");
        Check(sink.chain.size() == 5, "full genesis catchup");
        bool burn{};
        for (const auto &tx : sink.chain.front().transactions)
            for (const auto &wire : tx.outputs) {
                Output output;
                std::string error;
                Check(DecodeOutput(wire, output, error), error);
                burn |= output.IsBurn();
            }
        Check(burn, "genesis burn indexed");
        Check(Run(source, sink) == 1,
              "restart checkpoint requires one readiness step");
        Home target;
        for (size_t n : {0, 1, 4, 5, 6}) {
            target.Connect(n);
            target.Open();
        }
        Check(Run(target, sink) == 6,
              "linear reorg: 2 disconnects plus 3 connects plus readiness");
        Check(sink.disconnects == 2 && sink.chain.size() == 6 &&
                  sink.chain.back().anchor.block_id == H(V(6).id),
              "actual ancestry reorg");
        const auto &spend = sink.chain[3].transactions.back();
        Check(!spend.inputs.empty() && spend.inputs.front().input_index == 0,
              "actual spend ordinal");
        Home genesis_only;
        Check(Run(genesis_only, sink) == 6,
              "deep reorg: 5 disconnects plus readiness");
        Check(sink.chain.size() == 1 && sink.disconnects == 7,
              "deep reorg retains genesis");
        Check(Run(target, sink) == 6, "linear catchup after deep reorg");
        // A codec-authenticated mixed mint/spend frame preserves input slot 1.
        FramedBlock framed;
        std::string error;
        const auto profile = target.p.ordinary.transaction;
        Check(DecodeBlockWire(Bytes(V(4).wire), profile,
                              target.p.header.chain_id, framed, error),
              error);
        auto &tx = framed.transactions.back();
        auto mint = tx.inputs.front();
        mint.flags = 3;
        mint.prev_txid[0] ^= 1;
        mint.prev_index = 0;
        mint.sequence = UINT32_MAX;
        tx.inputs.insert(tx.inputs.begin(), mint);
        Check(CompleteTransactionRoot(framed.transactions, profile,
                                      target.p.header.chain_id,
                                      framed.header.tx_root, error),
              error);
        std::vector<uint8_t> wire;
        framed.header.size = HEADER_SIZE + 4;
        for (const auto &transaction : framed.transactions) {
            std::vector<uint8_t> frame;
            Check(EncodeTransaction(transaction, profile, frame, error), error);
            framed.header.size += CompactSizeWidth(frame.size()) + frame.size();
        }
        Check(EncodeBlockWire(framed.header, framed.transactions, profile, wire,
                              error),
              error);
        ChronikAnchor anchor;
        anchor.height = framed.header.height;
        Check(BlockId(target.p.header.chain_id, framed.header, anchor.block_id),
              "mixed block id");
        ChronikBlock converted;
        Check(MakeChronikBlock(wire, target.p.header.chain_id, profile, anchor,
                               converted, error),
              error);
        Check(converted.transactions.back().inputs.size() == 1 &&
                  converted.transactions.back().inputs.front().input_index == 1,
              "nonzero native input ordinal");
        wire.back() ^= 1;
        Check(!MakeChronikBlock(wire, target.p.header.chain_id, profile, anchor,
                                converted, error),
              "changed body rejected");
        std::cout << "chronik sync checks passed\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
