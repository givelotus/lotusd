// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_BLOCK_ASSEMBLER_TEST_FIXTURES_H
#define LOTUS_V2_BLOCK_ASSEMBLER_TEST_FIXTURES_H
#include "../block_assembler.h"
#include "../block_template.h"
#include "../dev_genesis.h"
#include "../development_runtime_test/fixtures.h"
#include <leveldb/db.h>
namespace assembler_fixture {
using namespace lotus::v2;
using runtime_fixture::Bytes;
using runtime_fixture::Check;
using runtime_fixture::H;
using runtime_fixture::Profiles;
using runtime_fixture::V;
struct Home {
    std::string path;
    ReorgProfiles p{Profiles()};
    MonetaryState initial{
        DecodeMonetaryState(Bytes(runtime_fixture::initial_money))};
    std::vector<uint8_t> genesis{Bytes(runtime_fixture::genesis_wire)};
    DiskStateStore store;
    explicit Home(bool insufficient = false) {
        char name[] = "/private/tmp/lotus-v2-assembler-XXXXXX";
        Check(mkdtemp(name) != nullptr, "assembler temporary home");
        path = name;
        if (insufficient) {
            // Existing bare toy monetary fixture: no invented funding.
            p.monetary = DevelopmentGenesis;
            // This separately mined toy genesis has target work 2.
            p.monetary.genesis_work = Hash{2};
            p.ordinary.dust_limit = p.monetary.dust_limit;
            initial = {};
            initial.bootstrap_reserve = 9;
            initial.tail_subsidy = 200;
            initial.prev_work[0] = 2;
            initial.ema_block_cost = 4;
            FramedBlock block;
            std::string error;
            Check(DecodeBlockWire(genesis, p.ordinary.transaction,
                                  p.header.chain_id, block, error),
                  error);
            block.header.state_root =
                StateRoot(p.header.chain_id, 0, EmptyUtxoRoot(), initial);
            Hash target;
            Check(DecodeTarget(block.header.bits, p.header.pow_limit, target) &&
                      SearchNonce(block.header, p.header.chain_id, target, 0,
                                  256),
                  "bounded toy genesis proof");
            Check(BlockId(p.header.chain_id, block.header, p.header.genesis_id),
                  "toy genesis identity");
            Check(EncodeBlockWire(block.header, block.transactions,
                                  p.ordinary.transaction, genesis, error),
                  error);
        }
        Open();
    }
    ~Home() {
        store = {};
        std::filesystem::remove_all(path);
    }
    DiskStateOptions Options() const {
        DiskStateOptions options;
        options.cache_bytes = 1024;
        options.write_buffer_bytes = 64 << 10;
        options.recovery = DiskRecoveryOptions{32 << 20, 4 << 20};
        options.candidates = CandidateStoreOptions{64, 64, 8};
        return options;
    }
    void Open() {
        store = {};
        std::string error;
        Check(OpenDevelopmentChain(path, genesis, p.header, p.ordinary,
                                   p.monetary, p.cost, initial, Options(),
                                   store, error),
              "assembler home open: " + error);
    }
};
using RawState = std::vector<std::pair<std::string, std::string>>;
RawState Raw(Home &home) {
    // Test-only full-key snapshot outside construction/validation. The actual
    // assembler has no UTXO enumeration API and uses bounded lookup overlays.
    home.store = {};
    std::map<std::string, std::string> rows;
    std::string error;
    Check(RawDiskStateSnapshot(home.path, rows, &error),
          "raw state snapshot open: " + error);
    RawState state(rows.begin(), rows.end());
    home.Open();
    return state;
}
std::vector<uint8_t> Script() {
    auto key = Bytes(
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    std::vector<uint8_t> script{0x20};
    script.insert(script.end(), key.begin(), key.end());
    script.insert(script.end(), {0xbc, 0x4e});
    return script;
}
Output Destination(uint64_t value = 0) {
    Output output;
    output.value = value;
    output.branches = {BranchLeaf(Script())};
    output.paths = {{0}};
    return output;
}
Transaction Spend(const Coin &coin, uint64_t value, const ReorgProfiles &p) {
    Transaction tx;
    Input input;
    input.flags = 1;
    input.prev_txid = coin.outpoint.tx_id;
    input.prev_index = coin.outpoint.index;
    input.sequence = UINT32_MAX;
    input.witnesses = {BranchWitness{Script(), {}, {std::vector<uint8_t>(64)}}};
    tx.inputs = {input};
    tx.outputs = {Destination(value)};
    Hash message;
    std::string error;
    Check(SigningMessage(tx, p.ordinary.transaction, p.header.chain_id,
                         {coin.output}, 0, 0, 0, std::nullopt, message, error),
          "signed fixture digest: " + error);
    std::array<uint8_t, 32> scalar{};
    scalar[31] = 3;
    std::array<uint8_t, 32> auxiliary{};
    Check(SignBip340Message(scalar, message, 0, auxiliary,
                            tx.inputs[0].witnesses[0].arguments[0], error),
          error);
    Check(
        VerifyBip340Signature(std::span<const uint8_t>(Script()).subspan(1, 32),
                              tx.inputs[0].witnesses[0].arguments[0], message,
                              false) == SignatureStatus::Valid,
        "real BIP340 signature fixture");
    return tx;
}
LocalBlockLimits Limits() {
    return {16, 1 << 20, 64};
}
LocalBlockRequest Request(Home &home, uint64_t max_claim = UINT64_MAX) {
    const auto meta = home.store.Metadata();
    Header parent;
    Check(ParseHeader(meta.header.data(), meta.header.size(), parent),
          "request parent header");
    LocalBlockRequest request;
    request.expected_parent = meta.tip;
    request.time = parent.time + home.p.header.spacing_seconds;
    request.max_claim = max_claim;
    request.coinbase_destination = Destination();
    return request;
}
FramedBlock Decode(const LocalBlockTemplate &block, const ReorgProfiles &p) {
    FramedBlock decoded;
    std::string error;
    Check(DecodeBlockWire(block.wire, p.ordinary.transaction, p.header.chain_id,
                          decoded, error),
          error);
    return decoded;
}
LocalBlockTemplate Build(Home &home, const LocalBlockRequest &request) {
    LocalBlockTemplate block;
    std::string error;
    Check(BuildLocalDiskBlockTemplate(request, Limits(), home.p.header,
                                      home.p.ordinary, home.p.monetary,
                                      home.p.cost, home.store, block,
                                      error) == LocalBlockBuildResult::Ready,
          "build actual local block: " + error);
    return block;
}
LocalBlockTemplate Mine(const LocalBlockTemplate &block,
                        const ReorgProfiles &p) {
    LocalBlockTemplate mined;
    std::string error;
    Check(SearchLocalBlockNonce(block, p.header.chain_id, p.header.pow_limit, 0,
                                256, mined, error) == LocalNonceResult::Found,
          "bounded local proof search: " + error);
    return mined;
}
StagedBlockTransition Connect(Home &home, const LocalBlockTemplate &mined) {
    StagedBlockTransition connected;
    std::string error;
    Check(ConnectStoredDiskBlock(mined.wire, home.p.header, home.p.ordinary,
                                 home.p.monetary, home.p.cost, home.store,
                                 connected,
                                 error) == CandidateCheckResult::Accepted,
          "normal full validator accepts assembled wire: " + error);
    return connected;
}
Coin CoinAt(const LocalBlockTemplate &block, size_t output,
            const ReorgProfiles &p, bool coinbase) {
    const auto decoded = Decode(block, p);
    const auto &tx = decoded.transactions[0];
    IdentityDigests ids;
    std::string error;
    Check(ComputeIdentities(tx, p.ordinary.transaction, p.header.chain_id, ids,
                            error),
          error);
    Coin coin;
    coin.outpoint = {ids.txid, uint32_t(output)};
    coin.output = tx.outputs.at(output);
    coin.creation_height = decoded.header.height;
    coin.coinbase = coinbase;
    return coin;
}
} // namespace assembler_fixture
#endif
