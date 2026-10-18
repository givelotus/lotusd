// Copyright (c) 2026 The Lotus developers
// Standalone ordinary-block model. This does not connect a block in lotusd.
#include "block.h"

#include "commitment.h"
#include "signing.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace lotus::v2;

namespace {
void Check(bool ok, const std::string &message) {
    if (!ok) throw std::runtime_error(message);
}

std::string Hex(const uint8_t *data, size_t size) {
    static const char *digits = "0123456789abcdef";
    std::string out(size * 2, '0');
    for (size_t i = 0; i < size; ++i) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0xf];
    }
    return out;
}
std::string HexHash(const Hash &hash) { return Hex(hash.data(), hash.size()); }

const std::vector<uint8_t> TRUE_SCRIPT{0x4e};
const MonetaryProfile kMonetary{2, 3, 2, 4, 3, 5, 2, 2000, 3, 1000, 200, Hash{9}};

OrdinaryCandidateProfile MakeProfile(VmCostUnits block_cap) {
    OrdinaryCandidateProfile profile{
        TxProfile{32, 32, 8, 512, 8, 8192, 64},
        VmProfile{512, 8, 8192, 32, 32, 65536, 16, 100000},
        VmCostProfile{}, 100, 50000, 2, 3, block_cap};
    profile.vm_cost.max_invocation_cost = 1000000;
    profile.vm_cost.structural_byte_cost = 1;
    for (auto &opcode : profile.vm_cost.opcode) opcode = {1, 1, 1};
    return profile;
}

Hash Chain() {
    Hash chain{};
    for (size_t i = 0; i < chain.size(); ++i) chain[i] = static_cast<uint8_t>(i);
    return chain;
}

MonetaryState InitialMoney() {
    MonetaryState money;
    money.bootstrap_reserve = 9;
    money.tail_subsidy = 200;
    money.prev_work[0] = 9;
    money.ema_block_cost = 4;
    return money;
}

Coin MakeFunding(uint8_t tag, uint32_t index, uint64_t value, const Hash &branch) {
    Coin coin;
    coin.outpoint.tx_id[0] = tag;
    coin.outpoint.index = index;
    coin.output.flags = 0;
    coin.output.value = value;
    coin.output.branches = {branch};
    coin.output.paths = {{0}};
    coin.creation_height = 90;
    coin.creation_parent_mtp = 49000;
    coin.coinbase = false;
    return coin;
}

Transaction Payment(const Outpoint &spent, uint64_t value) {
    Transaction tx;
    Input input;
    input.prev_txid = spent.tx_id;
    input.prev_index = spent.index;
    input.sequence = UINT32_MAX;
    input.flags = 1;
    input.path_index = 0;
    input.witnesses = {BranchWitness{TRUE_SCRIPT, {}, {}}};
    tx.inputs.push_back(input);
    Output output;
    output.value = value;
    output.branches = {BranchLeaf(TRUE_SCRIPT)};
    output.paths = {{0}};
    tx.outputs.push_back(output);
    return tx;
}

struct World {
    DevelopmentUtxoView view;
    IncrementalUtxoSet utxo;
    MonetaryState monetary = InitialMoney();
    OrdinaryParentContext parent;
    Hash branch = BranchLeaf(TRUE_SCRIPT);
    Coin funding;
    Coin other;
    World() : funding(MakeFunding(0x71, 3, 20000, branch)),
              other(MakeFunding(0x72, 1, 8000, branch)) {
        Check(view.emplace(funding.outpoint, funding).second &&
                  view.emplace(other.outpoint, other).second &&
                  utxo.Insert(funding) && utxo.Insert(other),
              "parent coins");
        parent.chain_id = Chain();
        parent.monetary = monetary;
        parent.header.height = 99;
        parent.header.time = 50000;
        parent.header.version = 1;
        parent.header.size = HEADER_SIZE;
        parent.header.state_root =
            StateRoot(parent.chain_id, parent.header.height, utxo.Root(), monetary);
    }
};

struct Built {
    Transaction first;
    Transaction second;
    Transaction third;
    VmCostUnits one_cost{};
    OrdinaryCandidateProfile profile;
};

Built BuildPayments(World &world) {
    Built built;
    built.first = Payment(world.funding.outpoint, 15000);
    auto wide = MakeProfile(1000000);
    OrdinaryCandidateEffects effects;
    std::string error;
    Check(CheckOrdinaryCandidate(built.first, wide, world.parent.chain_id,
                                 world.view, effects, error),
          "measure first payment: " + error);
    // OP_1 charges a 16-byte numeric result plus one structural byte.
    Check(effects.invocation_cost == 18 && effects.native_fee == 5000,
          "unexpected first payment cost or fee");
    built.one_cost = effects.invocation_cost;
    built.profile = MakeProfile(built.one_cost * 2);
    IdentityDigests first_id;
    Check(ComputeIdentities(built.first, built.profile.transaction,
                            world.parent.chain_id, first_id, error),
          "first identity");
    built.second = Payment(Outpoint{first_id.txid, 0}, 10000);
    Check(CheckOrdinaryCandidate(built.second, wide, world.parent.chain_id,
                                 world.view, effects, error) == false,
          "second must be unspendable until the first is connected");
    IdentityDigests second_id;
    // The second identity does not depend on the parent view.
    Check(ComputeIdentities(built.second, built.profile.transaction,
                            world.parent.chain_id, second_id, error),
          "second identity");
    built.third = Payment(Outpoint{second_id.txid, 0}, 5000);
    return built;
}

struct Report {
    OrdinaryBlockConnected connected;
    Hash parent_utxo{};
    Hash parent_state{};
    std::array<uint8_t, 56> parent_monetary{};
    Hash undo_utxo{};
    Hash undo_state{};
    std::array<uint8_t, 56> undo_monetary{};
    Hash snapshot_utxo{};
    Hash snapshot_state{};
    Hash over_cap_utxo{};
    std::array<uint8_t, 56> over_cap_monetary{};
    std::string over_cap;
    std::string coinbase;
    std::string mint;
    std::string bad_second;
    Hash bad_second_utxo{};
    Hash txid1{};
    Hash txid2{};
    std::vector<uint8_t> tx1_core;
    std::vector<uint8_t> tx1_output;
};

Report Run() {
    Report report;
    World world;
    report.parent_utxo = world.utxo.Root();
    report.parent_state = world.parent.header.state_root;
    report.parent_monetary = EncodeMonetaryState(world.monetary);
    Built built = BuildPayments(world);
    std::string error;
    Check(ConnectOrdinaryBlock({built.first, built.second}, world.parent,
                               built.profile, kMonetary, world.view, world.utxo,
                               world.monetary, report.connected, error),
          "connect two dependent payments: " + error);
    Check(report.connected.invocation_cost == built.one_cost * 2, "block cost");
    Check(report.connected.monetary.total_fees == 10000 &&
              report.connected.monetary.token_burn == 0 &&
              report.connected.monetary.burned_fees == 5000 &&
              report.connected.monetary.required_underclaim == 138 &&
              report.connected.monetary.actual_underclaim == 5202 &&
              report.connected.monetary.spendable_supply_delta == -10000 &&
              report.connected.monetary.subsidy == 202 &&
              report.connected.monetary.bootstrap_issued == 2 &&
              report.connected.monetary.state.bootstrap_reserve == 7 &&
              report.connected.monetary.state.tail_subsidy == 200 &&
              report.connected.monetary.state.ema_block_cost == 12 &&
              report.connected.monetary.state.prev_work[0] == 9,
          "monetary delta");
    Check(report.connected.utxo_root == world.utxo.Root() &&
              report.connected.state_root ==
                  StateRoot(world.parent.chain_id, 100, world.utxo.Root(),
                            world.monetary) &&
              report.connected.state_root != report.parent_state &&
              world.view.count(world.funding.outpoint) == 0 &&
              world.view.count(world.other.outpoint) == 1 &&
              world.view.size() == 2,
          "connected view");
    const Outpoint second_out{[&] {
        IdentityDigests ids;
        Check(ComputeIdentities(built.second, built.profile.transaction,
                                world.parent.chain_id, ids, error),
              "connected second id");
        report.txid2 = ids.txid;
        return Outpoint{ids.txid, 0};
    }()};
    Check(world.view.count(second_out) == 1, "second payment output is live");
    IdentityDigests first_id;
    Check(ComputeIdentities(built.first, built.profile.transaction,
                            world.parent.chain_id, first_id, error),
          "report first id");
    report.txid1 = first_id.txid;
    Check(EncodeInputCore(built.first.inputs[0], built.profile.transaction,
                          report.tx1_core, error) &&
              EncodeOutput(built.first.outputs[0], report.tx1_output, error),
          "report wires");

    std::vector<uint8_t> image;
    Check(WriteInMemorySnapshot(world.view, world.monetary, image, error),
          "write snapshot");
    Check(DisconnectOrdinaryBlock(report.connected.undo, world.view, world.utxo,
                                  world.monetary, error),
          "disconnect: " + error);
    report.undo_utxo = world.utxo.Root();
    report.undo_monetary = EncodeMonetaryState(world.monetary);
    report.undo_state = StateRoot(world.parent.chain_id, 99, report.undo_utxo,
                                  world.monetary);
    Check(report.undo_utxo == report.parent_utxo &&
              report.undo_monetary == report.parent_monetary &&
              report.undo_state == report.parent_state,
          "disconnect did not restore parent roots byte for byte");

    DevelopmentUtxoView reloaded_view;
    IncrementalUtxoSet reloaded_utxo;
    MonetaryState reloaded_money;
    Check(LoadInMemorySnapshot(image, reloaded_view, reloaded_utxo,
                               reloaded_money, error),
          "reload snapshot: " + error);
    report.snapshot_utxo = reloaded_utxo.Root();
    report.snapshot_state =
        StateRoot(world.parent.chain_id, 100, report.snapshot_utxo, reloaded_money);
    Check(report.snapshot_utxo == report.connected.utxo_root &&
              report.snapshot_state == report.connected.state_root &&
              EncodeMonetaryState(reloaded_money) ==
                  report.connected.monetary_bytes,
          "reloaded snapshot root mismatch");
    Check(DisconnectOrdinaryBlock(report.connected.undo, reloaded_view,
                                  reloaded_utxo, reloaded_money, error) &&
              reloaded_utxo.Root() == report.parent_utxo,
          "undo after reload");

    World over;
    Built over_built = BuildPayments(over);
    OrdinaryBlockConnected discarded;
    std::string over_error;
    Check(!ConnectOrdinaryBlock(
              {over_built.first, over_built.second, over_built.third},
              over.parent, over_built.profile, kMonetary, over.view, over.utxo,
              over.monetary, discarded, over_error),
          "over-cap block was accepted");
    report.over_cap = over_error;
    report.over_cap_utxo = over.utxo.Root();
    report.over_cap_monetary = EncodeMonetaryState(over.monetary);
    Check(report.over_cap == "block invocation cost over cap" &&
              report.over_cap_utxo == report.parent_utxo &&
              report.over_cap_monetary == report.parent_monetary &&
              over.view.count(over.funding.outpoint) == 1 &&
              StateRoot(over.parent.chain_id, over.parent.header.height,
                        over.utxo.Root(), over.monetary) == report.parent_state,
          "over-cap block left partial state");

    World coinbase_world;
    Built coinbase_profile = BuildPayments(coinbase_world);
    Transaction coinbase;
    Input coinbase_input;
    coinbase_input.sequence = UINT32_MAX;
    coinbase_input.flags = 2;
    coinbase.inputs.push_back(coinbase_input);
    coinbase.outputs.push_back(coinbase_profile.first.outputs[0]);
    std::string coinbase_error;
    OrdinaryBlockConnected unused;
    Check(!ConnectOrdinaryBlock({coinbase}, coinbase_world.parent,
                                coinbase_profile.profile, kMonetary,
                                coinbase_world.view, coinbase_world.utxo,
                                coinbase_world.monetary, unused, coinbase_error),
          "coinbase accepted");
    report.coinbase = coinbase_error;
    Check(coinbase_world.utxo.Root() == report.parent_utxo &&
              EncodeMonetaryState(coinbase_world.monetary) ==
                  report.parent_monetary,
          "coinbase rejection mutated state");

    World mint_world;
    Built mint_built = BuildPayments(mint_world);
    Transaction mint = mint_built.first;
    Input mint_input;
    mint_input.prev_txid[0] = 0x11;
    mint_input.sequence = UINT32_MAX;
    mint_input.flags = 3;
    mint_input.witnesses = {BranchWitness{TRUE_SCRIPT, {}, {}}};
    mint.inputs.push_back(mint_input);
    std::string mint_error;
    Check(!ConnectOrdinaryBlock({mint}, mint_world.parent, mint_built.profile,
                                kMonetary, mint_world.view, mint_world.utxo,
                                mint_world.monetary, unused, mint_error),
          "mint accepted");
    report.mint = mint_error;
    Check(mint_world.utxo.Root() == report.parent_utxo &&
              mint_world.view.count(mint_world.funding.outpoint) == 1,
          "mint rejection mutated state");

    World bad_world;
    Built bad_built = BuildPayments(bad_world);
    Transaction bad = Payment(Outpoint{Hash{}, 9}, 1000);
    bad.inputs[0].prev_txid[0] = 0x99;
    std::string bad_error;
    Check(!ConnectOrdinaryBlock({bad_built.first, bad}, bad_world.parent,
                                bad_built.profile, kMonetary, bad_world.view,
                                bad_world.utxo, bad_world.monetary, unused,
                                bad_error),
          "bad second accepted");
    report.bad_second = bad_error;
    report.bad_second_utxo = bad_world.utxo.Root();
    Check(bad_world.utxo.Root() == report.parent_utxo &&
              bad_world.view.count(bad_world.funding.outpoint) == 1,
          "invalid second left the first payment applied");
    return report;
}

void PrintReport(const Report &report) {
    const auto &m = report.connected.monetary;
    std::cout << "invocation_cost " << static_cast<unsigned long long>(
                     report.connected.invocation_cost)
              << "\n"
              << "total_fees " << m.total_fees << "\n"
              << "token_burn " << m.token_burn << "\n"
              << "burned_fees " << m.burned_fees << "\n"
              << "required_underclaim " << m.required_underclaim << "\n"
              << "actual_underclaim " << m.actual_underclaim << "\n"
              << "spendable_supply_delta " << m.spendable_supply_delta << "\n"
              << "subsidy " << m.subsidy << "\n"
              << "bootstrap_issued " << m.bootstrap_issued << "\n"
              << "reserve " << m.state.bootstrap_reserve << "\n"
              << "tail " << m.state.tail_subsidy << "\n"
              << "ema " << m.state.ema_block_cost << "\n"
              << "work " << static_cast<unsigned>(m.state.prev_work[0]) << "\n"
              << "parent_utxo " << HexHash(report.parent_utxo) << "\n"
              << "parent_state " << HexHash(report.parent_state) << "\n"
              << "parent_monetary "
              << Hex(report.parent_monetary.data(), report.parent_monetary.size())
              << "\n"
              << "connected_utxo " << HexHash(report.connected.utxo_root) << "\n"
              << "connected_state " << HexHash(report.connected.state_root) << "\n"
              << "connected_monetary "
              << Hex(report.connected.monetary_bytes.data(),
                     report.connected.monetary_bytes.size())
              << "\n"
              << "undo_utxo " << HexHash(report.undo_utxo) << "\n"
              << "undo_state " << HexHash(report.undo_state) << "\n"
              << "undo_monetary "
              << Hex(report.undo_monetary.data(), report.undo_monetary.size())
              << "\n"
              << "snapshot_utxo " << HexHash(report.snapshot_utxo) << "\n"
              << "snapshot_state " << HexHash(report.snapshot_state) << "\n"
              << "over_cap " << report.over_cap << "\n"
              << "over_cap_utxo " << HexHash(report.over_cap_utxo) << "\n"
              << "over_cap_monetary "
              << Hex(report.over_cap_monetary.data(),
                     report.over_cap_monetary.size())
              << "\n"
              << "coinbase " << report.coinbase << "\n"
              << "mint " << report.mint << "\n"
              << "bad_second " << report.bad_second << "\n"
              << "bad_second_utxo " << HexHash(report.bad_second_utxo) << "\n"
              << "txid1 " << HexHash(report.txid1) << "\n"
              << "txid2 " << HexHash(report.txid2) << "\n"
              << "tx1_core " << Hex(report.tx1_core.data(), report.tx1_core.size())
              << "\n"
              << "tx1_output "
              << Hex(report.tx1_output.data(), report.tx1_output.size()) << "\n";
}
void CheckBurnErasureAndEmptyTxRoot() {
    Hash empty_tx_root{};
    Check(TransactionRoot({}, empty_tx_root) &&
              HexHash(empty_tx_root) ==
                  "24518f458e1e543b742619b81b0f24839a1753a447ff5322ca80fcfa705b0856",
          "empty transaction root mismatch");
    DevelopmentUtxoView view;
    IncrementalUtxoSet utxo;
    MonetaryState monetary = InitialMoney();
    const Hash branch = BranchLeaf(TRUE_SCRIPT);
    const Coin funding = MakeFunding(0x71, 3, 20000, branch);
    Check(view.emplace(funding.outpoint, funding).second && utxo.Insert(funding),
          "burn world funding");
    const Hash parent_utxo = utxo.Root();
    const auto parent_monetary = EncodeMonetaryState(monetary);
    OrdinaryParentContext parent;
    parent.chain_id = Chain();
    parent.monetary = monetary;
    parent.header.height = 99;
    parent.header.time = 50000;
    parent.header.state_root = StateRoot(parent.chain_id, 99, parent_utxo, monetary);
    const Hash parent_state = parent.header.state_root;
    Transaction burn_tx = Payment(funding.outpoint, 15000);
    burn_tx.outputs[0].flags = 2;
    burn_tx.outputs[0].paths.clear();
    const auto profile = MakeProfile(100000);
    OrdinaryBlockConnected connected;
    std::string error;
    Check(ConnectOrdinaryBlock({burn_tx}, parent, profile, kMonetary, view, utxo,
                               monetary, connected, error),
          "burn connect: " + error);
    Check(view.empty() && utxo.Size() == 0 && utxo.Root() == EmptyUtxoRoot() &&
              connected.utxo_root == EmptyUtxoRoot(),
          "burn erasure leaves empty utxo state");
    Check(DisconnectOrdinaryBlock(connected.undo, view, utxo, monetary, error),
          "burn disconnect: " + error);
    Check(view.size() == 1 && view.count(funding.outpoint) == 1 &&
              utxo.Root() == parent_utxo &&
              EncodeMonetaryState(monetary) == parent_monetary &&
              StateRoot(parent.chain_id, 99, utxo.Root(), monetary) == parent_state,
          "burn disconnect restores parent state");
}
} // namespace

int main(int argc, char **argv) {
    try {
        const bool report = argc == 2 && std::string(argv[1]) == "--report";
        const Report result = Run();
        CheckBurnErasureAndEmptyTxRoot();
        if (report) PrintReport(result);
        else std::cout << "ordinary block connect/disconnect checks passed\n";
        return 0;
    } catch (const std::exception &failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
