// Copyright (c) 2026 The Lotus developers
// Development-profile coinbase candidate. Not lotusd ConnectTip and not a
// frozen mainnet entitlement. Nonce stays 0. This file does not mine.
#include "block.h"

#include "dev_genesis.h"
#include "header.h"
#include "signing.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lotus::v2;

namespace {
void Check(bool ok, const std::string &message) {
    if (!ok) throw std::runtime_error(message);
}

const std::vector<uint8_t> TRUE_SCRIPT{0x4e};
constexpr uint64_t kBurnValue = 10;
constexpr uint64_t kFundingValue = 50000;
constexpr uint64_t kPaymentValue = 1000;

MonetaryInteger WorkOf(const Hash &work) {
    MonetaryInteger value = 0;
    for (size_t i = work.size(); i > 0; --i) {
        value <<= 8;
        value += work[i - 1];
    }
    return value;
}

bool SameTransition(const MonetaryTransition &a, const MonetaryTransition &b) {
    return a.bootstrap_issued == b.bootstrap_issued && a.subsidy == b.subsidy &&
           a.total_fees == b.total_fees && a.token_burn == b.token_burn &&
           a.burned_fees == b.burned_fees &&
           a.required_underclaim == b.required_underclaim &&
           a.actual_underclaim == b.actual_underclaim &&
           a.spendable_supply_delta == b.spendable_supply_delta &&
           a.state.bootstrap_reserve == b.state.bootstrap_reserve &&
           a.state.tail_subsidy == b.state.tail_subsidy &&
           a.state.prev_work == b.state.prev_work &&
           a.state.ema_block_cost == b.state.ema_block_cost;
}

Output Native(uint64_t value) {
    Output output;
    output.value = value;
    output.branches = {BranchLeaf(TRUE_SCRIPT)};
    output.paths = {{0}};
    return output;
}

Output Burn(uint64_t value) {
    Output output;
    output.flags = 2;
    output.value = value;
    output.branches = {BranchLeaf(TRUE_SCRIPT)};
    return output;
}

Transaction MakeCoinbase(uint64_t pay, uint64_t burn, const Hash &parent_id,
                         uint64_t height) {
    Transaction tx;
    Input input;
    input.prev_txid = parent_id;
    Check(height <= std::numeric_limits<uint32_t>::max(), "coinbase height width");
    input.prev_index = static_cast<uint32_t>(height);
    input.sequence = UINT32_MAX;
    input.flags = 2;
    tx.inputs.push_back(input);
    tx.outputs.push_back(Native(pay));
    tx.outputs.push_back(Burn(burn));
    return tx;
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
    tx.outputs.push_back(Native(value));
    return tx;
}

OrdinaryCandidateProfile MakeProfile(const Header &parent) {
    OrdinaryCandidateProfile profile{
        TxProfile{32, 32, 8, 512, 8, 8192, 64},
        VmProfile{512, 8, 8192, 32, 32, 65536, 16, 100000},
        VmCostProfile{}, parent.height + 1, parent.time, 2, 3, 1000000};
    profile.vm_cost.max_invocation_cost = 1000000;
    profile.vm_cost.structural_byte_cost = 1;
    for (auto &opcode : profile.vm_cost.opcode) opcode = {1, 1, 1};
    return profile;
}

struct World {
    DevelopmentGenesisFixture genesis;
    DevelopmentUtxoView view;
    IncrementalUtxoSet utxo;
    MonetaryState monetary;
    OrdinaryParentContext parent;
    std::array<uint8_t, 56> monetary_bytes{};
    Hash utxo_root{};
    Coin funding{};
    bool funded = false;
};

World MakeEmpty() {
    World world;
    Check(MakeDevelopmentGenesis({}, 0, world.genesis), "development genesis");
    world.monetary = world.genesis.state;
    world.parent.header = world.genesis.header;
    world.parent.chain_id = kDevelopmentChainId;
    world.parent.monetary = world.monetary;
    world.monetary_bytes = EncodeMonetaryState(world.monetary);
    world.utxo_root = world.utxo.Root();
    Check(world.parent.header.nonce == 0 && world.parent.header.height == 0,
          "genesis header nonce or height");
    Check(world.utxo_root == EmptyUtxoRoot(), "genesis utxo root is not empty");
    Check(world.parent.header.state_root ==
              StateRoot(kDevelopmentChainId, 0, world.utxo_root, world.monetary),
          "genesis state root");
    Check(world.monetary_bytes == EncodeMonetaryState(world.genesis.state),
          "genesis monetary bytes");
    return world;
}

World MakeFunded() {
    World world = MakeEmpty();
    world.funding.outpoint.tx_id[0] = 0x71;
    world.funding.outpoint.index = 3;
    world.funding.output = Native(kFundingValue);
    world.funding.creation_height = 0;
    world.funding.creation_parent_mtp = world.parent.header.time;
    world.funding.coinbase = false;
    Check(world.view.emplace(world.funding.outpoint, world.funding).second &&
              world.utxo.Insert(world.funding),
          "funding coin");
    world.parent.header.state_root =
        StateRoot(world.parent.chain_id, world.parent.header.height,
                  world.utxo.Root(), world.monetary);
    world.utxo_root = world.utxo.Root();
    world.funded = true;
    Check(world.utxo_root != EmptyUtxoRoot(), "funded root is empty");
    Check(EncodeMonetaryState(world.monetary) ==
              EncodeMonetaryState(world.genesis.state),
          "funding changed genesis monetary bytes");
    return world;
}

void ExpectParent(const World &world) {
    Check(world.utxo.Root() == world.utxo_root, "parent utxo root changed");
    Check(EncodeMonetaryState(world.monetary) == world.monetary_bytes,
          "parent monetary bytes changed");
    if (!world.funded) {
        Check(world.view.empty() && world.utxo_root == EmptyUtxoRoot(),
              "empty utxo root changed");
    } else {
        Check(world.view.size() == 1 &&
                  world.view.count(world.funding.outpoint) == 1 &&
                  !world.view.begin()->second.coinbase,
              "funded parent view changed");
    }
}

struct MeasuredPayment {
    Transaction tx;
    MonetaryOrdinaryTx accounted;
    uint64_t cost = 0;
};

MeasuredPayment MeasurePayment(const World &world,
                               const OrdinaryCandidateProfile &profile) {
    MeasuredPayment measured;
    measured.tx = Payment(world.funding.outpoint, kPaymentValue);
    Check(measured.tx.inputs.size() == 1 &&
              measured.tx.inputs[0].witnesses.size() == 1 &&
              measured.tx.inputs[0].witnesses[0].script == TRUE_SCRIPT &&
              TRUE_SCRIPT.size() == 1 && TRUE_SCRIPT[0] == 0x4e,
          "ordinary payment is not OP_TRUE");
    OrdinaryCandidateEffects effects;
    std::string error;
    Check(CheckOrdinaryCandidate(measured.tx, profile, world.parent.chain_id,
                                 world.view, effects, error),
          "measure payment: " + error);
    Check(effects.invocation_cost <= std::numeric_limits<uint64_t>::max(),
          "payment cost width");
    measured.cost = static_cast<uint64_t>(effects.invocation_cost);
    measured.accounted = AccountValidatedOrdinary(
        measured.tx, effects, profile.transaction, DevelopmentGenesis);
    return measured;
}

uint64_t EncodedSize(const Transaction &tx, const TxProfile &profile) {
    std::vector<uint8_t> wire;
    std::string error;
    Check(EncodeTransaction(tx, profile, wire, error), "encode coinbase: " + error);
    return static_cast<uint64_t>(wire.size());
}

std::optional<uint64_t> PayableOutput(const MonetaryState &parent,
                                      const std::vector<MonetaryOrdinaryTx> &txs,
                                      uint64_t coinbase_bytes, uint64_t cost) {
    try {
        const MonetaryTransition probe = AdvanceMonetary(
            DevelopmentGenesis, parent, WorkOf(parent.prev_work), txs, 0, 0,
            coinbase_bytes, 0, cost, cost);
        const MonetaryInteger allowed =
            probe.actual_underclaim - probe.required_underclaim;
        if (allowed <= kBurnValue ||
            allowed - kBurnValue > std::numeric_limits<uint64_t>::max())
            return std::nullopt;
        return (allowed - kBurnValue).convert_to<uint64_t>();
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    }
}

struct CoinbasePlan {
    Transaction tx;
    uint64_t bytes = 0;
    uint64_t pay = 0;
    MonetaryTransition expected;
    Outpoint coin{};
    Outpoint burn{};
};

Hash ParentBlockId(const ChainId &chain, const Header &header) {
    Hash id{};
    Check(BlockId(chain, header, id), "parent block id");
    return id;
}

CoinbasePlan PlanCoinbase(const MonetaryState &parent, const TxProfile &tx_profile,
                          const ChainId &chain, const Header &header,
                          const std::vector<MonetaryOrdinaryTx> &txs,
                          uint64_t cost, uint64_t pay) {
    CoinbasePlan plan;
    plan.tx = MakeCoinbase(pay, kBurnValue, ParentBlockId(chain, header),
                           header.height + 1);
    plan.bytes = EncodedSize(plan.tx, tx_profile);
    Check(EncodedSize(MakeCoinbase(pay + 1, kBurnValue, plan.tx.inputs[0].prev_txid,
                                   plan.tx.inputs[0].prev_index),
                      tx_profile) == plan.bytes,
          "coinbase value changed the wire size");
    plan.pay = pay;
    plan.expected = AdvanceMonetary(
        DevelopmentGenesis, parent, WorkOf(parent.prev_work), txs,
        MonetaryInteger{pay} + kBurnValue, kBurnValue, plan.bytes, 0, cost, cost);
    std::string error;
    IdentityDigests ids;
    Check(ComputeIdentities(plan.tx, tx_profile, chain, ids, error),
          "coinbase identity: " + error);
    plan.coin = Outpoint{ids.txid, 0};
    plan.burn = Outpoint{ids.txid, 1};
    return plan;
}

bool Connect(World &world, const std::vector<Transaction> &txs,
             const OrdinaryCandidateProfile &profile,
             OrdinaryBlockConnected &connected, std::string &error) {
    return ConnectOrdinaryBlock(txs, world.parent, profile, DevelopmentGenesis,
                                world.view, world.utxo, world.monetary, connected,
                                error);
}

void ExpectCoinbaseCoin(const World &world, const OrdinaryCandidateProfile &profile,
                        const CoinbasePlan &plan) {
    const auto found = world.view.find(plan.coin);
    Check(found != world.view.end(), "coinbase coin was not created");
    const Coin &coin = found->second;
    Check(coin.coinbase && coin.creation_height == profile.candidate_height &&
              coin.creation_parent_mtp == profile.parent_mtp &&
              coin.output.value == plan.pay &&
              coin.output.branches == plan.tx.outputs[0].branches &&
              coin.output.paths == plan.tx.outputs[0].paths &&
              !coin.output.IsBurn(),
          "coinbase coin fields");
    Check(world.view.find(plan.burn) == world.view.end(),
          "burn output was inserted");
}

void AcceptCoinbase(World &world, const OrdinaryCandidateProfile &profile,
                    const std::vector<Transaction> &txs, const CoinbasePlan &plan) {
    OrdinaryBlockConnected connected;
    std::string error;
    Check(Connect(world, txs, profile, connected, error),
          "payable coinbase rejected: " + error);
    ExpectCoinbaseCoin(world, profile, plan);
    Check(SameTransition(connected.monetary, plan.expected),
          "coinbase transition does not match AdvanceMonetary");
    Check(connected.monetary_bytes == EncodeMonetaryState(plan.expected.state) &&
              connected.monetary_bytes == EncodeMonetaryState(world.monetary),
          "coinbase monetary bytes");
    Check(DisconnectOrdinaryBlock(connected.undo, world.view, world.utxo,
                                  world.monetary, error),
          "disconnect coinbase: " + error);
    Check(world.view.find(plan.coin) == world.view.end(),
          "disconnect left the coinbase coin");
    ExpectParent(world);
    Check(EncodeMonetaryState(world.monetary) ==
              EncodeMonetaryState(world.genesis.state),
          "disconnect did not restore genesis monetary bytes");
}

void RejectOverclaim(World world, const OrdinaryCandidateProfile &profile,
                     const std::vector<Transaction> &txs) {
    OrdinaryBlockConnected discarded;
    std::string error;
    Check(!Connect(world, txs, profile, discarded, error),
          "overclaim coinbase was accepted");
    Check(error == "coinbase overclaim", "overclaim error: " + error);
    ExpectParent(world);
}

void RejectPosition(World world, const std::vector<Transaction> &txs) {
    const OrdinaryCandidateProfile profile = MakeProfile(world.parent.header);
    OrdinaryBlockConnected discarded;
    std::string error;
    Check(!Connect(world, txs, profile, discarded, error),
          "misplaced coinbase was accepted");
    Check(error == "coinbase position", "position error: " + error);
    ExpectParent(world);
}

void SameBlockSpendRollsBack() {
    World world = MakeEmpty();
    const OrdinaryCandidateProfile profile = MakeProfile(world.parent.header);
    Transaction coinbase = MakeCoinbase(
        5000, kBurnValue, ParentBlockId(world.parent.chain_id, world.parent.header),
        profile.candidate_height);
    std::string error;
    IdentityDigests ids;
    Check(ComputeIdentities(coinbase, profile.transaction, world.parent.chain_id,
                            ids, error),
          "same-block identity: " + error);
    const Transaction spend = Payment(Outpoint{ids.txid, 0}, 1000);
    OrdinaryBlockConnected discarded;
    Check(!Connect(world, {coinbase, spend}, profile, discarded, error),
          "same-block coinbase spend was accepted");
    Check(error == "coinbase maturity or future coin",
          "same-block spend error: " + error);
    ExpectParent(world);
}

void OrdinaryZeros() {
    World world = MakeFunded();
    const OrdinaryCandidateProfile profile = MakeProfile(world.parent.header);
    const MeasuredPayment payment = MeasurePayment(world, profile);
    const MonetaryState parent = world.monetary;
    const MonetaryTransition full_entitlement = AdvanceMonetary(
        DevelopmentGenesis, parent, WorkOf(parent.prev_work), {payment.accounted},
        0, 0, 0, 0, payment.cost, payment.cost);
    OrdinaryBlockConnected connected;
    std::string error;
    Check(Connect(world, {payment.tx}, profile, connected, error),
          "ordinary payment rejected: " + error);
    Check(connected.monetary.actual_underclaim == full_entitlement.actual_underclaim,
          "ordinary actual_underclaim is not the full entitlement");
    Check(connected.monetary.required_underclaim ==
              full_entitlement.required_underclaim,
          "ordinary block did not pass zero coinbase fields");
    Check(SameTransition(connected.monetary, full_entitlement),
          "ordinary transition");
    Check(world.view.count(world.funding.outpoint) == 0, "payment did not spend");
}

void RunPayable(bool bare) {
    World world = bare ? MakeEmpty() : MakeFunded();
    const OrdinaryCandidateProfile profile = MakeProfile(world.parent.header);
    std::vector<MonetaryOrdinaryTx> txs;
    std::vector<Transaction> block;
    uint64_t cost = 0;
    std::optional<MeasuredPayment> payment;
    if (!bare) {
        payment = MeasurePayment(world, profile);
        txs.push_back(payment->accounted);
        cost = payment->cost;
    }
    const uint64_t bytes = EncodedSize(
        MakeCoinbase(1, kBurnValue,
                     ParentBlockId(world.parent.chain_id, world.parent.header),
                     profile.candidate_height),
        profile.transaction);
    const std::optional<uint64_t> pay =
        PayableOutput(world.monetary, txs, bytes, cost);
    Check(pay.has_value(), bare ? "bare coinbase is not payable"
                                : "fee-funded coinbase is not payable");
    const CoinbasePlan plan =
        PlanCoinbase(world.monetary, profile.transaction, world.parent.chain_id,
                     world.parent.header, txs, cost, *pay);
    Check(plan.bytes == bytes, "planned coinbase bytes drifted");
    block.push_back(plan.tx);
    if (payment) block.push_back(payment->tx);
    AcceptCoinbase(world, profile, block, plan);

    World rejected = bare ? MakeEmpty() : MakeFunded();
    Transaction too_much = plan.tx;
    too_much.outputs[0].value = *pay + 1;
    std::vector<Transaction> over{too_much};
    if (payment) over.push_back(payment->tx);
    RejectOverclaim(std::move(rejected), profile, over);
}

void EmptyRejections() {
    World not_first = MakeEmpty();
    const OrdinaryCandidateProfile profile = MakeProfile(not_first.parent.header);
    Transaction ordinary = Payment(Outpoint{}, 1);
    ordinary.inputs[0].prev_txid[0] = 0x44;
    const Hash parent_id =
        ParentBlockId(not_first.parent.chain_id, not_first.parent.header);
    RejectPosition(std::move(not_first),
                   {ordinary, MakeCoinbase(1, kBurnValue, parent_id, profile.candidate_height)});
    World second = MakeEmpty();
    const Hash second_id = ParentBlockId(second.parent.chain_id, second.parent.header);
    RejectPosition(std::move(second),
                   {MakeCoinbase(1, kBurnValue, second_id, profile.candidate_height),
                    MakeCoinbase(1, kBurnValue, second_id, profile.candidate_height)});

    World funded = MakeFunded();
    const MeasuredPayment payment = MeasurePayment(funded, profile);
    const uint64_t bytes = EncodedSize(
        MakeCoinbase(1, kBurnValue,
                     ParentBlockId(funded.parent.chain_id, funded.parent.header),
                     profile.candidate_height),
        profile.transaction);
    const std::optional<uint64_t> pay = PayableOutput(
        funded.monetary, {payment.accounted}, bytes, payment.cost);
    Check(pay.has_value(), "position fixture is not payable");
    const CoinbasePlan plan = PlanCoinbase(
        funded.monetary, profile.transaction, funded.parent.chain_id,
        funded.parent.header, {payment.accounted}, payment.cost, *pay);
    RejectPosition(std::move(funded), {payment.tx, plan.tx});
}
} // namespace

int main() {
    try {
        World probe = MakeEmpty();
        const OrdinaryCandidateProfile profile = MakeProfile(probe.parent.header);
        const uint64_t bytes = EncodedSize(
            MakeCoinbase(1, kBurnValue,
                         ParentBlockId(probe.parent.chain_id, probe.parent.header),
                         profile.candidate_height),
            profile.transaction);
        const bool bare =
            PayableOutput(probe.monetary, {}, bytes, 0).has_value();
        RunPayable(bare);
        if (!bare) {
            World empty = MakeEmpty();
            Transaction coinbase = MakeCoinbase(
                1, kBurnValue, ParentBlockId(empty.parent.chain_id, empty.parent.header),
                profile.candidate_height);
            OrdinaryBlockConnected discarded;
            std::string error;
            Check(!Connect(empty, {coinbase}, profile, discarded, error),
                  "unpayable bare coinbase was accepted");
            ExpectParent(empty);
        }
        EmptyRejections();
        SameBlockSpendRollsBack();
        OrdinaryZeros();
        World unbound = MakeEmpty();
        Transaction wrong_parent = MakeCoinbase(
            1, kBurnValue, Hash{}, profile.candidate_height);
        OrdinaryBlockConnected discarded;
        std::string error;
        Check(!Connect(unbound, {wrong_parent}, profile, discarded, error),
              "zero parent id was accepted");
        Check(error == "coinbase parent/height", "parent id error: " + error);
        ExpectParent(unbound);
        Transaction wrong_height = MakeCoinbase(
            1, kBurnValue, ParentBlockId(unbound.parent.chain_id, unbound.parent.header),
            unbound.parent.header.height);
        Check(!Connect(unbound, {wrong_height}, profile, discarded, error),
              "parent height was accepted as the candidate height");
        Check(error == "coinbase parent/height", "height error: " + error);
        ExpectParent(unbound);
        std::cout << "development coinbase candidate checks passed\n";
        return 0;
    } catch (const std::exception &failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
