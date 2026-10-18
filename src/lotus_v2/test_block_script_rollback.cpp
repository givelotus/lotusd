// Copyright (c) 2026 The Lotus developers
// In-memory rollback when an ordinary witness script fails.
// Not lotusd ConnectTip and not a claim that lotusd accepted a block.
#include "block.h"

#include "commitment.h"
#include "signing.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lotus::v2;

namespace {
void Check(bool ok, const std::string &message) {
    if (!ok) throw std::runtime_error(message);
}

// 0x4e is the numeric literal 1. 0x00 is ZERO. 0x65 is VERIFY.
const std::vector<uint8_t> TRUE_SCRIPT{0x4e};
const std::vector<uint8_t> PUSH_ZERO{0x00};
const std::vector<uint8_t> VERIFY_FALSE{0x00, 0x65};
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
    for (size_t i = 0; i < chain.size(); ++i)
        chain[i] = static_cast<uint8_t>(i);
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

Coin MakeFunding(uint8_t tag, uint32_t index, uint64_t value,
                 const Hash &branch) {
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

Transaction Payment(const Outpoint &spent, uint64_t value,
                    const std::vector<uint8_t> &witness = TRUE_SCRIPT) {
    Transaction tx;
    Input input;
    input.prev_txid = spent.tx_id;
    input.prev_index = spent.index;
    input.sequence = UINT32_MAX;
    input.flags = 1;
    input.path_index = 0;
    input.witnesses = {BranchWitness{witness, {}, {}}};
    tx.inputs.push_back(input);
    Output output;
    output.value = value;
    output.branches = {BranchLeaf(TRUE_SCRIPT)};
    output.paths = {{0}};
    tx.outputs.push_back(output);
    return tx;
}

// funding_alternate, when set, is a second spend path on the parent funding
// coin. Path 0 stays TRUE_SCRIPT so that coin can be spent again after the
// alternate witness fails. other_script is the single branch on the other coin.
struct World {
    DevelopmentUtxoView view;
    IncrementalUtxoSet utxo;
    MonetaryState monetary = InitialMoney();
    OrdinaryParentContext parent;
    Coin funding;
    Coin other;
    explicit World(const std::vector<uint8_t> &other_script = TRUE_SCRIPT,
                   const std::vector<uint8_t> &funding_alternate = {}) {
        funding = MakeFunding(0x71, 3, 20000, BranchLeaf(TRUE_SCRIPT));
        if (!funding_alternate.empty()) {
            funding.output.branches.push_back(BranchLeaf(funding_alternate));
            funding.output.paths.push_back({1});
        }
        other = MakeFunding(0x72, 1, 8000, BranchLeaf(other_script));
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
        parent.header.state_root = StateRoot(
            parent.chain_id, parent.header.height, utxo.Root(), monetary);
    }
};

struct ParentBytes {
    std::vector<std::vector<uint8_t>> coins;
    Hash utxo{};
    std::array<uint8_t, 56> monetary{};
    Hash state{};
};

ParentBytes Capture(const World &world) {
    ParentBytes snap;
    for (const auto &entry : world.view) {
        Check(entry.first == entry.second.outpoint, "view outpoint");
        std::vector<uint8_t> encoded;
        Check(EncodeCoin(entry.second, encoded), "encode parent coin");
        snap.coins.push_back(std::move(encoded));
    }
    snap.utxo = world.utxo.Root();
    snap.monetary = EncodeMonetaryState(world.monetary);
    snap.state = world.parent.header.state_root;
    return snap;
}

void ExpectParent(const World &world, const ParentBytes &parent,
                  const std::string &where) {
    const ParentBytes now = Capture(world);
    Check(now.coins == parent.coins, where + " view is not the parent coins");
    Check(now.utxo == parent.utxo, where + " utxo root moved");
    Check(now.monetary == parent.monetary, where + " monetary bytes moved");
    Check(StateRoot(world.parent.chain_id, world.parent.header.height,
                    world.utxo.Root(), world.monetary) == parent.state,
          where + " state root moved");
}

bool Connect(World &world, const std::vector<Transaction> &txs,
             const OrdinaryCandidateProfile &profile,
             OrdinaryBlockConnected &connected, std::string &error) {
    return ConnectOrdinaryBlock(txs, world.parent, profile, kMonetary,
                                world.view, world.utxo, world.monetary,
                                connected, error);
}

void FailingScriptRestoresParentAndTrueSpendWorks() {
    World world(TRUE_SCRIPT, PUSH_ZERO);
    const ParentBytes parent = Capture(world);
    const OrdinaryCandidateProfile profile = MakeProfile(1000000);
    Transaction failing = Payment(world.funding.outpoint, 15000, PUSH_ZERO);
    failing.inputs[0].path_index = 1;
    OrdinaryBlockConnected discarded;
    std::string error;
    Check(!Connect(world, {failing}, profile, discarded, error),
          "push-zero witness was accepted");
    Check(error == "witness VM invalid/unsupported: unclean final stack",
          "push-zero rejection: " + error);
    ExpectParent(world, parent, "push-zero");

    Transaction again = Payment(world.funding.outpoint, 15000);
    OrdinaryBlockConnected connected;
    error.clear();
    Check(Connect(world, {again}, profile, connected, error),
          "TRUE_SCRIPT spend of the parent coin after rollback: " + error);
    Check(connected.invocation_cost == 18, "true spend cost");
    Check(world.view.count(world.funding.outpoint) == 0,
          "parent coin was not spent by TRUE_SCRIPT");
    IdentityDigests ids;
    Check(ComputeIdentities(again, profile.transaction, world.parent.chain_id,
                            ids, error),
          "true spend identity");
    Check(world.view.count(Outpoint{ids.txid, 0}) == 1,
          "TRUE_SCRIPT output missing");
    Check(world.view.count(world.other.outpoint) == 1, "other coin missing");
}

void FailedSecondDropsFirstCreatedCoin() {
    World world(VERIFY_FALSE);
    const ParentBytes parent = Capture(world);
    const OrdinaryCandidateProfile profile = MakeProfile(1000000);
    const Transaction first = Payment(world.funding.outpoint, 15000);
    Transaction second = Payment(world.other.outpoint, 3000, VERIFY_FALSE);
    OrdinaryBlockConnected discarded;
    std::string error;
    Check(!Connect(world, {first, second}, profile, discarded, error),
          "block with a failing second script was accepted");
    Check(error == "witness VM invalid/unsupported: VERIFY false",
          "second-script rejection: " + error);
    ExpectParent(world, parent, "two-tx script failure");
    IdentityDigests first_id;
    Check(ComputeIdentities(first, profile.transaction, world.parent.chain_id,
                            first_id, error),
          "first identity");
    Check(world.view.count(Outpoint{first_id.txid, 0}) == 0,
          "first payment's created coin remained in the view");
    Check(world.view.count(world.funding.outpoint) == 1,
          "parent funding coin was not restored");
    Check(world.view.count(world.other.outpoint) == 1,
          "failing spend removed its parent coin");

    OrdinaryBlockConnected connected;
    error.clear();
    Check(Connect(world, {first}, profile, connected, error),
          "TRUE_SCRIPT payment after the two-tx rollback: " + error);
    Check(world.view.count(world.funding.outpoint) == 0 &&
              world.view.count(Outpoint{first_id.txid, 0}) == 1,
          "restored parent coin did not pay with TRUE_SCRIPT");
}

struct Built {
    Transaction first;
    Transaction second;
    VmCostUnits one_cost{};
    OrdinaryCandidateProfile profile;
};

Built BuildPayments(World &world) {
    Built built;
    built.first = Payment(world.funding.outpoint, 15000);
    const OrdinaryCandidateProfile wide = MakeProfile(1000000);
    OrdinaryCandidateEffects effects;
    std::string error;
    Check(CheckOrdinaryCandidate(built.first, wide, world.parent.chain_id,
                                 world.view, effects, error),
          "measure first payment: " + error);
    Check(effects.invocation_cost == 18 && effects.native_fee == 5000,
          "unexpected first payment cost or fee");
    built.one_cost = effects.invocation_cost;
    built.profile = MakeProfile(built.one_cost * 2);
    IdentityDigests first_id;
    Check(ComputeIdentities(built.first, built.profile.transaction,
                            world.parent.chain_id, first_id, error),
          "first identity");
    built.second = Payment(Outpoint{first_id.txid, 0}, 10000);
    return built;
}

void TrueScriptBlockStillConnects() {
    World world;
    const ParentBytes parent = Capture(world);
    Built built = BuildPayments(world);
    OrdinaryBlockConnected connected;
    std::string error;
    Check(Connect(world, {built.first, built.second}, built.profile, connected,
                  error),
          "true-script block: " + error);
    Check(connected.invocation_cost == built.one_cost * 2, "block cost");
    Check(world.utxo.Root() == connected.utxo_root &&
              world.utxo.Root() != parent.utxo,
          "true-script block did not move the utxo root");
    Check(EncodeMonetaryState(world.monetary) == connected.monetary_bytes &&
              connected.monetary_bytes != parent.monetary,
          "true-script block did not move monetary bytes");
    IdentityDigests second_id;
    Check(ComputeIdentities(built.second, built.profile.transaction,
                            world.parent.chain_id, second_id, error),
          "second identity");
    Check(world.view.count(world.funding.outpoint) == 0 &&
              world.view.count(world.other.outpoint) == 1 &&
              world.view.count(Outpoint{second_id.txid, 0}) == 1 &&
              world.view.size() == 2,
          "true-script block view");
}
} // namespace

int main() {
    try {
        FailingScriptRestoresParentAndTrueSpendWorks();
        FailedSecondDropsFirstCreatedCoin();
        TrueScriptBlockStillConnects();
        std::cout << "ordinary script rollback checks passed\n";
        return 0;
    } catch (const std::exception &failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
