// Copyright (c) 2026 The Lotus developers
#include "development_chain.h"
#include "block_wire.h"
#include "incremental_utxo.h"
#include "signing.h"
#include <stdexcept>
namespace lotus::v2 {
namespace {
MonetaryInteger Integer(const Hash &hash) {
    MonetaryInteger n = 0;
    for (auto i = hash.rbegin(); i != hash.rend(); ++i) { n <<= 8; n += *i; }
    return n;
}
void Require(bool condition, const char *message) {
    if (!condition) throw std::invalid_argument(message);
}
void CheckStoredTip(const DiskStateMetadata &meta, const Hash &root,
                    const HeaderChainProfile &hp) {
    std::vector<Header> history;
    std::vector<uint8_t> body;
    std::string error;
    Require(ReadDiskChainContext(meta, hp, history, body, error), "stored chain history");
    Require(!body.empty(), "stored tip body unavailable");
    const auto money = DecodeMonetaryState(meta.monetary);
    Hash target;
    Require(DecodeTarget(history.front().bits, hp.pow_limit, target) &&
            MeetsTarget(meta.tip, target), "stored tip proof of work");
    Require(Integer(money.prev_work) == (MonetaryInteger(1) << 256) / (Integer(target) + 1),
            "stored monetary target work");
    Require(StateRoot(hp.chain_id, history.front().height, root, money) ==
            history.front().state_root, "stored tip state commitment");
}
} // namespace
bool OpenDevelopmentChain(
    const std::string &directory, const std::vector<uint8_t> &genesis_wire,
    const HeaderChainProfile &hp, const OrdinaryCandidateProfile &op,
    const MonetaryProfile &mp, const BlockCostProfile &cp,
    const MonetaryState &initial, DiskStateOptions options,
    DiskStateStore &out, std::string &error) {
    try {
        Require(!out.IsOpen(), "output chainstate already open");
        Require(hp.genesis_id != Hash{}, "explicit genesis identity required");
        Require(hp.spacing_seconds > 0 && hp.half_life_seconds > 0, "development ASERT parameters");
        Require(op.coinbase_maturity && op.dust_limit && op.max_total_invocation_cost &&
                op.vm_cost.max_invocation_cost, "ordinary profile resource limits");
        Require(op.dust_limit == mp.dust_limit, "ordinary and monetary dust mismatch");
        const auto &vm = op.vm;
        Require(vm.max_script_bytes && vm.max_element_bytes &&
                vm.max_element_bytes <= VM_HARD_ELEMENT_BYTES && vm.max_stack_items &&
                vm.max_altstack_items && vm.max_vm_bytes && vm.max_ast_depth && vm.max_steps,
                "VM profile limits");
        if (!ValidateVmCostProfile(vm, op.vm_cost, error)) return false;
        // Validate the schedule without charging genesis or advancing issuance.
        (void)AuthenticatedEnvelopeCost(0, 1, cp);
        FramedBlock genesis;
        if (!DecodeBlockWire(genesis_wire, op.transaction, hp.chain_id, genesis, error)) return false;
        const auto &h = genesis.header;
        Require(genesis.transactions.size() == 1, "development genesis must contain only its coinbase");
        Require(h.height == 0 && h.prev_id == Hash{} && h.version == hp.version &&
                h.time == hp.genesis_time && h.bits == hp.genesis_bits &&
                h.size == genesis_wire.size(), "manifest genesis header");
        Hash id, target, tx_root;
        Require(BlockId(hp.chain_id, h, id) && id == hp.genesis_id &&
                DecodeTarget(h.bits, hp.pow_limit, target) && MeetsTarget(id, target),
                "manifest genesis identity or proof of work");
        Require(Integer(initial.prev_work) == (MonetaryInteger(1) << 256) / (Integer(target) + 1),
                "initial monetary genesis work");
        const auto money = InitializeMonetaryGenesis(mp, initial, 0);
        const auto &coinbase = genesis.transactions.front();
        if (!CheckCoinbaseContext(coinbase, Hash{}, 0, error) ||
            !CompleteTransactionRoot(genesis.transactions, op.transaction, hp.chain_id, tx_root, error)) return false;
        Require(tx_root == h.tx_root, "genesis transaction root");
        IdentityDigests ids;
        if (!ComputeIdentities(coinbase, op.transaction, hp.chain_id, ids, error)) return false;
        IncrementalUtxoSet tree;
        std::vector<Coin> coins;
        for (size_t i = 0; i < coinbase.outputs.size(); ++i) {
            const auto &output = coinbase.outputs[i];
            Require(!output.HasToken() && output.value == 0, "genesis native issuance");
            if (output.IsBurn()) continue;
            Coin coin{{ids.txid, uint32_t(i)}, output, 0, 0, true};
            Require(tree.Insert(coin), "genesis coin insertion");
            coins.push_back(std::move(coin));
        }
        Require(StateRoot(hp.chain_id, 0, tree.Root(), money) == h.state_root, "genesis state commitment");
        DiskStateMetadata expected;
        expected.tip = id;
        expected.header.assign(genesis_wire.begin(), genesis_wire.begin() + HEADER_SIZE);
        const auto monetary = EncodeMonetaryState(money);
        expected.monetary.assign(monetary.begin(), monetary.end());
        expected.auxiliary = EncodeDiskChainContext({h}, genesis_wire);
        options.header_index = hp;
        options.identity = hp.chain_id;
        options.profile_digest = BlockValidationProfileDigest(hp, op, mp, cp);
        DiskStateStore candidate;
        DiskStateError failure;
        if (!DiskStateStore::Open(directory, options, {}, candidate, failure)) {
            error = failure.message; return false;
        }
        if (candidate.Metadata() == DiskStateMetadata{}) {
            Require(!options.existing_only, "existing initialized development chain required");
            Require(candidate.Root() == EmptyUtxoRoot(), "uninitialized chain contains coins");
            DiskStateTransaction tx;
            if (!candidate.Begin(tx, failure)) { error = failure.message; return false; }
            for (const auto &coin : coins)
                if (!tx.Insert(coin, failure)) { error = failure.message; return false; }
            Require(tx.Root() == tree.Root(), "genesis disk root");
            if (!tx.Commit(expected, h, failure)) { error = failure.message; return false; }
        }
        CheckStoredTip(candidate.Metadata(), candidate.Root(), hp);
        Header stored;
        const auto metadata = candidate.Metadata();
        Require(ParseHeader(metadata.header.data(), metadata.header.size(), stored), "stored header");
        if (stored.height == 0)
            Require(metadata == expected && candidate.Root() == tree.Root(), "stored genesis differs from manifest");
        out = std::move(candidate);
        error.clear(); return true;
    } catch (const std::exception &e) { error = e.what(); return false; }
}
static bool DisconnectDevelopmentTipImpl(
    const Hash &expected_tip, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, const DiskRecoveryUpdate *recovery,
    DiskStateStore &store, std::string &error) {
    try {
        Require(hp.genesis_id != Hash{}, "explicit genesis identity required");
        Require(store.MatchesProfile(hp.chain_id, BlockValidationProfileDigest(hp, op, mp, cp)),
                "stored validator profile mismatch");
        const auto current = store.Metadata();
        Require(current.tip == expected_tip, "active tip changed");
        CheckStoredTip(current, store.Root(), hp);
        Header child;
        Require(ParseHeader(current.header.data(), current.header.size(), child), "stored child header");
        Require(child.height != 0 && current.tip != hp.genesis_id, "cannot disconnect genesis");
        DiskStateMetadataValidator validate = [&](const DiskStateMetadata &before,
                                                  const Hash &root, DiskStateError &failure) {
            try {
                CheckStoredTip(before, root, hp);
                Header parent;
                Require(ParseHeader(before.header.data(), before.header.size(), parent), "restored parent header");
                Require(parent.height == child.height - 1 && before.tip == child.prev_id,
                        "undo is not the active child's exact predecessor");
                return true;
            } catch (const std::exception &e) {
                failure = {DiskStateErrorCode::Corruption, e.what()}; return false;
            }
        };
        DiskStateError failure;
        const bool disconnected = recovery
            ? store.DisconnectRecovery(expected_tip, validate, *recovery, failure)
            : store.Disconnect(expected_tip, validate, failure);
        if (!disconnected) { error = failure.message; return false; }
        error.clear(); return true;
    } catch (const std::exception &e) { error = e.what(); return false; }
}
bool DisconnectDevelopmentTip(
    const Hash &expected_tip, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, DiskStateStore &store, std::string &error) {
    return DisconnectDevelopmentTipImpl(expected_tip, hp, op, mp, cp, nullptr, store, error);
}
bool DisconnectRecoveryDevelopmentTip(
    const Hash &expected_tip, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, const DiskRecoveryUpdate &recovery,
    DiskStateStore &store, std::string &error) {
    return DisconnectDevelopmentTipImpl(expected_tip, hp, op, mp, cp, &recovery, store, error);
}
} // namespace lotus::v2
