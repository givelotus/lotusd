// Copyright (c) 2026 The Lotus developers
// Synthetic authenticated parent, actual BIP340 CHECKSIG spend, no genesis
// funding or node/miner claim. Helpers follow existing complete/checksig tests.
#include "block_transition.h"
#include "asert_candidate.h"
#include "dev_genesis.h"
#include "signing.h"
#include "transaction_pool.h"
#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <type_traits>
using namespace lotus::v2;
namespace {
void Check(bool ok, const std::string &why) { if (!ok) throw std::runtime_error(why); }
std::vector<uint8_t> Hex(const char *hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; hex[i]; i += 2) bytes.push_back(uint8_t(std::stoul(std::string(hex + i, 2), nullptr, 16)));
    return bytes;
}
const TxProfile TX{32, 32, 8, 512, 8, 8192, 64};
const BlockCostProfile COST{1, 1, 1, 1};
const std::vector<uint8_t> TRUE{0x4e};
const auto PUBKEY = Hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
Output Native(uint64_t value, bool burn = false) {
    Output o; o.value = value; o.flags = burn ? 2 : 0; o.branches = {BranchLeaf(TRUE)};
    if (!burn) o.paths = {{0}};
    return o;
}
std::vector<uint8_t> Checksig() {
    std::vector<uint8_t> script{0x20}; script.insert(script.end(), PUBKEY.begin(), PUBKEY.end());
    script.push_back(0xbb); return script;
}
MonetaryInteger Integer(const Hash &bytes) {
    MonetaryInteger result{}; for (size_t i = bytes.size(); i-- > 0;) { result <<= 8; result += bytes[i]; }
    return result;
}
Hash Id(const ChainId &chain, const Header &header) {
    Hash id; Check(BlockId(chain, header, id), "fixture ID"); return id;
}
void Mine(const ChainId &chain, const Hash &limit, Header &header, bool valid = true) {
    Hash target; Check(DecodeTarget(header.bits, limit, target), "fixture target");
    for (unsigned i = 0; i < 100000; ++i, ++header.nonce)
        if (MeetsTarget(Id(chain, header), target) == valid) return;
    throw std::runtime_error("bounded fixture nonce search failed");
}
std::vector<std::vector<uint8_t>> CoinBytes(const DevelopmentUtxoView &coins) {
    std::vector<std::vector<uint8_t>> result;
    for (const auto &[key, coin] : coins) {
        Check(key == coin.outpoint, "coin key"); std::vector<uint8_t> bytes;
        Check(EncodeCoin(coin, bytes), "coin encoding"); result.push_back(std::move(bytes));
    }
    return result;
}
class Overlay final : public BlockStateTransaction {
public:
    DevelopmentUtxoView coins;
    IncrementalUtxoSet tree;
    size_t reads{}, mutations{}, aborts{};
    mutable size_t roots{};
    size_t fail_read{}, fail_mutation{}, throw_mutation{}, throw_root{};
    bool wrong_coin{};
    explicit Overlay(const DevelopmentUtxoView &initial) : coins(initial) {
        for (const auto &[key, coin] : initial) { (void)key; Check(tree.Insert(coin), "overlay init"); }
    }
    CoinReadResult Read(const Outpoint &key, Coin &out, std::string &error) override {
        if (++reads == fail_read) { error = "injected provider read error"; return CoinReadResult::Error; }
        const auto it = coins.find(key); if (it == coins.end()) return CoinReadResult::Missing;
        out = it->second; if (wrong_coin) ++out.outpoint.index;
        return CoinReadResult::Found;
    }
    bool Mutate(std::string &error) {
        if (++mutations == throw_mutation) throw std::invalid_argument("injected provider mutation exception");
        if (mutations == fail_mutation) { error = "injected provider mutation failure"; return false; }
        return true;
    }
    bool Insert(const Coin &coin, std::string &error) override {
        return Mutate(error) && coins.emplace(coin.outpoint, coin).second && tree.Insert(coin);
    }
    bool Erase(const Outpoint &key, std::string &error) override {
        return Mutate(error) && coins.erase(key) == 1 && tree.Erase(key);
    }
    Hash Root() const override {
        if (++roots == throw_root) throw std::invalid_argument("injected provider root exception");
        return tree.Root();
    }
    void Abort() noexcept override { ++aborts; coins.clear(); tree = IncrementalUtxoSet{}; }
};
struct Fixture {
    HeaderChainProfile hp;
    OrdinaryCandidateProfile op;
    OrdinaryParentContext parent;
    std::vector<Header> history;
    Coin funding;
    DevelopmentUtxoView initial;
    Transaction cb, spend;
    Hash parent_root{};
    Fixture() {
        hp.version = 2; hp.genesis_time = 1000; hp.genesis_bits = 0x207fffff;
        hp.pow_limit.fill(255); hp.half_life_seconds = 172800; hp.spacing_seconds = 120;
        funding.outpoint.tx_id[0] = 7; funding.output = Native(1000000000000000000ULL);
        funding.output.branches = {BranchLeaf(Checksig())}; funding.creation_parent_mtp = 1000;
        initial.emplace(funding.outpoint, funding); IncrementalUtxoSet tree;
        Check(tree.Insert(funding), "funding tree"); parent_root = tree.Root();
        parent.monetary.bootstrap_reserve = 9;
        // The synthetic parent has work 2; the development genesis anchor is 9.
        parent.monetary.tail_subsidy = AbsoluteTail(DevelopmentGenesis, 2);
        parent.monetary.prev_work[0] = 2; parent.monetary.ema_block_cost = 4;
        Header genesis; genesis.version = hp.version; genesis.bits = hp.genesis_bits;
        genesis.time = hp.genesis_time; genesis.size = HEADER_SIZE; Mine({}, hp.pow_limit, genesis);
        hp.genesis_id = Id({}, genesis);
        parent.header = genesis; parent.header.prev_id = hp.genesis_id;
        parent.header.height = 1; parent.header.time = 1120;
        parent.header.state_root = StateRoot({}, 1, parent_root, parent.monetary); Mine({}, hp.pow_limit, parent.header);
        history = {parent.header, genesis};
        op = {TX, VmProfile{512, 8, 8192, 32, 32, 65536, 16, 1000000}, VmCostProfile{}, 2, 1120, 2, 3, 1000000};
        op.vm_cost.max_invocation_cost = 1000000; op.vm_cost.structural_byte_cost = 1;
        for (auto &cost : op.vm_cost.opcode) cost = {1, 1, 1};
        Input coinbase; coinbase.prev_txid = Id({}, parent.header); coinbase.prev_index = 2;
        coinbase.sequence = UINT32_MAX; coinbase.flags = 2;
        cb.inputs = {coinbase}; cb.outputs = {Native(0, true)};
        Input input; input.prev_txid = funding.outpoint.tx_id; input.prev_index = funding.outpoint.index;
        input.sequence = UINT32_MAX; input.flags = 1;
        input.witnesses = {BranchWitness{Checksig(), {}, {std::vector<uint8_t>(64)}}};
        spend.inputs = {input}; spend.outputs = {Native(1000000)};
        Hash message; std::string error;
        Check(SigningMessage(spend, TX, {}, {funding.output}, 0, 0, 0, {}, message, error), error);
        std::array<uint8_t, 32> secret{}, aux{}; secret[31] = 3;
        auto &signature = spend.inputs[0].witnesses[0].arguments[0];
        Check(SignBip340Message(secret, message, 0, aux, signature, error), error);
        Check(VerifyBip340Signature(PUBKEY, signature, message, false) == SignatureStatus::Valid,
              "actual independent BIP340 verification");
    }
    std::vector<Transaction> Txs() const { return {cb, spend}; }
};
const BlockPreviewLimits LIMITS{32, 65536};
BlockPreview Sentinel() {
    BlockPreview p; p.header.version = 99; p.header.nonce = 123; p.parent_id[0] = 71; p.parent_utxo_root[0] = 72;
    p.profile_digest[0] = 73; p.utxo_root[0] = 74; p.state_root[0] = 75;
    p.monetary.state.tail_subsidy = 123; p.monetary.total_fees = 124;
    p.account_cost = 125; p.enforce_cost = 126; p.invocation_cost = 127;
    p.coinbase_bytes = 128; p.frame_prefix_bytes = 129; return p;
}
bool Same(const BlockPreview &a, const BlockPreview &b) {
    std::array<uint8_t, HEADER_SIZE> ah{}, bh{};
    return SerializeHeader(a.header, ah) && SerializeHeader(b.header, bh) && ah == bh &&
        a.parent_id == b.parent_id && a.parent_utxo_root == b.parent_utxo_root && a.profile_digest == b.profile_digest &&
        a.utxo_root == b.utxo_root && a.state_root == b.state_root && a.account_cost == b.account_cost &&
        a.enforce_cost == b.enforce_cost && a.invocation_cost == b.invocation_cost &&
        a.coinbase_bytes == b.coinbase_bytes && a.frame_prefix_bytes == b.frame_prefix_bytes &&
        EncodeMonetaryState(a.monetary.state) == EncodeMonetaryState(b.monetary.state) &&
        a.monetary.bootstrap_issued == b.monetary.bootstrap_issued && a.monetary.subsidy == b.monetary.subsidy &&
        a.monetary.total_fees == b.monetary.total_fees && a.monetary.token_burn == b.monetary.token_burn &&
        a.monetary.burned_fees == b.monetary.burned_fees && a.monetary.required_underclaim == b.monetary.required_underclaim &&
        a.monetary.actual_underclaim == b.monetary.actual_underclaim && a.monetary.spendable_supply_delta == b.monetary.spendable_supply_delta;
}
BlockPreviewResult Preview(const Fixture &f, const std::vector<Transaction> &txs, Overlay &overlay,
    BlockPreview &out, std::string &error, const BlockPreviewLimits &limits = LIMITS,
    uint64_t time = 1121, const OrdinaryCandidateProfile *op = nullptr) {
    const auto before = CoinBytes(f.initial);
    const auto result = PreviewBlockTemplate(txs, time, limits, f.parent, f.history, f.hp,
        op ? *op : f.op, DevelopmentGenesis, COST, overlay, out, error);
    Check(overlay.aborts == 1 && overlay.coins.empty() && overlay.tree.Root() == EmptyUtxoRoot(), "every preview discards private overlay exactly once");
    Check(CoinBytes(f.initial) == before, "authenticated external parent coins unchanged");
    return result;
}
BlockPreview Ready(const Fixture &f, const std::vector<Transaction> &txs) {
    Overlay state(f.initial); BlockPreview out; std::string error;
    Check(Preview(f, txs, state, out, error, LIMITS, f.op.parent_mtp + 1) == BlockPreviewResult::Ready, "ready signed preview: " + error);
    Check(state.reads && state.mutations && out.header.nonce == 0, "actual private transaction work happened and template stays unsealed");
    return out;
}
std::vector<uint8_t> Wire(const Fixture &f, Header &header, const std::vector<Transaction> &txs, bool valid_pow = true) {
    std::string error; header.size = HEADER_SIZE + 4;
    for (const auto &tx : txs) { std::vector<uint8_t> bytes; Check(EncodeTransaction(tx, TX, bytes, error), error);
        header.size += CompactSizeWidth(bytes.size()) + bytes.size(); }
    Check(CompleteTransactionRoot(txs, TX, {}, header.tx_root, error), error);
    Mine({}, f.hp.pow_limit, header, valid_pow);
    std::vector<uint8_t> wire; Check(EncodeBlockWire(header, txs, TX, wire, error), error); return wire;
}
void SignedReadyAndStage() {
    Fixture f; const auto txs = f.Txs(); const auto preview = Ready(f, txs);
    Check(preview.parent_id == Id({}, f.parent.header) && preview.parent_utxo_root == f.parent_root &&
          preview.profile_digest == BlockValidationProfileDigest(f.hp, f.op, DevelopmentGenesis, COST), "preview binds exact parent/profile");
    Hash root; std::string error;
    Check(CompleteTransactionRoot(txs, TX, {}, root, error) && root == preview.header.tx_root, "canonical transaction root");
    std::vector<uint8_t> cb_bytes, spend_bytes;
    Check(EncodeTransaction(f.cb, TX, cb_bytes, error) && EncodeTransaction(f.spend, TX, spend_bytes, error), error);
    const auto prefixes = CompactSizeWidth(cb_bytes.size()) + CompactSizeWidth(spend_bytes.size());
    Check(preview.coinbase_bytes == cb_bytes.size() && preview.frame_prefix_bytes == prefixes,
          "independent exact coinbase/frame-prefix byte counts");
    OrdinaryCandidateEffects effects;
    Check(CheckOrdinaryCandidate(f.spend, f.op, {}, f.initial, effects, error), error);
    IncrementalUtxoSet expected;
    for (const auto &coin : effects.created) Check(expected.Insert(coin), "independent expected resulting coins");
    const auto cb_cost = AuthenticatedTransactionCostsResolved(f.cb, TX, {}, 2, 1120, 0, COST);
    const auto spend_cost = AuthenticatedTransactionCostsResolved(f.spend, TX, {f.funding}, 2, 1120, effects.invocation_cost, COST);
    const auto account = BlockEffectiveCost(AuthenticatedEnvelopeCost(preview.frame_prefix_bytes, 2, COST),
        {cb_cost.account_linear, spend_cost.account_linear}, DevelopmentGenesis);
    const auto enforce = BlockEffectiveCost(AuthenticatedEnvelopeCost(preview.frame_prefix_bytes, 2, COST),
        {cb_cost.enforce_linear, spend_cost.enforce_linear}, DevelopmentGenesis);
    const auto money = AdvanceMonetary(DevelopmentGenesis, f.parent.monetary, 2,
        {AccountValidatedOrdinary(f.spend, effects, TX, DevelopmentGenesis)}, 0, 0,
        preview.coinbase_bytes, preview.frame_prefix_bytes, account, enforce);
    Check(preview.utxo_root == expected.Root() && preview.account_cost == account && preview.enforce_cost == enforce &&
          preview.invocation_cost == effects.invocation_cost && EncodeMonetaryState(preview.monetary.state) == EncodeMonetaryState(money.state) &&
          preview.state_root == StateRoot({}, 2, expected.Root(), money.state), "preview equals lower-level coin/cost/monetary oracle");
    auto header = preview.header; const auto wire = Wire(f, header, txs);
    Check(header.size == preview.header.size && wire.size() == preview.header.size, "exact canonical full framing");
    FramedBlock decoded; Check(DecodeBlockWire(wire, TX, {}, decoded, error), error);
    std::vector<uint8_t> roundtrip; Check(EncodeBlockWire(decoded.header, decoded.transactions, TX, roundtrip, error) && roundtrip == wire, "identical full wire roundtrip");
    Overlay stage(f.initial); StagedBlockTransition accepted; DeterministicBlockFailure proof;
    Check(StageCompleteBlock(wire, f.parent, f.history, f.hp, f.op, DevelopmentGenesis, COST, stage, accepted, error, &proof) ==
          CandidateCheckResult::Accepted && !stage.aborts && !proof.Valid(), "separate sealed Stage boundary accepted: " + error);
    Check(accepted.utxo_root == preview.utxo_root && accepted.state_root == preview.state_root &&
          accepted.account_cost == preview.account_cost && accepted.enforce_cost == preview.enforce_cost &&
          accepted.invocation_cost == preview.invocation_cost && EncodeMonetaryState(accepted.monetary.state) ==
          EncodeMonetaryState(preview.monetary.state), "Stage and preview exact evaluator parity");
    stage.Abort(); // test owns the separately successful staged transaction
    auto no_pow = preview.header; const auto bad_wire = Wire(f, no_pow, txs, false);
    Overlay rejected(f.initial); StagedBlockTransition untouched; untouched.block_id[0] = 123;
    Check(StageCompleteBlock(bad_wire, f.parent, f.history, f.hp, f.op, DevelopmentGenesis, COST, rejected, untouched, error, &proof) ==
          CandidateCheckResult::Invalid && !proof.Valid() && rejected.aborts == 1 && untouched.block_id[0] == 123 &&
          rejected.reads == 0 && rejected.mutations == 0, "preview Ready never bypasses Stage PoW gate or creates proof");
}
void FailuresAndProofClassification() {
    Fixture f; const auto ready = Ready(f, f.Txs());
    auto bad = f.spend; bad.inputs[0].witnesses[0].arguments[0][0] ^= 1;
    Hash message; std::string error;
    Check(SigningMessage(bad, TX, {}, {f.funding.output}, 0, 0, 0, {}, message, error) &&
          VerifyBip340Signature(PUBKEY, bad.inputs[0].witnesses[0].arguments[0], message, false) == SignatureStatus::InvalidSignature,
          "mutated signature independently invalid");
    auto run = [&](const std::vector<Transaction> &txs, Overlay &state, BlockPreviewResult expected,
                   const OrdinaryCandidateProfile *op = nullptr) {
        auto out = Sentinel(); const auto saved = out;
        Check(Preview(f, txs, state, out, error, LIMITS, 1121, op) == expected, "preview typed failure: " + error);
        Check(Same(out, saved), "all caller preview output fields unchanged on failure");
    };
    { Overlay state(f.initial); run({f.cb, bad}, state, BlockPreviewResult::InvalidTransactions); }
    { Overlay state(f.initial); auto nonexistent = f.spend; ++nonexistent.inputs[0].prev_index;
      run({f.cb, nonexistent}, state, BlockPreviewResult::InvalidTransactions); }
    { Overlay state(f.initial); state.wrong_coin = true; run(f.Txs(), state, BlockPreviewResult::StorageError); }
    { Overlay state(f.initial); state.fail_read = 1; run(f.Txs(), state, BlockPreviewResult::StorageError); }
    for (unsigned kind = 0; kind < 3; ++kind) {
        Overlay state(f.initial);
        if (kind == 0) state.fail_mutation = 2;
        if (kind == 1) state.throw_mutation = 2;
        if (kind == 2) state.throw_root = 2;
        run(f.Txs(), state, BlockPreviewResult::StorageError);
        Check(state.mutations >= 2, "provider failure after signed transaction evaluation/private mutation");
    }
    for (unsigned kind = 0; kind < 2; ++kind) {
        auto local = f.op; if (kind == 0) local.vm.max_steps = 1;
        else local.vm_cost.field_sizes = {{0xe7, {1}}};
        Overlay state(f.initial); run(f.Txs(), state, BlockPreviewResult::Inconclusive, &local);
    }
    // The old accepted boundary still issues a proof only for a complete body
    // whose exact header/root/parent bindings passed before deterministic failure.
    auto header = ready.header; const auto bad_wire = Wire(f, header, {f.cb, bad});
    Overlay invalid(f.initial); StagedBlockTransition staged; DeterministicBlockFailure proof;
    Check(StageCompleteBlock(bad_wire, f.parent, f.history, f.hp, f.op, DevelopmentGenesis, COST, invalid, staged, error, &proof) ==
          CandidateCheckResult::Invalid && proof.Valid() && invalid.aborts == 1 &&
          proof.BlockId() == Id({}, header) && proof.ParentId() == Id({}, f.parent.header) &&
          proof.ParentRoot() == f.parent_root, "signed Stage invalidity proof classification retained");
    Overlay io(f.initial); io.fail_read = 1;
    Check(StageCompleteBlock(bad_wire, f.parent, f.history, f.hp, f.op, DevelopmentGenesis, COST, io, staged, error, &proof) ==
          CandidateCheckResult::StorageError && !proof.Valid() && io.aborts == 1, "provider error clears stale Stage failure proof");
    auto local = f.op; local.vm.max_steps = 1; Overlay unsupported(f.initial);
    auto valid_header = ready.header; const auto valid_wire = Wire(f, valid_header, f.Txs());
    Check(StageCompleteBlock(valid_wire, f.parent, f.history, f.hp, local, DevelopmentGenesis, COST, unsupported, staged, error, &proof) ==
          CandidateCheckResult::Inconclusive && !proof.Valid() && unsupported.aborts == 1, "unsupported local execution cannot issue Stage proof");
}
void GrammarCapsAndContext() {
    Fixture f; const auto ready = Ready(f, f.Txs()); std::string error;
    std::vector<std::vector<Transaction>> invalid{{}, {f.spend}, {f.spend, f.cb}, {f.cb, f.cb}, {f.cb, f.spend, f.spend}};
    auto variant = f.spend; variant.inputs[0].witnesses[0].arguments[0][0] ^= 1;
    invalid.push_back({f.cb, f.spend, variant}); // same TxID, different witness/TxHash
    auto wrong_height = f.cb; ++wrong_height.inputs[0].prev_index; invalid.push_back({wrong_height, f.spend});
    auto oversized = f.spend;
    oversized.inputs[0].witnesses[0].arguments[0].resize(TX.max_argument_bytes + 1);
    invalid.push_back({f.cb, oversized});
    for (const auto &txs : invalid) {
        Overlay state(f.initial); auto out = Sentinel(); const auto saved = out;
        Check(Preview(f, txs, state, out, error) == BlockPreviewResult::InvalidTransactions && Same(out, saved), "first/only coinbase and duplicate-ID grammar: " + error);
    }
    for (auto cap : {BlockPreviewLimits{1, 65536}, BlockPreviewLimits{32, 137},
                     BlockPreviewLimits{32, ready.header.size - 1}}) {
        Overlay state(f.initial); auto out = Sentinel(); const auto saved = out;
        Check(Preview(f, f.Txs(), state, out, error, cap) == BlockPreviewResult::CapacityRefused &&
              Same(out, saved) && state.reads == 0 && state.mutations == 0, "count/byte refusal before full block-copy/evaluation");
    }
    for (auto cap : {BlockPreviewLimits{0, 65536}, BlockPreviewLimits{32, 0}}) {
        Overlay state(f.initial); auto out = Sentinel(); const auto saved = out;
        Check(Preview(f, f.Txs(), state, out, error, cap) == BlockPreviewResult::Inconclusive &&
              Same(out, saved) && state.reads == 0 && state.mutations == 0, "absent explicit cap is local configuration");
    }
    { Overlay state(f.initial); BlockPreview out;
      Check(Preview(f, f.Txs(), state, out, error, {2, ready.header.size}) == BlockPreviewResult::Ready && Same(out, ready), "exact count and byte cap succeeds"); }
    for (uint64_t time : {uint64_t{1120}, MAX_TIME + 1}) {
        Overlay state(f.initial); auto out = Sentinel(); const auto saved = out;
        Check(Preview(f, f.Txs(), state, out, error, LIMITS, time) == BlockPreviewResult::Inconclusive &&
              Same(out, saved) && state.reads == 0 && state.mutations == 0, "time is explicit local template context");
    }
    for (unsigned kind = 0; kind < 5; ++kind) {
        auto local = f;
        if (kind == 0) local.history.back().nonce ^= 1;
        if (kind == 1) ++local.op.parent_mtp;
        if (kind == 2) ++local.op.candidate_height;
        if (kind == 3) {
            local.parent.header.state_root[0] ^= 1;
            local.history.front() = local.parent.header;
        }
        if (kind == 4) {
            local.parent.monetary.prev_work[0] = 3;
            local.parent.header.state_root = StateRoot({}, 1, local.parent_root, local.parent.monetary);
            local.history.front() = local.parent.header;
        }
        Overlay state(local.initial); auto out = Sentinel(); const auto saved = out;
        const auto result = Preview(local, local.Txs(), state, out, error);
        Check(result == (kind >= 3 ? BlockPreviewResult::StorageError : BlockPreviewResult::Inconclusive) &&
              Same(out, saved) && state.reads == 0 && state.mutations == 0, "authenticated parent/history/profile gate: " + error);
    }
    {
        auto local = f; local.parent.header.state_root[0] ^= 1;
        local.history.front() = local.parent.header;
        Overlay state(local.initial); auto out = Sentinel(); const auto saved = out;
        Check(Preview(local, local.Txs(), state, out, error, {1, 65536}) == BlockPreviewResult::StorageError &&
              Same(out, saved) && state.roots == 1 && state.reads == 0 && state.mutations == 0,
              "authenticated parent mismatch precedes local count quota refusal");
    }
}
void RequiredAsertAndDependencies() {
    Fixture f; f.parent.header.time += 86400; Mine({}, f.hp.pow_limit, f.parent.header);
    f.history.front() = f.parent.header; f.op.parent_mtp = f.parent.header.time;
    f.cb.inputs[0].prev_txid = Id({}, f.parent.header);
    const auto preview = Ready(f, f.Txs());
    Hash target; Check(DecodeTarget(f.hp.genesis_bits, f.hp.pow_limit, target), "ASERT reference target");
    const auto required = RequiredAsertCandidateBits(f.hp.half_life_seconds, f.hp.spacing_seconds,
        Integer(target), f.hp.genesis_time, Integer(f.hp.pow_limit), {f.parent.header.time, f.parent.header.height});
    Check(required && required->bits != f.parent.header.bits && preview.header.bits == required->bits,
          "preview derives child target from authenticated parent ASERT rather than caller guess");
    auto header = preview.header; const auto wire = Wire(f, header, f.Txs()); Overlay state(f.initial);
    StagedBlockTransition out; std::string error;
    Check(StageCompleteBlock(wire, f.parent, f.history, f.hp, f.op, DevelopmentGenesis, COST, state, out, error) ==
          CandidateCheckResult::Accepted, "ASERT template accepted only after sealing: " + error);
    state.Abort();
    Fixture chain; IdentityDigests ids;
    Check(ComputeIdentities(chain.spend, TX, {}, ids, error), error);
    Transaction child; Input input; input.prev_txid = ids.txid; input.sequence = UINT32_MAX; input.flags = 1;
    input.witnesses = {BranchWitness{TRUE, {}, {}}}; child.inputs = {input}; child.outputs = {Native(1000)};
    const auto dependent = Ready(chain, {chain.cb, chain.spend, child});
    auto reversed = Sentinel(); Overlay reverse_state(chain.initial);
    Check(Preview(chain, {chain.cb, child, chain.spend}, reverse_state, reversed, error) ==
          BlockPreviewResult::InvalidTransactions && Same(reversed, Sentinel()), "ordered signed-parent dependency required");
    auto dependent_header = dependent.header; const auto dependent_wire = Wire(chain, dependent_header, {chain.cb, chain.spend, child});
    Overlay connected(chain.initial);
    Check(StageCompleteBlock(dependent_wire, chain.parent, chain.history, chain.hp, chain.op, DevelopmentGenesis, COST,
                             connected, out, error) == CandidateCheckResult::Accepted && out.state_root == dependent.state_root,
          "signed-parent dependency preview equals complete Stage: " + error);
    connected.Abort();
}
void ValidatedReceiptCacheAndParallelVerification() {
    Fixture f;
    std::string error;
    ClearOrdinaryValidationCache();
    auto stats = GetOrdinaryValidationCacheStats();
    Check(stats.hits == 0 && stats.misses == 0 && stats.entries == 0,
          "cache cleared initially");

    // 1. Cache hit across TransactionPool::Admit -> PreviewBlockTemplate -> StageCompleteBlock.
    PoolContext pool_ctx;
    pool_ctx.anchor = {Id({}, f.parent.header), 1};
    pool_ctx.profile = f.op;
    pool_ctx.chain_id = {};
    pool_ctx.active_coins = [&](const Outpoint &op, Coin &coin, std::string &) {
        const auto it = f.initial.find(op);
        if (it == f.initial.end()) return CoinReadResult::Missing;
        coin = it->second;
        return CoinReadResult::Found;
    };
    pool_ctx.current = [] { return true; };
    pool_ctx.cost = COST;
    TransactionPool pool(PoolLimits{});
    PoolBudget budget{10, 10000000};
    std::vector<uint8_t> spend_wire;
    Check(EncodeTransaction(f.spend, TX, spend_wire, error), error);
    const auto admitted = pool.Admit(spend_wire, pool_ctx, budget);
    Check(admitted.status == PoolStatus::Accepted, "pool admit: " + admitted.error);
    stats = GetOrdinaryValidationCacheStats();
    Check(stats.misses == 1 && stats.hits == 0 && stats.entries == 1,
          "pool admission populates validated receipt cache once");

    const auto preview = Ready(f, f.Txs());
    stats = GetOrdinaryValidationCacheStats();
    Check(stats.misses == 1 && stats.hits == 1 && stats.entries == 1,
          "PreviewBlockTemplate hits validated receipt cache");

    auto header = preview.header;
    const auto wire = Wire(f, header, f.Txs());
    Overlay stage(f.initial);
    StagedBlockTransition accepted;
    Check(StageCompleteBlock(wire, f.parent, f.history, f.hp, f.op,
                             DevelopmentGenesis, COST, stage, accepted, error) ==
              CandidateCheckResult::Accepted,
          "StageCompleteBlock after preview: " + error);
    stage.Abort();
    stats = GetOrdinaryValidationCacheStats();
    Check(stats.misses == 1 && stats.hits == 2 && stats.entries == 1,
          "StageCompleteBlock hits validated receipt cache");

    // 2. Cache invalidation / miss on any context, profile, coin, or witness change.
    OrdinaryCandidateEffects effects;
    {
        ChainId other_chain{};
        other_chain[0] = 1;
        // Signature binds chain_id, so a different chain_id misses the cache and fails signature verification.
        Check(!CheckOrdinaryCandidate(f.spend, f.op, other_chain, f.initial, effects, error),
              "changed chain_id rejected");
        stats = GetOrdinaryValidationCacheStats();
        Check(stats.misses == 2 && stats.hits == 2,
              "changed chain_id misses cache");
    }
    {
        auto diff_dust = f.op;
        ++diff_dust.dust_limit;
        Check(CheckOrdinaryCandidate(f.spend, diff_dust, {}, f.initial, effects, error),
              error);
        stats = GetOrdinaryValidationCacheStats();
        Check(stats.misses == 3 && stats.hits == 2 && stats.entries == 2,
              "changed dust_limit misses cache and populates distinct entry");
    }
    {
        auto diff_vm = f.op;
        ++diff_vm.vm.max_steps;
        Check(CheckOrdinaryCandidate(f.spend, diff_vm, {}, f.initial, effects, error),
              error);
        stats = GetOrdinaryValidationCacheStats();
        Check(stats.misses == 4 && stats.hits == 2 && stats.entries == 3,
              "changed vm profile misses cache");
    }
    {
        auto diff_view = f.initial;
        diff_view.begin()->second.creation_height = 1;
        Check(CheckOrdinaryCandidate(f.spend, f.op, {}, diff_view, effects, error),
              error);
        stats = GetOrdinaryValidationCacheStats();
        Check(stats.misses == 5 && stats.hits == 2 && stats.entries == 4,
              "changed resolved input Coin misses cache");
    }
    {
        auto low_budget = f.op;
        low_budget.max_total_invocation_cost = 1;
        Check(!CheckOrdinaryCandidate(f.spend, low_budget, {}, f.initial, effects, error) &&
                  error == "invocation cost unavailable or over budget",
              "lowered max_total_invocation_cost still enforces budget on cache hit");
        stats = GetOrdinaryValidationCacheStats();
        Check(stats.misses == 5 && stats.hits == 3,
              "budget check runs on cache hit");
    }
    {
        auto diff_height = f.op;
        ++diff_height.candidate_height;
        Check(CheckOrdinaryCandidate(f.spend, diff_height, {}, f.initial, effects, error),
              error);
        stats = GetOrdinaryValidationCacheStats();
        Check(stats.misses == 6 && stats.hits == 3 && stats.entries == 5,
              "changed candidate_height misses cache");
    }
    {
        auto diff_mtp = f.op;
        ++diff_mtp.parent_mtp;
        Check(CheckOrdinaryCandidate(f.spend, diff_mtp, {}, f.initial, effects, error),
              error);
        stats = GetOrdinaryValidationCacheStats();
        Check(stats.misses == 7 && stats.hits == 3 && stats.entries == 6,
              "changed parent_mtp misses cache");
    }

    // 3. Parallel multi-transaction verification and deterministic first-failure ordering.
    Fixture multi;
    multi.initial.clear();
    IncrementalUtxoSet multi_tree;
    std::vector<Transaction> multi_txs{multi.cb};
    for (uint8_t idx = 1; idx <= 6; ++idx) {
        Coin coin = multi.funding;
        coin.outpoint.tx_id[0] = uint8_t(20 + idx);
        coin.outpoint.index = idx;
        multi.initial.emplace(coin.outpoint, coin);
        Check(multi_tree.Insert(coin), "multi funding insert");

        Transaction tx = multi.spend;
        tx.inputs[0].prev_txid = coin.outpoint.tx_id;
        tx.inputs[0].prev_index = coin.outpoint.index;
        tx.outputs[0].value = 1000000 + idx * 1000;
        Hash msg;
        Check(SigningMessage(tx, TX, {}, {coin.output}, 0, 0, 0, {}, msg, error),
              error);
        std::array<uint8_t, 32> secret{}, aux{};
        secret[31] = 3;
        Check(SignBip340Message(secret, msg, 0, aux,
                                tx.inputs[0].witnesses[0].arguments[0], error),
              error);
        multi_txs.push_back(std::move(tx));
    }
    multi.parent_root = multi_tree.Root();
    multi.parent.header.nonce = 0;
    multi.parent.header.state_root =
        StateRoot({}, 1, multi.parent_root, multi.parent.monetary);
    Mine({}, multi.hp.pow_limit, multi.parent.header);
    multi.history[0] = multi.parent.header;
    multi.cb.inputs[0].prev_txid = Id({}, multi.parent.header);
    multi_txs[0] = multi.cb;

    ClearOrdinaryValidationCache();
    const auto multi_preview = Ready(multi, multi_txs);
    stats = GetOrdinaryValidationCacheStats();
    Check(stats.misses == 6 && stats.hits == 0 && stats.entries == 6,
          "parallel multi-transaction preview verifies all 6 uncached transactions");

    auto multi_header = multi_preview.header;
    const auto multi_wire = Wire(multi, multi_header, multi_txs);
    Overlay multi_stage(multi.initial);
    StagedBlockTransition multi_accepted;
    Check(StageCompleteBlock(multi_wire, multi.parent, multi.history, multi.hp,
                             multi.op, DevelopmentGenesis, COST, multi_stage,
                             multi_accepted, error) ==
              CandidateCheckResult::Accepted &&
              multi_accepted.state_root == multi_preview.state_root,
          "multi-transaction StageCompleteBlock matches preview: " + error);
    multi_stage.Abort();
    stats = GetOrdinaryValidationCacheStats();
    Check(stats.misses == 6 && stats.hits == 6 && stats.entries == 6,
          "multi-transaction StageCompleteBlock hits cache for all 6 transactions");

    // Corrupt both tx #2 (bad signature -> false top stack) and tx #4 (OP_FALSE OP_VERIFY -> VERIFY failed).
    auto bad_multi_txs = multi_txs;
    bad_multi_txs[2].inputs[0].witnesses[0].arguments[0][0] ^= 1;
    std::string expected_tx2_error;
    Check(!CheckOrdinaryCandidate(bad_multi_txs[2], multi.op, {}, multi.initial,
                                  effects, expected_tx2_error),
          "tx 2 independently invalid");
    // Give tx #4 a different script & coin branch so its failure message differs from tx #2.
    const std::vector<uint8_t> verify_fail_script{0x4d, 0x69}; // OP_FALSE OP_VERIFY
    const Outpoint op4{bad_multi_txs[4].inputs[0].prev_txid,
                       bad_multi_txs[4].inputs[0].prev_index};
    auto bad_multi_view_fixture = multi;
    bad_multi_view_fixture.initial.at(op4).output.branches = {
        BranchLeaf(verify_fail_script)};
    IncrementalUtxoSet bad_tree;
    for (const auto &[k, c] : bad_multi_view_fixture.initial) {
        (void)k;
        Check(bad_tree.Insert(c), "bad_tree insert");
    }
    bad_multi_view_fixture.parent_root = bad_tree.Root();
    bad_multi_view_fixture.parent.header.nonce = 0;
    bad_multi_view_fixture.parent.header.state_root = StateRoot(
        {}, 1, bad_multi_view_fixture.parent_root,
        bad_multi_view_fixture.parent.monetary);
    Mine({}, bad_multi_view_fixture.hp.pow_limit,
         bad_multi_view_fixture.parent.header);
    bad_multi_view_fixture.history[0] = bad_multi_view_fixture.parent.header;
    bad_multi_txs[0].inputs[0].prev_txid =
        Id({}, bad_multi_view_fixture.parent.header);
    bad_multi_txs[4].inputs[0].witnesses = {
        BranchWitness{verify_fail_script, {}, {}}};
    std::string expected_tx4_error;
    Check(!CheckOrdinaryCandidate(bad_multi_txs[4], bad_multi_view_fixture.op,
                                  {}, bad_multi_view_fixture.initial, effects,
                                  expected_tx4_error),
          "tx 4 independently invalid");
    Check(expected_tx2_error != expected_tx4_error,
          "tx 2 and tx 4 have distinct VM error strings");

    ClearOrdinaryValidationCache();
    Overlay bad_preview_state(bad_multi_view_fixture.initial);
    BlockPreview bad_preview_out = Sentinel();
    Check(Preview(bad_multi_view_fixture, bad_multi_txs, bad_preview_state,
                  bad_preview_out, error) ==
              BlockPreviewResult::InvalidTransactions &&
              error == expected_tx2_error,
          "parallel preview deterministically reports first failing tx error: " +
              error);
}
template <typename T> concept HasBlockId = requires(T t) { t.block_id; };
template <typename T> concept HasFailure = requires(T t) { t.failure; };
static_assert(!std::is_same_v<BlockPreviewResult, CandidateCheckResult>);
static_assert(!HasBlockId<BlockPreview> && !HasFailure<BlockPreview>);
} // namespace
int main() {
    try { SignedReadyAndStage(); FailuresAndProofClassification(); GrammarCapsAndContext(); RequiredAsertAndDependencies(); ValidatedReceiptCacheAndParallelVerification();
        std::cout << "signed block preview, abort and Stage proof gates pass\n";
    } catch (const std::exception &e) { std::cerr << "block preview: " << e.what() << '\n'; return 1; }
}
