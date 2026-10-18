// Copyright (c) 2026 The Lotus developers
#include "block_assembler.h"
#include "block_assembler_test/fixtures.h"
#include "development_runtime.h"
#include <functional>
#include <iostream>
#include <leveldb/env.h>
using namespace lotus::v2;
using namespace assembler_fixture;
namespace {
std::vector<Transaction> ZeroTransactions(Home &home,
                                          const LocalBlockRequest &request) {
    Header parent;
    const auto metadata = home.store.Metadata();
    Check(ParseHeader(metadata.header.data(), metadata.header.size(), parent),
          "zero quote parent");
    Transaction coinbase;
    Input input;
    input.flags = 2;
    input.prev_txid = request.expected_parent;
    input.prev_index = uint32_t(parent.height + 1);
    input.sequence = UINT32_MAX;
    if (request.coinbase_data) {
        input.has_coinbase_data = true;
        input.coinbase_data = *request.coinbase_data;
    }
    coinbase.inputs = {input};
    auto destination = request.coinbase_destination;
    destination.value = 0;
    coinbase.outputs = {destination};
    std::vector<Transaction> transactions{coinbase};
    transactions.insert(transactions.end(), request.ordinary.begin(),
                        request.ordinary.end());
    return transactions;
}
BlockPreview Quote(Home &home, const LocalBlockRequest &request) {
    BlockPreview quote;
    std::string error;
    Check(PreviewStoredBlockTemplate(
              ZeroTransactions(home, request), request.time, {17, 1 << 20},
              home.p.header, home.p.ordinary, home.p.monetary, home.p.cost,
              home.store, quote, error) == BlockPreviewResult::Ready,
          "independent zero-claim preview: " + error);
    return quote;
}
void Abortable(Home &home) {
    DiskStateTransaction transaction;
    DiskStateError error;
    Check(home.store.Begin(transaction, error),
          "preview released private writer: " + error.message);
    transaction.Abort();
}
void SameAccepted(const LocalBlockTemplate &built,
                  const StagedBlockTransition &accepted) {
    const auto &preview = built.preview;
    Check(accepted.utxo_root == preview.utxo_root &&
              accepted.state_root == preview.state_root &&
              EncodeMonetaryState(accepted.monetary.state) ==
                  EncodeMonetaryState(preview.monetary.state) &&
              accepted.account_cost == preview.account_cost &&
              accepted.enforce_cost == preview.enforce_cost &&
              accepted.invocation_cost == preview.invocation_cost &&
              accepted.monetary.required_underclaim ==
                  preview.monetary.required_underclaim &&
              accepted.monetary.actual_underclaim ==
                  preview.monetary.actual_underclaim,
          "normal validator exactly matches preview "
          "roots/money/cost/deduction/claim");
}
void RuntimeAccept(Home &replay, const LocalBlockTemplate &mined) {
    const auto parent = replay.store.Metadata();
    replay.store = {};
    DevelopmentRuntimeConfig config;
    config.directory = replay.path;
    config.genesis_wire = replay.genesis;
    config.profiles = replay.p;
    config.initial_money = replay.initial;
    config.storage = replay.Options();
    config.bodies = {3, 1 << 20, 3 << 20, 3, 3 << 20, 64};
    config.initial_body_epoch = 1;
    config.initial_context_generation = 1;
    std::unique_ptr<DevelopmentRuntime> runtime;
    std::string error;
    Check(DevelopmentRuntime::Open(config, runtime, error),
          "actual runtime open: " + error);
    HeaderAdmission header = HeaderAdmission::Invalid;
    Check(runtime->AdmitHeader(mined.preview.header, header, error) ==
                  DevelopmentRuntimeResult::Progress &&
              header == HeaderAdmission::Stored,
          "assembled header through runtime admission");
    CandidateBodyStatus body = CandidateBodyStatus::Malformed;
    Check(runtime->RetainBody(*mined.mined_id, mined.wire, body, error) ==
                  DevelopmentRuntimeResult::Progress &&
              body == CandidateBodyStatus::RetainedAuthenticated,
          "assembled wire through bounded runtime pool");
    DevelopmentTickLimits limits;
    limits.selection.query = {64, 20000, 20000, 1 << 20};
    limits.selection.fork = {8, 8, 1000};
    limits.selection.max_probe_calls = 128;
    limits.selection.max_probe_bytes = 1 << 20;
    limits.selection.max_missing_bodies = 8;
    limits.selection.max_resident_bytes = 1 << 20;
    limits.recovery = runtime_fixture::Limits();
    limits.propagation = {1, 1000, 1000, 1 << 20};
    bool completed = false, acknowledged = false;
    for (unsigned n = 0; n < 40; ++n) {
        const auto tick = runtime->Tick(UINT64_MAX, 0, limits);
        Check(tick.usage.recovery_calls <= 1,
              "runtime assembly publication remains one bounded recovery step");
        Check(tick.result != DevelopmentRuntimeResult::StorageError &&
                  tick.result != DevelopmentRuntimeResult::ReopenRequired &&
                  tick.result != DevelopmentRuntimeResult::Inconclusive,
              "runtime accepts mined payment: " + tick.diagnostic);
        if (tick.result == DevelopmentRuntimeResult::CompleteTarget) {
            completed = true;
            Check(tick.snapshot.chain && tick.snapshot.chain->pending_receipt,
                  "mined payment publication retains receipt gate");
        }
        if (tick.result == DevelopmentRuntimeResult::Acknowledged) {
            acknowledged = true;
            break;
        }
    }
    Check(completed && acknowledged,
          "assembled payment publishes and acknowledges normally");
    DiskStateMetadata actual;
    Hash root;
    const auto expected_money =
        EncodeMonetaryState(mined.preview.monetary.state);
    Check(runtime->ReadMetadata(1 << 20, actual, root, error) ==
                  DevelopmentRuntimeResult::Progress &&
              actual.tip == *mined.mined_id && actual.tip != parent.tip &&
              root == mined.preview.utxo_root &&
              actual.monetary == std::vector<uint8_t>(expected_money.begin(),
                                                      expected_money.end()),
          "runtime publishes exact assembled state");
    runtime.reset();
    replay.Open();
}
void SignedMatureParentChild() {
    Home home;
    auto request = Request(home, 100000);
    auto funding = Mine(Build(home, request), home.p);
    SameAccepted(funding, Connect(home, funding));
    auto second = Mine(Build(home, Request(home, 100000)), home.p);
    SameAccepted(second, Connect(home, second));
    Coin funding_coin = CoinAt(funding, 0, home.p, true);
    std::optional<Coin> authenticated;
    DiskStateError failure;
    Check(home.store.ReadCoin(funding_coin.outpoint, authenticated, failure) &&
              authenticated,
          "signed fixture resolves actual matured coinbase");
    funding_coin = *authenticated;
    auto parent = Spend(funding_coin, 95000, home.p);
    IdentityDigests parent_ids;
    std::string error;
    Check(ComputeIdentities(parent, home.p.ordinary.transaction,
                            home.p.header.chain_id, parent_ids, error),
          error);
    Coin intermediate;
    intermediate.outpoint = {parent_ids.txid, 0};
    intermediate.output = parent.outputs[0];
    auto child = Spend(intermediate, 90000, home.p);
    request = Request(home);
    request.ordinary = {parent, child};
    const auto before = Raw(home);
    const auto quote = Quote(home, request);
    Abortable(home);
    auto built = Build(home, request);
    Abortable(home);
    Check(!built.mined_id && built.preview.header.nonce == 0,
          "construction is not mining or acceptance");
    const auto decoded = Decode(built, home.p);
    const MonetaryInteger available =
        quote.monetary.actual_underclaim - quote.monetary.required_underclaim;
    Check(available >= 0 && available <= MonetaryInteger(UINT64_MAX),
          "real profile quote fits unsigned claim");
    Check(decoded.transactions[0].outputs[0].value ==
                  available.convert_to<uint64_t>() &&
              built.preview.monetary.actual_underclaim ==
                  quote.monetary.required_underclaim,
          "u64 maximum request claims exact authoritative entitlement minus "
          "mandatory deduction");
    Check(built.preview.account_cost == quote.account_cost &&
              built.preview.enforce_cost == quote.enforce_cost &&
              built.preview.invocation_cost == quote.invocation_cost &&
              EncodeMonetaryState(built.preview.monetary.state) ==
                  EncodeMonetaryState(quote.monetary.state) &&
              built.preview.monetary.required_underclaim ==
                  quote.monetary.required_underclaim &&
              built.preview.monetary.total_fees == 10000,
          "fixed-width final claim preserves both preview cost quotes and "
          "monetary recurrence");
    Check(Raw(home) == before, "zero preview plus final construction leave "
                               "every raw state key unchanged");
    auto capped = request;
    capped.max_claim = 100000;
    const auto limited = Build(home, capped);
    Check(Decode(limited, home.p).transactions[0].outputs[0].value == 100000,
          "explicit maximum claim cap");
    auto zero = request;
    zero.max_claim = 0;
    const auto zero_built = Build(home, zero);
    Check(Decode(zero_built, home.p).transactions[0].outputs[0].value == 0 &&
              zero_built.preview.monetary.actual_underclaim ==
                  quote.monetary.actual_underclaim,
          "zero claim is a canonical spendable zero coinbase with full "
          "underclaim");
    LocalBlockTemplate untouched;
    untouched.wire = {0x77};
    auto reversed = request;
    reversed.ordinary = {child, parent};
    Check(BuildLocalDiskBlockTemplate(
              reversed, Limits(), home.p.header, home.p.ordinary,
              home.p.monetary, home.p.cost, home.store, untouched,
              error) == LocalBlockBuildResult::InvalidTransactions &&
              untouched.wire == std::vector<uint8_t>{0x77},
          "supplied dependency order is enforced without reordering");
    auto invalid = request;
    invalid.ordinary[0].inputs[0].witnesses[0].arguments[0][0] ^= 1;
    Check(BuildLocalDiskBlockTemplate(
              invalid, Limits(), home.p.header, home.p.ordinary,
              home.p.monetary, home.p.cost, home.store, untouched,
              error) == LocalBlockBuildResult::InvalidTransactions &&
              untouched.wire == std::vector<uint8_t>{0x77},
          "bad actual BIP340 signature rejects without publication");
    Check(Raw(home) == before, "invalid signature/order and alternate claim "
                               "previews change no raw state keys");
    const auto mined = Mine(built, home.p);
    SameAccepted(mined, Connect(home, mined));
    std::optional<Coin> old, transient;
    Check(home.store.ReadCoin(funding_coin.outpoint, old, failure) && !old &&
              home.store.ReadCoin(intermediate.outpoint, transient, failure) &&
              !transient,
          "signed matured input and same-block parent output are consumed");
    Home replay;
    Connect(replay, funding);
    Connect(replay, second);
    RuntimeAccept(replay, mined);
}
void InsufficientAndResourceRefusals() {
    Home bare(true);
    const auto request = Request(bare);
    const auto transactions = ZeroTransactions(bare, request);
    std::string error;
    std::vector<uint8_t> encoded;
    Check(EncodeTransaction(transactions[0], bare.p.ordinary.transaction,
                            encoded, error),
          error);
    const auto linear = AuthenticatedTransactionCostsResolved(
        transactions[0], bare.p.ordinary.transaction, {}, 1,
        bare.p.header.genesis_time, 0, bare.p.cost);
    const auto cost = BlockEffectiveCost(
        AuthenticatedEnvelopeCost(CompactSizeWidth(encoded.size()), 1,
                                  bare.p.cost),
        {linear.enforce_linear}, bare.p.monetary);
    // Derive the actual encoded-charge floor, not a one-byte toy transition.
    // Even releasing the entire existing reserve plus tail cannot pay it.
    Check(
        RequiredBlockBurn(cost, bare.initial.ema_block_cost, bare.p.monetary) >
            MonetaryInteger(bare.initial.bootstrap_reserve) +
                bare.initial.tail_subsidy,
        "real encoded block charge exceeds an upper bound on bare-profile "
        "entitlement");
    const auto before = Raw(bare);
    LocalBlockTemplate untouched;
    untouched.wire = {0x77};
    Check(BuildLocalDiskBlockTemplate(
              request, Limits(), bare.p.header, bare.p.ordinary,
              bare.p.monetary, bare.p.cost, bare.store, untouched,
              error) == LocalBlockBuildResult::InvalidTransactions &&
              untouched.wire == std::vector<uint8_t>{0x77},
          "insufficient authoritative entitlement cannot create block");
    Check(Raw(bare) == before,
          "insufficient entitlement leaves all raw state keys unchanged");
    Home home;
    const auto parent = Raw(home);
    auto stale = Request(home);
    stale.expected_parent = Hash{};
    Check(BuildLocalDiskBlockTemplate(
              stale, Limits(), home.p.header, home.p.ordinary, home.p.monetary,
              home.p.cost, home.store, untouched,
              error) == LocalBlockBuildResult::StaleParent,
          "wrong expected parent fails before construction");
    auto limits = Limits();
    limits.max_block_bytes = HEADER_SIZE + 4;
    Check(BuildLocalDiskBlockTemplate(
              Request(home), limits, home.p.header, home.p.ordinary,
              home.p.monetary, home.p.cost, home.store, untouched,
              error) == LocalBlockBuildResult::CapacityRefused,
          "canonical framed block byte cap");
    auto data = Request(home);
    data.coinbase_data = std::vector<uint8_t>{1, 2, 3, 4};
    limits = Limits();
    limits.max_coinbase_data_bytes = 3;
    Check(BuildLocalDiskBlockTemplate(
              data, limits, home.p.header, home.p.ordinary, home.p.monetary,
              home.p.cost, home.store, untouched,
              error) == LocalBlockBuildResult::CapacityRefused,
          "coinbase data cap before copy");
    data.coinbase_data = std::vector<uint8_t>{};
    Check(BuildLocalDiskBlockTemplate(
              data, Limits(), home.p.header, home.p.ordinary, home.p.monetary,
              home.p.cost, home.store, untouched,
              error) == LocalBlockBuildResult::InvalidTransactions,
          "present empty coinbase data cannot bypass canonical framing");
    Check(untouched.wire == std::vector<uint8_t>{0x77} && Raw(home) == parent,
          "stale/resource/canonical refusals preserve output and raw state");
}
void BuilderExceptionsAreClassified() {
    Home home;
    for (unsigned kind = 0; kind < 4; ++kind) {
        LocalBlockTemplate out;
        out.wire = {0x77};
        std::string error;
        const auto before = Raw(home);
        SetLocalBlockBuildTestHook([=] {
            if (kind == 0) throw std::bad_alloc();
            if (kind == 1) throw std::length_error("injected length");
            if (kind == 2) throw std::runtime_error("injected builder step");
            throw 42;
        });
        const auto result = BuildLocalDiskBlockTemplate(
            Request(home), Limits(), home.p.header, home.p.ordinary,
            home.p.monetary, home.p.cost, home.store, out, error);
        SetLocalBlockBuildTestHook({});
        Check(result == (kind < 2 ? LocalBlockBuildResult::CapacityRefused :
                                  LocalBlockBuildResult::StorageError),
              "throwing builder step has a deterministic operational class");
        Check(!error.empty() && out.wire == std::vector<uint8_t>{0x77} &&
                  Raw(home) == before,
              "throwing builder step preserves output and state with diagnostics");
    }
}
void NonceBoundaries() {
    Home home;
    auto block = Build(home, Request(home, 0));
    auto hard = block;
    hard.preview.header.bits =
        0x01010000; // Canonical target1, nonce-only fixture.
    std::array<uint8_t, HEADER_SIZE> header;
    Check(SerializeHeader(hard.preview.header, header), "hard nonce header");
    std::copy(header.begin(), header.end(), hard.wire.begin());
    Hash target, id;
    Check(
        DecodeTarget(hard.preview.header.bits, home.p.header.pow_limit, target),
        "hard target");
    auto last = hard.preview.header;
    last.nonce = UINT64_MAX;
    Check(BlockId(home.p.header.chain_id, last, id) && !MeetsTarget(id, target),
          "fixed last nonce is not a solution");
    LocalBlockTemplate untouched;
    untouched.wire = {0x77};
    std::string error;
    Check(SearchLocalBlockNonce(
              hard, home.p.header.chain_id, home.p.header.pow_limit, UINT64_MAX,
              2, untouched, error) == LocalNonceResult::Exhausted &&
              untouched.wire == std::vector<uint8_t>{0x77},
          "nonce range exhaustion never wraps beyond u64 maximum");
    Check(SearchLocalBlockNonce(block, home.p.header.chain_id,
                                home.p.header.pow_limit, 0, 0, untouched,
                                error) == LocalNonceResult::Exhausted,
          "zero nonce attempts perform no search");
    Check(SearchLocalBlockNonce(block, home.p.header.chain_id,
                                home.p.header.pow_limit, 0, 257, untouched,
                                error) == LocalNonceResult::CapacityRefused,
          "more than256 attempts refused");
    auto changed = block;
    changed.wire[0] ^= 1;
    Check(SearchLocalBlockNonce(changed, home.p.header.chain_id,
                                home.p.header.pow_limit, 0, 256, untouched,
                                error) == LocalNonceResult::InvalidTemplate &&
              untouched.wire == std::vector<uint8_t>{0x77},
          "mutable header/wire mismatch cannot be mined");
    auto mined = Mine(block, home.p);
    Check(mined.mined_id && mined.preview.header.nonce < 256 &&
              BlockId(home.p.header.chain_id, mined.preview.header, id) &&
              id == *mined.mined_id,
          "bounded proof result names actual header ID");
}
class SyncObserver final : public leveldb::EnvWrapper {
public:
    std::function<void()> callback;
    SyncObserver() : EnvWrapper(leveldb::Env::Default()) {}
    class File final : public leveldb::WritableFile {
        SyncObserver &owner;
        std::unique_ptr<leveldb::WritableFile> file;

    public:
        File(SyncObserver &env, leveldb::WritableFile *raw)
            : owner(env), file(raw) {}
        std::string GetName() const override { return file->GetName(); }
        leveldb::Status Append(const leveldb::Slice &bytes) override {
            return file->Append(bytes);
        }
        leveldb::Status Flush() override { return file->Flush(); }
        leveldb::Status Close() override { return file->Close(); }
        leveldb::Status Sync() override {
            if (owner.callback) owner.callback();
            return file->Sync();
        }
    };
    leveldb::Status NewWritableFile(const std::string &name,
                                    leveldb::WritableFile **out) override {
        auto result = target()->NewWritableFile(name, out);
        if (result.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return result;
    }
    leveldb::Status NewAppendableFile(const std::string &name,
                                      leveldb::WritableFile **out) override {
        auto result = target()->NewAppendableFile(name, out);
        if (result.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return result;
    }
};
void RuntimePreviewFacade() {
    SyncObserver env;
    Home home;
    std::string error;
    for (size_t n : {0, 1, 2, 3}) {
        StagedBlockTransition result;
        Check(ConnectStoredDiskBlock(Bytes(V(n).wire), home.p.header,
                                     home.p.ordinary, home.p.monetary,
                                     home.p.cost, home.store, result,
                                     error) == CandidateCheckResult::Accepted,
              "facade actual source");
    }
    const auto request = Request(home, 100000);
    const auto direct = Build(home, request);
    const auto original = home.store.Metadata();
    const auto original_root = home.store.Root();
    home.store = {};
    DevelopmentRuntimeConfig config;
    config.directory = home.path;
    config.genesis_wire = home.genesis;
    config.profiles = home.p;
    config.initial_money = home.initial;
    config.storage = home.Options();
    config.storage.env = &env;
    config.bodies = {3, 1 << 20, 3 << 20, 3, 3 << 20, 64};
    config.initial_body_epoch = 1;
    config.initial_context_generation = 1;
    std::unique_ptr<DevelopmentRuntime> runtime;
    Check(DevelopmentRuntime::Open(config, runtime, error),
          "facade runtime open");
    for (size_t n : {4, 5, 6}) {
        HeaderAdmission header;
        CandidateBodyStatus body;
        Check(runtime->AdmitHeader(runtime_fixture::HeaderOf(V(n)), header,
                                   error) ==
                      DevelopmentRuntimeResult::Progress &&
                  runtime->RetainBody(H(V(n).id), Bytes(V(n).wire), body,
                                      error) ==
                      DevelopmentRuntimeResult::Progress,
              "facade candidate setup");
    }
    DevelopmentTickLimits limits;
    limits.selection.query = {64, 20000, 20000, 1 << 20};
    limits.selection.fork = {8, 8, 1000};
    limits.selection.max_probe_calls = 128;
    limits.selection.max_probe_bytes = 1 << 20;
    limits.selection.max_missing_bodies = 8;
    limits.selection.max_resident_bytes = 1 << 20;
    limits.recovery = runtime_fixture::Limits();
    limits.propagation = {1, 1000, 1000, 1 << 20};
    bool ready = false;
    for (unsigned n = 0; n < 40; ++n) {
        const auto tick = runtime->Tick(UINT64_MAX, 0, limits);
        if (tick.choices && tick.choices->best_ready) {
            ready = true;
            break;
        }
    }
    Check(ready, "facade retains a ready private selector choice");
    const auto before = runtime->Snapshot();
    LocalBlockBuildResult status = LocalBlockBuildResult::StorageError;
    LocalBlockTemplate out;
    Check(runtime->BuildTemplate(request, Limits(), status, out, error) ==
                  DevelopmentRuntimeResult::Progress &&
              status == LocalBlockBuildResult::Ready && out.wire == direct.wire,
          "facade dispatch returns typed Ready and exact private template");
    auto stale = request;
    stale.expected_parent = Hash{};
    out.wire = {0x77};
    Check(runtime->BuildTemplate(stale, Limits(), status, out, error) ==
                  DevelopmentRuntimeResult::Progress &&
              status == LocalBlockBuildResult::StaleParent &&
              out.wire == std::vector<uint8_t>{0x77},
          "completed facade call is not acceptance; typed stale result remains "
          "authoritative");
    auto small = Limits();
    small.max_block_bytes = HEADER_SIZE + 4;
    Check(runtime->BuildTemplate(request, small, status, out, error) ==
                  DevelopmentRuntimeResult::CapacityRefused &&
              status == LocalBlockBuildResult::CapacityRefused &&
              out.wire == std::vector<uint8_t>{0x77},
          "facade maps resource refusal without faulting or changing output");
    const auto after = runtime->Snapshot();
    DiskStateMetadata metadata;
    Hash root;
    Check(after.body_epoch == before.body_epoch &&
              after.context_generation == before.context_generation &&
              after.chain && before.chain &&
              after.chain->revision == before.chain->revision &&
              runtime->ReadMetadata(1 << 20, metadata, root, error) ==
                  DevelopmentRuntimeResult::Progress &&
              metadata == original && root == original_root,
          "facade previews preserve epochs and exact parent state");
    unsigned callbacks = 0;
    env.callback = [&] {
        ++callbacks;
        LocalBlockBuildResult unchanged = LocalBlockBuildResult::StaleParent;
        LocalBlockTemplate untouched;
        untouched.wire = {0x55};
        std::string nested_error;
        Check(runtime->BuildTemplate(request, Limits(), unchanged, untouched,
                                     nested_error) ==
                      DevelopmentRuntimeResult::Busy &&
                  unchanged == LocalBlockBuildResult::StaleParent &&
                  untouched.wire == std::vector<uint8_t>{0x55},
              "facade reentry preserves both typed status and template");
    };
    const auto prepared = runtime->Tick(UINT64_MAX, 0, limits);
    env.callback = {};
    Check(prepared.result == DevelopmentRuntimeResult::Prepared &&
              callbacks == 1,
          "private selector choice survives all nonmutating facade calls");
    const auto pending = runtime->Snapshot();
    Check(runtime->BuildTemplate(request, Limits(), status, out, error) ==
                  DevelopmentRuntimeResult::Progress &&
              status == LocalBlockBuildResult::Inconclusive &&
              out.wire == std::vector<uint8_t>{0x77},
          "facade cannot bypass pending journal and keeps typed local refusal");
    Check(runtime->Snapshot().body_epoch == pending.body_epoch &&
              runtime->Snapshot().context_generation ==
                  pending.context_generation,
          "refused facade does not mutate epochs");
    bool completed = false;
    for (unsigned n = 0; n < 40; ++n) {
        const auto tick = runtime->Tick(UINT64_MAX, 0, limits);
        if (tick.result == DevelopmentRuntimeResult::CompleteTarget) {
            completed = true;
            break;
        }
        Check(tick.result == DevelopmentRuntimeResult::Recovering ||
                  tick.result == DevelopmentRuntimeResult::Progress,
              "facade recovery progresses normally");
    }
    Check(completed, "facade baseline recovery reaches receipt");
    const auto receipt_request = [&] {
        auto next = request;
        DiskStateMetadata state;
        Hash state_root;
        Check(runtime->ReadMetadata(1 << 20, state, state_root, error) ==
                  DevelopmentRuntimeResult::Progress,
              "facade receipt metadata");
        Header parent;
        Check(ParseHeader(state.header.data(), state.header.size(), parent),
              "facade receipt parent");
        next.expected_parent = state.tip;
        next.time = parent.time + 120;
        return next;
    }();
    Check(runtime->BuildTemplate(receipt_request, Limits(), status, out,
                                 error) == DevelopmentRuntimeResult::Progress &&
              status == LocalBlockBuildResult::Inconclusive,
          "facade cannot bypass receipt acknowledgement");
    Check(runtime->Tick(UINT64_MAX, 0, limits).result ==
              DevelopmentRuntimeResult::Acknowledged,
          "facade receipt acknowledges normally");
    DevelopmentRuntime moved(std::move(*runtime));
    status = LocalBlockBuildResult::StaleParent;
    out.wire = {0x77};
    Check(runtime->BuildTemplate(request, Limits(), status, out, error) ==
                  DevelopmentRuntimeResult::Closed &&
              status == LocalBlockBuildResult::StaleParent &&
              out.wire == std::vector<uint8_t>{0x77},
          "closed facade access preserves both outputs");
}
void PendingRecoveryFences() {
    Home home;
    std::string error;
    for (size_t n : {0, 1, 2, 3}) {
        StagedBlockTransition connected;
        Check(ConnectStoredDiskBlock(Bytes(V(n).wire), home.p.header,
                                     home.p.ordinary, home.p.monetary,
                                     home.p.cost, home.store, connected,
                                     error) == CandidateCheckResult::Accepted,
              "real immutable source preparation");
    }
    for (size_t n : {4, 7, 8})
        Check(AdmitDevelopmentHeader(runtime_fixture::HeaderOf(V(n)),
                                     home.p.header, home.p.ordinary,
                                     home.p.monetary, home.p.cost, home.store,
                                     error) == HeaderAdmission::Stored,
              "real invalid-middle header preparation");
    ReorgBodySource bodies = [](const Hash &id, uint64_t cap,
                                std::vector<uint8_t> &out, std::string &) {
        for (size_t n : {4, 7, 8})
            if (H(V(n).id) == id) {
                const auto wire = Bytes(V(n).wire);
                if (wire.size() > cap) return ReorgBodyResult::CapacityRefused;
                out = wire;
                return ReorgBodyResult::Found;
            }
        return ReorgBodyResult::Missing;
    };
    ReorgProgress progress;
    Check(PrepareDevelopmentSwitch(home.store.Metadata().tip, H(V(8).id),
                                   UINT64_MAX, 0, runtime_fixture::Limits(),
                                   home.p, bodies, home.store, progress,
                                   error) == ReorgResult::Prepared,
          "real pending journal setup");
    auto refuse = [&](const char *label) {
        const auto before = Raw(home);
        LocalBlockTemplate out;
        out.wire = {0x77};
        Check(BuildLocalDiskBlockTemplate(
                  Request(home), Limits(), home.p.header, home.p.ordinary,
                  home.p.monetary, home.p.cost, home.store, out,
                  error) == LocalBlockBuildResult::Inconclusive &&
                  out.wire == std::vector<uint8_t>{0x77},
              label);
        Check(Raw(home) == before, "pending fence changes no raw state key");
    };
    refuse("assembler cannot bypass pending recovery journal");
    bool restored = false;
    for (unsigned n = 0; n < 40; ++n) {
        const auto result =
            StepDevelopmentSwitch(UINT64_MAX, 0, runtime_fixture::Limits(),
                                  home.p, home.store, progress, error);
        if (result == ReorgResult::RestoredSource) {
            restored = true;
            break;
        }
        Check(result == ReorgResult::Progress,
              "real recovery restores source before receipt fence");
    }
    Check(restored, "invalid middle source restored");
    refuse("assembler cannot bypass unacknowledged receipt");
    DiskStateError failure;
    std::optional<CandidateTerminalReceipt> receipt;
    Check(home.store.ReadCandidateReceipt(receipt, failure) && receipt &&
              receipt->failure,
          "actual deterministic receipt for propagation gate");
    Check(home.store.AcknowledgeCandidateReceipt(receipt->id,
                                                 receipt->stable_tip, failure),
          failure.message);
    refuse("assembler cannot bypass pending invalidity propagation");
    bool complete = false;
    for (unsigned n = 0; n < 20; ++n) {
        CandidateInvalidationProgress next;
        Check(home.store.StepCandidateInvalidation({1, 1000, 1000, 1 << 20},
                                                   next, failure),
              failure.message);
        if (next.complete) {
            complete = true;
            break;
        }
    }
    Check(complete, "bounded invalidity propagation completed");
    Build(home, Request(home));
}
} // namespace
int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--exceptions") {
            BuilderExceptionsAreClassified();
            std::cout << "builder exception classification tests passed\n";
            return 0;
        }
        SignedMatureParentChild();
        InsufficientAndResourceRefusals();
        BuilderExceptionsAreClassified();
        NonceBoundaries();
        PendingRecoveryFences();
        RuntimePreviewFacade();
        std::cout << "local block assembler signed integration tests passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
