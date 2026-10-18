// Copyright (c) 2026 The Lotus developers
#include "development_runtime.h"
#include "development_runtime_test/fixtures.h"
#include <functional>
#include <iostream>
#include <leveldb/env.h>
using namespace lotus::v2;
using namespace runtime_fixture;
namespace {
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
DevelopmentTickLimits TickLimits() {
    DevelopmentTickLimits limits;
    limits.selection.query = {64, 20000, 20000, 1 << 20};
    limits.selection.fork = {8, 8, 1000};
    limits.selection.max_probe_calls = 128;
    limits.selection.max_probe_bytes = 1 << 20;
    limits.selection.max_missing_bodies = 8;
    limits.selection.max_resident_bytes = 1 << 20;
    limits.recovery = runtime_fixture::Limits();
    limits.propagation = {1, 1000, 1000, 1 << 20};
    return limits;
}
void Seed(Home &home, bool guard = false) {
    for (size_t n : (guard ? std::vector<size_t>{9, 10, 11, 12}
                           : std::vector<size_t>{0, 1, 2, 3})) {
        home.Connect(n);
        home.Open();
        home.Match(n);
    }
    home.store = {};
}
std::unique_ptr<DevelopmentRuntime> Open(DevelopmentRuntimeConfig config) {
    std::unique_ptr<DevelopmentRuntime> out;
    std::string error;
    Check(DevelopmentRuntime::Open(std::move(config), out, error) && out,
          "open explicit runtime: " + error);
    return out;
}
void Announce(DevelopmentRuntime &runtime, const std::vector<size_t> &path,
              bool bodies = true) {
    std::string error;
    for (size_t n : path) {
        HeaderAdmission admitted = HeaderAdmission::Invalid;
        Check(runtime.AdmitHeader(HeaderOf(V(n)), admitted, error) ==
                      DevelopmentRuntimeResult::Progress &&
                  admitted == HeaderAdmission::Stored,
              "runtime contextual header admission: " + error);
        if (!bodies) continue;
        CandidateBodyStatus retained = CandidateBodyStatus::Malformed;
        Check(runtime.RetainBody(H(V(n).id), Bytes(V(n).wire), retained,
                                 error) == DevelopmentRuntimeResult::Progress &&
                  retained == CandidateBodyStatus::RetainedAuthenticated,
              "pool retains replacement bytes without contextual acceptance: " +
                  error);
    }
}
DevelopmentTick Tick(DevelopmentRuntime &runtime, uint64_t now = UINT64_MAX,
                     const DevelopmentTickLimits &limits = TickLimits()) {
    auto tick = runtime.Tick(now, 0, limits);
    Check(tick.usage.recovery_calls <= 1,
          "one recovery phase/block transition per tick");
    Check(tick.usage.selection.query.rows <= limits.selection.query.max_rows &&
              tick.usage.selection.query.reads <=
                  limits.selection.query.max_reads &&
              tick.usage.selection.query.iterator_steps <=
                  limits.selection.query.max_iterator_steps &&
              tick.usage.selection.query.decoded_bytes <=
                  limits.selection.query.max_decoded_bytes &&
              tick.usage.selection.probe_calls <=
                  limits.selection.max_probe_calls,
          "selector reports its own bounded usage");
    Check(tick.usage.propagation.rows <= limits.propagation.max_rows &&
              tick.usage.propagation.reads <= limits.propagation.max_reads &&
              tick.usage.propagation.iterator_steps <=
                  limits.propagation.max_iterator_steps &&
              tick.usage.propagation.decoded_bytes <=
                  limits.propagation.max_decoded_bytes,
          "propagation reports its own bounded usage");
    Check(tick.result != DevelopmentRuntimeResult::StorageError &&
              tick.result != DevelopmentRuntimeResult::InvalidConfiguration,
          "runtime tick: " + tick.diagnostic);
    return tick;
}
DiskStateMetadata Metadata(DevelopmentRuntime &runtime, Hash &root) {
    DiskStateMetadata metadata;
    std::string error;
    Check(runtime.ReadMetadata(1 << 20, metadata, root, error) ==
              DevelopmentRuntimeResult::Progress,
          "bounded runtime metadata: " + error);
    const auto total = metadata.header.size() + metadata.monetary.size() +
                       metadata.auxiliary.size();
    Check(total > metadata.auxiliary.size(), "metadata has header/money payload");
    DiskStateMetadata bounded;
    bounded.header = {0x42};
    Hash sentinel{};
    sentinel[0] = 0x42;
    for (const auto cap : {metadata.auxiliary.size(), total - 1}) {
        auto untouched_root = sentinel;
        Check(runtime.ReadMetadata(cap, bounded, untouched_root, error) ==
                  DevelopmentRuntimeResult::CapacityRefused &&
                  bounded.header == std::vector<uint8_t>{0x42} &&
                  untouched_root == sentinel,
              "metadata combined payload cap preserves outputs");
    }
    Hash exact_root;
    Check(runtime.ReadMetadata(total, bounded, exact_root, error) ==
                  DevelopmentRuntimeResult::Progress &&
                  bounded.header == metadata.header &&
                  bounded.monetary == metadata.monetary &&
                  bounded.auxiliary == metadata.auxiliary && exact_root == root,
          "metadata exact combined payload cap");
    return metadata;
}
void Match(DevelopmentRuntime &runtime, size_t n) {
    const auto &v = V(n);
    Hash root;
    const auto meta = Metadata(runtime, root);
    Check(meta.tip == H(v.id) && root == H(v.root) &&
              meta.monetary == Bytes(v.monetary),
          "runtime exact reference tip/root/monetary");
    const auto wire = Bytes(v.wire);
    Check(meta.header ==
              std::vector<uint8_t>(wire.begin(), wire.begin() + HEADER_SIZE),
          "runtime exact header commitment");
    std::string error;
    std::vector<uint8_t> body;
    Check(runtime.ReadConnectedBody(meta.tip, 1 << 20, body, error) ==
                  DevelopmentRuntimeResult::Progress &&
              body == wire,
          "connected bytes come from retained disk state");
    const auto snapshot = runtime.Snapshot();
    Check(snapshot.chain && snapshot.chain->stable_tip == meta.tip &&
              snapshot.chain->root == root,
          "runtime authoritative snapshot matches bounded diagnostics");
    std::map<Outpoint, std::vector<uint8_t>, OutpointLess> expected, all;
    for (const auto &encoded : v.coins) {
        auto b = Bytes(encoded);
        expected.emplace(Key(b), b);
    }
    for (const auto &row : vectors)
        for (const auto &encoded : row.coins) {
            auto b = Bytes(encoded);
            all.emplace(Key(b), b);
        }
    for (const auto &[key, ignored] : all) {
        (void)ignored;
        std::optional<Coin> coin;
        Check(runtime.ReadCoin(key, coin, error) ==
                  DevelopmentRuntimeResult::Progress,
              "bounded runtime coin read");
        const auto wanted = expected.find(key);
        Check(bool(coin) == (wanted != expected.end()),
              "runtime all touched coin presence");
        if (coin) {
            std::vector<uint8_t> encoded;
            Check(EncodeCoin(*coin, encoded) && encoded == wanted->second,
                  "runtime exact CoinEntry");
        }
        CoinProof proof;
        Check(runtime.ProveCoin(key, proof, error) ==
                      DevelopmentRuntimeResult::Progress &&
                  VerifyCoinProof(key, proof, root),
              "runtime touched coin proof");
    }
    std::vector<Hash> locator;
    DiskStateError failure;
    Check(runtime.BuildLocator(meta.tip, 16, locator, failure) ==
                  ChainIndexResult::Complete &&
              !locator.empty() && locator.front() == meta.tip,
          "runtime bounded active locator");
    std::vector<Header> headers;
    const Hash genesis = runtime_fixture::Profiles().header.genesis_id;
    Check(runtime.ReadHeaders(meta.tip, std::span<const Hash>(&genesis, 1),
                              Hash{}, 1, 16, headers,
                              failure) == ChainIndexResult::Complete &&
              headers.size() == HeaderOf(v).height,
          "runtime bounded active header sequence");
    Check(!headers.empty() &&
              headers.back().state_root == HeaderOf(v).state_root,
          "runtime active headers reach reference checkpoint");
}
DevelopmentTick Until(DevelopmentRuntime &runtime,
                      DevelopmentRuntimeResult wanted, unsigned max = 80) {
    for (unsigned n = 0; n < max; ++n) {
        auto tick = Tick(runtime);
        if (tick.result == wanted) return tick;
    }
    throw std::runtime_error("runtime did not reach bounded expected result");
}
DevelopmentBodyChunk Chunk(DevelopmentRuntime &runtime, const Hash &id,
                           uint64_t offset, uint64_t length,
                           DevelopmentBodyChunkUsage &usage) {
    DevelopmentBodyChunk chunk;
    std::string error;
    Check(runtime.ReadConnectedBodyChunk(id, 1 << 20, offset, length, chunk,
                                         error, &usage) ==
              DevelopmentRuntimeResult::Progress,
          "bounded connected body chunk: " + error);
    Check(usage.view_calls == 1 && chunk.bytes.size() <= length &&
              chunk.bytes.size() <= 65536 &&
              usage.copied_bytes == chunk.bytes.size() &&
              SameDevelopmentBodyAuthority(chunk.snapshot, runtime.Snapshot()),
          "one authority observation and bounded slice copy");
    return chunk;
}
void BodyChunkAuthority() {
    DevelopmentRuntimeSnapshot original;
    original.body_epoch = 7;
    original.context_generation = 11;
    original.chain.emplace();
    Check(SameDevelopmentBodyAuthority(original, original),
          "quiescent authority matches itself");
    for (unsigned field = 0; field < 14; ++field) {
        auto changed = original;
        switch (field) {
            case 0: ++changed.body_epoch; break;
            case 1: ++changed.context_generation; break;
            case 2: ++changed.chain->identity[0]; break;
            case 3: ++changed.chain->profile_digest[0]; break;
            case 4: ++changed.chain->stable_tip[0]; break;
            case 5: ++changed.chain->root[0]; break;
            case 6: ++changed.chain->revision; break;
            case 7: ++changed.chain->invalid_epoch; break;
            case 8: changed.reopen_required = true; break;
            case 9: changed.execution_paused = true; break;
            case 10: changed.chain->pending_journal = true; break;
            case 11: changed.chain->pending_receipt = true; break;
            case 12: changed.chain->pending_propagation = true; break;
            case 13: changed.chain.reset(); break;
        }
        Check(!SameDevelopmentBodyAuthority(original, changed) &&
                  !SameDevelopmentBodyAuthority(changed, original),
              "every authority field and unavailable state fences publication");
    }
}
void ConnectedBodyChunks() {
    Home home;
    Seed(home);
    auto config = Config(home);
    auto runtime = Open(config);
    const auto id = H(V(3).id);
    const auto wire = Bytes(V(3).wire);
    DevelopmentBodyChunkUsage usage;
    std::vector<uint8_t> reconstructed;
    uint64_t loads = 0, hits = 0;
    for (uint64_t offset = 0; offset < wire.size(); offset += 7) {
        const auto chunk = Chunk(*runtime, id, offset, 7, usage);
        Check(chunk.total_bytes == wire.size(), "chunk reports full wire length");
        reconstructed.insert(reconstructed.end(), chunk.bytes.begin(), chunk.bytes.end());
        loads += usage.body_load_attempts;
        hits += usage.cache_hits;
    }
    Check(reconstructed == wire && loads == 1 && hits > 1,
          "many chunks reuse exactly one actual retained-body validation");
    auto eof = Chunk(*runtime, id, wire.size(), 65536, usage);
    Check(eof.bytes.empty() && eof.total_bytes == wire.size() &&
              usage.body_load_attempts == 0 && usage.cache_hits == 1,
          "exact end succeeds with empty EOF slice");
    DevelopmentBodyChunk untouched;
    untouched.total_bytes = 42;
    untouched.bytes = {0x42};
    untouched.snapshot.body_epoch = 42;
    std::string error;
    const auto unchanged = [&] {
        Check(untouched.total_bytes == 42 && untouched.bytes == std::vector<uint8_t>{0x42} &&
                  untouched.snapshot.body_epoch == 42,
              "chunk refusal preserves all output fields");
    };
    Check(runtime->ReadConnectedBodyChunk(id, wire.size() - 1, 0, 7,
                                          untouched, error, &usage) ==
              DevelopmentRuntimeResult::CapacityRefused &&
              usage.cache_hits == 1 && usage.body_load_attempts == 0,
          "cache hit obeys current smaller full-body cap");
    unchanged();
    Chunk(*runtime, id, 0, 7, usage);
    Check(usage.cache_hits == 1, "cap refusal need not evict verified matching entry");
    Check(runtime->ReadConnectedBodyChunk(id, 1 << 20, wire.size() + 1, 7,
                                          untouched, error, &usage) ==
              DevelopmentRuntimeResult::InvalidConfiguration &&
              error == "readblock offset exceeds body size",
          "past-end hit retains invalid-request classification");
    unchanged();
    for (uint64_t length : {uint64_t{0}, uint64_t{65537}}) {
        usage = {42, 42, 42, 42};
        Check(runtime->ReadConnectedBodyChunk(id, 1 << 20, 0, length,
                                              untouched, error, &usage) ==
                  DevelopmentRuntimeResult::InvalidConfiguration &&
                  usage.view_calls == 0 && usage.body_load_attempts == 0 &&
                  usage.cache_hits == 0 && usage.copied_bytes == 0,
              "invalid lengths perform no observation or body load");
        unchanged();
    }
    // Failed replacement must discard the previous entry, and an invalid
    // range on a cold load must not install the newly validated bytes.
    Check(runtime->ReadConnectedBodyChunk(Hash{}, 1 << 20, 0, 7,
                                          untouched, error, &usage) ==
              DevelopmentRuntimeResult::MissingHeader && usage.cache_hits == 0,
          "missing replacement refuses before retained-body validation");
    unchanged();
    Chunk(*runtime, id, 0, 65536, usage);
    Check(usage.body_load_attempts == 1 && usage.cache_hits == 0,
          "failed replacement released the previous cache entry");
    const auto other = H(V(2).id);
    Check(runtime->ReadConnectedBodyChunk(other, 1 << 20, Bytes(V(2).wire).size() + 1,
                                          7, untouched, error, &usage) ==
              DevelopmentRuntimeResult::InvalidConfiguration &&
              usage.body_load_attempts == 1 && usage.cache_hits == 0,
          "cold invalid range validates bytes but installs nothing");
    unchanged();
    Chunk(*runtime, other, 0, 7, usage);
    Check(usage.body_load_attempts == 1, "invalid range did not populate cache");
    Check(runtime->ReadConnectedBodyChunk(id, 1, 0, 7, untouched, error, &usage) ==
              DevelopmentRuntimeResult::CapacityRefused &&
              usage.body_load_attempts == 1,
          "cold full-body cap refusal cannot install a cache entry");
    unchanged();
    Chunk(*runtime, id, 0, 7, usage);
    Check(usage.body_load_attempts == 1, "cold capacity refusal did not populate cache");
    const auto before = runtime->Snapshot();
    Announce(*runtime, {4});
    Check(runtime->ReadConnectedBodyChunk(H(V(4).id), 1 << 20, 0, 7,
                                          untouched, error, &usage) ==
              DevelopmentRuntimeResult::MissingBody &&
              usage.body_load_attempts == 0,
          "pool-only authenticated body is never served as connected");
    unchanged();
    auto reloaded = Chunk(*runtime, id, 0, 7, usage);
    Check(usage.body_load_attempts == 1 &&
              !SameDevelopmentBodyAuthority(before, reloaded.snapshot),
          "body inventory and context generation invalidate cached bytes");
    runtime.reset();
    auto mismatch = config;
    ++mismatch.profiles.monetary.genesis_tail;
    Check(!DevelopmentRuntime::Open(mismatch, runtime, error) && !runtime,
          "different validator profile cannot adopt previous cached authority");
    runtime = Open(config);
    Chunk(*runtime, id, 0, 7, usage);
    Check(usage.body_load_attempts == 1, "fresh owner cannot reuse old-profile cache");
}
void HeavierSelectionAndStaleChoices() {
    Home home;
    Seed(home);
    auto runtime = Open(Config(home));
    Announce(*runtime, {4, 5, 6});
    std::string error;
    std::vector<uint8_t> body;
    Check(runtime->ReadBody(H(V(6).id), 1 << 20, body, error) ==
                  DevelopmentRuntimeResult::Progress &&
              body == Bytes(V(6).wire),
          "replacement body is available only from pool before acceptance");
    Check(runtime->ReadConnectedBody(H(V(6).id), 1 << 20, body, error) ==
              DevelopmentRuntimeResult::MissingBody,
          "pool-only body is not served as connected");
    bool ready = false;
    for (unsigned calls = 0; calls < 40; ++calls) {
        auto tick = Tick(*runtime);
        if (tick.choices && tick.choices->best_ready) {
            Check(tick.choices->best_ready->target == H(V(6).id) &&
                      tick.choices->best_ready->fork.disconnect.size() == 2 &&
                      tick.choices->best_ready->fork.connect.size() == 3,
                  "runtime ranks strictly heavier real fork");
            ready = true;
            break;
        }
    }
    Check(ready, "runtime produced ready observation");
    const auto observed = runtime->Snapshot();
    CandidateBodyStatus status = CandidateBodyStatus::Malformed;
    Check(runtime->EvictBody(H(V(6).id), status, error) ==
                  DevelopmentRuntimeResult::Progress &&
              status == CandidateBodyStatus::Evicted,
          "explicit pool eviction");
    Check(runtime->Snapshot().body_epoch > observed.body_epoch,
          "body availability invalidates epoch");
    auto stale = Tick(*runtime);
    Check(stale.result != DevelopmentRuntimeResult::Prepared &&
              stale.snapshot.chain && !stale.snapshot.chain->pending_journal,
          "stale body choice cannot prepare");
    Match(*runtime, 3);
    Check(runtime->RetainBody(H(V(6).id), Bytes(V(6).wire), status, error) ==
              DevelopmentRuntimeResult::Progress,
          "restore missing candidate body");
    ready = false;
    for (unsigned calls = 0; calls < 40; ++calls) {
        auto tick = Tick(*runtime);
        if (tick.choices && tick.choices->best_ready) {
            ready = true;
            break;
        }
    }
    Check(ready, "new epoch obtains fresh ready choice");
    const auto before_context = runtime->Snapshot();
    Announce(*runtime, {7, 8}, false);
    const auto inserted = runtime->Snapshot();
    Check(inserted.context_generation == before_context.context_generation &&
              inserted.body_epoch == before_context.body_epoch &&
              inserted.chain && before_context.chain &&
              inserted.chain->revision > before_context.chain->revision,
          "header insert advances store revision without resetting "
          "context/body inventory epochs");
    stale = Tick(*runtime);
    Check(stale.result != DevelopmentRuntimeResult::Prepared &&
              stale.snapshot.chain && !stale.snapshot.chain->pending_journal,
          "stale context choice cannot prepare");
    auto prepared = Until(*runtime, DevelopmentRuntimeResult::Prepared);
    Check(prepared.usage.copied_body_bytes == Bytes(V(4).wire).size() +
                                                  Bytes(V(5).wire).size() +
                                                  Bytes(V(6).wire).size(),
          "prepare body-provider copies cover replacements only");
    auto complete = Until(*runtime, DevelopmentRuntimeResult::CompleteTarget);
    Check(complete.snapshot.chain && complete.snapshot.chain->pending_receipt &&
              !complete.snapshot.chain->pending_journal,
          "runtime terminal step exposes receipt gate");
    Match(*runtime, 6);
    auto ack = Tick(*runtime);
    Check(ack.result == DevelopmentRuntimeResult::Acknowledged &&
              ack.snapshot.chain && !ack.snapshot.chain->pending_receipt,
          "receipt acknowledgement consumes separate runtime tick");
    DevelopmentBodyChunkUsage usage;
    auto detached = Chunk(*runtime, H(V(3).id), 0, 65536, usage);
    Check(detached.bytes == Bytes(V(3).wire) && usage.body_load_attempts == 1,
          "detached previously connected body remains available under new stamp");
    runtime.reset();
    home.Open();
    home.Match(6);
}
void InvalidMiddleRestoration() {
    Home home;
    Seed(home);
    const auto source_id = H(V(3).id);
    auto runtime = Open(Config(home));
    Hash original_root;
    const auto original_metadata = Metadata(*runtime, original_root);
    Announce(*runtime, {4, 7, 8});
    DevelopmentBodyChunkUsage usage;
    const auto original_chunk = Chunk(*runtime, source_id, 0, 7, usage);
    Until(*runtime, DevelopmentRuntimeResult::Prepared);
    std::string error;
    DevelopmentBodyChunk blocked;
    blocked.bytes = {0x42};
    Check(runtime->ReadConnectedBodyChunk(source_id, 1 << 20, 0, 7,
                                          blocked, error, &usage) ==
              DevelopmentRuntimeResult::Recovering && usage.view_calls == 1 &&
              usage.body_load_attempts == 0 && blocked.bytes == std::vector<uint8_t>{0x42},
          "prepared journal fences a previously cached source body");
    // J owns full replacement copies; the three-slot pool never held a source
    // body and may now be emptied before deterministic failure/restoration.
    for (size_t n : {4, 7, 8}) {
        CandidateBodyStatus out;
        Check(runtime->EvictBody(H(V(n).id), out, error) ==
                  DevelopmentRuntimeResult::Progress,
              "release volatile replacement bytes after journal pins");
    }
    auto restored = Until(*runtime, DevelopmentRuntimeResult::RestoredSource);
    Check(restored.snapshot.chain && restored.snapshot.chain->pending_receipt &&
              restored.snapshot.chain->invalid_root_count == 0,
          "source restoration precedes invalidity acknowledgement");
    Check(runtime->ReadConnectedBodyChunk(source_id, 1 << 20, 0, 7,
                                          blocked, error, &usage) ==
              DevelopmentRuntimeResult::Recovering && usage.body_load_attempts == 0 &&
              blocked.bytes == std::vector<uint8_t>{0x42},
          "terminal receipt fences connected chunks");
    Match(*runtime, 3);
    Hash restored_root;
    Check(
        Metadata(*runtime, restored_root) == original_metadata &&
            restored_root == original_root,
        "invalid-middle restoration preserves the exact source metadata bytes");
    HeaderAdmission unchanged = HeaderAdmission::Known;
    Check(runtime->AdmitHeader(HeaderOf(V(5)), unchanged, error) ==
                  DevelopmentRuntimeResult::Inconclusive &&
              unchanged == HeaderAdmission::Known,
          "receipt gate refuses header mutation");
    auto ack = Tick(*runtime);
    Check(ack.result == DevelopmentRuntimeResult::Acknowledged &&
              ack.snapshot.chain && ack.snapshot.chain->pending_propagation &&
              ack.snapshot.chain->invalid_root_count == 1,
          "ack publishes failure and bounded propagation gate");
    Check(runtime->ReadConnectedBodyChunk(source_id, 1 << 20, 0, 7,
                                          blocked, error, &usage) ==
              DevelopmentRuntimeResult::Recovering && usage.body_load_attempts == 0 &&
              blocked.bytes == std::vector<uint8_t>{0x42},
          "invalidity propagation fences connected chunks");
    Check(runtime->AdmitHeader(HeaderOf(V(5)), unchanged, error) ==
              DevelopmentRuntimeResult::Inconclusive,
          "propagation gate refuses header mutation");
    bool done = false;
    for (unsigned calls = 0; calls < 20; ++calls) {
        auto tick = Tick(*runtime);
        Check(tick.result == DevelopmentRuntimeResult::Invalidated,
              "one propagation step per tick");
        if (tick.snapshot.chain && !tick.snapshot.chain->pending_propagation) {
            done = true;
            break;
        }
    }
    Check(done, "bounded invalidity propagation completes");
    const auto restored_chunk = Chunk(*runtime, source_id, 0, 7, usage);
    Check(restored_chunk.bytes == original_chunk.bytes && usage.body_load_attempts == 1 &&
              restored_chunk.snapshot.chain->stable_tip == original_chunk.snapshot.chain->stable_tip &&
              restored_chunk.snapshot.chain->root == original_chunk.snapshot.chain->root &&
              restored_chunk.snapshot.chain->revision != original_chunk.snapshot.chain->revision &&
              !SameDevelopmentBodyAuthority(restored_chunk.snapshot, original_chunk.snapshot),
          "real source restoration ABA reloads bytes under a new revision and invalidity epoch");
    std::optional<Hash> causal;
    Check(runtime->ReadInvalidity(H(V(8).id), causal, error) ==
                  DevelopmentRuntimeResult::Progress &&
              causal && *causal == H(V(7).id),
          "runtime descendant exclusion retains causal root");
    Check(runtime->ReadInvalidity(source_id, causal, error) ==
                  DevelopmentRuntimeResult::Progress &&
              !causal,
          "restored source is never marked invalid");
    Match(*runtime, 3);
    runtime.reset();
    home.Open();
    home.Match(3);
}
void InconclusivePausedRecovery() {
    auto profiles = Profiles();
    profiles.ordinary.vm.max_steps = 1;
    Home home(32 << 20, profiles);
    Seed(home, true);
    auto runtime = Open(Config(home));
    Announce(*runtime, {13, 14, 15});
    Until(*runtime, DevelopmentRuntimeResult::Prepared);
    auto paused = Until(*runtime, DevelopmentRuntimeResult::Inconclusive);
    Check(paused.snapshot.execution_paused && paused.snapshot.chain &&
              paused.snapshot.chain->pending_journal &&
              !paused.snapshot.chain->pending_receipt &&
              paused.snapshot.chain->invalid_root_count == 0,
          "host guard pauses with J and no invalid fact");
    DevelopmentBodyChunk blocked;
    blocked.bytes = {0x42};
    DevelopmentBodyChunkUsage usage;
    std::string error;
    Check(runtime->ReadConnectedBodyChunk(H(V(10).id), 1 << 20, 0, 7,
                                          blocked, error, &usage) ==
              DevelopmentRuntimeResult::Inconclusive && usage.view_calls == 1 &&
              usage.body_load_attempts == 0 && blocked.bytes == std::vector<uint8_t>{0x42},
          "paused execution cannot authorize cached chunks");
    Match(*runtime, 10);
    Hash root;
    const auto before = Metadata(*runtime, root);
    auto again = Tick(*runtime);
    Check(again.result == DevelopmentRuntimeResult::Inconclusive &&
              again.usage.recovery_calls == 0,
          "paused execution does not repeatedly validate without retry");
    Check(runtime->RetryPausedExecution(),
          "explicit retry clears local pause only");
    again = Tick(*runtime);
    Check(again.result == DevelopmentRuntimeResult::Inconclusive &&
              again.usage.recovery_calls == 1,
          "explicit retry reaches same host guard");
    Hash after;
    Check(Metadata(*runtime, after) == before && after == root,
          "retry preserves exact checkpoint");
    runtime.reset();
    home.Open();
    std::optional<std::vector<uint8_t>> journal;
    DiskStateError failure;
    Check(
        home.store.ReadRecoveryJournal(
            runtime_fixture::Limits().max_journal_bytes, journal, failure) &&
            journal,
        "bounded closed-runtime diagnostic reads actual inconclusive journal");
    home.store = {};
    auto reopened = Open(Config(home));
    again = Tick(*reopened);
    Check(again.result == DevelopmentRuntimeResult::Inconclusive &&
              again.snapshot.chain && again.snapshot.chain->pending_journal &&
              again.snapshot.chain->invalid_root_count == 0,
          "fresh runtime reopens authoritative inconclusive journal");
    Match(*reopened, 10);
    reopened.reset();
    home.Open();
    std::optional<std::vector<uint8_t>> after_journal;
    Check(home.store.ReadRecoveryJournal(
              runtime_fixture::Limits().max_journal_bytes, after_journal,
              failure) &&
              after_journal == journal,
          "fresh runtime inconclusive retry preserves exact raw journal bytes");
}
void HeaderInsertionKeepsBoundedScan() {
    Home home;
    for (size_t n : {0, 1}) {
        home.Connect(n);
        home.Open();
    }
    home.store = {};
    auto runtime = Open(Config(home));
    Announce(*runtime, {4});
    auto limits = TickLimits();
    limits.selection.query.max_rows = 1;
    limits.selection.max_probe_calls = 1;
    for (size_t header : {5, 6}) {
        auto tick = Tick(*runtime, UINT64_MAX, limits);
        Check(
            tick.result == DevelopmentRuntimeResult::Progress,
            "one-row scan remains bounded before competitive prefix completes");
        const auto before = runtime->Snapshot();
        Announce(*runtime, {header}, false);
        const auto after = runtime->Snapshot();
        Check(after.body_epoch == before.body_epoch &&
                  after.context_generation == before.context_generation &&
                  after.chain && before.chain &&
                  after.chain->revision > before.chain->revision,
              "header insertion preserves partial scan inventory namespace");
    }
    bool finished = false;
    for (unsigned calls = 0; calls < 80; ++calls) {
        auto tick = Tick(*runtime, UINT64_MAX, limits);
        if (tick.result != DevelopmentRuntimeResult::Progress) {
            Check(tick.result == DevelopmentRuntimeResult::NeedBodies ||
                      tick.result == DevelopmentRuntimeResult::Prepared,
                  "finite insertion workload completes a bounded competitive "
                  "pass");
            finished = true;
            break;
        }
    }
    Check(
        finished,
        "bounded selector pass does not restart forever after insertions stop");
}
class FaultEnv final : public leveldb::EnvWrapper {
public:
    bool fail_after_sync = false;
    unsigned failures = 0;
    std::function<void()> on_sync;
    FaultEnv() : EnvWrapper(leveldb::Env::Default()) {}
    class File final : public leveldb::WritableFile {
        FaultEnv &owner;
        std::unique_ptr<leveldb::WritableFile> file;

    public:
        File(FaultEnv &env, leveldb::WritableFile *raw)
            : owner(env), file(raw) {}
        std::string GetName() const override { return file->GetName(); }
        leveldb::Status Append(const leveldb::Slice &bytes) override {
            return file->Append(bytes);
        }
        leveldb::Status Flush() override { return file->Flush(); }
        leveldb::Status Close() override { return file->Close(); }
        leveldb::Status Sync() override {
            if (owner.on_sync) owner.on_sync();
            const auto status = file->Sync();
            if (status.ok() && owner.fail_after_sync) {
                owner.fail_after_sync = false;
                ++owner.failures;
                return leveldb::Status::IOError(
                    "injected reported failure after durable sync");
            }
            return status;
        }
    };
    leveldb::Status NewWritableFile(const std::string &name,
                                    leveldb::WritableFile **out) override {
        auto status = target()->NewWritableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return status;
    }
    leveldb::Status NewAppendableFile(const std::string &name,
                                      leveldb::WritableFile **out) override {
        auto status = target()->NewAppendableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return status;
    }
};
void ReentryAndAmbiguousWrite() {
    FaultEnv env;
    Home home(32 << 20, Profiles(), true, &env);
    Seed(home);
    auto runtime = Open(Config(home));
    Announce(*runtime, {4, 5, 6});
    Until(*runtime, DevelopmentRuntimeResult::Prepared);
    const auto prepared = runtime->Snapshot();
    unsigned callbacks = 0;
    env.on_sync = [&] {
        ++callbacks;
        auto nested = runtime->Tick(UINT64_MAX, 0, TickLimits());
        Check(nested.result == DevelopmentRuntimeResult::Busy &&
                  nested.usage.recovery_calls == 0,
              "stream/storage callback cannot reenter runtime tick");
        CandidateBodyStatus body = CandidateBodyStatus::Pinned;
        std::string error;
        Check(runtime->EvictBody(H(V(6).id), body, error) ==
                      DevelopmentRuntimeResult::Busy &&
                  body == CandidateBodyStatus::Pinned,
              "reentry preserves mutation output");
        HeaderAdmission header = HeaderAdmission::Known;
        Check(runtime->AdmitHeader(HeaderOf(V(7)), header, error) ==
                      DevelopmentRuntimeResult::Busy &&
                  header == HeaderAdmission::Known,
              "header reentry is refused before publication");
        Check(!runtime->RetryPausedExecution(),
              "reentry cannot alter execution pause");
        DevelopmentBodyChunk chunk;
        chunk.bytes = {0x42};
        DevelopmentBodyChunkUsage usage{42, 42, 42, 42};
        Check(runtime->ReadConnectedBodyChunk(H(V(3).id), 1 << 20, 0, 7,
                                              chunk, error, &usage) ==
                  DevelopmentRuntimeResult::Busy && usage.view_calls == 0 &&
                  usage.body_load_attempts == 0 && chunk.bytes == std::vector<uint8_t>{0x42},
              "reentrant chunk read refuses before observation or cache access");
        DiskStateMetadata metadata;
        metadata.tip = H(V(6).id);
        Hash root = H(V(6).root);
        Check(runtime->ReadMetadata(1 << 20, metadata, root, error) ==
                      DevelopmentRuntimeResult::Busy &&
                  metadata.tip == H(V(6).id) && root == H(V(6).root),
              "read reentry preserves output");
    };
    env.fail_after_sync = true;
    auto failed = Tick(*runtime);
    env.on_sync = {};
    Check(callbacks == 1 && env.failures == 1 &&
              failed.result == DevelopmentRuntimeResult::ReopenRequired &&
              failed.snapshot.reopen_required && !failed.snapshot.chain,
          "ambiguous write drops cached checkpoint authority");
    DiskStateMetadata untouched;
    untouched.tip = H(V(6).id);
    Hash untouched_root = H(V(6).root);
    std::string error;
    Check(runtime->ReadMetadata(1 << 20, untouched, untouched_root, error) ==
                  DevelopmentRuntimeResult::ReopenRequired &&
              untouched.tip == H(V(6).id) && untouched_root == H(V(6).root),
          "poisoned runtime never returns cached metadata as authoritative");
    DevelopmentBodyChunk poisoned;
    poisoned.bytes = {0x42};
    DevelopmentBodyChunkUsage usage;
    Check(runtime->ReadConnectedBodyChunk(H(V(3).id), 1 << 20, 0, 7,
                                          poisoned, error, &usage) ==
              DevelopmentRuntimeResult::ReopenRequired && usage.view_calls == 0 &&
              usage.body_load_attempts == 0 && poisoned.bytes == std::vector<uint8_t>{0x42},
          "faulted runtime never publishes cached chunks");
    auto reopened = Tick(*runtime);
    Check(reopened.result == DevelopmentRuntimeResult::Reopened &&
              reopened.usage.reopened && reopened.usage.recovery_calls == 0 &&
              reopened.snapshot.chain &&
              reopened.snapshot.body_epoch > prepared.body_epoch &&
              reopened.snapshot.context_generation >
                  prepared.context_generation,
          "reopen consumes one tick and invalidates old context/availability "
          "observations");
    // The injected Sync succeeded before reporting failure: authoritative
    // reopen must observe the first detach, rather than replaying it from
    // cached source.
    Match(*runtime, 2);
    Until(*runtime, DevelopmentRuntimeResult::CompleteTarget);
    Match(*runtime, 6);
    Check(Tick(*runtime).result == DevelopmentRuntimeResult::Acknowledged,
          "reopened attempt completes normally");
}
void CapsAndCounterExhaustion() {
    Home home;
    Seed(home);
    auto config = Config(home);
    config.bodies.max_bodies = 1;
    auto runtime = Open(config);
    Announce(*runtime, {4});
    Announce(*runtime, {5}, false);
    const auto before = runtime->Snapshot();
    CandidateBodyStatus status = CandidateBodyStatus::Pinned;
    std::string error;
    Check(runtime->RetainBody(H(V(5).id), Bytes(V(5).wire), status, error) ==
                  DevelopmentRuntimeResult::CapacityRefused &&
              status == CandidateBodyStatus::CapacityRefused,
          "pool count cap is operational");
    const auto after = runtime->Snapshot();
    Check(after.body_epoch == before.body_epoch &&
              after.context_generation == before.context_generation &&
              after.chain && before.chain &&
              after.chain->revision == before.chain->revision,
          "capacity refusal preserves body/context/store counters");
    auto limits = TickLimits();
    limits.selection.query.max_decoded_bytes = 1;
    const auto refused = Tick(*runtime, UINT64_MAX, limits);
    Check(refused.result == DevelopmentRuntimeResult::CapacityRefused &&
              refused.snapshot.chain &&
              !refused.snapshot.chain->pending_journal &&
              refused.snapshot.chain->invalid_root_count == 0,
          "selector cap never starts recovery or marks invalid");
    Match(*runtime, 3);
    runtime.reset();
    for (bool body : {false, true}) {
        config = Config(home);
        if (body)
            config.initial_body_epoch = UINT64_MAX;
        else
            config.initial_context_generation = UINT64_MAX;
        std::unique_ptr<DevelopmentRuntime> invalid;
        Check(!DevelopmentRuntime::Open(config, invalid, error) && !invalid,
              "exhausted initial counter is refused before store mutation");
        home.Open();
        home.Match(3);
        home.store = {};
    }
    for (bool body : {false, true}) {
        config = Config(home);
        if (body)
            config.initial_body_epoch = UINT64_MAX - 1;
        else
            config.initial_context_generation = UINT64_MAX - 1;
        runtime = Open(config);
        status = CandidateBodyStatus::Malformed;
        Check(runtime->RetainBody(H(V(4).id), Bytes(V(4).wire), status,
                                  error) == DevelopmentRuntimeResult::Progress,
              "last available inventory/context increment succeeds");
        const auto exhausted = runtime->Snapshot();
        Check((body ? exhausted.body_epoch : exhausted.context_generation) ==
                  UINT64_MAX,
              "inventory/context counter reaches maximum without wrap");
        Check(
            runtime->RetainBody(H(V(5).id), Bytes(V(5).wire), status, error) ==
                DevelopmentRuntimeResult::CapacityRefused,
            "counter exhaustion refuses mutation before pool/store changes");
        const auto refused = runtime->Snapshot();
        Check(refused.body_epoch == exhausted.body_epoch &&
                  refused.context_generation == exhausted.context_generation &&
                  refused.chain && exhausted.chain &&
                  refused.chain->revision == exhausted.chain->revision,
              "exhausted counters and store revision remain unchanged");
        Match(*runtime, 3);
        runtime.reset();
    }
}
} // namespace
int main() {
    try {
        BodyChunkAuthority();
        ConnectedBodyChunks();
        HeavierSelectionAndStaleChoices();
        InvalidMiddleRestoration();
        InconclusivePausedRecovery();
        HeaderInsertionKeepsBoundedScan();
        ReentryAndAmbiguousWrite();
        CapsAndCounterExhaustion();
        std::cout
            << "development runtime real-block integration tests passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
