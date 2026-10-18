// Copyright (c) 2026 The Lotus developers
// Storage mechanics fixtures: contextual consensus/body validity is caller-owned.
#include "disk_state.h"
#include "block_transition.h"
#include "vendor/blake3/blake3.h"
#include <algorithm>
#include <leveldb/db.h>
#include <leveldb/env.h>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
using namespace lotus::v2;
namespace {
void Check(bool ok, const std::string &message) {
    if (!ok) { std::cerr << "V2 candidate store: " << message << '\n'; std::exit(1); }
}
void Ok(bool ok, const DiskStateError &error, const char *message) {
    Check(ok, std::string(message) + ": " + error.message);
}
Hash Tag(uint32_t value) {
    Hash hash{}; for (unsigned i = 0; i < 4; ++i) hash[i] = value >> (8 * i); return hash;
}
struct Fixture {
    HeaderChainProfile profile;
    DiskStateOptions options;
    Header genesis;
    Fixture() {
        profile.chain_id = Tag(0x1234); profile.version = 2; profile.genesis_time = 1000;
        profile.genesis_bits = 0x207fffff; profile.half_life_seconds = 172800; profile.spacing_seconds = 120;
        Hash limit; limit.fill(255); Check(DecodeTarget(profile.genesis_bits, limit, profile.pow_limit), "fixture target");
        genesis.version = profile.version; genesis.bits = profile.genesis_bits; genesis.time = profile.genesis_time;
        genesis.size = HEADER_SIZE + 4; genesis.tx_root = Tag(1); genesis.state_root = Tag(2);
        Mine(genesis); profile.genesis_id = Id(genesis);
        options.identity = profile.chain_id; options.profile_digest = Tag(0x5678); options.header_index = profile;
        options.recovery = DiskRecoveryOptions{4096, 65536};
        options.candidates = CandidateStoreOptions{256, 256, 8};
        options.cache_bytes = 1024; options.write_buffer_bytes = 64 << 10;
    }
    Hash Id(const Header &header) const {
        Hash id; Check(BlockId(profile.chain_id, header, id), "fixture block identity"); return id;
    }
    void Mine(Header &header) const {
        Hash target; Check(DecodeTarget(header.bits, profile.pow_limit, target), "fixture mine target");
        while (!MeetsTarget(Id(header), target)) ++header.nonce;
    }
    Header Child(const Header &parent, uint32_t tag, uint64_t time = 0) const {
        Header header; header.prev_id = Id(parent); header.height = parent.height + 1; header.version = profile.version;
        header.bits = profile.genesis_bits; header.time = time ? time : parent.time + 120;
        header.size = HEADER_SIZE + 4; header.tx_root = Tag(tag); header.state_root = Tag(tag ^ 0xabcdef);
        Mine(header); return header;
    }
    DiskStateMetadata Meta(const Header &header) const {
        DiskStateMetadata metadata; metadata.tip = Id(header); std::array<uint8_t, HEADER_SIZE> bytes;
        Check(SerializeHeader(header, bytes), "fixture serialize"); metadata.header.assign(bytes.begin(), bytes.end());
        metadata.monetary = {1, 2, 3}; metadata.auxiliary = {4, 5, 6}; return metadata;
    }
    void Open(const std::string &path, DiskStateStore &store) const {
        DiskStateError error; Ok(DiskStateStore::Open(path, options, {}, store, error), error, "indexed open");
    }
    void Commit(DiskStateStore &store, const Header &header) const {
        DiskStateError error; DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "indexed begin");
        Ok(tx.Commit(Meta(header), header, error), error, "indexed commit");
    }
};
std::optional<std::string> Raw(const std::string &path, const std::string &key,
                               bool write = false, const std::optional<std::string> &value = std::nullopt) {
    std::string error;
    if (write) {
        Check(RawDiskStateAccess(path, std::nullopt, nullptr, {{key, value}}, &error),
              "raw index mutation: " + error);
        return std::nullopt;
    }
    std::optional<std::string> bytes;
    Check(RawDiskStateAccess(path, key, &bytes, {}, &error), "raw index read: " + error);
    return bytes;
}
class FaultEnv : public leveldb::EnvWrapper {
public:
    enum class Fault { None, Append, Sync } fault{Fault::None};
    FaultEnv() : EnvWrapper(leveldb::Env::Default()) {}
    class File : public leveldb::WritableFile {
        FaultEnv &env; std::unique_ptr<leveldb::WritableFile> file;
    public:
        File(FaultEnv &owner, leveldb::WritableFile *raw) : env(owner), file(raw) {}
        std::string GetName() const override { return file->GetName(); }
        leveldb::Status Append(const leveldb::Slice &bytes) override {
            return env.fault == Fault::Append ? leveldb::Status::IOError("index WAL append") : file->Append(bytes);
        }
        leveldb::Status Sync() override { return env.fault == Fault::Sync ? leveldb::Status::IOError("index WAL sync") : file->Sync(); }
        leveldb::Status Flush() override { return file->Flush(); }
        leveldb::Status Close() override { return file->Close(); }
    };
    leveldb::Status NewWritableFile(const std::string &name, leveldb::WritableFile **out) override {
        auto status = target()->NewWritableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out); return status;
    }
    leveldb::Status NewAppendableFile(const std::string &name, leveldb::WritableFile **out) override {
        auto status = target()->NewAppendableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out); return status;
    }
};
Coin CoinAt(uint32_t n) {
    Coin coin; coin.outpoint = {Tag(n), n}; coin.output.value = n;
    coin.output.branches = {Tag(1)}; coin.output.paths = {{0}}; return coin;
}
using Payload = std::vector<uint8_t>;
const CandidateQueryLimits generous{256, 4096, 32768, 4 << 20};
CandidateView View(const DiskStateStore &store) {
    DiskStateError error; CandidateView out; const auto reads = store.LastStats().database_reads;
    Ok(store.ReadCandidateView(out, error), error, "candidate view");
    Check(store.LastStats().database_reads - reads <= CANDIDATE_VIEW_MAX_READS, "fixed view read bound"); return out;
}
std::vector<CandidateRow> All(const DiskStateStore &store, uint64_t rows = 3) {
    DiskStateError error; std::vector<CandidateRow> result; std::optional<CandidateRankCursor> cursor;
    auto limits = generous; limits.max_rows = rows;
    for (unsigned calls = 0; calls < 1024; ++calls) {
        CandidatePage page; CandidateQueryUsage used; const auto reads = store.LastStats().database_reads;
        Ok(store.ReadCandidatePage(cursor, limits, page, error, &used), error, "candidate page");
        Check(used.reads == store.LastStats().database_reads - reads && used.reads == page.used.reads &&
              used.rows == page.rows.size() && used.rows <= rows && used.iterator_steps <= limits.max_iterator_steps &&
              used.decoded_bytes <= limits.max_decoded_bytes, "query exact usage and limits");
        result.insert(result.end(), page.rows.begin(), page.rows.end());
        if (page.complete) return result;
        Check(page.next.has_value() && page.next != cursor, "bounded scan advances"); cursor = page.next;
    }
    Check(false, "bounded test scan terminates"); return {};
}
DiskRecoveryUpdate Update(const DiskStateStore &store, std::optional<Payload> old,
                          std::optional<Payload> next) {
    return {std::move(old), std::move(next), store.Metadata().tip, store.Root(), store.Metadata().tip, std::nullopt};
}
CandidateTerminalReceipt FinishUnknown(DiskStateStore &store, const Hash &target, uint32_t attempt = 99,
                                       CandidateTerminalOutcome outcome = CandidateTerminalOutcome::RestoredSourceUnknown) {
    DiskStateError error; const Payload j{1};
    Ok(store.WriteRecoveryJournal(Update(store, std::nullopt, j), error), error, "prepare unknown receipt");
    Check(!store.WriteRecoveryJournal(Update(store, j, std::nullopt), error) && error.code == DiskStateErrorCode::TransactionAborted,
          "V4 raw terminal clear cannot bypass receipt");
    CandidateTerminalClaim claim{Tag(attempt), store.Metadata().tip, target, 7, outcome, std::nullopt};
    Ok(store.FinishCandidateRecovery(Update(store, j, std::nullopt), claim, error), error, "publish unknown/deferred receipt");
    std::optional<CandidateTerminalReceipt> receipt; Ok(store.ReadCandidateReceipt(receipt, error), error, "read unknown receipt");
    Check(receipt && !receipt->failure && receipt->outcome == outcome, "unknown/deferred never has deterministic fact"); return *receipt;
}
void InventoryAndPages(const std::string &path) {
    Fixture f; DiskStateStore store; f.Open(path, store); DiskStateError error; Check(store.CandidatesEnabled(), "explicit V4 mode");
    f.Commit(store, f.genesis); const auto child = f.Child(f.genesis, 2); f.Commit(store, child);
    auto parent = f.genesis; std::vector<Header> headers;
    for (unsigned n = 0; n < 48; ++n) {
        auto h = f.Child(parent, n + 100); Ok(store.PutCheckedHeader(h, error), error, "admit side header"); headers.push_back(h);
        if (n % 3 == 0) parent = h;
    }
    auto heavy = f.Child(f.genesis, 999); heavy.bits = 0x200fffff; heavy.nonce = 0; f.Mine(heavy);
    Ok(store.PutCheckedHeader(heavy, error), error, "shorter higher-work side header"); headers.push_back(heavy);
    auto rows = All(store); auto expected = rows;
    std::sort(expected.begin(), expected.end(), [](const auto &a, const auto &b) {
        const auto order = CompareChainWork(a.indexed.chain_work, b.indexed.chain_work); return order ? order > 0 : a.id > b.id;
    });
    Check(rows.size() == headers.size() && rows.size() == View(store).candidate_count, "all retained side headers enumerable");
    for (size_t i = 0; i < rows.size(); ++i) Check(rows[i].id == expected[i].id, "descending work then descending ID order");
    const auto before = View(store); Ok(store.PutCheckedHeader(headers.back(), error), error, "duplicate admission");
    Check(View(store).revision == before.revision, "duplicate does not consume inventory/revision");
    std::optional<Hash> after; std::vector<Hash> children; auto limits = generous; limits.max_rows = 2;
    for (unsigned n = 0; n < 64; ++n) {
        CandidateChildrenPage page; Ok(store.ReadCandidateChildren(f.Id(f.genesis), after, limits, page, error), error, "paged children");
        children.insert(children.end(), page.children.begin(), page.children.end()); if (page.complete) break;
        Check(page.next && page.next != after, "child cursor advances"); after = page.next;
    }
    Check(std::find(children.begin(), children.end(), f.Id(child)) != children.end() &&
          std::find(children.begin(), children.end(), f.Id(heavy)) != children.end() &&
          std::is_sorted(children.begin(), children.end()), "children include active and side sorted IDs");
    CandidatePage sentinel; sentinel.view.revision = 777;
    for (unsigned kind = 0; kind < 4; ++kind) {
        limits = generous; if (kind == 0) limits.max_rows = 0; if (kind == 1) limits.max_reads = 0;
        if (kind == 2) limits.max_iterator_steps = 0; if (kind == 3) limits.max_decoded_bytes = 0;
        CandidateQueryUsage used{999,999,999,999}; const auto reads = store.LastStats().database_reads;
        Check(!store.ReadCandidatePage({}, limits, sentinel, error, &used) && error.code == DiskStateErrorCode::Resource &&
              sentinel.view.revision == 777 && used.reads == store.LastStats().database_reads - reads &&
              used.reads <= limits.max_reads && used.iterator_steps <= limits.max_iterator_steps && used.decoded_bytes <= limits.max_decoded_bytes,
              "refusal preauthorizes and reports consumed work with unchanged page");
    }
    for (uint64_t budget = 1; budget < 30; ++budget) {
        limits = generous; limits.max_reads = budget; CandidatePage page; CandidateQueryUsage used;
        const auto reads = store.LastStats().database_reads; const bool ok = store.ReadCandidatePage({}, limits, page, error, &used);
        Check(used.reads <= budget && used.reads == store.LastStats().database_reads - reads, "actual read budget never exceeded");
        if (ok) Check(page.used.reads == used.reads && (!page.rows.empty() || page.complete), "partial bounded page meaningful");
        else Check(error.code == DiskStateErrorCode::Resource, "only expected budget refusal");
    }
    limits = generous; limits.max_rows = 1; CandidatePage first;
    Ok(store.ReadCandidatePage({}, limits, first, error), error, "scan first page");
    const auto newer = f.Child(headers.back(), 10000); Ok(store.PutCheckedHeader(newer, error), error, "insertion during pass");
    CandidatePage continuation; Ok(store.ReadCandidatePage(first.next, limits, continuation, error), error, "resume across insertions");
    Check(continuation.view.revision > first.view.revision && continuation.next != first.next, "revision observable without resetting cursor");
    // Active transition removes exactly its row; disconnect restores it atomically.
    const auto next = f.Child(child, 40000); Ok(store.PutCheckedHeader(next, error), error, "admit future active");
    const auto count = View(store).candidate_count; f.Commit(store, next);
    Check(View(store).candidate_count == count - 1, "connect removes candidate membership");
    Ok(store.Disconnect(f.Id(next), error), error, "disconnect active");
    Check(View(store).candidate_count == count && View(store).stable_tip == f.Id(child), "disconnect restores candidate membership");
    Check(!store.EvictCandidateLeaf(f.Id(next), error), "ever connected protected from eviction");
    Check(!store.EvictCandidateLeaf(f.Id(parent), error), "retained parent protected from eviction");
    Ok(store.EvictCandidateLeaf(f.Id(newer), error), error, "evict unconnected leaf");
    std::optional<IndexedHeader> missing; Ok(store.ReadIndexedHeader(f.Id(newer), missing, error), error, "evicted H missing"); Check(!missing, "eviction removes H");
    Ok(store.PutCheckedHeader(newer, error), error, "parent-first reannouncement admitted");
    const auto saved = View(store); store = {}; f.Open(path, store);
    Check(View(store).candidate_count == saved.candidate_count && All(store).size() == saved.candidate_count, "reopen inventory exact");
}
void Receipts(const std::string &path) {
    Fixture f; DiskStateStore store; f.Open(path, store); f.Commit(store, f.genesis); DiskStateError error;
    const auto target = f.Child(f.genesis, 2); Ok(store.PutCheckedHeader(target, error), error, "receipt target H");
    auto receipt = FinishUnknown(store, f.Id(target)); const auto root = store.Root();
    Check(View(store).pending_receipt && !View(store).pending_journal, "J removed with terminal receipt");
    DiskStateTransaction tx; Check(!store.Begin(tx, error) && !store.PutCheckedHeader(f.Child(target, 3), error), "receipt ordinary writer fence");
    Check(!store.AcknowledgeCandidateReceipt(Tag(999), f.Id(f.genesis), error), "unrelated ack refused");
    Check(!store.AcknowledgeCandidateReceipt(receipt.id, Tag(999), error), "wrong stable tip ack refused");
    store = {}; f.Open(path, store); Check(View(store).pending_receipt, "receipt durable before acknowledgement");
    Ok(store.AcknowledgeCandidateReceipt(receipt.id, f.Id(f.genesis), error), error, "ack unknown receipt");
    Check(!View(store).pending_receipt && !View(store).pending_propagation && View(store).invalid_root_count == 0, "unknown ack cannot invalidate");
    store = {}; f.Open(path, store);
    Ok(store.AcknowledgeCandidateReceipt(receipt.id, f.Id(f.genesis), error), error, "exact ack retry after reopen");
    Check(!store.AcknowledgeCandidateReceipt(Tag(999), f.Id(f.genesis), error), "unrelated retry refused");
    const auto second = FinishUnknown(store, f.Id(target), 100, CandidateTerminalOutcome::RestoredSourceDeferred);
    Check(!store.AcknowledgeCandidateReceipt(receipt.id, f.Id(f.genesis), error) && View(store).pending_receipt,
          "new outstanding receipt takes precedence over old T");
    Ok(store.AcknowledgeCandidateReceipt(second.id, f.Id(f.genesis), error), error, "ack deferred receipt");
    Check(store.Root() == root && View(store).invalid_root_count == 0, "deferred leaves state and invalidity unchanged");
    CandidateFailureFact fact; DeterministicBlockFailure unproved;
    Check(!CandidateFailureFact::FromValidation(unproved, fact) && !fact.Valid(), "default/unknown validator result cannot mint fact");
    const Payload j{1}; Ok(store.WriteRecoveryJournal(Update(store, {}, j), error), error, "unproved claim fixture J");
    CandidateTerminalClaim claim{Tag(101), f.Id(f.genesis), f.Id(target), 1, CandidateTerminalOutcome::RestoredSourceDeterministic, fact};
    Check(!store.FinishCandidateRecovery(Update(store, j, {}), claim, error) && View(store).pending_journal,
          "invalid/default proof cannot clear J or create invalid receipt");
    claim.outcome = CandidateTerminalOutcome::RestoredSourceUnknown; claim.failure.reset();
    Ok(store.FinishCandidateRecovery(Update(store, j, {}), claim, error), error, "unknown recovery remains safe");
}
void Put64(std::string &bytes, uint64_t n) { for (unsigned i = 0; i < 8; ++i) bytes.push_back(n >> (8*i)); }
void PutHash(std::string &bytes, const Hash &hash) { bytes.append(reinterpret_cast<const char *>(hash.data()), hash.size()); }
Hash Digest(const char *domain, const std::string &bytes) {
    blake3_hasher hasher; blake3_hasher_init(&hasher); blake3_hasher_update(&hasher, domain, std::char_traits<char>::length(domain) + 1);
    blake3_hasher_update(&hasher, bytes.data(), bytes.size()); Hash hash; blake3_hasher_finalize(&hasher, hash.data(), hash.size()); return hash;
}
// Mechanical persisted-record fixture only. This is not a VM validation proof;
// production creation uses opaque StageCompleteBlock evidence and trusted J codec.
Hash InjectReceipt(const std::string &path, const Fixture &f, const Header &target, const Hash &root, const Hash &parent_root) {
    const auto head = Raw(path, "S"); Check(head.has_value(), "persisted head for fixture");
    std::string bytes(1, 1); PutHash(bytes, f.options.identity); PutHash(bytes, f.options.profile_digest);
    PutHash(bytes, Tag(444)); PutHash(bytes, f.Id(f.genesis)); PutHash(bytes, f.Id(target)); PutHash(bytes, f.Id(f.genesis));
    PutHash(bytes, root); PutHash(bytes, Digest("Lotus/v2/storage/head", *head)); Put64(bytes, 7); bytes.push_back(3); bytes.push_back(1);
    PutHash(bytes, f.Id(target)); PutHash(bytes, target.prev_id); PutHash(bytes, f.options.profile_digest); PutHash(bytes, parent_root);
    Raw(path, "R", true, bytes); return Digest("Lotus/v2/storage/receipt", bytes);
}
void Propagation(const std::string &path) {
    Fixture f; f.options.candidates->max_invalid_roots = 1; DiskStateStore store; f.Open(path, store); f.Commit(store, f.genesis);
    DiskStateError error; const auto accepted_parent = f.Child(f.genesis, 55); DiskStateTransaction parent_tx;
    Ok(store.Begin(parent_tx, error), error, "historical parent begin"); Ok(parent_tx.Insert(CoinAt(1), error), error, "historical parent coin");
    Ok(parent_tx.Commit(f.Meta(accepted_parent), accepted_parent, error), error, "historical parent connect"); parent_tx.Abort();
    const Hash historical_parent_root = store.Root();
    const auto bad = f.Child(accepted_parent, 2); const auto sibling = f.Child(f.genesis, 99);
    Ok(store.PutCheckedHeader(bad, error), error, "bad branch H"); Ok(store.PutCheckedHeader(sibling, error), error, "sibling H");
    std::vector<Header> descendants; auto parent = bad;
    for (unsigned i = 0; i < 12; ++i) {
        auto child = f.Child(parent, i+100); Ok(store.PutCheckedHeader(child, error), error, "invalid descendants fixture"); descendants.push_back(child);
        if (i % 2 == 0) parent = child;
    }
    Ok(store.Disconnect(f.Id(accepted_parent), error), error, "restore source before receipt");
    const auto root = store.Root(); Check(root != historical_parent_root, "historical parent root differs from restored source"); store = {};
    (void)InjectReceipt(path, f, bad, root, root);
    Check(!DiskStateStore::Open(path, f.options, {}, store, error) && error.code == DiskStateErrorCode::Corruption,
          "wrong restored-source parent root cannot validate persisted fact");
    const Hash receipt = InjectReceipt(path, f, bad, root, historical_parent_root); f.Open(path, store);
    Ok(store.AcknowledgeCandidateReceipt(receipt, f.Id(f.genesis), error), error, "atomic invalid fact + queue ack");
    Check(View(store).pending_propagation && View(store).invalid_root_count == 1 && !View(store).pending_receipt, "receipt replaced by durable propagation");
    std::optional<Hash> invalid; Ok(store.ReadCandidateInvalidity(f.Id(bad), invalid, error), error, "root fact read"); Check(invalid == f.Id(bad), "root causal identity");
    DiskStateTransaction fenced; Check(!store.Begin(fenced, error), "propagation writer fence");
    Check(!store.PutCheckedHeader(f.Child(sibling, 777), error), "new children cannot escape propagation fence");
    auto limits = generous; limits.max_rows = 1; uint64_t previous = View(store).candidate_count; unsigned calls{};
    for (; calls < 64; ++calls) {
        CandidateInvalidationProgress progress; CandidateQueryUsage used;
        Ok(store.StepCandidateInvalidation(limits, progress, error, &used), error, "bounded propagation step");
        Check(used.rows <= 1 && used.reads <= limits.max_reads && used.iterator_steps <= limits.max_iterator_steps &&
              used.decoded_bytes <= limits.max_decoded_bytes, "propagation bounded before work");
        const auto view = View(store); Check(view.candidate_count <= previous, "propagation candidate removal monotone"); previous = view.candidate_count;
        store = {}; f.Open(path, store); if (progress.complete) break;
    }
    const auto remaining = All(store);
    Check(calls < 64 && !View(store).pending_propagation && remaining.size() == 2 && std::any_of(remaining.begin(), remaining.end(), [&](const auto &row) { return row.id == f.Id(sibling); }),
          "restart-per-step excludes full subtree and preserves sibling");
    for (const auto &child : descendants) { Ok(store.ReadCandidateInvalidity(f.Id(child), invalid, error), error, "descendant exclusion"); Check(invalid == f.Id(bad), "inherited root fact"); }
    Check(!store.PutCheckedHeader(f.Child(descendants.back(), 888), error), "new descendant rejected after propagation");
    Check(!store.CheckCandidateRecoveryCapacity(0, error) && error.code == DiskStateErrorCode::Resource, "invalid root ledger saturation visible before attempt");
    Check(store.Root() == root && View(store).stable_tip == f.Id(f.genesis), "invalidity never mutates stable state");
}
void LimitsAndCorruption(const std::string &base) {
    Fixture f; f.options.candidates = CandidateStoreOptions{2, 2, 1}; DiskStateStore store; f.Open(base + "-limits", store);
    f.Commit(store, f.genesis); const auto a = f.Child(f.genesis, 2), b = f.Child(a, 3), c = f.Child(b, 4); DiskStateError error;
    Ok(store.PutCheckedHeader(a, error), error, "capacity a"); Ok(store.PutCheckedHeader(b, error), error, "capacity b");
    Check(!store.PutCheckedHeader(c, error) && error.code == DiskStateErrorCode::Resource && View(store).candidate_count == 2,
          "admission capacity refuses all H/membership publication");
    std::optional<IndexedHeader> h; Ok(store.ReadIndexedHeader(f.Id(c), h, error), error, "capacity missing H"); Check(!h, "no hidden H at capacity");
    Check(!store.CheckCandidateRecoveryCapacity(1, error), "disconnect inventory reservation before attempt");
    Ok(store.EvictCandidateLeaf(f.Id(b), error), error, "capacity safe leaf eviction"); Ok(store.CheckCandidateRecoveryCapacity(1, error), error, "capacity available after eviction");
    Ok(store.PutCheckedHeader(b, error), error, "reannounce capacity leaf");
    const auto path = base + "-limits"; store = {}; const auto schema = Raw(path, "V"); auto old = f.options; old.candidates.reset();
    Check(!DiskStateStore::Open(path, old, {}, store, error) && error.code == DiskStateErrorCode::ProfileMismatch && Raw(path, "V") == schema,
          "V3 reader refuses V4 without migration");
    Ok(DiskStateStore::Open(base + "-v3", old, {}, store, error), error, "V3 own home preserved"); Check(!store.CandidatesEnabled(), "V3 mode distinct"); store = {};
    Check(!DiskStateStore::Open(base + "-v3", f.options, {}, store, error) && error.code == DiskStateErrorCode::ProfileMismatch,
          "V4 refuses old home");
    auto changed = f.options; ++changed.candidates->max_candidates;
    Check(!DiskStateStore::Open(path, changed, {}, store, error) && error.code == DiskStateErrorCode::ProfileMismatch, "candidate caps exact on reopen");
    auto counters = *Raw(path, "K"); auto bad = counters; bad[0] ^= 1; Raw(path, "K", true, bad);
    Check(!DiskStateStore::Open(path, f.options, {}, store, error) && error.code == DiskStateErrorCode::Corruption, "counter grammar rejected"); Raw(path, "K", true, counters);
    f.Open(path, store); auto rows = All(store); store = {};
    std::string key(1, 'W'); for (auto it = rows[0].indexed.chain_work.rbegin(); it != rows[0].indexed.chain_work.rend(); ++it) key.push_back(*it); PutHash(key, rows[0].id);
    const auto original = Raw(path, key); bad = *original; bad[0] ^= 1; Raw(path, key, true, bad); f.Open(path, store);
    CandidatePage sentinel; sentinel.view.revision = 777; CandidateQueryUsage used;
    Check(!store.ReadCandidatePage({}, generous, sentinel, error, &used) && error.code == DiskStateErrorCode::Corruption &&
          sentinel.view.revision == 777 && used.reads > 0, "corrupt rank summary operational with exact failure work"); store = {};
    Raw(path, key, true, original); f.Open(path, store); Check(All(store).size() == 2, "repair rank resumes");
}
void InvalidityFaults(const std::string &base) {
    Fixture f; DiskStateError error;
    for (auto fault : {FaultEnv::Fault::Append, FaultEnv::Fault::Sync}) {
        const auto path = base + (fault == FaultEnv::Fault::Append ? "-append" : "-sync");
        FaultEnv env; auto options = f.options; options.env = &env; DiskStateStore store;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "invalidity fault home"); f.Commit(store, f.genesis);
        const auto bad = f.Child(f.genesis, 2), child = f.Child(bad, 3);
        Ok(store.PutCheckedHeader(bad, error), error, "invalidity bad H"); Ok(store.PutCheckedHeader(child, error), error, "invalidity child H");
        const auto root = store.Root(); store = {}; const auto receipt = InjectReceipt(path, f, bad, root, root);
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "invalidity receipt reopen"); env.fault = fault;
        Check(!store.AcknowledgeCandidateReceipt(receipt, f.Id(f.genesis), error) && error.code == DiskStateErrorCode::Database,
              "failed receipt/invalid-root acknowledgement"); store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "invalid ack failure reopen");
        auto view = View(store); Check(view.pending_receipt != view.pending_propagation &&
              view.invalid_root_count == (view.pending_propagation ? 1 : 0) && view.candidate_count == (view.pending_propagation ? 1 : 2),
              "R or F/E/P/Q/T whole acknowledgement checkpoint");
        Ok(store.AcknowledgeCandidateReceipt(receipt, f.Id(f.genesis), error), error, "invalid ack exact retry");
        auto limits = generous; limits.max_rows = 1; CandidateInvalidationProgress progress; env.fault = fault;
        Check(!store.StepCandidateInvalidation(limits, progress, error) && error.code == DiskStateErrorCode::Database,
              "failed bounded invalid descendant step"); store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "invalidation failure reopen");
        std::optional<Hash> invalid; Ok(store.ReadCandidateInvalidity(f.Id(child), invalid, error), error, "failed propagation child fact");
        view = View(store); Check(view.candidate_count == (invalid ? 0 : 1) && view.invalid_root_count == 1 && view.pending_propagation,
                                 "descendant E/W/counters/queue recover whole step");
        for (unsigned n = 0; n < 8; ++n) {
            Ok(store.StepCandidateInvalidation(limits, progress, error), error, "resume invalid descendants"); if (progress.complete) break;
        }
        Check(progress.complete && All(store).empty() && store.Root() == root, "invalid propagation resumes to exact stable state");
    }
}
void Faults(const std::string &base) {
    Fixture f; DiskStateError error;
    for (auto fault : {FaultEnv::Fault::Append, FaultEnv::Fault::Sync}) {
        const auto path = base + (fault == FaultEnv::Fault::Append ? "-append" : "-sync");
        FaultEnv env; auto options = f.options; options.env = &env; DiskStateStore store;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "fault V4 home"); f.Commit(store, f.genesis);
        const auto child = f.Child(f.genesis, 2); env.fault = fault;
        Check(!store.PutCheckedHeader(child, error) && error.code == DiskStateErrorCode::Database, "failed atomic H/W/X/K admission");
        store = {}; env.fault = FaultEnv::Fault::None; Ok(DiskStateStore::Open(path, options, {}, store, error), error, "admission failure reopen");
        auto rows = All(store); Check(rows.size() == View(store).candidate_count && rows.size() <= 1, "whole admitted inventory or none");
        if (fault == FaultEnv::Fault::Append) Check(rows.empty(), "failed first append admits none");
        if (rows.empty()) Ok(store.PutCheckedHeader(child, error), error, "admission retry");
        DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "fault connect begin"); env.fault = fault;
        Check(!tx.Commit(f.Meta(child), child, error) && error.code == DiskStateErrorCode::Database, "failed candidate connect"); tx.Abort(); store = {};
        env.fault = FaultEnv::Fault::None; Ok(DiskStateStore::Open(path, options, {}, store, error), error, "connect failure reopen");
        const bool connected = store.Metadata().tip == f.Id(child); Check(View(store).candidate_count == (connected ? 0 : 1) &&
            All(store).size() == (connected ? 0 : 1), "S/A/I/H and candidate membership whole connect");
        if (!connected) f.Commit(store, child);
        env.fault = fault; Check(!store.Disconnect(f.Id(child), error) && error.code == DiskStateErrorCode::Database, "failed candidate disconnect");
        store = {}; env.fault = FaultEnv::Fault::None; Ok(DiskStateStore::Open(path, options, {}, store, error), error, "disconnect failure reopen");
        const bool detached = store.Metadata().tip == f.Id(f.genesis); Check(View(store).candidate_count == (detached ? 1 : 0) &&
            All(store).size() == (detached ? 1 : 0), "S/A/I/H and membership whole disconnect");
        if (!detached) Ok(store.Disconnect(f.Id(child), error), error, "disconnect retry");
        const Payload j{1}; Ok(store.WriteRecoveryJournal(Update(store, {}, j), error), error, "fault receipt prepare");
        CandidateTerminalClaim claim{Tag(100), f.Id(f.genesis), f.Id(child), 3, CandidateTerminalOutcome::RestoredSourceUnknown, {}};
        env.fault = fault; Check(!store.FinishCandidateRecovery(Update(store, j, {}), claim, error) && error.code == DiskStateErrorCode::Database, "failed Jclear/R publish");
        store = {}; env.fault = FaultEnv::Fault::None; Ok(DiskStateStore::Open(path, options, {}, store, error), error, "terminal failure reopen");
        auto view = View(store); Check(view.pending_journal != view.pending_receipt && view.stable_tip == f.Id(f.genesis), "J or R always fences terminal outcome");
        if (view.pending_journal) Ok(store.FinishCandidateRecovery(Update(store, j, {}), claim, error), error, "terminal retry");
        std::optional<CandidateTerminalReceipt> receipt; Ok(store.ReadCandidateReceipt(receipt, error), error, "fault receipt read"); Check(receipt.has_value(), "receipt exists");
        env.fault = fault; Check(!store.AcknowledgeCandidateReceipt(receipt->id, f.Id(f.genesis), error) && error.code == DiskStateErrorCode::Database, "failed acknowledgement");
        store = {}; env.fault = FaultEnv::Fault::None; Ok(DiskStateStore::Open(path, options, {}, store, error), error, "ack failure reopen");
        Ok(store.AcknowledgeCandidateReceipt(receipt->id, f.Id(f.genesis), error), error, "ack retry authoritative R/T");
        Check(!View(store).pending_receipt && View(store).invalid_root_count == 0, "unknown receipt never creates invalidity on failure");
    }
}
} // namespace
int main() {
    const auto path = (std::filesystem::temp_directory_path() / ("lotus-v2-candidate-store-" + std::to_string(std::random_device{}()))).string();
    Check(std::filesystem::create_directory(path), "temporary candidate directory"); std::cout << "candidate store artifacts: " << path << '\n';
    InventoryAndPages(path + "/inventory"); Receipts(path + "/receipts"); Propagation(path + "/propagation"); LimitsAndCorruption(path + "/caps"); Faults(path + "/fault"); InvalidityFaults(path + "/invalid-fault");
    std::filesystem::remove_all(path); std::cout << "V4 candidate storage ranked pages, capacities, receipts, propagation and failure cases passed\n";
}
