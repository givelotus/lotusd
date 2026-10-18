// Copyright (c) 2026 The Lotus developers
// Storage mechanics fixtures: contextual consensus/body validity is caller-owned.
#include "disk_state.h"
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
    if (!ok) { std::cerr << "V2 recovery storage: " << message << '\n'; std::exit(1); }
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
std::string UndoKey(const Hash &id) {
    std::string key(1, 'U'); key.append(reinterpret_cast<const char *>(id.data()), id.size()); return key;
}
std::optional<Payload> Journal(const DiskStateStore &store) {
    DiskStateError error; std::optional<Payload> out;
    Ok(store.ReadRecoveryJournal(4096, out, error), error, "read journal"); return out;
}
DiskRecoveryUpdate Update(const DiskStateStore &store, std::optional<Payload> old,
                          std::optional<Payload> next, const Hash &next_tip) {
    return {std::move(old), std::move(next), store.Metadata().tip, store.Root(), next_tip, std::nullopt};
}
void Active(const DiskStateStore &store, const Hash &tip, uint64_t height) {
    DiskStateError error; std::optional<ActiveChainIndex> active; std::optional<Hash> id;
    Ok(store.ReadActiveIndex(active, error), error, "read active index");
    Ok(store.ReadActiveId(height, id, error), error, "read active height");
    Check(active && active->tip == tip && active->height == height && id && *id == tip,
          "S/I/A checkpoint agreement");
}
void Seed(const Fixture &f, DiskStateStore &store, const Header &header, uint32_t coin) {
    DiskStateError error; DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "seed begin");
    Ok(tx.Insert(CoinAt(coin), error), error, "seed coin");
    Ok(tx.Commit(f.Meta(header), header, error), error, "seed commit");
}
void Flow(const std::string &path) {
    Fixture f; DiskStateStore store; f.Open(path, store); DiskStateError error;
    Check(!Journal(store), "fresh J absent"); Seed(f, store, f.genesis, 1);
    const Hash genesis_root = store.Root(); const Header child = f.Child(f.genesis, 2);
    Seed(f, store, child, 2); const Hash child_root = store.Root();
    std::optional<DiskRecoveryUndoInfo> undo;
    Ok(store.ProbeRecoveryUndo(f.Id(child), 65536, undo, error), error, "probe source undo");
    Check(undo && undo->before_tip == f.Id(f.genesis) && undo->after_tip == f.Id(child) &&
          undo->before_root == genesis_root && undo->after_root == child_root, "probe identities/root summary");
    const auto pinned = *undo; undo->bytes = 999;
    Check(!store.ProbeRecoveryUndo(f.Id(child), pinned.bytes - 1, undo, error) &&
          error.code == DiskStateErrorCode::Resource && undo->bytes == 999, "undo copy quota preserves output");
    Ok(store.ProbeRecoveryUndo(Tag(999), 0, undo, error), error, "missing source undo"); Check(!undo, "missing is explicit");
    std::optional<Payload> small = Payload{77};
    const Payload j1{1, 0xff, 0x80, 0}, j2{2, 0, 0xff}, j3{3}, j4{4};
    auto prepare = Update(store, std::nullopt, j1, f.Id(child));
    auto bad = prepare; bad.next_journal = Payload(4097, 0);
    Check(!store.WriteRecoveryJournal(bad, error) && error.code == DiskStateErrorCode::Resource && !Journal(store),
          "journal creation quota before publication");
    bad = prepare; bad.next_tip = f.Id(f.genesis);
    Check(!store.WriteRecoveryJournal(bad, error) && !Journal(store), "journal-only cannot change tip");
    Ok(store.WriteRecoveryJournal(prepare, error), error, "publish preparation");
    Check(Journal(store) == j1 && store.Root() == child_root, "preparation retains checkpoint");
    Check(!store.ReadRecoveryJournal(j1.size() - 1, small, error) && error.code == DiskStateErrorCode::Resource &&
          small == Payload{77}, "journal copy quota preserves output");
    Check(!store.WriteRecoveryJournal(prepare, error), "stale absent-J CAS refused");
    DiskStateTransaction tx;
    Check(!store.Begin(tx, error) && error.code == DiskStateErrorCode::TransactionAborted, "pending ordinary begin fenced");
    Check(!store.PutCheckedHeader(f.Child(child, 99), error) && error.code == DiskStateErrorCode::TransactionAborted,
          "pending header-only publication fenced");
    Check(!store.Disconnect(f.Id(child), error) && error.code == DiskStateErrorCode::TransactionAborted,
          "pending ordinary disconnect fenced");
    auto down = Update(store, j1, j2, f.Id(f.genesis)); down.expected_undo_digest = pinned.digest;
    for (unsigned kind = 0; kind < 4; ++kind) {
        bad = down;
        if (kind == 0) bad.expected_journal = j4;
        if (kind == 1) bad.expected_tip = Tag(999);
        if (kind == 2) bad.expected_root = Tag(999);
        if (kind == 3) bad.next_journal.reset();
        Check(!store.DisconnectRecovery(f.Id(child), {}, bad, error) && Journal(store) == j1 && store.Root() == child_root,
              "CAS/tip/root/retain fence leaves checkpoint intact");
    }
    bad = down; bad.expected_undo_digest = Tag(999);
    Check(!store.DisconnectRecovery(f.Id(child), {}, bad, error) && error.code == DiskStateErrorCode::Corruption,
          "pinned undo mismatch operational");
    Check(Journal(store) == j1 && store.Metadata() == f.Meta(child), "bad undo pin unchanged");
    const auto reject = [&](const DiskStateMetadata &meta, const Hash &root, DiskStateError &) {
        Check(meta == f.Meta(f.genesis) && root == genesis_root && store.Metadata() == f.Meta(child),
              "callback sees exact predecessor and current cached checkpoint");
        DiskStateError nested; DiskStateTransaction nested_tx;
        Check(!store.BeginRecovery(down, nested_tx, nested) &&
              !store.WriteRecoveryJournal(Update(store, j1, j4, f.Id(child)), nested), "callback recovery reentry fenced");
        return false;
    };
    Check(!store.DisconnectRecovery(f.Id(child), reject, down, error) && Journal(store) == j1 && store.Root() == child_root,
          "metadata refusal leaves J/state intact");
    Check(!store.DisconnectRecovery(f.Id(child), [](const auto &, const auto &, auto &) -> bool {
        throw std::runtime_error("validator refusal");
    }, down, error) && Journal(store) == j1, "metadata exception leaves J/state intact and releases active fence");
    store = {}; const auto immutable = Raw(path, UndoKey(f.Id(child))); f.Open(path, store);
    Check(Journal(store) == j1, "pending checkpoint survives reopen");
    Ok(store.DisconnectRecovery(f.Id(child), {}, down, error), error, "recovery source disconnect");
    Check(Journal(store) == j2 && store.Root() == genesis_root, "disconnect J/root same checkpoint");
    Active(store, f.Id(f.genesis), 0);
    std::optional<Coin> coin; Ok(store.ReadCoin(CoinAt(2).outpoint, coin, error), error, "restored coin absence");
    Check(!coin, "source delta removed");
    store = {}; Check(Raw(path, UndoKey(f.Id(child))) == immutable, "disconnect never mutates U"); f.Open(path, store);
    auto up = Update(store, j2, j3, f.Id(child));
    Ok(store.BeginRecovery(up, tx, error), error, "recovery abort begin");
    Ok(tx.Insert(CoinAt(2), error), error, "recovery abort coin"); tx.Abort();
    Check(Journal(store) == j2 && store.Root() == genesis_root, "abort drops overlay and journal update");
    bad = up; bad.next_tip = Tag(999);
    Ok(store.BeginRecovery(bad, tx, error), error, "wrong next-tip begin");
    Ok(tx.Insert(CoinAt(2), error), error, "wrong next-tip coin");
    Check(!tx.Commit(f.Meta(child), child, error) && Journal(store) == j2 && store.Root() == genesis_root,
          "actual commit tip must equal recovery envelope"); tx.Abort();
    Ok(store.BeginRecovery(up, tx, error), error, "recovery reconnect begin");
    Ok(tx.Insert(CoinAt(2), error), error, "recovery reconnect coin");
    Ok(tx.Commit(f.Meta(child), child, error), error, "recovery reconnect commit"); tx.Abort();
    Check(Journal(store) == j3 && store.Root() == child_root, "connect J/root atomic checkpoint"); Active(store, f.Id(child), 1);
    store = {}; Check(Raw(path, UndoKey(f.Id(child))) == immutable, "J revisions excluded from immutable U"); f.Open(path, store);
    Check(Journal(store) == j3, "connect checkpoint survives reopen");
    auto terminal = Update(store, j3, std::nullopt, f.Id(child));
    Ok(store.WriteRecoveryJournal(terminal, error), error, "verified coordinator terminal clear");
    Check(!Journal(store) && store.Root() == child_root, "terminal clear keeps stable state");
    Ok(store.Begin(tx, error), error, "ordinary writes resume after completion"); tx.Abort();
    Ok(store.PutCheckedHeader(f.Child(child, 99), error), error, "ordinary checked header resumes");
}
void CapsAndModes(const std::string &base) {
    Fixture f; DiskStateError error; DiskStateStore store; f.Open(base + "-measure", store);
    Seed(f, store, f.genesis, 1); std::optional<DiskRecoveryUndoInfo> info;
    Ok(store.ProbeRecoveryUndo(f.Id(f.genesis), 65536, info, error), error, "measure genesis U"); Check(info.has_value(), "genesis undo present");
    const auto bytes = info->bytes;
    const Payload full(4096, 0xff);
    Ok(store.WriteRecoveryJournal(Update(store, std::nullopt, full, f.Id(f.genesis)), error), error, "exact journal cap");
    Check(Journal(store) == full, "exact journal creation boundary accepted");
    Ok(store.WriteRecoveryJournal(Update(store, full, std::nullopt, f.Id(f.genesis)), error), error, "clear exact cap fixture");
    store = {};
    for (bool exact : {false, true}) {
        auto options = f.options; options.recovery->max_undo_bytes = bytes - (exact ? 0 : 1);
        const auto path = base + (exact ? "-equal" : "-small");
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "capped home open");
        DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "capped seed begin"); Ok(tx.Insert(CoinAt(1), error), error, "capped seed coin");
        const bool committed = tx.Commit(f.Meta(f.genesis), f.genesis, error);
        Check(committed == exact, "exact undo encoding creation-cap boundary");
        if (!exact) Check(error.code == DiskStateErrorCode::Resource && store.Metadata() == DiskStateMetadata{} && !Journal(store),
                          "undo refusal is operational and no state publication");
        tx.Abort(); store = {};
        Check(Raw(path, UndoKey(f.Id(f.genesis))).has_value() == exact, "creation-cap refusal publishes no undo");
    }
    auto old = f.options; old.recovery.reset();
    Ok(DiskStateStore::Open(base + "-v2", old, {}, store, error), error, "old V2 home"); store = {};
    const auto schema = Raw(base + "-v2", "V");
    Check(!DiskStateStore::Open(base + "-v2", f.options, {}, store, error) &&
          error.code == DiskStateErrorCode::ProfileMismatch && Raw(base + "-v2", "V") == schema, "V3 fails closed on V2 home");
    const auto path = base + "-measure"; const auto v3 = Raw(path, "V");
    Check(!DiskStateStore::Open(path, old, {}, store, error) && error.code == DiskStateErrorCode::ProfileMismatch,
          "V2 reader refuses V3 home");
    auto changed = f.options; ++changed.recovery->max_undo_bytes;
    Check(!DiskStateStore::Open(path, changed, {}, store, error) && error.code == DiskStateErrorCode::ProfileMismatch && Raw(path, "V") == v3,
          "creation caps immutable on reopen");
    changed = f.options; changed.header_index.reset();
    Check(!DiskStateStore::Open(base + "-bad", changed, {}, store, error) && error.code == DiskStateErrorCode::ProfileMismatch,
          "recovery requires indexed mode");
}
void Corruption(const std::string &path) {
    Fixture f; DiskStateError error; DiskStateStore store; f.Open(path, store);
    Seed(f, store, f.genesis, 1); const Header child = f.Child(f.genesis, 2); Seed(f, store, child, 2);
    const Payload j1{1, 0xff}, j2{2}; const auto prepare = Update(store, std::nullopt, j1, f.Id(child));
    Ok(store.WriteRecoveryJournal(prepare, error), error, "corruption fixture prepare");
    const auto down = Update(store, j1, j2, f.Id(f.genesis)); const auto metadata = store.Metadata(); const auto root = store.Root();
    store = {}; const auto journal = Raw(path, "J"); const auto undo = Raw(path, UndoKey(f.Id(child)));
    Check(journal && undo, "corruption fixture records");
    for (unsigned kind = 0; kind < 5; ++kind) {
        auto bad = *journal;
        if (kind < 3) bad[kind == 0 ? 0 : kind == 1 ? 1 : 33] ^= 1;
        if (kind == 3) bad += 'x';
        if (kind == 4) bad.append(4096, 'x');
        Raw(path, "J", true, bad);
        Check(!DiskStateStore::Open(path, f.options, {}, store, error) && error.code == DiskStateErrorCode::Corruption,
              "bad J version/tip/root/frame/creation bound rejects reopen");
        Check(Raw(path, "S").has_value() && Raw(path, UndoKey(f.Id(child))) == undo, "J corruption cannot mutate S/U");
    }
    Raw(path, "J", true, journal);
    for (unsigned kind = 0; kind < 4; ++kind) {
        auto bad = *undo;
        if (kind == 0) bad[0] = char(0xff);
        if (kind == 1) bad += 'x';
        if (kind == 2) bad.append(65536, 'x');
        Raw(path, UndoKey(f.Id(child)), true, kind == 3 ? std::nullopt : std::optional<std::string>(bad));
        f.Open(path, store); std::optional<DiskRecoveryUndoInfo> out = DiskRecoveryUndoInfo{}; out->bytes = 999;
        const bool probed = store.ProbeRecoveryUndo(f.Id(child), 65536, out, error);
        if (kind == 3) Check(probed && !out, "missing undo probe explicitly missing");
        else Check(!probed && error.code == DiskStateErrorCode::Corruption && out->bytes == 999, "corrupt undo preflight preserves output");
        Check(!store.DisconnectRecovery(f.Id(child), {}, down, error) && Journal(store) == j1 &&
              store.Metadata() == metadata && store.Root() == root, "missing/corrupt undo leaves pending checkpoint repairable");
        store = {};
    }
    Raw(path, UndoKey(f.Id(child)), true, undo); f.Open(path, store);
    Ok(store.DisconnectRecovery(f.Id(child), {}, down, error), error, "repaired pending checkpoint resumes");
}
void Faults(const std::string &base) {
    Fixture f; DiskStateError error;
    for (auto fault : {FaultEnv::Fault::Append, FaultEnv::Fault::Sync}) {
        const auto path = base + (fault == FaultEnv::Fault::Append ? "-append" : "-sync");
        FaultEnv env; auto options = f.options; options.env = &env; DiskStateStore store;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "fault home"); Seed(f, store, f.genesis, 1);
        const Hash before_root = store.Root(); const Header child = f.Child(f.genesis, 2);
        const Payload j1{1}, j2{2}, j3{3};
        auto prepare = Update(store, std::nullopt, j1, f.Id(f.genesis)); env.fault = fault;
        Check(!store.WriteRecoveryJournal(prepare, error) && error.code == DiskStateErrorCode::Database,
              "failed preparation write operational"); store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "preparation failure reopen");
        Check(store.Root() == before_root && (!Journal(store) || Journal(store) == j1), "preparation outcome keeps stable checkpoint");
        if (fault == FaultEnv::Fault::Append) Check(!Journal(store), "failed preparation append publishes no J");
        if (!Journal(store)) Ok(store.WriteRecoveryJournal(prepare, error), error, "fault preparation retry");
        auto up = Update(store, j1, j2, f.Id(child)); DiskStateTransaction tx;
        Ok(store.BeginRecovery(up, tx, error), error, "fault recovery begin"); Ok(tx.Insert(CoinAt(2), error), error, "fault recovery coin");
        const Hash after_root = tx.Root(); env.fault = fault;
        Check(!tx.Commit(f.Meta(child), child, error) && error.code == DiskStateErrorCode::Database && !store.IsOpen(),
              "failed recovery write operational/poisoned"); tx.Abort(); store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "failed connect reopen");
        const bool connected = store.Metadata().tip == f.Id(child);
        if (fault == FaultEnv::Fault::Append) Check(!connected, "failed first append leaves old checkpoint");
        Check(Journal(store) == (connected ? j2 : j1) && store.Root() == (connected ? after_root : before_root),
              "failure recovers complete J/S/root checkpoint"); Active(store, connected ? f.Id(child) : f.Id(f.genesis), connected ? 1 : 0);
        std::optional<Coin> coin; Ok(store.ReadCoin(CoinAt(2).outpoint, coin, error), error, "fault coin agreement");
        Check(coin.has_value() == connected, "C and J same batch");
        std::optional<IndexedHeader> header; Ok(store.ReadIndexedHeader(f.Id(child), header, error), error, "fault H agreement");
        Check(header.has_value() == connected, "H and J same batch");
        std::optional<DiskRecoveryUndoInfo> undo; Ok(store.ProbeRecoveryUndo(f.Id(child), 65536, undo, error), error, "fault U agreement");
        Check(undo.has_value() == connected, "U and J same batch");
        if (!connected) {
            Ok(store.BeginRecovery(up, tx, error), error, "retry recovery begin"); Ok(tx.Insert(CoinAt(2), error), error, "retry recovery coin");
            Ok(tx.Commit(f.Meta(child), child, error), error, "retry recovery commit"); tx.Abort();
        }
        const auto down = Update(store, j2, j3, f.Id(f.genesis)); env.fault = fault;
        Check(!store.DisconnectRecovery(f.Id(child), {}, down, error) && error.code == DiskStateErrorCode::Database,
              "failed recovery disconnect operational"); store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "failed disconnect reopen");
        const bool disconnected = store.Metadata().tip == f.Id(f.genesis);
        if (fault == FaultEnv::Fault::Append) Check(!disconnected, "failed first disconnect append keeps old checkpoint");
        Check(Journal(store) == (disconnected ? j3 : j2) && store.Root() == (disconnected ? before_root : after_root),
              "disconnect failure recovers complete journal/state tuple");
        Active(store, disconnected ? f.Id(f.genesis) : f.Id(child), disconnected ? 0 : 1);
        if (!disconnected) Ok(store.DisconnectRecovery(f.Id(child), {}, down, error), error, "retry disconnect");
        auto finish = Update(store, j3, std::nullopt, f.Id(f.genesis)); env.fault = fault;
        Check(!store.WriteRecoveryJournal(finish, error) && error.code == DiskStateErrorCode::Database, "failed terminal write");
        store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "terminal failure reopen");
        Check(store.Root() == before_root && (!Journal(store) || Journal(store) == j3), "terminal outcome always stable checkpoint");
        if (fault == FaultEnv::Fault::Append) Check(Journal(store) == j3, "failed terminal append retains fence");
    }
}
} // namespace
int main() {
    const auto path = (std::filesystem::temp_directory_path() / ("lotus-v2-reorg-storage-" + std::to_string(std::random_device{}()))).string();
    Check(std::filesystem::create_directory(path), "temporary recovery directory");
    std::cout << "recovery storage test artifacts: " << path << '\n';
    Flow(path + "/flow"); CapsAndModes(path + "/caps"); Corruption(path + "/corrupt"); Faults(path + "/fault");
    std::filesystem::remove_all(path);
    std::cout << "V2 recovery storage CAS, quotas, immutable undo, restart and atomic failure cases passed\n";
}
