// Copyright (c) 2026 The Lotus developers
#include "chain_index.h"
#include "disk_state.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <leveldb/db.h>
#include <leveldb/env.h>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <string>
using namespace lotus::v2;
using boost::multiprecision::cpp_int;
namespace {
void Check(bool ok, const std::string &message) {
    if (!ok) { std::cerr << "V2 chain index: " << message << '\n'; std::exit(1); }
}
void Ok(bool ok, const DiskStateError &error, const char *message) {
    Check(ok, std::string(message) + ": " + error.message);
}
Hash Tag(uint32_t value) {
    Hash hash{}; for (unsigned i = 0; i < 4; ++i) hash[i] = value >> (8 * i); return hash;
}
template <size_t N> cpp_int Integer(const std::array<uint8_t, N> &bytes) {
    cpp_int value{}; for (size_t i = bytes.size(); i-- > 0;) { value <<= 8; value += bytes[i]; } return value;
}
void WorkCases() {
    ChainWork work{}; work.fill(0x5a); const auto unchanged = work;
    Check(!HeaderWork(Hash{}, work) && work == unchanged, "zero target rejects without output mutation");
    auto CompareOracle = [&](const Hash &target) {
        ChainWork result{}; Check(HeaderWork(target, result), "positive target work");
        Check(Integer(result) == (cpp_int(1) << 256) / (Integer(target) + 1), "independent mathematical work oracle");
    };
    Hash maximum; maximum.fill(255); CompareOracle(maximum); CompareOracle(Tag(1));
    for (unsigned bit = 0; bit < 256; ++bit) {
        Hash target{}; target[bit / 8] = uint8_t(1 << (bit % 8)); CompareOracle(target);
        if (bit) { for (unsigned below = 0; below < bit; ++below) target[below / 8] |= uint8_t(1 << (below % 8)); CompareOracle(target); }
    }
    std::mt19937_64 random(0x79af1324);
    for (unsigned n = 0; n < 512; ++n) {
        Hash target{}; for (auto &byte : target) byte = random(); if (target == Hash{}) target[0] = 1;
        CompareOracle(target);
        const cpp_int integer = Integer(target);
        unsigned width = (boost::multiprecision::msb(integer) + 8) / 8;
        const cpp_int shifted = width <= 3 ? cpp_int(integer << (8 * (3 - width)))
                                           : cpp_int(integer >> (8 * (width - 3)));
        uint32_t mantissa = shifted.convert_to<uint32_t>();
        if (mantissa & 0x00800000U) { mantissa >>= 8; ++width; }
        Hash canonical; Check(DecodeTarget((width << 24) | mantissa, maximum, canonical), "canonical compact target");
        CompareOracle(canonical);
    }
    for (uint32_t bits : {0x01010000U, 0x02008000U, 0x03008000U, 0x1d00ffffU, 0x207fffffU, 0x2100ffffU}) {
        Hash target; Check(DecodeTarget(bits, maximum, target), "fixed compact oracle target"); CompareOracle(target);
    }
    ChainWork one{}, wide{}, total{}; one[0] = 1; wide.fill(255); total.fill(0x71);
    const auto preserved = total;
    Check(!AddChainWork(wide, one, total) && total == preserved, "u320 overflow rejects unchanged output");
    ChainWork high{}; Check(HeaderWork(Tag(1), high) && AddChainWork(high, high, total) && Integer(total) == (cpp_int(1) << 256),
                            "cumulative sum crosses u256 without wrapping");
    Check(CompareChainWork(total, high) > 0 && CompareChainWork(high, total) < 0 && CompareChainWork(high, high) == 0,
          "u320 ordering");
    Check(AddChainWork(one, one, one) && Integer(one) == 2, "aliased addition");
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
std::string HKey(const Hash &id) {
    std::string key(1, 'H'); key.append(reinterpret_cast<const char *>(id.data()), 32); return key;
}
std::string AKey(uint64_t height) {
    std::string key(1, 'A'); for (unsigned i = 8; i-- > 0;) key.push_back(height >> (8 * i)); return key;
}
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
void CheckActive(const Fixture &f, const DiskStateStore &store, const Header &header) {
    DiskStateError error; std::optional<ActiveChainIndex> active;
    Ok(store.ReadActiveIndex(active, error), error, "active index read");
    Check(active && active->tip == f.Id(header) && active->height == header.height &&
          Integer(active->chain_work) == cpp_int(2) * (cpp_int(header.height) + 1), "active height/work binding");
    std::optional<Hash> id; Ok(store.ReadActiveId(header.height, id, error), error, "active height lookup");
    Check(id && *id == f.Id(header), "active ID");
    std::optional<IndexedHeader> indexed; Ok(store.ReadIndexedHeader(*id, indexed, error), error, "active H lookup");
    Check(indexed && indexed->stage == HeaderStage::Connected && indexed->chain_work == active->chain_work,
          "active header ever connected");
}
void IndexAndQueries(const std::string &path) {
    Fixture f; DiskStateStore store; f.Open(path, store); DiskStateError error;
    std::optional<ActiveChainIndex> active; Ok(store.ReadActiveIndex(active, error), error, "blank index"); Check(!active, "blank has no active tip");
    Ok(store.PutCheckedHeader(f.genesis, error), error, "header-only genesis");
    std::optional<IndexedHeader> indexed; Ok(store.ReadIndexedHeader(f.profile.genesis_id, indexed, error), error, "header-only genesis read");
    Check(indexed && indexed->stage == HeaderStage::HeaderChecked && Integer(indexed->chain_work) == 2, "checked stage/work only");
    Ok(store.ReadActiveIndex(active, error), error, "header-only active check"); Check(!active, "header-only never activates");
    DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "raw indexed begin");
    Check(!tx.Commit(f.Meta(f.genesis), error) && error.code == DiskStateErrorCode::ProfileMismatch, "raw commit refuses indexed mode");
    Ok(tx.Commit(f.Meta(f.genesis), f.genesis, error), error, "retry connected genesis"); tx.Abort(); CheckActive(f, store, f.genesis);
    std::vector<Header> chain{f.genesis};
    for (unsigned height = 1; height <= 128; ++height) {
        chain.push_back(f.Child(chain.back(), height + 10)); f.Commit(store, chain.back());
    }
    CheckActive(f, store, chain.back());
    const auto cached = store.Metadata(); Ok(store.PutCheckedHeader(chain.back(), error), error, "duplicate checked header");
    Ok(store.ReadIndexedHeader(f.Id(chain.back()), indexed, error), error, "duplicate keeps stage");
    Check(indexed->stage == HeaderStage::Connected && store.Metadata() == cached, "checked call cannot downgrade or activate");
    Header fork = chain[120]; std::vector<Header> branch;
    for (unsigned n = 0; n < 10; ++n) {
        fork = f.Child(fork, 10000 + n, n == 0 ? 100000 : 16000 + n);
        Ok(store.PutCheckedHeader(fork, error), error, "fork header admission"); branch.push_back(fork);
    }
    Ok(store.ReadIndexedHeader(f.Id(branch.back()), indexed, error), error, "fork work/time read");
    Check(indexed && indexed->stage == HeaderStage::HeaderChecked && indexed->max_ancestor_time == 100000 &&
          Integer(indexed->chain_work) == 262, "fork aggregates derived from whole ancestry");
    CheckActive(f, store, chain.back());
    std::vector<Hash> locator{Tag(999999)}; const auto old_locator = locator;
    Check(BuildActiveLocator(store, f.Id(chain.back()), 1, locator, error) == ChainIndexResult::CapacityRefused && locator == old_locator,
          "locator quota preserves output");
    auto reads = store.LastStats().database_reads;
    Check(BuildActiveLocator(store, f.Id(chain.back()), 76, locator, error) == ChainIndexResult::Complete &&
          locator.front() == f.Id(chain.back()) && locator.back() == f.Id(f.genesis) && locator.size() < 30,
          "exponential direct-height locator");
    Check(store.LastStats().database_reads - reads <= 14 + 11 * locator.size(), "locator Gets bounded by locator length");
    std::vector<Header> headers{f.genesis}; const auto unchanged = headers;
    const std::vector<Hash> request{Tag(99999), f.Id(branch[2]), f.Id(chain[10]), f.Id(f.genesis)};
    reads = store.LastStats().database_reads;
    Check(ReadActiveHeaders(store, f.Id(chain.back()), request, f.Id(chain[13]), 4, 20, headers, error) == ChainIndexResult::Complete &&
          headers.size() == 3 && f.Id(headers.front()) == f.Id(chain[11]) && f.Id(headers.back()) == f.Id(chain[13]),
          "first active locator, ordered stop-inclusive reply");
    Check(store.LastStats().database_reads - reads <= 14 + 14 * (request.size() + headers.size()), "headers Gets independent of chain height");
    headers = unchanged;
    Check(ReadActiveHeaders(store, f.Id(chain.back()), request, Hash{}, 3, 20, headers, error) == ChainIndexResult::CapacityRefused &&
          headers.size() == unchanged.size() && f.Id(headers[0]) == f.Id(unchanged[0]), "locator input quota before growth");
    Check(ReadActiveHeaders(store, Tag(999), request, Hash{}, 4, 2, headers, error) == ChainIndexResult::StaleTip, "headers snapshot tip fence");
    Check(ReadActiveHeaders(store, f.Id(chain.back()), {}, f.Id(chain[99]), 0, 1, headers, error) == ChainIndexResult::Complete &&
          headers.size() == 1 && f.Id(headers[0]) == f.Id(chain[99]), "empty locator explicit stop only");
    ForkPlan plan; plan.source = Tag(999);
    const ForkLimits generous{8, 10, 1000};
    Check(PlanHeaderFork(store, f.Id(chain.back()), f.Id(branch.back()), generous, 99999, 0, plan, error) == ChainIndexResult::Deferred &&
          plan.source == Tag(999), "future ancestor defers without output mutation");
    Check(PlanHeaderFork(store, f.Id(chain.back()), f.Id(branch[7]), generous, 200000, 0, plan, error) == ChainIndexResult::NotHeavier,
          "equal-work fork retains active tip");
    Check(PlanHeaderFork(store, f.Id(chain.back()), Tag(999), generous, 200000, 0, plan, error) == ChainIndexResult::Missing, "unknown target");
    Check(PlanHeaderFork(store, Tag(999), f.Id(branch.back()), generous, 200000, 0, plan, error) == ChainIndexResult::StaleTip, "plan stale tip");
    Check(PlanHeaderFork(store, f.Id(chain.back()), f.Id(branch.back()), ForkLimits{7, 10, 1000}, 200000, 0, plan, error) == ChainIndexResult::CapacityRefused,
          "disconnect quota before ninth entry");
    Check(PlanHeaderFork(store, f.Id(chain.back()), f.Id(branch.back()), ForkLimits{8, 9, 1000}, 200000, 0, plan, error) == ChainIndexResult::CapacityRefused,
          "connect quota before tenth entry");
    for (uint64_t budget : {0ULL, 6ULL, 7ULL, 9ULL, 12ULL, 20ULL, 40ULL, 100ULL, 200ULL, 500ULL}) {
        reads = store.LastStats().database_reads; ForkPlan limited; limited.source = Tag(999);
        const auto result = PlanHeaderFork(store, f.Id(chain.back()), f.Id(branch.back()), {8, 10, budget}, 99999, 1, limited, error);
        Check(store.LastStats().database_reads - reads <= budget, "actual Gets never exceed authorized budget");
        Check(result == ChainIndexResult::Complete || (result == ChainIndexResult::CapacityRefused && limited.source == Tag(999)),
              "budget refusal preserves output");
    }
    Check(PlanHeaderFork(store, f.Id(chain.back()), f.Id(branch.back()), generous, 99999, 1, plan, error) == ChainIndexResult::Complete &&
          plan.source == f.Id(chain.back()) && plan.target == f.Id(branch.back()) && plan.fork == f.Id(chain[120]) &&
          plan.disconnect.size() == 8 && plan.connect.size() == 10 && plan.disconnect.front() == f.Id(chain.back()) &&
          plan.disconnect.back() == f.Id(chain[121]) && plan.connect.front() == f.Id(branch[0]) && plan.connect.back() == f.Id(branch.back()),
          "bounded fork list directions and exact common ancestor");
    Check(PlanHeaderFork(store, f.Id(chain.back()), f.Id(branch.back()), generous, 99000, 0, plan, error) == ChainIndexResult::Deferred,
          "clock rollback does not mark header invalid");
    Ok(store.Disconnect(f.Id(chain.back()), error), error, "indexed disconnect"); CheckActive(f, store, chain[127]);
    Ok(store.ReadIndexedHeader(f.Id(chain.back()), indexed, error), error, "disconnected H retained");
    Check(indexed && indexed->stage == HeaderStage::Connected, "Connected persists after disconnect");
    std::optional<Hash> id; Ok(store.ReadActiveId(128, id, error), error, "above tip mapping"); Check(!id, "old active height removed");
    store = {}; f.Open(path, store); CheckActive(f, store, chain[127]);
    f.Commit(store, chain.back()); CheckActive(f, store, chain.back()); // Immutable undo reused.
    store = {};
    // Historical fork record corruption is lazy and never changes active state.
    const auto fork_key = HKey(f.Id(branch.back())); const auto original = Raw(path, fork_key); Check(original.has_value(), "raw fork H");
    for (size_t offset : {size_t(1), size_t(136), size_t(176), size_t(2)}) {
        auto altered = *original; altered[offset] ^= offset == 1 ? 3 : 1; Raw(path, fork_key, true, altered);
        f.Open(path, store); indexed = IndexedHeader{}; indexed->max_ancestor_time = 777;
        Check(!store.ReadIndexedHeader(f.Id(branch.back()), indexed, error) && error.code == DiskStateErrorCode::Corruption &&
              indexed->max_ancestor_time == 777, "corrupt H rejects without output mutation"); store = {};
    }
    Raw(path, fork_key, true, original);
    const auto active_key = AKey(10); const auto active_original = Raw(path, active_key);
    Raw(path, active_key, true, std::string(reinterpret_cast<const char *>(f.profile.genesis_id.data()), 32));
    f.Open(path, store); id = Tag(777);
    Check(!store.ReadActiveId(10, id, error) && error.code == DiskStateErrorCode::Corruption && *id == Tag(777), "corrupt active height binding"); store = {};
    Raw(path, active_key, true, active_original);
    const auto marker = Raw(path, "I"); Raw(path, "I", true, std::nullopt);
    Check(!DiskStateStore::Open(path, f.options, {}, store, error) && error.code == DiskStateErrorCode::Corruption, "missing I fails reopen");
    Raw(path, "I", true, marker);
    auto changed = f.options; ++changed.header_index->spacing_seconds;
    Check(!DiskStateStore::Open(path, changed, {}, store, error) && error.code == DiskStateErrorCode::ProfileMismatch, "exact header profile pinned");
    changed = f.options; changed.header_index.reset();
    Check(!DiskStateStore::Open(path, changed, {}, store, error) && error.code == DiskStateErrorCode::ProfileMismatch, "generic reader refuses indexed home");
    f.Open(path, store); CheckActive(f, store, chain.back());
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
void AtomicAndModeCases(const std::string &base) {
    Fixture f; DiskStateError error;
    DiskStateStore generic; auto generic_options = f.options; generic_options.header_index.reset();
    Ok(DiskStateStore::Open(base + "-generic", generic_options, {}, generic, error), error, "generic mode open"); generic = {};
    const auto preserved = Raw(base + "-generic", "V");
    Check(!DiskStateStore::Open(base + "-generic", f.options, {}, generic, error) && error.code == DiskStateErrorCode::ProfileMismatch,
          "existing generic home refuses silent migration"); Check(Raw(base + "-generic", "V") == preserved, "migration refusal preserves old schema");
    for (auto fault : {FaultEnv::Fault::Append, FaultEnv::Fault::Sync}) {
        const std::string path = base + (fault == FaultEnv::Fault::Append ? "-append" : "-sync");
        FaultEnv env; auto options = f.options; options.env = &env; DiskStateStore store;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "fault index open");
        DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "fault genesis begin");
        Ok(tx.Insert(CoinAt(1), error), error, "fault genesis coin");
        Ok(tx.Commit(f.Meta(f.genesis), f.genesis, error), error, "fault genesis commit"); tx.Abort(); const Hash before_root = store.Root();
        const Header child = f.Child(f.genesis, 2);
        Ok(store.Begin(tx, error), error, "fault child begin"); Ok(tx.Insert(CoinAt(2), error), error, "fault child coin");
        const Hash after_root = tx.Root(); env.fault = fault;
        Check(!tx.Commit(f.Meta(child), child, error) && error.code == DiskStateErrorCode::Database && !store.IsOpen(), "indexed failed write operational/poisoned");
        tx.Abort(); store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "index reopen after write failure");
        const bool child_won = store.Metadata().tip == f.Id(child);
        Check(store.Metadata().tip == f.Id(f.genesis) || child_won, "one complete commit recovered");
        if (fault == FaultEnv::Fault::Append) Check(!child_won, "first failed append publishes no index/state");
        CheckActive(f, store, child_won ? child : f.genesis);
        Check(store.Root() == (child_won ? after_root : before_root), "root/index same recovered batch");
        std::optional<IndexedHeader> header; Ok(store.ReadIndexedHeader(f.Id(child), header, error), error, "failed write H availability");
        Check(header.has_value() == child_won, "H presence matches published state");
        std::optional<Coin> coin; Ok(store.ReadCoin(CoinAt(2).outpoint, coin, error), error, "failed write C availability"); Check(coin.has_value() == child_won, "C presence matches index");
        if (!child_won) { f.Commit(store, child); CheckActive(f, store, child); }
        env.fault = fault;
        Check(!store.Disconnect(f.Id(child), error) && error.code == DiskStateErrorCode::Database, "failed indexed disconnect");
        store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "index reopen after disconnect failure");
        const bool disconnected = store.Metadata().tip == f.Id(f.genesis);
        if (fault == FaultEnv::Fault::Append) Check(!disconnected, "failed disconnect append leaves active height");
        CheckActive(f, store, disconnected ? f.genesis : child);
        Ok(store.ReadIndexedHeader(f.Id(child), header, error), error, "disconnect retains H");
        Check(header && header->stage == HeaderStage::Connected, "disconnect never deletes connected knowledge");
        if (!disconnected) Ok(store.Disconnect(f.Id(child), error), error, "complete indexed disconnect");
        Check(!store.Disconnect(f.Id(f.genesis), error) && error.code == DiskStateErrorCode::UndoMismatch, "indexed genesis cannot disconnect");
        // Header-only failed publication also leaves S/A/I intact.
        const Header other = f.Child(f.genesis, 999); env.fault = FaultEnv::Fault::Append;
        Check(!store.PutCheckedHeader(other, error) && error.code == DiskStateErrorCode::Database, "failed header-only admission");
        store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, {}, store, error), error, "header-only failure reopen"); CheckActive(f, store, f.genesis);
        Ok(store.ReadIndexedHeader(f.Id(other), header, error), error, "header-only failure H"); Check(!header, "failed header-only H absent");
        store = {};
    }
}
} // namespace
int main() {
    const auto path = (std::filesystem::temp_directory_path() / ("lotus-v2-chain-index-" + std::to_string(std::random_device{}()))).string();
    Check(std::filesystem::create_directory(path), "temporary index directory");
    std::cout << "chain index test artifacts: " << path << '\n';
    WorkCases(); IndexAndQueries(path + "/indexed"); AtomicAndModeCases(path + "/atomic");
    std::filesystem::remove_all(path);
    std::cout << "V2 chain index work oracle, bounded queries, fork plans, atomicity and corruption cases passed\n";
}
