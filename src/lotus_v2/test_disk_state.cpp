// Copyright (c) 2026 The Lotus developers
#include "disk_state.h"
#include "incremental_utxo.h"

#include <crc32c/crc32c.h>
#include <leveldb/db.h>
#include <leveldb/env.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#ifndef _WIN32
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace lotus::v2;
namespace {
void Check(bool condition, const std::string &message) {
    if (!condition) { std::cerr << "V2 disk state: " << message << '\n'; std::exit(1); }
}
void Ok(bool value, const DiskStateError &error, const char *message) {
    Check(value, std::string(message) + ": " + error.message);
}
Hash Id(uint32_t id) {
    Hash hash{};
    for (unsigned i = 0; i < 4; ++i) hash[i] = id >> (8 * i);
    return hash;
}
Coin MakeCoin(uint32_t index) {
    Coin coin;
    coin.outpoint.tx_id = Id(index * 17);
    coin.outpoint.index = index;
    coin.output.value = 1000 + index;
    coin.output.branches = {Id(0x12345678)};
    coin.output.paths = {{0}};
    coin.creation_height = 1 + index;
    coin.creation_parent_mtp = 123456 + index;
    coin.coinbase = index % 2;
    return coin;
}
DiskStateMetadata Meta(uint32_t id) {
    DiskStateMetadata meta;
    meta.tip = Id(id); meta.header = {1, uint8_t(id), 3};
    meta.monetary = {4, uint8_t(id >> 8), 6}; meta.auxiliary = {7, uint8_t(id), 9};
    return meta;
}
DiskStateOptions Options() {
    DiskStateOptions opts;
    opts.identity = Id(0x1234); opts.profile_digest = Id(0x5678);
    opts.cache_bytes = 1024; opts.write_buffer_bytes = 64 << 10;
    return opts;
}
void DurabilityPolicyCases(const std::string &directory) {
    DiskStateStore store;
    DiskStateError error;
    Ok(DiskStateStore::Open(directory, Options(), Meta(0), store, error), error, "durability open");
    DiskStateSyncStatus status;
    Ok(RawDiskStateSyncStatus(store, status, error), error, "inspect actual MDBX profile");
    std::cout << "native MDBX profile: WRITEMAP=" << status.writable_map
              << " SAFE_NOSYNC=" << status.safe_nosync
              << " NOMETASYNC=" << status.nometasync
              << " UTTERLY_NOSYNC=" << status.utterly_nosync
              << " sync_bytes=" << status.sync_bytes
              << " sync_period=" << status.sync_period_16dot16 << '\n';
    Check(!status.writable_map, "native WRITEMAP disabled");
    Check(status.safe_nosync && status.nometasync && !status.utterly_nosync,
          "native safe bounded sync profile");
    Check(status.sync_bytes == (16U << 20) && status.sync_period_16dot16 == (1U << 16),
          "native bounded sync thresholds");
    DiskStateTransaction tx;
    Ok(store.Begin(tx, error), error, "durability begin");
    Ok(tx.Insert(MakeCoin(100), error), error, "durability insert");
    Ok(tx.Commit(Meta(1), error), error, "durable commit");
    tx.Abort();
    Ok(RawDiskStateSyncStatus(store, status, error), error, "inspect completed commit");
    Check(status.unsynced_bytes == 0, "successful native commit is synchronized");
    const auto root = store.Root();
    store = {};
    Ok(DiskStateStore::Open(directory, Options(), Meta(0), store, error), error, "durability reopen");
    Check(store.Root() == root && store.Metadata() == Meta(1), "durable metadata/root reopen");
}

#ifndef _WIN32
void CrashWriter(const std::string &directory, int signal_fd, unsigned cycle) {
    DiskStateStore store; DiskStateTransaction tx; DiskStateError error;
    Ok(DiskStateStore::Open(directory, Options(), Meta(0), store, error), error, "crash writer open");
    const uint32_t first = 1000 + cycle * 10000;
    Ok(store.Begin(tx, error), error, "crash acknowledged begin");
    for (uint32_t i = 0; i < 200; ++i)
        Ok(tx.Insert(MakeCoin(first + i), error), error, "crash acknowledged insert");
    Ok(tx.Commit(Meta(1), error), error, "crash acknowledged commit");
    tx.Abort();
    Check(::write(signal_fd, "A", 1) == 1, "acknowledged commit signal");
    Ok(store.Begin(tx, error), error, "crash pending begin");
    for (uint32_t i = 200; i < 2200; ++i)
        Ok(tx.Insert(MakeCoin(first + i), error), error, "crash pending insert");
    Check(::write(signal_fd, "B", 1) == 1, "pending commit signal");
    Ok(tx.Commit(Meta(2), error), error, "crash pending commit");
    // No destructor/close: the controller must either kill this commit in
    // flight or observe that this workload was too short for the crash gate.
    ::_exit(0);
}
void CrashRecoveryCases(const std::string &directory, const std::string &executable) {
    for (unsigned cycle = 0; cycle < 5; ++cycle) {
        const auto home = directory + "-" + std::to_string(cycle);
        int fds[2]; Check(::pipe(fds) == 0, "crash synchronization pipe");
        const std::string fd_arg = std::to_string(fds[1]);
        const std::string cycle_arg = std::to_string(cycle);
        std::cout.flush();
        const pid_t child = ::fork(); Check(child >= 0, "crash writer fork");
        if (child == 0) {
            ::close(fds[0]);
            ::execl(executable.c_str(), executable.c_str(), "--crash-writer",
                    home.c_str(), fd_arg.c_str(), cycle_arg.c_str(), nullptr);
            ::_exit(127);
        }
        ::close(fds[1]);
        char phase = 0;
        Check(::read(fds[0], &phase, 1) == 1 && phase == 'A', "durable commit acknowledged before kill");
        Check(::read(fds[0], &phase, 1) == 1 && phase == 'B', "pending commit entered before kill");
        ::close(fds[0]);
        ::usleep(500);
        Check(::kill(child, SIGKILL) == 0, "kill native commit writer");
        int status = 0; Check(::waitpid(child, &status, 0) == child, "reap native crash writer");
        Check(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "native writer killed before exit");
        DiskStateStore store; DiskStateError error;
        Ok(DiskStateStore::Open(home, Options(), Meta(0), store, error), error, "native crash reopen");
        const auto recovered = store.Metadata();
        Check(recovered == Meta(1) || recovered == Meta(2), "acknowledged head survives; pending commit atomic");
        IncrementalUtxoSet oracle;
        const uint32_t first = 1000 + cycle * 10000;
        const uint32_t count = recovered == Meta(1) ? 200 : 2200;
        for (uint32_t i = 0; i < count; ++i)
            Check(oracle.Insert(MakeCoin(first + i)), "native crash oracle insert");
        Check(store.Root() == oracle.Root(), "native crash authenticated root exact");
        for (uint32_t i = 0; i < count; ++i) {
            std::optional<Coin> coin;
            Ok(store.ReadCoin(MakeCoin(first + i).outpoint, coin, error), error, "native crash authenticated read");
            Check(coin.has_value(), "native crash complete coin table");
        }
        // Reverse the recovered head: this reads the referenced flat-file undo
        // and checks that data/index persistence did not leave a missing record.
        Ok(store.Disconnect(recovered.tip, error), error, "native crash undo readable");
        DiskStateTransaction tx;
        Ok(store.Begin(tx, error), error, "native crash continue begin");
        Ok(tx.Insert(MakeCoin(first + 9000), error), error, "native crash continue insert");
        Ok(tx.Commit(Meta(3), error), error, "native crash continue commit");
        tx.Abort();
        store = {};
        Ok(DiskStateStore::Open(home, Options(), Meta(0), store, error), error, "native crash continue reopen");
        Check(store.Metadata() == Meta(3), "native crash continued head persists");
        std::cout << "native process crash cycle " << cycle << " recovered " << count
                  << " coins; authenticated reads, undo and continuation passed\n";
    }
}
#endif

constexpr uint8_t ReverseByte(uint8_t b) {
    b = static_cast<uint8_t>(((b & 0xF0u) >> 4) | ((b & 0x0Fu) << 4));
    b = static_cast<uint8_t>(((b & 0xCCu) >> 2) | ((b & 0x33u) << 2));
    b = static_cast<uint8_t>(((b & 0xAAu) >> 1) | ((b & 0x55u) << 1));
    return b;
}
std::string Key(const Outpoint &outpoint) {
    std::string key(1, 'C');
    for (uint8_t b : outpoint.tx_id) key.push_back(static_cast<char>(ReverseByte(b)));
    for (unsigned i = 0; i < 4; ++i) key.push_back(outpoint.index >> (8 * i));
    return key;
}
std::string Encoded(const Coin &coin) {
    std::vector<uint8_t> bytes; Check(EncodeCoin(coin, bytes), "encode fixture");
    return std::string(bytes.begin(), bytes.end());
}
void SameProof(const CoinProof &actual, const CoinProof &expected, const Outpoint &query, const Hash &root) {
    Check(actual.presence == expected.presence && actual.bitmap == expected.bitmap &&
          actual.siblings == expected.siblings && actual.coin.has_value() == expected.coin.has_value(),
          "exact oracle proof structure");
    if (actual.coin) Check(Encoded(*actual.coin) == Encoded(*expected.coin), "exact terminal coin");
    Check(VerifyCoinProof(query, actual, root), "proof verification");
}
void Probe(DiskStateStore &store, const IncrementalUtxoSet &oracle, uint32_t index, bool present) {
    DiskStateError error;
    const auto query = MakeCoin(index).outpoint;
    CoinProof proof; Ok(store.Prove(query, proof, error), error, "prove disk state");
    SameProof(proof, oracle.Prove(query), query, oracle.Root());
    std::optional<Coin> coin;
    Ok(store.ReadCoin(query, coin, error), error, "authenticated coin read");
    Check(coin.has_value() == present, "authenticated membership");
    if (coin) Check(Encoded(*coin) == Encoded(MakeCoin(index)), "coin bytes");
}
// Inject failures into the existing LevelDB WAL, never into an invented DB.
class FaultEnv : public leveldb::EnvWrapper {
public:
    enum class Fault { None, Append, Sync } fault{Fault::None};
    FaultEnv() : EnvWrapper(leveldb::Env::Default()) {}
    class File : public leveldb::WritableFile {
        FaultEnv &env;
        std::unique_ptr<leveldb::WritableFile> file;
    public:
        File(FaultEnv &e, leveldb::WritableFile *f) : env(e), file(f) {}
        std::string GetName() const override { return file->GetName(); }
        leveldb::Status Append(const leveldb::Slice &data) override {
            if (env.fault == Fault::Append) return leveldb::Status::IOError("injected WAL append");
            return file->Append(data);
        }
        leveldb::Status Close() override { return file->Close(); }
        leveldb::Status Flush() override { return file->Flush(); }
        leveldb::Status Sync() override {
            if (env.fault == Fault::Sync) return leveldb::Status::IOError("injected WAL sync");
            return file->Sync();
        }
    };
    leveldb::Status NewWritableFile(const std::string &name, leveldb::WritableFile **out) override {
        auto status = target()->NewWritableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return status;
    }
    leveldb::Status NewAppendableFile(const std::string &name, leveldb::WritableFile **out) override {
        auto status = target()->NewAppendableFile(name, out);
        if (status.ok() && name.ends_with(".log")) *out = new File(*this, *out);
        return status;
    }
};
void RawChange(const std::string &directory, const std::string &key, const std::optional<std::string> &value) {
    std::string err;
    Check(RawDiskStateAccess(directory, std::nullopt, nullptr, {{key, value}}, &err), "raw mutation: " + err);
}
std::string RawRead(const std::string &directory, const std::string &key) {
    std::optional<std::string> value;
    std::string err;
    Check(RawDiskStateAccess(directory, key, &value, {}, &err) && value.has_value(), "raw read value: " + err);
    return *value;
}
struct UndoTestRow {
    std::string key;
    std::optional<std::string> before, after;
};
struct UndoTestRecord {
    std::string before_head, after_head;
    std::vector<UndoTestRow> rows;
};
UndoTestRecord ParseTestUndo(const std::string &bytes) {
    size_t at{};
    auto Int = [&](unsigned width) {
        Check(width <= bytes.size() - at, "test undo integer bounds");
        uint64_t value{};
        for (unsigned i = 0; i < width; ++i) value |= uint64_t(uint8_t(bytes[at++])) << (8 * i);
        return value;
    };
    auto Blob = [&]() {
        const auto size = Int(8); Check(size <= bytes.size() - at, "test undo blob bounds");
        const auto value = bytes.substr(at, size); at += size; return value;
    };
    auto Value = [&]() -> std::optional<std::string> {
        const auto present = Int(1); Check(present <= 1, "test undo value tag");
        return present ? std::optional<std::string>(Blob()) : std::nullopt;
    };
    UndoTestRecord record; record.before_head = Blob(); record.after_head = Blob();
    const auto count = Int(8); Check(count <= bytes.size(), "test undo row count");
    for (uint64_t i = 0; i < count; ++i) {
        UndoTestRow row; row.key = Blob(); row.before = Value(); row.after = Value();
        record.rows.push_back(std::move(row));
    }
    Check(at == bytes.size(), "test undo exact framing"); return record;
}
std::string EncodeTestUndo(const UndoTestRecord &record) {
    std::string bytes;
    auto Int = [&](uint64_t value, unsigned width) {
        for (unsigned i = 0; i < width; ++i) bytes.push_back(value >> (8 * i));
    };
    auto Blob = [&](const std::string &value) { Int(value.size(), 8); bytes += value; };
    auto Value = [&](const std::optional<std::string> &value) { Int(value.has_value(), 1); if (value) Blob(*value); };
    Blob(record.before_head); Blob(record.after_head); Int(record.rows.size(), 8);
    for (const auto &row : record.rows) { Blob(row.key); Value(row.before); Value(row.after); }
    return bytes;
}
void UndoBeforeCorruption(const std::string &directory) {
    auto options = Options(); DiskStateStore store; DiskStateError error;
    const Coin removed = MakeCoin(1);
    const bool removed_bit = OutpointKey(removed.outpoint)[0] & 1;
    Coin survivor;
    for (uint32_t id = 2;; ++id) {
        survivor = MakeCoin(id);
        if ((OutpointKey(survivor.outpoint)[0] & 1) != removed_bit) break;
    }
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "undo corruption open");
    DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "undo fixture begin");
    Ok(tx.Insert(removed, error), error, "undo fixture removed");
    Ok(tx.Insert(survivor, error), error, "undo fixture survivor");
    Ok(tx.Commit(Meta(1), error), error, "undo predecessor commit"); tx.Abort();
    const Hash predecessor = store.Root();
    Ok(store.Begin(tx, error), error, "undo erase begin");
    Ok(tx.Erase(removed.outpoint, error), error, "undo erase fixture");
    Ok(tx.Commit(Meta(2), error), error, "undo successor commit"); tx.Abort();
    const Hash successor = store.Root(); store = {};
    std::string undo_key(1, 'U'); const Hash tip = Id(2);
    undo_key.append(reinterpret_cast<const char *>(tip.data()), tip.size());
    const std::string canonical = RawRead(directory, undo_key);
    const UndoTestRecord original = ParseTestUndo(canonical);
    Check(EncodeTestUndo(original) == canonical, "independent undo framing roundtrip");
    std::string root_key(1, 'N'); root_key.append(34, '\0');
    const std::string original_head = RawRead(directory, "S"), original_root = RawRead(directory, root_key);
    for (unsigned variant = 0; variant < 8; ++variant) {
        auto altered = original; bool changed{};
        for (auto &row : altered.rows) {
            if (variant <= 1 && row.key == Key(removed.outpoint)) {
                if (variant == 0) { Coin bad = removed; ++bad.output.value; row.before = Encoded(bad); }
                else row.before.reset();
                changed = true;
            }
            if (variant == 2 && row.key[0] == 'N' && row.key != root_key && row.before && !changed) {
                (*row.before)[1] ^= 1; changed = true; // Old leaf hash disagrees with its coin/parent.
            }
            if (variant == 3 && row.key == root_key) {
                Check(row.before && row.before->size() == 99, "undo branch fixture");
                const size_t child_kind = 33 + 33 * !removed_bit;
                Check((*row.before)[child_kind] == 1, "undo singleton sibling fixture");
                (*row.before)[child_kind] = 2; changed = true; // Digests unchanged.
            }
            if (variant == 4 && row.key == root_key) { row.before.reset(); changed = true; }
        }
        if (variant == 5) {
            Check(altered.before_head.size() > 78, "undo predecessor head fixture");
            altered.before_head[78] ^= 1; changed = true; // Root digest only.
        }
        if (variant == 6) { altered.before_head.push_back('x'); changed = true; }
        if (variant == 7) { altered.before_head[45] ^= 1; changed = true; } // Profile digest.
        Check(changed, "undo corruption variant applied");
        RawChange(directory, undo_key, EncodeTestUndo(altered));
        Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "tampered undo reopen");
        const auto expected_error = variant == 7 ? DiskStateErrorCode::ProfileMismatch : DiskStateErrorCode::Corruption;
        bool callback_called{};
        const DiskStateMetadataValidator validate = [&](const DiskStateMetadata &, const Hash &, DiskStateError &) {
            callback_called = true; return true;
        };
        Check(!store.Disconnect(Id(2), validate, error) && error.code == expected_error,
              "undo before-value corruption must fail before publication, variant " + std::to_string(variant));
        Check(!callback_called, "inverse authentication precedes metadata callback");
        Check(store.Root() == successor && store.Metadata() == Meta(2), "failed undo keeps current head");
        std::optional<Coin> coin;
        Ok(store.ReadCoin(removed.outpoint, coin, error), error, "failed undo removed absence"); Check(!coin, "failed undo does not restore coin");
        Ok(store.ReadCoin(survivor.outpoint, coin, error), error, "failed undo survivor"); Check(coin.has_value(), "failed undo survivor unchanged");
        store = {};
        Check(RawRead(directory, "S") == original_head && RawRead(directory, root_key) == original_root,
              "tampered undo publishes no predecessor head/node writes");
    }
    RawChange(directory, undo_key, canonical);
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "restore undo reopen");
    Ok(store.Disconnect(Id(2), error), error, "untampered undo accepted");
    Check(store.Root() == predecessor && store.Metadata() == Meta(1), "untampered predecessor exact");
    std::optional<Coin> restored;
    Ok(store.ReadCoin(removed.outpoint, restored, error), error, "restored undo authenticated coin");
    Check(restored && Encoded(*restored) == Encoded(removed), "restored undo exact coin");
    Check(store.LastStats().database_reads < original.rows.size() * 260 + 4,
          "undo validation remains bounded by changed paths");
}
void UndoMetadataCallbacks(const std::string &directory) {
    const auto options = Options(); DiskStateStore store; DiskStateError error;
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "callback open");
    DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "callback predecessor begin");
    Ok(tx.Insert(MakeCoin(1), error), error, "callback predecessor coin");
    Ok(tx.Commit(Meta(1), error), error, "callback predecessor commit"); tx.Abort();
    const Hash predecessor = store.Root();
    Ok(store.Begin(tx, error), error, "callback successor begin");
    Ok(tx.Insert(MakeCoin(2), error), error, "callback successor coin");
    Ok(tx.Commit(Meta(2), error), error, "callback successor commit"); tx.Abort();
    const Hash successor = store.Root(); store = {};
    std::string root_key(1, 'N'); root_key.append(34, '\0');
    const auto raw_head = RawRead(directory, "S"), raw_root = RawRead(directory, root_key);
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "callback fixture reopen");
    for (unsigned variant = 0; variant < 7; ++variant) {
        unsigned calls{};
        const DiskStateMetadataValidator reject = [&](const DiskStateMetadata &metadata, const Hash &root,
                                                       DiskStateError &callback_error) -> bool {
            ++calls;
            Check(metadata == Meta(1) && root == predecessor, "callback receives exact predecessor metadata/root");
            Check(store.Root() == successor && store.Metadata() == Meta(2), "callback publication is deferred");
            DiskStateTransaction reentrant; DiskStateError nested;
            Check(!store.Begin(reentrant, nested) && nested.code == DiskStateErrorCode::TransactionAborted,
                  "callback blocks reentrant transaction");
            Check(!store.Disconnect(Id(2), nested) && nested.code == DiskStateErrorCode::TransactionAborted,
                  "callback blocks reentrant disconnect");
            std::optional<Coin> current;
            Ok(store.ReadCoin(MakeCoin(2).outpoint, current, nested), nested, "callback current-state read");
            Check(current.has_value(), "callback reads retain current committed view");
            if (variant == 0) callback_error = {DiskStateErrorCode::Corruption, "opaque predecessor rejected"};
            if (variant == 2) throw std::runtime_error("opaque metadata exception");
            if (variant == 3) throw 17;
            if (variant == 4) throw std::bad_alloc{};
            if (variant == 5) callback_error = {DiskStateErrorCode::InvalidCoin, "wrong callback error category"};
            if (variant == 6) callback_error = {DiskStateErrorCode::Resource, "metadata validation resources"};
            return false;
        };
        const auto expected = variant == 2 || variant == 3 ? DiskStateErrorCode::Database :
                              variant == 4 || variant == 6 ? DiskStateErrorCode::Resource : DiskStateErrorCode::Corruption;
        Check(!store.Disconnect(Id(2), reject, error) && error.code == expected, "callback refusal/exception operational");
        Check(calls == 1, "callback invoked once");
        Check(store.Root() == successor && store.Metadata() == Meta(2), "callback failure keeps cached head/root");
        Ok(store.Begin(tx, error), error, "callback guard released after failure"); tx.Abort();
        store = {};
        Check(RawRead(directory, "S") == raw_head && RawRead(directory, root_key) == raw_root &&
              RawRead(directory, Key(MakeCoin(2).outpoint)) == Encoded(MakeCoin(2)),
              "callback failure performs no state publication");
        Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "callback failure reopen");
    }
    unsigned accepted_calls{};
    const DiskStateMetadataValidator accept = [&](const DiskStateMetadata &metadata, const Hash &root,
                                                   DiskStateError &) {
        ++accepted_calls; Check(metadata == Meta(1) && root == predecessor, "accepted callback exact predecessor");
        Check(store.Root() == successor && store.Metadata() == Meta(2), "accepted callback precedes publication");
        return true;
    };
    Ok(store.Disconnect(Id(2), accept, error), error, "accepted metadata callback disconnect");
    Check(accepted_calls == 1 && store.Root() == predecessor && store.Metadata() == Meta(1), "accepted callback publishes predecessor");
    std::optional<Coin> current;
    Ok(store.ReadCoin(MakeCoin(2).outpoint, current, error), error, "accepted callback inverse coin"); Check(!current, "accepted callback restores coin absence");
    Ok(store.Disconnect(Id(1), error), error, "legacy disconnect overload");
    Check(store.Root() == EmptyUtxoRoot() && store.Metadata() == Meta(0), "legacy overload preserves behavior");
}
class RetainedReadEnv : public leveldb::EnvWrapper {
public:
    enum class Mode { None, CorruptRead, DifferentHead } mode{Mode::None};
    std::string head, different;
    mutable unsigned injections{};
    RetainedReadEnv() : EnvWrapper(leveldb::Env::Default()) {}
    class File : public leveldb::RandomAccessFile {
        RetainedReadEnv &env;
        std::unique_ptr<leveldb::RandomAccessFile> file;
    public:
        File(RetainedReadEnv &e, leveldb::RandomAccessFile *f) : env(e), file(f) {}
        std::string GetName() const override { return file->GetName(); }
        leveldb::Status Read(uint64_t offset, size_t n, leveldb::Slice *out, char *scratch) const override {
            auto status = file->Read(offset, n, out, scratch);
            if (!status.ok() || env.mode == Mode::None) return status;
            if (env.mode == Mode::CorruptRead) {
                ++env.injections; return leveldb::Status::Corruption("injected persisted head read");
            }
            // Inject a valid-but-different S value through the bundled Env.
            // Keep the uncompressed SST block's CRC valid to exercise the
            // cached-head fence rather than merely checksum verification.
            if (out->size() != n || n < 5 || (*out)[n - 5] != 0) return status;
            std::string bytes(out->data(), n); const auto at = bytes.find(env.head);
            if (at == std::string::npos) return status;
            Check(env.head.size() == env.different.size(), "head injection preserves framing");
            bytes.replace(at, env.head.size(), env.different);
            const uint32_t crc = crc32c::Crc32c(bytes.data(), n - 4);
            const uint32_t masked = ((crc >> 15) | (crc << 17)) + 0xa282ead8u;
            for (unsigned i = 0; i < 4; ++i) bytes[n - 4 + i] = masked >> (8 * i);
            std::memcpy(scratch, bytes.data(), n); *out = leveldb::Slice(scratch, n);
            ++env.injections; return status;
        }
    };
    leveldb::Status NewRandomAccessFile(const std::string &name, leveldb::RandomAccessFile **out) override {
        auto status = target()->NewRandomAccessFile(name, out);
        if (status.ok() && (name.ends_with(".ldb") || name.ends_with(".sst"))) *out = new File(*this, *out);
        return status;
    }
};
void RetainedStateCases(const std::string &directory) {
    auto options = Options(); DiskStateStore store; DiskStateError error;
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "retained open");
    DiskStateTransaction tx; std::vector<Hash> roots(5);
    Ok(store.Begin(tx, error), error, "retained first begin");
    Ok(tx.Insert(MakeCoin(1), error), error, "retained first insert");
    Ok(tx.Commit(Meta(1), error), error, "retained first commit"); tx.Abort(); roots[1] = store.Root();
    Ok(store.Begin(tx, error), error, "retained second begin");
    Ok(tx.Erase(MakeCoin(1).outpoint, error), error, "retained erase old coin");
    Ok(tx.Insert(MakeCoin(2), error), error, "retained second insert");
    Ok(tx.Commit(Meta(2), error), error, "retained second commit"); tx.Abort(); roots[2] = store.Root();
    Ok(store.Begin(tx, error), error, "retained third begin");
    Ok(tx.Insert(MakeCoin(3), error), error, "retained third insert");
    Ok(tx.Commit(Meta(3), error), error, "retained third commit"); tx.Abort(); roots[3] = store.Root();
    auto Read = [&](uint32_t id) {
        const auto reads = store.LastStats().database_reads;
        std::optional<RetainedDiskState> state;
        Ok(store.ReadRetainedState(Id(id), state, error), error, "retained metadata lookup");
        Check(state && state->metadata == Meta(id) && state->root == roots[id], "retained exact metadata/root");
        Check(store.LastStats().database_reads - reads == (store.Metadata().tip == Id(id) ? 1 : 2),
              "retained lookup reads only S and optional U, never live C/N");
    };
    Read(1); Read(2); Read(3);
    Ok(store.Begin(tx, error), error, "retained pending begin");
    Ok(tx.Insert(MakeCoin(4), error), error, "retained uncommitted coin");
    std::optional<RetainedDiskState> state;
    Ok(store.ReadRetainedState(Id(4), state, error), error, "uncommitted retained lookup"); Check(!state, "uncommitted ID missing"); tx.Abort();
    Ok(store.Disconnect(Id(3), error), error, "retained third disconnect"); Read(3);
    Ok(store.Disconnect(Id(2), error), error, "retained second disconnect"); Read(2); Read(1);
    Ok(store.Begin(tx, error), error, "retained fork begin");
    Ok(tx.Insert(MakeCoin(4), error), error, "retained fork insert");
    Ok(tx.Commit(Meta(4), error), error, "retained fork commit"); tx.Abort(); roots[4] = store.Root();
    store = {}; Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "retained reopen");
    Read(1); Read(2); Read(3); Read(4);
    state = RetainedDiskState{Meta(999), Id(999)};
    Ok(store.ReadRetainedState(Id(999), state, error), error, "missing retained ID"); Check(!state, "missing clears output");
    store = {};
    state = RetainedDiskState{Meta(999), Id(999)};
    Check(!store.ReadRetainedState(Id(1), state, error) && error.code == DiskStateErrorCode::Closed &&
          state->metadata == Meta(999) && state->root == Id(999), "closed retained lookup preserves output");
    std::string undo_key(1, 'U'); const Hash two = Id(2);
    undo_key.append(reinterpret_cast<const char *>(two.data()), two.size());
    const auto canonical = RawRead(directory, undo_key); const auto original = ParseTestUndo(canonical);
    for (unsigned variant = 0; variant < 12; ++variant) {
        auto altered = original;
        if (variant == 2) altered.after_head[110] ^= 1; // tip, same valid head grammar.
        if (variant == 3) altered.after_head[45] ^= 1; // profile digest.
        if (variant == 4) altered.before_head[45] ^= 1;
        if (variant == 5) altered.rows.front().key[0] = 'X';
        if (variant == 6) altered.rows[1].key = altered.rows[0].key;
        if (variant == 7) std::reverse(altered.rows.begin(), altered.rows.end());
        if (variant == 8) altered.rows.front().before = altered.rows.front().after;
        if (variant == 9) {
            auto it = std::find_if(altered.rows.begin(), altered.rows.end(), [](const auto &row) { return row.key[0] == 'C' && row.before.has_value(); });
            Check(it != altered.rows.end(), "retained old coin fixture");
            it->before = Encoded(MakeCoin(999));
        }
        if (variant == 10) {
            auto it = std::find_if(altered.rows.begin(), altered.rows.end(), [](const auto &row) { return row.key[0] == 'N' && row.before; });
            Check(it != altered.rows.end(), "retained old node fixture"); (*it->before)[1] ^= 1;
        }
        if (variant == 11) altered.after_head.push_back('x');
        auto bytes = EncodeTestUndo(altered);
        if (variant == 0) bytes.pop_back();
        if (variant == 1) bytes.push_back('x');
        RawChange(directory, undo_key, bytes);
        Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "corrupt historical U reopen");
        state = RetainedDiskState{Meta(999), Id(999)};
        const auto expected = variant == 3 || variant == 4 ? DiskStateErrorCode::ProfileMismatch : DiskStateErrorCode::Corruption;
        Check(!store.ReadRetainedState(Id(2), state, error) && error.code == expected &&
              state->metadata == Meta(999) && state->root == Id(999), "corrupt historical record preserves output");
        Check(store.Metadata() == Meta(4) && store.Root() == roots[4], "historical read never mutates chainstate");
        store = {};
    }
    RawChange(directory, undo_key, canonical);
    RetainedReadEnv env; env.head = RawRead(directory, "S"); env.different = env.head;
    env.different.back() ^= 1; // Valid metadata bytes with the same ID/root.
    options.env = &env; options.cache_bytes = 1;
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "retained SST reopen");
    for (auto mode : {RetainedReadEnv::Mode::DifferentHead, RetainedReadEnv::Mode::CorruptRead}) {
        store = {};
        Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "fresh retained read injection");
        env.mode = mode; env.injections = 0; state = RetainedDiskState{Meta(999), Id(999)};
        Check(!store.ReadRetainedState(Id(4), state, error) && error.code == DiskStateErrorCode::Corruption && env.injections &&
              state->metadata == Meta(999) && state->root == Id(999), "current S corruption rejects cached serving");
        if (mode == RetainedReadEnv::Mode::DifferentHead) Check(error.message == "persisted/cached head mismatch", "valid different S reaches cached-head fence");
        env.mode = RetainedReadEnv::Mode::None; store = {};
    }
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "retained injection cleanup reopen"); Read(4);
    std::optional<DiskBlockLocation> blk_loc;
    std::optional<DiskUndoLocation> undo_loc;
    Ok(store.ReadBlockLocation(Id(2), blk_loc, error), error, "read block location");
    Ok(store.ReadUndoLocation(Id(2), undo_loc, error), error, "read undo location");
    Check(blk_loc.has_value() && undo_loc.has_value() && undo_loc->length == canonical.size(), "flat file locations populated");
    std::vector<uint8_t> undo_slice;
    uint64_t undo_total{};
    Ok(store.ReadUndoSlice(Id(2), 4, 16, undo_slice, &undo_total, error), error, "read undo slice");
    Check(undo_total == canonical.size() && undo_slice.size() == 16 &&
          std::equal(undo_slice.begin(), undo_slice.end(), reinterpret_cast<const uint8_t *>(canonical.data() + 4)),
          "flat undo pread slice exact");
    store = {}; options.env = nullptr;
}
void SiblingKindCorruption(const std::string &directory) {
    auto options = Options(); DiskStateStore store; DiskStateError error;
    const Coin removed = MakeCoin(1);
    const bool removed_bit = OutpointKey(removed.outpoint)[0] & 1;
    Coin survivor;
    for (uint32_t id = 2;; ++id) {
        survivor = MakeCoin(id);
        if ((OutpointKey(survivor.outpoint)[0] & 1) != removed_bit) break;
    }
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "kind corruption open");
    DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "kind fixture begin");
    Ok(tx.Insert(removed, error), error, "kind removed fixture");
    Ok(tx.Insert(survivor, error), error, "kind survivor fixture");
    Ok(tx.Commit(Meta(1), error), error, "kind fixture commit"); tx.Abort();
    const Hash original_root = store.Root(); store = {};
    std::string root_key(1, 'N'); root_key.append(34, '\0');
    const std::string canonical = RawRead(directory, root_key);
    Check(canonical.size() == 99 && canonical[0] == 2, "two-leaf root branch fixture");
    std::string altered = canonical;
    const size_t sibling_kind_at = 33 + 33 * !removed_bit;
    Check(altered[sibling_kind_at] == 1, "sibling originally singleton");
    // Summary.kind is storage metadata; UtxoNode hashes only child digests.
    // Changing this byte leaves both authenticated leaf/root digests unchanged.
    altered[sibling_kind_at] = 2;
    RawChange(directory, root_key, altered);
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "kind corruption lazy reopen");
    Check(store.Root() == original_root, "tamper preserves root digest");
    std::optional<Coin> coin;
    Ok(store.ReadCoin(removed.outpoint, coin, error), error, "unaffected deletion path still authenticates");
    Check(coin.has_value(), "deletion input exists before collapse");
    Ok(store.Begin(tx, error), error, "kind deletion begin");
    Check(!tx.Erase(removed.outpoint, error) && error.code == DiskStateErrorCode::Corruption,
          "forged sibling cardinality cannot suppress singleton collapse");
    Check(!tx.Commit(Meta(2), error) && error.code == DiskStateErrorCode::TransactionAborted,
          "corrupted collapse cannot publish new root");
    tx.Abort();
    Check(store.Root() == original_root && store.Metadata() == Meta(1), "corrupt collapse leaves committed state");
    store = {};
    Check(RawRead(directory, root_key) == altered && RawRead(directory, Key(removed.outpoint)) == Encoded(removed),
          "failed collapse performs no disk writes");
    RawChange(directory, root_key, canonical);
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "kind canonical restore");
    Ok(store.Begin(tx, error), error, "kind valid erase begin");
    Ok(tx.Erase(removed.outpoint, error), error, "valid singleton collapse");
    Hash expected; Check(UtxoLeaf(survivor, expected) && tx.Root() == expected, "actual singleton uses leaf digest");
    Ok(tx.Commit(Meta(2), error), error, "valid collapse commit"); tx.Abort();
    Ok(store.Disconnect(Id(2), error), error, "valid collapse rollback");
    Check(store.Root() == original_root, "valid collapse rollback exact root");
}
void SmallCases(const std::string &directory) {
    DiskStateError error; auto options = Options(); DiskStateStore store;
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "open empty");
    IncrementalUtxoSet oracle;
    Probe(store, oracle, 0, false);
    Check(store.Root() == EmptyUtxoRoot() && store.Metadata() == Meta(0), "empty initial state");
    DiskStateTransaction tx;
    Ok(store.Begin(tx, error), error, "begin");
    DiskStateTransaction second;
    Check(!store.Begin(second, error) && error.code == DiskStateErrorCode::TransactionAborted, "single writer");
    Ok(tx.Insert(MakeCoin(0), error), error, "stage aborted coin");
    Check(store.Root() == EmptyUtxoRoot(), "stage invisible to committed root");
    tx.Abort(); Probe(store, oracle, 0, false);
    for (uint32_t id = 1; id <= 3; ++id) {
        Ok(store.Begin(tx, error), error, "begin small");
        Ok(tx.Insert(MakeCoin(id), error), error, "insert small"); Check(oracle.Insert(MakeCoin(id)), "oracle small");
        Check(tx.Root() == oracle.Root(), "staged root");
        CoinProof proof; Ok(tx.Prove(MakeCoin(id).outpoint, proof, error), error, "staged proof");
        SameProof(proof, oracle.Prove(MakeCoin(id).outpoint), MakeCoin(id).outpoint, oracle.Root());
        Check(!tx.Insert(MakeCoin(id), error) && error.code == DiskStateErrorCode::Duplicate, "duplicate");
        Check(!tx.Erase(MakeCoin(999).outpoint, error) && error.code == DiskStateErrorCode::Missing, "missing erase");
        Coin invalid = MakeCoin(999); invalid.output.flags = 2; invalid.output.paths.clear();
        Check(!tx.Insert(invalid, error) && error.code == DiskStateErrorCode::InvalidCoin, "burn coin");
        Ok(tx.Commit(Meta(id), error), error, "commit small"); tx.Abort();
        Check(store.Root() == oracle.Root() && store.Metadata() == Meta(id), "committed root and metadata");
        Probe(store, oracle, id, true);
    }
    const Hash three = store.Root();
    Ok(store.Begin(tx, error), error, "begin multi collapse");
    for (uint32_t id : {2U, 1U, 3U}) {
        Ok(tx.Erase(MakeCoin(id).outpoint, error), error, "erase multi collapse");
        Check(oracle.Erase(MakeCoin(id).outpoint), "oracle multi collapse");
        Check(tx.Root() == oracle.Root(), "collapse to one then empty root");
    }
    Ok(tx.Commit(Meta(4), error), error, "commit empty after multi erase"); tx.Abort();
    Check(store.Root() == EmptyUtxoRoot(), "multi erase commits empty");
    store = {}; Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "reopen collapsed empty");
    Ok(store.Disconnect(Id(4), error), error, "undo multi erase");
    for (uint32_t id = 1; id <= 3; ++id) Check(oracle.Insert(MakeCoin(id)), "oracle restore multi");
    Check(store.Root() == three, "multi erase exact rollback");
    Check(!store.Disconnect(Id(2), error) && error.code == DiskStateErrorCode::UndoMismatch, "wrong tip rejects");
    Ok(store.Disconnect(Id(3), error), error, "disconnect"); Check(oracle.Erase(MakeCoin(3).outpoint), "oracle disconnect");
    Probe(store, oracle, 3, false);
    // Existing undo cannot be replaced by a divergent state for the same ID.
    Ok(store.Begin(tx, error), error, "begin immutable undo check");
    Ok(tx.Insert(MakeCoin(44), error), error, "divergent coin");
    Check(!tx.Commit(Meta(3), error) && error.code == DiskStateErrorCode::UndoMismatch, "immutable undo");
    tx.Abort(); Check(store.Root() == oracle.Root(), "failed undo overwrite leaves state");
    Ok(store.Begin(tx, error), error, "reconnect");
    Ok(tx.Insert(MakeCoin(3), error), error, "reconnect coin"); Ok(tx.Commit(Meta(3), error), error, "reuse immutable undo"); tx.Abort();
    Check(store.Root() == three, "reconnect exact root"); Check(oracle.Insert(MakeCoin(3)), "oracle reconnect");
    for (uint32_t id = 3; id > 0; --id) {
        Ok(store.Disconnect(Id(id), error), error, "disconnect to empty");
        Check(oracle.Erase(MakeCoin(id).outpoint), "oracle collapse");
        Check(store.Root() == oracle.Root(), "single/empty collapse"); Probe(store, oracle, id, false);
    }
    Ok(store.Begin(tx, error), error, "begin net empty");
    Ok(tx.Insert(MakeCoin(81), error), error, "transient insert");
    Ok(tx.Erase(MakeCoin(81).outpoint, error), error, "transient erase");
    Check(tx.Stats().dirty_coins == 0 && tx.Stats().dirty_nodes == 0 && tx.Stats().pending_bytes == 0,
          "net no-op delta eliminated");
    Ok(tx.Commit(Meta(100), error), error, "empty delta metadata commit"); tx.Abort();
    Check(store.LastStats().batch_puts == 3 && store.LastStats().batch_deletes == 0, "empty batch schema/head/undo");
    Ok(store.Disconnect(Id(100), error), error, "empty delta undo");
    store = {};
    auto wrong = options; wrong.profile_digest = Id(99);
    Check(!DiskStateStore::Open(directory, wrong, Meta(0), store, error) && error.code == DiskStateErrorCode::ProfileMismatch,
          "profile mismatch");
    wrong = options; wrong.identity = Id(99);
    Check(!DiskStateStore::Open(directory, wrong, Meta(0), store, error) && error.code == DiskStateErrorCode::ProfileMismatch,
          "identity mismatch");
    Ok(DiskStateStore::Open(directory, options, Meta(9), store, error), error, "reopen empty");
    Check(store.Root() == EmptyUtxoRoot() && store.Metadata() == Meta(0), "persisted metadata overrides initializer");
}
void LargeAndMixed(const std::string &directory) {
    DiskStateStore store; DiskStateError error; auto options = Options();
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "open large");
    IncrementalUtxoSet oracle;
    constexpr uint32_t total = 4096, group = 64;
    uint32_t tip{};
    for (uint32_t start = 0; start < total; start += group) {
        DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "begin large");
        for (uint32_t id = start; id < start + group; ++id) {
            Ok(tx.Insert(MakeCoin(id), error), error, "large insert");
            Check(oracle.Insert(MakeCoin(id)), "large oracle insert"); Check(tx.Root() == oracle.Root(), "every insertion root");
        }
        const auto staged = tx.Stats();
        Check(staged.dirty_coins == group && staged.dirty_nodes < group * 257 && staged.database_reads < group * 1100,
              "changed-state path bounds");
        Ok(tx.Commit(Meta(++tip), error), error, "large commit");
        Check(store.LastStats().batch_puts == staged.dirty_coins + staged.dirty_nodes + 3,
              "deduplicated dirty nodes written once");
    }
    const Hash full = oracle.Root(); store = {};
    uint64_t data_size{};
    for (const auto &entry : std::filesystem::directory_iterator(directory))
        if (entry.is_regular_file()) data_size += entry.file_size();
    Check(data_size > options.cache_bytes * 100, "database much larger than tiny cache");
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "reopen large");
    Check(store.Root() == full && store.LastStats().database_reads <= 4, "bounded reopen without UTXO scan");
    for (uint32_t id = 0; id < total; id += 97) Probe(store, oracle, id, true);
    Probe(store, oracle, total + 5, false);
    const auto before = store.Metadata();
    std::vector<uint32_t> permutation(total); std::iota(permutation.begin(), permutation.end(), 0);
    std::mt19937 random(12345); std::shuffle(permutation.begin(), permutation.end(), random);
    DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "mixed begin");
    for (uint32_t i = 0; i < 512; ++i) {
        Ok(tx.Erase(MakeCoin(permutation[i]).outpoint, error), error, "mixed delete");
        Check(oracle.Erase(MakeCoin(permutation[i]).outpoint), "mixed oracle delete");
        Ok(tx.Insert(MakeCoin(total + i), error), error, "mixed insert");
        Check(oracle.Insert(MakeCoin(total + i)), "mixed oracle insert");
        Check(tx.Root() == oracle.Root(), "every mixed update root");
        if (i % 41 == 0) {
            CoinProof proof; const auto query = MakeCoin(permutation[i]).outpoint;
            Ok(tx.Prove(query, proof, error), error, "staged absence proof");
            SameProof(proof, oracle.Prove(query), query, oracle.Root());
        }
    }
    Ok(tx.Commit(Meta(++tip), error), error, "mixed commit"); tx.Abort();
    Check(store.Root() == oracle.Root(), "mixed committed root");
    for (uint32_t i = 0; i < 512; i += 31) { Probe(store, oracle, permutation[i], false); Probe(store, oracle, total + i, true); }
    store = {}; Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "reopen mixed");
    Ok(store.Disconnect(Id(tip), error), error, "disconnect after reopen");
    Check(store.Root() == full && store.Metadata() == before, "exact atomic metadata/root rollback");
    for (uint32_t i = 0; i < 512; ++i) { Check(oracle.Erase(MakeCoin(total + i).outpoint), "oracle undo insert"); Check(oracle.Insert(MakeCoin(permutation[i])), "oracle undo delete"); }
    Probe(store, oracle, permutation[0], true); Probe(store, oracle, total, false);
    // Alternate branch from the same predecessor, retained old branch undo.
    Ok(store.Begin(tx, error), error, "reorg begin");
    Ok(tx.Erase(MakeCoin(17).outpoint, error), error, "reorg delete");
    Ok(tx.Insert(MakeCoin(9000), error), error, "reorg insert");
    Ok(tx.Commit(Meta(9000), error), error, "reorg commit"); tx.Abort();
    Ok(store.Disconnect(Id(9000), error), error, "reorg disconnect");
    Check(store.Root() == full && store.Metadata() == before, "reorg predecessor restored");
    std::cout << "large-state bytes=" << data_size << " cache=" << options.cache_bytes
              << " oracle-coins=" << total << '\n';
}
void FailureCases(const std::string &directory) {
    DiskStateError error; auto options = Options(); DiskStateStore store;
    options.max_pending_bytes = 1;
    Ok(DiskStateStore::Open(directory + "-resource", options, Meta(0), store, error), error, "resource open");
    DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "resource begin");
    Check(!tx.Insert(MakeCoin(1), error) && error.code == DiskStateErrorCode::Resource, "resource distinct");
    Check(!tx.Commit(Meta(1), error) && error.code == DiskStateErrorCode::TransactionAborted, "partial stage cannot commit");
    tx.Abort(); Check(store.Root() == EmptyUtxoRoot() && store.Metadata() == Meta(0), "resource atomic abort");
    store = {}; options = Options();
    FaultEnv env; options.env = &env;
    for (auto fault : {FaultEnv::Fault::Append, FaultEnv::Fault::Sync}) {
        const auto path = directory + (fault == FaultEnv::Fault::Append ? "-append" : "-sync");
        Ok(DiskStateStore::Open(path, options, Meta(0), store, error), error, "fault open");
        Ok(store.Begin(tx, error), error, "fault begin"); Ok(tx.Insert(MakeCoin(1), error), error, "fault stage");
        const Hash staged = tx.Root(); env.fault = fault;
        Check(!tx.Commit(Meta(1), error) && error.code == DiskStateErrorCode::Database, "write error is operational");
        Check(!store.IsOpen(), "failed write requires reopen");
        Check(!tx.Commit(Meta(1), error), "failed write cannot retry poisoned store");
        tx.Abort(); store = {}; env.fault = FaultEnv::Fault::None;
        Ok(DiskStateStore::Open(path, options, Meta(0), store, error), error, "reopen after WAL failure");
        if (fault == FaultEnv::Fault::Append) Check(store.Root() == EmptyUtxoRoot(), "failed first WAL append publishes nothing");
        const bool committed = store.Root() == staged;
        Check(committed || store.Root() == EmptyUtxoRoot(), "failed sync recovers a whole state");
        Check(store.Metadata() == Meta(committed ? 1 : 0), "failure root/metadata atomicity");
        std::optional<Coin> coin; Ok(store.ReadCoin(MakeCoin(1).outpoint, coin, error), error, "postfailure coin");
        Check(coin.has_value() == committed, "failure coin/root atomicity");
        if (committed) { Ok(store.Disconnect(Id(1), error), error, "recovered commit has undo"); Check(store.Root() == EmptyUtxoRoot(), "recovered undo"); }
        store = {};
    }
}
void CorruptionCases(const std::string &directory) {
    auto options = Options(); DiskStateStore store; DiskStateError error;
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "corruption open");
    DiskStateTransaction tx; Ok(store.Begin(tx, error), error, "corruption begin");
    for (uint32_t id = 1; id <= 4; ++id) Ok(tx.Insert(MakeCoin(id), error), error, "corruption fixture insert");
    Ok(tx.Commit(Meta(1), error), error, "corruption fixture commit"); tx.Abort(); store = {};
    const auto coin = MakeCoin(1); const auto key = Key(coin.outpoint);
    for (bool missing : {true, false}) {
        Coin altered = coin; ++altered.output.value;
        RawChange(directory, key, missing ? std::nullopt : std::optional<std::string>(Encoded(altered)));
        Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "lazy corruption reopen");
        std::optional<Coin> out;
        Check(!store.ReadCoin(coin.outpoint, out, error) && error.code == DiskStateErrorCode::Corruption,
              "missing/changed committed row is operational corruption");
        Ok(store.Begin(tx, error), error, "corrupt transaction begin");
        Check(!tx.Erase(coin.outpoint, error) && error.code == DiskStateErrorCode::Corruption, "erase authenticates corrupted row");
        Check(!tx.Commit(Meta(2), error) && error.code == DiskStateErrorCode::TransactionAborted, "corrupt mutation aborts transaction");
        tx.Abort(); store = {};
    }
    RawChange(directory, key, Encoded(coin));
    // Orphan coin table rows also cannot resolve as real inputs.
    const auto orphan = MakeCoin(100); RawChange(directory, Key(orphan.outpoint), Encoded(orphan));
    Ok(DiskStateStore::Open(directory, options, Meta(0), store, error), error, "orphan reopen");
    std::optional<Coin> out;
    Check(!store.ReadCoin(orphan.outpoint, out, error) && error.code == DiskStateErrorCode::Corruption, "orphan row rejected");
    store = {}; RawChange(directory, Key(orphan.outpoint), std::nullopt);
    std::string root_key(1, 'N'); root_key.append(34, '\0');
    RawChange(directory, root_key, std::nullopt);
    Check(!DiskStateStore::Open(directory, options, Meta(0), store, error) && error.code == DiskStateErrorCode::Corruption,
          "reopen detects missing authenticated root");
}
} // namespace
int main(int argc, char **argv) {
#ifndef _WIN32
    if (argc == 5 && std::string(argv[1]) == "--crash-writer") {
        CrashWriter(argv[2], std::stoi(argv[3]), std::stoi(argv[4]));
        return 0;
    }
#endif
    const auto base = std::filesystem::temp_directory_path();
    const auto path = (base / ("lotus-v2-disk-state-test-" + std::to_string(std::random_device{}()))).string();
    Check(std::filesystem::create_directory(path), "temporary directory");
    // Preserve artifacts automatically on any assertion failure.
    std::cout << "disk state test artifacts: " << path << '\n';
#ifndef _WIN32
    if (argc == 2 && std::string(argv[1]) == "--crash-only") {
        CrashRecoveryCases(path + "/crash", std::filesystem::absolute(argv[0]).string());
        std::filesystem::remove_all(path);
        return 0;
    }
#endif
    DurabilityPolicyCases(path + "/durability");
#ifndef _WIN32
    CrashRecoveryCases(path + "/crash", std::filesystem::absolute(argv[0]).string());
#endif
    SmallCases(path + "/small"); LargeAndMixed(path + "/large");
    FailureCases(path + "/failure"); CorruptionCases(path + "/corrupt");
    SiblingKindCorruption(path + "/sibling-kind");
    UndoBeforeCorruption(path + "/undo-before");
    UndoMetadataCallbacks(path + "/undo-metadata");
    RetainedStateCases(path + "/retained");
    std::filesystem::remove_all(path);
    std::cout << "V2 disk state differential, atomicity, reopen, undo, reorg, corruption cases passed\n";
}
