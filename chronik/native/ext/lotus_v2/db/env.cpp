// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/db/env.h>

#include <chronik/native/mdbx_store.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>


namespace chronik::native::lotus_v2 {

namespace {

constexpr TableSpec kTables[] = {
    {"meta"},
    {"block_receipts"},
    {"undo"},
    {"tx_locations"},
    {"coins"},
    {"postings", TableSpec::Kind::Dup, 36},
    {"explorer_height"},
    {"explorer_block"},
    {"explorer_block_tx"},
    {"explorer_tx"},
    {"explorer_txhash"},
    {"explorer_input"},
    {"explorer_witness"},
    {"asset_summary"},
    {"asset_event"},
    {"asset_output"},
};
static_assert(std::size(kTables) == V2Env::N_TABLES);

/** The Rust v2_index env (chronik-db/src/mdbx.rs MdbxEnv::open). */
MdbxEnvProfile V2IndexProfile() {
    MdbxEnvProfile p;
    p.size_lower = -1;
    p.size_now = -1;
    p.size_upper = int64_t(16) << 30;
    p.growth_step = 16 << 20;
    p.shrink_threshold = 64 << 20;
    p.pagesize = 4096;
    // Durable: only NOSTICKYTHREADS | LIFORECLAIM.
    p.safe_nosync = false;
    p.nometasync = false;
    p.liforeclaim = true;
    p.nostickythreads = true;
    p.nomeminit = false;
    p.mode = 0644;
    p.max_readers = 256;
    p.max_dbs = 32;
    p.sync_bytes = std::nullopt;
    p.sync_period = std::nullopt;
    p.sync_after_open = false;
    return p;
}

/** Rust io::Error Display: "<description> (os error N)". */
std::string IoError(int err) {
    return std::string(std::strerror(err)) + " (os error " +
           std::to_string(err) + ")";
}

[[noreturn]] void ThrowDb(const std::string &msg) { throw V2Error::Db(msg); }

/** Native backend failures become V2 storage errors. */
template <typename F> auto Guard(F &&f) -> decltype(f()) {
    try {
        return f();
    } catch (const V2Error &) {
        throw;
    } catch (const ChronikError &e) {
        ThrowDb(e.what());
    }
}

bool StartsWith(ByteView bytes, ByteView prefix) {
    return bytes.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), bytes.begin());
}

Bytes Concat(ByteView a, ByteView b) {
    Bytes out(a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

ByteView Str(std::string_view s) {
    return ByteView(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

std::array<uint8_t, 33> PostingKey(const Bytes32 &root, uint8_t pos) {
    std::array<uint8_t, 33> k;
    std::copy(root.begin(), root.end(), k.begin());
    k[32] = pos;
    return k;
}

std::array<uint8_t, 36> Dup36(ByteView v) {
    if (v.size() != 36) {
        ThrowDb("dupfixed posting value has length " +
                std::to_string(v.size()));
    }
    std::array<uint8_t, 36> out;
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

} // namespace

// ---- Env ----

std::span<const TableSpec> V2Env::Tables() { return kTables; }

V2Env::Route V2Env::RouteKey(ByteView key) {
    auto meta = [&](std::string_view name) {
        return key.size() == name.size() && StartsWith(key, Str(name));
    };
    if (meta("v2-binding") || meta("tip") || meta("disconnected")) {
        return {META, key, std::nullopt};
    }
    if (key.size() >= 1) {
        const ByteView rest = key.subspan(1);
        switch (key[0]) {
            case 'b':
                if (rest.size() == 32) return {BLOCK_RECEIPTS, rest, {}};
                break;
            case 'u':
                if (rest.size() == 32) return {UNDO, rest, {}};
                break;
            case 't':
                if (rest.size() == 32) return {TX_LOCATIONS, rest, {}};
                break;
            case 'o':
                if (rest.size() == 36) return {COINS, rest, {}};
                break;
            case 'p':
                if (rest.size() == 69) {
                    return {POSTINGS, rest.first(33), rest.subspan(33)};
                }
                break;
            default:
                break;
        }
    }
    if (key.size() >= 2 && key[0] == 'e') {
        const ByteView rest = key.subspan(2);
        const struct {
            char c;
            size_t len;
            Table table;
        } families[] = {
            {'H', 8, EXPLORER_HEIGHT},    {'B', 32, EXPLORER_BLOCK},
            {'O', 36, EXPLORER_BLOCK_TX}, {'T', 32, EXPLORER_TX},
            {'X', 32, EXPLORER_TXHASH},   {'I', 36, EXPLORER_INPUT},
            {'W', 40, EXPLORER_WITNESS},  {'A', 32, ASSET_SUMMARY},
            {'E', 44, ASSET_EVENT},       {'P', 48, ASSET_OUTPUT},
        };
        for (const auto &f : families) {
            if (key[1] == uint8_t(f.c) && rest.size() == f.len) {
                return {f.table, rest, {}};
            }
        }
    }
    ThrowDb("unrecognized logical key of length " + std::to_string(key.size()));
}

V2Env::V2Env(const std::filesystem::path &dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        ThrowDb("create_dir_all " + dir.string() + ": " +
                IoError(ec.value()));
    }
    m_store = Guard([&] {
        return OpenMdbxStore(dir, kTables, StoreOptions{}, V2IndexProfile());
    });
}

V2Env::~V2Env() = default;

std::optional<Bytes> V2Env::Get(ByteView key) const {
    return Snapshot().Get(key);
}

void V2Env::Put(ByteView key, ByteView value) {
    V2WriteBatch batch;
    batch.Put(Bytes(key.begin(), key.end()), Bytes(value.begin(), value.end()));
    Write(batch);
}

void V2Env::Write(const V2WriteBatch &batch) {
    Guard([&] {
        auto txn = m_store->BeginWrite();
        for (const auto &[key, value] : batch.m_ops) {
            const Route route = RouteKey(key);
            if (route.dup) {
                if (value) {
                    if (!value->empty()) {
                        ThrowDb("dupfixed posting entry must have empty "
                                "payload");
                    }
                    txn->PutDup(route.table, route.subkey, *route.dup);
                } else {
                    txn->DelDup(route.table, route.subkey, *route.dup);
                }
            } else if (value) {
                txn->Put(route.table, route.subkey, *value);
            } else {
                txn->Del(route.table, route.subkey);
            }
        }
        txn->Commit();
    });
}

V2EnvSnapshot V2Env::Snapshot() const {
    return V2EnvSnapshot(*this, Guard([&] { return m_store->BeginRead(); }));
}

std::vector<std::pair<Bytes, Bytes>> V2Env::DumpAll() const {
    return Snapshot().DumpAll();
}

bool V2Env::IsEmpty() const { return DumpAll().empty(); }

// ---- Snapshot ----

V2EnvSnapshot::V2EnvSnapshot(const V2Env &env, std::unique_ptr<ReadTxn> txn)
    : m_env(&env), m_txn(std::move(txn)) {}
V2EnvSnapshot::V2EnvSnapshot(V2EnvSnapshot &&) noexcept = default;
V2EnvSnapshot &V2EnvSnapshot::operator=(V2EnvSnapshot &&) noexcept = default;
V2EnvSnapshot::~V2EnvSnapshot() = default;

std::optional<Bytes> V2EnvSnapshot::Get(ByteView key) const {
    const V2Env::Route route = V2Env::RouteKey(key);
    return Guard([&]() -> std::optional<Bytes> {
        if (route.dup) {
            auto cursor = m_txn->OpenDupCursor(route.table);
            if (cursor->SeekValueGe(route.subkey, *route.dup) &&
                std::ranges::equal(cursor->Value(), *route.dup)) {
                return Bytes{};
            }
            return std::nullopt;
        }
        auto value = m_txn->Get(route.table, route.subkey);
        if (!value) {
            return std::nullopt;
        }
        return Bytes(value->begin(), value->end());
    });
}

std::optional<std::array<uint8_t, 36>> V2EnvSnapshot::NextPostingDupfixed(
    const Bytes32 &root, uint8_t pos,
    const std::optional<std::array<uint8_t, 36>> &after) const {
    const auto key = PostingKey(root, pos);
    return Guard([&]() -> std::optional<std::array<uint8_t, 36>> {
        auto cursor = m_txn->OpenDupCursor(V2Env::POSTINGS);
        const bool found = after ? cursor->SeekValueGe(key, *after)
                                 : cursor->Seek(key);
        if (!found) {
            return std::nullopt;
        }
        if (after && std::ranges::equal(cursor->Value(), *after) &&
            !cursor->Next()) {
            return std::nullopt;
        }
        return Dup36(cursor->Value());
    });
}

std::vector<std::array<uint8_t, 36>> V2EnvSnapshot::PostingsDupfixedAfter(
    const Bytes32 &root, uint8_t pos,
    const std::optional<std::array<uint8_t, 36>> &after) const {
    const auto key = PostingKey(root, pos);
    return Guard([&] {
        std::vector<std::array<uint8_t, 36>> out;
        auto cursor = m_txn->OpenDupCursor(V2Env::POSTINGS);
        bool valid = after ? cursor->SeekValueGe(key, *after)
                           : cursor->Seek(key);
        if (valid && after && std::ranges::equal(cursor->Value(), *after)) {
            valid = cursor->Next();
        }
        while (valid) {
            out.push_back(Dup36(cursor->Value()));
            valid = cursor->Next();
        }
        return out;
    });
}

std::optional<std::pair<Bytes, Bytes>>
V2EnvSnapshot::SeekNextRegular(ByteView prefix, std::optional<ByteView> after,
                               const std::function<void()> &charge) const {
    TableId table;
    const std::string_view family =
        prefix.size() >= 2
            ? std::string_view(reinterpret_cast<const char *>(prefix.data()),
                               2)
            : std::string_view();
    if (family == "eH") {
        table = V2Env::EXPLORER_HEIGHT;
    } else if (family == "eO") {
        table = V2Env::EXPLORER_BLOCK_TX;
    } else if (family == "eI") {
        table = V2Env::EXPLORER_INPUT;
    } else if (family == "eW") {
        table = V2Env::EXPLORER_WITNESS;
    } else if (family == "eA") {
        table = V2Env::ASSET_SUMMARY;
    } else if (family == "eE") {
        table = V2Env::ASSET_EVENT;
    } else if (family == "eP") {
        table = V2Env::ASSET_OUTPUT;
    } else {
        ThrowDb("invalid regular seek family prefix");
    }
    const ByteView family_prefix = prefix.first(2);
    const ByteView sub_prefix = prefix.subspan(2);
    std::optional<ByteView> after_subkey;
    if (after) {
        after_subkey = after->subspan(2);
    }
    auto cursor = Guard([&] { return m_txn->OpenCursor(table); });
    charge();
    const ByteView start = after_subkey ? *after_subkey : sub_prefix;
    bool found = Guard([&] {
        return start.empty() ? cursor->SeekFirst() : cursor->SeekGe(start);
    });
    if (!found) {
        return std::nullopt;
    }
    if (after_subkey && std::ranges::equal(cursor->Key(), *after_subkey)) {
        charge();
        if (!Guard([&] { return cursor->Next(); })) {
            return std::nullopt;
        }
    }
    if (!StartsWith(cursor->Key(), sub_prefix)) {
        return std::nullopt;
    }
    return std::make_pair(Concat(family_prefix, cursor->Key()),
                          Bytes(cursor->Value().begin(),
                                cursor->Value().end()));
}

std::vector<std::pair<Bytes, Bytes>> V2EnvSnapshot::DumpAll() const {
    static const struct {
        V2Env::Table table;
        std::string_view prefix;
    } regular[] = {
        {V2Env::META, ""},
        {V2Env::BLOCK_RECEIPTS, "b"},
        {V2Env::UNDO, "u"},
        {V2Env::TX_LOCATIONS, "t"},
        {V2Env::COINS, "o"},
        {V2Env::EXPLORER_HEIGHT, "eH"},
        {V2Env::EXPLORER_BLOCK, "eB"},
        {V2Env::EXPLORER_BLOCK_TX, "eO"},
        {V2Env::EXPLORER_TX, "eT"},
        {V2Env::EXPLORER_TXHASH, "eX"},
        {V2Env::EXPLORER_INPUT, "eI"},
        {V2Env::EXPLORER_WITNESS, "eW"},
        {V2Env::ASSET_SUMMARY, "eA"},
        {V2Env::ASSET_EVENT, "eE"},
        {V2Env::ASSET_OUTPUT, "eP"},
    };
    return Guard([&] {
        std::vector<std::pair<Bytes, Bytes>> out;
        for (const auto &t : regular) {
            auto cursor = m_txn->OpenCursor(t.table);
            for (bool ok = cursor->SeekFirst(); ok; ok = cursor->Next()) {
                out.emplace_back(Concat(Str(t.prefix), cursor->Key()),
                                 Bytes(cursor->Value().begin(),
                                       cursor->Value().end()));
            }
        }
        // A plain cursor over the DUPSORT table visits every dup.
        auto cursor = m_txn->OpenCursor(V2Env::POSTINGS);
        for (bool ok = cursor->SeekFirst(); ok; ok = cursor->Next()) {
            Bytes key{'p'};
            key.insert(key.end(), cursor->Key().begin(), cursor->Key().end());
            key.insert(key.end(), cursor->Value().begin(),
                       cursor->Value().end());
            out.emplace_back(std::move(key), Bytes{});
        }
        std::sort(out.begin(), out.end(),
                  [](const auto &a, const auto &b) { return a.first < b.first; });
        return out;
    });
}

} // namespace chronik::native::lotus_v2
