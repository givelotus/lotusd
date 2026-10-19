// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Optional LevelDB backend of the native Chronik KvStore. The physical layout
// is documented in include/chronik/native/leveldb_store.h.

#include <chronik/native/codec/bytes.h>
#include <chronik/native/error.h>
#include <chronik/native/leveldb_store.h>

#include <leveldb/cache.h>
#include <leveldb/db.h>
#include <leveldb/filter_policy.h>
#include <leveldb/iterator.h>
#include <leveldb/options.h>
#include <leveldb/write_batch.h>

#include <algorithm>
#include <cstdio>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace chronik::native {

namespace {

constexpr std::string_view kFormat = "chronik-native-leveldb-1";
constexpr char kStoreMetaPrefix = 0x00;
constexpr std::string_view kFormatKey = "format";
constexpr std::string_view kTableKeyPrefix = "table:";
constexpr size_t kBlockCacheBytes = size_t(32) << 20;
constexpr size_t kWriteBufferBytes = size_t(16) << 20;

[[noreturn]] void ThrowLevelDb(const leveldb::Status &status,
                               std::string_view context) {
    throw ChronikError("LevelDB error: " + std::string(context) + ": " +
                       status.ToString());
}

void CheckStatus(const leveldb::Status &status, std::string_view context) {
    if (!status.ok()) {
        ThrowLevelDb(status, context);
    }
}

void AppendVarint(std::string &out, uint64_t v) {
    while (v >= 0x80) {
        out.push_back(char(uint8_t(v) | 0x80));
        v >>= 7;
    }
    out.push_back(char(uint8_t(v)));
}

/** Parses a varint at the start of s; nullopt if malformed. */
std::optional<uint64_t> ReadVarint(std::string_view &s) {
    uint64_t v = 0;
    for (unsigned shift = 0; shift < 64 && !s.empty(); shift += 7) {
        const uint8_t byte = uint8_t(s.front());
        s.remove_prefix(1);
        v |= uint64_t(byte & 0x7f) << shift;
        if (!(byte & 0x80)) {
            return v;
        }
    }
    return std::nullopt;
}

/** Smallest string greater than every string starting with prefix. */
std::optional<std::string> PrefixSuccessor(std::string prefix) {
    while (!prefix.empty()) {
        if (uint8_t(prefix.back()) != 0xff) {
            prefix.back() = char(uint8_t(prefix.back()) + 1);
            return prefix;
        }
        prefix.pop_back();
    }
    return std::nullopt;
}

inline leveldb::Slice ToSlice(ByteView v) {
    return leveldb::Slice(reinterpret_cast<const char *>(v.data()), v.size());
}

inline leveldb::Slice ToSlice(const std::string &s) {
    return leveldb::Slice(s);
}

inline ByteView ToView(std::string_view s) {
    if (s.empty()) {
        return ByteView();
    }
    return ByteView(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

inline std::string_view ToStringView(const leveldb::Slice &s) {
    return std::string_view(s.data(), s.size());
}

void AppendBytes(std::string &out, ByteView v) {
    out.append(reinterpret_cast<const char *>(v.data()), v.size());
}

/**
 * Order-preserving, prefix-free encoding of a dup table's key: 0x00 becomes
 * 0x00 0xff and the key ends with 0x00 0x00. Encoded keys compare like the
 * keys themselves (memcmp), so a plain cursor over a dup table visits keys
 * in MDBX order, and the dup value can follow without a length.
 */
void AppendEscapedKey(std::string &out, ByteView key) {
    for (uint8_t b : key) {
        out.push_back(char(b));
        if (b == 0x00) {
            out.push_back(char(0xff));
        }
    }
    out.push_back(char(0x00));
    out.push_back(char(0x00));
}

/**
 * Splits the part of a dup table's physical key after the table prefix into
 * the key (unescaped into key_out) and the dup value.
 */
std::string_view SplitEscapedKey(std::string_view rest, Bytes &key_out) {
    key_out.clear();
    for (size_t i = 0; i < rest.size(); ++i) {
        const uint8_t b = uint8_t(rest[i]);
        if (b != 0x00) {
            key_out.push_back(b);
            continue;
        }
        if (i + 1 >= rest.size()) {
            break;
        }
        if (uint8_t(rest[i + 1]) == 0x00) {
            return rest.substr(i + 2);
        }
        key_out.push_back(0x00);
        ++i;
    }
    throw ChronikError("Corrupted Chronik LevelDB dup key");
}

/** Pending writes of a WriteTxn: physical key -> value (nullopt = deleted). */
using Overlay = std::map<std::string, std::optional<std::string>, std::less<>>;

/**
 * What a cursor reads: a snapshot of the DB, optionally overlaid by a write
 * txn's pending writes, within one half-open physical key range [lo, hi).
 */
struct View {
    leveldb::DB *db = nullptr;
    const leveldb::Snapshot *snapshot = nullptr;
    /** Write txns only */
    const Overlay *overlay = nullptr;
    /** Write txns only: tables whose snapshot data was cleared */
    const std::set<TableId> *cleared = nullptr;
};

/**
 * Ordered cursor over the merge of the snapshot and the overlay, restricted
 * to [lo, hi). Overlay entries win over snapshot entries with the same key;
 * deleted overlay entries hide them. Positions are re-derived from the
 * current key on every move, so the overlay may change between moves; the
 * snapshot iterator is reused when it is still positioned on that key.
 */
class MergedCursor {
public:
    MergedCursor(const View &view, TableId table) : m_view(view), m_table(table) {
        leveldb::ReadOptions ro;
        ro.snapshot = view.snapshot;
        m_base.reset(view.db->NewIterator(ro));
    }

    void SetBounds(std::string lo, std::optional<std::string> hi) {
        m_lo = std::move(lo);
        m_hi = std::move(hi);
        m_valid = false;
    }

    bool FindGe(const std::string &target, bool inclusive) {
        std::string t = target;
        bool incl = inclusive;
        while (true) {
            const bool have_base = BaseGe(t, incl);
            const Overlay::const_iterator ov = OverlayGe(t, incl);
            const bool have_ov = m_view.overlay && ov != m_view.overlay->end();
            if (!have_base && !have_ov) {
                return m_valid = false;
            }
            if (have_ov &&
                (!have_base || std::string_view(ov->first) <= BaseKey())) {
                if (!ov->second) {
                    t = ov->first;
                    incl = false;
                    continue;
                }
                return Set(ov->first, *ov->second);
            }
            return Set(BaseKey(), BaseValue());
        }
    }

    bool FindLe(const std::string &target, bool inclusive) {
        std::string t = target;
        bool incl = inclusive;
        while (true) {
            const bool have_base = BaseLe(t, incl);
            const std::optional<Overlay::const_iterator> ov = OverlayLe(t, incl);
            if (!have_base && !ov) {
                return m_valid = false;
            }
            if (ov && (!have_base || std::string_view((*ov)->first) >= BaseKey())) {
                if (!(*ov)->second) {
                    t = (*ov)->first;
                    incl = false;
                    continue;
                }
                return Set((*ov)->first, *(*ov)->second);
            }
            return Set(BaseKey(), BaseValue());
        }
    }

    bool Valid() const { return m_valid; }
    const std::string &Key() const { return m_key; }
    const std::string &Value() const { return m_value; }
    const std::string &Lo() const { return m_lo; }
    const std::optional<std::string> &Hi() const { return m_hi; }

private:
    bool BaseEnabled() const {
        return !(m_view.cleared && m_view.cleared->count(m_table));
    }

    bool InBounds(std::string_view key) const {
        return key >= std::string_view(m_lo) &&
               (!m_hi || key < std::string_view(*m_hi));
    }

    std::string_view BaseKey() const { return ToStringView(m_base->key()); }
    std::string_view BaseValue() const { return ToStringView(m_base->value()); }

    void CheckBase() const {
        if (!m_base->Valid()) {
            CheckStatus(m_base->status(), "iterator");
        }
    }

    /** Positions the snapshot iterator at the first key >(=) t in bounds. */
    bool BaseGe(const std::string &t, bool incl) {
        if (!BaseEnabled()) {
            return false;
        }
        if (m_base->Valid() && BaseKey() == t) {
            if (!incl) {
                m_base->Next();
            }
        } else {
            m_base->Seek(ToSlice(t));
            if (!incl && m_base->Valid() && BaseKey() == t) {
                m_base->Next();
            }
        }
        CheckBase();
        return m_base->Valid() && InBounds(BaseKey());
    }

    /** Positions the snapshot iterator at the last key <(=) t in bounds. */
    bool BaseLe(const std::string &t, bool incl) {
        if (!BaseEnabled()) {
            return false;
        }
        if (m_base->Valid() && BaseKey() == t) {
            if (!incl) {
                m_base->Prev();
            }
        } else {
            m_base->Seek(ToSlice(t));
            if (!m_base->Valid()) {
                CheckBase();
                m_base->SeekToLast();
            } else if (BaseKey() > std::string_view(t) ||
                       (!incl && BaseKey() == t)) {
                m_base->Prev();
            }
        }
        CheckBase();
        return m_base->Valid() && InBounds(BaseKey());
    }

    Overlay::const_iterator OverlayGe(const std::string &t, bool incl) const {
        if (!m_view.overlay) {
            return {};
        }
        const Overlay &ov = *m_view.overlay;
        auto it = incl ? ov.lower_bound(t) : ov.upper_bound(t);
        if (it != ov.end() && !InBounds(it->first)) {
            return ov.end();
        }
        return it;
    }

    std::optional<Overlay::const_iterator> OverlayLe(const std::string &t,
                                                     bool incl) const {
        if (!m_view.overlay) {
            return std::nullopt;
        }
        const Overlay &ov = *m_view.overlay;
        auto it = incl ? ov.upper_bound(t) : ov.lower_bound(t);
        if (it == ov.begin()) {
            return std::nullopt;
        }
        --it;
        if (!InBounds(it->first)) {
            return std::nullopt;
        }
        return it;
    }

    bool Set(std::string_view key, std::string_view value) {
        m_key.assign(key);
        m_value.assign(value);
        return m_valid = true;
    }

    View m_view;
    TableId m_table;
    std::unique_ptr<leveldb::Iterator> m_base;
    std::string m_lo;
    std::optional<std::string> m_hi;
    std::string m_key;
    std::string m_value;
    bool m_valid = false;
};

class LevelDbStore;

class LevelDbCursor final : public Cursor {
public:
    LevelDbCursor(const View &view, TableId table, const std::string &prefix,
                  const std::string &prefix_end)
        : m_cursor(view, table), m_prefix_len(prefix.size()) {
        m_cursor.SetBounds(prefix, prefix_end);
    }

    bool SeekFirst() override { return m_cursor.FindGe(m_cursor.Lo(), true); }
    bool SeekLast() override { return m_cursor.FindLe(*m_cursor.Hi(), false); }
    bool SeekGe(ByteView key) override {
        return m_cursor.FindGe(Phys(key), true);
    }
    bool SeekLe(ByteView key) override {
        return m_cursor.FindLe(Phys(key), true);
    }
    bool Next() override {
        return m_cursor.Valid() && m_cursor.FindGe(Current(), false);
    }
    bool Prev() override {
        return m_cursor.Valid() && m_cursor.FindLe(Current(), false);
    }
    bool Valid() const override { return m_cursor.Valid(); }
    ByteView Key() const override {
        return ToView(std::string_view(m_cursor.Key()).substr(m_prefix_len));
    }
    ByteView Value() const override { return ToView(m_cursor.Value()); }

private:
    std::string Phys(ByteView key) const {
        std::string phys = m_cursor.Lo();
        AppendBytes(phys, key);
        return phys;
    }
    /** Copy: FindGe/FindLe overwrite the current key. */
    std::string Current() const { return m_cursor.Key(); }

    MergedCursor m_cursor;
    size_t m_prefix_len;
};

/**
 * Plain cursor over a dup table, like an MDBX cursor on a DUPSORT DBI: it
 * visits every (key, dup) pair, ordered by key then dup.
 */
class LevelDbDupTableCursor final : public Cursor {
public:
    LevelDbDupTableCursor(const View &view, TableId table,
                          const std::string &prefix,
                          const std::string &prefix_end)
        : m_cursor(view, table), m_prefix_len(prefix.size()) {
        m_cursor.SetBounds(prefix, prefix_end);
    }

    bool SeekFirst() override {
        return Decode(m_cursor.FindGe(m_cursor.Lo(), true));
    }
    bool SeekLast() override {
        return Decode(m_cursor.FindLe(*m_cursor.Hi(), false));
    }
    /** First dup of the first key >= key (MDBX_SET_RANGE) */
    bool SeekGe(ByteView key) override {
        return Decode(m_cursor.FindGe(KeyPrefix(key), true));
    }
    /** Last dup of the last key <= key */
    bool SeekLe(ByteView key) override {
        // The key prefix ends with 0x00 0x00, so its successor exists.
        return Decode(
            m_cursor.FindLe(*PrefixSuccessor(KeyPrefix(key)), false));
    }
    bool Next() override {
        return m_cursor.Valid() &&
               Decode(m_cursor.FindGe(std::string(m_cursor.Key()), false));
    }
    bool Prev() override {
        return m_cursor.Valid() &&
               Decode(m_cursor.FindLe(std::string(m_cursor.Key()), false));
    }
    bool Valid() const override { return m_cursor.Valid(); }
    ByteView Key() const override { return m_key; }
    ByteView Value() const override { return ToView(m_value); }

private:
    std::string KeyPrefix(ByteView key) const {
        std::string phys = m_cursor.Lo();
        AppendEscapedKey(phys, key);
        return phys;
    }
    bool Decode(bool ok) {
        if (ok) {
            m_value = SplitEscapedKey(
                std::string_view(m_cursor.Key()).substr(m_prefix_len), m_key);
        }
        return ok;
    }

    MergedCursor m_cursor;
    size_t m_prefix_len;
    Bytes m_key;
    std::string_view m_value;
};

class LevelDbDupCursor final : public DupCursor {
public:
    LevelDbDupCursor(const View &view, TableId table, const std::string &prefix,
                     const std::string &prefix_end,
                     std::optional<uint32_t> fixed)
        : m_view(view), m_table(table), m_cursor(view, table),
          m_table_prefix(prefix), m_table_end(prefix_end), m_fixed(fixed) {}

    bool Seek(ByteView key) override {
        SetKey(key);
        return m_cursor.FindGe(m_key_prefix, true);
    }
    bool SeekValueGe(ByteView key, ByteView value_prefix) override {
        SetKey(key);
        std::string target = m_key_prefix;
        // Like MDBX GET_BOTH_RANGE on a DUPFIXED table, a longer prefix is
        // truncated; a shorter one compares like its zero-padded form.
        ByteView prefix = value_prefix;
        if (m_fixed && prefix.size() > *m_fixed) {
            prefix = prefix.first(*m_fixed);
        }
        AppendBytes(target, prefix);
        return m_cursor.FindGe(target, true);
    }
    bool Next() override {
        if (!m_cursor.Valid()) {
            return false;
        }
        const std::string current = m_cursor.Key();
        return m_cursor.FindGe(current, false);
    }
    bool Valid() const override { return m_cursor.Valid(); }
    ByteView Value() const override {
        return ToView(
            std::string_view(m_cursor.Key()).substr(m_key_prefix.size()));
    }
    size_t CountRemaining() override {
        if (!m_cursor.Valid()) {
            return 0;
        }
        MergedCursor copy(m_view, m_table);
        copy.SetBounds(m_cursor.Lo(), m_cursor.Hi());
        size_t count = 0;
        for (bool ok = copy.FindGe(m_cursor.Key(), true); ok;
             ok = copy.FindGe(std::string(copy.Key()), false)) {
            ++count;
        }
        return count;
    }

    /** Physical key of (key, value) in this dup table. */
    static std::string DupPhys(const std::string &table_prefix, ByteView key,
                               ByteView value) {
        std::string phys = table_prefix;
        AppendEscapedKey(phys, key);
        AppendBytes(phys, value);
        return phys;
    }

private:
    void SetKey(ByteView key) {
        m_key_prefix = DupPhys(m_table_prefix, key, ByteView());
        std::optional<std::string> end = PrefixSuccessor(m_key_prefix);
        m_cursor.SetBounds(m_key_prefix, end ? *end : m_table_end);
    }

    View m_view;
    TableId m_table;
    MergedCursor m_cursor;
    std::string m_table_prefix;
    std::string m_table_end;
    std::optional<uint32_t> m_fixed;
    std::string m_key_prefix;
};

class LevelDbStore final : public KvStore {
public:
    LevelDbStore(const std::filesystem::path &dir,
                 std::span<const TableSpec> tables);
    ~LevelDbStore() override;

    TableId Table(std::string_view name) const override {
        auto it = m_by_name.find(std::string(name));
        if (it == m_by_name.end()) {
            throw ChronikError("Column family " + std::string(name) +
                               " doesn't exist");
        }
        return it->second;
    }
    std::vector<std::string> TableNames() const override { return m_names; }
    std::unique_ptr<ReadTxn> BeginRead() const override;
    std::unique_ptr<WriteTxn> BeginWrite() override;
    void Sync(bool /*force*/) override {
        leveldb::WriteOptions wo;
        wo.sync = true;
        leveldb::WriteBatch empty;
        CheckStatus(m_db->Write(wo, &empty), "sync");
    }

    leveldb::DB *Db() const { return m_db.get(); }
    const TableSpec &Spec(TableId id) const {
        if (id >= m_specs.size()) {
            throw ChronikError("Unknown Chronik table id " +
                               std::to_string(id));
        }
        return m_specs[id];
    }
    bool IsDup(TableId id) const {
        return Spec(id).kind == TableSpec::Kind::Dup;
    }
    const std::string &Prefix(TableId id) const {
        Spec(id);
        return m_prefixes[id];
    }
    const std::string &PrefixEnd(TableId id) const {
        Spec(id);
        return m_prefix_ends[id];
    }
    std::string PlainPhys(TableId id, ByteView key) const {
        std::string phys = Prefix(id);
        AppendBytes(phys, key);
        return phys;
    }

private:
    std::unique_ptr<leveldb::Cache> m_cache;
    std::unique_ptr<const leveldb::FilterPolicy> m_filter;
    std::unique_ptr<leveldb::DB> m_db;
    std::vector<std::string> m_names;
    std::vector<TableSpec> m_specs; // names point into m_names
    std::vector<std::string> m_prefixes;
    std::vector<std::string> m_prefix_ends;
    std::map<std::string, TableId> m_by_name;
};

/** Read operations shared by read and write txns. */
class TxnBase {
public:
    TxnBase(const LevelDbStore &store, const leveldb::Snapshot *snapshot)
        : m_store(store), m_snapshot(snapshot) {}

    std::optional<ByteView> BaseGet(TableId table, ByteView key) const {
        if (m_store.IsDup(table)) {
            throw ChronikError("Get on a dup table");
        }
        leveldb::ReadOptions ro;
        ro.snapshot = m_snapshot;
        std::string value;
        const std::string phys = m_store.PlainPhys(table, key);
        const leveldb::Status status =
            m_store.Db()->Get(ro, ToSlice(phys), &value);
        if (status.IsNotFound()) {
            return std::nullopt;
        }
        CheckStatus(status, "get");
        m_values.push_back(std::move(value));
        return ToView(m_values.back());
    }

    /**
     * LevelDB keeps no entry counts, so this counts the entries of the view
     * (exact; used only for progress logs before a reindex).
     */
    uint64_t Count(const View &view, TableId table) const {
        MergedCursor cursor(view, table);
        cursor.SetBounds(m_store.Prefix(table), m_store.PrefixEnd(table));
        uint64_t count = 0;
        for (bool ok = cursor.FindGe(m_store.Prefix(table), true); ok;
             ok = cursor.FindGe(std::string(cursor.Key()), false)) {
            ++count;
        }
        return count;
    }

    View MakeView(const Overlay *overlay,
                  const std::set<TableId> *cleared) const {
        return View{m_store.Db(), m_snapshot, overlay, cleared};
    }

    std::unique_ptr<Cursor> MakeCursor(const View &view, TableId table) const {
        if (m_store.IsDup(table)) {
            return std::make_unique<LevelDbDupTableCursor>(
                view, table, m_store.Prefix(table), m_store.PrefixEnd(table));
        }
        return std::make_unique<LevelDbCursor>(view, table,
                                               m_store.Prefix(table),
                                               m_store.PrefixEnd(table));
    }

    std::unique_ptr<DupCursor> MakeDup(const View &view, TableId table) const {
        if (!m_store.IsDup(table)) {
            throw ChronikError("Dup cursor on a plain table");
        }
        return std::make_unique<LevelDbDupCursor>(
            view, table, m_store.Prefix(table), m_store.PrefixEnd(table),
            m_store.Spec(table).dup_fixed_size);
    }

    const LevelDbStore &m_store;
    const leveldb::Snapshot *m_snapshot;
    /** Owns returned Get views (stable addresses) until the txn ends. */
    mutable std::deque<std::string> m_values;
};

class LevelDbReadTxn final : public ReadTxn {
public:
    explicit LevelDbReadTxn(const LevelDbStore &store)
        : m_base(store, store.Db()->GetSnapshot()) {}
    ~LevelDbReadTxn() override {
        m_base.m_store.Db()->ReleaseSnapshot(m_base.m_snapshot);
    }

    std::optional<ByteView> Get(TableId table, ByteView key) const override {
        return m_base.BaseGet(table, key);
    }
    std::unique_ptr<Cursor> OpenCursor(TableId table) const override {
        return m_base.MakeCursor(m_base.MakeView(nullptr, nullptr), table);
    }
    std::unique_ptr<DupCursor> OpenDupCursor(TableId table) const override {
        return m_base.MakeDup(m_base.MakeView(nullptr, nullptr), table);
    }
    uint64_t EstimateEntries(TableId table) const override {
        return m_base.Count(m_base.MakeView(nullptr, nullptr), table);
    }

private:
    TxnBase m_base;
};

class LevelDbWriteTxn final : public WriteTxn {
public:
    explicit LevelDbWriteTxn(LevelDbStore &store)
        : m_store(store), m_base(store, store.Db()->GetSnapshot()) {}
    ~LevelDbWriteTxn() override { Release(); }

    std::optional<ByteView> Get(TableId table, ByteView key) const override {
        Live();
        if (m_store.IsDup(table)) {
            throw ChronikError("Get on a dup table");
        }
        auto it = m_overlay.find(m_store.PlainPhys(table, key));
        if (it != m_overlay.end()) {
            if (!it->second) {
                return std::nullopt;
            }
            return ToView(*it->second);
        }
        if (m_cleared.count(table)) {
            return std::nullopt;
        }
        return m_base.BaseGet(table, key);
    }
    std::unique_ptr<Cursor> OpenCursor(TableId table) const override {
        Live();
        return m_base.MakeCursor(m_base.MakeView(&m_overlay, &m_cleared), table);
    }
    std::unique_ptr<DupCursor> OpenDupCursor(TableId table) const override {
        Live();
        return m_base.MakeDup(m_base.MakeView(&m_overlay, &m_cleared), table);
    }
    uint64_t EstimateEntries(TableId table) const override {
        Live();
        return m_base.Count(m_base.MakeView(&m_overlay, &m_cleared), table);
    }

    void Put(TableId table, ByteView key, ByteView value) override {
        Write();
        PlainOnly(table);
        m_overlay.insert_or_assign(
            m_store.PlainPhys(table, key),
            std::string(reinterpret_cast<const char *>(value.data()),
                        value.size()));
    }
    void Del(TableId table, ByteView key) override {
        Write();
        PlainOnly(table);
        m_overlay.insert_or_assign(m_store.PlainPhys(table, key),
                                   std::nullopt);
    }
    void PutDup(TableId table, ByteView key, ByteView value) override {
        Write();
        DupOnly(table);
        m_overlay.insert_or_assign(
            LevelDbDupCursor::DupPhys(m_store.Prefix(table), key, value),
            std::string());
    }
    void DelDup(TableId table, ByteView key, ByteView value) override {
        Write();
        DupOnly(table);
        m_overlay.insert_or_assign(
            LevelDbDupCursor::DupPhys(m_store.Prefix(table), key, value),
            std::nullopt);
    }
    void DelDupByPrefix(TableId table, ByteView key,
                        ByteView value_prefix) override {
        Write();
        DupOnly(table);
        // Same as the MDBX backend: the first dup >= the prefix, deleted
        // only if it starts with the prefix.
        auto cursor = OpenDupCursor(table);
        if (!cursor->SeekValueGe(key, value_prefix) ||
            !StartsWith(cursor->Value(), value_prefix)) {
            return;
        }
        m_overlay.insert_or_assign(
            LevelDbDupCursor::DupPhys(m_store.Prefix(table), key,
                                      cursor->Value()),
            std::nullopt);
    }
    void Clear(TableId table) override {
        Write();
        const std::string &lo = m_store.Prefix(table);
        const std::string &hi = m_store.PrefixEnd(table);
        m_overlay.erase(m_overlay.lower_bound(lo), m_overlay.lower_bound(hi));
        m_cleared.insert(table);
    }
    void Commit() override {
        Live();
        leveldb::WriteBatch batch;
        // Snapshot entries of cleared tables first; overlay entries written
        // after the Clear come later in the batch and so win.
        for (TableId table : m_cleared) {
            leveldb::ReadOptions ro;
            ro.snapshot = m_base.m_snapshot;
            ro.fill_cache = false;
            std::unique_ptr<leveldb::Iterator> it(
                m_store.Db()->NewIterator(ro));
            const std::string &hi = m_store.PrefixEnd(table);
            for (it->Seek(ToSlice(m_store.Prefix(table)));
                 it->Valid() && ToStringView(it->key()) < std::string_view(hi);
                 it->Next()) {
                batch.Delete(it->key());
            }
            CheckStatus(it->status(), "iterator(clear)");
        }
        for (const auto &[key, value] : m_overlay) {
            if (value) {
                batch.Put(ToSlice(key), ToSlice(*value));
            } else {
                batch.Delete(ToSlice(key));
            }
        }
        Release();
        leveldb::WriteOptions wo;
        wo.sync = false;
        CheckStatus(m_store.Db()->Write(wo, &batch), "write_batch");
    }

private:
    void Live() const {
        if (m_done) {
            throw ChronikError("Chronik write txn used after commit");
        }
    }
    /** Views returned by earlier Gets are valid until the next write. */
    void Write() {
        Live();
        m_base.m_values.clear();
    }
    void PlainOnly(TableId table) const {
        if (m_store.IsDup(table)) {
            throw ChronikError("Plain write on a dup table");
        }
    }
    void DupOnly(TableId table) const {
        if (!m_store.IsDup(table)) {
            throw ChronikError("Dup write on a plain table");
        }
    }
    void Release() {
        if (!m_done) {
            m_store.Db()->ReleaseSnapshot(m_base.m_snapshot);
            m_done = true;
            m_overlay.clear();
            m_cleared.clear();
            m_base.m_values.clear();
        }
    }

    LevelDbStore &m_store;
    TxnBase m_base;
    Overlay m_overlay;
    std::set<TableId> m_cleared;
    bool m_done = false;
};

std::unique_ptr<ReadTxn> LevelDbStore::BeginRead() const {
    return std::make_unique<LevelDbReadTxn>(*this);
}

std::unique_ptr<WriteTxn> LevelDbStore::BeginWrite() {
    return std::make_unique<LevelDbWriteTxn>(*this);
}

std::string StoreMetaKey(std::string_view name) {
    std::string key(1, kStoreMetaPrefix);
    key.append(name);
    return key;
}

LevelDbStore::LevelDbStore(const std::filesystem::path &dir,
                           std::span<const TableSpec> tables) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        throw ChronikError("LevelDB error: Failed to create DB directory " +
                           dir.string() + ": " + ec.message());
    }
    if (std::filesystem::exists(dir / "mdbx.dat")) {
        throw ChronikError(
            "Chronik LevelDB directory " + dir.string() +
            " contains an MDBX index; the backends are not compatible");
    }
    m_names.reserve(tables.size());
    for (const TableSpec &spec : tables) {
        m_names.emplace_back(spec.name);
    }
    for (size_t i = 0; i < tables.size(); ++i) {
        TableSpec spec = tables[i];
        spec.name = m_names[i];
        m_specs.push_back(spec);
        if (!m_by_name.emplace(m_names[i], TableId(i)).second) {
            throw ChronikError("Duplicate Chronik table " + m_names[i]);
        }
    }

    m_cache.reset(leveldb::NewLRUCache(kBlockCacheBytes));
    m_filter.reset(leveldb::NewBloomFilterPolicy(10));
    leveldb::Options options;
    options.create_if_missing = true;
    options.block_cache = m_cache.get();
    options.filter_policy = m_filter.get();
    options.write_buffer_size = kWriteBufferBytes;
    options.compression = leveldb::kNoCompression;
    leveldb::DB *db = nullptr;
    CheckStatus(leveldb::DB::Open(options, dir.string(), &db), "open");
    m_db.reset(db);

    // ---- format marker and persistent table ids ----
    leveldb::ReadOptions ro;
    std::string format;
    leveldb::Status status = m_db->Get(ro, StoreMetaKey(kFormatKey), &format);
    leveldb::WriteBatch batch;
    if (status.IsNotFound()) {
        std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(ro));
        it->SeekToFirst();
        CheckStatus(it->status(), "iterator");
        if (it->Valid()) {
            throw ChronikError("LevelDB directory " + dir.string() +
                               " is not a native Chronik index");
        }
        batch.Put(StoreMetaKey(kFormatKey), ToSlice(std::string(kFormat)));
    } else {
        CheckStatus(status, "get(format)");
        if (format != kFormat) {
            throw ChronikError("Unsupported Chronik LevelDB format \"" +
                               format + "\" in " + dir.string());
        }
    }

    std::map<std::string, uint64_t> ids;
    uint64_t max_id = 0;
    {
        const std::string prefix = StoreMetaKey(kTableKeyPrefix);
        std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(ro));
        for (it->Seek(prefix);
             it->Valid() && it->key().starts_with(ToSlice(prefix));
             it->Next()) {
            std::string_view value = ToStringView(it->value());
            const std::optional<uint64_t> id = ReadVarint(value);
            if (!id || *id == 0) {
                throw ChronikError("Corrupted Chronik LevelDB table id");
            }
            std::string name(ToStringView(it->key()).substr(prefix.size()));
            const auto spec_it = m_by_name.find(name);
            if (spec_it != m_by_name.end()) {
                const TableSpec &spec = m_specs[spec_it->second];
                std::string expected;
                expected.push_back(spec.kind == TableSpec::Kind::Dup ? 1 : 0);
                if (spec.dup_fixed_size) {
                    AppendVarint(expected, *spec.dup_fixed_size);
                }
                if (value != expected) {
                    throw ChronikError("Chronik LevelDB table " + name +
                                       " has a different layout; reindex "
                                       "with -chronikreindex");
                }
            }
            max_id = std::max(max_id, *id);
            ids.emplace(std::move(name), *id);
        }
        CheckStatus(it->status(), "iterator(tables)");
    }
    for (const TableSpec &spec : m_specs) {
        const std::string name(spec.name);
        auto it = ids.find(name);
        uint64_t id;
        if (it != ids.end()) {
            id = it->second;
        } else {
            id = ++max_id;
            std::string value;
            AppendVarint(value, id);
            value.push_back(spec.kind == TableSpec::Kind::Dup ? 1 : 0);
            if (spec.dup_fixed_size) {
                AppendVarint(value, *spec.dup_fixed_size);
            }
            batch.Put(StoreMetaKey(std::string(kTableKeyPrefix) + name),
                      value);
        }
        std::string prefix;
        AppendVarint(prefix, id);
        // The last varint byte is < 0x80, so the successor always exists.
        m_prefix_ends.push_back(*PrefixSuccessor(prefix));
        m_prefixes.push_back(std::move(prefix));
    }
    leveldb::WriteOptions wo;
    wo.sync = true;
    CheckStatus(m_db->Write(wo, &batch), "write(tables)");
}

LevelDbStore::~LevelDbStore() {
    if (m_db) {
        leveldb::WriteOptions wo;
        wo.sync = true;
        leveldb::WriteBatch empty;
        const leveldb::Status status = m_db->Write(wo, &empty);
        if (!status.ok()) {
            std::fprintf(stderr, "Chronik LevelDB shutdown sync failed: %s\n",
                         status.ToString().c_str());
        }
    }
    // The DB must close before its cache and filter policy are freed.
    m_db.reset();
}

} // namespace

std::unique_ptr<KvStore> OpenLevelDbStore(const std::filesystem::path &dir,
                                          std::span<const TableSpec> tables,
                                          const StoreOptions & /*opts*/) {
    return std::make_unique<LevelDbStore>(dir, tables);
}

void DestroyLevelDbStore(const std::filesystem::path &dir) {
    if (!std::filesystem::exists(dir)) {
        return;
    }
    CheckStatus(leveldb::DestroyDB(dir.string(), leveldb::Options()),
                "destroy");
    std::error_code ec;
    if (std::filesystem::is_empty(dir, ec)) {
        std::filesystem::remove(dir, ec);
    }
}

void RegisterLevelDbStore() {
    RegisterStoreBackend(
        StoreBackend::LevelDb,
        [](const std::filesystem::path &dir, std::span<const TableSpec> tables,
           const StoreOptions &opts) {
            return OpenLevelDbStore(dir, tables, opts);
        },
        [](const std::filesystem::path &dir) { DestroyLevelDbStore(dir); });
}

} // namespace chronik::native
