// Copyright (c) 2026 The Lotus developers
#include "reorg_recovery.h"
#include "development_chain.h"
#include "vendor/blake3/blake3.h"
#include <algorithm>
#include <limits>
#include <stdexcept>
namespace lotus::v2 {
// The only raw-fact reconstruction authority. The canonical journal decoder
// checks checksum/mode/phase before calling this historical checkpoint fence.
struct CandidateFailureJournalAccess {
    static CandidateFailureFact
    Restore(const std::array<Hash, 4> &e, const Header &failed_header,
            const IndexedHeader &parent, const RetainedDiskState &checkpoint,
            const HeaderChainProfile &hp, const Hash &profile) {
        Hash block{}, parent_id{};
        Header stored_parent;
        if (e[2] != profile || failed_header.prev_id != e[1] ||
            !BlockId(hp.chain_id, failed_header, block) || block != e[0] ||
            !BlockId(hp.chain_id, parent.header, parent_id) ||
            parent_id != e[1] || parent.stage != HeaderStage::Connected ||
            checkpoint.metadata.tip != e[1] || checkpoint.root != e[3] ||
            !ParseHeader(checkpoint.metadata.header.data(),
                         checkpoint.metadata.header.size(), stored_parent))
            throw std::runtime_error("recovery evidence checkpoint binding");
        std::array<uint8_t, HEADER_SIZE> a{}, b{};
        if (!SerializeHeader(parent.header, a) ||
            !SerializeHeader(stored_parent, b) || a != b ||
            StateRoot(hp.chain_id, parent.header.height, checkpoint.root,
                      DecodeMonetaryState(checkpoint.metadata.monetary)) !=
                parent.header.state_root)
            throw std::runtime_error(
                "recovery evidence authenticated parent root");
        return CandidateFailureFact(e[0], e[1], e[2], e[3]);
    }
};
namespace {
    using Bytes = std::vector<uint8_t>;
    // Fixed local journal slot, not a network/consensus parameter. Reservation
    // keeps failure transitions exactly the same size as their prepared J.
    constexpr size_t DIAGNOSTIC_SIZE = 256;
    struct Stop {
        ReorgResult result;
    };
    void Require(bool value, const char *message) {
        if (!value) throw std::runtime_error(message);
    }
    [[noreturn]] void End(ReorgResult result, std::string &error,
                          const char *message) {
        error = message;
        throw Stop{result};
    }
    void Put(Bytes &out, uint64_t value) {
        for (unsigned i = 0; i < 8; ++i)
            out.push_back(uint8_t(value >> (8 * i)));
    }
    void PutHash(Bytes &out, const Hash &h) {
        out.insert(out.end(), h.begin(), h.end());
    }
    void PutBlob(Bytes &out, const Bytes &blob) {
        Put(out, blob.size());
        out.insert(out.end(), blob.begin(), blob.end());
    }
    Hash Digest(const Bytes &bytes) {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        constexpr char domain[] = "Lotus/v2/local-recovery-plan";
        blake3_hasher_update(&hasher, domain, sizeof(domain));
        blake3_hasher_update(&hasher, bytes.data(), bytes.size());
        Hash hash{};
        blake3_hasher_finalize(&hasher, hash.data(), hash.size());
        return hash;
    }
    Hash JournalChecksum(const Bytes &bytes, size_t length) {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        constexpr char domain[] = "Lotus/v2/local-recovery-journal";
        blake3_hasher_update(&hasher, domain, sizeof(domain));
        blake3_hasher_update(&hasher, bytes.data(), length);
        Hash hash{};
        blake3_hasher_finalize(&hasher, hash.data(), hash.size());
        return hash;
    }
    struct Reader {
        const Bytes &bytes;
        size_t at{};
        void Need(size_t n) {
            Require(n <= bytes.size() - at, "truncated recovery journal");
        }
        uint64_t Number() {
            Need(8);
            uint64_t value{};
            for (unsigned i = 0; i < 8; ++i)
                value |= uint64_t(bytes[at++]) << (8 * i);
            return value;
        }
        Hash HashValue() {
            Need(32);
            Hash value{};
            std::copy_n(bytes.begin() + at, 32, value.begin());
            at += 32;
            return value;
        }
        Bytes Blob(uint64_t cap = std::numeric_limits<uint64_t>::max()) {
            const uint64_t n = Number();
            Require(n <= bytes.size() - at, "recovery blob length");
            if (n > cap) throw Stop{ReorgResult::CapacityRefused};
            Bytes value(bytes.begin() + at, bytes.begin() + at + size_t(n));
            at += size_t(n);
            return value;
        }
        Bytes FixedBlob(size_t expected) {
            const uint64_t n = Number();
            Require(n == expected && n <= bytes.size() - at,
                    "recovery fixed field length");
            Bytes value(bytes.begin() + at, bytes.begin() + at + expected);
            at += expected;
            return value;
        }
        Bytes Auxiliary(uint64_t body_cap) {
            const uint64_t n = Number();
            Require(n <= bytes.size() - at && n >= 6,
                    "recovery source auxiliary length");
            const std::array<uint8_t, 5> prefix{'L', 'V', '2', 'C', 1};
            Require(
                std::equal(prefix.begin(), prefix.end(), bytes.begin() + at) &&
                    bytes[at + 5] && bytes[at + 5] <= 11,
                "recovery source auxiliary framing");
            const size_t offset = 6 + size_t(bytes[at + 5]) * HEADER_SIZE;
            Require(n >= offset && n - offset >= HEADER_SIZE,
                    "recovery source body length");
            if (n - offset > body_cap) throw Stop{ReorgResult::CapacityRefused};
            Bytes value(bytes.begin() + at, bytes.begin() + at + size_t(n));
            at += size_t(n);
            return value;
        }
    };
    struct PinnedBody {
        Hash id{};
        Bytes wire;
        DiskRecoveryUndoInfo undo; // Used only for source bodies.
    };
    enum class TerminalCause : uint64_t {
        None,
        Deferred,
        SourceOperational,
        Deterministic
    };
    struct Journal {
        Hash profile{}, genesis{}, source{}, target{}, fork{}, source_root{},
            attempt{};
        DiskStateMetadata source_metadata;
        ChainWork target_work{};
        uint64_t max_time{}, revision{}, detached{}, connected{}, restored{};
        ReorgPhase phase{ReorgPhase::DisconnectSource};
        bool invalid{}, receipts{}, has_evidence{};
        TerminalCause cause{TerminalCause::None};
        std::array<Hash, 4> evidence{};
        Hash failed{}, source_failed{};
        Bytes source_error;
        std::vector<PinnedBody> source_bodies, target_bodies;
    };
    void PutMetadata(Bytes &out, const DiskStateMetadata &metadata) {
        PutHash(out, metadata.tip);
        PutBlob(out, metadata.header);
        PutBlob(out, metadata.monetary);
        PutBlob(out, metadata.auxiliary);
    }
    DiskStateMetadata GetMetadata(Reader &r, const ReorgLimits &limits) {
        DiskStateMetadata metadata;
        metadata.tip = r.HashValue();
        metadata.header = r.FixedBlob(HEADER_SIZE);
        metadata.monetary = r.FixedBlob(56);
        metadata.auxiliary = r.Auxiliary(limits.max_body_bytes);
        return metadata;
    }
    Bytes Immutable(const Journal &j) {
        Bytes out;
        PutHash(out, j.profile);
        PutHash(out, j.genesis);
        PutHash(out, j.source);
        PutHash(out, j.target);
        PutHash(out, j.fork);
        PutHash(out, j.source_root);
        PutMetadata(out, j.source_metadata);
        out.insert(out.end(), j.target_work.begin(), j.target_work.end());
        Put(out, j.max_time);
        Put(out, j.source_bodies.size());
        for (const auto &body : j.source_bodies) {
            PutHash(out, body.id);
            PutBlob(out, body.wire);
            Put(out, body.undo.bytes);
            PutHash(out, body.undo.digest);
            PutHash(out, body.undo.before_tip);
            PutHash(out, body.undo.after_tip);
            PutHash(out, body.undo.before_root);
            PutHash(out, body.undo.after_root);
        }
        Put(out, j.target_bodies.size());
        for (const auto &body : j.target_bodies) {
            PutHash(out, body.id);
            PutBlob(out, body.wire);
        }
        return out;
    }
    Bytes Encode(const Journal &j, const ReorgLimits &limits) {
        Bytes immutable = Immutable(j);
        Bytes out{'L', 'V', '2', 'R', uint8_t(j.receipts ? 2 : 1)};
        PutBlob(out, immutable);
        PutHash(out, j.attempt);
        Put(out, j.revision);
        Put(out, uint8_t(j.phase));
        Put(out, j.detached);
        Put(out, j.connected);
        Put(out, j.restored);
        Put(out, j.invalid);
        PutHash(out, j.failed);
        PutHash(out, j.source_failed);
        Require(j.source_error.size() <= DIAGNOSTIC_SIZE,
                "recovery diagnostic length");
        PutBlob(out, j.source_error);
        out.insert(out.end(), DIAGNOSTIC_SIZE - j.source_error.size(), 0);
        if (j.receipts) {
            // Reserved even before failure: every mutable receipt field has a
            // fixed width, preserving the exact preparation capacity.
            Put(out, 1); // Evidence codec version.
            Put(out, j.has_evidence);
            for (const auto &hash : j.evidence)
                PutHash(out, hash);
            Put(out, uint64_t(j.cause));
            PutHash(out, JournalChecksum(out, out.size()));
        }
        if (out.size() > limits.max_journal_bytes)
            throw Stop{ReorgResult::CapacityRefused};
        return out;
    }
    void AddBounded(uint64_t &sum, uint64_t value, uint64_t bound,
                    const char *message) {
        (void)message;
        if (value > bound || sum > bound - value)
            throw Stop{ReorgResult::CapacityRefused};
        sum += value;
    }
    Header BodyHeader(const PinnedBody &body,
                      const HeaderChainProfile &profile) {
        Require(body.wire.size() >= HEADER_SIZE, "recovery body header");
        Header header;
        Require(ParseHeader(body.wire.data(), HEADER_SIZE, header) &&
                    header.size == body.wire.size(),
                "recovery body header/size");
        Hash id{};
        Require(BlockId(profile.chain_id, header, id) && id == body.id,
                "recovery body identity");
        return header;
    }
    Hash CurrentTip(const Journal &j) {
        const auto detached_tip = [&] {
            return j.detached < j.source_bodies.size()
                       ? j.source_bodies[j.detached].id
                       : j.fork;
        };
        switch (j.phase) {
            case ReorgPhase::DisconnectSource:
                return detached_tip();
            case ReorgPhase::ConnectTarget:
            case ReorgPhase::RollbackTarget:
                return j.connected ? j.target_bodies[j.connected - 1].id
                                   : j.fork;
            case ReorgPhase::RestoreSource:
                return j.restored ? j.source_bodies[j.detached - j.restored].id
                                  : detached_tip();
        }
        throw std::runtime_error("recovery phase");
    }
    void ValidateShape(const Journal &j, const ReorgProfiles &p) {
        Require(j.profile == BlockValidationProfileDigest(p.header, p.ordinary,
                                                          p.monetary, p.cost) &&
                    j.genesis == p.header.genesis_id && j.genesis != Hash{},
                "recovery profile mismatch");
        Require(j.source_metadata.tip == j.source,
                "recovery source snapshot identity");
        std::vector<Header> history;
        Bytes body;
        std::string error;
        Require(ReadDiskChainContext(j.source_metadata, p.header, history, body,
                                     error),
                "recovery source history");
        const auto money = DecodeMonetaryState(j.source_metadata.monetary);
        Require(StateRoot(p.header.chain_id, history.front().height,
                          j.source_root, money) == history.front().state_root,
                "recovery source state");
        Require(j.detached <= j.source_bodies.size() &&
                    j.connected <= j.target_bodies.size() &&
                    j.restored <= j.detached &&
                    (!j.target_bodies.empty() || (!j.source_bodies.empty() && j.target == j.fork)),
                "recovery cursors");
        if (j.phase == ReorgPhase::DisconnectSource)
            Require(!j.connected && !j.restored && !j.invalid,
                    "recovery disconnect phase");
        if (j.phase == ReorgPhase::ConnectTarget ||
            j.phase == ReorgPhase::RollbackTarget)
            Require(j.detached == j.source_bodies.size() && !j.restored,
                    "recovery target phase");
        if (j.phase == ReorgPhase::RestoreSource)
            Require(!j.connected, "recovery restore phase");
        Require(j.invalid == (j.failed != Hash{}), "recovery failure identity");
        Require((j.source_failed != Hash{}) == !j.source_error.empty(),
                "recovery source failure diagnostic");
        if (j.source_failed != Hash{})
            Require(j.phase == ReorgPhase::RestoreSource && !j.invalid &&
                        j.detached && j.detached < j.source_bodies.size() &&
                        j.source_failed == j.source_bodies[j.detached].id,
                    "recovery source failure phase");
        if (j.receipts) {
            Require(j.has_evidence == j.invalid,
                    "recovery evidence discriminant");
            Require((j.cause == TerminalCause::Deterministic) == j.has_evidence,
                    "recovery deterministic outcome evidence");
            if (!j.has_evidence)
                Require(j.evidence == std::array<Hash, 4>{},
                        "unexpected recovery evidence bytes");
            if (j.source_failed != Hash{})
                Require(j.cause == TerminalCause::SourceOperational,
                        "recovery operational outcome");
            if (j.has_evidence) {
                Require(j.evidence[0] == j.failed && j.evidence[2] == j.profile,
                        "recovery evidence identity/profile");
                const auto failed =
                    std::find_if(j.target_bodies.begin(), j.target_bodies.end(),
                                 [&](const PinnedBody &body) {
                                     return body.id == j.failed;
                                 });
                Require(failed != j.target_bodies.end() &&
                            BodyHeader(*failed, p.header).prev_id ==
                                j.evidence[1],
                        "recovery evidence target parent");
                Require((j.phase == ReorgPhase::RollbackTarget ||
                         j.phase == ReorgPhase::RestoreSource) &&
                            j.detached == j.source_bodies.size() &&
                            j.connected <=
                                size_t(failed - j.target_bodies.begin()),
                        "recovery evidence execution phase");
            }
        }
        Hash cursor = j.source;
        uint64_t height = history.front().height;
        Hash root = j.source_root;
        for (const auto &source : j.source_bodies) {
            const auto h = BodyHeader(source, p.header);
            Require(source.id == cursor && h.height == height && height &&
                        source.undo.after_tip == cursor &&
                        source.undo.before_tip == h.prev_id &&
                        source.undo.after_root == root,
                    "recovery source path/undo");
            cursor = h.prev_id;
            --height;
            root = source.undo.before_root;
        }
        Require(cursor == j.fork, "recovery fork/source path");
        cursor = j.fork;
        for (const auto &target : j.target_bodies) {
            const auto h = BodyHeader(target, p.header);
            Require(height != std::numeric_limits<uint64_t>::max() &&
                        h.height == ++height && h.prev_id == cursor,
                    "recovery target path");
            cursor = target.id;
        }
        Require(cursor == j.target, "recovery target identity");
    }
    Journal Decode(const Bytes &bytes, const ReorgLimits &limits,
                   const ReorgProfiles &p, bool receipts) {
        Require(bytes.size() >= 5 &&
                    std::equal(bytes.begin(), bytes.begin() + 5,
                               std::array<uint8_t, 5>{'L', 'V', '2', 'R',
                                                      uint8_t(receipts ? 2 : 1)}
                                   .begin()),
                "recovery journal version");
        if (receipts) {
            Require(bytes.size() >= 32, "recovery journal checksum framing");
            const auto checksum = JournalChecksum(bytes, bytes.size() - 32);
            Require(
                std::equal(checksum.begin(), checksum.end(), bytes.end() - 32),
                "recovery journal checksum");
        }
        Reader outer{bytes, 5};
        Bytes immutable = outer.Blob(limits.max_journal_bytes);
        Journal j;
        j.receipts = receipts;
        j.attempt = outer.HashValue();
        Require(j.attempt == Digest(immutable), "recovery plan digest");
        j.revision = outer.Number();
        const auto phase = outer.Number();
        Require(phase <= uint8_t(ReorgPhase::RestoreSource),
                "recovery phase encoding");
        j.phase = ReorgPhase(phase);
        j.detached = outer.Number();
        j.connected = outer.Number();
        j.restored = outer.Number();
        const auto invalid = outer.Number();
        Require(invalid <= 1, "recovery failure encoding");
        j.invalid = invalid;
        j.failed = outer.HashValue();
        j.source_failed = outer.HashValue();
        j.source_error = outer.Blob(DIAGNOSTIC_SIZE);
        const size_t padding = DIAGNOSTIC_SIZE - j.source_error.size();
        outer.Need(padding);
        Require(std::all_of(bytes.begin() + outer.at,
                            bytes.begin() + outer.at + padding,
                            [](uint8_t byte) { return byte == 0; }),
                "recovery diagnostic padding");
        outer.at += padding;
        if (receipts) {
            Require(outer.Number() == 1, "recovery evidence version");
            const auto present = outer.Number();
            Require(present <= 1, "recovery evidence presence");
            j.has_evidence = present;
            for (auto &hash : j.evidence)
                hash = outer.HashValue();
            const auto cause = outer.Number();
            Require(cause <= uint64_t(TerminalCause::Deterministic),
                    "recovery terminal cause");
            j.cause = TerminalCause(cause);
            (void)outer.HashValue(); // Already authenticated before allocation.
        }
        Require(outer.at == bytes.size(), "trailing recovery bytes");
        Reader r{immutable};
        j.profile = r.HashValue();
        j.genesis = r.HashValue();
        j.source = r.HashValue();
        j.target = r.HashValue();
        j.fork = r.HashValue();
        j.source_root = r.HashValue();
        j.source_metadata = GetMetadata(r, limits);
        r.Need(j.target_work.size());
        std::copy_n(immutable.begin() + r.at, j.target_work.size(),
                    j.target_work.begin());
        r.at += j.target_work.size();
        j.max_time = r.Number();
        uint64_t count = r.Number();
        if (count > limits.fork.max_disconnect)
            throw Stop{ReorgResult::CapacityRefused};
        Require(count <= (immutable.size() - r.at) /
                             (32 + 8 + HEADER_SIZE + 8 + 5 * 32),
                "recovery source count");
        uint64_t body_total{}, undo_total{};
        for (uint64_t i = 0; i < count; ++i) {
            PinnedBody b;
            b.id = r.HashValue();
            Require(body_total <= limits.max_total_body_bytes,
                    "recovery body counter");
            b.wire = r.Blob(std::min(limits.max_body_bytes,
                                     limits.max_total_body_bytes - body_total));
            AddBounded(body_total, b.wire.size(), limits.max_total_body_bytes,
                       "recovery total body bytes");
            b.undo.bytes = r.Number();
            if (b.undo.bytes > limits.max_undo_bytes)
                throw Stop{ReorgResult::CapacityRefused};
            AddBounded(undo_total, b.undo.bytes, limits.max_total_undo_bytes,
                       "recovery total undo bytes");
            b.undo.digest = r.HashValue();
            b.undo.before_tip = r.HashValue();
            b.undo.after_tip = r.HashValue();
            b.undo.before_root = r.HashValue();
            b.undo.after_root = r.HashValue();
            j.source_bodies.push_back(std::move(b));
        }
        count = r.Number();
        if (count > limits.fork.max_connect)
            throw Stop{ReorgResult::CapacityRefused};
        Require(count <= (immutable.size() - r.at) / (32 + 8 + HEADER_SIZE),
                "recovery target count");
        for (uint64_t i = 0; i < count; ++i) {
            PinnedBody b;
            b.id = r.HashValue();
            Require(body_total <= limits.max_total_body_bytes,
                    "recovery body counter");
            b.wire = r.Blob(std::min(limits.max_body_bytes,
                                     limits.max_total_body_bytes - body_total));
            AddBounded(body_total, b.wire.size(), limits.max_total_body_bytes,
                       "recovery total body bytes");
            j.target_bodies.push_back(std::move(b));
        }
        Require(r.at == immutable.size(), "trailing recovery plan bytes");
        ValidateShape(j, p);
        return j;
    }
    ReorgProgress Progress(const Journal &j) {
        ReorgProgress p;
        p.attempt = j.attempt;
        p.source = j.source;
        p.target = j.target;
        p.fork = j.fork;
        p.current = CurrentTip(j);
        p.failed_block = j.failed;
        p.source_failure_block = j.source_failed;
        p.operational_error.assign(j.source_error.begin(),
                                   j.source_error.end());
        p.revision = j.revision;
        p.detached = j.detached;
        p.connected = j.connected;
        p.restored = j.restored;
        p.phase = j.phase;
        p.replacement_invalid = j.invalid;
        return p;
    }
    void Advance(Journal &j) {
        Require(j.revision != std::numeric_limits<uint64_t>::max(),
                "recovery revision exhausted");
        ++j.revision;
    }
    DiskRecoveryUpdate Update(const std::optional<Bytes> &old,
                              const std::optional<Bytes> &next,
                              const DiskStateStore &store, const Hash &tip) {
        DiskRecoveryUpdate u;
        u.expected_journal = old;
        u.next_journal = next;
        u.expected_tip = store.Metadata().tip;
        u.expected_root = store.Root();
        u.next_tip = tip;
        return u;
    }
    ReorgResult StorageFailure(const DiskStateError &failure,
                               std::string &error) {
        error = failure.message;
        return failure.code == DiskStateErrorCode::Resource
                   ? ReorgResult::CapacityRefused
                   : ReorgResult::StorageError;
    }
    void RequireProfile(const ReorgProfiles &p, const DiskStateStore &store) {
        Require(p.header.genesis_id != Hash{} &&
                    store.MatchesProfile(
                        p.header.chain_id,
                        BlockValidationProfileDigest(p.header, p.ordinary,
                                                     p.monetary, p.cost)),
                "recovery validator profile");
    }
    void CheckCurrent(const Journal &j, const ReorgProfiles &p,
                      const DiskStateStore &store) {
        Require(store.Metadata().tip == CurrentTip(j),
                "recovery journal/current tip mismatch");
        std::vector<Header> history;
        Bytes body;
        std::string error;
        const auto meta = store.Metadata();
        Require(ReadDiskChainContext(meta, p.header, history, body, error) &&
                    !body.empty(),
                "recovery current history/body");
        Require(StateRoot(p.header.chain_id, history.front().height,
                          store.Root(), DecodeMonetaryState(meta.monetary)) ==
                    history.front().state_root,
                "recovery current state");
        std::optional<ActiveChainIndex> active;
        DiskStateError failure;
        Require(store.ReadActiveIndex(active, failure) && active &&
                    active->tip == CurrentTip(j),
                "recovery current active index");
    }
    class ReadBudget {
        const DiskStateStore &store;
        uint64_t remaining;

    public:
        ReadBudget(const DiskStateStore &s, uint64_t n)
            : store(s), remaining(n) {}
        template <typename F> auto Read(uint64_t maximum, F &&f) {
            if (maximum > remaining) throw Stop{ReorgResult::CapacityRefused};
            const auto before = store.LastStats().database_reads;
            auto result = f();
            const auto after = store.LastStats().database_reads;
            Require(after >= before && after - before <= maximum,
                    "recovery read bound changed");
            remaining -= after - before;
            return result;
        }
        uint64_t Remaining() const { return remaining; }
    };
    void VerifyIndexes(const Journal &j, const ReorgProfiles &p,
                       const DiskStateStore &store, ReadBudget &budget) {
        DiskStateError failure;
        auto read = [&](const Hash &id) {
            std::optional<IndexedHeader> indexed;
            Require(budget.Read(3,
                                [&] {
                                    return store.ReadIndexedHeader(id, indexed,
                                                                   failure);
                                }) &&
                        indexed,
                    "recovery indexed header unavailable");
            return *indexed;
        };
        const auto target = read(j.target);
        Require(target.chain_work == j.target_work &&
                    target.max_ancestor_time == j.max_time,
                "recovery indexed target changed");
        for (const auto &source : j.source_bodies) {
            const auto indexed = read(source.id);
            std::array<uint8_t, HEADER_SIZE> a{}, b{};
            Require(SerializeHeader(indexed.header, a) &&
                        SerializeHeader(BodyHeader(source, p.header), b) &&
                        a == b && indexed.stage == HeaderStage::Connected,
                    "recovery indexed source changed");
        }
        for (const auto &body : j.target_bodies) {
            const auto indexed = read(body.id);
            std::array<uint8_t, HEADER_SIZE> a{}, b{};
            Require(SerializeHeader(indexed.header, a) &&
                        SerializeHeader(BodyHeader(body, p.header), b) &&
                        a == b,
                    "recovery indexed replacement changed");
        }
    }
    CandidateFailureFact RestoreEvidence(const Journal &j,
                                         const ReorgProfiles &p,
                                         const DiskStateStore &store,
                                         ReadBudget &budget) {
        if (!j.receipts || !j.has_evidence) return {};
        const auto failed = std::find_if(
            j.target_bodies.begin(), j.target_bodies.end(),
            [&](const PinnedBody &body) { return body.id == j.failed; });
        Require(failed != j.target_bodies.end(),
                "recovery failed body unavailable");
        std::optional<IndexedHeader> parent;
        std::optional<RetainedDiskState> checkpoint;
        DiskStateError failure;
        Require(budget.Read(3,
                            [&] {
                                return store.ReadIndexedHeader(j.evidence[1],
                                                               parent, failure);
                            }) &&
                    parent,
                "recovery evidence parent unavailable");
        Require(budget.Read(2,
                            [&] {
                                return store.ReadRetainedState(
                                    j.evidence[1], checkpoint, failure);
                            }) &&
                    checkpoint,
                "recovery evidence checkpoint unavailable");
        return CandidateFailureJournalAccess::Restore(
            j.evidence, BodyHeader(*failed, p.header), *parent, *checkpoint,
            p.header, j.profile);
    }
    bool Future(uint64_t maximum, uint64_t now, uint64_t window) {
        return maximum > now && maximum - now > window;
    }
    template <typename F> ReorgResult Run(std::string &error, F &&f) {
        error.clear();
        try {
            return f();
        } catch (const Stop &stop) {
            if (stop.result == ReorgResult::CapacityRefused)
                error = "recovery operational capacity";
            return stop.result;
        } catch (const std::exception &e) {
            error = e.what();
            return ReorgResult::StorageError;
        }
    }
} // namespace
ReorgResult PrepareDevelopmentSwitch(const Hash &source, const Hash &target,
                                     uint64_t now, uint64_t window,
                                     const ReorgLimits &limits,
                                     const ReorgProfiles &p,
                                     const ReorgBodySource &body_source,
                                     DiskStateStore &store, ReorgProgress &out,
                                     std::string &error, bool allow_parked_source) {
    return Run(error, [&] {
        RequireProfile(p, store);
        if (!limits.max_journal_bytes || !limits.max_body_bytes ||
            !limits.max_total_body_bytes)
            End(ReorgResult::CapacityRefused, error,
                "recovery preparation limits");
        ReadBudget budget(store, limits.fork.max_reads);
        std::optional<Bytes> existing;
        DiskStateError failure;
        if (!budget.Read(2, [&] {
                return store.ReadRecoveryJournal(limits.max_journal_bytes,
                                                 existing, failure);
            }))
            return StorageFailure(failure, error);
        if (existing)
            End(ReorgResult::StaleTip, error, "recovery already pending");
        if (store.Metadata().tip != source)
            End(ReorgResult::StaleTip, error, "recovery source changed");
        if (store.CandidatesEnabled()) {
            CandidateView view;
            if (!budget.Read(CANDIDATE_VIEW_MAX_READS, [&] {
                    return store.ReadCandidateView(view, failure);
                }))
                return StorageFailure(failure, error);
            if (view.pending_receipt || view.pending_propagation)
                End(ReorgResult::Inconclusive, error,
                    "candidate terminal work pending");
        }
        ForkPlan plan;
        auto fork_limits = limits.fork;
        fork_limits.max_reads = budget.Remaining();
        const auto planned = budget.Read(budget.Remaining(), [&] {
            return PlanHeaderFork(store, source, target, fork_limits, now,
                                  window, plan, failure, allow_parked_source);
        });
        switch (planned) {
            case ChainIndexResult::Complete:
                break;
            case ChainIndexResult::Missing:
                return ReorgResult::MissingBody;
            case ChainIndexResult::NotHeavier:
                return ReorgResult::NotHeavier;
            case ChainIndexResult::Excluded:
                return ReorgResult::ExcludedTarget;
            case ChainIndexResult::Deferred:
                return ReorgResult::Deferred;
            case ChainIndexResult::CapacityRefused:
                return ReorgResult::CapacityRefused;
            case ChainIndexResult::StaleTip:
                return ReorgResult::StaleTip;
            case ChainIndexResult::StorageError:
                return StorageFailure(failure, error);
        }
        Journal j;
        j.receipts = store.CandidatesEnabled();
        j.profile = BlockValidationProfileDigest(p.header, p.ordinary,
                                                 p.monetary, p.cost);
        j.genesis = p.header.genesis_id;
        j.source = plan.source;
        j.target = plan.target;
        j.fork = plan.fork;
        j.source_metadata = store.Metadata();
        j.source_root = store.Root();
        // Metadata() already copies the home-capped current tuple. Check its
        // embedded body before any further body decoding/copy or J publication.
        const auto &source_aux = j.source_metadata.auxiliary;
        Require(source_aux.size() >= 6 && source_aux[5] && source_aux[5] <= 11,
                "source snapshot auxiliary framing");
        const size_t source_offset = 6 + size_t(source_aux[5]) * HEADER_SIZE;
        Require(source_aux.size() >= source_offset,
                "source snapshot auxiliary length");
        if (source_aux.size() - source_offset > limits.max_body_bytes)
            return ReorgResult::CapacityRefused;
        std::optional<IndexedHeader> target_header;
        if (!budget.Read(3,
                         [&] {
                             return store.ReadIndexedHeader(
                                 target, target_header, failure);
                         }) ||
            !target_header)
            End(ReorgResult::StorageError, error,
                "recovery target unavailable");
        j.target_work = target_header->chain_work;
        j.max_time = target_header->max_ancestor_time;
        uint64_t total_body{}, total_undo{};
        for (const auto &id : plan.disconnect) {
            PinnedBody pinned;
            pinned.id = id;
            std::optional<DiskRecoveryUndoInfo> undo;
            if (!budget.Read(2, [&] {
                    return store.ProbeRecoveryUndo(
                        id,
                        std::min(limits.max_undo_bytes,
                                 limits.max_total_undo_bytes - total_undo),
                        undo, failure);
                }))
                return StorageFailure(failure, error);
            if (!undo)
                End(ReorgResult::StorageError, error,
                    "source undo unavailable");
            pinned.undo = *undo;
            AddBounded(total_undo, undo->bytes, limits.max_total_undo_bytes,
                       "source undo total capacity");
            const auto available = budget.Read(2, [&] {
                return ReadRetainedBlockBody(
                    id,
                    std::min(limits.max_body_bytes,
                             std::min(limits.max_total_body_bytes,
                                      limits.max_journal_bytes) -
                                 total_body),
                    p.header, p.ordinary, p.monetary, p.cost, store,
                    pinned.wire, error);
            });
            if (available == RetainedBodyStatus::Missing)
                return ReorgResult::MissingBody;
            if (available == RetainedBodyStatus::CapacityRefused)
                return ReorgResult::CapacityRefused;
            if (available != RetainedBodyStatus::Available)
                return ReorgResult::StorageError;
            AddBounded(
                total_body, pinned.wire.size(),
                std::min(limits.max_total_body_bytes, limits.max_journal_bytes),
                "source body total capacity");
            j.source_bodies.push_back(std::move(pinned));
        }
        for (const auto &id : plan.connect) {
            PinnedBody pinned;
            pinned.id = id;
            std::optional<IndexedHeader> indexed;
            if (!budget.Read(3,
                             [&] {
                                 return store.ReadIndexedHeader(id, indexed,
                                                                failure);
                             }) ||
                !indexed)
                End(ReorgResult::StorageError, error,
                    "replacement indexed header unavailable");
            if (!body_source)
                End(ReorgResult::MissingBody, error,
                    "replacement body source absent");
            const auto found =
                body_source(id,
                            std::min(limits.max_body_bytes,
                                     std::min(limits.max_total_body_bytes,
                                              limits.max_journal_bytes) -
                                         total_body),
                            pinned.wire, error);
            if (found == ReorgBodyResult::Missing)
                return ReorgResult::MissingBody;
            if (found == ReorgBodyResult::CapacityRefused)
                return ReorgResult::CapacityRefused;
            if (found != ReorgBodyResult::Found)
                return ReorgResult::StorageError;
            if (pinned.wire.size() > limits.max_body_bytes)
                return ReorgResult::CapacityRefused;
            AddBounded(
                total_body, pinned.wire.size(),
                std::min(limits.max_total_body_bytes, limits.max_journal_bytes),
                "replacement body total capacity");
            FramedBlock parsed;
            if (!DecodeBlockWire(pinned.wire, p.ordinary.transaction,
                                 p.header.chain_id, parsed, error))
                return ReorgResult::InvalidBody;
            std::array<uint8_t, HEADER_SIZE> expected{}, actual{};
            if (!SerializeHeader(indexed->header, expected) ||
                !SerializeHeader(parsed.header, actual) || expected != actual)
                End(ReorgResult::InvalidBody, error,
                    "replacement body differs from indexed header");
            if (!CheckCoinbaseContext(parsed.transactions.front(),
                                      parsed.header.prev_id,
                                      parsed.header.height, error))
                return ReorgResult::InvalidBody;
            j.target_bodies.push_back(std::move(pinned));
        }
        ValidateShape(j, p);
        j.attempt = Digest(Immutable(j));
        const auto bytes = Encode(j, limits);
        if (store.Metadata() != j.source_metadata ||
            store.Root() != j.source_root)
            End(ReorgResult::StaleTip, error,
                "recovery source changed during preparation");
        if (Future(j.max_time, now, window)) return ReorgResult::Deferred;
        if (j.receipts) {
            // Header records and public choices do not confer eligibility.
            const auto check = [&](const Hash &id) {
                std::optional<Hash> causal_root;
                if (!budget.Read(CANDIDATE_INVALIDITY_MAX_READS, [&] {
                        return store.ReadCandidateInvalidity(id, causal_root,
                                                             failure);
                    }))
                    return StorageFailure(failure, error);
                if (causal_root)
                    End(ReorgResult::ExcludedTarget, error,
                        "target has deterministic invalid ancestry");
                return ReorgResult::Progress;
            };
            const auto common = check(j.fork);
            if (common != ReorgResult::Progress) return common;
            for (const auto &body : j.target_bodies) {
                const auto eligible = check(body.id);
                if (eligible != ReorgResult::Progress) return eligible;
            }
        }
        if (j.receipts && !budget.Read(CANDIDATE_CAPACITY_MAX_READS, [&] {
                return store.CheckCandidateRecoveryCapacity(
                    j.source_bodies.size(), failure);
            }))
            return StorageFailure(failure, error);
        const auto update = Update(std::nullopt, bytes, store, source);
        if (!store.WriteRecoveryJournal(update, failure))
            return StorageFailure(failure, error);
        out = Progress(j);
        error.clear();
        return ReorgResult::Prepared;
    });
}
ReorgResult ReadDevelopmentSwitch(const ReorgLimits &limits,
                                  const ReorgProfiles &p,
                                  const DiskStateStore &store,
                                  ReorgProgress &out, std::string &error) {
    return Run(error, [&] {
        RequireProfile(p, store);
        ReadBudget budget(store, limits.fork.max_reads);
        std::optional<Bytes> bytes;
        DiskStateError failure;
        if (!budget.Read(2, [&] {
                return store.ReadRecoveryJournal(limits.max_journal_bytes,
                                                 bytes, failure);
            }))
            return StorageFailure(failure, error);
        if (!bytes) {
            error.clear();
            return ReorgResult::Idle;
        }
        const auto journal =
            Decode(*bytes, limits, p, store.CandidatesEnabled());
        budget.Read(7, [&] {
            CheckCurrent(journal, p, store);
            return 0;
        });
        VerifyIndexes(journal, p, store, budget);
        (void)RestoreEvidence(journal, p, store, budget);
        out = Progress(journal);
        error.clear();
        return ReorgResult::Progress;
    });
}
ReorgResult StepDevelopmentSwitch(uint64_t now, uint64_t window,
                                  const ReorgLimits &limits,
                                  const ReorgProfiles &p, DiskStateStore &store,
                                  ReorgProgress &out, std::string &error) {
    return Run(error, [&] {
        RequireProfile(p, store);
        ReadBudget budget(store, limits.fork.max_reads);
        std::optional<Bytes> bytes;
        DiskStateError failure;
        if (!budget.Read(2, [&] {
                return store.ReadRecoveryJournal(limits.max_journal_bytes,
                                                 bytes, failure);
            }))
            return StorageFailure(failure, error);
        if (!bytes) {
            error.clear();
            return ReorgResult::Idle;
        }
        const Journal old =
            Decode(*bytes, limits, p, store.CandidatesEnabled());
        budget.Read(7, [&] {
            CheckCurrent(old, p, store);
            return 0;
        });
        VerifyIndexes(old, p, store, budget);
        const auto fact = RestoreEvidence(old, p, store, budget);
        Journal next = old;
        const auto publish = [&](Journal &journal) {
            Advance(journal);
            const auto update = Update(bytes, Encode(journal, limits), store,
                                       CurrentTip(journal));
            if (!store.WriteRecoveryJournal(update, failure))
                return StorageFailure(failure, error);
            out = Progress(journal);
            error.clear();
            return ReorgResult::Progress;
        };
        const auto finish = [&](ReorgResult result) {
            const auto update =
                Update(bytes, std::nullopt, store, CurrentTip(old));
            if (old.receipts) {
                CandidateTerminalClaim claim;
                claim.attempt = old.attempt;
                claim.source = old.source;
                claim.target = old.target;
                claim.revision = old.revision;
                if (result == ReorgResult::CompleteTarget) {
                    Require(!old.has_evidence &&
                                old.cause == TerminalCause::None,
                            "completed target has failure evidence");
                    claim.outcome = CandidateTerminalOutcome::CompletedTarget;
                } else if (result == ReorgResult::Deferred ||
                           old.cause == TerminalCause::Deferred) {
                    Require(!old.has_evidence,
                            "deferred outcome has failure evidence");
                    claim.outcome =
                        CandidateTerminalOutcome::RestoredSourceDeferred;
                } else if (old.cause == TerminalCause::Deterministic) {
                    Require(old.invalid && fact.Valid(),
                            "deterministic terminal evidence unavailable");
                    claim.outcome =
                        CandidateTerminalOutcome::RestoredSourceDeterministic;
                    claim.failure = fact;
                } else {
                    Require(!old.has_evidence,
                            "unknown outcome has failure evidence");
                    claim.outcome =
                        CandidateTerminalOutcome::RestoredSourceUnknown;
                }
                if (!store.FinishCandidateRecovery(update, claim, failure))
                    return StorageFailure(failure, error);
            } else if (!store.WriteRecoveryJournal(update, failure))
                return StorageFailure(failure, error);
            out = Progress(old);
            error.clear();
            return result;
        };
        // Rollback/restoration intentionally bypass new clock gates. A backward
        // clock must not make restoration of the previously valid source fail.
        if ((old.phase == ReorgPhase::DisconnectSource ||
             old.phase == ReorgPhase::ConnectTarget) &&
            Future(old.max_time, now, window)) {
            if (!old.detached && !old.connected)
                return finish(ReorgResult::Deferred);
            if (next.receipts) next.cause = TerminalCause::Deferred;
            next.phase = old.connected ? ReorgPhase::RollbackTarget
                                       : ReorgPhase::RestoreSource;
            return publish(next);
        }
        if (old.phase == ReorgPhase::DisconnectSource) {
            if (old.detached == old.source_bodies.size()) {
                next.phase = ReorgPhase::ConnectTarget;
                return publish(next);
            }
            const auto &source = old.source_bodies[old.detached];
            ++next.detached;
            Advance(next);
            auto update =
                Update(bytes, Encode(next, limits), store, CurrentTip(next));
            update.expected_undo_digest = source.undo.digest;
            if (!DisconnectRecoveryDevelopmentTip(
                    source.id, p.header, p.ordinary, p.monetary, p.cost, update,
                    store, error)) {
                if (!old.detached) return ReorgResult::StorageError;
                const auto cause =
                    error.empty() ? "source detach operational failure" : error;
                Journal restore = old;
                restore.phase = ReorgPhase::RestoreSource;
                if (restore.receipts)
                    restore.cause = TerminalCause::SourceOperational;
                restore.source_failed = source.id;
                restore.source_error.assign(
                    cause.begin(),
                    cause.begin() + std::min(cause.size(), DIAGNOSTIC_SIZE));
                // This CAS succeeds only on the exact old checkpoint. A
                // poisoned/ambiguous write cannot guess durable progress.
                const auto result = publish(restore);
                if (result == ReorgResult::Progress) error = cause;
                return result;
            }
            out = Progress(next);
            error.clear();
            return ReorgResult::Progress;
        }
        if (old.phase == ReorgPhase::ConnectTarget) {
            if (old.connected == old.target_bodies.size()) {
                Require(store.Metadata().tip == old.target,
                        "recovery final target tip");
                return finish(ReorgResult::CompleteTarget);
            }
            const auto &body = old.target_bodies[old.connected];
            ++next.connected;
            Advance(next);
            const auto update =
                Update(bytes, Encode(next, limits), store, CurrentTip(next));
            StagedBlockTransition connected;
            DeterministicBlockFailure failure;
            const auto result = ConnectStoredRecoveryBlock(
                body.wire, p.header, p.ordinary, p.monetary, p.cost, update,
                store, connected, error, &failure);
            if (result == CandidateCheckResult::StorageError)
                return ReorgResult::StorageError;
            if (result == CandidateCheckResult::Inconclusive)
                return ReorgResult::Inconclusive;
            if (result == CandidateCheckResult::Invalid) {
                // An invalid supplied body alone is not evidence that its
                // authenticated header is permanently invalid.
                if (!failure.Valid() || failure.BlockId() != body.id ||
                    failure.ParentId() != store.Metadata().tip ||
                    failure.ParentRoot() != store.Root() ||
                    failure.ProfileDigest() !=
                        BlockValidationProfileDigest(p.header, p.ordinary,
                                                     p.monetary, p.cost))
                    return ReorgResult::Inconclusive;
                next = old;
                if (next.receipts) {
                    CandidateFailureFact fact;
                    if (!CandidateFailureFact::FromValidation(failure, fact) ||
                        !fact.Valid())
                        return ReorgResult::Inconclusive;
                    next.has_evidence = true;
                    next.evidence = {fact.BlockId(), fact.ParentId(),
                                     fact.ProfileDigest(), fact.ParentRoot()};
                    next.cause = TerminalCause::Deterministic;
                }
                next.invalid = true;
                next.failed = body.id;
                next.phase = ReorgPhase::RollbackTarget;
                return publish(next);
            }
            out = Progress(next);
            error.clear();
            return ReorgResult::Progress;
        }
        if (old.phase == ReorgPhase::RollbackTarget) {
            if (!old.connected) {
                next.phase = ReorgPhase::RestoreSource;
                return publish(next);
            }
            const auto id = old.target_bodies[old.connected - 1].id;
            --next.connected;
            Advance(next);
            const auto update =
                Update(bytes, Encode(next, limits), store, CurrentTip(next));
            if (!DisconnectRecoveryDevelopmentTip(id, p.header, p.ordinary,
                                                  p.monetary, p.cost, update,
                                                  store, error))
                return ReorgResult::StorageError;
            out = Progress(next);
            error.clear();
            return ReorgResult::Progress;
        }
        if (old.restored == old.detached) {
            Require(store.Metadata() == old.source_metadata &&
                        store.Root() == old.source_root,
                    "recovery restored source tuple differs");
            return finish(ReorgResult::RestoredSource);
        }
        const auto &source = old.source_bodies[old.detached - old.restored - 1];
        ++next.restored;
        Advance(next);
        const auto update =
            Update(bytes, Encode(next, limits), store, CurrentTip(next));
        StagedBlockTransition restored;
        const auto result = ConnectStoredRecoveryBlock(
            source.wire, p.header, p.ordinary, p.monetary, p.cost, update,
            store, restored, error);
        if (result != CandidateCheckResult::Accepted) {
            if (result == CandidateCheckResult::Inconclusive)
                return ReorgResult::Inconclusive;
            if (result == CandidateCheckResult::Invalid)
                error = "previously accepted source body failed recovery "
                        "validation";
            return ReorgResult::StorageError;
        }
        out = Progress(next);
        error.clear();
        return ReorgResult::Progress;
    });
}
} // namespace lotus::v2
