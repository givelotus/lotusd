// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license. See COPYING.
#include <net/full_mempool_reconciliation.h>
#include <lotus_v2/tagged_hash.h>
#include <consensus/consensus.h>
#include <core_memusage.h>

#include <algorithm>
#include <stdexcept>

namespace lotus::v2::net::fullrecon {
namespace {
bool Bit(const Hash &id, unsigned bit) {
    return (id[bit / 8] >> (bit % 8)) & 1;
}
Hash Identity(const uint256 &id) {
    Hash out;
    std::copy(id.begin(), id.end(), out.begin());
    return out;
}
Hash Branch(uint16_t depth, const Hash &left, const Hash &right) {
    std::array<uint8_t, 67> bytes{};
    bytes[0] = 1;
    bytes[1] = depth & 255;
    bytes[2] = depth >> 8;
    std::copy(left.begin(), left.end(), bytes.begin() + 3);
    std::copy(right.begin(), right.end(), bytes.begin() + 35);
    return TaggedHash(HashDomain::TxRoot, bytes);
}
bool Less(const Hash &a, const Hash &b) {
    for (unsigned i = 0; i < 256; ++i) {
        if (Bit(a, i) != Bit(b, i)) return !Bit(a, i);
    }
    return false;
}
Descriptor FoldAt(const std::array<Descriptor, 16> &children,
                  uint16_t depth, unsigned bit, unsigned index) {
    if (bit == 4) return children[index];
    const auto left{FoldAt(children, depth, bit + 1, index)};
    const auto right{FoldAt(children, depth, bit + 1, index | (1U << bit))};
    if (right.count > std::numeric_limits<uint64_t>::max() - left.count)
        throw std::ios_base::failure("full-recon count overflow");
    Descriptor out{left.count + right.count, EmptyDigest()};
    if (out.count == 1) out.digest = left.count ? left.digest : right.digest;
    else if (out.count > 1) out.digest = Branch(depth + bit, left.digest, right.digest);
    return out;
}
}

bool Prefix::Valid() const {
    if (depth > 256 || depth % 4) return false;
    for (unsigned i = depth; i < 256; ++i) if (Bit(bytes, i)) return false;
    return true;
}
bool Prefix::Contains(const Hash &id) const {
    if (!Valid()) return false;
    for (unsigned i = 0; i < depth; ++i) if (Bit(bytes, i) != Bit(id, i)) return false;
    return true;
}
Prefix Prefix::Child(unsigned index) const {
    if (!Valid() || depth > 252 || index >= 16)
        throw std::ios_base::failure("invalid full-recon child");
    Prefix out{*this};
    for (unsigned j = 0; j < 4; ++j)
        out.bytes[(depth + j) / 8] |= ((index >> j) & 1) << ((depth + j) % 8);
    out.depth += 4;
    return out;
}
Hash EmptyDigest() {
    static const Hash digest{TaggedHash(HashDomain::TxRoot, std::array<uint8_t, 1>{2})};
    return digest;
}
Hash LeafDigest(const Hash &id, const Hash &hash) {
    std::array<uint8_t, 65> bytes{};
    std::copy(id.begin(), id.end(), bytes.begin() + 1);
    std::copy(hash.begin(), hash.end(), bytes.begin() + 33);
    return TaggedHash(HashDomain::TxRoot, bytes);
}
Descriptor Fold(const std::array<Descriptor, 16> &children, uint16_t depth) {
    if (depth > 252 || depth % 4) throw std::ios_base::failure("invalid fold depth");
    for (const auto &child : children) {
        if (((child.count == 0) != (child.digest == EmptyDigest())) ||
            (depth == 252 && child.count > 1))
            throw std::ios_base::failure("invalid full-recon child descriptor");
    }
    return FoldAt(children, depth, 0, 0);
}

Snapshot::Snapshot(std::vector<CTransactionRef> transactions, size_t maximum_bytes) {
    // Check before reserving. At most two compressed nodes per identity; the
    // charge also accounts for pinned transaction serialization, not just refs.
    constexpr size_t per_item{sizeof(Item) + 2 * sizeof(Node) + sizeof(CTransactionRef)};
    if (transactions.size() > maximum_bytes / per_item ||
        transactions.size() > (uint64_t{Node::NONE} - 1) / 2)
        throw std::length_error("full-recon snapshot byte budget");
    const size_t input_bytes{memusage::DynamicUsage(transactions)};
    const size_t item_bytes{memusage::MallocUsage(transactions.size() * sizeof(Item))};
    const size_t node_bytes{memusage::MallocUsage(transactions.size() * 2 * sizeof(Node))};
    if (sizeof(Snapshot) > maximum_bytes || input_bytes > maximum_bytes - sizeof(Snapshot) ||
        item_bytes > maximum_bytes - sizeof(Snapshot) - input_bytes ||
        node_bytes > maximum_bytes - sizeof(Snapshot) - input_bytes - item_bytes)
        throw std::length_error("full-recon snapshot preallocation budget");
    m_items.reserve(transactions.size());
    m_nodes.reserve(transactions.size() * 2);
    // Include the by-value construction inventory and actual vector capacities.
    // Conservatively retain that temporary charge after construction as well.
    m_charged_bytes = sizeof(Snapshot) + memusage::DynamicUsage(m_items) +
                      memusage::DynamicUsage(m_nodes) +
                      memusage::DynamicUsage(transactions);
    if (m_charged_bytes > maximum_bytes)
        throw std::length_error("full-recon snapshot construction budget");
    for (const auto &tx : transactions) {
        if (!tx || tx->IsNull() || tx->IsCoinBase())
            throw std::invalid_argument("invalid full-recon member");
        const size_t bytes{std::max<size_t>(GetSerializeSize(*tx),
                                          RecursiveDynamicUsage(tx))};
        if (bytes > maximum_bytes - m_charged_bytes)
            throw std::length_error("full-recon pinned body byte budget");
        m_charged_bytes += bytes;
        m_items.push_back({Identity(tx->GetId()), Identity(tx->GetHash()), tx});
    }
    std::sort(m_items.begin(), m_items.end(), [](const Item &a, const Item &b) {
        return Less(a.id, b.id);
    });
    for (size_t i = 1; i < m_items.size(); ++i)
        if (m_items[i - 1].id == m_items[i].id)
            throw std::invalid_argument("duplicate full-recon identity");
    if (!m_items.empty()) Build(0, m_items.size());
}
uint32_t Snapshot::Build(size_t begin, size_t end) {
    const uint32_t index{static_cast<uint32_t>(m_nodes.size())};
    m_nodes.push_back(Node{begin, end});
    if (end - begin == 1) {
        m_nodes[index].digest = LeafDigest(m_items[begin].id, m_items[begin].hash);
        return index;
    }
    unsigned split{0};
    while (Bit(m_items[begin].id, split) == Bit(m_items[end - 1].id, split)) ++split;
    const auto middle{std::partition_point(m_items.begin() + begin,
        m_items.begin() + end, [&](const Item &item) { return !Bit(item.id, split); })};
    const size_t offset{static_cast<size_t>(middle - m_items.begin())};
    const uint32_t left{Build(begin, offset)}, right{Build(offset, end)};
    m_nodes[index].left = left;
    m_nodes[index].right = right;
    m_nodes[index].split = split;
    m_nodes[index].digest = Branch(split, NodeAt(left, split + 1).digest,
                                         NodeAt(right, split + 1).digest);
    return index;
}
Descriptor Snapshot::NodeAt(uint32_t index, uint16_t depth) const {
    const auto &node{m_nodes[index]};
    Descriptor out{node.end - node.begin, node.digest};
    if (out.count == 1) return out;
    for (unsigned d = node.split; d > depth; --d) {
        if (Bit(m_items[node.begin].id, d - 1)) out.digest = Branch(d - 1, EmptyDigest(), out.digest);
        else out.digest = Branch(d - 1, out.digest, EmptyDigest());
    }
    return out;
}
const Snapshot::Node *Snapshot::Find(const Prefix &prefix, uint32_t *out) const {
    if (!prefix.Valid()) throw std::invalid_argument("invalid full-recon prefix");
    if (m_nodes.empty()) return nullptr;
    uint32_t index{0};
    while (true) {
        const auto &node{m_nodes[index]};
        const auto &id{m_items[node.begin].id};
        for (unsigned bit = 0; bit < std::min<unsigned>(prefix.depth, node.split); ++bit)
            if (Bit(prefix.bytes, bit) != Bit(id, bit)) return nullptr;
        if (node.end - node.begin == 1 || prefix.depth <= node.split) {
            if (out) *out = index;
            return &node;
        }
        index = Bit(prefix.bytes, node.split) ? node.right : node.left;
    }
}
Descriptor Snapshot::At(const Prefix &prefix) const {
    uint32_t index{0};
    if (!Find(prefix, &index)) return {0, EmptyDigest()};
    return NodeAt(index, prefix.depth);
}
std::array<Descriptor, 16> Snapshot::Children(const Prefix &prefix) const {
    std::array<Descriptor, 16> out;
    for (unsigned i = 0; i < 16; ++i) out[i] = At(prefix.Child(i));
    return out;
}
std::optional<std::vector<CTransactionRef>> Snapshot::Page(
    const Prefix &prefix, size_t max_bytes) const {
    const auto *node{Find(prefix)};
    std::vector<CTransactionRef> out;
    if (!node) return out;
    if (node->end - node->begin > MAX_PAGE_BODIES) return std::nullopt;
    size_t bytes{0};
    for (size_t i = node->begin; i < node->end; ++i) {
        const size_t next{GetSerializeSize(*m_items[i].tx)};
        if (next > max_bytes - bytes) return std::nullopt;
        bytes += next;
        out.push_back(m_items[i].tx);
    }
    return out;
}
Hash Snapshot::PageDigest(const Prefix &prefix,
                         const std::vector<CTransactionRef> &bodies) {
    for (const auto &tx : bodies)
        if (!tx || !prefix.Contains(Identity(tx->GetId())))
            throw std::invalid_argument("full-recon body outside prefix");
    if (bodies.size() > MAX_PAGE_BODIES)
        throw std::length_error("full-recon page count budget");
    // The transport owns/reserves the already-decoded bodies; this temporary
    // builds only a <=64-member index and cannot reserve from claimed counts.
    Snapshot page{bodies, std::numeric_limits<size_t>::max()};
    return page.At(prefix).digest;
}
} // namespace lotus::v2::net::fullrecon

#include <net.h>
#include <net_processing.h>
#include <net/v2_protocol_handler.h>
#include <netmessagemaker.h>
#include <common/args.h>
#include <logging.h>
#include <random.h>
#include <txmempool.h>
#include <validation.h>
#include <util/time.h>
#include <map>
#include <set>
#include <deque>

namespace lotus::v2::net::fullrecon {
using namespace std::chrono_literals;
namespace {
using Clock = std::chrono::microseconds;
Clock Now() {
    return std::chrono::duration_cast<Clock>(MockableSteadyClock::now().time_since_epoch());
}
template <typename T> T Decode(DataStream &stream) {
    Require(stream.size() <= MAX_FRAME_BYTES);
    T out;
    stream >> out;
    Require(stream.empty());
    return out;
}
struct WorkItem { Prefix prefix; Descriptor remote; bool force_expand{false}; };
constexpr size_t FETCH_FIXED_CHARGE = 512 * 1024;
constexpr size_t PARSE_RESERVATION = 64 * 1024 * 1024;
constexpr auto EXCHANGE_SPACING = 125ms;
constexpr auto IDLE_LEASE = 60s;
constexpr auto ABSOLUTE_LEASE = 30min;
constexpr auto REQUEST_TIMEOUT = 5s;
constexpr auto CAPTURE_SPACING = 30s;
}
namespace {
/** Allocation-free grammar walk before the ordinary transaction decoder. Its
 * bound includes the native decoder's u16 reserves even on a truncated frame,
 * and the nested vector headers hidden behind one-byte empty arguments. */
class ExposureScanner {
    SpanReader reader;
    size_t footprint{0};
    void Add(size_t bytes) {
        if (bytes > std::numeric_limits<size_t>::max() - footprint)
            throw std::length_error("full-recon decode size overflow");
        footprint += bytes;
    }
    void Allocation(uint64_t count, size_t element) {
        if (count > std::numeric_limits<size_t>::max() / element)
            throw std::length_error("full-recon decode allocation overflow");
        Add(memusage::MallocUsage(size_t(count) * element));
    }
    template <typename T> T Read() { T out; reader >> out; return out; }
    uint64_t Count(uint64_t maximum) {
        const auto count{ReadCompactSize(reader)};
        Require(count <= maximum);
        return count;
    }
    void Bytes(uint64_t maximum) {
        const auto count{Count(maximum)};
        Require(count <= reader.size());
        Allocation(count, 1);
        reader.ignore(count);
    }
    void Witness() {
        Bytes(DefaultTxProfile.max_script_bytes);
        const auto siblings{Count(DefaultTxProfile.max_branch_proof_depth)};
        Require(siblings <= reader.size() / 32);
        Allocation(siblings, sizeof(Hash));
        reader.ignore(siblings * 32);
        const auto arguments{Count(DefaultTxProfile.max_arguments)};
        Require(arguments <= reader.size()); // each needs a CompactSize byte
        Allocation(arguments, sizeof(std::vector<uint8_t>));
        for (uint64_t i = 0; i < arguments; ++i)
            Bytes(DefaultTxProfile.max_argument_bytes);
    }
    void Transaction() {
        Add(sizeof(CTransaction) + 128); // shared owner and small allocator slack
        const auto version{Read<uint32_t>()};
        if (version == 1 || version == 2) {
            const auto inputs{Count(reader.size() / 41)};
            Allocation(inputs, sizeof(CTxIn));
            for (uint64_t i = 0; i < inputs; ++i) {
                reader.ignore(36);
                Bytes(MAX_FRAME_BYTES);
                reader.ignore(4);
            }
            const auto outputs{Count(reader.size() / 9)};
            Allocation(outputs, sizeof(CTxOut));
            for (uint64_t i = 0; i < outputs; ++i) {
                reader.ignore(8);
                Bytes(MAX_FRAME_BYTES);
            }
            reader.ignore(4);
            return;
        }
        Require(version == 7);
        reader.ignore(8);
        const auto inputs{Read<uint16_t>()}, outputs{Read<uint16_t>()};
        Require(inputs != 0);
        Allocation(inputs, sizeof(CTxIn));
        Allocation(outputs, sizeof(CTxOut));
        for (uint64_t i = 0; i < inputs; ++i) {
            reader.ignore(40);
            const auto flags{Read<uint8_t>()};
            if (flags == 1) {
                Count(MAX_OUTPUT_PATHS - 1);
                const auto witnesses{Count(MAX_OUTPUT_BRANCHES)};
                Require(witnesses != 0 && witnesses <= reader.size() / 3);
                Allocation(witnesses, sizeof(BranchWitness));
                for (uint64_t j = 0; j < witnesses; ++j) Witness();
            } else if (flags == 2) {
                if (Count(1)) Bytes(8192);
            } else {
                Require(flags == 3);
                Allocation(1, sizeof(BranchWitness));
                Witness();
            }
        }
        for (uint64_t i = 0; i < outputs; ++i) {
            const auto flags{Read<uint8_t>()};
            Require(!(flags & 0xf8) && !((flags & 4) && (flags & 2)));
            reader.ignore(8);
            if (flags & 1) reader.ignore(32);
            if (flags & 4) reader.ignore(32);
            const auto branches{Count(MAX_OUTPUT_BRANCHES)};
            Require(branches != 0 && branches <= reader.size() / 32);
            Allocation(branches, sizeof(Hash));
            reader.ignore(branches * 32);
            const auto paths{Count(MAX_OUTPUT_PATHS)};
            Require(paths <= reader.size());
            Allocation(paths, sizeof(std::vector<uint8_t>));
            for (uint64_t j = 0; j < paths; ++j) {
                const auto length{Count(MAX_OUTPUT_BRANCHES)};
                Require(length != 0 && length <= reader.size());
                Allocation(length, 1);
                for (uint64_t k = 0; k < length; ++k)
                    Count(MAX_OUTPUT_BRANCHES - 1);
            }
        }
    }
public:
    explicit ExposureScanner(Span<const uint8_t> bytes) : reader{bytes} {}
    size_t Page() {
        Reply header;
        uint8_t work, status;
        reader >> header.header >> header.request >> header.prefix >> work >> status;
        header.work = static_cast<Work>(work); header.status = static_cast<Status>(status);
        Require(header.work == Work::PAGE && header.status == Status::OK);
        const auto bodies{Count(MAX_PAGE_BODIES)};
        Allocation(bodies, sizeof(CTransactionRef));
        for (uint64_t i = 0; i < bodies; ++i) Transaction();
        Require(reader.empty());
        // Phase bound: nested data moves from decoded to immutable storage,
        // then ToV2Transaction may duplicate it once during identity hashing.
        // The two vin/vout header arrays can coexist; one current-output
        // conversion and vector capacity growth fit the remaining graph pair.
        // Summing all bodies also retains earlier bodies during the last peak.
        // Eight frame copies cover recorded/serialized wire and capacity
        // growth, full/core InputWire encoding, output-script conversion and
        // commitment leaves; the fixed MiB covers the <=64 verification index.
        constexpr size_t slack{8 * MAX_FRAME_BYTES + 1024 * 1024};
        if (footprint > (std::numeric_limits<size_t>::max() - slack) / 4)
            throw std::length_error("full-recon decode peak overflow");
        return footprint * 4 + slack;
    }
};
}
size_t PageDecodeExposure(Span<const uint8_t> bytes) {
    Require(bytes.size() <= MAX_FRAME_BYTES);
    return ExposureScanner{bytes}.Page();
}

struct Manager::Impl {
    ChainstateManager &chainman;
    CTxMemPool &pool;
    CConnman &connman;
    PeerManager &peerman;
    mutable Mutex mutex;
    Stats stats;
    struct Capture {
        std::shared_ptr<const Snapshot> snapshot;
        // Reset sequence advances on every erase/clear; between resets only
        // inserts can change immutable membership, so exact size completes
        // the version. External notification sequence skips addUnchecked.
        std::pair<uint64_t, size_t> generation{};
        uint256 anchor;
    } cache;
    Clock next_capture{0us};
    struct Serve {
        Header header;
        std::shared_ptr<const Snapshot> snapshot;
        uint256 anchor;
        uint64_t highest_request{0};
        Clock born, progress, next_reply{0us};
    };
    struct Fetch {
        Header header;
        uint256 anchor;
        std::shared_ptr<const Snapshot> local;
        std::vector<WorkItem> deferred;
        std::optional<WorkItem> active;
        std::optional<Request> request;
        uint64_t next_request{1};
        Clock born, progress, deadline{0us}, next_send{0us};
        size_t retries{0};
        std::map<TxId, CTransactionRef> recovered;
        size_t body_charge{0};
        std::vector<CTransactionRef> ordered;
        size_t admission_cursor{0};
        bool admitting{false};
        uint64_t rejected{0};
    };
    struct Peer {
        bool enabled{false};
        std::optional<Serve> serve;
        std::optional<Fetch> fetch;
        Clock next_offer{0us};
        size_t queued_charge{0};
        std::optional<Offer> pending_control;
        uint256 last_remote_context;
    };
    std::map<int64_t, Peer> peers;
    explicit Impl(ChainstateManager &c, CTxMemPool &p, CConnman &n, PeerManager &pm)
        : chainman(c), pool(p), connman(n), peerman(pm) {}
    size_t Budget() const {
        return static_cast<size_t>(std::clamp<int64_t>(
            gArgs.GetIntArg("-txreconmaxmemory", 256), 128, 4096)) * 1024 * 1024;
    }
    size_t Used(size_t *captures = nullptr) const {
        std::set<const Snapshot *> unique;
        size_t used{memusage::DynamicUsage(peers)};
        if (cache.snapshot) unique.insert(cache.snapshot.get());
        for (const auto &[_, peer] : peers) {
            if (peer.serve) unique.insert(peer.serve->snapshot.get());
            if (peer.fetch) {
                unique.insert(peer.fetch->local.get());
                used += FETCH_FIXED_CHARGE + peer.fetch->body_charge;
            }
            used += peer.queued_charge;
        }
        for (const auto *snapshot : unique) used += snapshot->ChargedBytes();
        if (captures) *captures = unique.size();
        return used;
    }
    bool Fits(size_t bytes) const {
        const auto used{Used()}, budget{Budget()};
        return used <= budget && bytes <= budget - used;
    }
    void QueueDrained(CNode &node, Peer &peer) {
        if (WITH_LOCK(node.cs_vSend, return node.nSendSize == 0)) peer.queued_charge = 0;
    }
    template <typename T> bool Send(CNode &node, Peer &peer,
                                    const std::string &command, const T &message) {
        if (node.fDisconnect || node.fPauseSend) return false;
        QueueDrained(node, peer);
        const auto bytes{GetSerializeSize(message)};
        if (bytes > MAX_FRAME_BYTES || !Fits(bytes + 64)) { ++stats.busy; return false; }
        connman.PushMessage(&node, NetMsg::Make(command, message));
        peer.queued_charge += bytes + 64;
        return true;
    }
    uint256 Anchor() const {
        LOCK(cs_main);
        const auto *tip{chainman.ActiveTip()};
        return tip ? uint256{tip->GetBlockHash()} : uint256{};
    }
    std::shared_ptr<const Snapshot> CapturePool(Clock now) {
        const auto anchor{Anchor()};
        const auto current_generation{WITH_LOCK(pool.cs, return (std::pair{
            pool.GetSnapshotResetSequence(), pool.mapTx.size()}))};
        if (cache.snapshot && cache.anchor == anchor &&
            cache.generation == current_generation) return cache.snapshot;
        if (now < next_capture) return cache.anchor == anchor ? cache.snapshot : nullptr;
        // A stale cache must not reserve its own replacement budget forever.
        // Active serving/fetching owners retain their immutable shared view;
        // a cache-only view can be freed before constructing the next one.
        cache.snapshot.reset();
        size_t captures{0};
        const size_t used{Used(&captures)}, budget{Budget()};
        if (used >= budget || captures >= 4 ||
            PARSE_RESERVATION + FETCH_FIXED_CHARGE > budget - used) {
            ++stats.busy; return nullptr;
        }
        const size_t available{budget - used - PARSE_RESERVATION - FETCH_FIXED_CHARGE};
        // A failed allocation/build must not turn peer ticks into O(N) retries.
        next_capture = now + CAPTURE_SPACING;
        size_t count{0};
        {
            LOCK(pool.cs);
            count = pool.mapTx.size();
            // Conservative reservation before copying any references. The
            // mempool's usage includes bodies and its own (unretained) indexes.
            if (count > available / 512 || pool.DynamicMemoryUsage() > available - count * 512) {
                ++stats.busy;
                return nullptr;
            }
        }
        std::vector<CTransactionRef> transactions;
        transactions.reserve(count); // never allocate inventory while locked
        std::pair<uint64_t, size_t> generation{};
        uint256 captured_anchor;
        const auto lock_started{Now()};
        Clock lock_acquired;
        {
            LOCK2(cs_main, pool.cs);
            lock_acquired = Now();
            if (pool.mapTx.size() > transactions.capacity() ||
                pool.mapTx.size() > available / 512 ||
                pool.DynamicMemoryUsage() > available - pool.mapTx.size() * 512)
                return nullptr;
            const auto *tip{chainman.ActiveTip()};
            if (!tip) return nullptr;
            captured_anchor = tip->GetBlockHash();
            generation = {pool.GetSnapshotResetSequence(), pool.mapTx.size()};
            for (const auto &entry : pool.mapTx) transactions.push_back(entry->GetSharedTx());
        }
        const auto copied{Now()};
        auto snapshot{std::make_shared<const Snapshot>(std::move(transactions), available)};
        if (Anchor() != captured_anchor) return nullptr;
        cache = {snapshot, generation, captured_anchor};
        next_capture = now + CAPTURE_SPACING;
        ++stats.captures;
        stats.captured_members += snapshot->Size();
        stats.capture_lock_wait_us += (lock_acquired - lock_started).count();
        stats.capture_lock_us += (copied - lock_acquired).count();
        stats.capture_build_us += (Now() - copied).count();
        LogEvent(BCLog::TXRELAY, "fullrecon_capture", "captured complete mempool count={count} bytes={bytes}")
            .Field(BCLog::LogField::Count, snapshot->Size())
            .Field(BCLog::LogField::Bytes, snapshot->ChargedBytes())
            .Field(BCLog::LogField::DurationUs, copied - lock_acquired);
        return snapshot;
    }
    void ControlFrame(CNode &node, Peer &peer, const Header &header, Control control) {
        Offer out;
        out.header = header;
        out.control = control;
        if (!Send(node, peer, NetMsgType::MERKLIXSYNC, out)) {
            // Preserve an owned completion under backpressure. Rejected offers'
            // CANCEL is best-effort; their bounded serving lease is the fallback.
            if (!peer.pending_control || control == Control::DONE)
                peer.pending_control = out;
        }
    }
    void Cancel(CNode &node, Peer &peer, const Header &header) noexcept {
        // Ownership is retired by the caller first. Notification is best-effort
        // and may never make resource release depend on another allocation.
        try { ControlFrame(node, peer, header, Control::CANCEL); }
        catch (...) {}
    }
    void Push(Fetch &fetch, WorkItem item) {
        const auto local{fetch.local->At(item.prefix)};
        if (item.remote.digest == local.digest) {
            Require(item.remote.count == local.count);
            return;
        }
        if (item.remote.digest == EmptyDigest()) return;
        if (fetch.deferred.size() >= MAX_DEFERRED_PREFIXES)
            throw std::ios_base::failure("full-recon traversal budget");
        fetch.deferred.push_back(std::move(item));
    }
    void Children(Fetch &fetch, const Prefix &parent,
                  const std::array<Descriptor, 16> &children) {
        std::array<WorkItem, 16> next;
        size_t count{0};
        for (unsigned i = 16; i-- > 0;) {
            WorkItem item{parent.Child(i), children[i]};
            const auto local{fetch.local->At(item.prefix)};
            if (item.remote.digest == local.digest) {
                Require(item.remote.count == local.count);
                continue;
            }
            if (item.remote.digest == EmptyDigest()) continue;
            next[count++] = item;
        }
        if (count > MAX_DEFERRED_PREFIXES - fetch.deferred.size())
            throw std::ios_base::failure("full-recon traversal budget");
        // All checks precede the nonallocating append to the reserved DFS stack.
        fetch.deferred.insert(fetch.deferred.end(), next.begin(), next.begin() + count);
    }
    void Topological(Fetch &fetch) {
        // One Kahn traversal for the recovered set, never a repeated page scan.
        std::map<TxId, size_t> index;
        std::vector<CTransactionRef> bodies;
        bodies.reserve(fetch.recovered.size());
        for (const auto &[id, body] : fetch.recovered) {
            index.emplace(id, bodies.size());
            bodies.push_back(body);
        }
        std::vector<size_t> degree(bodies.size(), 0);
        std::vector<std::pair<size_t, size_t>> edges;
        for (size_t child = 0; child < bodies.size(); ++child)
            for (const auto &input : bodies[child]->vin)
                if (const auto it = index.find(input.prevout.GetTxId()); it != index.end()) {
                    ++degree[child];
                    edges.emplace_back(it->second, child);
                }
        std::sort(edges.begin(), edges.end());
        std::deque<size_t> ready;
        for (size_t i = 0; i < degree.size(); ++i) if (!degree[i]) ready.push_back(i);
        fetch.ordered.reserve(bodies.size());
        while (!ready.empty()) {
            const auto parent{ready.front()}; ready.pop_front();
            fetch.ordered.push_back(bodies[parent]);
            auto it{std::lower_bound(edges.begin(), edges.end(), std::pair{parent, size_t{0}})};
            while (it != edges.end() && it->first == parent) {
                if (--degree[it->second] == 0) ready.push_back(it->second);
                ++it;
            }
        }
        if (fetch.ordered.size() != bodies.size())
            throw std::ios_base::failure("cyclic full-recon recovered dependencies");
        fetch.admitting = true;
    }
    void StartOffer(CNode &node, Peer &peer, Clock now) {
        auto snapshot{CapturePool(now)};
        if (!snapshot) return;
        Offer offer;
        offer.header.context = GetRandHash();
        offer.anchor = cache.anchor;
        offer.root = snapshot->Root();
        offer.children = snapshot->Children(Prefix{});
        // Register ownership only after successful serialization/enqueue.
        if (!Send(node, peer, NetMsgType::MERKLIXSYNC, offer)) return;
        peer.serve.emplace(Serve{offer.header, snapshot, offer.anchor, 0, now, now});
        peer.next_offer = now + CAPTURE_SPACING;
        ++stats.offers;
    }
    void OnOffer(CNode &node, Peer &peer, Offer offer, Clock now) {
        if (offer.control != Control::OFFER) {
            if (peer.serve && peer.serve->header.context == offer.header.context) peer.serve.reset();
            if (offer.control == Control::CANCEL && peer.fetch &&
                peer.fetch->header.context == offer.header.context) peer.fetch.reset();
            return;
        }
        if (peer.last_remote_context == offer.header.context) return; // replay cannot restart work
        if (peer.fetch || node.fPauseSend || !Fits(FETCH_FIXED_CHARGE)) {
            ControlFrame(node, peer, offer.header, Control::CANCEL);
            ++stats.busy;
            return;
        }
        auto local{CapturePool(now)};
        if (!local || !Fits(FETCH_FIXED_CHARGE)) {
            ControlFrame(node, peer, offer.header, Control::CANCEL);
            ++stats.busy;
            return;
        }
        Fetch fetch;
        fetch.header = offer.header;
        fetch.anchor = offer.anchor;
        fetch.local = std::move(local);
        fetch.born = fetch.progress = now;
        fetch.deferred.reserve(MAX_DEFERRED_PREFIXES);
        Children(fetch, Prefix{}, offer.children);
        peer.last_remote_context = offer.header.context;
        peer.fetch.emplace(std::move(fetch));
    }
    void OnRequest(CNode &node, Peer &peer, const Request &request, Clock now) {
        Reply reply;
        reply.header = request.header;
        reply.request = request.request;
        reply.prefix = request.prefix;
        reply.work = request.work;
        if (!peer.serve || peer.serve->header.context != request.header.context) reply.status = Status::GONE;
        else if (request.request <= peer.serve->highest_request) return;
        else if (now < peer.serve->next_reply) reply.status = Status::BUSY;
        else {
            auto &serve{*peer.serve};
            serve.highest_request = request.request;
            serve.next_reply = now + EXCHANGE_SPACING;
            if (request.work == Work::EXPAND) {
                if (request.prefix.depth >= 256) reply.status = Status::UNAVAILABLE;
                else reply.children = serve.snapshot->Children(request.prefix);
            } else {
                auto page{serve.snapshot->Page(request.prefix, MAX_FRAME_BYTES - 256)};
                if (!page) reply.status = request.prefix.depth == 256 ? Status::UNAVAILABLE : Status::LIMIT;
                else reply.bodies = std::move(*page);
                if (reply.status == Status::OK && GetSerializeSize(reply) > MAX_FRAME_BYTES) {
                    reply.bodies.clear();
                    reply.status = request.prefix.depth == 256 ? Status::UNAVAILABLE : Status::LIMIT;
                }
            }
            serve.progress = now;
        }
        if (Send(node, peer, NetMsgType::MERKLIXBUCK, reply)) ++stats.replies;
    }
    void OnReply(CNode &node, Peer &peer, const Reply &reply, Clock now) {
        if (!peer.fetch || !peer.fetch->request || !peer.fetch->active) return;
        auto &fetch{*peer.fetch};
        const auto &request{*fetch.request};
        Require(reply.header.context == fetch.header.context && reply.request == request.request &&
                reply.prefix == request.prefix && reply.work == request.work);
        if (reply.status == Status::BUSY) {
            fetch.request.reset();
            fetch.next_send = now + EXCHANGE_SPACING;
            return;
        }
        if (reply.status == Status::LIMIT && reply.work == Work::PAGE && reply.prefix.depth < 256) {
            fetch.active->force_expand = true;
            fetch.request.reset();
            fetch.next_send = now + EXCHANGE_SPACING;
            return;
        }
        if (reply.status != Status::OK) {
            ++stats.unresolved;
            const Header header{fetch.header};
            peer.fetch.reset();
            Cancel(node, peer, header);
            return;
        }
        const auto expected{fetch.active->remote};
        if (reply.work == Work::EXPAND) {
            const auto actual{Fold(reply.children, reply.prefix.depth)};
            Require(actual.digest == expected.digest && actual.count == expected.count);
            Children(fetch, reply.prefix, reply.children);
        } else {
            Require(reply.bodies.size() == expected.count &&
                    Snapshot::PageDigest(reply.prefix, reply.bodies) == expected.digest);
            size_t extra{0};
            for (const auto &body : reply.bodies) {
                if (fetch.recovered.contains(body->GetId()))
                    throw std::ios_base::failure("duplicate full-recon recovered member");
                const size_t charge{RecursiveDynamicUsage(body)};
                if (charge > (std::numeric_limits<size_t>::max() - 256) / 2 ||
                    extra > std::numeric_limits<size_t>::max() - (charge * 2 + 256))
                    throw std::length_error("full-recon body charge overflow");
                extra += charge * 2 + 256; // bodies plus topo/capacity scratch
            }
            if (extra > std::numeric_limits<size_t>::max() - PARSE_RESERVATION ||
                !Fits(extra + PARSE_RESERVATION))
                throw std::length_error("full-recon recovery body budget");
            std::map<TxId, CTransactionRef> additions;
            for (const auto &body : reply.bodies) additions.emplace(body->GetId(), body);
            // Allocate transactionally, then transfer nodes without allocation.
            // Failure cannot leave retained bodies outside the exposure charge.
            fetch.recovered.merge(additions);
            fetch.body_charge += extra;
            stats.verified_bodies += reply.bodies.size();
        }
        fetch.progress = now;
        fetch.request.reset();
        fetch.active.reset();
        fetch.retries = 0;
        fetch.next_send = now + EXCHANGE_SPACING;
    }
    void Tick(CNode &node, Peer &peer, Clock now) {
        QueueDrained(node, peer);
        if (peer.pending_control &&
            Send(node, peer, NetMsgType::MERKLIXSYNC, *peer.pending_control))
            peer.pending_control.reset();
        // Anchor is diagnostic/domain metadata, not an epoch authority. Chain
        // changes never mutate or cancel an immutable transport snapshot;
        // recovered bodies still face current normal admission.
        if (peer.serve && (now - peer.serve->progress > IDLE_LEASE ||
                           now - peer.serve->born > ABSOLUTE_LEASE)) {
            const Header header{peer.serve->header};
            peer.serve.reset(); ++stats.expired;
            Cancel(node, peer, header);
        }
        if (peer.fetch && (now - peer.fetch->progress > IDLE_LEASE ||
                           now - peer.fetch->born > ABSOLUTE_LEASE)) {
            const Header header{peer.fetch->header};
            peer.fetch.reset(); ++stats.expired;
            Cancel(node, peer, header);
        }
        if (!peer.serve && now >= peer.next_offer && !node.fPauseSend) StartOffer(node, peer, now);
        if (!peer.fetch || node.fPauseSend || node.fDisconnect) return;
        auto &fetch{*peer.fetch};
        if (fetch.admitting) {
            if (fetch.ordered.empty()) { peer.fetch.reset(); return; }
            const size_t end{std::min(fetch.admission_cursor + MAX_PAGE_BODIES, fetch.ordered.size())};
            std::array<CTransactionRef, MAX_PAGE_BODIES> pending;
            size_t pending_count{0};
            for (size_t i{fetch.admission_cursor}; i < end; ++i) {
                const auto &body{fetch.ordered[i]};
                const auto actual{pool.get(body->GetId())};
                // Membership coverage still authenticates every remote body.
                // Only exact bodies already admitted need no repeat validation;
                // a matching TxId with different bytes must use the normal path.
                if (actual && actual->GetHash() == body->GetHash()) ++stats.admitted;
                else pending[pending_count++] = body;
            }
            const std::span<const CTransactionRef> batch{pending.data(), pending_count};
            if (!batch.empty()) peerman.ProcessShortTxResponse(node, batch);
            for (const auto &body : batch) {
                const auto actual{pool.get(body->GetId())};
                if (actual && actual->GetHash() == body->GetHash()) ++stats.admitted;
                else { ++fetch.rejected; ++stats.unresolved; }
            }
            fetch.admission_cursor = end;
            fetch.progress = now;
            if (end == fetch.ordered.size()) {
                LogEvent(BCLog::TXRELAY, "fullrecon_admission_finished", "full reconciliation admission peer={peer_id} unresolved={count}")
                    .Field(BCLog::LogField::PeerId, node.GetId())
                    .Field(BCLog::LogField::Count, fetch.rejected);
                peer.fetch.reset();
            }
            return;
        }
        if (fetch.request) {
            if (now < fetch.deadline) return;
            fetch.request.reset();
            if (++fetch.retries > 3) {
                const Header header{fetch.header};
                peer.fetch.reset(); ++stats.unresolved;
                Cancel(node, peer, header);
                return;
            }
        }
        if (now < fetch.next_send) return;
        if (!fetch.active && !fetch.deferred.empty()) {
            fetch.active = fetch.deferred.back();
            fetch.deferred.pop_back();
        }
        if (!fetch.active) {
            Topological(fetch);
            ++stats.coverage_complete;
            ControlFrame(node, peer, fetch.header, Control::DONE);
            LogEvent(BCLog::TXRELAY, "fullrecon_coverage_complete", "verified remote snapshot peer={peer_id} bodies={count}")
                .Field(BCLog::LogField::PeerId, node.GetId())
                .Field(BCLog::LogField::Count, fetch.recovered.size());
            return;
        }
        Request request;
        request.header = fetch.header;
        if (fetch.next_request == std::numeric_limits<uint64_t>::max())
            throw std::ios_base::failure("full-recon request sequence exhausted");
        request.request = fetch.next_request++;
        request.prefix = fetch.active->prefix;
        request.work = (!fetch.active->force_expand && fetch.active->remote.count <= MAX_PAGE_BODIES)
            ? Work::PAGE : Work::EXPAND;
        if (Send(node, peer, NetMsgType::GETMERKLIXBUCK, request)) {
            fetch.request = request;
            fetch.deadline = now + REQUEST_TIMEOUT;
            fetch.next_send = now + EXCHANGE_SPACING;
            ++stats.requests;
        }
    }
};

Manager::Manager(ChainstateManager &chainman, CTxMemPool &pool, CConnman &connman, PeerManager &peerman)
    : m_impl{std::make_unique<Impl>(chainman, pool, connman, peerman)} {}
Manager::~Manager() = default;
void Manager::SetPeer(int64_t peer, bool enabled) {
    LOCK(m_impl->mutex);
    if (enabled) m_impl->peers[peer].enabled = true;
    else if (const auto it = m_impl->peers.find(peer); it != m_impl->peers.end()) {
        // Renegotiation cannot release bytes already owned by CNode's queue.
        // Only actual drain or connection teardown retires their exposure.
        it->second.enabled = false;
        it->second.serve.reset();
        it->second.fetch.reset();
        it->second.pending_control.reset();
    }
    if (std::none_of(m_impl->peers.begin(), m_impl->peers.end(),
                     [](const auto &entry) { return entry.second.enabled; }))
        m_impl->cache.snapshot.reset();
}
void Manager::RemovePeer(int64_t peer) {
    LOCK(m_impl->mutex);
    m_impl->peers.erase(peer);
    if (m_impl->peers.empty()) m_impl->cache.snapshot.reset();
}
std::optional<Clock> Manager::Tick(CNode &node, Clock now) {
    LOCK(m_impl->mutex);
    const auto it{m_impl->peers.find(node.GetId())};
    if (it == m_impl->peers.end()) return std::nullopt;
    m_impl->QueueDrained(node, it->second);
    if (!it->second.enabled) return std::nullopt;
    try { m_impl->Tick(node, it->second, now); }
    catch (const std::exception &) {
        ++m_impl->stats.unresolved;
        it->second.fetch.reset();
        it->second.serve.reset();
        it->second.next_offer = now + 1s;
    }
    const auto &fetch{it->second.fetch};
    if (!fetch || node.fPauseSend || node.fDisconnect) return std::nullopt;
    // A bounded admission slice must yield to other peers, but need not wait
    // for the message handler's otherwise idle 100ms receive heartbeat.
    if (fetch->admitting) return now;
    if (fetch->request) return fetch->deadline;
    return std::max(now, fetch->next_send);
}
bool Manager::Handle(CNode &node, const std::string &command, DataStream &stream, Clock time_received) {
    if (command != NetMsgType::MERKLIXSYNC && command != NetMsgType::GETMERKLIXBUCK &&
        command != NetMsgType::MERKLIXBUCK) return false;
    if (stream.empty() || uint8_t(*stream.begin()) != SCOPE) return false;
    LOCK(m_impl->mutex);
    const auto it{m_impl->peers.find(node.GetId())};
    if (it == m_impl->peers.end() || !it->second.enabled) return true;
    if (!m_impl->peerman.GetV2ProtocolHandler()->CheckPeerRateLimit(node.GetId(), time_received)) return true;
    if (stream.size() > MAX_FRAME_BYTES) { ++m_impl->stats.malformed; return true; }
    try {
        // Parse only fixed ownership metadata before permitting body allocation.
        // SpanReader borrows the incoming bytes without another frame copy.
        if (command == NetMsgType::MERKLIXBUCK) {
            SpanReader preview{Span<const uint8_t>{UCharCast(stream.data()), stream.size()}};
            Reply header;
            uint8_t work, status;
            preview >> header.header >> header.request >> header.prefix >> work >> status;
            header.work = static_cast<Work>(work); header.status = static_cast<Status>(status);
            const auto &fetch{it->second.fetch};
            if (!fetch || !fetch->request || !fetch->active ||
                header.header.context != fetch->header.context ||
                header.request != fetch->request->request ||
                header.prefix != fetch->request->prefix || header.work != fetch->request->work)
                return true;
            if (header.work == Work::PAGE && header.status == Status::OK &&
                !m_impl->Fits(PageDecodeExposure(Span<const uint8_t>{UCharCast(stream.data()), stream.size()})))
                throw std::length_error("full-recon decode exposure budget");
        }
        const auto now{Now()};
        if (command == NetMsgType::MERKLIXSYNC) m_impl->OnOffer(node, it->second, Decode<Offer>(stream), now);
        else if (command == NetMsgType::GETMERKLIXBUCK) m_impl->OnRequest(node, it->second, Decode<Request>(stream), now);
        else m_impl->OnReply(node, it->second, Decode<Reply>(stream), now);
    } catch (const std::length_error &) {
        ++m_impl->stats.busy;
        if (it->second.fetch) {
            const Header header{it->second.fetch->header};
            it->second.fetch.reset();
            m_impl->Cancel(node, it->second, header);
        }
    } catch (const std::exception &) {
        ++m_impl->stats.malformed;
        // Parsing/verification never consumes a valid pending request. A real
        // timeout retries it with a fresh ID; invalid frames do not renew leases.
    }
    return true;
}
Stats Manager::GetStats() const {
    LOCK(m_impl->mutex);
    auto stats{m_impl->stats};
    stats.charged_bytes = m_impl->Used();
    return stats;
}
} // namespace lotus::v2::net::fullrecon
