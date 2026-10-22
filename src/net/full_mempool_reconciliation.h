// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license. See COPYING.
#ifndef BITCOIN_NET_FULL_MEMPOOL_RECONCILIATION_H
#define BITCOIN_NET_FULL_MEMPOOL_RECONCILIATION_H

#include <lotus_v2/commitment.h>
#include <primitives/transaction.h>
#include <blockencodings.h>
#include <streams.h>
#include <chrono>
#include <string>
#include <serialize.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <ios>
#include <span>
#include <vector>

class CNode;
class CConnman;
class CTxMemPool;
class PeerManager;
class ChainstateManager;

namespace lotus::v2::net::fullrecon {
inline constexpr uint8_t SCOPE = 5;
inline constexpr uint64_t CAPABILITY = uint64_t{1} << 3;
inline constexpr size_t MAX_PAGE_BODIES = 64;
inline constexpr size_t MAX_FRAME_BYTES = 2 * 1024 * 1024;
inline constexpr size_t MAX_DEFERRED_PREFIXES = 64 * 15 + 1;

struct Prefix {
    uint16_t depth{0};
    Hash bytes{};
    bool Valid() const;
    bool Contains(const Hash &id) const;
    Prefix Child(unsigned index) const;
    friend bool operator==(const Prefix &, const Prefix &) = default;
    SERIALIZE_METHODS(Prefix, obj) {
        READWRITE(obj.depth, obj.bytes);
        if (!obj.Valid()) throw std::ios_base::failure("invalid full-recon prefix");
    }
};
struct Descriptor {
    uint64_t count{0}; // Scheduling hint; only digest equality authenticates data.
    Hash digest{};
    SERIALIZE_METHODS(Descriptor, obj) { READWRITE(obj.count, obj.digest); }
};
Hash EmptyDigest();
Hash LeafDigest(const Hash &id, const Hash &hash);
Descriptor Fold(const std::array<Descriptor, 16> &children, uint16_t depth);

/** Immutable complete membership captured once; no admission-time cutoff.
 * A compressed binary trie stores only real branch points and leaves. Unary
 * depth tags are folded without allocating nodes, including adversarial long
 * common prefixes. All bodies are shared immutable transaction references.
 */
class Snapshot {
public:
    explicit Snapshot(std::vector<CTransactionRef> transactions,
                      size_t maximum_bytes);
    Descriptor Root() const { return At(Prefix{}); }
    Descriptor At(const Prefix &prefix) const;
    std::array<Descriptor, 16> Children(const Prefix &prefix) const;
    /** Empty optional means the complete prefix exceeds count/byte bounds.
     * An empty vector is a complete empty prefix. Never returns a partial page.
     */
    std::optional<std::vector<CTransactionRef>> Page(
        const Prefix &prefix, size_t max_bytes) const;
    size_t ChargedBytes() const { return m_charged_bytes; }
    size_t Size() const { return m_items.size(); }
    /** Authenticate a whole body page at its original canonical prefix depth. */
    static Hash PageDigest(const Prefix &prefix,
                           const std::vector<CTransactionRef> &bodies);
private:
    // Narrow test fixture exercises adversarial canonical identities without
    // grinding transaction hashes; production captures always derive both IDs.
    friend struct SnapshotIdentityFixture;
    struct Item { Hash id, hash; CTransactionRef tx; };
    struct Node {
        size_t begin, end;
        uint32_t left{NONE}, right{NONE};
        uint16_t split{256};
        Hash digest{}; // Digest at split, before any compressed unary path.
        static constexpr uint32_t NONE = std::numeric_limits<uint32_t>::max();
    };
    std::vector<Item> m_items;
    std::vector<Node> m_nodes;
    size_t m_charged_bytes{0};
    uint32_t Build(size_t begin, size_t end);
    Descriptor NodeAt(uint32_t node, uint16_t depth) const;
    const Node *Find(const Prefix &prefix, uint32_t *index = nullptr) const;
};

inline void Require(bool ok) {
    if (!ok) throw std::ios_base::failure("invalid full-mempool reconciliation frame");
}
struct EnumByteFormatter {
    template <typename Stream, typename E> void Ser(Stream &stream, const E &value) const {
        ::Serialize(stream, static_cast<uint8_t>(value));
    }
    template <typename Stream, typename E> void Unser(Stream &stream, E &value) const {
        uint8_t byte; ::Unserialize(stream, byte); value = static_cast<E>(byte);
    }
};
enum class Control : uint8_t { OFFER = 0, DONE = 1, CANCEL = 2 };
enum class Work : uint8_t { EXPAND = 0, PAGE = 1 };
enum class Status : uint8_t { OK = 0, LIMIT = 1, GONE = 2, BUSY = 3, UNAVAILABLE = 4 };
struct Header {
    uint8_t scope{SCOPE}, version{1};
    uint256 context{};
    SERIALIZE_METHODS(Header, obj) {
        READWRITE(obj.scope, obj.version);
        Require(obj.scope == SCOPE && obj.version == 1);
        READWRITE(obj.context);
        Require(!obj.context.IsNull());
    }
};
struct Offer {
    Header header;
    Control control{Control::OFFER};
    uint256 anchor{};
    Descriptor root;
    std::array<Descriptor, 16> children;
    SERIALIZE_METHODS(Offer, obj) {
        READWRITE(obj.header, Using<EnumByteFormatter>(obj.control));
        Require(uint8_t(obj.control) <= uint8_t(Control::CANCEL));
        if (obj.control == Control::OFFER) {
            READWRITE(obj.anchor, obj.root);
            for (auto &child : obj.children) READWRITE(child);
            const auto actual{Fold(obj.children, 0)};
            Require(actual.digest == obj.root.digest && actual.count == obj.root.count);
        }
    }
};
struct Request {
    Header header;
    uint64_t request{0};
    Prefix prefix;
    Work work{Work::EXPAND};
    SERIALIZE_METHODS(Request, obj) {
        READWRITE(obj.header, obj.request, obj.prefix, Using<EnumByteFormatter>(obj.work));
        Require(obj.request != 0 && uint8_t(obj.work) <= uint8_t(Work::PAGE));
    }
};
struct Reply {
    Header header;
    uint64_t request{0};
    Prefix prefix;
    Work work{Work::EXPAND};
    Status status{Status::OK};
    std::array<Descriptor, 16> children;
    std::vector<CTransactionRef> bodies;
    SERIALIZE_METHODS(Reply, obj) {
        READWRITE(obj.header, obj.request, obj.prefix, Using<EnumByteFormatter>(obj.work), Using<EnumByteFormatter>(obj.status));
        Require(obj.request != 0 && uint8_t(obj.work) <= uint8_t(Work::PAGE) &&
                uint8_t(obj.status) <= uint8_t(Status::UNAVAILABLE));
        if (obj.status != Status::OK) return;
        if (obj.work == Work::EXPAND) {
            Require(obj.prefix.depth <= 252);
            for (auto &child : obj.children) READWRITE(child);
        } else {
            uint64_t count{obj.bodies.size()};
            if constexpr (ser_action.ForRead()) count = ReadCompactSize(s);
            Require(count <= MAX_PAGE_BODIES);
            if constexpr (ser_action.ForRead()) obj.bodies.resize(count);
            else WriteCompactSize(s, count);
            for (auto &tx : obj.bodies) {
                READWRITE(Using<TransactionCompression>(tx));
                Require(bool(tx));
            }
        }
    }
};
/** Allocation-free structural preflight; conservative decoder peak bytes. */
size_t PageDecodeExposure(Span<const uint8_t> bytes);

struct Stats {
    uint64_t captures{0}, captured_members{0}, capture_lock_us{0}, capture_lock_wait_us{0}, capture_build_us{0};
    uint64_t offers{0}, requests{0}, replies{0}, verified_bodies{0}, coverage_complete{0};
    uint64_t admitted{0}, unresolved{0}, malformed{0}, busy{0}, expired{0};
    size_t charged_bytes{0};
};
/** Connection-owned derived snapshots only; never primary mempool state. */
class Manager {
public:
    Manager(ChainstateManager &, CTxMemPool &, CConnman &, PeerManager &);
    ~Manager();
    void SetPeer(int64_t peer, bool enabled);
    void RemovePeer(int64_t peer);
    /** Earliest useful continuation, without changing wire pacing or work bounds. */
    std::optional<std::chrono::microseconds> Tick(CNode &, std::chrono::microseconds now);
    bool Handle(CNode &, const std::string &, DataStream &,
                std::chrono::microseconds now);
    Stats GetStats() const;
private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
} // namespace lotus::v2::net::fullrecon
#endif
