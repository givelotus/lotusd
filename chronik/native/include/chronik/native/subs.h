// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_SUBS_H
#define CHRONIK_NATIVE_SUBS_H

#include <chronik/native/token/structs.h>
#include <chronik/native/types.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

/**
 * Subscription hub: port of chronik-indexer subs.rs and subs_group.rs.
 *
 * Rust uses tokio::sync::broadcast channels. They are ported here as
 * BroadcastSender / BroadcastReceiver with exactly the semantics Chronik
 * observes:
 *  - the capacity is rounded up to a power of two (tokio does this; the
 *    Chronik capacities 16 / 32 / 16 already are);
 *  - a receiver only sees messages sent after it subscribed;
 *  - Send() fails (returns false, message dropped) iff there is no receiver;
 *  - each receiver retains at most `capacity` unread messages. Overflow drops
 *    the OLDEST message; the next receive then reports Lagged(n) once (n =
 *    number of dropped messages) and continues with the oldest retained
 *    message. ws.rs maps Lagged to WsAction::Nothing, i.e. it is ignored;
 *  - after the sender is destroyed, receivers drain their queue and then
 *    report Closed.
 *
 * The overflow is per receiver, so one slow WS session never affects
 * another, and the writer never blocks (design §6.3).
 *
 * Threading: the message queues are internally synchronized; a receiver may
 * be used (by one thread at a time) concurrently with sends. Subs itself is
 * NOT synchronized (as in Rust, where it lives in a tokio RwLock); use
 * SubsHub, whose Write() guard is the port of `indexer.subs().write()`.
 * Wakers (see BroadcastReceiver::SetWaker) are invoked without any channel or
 * hub lock held: SubsHub defers them until its guard is released.
 */
namespace chronik::native {

/** Height type used by Chronik (chronik-db io::BlockHeight = i32). */
using SubsBlockHeight = int32_t;

/** Callback invoked when a receiver got a new message or was closed. */
using Waker = std::function<void()>;
using WakerList = std::vector<std::shared_ptr<const Waker>>;

/** Same type as store.h's Sha256Fn: raw SHA-256 digest of `data`. */
using Sha256Fn = std::function<void(ByteView data, uint8_t out[32])>;

/** Invoke and clear deferred wakers. */
inline void InvokeWakers(WakerList &wakers) {
    WakerList local;
    local.swap(wakers);
    for (const auto &w : local) {
        if (w && *w) {
            (*w)();
        }
    }
}

// ---------------------------------------------------------------------------
// Broadcast channel (tokio::sync::broadcast port)
// ---------------------------------------------------------------------------

/** Outcome of BroadcastReceiver::TryRecv / RecvFor. */
enum class RecvStatus : uint8_t {
    /** `msg` holds the next message. */
    Message,
    /** No message queued (tokio TryRecvError::Empty / timeout). */
    Empty,
    /** Messages were dropped by overflow; `lagged` is their number. */
    Lagged,
    /** Sender gone and queue drained (tokio RecvError::Closed). */
    Closed,
};

template <typename T> struct RecvResult {
    RecvStatus status = RecvStatus::Empty;
    std::optional<T> msg;
    uint64_t lagged = 0;
};

template <typename T> class BroadcastSender;

namespace detail {

template <typename T> struct BroadcastSlot {
    std::deque<T> queue;
    uint64_t lagged = 0;
    std::shared_ptr<const Waker> waker;
};

template <typename T> struct BroadcastShared {
    explicit BroadcastShared(size_t cap) : capacity(cap) {}
    mutable std::mutex mu;
    std::condition_variable cv;
    const size_t capacity;
    std::vector<BroadcastSlot<T> *> slots;
    bool closed = false;
};

} // namespace detail

/** Port of tokio broadcast::Receiver. Move-only; unsubscribes on destroy. */
template <typename T> class BroadcastReceiver {
public:
    BroadcastReceiver() = default;
    BroadcastReceiver(BroadcastReceiver &&other) noexcept
        : m_shared(std::move(other.m_shared)), m_slot(std::move(other.m_slot)) {}
    BroadcastReceiver &operator=(BroadcastReceiver &&other) noexcept {
        if (this != &other) {
            Detach();
            m_shared = std::move(other.m_shared);
            m_slot = std::move(other.m_slot);
        }
        return *this;
    }
    BroadcastReceiver(const BroadcastReceiver &) = delete;
    BroadcastReceiver &operator=(const BroadcastReceiver &) = delete;
    ~BroadcastReceiver() { Detach(); }

    /** Whether this receiver is attached to a channel. */
    bool Valid() const { return m_slot != nullptr; }

    /** Non-blocking receive (tokio try_recv). */
    RecvResult<T> TryRecv() {
        if (!m_slot) {
            return {RecvStatus::Closed, std::nullopt, 0};
        }
        std::lock_guard lock(m_shared->mu);
        return PopLocked();
    }

    /** Blocking receive with timeout; Empty on timeout. */
    template <typename Rep, typename Period>
    RecvResult<T> RecvFor(std::chrono::duration<Rep, Period> timeout) {
        if (!m_slot) {
            return {RecvStatus::Closed, std::nullopt, 0};
        }
        std::unique_lock lock(m_shared->mu);
        m_shared->cv.wait_for(lock, timeout, [&] {
            return m_slot->lagged > 0 || !m_slot->queue.empty() ||
                   m_shared->closed;
        });
        return PopLocked();
    }

    /**
     * Register a callback run after every message pushed to this receiver
     * (also after an overflowing push) and when the channel closes. It is
     * called on the publishing thread, without channel locks held, and must
     * not block (e.g. post to the session's strand).
     */
    void SetWaker(Waker waker) {
        if (!m_slot) {
            return;
        }
        std::lock_guard lock(m_shared->mu);
        m_slot->waker = waker ? std::make_shared<const Waker>(std::move(waker))
                              : nullptr;
    }

    /** Number of queued (unread) messages (tokio Receiver::len). */
    size_t Len() const {
        if (!m_slot) {
            return 0;
        }
        std::lock_guard lock(m_shared->mu);
        return m_slot->queue.size();
    }
    bool IsEmpty() const { return Len() == 0; }

private:
    friend class BroadcastSender<T>;
    BroadcastReceiver(std::shared_ptr<detail::BroadcastShared<T>> shared,
                      std::unique_ptr<detail::BroadcastSlot<T>> slot)
        : m_shared(std::move(shared)), m_slot(std::move(slot)) {}

    RecvResult<T> PopLocked() {
        if (m_slot->lagged > 0) {
            const uint64_t n = m_slot->lagged;
            m_slot->lagged = 0;
            return {RecvStatus::Lagged, std::nullopt, n};
        }
        if (!m_slot->queue.empty()) {
            RecvResult<T> r{RecvStatus::Message,
                            std::move(m_slot->queue.front()), 0};
            m_slot->queue.pop_front();
            return r;
        }
        if (m_shared->closed) {
            return {RecvStatus::Closed, std::nullopt, 0};
        }
        return {RecvStatus::Empty, std::nullopt, 0};
    }

    void Detach() {
        if (!m_slot) {
            return;
        }
        {
            std::lock_guard lock(m_shared->mu);
            auto &slots = m_shared->slots;
            slots.erase(std::remove(slots.begin(), slots.end(), m_slot.get()),
                        slots.end());
        }
        m_slot.reset();
        m_shared.reset();
    }

    std::shared_ptr<detail::BroadcastShared<T>> m_shared;
    std::unique_ptr<detail::BroadcastSlot<T>> m_slot;
};

/** Port of tokio broadcast::Sender. Move-only; closes the channel on destroy. */
template <typename T> class BroadcastSender {
public:
    /** tokio broadcast::channel(capacity).0 (capacity > 0). */
    explicit BroadcastSender(size_t capacity)
        : m_shared(std::make_shared<detail::BroadcastShared<T>>(
              std::bit_ceil(std::max<size_t>(capacity, 1)))) {
        assert(capacity > 0);
    }
    BroadcastSender(BroadcastSender &&) noexcept = default;
    BroadcastSender &operator=(BroadcastSender &&other) noexcept {
        if (this != &other) {
            Close();
            m_shared = std::move(other.m_shared);
        }
        return *this;
    }
    BroadcastSender(const BroadcastSender &) = delete;
    BroadcastSender &operator=(const BroadcastSender &) = delete;
    ~BroadcastSender() { Close(); }

    /** New receiver; sees only messages sent from now on. */
    BroadcastReceiver<T> Subscribe() const {
        auto slot = std::make_unique<detail::BroadcastSlot<T>>();
        {
            std::lock_guard lock(m_shared->mu);
            m_shared->slots.push_back(slot.get());
        }
        return BroadcastReceiver<T>(m_shared, std::move(slot));
    }

    /** tokio Sender::receiver_count */
    size_t ReceiverCount() const {
        std::lock_guard lock(m_shared->mu);
        return m_shared->slots.size();
    }

    /** Ring capacity per receiver (after power-of-two rounding). */
    size_t Capacity() const { return m_shared->capacity; }

    /**
     * tokio Sender::send: false (SendError) iff there is no receiver, in which
     * case the message is dropped. Wakers of the receivers are appended to
     * `deferred` if given, otherwise invoked before returning (in both cases
     * without the channel lock held).
     */
    bool Send(const T &msg, WakerList *deferred = nullptr) const {
        WakerList local;
        WakerList &wakers = deferred ? *deferred : local;
        {
            std::lock_guard lock(m_shared->mu);
            auto &slots = m_shared->slots;
            if (slots.empty()) {
                return false;
            }
            for (auto *slot : slots) {
                if (slot->queue.size() >= m_shared->capacity) {
                    // Overflow: drop the oldest message (tokio Lagged)
                    slot->queue.pop_front();
                    ++slot->lagged;
                }
                slot->queue.push_back(msg);
                if (slot->waker) {
                    wakers.push_back(slot->waker);
                }
            }
        }
        m_shared->cv.notify_all();
        if (!deferred) {
            InvokeWakers(local);
        }
        return true;
    }

private:
    void Close() {
        if (!m_shared) {
            return;
        }
        WakerList wakers;
        {
            std::lock_guard lock(m_shared->mu);
            m_shared->closed = true;
            for (auto *slot : m_shared->slots) {
                if (slot->waker) {
                    wakers.push_back(slot->waker);
                }
            }
        }
        m_shared->cv.notify_all();
        m_shared.reset();
        InvokeWakers(wakers);
    }

    std::shared_ptr<detail::BroadcastShared<T>> m_shared;
};

// ---------------------------------------------------------------------------
// Messages (subs.rs BlockMsg / subs_group.rs TxMsg)
// ---------------------------------------------------------------------------

/** Type of message for the block. */
enum class BlockMsgType : uint8_t {
    /** Block connected to the blockchain */
    Connected,
    /** Block disconnected from the blockchain */
    Disconnected,
    /** Block has been finalized by Avalanche */
    Finalized,
    /** Block has been invalidated by Avalanche */
    Invalidated,
};

/** Block update message. */
struct BlockMsg {
    /** What happened with the block. */
    BlockMsgType msg_type = BlockMsgType::Connected;
    /** Hash of the block which we got an update for. */
    BlockHash hash;
    /** Height of the block which we got an update for. */
    SubsBlockHeight height = 0;
    /** The timestamp of the block */
    int64_t timestamp = 0;
    /**
     * The coinbase tx for the block, only available upon disconnect or
     * invalidate (Option<Tx>; shared so per-receiver copies are cheap).
     */
    TxRef coinbase_tx;

    bool operator==(const BlockMsg &o) const {
        if (msg_type != o.msg_type || hash != o.hash || height != o.height ||
            timestamp != o.timestamp) {
            return false;
        }
        if (!coinbase_tx || !o.coinbase_tx) {
            return !coinbase_tx && !o.coinbase_tx;
        }
        const Tx &a = *coinbase_tx, &b = *o.coinbase_tx;
        return a.txid == b.txid && a.version == b.version &&
               a.inputs == b.inputs && a.outputs == b.outputs &&
               a.locktime == b.locktime;
    }
};

/** Why did the tx finalize */
enum class TxFinalizationReason : uint8_t {
    /** Tx finalized by post-consensus */
    PostConsensus,
    /** Tx finalized by pre-consensus */
    PreConsensus,
};

/** What happened to a tx (Rust enum TxMsgType, incl. Finalized(reason)). */
struct TxMsgType {
    enum class Kind : uint8_t {
        /** Tx was added to the mempool. */
        AddedToMempool,
        /** Tx was removed from the mempool. */
        RemovedFromMempool,
        /** Tx was confirmed in a block. */
        Confirmed,
        /** Tx was finalized by Avalanche. */
        Finalized,
        /** Tx was invalidated by Avalanche. */
        Invalidated,
    };
    Kind kind = Kind::AddedToMempool;
    /** Only meaningful for Kind::Finalized. */
    TxFinalizationReason reason = TxFinalizationReason::PostConsensus;

    static constexpr TxMsgType AddedToMempool() { return {Kind::AddedToMempool}; }
    static constexpr TxMsgType RemovedFromMempool() {
        return {Kind::RemovedFromMempool};
    }
    static constexpr TxMsgType Confirmed() { return {Kind::Confirmed}; }
    static constexpr TxMsgType Finalized(TxFinalizationReason reason) {
        return {Kind::Finalized, reason};
    }
    static constexpr TxMsgType Invalidated() { return {Kind::Invalidated}; }

    constexpr bool operator==(const TxMsgType &o) const {
        return kind == o.kind && (kind != Kind::Finalized || reason == o.reason);
    }
};

/** Tx update message. */
struct TxMsg {
    /** What happened with the tx. */
    TxMsgType msg_type;
    /** TxId of the tx we got an update for. */
    TxId txid;
    bool operator==(const TxMsg &) const = default;
};

/** subs.rs BLOCK_CHANNEL_CAPACITY */
constexpr size_t BLOCK_CHANNEL_CAPACITY = 16;
/** subs.rs TXS_CHANNEL_CAPACITY */
constexpr size_t TXS_CHANNEL_CAPACITY = 32;
/** subs_group.rs GROUP_CHANNEL_CAPACITY */
constexpr size_t GROUP_CHANNEL_CAPACITY = 16;

// ---------------------------------------------------------------------------
// Groups (pluggable member extraction; keys are generic bytes)
// ---------------------------------------------------------------------------

/** One group member of a tx, as the hub sees it. */
struct SubsMember {
    /** Group::ser_member(member) */
    Bytes ser;
    /** Group::ser_hash_member(member); set iff the kind supports hashing. */
    std::optional<std::array<uint8_t, 32>> hash;
};

/**
 * Port of chronik-db TokenIdGroupAux: for each txid, the token ID (if any)
 * of each input and each output. Built by the token index.
 */
struct TokenIdSubsAux {
    using MaybeTokenIds = std::vector<std::optional<token::TokenId>>;
    std::map<TxId, std::pair<MaybeTokenIds, MaybeTokenIds>> txs;
};

/**
 * Per-event auxiliary data (Group::Aux). Only TokenIdGroup has a non-unit
 * Aux in the eCash tier; `extension` is for extension-defined groups.
 */
struct SubsAux {
    const TokenIdSubsAux *token_id = nullptr;
    const void *extension = nullptr;
};

/**
 * What a SubsGroup needs from a chronik-db Group: member extraction and
 * serialization. Implementations must be stateless/thread-safe.
 */
class SubsGroupKind {
public:
    virtual ~SubsGroupKind() = default;
    /** Group::is_hash_member_supported */
    virtual bool IsHashMemberSupported() const { return false; }
    /**
     * Group::ser_member of a member given in its natural byte form:
     * txid/token ID = 32 bytes in internal (LE) order, script = bytecode,
     * LOKAD ID = 4 bytes.
     */
    virtual Bytes SerMember(ByteView member) const = 0;
    /**
     * tx_members_for_group(group, GroupQuery{is_coinbase: false, tx}, aux):
     * input members then output members, duplicates allowed, each with
     * `hash` set iff IsHashMemberSupported().
     */
    virtual void TxMembers(const Tx &tx, const SubsAux &aux,
                           std::vector<SubsMember> &out) const = 0;
};

/** TxIdGroup: one output member, ser = txid big-endian bytes. */
class TxIdSubsGroupKind final : public SubsGroupKind {
public:
    Bytes SerMember(ByteView member) const override;
    void TxMembers(const Tx &tx, const SubsAux &aux,
                   std::vector<SubsMember> &out) const override;
};

/**
 * ScriptGroup: input coin scripts (stopping at the first input without a
 * coin), then non-OP_RETURN output scripts; ser = compressed script; hash =
 * SHA-256(script) in big-endian (scripthash) order.
 */
class ScriptSubsGroupKind final : public SubsGroupKind {
public:
    explicit ScriptSubsGroupKind(Sha256Fn sha256) : m_sha256(std::move(sha256)) {}
    bool IsHashMemberSupported() const override { return true; }
    Bytes SerMember(ByteView member) const override;
    void TxMembers(const Tx &tx, const SubsAux &aux,
                   std::vector<SubsMember> &out) const override;
    /** Group::ser_hash_member: SHA-256 reversed. */
    std::array<uint8_t, 32> HashMember(ByteView script) const;

private:
    Sha256Fn m_sha256;
};

/** TokenIdGroup: token IDs from SubsAux::token_id; ser = big-endian bytes. */
class TokenIdSubsGroupKind final : public SubsGroupKind {
public:
    Bytes SerMember(ByteView member) const override;
    void TxMembers(const Tx &tx, const SubsAux &aux,
                   std::vector<SubsMember> &out) const override;
};

/** LokadIdGroup: parse_tx_lokad_ids (outputs only); ser = the 4 bytes. */
class LokadIdSubsGroupKind final : public SubsGroupKind {
public:
    Bytes SerMember(ByteView member) const override;
    void TxMembers(const Tx &tx, const SubsAux &aux,
                   std::vector<SubsMember> &out) const override;
};

/** Byte-key comparator allowing lookup by ByteView. */
struct SubsKeyLess {
    using is_transparent = void;
    template <typename A, typename B> bool operator()(const A &a, const B &b) const {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(),
                                            b.end());
    }
};

/**
 * Port of SubsGroup<G>: subscriptions to group members. Subscribers are
 * notified of txs that have inputs/outputs matching the member; even if a
 * member appears several times in a tx, an update is only sent once.
 * Keys are serialized members (generic bytes); hash members (scripthash)
 * share the same key space, as in Rust.
 */
class SubsGroup {
public:
    explicit SubsGroup(std::unique_ptr<SubsGroupKind> kind)
        : m_kind(std::move(kind)) {}

    /** subscribe_to_member (member in natural form, see SerMember) */
    BroadcastReceiver<TxMsg> SubscribeToMember(ByteView member) {
        return SubscribeToSer(m_kind->SerMember(member));
    }
    /** subscribe_to_member with an already serialized member */
    BroadcastReceiver<TxMsg> SubscribeToSer(ByteView member_ser);
    /** subscribe_to_hash_member */
    BroadcastReceiver<TxMsg>
    SubscribeToHashMember(const std::array<uint8_t, 32> &hash_member) {
        return SubscribeToSer(hash_member);
    }

    /**
     * unsubscribe_from_member: removes the member's channel if it has no
     * receiver left (drop the receiver first).
     */
    void UnsubscribeFromMember(ByteView member) {
        UnsubscribeFromSer(m_kind->SerMember(member));
    }
    void UnsubscribeFromSer(ByteView member_ser);
    /** unsubscribe_from_hash_member */
    void UnsubscribeFromHashMember(const std::array<uint8_t, 32> &hash_member) {
        UnsubscribeFromSer(hash_member);
    }

    /**
     * handle_tx_event: send TxMsg{msg_type, tx.txid} to every subscribed
     * member of `tx` once; a member channel without receivers is removed
     * ("unclean unsubscribe"). Wakers go to `wakers` (or run immediately).
     */
    void HandleTxEvent(const Tx &tx, const SubsAux &aux, TxMsgType msg_type,
                       WakerList *wakers = nullptr);

    /** Whether there are no subscribers for this group */
    bool IsEmpty() const { return m_subs.empty(); }
    /** Number of member channels (test/diagnostics). */
    size_t NumChannels() const { return m_subs.size(); }
    bool HasChannel(ByteView member_ser) const {
        return m_subs.find(member_ser) != m_subs.end();
    }
    const SubsGroupKind &Kind() const { return *m_kind; }

private:
    std::unique_ptr<SubsGroupKind> m_kind;
    std::map<Bytes, BroadcastSender<TxMsg>, SubsKeyLess> m_subs;
    std::vector<SubsMember> m_scratch;
};

/**
 * Port of Subs: block, all-tx and per-group subscriptions. Not synchronized;
 * see SubsHub. Python plugin groups are not ported (no plugins), so
 * subs_plugins is always empty and omitted.
 */
class Subs {
public:
    /** Subs::new(script_group): default eCash-tier groups. */
    explicit Subs(Sha256Fn sha256);
    /** Custom group kinds (tests, extensions). */
    Subs(std::unique_ptr<SubsGroupKind> txid, std::unique_ptr<SubsGroupKind> script,
         std::unique_ptr<SubsGroupKind> token_id,
         std::unique_ptr<SubsGroupKind> lokad_id);
    Subs(const Subs &) = delete;
    Subs &operator=(const Subs &) = delete;

    /** Add a subscriber to block messages. */
    BroadcastReceiver<BlockMsg> SubToBlockMsgs() { return m_subs_block.Subscribe(); }
    /** Add a subscriber to all tx messages. */
    BroadcastReceiver<TxMsg> SubToTxMsgs() { return m_subs_txs.Subscribe(); }

    SubsGroup &SubsTxId() { return m_subs_txid; }
    SubsGroup &SubsScript() { return m_subs_script; }
    SubsGroup &SubsTokenId() { return m_subs_token_id; }
    SubsGroup &SubsLokadId() { return m_subs_lokad_id; }

    /** Send out updates to subscribers for this tx and msg_type. */
    void HandleTxEvent(const Tx &tx, TxMsgType msg_type, const SubsAux &aux = {});

    /**
     * Send out msg_type updates for the txs of the block to subscribers.
     * Like Rust, this short-circuits when no GROUP has subscribers, in which
     * case all-tx subscribers get nothing either.
     */
    void HandleBlockTxEvents(const std::vector<TxRef> &txs, TxMsgType msg_type,
                             const SubsAux &aux = {});
    void HandleBlockTxEvents(const std::vector<Tx> &txs, TxMsgType msg_type,
                             const SubsAux &aux = {});

    /** broadcast_block_msg (only if there is a receiver) */
    void BroadcastBlockMsg(const BlockMsg &msg);
    /** broadcast_tx_msg (only if there is a receiver) */
    void BroadcastTxMsg(const TxId &txid, TxMsgType msg_type);

    /** Wakers deferred by the calls above; SubsHub's guard runs them. */
    WakerList &PendingWakers() { return m_pending_wakers; }
    void FlushWakers() { InvokeWakers(m_pending_wakers); }

private:
    bool AllGroupsEmpty() const;
    void TxEventAllGroups(const Tx &tx, TxMsgType msg_type, const SubsAux &aux);

    BroadcastSender<BlockMsg> m_subs_block{BLOCK_CHANNEL_CAPACITY};
    BroadcastSender<TxMsg> m_subs_txs{TXS_CHANNEL_CAPACITY};
    SubsGroup m_subs_txid;
    SubsGroup m_subs_script;
    SubsGroup m_subs_token_id;
    SubsGroup m_subs_lokad_id;
    WakerList m_pending_wakers;
};

/**
 * Subs behind a lock (Rust: RwLock<Subs>, always taken for write). The
 * writer publishes through Write() after committing, outside the indexer's
 * state lock. Wakers collected while the guard is held run after the lock
 * is released.
 */
class SubsHub {
public:
    explicit SubsHub(Sha256Fn sha256) : m_subs(std::move(sha256)) {}
    explicit SubsHub(std::unique_ptr<SubsGroupKind> txid,
                     std::unique_ptr<SubsGroupKind> script,
                     std::unique_ptr<SubsGroupKind> token_id,
                     std::unique_ptr<SubsGroupKind> lokad_id)
        : m_subs(std::move(txid), std::move(script), std::move(token_id),
                 std::move(lokad_id)) {}

    class Guard {
    public:
        explicit Guard(SubsHub &hub) : m_hub(&hub), m_lock(hub.m_mutex) {}
        Guard(Guard &&other) noexcept
            : m_hub(std::exchange(other.m_hub, nullptr)),
              m_lock(std::move(other.m_lock)) {}
        Guard &operator=(Guard &&) = delete;
        ~Guard() {
            if (!m_hub) {
                return;
            }
            WakerList wakers;
            wakers.swap(m_hub->m_subs.PendingWakers());
            m_lock.unlock();
            InvokeWakers(wakers);
        }
        Subs *operator->() { return &m_hub->m_subs; }
        Subs &operator*() { return m_hub->m_subs; }

    private:
        SubsHub *m_hub;
        std::unique_lock<std::mutex> m_lock;
    };

    /** indexer.subs().write() */
    Guard Write() { return Guard(*this); }

private:
    std::mutex m_mutex;
    Subs m_subs;
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_SUBS_H
