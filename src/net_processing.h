// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_PROCESSING_H
#define BITCOIN_NET_PROCESSING_H

#include <avalanche/avalanche.h>
#include <net.h>
#include <primitives/transaction.h>

#include <span>
#include <sync.h>
#include <validationinterface.h>

namespace avalanche {
struct ProofId;
class Processor;
} // namespace avalanche

namespace lotus::v2::net { class V2PeerProtocolHandler; }

class AddrMan;
class CTxMemPool;
class ChainstateManager;
class Config;
struct PrecomputedAdmissionChecks;

/**
 * Context-free checks and transaction-owned sighash data for a received burst,
 * in receive order. No coins, scripts, relay state or admission decisions are
 * inspected here. Null slots remain unchecked. Call without cs_main held.
 */
std::vector<PrecomputedAdmissionChecks>
PrecomputeTxRelayBatch(const std::vector<CTransactionRef> &txs)
    LOCKS_EXCLUDED(cs_main);

/**
 * Default for -maxorphantx, maximum number of orphan transactions kept in
 * memory.
 */
static const uint32_t DEFAULT_MAX_ORPHAN_TRANSACTIONS{100};
/**
 * Maximum number of conflicting transactions kept in memory.
 */
static const uint32_t DEFAULT_MAX_CONFLICTING_TRANSACTIONS{100};
/**
 * Default number of non-mempool transactions to keep around for block
 * reconstruction. Includes orphan and rejected transactions.
 */
static const uint32_t DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN{100};
static const bool DEFAULT_PEERBLOCKFILTERS = false;
/** Maximum number of outstanding CMPCTBLOCK requests for the same block. */
static const unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;
/** The maximum number of address records permitted in an ADDR message. */
static constexpr size_t MAX_ADDR_TO_SEND{1000};

/**
 * Average delay between trickled inventory transmissions for inbound peers.
 * Since Nucleation relay, only avalanche proof announcements use this
 * Poisson timer; transaction announcements go out on the fixed relay tick.
 */
static constexpr std::chrono::milliseconds INBOUND_INVENTORY_BROADCAST_INTERVAL{
    5000};
/**
 * Average delay between trickled inventory transmissions for outbound peers
 * (proof announcements only, see above).
 */
static constexpr std::chrono::milliseconds
    OUTBOUND_INVENTORY_BROADCAST_INTERVAL{2000};
/**
 * Default interval of the transaction relay tick (-txrelaytick). Every peer
 * announces on the same tick boundaries of the monotonic clock; there is no
 * random delay. Under load the tick is what batches many transactions into
 * one announcement.
 */
static constexpr std::chrono::milliseconds DEFAULT_TXRELAY_TICK{10};
/** Bounds of -txrelaytick */
static constexpr std::chrono::milliseconds MIN_TXRELAY_TICK{1};
static constexpr std::chrono::milliseconds MAX_TXRELAY_TICK{1000};
/**
 * The first relay tick strictly after `now`: tick boundaries are the
 * multiples of `tick` on the monotonic clock, so peers that send at the
 * same boundary share it. A peer that sends at boundary b next sends at
 * b + tick (strictly after, so a send exactly on a boundary does not
 * repeat at the same instant).
 */
constexpr std::chrono::microseconds
NextRelayTick(std::chrono::microseconds now,
              std::chrono::microseconds tick) noexcept {
    return tick.count() <= 0 ? now : (now / tick + 1) * tick;
}
/**
 * Transaction relay fan-out: at each tick a relayed transaction is
 * announced to clamp(max(min, ceil(pct x relay peers)), min, max) peers,
 * picked uniformly among those not known to have it (-txrelayfanoutmin,
 * -txrelayfanoutpct, -txrelayfanoutmax). Transactions this node
 * originated (wallet, RPC) go to every relay peer.
 */
static constexpr size_t DEFAULT_TXRELAY_FANOUT_MIN{8};
static constexpr double DEFAULT_TXRELAY_FANOUT_PCT{0.25};
static constexpr size_t DEFAULT_TXRELAY_FANOUT_MAX{32};
/**
 * Default per-peer cap on transaction announcements per second
 * (-txrelayratemax), spent per tick: a peer is sent at most
 * ceil(rate x tick) announcements per tick and the excess waits for the
 * next tick (nothing is dropped). Sized for 1M transactions per second
 * network-wide: target TPS x 2 / fan-out minimum.
 */
static constexpr uint64_t DEFAULT_TXRELAY_RATE_MAX{250'000};

/**
 * Default for -txrelayshortids: announce transactions with 8-byte short ids
 * (invshort) to peers that negotiate them (sendinvshort). Other peers get
 * ordinary 36-byte INVs.
 */
static constexpr bool DEFAULT_TXRELAY_SHORTIDS{true};
/**
 * Default for -txrelaypushhb: whether bursts of 16 or more transactions are
 * pushed as unsolicited shorttx bodies to peers that explicitly negotiate
 * TXRELAY_HIGH_BANDWIDTH instead of being announced. Off:
 * the relay simulation puts the latency gain at ~0.1 s against a duplicate
 * body in most cases. Receiving pushed bodies is unchanged.
 */
static constexpr bool DEFAULT_TXRELAY_PUSH_HB{false};
/**
 * Continuous reconciliation (-txreconinterval, -txreconwindow): every
 * interval, send a LIVE_MEMPOOL Merklix summary of the transactions admitted
 * in the last window to the next negotiating peer, round robin, so it can
 * fetch what relay did not bring it. The safety net under fan-out.
 */
static constexpr std::chrono::milliseconds DEFAULT_TXRECON_INTERVAL{250};
static constexpr std::chrono::seconds DEFAULT_TXRECON_WINDOW{30};

/** Number of peers to announce a relayed transaction to (see above) */
size_t TxRelayFanout(size_t relay_peers, size_t fanout_min, double fanout_pct,
                     size_t fanout_max) noexcept;
/** The number of most recently announced transactions a peer can request. */
static constexpr unsigned int INVENTORY_MAX_RECENT_RELAY = 350000;


/**
 * Number of headers sent in one getheaders result. We rely on the assumption
 * that if a peer sends less than this number, we reached its tip. Changing
 * this value is a protocol upgrade.
 */
static const unsigned int MAX_HEADERS_RESULTS = 2000;

struct CNodeStateStats {
    int nSyncHeight = -1;
    int nCommonHeight = -1;
    int m_starting_height = -1;
    std::chrono::microseconds m_ping_wait;
    std::vector<int> vHeightInFlight;
    bool m_relay_txs;
    Amount m_fee_filter_received;
    uint64_t m_addr_processed = 0;
    uint64_t m_addr_rate_limited = 0;
    bool m_addr_relay_enabled{false};
    ServiceFlags their_services;
    int64_t presync_height{-1};
};

//! Default -blockmessagecache, MiB of serialized block messages kept for
//! serving the same block to several peers
static constexpr int64_t DEFAULT_BLOCK_MESSAGE_CACHE_MB{64};
//! Blocks smaller than this are cheap to serialize again and not cached
static constexpr size_t BLOCK_MESSAGE_CACHE_MIN_BYTES{64 * 1024};

class PeerManager : public CValidationInterface, public NetEventsInterface {
public:
    struct Options {
        //! Whether this node is running in -blocksonly mode
        bool ignore_incoming_txs{DEFAULT_BLOCKSONLY};
        //! Maximum number of orphan transactions kept in memory
        uint32_t max_orphan_txs{DEFAULT_MAX_ORPHAN_TRANSACTIONS};
        //! Maximum number of conflicting transactions kept in memory
        uint32_t max_conflicting_txs{DEFAULT_MAX_CONFLICTING_TRANSACTIONS};
        //! Number of non-mempool transactions to keep around for block
        //! reconstruction. Includes orphan and rejected transactions.
        uint32_t max_extra_txs{DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN};
        //! Whether all P2P messages are captured to disk
        bool capture_messages{false};
        //! Number of addresses a node may send in an ADDR message.
        //! This can be modified for tests only. Changing it on main net may
        //! cause disconnections.
        size_t max_addr_to_send{MAX_ADDR_TO_SEND};

        //! Minimum time between two AVAPOLL messages.
        int64_t avalanche_cooldown{AVALANCHE_DEFAULT_COOLDOWN};
        //! Minimum time before we will consider replacing a finalized proof
        //! with a conflicting one.
        int64_t avalanche_peer_replacement_cooldown{
            AVALANCHE_DEFAULT_PEER_REPLACEMENT_COOLDOWN};

        //! Whether or not the internal RNG behaves deterministically (this is
        //! a test-only option).
        bool deterministic_rng{false};
        //! Bytes of recently served block messages kept, with their
        //! checksums, for the next peers asking for them (0 disables)
        size_t block_message_cache_bytes{size_t(DEFAULT_BLOCK_MESSAGE_CACHE_MB)
                                         << 20};

        //! Interval of the transaction relay tick (-txrelaytick)
        std::chrono::milliseconds txrelay_tick{DEFAULT_TXRELAY_TICK};
        //! Fan-out of relayed transactions (see TxRelayFanout)
        size_t txrelay_fanout_min{DEFAULT_TXRELAY_FANOUT_MIN};
        double txrelay_fanout_pct{DEFAULT_TXRELAY_FANOUT_PCT};
        size_t txrelay_fanout_max{DEFAULT_TXRELAY_FANOUT_MAX};
        //! Per-peer announcements per second (-txrelayratemax)
        uint64_t txrelay_rate_max{DEFAULT_TXRELAY_RATE_MAX};
        //! Offer and use short-id announcements (-txrelayshortids)
        bool txrelay_shortids{DEFAULT_TXRELAY_SHORTIDS};
        //! Short id width; below 64 only in tests, to force collisions
        unsigned txrelay_shortid_bits{64};
        //! Push bodies to high-bandwidth peers (-txrelaypushhb)
        bool txrelay_push_hb{DEFAULT_TXRELAY_PUSH_HB};
        //! Reconcile with the next peer every interval; 0 = off
        std::chrono::milliseconds txrecon_interval{DEFAULT_TXRECON_INTERVAL};
        //! Reconciliation set: transactions admitted within this window
        std::chrono::seconds txrecon_window{DEFAULT_TXRECON_WINDOW};
    };

    static std::unique_ptr<PeerManager>
    make(CConnman &connman, AddrMan &addrman, BanMan *banman,
         ChainstateManager &chainman, CTxMemPool &pool,
         avalanche::Processor *const avalanche, Options opts);
    virtual ~PeerManager() = default;

    /**
     * Attempt to manually fetch block from a given peer. We must already have
     * the header.
     *
     * @param[in]  config       The global config
     * @param[in]  peer_id      The peer id
     * @param[in]  block_index  The block index
     * @returns std::nullopt if a request was successfully made, otherwise an
     *     error message
     */
    virtual std::optional<std::string>
    FetchBlock(const Config &config, NodeId peer_id,
               const CBlockIndex &block_index) = 0;

    /** Begin running background tasks, should only be called once */
    virtual void StartScheduledTasks(CScheduler &scheduler) = 0;

    /** Get statistics from node state */
    virtual bool GetNodeStateStats(NodeId nodeid,
                                   CNodeStateStats &stats) const = 0;

    /** Whether this node ignores txs received over p2p. */
    virtual bool IgnoresIncomingTxs() = 0;

    virtual lotus::v2::net::V2PeerProtocolHandler *GetV2ProtocolHandler() = 0;
    virtual void MarkPeerKnownTx(NodeId peer_id, const TxId &txid) = 0;

    /**
     * Queue a transaction for relay. At the next relay tick it is announced
     * to a fan-out of peers (to every peer if this node originated it).
     */
    virtual void RelayTransaction(const TxId &txid) = 0;

    /** Batch interface; implementations may coalesce peer locking. */
    virtual void RelayTransactionBatch(std::span<const CTransactionRef> txs) {
        for (const auto &tx : txs) {
            if (tx) RelayTransaction(tx->GetId());
        }
    }
    /**
     * Transactions a peer served for relay-epoch short ids (getshorttx):
     * processed as if each had arrived in a tx message.
     */
    /** Select relay-epoch bodies against the authoritative request tracker.
     * An opted-in peer may also send unsolicited bodies. Other peers must
     * answer requests issued to that exact peer in the declared epoch.
     */
    virtual std::vector<CTransactionRef> FilterRequestedShortTxResponse(
        NodeId peer_id, const uint256 &epoch_id,
        std::span<const CTransactionRef> txs,
        bool allow_unsolicited) = 0;
    virtual void ProcessShortTxResponse(CNode &node,
                                        std::span<const CTransactionRef> txs) {}
    /**
     * Short ids of a relay epoch that reconciliation found this peer has
     * and we lack: fetched as if the peer had announced them.
     */
    virtual void
    AddRelayShortIdAnnouncements(const CNode &node, const uint256 &epoch_id,
                                 const std::vector<uint64_t> &short_ids) {}
    virtual void MarkPeerKnownTxBatch(NodeId peer_id,
                                      std::span<const CTransactionRef> txs) {
        for (const auto &tx : txs) {
            if (tx) MarkPeerKnownTx(peer_id, tx->GetId());
        }
    }


    /** Relay proof to all peers */
    virtual void RelayProof(const avalanche::ProofId &proofid) = 0;

    /** Send ping message to all peers */
    virtual void SendPings() = 0;

    /** Set the best height */
    virtual void SetBestHeight(int height) = 0;

    /** Public for unit testing. */
    virtual void UnitTestMisbehaving(const NodeId peer_id) = 0;

    /**
     * Evict extra outbound peers. If we think our tip may be stale, connect to
     * an extra outbound.
     */
    virtual void CheckForStaleTipAndEvictPeers() = 0;

    /** Process a single message from a peer. Public for fuzz testing */
    virtual void ProcessMessage(const Config &config, CNode &pfrom,
                                const std::string &msg_type, DataStream &vRecv,
                                const std::chrono::microseconds time_received,
                                const std::atomic<bool> &interruptMsgProc)
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;

    /**
     * This function is used for testing the stale tip eviction logic, see
     * denialofservice_tests.cpp
     */
    virtual void UpdateLastBlockAnnounceTime(NodeId node,
                                             int64_t time_in_seconds) = 0;
};

#endif // BITCOIN_NET_PROCESSING_H
