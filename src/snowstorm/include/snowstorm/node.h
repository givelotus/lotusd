// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/stats.h>
#include <functional>
/** @defgroup snowstorm_node_contract Snowstorm node public contract
 * §§1–10: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §§1,8: pure root over supplied canonical candidate bodies and tip only. */
using RootFn = std::function<Root(const TipContext &, std::span<const TxHandle>)>;
/** §1: the complete configuration; pooling is mandatory and not configurable. */
struct Config {
    double beta_max{0.2};
    double epsilon{1e-9};
    std::uint64_t max_set_size{};
    RootFn root_fn;
    std::uint64_t rng_seed{};
};
/** §§1,5: atomically reset the height/key and surviving host-admitted bodies. */
struct TipParams {
    TipContext context{};
    ShortIdKey key{};
    std::vector<TxHandle> surviving;
};
/** §§1,6.5: negotiated compatible version and initial positive RTT in us. */
struct PeerCaps {
    std::uint8_t protocol_version{1};
    Time rtt{};
};
/** §1: owned canonical wire payload for one compatible connection. */
struct Send { PeerId peer{}; Bytes bytes; };
/** §§1,6.3: one host-owned validation/admission request with unique token. */
struct FetchBody { PeerId peer{}; ShortId short_id{}; FetchId fetch_id{}; };
/** §§1,8: candidate-root transition, unique sorted full txids. */
struct Frozen { Root root{}; std::vector<TxId> txids; };
/** §1: host chooses actual penalty; core does not disconnect sockets. */
struct PeerMisbehaved { PeerId peer{}; Misbehavior reason{}; };
/** §§1,6.5: earliest future monotonic deadline; obsolete host timers are harmless. */
struct ScheduleTimer { Time at{}; };
/** §1: all core effects are explicit values in deterministic order. */
using Action = std::variant<Send, FetchBody, Frozen, PeerMisbehaved, ScheduleTimer>;
/** §1: returned actions are host-owned; there is no hidden outbound queue. */
using Actions = std::vector<Action>;
/** §§1–10: single-owner deterministic sans-IO state machine, no host truth input. */
class SnowstormNode {
public:
    /** §1: invalid local Config throws invalid_argument before protocol allocation. */
    explicit SnowstormNode(Config cfg);
    /** §1: release owned state; no implicit host effects. */
    ~SnowstormNode();
    /** §1: transfer state ownership without changing protocol identity or timers. */
    SnowstormNode(SnowstormNode &&) noexcept;
    /** §1: transfer state ownership; host serializes access. */
    SnowstormNode &operator=(SnowstormNode &&) noexcept;
    /** §1: live protocol state has a single owner. */
    SnowstormNode(const SnowstormNode &) = delete;
    /** §1: live protocol state has a single owner. */
    SnowstormNode &operator=(const SnowstormNode &) = delete;
    /** §§1,3,5: accept only actual host admission; recompute ID with current key. */
    Actions on_tx_admitted(TxHandle tx, Time now);
    /** §§1,3: explicit whole-ID-bucket removal for any RemovalReason. */
    Actions on_tx_removed(ShortId item, RemovalReason reason, Time now);
    /** §§1,3: remove this body immediately; last-body removal also changes ID sketch. */
    Actions on_tx_body_removed(ShortId item, TxHash hash, RemovalReason reason,
                               Time now);
    /** §§1,6.3: token/hash/binding-correlated host result; never fake admission.
     * Discard stale results first. For a live token validate both status and
     * binding enum domains before not_found ignores a valid binding/hash value.
     */
    Actions on_tx_bodies_result(PeerId peer, ShortId item, BodyResult result,
                                Time now);
    /** §§1,6.1: bounded canonical bytes; malformed remote input never escapes/aborts. */
    Actions on_message(PeerId peer, ByteSpan bytes, Time now);
    /** §§1,6.5: service due resends/waves once; same-Time duplicate is harmless. */
    Actions on_timer(Time now);
    /** §§1,8: fresh never-reused PeerId; incompatible caps do not join population. */
    Actions on_peer_connected(PeerId peer, PeerCaps caps, Time now);
    /** §§1,5,6.3: purge connection models/donors and invalidate wave population.
     * Cancel in-flight fetches and retry known usable alternates; preserve an
     * awaiting-admission record because the host still owes its admission callback.
     */
    Actions on_peer_disconnected(PeerId peer, Time now);
    /** §§1,5: reset height state and rekey supplied surviving bodies atomically. */
    Actions on_new_tip(TipParams tip, Time now);
    /** §§1,5: identical reset semantics for reorg/block disconnect. */
    Actions on_block_disconnected(TipParams tip, Time now);
    /** §10: read-only complete diagnostics; value copy may allocate outside hot paths. */
    Stats stats() const;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace snowstorm
/** @} */
