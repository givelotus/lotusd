// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#include "host.h"
#include "../oracle/model.h"
#include <algorithm>
#include <limits>
#include <queue>
#include <snowstorm/messages.h>
#include <snowstorm/short_id.h>
#include <stdexcept>
#include <tuple>
#include <type_traits>
namespace snowstorm::test {
namespace {
    void require(bool b, const char *s) {
        if (!b) throw std::runtime_error(s);
    }
    void put(Bytes &b, std::uint64_t v) {
        for (unsigned i = 0; i < 8; ++i)
            b.push_back(static_cast<Byte>(v >> (8 * i)));
    }
    Time later(Time a, Time b) {
        require(b >= 0 && a <= std::numeric_limits<Time>::max() - b,
                "host time overflow");
        return a + b;
    }
    snowstorm_oracle::Cell convert(const Cell &c) {
        return {c.count, c.s1, c.s3, c.s5};
    }
} // namespace
Root canonical_root(const TipContext &tip, std::span<const TxHandle> bodies) {
    std::vector<std::pair<TxId, TxHash>> pairs;
    for (const auto &b : bodies)
        pairs.emplace_back(b->txid(), b->tx_hash());
    std::sort(pairs.begin(), pairs.end());
    Bytes bytes{'S', 'N', 'O', 'W', 'H', 'O', 'S', 'T', 1};
    bytes.insert(bytes.end(), tip.begin(), tip.end());
    put(bytes, pairs.size());
    for (const auto &[id, hash] : pairs) {
        bytes.insert(bytes.end(), id.begin(), id.end());
        bytes.insert(bytes.end(), hash.begin(), hash.end());
    }
    return sha256(bytes);
}
TipParams default_tip(std::uint64_t height) {
    TipParams p;
    for (unsigned i = 0; i < 8; ++i)
        p.context[i] = static_cast<Byte>(height >> (8 * i));
    p.key = {0x0706050403020100ULL ^ height, 0x0f0e0d0c0b0a0908ULL};
    return p;
}
Config default_config(std::uint64_t m, std::uint64_t seed) {
    Config c;
    c.max_set_size = m;
    c.rng_seed = seed;
    c.root_fn = canonical_root;
    return c;
}
class Host::Impl {
public:
    struct Endpoint {
        bool active{true};
        bool wire{};
        NodeId remote{};
        PeerId counterpart{};
        LinkOptions link;
        WireHandler handler;
    };
    struct FetchExpectation {
        PeerId peer{};
        ShortId item{};
        ShortIdKey key{};
        std::uint64_t generation{};
        bool awaiting{};
        std::optional<TxHash> expected_hash;
    };
    struct ModelExpectation {
        std::set<ShortId> plus, minus;
        // Provenance belongs only to an actual positive decode in this model.
        // Copying an assumption or retaining an own removal does not create it.
        std::set<ShortId> decoded_plus;
        bool open{true};
    };
    using ModelKey = std::pair<PeerId, SessionId>;
    struct PendingNotification {
        std::uint64_t generation{}, incarnation{};
        DeliveryObservation observation;
    };
    struct Node {
        std::unique_ptr<SnowstormNode> core;
        TipParams tip;
        // Actual host admission is independent of notification delivery.
        std::map<TxHash, TxHandle> bodies;
        std::map<TxHash, TxHandle> notified_bodies;
        std::map<TxHash, std::uint64_t> body_versions;
        std::map<TxHash, PendingNotification> pending_notifications;
        std::map<PeerId, Endpoint> peers;
        std::uint64_t generation{};
        RootFn root;
        std::uint64_t max_set_size{};
        std::set<ShortId> expected_rejected;
        std::map<FetchId, FetchExpectation> expected_fetches;
        std::optional<FetchId> largest_fetch_token;
        bool expected_rejection_suspension{};
        std::map<ModelKey, ModelExpectation> expected_models;
        std::set<ShortId> previous_projected, expected_probation,
            expected_local_rejected;
        std::set<std::pair<PeerId, ShortId>> expected_unavailable;
        std::set<ModelKey> must_release;
        bool tip_reset_pending{};
    };
    struct BodyJob {
        std::shared_ptr<std::size_t> activity;
        explicit BodyJob(std::shared_ptr<std::size_t> count)
            : activity(std::move(count)) {
            ++*activity;
        }
        ~BodyJob() { --*activity; }
        BodyFetchContext fetch;
        std::uint64_t requester_generation{};
        std::optional<PeerId> donor_local_peer;
        bool terminal{};
        DeliveryObservation request_packet, response_packet;
    };
    struct Event {
        Time at;
        std::uint64_t serial;
        std::function<void()> fn;
    };
    struct Compare {
        bool operator()(const Event &a, const Event &b) const {
            return std::tie(a.at, a.serial) > std::tie(b.at, b.serial);
        }
    };
    struct Snapshot {
        std::set<ShortId> raw, candidate;
        Root root;
    };
    using SnapshotKey = std::tuple<NodeId, PeerId, SessionId, TipContext>;
    struct WireAnchor {
        std::optional<RequestId> request;
        std::vector<Range> ranges;
        std::optional<Sequence> snapshot_seq;
        std::map<SymbolIndex, snowstorm_oracle::Cell> raw;
        bool inconsistent{};
    };
    std::vector<std::unique_ptr<Node>> nodes;
    std::priority_queue<Event, std::vector<Event>, Compare> events;
    std::map<std::tuple<NodeId, PeerId, ShortId>, BodyRule> rules;
    std::map<SnapshotKey, Snapshot> snapshots;
    std::map<SnapshotKey, WireAnchor> wire_anchors;
    std::vector<Observation> observations;
    std::vector<Completion> completions;
    Transcript transcript;
    Traffic traffic;
    HostOptions options;
    std::function<void(const Observation &)> observer;
    std::function<void(NodeId, Time, std::string_view, std::span<const Action>)>
        action_observer;
    TransportPolicy transport_policy;
    std::optional<BodyServicePolicy> body_service_policy;
    std::function<void(const DeliveryObservation &)> delivery_observer;
    std::shared_ptr<std::size_t> active_body_jobs{
        std::make_shared<std::size_t>(0)};
    unsigned callback_depth{};
    std::uint64_t packet_sequence{};
    Time now{};
    std::uint64_t serial{}, rng;
    PeerId next_peer{1};
    explicit Impl(std::uint64_t s, HostOptions o) : options(o), rng(s) {
        if (o.observation_mode != ObservationMode::full_every_call &&
            o.observation_mode != ObservationMode::simulation_observation)
            throw std::invalid_argument("invalid host observation mode");
        if (!full_observation() &&
            (o.retain_observations || o.retain_completions))
            throw std::invalid_argument("simulation observation cannot retain "
                                        "omitted Stats/completions");
    }
    void ensure_mutable() const {
        if (callback_depth)
            throw std::logic_error(
                "Host mutation/reentry from observer or policy callback");
    }
    template <typename F> decltype(auto) callback(F &&function) {
        struct Guard {
            unsigned &depth;
            explicit Guard(unsigned &d) : depth(d) { ++depth; }
            ~Guard() { --depth; }
        } guard(callback_depth);
        return function();
    }
    DeliveryObservation
    packet(NodeId n, PeerId peer, bool reverse,
           TrafficClass traffic_class = TrafficClass::reconciliation,
           std::optional<FetchId> token = {}, std::optional<ShortId> item = {},
           std::optional<TipContext> tip = {}) {
        require(packet_sequence < std::numeric_limits<std::uint64_t>::max(),
                "host packet identity exhausted");
        DeliveryObservation out;
        out.packet_id = ++packet_sequence;
        out.local_node = n;
        out.local_peer = peer;
        out.connection_generation = peer;
        out.traffic_class = traffic_class;
        out.fetch_id = token;
        out.item = item;
        out.tip = tip.value_or(node(n).tip.context);
        const auto endpoint = node(n).peers.find(peer);
        if (reverse) {
            out.receiver = n;
            if (endpoint != node(n).peers.end() && !endpoint->second.wire)
                out.sender = endpoint->second.remote;
        } else {
            out.sender = n;
            if (endpoint != node(n).peers.end() && !endpoint->second.wire)
                out.receiver = endpoint->second.remote;
        }
        return out;
    }
    void delivery(const DeliveryObservation &base, DeliveryStage stage,
                  ApplicationDisposition disposition, ByteSpan bytes = {},
                  std::optional<Time> arrival = {},
                  std::optional<BodyStatus> result = {}) {
        if (!delivery_observer) return;
        auto observation = base;
        observation.stage = stage;
        observation.disposition = disposition;
        observation.time = now;
        observation.scheduled_arrival = arrival;
        observation.bytes = bytes;
        observation.byte_count = bytes.size();
        observation.result = result;
        callback([&] { delivery_observer(observation); });
    }
    TransportDecision transport(const TransportInput &input) {
        return callback([&] { return transport_policy(input); });
    }
    bool full_observation() const {
        return options.observation_mode == ObservationMode::full_every_call;
    }
    std::uint64_t random() {
        rng += 0x9e3779b97f4a7c15ULL;
        auto z = rng;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    Node &node(NodeId n) { return *nodes.at(n); }
    const Node &node(NodeId n) const { return *nodes.at(n); }
    std::set<ShortId> truth(NodeId n) const {
        std::set<ShortId> out;
        for (const auto &[h, b] : node(n).bodies)
            out.insert(short_id(node(n).tip.key, h));
        return out;
    }
    std::set<ShortId> projected_truth(NodeId n) const {
        std::set<ShortId> ids;
        for (const auto &[hash, body] : node(n).notified_bodies) {
            (void)body;
            ids.insert(short_id(node(n).tip.key, hash));
        }
        for (auto id : node(n).expected_rejected)
            ids.erase(id);
        return ids;
    }
    bool has_fetch_support(NodeId n, ShortId item, bool awaiting_only) const {
        const auto &owner = node(n);
        return std::any_of(
            owner.expected_fetches.begin(), owner.expected_fetches.end(),
            [&](const auto &entry) {
                return entry.second.item == item &&
                       entry.second.generation == owner.generation &&
                       (!awaiting_only || entry.second.awaiting);
            });
    }
    std::set<ShortId> expected_pending(NodeId n) const {
        std::set<ShortId> pending;
        const auto &owner = node(n);
        const auto own = projected_truth(n);
        for (const auto &[token, fetch] : owner.expected_fetches) {
            (void)token;
            if (fetch.generation == owner.generation &&
                (!owner.expected_rejection_suspension || fetch.awaiting))
                pending.insert(fetch.item);
        }
        if (!owner.expected_rejection_suspension)
            for (const auto &[key, model] : owner.expected_models) {
                if (!model.open || owner.must_release.contains(key)) continue;
                for (auto id : model.decoded_plus)
                    if (model.plus.contains(id)) pending.insert(id);
            }
        for (auto it = pending.begin(); it != pending.end();) {
            if (own.contains(*it) || owner.expected_rejected.contains(*it) ||
                owner.expected_probation.contains(*it) ||
                owner.expected_local_rejected.contains(*it))
                it = pending.erase(it);
            else
                ++it;
        }
        return pending;
    }
    std::set<ShortId> model_reference(NodeId n,
                                      const ModelExpectation &model) const {
        auto ref = projected_truth(n);
        ref.insert(model.plus.begin(), model.plus.end());
        for (auto id : model.minus)
            ref.erase(id);
        return ref;
    }
    void revoke_assumption(NodeId n, ShortId id) {
        auto &owner = node(n);
        for (auto &[key, model] : owner.expected_models) {
            model.decoded_plus.erase(id);
            if (model.plus.erase(id)) owner.must_release.insert(key);
        }
    }
    void register_fetch(NodeId n, const FetchBody &f) {
        require(!node(n).largest_fetch_token ||
                    f.fetch_id > *node(n).largest_fetch_token,
                "fetch token is not globally monotonic across this node's "
                "generations");
        node(n).largest_fetch_token = f.fetch_id;
        require(!projected_truth(n).contains(f.short_id) &&
                    !node(n).expected_rejected.contains(f.short_id) &&
                    !node(n).expected_local_rejected.contains(f.short_id),
                "fetch issued for admitted/rejected/local-refused ID");
        require(!node(n).expected_rejection_suspension,
                "fetch issued while speculation is suspended");
        for (const auto &[token, fetch] : node(n).expected_fetches) {
            (void)token;
            require(fetch.item != f.short_id,
                    "duplicate active fetch for one ID");
        }
        require(node(n)
                    .expected_fetches
                    .emplace(f.fetch_id, FetchExpectation{f.peer,
                                                          f.short_id,
                                                          node(n).tip.key,
                                                          node(n).generation,
                                                          false,
                                                          {}})
                    .second,
                "reused fetch token");
    }
    std::vector<TxHandle> handles(NodeId n) const {
        std::vector<TxHandle> v;
        for (const auto &[h, b] : node(n).bodies)
            v.push_back(b);
        return v;
    }
    void record(Byte kind, NodeId n, Bytes b = {}) {
        if (options.retain_transcript) transcript.event(kind, n, now, b);
    }
    void enqueue(Time at, std::function<void()> fn) {
        require(at >= now, "event in past");
        events.push({at, ++serial, std::move(fn)});
    }
    void replay_reference_events(NodeId n, const Stats &after) {
        auto &owner = node(n);
        const auto own = projected_truth(n);
        if (owner.tip_reset_pending) {
            for (const auto &[key, model] : owner.expected_models) {
                (void)model;
                owner.must_release.insert(key);
            }
        } else {
            for (auto removed : owner.previous_projected)
                if (!own.contains(removed)) {
                    for (auto &[key, model] : owner.expected_models) {
                        (void)key;
                        if (!model.plus.contains(removed) &&
                            !model.minus.contains(removed))
                            model.plus.insert(removed);
                    }
                }
        }
        if (owner.expected_rejection_suspension) {
            for (auto &[key, model] : owner.expected_models) {
                for (auto it = model.plus.begin(); it != model.plus.end();) {
                    const bool awaiting = has_fetch_support(n, *it, true);
                    if (!own.contains(*it) && !awaiting) {
                        model.decoded_plus.erase(*it);
                        it = model.plus.erase(it);
                        owner.must_release.insert(key);
                    } else
                        ++it;
                }
            }
        }
        // Only ordering metadata is read from core. References are
        // reconstructed from host notifications and previously validated atomic
        // differences.
        struct EventRef {
            std::uint64_t order;
            unsigned kind;
            std::size_t index;
        };
        std::vector<EventRef> events;
        const auto &audit = after.last_call;
        const auto ordered = [](const auto &entries) {
            for (std::size_t i = 1; i < entries.size(); ++i)
                require(entries[i - 1].event_order < entries[i].event_order,
                        "audit array is not in emission order");
        };
        ordered(audit.lifecycle);
        ordered(audit.decodes);
        ordered(audit.completions);
        ordered(audit.actions);
        for (std::size_t i = 0; i < audit.lifecycle.size(); ++i)
            events.push_back({audit.lifecycle[i].event_order, 0, i});
        for (std::size_t i = 0; i < audit.decodes.size(); ++i)
            events.push_back({audit.decodes[i].event_order, 1, i});
        for (std::size_t i = 0; i < audit.completions.size(); ++i)
            events.push_back({audit.completions[i].event_order, 2, i});
        for (std::size_t i = 0; i < audit.actions.size(); ++i)
            events.push_back({audit.actions[i].event_order, 3, i});
        std::sort(
            events.begin(), events.end(),
            [](const auto &a, const auto &b) { return a.order < b.order; });
        for (std::size_t i = 1; i < events.size(); ++i)
            require(events[i - 1].order < events[i].order,
                    "duplicate event ordering ordinal");
        for (const auto &event : events) {
            if (event.kind == 0) {
                const auto &life = audit.lifecycle[event.index];
                const ModelKey key{life.peer, life.session_id};
                if (life.kind == ModelLifecycleKind::created) {
                    require(!owner.expected_models.contains(key),
                            "requester model created twice");
                    ModelExpectation model;
                    model.plus = expected_pending(n);
                    owner.expected_models.emplace(key, std::move(model));
                } else {
                    require(life.kind == ModelLifecycleKind::released,
                            "invalid model lifecycle kind");
                    require(owner.expected_models.erase(key) == 1,
                            "unknown requester model released");
                    owner.must_release.erase(key);
                }
            } else if (event.kind == 1) {
                const auto &entry = audit.decodes[event.index];
                const ModelKey key{entry.peer, entry.session_id};
                auto found = owner.expected_models.find(key);
                require(found != owner.expected_models.end() &&
                            found->second.open &&
                            !owner.must_release.contains(key),
                        "decode outside a valid open requester model");
                auto &model = found->second;
                const auto reference = model_reference(n, model);
                const auto &decode = entry.decode;
                require((decode.decoded.kind == DecodeKind::one &&
                         decode.decoded.size == 1) ||
                            (decode.decoded.kind == DecodeKind::two &&
                             decode.decoded.size == 2),
                        "noncommitted decode in mutation audit");
                std::vector<snowstorm_oracle::SignedItem> items;
                for (unsigned i = 0; i < decode.decoded.size; ++i) {
                    const auto item = decode.decoded.items[i];
                    require(decode.in_reference_before[i] ==
                                reference.contains(item.item),
                            "reported predecode membership differs from "
                            "independently replayed reference");
                    items.push_back({item.item, static_cast<int>(item.sign)});
                }
                require(snowstorm_oracle::verifies_decode(
                            convert(decode.source_before), decode.index, items,
                            reference),
                        "decode fails independent predecode reference proof");
                const auto wire = wire_anchors.find(
                    {n, entry.peer, entry.session_id, after.tip_context});
                require(wire != wire_anchors.end() &&
                            wire->second.snapshot_seq &&
                            *wire->second.snapshot_seq == entry.snapshot_seq &&
                            !wire->second.inconsistent,
                        "decode has no immutable owned wire snapshot");
                const auto source = wire->second.raw.find(decode.index);
                require(
                    source != wire->second.raw.end(),
                    "decode source index was never supplied by its wire peer");
                const auto encoded_reference =
                    snowstorm_oracle::encode(reference, decode.index,
                                             decode.index + 1)
                        .front();
                require(convert(decode.source_before) ==
                            snowstorm_oracle::subtract(source->second,
                                                       encoded_reference),
                        "decode source differs from actual supplied wire cell "
                        "minus independent reference");
                const auto pinned = snapshots.find(
                    {n, entry.peer, entry.session_id, after.tip_context});
                if (pinned != snapshots.end()) {
                    const auto raw =
                        snowstorm_oracle::encode(pinned->second.raw,
                                                 decode.index, decode.index + 1)
                            .front();
                    const auto encoded =
                        snowstorm_oracle::encode(reference, decode.index,
                                                 decode.index + 1)
                            .front();
                    require(convert(decode.source_before) ==
                                snowstorm_oracle::subtract(raw, encoded),
                            "decode source differs from independently "
                            "reconstructed honest residual");
                    for (const auto &item : items)
                        require((item.sign > 0) ==
                                    pinned->second.raw.contains(item.item),
                                "decoded sign contradicts honest raw snapshot");
                }
                for (const auto &item : items) {
                    if (item.sign > 0) {
                        require(!owner.expected_rejected.contains(item.item) &&
                                    (own.contains(item.item) ||
                                     (!owner.expected_probation.contains(
                                          item.item) &&
                                      !owner.expected_local_rejected.contains(
                                          item.item))),
                                "forbidden speculative positive mutation "
                                "committed");
                        model.decoded_plus.insert(item.item);
                        model.minus.erase(item.item);
                        model.plus.insert(item.item);
                    } else {
                        model.decoded_plus.erase(item.item);
                        model.plus.erase(item.item);
                        model.minus.insert(item.item);
                    }
                }
                for (const auto &item : items)
                    if (item.sign > 0 && !own.contains(item.item)) {
                        for (auto &[other_key, other] : owner.expected_models)
                            if (other_key != key && other.open &&
                                !owner.must_release.contains(other_key) &&
                                !other.plus.contains(item.item) &&
                                !other.minus.contains(item.item))
                                other.plus.insert(item.item);
                    }
                ++traffic.decode_checks;
            } else if (event.kind == 2) {
                const auto &complete = audit.completions[event.index];
                auto found = owner.expected_models.find(
                    {complete.peer, complete.session_id});
                require(found != owner.expected_models.end(),
                        "completion lacks independently tracked model");
                auto &model = found->second;
                if (complete.state == SessionState::done) {
                    require(std::set<ShortId>(complete.reference.begin(),
                                              complete.reference.end()) ==
                                model_reference(n, model),
                            "Done reference differs from independently "
                            "replayed reference");
                    for (auto id : own) {
                        model.decoded_plus.erase(id);
                        model.plus.erase(id);
                    }
                    for (auto it = model.minus.begin();
                         it != model.minus.end();) {
                        if (!own.contains(*it))
                            it = model.minus.erase(it);
                        else
                            ++it;
                    }
                }
                model.open = false;
                model.decoded_plus.clear();
                if (complete.state != SessionState::done &&
                    complete.state != SessionState::root_matched)
                    owner.must_release.insert(
                        {complete.peer, complete.session_id});
            } else {
                const auto &action = audit.actions[event.index];
                if (action.kind == ActionKind::fetch_body)
                    register_fetch(n, FetchBody{action.peer, action.item,
                                                action.fetch_id});
            }
        }
        require(owner.must_release.empty(),
                "required model invalidation/release missing");
        owner.previous_projected = own;
        owner.tip_reset_pending = false;
        require(expected_pending(n) == std::set<ShortId>(after.pending.begin(),
                                                         after.pending.end()),
                "Pending differs from independently reconstructed support");
    }
    void check(NodeId n, const Stats &s) const {
        const auto own = projected_truth(n);
        require(node(n).expected_rejected ==
                    std::set<ShortId>(s.rejected.begin(), s.rejected.end()),
                "rejected IDs differ from independent host outcome ledger");
        if (node(n).expected_rejection_suspension)
            require(
                s.suspended_unadmitted,
                "rejection capacity exhaustion did not suspend speculation");
        require(own == std::set<ShortId>(s.own_ids.begin(), s.own_ids.end()),
                "host/core admitted membership differs");
        std::set<ShortId> candidate_ids;
        std::vector<TxHandle> candidate_bodies;
        std::set<std::pair<TxId, TxHash>> actual_bodies, reported_bodies;
        for (const auto &[hash, body] : node(n).notified_bodies) {
            auto id = short_id(node(n).tip.key, hash);
            if (node(n).expected_rejected.contains(id)) continue;
            actual_bodies.emplace(body->txid(), hash);
            auto confidence =
                std::find_if(s.confidence.begin(), s.confidence.end(),
                             [&](const auto &c) { return c.item == id; });
            if (confidence == s.confidence.end() ||
                confidence->lambda > -static_cast<double>(s.b_tx)) {
                candidate_ids.insert(id);
                candidate_bodies.push_back(body);
            }
        }
        for (const auto &b : s.bodies)
            reported_bodies.emplace(b.txid, b.tx_hash);
        require(actual_bodies == reported_bodies,
                "host/core body inventory differs");
        require(candidate_ids == std::set<ShortId>(s.candidate_ids.begin(),
                                                   s.candidate_ids.end()),
                "candidate membership differs from confidence rule");
        std::sort(candidate_bodies.begin(), candidate_bodies.end(),
                  [](const auto &a, const auto &b) {
                      return std::pair{a->txid(), a->tx_hash()} <
                             std::pair{b->txid(), b->tx_hash()};
                  });
        require(node(n).root(node(n).tip.context, candidate_bodies) ==
                    s.own_root,
                "own root differs from actual candidate bodies");
        require(s.fetches.size() == node(n).expected_fetches.size(),
                "fetch record count differs from independent token ledger");
        for (const auto &fetch : s.fetches) {
            const auto expected = node(n).expected_fetches.find(fetch.fetch_id);
            require(expected != node(n).expected_fetches.end(),
                    "unissued fetch token retained");
            const auto &record = expected->second;
            require(fetch.item == record.item && fetch.peer == record.peer &&
                        fetch.tip_context == node(n).tip.context &&
                        fetch.state == (record.awaiting
                                            ? FetchState::awaiting_admission
                                            : FetchState::in_flight) &&
                        fetch.expected_tx_hash == record.expected_hash,
                    "fetch record differs from independent host state");
        }
        for (const auto &[key, model] : node(n).expected_models) {
            const auto peer = std::find_if(
                s.peers.begin(), s.peers.end(), [&](const auto &p) {
                    return p.peer == key.first && p.session_id == key.second;
                });
            require(peer != s.peers.end(),
                    "live requester model missing from peer diagnostics");
            require(model.open ? peer->state == SessionState::open
                               : (peer->state == SessionState::done ||
                                  peer->state == SessionState::root_matched),
                    "requester model lifecycle state disagrees");
        }
        for (const auto &p : s.peers) {
            auto found = node(n).expected_models.find({p.peer, p.session_id});
            auto ref = own;
            if (found != node(n).expected_models.end()) {
                require(
                    found->second.plus ==
                            std::set<ShortId>(p.plus.begin(), p.plus.end()) &&
                        found->second.minus ==
                            std::set<ShortId>(p.minus.begin(), p.minus.end()),
                    "reported model deltas differ from independent replay");
                ref = model_reference(n, found->second);
            } else
                require(p.plus.empty() && p.minus.empty() &&
                            p.residuals.empty(),
                        "untracked model carries reference state");
            for (const auto &cell : p.residuals) {
                const auto wire =
                    wire_anchors.find({n, p.peer, p.session_id, s.tip_context});
                require(wire != wire_anchors.end() &&
                            wire->second.snapshot_seq &&
                            *wire->second.snapshot_seq == p.snapshot_seq &&
                            !wire->second.inconsistent,
                        "stored residual has no owned wire snapshot");
                const auto supplied = wire->second.raw.find(cell.index);
                require(supplied != wire->second.raw.end() &&
                            supplied->second == convert(cell.raw),
                        "reported raw cell differs from actual supplied "
                        "immutable wire bytes");
                auto pinned =
                    snapshots.find({n, p.peer, p.session_id, s.tip_context});
                if (pinned != snapshots.end())
                    require(convert(cell.raw) == snowstorm_oracle::encode(
                                                     pinned->second.raw,
                                                     cell.index, cell.index + 1)
                                                     .front(),
                            "received cell differs from honest snapshot");
                auto encoded =
                    snowstorm_oracle::encode(ref, cell.index, cell.index + 1);
                require(snowstorm_oracle::subtract(convert(cell.raw),
                                                   encoded.front()) ==
                            convert(cell.residual),
                        "independent residual invariant failed");
            }
            for (const auto &a : p.allocations)
                require(a.live_records <= a.maximum_records,
                        "peer resource cap exceeded");
        }
        for (const auto &a : s.global_allocations)
            require(a.live_records <= a.maximum_records,
                    "global resource cap exceeded");
    }
    void call(NodeId n, const std::string &name,
              const std::function<Actions(SnowstormNode &)> &fn,
              Bytes input = {}) {
        if (!full_observation()) {
            record(1, n, Bytes(name.begin(), name.end()));
            record(2, n, std::move(input));
            Actions actions = fn(*node(n).core);
            ++traffic.calls;
            if (action_observer)
                callback([&] { action_observer(n, now, name, actions); });
            for (const auto &action : actions) {
                if (const auto *fetch = std::get_if<FetchBody>(&action))
                    register_fetch(n, *fetch);
                if (options.retain_transcript)
                    transcript.action(n, now, action);
                std::visit([&](const auto &value) { dispatch(n, value); },
                           action);
            }
            return;
        }
        auto before = node(n).core->stats();
        record(1, n, Bytes(name.begin(), name.end()));
        record(2, n, std::move(input));
        Actions actions = fn(*node(n).core);
        auto after = node(n).core->stats();
        ++traffic.calls;
        require(actions.size() == after.last_call.actions.size(),
                "returned actions and action audit counts differ");
        for (std::size_t i = 0; i < actions.size(); ++i) {
            const auto &reported = after.last_call.actions[i];
            std::visit(
                [&](const auto &actual) {
                    using T = std::decay_t<decltype(actual)>;
                    bool equal = false;
                    if constexpr (std::is_same_v<T, Send>)
                        equal = reported.kind == ActionKind::send &&
                                reported.peer == actual.peer &&
                                reported.bytes == actual.bytes;
                    else if constexpr (std::is_same_v<T, FetchBody>)
                        equal = reported.kind == ActionKind::fetch_body &&
                                reported.peer == actual.peer &&
                                reported.item == actual.short_id &&
                                reported.fetch_id == actual.fetch_id;
                    else if constexpr (std::is_same_v<T, Frozen>)
                        equal = reported.kind == ActionKind::frozen &&
                                reported.root == actual.root &&
                                reported.txids == actual.txids;
                    else if constexpr (std::is_same_v<T, PeerMisbehaved>)
                        equal = reported.kind == ActionKind::misbehaved &&
                                reported.peer == actual.peer &&
                                reported.reason == actual.reason;
                    else if constexpr (std::is_same_v<T, ScheduleTimer>)
                        equal = reported.kind == ActionKind::timer &&
                                reported.at == actual.at;
                    require(equal, "returned action differs from same-position "
                                   "action audit");
                },
                actions[i]);
        }
        replay_reference_events(n, after);
        check(n, after);
        for (const auto &p : after.peers)
            traffic.residual_checks += p.residuals.size();
        for (const auto &a : after.last_call.completions) {
            Completion c{n, now, a, false, {}, {}, {}};
            auto it =
                snapshots.find({n, a.peer, a.session_id, after.tip_context});
            if (it != snapshots.end()) {
                c.honest_source = true;
                c.raw = it->second.raw;
                c.candidate = it->second.candidate;
                c.candidate_root = it->second.root;
                std::set<ShortId> actual(a.reference.begin(),
                                         a.reference.end());
                if (a.state == SessionState::done)
                    require(actual == c.raw,
                            "Done differs from honest raw snapshot");
                if (a.state == SessionState::root_matched) {
                    require(a.root == c.candidate_root,
                            "RootMatched differs from honest candidate root");
                    require(std::set<ShortId>(
                                a.candidate_ids_at_completion.begin(),
                                a.candidate_ids_at_completion.end()) ==
                                c.candidate,
                            "RootMatched differs from honest candidate set");
                }
            }
            if (options.retain_completions) completions.push_back(std::move(c));
        }
        for (const auto &w : after.last_call.waves)
            require(w.ended <= w.wave.deadline, "wave ended after deadline");
        Observation observation{n,     now,    name, std::move(before),
                                after, actions};
        if (observer) callback([&] { observer(observation); });
        if (action_observer)
            callback([&] { action_observer(n, now, name, actions); });
        if (options.retain_observations)
            observations.push_back(std::move(observation));
        for (const auto &a : actions) {
            if (options.retain_transcript) transcript.action(n, now, a);
            std::visit([&](const auto &v) { dispatch(n, v); }, a);
        }
    }
    static bool same_ranges(const std::vector<Range> &a,
                            const std::vector<Range> &b) {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i)
            if (a[i].begin != b[i].begin || a[i].end != b[i].end) return false;
        return true;
    }
    void record_wire_send(NodeId n, const Send &send) {
        if (!full_observation()) return;
        const auto parsed = parse(send.bytes, node(n).core->stats().limits);
        require(parsed.message.has_value(),
                "node emitted unparseable wire bytes");
        if (const auto *request = std::get_if<ReconReq>(&*parsed.message)) {
            require(request->tip_context == node(n).tip.context,
                    "node emitted request for stale tip");
            const SnapshotKey key{n, send.peer, request->session_id,
                                  request->tip_context};
            for (auto it = wire_anchors.begin(); it != wire_anchors.end();) {
                if (std::get<0>(it->first) == n &&
                    std::get<1>(it->first) == send.peer && it->first != key)
                    it = wire_anchors.erase(it);
                else
                    ++it;
            }
            auto &anchor = wire_anchors[key];
            if (anchor.request && *anchor.request == request->request_id)
                require(same_ranges(anchor.ranges, request->ranges),
                        "logical request changed its ranges");
            else {
                require(!anchor.request ||
                            request->request_id > *anchor.request,
                        "request identity went backwards");
                anchor.request = request->request_id;
                anchor.ranges = request->ranges;
            }
        } else if (const auto *close =
                       std::get_if<ReconClose>(&*parsed.message)) {
            const auto found = wire_anchors.find(
                {n, send.peer, close->session_id, close->tip_context});
            if (found != wire_anchors.end()) found->second.request.reset();
        }
    }
    void anchor_wire_response(NodeId n, PeerId peer, ByteSpan bytes) {
        if (!full_observation()) return;
        const auto parsed = parse(bytes, node(n).core->stats().limits);
        if (!parsed.message) return;
        const auto *response = std::get_if<ReconSymbols>(&*parsed.message);
        if (!response || response->status != SymbolsStatus::normal ||
            response->tip_context != node(n).tip.context)
            return;
        const auto found = wire_anchors.find(
            {n, peer, response->session_id, response->tip_context});
        if (found == wire_anchors.end()) return;
        auto &anchor = found->second;
        if (!anchor.request || *anchor.request != response->request_id ||
            !same_ranges(anchor.ranges, response->ranges))
            return;
        std::size_t cell_count = 0;
        for (const auto &range : response->ranges) {
            if (range.end < range.begin ||
                range.end - range.begin > response->cells.size() - cell_count)
                return;
            cell_count += static_cast<std::size_t>(range.end - range.begin);
        }
        if (cell_count != response->cells.size()) return;
        if (anchor.snapshot_seq &&
            *anchor.snapshot_seq != response->snapshot_seq)
            anchor.inconsistent = true;
        else if (!anchor.snapshot_seq)
            anchor.snapshot_seq = response->snapshot_seq;
        std::size_t at = 0;
        for (const auto &range : response->ranges)
            for (auto index = range.begin; index < range.end; ++index) {
                const auto raw = convert(response->cells[at++]);
                const auto [cell, inserted] = anchor.raw.emplace(index, raw);
                if (!inserted && cell->second != raw)
                    anchor.inconsistent = true;
            }
        require(anchor.raw.size() <= 18 * node(n).max_set_size + 224,
                "wire raw anchor exceeded maximum declared session budget");
        if (anchor.inconsistent &&
            node(n).expected_models.contains({peer, response->session_id}))
            node(n).must_release.insert({peer, response->session_id});
    }
    void snapshot(NodeId responder, PeerId responder_peer, ByteSpan bytes) {
        if (!full_observation()) return;
        auto &ep = node(responder).peers.at(responder_peer);
        if (ep.wire) return;
        auto st = node(responder).core->stats();
        auto parsed = parse(bytes, st.limits);
        if (!parsed.message) return;
        auto req = std::get_if<ReconReq>(&*parsed.message);
        if (!req || !req->open ||
            req->tip_context != node(responder).tip.context ||
            req->tip_context != node(ep.remote).tip.context)
            return;
        SnapshotKey key{ep.remote, ep.counterpart, req->session_id,
                        req->tip_context};
        if (snapshots.contains(key)) return;
        for (auto it = snapshots.begin(); it != snapshots.end();) {
            if (std::get<0>(it->first) == ep.remote &&
                std::get<1>(it->first) == ep.counterpart &&
                std::get<3>(it->first) == req->tip_context) {
                if (std::get<2>(it->first) > req->session_id) return;
                it = snapshots.erase(it);
            } else
                ++it;
        }
        Snapshot s;
        s.raw = projected_truth(responder);
        std::vector<TxHandle> candidate;
        for (const auto &[h, b] : node(responder).notified_bodies) {
            auto id = short_id(node(responder).tip.key, h);
            if (node(responder).expected_rejected.contains(id)) continue;
            auto ci = std::find_if(st.confidence.begin(), st.confidence.end(),
                                   [&](const auto &c) { return c.item == id; });
            if (ci == st.confidence.end() ||
                ci->lambda > -static_cast<double>(st.b_tx)) {
                s.candidate.insert(id);
                candidate.push_back(b);
            }
        }
        std::sort(candidate.begin(), candidate.end(),
                  [](const auto &a, const auto &b) {
                      return std::pair{a->txid(), a->tx_hash()} <
                             std::pair{b->txid(), b->tx_hash()};
                  });
        s.root = node(responder).root(node(responder).tip.context, candidate);
        snapshots.emplace(key, std::move(s));
    }
    void deliver(NodeId n, PeerId p, Bytes bytes,
                 std::optional<DeliveryObservation> supplied_packet = {}) {
        auto observed = supplied_packet.value_or(DeliveryObservation{});
        if (!supplied_packet) {
            observed = packet(n, p, true);
            delivery(observed, DeliveryStage::offered,
                     ApplicationDisposition::not_applicable, bytes);
        }
        auto it = node(n).peers.find(p);
        if (it == node(n).peers.end() || !it->second.active) {
            delivery(observed, DeliveryStage::arrived,
                     ApplicationDisposition::canceled, bytes);
            ++traffic.dropped;
            record(4, n, bytes);
            return;
        }
        ++traffic.delivered;
        delivery(observed, DeliveryStage::arrived,
                 ApplicationDisposition::delivered_to_core, bytes);
        record(3, n, bytes);
        snapshot(n, p, bytes);
        anchor_wire_response(n, p, bytes);
        Bytes input;
        put(input, p);
        input.insert(input.end(), bytes.begin(), bytes.end());
        call(
            n, "message",
            [&](auto &core) { return core.on_message(p, bytes, now); },
            std::move(input));
    }
    void dispatch(NodeId n, const Send &s) {
        record_wire_send(n, s);
        ++traffic.sent;
        traffic.bytes += s.bytes.size();
        auto observed = packet(n, s.peer, false);
        delivery(observed, DeliveryStage::offered,
                 ApplicationDisposition::not_applicable, s.bytes);
        auto it = node(n).peers.find(s.peer);
        if (it == node(n).peers.end() || !it->second.active) {
            delivery(observed, DeliveryStage::disconnected,
                     ApplicationDisposition::canceled, s.bytes);
            ++traffic.dropped;
            return;
        }
        const auto ep = it->second;
        TransportDecision decision;
        if (transport_policy) {
            decision =
                transport({n, s.peer, false, n,
                           ep.wire ? std::optional<NodeId>{}
                                   : std::optional<NodeId>{ep.remote},
                           ep.wire ? std::optional<PeerId>{}
                                   : std::optional<PeerId>{ep.counterpart},
                           now, s.bytes});
        } else {
            require(ep.link.loss_per_million <= 1000000 && ep.link.delay >= 0 &&
                        ep.link.jitter >= 0,
                    "invalid link");
            decision.drop = random() % 1000000 < ep.link.loss_per_million;
            if (!decision.drop) {
                const Time jitter =
                    ep.link.jitter
                        ? static_cast<Time>(
                              random() %
                              (static_cast<std::uint64_t>(ep.link.jitter) + 1))
                        : 0;
                decision.delay = later(ep.link.delay, jitter);
            }
        }
        const auto at = later(now, decision.delay);
        if (decision.drop) {
            delivery(observed, DeliveryStage::policy_drop,
                     ApplicationDisposition::not_applicable, s.bytes);
            ++traffic.dropped;
            record(4, n, s.bytes);
            return;
        }
        delivery(observed, DeliveryStage::scheduled,
                 ApplicationDisposition::not_applicable, s.bytes, at);
        if (ep.wire)
            enqueue(at, [this, n, p = s.peer, bytes = s.bytes, observed] {
                auto it = node(n).peers.find(p);
                if (it == node(n).peers.end() || !it->second.active) {
                    delivery(observed, DeliveryStage::arrived,
                             ApplicationDisposition::canceled, bytes);
                    ++traffic.dropped;
                    return;
                }
                ++traffic.delivered;
                delivery(observed, DeliveryStage::arrived,
                         it->second.handler
                             ? ApplicationDisposition::served
                             : ApplicationDisposition::not_applicable,
                         bytes);
                if (it->second.handler)
                    for (auto reply : it->second.handler({n, p, now, bytes})) {
                        const auto ready = later(now, reply.delay);
                        if (!transport_policy) {
                            auto reverse = packet(n, p, true);
                            reverse.parent_packet_id = observed.packet_id;
                            delivery(reverse, DeliveryStage::offered,
                                     ApplicationDisposition::not_applicable,
                                     reply.bytes);
                            delivery(reverse, DeliveryStage::scheduled,
                                     ApplicationDisposition::not_applicable,
                                     reply.bytes, ready);
                            enqueue(ready,
                                    [this, n, p, b = std::move(reply.bytes),
                                     reverse] { deliver(n, p, b, reverse); });
                            continue;
                        }
                        enqueue(ready, [this, n, p, b = std::move(reply.bytes),
                                        parent = observed.packet_id] {
                            auto reverse = packet(n, p, true);
                            reverse.parent_packet_id = parent;
                            delivery(reverse, DeliveryStage::offered,
                                     ApplicationDisposition::not_applicable, b);
                            TransportDecision decision;
                            if (transport_policy)
                                decision = transport(
                                    {n, p, true, std::nullopt, n, p, now, b});
                            const auto arrival = later(now, decision.delay);
                            if (decision.drop) {
                                delivery(reverse, DeliveryStage::policy_drop,
                                         ApplicationDisposition::not_applicable,
                                         b);
                                ++traffic.dropped;
                                record(4, n, b);
                                return;
                            }
                            delivery(reverse, DeliveryStage::scheduled,
                                     ApplicationDisposition::not_applicable, b,
                                     arrival);
                            enqueue(arrival,
                                    [this, n, p, b = std::move(b), reverse] {
                                        deliver(n, p, b, reverse);
                                    });
                        });
                    }
            });
        else
            enqueue(at,
                    [this, remote = ep.remote, p = ep.counterpart, b = s.bytes,
                     observed] { deliver(remote, p, b, observed); });
    }
    ApplicationDisposition body_ownership(const BodyJob &job) const {
        const auto &fetch = job.fetch;
        if (now >= fetch.deadline) return ApplicationDisposition::expired;
        if (job.terminal ||
            node(fetch.requester).generation != job.requester_generation ||
            node(fetch.requester).tip.context != fetch.tip)
            return ApplicationDisposition::stale;
        const auto endpoint =
            node(fetch.requester).peers.find(fetch.donor_peer);
        if (endpoint == node(fetch.requester).peers.end() ||
            !endpoint->second.active)
            return ApplicationDisposition::canceled;
        if (fetch.donor) {
            const auto remote =
                node(*fetch.donor).peers.find(*job.donor_local_peer);
            if (remote == node(*fetch.donor).peers.end() ||
                !remote->second.active ||
                remote->second.remote != fetch.requester)
                return ApplicationDisposition::canceled;
        }
        const auto token =
            node(fetch.requester).expected_fetches.find(fetch.token);
        if (token == node(fetch.requester).expected_fetches.end() ||
            token->second.awaiting)
            return ApplicationDisposition::stale;
        return ApplicationDisposition::not_applicable;
    }
    void validate_body_plan(const BodyJob &job, BodyResponsePlan &plan) {
        require(body_service_policy.has_value(),
                "body service policy disappeared during operation");
        if (plan.bytes.size() > body_service_policy->max_payload_bytes ||
            plan.result.result_delay != 0 || plan.service_delay < 0 ||
            plan.result.admission_delay < 0)
            throw std::invalid_argument("invalid bounded body service plan");
        (void)later(now, plan.service_delay);
        (void)later(now, plan.result.admission_delay);
        auto &rule = plan.result;
        if (static_cast<unsigned>(rule.status) >
                static_cast<unsigned>(BodyStatus::local_rejected) ||
            static_cast<unsigned>(rule.binding) >
                static_cast<unsigned>(BodyBinding::unbound))
            throw std::invalid_argument("invalid body service outcome enum");
        if (!rule.expected_tx_hash && rule.body)
            rule.expected_tx_hash = rule.body->tx_hash();
        if (rule.status == BodyStatus::admitted) {
            if (!rule.body)
                throw std::invalid_argument(
                    "admitted body service outcome lacks actual body");
            if (short_id(job.fetch.key, rule.body->tx_hash()) !=
                job.fetch.item) {
                rule.status = BodyStatus::invalid;
                rule.binding = BodyBinding::unbound;
                rule.deliver_admission = false;
            } else if (rule.expected_tx_hash != rule.body->tx_hash())
                throw std::invalid_argument(
                    "body service expected hash differs from actual admitted "
                    "body");
        }
        const bool requires_bound = rule.status == BodyStatus::admitted ||
                                    rule.status == BodyStatus::local_rejected ||
                                    (rule.status == BodyStatus::invalid &&
                                     rule.binding == BodyBinding::matched);
        if (requires_bound &&
            (rule.binding != BodyBinding::matched || !rule.expected_tx_hash ||
             short_id(job.fetch.key, *rule.expected_tx_hash) != job.fetch.item))
            throw std::invalid_argument(
                "body service outcome is not bound to its request");
    }
    void body_response_ready(const std::shared_ptr<BodyJob> &job,
                             BodyResponsePlan plan) {
        if (body_ownership(*job) != ApplicationDisposition::not_applicable)
            return;
        const auto &fetch = job->fetch;
        TransportInput input;
        if (fetch.donor) {
            input.local_node = *fetch.donor;
            input.local_peer = *job->donor_local_peer;
            input.sender = *fetch.donor;
            input.receiver = fetch.requester;
            input.receiver_peer = fetch.donor_peer;
            job->response_packet = packet(input.local_node, input.local_peer,
                                          false, TrafficClass::body_response,
                                          fetch.token, fetch.item, fetch.tip);
        } else {
            input.local_node = fetch.requester;
            input.local_peer = fetch.donor_peer;
            input.from_wire_peer = true;
            input.receiver = fetch.requester;
            input.receiver_peer = fetch.donor_peer;
            job->response_packet = packet(fetch.requester, fetch.donor_peer,
                                          true, TrafficClass::body_response,
                                          fetch.token, fetch.item, fetch.tip);
        }
        job->response_packet.parent_packet_id = job->request_packet.packet_id;
        input.now = now;
        input.bytes = plan.bytes;
        input.traffic_class = TrafficClass::body_response;
        input.fetch_id = fetch.token;
        input.tip_context = fetch.tip;
        delivery(job->response_packet, DeliveryStage::offered,
                 ApplicationDisposition::not_applicable, plan.bytes);
        const auto decision = transport(input);
        const auto arrival = later(now, decision.delay);
        if (!decision.drop && arrival < fetch.deadline &&
            plan.result.status == BodyStatus::admitted &&
            plan.result.deliver_admission)
            (void)later(arrival, plan.result.admission_delay);
        if (decision.drop) {
            delivery(job->response_packet, DeliveryStage::policy_drop,
                     ApplicationDisposition::not_applicable, plan.bytes);
            return;
        }
        delivery(job->response_packet, DeliveryStage::scheduled,
                 ApplicationDisposition::not_applicable, plan.bytes, arrival);
        enqueue(arrival, [this, job, plan = std::move(plan)] {
            const auto disposition = body_ownership(*job);
            delivery(job->response_packet, DeliveryStage::arrived,
                     disposition == ApplicationDisposition::not_applicable
                         ? ApplicationDisposition::served
                         : disposition,
                     plan.bytes);
            if (disposition != ApplicationDisposition::not_applicable) return;
            job->terminal = true;
            complete_body_result(
                job->fetch.requester,
                {job->fetch.donor_peer, job->fetch.item, job->fetch.token},
                plan.result, job->requester_generation, job->response_packet,
                false, job);
        });
    }
    void dispatch_body_service(NodeId n, const FetchBody &fetch) {
        const auto deadline = later(now, body_service_policy->timeout);
        auto job = std::make_shared<BodyJob>(active_body_jobs);
        job->fetch = {n,
                      fetch.peer,
                      {},
                      fetch.short_id,
                      fetch.fetch_id,
                      node(n).tip.context,
                      node(n).tip.key,
                      now,
                      deadline};
        job->requester_generation = node(n).generation;
        const auto endpoint = node(n).peers.find(fetch.peer);
        if (endpoint != node(n).peers.end() && !endpoint->second.wire) {
            job->fetch.donor = endpoint->second.remote;
            job->donor_local_peer = endpoint->second.counterpart;
        }
        // This deadline alone owns the terminal fallback, including canceled
        // tokens.
        enqueue(deadline, [this, job] {
            if (job->terminal) return;
            job->terminal = true;
            auto outcome = job->response_packet;
            if (!outcome.packet_id) {
                outcome.local_node = job->fetch.requester;
                outcome.local_peer = job->fetch.donor_peer;
                outcome.connection_generation = job->fetch.donor_peer;
                outcome.receiver = job->fetch.requester;
                outcome.sender = job->fetch.donor;
                outcome.parent_packet_id = job->request_packet.packet_id;
                outcome.fetch_id = job->fetch.token;
                outcome.item = job->fetch.item;
                outcome.tip = job->fetch.tip;
            }
            outcome.traffic_class = TrafficClass::body_result;
            delivery(outcome, DeliveryStage::terminal_timeout,
                     ApplicationDisposition::expired, {}, {},
                     BodyStatus::not_found);
            BodyRule result;
            result.status = BodyStatus::not_found;
            result.result_delay = 0;
            result.deliver_admission = false;
            complete_body_result(
                job->fetch.requester,
                {job->fetch.donor_peer, job->fetch.item, job->fetch.token},
                result, job->requester_generation, outcome, true, job);
        });
        auto bytes = callback(
            [&] { return body_service_policy->request_bytes(job->fetch); });
        if (bytes.size() > body_service_policy->max_payload_bytes)
            throw std::invalid_argument(
                "body request payload exceeds configured cap");
        job->request_packet =
            packet(n, fetch.peer, false, TrafficClass::body_request,
                   fetch.fetch_id, fetch.short_id, job->fetch.tip);
        delivery(job->request_packet, DeliveryStage::offered,
                 ApplicationDisposition::not_applicable, bytes);
        const auto ownership = body_ownership(*job);
        if (ownership != ApplicationDisposition::not_applicable) {
            delivery(job->request_packet, DeliveryStage::disconnected,
                     ownership, bytes);
            return;
        }
        const TransportInput input{n,
                                   fetch.peer,
                                   false,
                                   n,
                                   job->fetch.donor,
                                   job->donor_local_peer,
                                   now,
                                   bytes,
                                   TrafficClass::body_request,
                                   fetch.fetch_id,
                                   job->fetch.tip};
        const auto decision = transport(input);
        const auto arrival = later(now, decision.delay);
        if (decision.drop) {
            delivery(job->request_packet, DeliveryStage::policy_drop,
                     ApplicationDisposition::not_applicable, bytes);
            return;
        }
        delivery(job->request_packet, DeliveryStage::scheduled,
                 ApplicationDisposition::not_applicable, bytes, arrival);
        enqueue(arrival, [this, job, bytes = std::move(bytes)] {
            const auto disposition = body_ownership(*job);
            delivery(job->request_packet, DeliveryStage::arrived,
                     disposition == ApplicationDisposition::not_applicable
                         ? ApplicationDisposition::served
                         : disposition,
                     bytes);
            if (disposition != ApplicationDisposition::not_applicable) return;
            TxHandle available;
            if (job->fetch.donor)
                for (const auto &[hash, body] : node(*job->fetch.donor).bodies)
                    if (short_id(job->fetch.key, hash) == job->fetch.item) {
                        available = body;
                        break;
                    }
            auto response = callback([&] {
                return body_service_policy->serve({job->fetch, now, available});
            });
            validate_body_plan(*job, response);
            const auto ready = later(now, response.service_delay);
            enqueue(ready,
                    [this, job, response = std::move(response)]() mutable {
                        body_response_ready(job, std::move(response));
                    });
        });
    }
    void dispatch(NodeId n, const FetchBody &f) {
        if (body_service_policy) {
            dispatch_body_service(n, f);
            return;
        }
        BodyRule rule;
        auto ri = rules.find({n, f.peer, f.short_id});
        if (ri != rules.end())
            rule = ri->second;
        else {
            auto ei = node(n).peers.find(f.peer);
            if (ei != node(n).peers.end() && ei->second.active &&
                !ei->second.wire)
                for (const auto &[h, b] : node(ei->second.remote).bodies)
                    if (short_id(node(n).tip.key, h) == f.short_id) {
                        rule.body = b;
                        break;
                    }
            if (!rule.body) rule.status = BodyStatus::not_found;
        }
        // Host validates the requested identity before any admitted/matched
        // outcome.
        if (rule.status == BodyStatus::admitted) {
            require(bool(rule.body), "admitted body result lacks body");
            if (short_id(node(n).tip.key, rule.body->tx_hash()) != f.short_id) {
                rule.status = BodyStatus::invalid;
                rule.binding = BodyBinding::unbound;
                rule.deliver_admission = false;
            }
        }
        auto generation = node(n).generation;
        DeliveryObservation outcome;
        outcome.local_node = n;
        outcome.local_peer = f.peer;
        outcome.connection_generation = f.peer;
        outcome.receiver = n;
        const auto donor = node(n).peers.find(f.peer);
        if (donor != node(n).peers.end() && !donor->second.wire)
            outcome.sender = donor->second.remote;
        outcome.fetch_id = f.fetch_id;
        outcome.item = f.short_id;
        outcome.tip = node(n).tip.context;
        enqueue(later(now, rule.result_delay),
                [this, n, f, rule, generation, outcome] {
                    complete_body_result(n, f, rule, generation, outcome);
                });
    }
    void complete_body_result(NodeId n, const FetchBody &f,
                              const BodyRule &rule, std::uint64_t generation,
                              DeliveryObservation outcome, bool timeout = false,
                              std::shared_ptr<BodyJob> operation = {}) {
        auto expected = rule.expected_tx_hash;
        if (!expected && rule.body) expected = rule.body->tx_hash();
        BodyResult result{f.fetch_id, rule.status, rule.binding, expected};
        auto &owner = node(n);
        auto live = owner.expected_fetches.find(f.fetch_id);
        bool accepted_result = live != owner.expected_fetches.end() &&
                               live->second.generation == owner.generation &&
                               !live->second.awaiting;
        if (accepted_result) {
            const auto fetch = live->second;
            const bool required_bound =
                result.status == BodyStatus::admitted ||
                result.status == BodyStatus::local_rejected ||
                (result.status == BodyStatus::invalid &&
                 result.binding == BodyBinding::matched);
            const bool valid_enums =
                static_cast<unsigned>(result.status) <=
                    static_cast<unsigned>(BodyStatus::local_rejected) &&
                static_cast<unsigned>(result.binding) <=
                    static_cast<unsigned>(BodyBinding::unbound);
            const bool valid_payload =
                valid_enums &&
                (!required_bound ||
                 (result.binding == BodyBinding::matched && expected &&
                  short_id(fetch.key, *expected) == fetch.item));
            accepted_result = valid_payload;
            if (valid_payload && !projected_truth(n).contains(fetch.item)) {
                if (result.status == BodyStatus::invalid &&
                    result.binding == BodyBinding::matched) {
                    if (owner.expected_rejected.size() <
                        8 * owner.max_set_size + 128)
                        owner.expected_rejected.insert(fetch.item);
                    else
                        owner.expected_rejection_suspension = true;
                }
                const auto cap = 8 * owner.max_set_size + 128;
                const auto mark = [&](auto &set, const auto &value) {
                    if (set.contains(value)) return;
                    if (set.size() < cap)
                        set.insert(value);
                    else
                        owner.expected_rejection_suspension = true;
                };
                if (result.status == BodyStatus::invalid &&
                    result.binding == BodyBinding::matched) {
                    owner.expected_probation.erase(fetch.item);
                    revoke_assumption(n, fetch.item);
                } else if (result.status == BodyStatus::not_found ||
                           (result.status == BodyStatus::invalid &&
                            result.binding == BodyBinding::unbound)) {
                    mark(owner.expected_unavailable,
                         std::pair{fetch.peer, fetch.item});
                    mark(owner.expected_probation, fetch.item);
                    revoke_assumption(n, fetch.item);
                } else if (result.status == BodyStatus::local_rejected) {
                    mark(owner.expected_local_rejected, fetch.item);
                    owner.expected_probation.erase(fetch.item);
                    revoke_assumption(n, fetch.item);
                }
                if (result.status == BodyStatus::admitted) {
                    owner.expected_probation.erase(fetch.item);
                    live->second.awaiting = true;
                    live->second.expected_hash = expected;
                } else
                    owner.expected_fetches.erase(live);
            } else if (valid_payload)
                owner.expected_fetches.erase(live);
            if (owner.expected_rejection_suspension)
                for (auto it = owner.expected_fetches.begin();
                     it != owner.expected_fetches.end();) {
                    if (!it->second.awaiting)
                        it = owner.expected_fetches.erase(it);
                    else
                        ++it;
                }
        }
        std::optional<std::uint64_t> admission_version;
        if (accepted_result && result.status == BodyStatus::admitted &&
            rule.body) {
            require(expected == rule.body->tx_hash(),
                    "admitted result hash differs from actually admitted body");
            const auto hash = rule.body->tx_hash();
            owner.bodies[hash] = rule.body;
            admission_version = ++owner.body_versions[hash];
            auto notification = outcome;
            notification.bytes = {};
            notification.byte_count = 0;
            notification.scheduled_arrival.reset();
            owner.pending_notifications[hash] = {generation, *admission_version,
                                                 std::move(notification)};
        }
        Bytes input;
        put(input, f.peer);
        put(input, f.short_id);
        put(input, f.fetch_id);
        input.push_back(static_cast<Byte>(result.status));
        input.push_back(static_cast<Byte>(result.binding));
        if (expected)
            input.insert(input.end(), expected->begin(), expected->end());
        call(
            n, "body_result",
            [&](auto &c) {
                return c.on_tx_bodies_result(f.peer, f.short_id, result, now);
            },
            std::move(input));
        outcome.traffic_class = TrafficClass::body_result;
        delivery(outcome, DeliveryStage::result_callback,
                 accepted_result
                     ? (timeout ? ApplicationDisposition::expired
                                : ApplicationDisposition::delivered_to_core)
                     : ApplicationDisposition::stale,
                 {}, {}, result.status);
        if (accepted_result && rule.status == BodyStatus::admitted &&
            rule.deliver_admission && rule.body)
            enqueue(later(now, rule.admission_delay),
                    [this, n, rule, generation, admission_version, operation] {
                        const auto hash = rule.body->tx_hash();
                        if (node(n).generation == generation &&
                            admission_version &&
                            node(n).body_versions[hash] == *admission_version &&
                            node(n).bodies.contains(hash)) {
                            admit(n, rule.body);
                        }
                    });
    }
    void dispatch(NodeId n, const ScheduleTimer &t) {
        require(t.at >= now, "node scheduled past timer");
        enqueue(t.at, [this, n] {
            call(n, "timer", [&](auto &c) { return c.on_timer(now); });
        });
    }
    void dispatch(NodeId n, const Frozen &f) {
        if (!full_observation()) return;
        const auto stats = node(n).core->stats();
        std::vector<TxHandle> candidate;
        std::set<TxId> txids;
        for (const auto &[hash, body] : node(n).notified_bodies) {
            const auto id = short_id(node(n).tip.key, hash);
            if (node(n).expected_rejected.contains(id)) continue;
            const auto confidence =
                std::find_if(stats.confidence.begin(), stats.confidence.end(),
                             [&](const auto &c) { return c.item == id; });
            if (confidence == stats.confidence.end() ||
                confidence->lambda > -static_cast<double>(stats.b_tx)) {
                candidate.push_back(body);
                txids.insert(body->txid());
            }
        }
        std::sort(candidate.begin(), candidate.end(),
                  [](const auto &a, const auto &b) {
                      return std::pair{a->txid(), a->tx_hash()} <
                             std::pair{b->txid(), b->tx_hash()};
                  });
        require(f.root == node(n).root(node(n).tip.context, candidate),
                "Frozen root differs from candidate body truth");
        require(
            f.txids == std::vector<TxId>(txids.begin(), txids.end()),
            "Frozen txids are not exact sorted unique candidate body TxIDs");
    }
    void dispatch(NodeId, const PeerMisbehaved &) {}
    void admit(NodeId n, TxHandle body) {
        require(bool(body), "null body");
        auto hash = body->tx_hash();
        auto id = short_id(node(n).tip.key, hash);
        const bool rejected = node(n).expected_rejected.contains(id);
        std::optional<DeliveryObservation> notification;
        const auto pending = node(n).pending_notifications.find(hash);
        if (pending != node(n).pending_notifications.end()) {
            if (pending->second.generation == node(n).generation &&
                pending->second.incarnation == node(n).body_versions[hash])
                notification = pending->second.observation;
            node(n).pending_notifications.erase(pending);
        }
        node(n).bodies[hash] = body;
        node(n).notified_bodies[hash] = body;
        ++node(n).body_versions[hash];
        if (!rejected) {
            node(n).expected_probation.erase(id);
            node(n).expected_local_rejected.erase(id);
            for (auto it = node(n).expected_fetches.begin();
                 it != node(n).expected_fetches.end();) {
                if (it->second.item == id &&
                    (!it->second.awaiting || it->second.expected_hash == hash))
                    it = node(n).expected_fetches.erase(it);
                else
                    ++it;
            }
        }
        Bytes b(hash.begin(), hash.end());
        auto txid = body->txid();
        b.insert(b.end(), txid.begin(), txid.end());
        call(
            n, "admit", [&](auto &c) { return c.on_tx_admitted(body, now); },
            std::move(b));
        if (notification) {
            notification->traffic_class = TrafficClass::body_admission;
            delivery(*notification, DeliveryStage::admission_callback,
                     ApplicationDisposition::delivered_to_core, {}, {},
                     BodyStatus::admitted);
        }
        if (rejected && full_observation())
            require(node(n).core->stats().last_api_error == Error::rejected_id,
                    "late admission under independently rejected ID lacks "
                    "RejectedId");
    }
};
Host::Host(std::uint64_t seed, HostOptions o)
    : impl_(std::make_unique<Impl>(seed, o)) {}
Host::Host(std::uint64_t seed, std::size_t n, std::uint64_t m, HostOptions o)
    : Host(seed, o) {
    for (std::size_t i = 0; i < n; ++i)
        add_node(default_config(m, seed + i), default_tip());
}
Host::~Host() = default;
NodeId Host::add_node(Config config, TipParams tip) {
    impl_->ensure_mutable();
    auto n = impl_->nodes.size();
    auto p = std::make_unique<Impl::Node>();
    auto supplied_root = config.root_fn;
    if (supplied_root)
        config.root_fn = [supplied_root](const TipContext &context,
                                         std::span<const TxHandle> bodies) {
            require(
                std::is_sorted(bodies.begin(), bodies.end(),
                               [](const auto &a, const auto &b) {
                                   return std::pair{a->txid(), a->tx_hash()} <
                                          std::pair{b->txid(), b->tx_hash()};
                               }),
                "RootFn input is not canonical txid/tx_hash order");
            return supplied_root(context, bodies);
        };
    p->root = config.root_fn;
    p->max_set_size = config.max_set_size;
    p->core = std::make_unique<SnowstormNode>(config);
    impl_->nodes.push_back(std::move(p));
    change_tip(n, std::move(tip));
    return n;
}
Connection Host::connect(NodeId a, NodeId b, LinkOptions l) {
    impl_->ensure_mutable();
    Connection c{a, b, impl_->next_peer++, impl_->next_peer++};
    impl_->node(a).peers.emplace(
        c.left_peer, Impl::Endpoint{true, false, b, c.right_peer, l, {}});
    impl_->node(b).peers.emplace(
        c.right_peer, Impl::Endpoint{true, false, a, c.left_peer, l, {}});
    impl_->call(
        a, "connect",
        [&](auto &x) {
            return x.on_peer_connected(c.left_peer, {1, l.initial_rtt}, now());
        },
        [&] {
            Bytes b;
            put(b, c.left_peer);
            put(b, l.initial_rtt);
            b.push_back(1);
            return b;
        }());
    impl_->call(
        b, "connect",
        [&](auto &x) {
            return x.on_peer_connected(c.right_peer, {1, l.initial_rtt}, now());
        },
        [&] {
            Bytes b;
            put(b, c.right_peer);
            put(b, l.initial_rtt);
            b.push_back(1);
            return b;
        }());
    return c;
}
PeerId Host::connect_wire(NodeId n, WireHandler h, LinkOptions l) {
    impl_->ensure_mutable();
    auto p = impl_->next_peer++;
    impl_->node(n).peers.emplace(
        p, Impl::Endpoint{true, true, 0, 0, l, std::move(h)});
    impl_->call(
        n, "connect_wire",
        [&](auto &c) {
            return c.on_peer_connected(p, {1, l.initial_rtt}, now());
        },
        [&] {
            Bytes b;
            put(b, p);
            put(b, l.initial_rtt);
            b.push_back(1);
            return b;
        }());
    return p;
}
void Host::disconnect(Connection c) {
    impl_->ensure_mutable();
    disconnect_peer(c.left, c.left_peer);
    disconnect_peer(c.right, c.right_peer);
}
void Host::disconnect_peer(NodeId n, PeerId p) {
    impl_->ensure_mutable();
    impl_->node(n).peers.at(p).active = false;
    for (auto it = impl_->wire_anchors.begin();
         it != impl_->wire_anchors.end();) {
        if (std::get<0>(it->first) == n && std::get<1>(it->first) == p)
            it = impl_->wire_anchors.erase(it);
        else
            ++it;
    }
    for (auto it = impl_->node(n).expected_fetches.begin();
         it != impl_->node(n).expected_fetches.end();) {
        if (it->second.peer == p && !it->second.awaiting)
            it = impl_->node(n).expected_fetches.erase(it);
        else
            ++it;
    }
    impl_->call(
        n, "disconnect",
        [&](auto &c) { return c.on_peer_disconnected(p, now()); },
        [&] {
            Bytes b;
            put(b, p);
            return b;
        }());
}
void Host::set_link(NodeId n, PeerId p, LinkOptions l) {
    impl_->ensure_mutable();
    require(l.delay >= 0 && l.jitter >= 0 && l.loss_per_million <= 1000000,
            "invalid link");
    impl_->node(n).peers.at(p).link = l;
}
void Host::set_link(Connection c, LinkOptions l) {
    impl_->ensure_mutable();
    set_link(c.left, c.left_peer, l);
    set_link(c.right, c.right_peer, l);
}
void Host::set_transport_policy(TransportPolicy policy) {
    impl_->ensure_mutable();
    if (*impl_->active_body_jobs)
        throw std::logic_error(
            "transport policy replacement while body phases remain");
    if (impl_->body_service_policy && !policy)
        throw std::invalid_argument("body service requires transport policy");
    impl_->transport_policy = std::move(policy);
}
void Host::set_body_service_policy(std::optional<BodyServicePolicy> policy) {
    impl_->ensure_mutable();
    if (*impl_->active_body_jobs)
        throw std::logic_error(
            "body policy replacement while operation phases remain");
    if (policy && (!impl_->transport_policy || policy->timeout <= 0 ||
                   !policy->max_payload_bytes ||
                   policy->max_payload_bytes > 16 * 1024 * 1024 ||
                   !policy->request_bytes || !policy->serve))
        throw std::invalid_argument("invalid bounded body service policy");
    impl_->body_service_policy = std::move(policy);
}
void Host::observe_delivery(
    std::function<void(const DeliveryObservation &)> observer) {
    impl_->ensure_mutable();
    impl_->delivery_observer = std::move(observer);
}
void Host::admit(NodeId n, TxHandle b) {
    impl_->ensure_mutable();
    impl_->admit(n, std::move(b));
}
void Host::remove(NodeId n, ShortId id, RemovalReason r) {
    impl_->ensure_mutable();
    auto &node = impl_->node(n);
    // Preserve host callback order if removal overtakes a delayed admission.
    std::vector<TxHandle> flush;
    for (const auto &[hash, body] : node.bodies)
        if (short_id(node.tip.key, hash) == id &&
            !node.notified_bodies.contains(hash))
            flush.push_back(body);
    for (const auto &body : flush)
        impl_->admit(n, body);
    for (auto it = node.bodies.begin(); it != node.bodies.end();)
        if (short_id(node.tip.key, it->first) == id) {
            ++node.body_versions[it->first];
            it = node.bodies.erase(it);
        } else
            ++it;
    for (auto it = node.notified_bodies.begin();
         it != node.notified_bodies.end();) {
        if (short_id(node.tip.key, it->first) == id)
            it = node.notified_bodies.erase(it);
        else
            ++it;
    }
    Bytes b;
    put(b, id);
    b.push_back(static_cast<Byte>(r));
    impl_->call(
        n, "remove", [&](auto &c) { return c.on_tx_removed(id, r, now()); }, b);
}
void Host::remove_body(NodeId n, ShortId id, const TxHash &h, RemovalReason r) {
    impl_->ensure_mutable();
    auto &owner = impl_->node(n);
    if (owner.bodies.contains(h) && !owner.notified_bodies.contains(h))
        impl_->admit(n, owner.bodies.at(h));
    impl_->node(n).bodies.erase(h);
    impl_->node(n).notified_bodies.erase(h);
    ++impl_->node(n).body_versions[h];
    Bytes b;
    put(b, id);
    b.insert(b.end(), h.begin(), h.end());
    b.push_back(static_cast<Byte>(r));
    impl_->call(
        n, "remove_body",
        [&](auto &c) { return c.on_tx_body_removed(id, h, r, now()); }, b);
}
void Host::change_tip(NodeId n, TipParams tip, bool disconnected) {
    impl_->ensure_mutable();
    auto &p = impl_->node(n);
    ++p.generation;
    p.expected_rejected.clear();
    p.expected_fetches.clear();
    p.expected_rejection_suspension = false;
    p.expected_probation.clear();
    p.expected_local_rejected.clear();
    p.expected_unavailable.clear();
    p.must_release.clear();
    p.tip_reset_pending = true;
    for (auto it = impl_->wire_anchors.begin();
         it != impl_->wire_anchors.end();) {
        if (std::get<0>(it->first) == n)
            it = impl_->wire_anchors.erase(it);
        else
            ++it;
    }
    for (auto it = impl_->snapshots.begin(); it != impl_->snapshots.end();) {
        auto owner = std::get<0>(it->first);
        if (owner == n)
            it = impl_->snapshots.erase(it);
        else
            ++it;
    }
    p.tip = tip;
    p.bodies.clear();
    p.notified_bodies.clear();
    p.body_versions.clear();
    p.pending_notifications.clear();
    for (auto &b : tip.surviving) {
        p.bodies[b->tx_hash()] = b;
        p.notified_bodies[b->tx_hash()] = b;
    }
    Bytes input(tip.context.begin(), tip.context.end());
    put(input, tip.key.k0);
    put(input, tip.key.k1);
    for (auto &b : tip.surviving) {
        auto h = b->tx_hash();
        input.insert(input.end(), h.begin(), h.end());
    }
    impl_->call(
        n, disconnected ? "block_disconnected" : "new_tip",
        [&](auto &c) {
            return disconnected ? c.on_block_disconnected(tip, now())
                                : c.on_new_tip(tip, now());
        },
        input);
}
void Host::body_rule(NodeId n, PeerId p, ShortId id, BodyRule r) {
    impl_->ensure_mutable();
    impl_->rules[{n, p, id}] = std::move(r);
}
void Host::clear_body_rule(NodeId n, PeerId p, ShortId id) {
    impl_->ensure_mutable();
    impl_->rules.erase({n, p, id});
}
void Host::send_wire(NodeId n, PeerId p, Bytes b, Time delay) {
    impl_->ensure_mutable();
    const auto arrival = later(now(), delay);
    auto packet = impl_->packet(n, p, true);
    impl_->delivery(packet, DeliveryStage::offered,
                    ApplicationDisposition::not_applicable, b);
    impl_->delivery(packet, DeliveryStage::scheduled,
                    ApplicationDisposition::not_applicable, b, arrival);
    impl_->enqueue(arrival, [this, n, p, b = std::move(b), packet] {
        impl_->deliver(n, p, b, packet);
    });
}
void Host::inject(NodeId n, PeerId p, ByteSpan b) {
    impl_->ensure_mutable();
    impl_->deliver(n, p, Bytes(b.begin(), b.end()));
}
void Host::timer(NodeId n) {
    impl_->ensure_mutable();
    impl_->call(n, "timer", [&](auto &c) { return c.on_timer(now()); });
}
bool Host::step() {
    impl_->ensure_mutable();
    if (impl_->events.empty()) return false;
    auto e = impl_->events.top();
    impl_->events.pop();
    impl_->now = e.at;
    e.fn();
    return true;
}
void Host::advance_to(Time t, std::uint64_t max) {
    impl_->ensure_mutable();
    require(t >= now(), "host time went backwards");
    std::uint64_t n = 0;
    while (!impl_->events.empty() && impl_->events.top().at <= t) {
        require(n++ < max, "host event budget exhausted");
        step();
    }
    impl_->now = t;
}
void Host::run_for(Time t, std::uint64_t max) {
    impl_->ensure_mutable();
    advance_to(later(now(), t), max);
}
bool Host::run_until(const std::function<bool(const Host &)> &predicate,
                     Time deadline, std::uint64_t max) {
    impl_->ensure_mutable();
    require(deadline >= now(), "past deadline");
    for (std::uint64_t i = 0; !predicate(*this); ++i) {
        if (impl_->events.empty() || impl_->events.top().at > deadline) {
            impl_->now = deadline;
            return predicate(*this);
        }
        require(i < max, "host event budget exhausted");
        step();
    }
    return true;
}
Time Host::now() const {
    return impl_->now;
}
std::size_t Host::size() const {
    return impl_->nodes.size();
}
Stats Host::stats(NodeId n) const {
    return impl_->node(n).core->stats();
}
std::set<ShortId> Host::truth(NodeId n) const {
    return impl_->truth(n);
}
std::vector<TxHandle> Host::bodies(NodeId n) const {
    return impl_->handles(n);
}
std::vector<TxHandle> Host::notified_bodies(NodeId n) const {
    std::vector<TxHandle> result;
    for (const auto &[hash, body] : impl_->node(n).notified_bodies) {
        (void)hash;
        result.push_back(body);
    }
    return result;
}
std::set<ShortId> Host::projected_truth(NodeId n) const {
    return impl_->projected_truth(n);
}
const std::vector<Observation> &Host::observations() const {
    return impl_->observations;
}
const std::vector<Completion> &Host::completions() const {
    return impl_->completions;
}
const Transcript &Host::transcript() const {
    return impl_->transcript;
}
const Traffic &Host::traffic() const {
    return impl_->traffic;
}
void Host::observe(std::function<void(const Observation &)> f) {
    impl_->ensure_mutable();
    if (!impl_->full_observation())
        throw std::logic_error(
            "Stats observation is disabled in simulation observation mode");
    impl_->observer = std::move(f);
}
void Host::observe_actions(
    std::function<void(NodeId, Time, std::string_view, std::span<const Action>)>
        f) {
    impl_->ensure_mutable();
    impl_->action_observer = std::move(f);
}
void Host::audit() const {
    if (!impl_->full_observation())
        throw std::logic_error("omitted transient reference history cannot be "
                               "audited retroactively");
    for (NodeId n = 0; n < size(); ++n)
        impl_->check(n, stats(n));
}
bool Host::equal_truth() const {
    if (!size()) return true;
    auto first = truth(0);
    for (NodeId n = 1; n < size(); ++n)
        if (truth(n) != first) return false;
    return true;
}
} // namespace snowstorm::test
