// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "wave.h"
#include <algorithm>
#include <cassert>
#include <limits>
#include <stdexcept>
namespace snowstorm::detail {
VotingState::VotingState(double beta, double epsilon, std::uint64_t seed,
                         std::uint64_t item_limit)
    : beta_(beta), epsilon_(epsilon), item_limit_(item_limit) {
    if (voting_parameters(0,beta,epsilon,parameters_) != Error::ok)
        throw std::invalid_argument("invalid voting configuration");
    constexpr auto HALF_WORD_BITS = 32;
    std::seed_seq seeds{static_cast<std::uint32_t>(seed),static_cast<std::uint32_t>(seed >> HALF_WORD_BITS)};
    random_.seed(seeds);
}
Error VotingState::prepare(std::size_t candidates, std::size_t confidence) {
    if (candidates > item_limit_ || confidence > item_limit_) return Error::capacity;
    candidates_.reserve(candidates); items_.reserve(confidence);
    return Error::ok;
}
Error VotingState::population(std::uint64_t size) noexcept {
    if (size > params::MAX_PEERS) return Error::invalid_argument;
    if (size == parameters_.population) return Error::ok;
    VotingParameters next;
    const auto error = voting_parameters(size,beta_,epsilon_,next);
    if (error != Error::ok) return error;
    parameters_ = next; confidence_ = 0; active_ = false;
    invalidated_ = true; prior_ = false; sample_size_ = 0;
    candidates_.clear();
    return Error::ok;
}
void VotingState::root_changed(const Root &root) noexcept {
    if (root == current_root_) return;
    current_root_ = root; confidence_ = 0; frozen_ = false; prior_ = false;
    if (active_) {
        invalidated_ = true;
        for (auto &slot : slots_) { slot.matching = false; slot.root_matched = false; }
    }
}
Error VotingState::begin(WavePopulation peers, std::span<const ShortId> candidates, Time now) noexcept {
    if (active_ || peers.size != parameters_.population || !peers.at || now < 0)
        return Error::invalid_argument;
    if (peers.size == 0) return Error::not_found;
    if (number_ == std::numeric_limits<WaveId>::max()) return Error::overflow;
    if (candidates.size() > candidates_.capacity()) return Error::capacity;
    if (!std::is_sorted(candidates.begin(),candidates.end()) ||
        std::adjacent_find(candidates.begin(),candidates.end()) != candidates.end()) return Error::invalid_argument;
    std::array<WavePeer,params::VOTING_SAMPLE> selected{};
    auto random = random_;
    const auto count = static_cast<std::size_t>(parameters_.k);
    PeerId previous = 0;
    for (std::size_t i = 0; i < peers.size; ++i) {
        const auto peer = peers.at(peers.context,i);
        if ((i && peer.peer <= previous) || peer.rtt < params::MIN_RTT) return Error::invalid_argument;
        previous = peer.peer;
        if (i < count) selected[i] = peer;
        else {
            std::uniform_int_distribution<std::size_t> uniform(0,i);
            const auto position = uniform(random);
            if (position < count) selected[position] = peer;
        }
    }
    Time maximum = params::MIN_RTT;
    for (std::size_t i = 0; i < count; ++i) maximum = std::max(maximum,selected[i].rtt);
    if (maximum > (std::numeric_limits<Time>::max()-now)/params::RETRANSMIT_FACTOR) return Error::overflow;
    auto alternative = parameters_.m1tx;
    if (prior_) {
        const auto error = estimate_m1(parameters_.population,parameters_.m0,prior_matches_,prior_sample_,alternative);
        if (error != Error::ok) return error;
    }
    std::sort(selected.begin(),selected.begin()+count,[](auto a,auto b){return a.peer < b.peer;});
    for (std::size_t i = 0; i < count; ++i) slots_[i] = {selected[i].peer,0,false,false,false,false};
    candidates_.assign(candidates.begin(),candidates.end());
    sample_size_ = count; random_ = random; alternative_ = alternative;
    ++number_; start_ = now; deadline_ = now + params::RETRANSMIT_FACTOR * maximum;
    root_ = current_root_; active_ = true; invalidated_ = false;
    return Error::ok;
}
bool VotingState::reply(PeerId peer, PollId poll, bool normal, const Root &vote,
                        const Root &current, SessionId session) noexcept {
    if (!active_ || poll != number_) return false;
    const auto found = std::find_if(slots_.begin(),slots_.begin()+sample_size_,[peer](auto slot){return slot.peer == peer;});
    if (found == slots_.begin()+sample_size_ || found->answered) return false;
    found->answered = true; found->session = session; found->abstain = found->abstain || !normal;
    found->matching = normal && !found->abstain && !invalidated_ && vote == root_ && current == root_;
    found->root_matched = found->matching;
    return true;
}
void VotingState::discard_peer(PeerId peer) noexcept {
    for (auto &slot : slots_) if (slot.peer == peer) { slot.matching = false; slot.root_matched = false; slot.abstain = true; }
}
bool VotingState::due(Time now) const noexcept {
    return active_ && (now >= deadline_ || std::all_of(slots_.begin(),slots_.begin()+sample_size_,[](auto slot){return slot.answered;}));
}
WaveScore VotingState::score(Time now, EvidenceSource evidence, EvidenceSink sink) noexcept {
    WaveScore result{Error::ok,false,0,confidence_,confidence_};
    if (!due(now)) return result;
    if (now < start_) return {Error::nonmonotonic_time,false,0,confidence_,confidence_};
    std::uint64_t matches = 0;
    for (const auto &slot : sample()) matches += slot.matching;
    if (!invalidated_) {
        const auto increment = hypergeometric_llr(matches,parameters_.population,parameters_.m0,alternative_,sample_size_);
        assert(increment.error == Error::ok);
        result.increment = increment.value;
        confidence_ = update_root_confidence(confidence_,increment.value,parameters_.b_root).value;
        prior_matches_ = matches; prior_sample_ = sample_size_; prior_ = true;
    }
    for (auto &item : items_) score_item(item,evidence,sink);
    active_ = false; result.scored = true; result.after = confidence_;
    return result;
}
void VotingState::score_item(ConfidenceObservation &item, EvidenceSource evidence, EvidenceSink sink) noexcept {
        std::array<ItemEvidence,params::VOTING_SAMPLE> votes{};
        item.k = item.y = 0; item.increment = 0;
        if (!invalidated_) for (std::size_t i = 0; i < sample_size_; ++i) {
            const auto &slot = slots_[i];
            if (slot.abstain) continue;
            if (slot.root_matched) votes[i] = {true,std::binary_search(candidates_.begin(),candidates_.end(),item.item),true,slot.session};
            else if (evidence.read) votes[i] = evidence.read(evidence.context,slot.peer,item.item,number_);
            if (votes[i].eligible) { ++item.k; item.y += votes[i].yes; }
        }
        const auto before = item.lambda;
        if (item.k) {
            item.increment = hypergeometric_llr(item.y,parameters_.population,parameters_.m0,parameters_.m1tx,item.k).value;
            item.lambda = update_tx_confidence(item.lambda,item.increment,parameters_.b_tx).value;
        }
        if (sink.record) for (std::size_t i = 0; i < sample_size_; ++i) if (votes[i].eligible)
            sink.record(sink.context,{slots_[i].peer,item.item,number_,votes[i].session,true,votes[i].yes,votes[i].root_matched,before,item.lambda});
}
Error VotingState::track(ShortId id, bool admitted, Sequence sequence) noexcept {
    if (id == 0 || (admitted && sequence == 0)) return Error::invalid_argument;
    auto it = std::lower_bound(items_.begin(),items_.end(),id,[](const auto &entry,auto value){return entry.item < value;});
    if (it == items_.end() || it->item != id) {
        if (items_.size() >= item_limit_ || items_.size() == items_.capacity()) return Error::capacity;
        it = items_.insert(it,ConfidenceObservation{}); it->item = id;
    }
    it->admitted = admitted; it->admission_seq = admitted ? sequence : 0;
    return Error::ok;
}
void VotingState::erase(ShortId id) noexcept {
    const auto it = std::lower_bound(items_.begin(),items_.end(),id,[](const auto &entry,auto value){return entry.item < value;});
    if (it != items_.end() && it->item == id) items_.erase(it);
}
const ConfidenceObservation *VotingState::find(ShortId id) const noexcept {
    const auto it = std::lower_bound(items_.begin(),items_.end(),id,[](const auto &entry,auto value){return entry.item < value;});
    return it != items_.end() && it->item == id ? &*it : nullptr;
}
bool VotingState::candidate(ShortId id) const noexcept {
    const auto *entry = find(id);
    return entry && entry->admitted && entry->lambda > -static_cast<double>(parameters_.b_tx);
}
bool VotingState::freeze_transition(bool all_candidates_confirmed) noexcept {
    if (frozen_ || confidence_ < static_cast<double>(parameters_.b_root) || !all_candidates_confirmed) return false;
    frozen_ = true; return true;
}
void VotingState::reset(const Root &root) noexcept {
    root_ = current_root_ = root; confidence_ = 0; prior_ = frozen_ = active_ = invalidated_ = false;
    sample_size_ = 0; candidates_.clear(); items_.clear();
    // Wave/poll IDs and RNG identity are never rewound on a tip transition.
}
WaveObservation VotingState::observation() const {
    WaveObservation value;
    value.number = number_; value.active = active_; value.invalidated = invalidated_;
    value.started = start_; value.deadline = deadline_; value.root = root_;
    value.population = parameters_.population; value.k = sample_size_;
    value.m0 = parameters_.m0; value.m1hat = alternative_; value.m1tx = parameters_.m1tx;
    for (const auto &slot : sample()) {
        value.sampled.push_back(slot.peer);
        if (slot.answered) value.answered.push_back(slot.peer);
        if (slot.matching) { value.matching.push_back(slot.peer); ++value.y; }
    }
    return value;
}
std::size_t VotingState::allocated_bytes() const noexcept {
    return candidates_.capacity()*sizeof(ShortId) + items_.capacity()*sizeof(ConfidenceObservation);
}
ItemEvidence reconciled_evidence(ShortId, WaveId scoring, WaveId completed,
    SessionId session, Sequence own_sequence_at_done, std::optional<Sequence> admission,
    bool plus, bool member, bool excluded) noexcept {
    if (completed > scoring || scoring-completed > 1 || completed == 0 ||
        (!plus && (!admission || *admission > own_sequence_at_done))) return {};
    return {true,member && !excluded,false,session};
}
constexpr std::size_t RECORD_BYTES = 128;
static_assert(sizeof(ConfidenceObservation) <= RECORD_BYTES);
static_assert(sizeof(WaveSlot) <= RECORD_BYTES);
} // namespace snowstorm::detail
