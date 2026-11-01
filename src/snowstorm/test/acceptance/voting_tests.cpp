// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include <snowstorm/voting.h>
#include <snowstorm/node.h>
#include <snowstorm/messages.h>
#include <snowstorm/short_id.h>
#include "../harness/host.h"
#include <optional>
#include <stdexcept>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <tuple>
#include <variant>

namespace {
using namespace snowstorm;

// §8 independent small-population oracle. Counts are exact integers, not a
// second log-factorial implementation. D<=12 keeps every product within u64.
std::uint64_t choose_small(std::uint64_t n, std::uint64_t k) {
    if (k > n) return 0;
    k = std::min(k, n - k);
    std::uint64_t value = 1;
    for (std::uint64_t i = 1; i <= k; ++i) {
        value = value * (n - k + i) / i;
    }
    return value;
}

std::uint64_t sample_count(std::uint64_t population, std::uint64_t support,
                           std::uint64_t draws, std::uint64_t yes) {
    if (yes > support || yes > draws) return 0;
    if (draws - yes > population - support) return 0;
    return choose_small(support, yes) *
           choose_small(population - support, draws - yes);
}

double expected_llr(std::uint64_t population, std::uint64_t null_support,
                    std::uint64_t alternative, std::uint64_t draws,
                    std::uint64_t yes) {
    if (draws == 0) return 0;
    const auto denominator = sample_count(population, null_support, draws, yes);
    const auto numerator = sample_count(population, alternative, draws, yes);
    if (numerator != 0 && denominator != 0) {
        return std::log2(static_cast<double>(numerator) /
                         static_cast<double>(denominator));
    }
    if (numerator != 0) return std::numeric_limits<double>::infinity();
    if (denominator != 0) return -std::numeric_limits<double>::infinity();
    // Both-zero is the APPROVED monotone extension, not an invented finite
    // approximation to 0/0. Ordered hypergeometric supports exhaust these tails.
    if (yes > std::min(draws, null_support)) {
        return std::numeric_limits<double>::infinity();
    }
    return -std::numeric_limits<double>::infinity();
}

void require_same_number(double actual, double expected) {
    BOOST_REQUIRE(!std::isnan(actual));
    if (std::isinf(expected)) {
        BOOST_REQUIRE(std::isinf(actual));
        BOOST_CHECK_EQUAL(std::signbit(actual), std::signbit(expected));
        return;
    }
    BOOST_CHECK_SMALL(actual - expected, 1e-9);
}

void require_result(const MathResult &actual, double expected) {
    BOOST_REQUIRE(static_cast<bool>(actual.error == Error::ok));
    require_same_number(actual.value, expected);
}

struct HandVector {
    std::uint64_t draws;
    std::uint64_t yes;
    double expected;
};

// §8 six hand-reducible likelihood ratios for D=32, M0=19, M1tx=26.
// C(32,K) cancels. All six are finite; infinity tests below are additional.
constexpr HandVector HAND_VECTORS[] = {
    {1, 1, 0.45251220469750669},   // 26/19.
    {1, 0, -1.1154772174199359},   // 6/13.
    {2, 0, -2.3785116232537296},   // C(6,2)/C(13,2)=15/78=5/26.
    {2, 1, -0.66296501272242936},  // (26*6)/(19*13)=156/247=12/19.
    {2, 2, 0.92644339302991907},   // C(26,2)/C(19,2)=325/171.
    {3, 1, -1.9259994185562233},   // 26*C(6,2)/(19*C(13,2))=390/1482=5/19.
};

void check_draws(std::uint64_t d, std::uint64_t m0, std::uint64_t m1,
                 std::uint64_t k) {
    const auto support = hypergeometric_support(d, m0, k);
    BOOST_REQUIRE(static_cast<bool>(support.error == Error::ok));
    BOOST_CHECK_EQUAL(support.lower, k > d - m0 ? k - (d - m0) : 0);
    BOOST_CHECK_EQUAL(support.upper, std::min(k, m0));
    for (std::uint64_t y = 0; y <= k; ++y) {
        const auto actual = hypergeometric_llr(y, d, m0, m1, k);
        BOOST_REQUIRE(static_cast<bool>(actual.error == Error::ok));
        require_same_number(actual.value, expected_llr(d, m0, m1, k, y));
        const auto pmf = hypergeometric_log2(y, d, m0, k);
        BOOST_REQUIRE(static_cast<bool>(pmf.error == Error::ok));
        const auto count = sample_count(d, m0, k, y);
        const double expected = count == 0
            ? -std::numeric_limits<double>::infinity()
            : std::log2(static_cast<double>(count) / choose_small(d, k));
        require_same_number(pmf.value, expected);
    }
}

void check_alternative(std::uint64_t d, std::uint64_t m0, std::uint64_t m1) {
    for (std::uint64_t k = 0; k <= d; ++k) check_draws(d, m0, m1, k);
}

void check_null(std::uint64_t d, std::uint64_t m0) {
    for (std::uint64_t m1 = m0 + 1; m1 <= d; ++m1) {
        check_alternative(d, m0, m1);
    }
}

void check_population(std::uint64_t d) {
    for (std::uint64_t m0 = 0; m0 < d; ++m0) check_null(d, m0);
}


using snowstorm::test::Host;
using snowstorm::test::Observation;

void connect_withholding_peers(Host &host, std::size_t count = 32) {
    for (std::size_t i = 0; i < count; ++i) {
        host.connect_wire(0, [](const snowstorm::test::WireInput &) {
            return std::vector<snowstorm::test::WireReply>{};
        });
    }
    // The first connection may open a D=1 wave; finish it before testing D=32.
    host.advance_to(host.stats(0).wave.deadline);
}

PeerId first_sampled(const Host &host) {
    const auto stats = host.stats(0);
    BOOST_REQUIRE(stats.wave.active);
    BOOST_REQUIRE_EQUAL(stats.wave.population, 32U);
    BOOST_REQUIRE_EQUAL(stats.wave.sampled.size(), 8U);
    return stats.wave.sampled.front();
}

ReconReq poll_request(const Host &host, PeerId peer) {
    const auto state = host.stats(0);
    const auto peer_it = std::find_if(state.peers.begin(), state.peers.end(),
        [peer](const PeerStats &value) { return value.peer == peer; });
    BOOST_REQUIRE(static_cast<bool>(peer_it != state.peers.end()));
    for (auto obs = host.observations().rbegin(); obs != host.observations().rend(); ++obs) {
        for (auto action = obs->actions.rbegin(); action != obs->actions.rend(); ++action) {
            const auto *send = std::get_if<Send>(&*action);
            if (!send || send->peer != peer) continue;
            const auto parsed = parse(send->bytes, state.limits);
            BOOST_REQUIRE(static_cast<bool>(parsed.error == Error::ok));
            BOOST_REQUIRE(parsed.message.has_value());
            const auto *request = std::get_if<ReconReq>(&*parsed.message);
            if (!request || request->request_id != peer_it->request_id) continue;
            if (request->poll_id != peer_it->poll_id) continue;
            return *request;
        }
    }
    throw std::runtime_error("no correlated emitted poll in host transcript");
}

void reply(Host &host, PeerId peer, const snowstorm_oracle::IdSet &raw,
           const Root &root, std::vector<ShortId> excluded = {}) {
    const auto request = poll_request(host, peer);
    ReconSymbols symbols;
    symbols.tip_context = request.tip_context;
    symbols.session_id = request.session_id;
    symbols.request_id = request.request_id;
    symbols.poll_id = request.poll_id;
    symbols.snapshot_seq = 1;
    symbols.current_seq = 1;
    symbols.ranges = request.ranges;
    symbols.root_vote = root;
    symbols.exclusion_version = 1;
    symbols.exclusions = std::move(excluded);
    for (const auto &range : request.ranges) {
        for (const auto &cell : snowstorm_oracle::encode(raw, range.begin, range.end)) {
            symbols.cells.push_back(snowstorm_test::to_core(cell));
        }
    }
    Bytes bytes;
    BOOST_REQUIRE(static_cast<bool>(serialize(Message{symbols}, host.stats(0).limits, bytes) == Error::ok));
    host.inject(0, peer, bytes);
}

Root different_root(const Root &root) {
    auto other = root;
    other.front() ^= 1;
    return other;
}

ConfidenceObservation confidence(const Stats &stats, ShortId item) {
    const auto found = std::find_if(stats.confidence.begin(), stats.confidence.end(),
        [item](const auto &entry) { return entry.item == item; });
    BOOST_REQUIRE(static_cast<bool>(found != stats.confidence.end()));
    return *found;
}

Observation scored_wave(const Host &host, WaveId wave) {
    for (auto it = host.observations().rbegin(); it != host.observations().rend(); ++it) {
        const auto found = std::find_if(it->after.last_call.waves.begin(),
            it->after.last_call.waves.end(), [wave](const WaveAudit &audit) {
                return audit.wave.number == wave;
            });
        if (found != it->after.last_call.waves.end()) return *it;
    }
    throw std::runtime_error("required wave was not scored by actual node");
}

Observation finish_wave(Host &host, const WaveObservation &wave) {
    host.advance_to(wave.deadline);
    return scored_wave(host, wave.number);
}

void require_match_closed_without_decode(const Observation &response,
                                         PeerId peer, SessionId session) {
    BOOST_CHECK_EQUAL(response.after.decode_steps, response.before.decode_steps);
    BOOST_CHECK(response.after.last_call.decodes.empty());
    std::size_t closes = 0;
    std::size_t continuations = 0;
    for (const auto &action : response.actions) {
        const auto *send = std::get_if<Send>(&action);
        if (!send || send->peer != peer) continue;
        const auto parsed = parse(send->bytes, response.after.limits);
        BOOST_REQUIRE(static_cast<bool>(parsed.error == Error::ok));
        BOOST_REQUIRE(parsed.message.has_value());
        const auto *close = std::get_if<ReconClose>(&*parsed.message);
        if (close && close->session_id == session) ++closes;
        const auto *request = std::get_if<ReconReq>(&*parsed.message);
        if (request && request->session_id == session && !request->open) ++continuations;
    }
    BOOST_CHECK_EQUAL(closes, 1U);
    BOOST_CHECK_EQUAL(continuations, 0U);
    const auto found = std::find_if(response.after.last_call.completions.begin(),
        response.after.last_call.completions.end(), [peer, session](const auto &entry) {
            return entry.peer == peer && entry.session_id == session &&
                   entry.state == SessionState::root_matched;
        });
    BOOST_CHECK(static_cast<bool>(found != response.after.last_call.completions.end()));
}

void require_evidence(const Observation &score, PeerId peer, ShortId item,
                      bool yes, bool root_match) {
    const auto &evidence = score.after.last_call.evidence;
    const auto count = std::count_if(evidence.begin(), evidence.end(),
        [peer, item, yes, root_match](const EvidenceAudit &entry) {
            return entry.peer == peer && entry.item == item && entry.eligible &&
                   entry.yes == yes && entry.root_matched == root_match;
        });
    BOOST_CHECK_EQUAL(count, 1);
}

void drive_one_negative(Host &host, ShortId item) {
    const auto wave = host.stats(0).wave;
    const auto peer = first_sampled(host);
    reply(host, peer, {}, different_root(host.stats(0).own_root));
    const auto score = finish_wave(host, wave);
    const auto value = confidence(score.after, item);
    BOOST_CHECK_EQUAL(value.k, 1U);
    BOOST_CHECK_EQUAL(value.y, 0U);
}

} // namespace

BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)


BOOST_AUTO_TEST_CASE(T13_voting_math_exact_thresholds_and_hand_vectors) {
    VotingParameters params;
    BOOST_REQUIRE(static_cast<bool>(voting_parameters(32, 0.2, 1e-9, params) == Error::ok));
    BOOST_CHECK_EQUAL(params.population, 32U);
    BOOST_CHECK_EQUAL(params.m0, 19U);
    BOOST_CHECK_EQUAL(params.m1tx, 26U);
    BOOST_CHECK_EQUAL(params.b_root, 35U);
    BOOST_CHECK_EQUAL(params.b_tx, 12U);
    BOOST_CHECK_EQUAL(params.k, 8U);
    for (const auto &test : HAND_VECTORS) {
        const auto result = hypergeometric_llr(test.yes, 32, 19, 26, test.draws);
        BOOST_REQUIRE(static_cast<bool>(result.error == Error::ok));
        require_same_number(result.value, test.expected);
    }
    const auto one_yes = hypergeometric_llr(1, 32, 19, 26, 1);
    BOOST_REQUIRE(static_cast<bool>(one_yes.error == Error::ok));
    const auto accumulated = update_tx_confidence(3.25, one_yes.value, 12);
    BOOST_REQUIRE(static_cast<bool>(accumulated.error == Error::ok));
    require_same_number(accumulated.value - 3.25, std::log2(26.0 / 19.0));
    const auto no_evidence = hypergeometric_llr(0, 32, 19, 26, 0);
    BOOST_REQUIRE(static_cast<bool>(no_evidence.error == Error::ok));
    BOOST_CHECK_EQUAL(no_evidence.value, 0.0);
    const auto unchanged = update_tx_confidence(-4.125, no_evidence.value, 12);
    BOOST_REQUIRE(static_cast<bool>(unchanged.error == Error::ok));
    BOOST_CHECK_EQUAL(unchanged.value, -4.125);
}

BOOST_AUTO_TEST_CASE(T13_exhaustive_small_supports_and_unanimous_populations) {
    // Every valid tuple D,M0,M1,K,Y for D=1..12, including disjoint supports,
    // both-zero tails, missing-response low tails and K=0. No random omissions.
    for (std::uint64_t d = 1; d <= 12; ++d) check_population(d);
    for (std::uint64_t d = 5; d <= 8; ++d) {
        VotingParameters params;
        BOOST_REQUIRE(static_cast<bool>(voting_parameters(d, 0.2, 1e-9, params) == Error::ok));
        const auto unanimous = hypergeometric_llr(d, d, params.m0, params.m1tx, d);
        BOOST_REQUIRE(static_cast<bool>(unanimous.error == Error::ok));
        BOOST_REQUIRE(std::isinf(unanimous.value));
        BOOST_CHECK(!std::signbit(unanimous.value));
        require_result(update_tx_confidence(0, unanimous.value, 12), 12);
    }
    BOOST_CHECK(static_cast<bool>(hypergeometric_llr(2, 32, 19, 26, 1).error != Error::ok));
    BOOST_CHECK(static_cast<bool>(hypergeometric_llr(1, 32, 26, 19, 1).error != Error::ok));
    BOOST_CHECK(static_cast<bool>(hypergeometric_llr(1, 32, 19, 19, 1).error != Error::ok));
    BOOST_CHECK(static_cast<bool>(hypergeometric_llr(1, 32, 19, 33, 1).error != Error::ok));
    BOOST_CHECK(static_cast<bool>(hypergeometric_llr(1, 32, 19, 26, 33).error != Error::ok));
    BOOST_CHECK(static_cast<bool>(hypergeometric_support(32, 33, 1).error != Error::ok));
}

BOOST_AUTO_TEST_CASE(T13_explicit_infinities_saturation_and_stable_epsilon) {
    const double infinity = std::numeric_limits<double>::infinity();
    require_result(update_root_confidence(7, infinity, 35), 35);
    require_result(update_root_confidence(35, -infinity, 35), 0);
    require_result(update_tx_confidence(-2, infinity, 12), 12);
    require_result(update_tx_confidence(12, -infinity, 12), -12);
    require_result(update_root_confidence(34, 8, 35), 35);
    require_result(update_root_confidence(35, -3, 35), 32);
    require_result(update_tx_confidence(11, 8, 12), 12);
    require_result(update_tx_confidence(-11, -8, 12), -12);
    VotingParameters normal;
    VotingParameters subnormal;
    BOOST_REQUIRE(static_cast<bool>(voting_parameters(32, 0.2, std::numeric_limits<double>::min(), normal) == Error::ok));
    BOOST_REQUIRE(static_cast<bool>(voting_parameters(32, 0.2, std::numeric_limits<double>::denorm_min(), subnormal) == Error::ok));
    // min=2^-1022 and denorm_min=2^-1074; 4<log2(25)<5.
    BOOST_CHECK_EQUAL(normal.b_root, 1027U);
    BOOST_CHECK_EQUAL(normal.b_tx, 343U);
    BOOST_CHECK_EQUAL(subnormal.b_root, 1079U);
    BOOST_CHECK_EQUAL(subnormal.b_tx, 360U);
    BOOST_CHECK(static_cast<bool>(voting_parameters(32, 0.2, 0, normal) != Error::ok));
    BOOST_CHECK(static_cast<bool>(voting_parameters(32, 0.2, 1, normal) != Error::ok));
    BOOST_CHECK(static_cast<bool>(voting_parameters(32, 0.2, infinity, normal) != Error::ok));
    BOOST_CHECK(static_cast<bool>(voting_parameters(32, 0.2, std::numeric_limits<double>::quiet_NaN(), normal) != Error::ok));
    BOOST_CHECK(static_cast<bool>(voting_parameters(32, -0.01, 1e-9, normal) != Error::ok));
    BOOST_CHECK(static_cast<bool>(voting_parameters(32, 1.0 / 3.0, 1e-9, normal) != Error::ok));
}

BOOST_AUTO_TEST_CASE(T13_predictable_prior_wave_estimator) {
    std::uint64_t alternative = 0;
    BOOST_REQUIRE(static_cast<bool>(estimate_m1(32, 19, 0, 8, alternative) == Error::ok));
    BOOST_CHECK_EQUAL(alternative, 20U);
    BOOST_REQUIRE(static_cast<bool>(estimate_m1(32, 19, 4, 8, alternative) == Error::ok));
    BOOST_CHECK_EQUAL(alternative, 20U);
    BOOST_REQUIRE(static_cast<bool>(estimate_m1(32, 19, 6, 8, alternative) == Error::ok));
    BOOST_CHECK_EQUAL(alternative, 24U);
    BOOST_REQUIRE(static_cast<bool>(estimate_m1(32, 19, 8, 8, alternative) == Error::ok));
    BOOST_CHECK_EQUAL(alternative, 32U);
}


BOOST_AUTO_TEST_CASE(T13_rootmatched_candidate_yes_and_abstainers_are_not_no_votes) {
    Host host(13001, 1, 512);
    host.admit(0, snowstorm_test::make_body(13001));
    host.admit(0, snowstorm_test::make_body(130013));
    connect_withholding_peers(host);
    const auto x = *host.truth(0).begin();
    const auto wave = host.stats(0).wave;
    const auto peer = first_sampled(host);
    const auto request = poll_request(host, peer);
    reply(host, peer, host.truth(0), host.stats(0).own_root);
    require_match_closed_without_decode(host.observations().back(), peer, request.session_id);
    const auto score = finish_wave(host, wave);
    const auto value = confidence(score.after, x);
    BOOST_CHECK_EQUAL(value.k, 1U);
    BOOST_CHECK_EQUAL(value.y, 1U);
    require_same_number(value.increment, std::log2(26.0 / 19.0));
    require_same_number(value.lambda, std::log2(26.0 / 19.0));
    require_evidence(score, peer, x, true, true);
    BOOST_REQUIRE_EQUAL(host.truth(0).size(), 2U);
    for (const auto item : host.truth(0)) {
        require_evidence(score, peer, item, true, true);
        require_same_number(confidence(score.after, item).lambda, std::log2(26.0 / 19.0));
    }
    const auto silent = finish_wave(host, host.stats(0).wave);
    BOOST_CHECK_EQUAL(confidence(silent.after, x).k, 0U);
    require_same_number(confidence(silent.after, x).lambda, value.lambda);
}

BOOST_AUTO_TEST_CASE(T13_unfinished_mismatch_abstains_until_done) {
    Host host(13002, 1, 512);
    host.admit(0, snowstorm_test::make_body(13002));
    connect_withholding_peers(host);
    const auto x = *host.truth(0).begin();
    auto raw = host.truth(0);
    for (ShortId id = 1; raw.size() < 4; ++id) raw.insert(id);
    const auto wave = host.stats(0).wave;
    const auto peer = first_sampled(host);
    // Index zero contains three additions, so this first symbol cannot decode.
    reply(host, peer, raw, different_root(host.stats(0).own_root));
    BOOST_CHECK(host.observations().back().after.last_call.completions.empty());
    const auto score = finish_wave(host, wave);
    BOOST_CHECK_EQUAL(confidence(score.after, x).k, 0U);
    require_same_number(confidence(score.after, x).lambda, 0);
}

BOOST_AUTO_TEST_CASE(T13_rootmatched_excluded_item_is_no_while_candidate_is_yes) {
    Host host(13003, 1, 512);
    host.admit(0, snowstorm_test::make_body(13003));
    connect_withholding_peers(host);
    const auto x = *host.truth(0).begin();
    for (unsigned i = 0; i < 12; ++i) drive_one_negative(host, x);
    require_same_number(confidence(host.stats(0), x).lambda, -12);
    host.admit(0, snowstorm_test::make_body(13004));
    host.advance_to(host.stats(0).wave.deadline);
    auto current = host.truth(0);
    current.erase(x);
    BOOST_REQUIRE_EQUAL(current.size(), 1U);
    const auto y = *current.begin();
    const auto wave = host.stats(0).wave;
    const auto peer = first_sampled(host);
    const auto request = poll_request(host, peer);
    reply(host, peer, host.truth(0), host.stats(0).own_root, {x});
    require_match_closed_without_decode(host.observations().back(), peer, request.session_id);
    const auto score = finish_wave(host, wave);
    require_evidence(score, peer, x, false, true);
    require_evidence(score, peer, y, true, true);
    require_same_number(confidence(score.after, x).lambda, -12);
    require_same_number(confidence(score.after, y).lambda, std::log2(26.0 / 19.0));
}

BOOST_AUTO_TEST_CASE(T13_pending_lambda_survives_result_timer_and_transfers_on_admission) {
    Host host(13005, 1, 512);
    host.admit(0, snowstorm_test::make_body(13005));
    connect_withholding_peers(host);
    const auto body = snowstorm_test::make_body(13006);
    const auto id = short_id(snowstorm::test::default_tip().key, body->tx_hash());
    const auto start = host.now();
    const auto peer = first_sampled(host);
    snowstorm::test::BodyRule rule;
    rule.body = body;
    rule.expected_tx_hash = body->tx_hash();
    rule.result_delay = 7000;
    rule.admission_delay = 2000;
    host.body_rule(0, peer, id, rule);
    auto raw = host.truth(0);
    raw.insert(id);
    const auto first = host.stats(0).wave;
    reply(host, peer, raw, different_root(host.stats(0).own_root));
    const auto initial = finish_wave(host, first);
    require_evidence(initial, peer, id, true, false);
    require_same_number(confidence(initial.after, id).lambda, std::log2(26.0 / 19.0));
    const auto second = host.stats(0).wave;
    const auto matched = first_sampled(host);
    reply(host, matched, host.truth(0), host.stats(0).own_root);
    const auto no = finish_wave(host, second);
    require_evidence(no, matched, id, false, true);
    const double expected = std::log2(26.0 / 19.0) + std::log2(6.0 / 13.0);
    require_same_number(confidence(no.after, id).lambda, expected);
    host.advance_to(start + 7000);
    auto state = host.stats(0);
    const auto fetch = std::find_if(state.fetches.begin(), state.fetches.end(),
        [id](const auto &entry) { return entry.item == id; });
    BOOST_REQUIRE(static_cast<bool>(fetch != state.fetches.end()));
    BOOST_CHECK(static_cast<bool>(fetch->state == FetchState::awaiting_admission));
    BOOST_REQUIRE(fetch->expected_tx_hash.has_value());
    BOOST_CHECK(*fetch->expected_tx_hash == body->tx_hash());
    BOOST_CHECK_EQUAL(host.truth(0).count(id), 1U);
    BOOST_CHECK_EQUAL(host.projected_truth(0).count(id), 0U);
    require_same_number(confidence(state, id).lambda, expected);
    host.advance_to(start + 8000);
    require_same_number(confidence(host.stats(0), id).lambda, expected);
    host.advance_to(start + 9000);
    state = host.stats(0);
    BOOST_CHECK_EQUAL(host.truth(0).count(id), 1U);
    BOOST_CHECK_EQUAL(host.projected_truth(0).count(id), 1U);
    BOOST_CHECK(confidence(state, id).admitted);
    require_same_number(confidence(state, id).lambda, expected);
    BOOST_CHECK(std::none_of(state.fetches.begin(), state.fetches.end(),
        [id](const auto &entry) { return entry.item == id; }));
    require_same_number(state.root_confidence, 0);
}

BOOST_AUTO_TEST_CASE(T13_frozen_requires_both_confidence_barriers_and_emits_once) {
    Host host(13007, 1, 512);
    host.admit(0, snowstorm_test::make_body(13007));
    connect_withholding_peers(host);
    std::size_t frozen = 0;
    host.observe([&frozen](const Observation &observation) {
        for (const auto &action : observation.actions) {
            if (!std::holds_alternative<Frozen>(action)) continue;
            ++frozen;
            BOOST_CHECK(observation.after.frozen);
            BOOST_CHECK_GE(observation.after.root_confidence, observation.after.b_root);
            for (const auto id : observation.after.candidate_ids) {
                BOOST_CHECK_GE(confidence(observation.after, id).lambda, observation.after.b_tx);
            }
        }
    });
    for (unsigned wave = 0; wave < 20; ++wave) {
        const auto peers = host.stats(0).wave.sampled;
        for (const auto peer : peers) reply(host, peer, host.truth(0), host.stats(0).own_root);
    }
    BOOST_CHECK_EQUAL(frozen, 1U);
    BOOST_CHECK(host.stats(0).frozen);
    host.admit(0, snowstorm_test::make_body(13008));
    BOOST_CHECK(!host.stats(0).frozen);
    require_same_number(host.stats(0).root_confidence, 0);
}


BOOST_AUTO_TEST_CASE(T13_colliding_body_changes_reset_root_confidence_without_id_change) {
    Host host(13009);
    auto tip = snowstorm::test::default_tip();
    tip.key = snowstorm_test::collision_key;
    host.add_node(snowstorm::test::default_config(512, 13009), tip);
    const auto bodies = snowstorm_test::collision_bodies();
    BOOST_REQUIRE_EQUAL(short_id(tip.key, bodies[0]->tx_hash()), snowstorm_test::collision_id);
    BOOST_REQUIRE_EQUAL(short_id(tip.key, bodies[1]->tx_hash()), snowstorm_test::collision_id);
    host.admit(0, bodies[0]);
    connect_withholding_peers(host);
    const auto peers = host.stats(0).wave.sampled;
    for (const auto peer : peers) reply(host, peer, host.truth(0), host.stats(0).own_root);
    const auto before = host.stats(0);
    BOOST_CHECK_GT(before.root_confidence, 0);
    host.admit(0, bodies[1]);
    const auto added = host.stats(0);
    BOOST_CHECK(added.own_root != before.own_root);
    BOOST_CHECK_EQUAL(added.own_ids.size(), 1U);
    BOOST_CHECK_EQUAL(added.bodies.size(), 2U);
    require_same_number(added.root_confidence, 0);
    host.remove_body(0, snowstorm_test::collision_id, bodies[1]->tx_hash());
    const auto removed = host.stats(0);
    BOOST_CHECK(removed.own_root == before.own_root);
    BOOST_CHECK_EQUAL(removed.own_ids.size(), 1U);
    BOOST_CHECK_EQUAL(removed.bodies.size(), 1U);
    require_same_number(removed.root_confidence, 0);
}


BOOST_AUTO_TEST_CASE(T13_unsampled_late_done_is_not_extra_item_evidence) {
    Host host(13010, 1, 512);
    host.admit(0, snowstorm_test::make_body(13010));
    connect_withholding_peers(host);
    const auto x = *host.truth(0).begin();
    auto previous = host.stats(0).wave.sampled;
    finish_wave(host, host.stats(0).wave);
    auto current = host.stats(0).wave.sampled;
    auto absent = std::find_if(previous.begin(), previous.end(), [&current](PeerId peer) {
        return std::find(current.begin(), current.end(), peer) == current.end();
    });
    BOOST_REQUIRE(static_cast<bool>(absent != previous.end()));
    const auto peer = *absent;
    const auto wave = host.stats(0).wave;
    // Its still-outstanding old poll may finish reconciliation, but the peer is
    // outside this wave's sample. Neither a root vote nor an item vote is fresh.
    reply(host, peer, host.truth(0), different_root(host.stats(0).own_root));
    const auto received = host.observations().back();
    BOOST_REQUIRE_EQUAL(received.after.last_call.replies.size(), 1U);
    BOOST_CHECK(received.after.last_call.replies.front().accepted_data);
    BOOST_CHECK(!received.after.last_call.replies.front().accepted_root_vote);
    BOOST_CHECK(!received.after.last_call.replies.front().answered_current_wave);
    BOOST_REQUIRE_EQUAL(received.after.last_call.completions.size(), 1U);
    BOOST_CHECK(static_cast<bool>(received.after.last_call.completions.front().state == SessionState::done));
    const auto score = finish_wave(host, wave);
    BOOST_CHECK_EQUAL(confidence(score.after, x).k, 0U);
    BOOST_CHECK(std::none_of(score.after.last_call.evidence.begin(), score.after.last_call.evidence.end(),
        [peer](const auto &entry) { return entry.peer == peer && entry.eligible; }));
}

BOOST_AUTO_TEST_CASE(T13_admission_after_completion_invalidates_captured_root_and_evidence) {
    Host host(13011, 1, 512);
    host.admit(0, snowstorm_test::make_body(13011));
    connect_withholding_peers(host);
    const auto wave = host.stats(0).wave;
    const auto peer = first_sampled(host);
    reply(host, peer, host.truth(0), different_root(host.stats(0).own_root));
    const auto done = host.observations().back();
    BOOST_REQUIRE_EQUAL(done.after.last_call.completions.size(), 1U);
    const auto completion_seq = done.after.last_call.completions.front().own_seq_at_done;
    const auto body = snowstorm_test::make_body(13012);
    const auto y = short_id(snowstorm::test::default_tip().key, body->tx_hash());
    host.admit(0, body);
    BOOST_CHECK_GT(confidence(host.stats(0), y).admission_seq, completion_seq);
    const auto score = finish_wave(host, wave);
    require_same_number(confidence(score.after, y).lambda, 0);
    require_same_number(score.after.root_confidence, 0);
    BOOST_CHECK(std::none_of(score.after.last_call.evidence.begin(), score.after.last_call.evidence.end(),
        [y](const auto &entry) { return entry.item == y && entry.eligible; }));
}


BOOST_AUTO_TEST_CASE(T13_node_estimator_uses_only_completed_previous_wave) {
    Host host(13013, 1, 128);
    for (std::size_t i = 0; i < 32; ++i) {
        host.connect_wire(0, [](const snowstorm::test::WireInput &) {
            return std::vector<snowstorm::test::WireReply>{};
        });
    }
    // Population changes abandon old waves. The first D=32 generation
    // starts at M1tx=26; only completed preceding waves may change it.
    const std::array<std::uint64_t, 4> yes_counts{6, 8, 0, 4};
    const std::array<std::uint64_t, 4> alternatives{26, 24, 32, 20};
    for (std::size_t round = 0; round < yes_counts.size(); ++round) {
        const auto wave = host.stats(0).wave;
        BOOST_REQUIRE_EQUAL(wave.population, 32U);
        BOOST_REQUIRE_EQUAL(wave.k, 8U);
        BOOST_CHECK_EQUAL(wave.m1hat, alternatives[round]);
        for (std::size_t i = 0; i < wave.sampled.size(); ++i) {
            const auto root = i < yes_counts[round] ? wave.root : different_root(wave.root);
            reply(host, wave.sampled[i], {}, root);
            if (i + 1 == wave.sampled.size()) continue;
            BOOST_CHECK_EQUAL(host.stats(0).wave.number, wave.number);
            BOOST_CHECK_EQUAL(host.stats(0).wave.m1hat, alternatives[round]);
        }
        const auto scored = scored_wave(host, wave.number);
        const auto audit = std::find_if(scored.after.last_call.waves.begin(),
            scored.after.last_call.waves.end(), [wave](const auto &entry) {
                return entry.wave.number == wave.number;
            });
        BOOST_REQUIRE(static_cast<bool>(audit != scored.after.last_call.waves.end()));
        BOOST_CHECK_EQUAL(audit->wave.y, yes_counts[round]);
        BOOST_CHECK_EQUAL(audit->wave.m1hat, alternatives[round]);
        // Independent integer binomial counts; no production LLR helper.
        const double increment = expected_llr(32, 19, alternatives[round], 8, yes_counts[round]);
        require_same_number(audit->root_increment, increment);
        const double expected = std::clamp(audit->confidence_before + increment, 0.0, 35.0);
        require_same_number(audit->confidence_after, expected);
        const auto next_alternative = std::max<std::uint64_t>(20, 4 * yes_counts[round]);
        BOOST_CHECK_EQUAL(host.stats(0).wave.m1hat, next_alternative);
    }
}

BOOST_AUTO_TEST_CASE(T13_node_fresh_uniform_distinct_samples_seeded_observations) {
    constexpr std::size_t population = 32;
    constexpr std::size_t draws = 8;
    constexpr std::size_t waves = 4096;
    snowstorm::test::HostOptions options;
    options.retain_observations = false;
    options.retain_transcript = false;
    options.retain_completions = false;
    Host host(13014, 1, 128, options);
    connect_withholding_peers(host);
    const auto initial = host.stats(0);
    std::vector<PeerId> population_ids;
    for (const auto &peer : initial.peers) population_ids.push_back(peer.peer);
    std::sort(population_ids.begin(), population_ids.end());
    BOOST_REQUIRE_EQUAL(population_ids.size(), population);
    std::array<std::uint64_t, population> occurrences{};
    std::array<std::array<std::uint64_t, population>, population> pairs{};
    std::vector<PeerId> previous;
    std::uint64_t overlap_sum = 0;
    WaveId previous_wave = 0;
    for (std::size_t index = 0; index < waves; ++index) {
        const auto wave = host.stats(0).wave;
        BOOST_CHECK_GT(wave.number, previous_wave);
        previous_wave = wave.number;
        BOOST_REQUIRE_EQUAL(wave.population, population);
        BOOST_REQUIRE_EQUAL(wave.k, draws);
        auto sample = wave.sampled;
        std::sort(sample.begin(), sample.end());
        BOOST_REQUIRE_EQUAL(sample.size(), draws);
        BOOST_CHECK(static_cast<bool>(std::adjacent_find(sample.begin(), sample.end()) == sample.end()));
        for (const auto peer : sample) {
            const auto position = std::lower_bound(population_ids.begin(), population_ids.end(), peer);
            BOOST_REQUIRE(static_cast<bool>(position != population_ids.end()));
            BOOST_REQUIRE_EQUAL(*position, peer);
            ++occurrences[static_cast<std::size_t>(position - population_ids.begin())];
            overlap_sum += std::binary_search(previous.begin(), previous.end(), peer) ? 1 : 0;
        }
        // Joint inclusion detects biased fixed groups that marginal frequencies miss.
        for (std::size_t i = 0; i < population; ++i) {
            if (!std::binary_search(sample.begin(), sample.end(), population_ids[i])) continue;
            for (std::size_t j = i + 1; j < population; ++j) {
                pairs[i][j] += std::binary_search(sample.begin(), sample.end(), population_ids[j]) ? 1 : 0;
            }
        }
        previous = std::move(sample);
        host.advance_to(wave.deadline);
    }
    // Fixed seed, broad >=8-sigma marginal/joint tolerances. This is a
    // deterministic regression for uniform sampling, not a proof of RNG quality.
    // P(peer)=8/32; P(pair)=8*7/(32*31); E(adjacent overlap)=8*8/32=2.
    const double marginal_mean = waves * 8.0 / 32.0;
    const double pair_mean = waves * 56.0 / 992.0;
    for (const auto count : occurrences) BOOST_CHECK_LT(std::abs(count - marginal_mean), 224.0);
    for (std::size_t i = 0; i < population; ++i) {
        for (std::size_t j = i + 1; j < population; ++j) {
            BOOST_CHECK_LT(std::abs(pairs[i][j] - pair_mean), 120.0);
        }
    }
    BOOST_CHECK_LT(std::abs(static_cast<double>(overlap_sum) - 2.0 * (waves - 1)), 600.0);
}

BOOST_AUTO_TEST_SUITE_END()
