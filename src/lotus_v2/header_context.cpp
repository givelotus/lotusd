#include "header_context.h"
#include "asert_candidate.h"
#include <algorithm>
#include <limits>
namespace lotus::v2 {
namespace {
    AsertInteger Integer(const Hash &h) {
        AsertInteger n = 0;
        for (auto i = h.rbegin(); i != h.rend(); ++i) {
            n <<= 8;
            n += *i;
        }
        return n;
    }
    bool Same(const Header &a, const Header &b) {
        std::array<uint8_t, HEADER_SIZE> x{}, y{};
        return SerializeHeader(a, x) && SerializeHeader(b, y) && x == y;
    }
} // namespace
std::optional<uint64_t> ParentMedianTime(const HeaderChainProfile &p,
                                         const Header &parent,
                                         const std::vector<Header> &history) {
    const size_t count = parent.height >= 10 ? 11 : size_t(parent.height) + 1;
    if (history.size() != count || !Same(history.front(), parent))
        return std::nullopt;
    std::vector<uint64_t> times;
    for (size_t i = 0; i < count; ++i) {
        const auto &h = history[i];
        std::array<uint8_t, HEADER_SIZE> bytes{};
        if (h.height != parent.height - i || h.version != p.version ||
            !SerializeHeader(h, bytes))
            return std::nullopt;
        if (i + 1 < count) {
            Hash id{};
            if (!BlockId(p.chain_id, history[i + 1], id) || h.prev_id != id)
                return std::nullopt;
        }
        if (h.height == 0 && (h.time != p.genesis_time ||
                              h.bits != p.genesis_bits || h.prev_id != Hash{}))
            return std::nullopt;
        if (h.height == 0 && p.genesis_id != Hash{}) {
            Hash genesis_id;
            if (!BlockId(p.chain_id, h, genesis_id) || genesis_id != p.genesis_id)
                return std::nullopt;
        }
        times.push_back(h.time);
    }
    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}
HeaderCheckResult ValidateChildHeaderChecked(
    const HeaderChainProfile &p, const Header &parent,
    const std::vector<Header> &history, const Header &child, const Hash &tx,
    const Hash &state, uint64_t size, std::string &error) {
    try {
        auto fail = [&](const char *why) {
            error = why;
            return HeaderCheckResult::Invalid;
        };
        const auto mtp = ParentMedianTime(p, parent, history);
        if (!mtp) {
            error = "authenticated parent history";
            return HeaderCheckResult::Inconclusive;
        }
        const auto limit = Integer(p.pow_limit);
        const auto genesis = DecodeCompactTarget(p.genesis_bits, limit);
        if (!genesis || p.half_life_seconds <= 0 || p.spacing_seconds <= 0 ||
            p.genesis_time > MAX_TIME) {
            error = "chain profile";
            return HeaderCheckResult::Inconclusive;
        }
        if (parent.height == std::numeric_limits<uint64_t>::max()) {
            error = "parent height exhausted";
            return HeaderCheckResult::Inconclusive;
        }
        if (child.height != parent.height + 1) return fail("child height");
        Hash parent_id{};
        if (!BlockId(p.chain_id, parent, parent_id)) {
            error = "parent identity unavailable";
            return HeaderCheckResult::Inconclusive;
        }
        if (child.prev_id != parent_id) return fail("child parent");
        if (child.version != p.version) return fail("child version");
        if (child.time > MAX_TIME || child.time <= *mtp)
            return fail("child median time");
        if (child.tx_root != tx || child.state_root != state ||
            child.size != size)
            return fail("child commitments");
        const auto required = RequiredAsertCandidateBits(
            p.half_life_seconds, p.spacing_seconds, *genesis, p.genesis_time,
            limit, {parent.time, parent.height});
        Hash target{}, id{};
        if (!required) {
            error = "required target context";
            return HeaderCheckResult::Inconclusive;
        }
        if (child.bits != required->bits ||
            !DecodeTarget(child.bits, p.pow_limit, target))
            return fail("required target");
        if (!BlockId(p.chain_id, child, id) || !MeetsTarget(id, target))
            return fail("proof of work");
        error.clear();
        return HeaderCheckResult::Valid;
    } catch (const std::exception &exception) {
        error = exception.what();
        return HeaderCheckResult::Inconclusive;
    }
}
bool ValidateChildHeader(const HeaderChainProfile &p, const Header &parent,
                         const std::vector<Header> &history,
                         const Header &child, const Hash &tx, const Hash &state,
                         uint64_t size, std::string &error) {
    return ValidateChildHeaderChecked(p, parent, history, child, tx, state,
                                      size, error) == HeaderCheckResult::Valid;
}
} // namespace lotus::v2
