#include "asert_candidate.h"
#include "header_context.h"
#include <iostream>
#include <stdexcept>
using namespace lotus::v2;
void Check(bool b, const char *message = "header context regression") {
    if (!b) throw std::runtime_error(message);
}
int main() {
    HeaderChainProfile p;
    p.version = 2;
    p.genesis_time = 1000;
    p.genesis_bits = 0x207fffff;
    p.pow_limit.fill(255);
    p.half_life_seconds = 172800;
    p.spacing_seconds = 120;
    std::vector<Header> history;
    for (uint64_t height = 0; height < 12; ++height) {
        Header h;
        h.version = 2;
        h.height = height;
        h.bits = p.genesis_bits;
        h.time = height < 11 ? 1000 + 120 * height : 5000;
        h.size = 200;
        if (!history.empty())
            Check(BlockId(p.chain_id, history.front(), h.prev_id));
        Hash history_target{}, history_id{};
        Check(DecodeTarget(h.bits, p.pow_limit, history_target));
        do {
            Check(BlockId(p.chain_id, h, history_id));
            if (MeetsTarget(history_id, history_target)) break;
            ++h.nonce;
        } while (true);
        history.insert(history.begin(), h);
    }
    history.resize(11);
    Check(ParentMedianTime(p, history.front(), history) == 1720);
    Header child;
    child.version = 2;
    child.height = 12;
    child.size = 200;
    child.time = 2400;
    Check(BlockId(p.chain_id, history.front(), child.prev_id));
    AsertInteger limit = (AsertInteger(1) << 256) - 1;
    auto genesis = DecodeCompactTarget(p.genesis_bits, limit);
    child.bits = RequiredAsertCandidateBits(172800, 120, *genesis, 1000, limit,
                                            {5000, 11})
                     ->bits;
    Hash target{}, id{};
    Check(DecodeTarget(child.bits, p.pow_limit, target));
    do {
        Check(BlockId(p.chain_id, child, id));
        if (MeetsTarget(id, target)) break;
        ++child.nonce;
    } while (true);
    std::string error;
    auto valid = [&](const Header &h) {
        return ValidateChildHeader(p, history.front(), history, h, Hash{},
                                   Hash{}, 200, error);
    };
    Check(valid(child), "child earlier than parent and above MTP must pass");
    for (int mutation = 0; mutation < 9; ++mutation) {
        auto h = child;
        switch (mutation) {
            case 0:
                h.time = 1720;
                break;
            case 1:
                ++h.height;
                break;
            case 2:
                ++h.version;
                break;
            case 3:
                h.bits = p.genesis_bits;
                break;
            case 4:
                ++h.size;
                break;
            case 5:
                h.tx_root[0] = 1;
                break;
            case 6:
                h.state_root[0] = 1;
                break;
            case 7:
                h.prev_id[0] ^= 1;
                break;
            case 8:
                h.time = MAX_TIME + 1;
                break;
        }
        const char *cases[] = {
            "time equal to MTP",   "wrong height", "wrong version",
            "wrong required bits", "wrong size",   "wrong transaction root",
            "wrong state root",    "wrong parent", "timestamp overflow"};
        Check(!valid(h), cases[mutation]);
    }
    auto bad_work = child;
    do {
        ++bad_work.nonce;
        Check(BlockId(p.chain_id, bad_work, id));
    } while (MeetsTarget(id, target));
    Check(!valid(bad_work), "insufficient proof of work must reject");
    history.pop_back();
    Check(!ParentMedianTime(p, history.front(), history));
    Header genesis_header;
    genesis_header.version = 2;
    genesis_header.time = 1000;
    genesis_header.bits = p.genesis_bits;
    Check(ParentMedianTime(p, genesis_header, {genesis_header}) == 1000);
    Check(BlockId(p.chain_id, genesis_header, p.genesis_id));
    Check(ParentMedianTime(p, genesis_header, {genesis_header}) == 1000,
          "exact manifest genesis accepted");
    auto other_genesis = genesis_header;
    other_genesis.state_root[0] ^= 1;
    Check(!ParentMedianTime(p, other_genesis, {other_genesis}),
          "same time and target cannot substitute another genesis state");
    auto wrong_anchor = p;
    wrong_anchor.genesis_id[0] ^= 1;
    Check(!ParentMedianTime(wrong_anchor, genesis_header, {genesis_header}),
          "different manifest genesis rejected");
    Check(!RequiredAsertCandidateBits(172800, 0, *genesis, 1000, limit,
                                      {1000, 0}),
          "zero spacing must reject: native formerly accepted unlike Python");
    std::cout << "header context checks passed\n";
}
