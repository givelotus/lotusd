// Internal eCash state-transfer adapter. Does not modify transaction serialization.
#ifndef LOTUS_LEGACY_STATE_COIN_H
#define LOTUS_LEGACY_STATE_COIN_H
#include <lotus_v2/output.h>
#include <primitives/transaction.h>
#include <stdexcept>
namespace lotus::v2 {
inline Output LegacyStateOutput(const CTxOut &out) {
    if (!MoneyRange(out.nValue)) throw std::invalid_argument("legacy state amount");
    Output result;
    result.value = out.nValue / SATOSHI;
    result.legacy_script.emplace(out.scriptPubKey.begin(), out.scriptPubKey.end());
    return result;
}
inline CTxOut LegacyTxOutput(const Output &out) {
    if (!out.legacy_script || out.value > uint64_t(MAX_MONEY / SATOSHI) ||
        out.legacy_script->size() > MAX_SCRIPT_SIZE || out.flags ||
        out.token_id != Hash32{} || !out.branches.empty() || !out.paths.empty())
        throw std::invalid_argument("invalid legacy state output");
    return CTxOut(int64_t(out.value) * SATOSHI,
                  CScript(out.legacy_script->begin(), out.legacy_script->end()));
}
} // namespace lotus::v2
#endif
