// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_V2_OUTPUTS_H
#define BITCOIN_PRIMITIVES_V2_OUTPUTS_H

#include <consensus/amount.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/output.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <algorithm>
#include <span>
#include <vector>

/**
 * Explicit V2 outputs for version 7 transactions. A version 7 output never
 * holds a legacy script; these build the V2 output a caller means.
 */

/**
 * The V2 output with one branch, the V0 leaf over script, spent through path
 * 0. A script starting with OP_RETURN gives a burn output with that leaf and
 * no path. This is the output a legacy script used to be mapped to
 * implicitly, so it keeps the identities of existing V2 outputs.
 */
inline lotus::v2::Output V0LeafV2Output(Amount value,
                                        std::span<const uint8_t> bytes) {
    lotus::v2::Output out;
    out.value =
        static_cast<uint64_t>(std::max<int64_t>(0, value / SATOSHI));
    out.branches = {lotus::v2::BranchLeaf(bytes)};
    if (!bytes.empty() && bytes[0] == OP_RETURN) {
        out.flags = 2;
        out.paths = {};
    } else {
        out.flags = 0;
        out.paths = {{0}};
    }
    return out;
}

inline lotus::v2::Output V0LeafV2Output(Amount value, const CScript &script) {
    return V0LeafV2Output(value,
                          std::span<const uint8_t>(script.data(), script.size()));
}

/** V0LeafV2Output as a CTxOut of a version 7 transaction. */
inline CTxOut V0LeafOutput(Amount value, const CScript &script) {
    return CTxOut::FromV2Output(V0LeafV2Output(value, script));
}

/** The V2 script that always succeeds: OP_TRUE of the V2 VM (0x4e). */
inline constexpr uint8_t V2_OP_TRUE = 0x4e;

/** The V2 output anyone can spend with the V2 OP_TRUE witness script. */
inline CTxOut OpTrueOutput(Amount value) {
    const uint8_t script[1] = {V2_OP_TRUE};
    return CTxOut::FromV2Output(V0LeafV2Output(value, script));
}

/**
 * Whether a coinbase output pays to script: a legacy output holds script, a
 * V2 output is the V0-leaf output over it (SetCoinbaseOutputs). Used by the
 * miner fund, staking and treasury rules, which name payees by script.
 */
inline bool CoinbaseOutputPaysScript(const CTxOut &out, const CScript &script) {
    if (out.IsLegacy()) {
        return out.scriptPubKey == script;
    }
    const lotus::v2::Output expected = V0LeafV2Output(out.nValue, script);
    return out.nFlags == expected.flags && out.tokenId.IsNull() &&
           out.stateRoot.IsNull() && out.vBranches == expected.branches &&
           out.vPaths == expected.paths;
}

#endif // BITCOIN_PRIMITIVES_V2_OUTPUTS_H
