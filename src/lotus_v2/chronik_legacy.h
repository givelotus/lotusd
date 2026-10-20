// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef LOTUS_V2_CHRONIK_LEGACY_H
#define LOTUS_V2_CHRONIK_LEGACY_H
#include <lotus_v2/chronik_explorer.h>
#include <lotus_v2/legacy_coin.h>
#include <lotus_v2/sparse_state.h>
#include <streams.h>

namespace lotus::v2 {
/** Index facts for the legacy grammar, without inventing V2 branches or
 * witnesses. Input selectors 4/5 mean legacy spend/coinbase; 1/2/3 retain
 * native meanings. Transaction identities always come from CTransaction, never
 * this projection.
 */
struct ChronikLegacyFacts {
    std::vector<uint8_t> wire;
    std::vector<ChronikFullInput> inputs;
    std::vector<std::vector<uint8_t>> outputs;
};
inline ChronikLegacyFacts MakeChronikLegacyFacts(const CTransaction &tx) {
    if (tx.nVersion != 1 && tx.nVersion != 2) {
        throw std::invalid_argument("not a legacy transaction");
    }
    ChronikLegacyFacts facts;
    DataStream stream;
    stream << tx;
    const auto raw = MakeUCharSpan(stream);
    facts.wire.assign(raw.begin(), raw.end());
    size_t pos = 4 + GetSizeOfCompactSize(tx.vin.size());
    for (const auto &in : tx.vin) {
        ChronikFullInput fact;
        std::copy(in.prevout.GetTxId().begin(), in.prevout.GetTxId().end(),
                  fact.prev_txid.begin());
        fact.prev_index = in.prevout.GetN();
        fact.sequence = in.nSequence;
        fact.flags = tx.IsCoinBase() ? 5 : 4;
        if (tx.IsCoinBase() && !in.scriptSig.empty()) {
            fact.has_coinbase_data = true;
            fact.coinbase_data = {pos + 36 +
                                      GetSizeOfCompactSize(in.scriptSig.size()),
                                  in.scriptSig.size()};
        }
        facts.inputs.push_back(std::move(fact));
        pos += GetSerializeSize(in);
    }
    for (const auto &out : tx.vout) {
        // Index even oversized legacy scripts: they are valid transaction
        // outputs, but IsUnspendable removes them from the UTXO set.
        DataStream encoded;
        encoded << out;
        const auto bytes = MakeUCharSpan(encoded);
        std::vector<uint8_t> wire{0x80};
        wire.insert(wire.end(), bytes.begin(), bytes.end());
        facts.outputs.push_back(std::move(wire));
    }
    return facts;
}
} // namespace lotus::v2
#endif
