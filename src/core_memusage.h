// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CORE_MEMUSAGE_H
#define BITCOIN_CORE_MEMUSAGE_H

#include <memusage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>

static inline size_t RecursiveDynamicUsage(const CScript &script) {
    return memusage::DynamicUsage(*static_cast<const CScriptBase *>(&script));
}

static inline size_t RecursiveDynamicUsage(const COutPoint &out) {
    return 0;
}

static inline size_t RecursiveDynamicUsage(const CTxIn &in) {
    size_t mem = RecursiveDynamicUsage(in.scriptSig) +
                 RecursiveDynamicUsage(in.prevout) +
                 memusage::DynamicUsage(in.vWitnesses) +
                 memusage::DynamicUsage(in.vCoinbaseData);
    for (const auto &witness : in.vWitnesses) {
        mem += memusage::DynamicUsage(witness.script) +
               memusage::DynamicUsage(witness.siblings) +
               memusage::DynamicUsage(witness.arguments);
        for (const auto &argument : witness.arguments)
            mem += memusage::DynamicUsage(argument);
    }
    return mem;
}

static inline size_t RecursiveDynamicUsage(const CTxOut &out) {
    size_t mem = RecursiveDynamicUsage(out.scriptPubKey) +
                 memusage::DynamicUsage(out.vBranches) +
                 memusage::DynamicUsage(out.vPaths);
    for (const auto &path : out.vPaths) mem += memusage::DynamicUsage(path);
    return mem;
}

static inline size_t RecursiveDynamicUsage(const CTransaction &tx) {
    // Input/output objects and long scripts share the transaction allocation.
    // Native witnesses, coinbase payloads, branches and paths retain separate
    // allocations; borrowed script storage itself reports zero dynamic usage.
    size_t mem = tx.GetStorageSize();
    for (const auto &input : tx.vin) mem += RecursiveDynamicUsage(input);
    for (const auto &output : tx.vout) mem += RecursiveDynamicUsage(output);
    return mem;
}

static inline size_t RecursiveDynamicUsage(const CMutableTransaction &tx) {
    size_t mem =
        memusage::DynamicUsage(tx.vin) + memusage::DynamicUsage(tx.vout);
    for (std::vector<CTxIn>::const_iterator it = tx.vin.begin();
         it != tx.vin.end(); it++) {
        mem += RecursiveDynamicUsage(*it);
    }
    for (std::vector<CTxOut>::const_iterator it = tx.vout.begin();
         it != tx.vout.end(); it++) {
        mem += RecursiveDynamicUsage(*it);
    }
    return mem;
}

template <typename X>
static inline size_t RecursiveDynamicUsage(const std::shared_ptr<X> &p) {
    return p ? memusage::DynamicUsage(p) + RecursiveDynamicUsage(*p) : 0;
}

#endif // BITCOIN_CORE_MEMUSAGE_H
