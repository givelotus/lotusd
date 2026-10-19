// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MEM_MEMPOOL_TX_H
#define CHRONIK_NATIVE_MEM_MEMPOOL_TX_H

#include <chronik/native/types.h>

#include <cstdint>

namespace chronik::native::mem {

/** Rust `MempoolTx`: tx in the mempool. */
struct MempoolTx {
    /** Transaction, including spent coins. */
    TxRef tx;
    /** Time this tx has been added to the node's mempool. */
    int64_t time_first_seen = 0;
};

} // namespace chronik::native::mem

#endif // CHRONIK_NATIVE_MEM_MEMPOOL_TX_H
