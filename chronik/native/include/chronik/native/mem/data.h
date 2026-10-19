// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MEM_DATA_H
#define CHRONIK_NATIVE_MEM_DATA_H

#include <chronik/native/index/group_history.h>
#include <chronik/native/index/group_utxos.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/index/spent_by.h>
#include <chronik/native/index/txs.h>

/** Port of chronik-db mem/data.rs: in-memory data of the DB writers. */
namespace chronik::native::mem {

/** Settings for the in-memory data. */
struct MemDataConf {
    /** Settings for tuning TxNumCache. */
    index::TxNumCacheSettings tx_num_cache;
    /** Settings for script history */
    index::GroupHistorySettings script_history;
};

/** Stats data of the writers. */
struct StatsData {
    index::TxsStats txs;
    index::GroupHistoryStats script_history;
    index::GroupUtxoStats script_utxos;
    index::SpentByStats spent_by;
};

/** In-memory data for indexing. */
struct MemData {
    /** In-memory data for indexing txs. */
    index::TxsMemData txs;
    /** In-memory TxNumCache. */
    index::TxNumCache tx_num_cache;
    /** In-memory data for indexing script tx history. */
    index::GroupHistoryMemData script_history;
    /** In-memory data for indexing script UTXOs. */
    index::GroupUtxoMemData script_utxos;
    /** In-memory data for indexing spent-by data. */
    index::SpentByMemData spent_by;

    explicit MemData(const MemDataConf &conf)
        : tx_num_cache(conf.tx_num_cache),
          script_history(conf.script_history) {}

    /** Only the stats data from this MemData. */
    StatsData Stats() const {
        return StatsData{txs.stats, script_history.stats, script_utxos.stats,
                         spent_by.stats};
    }
};

} // namespace chronik::native::mem

#endif // CHRONIK_NATIVE_MEM_DATA_H
