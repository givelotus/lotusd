# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Index tables: blocks, txs, block stats, reverse lookups, spent-by, merges
# (port of chronik-db io/{blocks,txs,block_stats,spent_by,merge}.rs,
# reverse_lookup.rs, index_tx.rs, data.rs).
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/index/block_stats.cpp
    core/index/blocks.cpp
    core/index/index_tx.cpp
    core/index/merge.cpp
    core/index/spent_by.cpp
    core/index/txs.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/index_block_stats_tests.cpp
    test/index_blocks_tests.cpp
    test/index_index_tx_tests.cpp
    test/index_merge_tests.cpp
    test/index_reverse_lookup_tests.cpp
    test/index_spent_by_tests.cpp
    test/index_txs_tests.cpp
)
