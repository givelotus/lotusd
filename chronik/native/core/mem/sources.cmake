# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Mempool indexes (port of chronik-db mem/{data,group_history,group_utxos,
# spent_by,mempool}.rs, without tokens and plugins). Needs core/groups.
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/mem/group_history.cpp
    core/mem/group_utxos.cpp
    core/mem/mempool.cpp
    core/mem/spent_by.cpp
    core/mem/tokens.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/mem_group_history_tests.cpp
    test/mem_group_utxos_tests.cpp
    test/mem_mempool_tests.cpp
    test/mem_spent_by_tests.cpp
    test/mem_tokens_tests.cpp
)
