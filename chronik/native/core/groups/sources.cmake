# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Groups (port of chronik-db group.rs, groups/{script,lokad_id,txid}.rs) and
# the group engine: io/group_history.rs, io/group_utxos.rs. The engine lives
# in core/index/ but is listed here, so the index tables (core/index/) build
# without groups.
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/groups/group.cpp
    core/groups/lokad_id.cpp
    core/groups/script.cpp
    core/groups/token_id.cpp
    core/groups/txid.cpp
    core/index/group_history.cpp
    core/index/group_utxos.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/groups_script_tests.cpp
    test/groups_token_id_tests.cpp
    test/index_group_history_tests.cpp
    test/index_group_utxos_tests.cpp
)
