# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# V2 branch/asset groups of the legacy index (chronik-db groups/v2.rs).
list(APPEND CHRONIK_NATIVE_LOTUS_V2_SOURCES
    "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/groups/groups.cpp"
)
list(APPEND CHRONIK_NATIVE_LOTUS_V2_TEST_SOURCES
    "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/groups/test/groups_tests.cpp"
)
