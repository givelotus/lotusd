# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Bounded V2 queries: branch postings, explorer pages and asset pages.
if(CHRONIK_NATIVE_MDBX)
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_SOURCES
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/query/assets.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/query/branches.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/query/explorer.cpp"
    )
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_TEST_SOURCES
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/query/test/v2_query_assets_tests.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/query/test/v2_query_branches_tests.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/query/test/v2_query_explorer_tests.cpp"
    )
endif()
