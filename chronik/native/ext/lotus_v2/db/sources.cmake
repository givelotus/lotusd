# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# The v2_index env (design 060): flat segment files and named MDBX
# subdatabases, the V2 branch DB, explorer and asset facts.
# The service needs the MDBX store: Rust's v2_index layout is an MDBX env
# (16 named DBIs plus flat files). Builds without MDBX have no V2 service.
if(CHRONIK_NATIVE_MDBX)
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_SOURCES
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/asset.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/branch.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/env.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/explorer.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/model.cpp"
    )
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_TEST_SOURCES
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/test/v2_asset_tests.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/test/v2_branch_tests.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/test/v2_env_tests.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/db/test/v2_explorer_model_tests.cpp"
    )
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_LIBRARIES chronik_native_store_mdbx)
endif()
