# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# The /v2 and /v2/explorer/v1 JSON routes over the native V2 service.
if(CHRONIK_NATIVE_MDBX)
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_SOURCES
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/http/explorer_routes.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/http/json.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/http/util.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/http/v2_routes.cpp"
    )
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_TEST_SOURCES
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/http/test/v2_explorer_http_tests.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/http/test/v2_http_json_tests.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/http/test/v2_http_tests.cpp"
    )
endif()
