# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# The native V2 service: transitions, status, branch queries and authority.
if(CHRONIK_NATIVE_MDBX)
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_SOURCES
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/service/authority.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/service/service.cpp"
    )
    list(APPEND CHRONIK_NATIVE_LOTUS_V2_TEST_SOURCES
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/service/test/v2_authority_tests.cpp"
        "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/service/test/v2_service_tests.cpp"
    )
endif()
