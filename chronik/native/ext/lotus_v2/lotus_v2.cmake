# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Lotus V2 tier extension of the native Chronik (design C1 §5, §7.2):
# the V2 branch/asset groups of the legacy index and the native V2 service
# (v2_index env, /v2 and /v2/explorer/v1 routes). Plain C++ on the native
# core; it never includes node headers (the host adapter converts node
# blocks into the extension's input).
#
# Each area keeps its own list in ext/lotus_v2/<area>/sources.cmake,
# appending to CHRONIK_NATIVE_LOTUS_V2_SOURCES / _TEST_SOURCES and, for
# libraries it needs (e.g. the MDBX store), CHRONIK_NATIVE_LOTUS_V2_LIBRARIES.

set(CHRONIK_NATIVE_LOTUS_V2_ROOT "${CHRONIK_NATIVE_ROOT}/ext/lotus_v2")
set(CHRONIK_NATIVE_LOTUS_V2_SOURCES
    "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/types.cpp"
)
set(CHRONIK_NATIVE_LOTUS_V2_TEST_SOURCES
    "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/test/types_tests.cpp"
)
set(CHRONIK_NATIVE_LOTUS_V2_LIBRARIES)
file(GLOB _lotus_v2_source_lists CONFIGURE_DEPENDS
    "${CHRONIK_NATIVE_LOTUS_V2_ROOT}/*/sources.cmake")
list(SORT _lotus_v2_source_lists)
foreach(_list ${_lotus_v2_source_lists})
    include("${_list}")
endforeach()

add_library(chronik_native_lotus_v2 STATIC ${CHRONIK_NATIVE_LOTUS_V2_SOURCES})
target_include_directories(chronik_native_lotus_v2
    PUBLIC "${CHRONIK_NATIVE_ROOT}")
target_link_libraries(chronik_native_lotus_v2
    PUBLIC chronik_native_core ${CHRONIK_NATIVE_LOTUS_V2_LIBRARIES})
set_target_properties(chronik_native_lotus_v2 PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

target_sources(test_chronik_native PRIVATE ${CHRONIK_NATIVE_LOTUS_V2_TEST_SOURCES})
target_link_libraries(test_chronik_native chronik_native_lotus_v2)
target_compile_definitions(test_chronik_native PRIVATE
    # The Rust V2 test vectors, shared with bitcoinsuite-core.
    CHRONIK_NATIVE_LOTUS_V2_FIXTURES_DIR="${CHRONIK_NATIVE_REPO_ROOT}/chronik/bitcoinsuite-core/src/lotus_v2/fixtures"
)
