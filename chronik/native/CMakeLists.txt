# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Native C++ Chronik (CHRONIK_IMPLEMENTATION=native).
#
# This directory builds either as part of the node (added from
# chronik/CMakeLists.txt) or standalone, for fast iteration on the core and its
# unit tests:
#
#   cmake -GNinja -S chronik/native -B build/native-core
#   ninja -C build/native-core test_chronik_native
#
# The core (chronik_native_core) depends only on the C++20 standard library,
# and later libprotobuf and header-only Boost. It never includes node headers
# and never includes a database header: storage goes through the KvStore
# interface, implemented by separate backend libraries.

cmake_minimum_required(VERSION 3.22)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(chronik_native LANGUAGES C CXX)
    set(CHRONIK_NATIVE_STANDALONE ON)
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()
    enable_testing()
else()
    set(CHRONIK_NATIVE_STANDALONE OFF)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CHRONIK_NATIVE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CHRONIK_NATIVE_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
find_package(Boost 1.73 REQUIRED CONFIG)

# Storage backends. The core only knows the KvStore interface; each backend is
# its own library so a host links exactly the backends it uses (e.g. BCHN can
# build LevelDB-only, with no MDBX code linked).
option(CHRONIK_NATIVE_MDBX "Build the MDBX storage backend (default backend)" ON)
option(CHRONIK_NATIVE_LEVELDB "Build the optional LevelDB storage backend" OFF)
if(NOT CHRONIK_NATIVE_MDBX AND NOT CHRONIK_NATIVE_LEVELDB)
    message(FATAL_ERROR "The native Chronik needs at least one storage backend")
endif()

# ---- Source lists ----
# Each area of the core keeps its own source list in <area>/sources.cmake,
# appending to these variables, so areas can be added independently.
set(CHRONIK_NATIVE_CORE_SOURCES core/version.cpp)
set(CHRONIK_NATIVE_TEST_SOURCES test/main.cpp test/skeleton_tests.cpp)
file(GLOB CHRONIK_NATIVE_SOURCE_LISTS CONFIGURE_DEPENDS
    "${CHRONIK_NATIVE_ROOT}/core/*/sources.cmake")
list(SORT CHRONIK_NATIVE_SOURCE_LISTS)
foreach(_list ${CHRONIK_NATIVE_SOURCE_LISTS})
    include("${_list}")
endforeach()
# Libraries the unit tests link in addition to the core (backends, protobuf).
# Backend/transport source lists below append to it.

# ---- Storage backends (each its own library; see store/store.cmake) ----
include("${CHRONIK_NATIVE_ROOT}/store/store.cmake")

# ---- Core library ----
add_library(chronik_native_core STATIC ${CHRONIK_NATIVE_CORE_SOURCES})
target_include_directories(chronik_native_core
    PUBLIC
        "${CHRONIK_NATIVE_ROOT}/include"
    PRIVATE
        "${CHRONIK_NATIVE_ROOT}"
)
target_link_libraries(chronik_native_core PUBLIC Boost::headers)
set_target_properties(chronik_native_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

# ---- Unit tests (core only, plus a fake host) ----
add_executable(test_chronik_native ${CHRONIK_NATIVE_TEST_SOURCES})
target_include_directories(test_chronik_native PRIVATE "${CHRONIK_NATIVE_ROOT}")
target_link_libraries(test_chronik_native
    chronik_native_core
    ${CHRONIK_NATIVE_TEST_LIBRARIES}
    Boost::headers
)
target_compile_definitions(test_chronik_native PRIVATE
    CHRONIK_NATIVE_FIXTURES_DIR="${CHRONIK_NATIVE_ROOT}/test/fixtures"
)
if(CHRONIK_NATIVE_STANDALONE)
    add_test(NAME test_chronik_native COMMAND test_chronik_native)
else()
    add_custom_target(check-chronik-native
        COMMAND test_chronik_native
        DEPENDS test_chronik_native
        COMMENT "Running native Chronik unit tests"
    )
endif()

# ---- Protobuf messages (chronik.proto) and HTTP/WS transports ----
include("${CHRONIK_NATIVE_ROOT}/proto/proto.cmake")
include("${CHRONIK_NATIVE_ROOT}/transport/transport.cmake")
include("${CHRONIK_NATIVE_ROOT}/core/service/service.cmake")

# ---- Host adapter (node build only) ----
if(NOT CHRONIK_NATIVE_STANDALONE)
    add_library(chronik_native_host_abc STATIC
        hosts/abc/abc_entry.cpp
        # chronik::native::Host for the node (ChronikBridge port).
        hosts/abc/abc_host.cpp
        # Validation-interface worker feeding the Service.
        hosts/abc/abc_subscriber.cpp
        # In-process /chronik on the node's HTTP server.
        hosts/abc/abc_http.cpp
    )
    target_include_directories(chronik_native_host_abc
        PUBLIC
            # Provides <chronik-cpp/chronik.h>, the entry points init.cpp uses.
            "${CHRONIK_NATIVE_REPO_ROOT}/chronik"
            # Provides <hosts/abc/abc_host.h> to the node's unit tests.
            "${CHRONIK_NATIVE_ROOT}"
    )
    target_link_libraries(chronik_native_host_abc
        chronik_native_core
        chronik_native_service
        util
    )
    # Storage backends: only the selected ones are linked.
    if(CHRONIK_NATIVE_MDBX)
        target_link_libraries(chronik_native_host_abc chronik_native_store_mdbx)
        target_compile_definitions(chronik_native_host_abc
            PRIVATE CHRONIK_NATIVE_HAVE_MDBX=1)
    endif()
    target_link_libraries(server chronik_native_host_abc)
endif()

# ---- Tools ----
if(CHRONIK_NATIVE_MDBX)
    # DB dump for the parity tooling (contrib/chronik-parity).
    add_executable(chronik-native-dump tools/chronik_native_dump.cpp)
    target_include_directories(chronik-native-dump PRIVATE "${CHRONIK_NATIVE_ROOT}")
    target_link_libraries(chronik-native-dump chronik_native_store_mdbx chronik_native_core)
endif()
