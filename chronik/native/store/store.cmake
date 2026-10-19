# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Storage backends of the native Chronik. Each backend is a separate library
# implementing the KvStore interface (include/chronik/native/store.h); the core
# library never links a database. Hosts link the backends they select and call
# their Register*Store() functions.

if(CHRONIK_NATIVE_MDBX)
    if(NOT TARGET lotus_v2_mdbx)
        # Standalone build: the vendored libmdbx, compiled exactly as
        # src/lotus_v2/CMakeLists.txt does for the node.
        set(_mdbx_dir "${CHRONIK_NATIVE_REPO_ROOT}/src/lotus_v2/vendor/libmdbx")
        add_library(lotus_v2_mdbx STATIC
            "${_mdbx_dir}/mdbx.c"
            "${_mdbx_dir}/mdbx_batch.c"
        )
        set_target_properties(lotus_v2_mdbx PROPERTIES
            C_STANDARD 11 POSITION_INDEPENDENT_CODE ON)
        target_include_directories(lotus_v2_mdbx PUBLIC "${_mdbx_dir}")
        target_compile_definitions(lotus_v2_mdbx
            PUBLIC MDBX_BUILD_SHARED_LIBRARY=0
            PRIVATE NDEBUG MDBX_BUILD_FLAGS="-O3 -DNDEBUG" MDBX_WITHOUT_MSVC_CRT=0)
        target_compile_options(lotus_v2_mdbx PRIVATE -O3 -Wno-unused-parameter
            -Wno-sign-compare -Wno-cast-align -Wno-gnu -Wno-shadow
            -Wno-documentation -Wno-implicit-fallthrough)
        find_package(Threads REQUIRED)
        target_link_libraries(lotus_v2_mdbx PUBLIC Threads::Threads)
    endif()

    add_library(chronik_native_store_mdbx STATIC
        "${CHRONIK_NATIVE_ROOT}/store/mdbx/mdbx_store.cpp"
    )
    target_include_directories(chronik_native_store_mdbx
        PUBLIC "${CHRONIK_NATIVE_ROOT}/include")
    target_link_libraries(chronik_native_store_mdbx
        PUBLIC chronik_native_core
        PRIVATE lotus_v2_mdbx)
    set_target_properties(chronik_native_store_mdbx PROPERTIES
        POSITION_INDEPENDENT_CODE ON)
    target_compile_definitions(chronik_native_store_mdbx
        PUBLIC CHRONIK_NATIVE_HAVE_MDBX=1)
    list(APPEND CHRONIK_NATIVE_TEST_LIBRARIES chronik_native_store_mdbx)
endif()

if(CHRONIK_NATIVE_LEVELDB)
    if(NOT TARGET leveldb)
        # Standalone build: the node's vendored LevelDB (and its crc32c),
        # without their tests.
        list(APPEND CMAKE_MODULE_PATH "${CHRONIK_NATIVE_REPO_ROOT}/cmake/modules")
        include(AddCompilerFlags)
        set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(CRC32C_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        add_subdirectory("${CHRONIK_NATIVE_REPO_ROOT}/src/crc32c"
            "${CMAKE_CURRENT_BINARY_DIR}/vendor/crc32c" EXCLUDE_FROM_ALL)
        add_subdirectory("${CHRONIK_NATIVE_REPO_ROOT}/src/leveldb"
            "${CMAKE_CURRENT_BINARY_DIR}/vendor/leveldb" EXCLUDE_FROM_ALL)
    endif()

    add_library(chronik_native_store_leveldb STATIC
        "${CHRONIK_NATIVE_ROOT}/store/leveldb/leveldb_store.cpp"
    )
    target_include_directories(chronik_native_store_leveldb
        PUBLIC "${CHRONIK_NATIVE_ROOT}/include")
    target_link_libraries(chronik_native_store_leveldb
        PUBLIC chronik_native_core
        PRIVATE leveldb)
    set_target_properties(chronik_native_store_leveldb PROPERTIES
        POSITION_INDEPENDENT_CODE ON)
    target_compile_definitions(chronik_native_store_leveldb
        PUBLIC CHRONIK_NATIVE_HAVE_LEVELDB=1)
    list(APPEND CHRONIK_NATIVE_TEST_LIBRARIES chronik_native_store_leveldb)
endif()
