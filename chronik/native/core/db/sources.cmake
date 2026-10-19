# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Storage-neutral DB layer: backend registry, table schema, metadata.
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/db/metadata.cpp
    core/db/schema.cpp
    core/db/store_registry.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/metadata_tests.cpp
    test/store_tests.cpp
)
