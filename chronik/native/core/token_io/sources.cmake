# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Token DB index (port of chronik-db io/token/{data,batch,io}.rs): the
# token_tx, token_meta and token_genesis_info tables. Needs core/token and
# core/index.
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/token_io/batch.cpp
    core/token_io/data.cpp
    core/token_io/io.cpp
    core/token_io/token_index.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/token_io_tests.cpp
)
