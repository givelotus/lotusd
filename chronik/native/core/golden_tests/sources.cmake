# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Golden DB value tests: native decode/encode of the values the Rust
# chronik-db (eCash tier) stores, checked against fixtures/db_values.json
# (written by chronik/chronik-db/tests/export_native_db_values.rs). Test-only;
# needs core/index, core/groups (group_history/group_utxos) and core/token_io.
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/golden_db_values_tests.cpp
)
