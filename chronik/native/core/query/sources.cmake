# Query layer (port of chronik-indexer query/*.rs and chronik-http
# handlers.rs / server.rs routes).
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/query/util.cpp
    core/query/blocks.cpp
    core/query/txs.cpp
    core/query/group_history.cpp
    core/query/group_utxos.cpp
    core/query/broadcast.cpp
    core/query/handlers.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/query_tests.cpp
)
