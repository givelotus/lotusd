# ChronikIndexer (port of chronik-indexer indexer.rs) and the core routes.
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/indexer/indexer.cpp
    core/indexer/routes.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/indexer_tests.cpp
    test/indexer_property_tests.cpp
)
