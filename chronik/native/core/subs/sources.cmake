# Subscription hub (port of chronik-indexer subs.rs / subs_group.rs).
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/subs/subs.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/subs_tests.cpp
)
