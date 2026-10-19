# Indexer helpers: pause/resume, block merkle proofs, Avalanche state
# (port of chronik-indexer pause.rs, merkle.rs, avalanche.rs).
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/indexer_util/avalanche.cpp
    core/indexer_util/merkle.cpp
    core/indexer_util/pause.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/avalanche_tests.cpp
    test/merkle_tests.cpp
    test/pause_tests.cpp
)
