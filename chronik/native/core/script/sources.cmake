# Script parsing and classification (port of bitcoinsuite-core script).
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/script/opcode.cpp
    core/script/script.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/script_tests.cpp
)
