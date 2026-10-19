# SLP and ALP token protocols (port of bitcoinsuite-slp).
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/token/alp_parse.cpp
    core/token/color.cpp
    core/token/empp.cpp
    core/token/lokad_id.cpp
    core/token/slp_parse.cpp
    core/token/structs.cpp
    core/token/verify.cpp
)
file(GLOB CHRONIK_NATIVE_TOKEN_TESTS CONFIGURE_DEPENDS
    "${CHRONIK_NATIVE_ROOT}/test/token_*_tests.cpp")
list(APPEND CHRONIK_NATIVE_TEST_SOURCES ${CHRONIK_NATIVE_TOKEN_TESTS})
