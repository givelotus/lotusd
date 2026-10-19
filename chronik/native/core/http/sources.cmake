# HTTP framework: router, errors, protobuf extractor, parameter parsing.
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/http/http.cpp
    core/http/router.cpp
    core/http/protobuf_io.cpp
    core/http/parse.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/http_tests.cpp
)
