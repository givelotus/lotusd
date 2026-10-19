# WebSocket subscription limits (port of chronik-http subscription_limits.rs).
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/ws/limits.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/ws_limits_tests.cpp
)
