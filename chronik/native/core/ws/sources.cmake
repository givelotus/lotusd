# WebSocket subscription limits (port of chronik-http subscription_limits.rs)
# and the per-session handler (port of chronik-http ws.rs).
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/ws/limits.cpp
    core/ws/ws_handler.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/ws_limits_tests.cpp
    test/ws_handler_tests.cpp
)
