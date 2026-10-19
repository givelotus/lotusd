# Service: indexer + router + query pool + listeners (port of chronik-lib
# bridge.rs setup). A separate library because it needs the transport; host
# adapters link chronik_native_service.
add_library(chronik_native_service STATIC
    core/service/bind_parse.cpp
    core/service/service.cpp
)
target_include_directories(chronik_native_service
    PUBLIC "${CHRONIK_NATIVE_ROOT}/include"
    PRIVATE "${CHRONIK_NATIVE_ROOT}"
)
target_link_libraries(chronik_native_service
    PUBLIC chronik_native_core chronik_native_transport
)
set_target_properties(chronik_native_service PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

target_sources(test_chronik_native PRIVATE
    test/service_tests.cpp
)
target_link_libraries(test_chronik_native chronik_native_service)
