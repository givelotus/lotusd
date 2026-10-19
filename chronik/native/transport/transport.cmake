# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# HTTP/WebSocket transports: the query pool and the standalone Beast listener
# (-chronikbind). Header-only Boost.Asio/Beast.
add_library(chronik_native_transport STATIC
    transport/query_pool.cpp
    transport/beast_listener.cpp
)
target_include_directories(chronik_native_transport
    PUBLIC "${CHRONIK_NATIVE_ROOT}/include"
)
target_link_libraries(chronik_native_transport
    PUBLIC chronik_native_core Boost::headers
)
find_package(Threads REQUIRED)
target_link_libraries(chronik_native_transport PUBLIC Threads::Threads)
set_target_properties(chronik_native_transport PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

target_sources(test_chronik_native PRIVATE
    test/transport_tests.cpp
)
target_link_libraries(test_chronik_native chronik_native_transport)
