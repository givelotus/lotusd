# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Compile the shared chronik.proto (the same file the Rust build uses) with
# protoc. The generated header is included as <chronik.pb.h>; the messages are
# in namespace ::chronik (package chronik), aliased as chronik::native::proto by
# <chronik/native/proto.h>.
#
# The protobuf-config.cmake file is preferred, as recent protobuf (> 21) does
# not play nicely with the cmake-supplied FindProtobuf.cmake (Abseil
# dependencies, versioning). Fall back to FindProtobuf otherwise. Same pattern
# as src/qt/CMakeLists.txt.
find_package(Protobuf CONFIG QUIET)
if(NOT Protobuf_FOUND)
    find_package(Protobuf REQUIRED)
endif()

set(CHRONIK_NATIVE_PROTO_DIR "${CHRONIK_NATIVE_REPO_ROOT}/chronik/chronik-proto/proto")
set(CHRONIK_NATIVE_PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/proto")
file(MAKE_DIRECTORY "${CHRONIK_NATIVE_PROTO_OUT_DIR}")

add_library(chronik_native_proto STATIC
    "${CHRONIK_NATIVE_PROTO_DIR}/chronik.proto"
)
target_link_libraries(chronik_native_proto PUBLIC protobuf::libprotobuf)
target_include_directories(chronik_native_proto
    PUBLIC "$<BUILD_INTERFACE:${CHRONIK_NATIVE_PROTO_OUT_DIR}>"
)
set_target_properties(chronik_native_proto PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

if(COMMAND protobuf_generate)
    protobuf_generate(
        LANGUAGE cpp
        TARGET chronik_native_proto
        IMPORT_DIRS "${CHRONIK_NATIVE_PROTO_DIR}"
        PROTOC_OUT_DIR "${CHRONIK_NATIVE_PROTO_OUT_DIR}"
    )
else()
    # Old FindProtobuf without protobuf_generate
    protobuf_generate_cpp(_CHRONIK_PB_SRCS _CHRONIK_PB_HDRS
        "${CHRONIK_NATIVE_PROTO_DIR}/chronik.proto")
    target_sources(chronik_native_proto PRIVATE ${_CHRONIK_PB_SRCS})
    target_include_directories(chronik_native_proto
        PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>")
endif()

# Generated code is not ours to lint/warn about.
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(chronik_native_proto PRIVATE -w)
endif()
if(ENABLE_CLANG_TIDY)
    include(ClangTidy)
    target_disable_clang_tidy(chronik_native_proto)
endif()

target_link_libraries(chronik_native_core PUBLIC chronik_native_proto)
