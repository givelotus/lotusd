cmake_minimum_required(VERSION 3.18)
project(lotus_v2_candidate_body_pool_review LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
get_filename_component(LOTUS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
include_directories("${LOTUS_SRC}")
if(NOT DEFINED LOTUS_SECP_LIBRARY OR NOT EXISTS "${LOTUS_SECP_LIBRARY}")
    message(FATAL_ERROR "Set LOTUS_SECP_LIBRARY to a locally built ABC libsecp256k1.a")
endif()
add_library(pool_blake3 STATIC ../vendor/blake3/blake3.c
    ../vendor/blake3/blake3_dispatch.c ../vendor/blake3/blake3_portable.c)
target_compile_definitions(pool_blake3 PRIVATE BLAKE3_NO_SSE2 BLAKE3_NO_SSE41
    BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
add_executable(lotus_v2_candidate_body_pool_test ../candidate_body_pool.cpp ../test_candidate_body_pool.cpp
    ../header.cpp ../block_wire.cpp ../transaction.cpp ../output.cpp
    ../commitment.cpp ../signing.cpp ../../support/cleanse.cpp ../tagged_hash.cpp
    ../../crypto/sha256.cpp ../../crypto/siphash.cpp)
target_include_directories(lotus_v2_candidate_body_pool_test PRIVATE "${LOTUS_SRC}"
    "${LOTUS_SRC}/secp256k1/include")
target_link_libraries(lotus_v2_candidate_body_pool_test PRIVATE pool_blake3 "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_candidate_body_pool_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
if(LOTUS_SANITIZE)
    target_compile_options(lotus_v2_candidate_body_pool_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(lotus_v2_candidate_body_pool_test PRIVATE -fsanitize=address,undefined)
endif()
set_source_files_properties(../../crypto/sha256.cpp PROPERTIES
    COMPILE_OPTIONS "-Wno-unused-function")
enable_testing()
add_test(NAME lotus_v2_candidate_body_pool_test COMMAND lotus_v2_candidate_body_pool_test)
