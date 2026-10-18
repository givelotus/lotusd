# Standalone review target; no production node linkage.
cmake_minimum_required(VERSION 3.18)
project(lotus_v2_signing_review LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
get_filename_component(LOTUS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
if(NOT DEFINED LOTUS_SECP_LIBRARY OR NOT EXISTS "${LOTUS_SECP_LIBRARY}")
    message(FATAL_ERROR "Set LOTUS_SECP_LIBRARY to a locally built ABC libsecp256k1.a")
endif()
add_library(lotus_v2_signing_blake3 STATIC
    ../vendor/blake3/blake3.c
    ../vendor/blake3/blake3_dispatch.c
    ../vendor/blake3/blake3_portable.c)
target_compile_definitions(lotus_v2_signing_blake3 PRIVATE
    BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
add_executable(lotus_v2_signing_test
    ../output.cpp ../transaction.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../test_signing.cpp "${LOTUS_SRC}/support/cleanse.cpp")
target_include_directories(lotus_v2_signing_test PRIVATE "${LOTUS_SRC}/secp256k1/include" "${LOTUS_SRC}")
target_link_libraries(lotus_v2_signing_test PRIVATE lotus_v2_signing_blake3 "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_signing_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
enable_testing()
add_test(NAME lotus_v2_signing_test COMMAND lotus_v2_signing_test)

# Instrument the cleansing boundary without recording secret contents. The
# wrapper delegates to the exact ABC primitive and checks zeroed bytes.
add_library(lotus_v2_test_cleanse OBJECT "${LOTUS_SRC}/support/cleanse.cpp")
target_include_directories(lotus_v2_test_cleanse PRIVATE "${LOTUS_SRC}")
target_compile_definitions(lotus_v2_test_cleanse PRIVATE memory_cleanse=lotus_v2_test_real_cleanse)
add_executable(lotus_v2_signing_cleanup_test
    test_cleanup.cpp ../output.cpp ../transaction.cpp ../commitment.cpp
    ../tagged_hash.cpp ../signing.cpp $<TARGET_OBJECTS:lotus_v2_test_cleanse>)
target_include_directories(lotus_v2_signing_cleanup_test PRIVATE
    "${LOTUS_SRC}/secp256k1/include" "${LOTUS_SRC}")
target_link_libraries(lotus_v2_signing_cleanup_test PRIVATE
    lotus_v2_signing_blake3 "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_signing_cleanup_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME lotus_v2_signing_cleanup_test COMMAND lotus_v2_signing_cleanup_test)
