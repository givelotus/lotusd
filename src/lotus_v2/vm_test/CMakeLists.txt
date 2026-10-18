# Standalone P03 review target. P05 accounting is deliberately outside this core.
cmake_minimum_required(VERSION 3.18)
project(lotus_v2_vm_core_review LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
get_filename_component(LOTUS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
include_directories("${LOTUS_SRC}")
if(NOT DEFINED LOTUS_SECP_LIBRARY OR NOT EXISTS "${LOTUS_SECP_LIBRARY}")
    message(FATAL_ERROR "Set LOTUS_SECP_LIBRARY to a locally built ABC libsecp256k1.a")
endif()
add_library(lotus_v2_vm_blake3 STATIC
    ../vendor/blake3/blake3.c
    ../vendor/blake3/blake3_dispatch.c
    ../vendor/blake3/blake3_portable.c)
target_compile_definitions(lotus_v2_vm_blake3 PRIVATE
    BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
add_executable(lotus_v2_vm_core_test
    ../vm.cpp ../field_size.cpp ../test_vm.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../../support/cleanse.cpp ../transaction.cpp ../output.cpp)
target_include_directories(lotus_v2_vm_core_test PRIVATE ../ "${LOTUS_SRC}/secp256k1/include")
target_link_libraries(lotus_v2_vm_core_test PRIVATE lotus_v2_vm_blake3 OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_vm_core_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(lotus_v2_vm_core_test PRIVATE LOTUS_V2_VM_TEST_INSTRUMENTATION)
enable_testing()
add_test(NAME lotus_v2_vm_core_test COMMAND lotus_v2_vm_core_test)
add_executable(lotus_v2_vm_runner
    runner.cpp ../vm.cpp ../field_size.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../../support/cleanse.cpp ../transaction.cpp ../output.cpp)
target_include_directories(lotus_v2_vm_runner PRIVATE ../ "${LOTUS_SRC}/secp256k1/include")
target_link_libraries(lotus_v2_vm_runner PRIVATE lotus_v2_vm_blake3 OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_vm_runner PRIVATE -Wall -Wextra -Wpedantic -Werror)
