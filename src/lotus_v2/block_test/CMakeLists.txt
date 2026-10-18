cmake_minimum_required(VERSION 3.18)
project(lotus_v2_block_review LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_path(LOTUS_BOOST_INCLUDE boost/multiprecision/cpp_int.hpp
    PATHS /opt/homebrew/opt/boost/include)
if(NOT LOTUS_BOOST_INCLUDE)
    message(FATAL_ERROR "Set LOTUS_BOOST_INCLUDE to Boost headers")
endif()
get_filename_component(LOTUS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
include_directories("${LOTUS_SRC}")
if(NOT DEFINED LOTUS_SECP_LIBRARY OR NOT EXISTS "${LOTUS_SECP_LIBRARY}")
    message(FATAL_ERROR "Set LOTUS_SECP_LIBRARY to a locally built ABC libsecp256k1.a")
endif()
add_library(lotus_v2_block_blake3 STATIC
    ../vendor/blake3/blake3.c
    ../vendor/blake3/blake3_dispatch.c
    ../vendor/blake3/blake3_portable.c)
target_compile_definitions(lotus_v2_block_blake3 PRIVATE
    BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
add_executable(lotus_v2_block_test
    ../output.cpp ../transaction.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../../support/cleanse.cpp ../vm.cpp ../field_size.cpp ../sparse_state.cpp
    ../incremental_utxo.cpp ../ordinary_validation.cpp ../monetary.cpp
    ../block.cpp ../block_wire.cpp ../block_cost.cpp ../header_context.cpp ../asert_candidate.cpp ../header.cpp
    ../test_block.cpp)
target_include_directories(lotus_v2_block_test PRIVATE
    "${LOTUS_SRC}/secp256k1/include" "${LOTUS_BOOST_INCLUDE}" ../vendor/blake3)
target_link_libraries(lotus_v2_block_test PRIVATE
    lotus_v2_block_blake3 OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_block_test PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Werror>)
add_executable(lotus_v2_block_script_rollback_test
    ../output.cpp ../transaction.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../../support/cleanse.cpp ../vm.cpp ../field_size.cpp ../sparse_state.cpp
    ../incremental_utxo.cpp ../ordinary_validation.cpp ../monetary.cpp
    ../block.cpp ../block_wire.cpp ../block_cost.cpp ../header_context.cpp ../asert_candidate.cpp ../header.cpp
    ../test_block_script_rollback.cpp)
target_include_directories(lotus_v2_block_script_rollback_test PRIVATE
    "${LOTUS_SRC}/secp256k1/include" "${LOTUS_BOOST_INCLUDE}" ../vendor/blake3)
target_link_libraries(lotus_v2_block_script_rollback_test PRIVATE
    lotus_v2_block_blake3 OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_block_script_rollback_test PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Werror>)
add_executable(lotus_v2_block_checksig_test
    ../output.cpp ../transaction.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../../support/cleanse.cpp ../vm.cpp ../field_size.cpp ../sparse_state.cpp
    ../incremental_utxo.cpp ../ordinary_validation.cpp ../monetary.cpp
    ../block.cpp ../block_wire.cpp ../block_cost.cpp ../header_context.cpp ../asert_candidate.cpp ../header.cpp
    ../test_block_checksig.cpp)
target_include_directories(lotus_v2_block_checksig_test PRIVATE
    "${LOTUS_SRC}/secp256k1/include" "${LOTUS_BOOST_INCLUDE}" ../vendor/blake3)
target_link_libraries(lotus_v2_block_checksig_test PRIVATE
    lotus_v2_block_blake3 OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_block_checksig_test PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Werror>)
add_executable(lotus_v2_block_dev_coinbase_test
    ../output.cpp ../transaction.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../../support/cleanse.cpp ../vm.cpp ../field_size.cpp ../sparse_state.cpp
    ../incremental_utxo.cpp ../ordinary_validation.cpp ../monetary.cpp
    ../block.cpp ../block_wire.cpp ../block_cost.cpp ../header_context.cpp ../asert_candidate.cpp ../header.cpp
    ../dev_genesis.cpp ../test_block_dev_coinbase.cpp)
target_include_directories(lotus_v2_block_dev_coinbase_test PRIVATE
    "${LOTUS_SRC}/secp256k1/include" "${LOTUS_BOOST_INCLUDE}" ../vendor/blake3)
target_link_libraries(lotus_v2_block_dev_coinbase_test PRIVATE
    lotus_v2_block_blake3 OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_block_dev_coinbase_test PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Werror>)

enable_testing()
add_test(NAME lotus_v2_block_test COMMAND lotus_v2_block_test)
add_test(NAME lotus_v2_block_script_rollback_test
    COMMAND lotus_v2_block_script_rollback_test)
add_test(NAME lotus_v2_block_checksig_test COMMAND lotus_v2_block_checksig_test)
add_test(NAME lotus_v2_block_dev_coinbase_test
    COMMAND lotus_v2_block_dev_coinbase_test)

add_executable(lotus_v2_block_complete_test
    ../output.cpp ../transaction.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../../support/cleanse.cpp ../vm.cpp ../field_size.cpp ../sparse_state.cpp
    ../incremental_utxo.cpp ../ordinary_validation.cpp ../monetary.cpp
    ../block.cpp ../block_wire.cpp ../block_cost.cpp ../header_context.cpp
    ../asert_candidate.cpp ../header.cpp
    ../block_transition.cpp ../test_block_complete.cpp)
target_include_directories(lotus_v2_block_complete_test PRIVATE
    "${LOTUS_SRC}/secp256k1/include" "${LOTUS_BOOST_INCLUDE}" ../vendor/blake3)
target_link_libraries(lotus_v2_block_complete_test PRIVATE
    lotus_v2_block_blake3 OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(lotus_v2_block_complete_test PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Werror>)
add_test(NAME lotus_v2_block_complete_test COMMAND lotus_v2_block_complete_test)
