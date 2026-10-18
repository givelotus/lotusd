cmake_minimum_required(VERSION 3.18)
project(lotus_v2_disk_block LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(../disk_state_test disk_state)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
if(NOT DEFINED LOTUS_SECP_LIBRARY OR NOT EXISTS "${LOTUS_SECP_LIBRARY}")
    message(FATAL_ERROR "Set LOTUS_SECP_LIBRARY to ABC libsecp256k1.a")
endif()
get_filename_component(LOTUS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
include_directories("${LOTUS_SRC}")
add_executable(disk_block_test
    ../disk_block.cpp ../block_transition.cpp ../test_block_complete.cpp
    ../output.cpp ../transaction.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../../support/cleanse.cpp ../vm.cpp ../field_size.cpp ../sparse_state.cpp
    ../incremental_utxo.cpp ../ordinary_validation.cpp ../monetary.cpp
    ../block.cpp ../block_wire.cpp ../block_cost.cpp ../header_context.cpp
    ../asert_candidate.cpp ../header.cpp)
target_compile_definitions(disk_block_test PRIVATE LOTUS_V2_TEST_DISK=1)
target_include_directories(disk_block_test PRIVATE "${LOTUS_SRC}/secp256k1/include"
    "${LOTUS_BOOST_INCLUDE}" ../vendor/blake3)
target_link_libraries(disk_block_test PRIVATE lotus_v2_disk_state blake3
    OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(disk_block_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
enable_testing()
add_test(NAME disk_block_test COMMAND disk_block_test)
