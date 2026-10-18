cmake_minimum_required(VERSION 3.18)
project(lotus_v2_existing_home LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(../disk_state_test disk_state)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
if(NOT DEFINED LOTUS_SECP_LIBRARY OR NOT EXISTS "${LOTUS_SECP_LIBRARY}")
    message(FATAL_ERROR "Set LOTUS_SECP_LIBRARY to ABC libsecp256k1.a")
endif()
get_filename_component(LOTUS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_executable(existing_home_test
    ../../support/cleanse.cpp
    ../header_admission.cpp ../disk_body.cpp ../development_chain.cpp ../disk_block.cpp ../block_transition.cpp test_existing_home.cpp
    ../output.cpp ../transaction.cpp ../commitment.cpp ../tagged_hash.cpp
    ../signing.cpp ../vm.cpp ../field_size.cpp ../sparse_state.cpp
    ../incremental_utxo.cpp ../ordinary_validation.cpp ../monetary.cpp
    ../block.cpp ../block_wire.cpp ../block_cost.cpp ../header_context.cpp
    ../asert_candidate.cpp ../header.cpp)
target_include_directories(existing_home_test PRIVATE "${LOTUS_SRC}" "${LOTUS_SRC}/secp256k1/include"
    "${LOTUS_BOOST_INCLUDE}" ../vendor/blake3)
target_link_libraries(existing_home_test PRIVATE lotus_v2_disk_state blake3
    OpenSSL::Crypto "${LOTUS_SECP_LIBRARY}")
target_compile_options(existing_home_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
enable_testing()
add_test(NAME existing_home_test COMMAND existing_home_test)
