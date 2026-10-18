# Standalone wallet API tests using reviewed full-tree static libraries.
cmake_minimum_required(VERSION 3.18)
project(lotus_v2_native_wallet LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT EXISTS "${LOTUS_BUILD_DIR}/src/wallet/libwallet.a")
    message(FATAL_ERROR "Set LOTUS_BUILD_DIR to a reviewed full-tree wallet-enabled build")
endif()
get_filename_component(LOTUS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)
get_filename_component(LOTUS_DEPENDENCY_SOURCE_ROOT "${LOTUS_BUILD_DIR}/.." REALPATH)
# DiskStateOptions changed layout during development; mixing a command checkout's
# headers with another build's validation archive caused a demonstrated failure.
# Consume command source and headers from the exact source owning these libraries.
if(DEFINED LOTUS_COMMAND_SOURCE_ROOT AND NOT LOTUS_COMMAND_SOURCE_ROOT STREQUAL "")
    get_filename_component(LOTUS_COMMAND_SOURCE_ROOT "${LOTUS_COMMAND_SOURCE_ROOT}" REALPATH)
    if(NOT LOTUS_COMMAND_SOURCE_ROOT STREQUAL LOTUS_DEPENDENCY_SOURCE_ROOT)
        message(FATAL_ERROR "Command source must match LOTUS_BUILD_DIR's source root; mixed header/library ABI is unsupported")
    endif()
endif()
set(LOTUS_COMMAND_SOURCE_ROOT "${LOTUS_DEPENDENCY_SOURCE_ROOT}")
file(READ "${LOTUS_DEPENDENCY_SOURCE_ROOT}/src/lotus_v2/development_command.h" COMMAND_HEADER)
string(FIND "${COMMAND_HEADER}" "OpenDevelopmentHome" COMMAND_ADAPTER)
if(COMMAND_ADAPTER EQUAL -1)
    message(FATAL_ERROR "The dependency build needs the reviewed OpenDevelopmentHome adapter and signer cleansing")
endif()
add_executable(v2_wallet_test
    main.cpp ../test/v2_wallet_tests.cpp ../v2_wallet.cpp ../v2_payment.cpp
    ../sqlite.cpp ../crypter.cpp)
target_compile_definitions(v2_wallet_test PRIVATE LOTUS_V2_WALLET_STANDALONE=1 HAVE_CONFIG_H=1)
function(configure_wallet_target target)
    target_include_directories(${target} PRIVATE "${LOTUS_SRC}" "${LOTUS_BUILD_DIR}/src"
        "${LOTUS_SRC}/secp256k1/include" "${LOTUS_SRC}/univalue/include" /opt/homebrew/opt/boost/include)
    target_include_directories(${target} BEFORE PRIVATE "${LOTUS_DEPENDENCY_SOURCE_ROOT}/src")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
    set(B "${LOTUS_BUILD_DIR}/src")
    target_link_libraries(${target} PRIVATE
        "${B}/lotus_v2/liblotus_v2_validation.a"
        "${B}/lotus_v2/liblotus_v2_incremental_utxo.a"
        "${B}/lotus_v2/liblotus_v2_sparse_state.a"
        "${B}/lotus_v2/liblotus_v2_commitment.a"
        "${B}/lotus_v2/liblotus_v2_header.a"
        "${B}/lotus_v2/liblotus_v2_blake3.a"
        "${B}/leveldb/libleveldb.a" "${B}/crc32c/libcrc32c.a"
        "${B}/libcommon.a" "${B}/libutil.a" "${B}/libbitcoinconsensus.a"
        "${B}/libscript.a" "${B}/libcommon.a" "${B}/libutil.a"
        "${B}/crypto/libcrypto.a" "${B}/secp256k1/libsecp256k1.a"
        SQLite3::SQLite3 OpenSSL::Crypto Threads::Threads)
endfunction()
configure_wallet_target(v2_wallet_test)
if(LOTUS_COMMAND_SOURCE_ROOT)
    add_executable(lotus-v2-wallet-pilot pilot.cpp ../v2_wallet.cpp ../v2_payment.cpp
        ../sqlite.cpp ../crypter.cpp "${LOTUS_COMMAND_SOURCE_ROOT}/src/lotus_v2/development_command.cpp")
    configure_wallet_target(lotus-v2-wallet-pilot)
    target_compile_definitions(lotus-v2-wallet-pilot PRIVATE HAVE_CONFIG_H=1)
    target_include_directories(lotus-v2-wallet-pilot BEFORE PRIVATE "${LOTUS_COMMAND_SOURCE_ROOT}/src")
    target_link_libraries(lotus-v2-wallet-pilot PRIVATE "${LOTUS_BUILD_DIR}/src/univalue/libunivalue.a")
endif()
enable_testing()
add_test(NAME v2_wallet_test COMMAND v2_wallet_test)
