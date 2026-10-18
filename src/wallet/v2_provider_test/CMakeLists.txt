# Standalone wallet API tests using reviewed full-tree static libraries.
cmake_minimum_required(VERSION 3.18)
project(lotus_v2_wallet_provider LANGUAGES C CXX)
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
# Borrowed wallet adapters compile locally. Native storage headers must match
# the source owning the linked validation archives (DiskStateOptions has ABI).
foreach(header disk_state.h disk_block.h sparse_state.h)
    file(SHA256 "${LOTUS_SRC}/lotus_v2/${header}" LOCAL_HEADER_HASH)
    file(SHA256 "${LOTUS_DEPENDENCY_SOURCE_ROOT}/src/lotus_v2/${header}" LIBRARY_HEADER_HASH)
    if(NOT LOCAL_HEADER_HASH STREQUAL LIBRARY_HEADER_HASH)
        message(FATAL_ERROR "Native header/library source mismatch: ${header}")
    endif()
endforeach()
add_executable(v2_provider_test ../test/v2_provider_tests.cpp
    ../v2_wallet.cpp ../v2_payment.cpp ../v2_node_provider.cpp ../sqlite.cpp ../crypter.cpp)
target_compile_definitions(v2_provider_test PRIVATE HAVE_CONFIG_H=1)
function(configure_wallet_target target)
    target_include_directories(${target} PRIVATE "${LOTUS_SRC}" "${LOTUS_BUILD_DIR}/src"
        "${LOTUS_SRC}/secp256k1/include" "${LOTUS_SRC}/univalue/include" /opt/homebrew/opt/boost/include)

    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter -UNDEBUG)
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
        "${B}/univalue/libunivalue.a"
        SQLite3::SQLite3 OpenSSL::Crypto Threads::Threads)
endfunction()
configure_wallet_target(v2_provider_test)
add_executable(v2_provider_wallet_regression ../v2_wallet_test/main.cpp
    ../test/v2_wallet_tests.cpp ../v2_wallet.cpp ../v2_payment.cpp
    ../sqlite.cpp ../crypter.cpp)
target_compile_definitions(v2_provider_wallet_regression PRIVATE
    HAVE_CONFIG_H=1 LOTUS_V2_WALLET_STANDALONE=1)
configure_wallet_target(v2_provider_wallet_regression)
enable_testing()
add_test(NAME v2_provider_test COMMAND v2_provider_test)
add_test(NAME v2_provider_wallet_regression COMMAND v2_provider_wallet_regression)
