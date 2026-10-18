cmake_minimum_required(VERSION 3.18)
project(lotus_v2_monetary_review LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_path(LOTUS_BOOST_INCLUDE boost/multiprecision/cpp_int.hpp
    PATHS /opt/homebrew/opt/boost/include)
if(NOT LOTUS_BOOST_INCLUDE)
    message(FATAL_ERROR "Set LOTUS_BOOST_INCLUDE to Boost headers")
endif()
add_executable(lotus_v2_monetary_test
    ../output.cpp ../transaction.cpp ../monetary.cpp ../sparse_state.cpp
    ../tagged_hash.cpp ../test_monetary.cpp
    ../vendor/blake3/blake3.c ../vendor/blake3/blake3_dispatch.c
    ../vendor/blake3/blake3_portable.c)
target_include_directories(lotus_v2_monetary_test PRIVATE "${LOTUS_BOOST_INCLUDE}")
target_include_directories(lotus_v2_monetary_test PRIVATE ../vendor/blake3)
target_compile_definitions(lotus_v2_monetary_test PRIVATE
    BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
target_compile_options(lotus_v2_monetary_test PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Werror>)
enable_testing()
add_test(NAME lotus_v2_monetary_test COMMAND lotus_v2_monetary_test)
