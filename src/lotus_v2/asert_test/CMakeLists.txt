cmake_minimum_required(VERSION 3.18)
project(lotus_v2_asert_candidate LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Standalone P04 candidate. lotusd does not link this target.
find_path(LOTUS_BOOST_INCLUDE boost/multiprecision/cpp_int.hpp
    PATHS /opt/homebrew/opt/boost/include)
if(NOT LOTUS_BOOST_INCLUDE)
    message(FATAL_ERROR "Set LOTUS_BOOST_INCLUDE to Boost headers")
endif()
add_executable(lotus_v2_asert_test
    ../asert_candidate.cpp
    ../test_asert_candidate.cpp)
target_include_directories(lotus_v2_asert_test SYSTEM PRIVATE
    "${LOTUS_BOOST_INCLUDE}")
target_compile_options(lotus_v2_asert_test PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
enable_testing()
add_test(NAME lotus_v2_asert_test COMMAND lotus_v2_asert_test)
