# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license; see the accompanying COPYING.
# T14: compile-time boundary plus a source include audit. This is not a claim
# that text scanning alone proves arbitrary C++ has no semantic truth leak;
# the independent contract review also inspects every public API call site.
cmake_minimum_required(VERSION 3.22)
if(NOT DEFINED SNOWSTORM_SOURCE_ROOT)
    get_filename_component(SNOWSTORM_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." REALPATH)
endif()
set(_root "${SNOWSTORM_SOURCE_ROOT}/src/snowstorm")
file(GLOB_RECURSE _core LIST_DIRECTORIES FALSE
    "${_root}/src/*" "${_root}/include/snowstorm/*")
file(GLOB_RECURSE _oracles LIST_DIRECTORIES FALSE "${_root}/test/oracle/*")
file(GLOB_RECURSE _harness LIST_DIRECTORIES FALSE "${_root}/test/harness/*")
if(NOT _core OR NOT _oracles OR NOT _harness)
    message(FATAL_ERROR "Public API, independent oracles and harness must all exist")
endif()

function(snowstorm_includes FILE OUTPUT)
    file(STRINGS "${FILE}" _lines REGEX "^[ \t]*#[ \t]*include")
    set(_includes)
    foreach(_line IN LISTS _lines)
        if(NOT _line MATCHES "^[ \t]*#[ \t]*include[ \t]*[<\"]([^>\"]+)[>\"]")
            message(FATAL_ERROR "Computed include cannot be audited: ${FILE}: ${_line}")
        endif()
        list(APPEND _includes "${CMAKE_MATCH_1}")
    endforeach()
    set(${OUTPUT} "${_includes}" PARENT_SCOPE)
endfunction()

foreach(_file IN LISTS _core)
    if(NOT _file MATCHES "\\.(h|hpp|c|cpp|cc|cxx)$")
        continue()
    endif()
    snowstorm_includes("${_file}" _includes)
    foreach(_include IN LISTS _includes)
        if(_include MATCHES "(^|/)(test|sim|fuzz|bench|archive)(/|$)" OR _include MATCHES "^/")
            message(FATAL_ERROR "Core/public API forbidden include: ${_file}: ${_include}")
        endif()
    endforeach()
endforeach()

foreach(_file IN LISTS _oracles)
    if(NOT _file MATCHES "\\.(h|hpp|cpp|cc|cxx)$")
        continue()
    endif()
    snowstorm_includes("${_file}" _includes)
    foreach(_include IN LISTS _includes)
        if(_include MATCHES "(^|/)(snowstorm|src|include|harness|acceptance|archive)(/|$)" OR _include MATCHES "^/")
            message(FATAL_ERROR "Independent oracle forbidden include: ${_file}: ${_include}")
        endif()
    endforeach()
endforeach()

# Host sources may include public Snowstorm headers, their own headers, the
# independent external audit oracle, and standard-library headers. Oracle truth
# remains host-side audit data and must never be passed into the node API; that
# semantic boundary is also checked by independent artifact review.
set(_standard_headers
    algorithm array bit bitset cassert cctype cerrno charconv chrono cmath
    compare concepts cstddef cstdint cstdlib cstring deque exception filesystem
    fstream functional iomanip ios iosfwd iostream iterator limits map memory
    numeric optional ostream queue random ranges set span sstream stdexcept
    string string_view tuple type_traits unordered_map unordered_set utility
    variant vector
)
set(_saw_node_header FALSE)
foreach(_file IN LISTS _harness)
    if(NOT _file MATCHES "\\.(h|hpp|cpp|cc|cxx)$")
        continue()
    endif()
    file(READ "${_file}" _contents)
    if(_contents MATCHES "#[ \t]*define[ \t]+(private|protected)" OR
        _contents MATCHES "#[ \t]*include_next")
        message(FATAL_ERROR "Harness attempts to bypass public access: ${_file}")
    endif()
    snowstorm_includes("${_file}" _includes)
    foreach(_include IN LISTS _includes)
        if(_include STREQUAL "snowstorm/node.h")
            set(_saw_node_header TRUE)
        endif()
        if(_include MATCHES "^snowstorm/[A-Za-z0-9_]+\\.h$" OR
            _include MATCHES "^(harness/)?(host|transcript)\\.h$" OR
            _include MATCHES "^(\\.\\./)?oracle/(model|field|schedule)\\.h$" OR
            _include IN_LIST _standard_headers)
            continue()
        endif()
        message(FATAL_ERROR "Harness non-public dependency: ${_file}: ${_include}")
    endforeach()
endforeach()
if(NOT _saw_node_header)
    message(FATAL_ERROR "Harness does not include the real public SnowstormNode API")
endif()
list(LENGTH _core _core_count)
list(LENGTH _oracles _oracle_count)
list(LENGTH _harness _harness_count)
message(STATUS "Snowstorm public-only boundary verified: ${_core_count} core/API, ${_oracle_count} oracle, ${_harness_count} host files")
