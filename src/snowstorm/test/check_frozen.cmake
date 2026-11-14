# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license; see the accompanying COPYING.
# T14 / freeze contract: invoke this reviewed path directly, not only via CTest.
# ACCEPTANCE.sha256 is anchored by the independently reviewed contract commit.
# It deliberately does not hash itself; changing both it and this checker cannot
# authenticate a revision. Frozen defects require stopping, not rebaselining.
cmake_minimum_required(VERSION 3.22)

if(NOT DEFINED SNOWSTORM_SOURCE_ROOT)
    get_filename_component(SNOWSTORM_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." REALPATH)
endif()
get_filename_component(SNOWSTORM_SOURCE_ROOT "${SNOWSTORM_SOURCE_ROOT}" REALPATH)
if(NOT IS_DIRECTORY "${SNOWSTORM_SOURCE_ROOT}/src/snowstorm")
    message(FATAL_ERROR "SNOWSTORM_SOURCE_ROOT does not contain src/snowstorm")
endif()
if(NOT DEFINED SNOWSTORM_SPEC_ROOT OR SNOWSTORM_SPEC_ROOT STREQUAL "")
    execute_process(COMMAND git -C "${SNOWSTORM_SOURCE_ROOT}" rev-parse --show-superproject-working-tree
        OUTPUT_VARIABLE SNOWSTORM_SPEC_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _git_result)
    if(NOT _git_result EQUAL 0 OR SNOWSTORM_SPEC_ROOT STREQUAL "")
        execute_process(COMMAND git -C "${SNOWSTORM_SOURCE_ROOT}" rev-parse --show-toplevel
            OUTPUT_VARIABLE SNOWSTORM_SPEC_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY)
    endif()
endif()
get_filename_component(SNOWSTORM_SPEC_ROOT "${SNOWSTORM_SPEC_ROOT}" REALPATH)
if(NOT EXISTS "${SNOWSTORM_SPEC_ROOT}/docs/lotus-v2/snowstorm.md")
    message(FATAL_ERROR "Normative parent specification missing; set SNOWSTORM_SPEC_ROOT explicitly")
endif()
set(_manifest "${SNOWSTORM_SOURCE_ROOT}/src/snowstorm/ACCEPTANCE.sha256")
if(NOT EXISTS "${_manifest}")
    message(FATAL_ERROR "Missing reviewed ACCEPTANCE.sha256; the contract is not frozen")
endif()

# LF-inclusive extraction, with exactly one standalone begin/end marker in order.
# Each extracted span is hashed using file(SHA256), as required by the contract.
function(snowstorm_hash_span INPUT BEGIN END OUTPUT KEY)
    file(READ "${INPUT}" _text)
    foreach(_marker IN ITEMS "${BEGIN}" "${END}")
        string(FIND "${_text}" "${_marker}" _position)
        if(_position LESS 0)
            message(FATAL_ERROR "Missing marker ${_marker} in ${INPUT}")
        endif()
        string(LENGTH "${_marker}" _marker_length)
        math(EXPR _after "${_position}+${_marker_length}")
        string(SUBSTRING "${_text}" ${_after} -1 _tail)
        string(FIND "${_tail}" "${_marker}" _duplicate)
        if(NOT _duplicate LESS 0)
            message(FATAL_ERROR "Duplicate marker ${_marker} in ${INPUT}")
        endif()
        string(SUBSTRING "${_tail}" 0 1 _next)
        if(NOT _next STREQUAL "\n")
            message(FATAL_ERROR "Marker must end in LF, without CR or trailing bytes: ${INPUT}")
        endif()
        if(_position GREATER 0)
            math(EXPR _before "${_position}-1")
            string(SUBSTRING "${_text}" ${_before} 1 _previous)
            if(NOT _previous STREQUAL "\n")
                message(FATAL_ERROR "Marker must start a line: ${INPUT}")
            endif()
        endif()
    endforeach()
    string(FIND "${_text}" "${BEGIN}" _first)
    string(FIND "${_text}" "${END}" _last)
    if(_last LESS _first)
        message(FATAL_ERROR "Reversed markers in ${INPUT}")
    endif()
    string(LENGTH "${END}" _end_length)
    math(EXPR _length "${_last}+${_end_length}+1-${_first}")
    string(SUBSTRING "${_text}" ${_first} ${_length} _span)
    string(SHA256 _key_hash "${KEY}")
    set(_scratch "${SNOWSTORM_SPEC_ROOT}/.scratch/snowstorm-freeze-check")
    file(MAKE_DIRECTORY "${_scratch}")
    set(_input "${_scratch}/${_key_hash}.bytes")
    file(WRITE "${_input}" "${_span}")
    file(SHA256 "${_input}" _actual)
    set(${OUTPUT} "${_actual}" PARENT_SCOPE)
endfunction()

set(_required_keys
    "normative:docs/lotus-v2/snowstorm.md"
    "span:src/CMakeLists.txt#option"
    "span:src/CMakeLists.txt#registration"
    "span:src/snowstorm/CMakeLists.txt#test-registration"
    "file:src/snowstorm/CONTRACT.md"
    "file:src/snowstorm/test/CMakeLists.txt"
    "file:src/snowstorm/test/check_frozen.cmake"
    "file:src/snowstorm/test/check_no_oracle.cmake"
    "file:src/snowstorm/test/check_determinism.cmake"
)
set(_fixed_files
    "src/snowstorm/CONTRACT.md"
    "src/snowstorm/test/CMakeLists.txt"
    "src/snowstorm/test/check_frozen.cmake"
    "src/snowstorm/test/check_no_oracle.cmake"
    "src/snowstorm/test/check_determinism.cmake"
)
set(_expected_files)
set(_seen_keys)
file(STRINGS "${_manifest}" _lines ENCODING UTF-8)
foreach(_line IN LISTS _lines)
    if(_line STREQUAL "" OR _line MATCHES "^#")
        continue()
    endif()
    if(NOT _line MATCHES "^([0-9a-f]+)  (file|span|normative):([A-Za-z0-9_./#-]+)$")
        message(FATAL_ERROR "Malformed freeze-manifest row: ${_line}")
    endif()
    set(_expected "${CMAKE_MATCH_1}")
    set(_kind "${CMAKE_MATCH_2}")
    set(_path "${CMAKE_MATCH_3}")
    string(LENGTH "${_expected}" _hash_length)
    if(NOT _hash_length EQUAL 64 OR _path MATCHES "(^/|(^|/)\\.\\.(/|$))")
        message(FATAL_ERROR "Invalid hash or non-relative path in freeze manifest")
    endif()
    set(_key "${_kind}:${_path}")
    if(_key IN_LIST _seen_keys)
        message(FATAL_ERROR "Duplicate freeze-manifest key: ${_key}")
    endif()
    list(APPEND _seen_keys "${_key}")
    if(_kind STREQUAL "normative")
        if(NOT _path STREQUAL "docs/lotus-v2/snowstorm.md")
            message(FATAL_ERROR "Unexpected normative path: ${_path}")
        endif()
        snowstorm_hash_span("${SNOWSTORM_SPEC_ROOT}/${_path}"
            "<!-- snowstorm-core-normative:begin -->"
            "<!-- snowstorm-core-normative:end -->" _actual "${_key}")
    elseif(_kind STREQUAL "span")
        if(NOT _key IN_LIST _required_keys OR NOT _path MATCHES "^([^#]+)#([a-z-]+)$")
            message(FATAL_ERROR "Unexpected registration span: ${_path}")
        endif()
        set(_file "${CMAKE_MATCH_1}")
        set(_name "${CMAKE_MATCH_2}")
        if(NOT EXISTS "${SNOWSTORM_SOURCE_ROOT}/${_file}")
            message(FATAL_ERROR "Missing registration file: ${_file}")
        endif()
        snowstorm_hash_span("${SNOWSTORM_SOURCE_ROOT}/${_file}"
            "# snowstorm-frozen:${_name}:begin" "# snowstorm-frozen:${_name}:end"
            _actual "${_key}")
    else()
        if(NOT _path IN_LIST _fixed_files AND NOT _path MATCHES
            "^src/snowstorm/(include/snowstorm|test/oracle|test/harness|test/acceptance)/")
            message(FATAL_ERROR "Unexpected frozen file path: ${_path}")
        endif()
        if(NOT EXISTS "${SNOWSTORM_SOURCE_ROOT}/${_path}" OR IS_DIRECTORY "${SNOWSTORM_SOURCE_ROOT}/${_path}")
            message(FATAL_ERROR "Missing frozen file: ${_path}")
        endif()
        if(IS_SYMLINK "${SNOWSTORM_SOURCE_ROOT}/${_path}")
            message(FATAL_ERROR "Frozen source must not be a symlink: ${_path}")
        endif()
        file(SHA256 "${SNOWSTORM_SOURCE_ROOT}/${_path}" _actual)
        list(APPEND _expected_files "${_path}")
    endif()
    if(NOT _actual STREQUAL _expected)
        message(FATAL_ERROR "Frozen hash mismatch: ${_key}\nexpected ${_expected}\nactual   ${_actual}")
    endif()
endforeach()
foreach(_key IN LISTS _required_keys)
    if(NOT _key IN_LIST _seen_keys)
        message(FATAL_ERROR "Required freeze-manifest item absent: ${_key}")
    endif()
endforeach()

set(_actual_files ${_fixed_files})
foreach(_directory IN ITEMS include/snowstorm test/oracle test/harness test/acceptance)
    file(GLOB_RECURSE _files LIST_DIRECTORIES FALSE RELATIVE "${SNOWSTORM_SOURCE_ROOT}"
        "${SNOWSTORM_SOURCE_ROOT}/src/snowstorm/${_directory}/*")
    if(NOT _files)
        message(FATAL_ERROR "Frozen source directory is empty or missing: ${_directory}")
    endif()
    list(APPEND _actual_files ${_files})
endforeach()
list(SORT _actual_files)
list(SORT _expected_files)
if(NOT _actual_files STREQUAL _expected_files)
    message(FATAL_ERROR "Frozen file inventory mismatch (extra or missing files)\nexpected: ${_expected_files}\nactual: ${_actual_files}")
endif()
list(LENGTH _seen_keys _count)
message(STATUS "Snowstorm frozen contract verified: ${_count} entries; trust anchor is the separately reviewed manifest/commit")
