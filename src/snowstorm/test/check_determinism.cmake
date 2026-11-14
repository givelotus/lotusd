# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license; see the accompanying COPYING.
# T15: compare complete serialized messages/actions from independent processes.
cmake_minimum_required(VERSION 3.22)
if(NOT DEFINED SNOWSTORM_TEST_EXECUTABLE OR NOT EXISTS "${SNOWSTORM_TEST_EXECUTABLE}")
    message(FATAL_ERROR "SNOWSTORM_TEST_EXECUTABLE must name the linked acceptance binary")
endif()
if(NOT DEFINED SNOWSTORM_SPEC_ROOT OR NOT EXISTS "${SNOWSTORM_SPEC_ROOT}/docs/lotus-v2/snowstorm.md")
    message(FATAL_ERROR "SNOWSTORM_SPEC_ROOT must identify the parent specification checkout")
endif()
set(_directory "${SNOWSTORM_SPEC_ROOT}/.scratch/snowstorm-determinism")
file(MAKE_DIRECTORY "${_directory}")
foreach(_run RANGE 1 2)
    set(_transcript "${_directory}/process-${_run}.bin")
    # Truncating the owned output prevents a stale successful artifact from
    # satisfying this check when a process fails to write a new transcript.
    file(WRITE "${_transcript}" "")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "SNOWSTORM_TRANSCRIPT_FILE=${_transcript}"
            "${SNOWSTORM_TEST_EXECUTABLE}"
            --run_test=snowstorm_acceptance/T15_transcript_process
            --report_level=no --log_level=nothing
        RESULT_VARIABLE _result OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr
        TIMEOUT 120)
    file(WRITE "${_directory}/process-${_run}.log" "${_stdout}\n${_stderr}")
    if(NOT _result STREQUAL "0")
        message(FATAL_ERROR "Transcript process ${_run} failed: ${_result}\n${_stdout}\n${_stderr}")
    endif()
    file(SIZE "${_transcript}" _size)
    if(_size EQUAL 0)
        message(FATAL_ERROR "Transcript process ${_run} produced no messages/actions")
    endif()
endforeach()
execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files
    "${_directory}/process-1.bin" "${_directory}/process-2.bin"
    RESULT_VARIABLE _comparison)
if(NOT _comparison EQUAL 0)
    message(FATAL_ERROR "Same-seed transcripts differ across processes; artifacts in ${_directory}")
endif()
message(STATUS "Snowstorm cross-process transcript equality verified (${_size} bytes, full byte comparison)")
