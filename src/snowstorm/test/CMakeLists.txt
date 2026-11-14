# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license; see the accompanying COPYING.
# Frozen acceptance registration: specification §1–§10 and T1–T16.

include(TestSuite)
create_test_suite(snowstorm)
add_dependencies(check check-snowstorm)

set(SNOWSTORM_SPEC_ROOT "" CACHE PATH "Parent repository containing docs/lotus-v2/snowstorm.md")
if(NOT SNOWSTORM_SPEC_ROOT)
    execute_process(COMMAND git -C "${CMAKE_SOURCE_DIR}" rev-parse --show-superproject-working-tree
        OUTPUT_VARIABLE SNOWSTORM_SPEC_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _snowstorm_git_result)
    if(NOT _snowstorm_git_result EQUAL 0 OR NOT SNOWSTORM_SPEC_ROOT)
        execute_process(COMMAND git -C "${CMAKE_SOURCE_DIR}" rev-parse --show-toplevel
            OUTPUT_VARIABLE SNOWSTORM_SPEC_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY)
    endif()
endif()
get_filename_component(SNOWSTORM_SPEC_ROOT "${SNOWSTORM_SPEC_ROOT}" REALPATH)
if(NOT EXISTS "${SNOWSTORM_SPEC_ROOT}/docs/lotus-v2/snowstorm.md")
    message(FATAL_ERROR "Set SNOWSTORM_SPEC_ROOT to the parent repository containing the normative document")
endif()

add_library(snowstorm-oracle OBJECT
    oracle/field.cpp
    oracle/schedule.cpp
    oracle/model.cpp
)
target_compile_features(snowstorm-oracle PRIVATE cxx_std_20)
target_include_directories(snowstorm-oracle PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/oracle")

add_executable(snowstorm-oracle-self-tests EXCLUDE_FROM_ALL
    oracle/self_tests.cpp
    $<TARGET_OBJECTS:snowstorm-oracle>
)
target_compile_features(snowstorm-oracle-self-tests PRIVATE cxx_std_20)
target_include_directories(snowstorm-oracle-self-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/oracle")

# This target proves compilation independently of the intentionally absent core.
add_library(snowstorm-acceptance-objects OBJECT
    acceptance/fixture.cpp
    acceptance/field_tests.cpp
    acceptance/cell_tests.cpp
    acceptance/schedule_tests.cpp
    acceptance/sketch_tests.cpp
    acceptance/peeler_tests.cpp
    acceptance/setstore_tests.cpp
    acceptance/session_tests.cpp
    acceptance/pooling_tests.cpp
    acceptance/adversarial_tests.cpp
    acceptance/voting_tests.cpp
    acceptance/determinism_tests.cpp
    acceptance/timing_tests.cpp
    harness/host.cpp
    harness/transcript.cpp
)
target_compile_features(snowstorm-acceptance-objects PRIVATE cxx_std_20)
target_include_directories(snowstorm-acceptance-objects PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(snowstorm-acceptance-objects PRIVATE Boost::boost)

add_executable(test-snowstorm EXCLUDE_FROM_ALL
    $<TARGET_OBJECTS:snowstorm-acceptance-objects>
    $<TARGET_OBJECTS:snowstorm-oracle>
)
# Evaluated at generation time so the later real core can be linked without
# editing this frozen file. With no core target the expected failure is undefined
# Snowstorm definitions, never a deliberately supplied stub implementation.
target_link_libraries(test-snowstorm PRIVATE "$<$<TARGET_EXISTS:snowstorm>:snowstorm>")
add_dependencies(check-snowstorm test-snowstorm snowstorm-oracle-self-tests)
add_test_runner(snowstorm acceptance test-snowstorm --run_test=snowstorm_acceptance --report_level=detailed)
add_test_runner(snowstorm oracles snowstorm-oracle-self-tests)

add_test(NAME snowstorm_oracle_self_tests COMMAND snowstorm-oracle-self-tests)
add_test(NAME snowstorm_acceptance
    COMMAND test-snowstorm --run_test=snowstorm_acceptance --report_level=detailed)
add_test(NAME snowstorm_acceptance_frozen
    COMMAND "${CMAKE_COMMAND}" "-DSNOWSTORM_SOURCE_ROOT=${CMAKE_SOURCE_DIR}"
        "-DSNOWSTORM_SPEC_ROOT=${SNOWSTORM_SPEC_ROOT}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/check_frozen.cmake")
add_test(NAME snowstorm_acceptance_no_oracle_access
    COMMAND "${CMAKE_COMMAND}" "-DSNOWSTORM_SOURCE_ROOT=${CMAKE_SOURCE_DIR}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/check_no_oracle.cmake")
add_test(NAME snowstorm_acceptance_determinism_processes
    COMMAND "${CMAKE_COMMAND}" "-DSNOWSTORM_TEST_EXECUTABLE=$<TARGET_FILE:test-snowstorm>"
        "-DSNOWSTORM_SPEC_ROOT=${SNOWSTORM_SPEC_ROOT}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/check_determinism.cmake")
set_tests_properties(snowstorm_oracle_self_tests snowstorm_acceptance
    snowstorm_acceptance_frozen snowstorm_acceptance_no_oracle_access
    snowstorm_acceptance_determinism_processes PROPERTIES LABELS "snowstorm;contract")
set_tests_properties(snowstorm_acceptance PROPERTIES TIMEOUT 7200)
set_tests_properties(snowstorm_acceptance_determinism_processes PROPERTIES
    TIMEOUT 300 RUN_SERIAL TRUE)

# Keep direct suite invocation equivalent to its CTest contract guards.
add_custom_target(check-snowstorm-guards
    COMMAND "${CMAKE_COMMAND}" "-DSNOWSTORM_SOURCE_ROOT=${CMAKE_SOURCE_DIR}"
        "-DSNOWSTORM_SPEC_ROOT=${SNOWSTORM_SPEC_ROOT}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/check_frozen.cmake"
    COMMAND "${CMAKE_COMMAND}" "-DSNOWSTORM_SOURCE_ROOT=${CMAKE_SOURCE_DIR}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/check_no_oracle.cmake"
    COMMAND "${CMAKE_COMMAND}" "-DSNOWSTORM_TEST_EXECUTABLE=$<TARGET_FILE:test-snowstorm>"
        "-DSNOWSTORM_SPEC_ROOT=${SNOWSTORM_SPEC_ROOT}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/check_determinism.cmake"
    DEPENDS test-snowstorm
    VERBATIM
)
add_dependencies(check-snowstorm check-snowstorm-guards)
