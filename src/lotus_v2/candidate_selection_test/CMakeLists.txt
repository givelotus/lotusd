cmake_minimum_required(VERSION 3.18)
project(lotus_v2_candidate_selection LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
enable_testing()
# Allows the separately owned prerequisite to be tested before root integrates
# its commit; no source is copied or modified in that worktree.
set(LOTUS_CANDIDATE_STORE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "V4 candidate-store source directory")
get_filename_component(LOTUS_CANDIDATE_STORE_SOURCE "${LOTUS_CANDIDATE_STORE_SOURCE}" ABSOLUTE)
add_subdirectory("${LOTUS_CANDIDATE_STORE_SOURCE}/disk_state_test" disk_state)
get_target_property(LOTUS_STORE_SOURCES lotus_v2_disk_state SOURCES)
get_target_property(LOTUS_STORE_DIRECTORY lotus_v2_disk_state SOURCE_DIR)
set(LOTUS_STORE_HAS_CANDIDATE_SOURCE OFF)
foreach(LOTUS_STORE_FILE IN LISTS LOTUS_STORE_SOURCES)
    get_filename_component(LOTUS_STORE_FILE "${LOTUS_STORE_FILE}" ABSOLUTE BASE_DIR "${LOTUS_STORE_DIRECTORY}")
    if(LOTUS_STORE_FILE STREQUAL "${LOTUS_CANDIDATE_STORE_SOURCE}/candidate_store.cpp")
        set(LOTUS_STORE_HAS_CANDIDATE_SOURCE ON)
    endif()
endforeach()
if(NOT LOTUS_STORE_HAS_CANDIDATE_SOURCE)
    target_sources(lotus_v2_disk_state PRIVATE "${LOTUS_CANDIDATE_STORE_SOURCE}/candidate_store.cpp")
endif()
target_include_directories(lotus_v2_disk_state SYSTEM PRIVATE "${LOTUS_BOOST_INCLUDE}")
add_executable(candidate_selection_test ../test_candidate_selection.cpp ../candidate_selection.cpp
    "${LOTUS_CANDIDATE_STORE_SOURCE}/chain_index.cpp"
    "${LOTUS_CANDIDATE_STORE_SOURCE}/sparse_state.cpp"
    "${LOTUS_CANDIDATE_STORE_SOURCE}/output.cpp"
    "${LOTUS_CANDIDATE_STORE_SOURCE}/header.cpp"
    "${LOTUS_CANDIDATE_STORE_SOURCE}/tagged_hash.cpp")
# Force prerequisite declarations before the local base disk_state.h when the
# optional external source directory is used. Normal integrated builds coincide.
target_compile_options(candidate_selection_test PRIVATE
    -include "${LOTUS_CANDIDATE_STORE_SOURCE}/disk_state.h" -Wall -Wextra -Wpedantic -Werror)
target_include_directories(candidate_selection_test PRIVATE "${LOTUS_CANDIDATE_STORE_SOURCE}")
target_link_libraries(candidate_selection_test PRIVATE lotus_v2_disk_state blake3)
add_test(NAME candidate_selection_test COMMAND candidate_selection_test)
