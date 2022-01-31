# Copyright (c) 2021 The Logos Foundation

cmake_minimum_required(VERSION 3.15)

project(nng_interface)

add_library(nng_interface
    nng_interface.cpp
)

# Find NNG library
find_package(nng CONFIG REQUIRED)

# Find flatbuffers library
find_package(Flatbuffers CONFIG REQUIRED)

# Find flatc executable
find_program(_FLATC flatc)
message(STATUS "Using flatc executable: ${_FLATC}")

# Location of the .fbs file for the NNG interface
get_filename_component(FLATBUFFERS_FILE "nng_interface.fbs" ABSOLUTE)

# Set output paths (determined by flatc's naming conventions)
set(GENFLATBUF_FOLDER "${CMAKE_CURRENT_BINARY_DIR}")
set(NNG_FLATBUF_H "${GENFLATBUF_FOLDER}/nng_interface_generated.h")
set(NNG_FLATBUF_PY "${GENFLATBUF_FOLDER}/NngInterface")

# Generate Python and CPP files for NNG interface flatbuffers
add_custom_command(
    OUTPUT "${NNG_FLATBUF_H}" "${NNG_FLATBUF_PY}"
    COMMAND ${_FLATC}
    ARGS -o "${GENFLATBUF_FOLDER}"
        --cpp
        --python
        "${FLATBUFFERS_FILE}"
    DEPENDS "${FLATBUFFERS_FILE}")

# Custom target for flatbuf files, so they get re-generated
add_custom_target(nng_files ALL
    DEPENDS "${NNG_FLATBUF_H}" "${NNG_FLATBUF_PY}")

# Include generated *_generated.h files
include_directories("${GENFLATBUF_FOLDER}")

# Add custom target as dependency
add_dependencies(nng_interface nng_files)

# Add required libraries to nng_interface
target_link_libraries(nng_interface
    nng::nng
    util
    leveldb)
