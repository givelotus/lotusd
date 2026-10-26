# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license; see the accompanying COPYING.

# Core implementation stays independent of daemon services and test oracles.
add_library(snowstorm STATIC
    src/gf64.cpp
    src/types.cpp
    src/cell.cpp
    src/cell_decode.cpp
    src/schedule.cpp
    src/sketch.cpp
    src/peeler.cpp
    src/peeler_engine.cpp
    src/messages.cpp
    src/limits.cpp
    src/short_id.cpp
    src/setstore.cpp
    src/session_request.cpp
    src/session_responder.cpp
    src/session_model.cpp
    src/pending.cpp
)
target_compile_features(snowstorm PUBLIC cxx_std_20)
target_include_directories(snowstorm PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# snowstorm-frozen:test-registration:begin
if(NOT ENABLE_SNOWSTORM)
    message(FATAL_ERROR "Snowstorm must only be entered with ENABLE_SNOWSTORM=ON")
endif()
add_subdirectory(test)
# snowstorm-frozen:test-registration:end
