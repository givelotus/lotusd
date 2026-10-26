# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license; see the accompanying COPYING.

# Core implementation stays independent of daemon services and test oracles.
add_library(snowstorm STATIC src/gf64.cpp src/types.cpp)
target_compile_features(snowstorm PUBLIC cxx_std_20)
target_include_directories(snowstorm PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# snowstorm-frozen:test-registration:begin
if(NOT ENABLE_SNOWSTORM)
    message(FATAL_ERROR "Snowstorm must only be entered with ENABLE_SNOWSTORM=ON")
endif()
add_subdirectory(test)
# snowstorm-frozen:test-registration:end
