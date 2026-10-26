# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license; see the accompanying COPYING.

# Future implementation targets belong above the frozen test traversal below.
# The contract stage deliberately defines no Snowstorm library or stub target.

# snowstorm-frozen:test-registration:begin
if(NOT ENABLE_SNOWSTORM)
    message(FATAL_ERROR "Snowstorm must only be entered with ENABLE_SNOWSTORM=ON")
endif()
add_subdirectory(test)
# snowstorm-frozen:test-registration:end
