# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license; see the accompanying COPYING.
# Pure math target: deliberately requires neither Node nor the acceptance host.
add_executable(snowstorm-voting-early-tests voting_early_tests.cpp ../src/voting.cpp)
target_compile_features(snowstorm-voting-early-tests PRIVATE cxx_std_20)
target_include_directories(snowstorm-voting-early-tests PRIVATE ../include)
add_test(NAME snowstorm_voting_early COMMAND snowstorm-voting-early-tests)
