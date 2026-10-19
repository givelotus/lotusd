# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Codecs: postcard, seahash, hex, script compression.
list(APPEND CHRONIK_NATIVE_CORE_SOURCES
    core/codec/hex.cpp
    core/codec/postcard.cpp
    core/codec/script_compress.cpp
    core/codec/seahash.cpp
)
list(APPEND CHRONIK_NATIVE_TEST_SOURCES
    test/codec_tests.cpp
)
