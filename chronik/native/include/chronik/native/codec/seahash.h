// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CODEC_SEAHASH_H
#define CHRONIK_NATIVE_CODEC_SEAHASH_H

#include <chronik/native/types.h>

#include <cstdint>

namespace chronik::native {

/**
 * Bit-exact port of the Rust `seahash` crate (v4.1) `hash()` with its default
 * keys. Chronik derives the `lookup_blk_by_hash` / `lookup_tx_by_hash` keys
 * from it, so it must never change.
 */
uint64_t SeaHash(ByteView data);
uint64_t SeaHashSeeded(ByteView data, uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_CODEC_SEAHASH_H
