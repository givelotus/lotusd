// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CODEC_SCRIPT_COMPRESS_H
#define CHRONIK_NATIVE_CODEC_SCRIPT_COMPRESS_H

#include <chronik/native/types.h>

#include <functional>
#include <optional>

/**
 * Script compression used for the `script_*` group member keys: a port of
 * bitcoinsuite-core `compress_script_variant(&script.variant())`, which is
 * Bitcoin Core's `ScriptCompression`:
 *  - P2PKH:  00 || hash20
 *  - P2SH:   01 || hash20
 *  - P2PK compressed (02/03): the 33-byte pubkey
 *  - P2PK uncompressed: (04 | (y & 1)) || x32
 *  - other:  VARINT(len + 6) || script   (Core VARINT, not CompactSize)
 */
namespace chronik::native {

inline constexpr size_t kCompressNumSpecialScripts = 6;

/** Compress a script (classifies it first, like Script::variant()). */
Bytes CompressScript(ByteView script);

/** Bitcoin Core VARINT (serialize.h WriteVarInt, VarIntMode::DEFAULT). */
void WriteCoreVarInt(Bytes &out, uint64_t n);
/** Returns false on overflow/truncation. */
bool ReadCoreVarInt(ByteView in, size_t &pos, uint64_t &n);

/**
 * Receives the 33-byte 04/05 || x32 form; returns the 65-byte 04 || x || y key.
 * Needs EC point decompression, which only the host has (secp256k1).
 */
using DecompressPubKeyFn = std::function<std::optional<Bytes>(ByteView)>;

/**
 * Inverse of CompressScript. Returns nullopt on malformed input, or for the
 * 04/05 forms when no decompress_pubkey hook is given.
 */
std::optional<Bytes>
DecompressScript(ByteView compressed,
                 const DecompressPubKeyFn &decompress_pubkey = {});

} // namespace chronik::native

#endif // CHRONIK_NATIVE_CODEC_SCRIPT_COMPRESS_H
