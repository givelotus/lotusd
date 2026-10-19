// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_LOKAD_ID_H
#define CHRONIK_NATIVE_TOKEN_LOKAD_ID_H

#include <chronik/native/token/structs.h>
#include <chronik/native/types.h>

#include <optional>
#include <vector>

/** Port of bitcoinsuite-slp lokad_id.rs */
namespace chronik::native::token {

/** LOKAD ID of an "OP_RETURN <lokad id> ..." script */
std::optional<LokadId> ParseOpreturnLokadId(ByteView script);

/** LOKAD ID prefixes of eMPP pushdata (pushdata shorter than 4 stop it). */
std::vector<LokadId> EmppLokadIds(const std::vector<Bytes> &pushdata);

/** LOKAD ID of an input script (first pushop is exactly 4 bytes). */
std::optional<LokadId> ParseInputScriptLokadId(ByteView script);

/**
 * All LOKAD IDs of a tx, in Rust's iteration order: OP_RETURN LOKAD ID of
 * output 0, then its eMPP LOKAD IDs, then input LOKAD IDs (stopping at the
 * first input without one).
 */
std::vector<LokadId> ParseTxLokadIds(const Tx &tx);

} // namespace chronik::native::token

#endif // CHRONIK_NATIVE_TOKEN_LOKAD_ID_H
