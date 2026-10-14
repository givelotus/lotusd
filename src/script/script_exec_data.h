// Copyright (c) 2021 The Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_EXEC_DATA_H
#define BITCOIN_SCRIPT_SCRIPT_EXEC_DATA_H

#include <hash.h>
#include <script/script.h>
#include <uint256.h>

/**
 * Struct for holding data generated during script execution which is used
 * during script execution, e.g. for computing sig hashes.
 */
struct ScriptExecutionData {
    static constexpr uint32_t DEFAULT_CODESEP_POS = 0xffff'ffff;

    /**
     * Opcode position of the last executed OP_CODESEPARATOR.
     *
     * This allows signatures to commit to certain code paths.
     */
    uint32_t m_codeseparator_pos;

    /**
     * SHA256 of the (complete) script being executed, regardless of
     * OP_CODESEPARATOR.
     *
     * - In plain scripts, this is the SHA256 of the scriptPubKey.
     * - In P2SH, this is the SHA256 of the redeemScript.
     * - In Tapscripts, this is the "tapleaf hash", calculated as defined in
     *   BIP341: taggedhash_TapLeaf(version || compact_size(len(script)) ||
     *                              script).
     * - In Taproot, this entire struct would not be constructed.
     */
    uint256 m_executed_script_hash;

    /**
     * ScriptExecutionData with the SHA-256 of executed_script and as
     * codeseparator position.
     */
    ScriptExecutionData(const CScript &executed_script,
                        uint32_t codeseparator_pos = DEFAULT_CODESEP_POS) {
        CSHA256()
            .Write(executed_script.data(), executed_script.size())
            .Finalize(m_executed_script_hash.begin());
        m_codeseparator_pos = codeseparator_pos;
    }

    ScriptExecutionData(const uint256 &executed_script_hash,
                        uint32_t codeseparator_pos = DEFAULT_CODESEP_POS) {
        m_executed_script_hash = executed_script_hash;
        m_codeseparator_pos = codeseparator_pos;
    }

    ScriptExecutionData() = delete;
};

#endif // BITCOIN_SCRIPT_SCRIPT_EXEC_DATA_H
