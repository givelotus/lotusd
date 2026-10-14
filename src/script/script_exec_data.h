// Copyright (c) 2021 The Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_EXEC_DATA_H
#define BITCOIN_SCRIPT_SCRIPT_EXEC_DATA_H

#include <uint256.h>

/**
 * Struct for holding data generated during script execution which is used
 * during script execution, e.g. for computing sig hashes.
 */
struct ScriptExecutionData {
    /**
     * Opcode position of the last executed OP_CODESEPARATOR.
     * 
     * This allows signatures to commit to certain code paths.
     */
    uint32_t m_codeseparator_pos;
};

#endif // BITCOIN_SCRIPT_SCRIPT_EXEC_DATA_H
