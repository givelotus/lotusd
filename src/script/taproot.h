// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_TAPROOT_H
#define BITCOIN_SCRIPT_TAPROOT_H

#include <script/script.h>
#include <uint256.h>

typedef std::vector<uint8_t> valtype;

static constexpr uint8_t TAPROOT_LEAF_MASK = 0xfe;
static constexpr uint8_t TAPROOT_LEAF_TAPSCRIPT = 0xc0;
static constexpr size_t TAPROOT_CONTROL_BASE_SIZE = 33;
static constexpr size_t TAPROOT_CONTROL_NODE_SIZE = 32;
static constexpr size_t TAPROOT_CONTROL_MAX_NODE_COUNT = 128;
static constexpr size_t TAPROOT_CONTROL_MAX_SIZE =
    TAPROOT_CONTROL_BASE_SIZE +
    TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

/**
 * Verifies that the control block proves that script is part of the commitment.
 *
 * - tapleaf_hash: Output; the tapleaf hash of script.
 * - control_block: Must have length 33 + 32 * n.
 *   First byte is (leaf version | parity of internal_pubkey), next 32 bytes are
 *   the X-coordinate of internal_pubkey, and then up to
 *   TAPROOT_CONTROL_MAX_NODE_COUNT nodes of each 32 bytes.
 * - commitment: Public key that has been committed to.
 * - script: Script we are proving inclusion in commitment for.
 *
 * Note: The length requirements on control_block and commitment have to be
 * upheld by the caller.
 */
bool VerifyTaprootCommitment(uint256 &tapleaf_hash,
                             const valtype &control_block,
                             const valtype &commitment, const CScript &script);

#endif // BITCOIN_SCRIPT_TAPROOT_H
