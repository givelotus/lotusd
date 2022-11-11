// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MERKLE_H
#define BITCOIN_CONSENSUS_MERKLE_H

#include <vector>

#include <primitives/block.h>
#include <uint256.h>

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, size_t &num_layers);

/**
 * Compute the Merkle root of the transactions in a block.
 */
uint256 BlockMerkleRoot(const CBlock &block);

uint256 TxInputsMerkleRoot(int32_t nVersion, const std::vector<CTxIn> &vin,
                           size_t &num_layers);
uint256 TxOutputsMerkleRoot(int32_t nVersion, const std::vector<CTxOut> &vout,
                            size_t &num_layers);

#endif // BITCOIN_CONSENSUS_MERKLE_H
