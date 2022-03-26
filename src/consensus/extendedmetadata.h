// Copyright (c) 2022 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <vector>

#include <primitives/block.h>
#include <uint256.h>

class BlockValidationState;
class CBlockIndex;
class BlockValidationOptions;

std::vector<uint256> CollectEpochMerkleLeaves(const CBlock &block,
                                              const CBlockIndex *pindexPrev);

std::vector<uint8_t> BuildEpochMerkleRoot(const CBlock &block,
                                          const CBlockIndex *pindexPrev);

std::vector<CBlockMetadataField>
BuildExtendedMetadata(const Consensus::Params &params, const CBlock &block,
                      const CBlockIndex *pindexPrev, bool isDummy);

bool ContextualCheckExtendedMetadata(const Consensus::Params &params,
                                     const CBlock &block,
                                     const CBlockIndex *pindexPrev,
                                     BlockValidationState &state,
                                     BlockValidationOptions validationOptions);
