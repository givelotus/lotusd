// Copyright (c) 2022 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockindex.h>
#include <consensus/activation.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <hash.h>
#include <logging.h>
#include <streams.h>
#include <validation.h>
#include <version.h>

#include <consensus/extendedmetadata.h>

static const size_t EPOCH_MERKLE_ROOT_LENGTH = 33;

std::vector<uint256> CollectEpochMerkleLeaves(const CBlock &block,
                                              const CBlockIndex *pindexPrev) {
    const uint256 currentEpochBlockHash = block.hashEpochBlock;
    std::vector<uint256> epochMerkleLeaves;
    size_t dummyNumLayers;

    // Add block's own merkle root
    // 0 for the block hash, as we cannot know our own block hash here
    epochMerkleLeaves.push_back(
        ComputeMerkleRoot({uint256(), block.hashMerkleRoot}, dummyNumLayers));

    // Walk back chain until epoch hash changes
    while (pindexPrev && pindexPrev->hashEpochBlock == currentEpochBlockHash) {
        // Add H(block hash || merkle root)
        epochMerkleLeaves.push_back(ComputeMerkleRoot(
            {pindexPrev->GetBlockHash(), pindexPrev->hashMerkleRoot},
            dummyNumLayers));
        pindexPrev = pindexPrev->pprev;
    }

    // Leaves need to be sorted by height ascendingly.
    // Currently sorted descendingly, so we simply reverse.
    std::reverse(epochMerkleLeaves.begin(), epochMerkleLeaves.end());
    return epochMerkleLeaves;
}

std::vector<uint8_t> BuildEpochMerkleRoot(const CBlock &block,
                                          const CBlockIndex *pindexPrev) {
    size_t numLayers;
    std::vector<uint256> merkleRoots =
        CollectEpochMerkleLeaves(block, pindexPrev);
    const uint256 merkleRoot =
        ComputeMerkleRoot(std::move(merkleRoots), numLayers);

    std::vector<uint8_t> epochMerkleRoot(merkleRoot.begin(), merkleRoot.end());
    // Add number of layers to reach leaves as single byte at the end
    epochMerkleRoot.push_back(uint8_t(numLayers));
    return epochMerkleRoot;
}

std::vector<CBlockMetadataField>
BuildExtendedMetadata(const Consensus::Params &params, const CBlock &block,
                      const CBlockIndex *pindexPrev, bool isDummy) {
    std::vector<CBlockMetadataField> metadata;

    if (IsLeviticusEnabled(params, pindexPrev)) {
        // Build and add Epoch Merkle root
        const std::vector<uint8_t> epochMerkleRoot =
            isDummy ? std::vector<uint8_t>(EPOCH_MERKLE_ROOT_LENGTH)
                    : BuildEpochMerkleRoot(block, pindexPrev);
        CBlockMetadataField field = {
            .nFieldId = uint32_t(MetadataFieldId::EPOCH_MERKLE_ROOT),
            .vData = epochMerkleRoot,
        };
        metadata.push_back(field);
    }

    return metadata;
}

static bool CheckEpochMerkleRoot(const Consensus::Params &params,
                                 const CBlock &block,
                                 const CBlockIndex *pindexPrev,
                                 const std::vector<uint8_t> &epochMerkleRoot,
                                 BlockValidationState &state) {
    // Verify field size
    if (epochMerkleRoot.size() != EPOCH_MERKLE_ROOT_LENGTH) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-metadata-field",
                             "invalid EPOCH_MERKLE_ROOT length");
    }
    // Build Epoch Merkle root and check if it matches metadata
    const std::vector<uint8_t> expectedEpochMerkleRoot =
        BuildEpochMerkleRoot(block, pindexPrev);
    if (epochMerkleRoot != expectedEpochMerkleRoot) {
        LogPrintf("ERROR: expected epoch merkle root %s, but got %s\n",
                  HexStr(expectedEpochMerkleRoot), HexStr(epochMerkleRoot));
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-epoch-merkle-root",
                             "invalid epoch merkle root");
    }
    return true;
}

static bool CheckMetadataField(const Consensus::Params &params,
                               const CBlock &block,
                               const CBlockIndex *pindexPrev,
                               const CBlockMetadataField &field,
                               BlockValidationState &state,
                               BlockValidationOptions validationOptions) {
    // Only MetadataFieldId::EPOCH_MERKLE_ROOT allowed (for now)
    if (field.nFieldId != uint32_t(MetadataFieldId::EPOCH_MERKLE_ROOT)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-metadata",
                             "forbidden extended metadata field");
    }
    // Validate Epoch Merkle root
    if (validationOptions.shouldValidateMerkleRoot() &&
        !CheckEpochMerkleRoot(params, block, pindexPrev, field.vData, state)) {
        return false; // state filled in by CheckEpochMerkleRoot
    }
    return true;
}

bool ContextualCheckExtendedMetadata(const Consensus::Params &params,
                                     const CBlock &block,
                                     const CBlockIndex *pindexPrev,
                                     BlockValidationState &state,
                                     BlockValidationOptions validationOptions) {
    // Before Leviticus, metadata must be empty
    if (!IsLeviticusEnabled(params, pindexPrev)) {
        if (!block.vMetadata.empty()) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                 "bad-metadata",
                                 "forbidden extended metadata field");
        }
        return true;
    }

    // After, it must have exactly one field
    if (block.vMetadata.size() != 1) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-metadata",
                             "invalid number of metadata fields");
    }

    // Verify that field
    if (!CheckMetadataField(params, block, pindexPrev, block.vMetadata[0],
                            state, validationOptions)) {
        return false; // state filled in by CheckMetadataField
    }

    return true;
}
