// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <merkleblock.h>

#include <consensus/consensus.h>
#include <hash.h>

std::vector<uint8_t> BitsToBytes(const std::vector<bool> &bits) {
    std::vector<uint8_t> ret((bits.size() + 7) / 8);
    for (unsigned int p = 0; p < bits.size(); p++) {
        ret[p / 8] |= bits[p] << (p % 8);
    }
    return ret;
}

std::vector<bool> BytesToBits(const std::vector<uint8_t> &bytes) {
    std::vector<bool> ret(bytes.size() * 8);
    for (unsigned int p = 0; p < ret.size(); p++) {
        ret[p] = (bytes[p / 8] & (1 << (p % 8))) != 0;
    }
    return ret;
}

CMerkleBlock::CMerkleBlock(const CBlock &block, CBloomFilter *filter,
                           const std::set<TxId> *txids) {
    header = block.GetBlockHeader();

    std::vector<bool> vMatch;
    std::vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size() * 2);
    vHashes.reserve(block.vtx.size() * 2);

    if (filter) {
        for (const auto &tx : block.vtx) {
            vMatch.push_back(false);
            vMatch.push_back(filter->MatchAndInsertOutputs(*tx));
        }
    }

    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction *tx = block.vtx[i].get();
        const TxHash &txhash = tx->GetHash();
        const TxId &txid = tx->GetId();
        const size_t matchidx = i * 2 + 1;
        if (filter) {
            if (!vMatch[matchidx]) {
                vMatch[matchidx] = filter->MatchInputs(*tx);
            }
            if (vMatch[matchidx]) {
                vMatchedTxn.push_back(std::make_pair(i, txid));
            }
        } else {
            vMatch.push_back(false);
            vMatch.push_back(txids && txids->count(txid));
        }

        vHashes.push_back(txhash);
        vHashes.push_back(txid);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}

uint256 CPartialMerkleTree::CalcHash(int height, size_t pos,
                                     const std::vector<uint256> &vHashes) {
    // we can never have zero txs in a merkle block, we always need the
    // coinbase tx if we do not have this assert, we can hit a memory
    // access violation when indexing into vHashes
    assert(vHashes.size() != 0);
    if (height == 0) {
        // hash at height 0 is the txids themself.
        return vHashes[pos];
    }

    // Calculate left hash.
    uint256 left = CalcHash(height - 1, pos * 2, vHashes), right;
    // Calculate right hash if not beyond the end of the array - copy left hash
    // otherwise.
    if (pos * 2 + 1 < CalcTreeWidth(height - 1)) {
        right = CalcHash(height - 1, pos * 2 + 1, vHashes);
    } else {
        right = uint256();
    }

    // Combine subhashes.
    return Hash(left, right);
}

void CPartialMerkleTree::TraverseAndBuild(int height, size_t pos,
                                          const std::vector<uint256> &vHashes,
                                          const std::vector<bool> &vfMatch) {
    // Determine whether this node is the parent of at least one matched txid.
    bool fParentOfMatch = false;
    for (size_t p = pos << height; p < (pos + 1) << height && p < nLeaves;
         p++) {
        fParentOfMatch |= vfMatch[p];
    }

    // Store as flag bit.
    vBits.push_back(fParentOfMatch);
    if (height == 0 || !fParentOfMatch) {
        // If at height 0, or nothing interesting below, store hash and stop.
        vHash.push_back(CalcHash(height, pos, vHashes));
    } else {
        // Otherwise, don't store any hash, but descend into the subtrees.
        TraverseAndBuild(height - 1, pos * 2, vHashes, vfMatch);
        if (pos * 2 + 1 < CalcTreeWidth(height - 1)) {
            TraverseAndBuild(height - 1, pos * 2 + 1, vHashes, vfMatch);
        }
    }
}

uint256 CPartialMerkleTree::TraverseAndExtract(int height, size_t pos,
                                               size_t &nBitsUsed,
                                               size_t &nHashUsed,
                                               std::vector<uint256> &vMatch,
                                               std::vector<size_t> &vnIndex) {
    if (nBitsUsed >= vBits.size()) {
        // Overflowed the bits array - failure
        fBad = true;
        return uint256();
    }

    bool fParentOfMatch = vBits[nBitsUsed++];
    if (height == 0 || !fParentOfMatch) {
        // If at height 0, or nothing interesting below, use stored hash and do
        // not descend.
        if (nHashUsed >= vHash.size()) {
            // Overflowed the hash array - failure
            fBad = true;
            return uint256();
        }
        const uint256 &hash = vHash[nHashUsed++];
        // In case of height 0, we have a matched txid.
        if (height == 0 && fParentOfMatch) {
            vMatch.push_back(hash);
            vnIndex.push_back(pos / 2);
        }
        return hash;
    }

    // Otherwise, descend into the subtrees to extract matched txids and hashes.
    uint256 left = TraverseAndExtract(height - 1, pos * 2, nBitsUsed, nHashUsed,
                                      vMatch, vnIndex),
            right;
    if (pos * 2 + 1 < CalcTreeWidth(height - 1)) {
        right = TraverseAndExtract(height - 1, pos * 2 + 1, nBitsUsed,
                                   nHashUsed, vMatch, vnIndex);
        if (right == left) {
            // The left and right branches should never be identical, as the
            // transaction hashes covered by them must each be unique.
            fBad = true;
        }
    } else {
        right = uint256();
    }

    // and combine them before returning.
    return Hash(left, right);
}

CPartialMerkleTree::CPartialMerkleTree(const std::vector<uint256> &vHashes,
                                       const std::vector<bool> &vfMatch)
    : nLeaves(vHashes.size()), fBad(false) {
    // reset state
    vBits.clear();
    vHash.clear();

    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1) {
        nHeight++;
    }

    // traverse the partial tree
    TraverseAndBuild(nHeight, 0, vHashes, vfMatch);
}

CPartialMerkleTree::CPartialMerkleTree() : nLeaves(0), fBad(true) {}

uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch,
                                           std::vector<size_t> &vnIndex) {
    vMatch.clear();

    // An empty set will not work
    if (nLeaves == 0) {
        return uint256();
    }

    // Check for excessively high numbers of transactions.
    // FIXME: Track the maximum block size we've seen and use it here.

    // There can never be more hashes provided than one for every txid.
    if (vHash.size() > nLeaves) {
        return uint256();
    }

    // There must be at least one bit per node in the partial tree, and at least
    // one node per hash.
    if (vBits.size() < vHash.size()) {
        return uint256();
    }

    // calculate height of tree.
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1) {
        nHeight++;
    }

    // traverse the partial tree.
    size_t nBitsUsed = 0, nHashUsed = 0;
    uint256 hashMerkleRoot =
        TraverseAndExtract(nHeight, 0, nBitsUsed, nHashUsed, vMatch, vnIndex);

    // verify that no problems occurred during the tree traversal.
    if (fBad) {
        return uint256();
    }

    // verify that all bits were consumed (except for the padding caused by
    // serializing it as a byte sequence)
    if ((nBitsUsed + 7) / 8 != (vBits.size() + 7) / 8) {
        return uint256();
    }

    // verify that all hashes were consumed.
    if (nHashUsed != vHash.size()) {
        return uint256();
    }

    return hashMerkleRoot;
}
