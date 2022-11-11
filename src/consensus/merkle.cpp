// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <hash.h>

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, size_t &num_layers) {
    if (hashes.size() == 0) {
        num_layers = 0;
        return uint256();
    }
    num_layers = 1;
    while (hashes.size() > 1) {
        num_layers++;
        if (hashes.size() & 1) {
            hashes.push_back(uint256());
        }
        SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
        hashes.resize(hashes.size() / 2);
    }
    return hashes[0];
}

uint256 BlockMerkleRoot(const CBlock &block) {
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    size_t num_layers;
    for (size_t i = 0; i < block.vtx.size(); i++) {
        CHashWriter leaf_hash(SER_GETHASH, 0);
        leaf_hash << block.vtx[i]->GetHash();
        leaf_hash << block.vtx[i]->GetId();
        leaves[i] = leaf_hash.GetHash();
    }
    return ComputeMerkleRoot(std::move(leaves), num_layers);
}

uint256 TxInputsMerkleRoot(int32_t nVersion, const std::vector<CTxIn> &vin,
                           size_t &num_layers) {
    std::vector<uint256> leaves;
    leaves.resize(vin.size());
    for (size_t i = 0; i < vin.size(); i++) {
        CHashWriter leaf_hash(SER_GETHASH, 0);
        leaf_hash << vin[i].prevout;
        leaf_hash << vin[i].nSequence;
        if (nVersion == TX_VERSION_MITRA) {
            leaf_hash << Using<CTxOutMitraFormatter>(vin[i].output);
            leaf_hash << vin[i].preambleMerkleRoot;
        }
        leaves[i] = leaf_hash.GetHash();
    }
    return ComputeMerkleRoot(std::move(leaves), num_layers);
}

uint256 TxOutputsMerkleRoot(int32_t nVersion, const std::vector<CTxOut> &vout,
                            size_t &num_layers) {
    std::vector<uint256> leaves;
    leaves.resize(vout.size());
    for (size_t i = 0; i < vout.size(); i++) {
        if (nVersion == TX_VERSION_MITRA) {
            leaves[i] = SerializeHash(Using<CTxOutMitraFormatter>(vout[i]));
        } else {
            leaves[i] = SerializeHash(vout[i]);
        }
    }
    return ComputeMerkleRoot(std::move(leaves), num_layers);
}
