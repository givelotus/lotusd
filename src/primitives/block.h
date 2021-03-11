// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/blockhash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <array>

typedef std::array<uint8_t, 6> block_time_t;
typedef std::array<uint8_t, 10> nonce_t;

constexpr int32_t EPOCH_NUM_BLOCKS = 5040;  // one week

/**
 * Nodes collect new transactions into a block, hash them into a hash tree, and
 * scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements. When they solve the proof-of-work, they broadcast the block to
 * everyone and the block is added to the block chain. The first transaction in
 * the block is a special one that creates a new coin owned by the creator of
 * the block.
 */
class CBlockHeader {
public:
    // header
    BlockHash hashPrevBlock;
    uint32_t nBits;
    block_time_t vTime;
    nonce_t vNonce;
    uint32_t nVersion;
    uint32_t nSizeMB;
    int32_t nHeight;
    uint256 hashEpochBlock;
    uint256 hashMerkleRoot;
    uint256 hashExtendedMetadata;

    CBlockHeader() { SetNull(); }

    SERIALIZE_METHODS(CBlockHeader, obj) {
        READWRITE(obj.hashPrevBlock);
        READWRITE(obj.nBits);
        READWRITE(obj.vTime);
        READWRITE(obj.vNonce);
        READWRITE(obj.nVersion);
        READWRITE(obj.nSizeMB);
        READWRITE(obj.nHeight);
        READWRITE(obj.hashEpochBlock);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.hashExtendedMetadata);
    }

    void SetNull() {
        hashPrevBlock = BlockHash();
        nBits = 0;
        vTime.fill(0);
        vNonce.fill(0);
        nVersion = 0;
        nSizeMB = 0;
        nHeight = 0;
        hashEpochBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashExtendedMetadata.SetNull();
    }

    bool IsNull() const { return (nBits == 0); }

    BlockHash GetHash() const;

    int64_t GetBlockTime() const {
        return int64_t(vTime[0]) |
               (int64_t(vTime[1]) >> 8) |
               (int64_t(vTime[2]) >> 16) |
               (int64_t(vTime[3]) >> 24) |
               (int64_t(vTime[4]) >> 32) |
               (int64_t(vTime[5]) >> 40);
    }

    void SetBlockTime(int64_t nTime) {
        vTime = {
            uint8_t((nTime & 0x0000000000ff)),
            uint8_t((nTime & 0x00000000ff00) >> 8),
            uint8_t((nTime & 0x000000ff0000) >> 16),
            uint8_t((nTime & 0x0000ff000000) >> 24),
            uint8_t((nTime & 0x00ff00000000) >> 32),
            uint8_t((nTime & 0xff0000000000) >> 40),
        };
    }

    void IncrementNonce() {
        for (uint8_t &v : vNonce) {
            ++v;
            if (v != 0) break;
        }
    }
};

class CBlockMetadataField {
public:
    uint32_t nFieldId;
    std::vector<uint8_t> vData;

    SERIALIZE_METHODS(CBlockMetadataField, obj) {
        READWRITE(obj.nFieldId);
        READWRITE(obj.vData);
    }
};

class CBlock : public CBlockHeader {
public:
    std::vector<CBlockMetadataField> vMetadata; 
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock() { SetNull(); }

    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader *>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj) {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vMetadata);
        READWRITE(obj.vtx);
    }

    void SetNull() {
        CBlockHeader::SetNull();
        vtx.clear();
        vMetadata.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const {
        CBlockHeader header;
        header.hashPrevBlock = hashPrevBlock;
        header.nBits = nBits;
        header.vTime = vTime;
        header.vNonce = vNonce;
        header.nVersion = nVersion;
        header.nSizeMB = nSizeMB;
        header.nHeight = nHeight;
        header.hashEpochBlock = hashEpochBlock;
        header.hashMerkleRoot = hashMerkleRoot;
        header.hashExtendedMetadata = hashExtendedMetadata;
        return header;
    }

    std::string ToString() const;
};

/**
 * Describes a place in the block chain to another node such that if the other
 * node doesn't have the same branch, it can find a recent common trunk.  The
 * further back it is, the further before the fork it may be.
 */
struct CBlockLocator {
    std::vector<BlockHash> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<BlockHash> &vHaveIn)
        : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(nVersion);
        }
        READWRITE(obj.vHave);
    }

    void SetNull() { vHave.clear(); }

    bool IsNull() const { return vHave.empty(); }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
