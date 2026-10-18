// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

#include <arith_uint256.h>
#include <blockindex.h>
#include <blockstatus.h>
#include <blockvalidity.h>
#include <consensus/params.h>
#include <crypto/common.h> // for ReadLE64
#include <flatfile.h>
#include <kernel/cs_main.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>

#include <unordered_map>
#include <vector>

/**
 * Maximum amount of time that a block timestamp is allowed to exceed the
 * current network-adjusted time before the block will be accepted.
 */
static constexpr int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

/**
 * Timestamp window used as a grace period by code that compares external
 * timestamps (such as timestamps passed to RPCs, or wallet key creation times)
 * to block timestamps. This should be set at least as high as
 * MAX_FUTURE_BLOCK_TIME.
 */
static constexpr int64_t TIMESTAMP_WINDOW = MAX_FUTURE_BLOCK_TIME;

/**
 * Maximum gap between node time and block time used
 * for the "Catching up..." mode in GUI.
 *
 * Ref: https://github.com/bitcoin/bitcoin/pull/1026
 */
static constexpr int64_t MAX_BLOCK_TIME_GAP = 90 * 60;

arith_uint256 GetBlockProof(const CBlockIndex &block);

/**
 * Return the time it would take to redo the work difference between from and
 * to, assuming the current hashrate corresponds to the difficulty at tip, in
 * seconds.
 */
int64_t GetBlockProofEquivalentTime(const CBlockIndex &to,
                                    const CBlockIndex &from,
                                    const CBlockIndex &tip,
                                    const Consensus::Params &);
/**
 * Find the forking point between two chain tips.
 */
const CBlockIndex *LastCommonAncestor(const CBlockIndex *pa,
                                      const CBlockIndex *pb);

/**
 * Check if two block index are on the same fork.
 */
bool AreOnTheSameFork(const CBlockIndex *pa, const CBlockIndex *pb);

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex {
    /** Legacy records use the historical client-version tag (up to 320400).
     * Development tag 320401 retains block sizes after pruning for deterministic
     * adaptive-policy reconstruction; old conditional-size records remain readable.
     */
    static constexpr int DUMMY_VERSION = 320401;

public:
    BlockHash hashPrev;

    CDiskBlockIndex() : hashPrev() {}

    explicit CDiskBlockIndex(const CBlockIndex *pindex) : CBlockIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBlockHash() : BlockHash());
    }

    SERIALIZE_METHODS(CDiskBlockIndex, obj) {
        LOCK(::cs_main);
        int _nVersion = DUMMY_VERSION;
        READWRITE(VARINT_MODE(_nVersion, VarIntMode::NONNEGATIVE_SIGNED));
        if (_nVersion > DUMMY_VERSION) throw std::ios_base::failure("unknown block-index record format");

        READWRITE(obj.nStatus);
        READWRITE(VARINT(obj.nTx));

        // Adaptive policy reconstruction needs sizes even after block files are pruned.
        // 320400 stored the size only while hasData; 320401 always preserves it.
        if (_nVersion >= 320401 || obj.nStatus.hasData()) {
            READWRITE(VARINT(obj.nSize));
        }

        if (obj.nStatus.hasData() || obj.nStatus.hasUndo()) {
            READWRITE(VARINT_MODE(obj.nFile, VarIntMode::NONNEGATIVE_SIGNED));
        }
        if (obj.nStatus.hasData()) {
            READWRITE(VARINT(obj.nDataPos));
        }
        if (obj.nStatus.hasUndo()) {
            READWRITE(VARINT(obj.nUndoPos));
        }

        // block header
        READWRITE(obj.hashPrev);
        READWRITE(obj.nBits);
        READWRITE(obj.nTime);
        READWRITE(obj.nNonce);
        READWRITE(obj.nHeaderVersion);
        READWRITE(obj.nSize);
        READWRITE(obj.nHeight);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.hashStateRoot);
    }

    BlockHash ConstructBlockHash() const {
        CBlockHeader header;
        header.hashPrevBlock = hashPrev;
        header.nBits = nBits;
        header.SetBlockTime(nTime);
        header.nNonce = nNonce;
        header.nHeaderVersion = nHeaderVersion;
        header.SetSize(nSize);
        header.nHeight = uint64_t(nHeight);
        header.hashMerkleRoot = hashMerkleRoot;
        header.hashStateRoot = hashStateRoot;
        return header.GetHash();
    }

    BlockHash GetBlockHash() = delete;
    std::string ToString() = delete;
};

/**
 * An in-memory indexed chain of blocks.
 */
class CChain {
private:
    std::vector<CBlockIndex *> vChain;

public:
    /**
     * Returns the index entry for the genesis block of this chain, or nullptr
     * if none.
     */
    CBlockIndex *Genesis() const {
        return vChain.size() > 0 ? vChain[0] : nullptr;
    }

    /**
     * Returns the index entry for the tip of this chain, or nullptr if none.
     */
    CBlockIndex *Tip() const {
        return vChain.size() > 0 ? vChain[vChain.size() - 1] : nullptr;
    }

    /**
     * Returns the index entry at a particular height in this chain, or nullptr
     * if no such height exists.
     */
    CBlockIndex *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)vChain.size()) {
            return nullptr;
        }
        return vChain[nHeight];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const {
        return (*this)[pindex->nHeight] == pindex;
    }

    /**
     * Find the successor of a block in this chain, or nullptr if the given
     * index is not found or is the tip.
     */
    CBlockIndex *Next(const CBlockIndex *pindex) const {
        if (!Contains(pindex)) {
            return nullptr;
        }

        return (*this)[pindex->nHeight + 1];
    }

    /**
     * Return the maximal height in the chain. Is equal to chain.Tip() ?
     * chain.Tip()->nHeight : -1.
     */
    int Height() const { return int(vChain.size()) - 1; }

    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex &block);

    /** Return a CBlockLocator that refers to the tip of this chain */
    CBlockLocator GetLocator() const;

    /**
     * Find the last common block between this chain and a block index entry.
     */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;

    /**
     * Find the earliest block with timestamp equal or greater than the given
     * time and height equal or greater than the given height.
     */
    CBlockIndex *FindEarliestAtLeast(int64_t nTime, int height) const;
};

/** Get a locator for a block index entry. */
CBlockLocator GetLocator(const CBlockIndex *index);

/** Construct a list of hash entries to put in a locator.  */
std::vector<BlockHash> LocatorEntries(const CBlockIndex *index);

#endif // BITCOIN_CHAIN_H
