// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <array>
#include <lotus_v2/header.h>
#include <lotus_v2/monetary.h>
#include <memory>
#include <primitives/blockhash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span>
#include <stdexcept>
#include <uint256.h>
#include <util/time.h>

// Local persistence/cache failure, distinct from a peer consensus violation.
class V2StateCacheError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

typedef std::array<uint8_t, 6> block_time_t;

/** Current thread's scoped construction domain, otherwise the startup-selected
 * process domain. A reference to a scoped value must not outlive that scope;
 * callers retaining the domain beyond their call must copy it. */
const lotus::v2::ChainId &GetActiveV2ChainId();
/** Select the process-wide domain during startup, before concurrent readers.
 * Runtime parameter construction must use ScopedV2ChainId, never this setter. */
void SetActiveV2ChainId(const lotus::v2::ChainId &chain_id);

/** Temporarily override only this thread's chain domain. Own the value rather
 * than borrowing caller storage; worker threads retain the selected process
 * domain unless they independently create an explicit scope. Scopes nest LIFO. */
class ScopedV2ChainId final {
public:
    explicit ScopedV2ChainId(const lotus::v2::ChainId &chain_id) noexcept;
    ~ScopedV2ChainId() noexcept;
    ScopedV2ChainId(const ScopedV2ChainId &) = delete;
    ScopedV2ChainId &operator=(const ScopedV2ChainId &) = delete;
    ScopedV2ChainId(ScopedV2ChainId &&) = delete;
    ScopedV2ChainId &operator=(ScopedV2ChainId &&) = delete;

private:
    const lotus::v2::ChainId m_chain_id;
    const lotus::v2::ChainId *const m_previous;
};

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
    /** Hash of block this block is extending, or all zeros for genesis block */
    BlockHash hashPrevBlock;
    /** Target blockhash should meet encoded compactly */
    uint32_t nBits;
    /** Block time of the block encoded little endian (6 bytes) */
    block_time_t vTime;
    /** Nonce for miners to tweak the blockhash */
    uint64_t nNonce;
    /** Version of the header; lotus::v2::kHeaderVersion (2) for Lotus V2 */
    uint32_t nHeaderVersion;
    /** Size of the block in bytes */
    uint64_t nSize;
    /** Height of the block; length of the chain from genesis */
    uint64_t nHeight;
    /** Merkle root of the txs in the block (tx_root) */
    uint256 hashMerkleRoot;
    /** Sparse Merkle Tree state root after applying this block (state_root) */
    uint256 hashStateRoot;

    CBlockHeader() { SetNull(); }

    SERIALIZE_METHODS(CBlockHeader, obj) {
        READWRITE(obj.hashPrevBlock);
        READWRITE(obj.nBits);
        READWRITE(obj.vTime);
        READWRITE(obj.nNonce);
        READWRITE(obj.nHeaderVersion);
        READWRITE(obj.nSize);
        READWRITE(obj.nHeight);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.hashStateRoot);
    }

    void SetNull() {
        hashPrevBlock = BlockHash();
        nBits = 0;
        vTime.fill(0);
        nNonce = 0;
        nHeaderVersion = 0;
        nSize = 0;
        nHeight = 0;
        hashMerkleRoot.SetNull();
        hashStateRoot.SetNull();
    }

    bool IsNull() const { return (nBits == 0); }

    lotus::v2::Header ToV2Header() const;
    static CBlockHeader FromV2Header(const lotus::v2::Header &h);

    BlockHash GetHash() const;

    NodeSeconds Time() const {
        return NodeSeconds{std::chrono::seconds{GetBlockTime()}};
    }

    /**
     * Block time as advertised in the block header.
     * Might not correspond to actual mined or received time.
     */
    int64_t GetBlockTime() const {
        return uint64_t(vTime[0]) | (uint64_t(vTime[1]) << 8) |
               (uint64_t(vTime[2]) << 16) | (uint64_t(vTime[3]) << 24) |
               (uint64_t(vTime[4]) << 32) | (uint64_t(vTime[5]) << 40);
    }

    /** Set the block time as advertised in the block header. */
    void SetBlockTime(uint64_t nTime) {
        vTime = {{
            uint8_t((nTime & 0x0000000000ffULL)),
            uint8_t((nTime & 0x00000000ff00ULL) >> 8),
            uint8_t((nTime & 0x000000ff0000ULL) >> 16),
            uint8_t((nTime & 0x0000ff000000ULL) >> 24),
            uint8_t((nTime & 0x00ff00000000ULL) >> 32),
            uint8_t((nTime & 0xff0000000000ULL) >> 40),
        }};
    }

    /**
     * Block size, with full encoding, including header and txs.
     */
    uint64_t GetSize() const { return nSize; }

    /** Set the advertised block size in the block header. */
    void SetSize(uint64_t size) { nSize = size; }
};

class CBlock : public CBlockHeader {
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // Memory-only flags for caching expensive checks
    // CheckBlock()
    mutable bool fChecked;
    // CheckMerkleRoot()
    mutable bool m_checked_merkle_root{false};

    CBlock() { SetNull(); }

    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader *>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj) {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
    }

    void SetNull() {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        m_checked_merkle_root = false;
    }

    CBlockHeader GetBlockHeader() const {
        CBlockHeader header;
        header.hashPrevBlock = hashPrevBlock;
        header.nBits = nBits;
        header.vTime = vTime;
        header.nNonce = nNonce;
        header.nHeaderVersion = nHeaderVersion;
        header.nSize = nSize;
        header.nHeight = nHeight;
        header.hashMerkleRoot = hashMerkleRoot;
        header.hashStateRoot = hashStateRoot;
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
    /**
     * Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network
     * stream. SerParams can be used if the field requires any meaning in the
     * future,
     */
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<BlockHash> vHave;

    CBlockLocator() = default;

    explicit CBlockLocator(std::vector<BlockHash> &&vHaveIn)
        : vHave(std::move(vHaveIn)) {}

    SERIALIZE_METHODS(CBlockLocator, obj) {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull() { vHave.clear(); }

    bool IsNull() const { return vHave.empty(); }
};

namespace lotus::v2 {
struct Coin;
struct SmtNode;
struct MonetaryState;
struct BlockUndoMessage;
class UtxoOverlayArena;
class MempoolOverlayLayer;
class MerklixOverlayManager;
} // namespace lotus::v2

struct V2TemplateBaseState {
    std::shared_ptr<const lotus::v2::SmtNode> utxo_root;
    // [Patch 035 optimization] Flat arena snapshot from MerklixOverlayManager
    // avoids exporting O(U) shared_ptr<SmtNode> trees on every mempool update.
    std::shared_ptr<const lotus::v2::UtxoOverlayArena> utxo_arena;
    lotus::v2::MonetaryState mon_state{};
    lotus::v2::MonetaryInteger sum_non_cb_effective_cost{0};
    size_t non_cb_tx_count{0};
    uint64_t height{0};
    uint64_t parent_mtp{0};
};

void SetV2StatePersistDir(const std::string &dir_path);
// False if a pending native state could not be persisted.
bool FlushV2BlockStatesToDisk();
bool GetV2BlockStateSnapshot(
    const BlockHash &blockHash,
    std::shared_ptr<const lotus::v2::SmtNode> &utxo_root_out,
    lotus::v2::MonetaryState &mon_state_out);
uint256 ComputeV2BlockStateRoot(const CBlock &block,
                                const BlockHash &hashPrevBlock,
                                uint64_t nHeight,
                                uint64_t nParentMtp,
                                bool record = false);
void RecordV2BlockState(const CBlock &block,
                        const BlockHash &blockHash,
                        const BlockHash &hashPrevBlock,
                        uint64_t nHeight,
                        uint64_t nParentMtp);
// Only validation may enable its existing min-difficulty-network zero-root
// policy (currently testnet/regtest, unless -strictstateroot is enabled).
void RecordV2BlockState(const CBlock &block,
                        const BlockHash &blockHash,
                        const BlockHash &hashPrevBlock,
                        uint64_t nHeight,
                        uint64_t nParentMtp,
                        bool allow_uncommitted_state_root);
uint64_t GetV2BlockCirculatingSupply(const BlockHash &blockHash);
void SetV2BlockCirculatingSupplyForTest(const BlockHash &blockHash,
                                        uint64_t circulating_supply);
uint256 ComputeV2TxRootFromSubtreeA(const CTransaction &coinbase_tx,
                                    const lotus::v2::Hash &subtree_a_root);
uint256 ComputeV2StateRootFromOverlay(
    const CTransaction &coinbase_tx,
    const lotus::v2::MempoolOverlayLayer &overlay,
    uint32_t nBits,
    uint64_t nHeight,
    uint64_t nParentMtp,
    bool record = false,
    const BlockHash *pBlockHash = nullptr);
uint256 ComputeV2StateRootFromOverlay(
    const CTransaction &coinbase_tx,
    const lotus::v2::MempoolOverlayLayer &overlay,
    uint32_t nBits, uint64_t nHeight, uint64_t nParentMtp,
    bool record, const BlockHash *pBlockHash,
    const uint256 *declared_state_root);
bool AddTransactionToOverlay(lotus::v2::MempoolOverlayLayer &overlay,
                             const CTransactionRef &ptx,
                             int64_t fee_sats = 0,
                             int64_t sigchecks = 0);
bool AddTransactionToOverlay(lotus::v2::MerklixOverlayManager &manager,
                             const CTransactionRef &ptx,
                             int64_t fee_sats = 0,
                             int64_t sigchecks = 0);
size_t AddTransactionsToOverlayBatch(
    lotus::v2::MempoolOverlayLayer &overlay,
    std::span<const std::tuple<CTransactionRef, int64_t, int64_t>> txs);
size_t AddTransactionsToOverlayBatch(
    lotus::v2::MerklixOverlayManager &manager,
    std::span<const std::tuple<CTransactionRef, int64_t, int64_t>> txs);
bool RemoveTransactionFromOverlay(lotus::v2::MempoolOverlayLayer &overlay,
                                  const CTransaction &tx);
bool RemoveTransactionFromOverlay(lotus::v2::MerklixOverlayManager &manager,
                                  const CTransaction &tx);
V2TemplateBaseState BuildV2TemplateBaseState(
    std::span<const CTransactionRef> non_coinbase_txs,
    const BlockHash &hashPrevBlock,
    uint64_t nHeight,
    uint64_t nParentMtp);
uint256 ComputeV2StateRootFromTemplate(
    const V2TemplateBaseState &base_state,
    const CTransaction &coinbase_tx,
    uint32_t nBits);
bool GetV2BlockStateCoinsAndMonetary(
    const BlockHash &blockHash,
    uint64_t nHeight,
    std::vector<lotus::v2::Coin> &coins_out,
    lotus::v2::MonetaryState &monetary_out);
// A configured persistence failure leaves the snapshot unpublished and returns
// false. With no persistence directory this remains an in-memory import.
bool ImportV2BlockStateCoinsAndMonetary(
    const BlockHash &blockHash,
    const std::vector<lotus::v2::Coin> &coins,
    const lotus::v2::MonetaryState &monetary_state,
    bool is_tip = true);
lotus::v2::MonetaryState AdvanceV2BlockMonetaryState(
    const CBlock &block,
    const lotus::v2::MonetaryState &parent_mon_state);
std::shared_ptr<const lotus::v2::SmtNode>
GetV2BlockUtxoRoot(const BlockHash &blockHash, bool *found_out = nullptr);
std::optional<CTxOut>
LookupV2SmtCoin(const std::shared_ptr<const lotus::v2::SmtNode> &root,
                const COutPoint &outpoint,
                uint32_t *height_out = nullptr,
                bool *coinbase_out = nullptr);

#endif // BITCOIN_PRIMITIVES_BLOCK_H

