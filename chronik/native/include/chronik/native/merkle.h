// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MERKLE_H
#define CHRONIK_NATIVE_MERKLE_H

#include <chronik/native/error.h>
#include <chronik/native/types.h>

#include <cstddef>
#include <functional>
#include <span>
#include <utility>
#include <vector>

/**
 * Port of chronik-indexer merkle.rs: merkle proof helpers for header
 * checkpoints and in-block tx proofs.
 *
 * Hashes are Hash32 in internal (little-endian) order, i.e. Rust's
 * Sha256d::as_le_bytes(). SHA-256d is a hook so the core never links node
 * crypto.
 */
namespace chronik::native {

/** Raw SHA-256d digest of `data` (Rust Sha256d::digest). */
using Sha256dFn = std::function<Hash32(ByteView data)>;

/** Build a Sha256dFn from a single SHA-256 (e.g. Host::Sha256). */
Sha256dFn Sha256dFromSha256(std::function<void(ByteView, uint8_t[32])> sha256);

/** Errors from MerkleTree operations (MerkleTreeError). */
class MerkleTreeError : public ChronikError {
public:
    enum class Kind { BadArgs, HashCountMismatch };
    /** "Invalid merkle tree arguments" */
    static MerkleTreeError BadArgs();
    /** "Expected {expected} hashes from provider, got {actual}" */
    static MerkleTreeError HashCountMismatch(size_t expected, size_t actual);

    Kind kind() const { return m_kind; }
    size_t expected() const { return m_expected; }
    size_t actual() const { return m_actual; }

private:
    MerkleTreeError(Kind kind, const std::string &msg, size_t expected,
                    size_t actual)
        : ChronikError(msg), m_kind(kind), m_expected(expected),
          m_actual(actual) {}
    Kind m_kind;
    size_t m_expected;
    size_t m_actual;
};

/**
 * Length of a merkle branch for `num_hashes` hashes (ceil(log2)). Throws
 * std::invalid_argument for 0 (Rust assert! panic).
 */
size_t CalcBranchLen(size_t num_hashes);

/**
 * Merkle root and branch for a full list of leaf hashes (Bitcoin-style:
 * odd levels duplicate the last hash). Throws std::logic_error with
 * "merkle_root_and_branch called with invalid args" for empty input or
 * out-of-range index (Rust expect() panic).
 */
std::pair<Hash32, std::vector<Hash32>>
MerkleRootAndBranch(const Sha256dFn &sha256d, std::span<const Hash32> hashes,
                    size_t index);

/**
 * `get_hashes(start, count)` must return exactly `count` leaf hashes starting
 * at height `start`; it may throw (propagated unchanged).
 */
using MerkleHashGetter =
    std::function<std::vector<Hash32>(size_t start, size_t count)>;

/**
 * Cached mid-level merkle tree over the block-hash chain. Stores hashes at
 * `depth_higher` above the leaves; proofs fetch only one leaf segment of size
 * `1 << depth_higher` and combine it with the cache. Not synchronized (Rust
 * keeps it in a Mutex).
 */
class MerkleTree {
public:
    explicit MerkleTree(Sha256dFn sha256d) : m_sha256d(std::move(sha256d)) {}

    /** Whether the mid-level cache has been built. */
    bool IsInitialized() const { return m_initialized; }
    /** Number of leaf hashes the cache currently covers. */
    size_t Length() const { return m_length; }

    /**
     * Truncate the cache to at most `length` leaf hashes (e.g. after a
     * reorg), rounded down to a segment boundary; 0 clears the cache.
     */
    void Truncate(size_t length);

    /**
     * Merkle root of the first `length` block hashes and the branch proving
     * the hash at `index` is included. Throws MerkleTreeError.
     */
    std::pair<Hash32, std::vector<Hash32>>
    MerkleRootAndBranch(size_t length, size_t index,
                        const MerkleHashGetter &get_hashes);

private:
    size_t SegmentLength() const { return size_t(1) << m_depth_higher; }
    size_t LeafStart(size_t index) const {
        return (index >> m_depth_higher) << m_depth_higher;
    }
    void Reset();
    void InitializeWithHashes(std::span<const Hash32> hashes);
    void ExtendTo(size_t length, const MerkleHashGetter &get_hashes);
    std::vector<Hash32> LevelFor(size_t length,
                                 const MerkleHashGetter &get_hashes) const;

    Sha256dFn m_sha256d;
    size_t m_length = 0;
    size_t m_depth_higher = 0;
    std::vector<Hash32> m_level;
    bool m_initialized = false;
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_MERKLE_H
