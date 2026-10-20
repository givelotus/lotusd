// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_HOSTS_COMMON_FLAT_FILE_READER_H
#define CHRONIK_NATIVE_HOSTS_COMMON_FLAT_FILE_READER_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <utility>
#include <vector>

/**
 * Block-file reads for Chronik host adapters.
 *
 * A host loads one tx (and its undo data) per tx of a response. Opening the
 * blk/rev file, seeking, reading through stdio and closing it again costs
 * about seven syscalls per read. FlatFileReadCache keeps a small LRU of
 * read-only descriptors, keyed by file kind and number, and reads with
 * pread(2), so a hit costs one syscall.
 *
 * Only files the node will never append to again are cached. The host says
 * which files those are (FlatFileReadCache::Hooks::may_append); for the
 * others Acquire() returns nullptr and the host keeps its existing read path.
 * Before the node deletes a file (pruning), the host calls Invalidate(), and
 * the descriptor is closed as soon as no reader still holds it. The cache is
 * independent of the node: it only knows file paths, so every host (ABC,
 * BCHN, Bitcoin Core) can use it.
 *
 * Bitcoin Core: its blk/rev files are XOR-obfuscated with the key in
 * blocks/xor.dat (Core >= 28). A Core host must un-XOR what ReadAt returns,
 * with key byte (file offset % 8) for each byte, before decoding. A cursor
 * that knows the absolute offset of its buffer (FlatFileCursor::Pos) can do
 * that per refill. A memory-mapped variant could not decode in place (the
 * mapping is read-only and shared); it would also have to copy each tx out
 * while un-XORing, which removes most of its advantage over pread.
 *
 * Not available on Windows (no pread); Acquire() then always returns
 * nullptr and hosts read as before.
 */
namespace chronik::native::hosts {

/** Which of a node's flat-file sequences a file belongs to. */
enum class FlatFileKind : uint8_t {
    BLOCK = 0, // blk?????.dat
    UNDO = 1,  // rev?????.dat
};

/**
 * A read-only file descriptor shared by the cache and the readers that
 * acquired it. It is closed when the last reference goes away, so eviction
 * and invalidation never close a descriptor a reader still uses.
 */
class CachedFlatFile {
public:
    ~CachedFlatFile();
    CachedFlatFile(const CachedFlatFile &) = delete;
    CachedFlatFile &operator=(const CachedFlatFile &) = delete;

    /**
     * Read up to out.size() bytes at offset with pread(2), retrying on EINTR
     * and short reads. Returns the number of bytes read, which is smaller
     * than out.size() only at the end of the file. Throws
     * std::ios_base::failure on a read error.
     */
    size_t ReadAt(uint64_t offset, std::span<uint8_t> out) const;

    /** Opens path read-only; nullptr if it can't be opened. */
    static std::shared_ptr<const CachedFlatFile> Open(const std::string &path);

private:
    explicit CachedFlatFile(int fd) : m_fd{fd} {}
    int m_fd;
};

struct FlatFileCacheStats {
    /** Acquire() calls answered from the cache. */
    uint64_t hits = 0;
    /** Acquire() calls that opened and cached a file. */
    uint64_t misses = 0;
    /** Acquire() calls for files the node may still append to. */
    uint64_t bypasses = 0;
    /** Acquire() calls whose open() failed (e.g. a deleted file). */
    uint64_t open_failures = 0;
    /** Files closed to make room for others. */
    uint64_t evictions = 0;
    /** Files dropped by Invalidate()/Clear(). */
    uint64_t invalidations = 0;
    /** Files currently held by the cache. */
    size_t open_files = 0;
};

class FlatFileReadCache {
public:
    struct Hooks {
        /** Path of a file of the node. */
        std::function<std::string(FlatFileKind, uint32_t file_num)> file_path;
        /**
         * True if the node may still write to this file. Called without the
         * cache's lock held, on every Acquire() of a file that isn't cached.
         */
        std::function<bool(FlatFileKind, uint32_t file_num)> may_append;
    };

    /** Small, because each entry is a descriptor of the node's process. */
    static constexpr size_t DEFAULT_MAX_OPEN_FILES = 16;

    explicit FlatFileReadCache(Hooks hooks,
                               size_t max_open_files = DEFAULT_MAX_OPEN_FILES);

    /**
     * The cached descriptor of a file, opening it on a miss. nullptr if the
     * node may still append to the file, if it can't be opened, or on
     * platforms without pread: the caller then uses its own read path.
     * Thread-safe.
     */
    std::shared_ptr<const CachedFlatFile> Acquire(FlatFileKind kind,
                                                  uint32_t file_num);

    /**
     * Forget both kinds of file_num, e.g. before the node deletes them. A
     * concurrent Acquire() that opened the file before this call doesn't
     * insert it afterwards.
     */
    void Invalidate(uint32_t file_num);
    /** Forget every file. */
    void Clear();

    FlatFileCacheStats Stats() const;

    /** False on platforms without pread (Windows). */
    static bool Supported();

private:
    using Key = std::pair<uint8_t, uint32_t>;
    struct Entry {
        Key key;
        std::shared_ptr<const CachedFlatFile> file;
    };

    Hooks m_hooks;
    const size_t m_max_open_files;

    mutable std::mutex m_mutex;
    /** Most recently used first. */
    std::list<Entry> m_lru;
    std::map<Key, std::list<Entry>::iterator> m_index;
    /** Bumped by Invalidate()/Clear(); an Acquire() that opened a file under
     * an older generation doesn't cache it. */
    uint64_t m_generation = 0;
    FlatFileCacheStats m_stats;
};

/**
 * Sequential reader over a CachedFlatFile, for deserializers: it serves
 * Read() calls from a buffer refilled with pread()s of chunk_size bytes.
 */
class FlatFileCursor {
public:
    static constexpr size_t DEFAULT_CHUNK_SIZE = 4096;

    FlatFileCursor(std::shared_ptr<const CachedFlatFile> file, uint64_t pos,
                   size_t chunk_size = DEFAULT_CHUNK_SIZE);

    /**
     * Copy exactly out.size() bytes. Throws std::ios_base::failure if the
     * file ends first (like AutoFile).
     */
    void Read(std::span<uint8_t> out);
    void Skip(size_t n);
    /** Absolute file offset of the next byte Read() returns. */
    uint64_t Pos() const { return m_buf_pos + m_buf_off; }

private:
    void Refill(size_t want);

    std::shared_ptr<const CachedFlatFile> m_file;
    std::vector<uint8_t> m_buf;
    /** File offset of m_buf[0]. */
    uint64_t m_buf_pos;
    size_t m_buf_off = 0;
    size_t m_buf_len = 0;
    const size_t m_chunk_size;
};

} // namespace chronik::native::hosts

#endif // CHRONIK_NATIVE_HOSTS_COMMON_FLAT_FILE_READER_H
