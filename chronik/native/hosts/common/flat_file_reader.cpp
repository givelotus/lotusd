// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hosts/common/flat_file_reader.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ios>

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace chronik::native::hosts {

CachedFlatFile::~CachedFlatFile() {
#if !defined(_WIN32)
    ::close(m_fd);
#endif
}

std::shared_ptr<const CachedFlatFile>
CachedFlatFile::Open(const std::string &path) {
#if defined(_WIN32)
    (void)path;
    return nullptr;
#else
    int fd;
    do {
        fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return nullptr;
    }
    return std::shared_ptr<const CachedFlatFile>(new CachedFlatFile(fd));
#endif
}

size_t CachedFlatFile::ReadAt(uint64_t offset, std::span<uint8_t> out) const {
#if defined(_WIN32)
    (void)offset;
    (void)out;
    throw std::ios_base::failure("CachedFlatFile: unsupported platform");
#else
    size_t done = 0;
    while (done < out.size()) {
        const ssize_t n = ::pread(m_fd, out.data() + done, out.size() - done,
                                  static_cast<off_t>(offset + done));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::ios_base::failure(std::string("CachedFlatFile: ") +
                                         std::strerror(errno));
        }
        if (n == 0) {
            break; // end of file
        }
        done += static_cast<size_t>(n);
    }
    return done;
#endif
}

FlatFileReadCache::FlatFileReadCache(Hooks hooks, size_t max_open_files)
    : m_hooks{std::move(hooks)}, m_max_open_files{max_open_files} {}

bool FlatFileReadCache::Supported() {
#if defined(_WIN32)
    return false;
#else
    return true;
#endif
}

std::shared_ptr<const CachedFlatFile>
FlatFileReadCache::Acquire(FlatFileKind kind, uint32_t file_num) {
    const Key key{static_cast<uint8_t>(kind), file_num};
    uint64_t generation;
    {
        std::lock_guard lock{m_mutex};
        auto it = m_index.find(key);
        if (it != m_index.end()) {
            m_lru.splice(m_lru.begin(), m_lru, it->second);
            ++m_stats.hits;
            return it->second->file;
        }
        generation = m_generation;
    }
    if (!Supported() || m_max_open_files == 0) {
        return nullptr;
    }
    // The hooks may take node locks; never call them with m_mutex held.
    if (m_hooks.may_append(kind, file_num)) {
        std::lock_guard lock{m_mutex};
        ++m_stats.bypasses;
        return nullptr;
    }
    std::shared_ptr<const CachedFlatFile> file =
        CachedFlatFile::Open(m_hooks.file_path(kind, file_num));

    std::lock_guard lock{m_mutex};
    if (!file) {
        ++m_stats.open_failures;
        return nullptr;
    }
    if (generation != m_generation) {
        // Invalidated while opening: use the descriptor for this read only.
        ++m_stats.misses;
        return file;
    }
    auto it = m_index.find(key);
    if (it != m_index.end()) {
        // Another reader cached it meanwhile; keep theirs.
        m_lru.splice(m_lru.begin(), m_lru, it->second);
        ++m_stats.hits;
        return it->second->file;
    }
    ++m_stats.misses;
    m_lru.push_front(Entry{key, file});
    m_index.emplace(key, m_lru.begin());
    while (m_lru.size() > m_max_open_files) {
        m_index.erase(m_lru.back().key);
        m_lru.pop_back();
        ++m_stats.evictions;
    }
    return file;
}

void FlatFileReadCache::Invalidate(uint32_t file_num) {
    std::lock_guard lock{m_mutex};
    ++m_generation;
    for (uint8_t kind : {static_cast<uint8_t>(FlatFileKind::BLOCK),
                         static_cast<uint8_t>(FlatFileKind::UNDO)}) {
        auto it = m_index.find(Key{kind, file_num});
        if (it != m_index.end()) {
            m_lru.erase(it->second);
            m_index.erase(it);
            ++m_stats.invalidations;
        }
    }
}

void FlatFileReadCache::Clear() {
    std::lock_guard lock{m_mutex};
    ++m_generation;
    m_stats.invalidations += m_lru.size();
    m_index.clear();
    m_lru.clear();
}

FlatFileCacheStats FlatFileReadCache::Stats() const {
    std::lock_guard lock{m_mutex};
    FlatFileCacheStats stats = m_stats;
    stats.open_files = m_lru.size();
    return stats;
}

FlatFileCursor::FlatFileCursor(std::shared_ptr<const CachedFlatFile> file,
                               uint64_t pos, size_t chunk_size)
    : m_file{std::move(file)}, m_buf_pos{pos},
      m_chunk_size{std::max<size_t>(chunk_size, 1)} {}

void FlatFileCursor::Refill(size_t want) {
    // Keep the unread tail, then read at least `want` more bytes.
    const size_t tail = m_buf_len - m_buf_off;
    if (m_buf_off > 0 && tail > 0) {
        std::memmove(m_buf.data(), m_buf.data() + m_buf_off, tail);
    }
    m_buf_pos += m_buf_off;
    m_buf_off = 0;
    m_buf_len = tail;
    const size_t read_size = std::max(m_chunk_size, want);
    if (m_buf.size() < tail + read_size) {
        m_buf.resize(tail + read_size);
    }
    m_buf_len += m_file->ReadAt(m_buf_pos + tail,
                                std::span(m_buf.data() + tail, read_size));
}

void FlatFileCursor::Read(std::span<uint8_t> out) {
    size_t avail = m_buf_len - m_buf_off;
    if (avail < out.size()) {
        Refill(out.size() - avail);
        avail = m_buf_len - m_buf_off;
        if (avail < out.size()) {
            throw std::ios_base::failure(
                "FlatFileCursor::Read: end of file");
        }
    }
    std::memcpy(out.data(), m_buf.data() + m_buf_off, out.size());
    m_buf_off += out.size();
}

void FlatFileCursor::Skip(size_t n) {
    const size_t avail = m_buf_len - m_buf_off;
    if (n <= avail) {
        m_buf_off += n;
        return;
    }
    // Drop the buffer and continue after the skipped range; the next Read()
    // reports a skip past the end of the file.
    m_buf_pos += m_buf_off + n;
    m_buf_off = 0;
    m_buf_len = 0;
}

} // namespace chronik::native::hosts
