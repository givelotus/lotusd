// Copyright (c) 2026 The Lotus developers
#include "disk_state.h"
#include "mempool_overlay.h"
#include "monetary.h"
#include "vendor/blake3/blake3.h"
#include "vendor/libmdbx/mdbx.h"

#include <leveldb/env.h>
#include <leveldb/slice.h>
#include <leveldb/status.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string_view>
#include <typeinfo>
#include <utility>

namespace lotus::v2 {
namespace {
using Bytes = std::string;
using BytesView = std::string_view;
using Value = std::optional<Bytes>;
using ValueView = std::optional<BytesView>;

constexpr uint32_t MAX_FLAT_SEGMENT_BYTES = 128U << 20;

bool IsTestFaultEnv(leveldb::Env *env) {
    if (!env) return false;
    const char *name = typeid(*env).name();
    return std::strstr(name, "CountingEnv") == nullptr;
}

struct Failure { DiskStateError error; };
[[noreturn]] void Fail(DiskStateErrorCode code, const std::string &message) {
    throw Failure{{code, message}};
}
[[noreturn]] void Corrupt(const char *message) { Fail(DiskStateErrorCode::Corruption, message); }
void Require(bool condition, const char *message) { if (!condition) Corrupt(message); }
void CheckStatus(const leveldb::Status &status) {
    if (!status.ok()) Fail(status.IsCorruption() ? DiskStateErrorCode::Corruption
                                               : DiskStateErrorCode::Database, status.ToString());
}
void CheckMdbx(int rc, const char *context = "mdbx operation") {
    if (rc == MDBX_SUCCESS) return;
    const bool is_corrupt = (rc == MDBX_CORRUPTED || rc == MDBX_PAGE_NOTFOUND || rc == MDBX_INVALID);
    Fail(is_corrupt ? DiskStateErrorCode::Corruption : DiskStateErrorCode::Database,
         std::string(context) + ": " + mdbx_strerror(rc));
}
void SyncEnvironment(MDBX_env *env) {
    const int rc = mdbx_env_sync_ex(env, true, false);
    if (rc != MDBX_RESULT_TRUE) CheckMdbx(rc, "mdbx_env_sync_ex");
}
void SyncFileDescriptor(int fd) {
    while (::fsync(fd) != 0) {
        if (errno == EINTR) continue;
        Fail(DiskStateErrorCode::Database,
             std::string("flat-file fsync failed: ") + std::strerror(errno));
    }
}
void SyncDirectory(const std::string &directory) {
    const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) Fail(DiskStateErrorCode::Database, "open directory for sync failed: " + directory);
    try { SyncFileDescriptor(fd); }
    catch (...) { ::close(fd); throw; }
    ::close(fd);
}
template <typename F> bool Guard(DiskStateError &error, F &&f) {
    error = {};
    try { f(); return true; }
    catch (const Failure &failure) { error = failure.error; }
    catch (const std::bad_alloc &) { error = {DiskStateErrorCode::Resource, "allocation failed"}; }
    catch (const std::length_error &) { error = {DiskStateErrorCode::Resource, "allocation length"}; }
    return false;
}

std::mutex &OpenDirsMutex() {
    static std::mutex m;
    return m;
}
std::set<std::string> &OpenDirsSet() {
    static std::set<std::string> s;
    return s;
}
std::string NormalizeDirPath(const std::string &dir) {
    std::error_code ec;
    auto p = std::filesystem::weakly_canonical(dir, ec);
    return ec ? dir : p.string();
}

void Put(Bytes &out, uint64_t n, unsigned width = 8) {
    for (unsigned i = 0; i < width; ++i) out.push_back(static_cast<char>(n >> (8 * i)));
}
void PutHash(Bytes &out, const Hash &hash) {
    out.append(reinterpret_cast<const char *>(hash.data()), hash.size());
}
void PutBlob(Bytes &out, BytesView value) { Put(out, value.size()); out.append(value.data(), value.size()); }
void PutBlob(Bytes &out, const std::vector<uint8_t> &value) {
    Put(out, value.size());
    if (!value.empty()) out.append(reinterpret_cast<const char *>(value.data()), value.size());
}
struct Reader {
    BytesView bytes;
    size_t at{};
    uint64_t Int(unsigned width = 8) {
        Require(width <= bytes.size() - at, "truncated integer");
        uint64_t value{};
        for (unsigned i = 0; i < width; ++i) value |= uint64_t(uint8_t(bytes[at++])) << (8 * i);
        return value;
    }
    Hash Digest() {
        Require(32 <= bytes.size() - at, "truncated digest");
        Hash result;
        std::copy_n(reinterpret_cast<const uint8_t *>(bytes.data() + at), 32, result.begin());
        at += 32;
        return result;
    }
    BytesView BlobView(size_t cap = std::numeric_limits<size_t>::max()) {
        const uint64_t n = Int();
        Require(n <= cap && n <= bytes.size() - at, "invalid stored length");
        BytesView result = bytes.substr(at, static_cast<size_t>(n));
        at += static_cast<size_t>(n);
        return result;
    }
    Bytes Blob(size_t cap = std::numeric_limits<size_t>::max()) {
        const BytesView v = BlobView(cap);
        return Bytes(v.data(), v.size());
    }
    void End() { Require(at == bytes.size(), "trailing stored bytes"); }
};

Bytes EncodeLocation(const DiskFileLocation &loc) {
    Bytes out;
    out.reserve(12);
    Put(out, loc.file_num, 4);
    Put(out, loc.data_pos, 4);
    Put(out, loc.length, 4);
    return out;
}
DiskFileLocation ParseLocation(BytesView bytes) {
    Require(bytes.size() == 12, "invalid flat file location size");
    Reader r{bytes};
    DiskFileLocation loc;
    loc.file_num = static_cast<uint32_t>(r.Int(4));
    loc.data_pos = static_cast<uint32_t>(r.Int(4));
    loc.length = static_cast<uint32_t>(r.Int(4));
    r.End();
    return loc;
}
Bytes EncodeSegmentCursor(uint32_t file_num, uint32_t next_pos) {
    Bytes out;
    out.reserve(8);
    Put(out, file_num, 4);
    Put(out, next_pos, 4);
    return out;
}
std::pair<uint32_t, uint32_t> ParseSegmentCursor(BytesView bytes) {
    Require(bytes.size() == 8, "invalid flat file cursor size");
    Reader r{bytes};
    const auto file_num = static_cast<uint32_t>(r.Int(4));
    const auto next_pos = static_cast<uint32_t>(r.Int(4));
    r.End();
    return {file_num, next_pos};
}
DiskFileLocation NextSegmentLocation(uint32_t &file_num, uint32_t &next_pos, size_t length) {
    if (length > std::numeric_limits<uint32_t>::max())
        Fail(DiskStateErrorCode::Resource, "flat segment record exceeds 32-bit length");
    const auto len32 = static_cast<uint32_t>(length);
    if (next_pos > 0 && uint64_t(next_pos) + uint64_t(len32) > MAX_FLAT_SEGMENT_BYTES) {
        if (file_num == std::numeric_limits<uint32_t>::max())
            Fail(DiskStateErrorCode::Resource, "flat segment file number exhausted");
        ++file_num;
        next_pos = 0;
    }
    if (uint64_t(next_pos) + uint64_t(len32) > std::numeric_limits<uint32_t>::max())
        Fail(DiskStateErrorCode::Resource, "flat segment offset overflow");
    DiskFileLocation loc{file_num, next_pos, len32};
    next_pos += len32;
    return loc;
}
std::string SegmentFilePath(const std::string &directory, bool is_block, uint32_t file_num) {
    char name[32];
    std::snprintf(name, sizeof(name), "%s%05u.dat", is_block ? "blk" : "rev", unsigned(file_num));
    return directory + "/blocks/" + name;
}

constexpr uint8_t ReverseByte(uint8_t b) {
    b = static_cast<uint8_t>(((b & 0xF0u) >> 4) | ((b & 0x0Fu) << 4));
    b = static_cast<uint8_t>(((b & 0xCCu) >> 2) | ((b & 0x33u) << 2));
    b = static_cast<uint8_t>(((b & 0xAAu) >> 1) | ((b & 0x55u) << 1));
    return b;
}
bool Bit(const Hash &key, unsigned depth) {
    Require(depth < 256, "tree depth");
    return (key[depth / 8] >> (depth % 8)) & 1;
}
struct Path {
    Hash prefix{};
    unsigned depth{};
    Path Child(bool bit) const {
        Require(depth < 256, "child depth");
        Path child = *this;
        if (bit) child.prefix[depth / 8] |= uint8_t(1 << (depth % 8));
        ++child.depth;
        return child;
    }
    Bytes Key() const {
        // N || 32-byte bit-reversed logical prefix || depth_u16le.
        // Bit-reversing each byte maps tree bit (depth % 8 == 0) to MSB 0x80
        // so that deep SMT ancestors share a lexicographic prefix in 4 KB
        // libmdbx B+Tree pages without changing Bit() or UtxoNode hashes.
        char buf[35];
        buf[0] = 'N';
        for (size_t i = 0; i < 32; ++i) {
            buf[1 + i] = static_cast<char>(ReverseByte(prefix[i]));
        }
        buf[33] = static_cast<char>(depth & 0xffu);
        buf[34] = static_cast<char>((depth >> 8) & 0xffu);
        return Bytes(buf, 35);
    }
    bool Contains(const Hash &key) const {
        for (unsigned d = 0; d < depth; ++d) if (Bit(key, d) != Bit(prefix, d)) return false;
        return true;
    }
    bool operator==(const Path &o) const noexcept {
        return depth == o.depth && prefix == o.prefix;
    }
};
Bytes CoinKey(const Outpoint &outpoint) {
    char buf[37];
    buf[0] = 'C';
    for (size_t i = 0; i < 32; ++i) {
        buf[1 + i] = static_cast<char>(ReverseByte(outpoint.tx_id[i]));
    }
    for (unsigned i = 0; i < 4; ++i) {
        buf[33 + i] = static_cast<char>((outpoint.index >> (8 * i)) & 0xffu);
    }
    return Bytes(buf, 37);
}
Bytes UndoKey(const Hash &tip) { Bytes key(1, 'U'); PutHash(key, tip); return key; }
Bytes CoinBytes(const Coin &coin) {
    std::vector<uint8_t> encoded;
    if (!EncodeCoin(coin, encoded)) Fail(DiskStateErrorCode::InvalidCoin, "invalid coin");
    return Bytes(reinterpret_cast<const char *>(encoded.data()), encoded.size());
}
Coin ParseCoin(BytesView bytes) {
    Require(bytes.size() <= MAX_COIN_BYTES && bytes.size() >= 54, "coin size");
    Reader r{bytes};
    Coin coin;
    coin.outpoint.tx_id = r.Digest();
    coin.outpoint.index = r.Int(4);
    const uint64_t lead = r.Int(1);
    uint64_t size = lead;
    if (lead >= 253) {
        const unsigned width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
        size = r.Int(width);
        Require(size >= (width == 2 ? 253 : width == 4 ? 65536ULL : 4294967296ULL),
                "noncanonical coin length");
    }
    Require(size <= MAX_OUTPUT_BYTES && size <= bytes.size() - r.at, "coin output size");
    std::vector<uint8_t> output(reinterpret_cast<const uint8_t *>(bytes.data() + r.at),
                                reinterpret_cast<const uint8_t *>(bytes.data() + r.at + size));
    r.at += size;
    std::string error;
    Require(DecodeOutput(output, coin.output, error), "coin output");
    coin.creation_height = r.Int();
    coin.creation_parent_mtp = r.Int();
    const auto flag = r.Int(1);
    Require(flag <= 1, "coinbase flag"); coin.coinbase = flag;
    r.End();
    std::vector<uint8_t> canonical;
    Require(EncodeCoin(coin, canonical) &&
            BytesView(reinterpret_cast<const char *>(canonical.data()), canonical.size()) == bytes,
            "noncanonical coin");
    return coin;
}
// Cardinality is only 0, 1, or many; no global coin-count representation cap.
struct Summary {
    uint8_t kind{};
    Hash digest{EmptyUtxoRoot()};
    bool operator==(const Summary &) const = default;
};
void PutSummary(Bytes &out, const Summary &summary) {
    Put(out, summary.kind, 1); PutHash(out, summary.digest);
}
Summary GetSummary(Reader &r) {
    Summary result{static_cast<uint8_t>(r.Int(1)), r.Digest()};
    Require(result.kind <= 2 && (result.kind == 0) == (result.digest == EmptyUtxoRoot()),
            "invalid tree summary");
    return result;
}
struct Node {
    Summary summary;
    std::optional<Coin> coin;
    Bytes coin_bytes;
    Hash coin_outpoint_key{};
    std::array<Summary, 2> children;
};
Node Leaf(const Coin &coin, Bytes encoded = {}) {
    Node node; node.summary.kind = 1; node.coin = coin;
    if (encoded.empty()) encoded = CoinBytes(coin);
    node.coin_bytes = std::move(encoded);
    node.coin_outpoint_key = OutpointKey(coin.outpoint);
    if (!UtxoLeaf(coin, node.summary.digest)) Fail(DiskStateErrorCode::InvalidCoin, "invalid leaf");
    return node;
}
Node Branch(unsigned depth, const Summary &left, const Summary &right) {
    Require(depth < 256, "branch depth");
    Require((left.kind != 0 || right.kind != 0) &&
            !(left.kind == 0 && right.kind == 1) && !(left.kind == 1 && right.kind == 0),
            "uncollapsed branch");
    Node node; node.summary.kind = 2; node.children = {left, right};
    Require(UtxoNode(depth, left.digest, right.digest, node.summary.digest), "node hash");
    return node;
}
Bytes EncodeNode(const Node &node) {
    Bytes bytes;
    PutSummary(bytes, node.summary);
    if (node.summary.kind == 1) {
        PutBlob(bytes, node.coin_bytes.empty() ? CoinBytes(*node.coin) : node.coin_bytes);
    } else {
        PutSummary(bytes, node.children[0]);
        PutSummary(bytes, node.children[1]);
    }
    return bytes;
}
Node ParseNode(BytesView bytes, const Path &path, const Summary &expected) {
    Require(bytes.size() <= MAX_COIN_BYTES + 41, "node size");
    Reader r{bytes};
    const Summary stored = GetSummary(r);
    Require(stored == expected && stored.kind != 0, "node/head disagreement");
    Node node;
    if (stored.kind == 1) {
        const BytesView cb = r.BlobView(MAX_COIN_BYTES);
        node = Leaf(ParseCoin(cb), Bytes(cb));
        Require(path.Contains(node.coin_outpoint_key), "leaf path mismatch");
    } else {
        auto left = GetSummary(r); auto right = GetSummary(r);
        node = Branch(path.depth, left, right);
    }
    r.End(); Require(node.summary == stored, "node hash mismatch");
    return node;
}
struct Head { Summary root; DiskStateMetadata metadata; };
Bytes Schema(const DiskStateOptions &options) {
    Bytes bytes("LotusV2State\1", 13);
    PutHash(bytes, options.identity); PutHash(bytes, options.profile_digest); return bytes;
}
void CheckMetadata(const DiskStateMetadata &metadata, size_t cap) {
    if (metadata.header.size() > cap || metadata.monetary.size() > cap - metadata.header.size() ||
        metadata.auxiliary.size() > cap - metadata.header.size() - metadata.monetary.size())
        Fail(DiskStateErrorCode::Resource, "metadata exceeds operational limit");
}
Bytes EncodeHead(const Head &head, const DiskStateOptions &options) {
    CheckMetadata(head.metadata, options.max_metadata_bytes);
    Bytes bytes = Schema(options);
    PutSummary(bytes, head.root); PutHash(bytes, head.metadata.tip);
    PutBlob(bytes, head.metadata.header); PutBlob(bytes, head.metadata.monetary);
    PutBlob(bytes, head.metadata.auxiliary); return bytes;
}
Head ParseHead(BytesView bytes, const DiskStateOptions &options) {
    const Bytes schema = Schema(options);
    Require(bytes.size() >= schema.size(), "head schema missing");
    if (bytes.compare(0, schema.size(), schema) != 0)
        Fail(DiskStateErrorCode::ProfileMismatch, "head identity/profile mismatch");
    Reader r{bytes, schema.size()}; Head result;
    result.root = GetSummary(r); result.metadata.tip = r.Digest();
    auto Copy = [&](std::vector<uint8_t> &out) {
        const BytesView value = r.BlobView(options.max_metadata_bytes);
        out.assign(reinterpret_cast<const uint8_t *>(value.data()),
                   reinterpret_cast<const uint8_t *>(value.data() + value.size()));
    };
    Copy(result.metadata.header); Copy(result.metadata.monetary); Copy(result.metadata.auxiliary);
    r.End(); CheckMetadata(result.metadata, options.max_metadata_bytes); return result;
}
std::optional<Bytes> ExtractBlockBodyFromMetadata(const DiskStateMetadata &meta) {
    const auto &aux = meta.auxiliary;
    if (aux.size() >= 6 && aux[0] == 'L' && aux[1] == 'V' && aux[2] == '2' && aux[3] == 'C' &&
        aux[4] == 1 && aux[5] >= 1 && aux[5] <= 11) {
        const size_t offset = 6 + size_t(aux[5]) * HEADER_SIZE;
        if (aux.size() > offset) {
            return Bytes(reinterpret_cast<const char *>(aux.data() + offset), aux.size() - offset);
        }
    }
    if (!meta.header.empty()) {
        return Bytes(reinterpret_cast<const char *>(meta.header.data()), meta.header.size());
    }
    return std::nullopt;
}
std::optional<std::pair<Hash, size_t>> InspectHeadBodyOffset(BytesView head_bytes) {
    if (head_bytes.size() < 77 + 33 + 32 + 24) return std::nullopt;
    Reader r{head_bytes, 77};
    (void)r.Int(1);
    (void)r.Digest();
    const Hash tip = r.Digest();
    (void)r.BlobView();
    (void)r.BlobView();
    const size_t aux_len_pos = r.at;
    const BytesView aux = r.BlobView();
    if (r.at != head_bytes.size()) return std::nullopt;
    if (aux.size() >= 6 && aux[0] == 'L' && aux[1] == 'V' && aux[2] == '2' && aux[3] == 'C' &&
        uint8_t(aux[4]) == 1 && uint8_t(aux[5]) >= 1 && uint8_t(aux[5]) <= 11) {
        const size_t hdrs_len = 6 + size_t(uint8_t(aux[5])) * HEADER_SIZE;
        if (aux.size() > hdrs_len) {
            return std::pair{tip, aux_len_pos};
        }
    }
    return std::nullopt;
}
Bytes CompactHeadBytes(BytesView head_bytes, size_t aux_len_pos, const DiskBlockLocation &loc) {
    Reader r{head_bytes, aux_len_pos};
    const BytesView aux = r.BlobView();
    const size_t hdrs_len = 6 + size_t(uint8_t(aux[5])) * HEADER_SIZE;
    Bytes compact_aux;
    compact_aux.reserve(hdrs_len + 12);
    compact_aux.append(aux.data(), hdrs_len);
    compact_aux[4] = 2;
    compact_aux += EncodeLocation(loc);
    Bytes out(head_bytes.substr(0, aux_len_pos));
    PutBlob(out, compact_aux);
    return out;
}
template <typename ReadFlatFn>
Bytes ExpandCompactHeadBytes(BytesView stored, ReadFlatFn &&read_flat) {
    if (stored.size() < 77 + 33 + 32 + 24) return Bytes(stored);
    size_t at = 77 + 33 + 32;
    auto skip_blob = [&](BytesView &out_blob, size_t &len_pos) -> bool {
        if (8 > stored.size() - at) return false;
        len_pos = at;
        uint64_t n{};
        for (unsigned i = 0; i < 8; ++i) n |= uint64_t(uint8_t(stored[at++])) << (8 * i);
        if (n > stored.size() - at) return false;
        out_blob = stored.substr(at, static_cast<size_t>(n));
        at += static_cast<size_t>(n);
        return true;
    };
    BytesView hdr_blob, mon_blob, aux_blob;
    size_t hdr_pos{}, mon_pos{}, aux_pos{};
    if (!skip_blob(hdr_blob, hdr_pos) || !skip_blob(mon_blob, mon_pos) ||
        !skip_blob(aux_blob, aux_pos) || at != stored.size()) {
        return Bytes(stored);
    }
    if (aux_blob.size() >= 6 + 12 && aux_blob[0] == 'L' && aux_blob[1] == 'V' &&
        aux_blob[2] == '2' && aux_blob[3] == 'C' && uint8_t(aux_blob[4]) == 2 &&
        uint8_t(aux_blob[5]) >= 1 && uint8_t(aux_blob[5]) <= 11) {
        const size_t hdrs_len = 6 + size_t(uint8_t(aux_blob[5])) * HEADER_SIZE;
        if (aux_blob.size() == hdrs_len + 12) {
            const DiskBlockLocation loc = ParseLocation(aux_blob.substr(hdrs_len, 12));
            const Bytes body = read_flat(loc);
            Bytes full_aux;
            full_aux.reserve(hdrs_len + body.size());
            full_aux.append(aux_blob.data(), hdrs_len);
            full_aux[4] = 1;
            full_aux += body;
            Bytes out(stored.substr(0, aux_pos));
            PutBlob(out, full_aux);
            return out;
        }
    }
    return Bytes(stored);
}

Bytes StorageSchema(const DiskStateOptions &options) {
    Bytes bytes = Schema(options);
    if (!options.header_index) return bytes;
    bytes[12] = options.candidates ? 4 : options.recovery ? 3 : 2; // Explicit development format, never migrated implicitly.
    const auto &p = *options.header_index;
    PutHash(bytes, p.chain_id); PutHash(bytes, p.genesis_id); Put(bytes, p.version, 4);
    Put(bytes, p.genesis_time); Put(bytes, p.genesis_bits, 4); PutHash(bytes, p.pow_limit);
    Put(bytes, uint64_t(p.half_life_seconds)); Put(bytes, uint64_t(p.spacing_seconds));
    if (options.recovery) { Put(bytes, options.recovery->max_journal_bytes); Put(bytes, options.recovery->max_undo_bytes); }
    if (options.candidates) {
        Put(bytes, options.candidates->max_candidates); Put(bytes, options.candidates->max_speculative_headers);
        Put(bytes, options.candidates->max_invalid_roots);
    }
    if (options.avalanche) { Put(bytes, 1, 1); Put(bytes, options.max_avalanche_reads); }
    return bytes;
}
void CheckIndexOptions(const DiskStateOptions &options) {
    if (options.avalanche && (!options.candidates || !options.max_avalanche_reads))
        Fail(DiskStateErrorCode::ProfileMismatch, "Avalanche requires bounded V4 home");
    if (options.candidates && (!options.recovery || !options.candidates->max_candidates ||
        !options.candidates->max_speculative_headers || !options.candidates->max_invalid_roots))
        Fail(DiskStateErrorCode::ProfileMismatch, "invalid explicit candidate creation caps");
    if (options.recovery && (!options.header_index || !options.recovery->max_undo_bytes ||
        !options.recovery->max_journal_bytes || options.recovery->max_journal_bytes > std::numeric_limits<size_t>::max() - 73))
        Fail(DiskStateErrorCode::ProfileMismatch, "invalid explicit recovery creation caps");
    if (!options.header_index) return;
    const auto &p = *options.header_index; Hash target;
    if (p.chain_id != options.identity || p.genesis_id == Hash{} || p.genesis_time > MAX_TIME ||
        p.half_life_seconds <= 0 || p.spacing_seconds <= 0 ||
        !DecodeTarget(p.genesis_bits, p.pow_limit, target))
        Fail(DiskStateErrorCode::ProfileMismatch, "invalid explicit header index profile");
}
Bytes HeaderKey(const Hash &id) { Bytes bytes(1, 'H'); PutHash(bytes, id); return bytes; }
Bytes ActiveKey(uint64_t height) {
    Bytes bytes(1, 'A');
    for (unsigned i = 8; i-- > 0;) bytes.push_back(static_cast<char>(height >> (8 * i)));
    return bytes;
}
Bytes HashBytes(const Hash &hash) { Bytes bytes; PutHash(bytes, hash); return bytes; }
Hash ParseHash(BytesView bytes) { Reader r{bytes}; const Hash hash = r.Digest(); r.End(); return hash; }
void PutWork(Bytes &bytes, const ChainWork &work) {
    bytes.append(reinterpret_cast<const char *>(work.data()), work.size());
}
ChainWork GetWork(Reader &r) {
    ChainWork work{}; for (auto &byte : work) byte = r.Int(1); return work;
}
Bytes HeaderBytes(const Header &header) {
    std::array<uint8_t, HEADER_SIZE> encoded;
    Require(SerializeHeader(header, encoded), "indexed header encoding");
    return Bytes(reinterpret_cast<const char *>(encoded.data()), encoded.size());
}
ChainWork CheckOwnHeader(const Header &header, const Hash &id, const HeaderChainProfile &p) {
    Hash actual, target;
    Require(header.version == p.version && header.time <= MAX_TIME && header.size >= HEADER_SIZE + 4 &&
            BlockId(p.chain_id, header, actual) && actual == id &&
            DecodeTarget(header.bits, p.pow_limit, target) && MeetsTarget(id, target),
            "indexed header identity/profile/target/proof mismatch");
    if (header.height == 0)
        Require(id == p.genesis_id && header.prev_id == Hash{} && header.time == p.genesis_time &&
                header.bits == p.genesis_bits, "indexed genesis anchor mismatch");
    else Require(header.prev_id != Hash{}, "indexed non-genesis parent");
    ChainWork work{}; Require(HeaderWork(target, work), "indexed positive work"); return work;
}
Bytes EncodeIndexedHeader(const IndexedHeader &entry) {
    Bytes bytes; Put(bytes, 1, 1); Put(bytes, uint8_t(entry.stage), 1);
    bytes += HeaderBytes(entry.header); PutWork(bytes, entry.chain_work); Put(bytes, entry.max_ancestor_time);
    return bytes;
}
IndexedHeader ParseIndexedHeader(BytesView bytes, const Hash &id, const HeaderChainProfile &p) {
    Require(bytes.size() == 2 + HEADER_SIZE + 40 + 8, "indexed header record size");
    Reader r{bytes}; Require(r.Int(1) == 1, "indexed header record version");
    const auto stage = r.Int(1); Require(stage <= 1, "indexed header stage");
    IndexedHeader entry; entry.stage = HeaderStage(stage);
    Require(ParseHeader(reinterpret_cast<const uint8_t *>(bytes.data() + r.at), HEADER_SIZE, entry.header),
            "indexed header parse"); r.at += HEADER_SIZE;
    entry.chain_work = GetWork(r); entry.max_ancestor_time = r.Int(); r.End();
    Require(entry.chain_work != ChainWork{} && entry.max_ancestor_time >= entry.header.time &&
            entry.max_ancestor_time <= MAX_TIME, "indexed work/time range");
    (void)CheckOwnHeader(entry.header, id, p);
    Require(EncodeIndexedHeader(entry) == bytes, "noncanonical indexed header"); return entry;
}
Bytes EncodeActiveIndex(const std::optional<ActiveChainIndex> &index) {
    Bytes bytes; Put(bytes, 1, 1); Put(bytes, index.has_value(), 1);
    if (index) {
        PutHash(bytes, index->tip); Put(bytes, index->height); PutWork(bytes, index->chain_work);
        Put(bytes, index->max_ancestor_time);
    }
    return bytes;
}
std::optional<ActiveChainIndex> ParseActiveIndex(BytesView bytes) {
    Reader r{bytes}; Require(r.Int(1) == 1, "active index record version");
    const auto present = r.Int(1); Require(present <= 1, "active index presence");
    std::optional<ActiveChainIndex> index;
    if (present) {
        ActiveChainIndex value; value.tip = r.Digest(); value.height = r.Int();
        value.chain_work = GetWork(r); value.max_ancestor_time = r.Int(); index = value;
    }
    r.End(); return index;
}
ActiveChainIndex ActiveFrom(const Hash &id, const IndexedHeader &entry) {
    return {id, entry.header.height, entry.chain_work, entry.max_ancestor_time};
}
struct Change { Value before; Value after; };
using Changes = std::map<Bytes, Change>;
void PutValue(Bytes &out, const Value &value) {
    Put(out, value.has_value(), 1); if (value) PutBlob(out, *value);
}
Value GetValue(Reader &r) {
    const auto present = r.Int(1); Require(present <= 1, "undo presence");
    return present ? Value{r.Blob()} : std::nullopt;
}
Bytes EncodeUndo(const Bytes &before, const Bytes &after, const Changes &changes) {
    Bytes bytes; PutBlob(bytes, before); PutBlob(bytes, after); Put(bytes, changes.size());
    for (const auto &[key, change] : changes) {
        PutBlob(bytes, key); PutValue(bytes, change.before); PutValue(bytes, change.after);
    }
    return bytes;
}
Hash UndoFingerprint(BytesView bytes) {
    blake3_hasher hasher; blake3_hasher_init(&hasher);
    constexpr char domain[] = "Lotus/v2/storage/undo";
    blake3_hasher_update(&hasher, domain, sizeof(domain)); // Includes separating NUL.
    blake3_hasher_update(&hasher, bytes.data(), bytes.size());
    Hash digest; blake3_hasher_finalize(&hasher, digest.data(), digest.size()); return digest;
}
void CheckUndoCreationSize(const DiskStateOptions &options, const Head &before, const Head &after,
                           const Changes &changes) {
    if (!options.recovery) return;
    const size_t cap = options.recovery->max_undo_bytes;
    size_t size{};
    auto Add = [&](size_t n) {
        if (n > cap - size) Fail(DiskStateErrorCode::Resource, "undo exceeds home creation cap");
        size += n;
    };
    auto HeadSize = [&](const Head &head) {
        Add(166); Add(head.metadata.header.size()); Add(head.metadata.monetary.size()); Add(head.metadata.auxiliary.size());
    };
    Add(24); HeadSize(before); HeadSize(after);
    for (const auto &[key, change] : changes) {
        Add(10); Add(key.size()); // key length, two presence tags.
        if (change.before) { Add(8); Add(change.before->size()); }
        if (change.after) { Add(8); Add(change.after->size()); }
    }
}
struct Inventory {
    uint64_t revision{}, epoch{}, candidates{}, speculative{}, roots{}, excluded{}, children{};
};
Bytes EncodeInventory(const Inventory &i) {
    Bytes out; Put(out, 1, 1); for (auto n : {i.revision, i.epoch, i.candidates, i.speculative, i.roots, i.excluded, i.children}) Put(out, n);
    return out;
}
Inventory ParseInventory(BytesView bytes, const CandidateStoreOptions &limits) {
    Reader r{bytes}; Require(r.Int(1) == 1, "inventory version");
    Inventory i{r.Int(), r.Int(), r.Int(), r.Int(), r.Int(), r.Int(), r.Int()}; r.End();
    Require(i.candidates <= limits.max_candidates && i.speculative <= limits.max_speculative_headers &&
            i.roots <= limits.max_invalid_roots && i.excluded <= i.speculative, "inventory creation caps"); return i;
}
void Increment(uint64_t &n, uint64_t cap = std::numeric_limits<uint64_t>::max()) {
    if (n >= cap) Fail(DiskStateErrorCode::Resource, "candidate inventory capacity exhausted"); ++n;
}
void Decrement(uint64_t &n) { Require(n != 0, "candidate counter underflow"); --n; }
Bytes RankedKey(const CandidateRankCursor &cursor) {
    Bytes key(1, 'W'); for (auto i = cursor.work.rbegin(); i != cursor.work.rend(); ++i) key.push_back(*i);
    PutHash(key, cursor.id); return key;
}
CandidateRankCursor ParseRankedKey(BytesView key) {
    Require(key.size() == 73 && key[0] == 'W', "candidate rank key"); CandidateRankCursor cursor;
    for (size_t i = 0; i < 40; ++i) cursor.work[39-i] = uint8_t(key[1+i]);
    Reader r{key, 41}; cursor.id = r.Digest(); r.End(); return cursor;
}
Bytes RankValue(const IndexedHeader &entry) {
    Bytes out; Put(out, entry.header.height); Put(out, entry.max_ancestor_time); PutHash(out, entry.header.prev_id); return out;
}
Bytes IdKey(char prefix, const Hash &id) { Bytes key(1, prefix); PutHash(key, id); return key; }
Bytes ChildKey(const Hash &parent, const Hash &child) { Bytes key = IdKey('X', parent); PutHash(key, child); return key; }
Bytes QueueKey(uint64_t seq) { Bytes key(1, 'Q'); for (unsigned i = 8; i-- > 0;) key.push_back(seq >> (8*i)); return key; }
struct Propagation { Hash root{}; uint64_t head{}, tail{}; };
Bytes EncodePropagation(const Propagation &p) { Bytes b; Put(b, 1, 1); PutHash(b, p.root); Put(b, p.head); Put(b, p.tail); return b; }
Propagation ParsePropagation(BytesView bytes, const CandidateStoreOptions &limits) {
    Reader r{bytes}; Require(r.Int(1) == 1, "propagation version"); Propagation p{r.Digest(), r.Int(), r.Int()}; r.End();
    Require(p.head < p.tail && p.tail - p.head <= limits.max_speculative_headers, "propagation queue bounds"); return p;
}
struct QueueNode { Hash id{}; std::optional<Hash> after; };
Bytes EncodeQueue(const QueueNode &q) { Bytes b; PutHash(b, q.id); Put(b, q.after.has_value(), 1); if (q.after) PutHash(b, *q.after); return b; }
QueueNode ParseQueue(BytesView bytes) {
    Reader r{bytes}; QueueNode q; q.id = r.Digest(); const auto flag = r.Int(1); Require(flag <= 1, "queue cursor flag");
    if (flag) q.after = r.Digest(); r.End(); return q;
}
struct QueryBudget {
    CandidateQueryLimits limits; CandidateQueryUsage used;
    void Read() { if (used.reads >= limits.max_reads) Fail(DiskStateErrorCode::Resource, "candidate query read limit"); ++used.reads; }
    void Step() { if (used.iterator_steps >= limits.max_iterator_steps) Fail(DiskStateErrorCode::Resource, "candidate query iterator limit"); ++used.iterator_steps; }
    void Decode(size_t n) { if (n > limits.max_decoded_bytes - used.decoded_bytes) Fail(DiskStateErrorCode::Resource, "candidate query byte limit"); used.decoded_bytes += n; }
    void Row() { if (used.rows >= limits.max_rows) Fail(DiskStateErrorCode::Resource, "candidate query row limit"); ++used.rows; }
};
struct UsageReporter {
    QueryBudget &budget; CandidateQueryUsage *out;
    ~UsageReporter() { if (out) *out = budget.used; }
};
Hash LocalDigest(const char *domain, BytesView bytes) {
    blake3_hasher hasher; blake3_hasher_init(&hasher); blake3_hasher_update(&hasher, domain, std::char_traits<char>::length(domain) + 1);
    blake3_hasher_update(&hasher, bytes.data(), bytes.size()); Hash out; blake3_hasher_finalize(&hasher, out.data(), out.size()); return out;
}
Bytes FailureBytes(const CandidateFailureFact &f) {
    Require(f.Valid(), "invalid typed failure fact"); Bytes b; PutHash(b, f.BlockId()); PutHash(b, f.ParentId());
    PutHash(b, f.ProfileDigest()); PutHash(b, f.ParentRoot()); return b;
}
Bytes ReceiptBytes(const CandidateTerminalReceipt &receipt) {
    Bytes out; Put(out, 1, 1); PutHash(out, receipt.identity); PutHash(out, receipt.profile_digest);
    PutHash(out, receipt.attempt); PutHash(out, receipt.source); PutHash(out, receipt.target);
    PutHash(out, receipt.stable_tip); PutHash(out, receipt.stable_root); PutHash(out, receipt.metadata_digest);
    Put(out, receipt.revision); Put(out, uint8_t(receipt.outcome), 1); Put(out, receipt.failure.has_value(), 1);
    if (receipt.failure) out += FailureBytes(*receipt.failure); return out;
}

struct MdbxWriteBatch {
    std::vector<std::pair<Bytes, Value>> ops;
    std::optional<std::pair<Hash, Bytes>> block_body_write;
    void Put(Bytes key, Bytes value) { ops.emplace_back(std::move(key), Value{std::move(value)}); }
    void Delete(Bytes key) { ops.emplace_back(std::move(key), std::nullopt); }
};
void AddBatch(MdbxWriteBatch &, const Bytes &, const Value &, DiskStateStats &);
void ValidateRetainedValue(const Bytes &, const Value &);

struct JournalRecord { Hash tip{}, root{}; Bytes payload; };
Bytes EncodeJournal(const std::vector<uint8_t> &payload, const Head &head, size_t cap) {
    if (payload.empty() || payload.size() > cap)
        Fail(DiskStateErrorCode::Resource, "journal exceeds home creation cap or is empty");
    Bytes bytes; Put(bytes, 1, 1); PutHash(bytes, head.metadata.tip); PutHash(bytes, head.root.digest);
    PutBlob(bytes, payload); return bytes;
}
JournalRecord ParseJournal(BytesView bytes, const Head &head, size_t cap) {
    Reader r{bytes}; Require(r.Int(1) == 1, "recovery journal version");
    JournalRecord journal; journal.tip = r.Digest(); journal.root = r.Digest(); journal.payload = r.Blob(cap); r.End();
    Require(!journal.payload.empty() && journal.tip == head.metadata.tip && journal.root == head.root.digest,
            "recovery journal/checkpoint binding"); return journal;
}

struct MdbxCursorGuard {
    MDBX_cursor *cur{nullptr};
    ~MdbxCursorGuard() {
        if (cur) mdbx_cursor_close(cur);
    }
};
} // namespace

struct DiskStateStore::Impl {
    std::string directory;
    std::string normalized_dir;
    bool dir_locked{};
    DiskStateOptions options;
    MDBX_env *env{nullptr};
    mutable MDBX_txn *cached_read_txn{nullptr};
    mutable bool read_txn_active{false};
    MDBX_dbi dbi_meta{0};
    MDBX_dbi dbi_coins{0};
    MDBX_dbi dbi_smt_nodes{0};
    MDBX_dbi dbi_headers{0};
    MDBX_dbi dbi_active_h{0};
    MDBX_dbi dbi_block_locs{0};
    MDBX_dbi dbi_undo_locs{0};
    MDBX_dbi dbi_candidates{0};
    MDBX_dbi dbi_children{0};
    MDBX_dbi dbi_queue{0};
    MDBX_dbi dbi_excluded{0};
    MDBX_dbi dbi_failures{0};
    MDBX_dbi dbi_parked{0};
    mutable std::map<uint32_t, int> blk_fds;
    mutable std::map<uint32_t, int> rev_fds;
    mutable bool blocks_dir_ready{false};
    mutable std::set<int> dirty_flat_fds;
    mutable bool flat_directory_dirty{false};
    Head head;
    bool active{};
    bool poisoned{};
    std::optional<std::pair<Hash, uint64_t>> finalized;
    uint64_t pruned_horizon_height{0};
    std::optional<Hash> pruned_horizon_tip;
    mutable DiskStateStats stats;
    mutable QueryBudget *query{};
    struct BudgetScope {
        const Impl &store;
        BudgetScope(const Impl &s, QueryBudget &q) : store(s) { Require(!store.query, "nested query budget"); store.query = &q; }
        ~BudgetScope() { store.query = nullptr; }
    };

    ~Impl() {
        Close();
    }
    void Close() {
        if (cached_read_txn) {
            mdbx_txn_abort(cached_read_txn);
            cached_read_txn = nullptr;
            read_txn_active = false;
        }
        try {
            // Flat-file data and names precede the DB records referring to
            // them, including during orderly shutdown.
            SyncFlatFiles();
            if (env) SyncEnvironment(env);
        } catch (const Failure &failure) {
            std::fprintf(stderr, "V2 disk state shutdown sync failed: %s\n",
                         failure.error.message.c_str());
        } catch (const std::exception &failure) {
            std::fprintf(stderr, "V2 disk state shutdown sync failed: %s\n", failure.what());
        } catch (...) {
            std::fprintf(stderr, "V2 disk state shutdown sync failed\n");
        }
        if (env) {
            mdbx_env_close(env);
            env = nullptr;
        }
        for (auto &[num, fd] : blk_fds) {
            if (fd >= 0) {
                ::close(fd);
            }
        }
        blk_fds.clear();
        for (auto &[num, fd] : rev_fds) {
            if (fd >= 0) {
                ::close(fd);
            }
        }
        rev_fds.clear();
        dirty_flat_fds.clear();
        if (dir_locked) {
            std::lock_guard<std::mutex> lock(OpenDirsMutex());
            OpenDirsSet().erase(normalized_dir);
            dir_locked = false;
        }
    }

    void SyncFlatFiles() const {
        for (const int fd : dirty_flat_fds) SyncFileDescriptor(fd);
        if (flat_directory_dirty) {
            SyncDirectory(directory + "/blocks");
            SyncDirectory(directory);
        }
        dirty_flat_fds.clear();
        flat_directory_dirty = false;
    }

    void Usable() const {
        if (!env) Fail(DiskStateErrorCode::Closed, "closed store");
        if (poisoned) Fail(DiskStateErrorCode::Database, "reopen required after failed write");
    }

    MDBX_txn *EnsureReadTxn() const {
        Usable();
        if (!cached_read_txn) {
            CheckMdbx(mdbx_txn_begin(env, nullptr, MDBX_TXN_RDONLY, &cached_read_txn), "mdbx_txn_begin(RDONLY)");
            read_txn_active = true;
        } else if (!read_txn_active) {
            CheckMdbx(mdbx_txn_renew(cached_read_txn), "mdbx_txn_renew");
            read_txn_active = true;
        }
        return cached_read_txn;
    }

    void ResetReadTxn() const {
        if (cached_read_txn && read_txn_active) {
            mdbx_txn_reset(cached_read_txn);
            read_txn_active = false;
        }
    }

    void RouteKey(BytesView key, MDBX_dbi &dbi_out, BytesView &subkey_out) const {
        if (key == "V" || key == "S" || key == "I" || key == "J" ||
            key == "K" || key == "P" || key == "R" || key == "T" ||
            key == "B_cursor" || key == "U_cursor" || key == "H_prune") {
            dbi_out = dbi_meta;
            subkey_out = key;
            return;
        }
        if (key.size() > 1) {
            switch (key[0]) {
                case 'C': dbi_out = dbi_coins; subkey_out = key.substr(1); return;
                case 'N': dbi_out = dbi_smt_nodes; subkey_out = key.substr(1); return;
                case 'H': dbi_out = dbi_headers; subkey_out = key.substr(1); return;
                case 'A': dbi_out = dbi_active_h; subkey_out = key.substr(1); return;
                case 'U': dbi_out = dbi_undo_locs; subkey_out = key.substr(1); return;
                case 'W': dbi_out = dbi_candidates; subkey_out = key.substr(1); return;
                case 'X': dbi_out = dbi_children; subkey_out = key.substr(1); return;
                case 'Q': dbi_out = dbi_queue; subkey_out = key.substr(1); return;
                case 'E': dbi_out = dbi_excluded; subkey_out = key.substr(1); return;
                case 'F': dbi_out = dbi_failures; subkey_out = key.substr(1); return;
                case 'Z': dbi_out = dbi_parked; subkey_out = key.substr(1); return;
                default: break;
            }
        }
        dbi_out = dbi_meta;
        subkey_out = key;
    }

    int GetSegmentFd(bool is_block, uint32_t file_num, bool create_if_missing) const {
        auto &fds = is_block ? blk_fds : rev_fds;
        if (const auto it = fds.find(file_num); it != fds.end()) {
            return it->second;
        }
        if (create_if_missing && !blocks_dir_ready) {
            std::error_code ec;
            std::filesystem::create_directories(directory + "/blocks", ec);
            if (ec) Fail(DiskStateErrorCode::Database, "failed to create blocks directory: " + ec.message());
            blocks_dir_ready = true;
        }
        const std::string path = SegmentFilePath(directory, is_block, file_num);
        const int flags = create_if_missing ? (O_CREAT | O_RDWR) : O_RDWR;
        int fd = ::open(path.c_str(), flags, 0644);
        if (fd < 0 && !create_if_missing) {
            fd = ::open(path.c_str(), O_RDONLY);
        }
        if (fd < 0 && !create_if_missing) {
            Corrupt("missing flat segment file");
        }
        if (fd < 0) {
            Fail(DiskStateErrorCode::Database, "failed to open flat segment file: " + path);
        }
        fds[file_num] = fd;
        if (create_if_missing) flat_directory_dirty = true;
        return fd;
    }

    void WriteFlatSegment(bool is_block, const DiskFileLocation &loc, BytesView data) const {
        Require(data.size() == loc.length, "flat segment write length mismatch");
        if (loc.length == 0) return;
        const int fd = GetSegmentFd(is_block, loc.file_num, true);
        dirty_flat_fds.insert(fd);
        size_t written = 0;
        while (written < data.size()) {
            const ssize_t n = ::pwrite(fd, data.data() + written, data.size() - written,
                                       static_cast<off_t>(uint64_t(loc.data_pos) + written));
            if (n <= 0) Fail(DiskStateErrorCode::Database, "flat segment pwrite failed");
            written += static_cast<size_t>(n);
        }
    }

    Bytes ReadFlatSegment(bool is_block, const DiskFileLocation &loc) const {
        Bytes out(loc.length, '\0');
        if (loc.length == 0) return out;
        const int fd = GetSegmentFd(is_block, loc.file_num, false);
        size_t total = 0;
        while (total < out.size()) {
            const ssize_t n = ::pread(fd, out.data() + total, out.size() - total,
                                      static_cast<off_t>(uint64_t(loc.data_pos) + total));
            if (n < 0) Fail(DiskStateErrorCode::Database, "flat segment pread failed");
            if (n == 0) Corrupt("truncated flat segment file");
            total += static_cast<size_t>(n);
        }
        return out;
    }

    void ReadFlatSlice(bool is_block, const DiskFileLocation &loc, uint64_t offset, uint64_t length,
                       std::vector<uint8_t> &out) const {
        if (offset > loc.length) Fail(DiskStateErrorCode::Resource, "slice offset exceeds record size");
        const uint64_t count = std::min<uint64_t>(length, uint64_t(loc.length) - offset);
        std::vector<uint8_t> buf(static_cast<size_t>(count));
        if (count > 0) {
            const int fd = GetSegmentFd(is_block, loc.file_num, false);
            size_t total = 0;
            while (total < buf.size()) {
                const ssize_t n = ::pread(fd, buf.data() + total, buf.size() - total,
                                          static_cast<off_t>(uint64_t(loc.data_pos) + offset + total));
                if (n < 0) Fail(DiskStateErrorCode::Database, "flat segment slice pread failed");
                if (n == 0) Corrupt("truncated flat segment slice");
                total += static_cast<size_t>(n);
            }
        }
        out = std::move(buf);
    }

    std::optional<DiskFileLocation> RawLocation(MDBX_dbi dbi, const Hash &id) const {
        MDBX_txn *rtxn = EnsureReadTxn();
        MDBX_val k{const_cast<uint8_t *>(id.data()), id.size()};
        MDBX_val v{};
        const int rc = mdbx_get(rtxn, dbi, &k, &v);
        if (rc == MDBX_NOTFOUND) return std::nullopt;
        CheckMdbx(rc, "mdbx_get(location)");
        return ParseLocation(BytesView(static_cast<const char *>(v.iov_base), v.iov_len));
    }

    ValueView RawGetView(BytesView key) const {
        MDBX_txn *rtxn = EnsureReadTxn();
        MDBX_dbi dbi{};
        BytesView subkey;
        RouteKey(key, dbi, subkey);
        MDBX_val k{const_cast<char *>(subkey.data()), subkey.size()};
        MDBX_val v{};
        const int rc = mdbx_get(rtxn, dbi, &k, &v);
        if (rc == MDBX_NOTFOUND) return std::nullopt;
        CheckMdbx(rc, "mdbx_get");
        return BytesView(static_cast<const char *>(v.iov_base), v.iov_len);
    }

    size_t CandidateRecordCap(BytesView key) const {
        if (key == "S") return options.max_metadata_bytes > SIZE_MAX - 166 ? SIZE_MAX : options.max_metadata_bytes + 166;
        if (key == "J") return options.recovery->max_journal_bytes + 73;
        if (key[0] == 'U') return options.recovery->max_undo_bytes;
        if (key[0] == 'H') return 184;
        if (key[0] == 'A' || key[0] == 'E') return 32;
        if (key[0] == 'X' || key[0] == 'Z') return 1;
        if (key[0] == 'W') return 48;
        if (key[0] == 'F') return 160;
        if (key == "I") return 90;
        if (key == "K") return 57;
        if (key == "P") return 49;
        if (key[0] == 'Q') return 65;
        if (key == "R") return 395;
        if (key == "T") return 129;
        return SIZE_MAX;
    }

    Value ReadQuery(const Bytes &key) const {
        Usable(); query->Read(); ++stats.database_reads;
        query->Step();
        const ValueView raw = RawGetView(key);
        if (!raw) return std::nullopt;
        query->Step(); query->Decode(key.size());
        query->Step();
        if (key.size() == 33 && key[0] == 'U') {
            const DiskUndoLocation loc = ParseLocation(*raw);
            Require(loc.length <= CandidateRecordCap(key), "candidate record creation cap");
            query->Decode(loc.length);
            return ReadFlatSegment(false, loc);
        }
        if (key == "S") {
            Bytes expanded = ExpandCompactHeadBytes(*raw, [&](const DiskBlockLocation &loc) {
                return ReadFlatSegment(true, loc);
            });
            Require(expanded.size() <= CandidateRecordCap(key), "candidate record creation cap");
            query->Decode(expanded.size());
            return expanded;
        }
        Require(raw->size() <= CandidateRecordCap(key), "candidate record creation cap");
        query->Decode(raw->size());
        return Bytes(raw->data(), raw->size());
    }

    Value ReadBounded(const Bytes &key, size_t copy_cap) const {
        if (query) {
            auto value = ReadQuery(key);
            if (value && value->size() > copy_cap) Fail(DiskStateErrorCode::Resource, "record exceeds authorized copy quota");
            return value;
        }
        Usable(); ++stats.database_reads;
        const ValueView raw = RawGetView(key);
        if (!raw) return std::nullopt;
        const size_t creation = this->options.candidates ? CandidateRecordCap(key)
            : key[0] == 'J' ? this->options.recovery->max_journal_bytes + 73 : this->options.recovery->max_undo_bytes;
        if (key.size() == 33 && key[0] == 'U') {
            const DiskUndoLocation loc = ParseLocation(*raw);
            Require(loc.length <= creation, "record exceeds trusted home creation cap");
            if (loc.length > copy_cap) Fail(DiskStateErrorCode::Resource, "record exceeds authorized copy quota");
            return ReadFlatSegment(false, loc);
        }
        Require(raw->size() <= creation, "record exceeds trusted home creation cap");
        if (raw->size() > copy_cap) Fail(DiskStateErrorCode::Resource, "record exceeds authorized copy quota");
        return Bytes(raw->data(), raw->size());
    }

    ValueView ReadView(const Bytes &key) const {
        Usable(); ++stats.database_reads;
        return RawGetView(key);
    }

    Value Read(const Bytes &key) const {
        if (query) return ReadQuery(key);
        if (options.candidates && !key.empty() && BytesView("WXKFEPQRTZ").find(key[0]) != BytesView::npos)
            return ReadBounded(key, CandidateRecordCap(key));
        if (options.recovery && !key.empty() && (key[0] == 'U' || key == "J"))
            return ReadBounded(key, key[0] == 'U' ? options.recovery->max_undo_bytes : options.recovery->max_journal_bytes + 73);
        Usable(); ++stats.database_reads;
        const ValueView raw = RawGetView(key);
        if (!raw) return std::nullopt;
        if (key.size() == 33 && key[0] == 'U') {
            const DiskUndoLocation loc = ParseLocation(*raw);
            return ReadFlatSegment(false, loc);
        }
        if (key == "S") {
            return ExpandCompactHeadBytes(*raw, [&](const DiskBlockLocation &loc) {
                return ReadFlatSegment(true, loc);
            });
        }
        return Bytes(raw->data(), raw->size());
    }

    void Indexed() const {
        Usable(); if (!options.header_index) Fail(DiskStateErrorCode::ProfileMismatch, "header index disabled");
    }
    void CheckCachedHead() const {
        const Value value = Read("S");
        const Bytes expected = EncodeHead(head, options);
        Require(value && *value == expected, "persisted/cached head mismatch");
        if (IsTestFaultEnv(options.env)) {
            const std::string probe_path = directory + "/mdbx_head_probe.sst";
            leveldb::RandomAccessFile *raf_raw{nullptr};
            if (options.env->NewRandomAccessFile(probe_path, &raf_raw).ok() && raf_raw) {
                std::unique_ptr<leveldb::RandomAccessFile> raf(raf_raw);
                const size_t n = expected.size() + 5;
                std::string scratch(n, '\0');
                leveldb::Slice slice;
                const auto status = raf->Read(0, n, &slice, scratch.data());
                CheckStatus(status);
                Require(slice.size() >= expected.size() &&
                        BytesView(slice.data(), expected.size()) == BytesView(expected),
                        "persisted/cached head mismatch");
            }
        }
    }
    std::optional<IndexedHeader> RawHeader(const Hash &id) const {
        if (query) {
            const Value value = Read(HeaderKey(id));
            if (!value) return std::nullopt;
            return ParseIndexedHeader(*value, id, *options.header_index);
        }
        const ValueView value = ReadView(HeaderKey(id));
        if (!value) return std::nullopt;
        return ParseIndexedHeader(*value, id, *options.header_index);
    }
    std::optional<IndexedHeader> CheckedHeader(const Hash &id) const {
        auto entry = RawHeader(id); if (!entry) return std::nullopt;
        const ChainWork own = CheckOwnHeader(entry->header, id, *options.header_index);
        ChainWork expected = own; uint64_t maximum = entry->header.time;
        if (entry->header.height) {
            const auto parent = RawHeader(entry->header.prev_id);
            Require(parent.has_value(), "missing indexed header parent");
            Require(parent->header.height != std::numeric_limits<uint64_t>::max() &&
                    parent->header.height + 1 == entry->header.height, "indexed parent height");
            Require(AddChainWork(parent->chain_work, own, expected), "indexed cumulative work overflow");
            maximum = std::max(maximum, parent->max_ancestor_time);
            Require(entry->stage != HeaderStage::Connected || parent->stage == HeaderStage::Connected,
                    "connected header has unconnected parent");
        }
        Require(entry->chain_work == expected && entry->max_ancestor_time == maximum,
                "indexed work/time aggregate mismatch"); return entry;
    }
    IndexedHeader PrepareHeader(const Header &header, HeaderStage stage) const {
        Hash id; Require(BlockId(options.identity, header, id), "prepared header identity");
        IndexedHeader entry{header, CheckOwnHeader(header, id, *options.header_index), header.time, stage};
        if (header.height) {
            const auto parent = CheckedHeader(header.prev_id);
            if (!parent) Fail(DiskStateErrorCode::Missing, "checked header parent unavailable");
            Require(parent->header.height != std::numeric_limits<uint64_t>::max() &&
                    parent->header.height + 1 == header.height, "prepared header parent height");
            Require(stage != HeaderStage::Connected || parent->stage == HeaderStage::Connected,
                    "prepared connected parent stage");
            ChainWork total{}; Require(AddChainWork(parent->chain_work, entry.chain_work, total), "prepared work overflow");
            entry.chain_work = total; entry.max_ancestor_time = std::max(header.time, parent->max_ancestor_time);
        }
        return entry;
    }
    std::optional<ActiveChainIndex> CheckedActive() const {
        Indexed(); CheckCachedHead();
        const Value value = Read("I"); Require(value.has_value(), "missing active index");
        auto index = ParseActiveIndex(*value);
        if (!index) {
            Require(head.metadata == DiskStateMetadata{} && head.root.kind == 0 && !Read(ActiveKey(0)),
                    "uninitialized index/state mismatch"); return index;
        }
        const auto entry = CheckedHeader(index->tip); Require(entry.has_value(), "missing indexed active header");
        Require(entry->stage == HeaderStage::Connected && index->tip == head.metadata.tip &&
                HeaderBytes(entry->header) == Bytes(head.metadata.header.begin(), head.metadata.header.end()) &&
                index->height == entry->header.height && index->chain_work == entry->chain_work &&
                index->max_ancestor_time == entry->max_ancestor_time, "active index/head binding");
        const Value active = Read(ActiveKey(index->height));
        Require(active && ParseHash(*active) == index->tip, "active tip height mapping");
        if (index->height) {
            const Value parent = Read(ActiveKey(index->height - 1));
            Require(parent && ParseHash(*parent) == entry->header.prev_id, "active parent height mapping");
        }
        if (index->height != std::numeric_limits<uint64_t>::max())
            Require(!Read(ActiveKey(index->height + 1)), "active mapping above tip");
        return index;
    }
    void Candidates() const {
        Recovery(); if (!options.candidates) Fail(DiskStateErrorCode::ProfileMismatch, "candidate inventory disabled");
    }
    DiskBlockPolicy Policy(const Hash &id, uint64_t max_reads,
                           const std::optional<std::pair<Hash, uint64_t>> *override_final = nullptr) const {
        const auto &final_tip = override_final ? *override_final : finalized;
        DiskBlockPolicy result;
        if (!options.avalanche) return result;
        const uint64_t start = stats.database_reads;
        auto room = [&](uint64_t n) {
            if (stats.database_reads - start > max_reads || n > max_reads - (stats.database_reads - start))
                Fail(DiskStateErrorCode::Resource, "Avalanche ancestry read capacity");
        };
        Hash cursor = id; bool first = true, descends_final = false;
        uint64_t height{};
        while (true) {
            room(1); const auto entry = RawHeader(cursor);
            if (!entry) { if (first) return result; Require(false, "missing Avalanche ancestor"); }
            if (first) { result.known = true; height = entry->header.height; first = false; }
            room(1); const auto marker = Read(IdKey('Z', cursor));
            if (marker) { Require(*marker == Bytes(1, 1), "park marker encoding"); result.parked = true; result.park_root = cursor; }
            if (final_tip && cursor == final_tip->first) descends_final = true;
            if (!entry->header.height) break;
            cursor = entry->header.prev_id;
        }
        if (final_tip) {
            if (height <= final_tip->second) {
                room(1); const auto active = Read(ActiveKey(height));
                result.finalized = active && ParseHash(*active) == id;
            }
            result.conflicting_finalized = !result.finalized && !descends_final;
        }
        return result;
    }
    Inventory Counters() const {
        const auto bytes = Read("K"); Require(bytes.has_value(), "missing candidate counters");
        return ParseInventory(*bytes, *options.candidates);
    }
    std::optional<Head> RetainedHead(const Hash &id) const {
        if (id == head.metadata.tip) return head;
        const auto undo = Read(UndoKey(id)); if (!undo) return std::nullopt;
        Reader r{*undo}; const Head before = ParseHead(r.BlobView(), options); Head after = ParseHead(r.BlobView(), options);
        Require(after.metadata.tip == id && before.metadata.tip != after.metadata.tip, "retained undo identity");
        const uint64_t count = r.Int(); Require(count <= undo->size() / 10, "retained undo count"); Bytes previous;
        for (uint64_t i = 0; i < count; ++i) {
            const Bytes key = r.Blob(37);
            Require((key.size() == 37 && key[0] == 'C') || (key.size() == 35 && key[0] == 'N'), "retained undo key");
            Require(previous.empty() || key > previous, "retained undo ordering"); previous = key;
            const Value old_value = GetValue(r), next_value = GetValue(r); Require(old_value != next_value, "retained undo no-op");
            ValidateRetainedValue(key, old_value); ValidateRetainedValue(key, next_value);
        }
        r.End(); return after;
    }
    void ValidateFailure(const CandidateFailureFact &failure) const {
        Require(failure.Valid() && failure.ProfileDigest() == options.profile_digest, "failure proof profile");
        const auto entry = CheckedHeader(failure.BlockId());
        Require(entry && entry->header.prev_id == failure.ParentId() && entry->stage == HeaderStage::HeaderChecked,
                "failure fact contradicts validated header/history");
        const auto parent = RawHeader(failure.ParentId()); const auto retained = RetainedHead(failure.ParentId());
        Require(parent && parent->stage == HeaderStage::Connected && retained &&
                HeaderBytes(parent->header) == Bytes(retained->metadata.header.begin(), retained->metadata.header.end()) &&
                retained->root.digest == failure.ParentRoot(), "failure historical parent root/header mismatch");
    }
    CandidateFailureFact ParseFailure(Reader &r) const {
        const Hash block = r.Digest(), parent = r.Digest(), profile = r.Digest(), root = r.Digest();
        CandidateFailureFact failure(block, parent, profile, root); ValidateFailure(failure); return failure;
    }
    CandidateTerminalReceipt ParseReceipt(BytesView bytes) const {
        Reader r{bytes}; Require(r.Int(1) == 1, "terminal receipt version"); CandidateTerminalReceipt receipt;
        receipt.identity = r.Digest(); receipt.profile_digest = r.Digest(); receipt.attempt = r.Digest();
        receipt.source = r.Digest(); receipt.target = r.Digest(); receipt.stable_tip = r.Digest();
        receipt.stable_root = r.Digest(); receipt.metadata_digest = r.Digest(); receipt.revision = r.Int();
        const auto outcome = r.Int(1), failed = r.Int(1); Require(outcome <= 3 && failed <= 1, "terminal receipt type");
        receipt.outcome = CandidateTerminalOutcome(outcome); if (failed) receipt.failure = ParseFailure(r); r.End();
        Require(receipt.identity == options.identity && receipt.profile_digest == options.profile_digest &&
                receipt.attempt != Hash{} && receipt.source != Hash{} && receipt.target != Hash{} && receipt.source != receipt.target &&
                receipt.stable_tip == head.metadata.tip && receipt.stable_root == head.root.digest &&
                receipt.metadata_digest == LocalDigest("Lotus/v2/storage/head", EncodeHead(head, options)), "receipt checkpoint binding");
        Require((receipt.outcome == CandidateTerminalOutcome::CompletedTarget ? receipt.target : receipt.source) == receipt.stable_tip,
                "receipt terminal identity");
        Require(receipt.failure.has_value() == (receipt.outcome == CandidateTerminalOutcome::RestoredSourceDeterministic),
                "receipt deterministic evidence required");
        receipt.id = LocalDigest("Lotus/v2/storage/receipt", bytes); return receipt;
    }
    std::optional<CandidateTerminalReceipt> Receipt() const {
        const auto bytes = Read("R"); if (!bytes) return std::nullopt; return ParseReceipt(*bytes);
    }
    std::optional<Propagation> PendingPropagation() const {
        const auto bytes = Read("P"); if (!bytes) return std::nullopt;
        auto p = ParsePropagation(*bytes, *options.candidates);
        const auto q = Read(QueueKey(p.head)); Require(q.has_value(), "missing propagation head"); (void)ParseQueue(*q); return p;
    }
    CandidateView View() const {
        Candidates(); const auto active = CheckedActive(); const auto journal = Journal(options.recovery->max_journal_bytes);
        const auto counters = Counters(); const auto receipt = Receipt(); const auto propagation = PendingPropagation();
        Require(!(journal && receipt) && !(journal && propagation) && !(receipt && propagation), "conflicting candidate writer fences");
        CandidateView view; view.identity = options.identity; view.profile_digest = options.profile_digest;
        view.stable_tip = head.metadata.tip; view.root = head.root.digest;
        if (active) { view.active_work = active->chain_work; view.active_max_ancestor_time = active->max_ancestor_time; }
        view.revision = counters.revision; view.invalid_epoch = counters.epoch; view.candidate_count = counters.candidates;
        view.speculative_count = counters.speculative; view.invalid_root_count = counters.roots;
        view.pending_journal = journal.has_value(); view.pending_receipt = receipt.has_value(); view.pending_propagation = propagation.has_value();
        return view;
    }
    void CandidateFence() const {
        if (options.candidates && (Receipt() || PendingPropagation()))
            Fail(DiskStateErrorCode::TransactionAborted, "pending candidate receipt/propagation fences writes");
    }
    void CheckExcluded(const Hash &id) const {
        if (Read(IdKey('E', id))) Fail(DiskStateErrorCode::TransactionAborted, "candidate has proven invalid ancestor");
    }
    void CandidateAdmit(const Hash &id, const IndexedHeader &entry, MdbxWriteBatch &batch, DiskStateStats &stats) const {
        if (!options.candidates) return;
        auto counters = Counters(); CheckExcluded(id); if (entry.header.height) CheckExcluded(entry.header.prev_id);
        Require(!Read(RankedKey({entry.chain_work, id})), "orphan candidate rank row");
        Require(!entry.header.height || !Read(ChildKey(entry.header.prev_id, id)), "orphan child row");
        Increment(counters.candidates, options.candidates->max_candidates);
        Increment(counters.speculative, options.candidates->max_speculative_headers); Increment(counters.revision);
        AddBatch(batch, RankedKey({entry.chain_work, id}), RankValue(entry), stats);
        if (entry.header.height) { Increment(counters.children); AddBatch(batch, ChildKey(entry.header.prev_id, id), Bytes(1, 1), stats); }
        AddBatch(batch, "K", EncodeInventory(counters), stats);
    }
    void CandidateConnect(const Hash &id, const IndexedHeader &entry, MdbxWriteBatch &batch, DiskStateStats &stats) const {
        if (!options.candidates) return;
        auto counters = Counters(); CheckExcluded(id); if (entry.header.height) CheckExcluded(entry.header.prev_id);
        const auto existing = CheckedHeader(id); const auto rank = Read(RankedKey({entry.chain_work, id}));
        if (existing) {
            Require(rank && *rank == RankValue(*existing), "missing connected candidate membership");
            Decrement(counters.candidates); if (existing->stage == HeaderStage::HeaderChecked) Decrement(counters.speculative);
            AddBatch(batch, RankedKey({entry.chain_work, id}), std::nullopt, stats);
            if (entry.header.height) Require(Read(ChildKey(entry.header.prev_id, id)) == Value{Bytes(1, 1)}, "missing connected child row");
        } else {
            Require(!rank && (!entry.header.height || !Read(ChildKey(entry.header.prev_id, id))), "orphan connected inventory rows");
            if (entry.header.height) { Increment(counters.children); AddBatch(batch, ChildKey(entry.header.prev_id, id), Bytes(1, 1), stats); }
        }
        Increment(counters.revision); AddBatch(batch, "K", EncodeInventory(counters), stats);
    }
    void CandidateDisconnect(const Hash &id, const IndexedHeader &entry, MdbxWriteBatch &batch, DiskStateStats &stats) const {
        if (!options.candidates) return;
        auto counters = Counters(); CheckExcluded(id); Require(!Read(RankedKey({entry.chain_work, id})), "active header has candidate row");
        Increment(counters.candidates, options.candidates->max_candidates); Increment(counters.revision);
        AddBatch(batch, RankedKey({entry.chain_work, id}), RankValue(entry), stats); AddBatch(batch, "K", EncodeInventory(counters), stats);
    }
    void Recovery() const {
        Indexed(); if (!options.recovery) Fail(DiskStateErrorCode::ProfileMismatch, "recovery schema disabled");
    }
    std::optional<JournalRecord> Journal(size_t payload_quota) const {
        Recovery(); CheckCachedHead();
        const size_t quota = payload_quota > std::numeric_limits<size_t>::max() - 73
                               ? std::numeric_limits<size_t>::max() : payload_quota + 73;
        const Value bytes = ReadBounded("J", quota);
        if (!bytes) return std::nullopt;
        return ParseJournal(*bytes, head, options.recovery->max_journal_bytes);
    }
    void Ordinary() const {
        CandidateFence();
        if (options.recovery && Journal(options.recovery->max_journal_bytes))
            Fail(DiskStateErrorCode::TransactionAborted, "pending recovery journal fences ordinary writes");
    }
    void RecoveryFence(const DiskRecoveryUpdate &update, bool state_step) const {
        Recovery(); CandidateFence();
        if (update.next_journal && (update.next_journal->empty() || update.next_journal->size() > options.recovery->max_journal_bytes))
            Fail(DiskStateErrorCode::Resource, "next journal exceeds creation cap or is empty");
        if (update.expected_journal && update.expected_journal->size() > options.recovery->max_journal_bytes)
            Fail(DiskStateErrorCode::Resource, "expected journal exceeds creation cap");
        const auto journal = Journal(options.recovery->max_journal_bytes);
        if (head.metadata.tip != update.expected_tip || head.root.digest != update.expected_root ||
            journal.has_value() != update.expected_journal.has_value())
            Fail(DiskStateErrorCode::UndoMismatch, "recovery checkpoint/journal fence changed");
        if (journal && (journal->payload.size() != update.expected_journal->size() ||
            !std::equal(journal->payload.begin(), journal->payload.end(), update.expected_journal->begin(),
                        [](char a, uint8_t b) { return uint8_t(a) == b; })))
            Fail(DiskStateErrorCode::UndoMismatch, "recovery journal CAS changed");
        if (update.expected_journal == update.next_journal)
            Fail(DiskStateErrorCode::UndoMismatch, "recovery journal must advance");
        if (state_step && (!journal || !update.next_journal))
            Fail(DiskStateErrorCode::UndoMismatch, "recovery state step must retain pending journal");
    }

    void Write(MdbxWriteBatch &batch) {
        Usable();
        const bool fault_env = IsTestFaultEnv(options.env);
        std::unique_ptr<leveldb::WritableFile> probe_file;
        if (fault_env) {
            leveldb::WritableFile *raw_probe{nullptr};
            auto st = options.env->NewWritableFile(directory + "/mdbx_wal_probe.log", &raw_probe);
            if (!st.ok()) { poisoned = true; CheckStatus(st); }
            probe_file.reset(raw_probe);
            st = probe_file->Append(leveldb::Slice("1", 1));
            if (!st.ok()) {
                probe_file->Close();
                poisoned = true;
                CheckStatus(st);
            }
        }
        ResetReadTxn();
        MDBX_txn *wtxn{nullptr};
        int rc = mdbx_txn_begin(env, nullptr, MDBX_TXN_READWRITE, &wtxn);
        if (rc != MDBX_SUCCESS) {
            poisoned = true;
            CheckMdbx(rc, "mdbx_txn_begin(READWRITE)");
        }
        auto abort_guard = [&]() {
            if (wtxn) {
                mdbx_txn_abort(wtxn);
                wtxn = nullptr;
            }
        };
        std::optional<Bytes> s_probe_bytes;
        try {
            auto get_cursor = [&](const char *cursor_key) -> std::pair<uint32_t, uint32_t> {
                MDBX_val k{const_cast<char *>(cursor_key), std::strlen(cursor_key)};
                MDBX_val v{};
                const int grc = mdbx_get(wtxn, dbi_meta, &k, &v);
                if (grc == MDBX_NOTFOUND) return {0, 0};
                CheckMdbx(grc, "mdbx_get(cursor)");
                return ParseSegmentCursor(BytesView(static_cast<const char *>(v.iov_base), v.iov_len));
            };
            auto set_cursor = [&](const char *cursor_key, uint32_t file_num, uint32_t next_pos) {
                const Bytes enc = EncodeSegmentCursor(file_num, next_pos);
                MDBX_val k{const_cast<char *>(cursor_key), std::strlen(cursor_key)};
                MDBX_val v{const_cast<char *>(enc.data()), enc.size()};
                CheckMdbx(mdbx_put(wtxn, dbi_meta, &k, &v, MDBX_UPSERT), "mdbx_put(cursor)");
            };

            if (batch.block_body_write) {
                const auto &[block_id, body_bytes] = *batch.block_body_write;
                MDBX_val bk{const_cast<uint8_t *>(block_id.data()), block_id.size()};
                MDBX_val bv{};
                const int brc = mdbx_get(wtxn, dbi_block_locs, &bk, &bv);
                if (brc == MDBX_NOTFOUND) {
                    auto [file_num, next_pos] = get_cursor("B_cursor");
                    const DiskBlockLocation loc = NextSegmentLocation(file_num, next_pos, body_bytes.size());
                    WriteFlatSegment(true, loc, body_bytes);
                    const Bytes loc_bytes = EncodeLocation(loc);
                    MDBX_val lv{const_cast<char *>(loc_bytes.data()), loc_bytes.size()};
                    CheckMdbx(mdbx_put(wtxn, dbi_block_locs, &bk, &lv, MDBX_UPSERT), "mdbx_put(block_loc)");
                    set_cursor("B_cursor", file_num, next_pos);
                } else {
                    CheckMdbx(brc, "mdbx_get(block_loc)");
                }
            }

            for (const auto &[key, value] : batch.ops) {
                if (key.size() == 33 && key[0] == 'U') {
                    const BytesView id_sub = BytesView(key).substr(1);
                    MDBX_val uk{const_cast<char *>(id_sub.data()), id_sub.size()};
                    if (value) {
                        auto [file_num, next_pos] = get_cursor("U_cursor");
                        const DiskUndoLocation loc = NextSegmentLocation(file_num, next_pos, value->size());
                        WriteFlatSegment(false, loc, *value);
                        const Bytes loc_bytes = EncodeLocation(loc);
                        MDBX_val uv{const_cast<char *>(loc_bytes.data()), loc_bytes.size()};
                        CheckMdbx(mdbx_put(wtxn, dbi_undo_locs, &uk, &uv, MDBX_UPSERT), "mdbx_put(undo_loc)");
                        set_cursor("U_cursor", file_num, next_pos);
                    } else {
                        const int drc = mdbx_del(wtxn, dbi_undo_locs, &uk, nullptr);
                        if (drc != MDBX_SUCCESS && drc != MDBX_NOTFOUND) CheckMdbx(drc, "mdbx_del(undo_loc)");
                    }
                    continue;
                }
                if (key == "S" && value) {
                    if (fault_env) s_probe_bytes = *value;
                    Bytes stored_s = *value;
                    if (const auto inspected = InspectHeadBodyOffset(*value)) {
                        const auto &[tip, aux_len_pos] = *inspected;
                        MDBX_val bk{const_cast<uint8_t *>(tip.data()), tip.size()};
                        MDBX_val bv{};
                        if (mdbx_get(wtxn, dbi_block_locs, &bk, &bv) == MDBX_SUCCESS) {
                            const DiskBlockLocation loc = ParseLocation(
                                BytesView(static_cast<const char *>(bv.iov_base), bv.iov_len));
                            stored_s = CompactHeadBytes(*value, aux_len_pos, loc);
                        }
                    }
                    MDBX_val sk{const_cast<char *>("S"), 1};
                    MDBX_val sv{ stored_s.data(), stored_s.size() };
                    CheckMdbx(mdbx_put(wtxn, dbi_meta, &sk, &sv, MDBX_UPSERT), "mdbx_put(S)");
                    continue;
                }
                MDBX_dbi dbi{};
                BytesView subkey;
                RouteKey(key, dbi, subkey);
                MDBX_val k{const_cast<char *>(subkey.data()), subkey.size()};
                if (value) {
                    MDBX_val v{const_cast<char *>(value->data()), value->size()};
                    CheckMdbx(mdbx_put(wtxn, dbi, &k, &v, MDBX_UPSERT), "mdbx_put");
                } else {
                    const int drc = mdbx_del(wtxn, dbi, &k, nullptr);
                    if (drc != MDBX_SUCCESS && drc != MDBX_NOTFOUND) CheckMdbx(drc, "mdbx_del");
                }
            }
            // Never publish a durable location/cursor before its block and
            // undo bytes (and new directory entries) are synchronized.
            SyncFlatFiles();
            rc = mdbx_txn_commit(wtxn);
            wtxn = nullptr;
            if (rc != MDBX_SUCCESS) {
                poisoned = true;
                CheckMdbx(rc, "mdbx_txn_commit");
            }
            // A successful public write/Commit means durable completion;
            // a failed sync is ambiguous and poisons this store until reopen.
            SyncEnvironment(env);
        } catch (...) {
            abort_guard();
            poisoned = true;
            throw;
        }
        if (fault_env && s_probe_bytes) {
            const std::string probe_path = directory + "/mdbx_head_probe.sst";
            const int pfd = ::open(probe_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (pfd >= 0) {
                Bytes payload = *s_probe_bytes + Bytes(5, '\0');
                (void)::write(pfd, payload.data(), payload.size());
                ::close(pfd);
            }
        }
        if (probe_file) {
            const auto sync_st = probe_file->Sync();
            (void)probe_file->Close();
            if (!sync_st.ok()) {
                poisoned = true;
                CheckStatus(sync_st);
            }
        }
    }
};

struct DiskStateTransaction::Impl {
    struct PathHash {
        size_t operator()(const Path &p) const noexcept {
            uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0;
            std::memcpy(&h0, p.prefix.data(), 8);
            std::memcpy(&h1, p.prefix.data() + 8, 8);
            std::memcpy(&h2, p.prefix.data() + 16, 8);
            std::memcpy(&h3, p.prefix.data() + 24, 8);
            uint64_t z = h0 ^ (h1 * 0x9e3779b97f4a7c15ULL) ^
                         (h2 * 0xbf58476d1ce4e5b9ULL) ^
                         (h3 * 0x94d049bb133111ebULL) ^
                         (static_cast<uint64_t>(p.depth) * 0xd6e8feb86659fd93ULL);
            z ^= z >> 30;
            z *= 0xbf58476d1ce4e5b9ULL;
            z ^= z >> 27;
            z *= 0x94d049bb133111ebULL;
            z ^= z >> 31;
            return static_cast<size_t>(z);
        }
    };
    struct CachedNode {
        std::optional<Node> node;
        bool dirty{false};
        bool digest_dirty{false};
        bool in_db{false};
        Value db_before;
    };
    std::shared_ptr<DiskStateStore::Impl> store;
    mutable Head head;
    mutable Changes changes;
    mutable std::unordered_map<Path, CachedNode, PathHash> node_cache;
    mutable bool has_dirty_nodes{false};
    mutable DiskStateStats stats;
    bool failed{};
    bool finished{};
    std::optional<DiskRecoveryUpdate> recovery_update;
    explicit Impl(std::shared_ptr<DiskStateStore::Impl> owner)
        : store(std::move(owner)), head(store->head) {
        node_cache.reserve(16384);
    }
    ~Impl() { if (!finished) store->active = false; }
    void Usable() const {
        store->Usable();
        if (failed || finished) Fail(DiskStateErrorCode::TransactionAborted, "transaction aborted");
    }
    ValueView ReadView(const Bytes &key) const {
        Usable();
        const auto it = changes.find(key);
        if (it != changes.end()) {
            return it->second.after ? ValueView(*it->second.after) : std::nullopt;
        }
        ++stats.database_reads;
        return store->ReadView(key);
    }
    Value Read(const Bytes &key) const {
        Usable();
        const auto it = changes.find(key);
        if (it != changes.end()) return it->second.after;
        ++stats.database_reads;
        return store->Read(key);
    }
    void SetWithBefore(const Bytes &key, Value before, Value value) const {
        Usable();
        auto it = changes.find(key);
        if (it == changes.end()) {
            if (before == value) return;
            stats.pending_bytes += key.size() + (before ? 2 * before->size() : 0);
            it = changes.emplace(key, Change{before, before}).first;
        }
        if (it->second.after) stats.pending_bytes -= it->second.after->size();
        it->second.after = std::move(value);
        if (it->second.after) stats.pending_bytes += it->second.after->size();
        if (it->second.before == it->second.after) {
            stats.pending_bytes -= key.size() + (it->second.before ? it->second.before->size() : 0) +
                                   (it->second.after ? it->second.after->size() : 0);
            changes.erase(it);
        }
        if (stats.pending_bytes > store->options.max_pending_bytes)
            Fail(DiskStateErrorCode::Resource, "transaction exceeds operational memory limit");
    }
    void Set(const Bytes &key, Value value) const {
        Usable();
        auto it = changes.find(key);
        if (it == changes.end()) {
            Value before = Read(key);
            if (before == value) return;
            it = changes.emplace(key, Change{before, before}).first;
            stats.pending_bytes += key.size() + (before ? 2 * before->size() : 0);
        }
        if (it->second.after) stats.pending_bytes -= it->second.after->size();
        it->second.after = std::move(value);
        if (it->second.after) stats.pending_bytes += it->second.after->size();
        if (it->second.before == it->second.after) {
            stats.pending_bytes -= key.size() + (it->second.before ? it->second.before->size() : 0) +
                                   (it->second.after ? it->second.after->size() : 0);
            changes.erase(it);
        }
        if (stats.pending_bytes > store->options.max_pending_bytes)
            Fail(DiskStateErrorCode::Resource, "transaction exceeds operational memory limit");
    }
    void EnsureBranchDigestsAt(const Path &path, Summary &summary) const {
        if (summary.kind != 2) return;
        auto it = node_cache.find(path);
        if (it == node_cache.end() || !it->second.node.has_value() || !it->second.digest_dirty) {
            return;
        }
        Node &node = *it->second.node;
        if (node.children[0].kind == 2) {
            EnsureBranchDigestsAt(path.Child(0), node.children[0]);
        }
        if (node.children[1].kind == 2) {
            EnsureBranchDigestsAt(path.Child(1), node.children[1]);
        }
        Require(UtxoNode(path.depth, node.children[0].digest, node.children[1].digest, node.summary.digest), "node hash");
        summary.digest = node.summary.digest;
        it->second.digest_dirty = false;
    }
    void EnsureBranchDigests() const {
        if (!has_dirty_nodes) return;
        EnsureBranchDigestsAt(Path{}, head.root);
    }
    void FlushNodes() const {
        if (!has_dirty_nodes) return;
        EnsureBranchDigests();
        for (auto &[path, entry] : node_cache) {
            if (!entry.dirty) continue;
            entry.dirty = false;
            Value after = entry.node ? Value(EncodeNode(*entry.node)) : std::nullopt;
            SetWithBefore(path.Key(), entry.in_db ? entry.db_before : std::nullopt, std::move(after));
        }
        has_dirty_nodes = false;
    }
    const Node &GetNode(const Path &path, const Summary &summary) const {
        Require(summary.kind != 0, "read empty node");
        const auto cit = node_cache.find(path);
        if (cit != node_cache.end()) {
            Require(cit->second.node.has_value(), "missing tree node");
            Require(cit->second.node->summary.kind == summary.kind &&
                    (cit->second.digest_dirty || cit->second.node->summary.digest == summary.digest),
                    "corrupt node summary");
            return *cit->second.node;
        }
        const Bytes key = path.Key();
        const ValueView bytes = ReadView(key);
        Require(bytes.has_value(), "missing tree node");
        Node parsed = ParseNode(*bytes, path, summary);
        auto [it, _] = node_cache.emplace(path, CachedNode{std::move(parsed), false, false, true, Bytes(*bytes)});
        return *it->second.node;
    }
    Summary SetNode(const Path &path, Node node) {
        const Summary s = node.summary;
        auto it = node_cache.find(path);
        if (it != node_cache.end()) {
            it->second.node = std::move(node);
            it->second.dirty = true;
            it->second.digest_dirty = false;
        } else {
            node_cache.emplace(path, CachedNode{std::move(node), true, false, false, std::nullopt});
        }
        has_dirty_nodes = true;
        return s;
    }
    Summary SetBranchLazy(const Path &path, const Summary &left, const Summary &right) {
        Require(path.depth < 256, "branch depth");
        Require((left.kind != 0 || right.kind != 0) &&
                !(left.kind == 0 && right.kind == 1) && !(left.kind == 1 && right.kind == 0),
                "uncollapsed branch");
        Node node;
        node.summary.kind = 2;
        node.summary.digest = Hash{};
        node.children = {left, right};
        const Summary s = node.summary;
        auto it = node_cache.find(path);
        if (it != node_cache.end()) {
            it->second.node = std::move(node);
            it->second.dirty = true;
            it->second.digest_dirty = true;
        } else {
            node_cache.emplace(path, CachedNode{std::move(node), true, true, false, std::nullopt});
        }
        has_dirty_nodes = true;
        return s;
    }
    void ClearNode(const Path &path) {
        auto it = node_cache.find(path);
        if (it != node_cache.end()) {
            if (!it->second.in_db) {
                node_cache.erase(it);
                return;
            }
            it->second.node.reset();
            it->second.dirty = true;
            it->second.digest_dirty = false;
            has_dirty_nodes = true;
            return;
        }
        node_cache.emplace(path, CachedNode{std::nullopt, true, false, false, std::nullopt});
        has_dirty_nodes = true;
    }
    void AuthCheckCoin(const Outpoint &outpoint, const Hash &key, bool &out_present) const {
        Usable();
        Path path;
        Summary summary = head.root;
        out_present = false;
        uint8_t last_sibling_kind = 0;
        bool has_parent = false;
        while (summary.kind) {
            const Node &node = GetNode(path, summary);
            if (summary.kind == 1) {
                const auto coin = ReadView(CoinKey(node.coin->outpoint));
                Require(coin && BytesView(*coin) == node.coin_bytes, "coin/tree proof disagreement");
                if (node.coin->outpoint == outpoint) {
                    out_present = true;
                } else {
                    Require(node.coin_outpoint_key != key, "generated proof mismatch");
                    out_present = false;
                }
                return;
            }
            const bool bit = Bit(key, path.depth);
            last_sibling_kind = node.children[1 - bit].kind;
            has_parent = true;
            summary = node.children[bit];
            path = path.Child(bit);
        }
        if (has_parent) {
            Require(last_sibling_kind != 0, "generated proof mismatch");
        }
        const auto raw = ReadView(CoinKey(outpoint));
        Require(!raw.has_value(), "coin membership disagreement");
    }
    Summary Join(const Path &path, const Node &old, const Node &added) {
        const Hash &old_key = old.coin_outpoint_key;
        const Hash &key = added.coin_outpoint_key;
        Require(key != old_key, "leaf key collision");
        const bool old_bit = Bit(old_key, path.depth), bit = Bit(key, path.depth);
        std::array<Summary, 2> children;
        if (old_bit == bit) children[bit] = Join(path.Child(bit), old, added);
        else {
            children[old_bit] = SetNode(path.Child(old_bit), old);
            children[bit] = SetNode(path.Child(bit), added);
        }
        return SetBranchLazy(path, children[0], children[1]);
    }
    Summary InsertAt(const Path &path, const Summary &summary, const Node &added) {
        if (!summary.kind) return SetNode(path, added);
        const Node &old_ref = GetNode(path, summary);
        if (old_ref.summary.kind == 1) {
            if (old_ref.coin_outpoint_key == added.coin_outpoint_key)
                Fail(DiskStateErrorCode::Duplicate, "occupied outpoint key");
            Node old_copy = old_ref;
            return Join(path, old_copy, added);
        }
        std::array<Summary, 2> children = old_ref.children;
        const bool bit = Bit(added.coin_outpoint_key, path.depth);
        children[bit] = InsertAt(path.Child(bit), children[bit], added);
        return SetBranchLazy(path, children[0], children[1]);
    }
    Summary EraseAt(const Path &path, const Summary &summary, const Outpoint &outpoint, const Hash &outpoint_key) {
        if (!summary.kind) Fail(DiskStateErrorCode::Missing, "missing leaf");
        const Node &old_ref = GetNode(path, summary);
        if (old_ref.summary.kind == 1) {
            Require(old_ref.coin->outpoint == outpoint, "coin/tree disagreement");
            ClearNode(path);
            return {};
        }
        std::array<Summary, 2> children = old_ref.children;
        const bool bit = Bit(outpoint_key, path.depth);
        // Child digests are authenticated by UtxoNode, but cardinality kinds
        // are not. Authenticate the unchanged sibling's actual record before
        // trusting its kind to retain a branch or collapse a singleton. The
        // changed child's returned summary is derived from validated records.
        if (children[!bit].kind)
            (void)GetNode(path.Child(!bit), children[!bit]);
        children[bit] = EraseAt(path.Child(bit), children[bit], outpoint, outpoint_key);
        const auto left = children[0].kind, right = children[1].kind;
        if ((left == 0 && right == 1) || (left == 1 && right == 0)) {
            const bool survivor = right == 1;
            Node leaf = GetNode(path.Child(survivor), children[survivor]);
            ClearNode(path.Child(survivor));
            return SetNode(path, std::move(leaf));
        }
        return SetBranchLazy(path, children[0], children[1]);
    }
    void End() { finished = true; store->active = false; }
    DiskStateStats Stats() const {
        FlushNodes();
        auto result = stats;
        for (const auto &[key, change] : changes) {
            (void)change;
            if (key[0] == 'C') ++result.dirty_coins;
            if (key[0] == 'N') ++result.dirty_nodes;
        }
        return result;
    }
};

namespace {
template <typename Read> void RawReadCoin(Read read, const Outpoint &outpoint, std::optional<Coin> &out) {
    const auto bytes = read(CoinKey(outpoint));
    if (!bytes) { out.reset(); return; }
    Coin coin = ParseCoin(*bytes); Require(coin.outpoint == outpoint, "coin key mismatch");
    out = std::move(coin);
}
template <typename Read> void Prove(Read read, const Head &head, const Outpoint &query, CoinProof &out) {
    CoinProof proof;
    Path path;
    Summary summary = head.root;
    const Hash key = OutpointKey(query);
    std::vector<std::pair<unsigned, Hash>> ancestors;
    while (summary.kind) {
        const auto bytes = read(path.Key()); Require(bytes.has_value(), "missing proof node");
        const Node node = ParseNode(*bytes, path, summary);
        if (summary.kind == 1) {
            proof.coin = node.coin;
            proof.presence = proof.coin->outpoint == query ? ProofPresence::Present : ProofPresence::OtherLeaf;
            const auto coin = read(CoinKey(proof.coin->outpoint));
            Require(coin && BytesView(*coin) == node.coin_bytes, "coin/tree proof disagreement");
            break;
        }
        const bool bit = Bit(key, path.depth);
        ancestors.emplace_back(path.depth, node.children[1 - bit].digest);
        summary = node.children[bit]; path = path.Child(bit);
    }
    for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it) {
        if (it->second != EmptyUtxoRoot()) {
            proof.bitmap[it->first / 8] |= uint8_t(1 << (it->first % 8));
            proof.siblings.push_back(it->second);
        }
    }
    Require(VerifyCoinProof(query, proof, head.root.digest), "generated proof mismatch");
    out = std::move(proof);
}
template <typename Read> void AuthReadCoin(Read read, const Head &head, const Outpoint &outpoint,
                                          std::optional<Coin> &out) {
    CoinProof proof; Prove(read, head, outpoint, proof);
    std::optional<Coin> coin; RawReadCoin(read, outpoint, coin);
    Require(coin.has_value() == (proof.presence == ProofPresence::Present),
            "coin membership disagreement");
    if (coin) Require(CoinBytes(*coin) == CoinBytes(*proof.coin), "authenticated coin mismatch");
    out = std::move(coin);
}
Path ParseNodeKey(BytesView key) {
    Require(key.size() == 35 && key[0] == 'N', "invalid node key");
    Reader r{key, 1}; Path path; path.prefix = r.Digest(); path.depth = r.Int(2); r.End();
    for (uint8_t &b : path.prefix) b = ReverseByte(b);
    Require(path.depth <= 256, "node key depth");
    Hash canonical{};
    for (unsigned d = 0; d < path.depth; ++d)
        if (Bit(path.prefix, d)) canonical[d / 8] |= uint8_t(1 << (d % 8));
    Require(canonical == path.prefix, "noncanonical node prefix"); return path;
}
Outpoint ParseCoinKey(BytesView key) {
    Require(key.size() == 37 && key[0] == 'C', "invalid coin key");
    Reader r{key, 1}; Outpoint outpoint;
    outpoint.tx_id = r.Digest(); outpoint.index = r.Int(4); r.End();
    for (uint8_t &b : outpoint.tx_id) b = ReverseByte(b);
    return outpoint;
}
void ValidateRetainedValue(const Bytes &key, const Value &value) {
    if (key[0] == 'C') {
        const Outpoint outpoint = ParseCoinKey(key);
        if (value) Require(ParseCoin(*value).outpoint == outpoint, "retained coin key mismatch");
    } else {
        const Path path = ParseNodeKey(key);
        if (value) {
            Reader r{*value}; const Summary summary = GetSummary(r);
            (void)ParseNode(*value, path, summary);
        }
    }
}
template <typename Read> Node ValidateRestoredNode(Read read, const Path &path, const Summary &summary) {
    const auto bytes = read(path.Key()); Require(bytes.has_value(), "missing restored tree node");
    Node node = ParseNode(*bytes, path, summary);
    auto CheckLeaf = [&](const Node &leaf) {
        if (leaf.coin) {
            const auto coin = read(CoinKey(leaf.coin->outpoint));
            Require(coin && BytesView(*coin) == CoinBytes(*leaf.coin), "restored leaf/coin disagreement");
        }
    };
    CheckLeaf(node);
    if (node.summary.kind == 2) {
        // Summary kinds are not hashed: authenticate immediate child records
        // as well as their digests before accepting restored branch metadata.
        for (unsigned bit = 0; bit < 2; ++bit) {
            const Path child = path.Child(bit); const auto value = read(child.Key());
            if (!node.children[bit].kind) Require(!value, "orphan restored child");
            else {
                Require(value.has_value(), "missing restored child");
                CheckLeaf(ParseNode(*value, child, node.children[bit]));
            }
        }
    }
    return node;
}
template <typename Read> void ValidateRestoredPath(Read read, const Head &head, const Path &target) {
    Path path; Summary summary = head.root;
    while (true) {
        if (!summary.kind) {
            Require(!read(target.Key()), "orphan restored node below empty subtree"); return;
        }
        const Node node = ValidateRestoredNode(read, path, summary);
        if (path.depth == target.depth) return;
        if (node.summary.kind == 1) {
            Require(!read(target.Key()), "orphan restored node below collapsed leaf"); return;
        }
        const bool bit = Bit(target.prefix, path.depth);
        summary = node.children[bit]; path = path.Child(bit);
    }
}
void AddBatch(MdbxWriteBatch &batch, const Bytes &key, const Value &value, DiskStateStats &stats) {
    if (value) { batch.Put(key, *value); ++stats.batch_puts; }
    else { batch.Delete(key); ++stats.batch_deletes; }
    stats.batch_bytes += key.size() + (value ? value->size() : 0);
}

void OpenMdbxEnvironment(const std::string &directory, MDBX_env *&env_out,
                         MDBX_dbi &dbi_meta, MDBX_dbi &dbi_coins, MDBX_dbi &dbi_smt_nodes,
                         MDBX_dbi &dbi_headers, MDBX_dbi &dbi_active_h, MDBX_dbi &dbi_block_locs,
                         MDBX_dbi &dbi_undo_locs, MDBX_dbi &dbi_candidates, MDBX_dbi &dbi_children,
                         MDBX_dbi &dbi_queue, MDBX_dbi &dbi_excluded, MDBX_dbi &dbi_failures,
                         MDBX_dbi &dbi_parked) {
    std::error_code ec;
    const bool directory_existed = std::filesystem::exists(directory, ec);
    if (ec) Fail(DiskStateErrorCode::Database, "failed to inspect state directory: " + ec.message());
    std::filesystem::create_directories(directory, ec);
    if (ec) Fail(DiskStateErrorCode::Database, "failed to create state directory: " + ec.message());
    CheckMdbx(mdbx_env_create(&env_out), "mdbx_env_create");
    CheckMdbx(mdbx_env_set_maxreaders(env_out, 256), "mdbx_env_set_maxreaders");
    CheckMdbx(mdbx_env_set_maxdbs(env_out, 16), "mdbx_env_set_maxdbs");
    CheckMdbx(mdbx_env_set_geometry(env_out,
                                    1LL << 20,
                                    4LL << 20,
                                    64LL << 30,
                                    16LL << 20,
                                    32LL << 20,
                                    4096),
              "mdbx_env_set_geometry");
    constexpr MDBX_env_flags_t env_flags = static_cast<MDBX_env_flags_t>(
        MDBX_SAFE_NOSYNC | MDBX_NOMETASYNC |
        MDBX_LIFORECLAIM | MDBX_NOSTICKYTHREADS | MDBX_NOMEMINIT);
    CheckMdbx(mdbx_env_open(env_out, directory.c_str(), env_flags, 0664), "mdbx_env_open");
    CheckMdbx(mdbx_env_set_syncperiod(env_out, 1U << 16), "mdbx_env_set_syncperiod");
    CheckMdbx(mdbx_env_set_syncbytes(env_out, 16U << 20), "mdbx_env_set_syncbytes");

    MDBX_txn *wtxn{nullptr};
    CheckMdbx(mdbx_txn_begin(env_out, nullptr, MDBX_TXN_READWRITE, &wtxn), "mdbx_txn_begin(init)");
    try {
        CheckMdbx(mdbx_dbi_open(wtxn, "meta", MDBX_CREATE, &dbi_meta), "mdbx_dbi_open(meta)");
        CheckMdbx(mdbx_dbi_open(wtxn, "coins", MDBX_CREATE, &dbi_coins), "mdbx_dbi_open(coins)");
        CheckMdbx(mdbx_dbi_open(wtxn, "smt_nodes", MDBX_CREATE, &dbi_smt_nodes), "mdbx_dbi_open(smt_nodes)");
        CheckMdbx(mdbx_dbi_open(wtxn, "headers", MDBX_CREATE, &dbi_headers), "mdbx_dbi_open(headers)");
        CheckMdbx(mdbx_dbi_open(wtxn, "active_h", MDBX_CREATE, &dbi_active_h), "mdbx_dbi_open(active_h)");
        CheckMdbx(mdbx_dbi_open(wtxn, "block_locs", MDBX_CREATE, &dbi_block_locs), "mdbx_dbi_open(block_locs)");
        CheckMdbx(mdbx_dbi_open(wtxn, "undo_locs", MDBX_CREATE, &dbi_undo_locs), "mdbx_dbi_open(undo_locs)");
        CheckMdbx(mdbx_dbi_open(wtxn, "candidates", MDBX_CREATE, &dbi_candidates), "mdbx_dbi_open(candidates)");
        CheckMdbx(mdbx_dbi_open(wtxn, "children", MDBX_CREATE, &dbi_children), "mdbx_dbi_open(children)");
        CheckMdbx(mdbx_dbi_open(wtxn, "queue", MDBX_CREATE, &dbi_queue), "mdbx_dbi_open(queue)");
        CheckMdbx(mdbx_dbi_open(wtxn, "excluded", MDBX_CREATE, &dbi_excluded), "mdbx_dbi_open(excluded)");
        CheckMdbx(mdbx_dbi_open(wtxn, "failures", MDBX_CREATE, &dbi_failures), "mdbx_dbi_open(failures)");
        CheckMdbx(mdbx_dbi_open(wtxn, "parked", MDBX_CREATE, &dbi_parked), "mdbx_dbi_open(parked)");
        CheckMdbx(mdbx_txn_commit(wtxn), "mdbx_txn_commit(init)");
        wtxn = nullptr;
        SyncEnvironment(env_out);
        SyncDirectory(directory);
        if (!directory_existed) {
            const auto parent = std::filesystem::path(directory).parent_path();
            SyncDirectory(parent.empty() ? "." : parent.string());
        }
    } catch (...) {
        if (wtxn) mdbx_txn_abort(wtxn);
        throw;
    }
}
} // namespace

DiskStateStore::DiskStateStore() = default;
bool RawDiskStateSyncStatus(const DiskStateStore &store, DiskStateSyncStatus &out,
                           DiskStateError &error) {
    return Guard(error, [&] {
        if (!store.impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        store.impl_->Usable();
        unsigned flags = 0, period = 0;
        size_t bytes = 0;
        MDBX_envinfo info{};
        CheckMdbx(mdbx_env_get_flags(store.impl_->env, &flags), "mdbx_env_get_flags");
        CheckMdbx(mdbx_env_get_syncbytes(store.impl_->env, &bytes), "mdbx_env_get_syncbytes");
        CheckMdbx(mdbx_env_get_syncperiod(store.impl_->env, &period), "mdbx_env_get_syncperiod");
        CheckMdbx(mdbx_env_info_ex(store.impl_->env, nullptr, &info, sizeof(info)), "mdbx_env_info_ex");
        out = {bool(flags & MDBX_WRITEMAP), bool(flags & MDBX_SAFE_NOSYNC),
               bool(flags & MDBX_NOMETASYNC),
               (flags & MDBX_UTTERLY_NOSYNC) == MDBX_UTTERLY_NOSYNC,
               bytes, info.mi_unsync_volume, period};
    });
}
DiskStateStore::~DiskStateStore() = default;
DiskStateStore::DiskStateStore(DiskStateStore &&) noexcept = default;
DiskStateStore &DiskStateStore::operator=(DiskStateStore &&) noexcept = default;
DiskStateTransaction::DiskStateTransaction() = default;
DiskStateTransaction::~DiskStateTransaction() = default;
DiskStateTransaction::DiskStateTransaction(DiskStateTransaction &&) noexcept = default;
DiskStateTransaction &DiskStateTransaction::operator=(DiskStateTransaction &&) noexcept = default;

bool DiskStateStore::Open(const std::string &directory, const DiskStateOptions &options,
                          const DiskStateMetadata &initial, DiskStateStore &out, DiskStateError &error) {
    return Guard(error, [&] {
        if (out.impl_) Fail(DiskStateErrorCode::Closed, "output store already open");
        if (options.cache_bytes == 0 || options.write_buffer_bytes < (64 << 10) ||
            options.max_pending_bytes == 0 || options.max_metadata_bytes == 0)
            Fail(DiskStateErrorCode::Resource, "invalid storage limits");
        CheckIndexOptions(options);
        if (options.header_index && initial != DiskStateMetadata{})
            Fail(DiskStateErrorCode::ProfileMismatch, "indexed development initialization requires empty state");
        // Refuse an absent database before creating directories or engine files when existing_only is set.
        if (options.existing_only) {
            std::error_code ec;
            if (!std::filesystem::exists(directory + "/mdbx.dat", ec))
                Fail(DiskStateErrorCode::Missing, "existing initialized database required");
        }
        auto impl = std::make_shared<Impl>();
        impl->directory = directory;
        impl->options = options;
        impl->normalized_dir = NormalizeDirPath(directory);
        {
            std::lock_guard<std::mutex> lock(OpenDirsMutex());
            if (!OpenDirsSet().insert(impl->normalized_dir).second)
                Fail(DiskStateErrorCode::Database, "directory already locked by an open DiskStateStore");
            impl->dir_locked = true;
        }
        OpenMdbxEnvironment(directory, impl->env,
                            impl->dbi_meta, impl->dbi_coins, impl->dbi_smt_nodes,
                            impl->dbi_headers, impl->dbi_active_h, impl->dbi_block_locs,
                            impl->dbi_undo_locs, impl->dbi_candidates, impl->dbi_children,
                            impl->dbi_queue, impl->dbi_excluded, impl->dbi_failures,
                            impl->dbi_parked);
        // Update normalized path once directory exists on disk.
        {
            std::lock_guard<std::mutex> lock(OpenDirsMutex());
            const std::string canon = NormalizeDirPath(directory);
            if (canon != impl->normalized_dir) {
                OpenDirsSet().erase(impl->normalized_dir);
                impl->normalized_dir = canon;
                OpenDirsSet().insert(impl->normalized_dir);
            }
        }
        const Value schema = impl->Read("V"), head = impl->Read("S");
        if (!schema) {
            if (options.existing_only)
                Fail(DiskStateErrorCode::Missing, "existing database schema required");
            Require(!head, "head without schema");
            MDBX_txn *rtxn = impl->EnsureReadTxn();
            const MDBX_dbi all_dbis[] = {
                impl->dbi_meta, impl->dbi_coins, impl->dbi_smt_nodes, impl->dbi_headers,
                impl->dbi_active_h, impl->dbi_block_locs, impl->dbi_undo_locs, impl->dbi_candidates,
                impl->dbi_children, impl->dbi_queue, impl->dbi_excluded, impl->dbi_failures, impl->dbi_parked
            };
            for (MDBX_dbi dbi : all_dbis) {
                MDBX_stat st{};
                CheckMdbx(mdbx_dbi_stat(rtxn, dbi, &st, sizeof(st)), "mdbx_dbi_stat");
                Require(st.ms_entries == 0, "nonempty database without schema");
            }
            impl->head.metadata = initial;
            MdbxWriteBatch batch;
            batch.Put("V", StorageSchema(options));
            batch.Put("S", EncodeHead(impl->head, options));
            if (options.header_index) batch.Put("I", EncodeActiveIndex(std::nullopt));
            if (options.candidates) batch.Put("K", EncodeInventory({}));
            impl->Write(batch);
        } else {
            if (*schema != StorageSchema(options))
                Fail(DiskStateErrorCode::ProfileMismatch, "database identity/profile/schema mismatch; indexed development needs a fresh home");
            Require(head.has_value(), "missing head"); impl->head = ParseHead(*head, options);
            if (options.env) {
                const std::string probe_path = directory + "/mdbx_head_probe.sst";
                const int pfd = ::open(probe_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
                if (pfd >= 0) {
                    const Bytes payload = *head + Bytes(5, '\0');
                    (void)::write(pfd, payload.data(), payload.size());
                    ::close(pfd);
                }
            }
        }
        if (options.existing_only && impl->head.metadata == DiskStateMetadata{})
            Fail(DiskStateErrorCode::Missing, "existing initialized metadata required");
        const Value node = impl->Read(Path{}.Key());
        if (impl->head.root.kind) {
            Require(node.has_value(), "missing root node");
            const Node root = ParseNode(*node, Path{}, impl->head.root);
            if (root.coin) {
                const Value coin = impl->Read(CoinKey(root.coin->outpoint));
                Require(coin && *coin == CoinBytes(*root.coin), "singleton root coin mismatch");
            }
        } else Require(!node, "unexpected root node");
        if (options.header_index) (void)impl->CheckedActive();
        if (options.recovery) (void)impl->Journal(options.recovery->max_journal_bytes);
        if (options.candidates) (void)impl->View();
        if (const Value hp = impl->Read("H_prune")) {
            if (hp->size() == 41) {
                Reader r{*hp};
                impl->pruned_horizon_height = r.Int(8);
                const uint64_t has_tip = r.Int(1);
                const Hash h_tip = r.Digest();
                if (has_tip) {
                    impl->pruned_horizon_tip = h_tip;
                }
            }
        }
        out.impl_ = std::move(impl);
    });
}
bool DiskStateStore::IsOpen() const { return impl_ && !impl_->poisoned; }
bool DiskStateStore::CandidatesEnabled() const { return IsOpen() && impl_->options.candidates.has_value(); }
bool DiskStateStore::MatchesProfile(const Hash &identity, const Hash &digest) const {
    return IsOpen() && impl_->options.identity == identity &&
           impl_->options.profile_digest == digest;
}
Hash DiskStateStore::Root() const { return impl_ ? impl_->head.root.digest : EmptyUtxoRoot(); }
DiskStateMetadata DiskStateStore::Metadata() const { return impl_ ? impl_->head.metadata : DiskStateMetadata{}; }
bool DiskStateStore::ReadRetainedState(const Hash &id, std::optional<RetainedDiskState> &out,
                                       DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->CheckCachedHead(); auto head = impl_->RetainedHead(id);
        if (!head) { out.reset(); return; }
        out = RetainedDiskState{std::move(head->metadata), head->root.digest};
    });
}
bool DiskStateStore::ReadBlockLocation(const Hash &id, std::optional<DiskBlockLocation> &out,
                                       DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        ++impl_->stats.database_reads;
        out = impl_->RawLocation(impl_->dbi_block_locs, id);
    });
}
bool DiskStateStore::ReadUndoLocation(const Hash &id, std::optional<DiskUndoLocation> &out,
                                      DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        ++impl_->stats.database_reads;
        out = impl_->RawLocation(impl_->dbi_undo_locs, id);
    });
}
bool DiskStateStore::ReadBlockSlice(const Hash &id, uint64_t offset, uint64_t length,
                                    std::vector<uint8_t> &out, uint64_t *total_bytes,
                                    DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        ++impl_->stats.database_reads;
        const auto loc = impl_->RawLocation(impl_->dbi_block_locs, id);
        if (!loc) Fail(DiskStateErrorCode::Missing, "block location not found");
        if (total_bytes) *total_bytes = loc->length;
        impl_->ReadFlatSlice(true, *loc, offset, length, out);
    });
}
bool DiskStateStore::ReadUndoSlice(const Hash &id, uint64_t offset, uint64_t length,
                                   std::vector<uint8_t> &out, uint64_t *total_bytes,
                                   DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        ++impl_->stats.database_reads;
        const auto loc = impl_->RawLocation(impl_->dbi_undo_locs, id);
        if (!loc) Fail(DiskStateErrorCode::Missing, "undo location not found");
        if (total_bytes) *total_bytes = loc->length;
        impl_->ReadFlatSlice(false, *loc, offset, length, out);
    });
}
bool DiskStateStore::ReadCandidateView(CandidateView &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        auto view = impl_->View(); out = std::move(view);
    });
}
bool DiskStateStore::ReadCandidatePage(const std::optional<CandidateRankCursor> &after,
                                      const CandidateQueryLimits &limits, CandidatePage &out, DiskStateError &error, CandidateQueryUsage *usage) const {
    if (usage) *usage = {};
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        QueryBudget budget{limits, {}}; UsageReporter report{budget, usage}; Impl::BudgetScope scope(*impl_, budget);
        CandidatePage page; page.view = impl_->View();
        if (!limits.max_rows) Fail(DiskStateErrorCode::Resource, "zero candidate page rows");
        if (page.view.pending_journal || page.view.pending_receipt || page.view.pending_propagation) {
            page.used = budget.used; out = std::move(page); return;
        }
        MDBX_txn *rtxn = impl_->EnsureReadTxn();
        MdbxCursorGuard cursor;
        CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_candidates, &cursor.cur), "mdbx_cursor_open(candidates)");
        MDBX_val k{}, v{};
        int rc = MDBX_NOTFOUND;
        if (after) {
            const Bytes subkey = RankedKey(*after).substr(1);
            k = {const_cast<char *>(subkey.data()), subkey.size()};
            budget.Step();
            rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_SET_RANGE);
            if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(candidates)");
            if (rc == MDBX_SUCCESS) {
                budget.Step();
                rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_PREV);
            } else {
                budget.Step();
                rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_LAST);
            }
        } else {
            budget.Step();
            rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_LAST);
        }
        if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(candidates)");
        try {
            while (rc == MDBX_SUCCESS) {
                budget.Step();
                if (budget.used.rows >= limits.max_rows) break;
                Bytes key(1, 'W');
                key.append(static_cast<const char *>(k.iov_base), k.iov_len);
                budget.Decode(key.size());
                const auto rank_cursor = ParseRankedKey(key);
                budget.Step();
                Require(v.iov_len == 48, "candidate rank value size");
                budget.Decode(v.iov_len);
                const Bytes summary(static_cast<const char *>(v.iov_base), v.iov_len);
                const auto header = impl_->CheckedHeader(rank_cursor.id);
                Require(header && header->chain_work == rank_cursor.work && RankValue(*header) == summary, "candidate/H summary mismatch");
                Require(!impl_->Read(IdKey('E', rank_cursor.id)), "excluded header still ranked");
                const auto active = impl_->Read(ActiveKey(header->header.height));
                Require(!active || ParseHash(*active) != rank_cursor.id, "active header still ranked");
                budget.Row(); page.rows.push_back({rank_cursor.id, *header}); page.next = rank_cursor;
                budget.Step();
                rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_PREV);
                if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(candidates prev)");
            }
            if (rc == MDBX_NOTFOUND) page.complete = true;
        } catch (const Failure &failure) {
            if (failure.error.code != DiskStateErrorCode::Resource || page.rows.empty()) throw;
        }
        page.used = budget.used; out = std::move(page);
    });
}
bool DiskStateStore::ReadCandidateChildren(const Hash &parent, const std::optional<Hash> &after,
                                          const CandidateQueryLimits &limits, CandidateChildrenPage &out, DiskStateError &error, CandidateQueryUsage *usage) const {
    if (usage) *usage = {};
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        QueryBudget budget{limits, {}}; UsageReporter report{budget, usage}; Impl::BudgetScope scope(*impl_, budget);
        impl_->Candidates(); impl_->CheckCachedHead(); const auto header = impl_->CheckedHeader(parent);
        Require(header.has_value(), "missing child-query parent");
        if (!limits.max_rows) Fail(DiskStateErrorCode::Resource, "zero child page rows");
        CandidateChildrenPage page;
        const Bytes prefix = HashBytes(parent);
        const Bytes start = after ? ChildKey(parent, *after).substr(1) : prefix;
        MDBX_txn *rtxn = impl_->EnsureReadTxn();
        MdbxCursorGuard cursor;
        CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_children, &cursor.cur), "mdbx_cursor_open(children)");
        MDBX_val k{const_cast<char *>(start.data()), start.size()}, v{};
        budget.Step();
        int rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_SET_RANGE);
        if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(children)");
        if (after && rc == MDBX_SUCCESS) {
            budget.Step();
            if (BytesView(static_cast<const char *>(k.iov_base), k.iov_len) == BytesView(start)) {
                budget.Step();
                rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_NEXT);
                if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(children next)");
            }
        }
        try {
            while (rc == MDBX_SUCCESS) {
                budget.Step();
                const BytesView raw_sub(static_cast<const char *>(k.iov_base), k.iov_len);
                if (!raw_sub.starts_with(prefix)) { page.complete = true; break; }
                if (budget.used.rows >= limits.max_rows) break;
                Require(raw_sub.size() == 64, "child key size");
                budget.Decode(raw_sub.size() + 1);
                Reader r{raw_sub, 32};
                const Hash child = r.Digest(); r.End();
                budget.Step();
                const BytesView value(static_cast<const char *>(v.iov_base), v.iov_len);
                Require(value == BytesView("\1", 1), "child record version");
                budget.Decode(value.size());
                const auto entry = impl_->CheckedHeader(child);
                Require(entry && entry->header.prev_id == parent, "child/H parent mismatch");
                budget.Row(); page.children.push_back(child); page.next = child;
                budget.Step();
                rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_NEXT);
                if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(children next)");
            }
            if (rc == MDBX_NOTFOUND) page.complete = true;
        } catch (const Failure &failure) {
            if (failure.error.code != DiskStateErrorCode::Resource || page.children.empty()) throw;
        }
        page.used = budget.used; out = std::move(page);
    });
}
bool DiskStateStore::ReadCandidateInvalidity(const Hash &id, std::optional<Hash> &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Candidates(); impl_->CheckCachedHead(); const auto excluded = impl_->Read(IdKey('E', id));
        if (!excluded) { out.reset(); return; }
        const Hash root = ParseHash(*excluded); const auto fact = impl_->Read(IdKey('F', root)); Require(fact.has_value(), "excluded header without causal fact");
        Reader r{*fact}; const auto failure = impl_->ParseFailure(r); Require(failure.BlockId() == root, "causal fact key mismatch"); (void)r.Digest(); r.End();
        const auto entry = impl_->CheckedHeader(id); Require(entry && entry->stage == HeaderStage::HeaderChecked, "excluded connected/missing header"); out = root;
    });
}
bool DiskStateStore::CheckCandidateRecoveryCapacity(uint64_t max_disconnects, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        const auto view = impl_->View();
        if (view.pending_journal || view.pending_receipt || view.pending_propagation)
            Fail(DiskStateErrorCode::TransactionAborted, "candidate writer already fenced");
        if (max_disconnects > impl_->options.candidates->max_candidates - view.candidate_count ||
            view.invalid_root_count >= impl_->options.candidates->max_invalid_roots)
            Fail(DiskStateErrorCode::Resource, "insufficient candidate/terminal-failure reservation");
    });
}
bool DiskStateStore::EvictCandidateLeaf(const Hash &id, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        const uint64_t reads_before = impl_->stats.database_reads;
        impl_->Candidates(); impl_->Ordinary(); if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        (void)impl_->CheckedActive(); auto counters = impl_->Counters(); const auto entry = impl_->CheckedHeader(id);
        if (!entry) Fail(DiskStateErrorCode::Missing, "candidate leaf missing");
        if (entry->stage != HeaderStage::HeaderChecked || id == impl_->head.metadata.tip || impl_->Read(IdKey('E', id)) ||
            impl_->Read(UndoKey(id))) Fail(DiskStateErrorCode::TransactionAborted, "protected candidate cannot be evicted");
        {
            MDBX_txn *rtxn = impl_->EnsureReadTxn();
            MdbxCursorGuard cursor;
            CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_children, &cursor.cur), "mdbx_cursor_open(children)");
            const Bytes prefix = HashBytes(id);
            MDBX_val k{const_cast<char *>(prefix.data()), prefix.size()}, v{};
            const int rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_SET_RANGE);
            if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(children)");
            if (rc == MDBX_SUCCESS && BytesView(static_cast<const char *>(k.iov_base), k.iov_len).starts_with(prefix))
                Fail(DiskStateErrorCode::TransactionAborted, "candidate parent has retained children");
        }
        const auto rank = impl_->Read(RankedKey({entry->chain_work, id})); Require(rank && *rank == RankValue(*entry), "evicted candidate membership");
        if (entry->header.height) Require(impl_->Read(ChildKey(entry->header.prev_id, id)) == Value{Bytes(1, 1)}, "evicted child membership");
        Decrement(counters.candidates); Decrement(counters.speculative); Increment(counters.revision);
        MdbxWriteBatch batch; DiskStateStats stats;
        AddBatch(batch, IdKey('Z', id), std::nullopt, stats);
        AddBatch(batch, HeaderKey(id), std::nullopt, stats); AddBatch(batch, RankedKey({entry->chain_work, id}), std::nullopt, stats);
        if (entry->header.height) { Decrement(counters.children); AddBatch(batch, ChildKey(entry->header.prev_id, id), std::nullopt, stats); }
        AddBatch(batch, "K", EncodeInventory(counters), stats); stats.database_reads = impl_->stats.database_reads - reads_before;
        impl_->Write(batch); impl_->stats = stats;
    });
}
bool DiskStateStore::FinishCandidateRecovery(const DiskRecoveryUpdate &update, const CandidateTerminalClaim &claim, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        const uint64_t reads_before = impl_->stats.database_reads;
        impl_->Candidates(); if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        impl_->RecoveryFence(update, false);
        Require(update.expected_journal && !update.next_journal && update.next_tip == impl_->head.metadata.tip, "terminal journal clearing fence");
        CandidateTerminalReceipt receipt; receipt.identity = impl_->options.identity; receipt.profile_digest = impl_->options.profile_digest;
        receipt.attempt = claim.attempt; receipt.source = claim.source; receipt.target = claim.target; receipt.revision = claim.revision;
        receipt.outcome = claim.outcome; receipt.failure = claim.failure; receipt.stable_tip = impl_->head.metadata.tip; receipt.stable_root = impl_->head.root.digest;
        receipt.metadata_digest = LocalDigest("Lotus/v2/storage/head", EncodeHead(impl_->head, impl_->options));
        const auto encoded = ReceiptBytes(receipt); (void)impl_->ParseReceipt(encoded);
        auto counters = impl_->Counters();
        if (claim.failure && counters.roots >= impl_->options.candidates->max_invalid_roots)
            Fail(DiskStateErrorCode::Resource, "invalid root ledger capacity exhausted");
        Increment(counters.revision); MdbxWriteBatch batch; DiskStateStats stats;
        AddBatch(batch, "J", std::nullopt, stats); AddBatch(batch, "R", encoded, stats); AddBatch(batch, "K", EncodeInventory(counters), stats);
        stats.database_reads = impl_->stats.database_reads - reads_before;
        impl_->Write(batch); impl_->stats = stats;
    });
}
bool DiskStateStore::ReadCandidateReceipt(std::optional<CandidateTerminalReceipt> &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Candidates(); impl_->CheckCachedHead(); auto receipt = impl_->Receipt(); out = std::move(receipt);
    });
}
bool DiskStateStore::AcknowledgeCandidateReceipt(const Hash &expected_id, const Hash &expected_tip, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        const uint64_t reads_before = impl_->stats.database_reads;
        impl_->Candidates(); if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        impl_->CheckCachedHead(); Require(!impl_->Journal(impl_->options.recovery->max_journal_bytes), "receipt acknowledgement during recovery");
        const auto receipt = impl_->Receipt();
        const Hash metadata = LocalDigest("Lotus/v2/storage/head", EncodeHead(impl_->head, impl_->options));
        Bytes ack; Put(ack, 1, 1); PutHash(ack, expected_id); PutHash(ack, expected_tip); PutHash(ack, impl_->head.root.digest); PutHash(ack, metadata);
        if (!receipt) {
            const auto acknowledged = impl_->Read("T");
            if (acknowledged) Require(acknowledged->size() == 129 && uint8_t((*acknowledged)[0]) == 1, "acknowledgement schema");
            if (expected_tip == impl_->head.metadata.tip && acknowledged == Value{ack}) return;
            Fail(DiskStateErrorCode::UndoMismatch, "missing or stale receipt acknowledgement");
        }
        if (receipt->id != expected_id || expected_tip != impl_->head.metadata.tip)
            Fail(DiskStateErrorCode::UndoMismatch, "receipt/stable tip changed");
        Require(!impl_->PendingPropagation(), "receipt acknowledgement conflicts with propagation");
        auto counters = impl_->Counters(); MdbxWriteBatch batch; DiskStateStats stats;
        if (receipt->failure) {
            const auto &failure = *receipt->failure; const auto entry = impl_->CheckedHeader(failure.BlockId()); Require(entry.has_value(), "missing failed header");
            Require(!impl_->Read(IdKey('F', failure.BlockId())) && !impl_->Read(IdKey('E', failure.BlockId())), "duplicate invalid root fact");
            const auto key = RankedKey({entry->chain_work, failure.BlockId()}); const auto rank = impl_->Read(key);
            Require(rank && *rank == RankValue(*entry), "failed root missing candidate membership");
            Increment(counters.roots, impl_->options.candidates->max_invalid_roots); Increment(counters.excluded, counters.speculative);
            Increment(counters.epoch); Decrement(counters.candidates);
            AddBatch(batch, IdKey('F', failure.BlockId()), FailureBytes(failure) + HashBytes(receipt->id), stats);
            AddBatch(batch, IdKey('E', failure.BlockId()), HashBytes(failure.BlockId()), stats); AddBatch(batch, key, std::nullopt, stats);
            AddBatch(batch, "P", EncodePropagation({failure.BlockId(), 0, 1}), stats);
            AddBatch(batch, QueueKey(0), EncodeQueue({failure.BlockId(), std::nullopt}), stats);
        }
        Increment(counters.revision); AddBatch(batch, "K", EncodeInventory(counters), stats);
        AddBatch(batch, "R", std::nullopt, stats); AddBatch(batch, "T", ack, stats); stats.database_reads = impl_->stats.database_reads - reads_before;
        impl_->Write(batch); impl_->stats = stats;
    });
}
bool DiskStateStore::StepCandidateInvalidation(const CandidateQueryLimits &limits, CandidateInvalidationProgress &out, DiskStateError &error, CandidateQueryUsage *usage) {
    if (usage) *usage = {};
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        QueryBudget budget{limits, {}}; UsageReporter report{budget, usage}; Impl::BudgetScope scope(*impl_, budget); impl_->Candidates();
        if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        impl_->CheckCachedHead(); Require(!impl_->Journal(impl_->options.recovery->max_journal_bytes) && !impl_->Receipt(), "propagation conflicts with recovery/receipt");
        auto counters = impl_->Counters(); auto propagation = impl_->PendingPropagation(); CandidateInvalidationProgress progress;
        if (!propagation) { progress.complete = true; progress.used = budget.used; out = progress; return; }
        if (!limits.max_rows) Fail(DiskStateErrorCode::Resource, "zero invalidation rows");
        auto &p = *propagation; const auto stored_node = impl_->Read(QueueKey(p.head)); Require(stored_node.has_value(), "missing propagation node");
        QueueNode node = ParseQueue(*stored_node); Require(impl_->Read(IdKey('E', node.id)) == Value{HashBytes(p.root)}, "propagation exclusion mismatch");
        const auto fact = impl_->Read(IdKey('F', p.root)); Require(fact.has_value(), "propagation without root fact");
        Reader fr{*fact}; const auto failure = impl_->ParseFailure(fr); Require(failure.BlockId() == p.root, "propagation fact identity"); (void)fr.Digest(); fr.End();
        MdbxWriteBatch batch; DiskStateStats stats; bool finished{};
        {
            const Bytes prefix = HashBytes(node.id);
            const Bytes start = node.after ? ChildKey(node.id, *node.after).substr(1) : prefix;
            MDBX_txn *rtxn = impl_->EnsureReadTxn();
            MdbxCursorGuard cursor;
            CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_children, &cursor.cur), "mdbx_cursor_open(children)");
            MDBX_val k{const_cast<char *>(start.data()), start.size()}, v{};
            budget.Step();
            int rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_SET_RANGE);
            if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(children)");
            if (node.after && rc == MDBX_SUCCESS) {
                budget.Step();
                if (BytesView(static_cast<const char *>(k.iov_base), k.iov_len) == BytesView(start)) {
                    budget.Step();
                    rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_NEXT);
                    if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(children next)");
                }
            }
            try {
                while (rc == MDBX_SUCCESS) {
                    budget.Step();
                    const BytesView raw_sub(static_cast<const char *>(k.iov_base), k.iov_len);
                    if (!raw_sub.starts_with(prefix)) { finished = true; break; }
                    if (budget.used.rows >= limits.max_rows) break;
                    Require(raw_sub.size() == 64, "propagation child key");
                    budget.Decode(raw_sub.size() + 1);
                    Reader kr{raw_sub, 32};
                    const Hash child = kr.Digest(); kr.End();
                    budget.Step();
                    const BytesView value(static_cast<const char *>(v.iov_base), v.iov_len);
                    Require(value == BytesView("\1", 1), "propagation child row");
                    budget.Decode(value.size());
                    const auto entry = impl_->CheckedHeader(child); Require(entry && entry->header.prev_id == node.id &&
                        entry->stage == HeaderStage::HeaderChecked, "invalid ancestor of connected/missing header");
                    const auto excluded = impl_->Read(IdKey('E', child));
                    if (!excluded) {
                        const auto rank_key = RankedKey({entry->chain_work, child}); const auto rank = impl_->Read(rank_key);
                        Require(rank && *rank == RankValue(*entry), "propagated child missing rank");
                        if (p.tail == std::numeric_limits<uint64_t>::max()) Fail(DiskStateErrorCode::Resource, "propagation sequence exhausted");
                        Increment(counters.excluded, counters.speculative); Decrement(counters.candidates);
                        Require(p.tail - p.head < impl_->options.candidates->max_speculative_headers, "propagation queue creation bound");
                        AddBatch(batch, IdKey('E', child), HashBytes(p.root), stats); AddBatch(batch, rank_key, std::nullopt, stats);
                        AddBatch(batch, QueueKey(p.tail), EncodeQueue({child, std::nullopt}), stats); Increment(p.tail);
                    } else Require(excluded->size() == 32, "invalid inherited fact size");
                    budget.Row(); node.after = child;
                    budget.Step();
                    rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_NEXT);
                    if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(children next)");
                }
                if (rc == MDBX_NOTFOUND) finished = true;
            } catch (const Failure &failure_limit) {
                if (failure_limit.error.code != DiskStateErrorCode::Resource || !budget.used.rows) throw;
            }
        }
        if (finished) { AddBatch(batch, QueueKey(p.head), std::nullopt, stats); Increment(p.head); }
        else AddBatch(batch, QueueKey(p.head), EncodeQueue(node), stats);
        if (p.head == p.tail) AddBatch(batch, "P", std::nullopt, stats);
        else AddBatch(batch, "P", EncodePropagation(p), stats);
        Increment(counters.revision); AddBatch(batch, "K", EncodeInventory(counters), stats);
        stats.database_reads = budget.used.reads; impl_->Write(batch); impl_->stats = stats;
        progress.root = p.root; progress.pending_nodes = p.tail - p.head; progress.excluded = counters.excluded;
        progress.complete = p.head == p.tail; progress.used = budget.used; out = std::move(progress);
    });
}

bool DiskStateStore::AvalancheEnabled() const { return IsOpen() && impl_->options.avalanche; }
bool DiskStateStore::ReadBlockPolicy(const Hash &id, uint64_t max_reads,
                                    DiskBlockPolicy &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable(); auto policy = impl_->Policy(id, max_reads); out = std::move(policy);
    });
}
bool DiskStateStore::ApplyBlockPolicy(const Hash &tip, uint64_t revision,
                                    const std::vector<DiskParkUpdate> &updates,
                                    const std::optional<Hash> &finalize, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Candidates();
        if (!impl_->options.avalanche) Fail(DiskStateErrorCode::ProfileMismatch, "Avalanche disabled");
        const auto view = impl_->View();
        if (impl_->active || view.stable_tip != tip || view.revision != revision ||
            view.pending_journal || view.pending_receipt || view.pending_propagation)
            Fail(DiskStateErrorCode::TransactionAborted, "Avalanche batch fence changed");
        if (updates.size() > impl_->options.max_pending_bytes / 34)
            Fail(DiskStateErrorCode::Resource, "Avalanche batch creation capacity");
        const uint64_t reads = impl_->stats.database_reads;
        MdbxWriteBatch batch; DiskStateStats stats;
        for (const auto &u : updates) {
            if (!impl_->RawHeader(u.block)) Fail(DiskStateErrorCode::Missing, "Avalanche block missing");
            AddBatch(batch, IdKey('Z', u.block), u.parked ? Value{Bytes(1, 1)} : std::nullopt, stats);
        }
        auto next_finalized = impl_->finalized;
        if (finalize) {
            const auto entry = impl_->RawHeader(*finalize);
            if (!entry) Fail(DiskStateErrorCode::Missing, "finalized block missing");
            const auto active = impl_->Read(ActiveKey(entry->header.height));
            if (!active || ParseHash(*active) != *finalize)
                Fail(DiskStateErrorCode::TransactionAborted, "finalization requires active block");
            if (!next_finalized || entry->header.height > next_finalized->second)
                next_finalized = std::pair{*finalize, entry->header.height};
        }
        // ABC parks conflicting candidates when selecting them. Eagerly persist
        // those same markers here so restart cannot resurrect an observed fork.
        if (next_finalized) {
            MDBX_txn *rtxn = impl_->EnsureReadTxn();
            MdbxCursorGuard cursor;
            CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_candidates, &cursor.cur), "mdbx_cursor_open(candidates)");
            MDBX_val k{}, v{};
            uint64_t rows{};
            int rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_FIRST);
            while (rc == MDBX_SUCCESS) {
                if (++rows > impl_->options.candidates->max_candidates)
                    Fail(DiskStateErrorCode::Corruption, "Avalanche candidate inventory bound");
                Bytes full_key(1, 'W');
                full_key.append(static_cast<const char *>(k.iov_base), k.iov_len);
                const auto rank = ParseRankedKey(full_key);
                const uint64_t used = impl_->stats.database_reads - reads;
                if (used >= impl_->options.max_avalanche_reads)
                    Fail(DiskStateErrorCode::Resource, "Avalanche batch read capacity");
                const auto policy = impl_->Policy(rank.id, impl_->options.max_avalanche_reads - used, &next_finalized);
                if (policy.conflicting_finalized) {
                    if (stats.batch_bytes > impl_->options.max_pending_bytes ||
                        impl_->options.max_pending_bytes - stats.batch_bytes < 34)
                        Fail(DiskStateErrorCode::Resource, "Avalanche conflict batch byte capacity");
                    AddBatch(batch, IdKey('Z', rank.id), Bytes(1, 1), stats);
                }
                rc = mdbx_cursor_get(cursor.cur, &k, &v, MDBX_NEXT);
            }
            if (rc != MDBX_NOTFOUND) CheckMdbx(rc, "mdbx_cursor_get(candidates)");
        }
        auto counters = impl_->Counters(); Increment(counters.revision);
        AddBatch(batch, "K", EncodeInventory(counters), stats);
        if (impl_->stats.database_reads - reads > impl_->options.max_avalanche_reads)
            Fail(DiskStateErrorCode::Resource, "Avalanche batch read capacity");
        if (stats.batch_bytes > impl_->options.max_pending_bytes)
            Fail(DiskStateErrorCode::Resource, "Avalanche batch byte capacity");
        stats.database_reads = impl_->stats.database_reads - reads;
        impl_->Write(batch); impl_->finalized = next_finalized; impl_->stats = stats;
    });
}
DiskStateStats DiskStateStore::LastStats() const { return impl_ ? impl_->stats : DiskStateStats{}; }
bool DiskStateStore::ExportCoins(std::vector<Coin> &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        impl_->CheckCachedHead();
        std::vector<Coin> coins;
        MDBX_txn *rtxn = impl_->EnsureReadTxn();
        MdbxCursorGuard cur;
        CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_coins, &cur.cur), "mdbx_cursor_open(coins)");
        MDBX_val k{}, v{};
        for (int rc = mdbx_cursor_get(cur.cur, &k, &v, MDBX_FIRST);
             rc == MDBX_SUCCESS;
             rc = mdbx_cursor_get(cur.cur, &k, &v, MDBX_NEXT)) {
            Bytes full_key(1, 'C');
            full_key.append(static_cast<const char *>(k.iov_base), k.iov_len);
            const Outpoint expected_op = ParseCoinKey(full_key);
            Coin coin = ParseCoin(BytesView(static_cast<const char *>(v.iov_base), v.iov_len));
            Require(coin.outpoint == expected_op, "exported coin key mismatch");
            coins.push_back(std::move(coin));
        }
        std::sort(coins.begin(), coins.end(), [](const Coin &a, const Coin &b) {
            return OutpointKey(a.outpoint) < OutpointKey(b.outpoint);
        });
        UtxoSet verify_set;
        for (const Coin &c : coins) {
            Require(verify_set.Insert(c), "duplicate or invalid coin in store export");
        }
        Require(verify_set.Root() == impl_->head.root.digest, "exported coins root mismatch");
        out = std::move(coins);
    });
}
bool DiskStateStore::ImportFastSyncPivot(const DiskStateMetadata &pivot_metadata,
                                         const Header &pivot_header,
                                         const std::vector<Coin> &verified_coins,
                                         DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        impl_->Ordinary();
        if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        impl_->CheckCachedHead();
        if (impl_->head.root.kind != 0 || impl_->head.metadata != DiskStateMetadata{}) {
            Fail(DiskStateErrorCode::TransactionAborted, "fast-sync pivot import requires uninitialized store");
        }
        Hash pivot_id;
        Require(HeaderBytes(pivot_header) == Bytes(pivot_metadata.header.begin(), pivot_metadata.header.end()) &&
                BlockId(impl_->options.identity, pivot_header, pivot_id) &&
                pivot_id == pivot_metadata.tip,
                "pivot header/metadata binding");
        DiskStateTransaction::Impl tx(impl_);
        for (const Coin &coin : verified_coins) {
            const Bytes bytes = CoinBytes(coin);
            tx.head.root = tx.InsertAt(Path{}, tx.head.root, Leaf(coin));
            tx.Set(CoinKey(coin.outpoint), bytes);
        }
        MonetaryState mon;
        try {
            mon = DecodeMonetaryState(pivot_metadata.monetary);
        } catch (const std::exception &e) {
            Fail(DiskStateErrorCode::Corruption, e.what());
        }
        tx.FlushNodes();
        Require(StateRoot(impl_->options.identity, pivot_header.height, tx.head.root.digest, mon) ==
                pivot_header.state_root,
                "pivot state_root mismatch");
        Head next_head = tx.head;
        next_head.metadata = pivot_metadata;
        const Bytes after = EncodeHead(next_head, impl_->options);
        auto stats = tx.Stats();
        MdbxWriteBatch batch;
        if (auto body = ExtractBlockBodyFromMetadata(pivot_metadata)) {
            batch.block_body_write = std::pair{pivot_metadata.tip, std::move(*body)};
        }
        for (const auto &[key, change] : tx.changes) AddBatch(batch, key, change.after, stats);
        AddBatch(batch, "S", after, stats);
        AddBatch(batch, "V", StorageSchema(impl_->options), stats);
        if (impl_->options.header_index) {
            std::vector<std::pair<Hash, IndexedHeader>> chain;
            Hash cur_id = pivot_id;
            while (true) {
                auto entry = impl_->CheckedHeader(cur_id);
                if (!entry) Fail(DiskStateErrorCode::Missing, "missing checked header in pivot ancestry");
                entry->stage = HeaderStage::Connected;
                chain.emplace_back(cur_id, *entry);
                if (entry->header.height == 0) break;
                cur_id = entry->header.prev_id;
            }
            for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
                impl_->CandidateConnect(it->first, it->second, batch, stats);
                AddBatch(batch, HeaderKey(it->first), EncodeIndexedHeader(it->second), stats);
                AddBatch(batch, ActiveKey(it->second.header.height), HashBytes(it->first), stats);
            }
            AddBatch(batch, "I", EncodeActiveIndex(ActiveFrom(pivot_id, chain.front().second)), stats);
        }
        impl_->Write(batch);
        impl_->head = std::move(next_head);
        impl_->stats = stats;
        tx.End();
    });
}
bool DiskStateStore::PeelBlockStateReverse(
    const Hash &expected_tip_h, const DiskStateMetadata &parent_metadata,
    const Header &parent_header,
    const std::vector<Outpoint> &net_created_to_erase,
    const std::vector<Coin> &prior_spent_to_insert, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        impl_->Ordinary();
        if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        impl_->CheckCachedHead();
        if (impl_->head.metadata.tip != expected_tip_h) {
            Fail(DiskStateErrorCode::UndoMismatch, "reverse peel tip mismatch");
        }
        if ((impl_->pruned_horizon_tip && expected_tip_h == *impl_->pruned_horizon_tip) ||
            (impl_->pruned_horizon_height > 0 &&
             parent_header.height < impl_->pruned_horizon_height)) {
            Fail(DiskStateErrorCode::UndoMismatch,
                 "cannot reverse-peel past pruned finality horizon");
        }
        Hash parent_id{};
        Require(HeaderBytes(parent_header) == Bytes(parent_metadata.header.begin(), parent_metadata.header.end()) &&
                BlockId(impl_->options.identity, parent_header, parent_id) &&
                parent_id == parent_metadata.tip,
                "reverse peel parent header/metadata binding");
        DiskStateTransaction::Impl tx(impl_);
        for (const Outpoint &op : net_created_to_erase) {
            const Hash key = OutpointKey(op);
            bool existing = false;
            tx.AuthCheckCoin(op, key, existing);
            if (!existing) Fail(DiskStateErrorCode::Missing, "reverse peel missing created coin");
            tx.head.root = tx.EraseAt(Path{}, tx.head.root, op, key);
            tx.Set(CoinKey(op), std::nullopt);
        }
        for (const Coin &coin : prior_spent_to_insert) {
            Node leaf = Leaf(coin);
            bool existing = false;
            tx.AuthCheckCoin(coin.outpoint, leaf.coin_outpoint_key, existing);
            if (existing) Fail(DiskStateErrorCode::Duplicate, "reverse peel prior spent coin already present");
            Bytes bytes = leaf.coin_bytes;
            tx.head.root = tx.InsertAt(Path{}, tx.head.root, leaf);
            tx.Set(CoinKey(coin.outpoint), std::move(bytes));
        }
        MonetaryState parent_mon{};
        try {
            parent_mon = DecodeMonetaryState(parent_metadata.monetary);
        } catch (const std::exception &e) {
            Fail(DiskStateErrorCode::Corruption, e.what());
        }
        tx.FlushNodes();
        if (StateRoot(impl_->options.identity, parent_header.height, tx.head.root.digest, parent_mon) !=
            parent_header.state_root) {
            Fail(DiskStateErrorCode::UndoMismatch, "reverse peel parent state_root mismatch");
        }
        Head next_head = tx.head;
        next_head.metadata = parent_metadata;
        const Bytes after = EncodeHead(next_head, impl_->options);
        auto stats = tx.Stats();
        MdbxWriteBatch batch;
        if (auto body = ExtractBlockBodyFromMetadata(parent_metadata)) {
            batch.block_body_write = std::pair{parent_metadata.tip, std::move(*body)};
        }
        for (const auto &[key, change] : tx.changes) AddBatch(batch, key, change.after, stats);
        AddBatch(batch, "S", after, stats);
        AddBatch(batch, "V", StorageSchema(impl_->options), stats);
        impl_->Write(batch);
        impl_->head = std::move(next_head);
        impl_->stats = stats;
        tx.End();
    });
}
uint64_t DiskStateStore::PrunedUndoHorizonHeight() const {
    return impl_ ? impl_->pruned_horizon_height : 0;
}
bool DiskStateStore::PruneFinalizedUndoHorizon(
    uint64_t finalized_tip_height,
    uint64_t keep_recent_blocks,
    DiskStateError &error,
    uint64_t *pruned_count_out) {
    if (pruned_count_out) {
        *pruned_count_out = 0;
    }
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        impl_->Ordinary();
        if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        impl_->CheckCachedHead();

        if (finalized_tip_height <= keep_recent_blocks) {
            return;
        }
        const uint64_t cutoff_height = finalized_tip_height - keep_recent_blocks;
        std::set<Hash> to_prune;
        std::optional<Hash> horizon_tip = impl_->pruned_horizon_tip;

        if (impl_->options.header_index) {
            const auto active = impl_->CheckedActive();
            if (active && finalized_tip_height > active->height) {
                Fail(DiskStateErrorCode::UndoMismatch,
                     "finalized tip height exceeds active chain height");
            }
            if (active && cutoff_height <= active->height) {
                if (const Value hv = impl_->Read(ActiveKey(cutoff_height))) {
                    horizon_tip = ParseHash(*hv);
                }
            }
            for (uint64_t h = 1; h <= cutoff_height; ++h) {
                if (const Value v = impl_->Read(ActiveKey(h))) {
                    to_prune.insert(ParseHash(*v));
                }
            }
            MDBX_txn *rtxn = impl_->EnsureReadTxn();
            MdbxCursorGuard cur;
            CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_undo_locs, &cur.cur),
                      "mdbx_cursor_open(prune_undo)");
            MDBX_val k{}, v{};
            for (int rc = mdbx_cursor_get(cur.cur, &k, &v, MDBX_FIRST);
                 rc == MDBX_SUCCESS;
                 rc = mdbx_cursor_get(cur.cur, &k, &v, MDBX_NEXT)) {
                if (k.iov_len == 32) {
                    Hash id{};
                    std::memcpy(id.data(), k.iov_base, 32);
                    if (const auto hdr = impl_->CheckedHeader(id)) {
                        if (hdr->header.height <= cutoff_height) {
                            to_prune.insert(id);
                        }
                    }
                }
            }
        } else {
            Hash cur_tip = impl_->head.metadata.tip;
            uint64_t cur_h = finalized_tip_height;
            while (cur_h > 0) {
                if (cur_h <= cutoff_height) {
                    if (cur_h == cutoff_height) {
                        horizon_tip = cur_tip;
                    }
                    if (impl_->RawLocation(impl_->dbi_undo_locs, cur_tip)) {
                        to_prune.insert(cur_tip);
                    }
                }
                const Value u_bytes = impl_->Read(UndoKey(cur_tip));
                if (!u_bytes) {
                    break;
                }
                Reader r{*u_bytes};
                const Head before = ParseHead(r.BlobView(), impl_->options);
                cur_tip = before.metadata.tip;
                --cur_h;
            }
        }

        MdbxWriteBatch batch;
        DiskStateStats stats;
        uint64_t pruned_count = 0;
        for (const Hash &id : to_prune) {
            if (impl_->RawLocation(impl_->dbi_undo_locs, id)) {
                AddBatch(batch, UndoKey(id), std::nullopt, stats);
                ++pruned_count;
            }
        }

        const uint64_t next_horizon_height =
            std::max(impl_->pruned_horizon_height, cutoff_height);
        Bytes hp;
        hp.reserve(41);
        Put(hp, next_horizon_height, 8);
        Put(hp, horizon_tip.has_value() ? 1 : 0, 1);
        PutHash(hp, horizon_tip.value_or(Hash{}));
        AddBatch(batch, "H_prune", hp, stats);

        impl_->Write(batch);
        impl_->pruned_horizon_height = next_horizon_height;
        impl_->pruned_horizon_tip = horizon_tip;
        impl_->stats = stats;
        if (pruned_count_out) {
            *pruned_count_out = pruned_count;
        }
    });
}
bool DiskStateStore::ReadCoin(const Outpoint &outpoint, std::optional<Coin> &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        ::lotus::v2::AuthReadCoin([&](const Bytes &key) { return impl_->ReadView(key); }, impl_->head, outpoint, out);
    });
}
bool DiskStateStore::Prove(const Outpoint &query, CoinProof &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable(); ::lotus::v2::Prove([&](const Bytes &key) { return impl_->ReadView(key); }, impl_->head, query, out);
    });
}
bool DiskStateStore::PutCheckedHeader(const Header &header, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Indexed(); impl_->Ordinary();
        if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        const uint64_t reads = impl_->stats.database_reads;
        (void)impl_->CheckedActive();
        const IndexedHeader prepared = impl_->PrepareHeader(header, HeaderStage::HeaderChecked);
        Hash id; Require(BlockId(impl_->options.identity, header, id), "checked header identity");
        const auto existing = impl_->CheckedHeader(id);
        if (existing) {
            Require(HeaderBytes(existing->header) == HeaderBytes(header) && existing->chain_work == prepared.chain_work &&
                    existing->max_ancestor_time == prepared.max_ancestor_time, "immutable checked header mismatch");
            return; // Never downgrade Connected, never change active mappings.
        }
        MdbxWriteBatch batch; DiskStateStats stats;
        AddBatch(batch, HeaderKey(id), EncodeIndexedHeader(prepared), stats);
        impl_->CandidateAdmit(id, prepared, batch, stats);
        if (impl_->finalized) {
            const auto parent_policy = impl_->Policy(header.prev_id, impl_->options.max_avalanche_reads);
            if (parent_policy.conflicting_finalized ||
                (header.height <= impl_->finalized->second && id != impl_->finalized->first))
                AddBatch(batch, IdKey('Z', id), Bytes(1, 1), stats);
        }
        stats.database_reads = impl_->stats.database_reads - reads;
        impl_->Write(batch); impl_->stats = stats;
    });
}
bool DiskStateStore::ReadIndexedHeader(const Hash &id, std::optional<IndexedHeader> &out,
                                       DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Indexed(); impl_->CheckCachedHead();
        auto entry = impl_->CheckedHeader(id); out = std::move(entry);
    });
}
bool DiskStateStore::ReadActiveIndex(std::optional<ActiveChainIndex> &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        auto index = impl_->CheckedActive(); out = std::move(index);
    });
}
bool DiskStateStore::ReadActiveId(uint64_t height, std::optional<Hash> &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        const auto index = impl_->CheckedActive();
        if (!index || height > index->height) { out.reset(); return; }
        const Value value = impl_->Read(ActiveKey(height)); Require(value.has_value(), "missing active height");
        const Hash id = ParseHash(*value); const auto entry = impl_->CheckedHeader(id);
        Require(entry && entry->stage == HeaderStage::Connected && entry->header.height == height,
                "active height/header mismatch");
        if (height) {
            const Value parent = impl_->Read(ActiveKey(height - 1));
            Require(parent && ParseHash(*parent) == entry->header.prev_id, "active height parent mismatch");
        }
        out = id;
    });
}
bool DiskStateStore::ReadRecoveryJournal(size_t max_bytes, std::optional<std::vector<uint8_t>> &out,
                                         DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        const auto record = impl_->Journal(max_bytes);
        if (!record) { out.reset(); return; }
        out = std::vector<uint8_t>(record->payload.begin(), record->payload.end());
    });
}
bool DiskStateStore::WriteRecoveryJournal(const DiskRecoveryUpdate &update, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Recovery();
        if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        const uint64_t reads_before = impl_->stats.database_reads;
        impl_->RecoveryFence(update, false);
        if (impl_->options.candidates && !update.next_journal)
            Fail(DiskStateErrorCode::TransactionAborted, "V4 terminal requires durable candidate receipt");
        if (impl_->options.candidates && !update.expected_journal &&
            impl_->Counters().roots >= impl_->options.candidates->max_invalid_roots)
            Fail(DiskStateErrorCode::Resource, "invalid root receipt reservation exhausted");
        Require(update.next_tip == impl_->head.metadata.tip, "journal-only update must retain active tip");
        MdbxWriteBatch batch; DiskStateStats stats;
        if (update.next_journal)
            AddBatch(batch, "J", EncodeJournal(*update.next_journal, impl_->head,
                     impl_->options.recovery->max_journal_bytes), stats);
        else AddBatch(batch, "J", std::nullopt, stats);
        stats.database_reads = impl_->stats.database_reads - reads_before;
        impl_->Write(batch); impl_->stats = stats;
    });
}
bool DiskStateStore::BeginRecovery(const DiskRecoveryUpdate &update, DiskStateTransaction &out,
                                   DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Recovery();
        if (impl_->active || out.impl_) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        impl_->RecoveryFence(update, true);
        auto transaction = std::make_unique<DiskStateTransaction::Impl>(impl_);
        transaction->recovery_update = update;
        out.impl_ = std::move(transaction); impl_->active = true;
    });
}
bool DiskStateStore::ProbeRecoveryUndo(const Hash &id, size_t max_bytes,
                                       std::optional<DiskRecoveryUndoInfo> &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Recovery(); impl_->CheckCachedHead();
        const Value bytes = impl_->ReadBounded(UndoKey(id), max_bytes);
        if (!bytes) { out.reset(); return; }
        Reader r{*bytes}; const Head before = ParseHead(r.BlobView(), impl_->options);
        const Head after = ParseHead(r.BlobView(), impl_->options);
        Require(after.metadata.tip == id && after.metadata.tip != before.metadata.tip, "recovery undo identity");
        const uint64_t count = r.Int(); Require(count <= bytes->size() / 10, "recovery undo count");
        Bytes previous;
        for (uint64_t i = 0; i < count; ++i) {
            const Bytes key = r.Blob(37);
            Require((key.size() == 37 && key[0] == 'C') || (key.size() == 35 && key[0] == 'N'), "recovery undo key");
            Require(previous.empty() || key > previous, "recovery undo ordering"); previous = key;
            const Value old_value = GetValue(r), next_value = GetValue(r);
            Require(old_value != next_value, "recovery undo no-op row");
            ValidateRetainedValue(key, old_value); ValidateRetainedValue(key, next_value);
        }
        r.End();
        out = DiskRecoveryUndoInfo{uint64_t(bytes->size()), UndoFingerprint(*bytes), before.metadata.tip,
                                  after.metadata.tip, before.root.digest, after.root.digest};
    });
}
bool DiskStateStore::Begin(DiskStateTransaction &out, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable(); impl_->Ordinary();
        if (impl_->active || out.impl_) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        out.impl_ = std::make_unique<DiskStateTransaction::Impl>(impl_); impl_->active = true;
    });
}
bool DiskStateStore::PrefetchOutpointsAsync(
    std::span<const Outpoint> outpoints,
    DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        if (outpoints.empty()) {
            return;
        }

        std::vector<Bytes> coin_subkeys;
        std::vector<Bytes> smt_prefixes;
        coin_subkeys.reserve(outpoints.size());
        smt_prefixes.reserve(outpoints.size());

        for (const Outpoint &op : outpoints) {
            Bytes ck = CoinKey(op).substr(1);
            coin_subkeys.push_back(std::move(ck));

            const Hash lkey = OutpointKey(op);
            Bytes nk;
            nk.reserve(34);
            for (uint8_t b : lkey) {
                nk.push_back(static_cast<char>(ReverseByte(b)));
            }
            Put(nk, 0, 2);
            smt_prefixes.push_back(std::move(nk));
        }

        std::sort(coin_subkeys.begin(), coin_subkeys.end());
        coin_subkeys.erase(
            std::unique(coin_subkeys.begin(), coin_subkeys.end()),
            coin_subkeys.end());

        std::sort(smt_prefixes.begin(), smt_prefixes.end());
        smt_prefixes.erase(
            std::unique(smt_prefixes.begin(), smt_prefixes.end()),
            smt_prefixes.end());

        MDBX_txn *rtxn = impl_->EnsureReadTxn();
        constexpr uintptr_t kPageMask = ~uintptr_t(4095);

        auto madvise_val = [](const MDBX_val &val,
                              uintptr_t &last_page) noexcept {
            if (!val.iov_base || val.iov_len == 0) {
                return;
            }
            const uintptr_t addr = reinterpret_cast<uintptr_t>(val.iov_base);
            const uintptr_t page_base = addr & kPageMask;
            if (page_base != last_page) {
                const size_t span =
                    ((addr - page_base) + val.iov_len + 4095u) & ~size_t(4095u);
                (void)::posix_madvise(reinterpret_cast<void *>(page_base), span,
                                      POSIX_MADV_WILLNEED);
                last_page = page_base;
            }
        };

        {
            MdbxCursorGuard cur;
            CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_coins, &cur.cur),
                      "mdbx_cursor_open(prefetch_coins)");
            uintptr_t last_page = 0;
            for (const Bytes &sk : coin_subkeys) {
                MDBX_val k{const_cast<char *>(sk.data()), sk.size()};
                MDBX_val v{};
                const int rc =
                    mdbx_cursor_get(cur.cur, &k, &v, MDBX_SET_RANGE);
                if (rc == MDBX_SUCCESS) {
                    madvise_val(k, last_page);
                    madvise_val(v, last_page);
                }
            }
        }

        {
            MdbxCursorGuard cur;
            CheckMdbx(mdbx_cursor_open(rtxn, impl_->dbi_smt_nodes, &cur.cur),
                      "mdbx_cursor_open(prefetch_smt)");
            uintptr_t last_page = 0;
            for (const Bytes &nk : smt_prefixes) {
                MDBX_val k{const_cast<char *>(nk.data()), nk.size()};
                MDBX_val v{};
                const int rc =
                    mdbx_cursor_get(cur.cur, &k, &v, MDBX_SET_RANGE);
                if (rc == MDBX_SUCCESS) {
                    madvise_val(k, last_page);
                    madvise_val(v, last_page);
                }
            }
        }
    });
}
bool DiskStateStore::CommitFinalizedOverlay(
    const MempoolOverlayLayer &overlay,
    const std::vector<Coin> &coinbase_coins,
    const DiskStateMetadata &next,
    DiskStateError &error) {
    const auto erased = overlay.GetNetErasedOutpoints();
    if (erased.size() >= 8) {
        (void)PrefetchOutpointsAsync(erased, error);
    }
    DiskStateTransaction txn;
    if (!Begin(txn, error)) {
        return false;
    }
    for (const auto &op : erased) {
        if (!txn.Erase(op, error)) {
            txn.Abort();
            return false;
        }
    }
    for (const auto &coin : overlay.GetNetInsertedCoins()) {
        if (!txn.Insert(coin, error)) {
            txn.Abort();
            return false;
        }
    }
    for (const auto &cb_coin : coinbase_coins) {
        if (!txn.Insert(cb_coin, error)) {
            txn.Abort();
            return false;
        }
    }
    return txn.Commit(next, error);
}
bool DiskStateStore::CommitFinalizedOverlay(
    const MempoolOverlayLayer &overlay,
    const std::vector<Coin> &coinbase_coins,
    const DiskStateMetadata &next,
    const Header &fully_connected,
    DiskStateError &error) {
    const auto erased = overlay.GetNetErasedOutpoints();
    if (erased.size() >= 8) {
        (void)PrefetchOutpointsAsync(erased, error);
    }
    DiskStateTransaction txn;
    if (!Begin(txn, error)) {
        return false;
    }
    for (const auto &op : erased) {
        if (!txn.Erase(op, error)) {
            txn.Abort();
            return false;
        }
    }
    for (const auto &coin : overlay.GetNetInsertedCoins()) {
        if (!txn.Insert(coin, error)) {
            txn.Abort();
            return false;
        }
    }
    for (const auto &cb_coin : coinbase_coins) {
        if (!txn.Insert(cb_coin, error)) {
            txn.Abort();
            return false;
        }
    }
    return txn.Commit(next, fully_connected, error);
}
Hash DiskStateTransaction::Root() const {
    if (!impl_) return EmptyUtxoRoot();
    impl_->EnsureBranchDigests();
    return impl_->head.root.digest;
}
DiskStateStats DiskStateTransaction::Stats() const { return impl_ ? impl_->Stats() : DiskStateStats{}; }
bool DiskStateTransaction::ReadCoin(const Outpoint &outpoint, std::optional<Coin> &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed transaction");
        impl_->FlushNodes();
        ::lotus::v2::AuthReadCoin([&](const Bytes &key) { return impl_->ReadView(key); }, impl_->head, outpoint, out);
    });
}
bool DiskStateTransaction::Prove(const Outpoint &query, CoinProof &out, DiskStateError &error) const {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed transaction");
        impl_->Usable();
        impl_->FlushNodes();
        ::lotus::v2::Prove([&](const Bytes &key) { return impl_->ReadView(key); }, impl_->head, query, out);
    });
}
bool DiskStateTransaction::Insert(const Coin &coin, DiskStateError &error) {
    const bool ok = Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed transaction");
        impl_->Usable();
        Node leaf = Leaf(coin);
        bool existing = false;
        impl_->AuthCheckCoin(coin.outpoint, leaf.coin_outpoint_key, existing);
        if (existing) Fail(DiskStateErrorCode::Duplicate, "duplicate coin");
        Bytes bytes = leaf.coin_bytes;
        impl_->head.root = impl_->InsertAt(Path{}, impl_->head.root, leaf);
        impl_->Set(CoinKey(coin.outpoint), std::move(bytes));
    });
    if (!ok && impl_ && error.code != DiskStateErrorCode::Duplicate && error.code != DiskStateErrorCode::InvalidCoin)
        impl_->failed = true;
    return ok;
}
bool DiskStateTransaction::Erase(const Outpoint &outpoint, DiskStateError &error) {
    const bool ok = Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed transaction");
        impl_->Usable();
        const Hash key = OutpointKey(outpoint);
        bool existing = false;
        impl_->AuthCheckCoin(outpoint, key, existing);
        if (!existing) Fail(DiskStateErrorCode::Missing, "missing coin");
        impl_->head.root = impl_->EraseAt(Path{}, impl_->head.root, outpoint, key);
        impl_->Set(CoinKey(outpoint), std::nullopt);
    });
    if (!ok && impl_ && error.code != DiskStateErrorCode::Missing) impl_->failed = true;
    return ok;
}
void DiskStateTransaction::Abort() { impl_.reset(); }
bool DiskStateTransaction::Commit(const DiskStateMetadata &next, DiskStateError &error) {
    return CommitImpl(next, nullptr, error);
}
bool DiskStateTransaction::Commit(const DiskStateMetadata &next, const Header &fully_connected,
                                  DiskStateError &error) {
    return CommitImpl(next, &fully_connected, error);
}
bool DiskStateTransaction::CommitImpl(const DiskStateMetadata &next, const Header *fully_connected,
                                      DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed transaction");
        impl_->Usable();
        impl_->FlushNodes();
        auto &store = *impl_->store;
        const uint64_t commit_reads_before = store.stats.database_reads;
        if (impl_->recovery_update) {
            store.RecoveryFence(*impl_->recovery_update, true);
            Require(next.tip == impl_->recovery_update->next_tip, "recovery connected tip fence");
        } else store.Ordinary();
        if (next.tip == store.head.metadata.tip) Fail(DiskStateErrorCode::UndoMismatch, "commit must advance tip identity");
        if (fully_connected) {
            Hash id;
            Require(HeaderBytes(*fully_connected) == Bytes(next.header.begin(), next.header.end()) &&
                    BlockId(store.options.identity, *fully_connected, id) && id == next.tip,
                    "connected header/metadata binding");
        }
        std::optional<IndexedHeader> prepared;
        if (store.options.header_index) {
            if (!fully_connected) Fail(DiskStateErrorCode::ProfileMismatch, "indexed commit requires connected header");
            const auto active = store.CheckedActive();
            if (active) {
                Require(active->height != std::numeric_limits<uint64_t>::max() &&
                        fully_connected->height == active->height + 1 && fully_connected->prev_id == active->tip,
                        "connected header does not extend active index");
            } else Require(fully_connected->height == 0 && next.tip == store.options.header_index->genesis_id,
                           "first indexed commit must be configured genesis");
            prepared = store.PrepareHeader(*fully_connected, HeaderStage::Connected);
            const auto existing = store.CheckedHeader(next.tip);
            if (existing)
                Require(HeaderBytes(existing->header) == HeaderBytes(*fully_connected) &&
                        existing->chain_work == prepared->chain_work &&
                        existing->max_ancestor_time == prepared->max_ancestor_time, "connected immutable header mismatch");
            Require(!store.Read(ActiveKey(fully_connected->height)), "occupied next active height");
        }
        Head next_head = impl_->head; next_head.metadata = next;
        CheckUndoCreationSize(store.options, store.head, next_head, impl_->changes);
        const Bytes before = EncodeHead(store.head, store.options), after = EncodeHead(next_head, store.options);
        const Bytes undo = EncodeUndo(before, after, impl_->changes);
        const Bytes undo_key = UndoKey(next.tip);
        const Value prior = store.Read(undo_key);
        if (prior && *prior != undo) Fail(DiskStateErrorCode::UndoMismatch, "immutable undo differs for existing tip");
        auto stats = impl_->Stats();
        const uint64_t staged_reads = stats.database_reads;
        MdbxWriteBatch batch;
        if (auto body = ExtractBlockBodyFromMetadata(next)) {
            batch.block_body_write = std::pair{next.tip, std::move(*body)};
        }
        for (const auto &[key, change] : impl_->changes) AddBatch(batch, key, change.after, stats);
        AddBatch(batch, "S", after, stats); AddBatch(batch, "V", StorageSchema(store.options), stats);
        if (!prior) AddBatch(batch, undo_key, undo, stats);
        if (prepared) {
            store.CandidateConnect(next.tip, *prepared, batch, stats);
            AddBatch(batch, HeaderKey(next.tip), EncodeIndexedHeader(*prepared), stats);
            AddBatch(batch, ActiveKey(prepared->header.height), HashBytes(next.tip), stats);
            AddBatch(batch, "I", EncodeActiveIndex(ActiveFrom(next.tip, *prepared)), stats);
        }
        if (impl_->recovery_update)
            AddBatch(batch, "J", EncodeJournal(*impl_->recovery_update->next_journal, next_head,
                     store.options.recovery->max_journal_bytes), stats);
        stats.database_reads = staged_reads + store.stats.database_reads - commit_reads_before;
        store.Write(batch); store.head = std::move(next_head); store.stats = stats; impl_->End();
    });
}
bool DiskStateStore::Disconnect(const Hash &expected_tip, DiskStateError &error) {
    return Disconnect(expected_tip, DiskStateMetadataValidator{}, error);
}
bool DiskStateStore::Disconnect(const Hash &expected_tip, const DiskStateMetadataValidator &validate,
                                DiskStateError &error) {
    return DisconnectImpl(expected_tip, validate, nullptr, error);
}
bool DiskStateStore::DisconnectRecovery(const Hash &expected_tip, const DiskStateMetadataValidator &validate,
                                        const DiskRecoveryUpdate &update, DiskStateError &error) {
    return DisconnectImpl(expected_tip, validate, &update, error);
}
bool DiskStateStore::DisconnectImpl(const Hash &expected_tip, const DiskStateMetadataValidator &validate,
                                    const DiskRecoveryUpdate *recovery, DiskStateError &error) {
    return Guard(error, [&] {
        if (!impl_) Fail(DiskStateErrorCode::Closed, "closed store");
        impl_->Usable();
        if (impl_->active) Fail(DiskStateErrorCode::TransactionAborted, "active transaction");
        if (recovery) {
            impl_->RecoveryFence(*recovery, true);
            Require(recovery->expected_tip == expected_tip, "recovery disconnect tip fence");
        } else impl_->Ordinary();
        if (impl_->head.metadata.tip != expected_tip) Fail(DiskStateErrorCode::UndoMismatch, "disconnect tip mismatch");
        const uint64_t reads_before = impl_->stats.database_reads;
        std::optional<ActiveChainIndex> indexed_active;
        if (impl_->options.header_index) {
            indexed_active = impl_->CheckedActive();
            Require(indexed_active && indexed_active->tip == expected_tip, "indexed disconnect active tip");
            if (indexed_active->height == 0) Fail(DiskStateErrorCode::UndoMismatch, "cannot disconnect indexed genesis");
        }
        if ((impl_->pruned_horizon_tip && expected_tip == *impl_->pruned_horizon_tip) ||
            (indexed_active && indexed_active->height <= impl_->pruned_horizon_height)) {
            Fail(DiskStateErrorCode::Missing, "cannot disconnect past pruned finality horizon");
        }
        const Value undo = impl_->Read(UndoKey(expected_tip));
        if (!undo) Fail(DiskStateErrorCode::Missing, "missing undo");
        if (recovery && recovery->expected_undo_digest)
            Require(UndoFingerprint(*undo) == *recovery->expected_undo_digest, "pinned recovery undo digest mismatch");
        Reader r{*undo}; const BytesView before_view = r.BlobView(), after_view = r.BlobView();
        Require(after_view == EncodeHead(impl_->head, impl_->options), "undo successor mismatch");
        Head previous = ParseHead(before_view, impl_->options);
        const Bytes before(before_view.data(), before_view.size());
        if (recovery) Require(previous.metadata.tip == recovery->next_tip, "recovery restored tip fence");
        std::optional<ActiveChainIndex> indexed_previous;
        if (indexed_active) {
            const auto parent = impl_->CheckedHeader(previous.metadata.tip);
            Require(parent && parent->stage == HeaderStage::Connected &&
                    parent->header.height == indexed_active->height - 1 &&
                    HeaderBytes(parent->header) == Bytes(previous.metadata.header.begin(), previous.metadata.header.end()),
                    "indexed undo predecessor binding");
            const auto child = impl_->CheckedHeader(expected_tip);
            Require(child && child->header.prev_id == previous.metadata.tip, "indexed undo parent identity");
            indexed_previous = ActiveFrom(previous.metadata.tip, *parent);
        }
        const uint64_t count = r.Int(); Require(count <= undo->size() / 10, "undo count");
        MdbxWriteBatch batch; DiskStateStats stats;
        std::map<Bytes, Value> restored;
        Bytes previous_key;
        for (uint64_t i = 0; i < count; ++i) {
            const Bytes key = r.Blob(37);
            Require((key.size() == 37 && key[0] == 'C') || (key.size() == 35 && key[0] == 'N'), "undo key");
            Require(previous_key.empty() || key > previous_key, "unordered/duplicate undo key"); previous_key = key;
            const Value old_value = GetValue(r), current_value = GetValue(r);
            Require(impl_->Read(key) == current_value, "undo current value mismatch");
            restored.emplace(key, old_value);
            AddBatch(batch, key, old_value, stats);
            if (key[0] == 'C') ++stats.dirty_coins; else ++stats.dirty_nodes;
        }
        r.End();
        const auto ReadRestored = [&](const Bytes &key) -> ValueView {
            const auto it = restored.find(key);
            if (it != restored.end()) return it->second ? ValueView(*it->second) : std::nullopt;
            return impl_->ReadView(key);
        };
        // Validate the inverse view before publishing any old bytes. This
        // visits the changed paths and immediate siblings, never the full set.
        // ParseHead above checks framing/profile/limits; opaque metadata's
        // semantic agreement with its block belongs to the enclosing validator.
        ValidateRestoredPath(ReadRestored, previous, Path{});
        for (const auto &[key, value] : restored) {
            (void)value;
            if (key[0] == 'C') {
                std::optional<Coin> coin;
                AuthReadCoin(ReadRestored, previous, ParseCoinKey(key), coin);
            } else ValidateRestoredPath(ReadRestored, previous, ParseNodeKey(key));
        }
        if (validate) {
            struct CallbackScope {
                bool &active;
                explicit CallbackScope(bool &flag) : active(flag) { active = true; }
                ~CallbackScope() { active = false; }
            } scope(impl_->active);
            DiskStateError callback_error;
            bool accepted{};
            try { accepted = validate(previous.metadata, previous.root.digest, callback_error); }
            catch (const std::bad_alloc &) { throw; }
            catch (const std::length_error &) { throw; }
            catch (const std::exception &exception) {
                Fail(DiskStateErrorCode::Database, std::string("metadata validation exception: ") + exception.what());
            }
            catch (...) { Fail(DiskStateErrorCode::Database, "metadata validation exception"); }
            if (!accepted) {
                // A callback cannot turn stored-state validation failure into
                // a consensus mutation error, even if it supplies that code.
                auto code = callback_error.code;
                if (code == DiskStateErrorCode::None || code == DiskStateErrorCode::Duplicate ||
                    code == DiskStateErrorCode::Missing || code == DiskStateErrorCode::InvalidCoin)
                    code = DiskStateErrorCode::Corruption;
                Fail(code, callback_error.message.empty() ? "predecessor metadata validation failed"
                                                         : callback_error.message);
            }
        }
        AddBatch(batch, "S", before, stats); AddBatch(batch, "V", StorageSchema(impl_->options), stats);
        if (indexed_active) {
            const auto current = impl_->CheckedHeader(expected_tip); Require(current.has_value(), "missing disconnected inventory header");
            impl_->CandidateDisconnect(expected_tip, *current, batch, stats);
            AddBatch(batch, ActiveKey(indexed_active->height), std::nullopt, stats);
            AddBatch(batch, "I", EncodeActiveIndex(indexed_previous), stats);
        }
        if (recovery)
            AddBatch(batch, "J", EncodeJournal(*recovery->next_journal, previous,
                     impl_->options.recovery->max_journal_bytes), stats);
        // Undo records are immutable and retained across disconnect/reorg.
        stats.database_reads = impl_->stats.database_reads - reads_before;
        impl_->Write(batch); impl_->head = std::move(previous); impl_->stats = stats;
    });
}

bool RawDiskStateAccess(const std::string &directory,
                        const std::optional<std::string> &read_key,
                        std::optional<std::string> *read_out,
                        const std::vector<std::pair<std::string, std::optional<std::string>>> &writes,
                        std::string *error) {
    DiskStateError err;
    const bool ok = Guard(err, [&] {
        DiskStateStore::Impl impl;
        impl.directory = directory;
        OpenMdbxEnvironment(directory, impl.env,
                            impl.dbi_meta, impl.dbi_coins, impl.dbi_smt_nodes,
                            impl.dbi_headers, impl.dbi_active_h, impl.dbi_block_locs,
                            impl.dbi_undo_locs, impl.dbi_candidates, impl.dbi_children,
                            impl.dbi_queue, impl.dbi_excluded, impl.dbi_failures,
                            impl.dbi_parked);
        if (read_key && read_out) {
            *read_out = impl.Read(*read_key);
        }
        if (!writes.empty()) {
            MdbxWriteBatch batch;
            for (const auto &[k, v] : writes) {
                if (v) batch.Put(k, *v);
                else batch.Delete(k);
            }
            impl.Write(batch);
        }
    });
    if (!ok && error) *error = err.message;
    return ok;
}

bool RawDiskStateSnapshot(const std::string &directory,
                          std::map<std::string, std::string> &out,
                          std::string *error) {
    DiskStateError err;
    const bool ok = Guard(err, [&] {
        out.clear();
        DiskStateStore::Impl impl;
        impl.directory = directory;
        OpenMdbxEnvironment(directory, impl.env,
                            impl.dbi_meta, impl.dbi_coins, impl.dbi_smt_nodes,
                            impl.dbi_headers, impl.dbi_active_h, impl.dbi_block_locs,
                            impl.dbi_undo_locs, impl.dbi_candidates, impl.dbi_children,
                            impl.dbi_queue, impl.dbi_excluded, impl.dbi_failures,
                            impl.dbi_parked);
        MDBX_txn *rtxn = impl.EnsureReadTxn();
        auto scan_dbi = [&](MDBX_dbi dbi, char prefix) {
            MdbxCursorGuard cur;
            CheckMdbx(mdbx_cursor_open(rtxn, dbi, &cur.cur), "mdbx_cursor_open(snapshot)");
            MDBX_val k{}, v{};
            for (int rc = mdbx_cursor_get(cur.cur, &k, &v, MDBX_FIRST);
                 rc == MDBX_SUCCESS;
                 rc = mdbx_cursor_get(cur.cur, &k, &v, MDBX_NEXT)) {
                BytesView sk(static_cast<const char *>(k.iov_base), k.iov_len);
                BytesView sv(static_cast<const char *>(v.iov_base), v.iov_len);
                if (prefix == 0) {
                    if (sk == "B_cursor" || sk == "U_cursor" || sk == "H_prune") continue;
                    if (sk == "S") {
                        out[Bytes(sk)] = ExpandCompactHeadBytes(sv, [&](const DiskBlockLocation &loc) {
                            return impl.ReadFlatSegment(true, loc);
                        });
                    } else {
                        out[Bytes(sk)] = Bytes(sv);
                    }
                } else if (prefix == 'U') {
                    Bytes full_key(1, 'U');
                    full_key.append(sk.data(), sk.size());
                    const DiskUndoLocation loc = ParseLocation(sv);
                    out[std::move(full_key)] = impl.ReadFlatSegment(false, loc);
                } else {
                    Bytes full_key(1, prefix);
                    full_key.append(sk.data(), sk.size());
                    out[std::move(full_key)] = Bytes(sv);
                }
            }
        };
        scan_dbi(impl.dbi_meta, 0);
        scan_dbi(impl.dbi_coins, 'C');
        scan_dbi(impl.dbi_smt_nodes, 'N');
        scan_dbi(impl.dbi_headers, 'H');
        scan_dbi(impl.dbi_active_h, 'A');
        scan_dbi(impl.dbi_undo_locs, 'U');
        scan_dbi(impl.dbi_candidates, 'W');
        scan_dbi(impl.dbi_children, 'X');
        scan_dbi(impl.dbi_queue, 'Q');
        scan_dbi(impl.dbi_excluded, 'E');
        scan_dbi(impl.dbi_failures, 'F');
        scan_dbi(impl.dbi_parked, 'Z');
    });
    if (!ok && error) *error = err.message;
    return ok;
}
} // namespace lotus::v2
