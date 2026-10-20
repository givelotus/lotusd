// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/types.h>

#include <algorithm>

namespace chronik::native::lotus_v2 {

namespace {

/** Rust `Reader`: consumes a byte slice from the front. */
class Reader {
public:
    explicit Reader(ByteView bytes) : m_rest(bytes) {}

    bool Take(size_t n, ByteView &out) {
        if (n > m_rest.size()) {
            return false;
        }
        out = m_rest.first(n);
        m_rest = m_rest.subspan(n);
        return true;
    }
    bool Byte(uint8_t &out) {
        ByteView b;
        if (!Take(1, b)) {
            return false;
        }
        out = b[0];
        return true;
    }
    bool Hash(Hash32 &out) {
        ByteView b;
        if (!Take(32, b)) {
            return false;
        }
        std::copy(b.begin(), b.end(), out.b.begin());
        return true;
    }
    /** Multi-byte CompactSize cannot encode any permitted count minimally. */
    bool Count(uint8_t cap, size_t &out) {
        uint8_t n;
        if (!Byte(n) || n > cap) {
            return false;
        }
        out = n;
        return true;
    }
    size_t Remaining() const { return m_rest.size(); }

private:
    ByteView m_rest;
};

std::optional<Output> Fail(OutputError *error, std::string_view category) {
    if (error) {
        *error = OutputError{category};
    }
    return std::nullopt;
}

} // namespace

std::string OutputError::Message() const {
    return "invalid Lotus V2 output: " + std::string(category);
}

std::optional<OutputError> Output::Validate() const {
    auto fail = [](std::string_view category) {
        return std::optional<OutputError>(OutputError{category});
    };
    if (flags & 0xf8) {
        return fail("flags");
    }
    if (HasState()) {
        if (IsBurn()) {
            return fail("burn state");
        }
        if (state_root == Hash32{}) {
            return fail("zero state root");
        }
    } else if (state_root != Hash32{}) {
        return fail("stateless root field");
    }
    if (HasToken()) {
        if (token_id == Hash32{}) {
            return fail("zero token");
        }
    } else if (token_id != Hash32{}) {
        return fail("native token field");
    }
    if (branches.empty() || branches.size() > 16) {
        return fail("branch count");
    }
    for (size_t i = 0; i < branches.size(); ++i) {
        if (std::find(branches.begin(), branches.begin() + i, branches[i]) !=
            branches.begin() + i) {
            return fail("duplicate branch");
        }
    }
    if (IsBurn()) {
        if (!paths.empty()) {
            return fail("burn paths");
        }
    } else if (paths.empty() || paths.size() > 16) {
        return fail("path count");
    }
    for (size_t p = 0; p < paths.size(); ++p) {
        const std::vector<uint8_t> &path = paths[p];
        if (path.empty() || path.size() > branches.size()) {
            return fail("path length");
        }
        for (size_t i = 0; i < path.size(); ++i) {
            if (path[i] >= branches.size() ||
                (i > 0 && path[i - 1] >= path[i])) {
                return fail("path index");
            }
        }
        if (p > 0 && paths[p - 1] >= path) {
            return fail("path order");
        }
    }
    return std::nullopt;
}

std::optional<Bytes> Output::Encode(OutputError *error) const {
    if (auto err = Validate()) {
        if (error) {
            *error = *err;
        }
        return std::nullopt;
    }
    Bytes bytes;
    bytes.reserve(MAX_OUTPUT_BYTES);
    bytes.push_back(flags);
    for (int i = 0; i < 8; ++i) {
        bytes.push_back(uint8_t(value >> (8 * i)));
    }
    if (HasToken()) {
        bytes.insert(bytes.end(), token_id.b.begin(), token_id.b.end());
    }
    if (HasState()) {
        bytes.insert(bytes.end(), state_root.b.begin(), state_root.b.end());
    }
    // All CompactSize fields are bounded below 253, hence one byte.
    bytes.push_back(uint8_t(branches.size()));
    for (const Hash32 &root : branches) {
        bytes.insert(bytes.end(), root.b.begin(), root.b.end());
    }
    bytes.push_back(uint8_t(paths.size()));
    for (const std::vector<uint8_t> &path : paths) {
        bytes.push_back(uint8_t(path.size()));
        bytes.insert(bytes.end(), path.begin(), path.end());
    }
    if (bytes.size() > MAX_OUTPUT_BYTES) {
        if (error) {
            *error = OutputError{"output bytes"};
        }
        return std::nullopt;
    }
    return bytes;
}

std::optional<Output> Output::Decode(ByteView bytes, OutputError *error) {
    if (bytes.size() > MAX_OUTPUT_BYTES) {
        return Fail(error, "output bytes");
    }
    Reader r(bytes);
    Output output;
    if (!r.Byte(output.flags)) {
        return Fail(error, "truncated flags");
    }
    if (output.flags & 0xf8) {
        return Fail(error, "flags");
    }
    ByteView value;
    if (!r.Take(8, value)) {
        return Fail(error, "truncated value");
    }
    for (int i = 0; i < 8; ++i) {
        output.value |= uint64_t(value[i]) << (8 * i);
    }
    if ((output.flags & 1) && !r.Hash(output.token_id)) {
        return Fail(error, "truncated token");
    }
    if ((output.flags & 4) && !r.Hash(output.state_root)) {
        return Fail(error, "truncated state root");
    }
    size_t n;
    if (!r.Count(16, n)) {
        return Fail(error, "branch count");
    }
    if (n > r.Remaining() / 32) {
        return Fail(error, "truncated branches");
    }
    output.branches.resize(n);
    for (Hash32 &branch : output.branches) {
        if (!r.Hash(branch)) {
            return Fail(error, "truncated branches");
        }
    }
    if (!r.Count(16, n)) {
        return Fail(error, "path count");
    }
    if (n > r.Remaining()) {
        return Fail(error, "truncated paths");
    }
    output.paths.reserve(n);
    for (size_t p = 0; p < n; ++p) {
        size_t length;
        if (!r.Count(16, length)) {
            return Fail(error, "path length");
        }
        if (length > r.Remaining()) {
            return Fail(error, "truncated path");
        }
        std::vector<uint8_t> path;
        path.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            size_t idx;
            if (!r.Count(15, idx)) {
                return Fail(error, "path index");
            }
            path.push_back(uint8_t(idx));
        }
        output.paths.push_back(std::move(path));
    }
    if (r.Remaining() != 0) {
        return Fail(error, "trailing bytes");
    }
    if (auto err = output.Validate()) {
        return Fail(error, err->category);
    }
    return output;
}

} // namespace chronik::native::lotus_v2
