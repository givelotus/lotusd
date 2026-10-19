#include "output.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace lotus::v2 {
namespace {

    class Reader {
    public:
        explicit Reader(const std::vector<uint8_t> &bytes) : bytes_(bytes) {}

        size_t Remaining() const { return bytes_.size() - offset_; }
        bool Finished() const { return Remaining() == 0; }

        bool Take(size_t count, const uint8_t *&start) {
            if (count > Remaining()) return false;
            start = bytes_.data() + offset_;
            offset_ += count;
            return true;
        }

        bool Integer(size_t width, uint64_t &value) {
            if (width == 0 || width > 8) return false;
            const uint8_t *start = nullptr;
            if (!Take(width, start)) return false;
            value = 0;
            for (size_t i = 0; i < width; ++i)
                value |= uint64_t(start[i]) << (8 * i);
            return true;
        }

        bool CompactSize(uint64_t cap, uint64_t &value) {
            uint64_t lead;
            if (!Integer(1, lead)) return false;
            if (lead < 253)
                value = lead;
            else {
                size_t width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
                if (!Integer(width, value)) return false;
                if (value < (width == 2   ? 253ULL
                             : width == 4 ? 65536ULL
                                          : 4294967296ULL))
                    return false;
            }
            return value <= cap;
        }

    private:
        const std::vector<uint8_t> &bytes_;
        size_t offset_ = 0;
    };

    void AppendInteger(uint64_t value, size_t width,
                       std::vector<uint8_t> &out) {
        for (size_t i = 0; i < width; ++i)
            out.push_back(uint8_t(value >> (8 * i)));
    }

    void AppendCompactSize(uint64_t value, std::vector<uint8_t> &out) {
        if (value < 253)
            AppendInteger(value, 1, out);
        else if (value <= 65535) {
            out.push_back(253);
            AppendInteger(value, 2, out);
        } else if (value <= 4294967295ULL) {
            out.push_back(254);
            AppendInteger(value, 4, out);
        } else {
            out.push_back(255);
            AppendInteger(value, 8, out);
        }
    }

    bool Valid(const Output &output, std::string &error) {
        if (output.legacy_script) { error = "legacy state output is not a V2 transaction output"; return false; }
        if ((output.flags & 0xf8) || (output.HasState() && output.IsBurn())) {
            error = "flags";
            return false;
        }
        if (output.HasState()) {
            if (output.state_root == Hash32{}) {
                error = "zero state root";
                return false;
            }
        } else if (output.state_root != Hash32{}) {
            error = "absent state root";
            return false;
        }
        if (output.HasToken()) {
            if (output.token_id == Hash32{}) {
                error = "zero token";
                return false;
            }
        } else if (output.token_id != Hash32{}) {
            error = "native token field";
            return false;
        }
        if (output.branches.empty() ||
            output.branches.size() > MAX_OUTPUT_BRANCHES) {
            error = "branch count";
            return false;
        }
        for (size_t i = 0; i < output.branches.size(); ++i) {
            for (size_t j = 0; j < i; ++j) {
                if (output.branches[i] == output.branches[j]) {
                    error = "duplicate branch";
                    return false;
                }
            }
        }
        if (output.IsBurn()) {
            if (!output.paths.empty()) {
                error = "burn paths";
                return false;
            }
        } else if (output.paths.empty() ||
                   output.paths.size() > MAX_OUTPUT_PATHS) {
            error = "path count";
            return false;
        }
        for (size_t p = 0; p < output.paths.size(); ++p) {
            const auto &path = output.paths[p];
            if (path.empty() || path.size() > output.branches.size()) {
                error = "path length";
                return false;
            }
            for (size_t i = 0; i < path.size(); ++i) {
                if (path[i] >= output.branches.size() ||
                    (i && path[i - 1] >= path[i])) {
                    error = "path index";
                    return false;
                }
            }
            if (p && !(output.paths[p - 1] < path)) {
                error = "path order";
                return false;
            }
        }
        return true;
    }

} // namespace

bool DecodeOutput(const std::vector<uint8_t> &frame, Output &result,
                  std::string &error) {
    if (frame.size() > MAX_OUTPUT_BYTES) {
        error = "output bytes";
        return false;
    }
    Reader reader(frame);
    Output parsed;
    uint64_t value;
    if (!reader.Integer(1, value)) {
        error = "truncated flags";
        return false;
    }
    parsed.flags = uint8_t(value);
    if (parsed.flags & 0xf8) {
        error = "flags";
        return false;
    }
    if (!reader.Integer(8, parsed.value)) {
        error = "truncated value";
        return false;
    }
    if (parsed.HasToken()) {
        const uint8_t *token;
        if (!reader.Take(32, token)) {
            error = "truncated token";
            return false;
        }
        std::copy_n(token, 32, parsed.token_id.begin());
    }
    if (parsed.HasState()) {
        const uint8_t *root;
        if (!reader.Take(32, root)) {
            error = "truncated state root";
            return false;
        }
        std::copy_n(root, 32, parsed.state_root.begin());
    }
    uint64_t count;
    if (!reader.CompactSize(MAX_OUTPUT_BRANCHES, count)) {
        error = "branch count";
        return false;
    }
    // Division avoids host-width multiplication overflow before reserving
    // storage.
    if (count > reader.Remaining() / 32) {
        error = "truncated branches";
        return false;
    }
    parsed.branches.reserve(size_t(count));
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t *branch;
        if (!reader.Take(32, branch)) {
            error = "truncated branches";
            return false;
        }
        Hash32 root;
        std::copy_n(branch, 32, root.begin());
        parsed.branches.push_back(root);
    }
    if (!reader.CompactSize(MAX_OUTPUT_PATHS, count)) {
        error = "path count";
        return false;
    }
    if (count > reader.Remaining()) {
        error = "truncated paths";
        return false;
    }
    parsed.paths.reserve(size_t(count));
    for (uint64_t p = 0; p < count; ++p) {
        uint64_t length;
        if (!reader.CompactSize(MAX_OUTPUT_BRANCHES, length)) {
            error = "path length";
            return false;
        }
        if (length > reader.Remaining()) {
            error = "truncated path";
            return false;
        }
        std::vector<uint8_t> path;
        path.reserve(size_t(length));
        for (uint64_t i = 0; i < length; ++i) {
            uint64_t index;
            if (!reader.CompactSize(MAX_OUTPUT_BRANCHES - 1, index)) {
                error = "path index";
                return false;
            }
            path.push_back(uint8_t(index));
        }
        parsed.paths.push_back(std::move(path));
    }
    if (!reader.Finished()) {
        error = "trailing bytes";
        return false;
    }
    if (!Valid(parsed, error)) return false;
    result = std::move(parsed);
    error.clear();
    return true;
}

bool ComputeOutputSerializedSize(const Output &output, size_t &size,
                                 std::string &error) {
    if (!Valid(output, error)) return false;
    size_t total = 1 + 8 + (output.HasToken() ? 32 : 0) +
                   (output.HasState() ? 32 : 0) + 1 +
                   output.branches.size() * 32 + 1;
    for (const auto &path : output.paths) {
        total += 1 + path.size();
    }
    if (total > MAX_OUTPUT_BYTES) {
        error = "output bytes";
        return false;
    }
    size = total;
    error.clear();
    return true;
}

bool EncodeOutput(const Output &output, std::vector<uint8_t> &result,
                  std::string &error) {
    size_t exact_size = 0;
    if (!ComputeOutputSerializedSize(output, exact_size, error)) return false;
    result.clear();
    result.reserve(exact_size);
    result.push_back(output.flags);
    AppendInteger(output.value, 8, result);
    if (output.HasToken())
        result.insert(result.end(), output.token_id.begin(),
                      output.token_id.end());
    if (output.HasState())
        result.insert(result.end(), output.state_root.begin(),
                      output.state_root.end());
    AppendCompactSize(output.branches.size(), result);
    for (const auto &branch : output.branches)
        result.insert(result.end(), branch.begin(), branch.end());
    AppendCompactSize(output.paths.size(), result);
    for (const auto &path : output.paths) {
        AppendCompactSize(path.size(), result);
        for (uint8_t index : path)
            AppendCompactSize(index, result);
    }
    error.clear();
    return true;
}

namespace {
bool ValidLegacyCoin(const Output &coin, std::string &error) {
    if (coin.legacy_script->size() > MAX_LEGACY_COIN_SCRIPT_BYTES ||
        coin.flags || coin.token_id != Hash32{} ||
        coin.state_root != Hash32{} || !coin.branches.empty() ||
        !coin.paths.empty()) {
        error = "legacy coin";
        return false;
    }
    return true;
}

size_t CompactSizeBytes(uint64_t value) {
    return value < 253 ? 1 : value <= 65535 ? 3 : value <= 4294967295ULL ? 5 : 9;
}
} // namespace

bool ComputeCoinOutputSerializedSize(const Output &coin, size_t &size,
                                     std::string &error) {
    if (!coin.legacy_script) {
        return ComputeOutputSerializedSize(coin, size, error);
    }
    if (!ValidLegacyCoin(coin, error)) return false;
    const size_t n = coin.legacy_script->size();
    size = 1 + 8 + CompactSizeBytes(n) + n;
    error.clear();
    return true;
}

bool EncodeCoinOutput(const Output &coin, std::vector<uint8_t> &result,
                      std::string &error) {
    if (!coin.legacy_script) {
        return EncodeOutput(coin, result, error);
    }
    if (!ValidLegacyCoin(coin, error)) return false;
    const auto &script = *coin.legacy_script;
    result.clear();
    result.reserve(1 + 8 + CompactSizeBytes(script.size()) + script.size());
    result.push_back(0x80);
    AppendInteger(coin.value, 8, result);
    AppendCompactSize(script.size(), result);
    result.insert(result.end(), script.begin(), script.end());
    error.clear();
    return true;
}

} // namespace lotus::v2
