// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#ifndef LOTUS_V2_PSBT_MAP_H
#define LOTUS_V2_PSBT_MAP_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace lotus::v2::psbt_detail {

using Bytes = std::vector<uint8_t>;
using Map = std::map<Bytes, Bytes>;

// BIP174 maps use canonical CompactSize lengths and byte-string keys. Keep
// unknown keys and values opaque; decoding never normalizes their payloads.
class Reader {
    std::span<const uint8_t> bytes_;
    size_t pos_{};

public:
    explicit Reader(std::span<const uint8_t> bytes) : bytes_(bytes) {}
    size_t Remaining() const { return bytes_.size() - pos_; }
    bool Empty() const { return Remaining() == 0; }

    bool Integer(size_t width, uint64_t &value) {
        if (width > 8 || width > Remaining()) return false;
        value = 0;
        for (size_t i = 0; i < width; ++i) {
            value |= uint64_t(bytes_[pos_++]) << (8 * i);
        }
        return true;
    }

    bool Compact(uint64_t &value) {
        uint64_t lead;
        if (!Integer(1, lead)) return false;
        if (lead < 253) {
            value = lead;
            return true;
        }
        const size_t width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
        return Integer(width, value) && (width == 2   ? value >= 253
                                         : width == 4 ? value > 0xffff
                                                      : value > 0xffffffff);
    }

    bool Blob(size_t count, Bytes &value) {
        if (count > Remaining()) return false;
        value.assign(bytes_.begin() + pos_, bytes_.begin() + pos_ + count);
        pos_ += count;
        return true;
    }

    bool Vector(size_t limit, Bytes &value) {
        uint64_t count;
        return Compact(count) && count <= limit && count <= Remaining() &&
               Blob(static_cast<size_t>(count), value);
    }

    bool ReadMap(Map &result, size_t max_key, size_t max_value,
                 size_t max_entries, std::string &error) {
        Map parsed;
        while (!Empty()) {
            Bytes key;
            if (!Vector(max_key, key)) {
                error = "invalid PSBT key length";
                return false;
            }
            if (key.empty()) {
                result = std::move(parsed);
                error.clear();
                return true;
            }
            // A key's type itself is CompactSize, including unknown types.
            Reader type_reader(key);
            uint64_t type;
            if (!type_reader.Compact(type)) {
                error = "invalid PSBT key type";
                return false;
            }
            Bytes value;
            if (!Vector(max_value, value)) {
                error = "invalid PSBT value length";
                return false;
            }
            if (parsed.size() >= max_entries) {
                error = "too many PSBT map entries";
                return false;
            }
            if (!parsed.emplace(std::move(key), std::move(value)).second) {
                error = "duplicate PSBT key";
                return false;
            }
        }
        error = "missing PSBT map separator";
        return false;
    }
};

inline void Integer(uint64_t value, size_t width, Bytes &result) {
    for (size_t i = 0; i < width; ++i) {
        result.push_back(uint8_t(value >> (8 * i)));
    }
}

inline void Compact(uint64_t value, Bytes &result) {
    if (value < 253) {
        Integer(value, 1, result);
    } else {
        result.push_back(value <= 0xffff       ? 253
                         : value <= 0xffffffff ? 254
                                               : 255);
        Integer(value,
                value <= 0xffff       ? 2
                : value <= 0xffffffff ? 4
                                      : 8,
                result);
    }
}

inline void Vector(std::span<const uint8_t> bytes, Bytes &result) {
    Compact(bytes.size(), result);
    result.insert(result.end(), bytes.begin(), bytes.end());
}

inline void WriteMap(const Map &map, Bytes &result) {
    for (const auto &[key, value] : map) {
        Vector(key, result);
        Vector(value, result);
    }
    result.push_back(0);
}

// Combiner conflicts are errors even for fields this implementation does not
// understand. Stage into a copy so a failed combine cannot partially mutate.
inline bool MergeMap(Map &target, const Map &source, std::string &error) {
    Map merged = target;
    for (const auto &[key, value] : source) {
        auto [it, added] = merged.emplace(key, value);
        if (!added && it->second != value) {
            error = "conflicting PSBT map value";
            return false;
        }
    }
    target = std::move(merged);
    error.clear();
    return true;
}

} // namespace lotus::v2::psbt_detail
#endif
