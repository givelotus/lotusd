// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_REVERSE_LOOKUP_H
#define CHRONIK_NATIVE_INDEX_REVERSE_LOOKUP_H

#include <chronik/native/codec/postcard.h>
#include <chronik/native/error.h>
#include <chronik/native/index/merge.h>
#include <chronik/native/store.h>

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

/**
 * Port of chronik-db reverse_lookup.rs.
 *
 * Allows reverse-looking up data that has been indexed using a serial number
 * (`SerialNum -> Data`, e.g. `BlockHeight -> SerBlock`), by a 32-byte key
 * contained in the data, with the index `CheapHash -> [SerialNum]`. CheapHash
 * is a short hash, so collisions are kept in a sorted list.
 *
 * `L` is the LookupColumn:
 *   using SerialNum, Data;
 *   static constexpr std::string_view kCfData, kCfIndex;
 *   static constexpr std::string_view kSerialTypeName;    // e.g. "u64"
 *   static constexpr std::string_view kSerialVecTypeName; // "alloc::vec::Vec<u64>"
 *   static Bytes CheapHash(const std::array<uint8_t, 32> &key);
 *   static const std::array<uint8_t, 32> &DataKey(const Data &);
 *   static void SerSerial(postcard::Writer &, SerialNum);
 *   static SerialNum DeserSerial(postcard::Reader &);
 *   TableId IndexTable() const;
 *   std::optional<Data> GetData(SerialNum) const;
 *   std::vector<std::optional<Data>>
 *       GetDataMulti(const std::vector<SerialNum> &) const;
 */
namespace chronik::native::index {

using Key32 = std::array<uint8_t, 32>;

template <typename L> class ReverseLookup {
public:
    using SerialNum = typename L::SerialNum;
    using Data = typename L::Data;

    /** Read by key from the DB using the index. */
    static std::optional<std::pair<SerialNum, Data>>
    Get(const L &col, const ReadTxn &txn, const Key32 &key) {
        const Bytes cheap_hash = L::CheapHash(key);
        // Lookup CheapHash -> [SerialNum]
        const std::optional<ByteView> serials =
            txn.Get(col.IndexTable(), cheap_hash);
        if (!serials) {
            return std::nullopt;
        }
        // Iterate serials, read each's data, find the one with the given key.
        for (const SerialNum serial : DeserSerials(*serials)) {
            std::optional<Data> value = col.GetData(serial);
            if (!value) {
                ThrowNotInDataColumn(serial);
            }
            if (L::DataKey(*value) == key) {
                return std::make_pair(serial, std::move(*value));
            }
        }
        // We have a key that collides with others but no actual match
        return std::nullopt;
    }

    static std::vector<std::optional<std::pair<SerialNum, Data>>>
    GetMulti(const L &col, const ReadTxn &txn, const std::vector<Key32> &keys) {
        std::vector<std::vector<SerialNum>> serial_lists;
        serial_lists.reserve(keys.size());
        for (const Key32 &key : keys) {
            const std::optional<ByteView> serials =
                txn.Get(col.IndexTable(), L::CheapHash(key));
            serial_lists.push_back(serials ? DeserSerials(*serials)
                                           : std::vector<SerialNum>{});
        }
        std::vector<SerialNum> all_serials;
        for (const auto &list : serial_lists) {
            all_serials.insert(all_serials.end(), list.begin(), list.end());
        }
        std::vector<std::optional<Data>> data_lists =
            col.GetDataMulti(all_serials);
        size_t data_idx = 0;
        std::vector<std::optional<std::pair<SerialNum, Data>>> result;
        result.reserve(serial_lists.size());
        for (size_t i = 0; i < serial_lists.size(); ++i) {
            bool has_found = false;
            for (const SerialNum serial : serial_lists[i]) {
                if (!has_found) {
                    std::optional<Data> &data = data_lists[data_idx];
                    if (data && L::DataKey(*data) == keys[i]) {
                        result.emplace_back(
                            std::make_pair(serial, std::move(*data)));
                        has_found = true;
                    }
                }
                ++data_idx;
            }
            if (!has_found) {
                result.emplace_back(std::nullopt);
            }
        }
        return result;
    }

    /** Insert into the index (Rust: one merge_cf per pair). */
    static void
    InsertPairs(const L &col, WriteTxn &txn,
                const std::vector<std::pair<SerialNum, Key32>> &pairs) {
        // Operands queued on the same cheap hash within one batch are merged
        // together, in order, like Rust's merge at write_batch time.
        std::vector<std::pair<Bytes, std::vector<Bytes>>> by_hash;
        std::map<Bytes, size_t> hash_idx;
        for (const auto &[serial, key] : pairs) {
            Bytes cheap_hash = L::CheapHash(key);
            auto [it, inserted] = hash_idx.emplace(cheap_hash, by_hash.size());
            if (inserted) {
                by_hash.emplace_back(std::move(cheap_hash),
                                     std::vector<Bytes>{});
            }
            Bytes operand;
            postcard::Writer w(operand);
            L::SerSerial(w, serial);
            by_hash[it->second].second.push_back(std::move(operand));
        }
        for (const auto &[cheap_hash, operands] : by_hash) {
            merge::CatchMergeErrors(
                txn, col.IndexTable(), cheap_hash, operands,
                // init_ordered_list
                [](ByteView, std::optional<ByteView> existing, size_t n) {
                    std::vector<SerialNum> nums;
                    if (existing) {
                        nums = DeserSerials(*existing);
                    }
                    nums.reserve(nums.size() + n);
                    return nums;
                },
                // apply_ordered_list
                [](ByteView, std::vector<SerialNum> &nums, ByteView operand) {
                    const SerialNum num = postcard::DbDeserialize(
                        operand, L::kSerialTypeName,
                        [](postcard::Reader &r) { return L::DeserSerial(r); });
                    auto it = std::lower_bound(nums.begin(), nums.end(), num);
                    if (it != nums.end() && *it == num) {
                        throw ChronikError(
                            "Inconsistent DB: Tried inserting " +
                            std::to_string(num) + " into " +
                            std::string(L::kCfIndex) +
                            ", but value already exists");
                    }
                    nums.insert(it, num);
                },
                // ser_ordered_list
                [](ByteView, std::vector<SerialNum> &&nums) {
                    return SerSerials(nums);
                });
        }
    }

    /** Delete from the index. */
    static void
    DeletePairs(const L &col, WriteTxn &txn,
                const std::vector<std::pair<SerialNum, Key32>> &pairs) {
        std::map<Bytes, std::set<SerialNum>> new_entries;
        for (const auto &[serial, key] : pairs) {
            std::set<SerialNum> &serials =
                GetOrFetch(col, txn, new_entries, key);
            if (serials.erase(serial) == 0) {
                ThrowNotInDataColumn(serial);
            }
        }
        for (const auto &[key, serials] : new_entries) {
            if (serials.empty()) {
                // Delete the entry from the DB if it doesn't contain any
                // serials anymore
                txn.Del(col.IndexTable(), key);
            } else {
                // Otherwise, override entry with only the remaining serials
                txn.Put(col.IndexTable(), key,
                        SerSerials(std::vector<SerialNum>(serials.begin(),
                                                          serials.end())));
            }
        }
    }

    static std::vector<SerialNum> DeserSerials(ByteView bytes) {
        return postcard::DbDeserialize(
            bytes, L::kSerialVecTypeName, [](postcard::Reader &r) {
                const uint64_t len = r.SeqLen();
                std::vector<SerialNum> nums;
                for (uint64_t i = 0; i < len; ++i) {
                    nums.push_back(L::DeserSerial(r));
                }
                return nums;
            });
    }

    static Bytes SerSerials(const std::vector<SerialNum> &nums) {
        Bytes out;
        postcard::Writer w(out);
        w.SeqLen(nums.size());
        for (const SerialNum num : nums) {
            L::SerSerial(w, num);
        }
        return out;
    }

private:
    [[noreturn]] static void ThrowNotInDataColumn(SerialNum serial) {
        throw ChronikError("Inconsistent DB: Lookup index " +
                           std::string(L::kCfData) + " contains " +
                           std::to_string(serial) + ", but value column " +
                           std::string(L::kCfIndex) + " doesn't");
    }

    /** Query from `new_entries`, or from DB and then store in `new_entries`. */
    static std::set<SerialNum> &
    GetOrFetch(const L &col, const ReadTxn &txn,
               std::map<Bytes, std::set<SerialNum>> &new_entries,
               const Key32 &key) {
        Bytes cheap_hash = L::CheapHash(key);
        auto it = new_entries.find(cheap_hash);
        if (it != new_entries.end()) {
            return it->second;
        }
        std::set<SerialNum> serials;
        if (const std::optional<ByteView> bytes =
                txn.Get(col.IndexTable(), cheap_hash)) {
            for (const SerialNum num : DeserSerials(*bytes)) {
                serials.insert(num);
            }
        }
        return new_entries.emplace(std::move(cheap_hash), std::move(serials))
            .first->second;
    }
};

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_REVERSE_LOOKUP_H
