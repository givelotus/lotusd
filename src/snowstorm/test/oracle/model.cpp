// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#include "model.h"

#include "field.h"
#include "schedule.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace snowstorm_oracle {
namespace {
bool legal_count(std::int64_t count) {
    constexpr auto bound = std::numeric_limits<std::int32_t>::max();
    return count >= -std::int64_t{bound} && count <= bound;
}

void check_range(std::uint64_t begin, std::uint64_t end) {
    if (begin > end || end > (std::uint64_t{1} << 40)) {
        throw std::invalid_argument("oracle encoding range is invalid");
    }
}

bool legal_decoded_item(const SignedItem &entry, std::uint64_t index,
                        const IdSet &reference) {
    if (entry.item == 0 || (entry.sign != -1 && entry.sign != 1)) {
        return false;
    }
    if ((entry.sign == -1) != reference.contains(entry.item)) {
        return false;
    }
    return includes(entry.item, index);
}

void encode_item(std::vector<Cell> &cells, const SignedItem &entry,
                 std::uint64_t begin, std::uint64_t end) {
    const auto indices = schedule(entry.item, end - 1);
    for (const auto index : indices) {
        if (index < begin) {
            continue;
        }
        if (!add(cells[index - begin], entry.item, entry.sign)) {
            throw std::overflow_error("oracle cell add failed");
        }
    }
}
} // namespace

bool add(Cell &cell, std::uint64_t item, int sign) {
    if (item == 0 || (sign != -1 && sign != 1)) {
        return false;
    }
    const std::int64_t count = std::int64_t{cell.count} + sign;
    if (!legal_count(cell.count) || !legal_count(count)) {
        return false;
    }
    cell.count = static_cast<std::int32_t>(count);
    cell.s1 ^= item;
    cell.s3 ^= power(item, 3);
    cell.s5 ^= power(item, 5);
    return true;
}

Cell subtract(const Cell &received, const Cell &reference) {
    const std::int64_t count = std::int64_t{received.count} - reference.count;
    if (!legal_count(received.count) || !legal_count(reference.count) ||
        !legal_count(count)) {
        throw std::overflow_error("oracle cell subtraction overflow");
    }
    return Cell{static_cast<std::int32_t>(count), received.s1 ^ reference.s1,
                received.s3 ^ reference.s3, received.s5 ^ reference.s5};
}

bool verifies_decode(const Cell &source, std::uint64_t index,
                     std::span<const SignedItem> decoded,
                     const IdSet &reference) {
    if (decoded.size() > 2 || !legal_count(source.count)) {
        return false;
    }
    if (decoded.empty()) {
        return source == Cell{};
    }
    if (decoded.size() == 2 && decoded[0].item >= decoded[1].item) {
        return false;
    }
    Cell reconstructed{};
    for (const auto &entry : decoded) {
        if (!legal_decoded_item(entry, index, reference)) {
            return false;
        }
        if (!add(reconstructed, entry.item, entry.sign)) {
            return false;
        }
    }
    return source == reconstructed;
}

std::vector<Cell> encode(const IdSet &items, std::uint64_t begin,
                         std::uint64_t end) {
    check_range(begin, end);
    std::vector<Cell> cells(end - begin);
    if (begin == end) {
        return cells;
    }
    for (const auto item : items) {
        encode_item(cells, SignedItem{item, 1}, begin, end);
    }
    return cells;
}

std::vector<Cell> encode_signed(std::span<const SignedItem> items,
                                std::uint64_t begin, std::uint64_t end) {
    check_range(begin, end);
    std::vector<Cell> cells(end - begin);
    if (begin == end) {
        return cells;
    }
    for (const auto &entry : items) {
        if (entry.sign != -1 && entry.sign != 1) {
            throw std::invalid_argument("oracle sign must be +1 or -1");
        }
        encode_item(cells, entry, begin, end);
    }
    return cells;
}

IdSet snapshot(std::span<const Operation> log, std::uint64_t at_seq,
               const IdSet &initial) {
    IdSet result = initial;
    std::uint64_t previous_seq = 0;
    for (const auto &operation : log) {
        if (operation.seq <= previous_seq || operation.item == 0 ||
            operation.sign < -1 || operation.sign > 1) {
            throw std::invalid_argument("oracle operation log is invalid");
        }
        previous_seq = operation.seq;
        if (operation.seq > at_seq) {
            continue;
        }
        if (operation.sign == 1) {
            result.insert(operation.item);
        }
        if (operation.sign == -1) {
            result.erase(operation.item);
        }
    }
    return result;
}

} // namespace snowstorm_oracle
