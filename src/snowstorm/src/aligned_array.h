// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <cstddef>
#include <limits>
#include <memory>
#include <new>
#include <type_traits>
namespace snowstorm::detail {
inline constexpr std::size_t ARRAY_ALIGNMENT = 64;
template <typename T> struct AlignedDelete {
    void operator()(T *pointer) const noexcept {
        ::operator delete[](pointer, std::align_val_t{ARRAY_ALIGNMENT});
    }
};
template <typename T> using AlignedArray = std::unique_ptr<T[], AlignedDelete<T>>;
template <typename T> AlignedArray<T> aligned_array(std::size_t count) {
    static_assert(std::is_trivial_v<T>);
    if (count > std::numeric_limits<std::size_t>::max() / sizeof(T)) throw std::bad_array_new_length();
    if (count == 0) return {};
    AlignedArray<T> result(static_cast<T *>(::operator new[](count * sizeof(T), std::align_val_t{ARRAY_ALIGNMENT})));
    std::uninitialized_value_construct_n(result.get(), count);
    return result;
}
} // namespace snowstorm::detail
