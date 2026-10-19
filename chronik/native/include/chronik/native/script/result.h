// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_SCRIPT_RESULT_H
#define CHRONIK_NATIVE_SCRIPT_RESULT_H

#include <cassert>
#include <type_traits>
#include <utility>
#include <variant>

namespace chronik::native {

/** Error wrapper, to construct a Result holding an error. */
template <typename E> struct Unexpected {
    E error;
    bool operator==(const Unexpected &) const = default;
};

template <typename E> Unexpected<std::decay_t<E>> Err(E &&e) {
    return Unexpected<std::decay_t<E>>{std::forward<E>(e)};
}

/**
 * Minimal value-or-error type (like Rust's Result / C++23 std::expected),
 * used where the Rust code returns typed errors that are compared in tests.
 */
template <typename T, typename E> class Result {
public:
    Result(T value) : v_(std::in_place_index<0>, std::move(value)) {}
    Result(Unexpected<E> err)
        : v_(std::in_place_index<1>, std::move(err.error)) {}
    template <typename U,
              std::enable_if_t<!std::is_same_v<std::decay_t<U>, T> &&
                                   !std::is_same_v<std::decay_t<U>, E> &&
                                   std::is_convertible_v<U, E>,
                               int> = 0>
    Result(Unexpected<U> err)
        : v_(std::in_place_index<1>, E(std::move(err.error))) {}

    bool ok() const { return v_.index() == 0; }
    explicit operator bool() const { return ok(); }

    T &value() {
        assert(ok());
        return std::get<0>(v_);
    }
    const T &value() const {
        assert(ok());
        return std::get<0>(v_);
    }
    E &error() {
        assert(!ok());
        return std::get<1>(v_);
    }
    const E &error() const {
        assert(!ok());
        return std::get<1>(v_);
    }

    bool operator==(const Result &other) const { return v_ == other.v_; }

private:
    std::variant<T, E> v_;
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_SCRIPT_RESULT_H
