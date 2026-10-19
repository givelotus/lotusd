// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_ERROR_H
#define CHRONIK_NATIVE_ERROR_H

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace chronik::native {

/**
 * Error carrying a message in the Rust Chronik format. Like the Rust
 * `abc_rust_error`, an HTTP status is encoded as a "NNN: " prefix of the
 * message, e.g. "404: Block not found: 1234". Messages without such a prefix
 * are internal errors (HTTP 500 "Unknown error, contact admins").
 */
class ChronikError : public std::runtime_error {
public:
    explicit ChronikError(const std::string &msg) : std::runtime_error(msg) {}
};

/** Parse the "NNN: " status prefix of a message, as abc_rust_error does. */
inline std::optional<int> ParseErrorStatus(std::string_view msg) {
    if (msg.size() < 5 || msg[3] != ':' || msg[4] != ' ') {
        return std::nullopt;
    }
    int status = 0;
    for (size_t i = 0; i < 3; ++i) {
        if (msg[i] < '0' || msg[i] > '9') {
            return std::nullopt;
        }
        status = status * 10 + (msg[i] - '0');
    }
    if (status < 100 || status > 999) {
        return std::nullopt;
    }
    return status;
}

[[noreturn]] inline void ThrowError(const std::string &msg) {
    throw ChronikError(msg);
}

} // namespace chronik::native

#endif // CHRONIK_NATIVE_ERROR_H
