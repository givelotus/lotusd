// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#pragma once
#include <snowstorm/node.h>
#include <string>
namespace snowstorm::test {
/** Length-framed canonical little-endian events, independent of addresses and
 * ABI. */
class Transcript {
    Bytes bytes_;

public:
    void event(std::uint8_t kind, std::uint64_t node, Time time,
               ByteSpan payload = {});
    void action(std::uint64_t node, Time time, const Action &);
    const Bytes &bytes() const noexcept { return bytes_; }
    void write(const std::string &path) const;
    void write_from_environment() const;
};
Root sha256(ByteSpan);
} // namespace snowstorm::test
