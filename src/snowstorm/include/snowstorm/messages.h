// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/cell.h>
#include <variant>
/** @defgroup snowstorm_messages_contract Snowstorm messages public contract
 * §6.1: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §6.1: exact wire discriminants; no implementation-private aliases. */
enum class MessageKind : std::uint8_t { request = 0, symbols = 1, close = 2 };
/** §6.1: terminal responses carry no normal/root/cell payload. */
enum class SymbolsStatus : std::uint8_t {
    normal = 0, expired = 1, resource_limited = 2,
};
/** §6.1: exact resource_limited reason byte. */
enum class ResourceReason : std::uint8_t {
    declared_reference_capacity = 0, symbol_budget = 1,
    session_capacity = 2, storage_capacity = 3,
};
/** §6.1: canonical request; null known_excl_version is explicit unknown flag. */
struct ReconReq {
    std::uint8_t version{1};
    TipContext tip_context{};
    SessionId session_id{};
    RequestId request_id{};
    PollId poll_id{};
    bool open{};
    std::uint64_t reference_size{};
    std::optional<std::uint64_t> known_excl_version;
    std::vector<Range> ranges;
};
/** §6.1: immutable-snapshot response; current_seq is diagnostic only.
 * For terminal status all normal fields are ignored on serialization and empty
 * after parsing. Resource reason is present only for resource_limited.
 */
struct ReconSymbols {
    std::uint8_t version{1};
    TipContext tip_context{};
    SessionId session_id{};
    RequestId request_id{};
    PollId poll_id{};
    SymbolsStatus status{SymbolsStatus::normal};
    ResourceReason resource_reason{ResourceReason::storage_capacity};
    Sequence snapshot_seq{};
    Sequence current_seq{};
    std::vector<Range> ranges;
    std::vector<Cell> cells;
    Root root_vote{};
    std::uint64_t exclusion_version{};
    std::optional<std::vector<ShortId>> exclusions;
};
/** §6.1: close only the matching session within the supplied tip context. */
struct ReconClose {
    std::uint8_t version{1};
    TipContext tip_context{};
    SessionId session_id{};
};
/** §6.1: the only three wire message kinds. */
using Message = std::variant<ReconReq, ReconSymbols, ReconClose>;
/** §6.1: parser result; no partial message escapes an error. */
struct ParseResult {
    Error error{Error::ok};
    std::optional<Message> message;
};
/** §6.1: canonical byte size, checked against static limits before allocation. */
Error serialized_size(const Message &message, const Limits &limits,
                      std::size_t &bytes) noexcept;
/** §6.1: canonical bounded encoding into caller storage; bytes_written=0 on error. */
Error serialize(const Message &message, const Limits &limits,
                MutableByteSpan output, std::size_t &bytes_written) noexcept;
/** §6.1: owning convenience encoding; output unchanged on error. */
Error serialize(const Message &message, const Limits &limits, Bytes &output);
/** §6.1: canonical parse, all static lengths checked before allocation; no throw. */
ParseResult parse(ByteSpan bytes, const Limits &limits) noexcept;
} // namespace snowstorm
/** @} */
