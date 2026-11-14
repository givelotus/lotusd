// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/messages.h>
#include "wire_cursor.h"
#include "cell_count.h"
#include "range_validation.h"
#include "message_size.h"
#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>

namespace snowstorm {
namespace {
using detail::WireReader;
using detail::WireWriter;
using detail::check_range;
using detail::check_ranges;
std::size_t byte_limit(const Limits &limits) noexcept {
    return static_cast<std::size_t>(std::min(limits.max_message_bytes, params::MESSAGE_BYTES));
}
Error validate(const ReconReq &request, const Limits &limits) noexcept {
    if (request.version != params::PROTOCOL_VERSION) return Error::unsupported_version;
    if (request.session_id == 0 || request.request_id == 0) return Error::malformed_message;
    std::uint64_t total{};
    return check_ranges(request.ranges, limits, total);
}
Error validate(const ReconClose &close, const Limits &) noexcept {
    if (close.version != params::PROTOCOL_VERSION) return Error::unsupported_version;
    return close.session_id ? Error::ok : Error::malformed_message;
}
Error validate_exclusions(const ReconSymbols &symbols, const Limits &limits) noexcept {
    if (!symbols.exclusions) return Error::ok;
    if (symbols.exclusions->size() > limits.max_exclusions) return Error::capacity;
    ShortId previous{};
    for (const auto id : *symbols.exclusions) {
        if (id <= previous) return Error::invalid_id;
        previous = id;
    }
    return Error::ok;
}
Error validate(const ReconSymbols &symbols, const Limits &limits) noexcept {
    if (symbols.version != params::PROTOCOL_VERSION) return Error::unsupported_version;
    if (symbols.session_id == 0 || symbols.request_id == 0) return Error::malformed_message;
    if (symbols.status == SymbolsStatus::expired) return Error::ok;
    if (symbols.status == SymbolsStatus::resource_limited) {
        return symbols.resource_reason <= ResourceReason::storage_capacity ? Error::ok : Error::malformed_message;
    }
    if (symbols.status != SymbolsStatus::normal) return Error::malformed_message;
    std::uint64_t total{};
    const auto range_error = check_ranges(symbols.ranges, limits, total);
    if (range_error != Error::ok) return range_error;
    if (symbols.cells.size() != total) return Error::malformed_message;
    for (const auto &cell : symbols.cells) {
        if (!detail::valid_cell_count(cell.count)) return Error::overflow;
    }
    return validate_exclusions(symbols, limits);
}
void write_ranges(WireWriter &writer, std::span<const Range> ranges) noexcept {
    writer.compact(ranges.size());
    for (const auto range : ranges) { writer.integer(range.begin); writer.integer(range.end); }
}
void write_payload(WireWriter &writer, const ReconReq &request) noexcept {
    writer.integer(request.session_id); writer.integer(request.request_id); writer.integer(request.poll_id);
    writer.integer(static_cast<Byte>(request.open)); writer.integer(request.reference_size);
    writer.integer(static_cast<Byte>(request.known_excl_version.has_value()));
    if (request.known_excl_version) writer.integer(*request.known_excl_version);
    write_ranges(writer, request.ranges);
}
void write_payload(WireWriter &writer, const ReconClose &close) noexcept { writer.integer(close.session_id); }
void write_payload(WireWriter &writer, const ReconSymbols &symbols) noexcept {
    writer.integer(symbols.session_id); writer.integer(symbols.request_id); writer.integer(symbols.poll_id);
    writer.integer(static_cast<Byte>(symbols.status));
    if (symbols.status == SymbolsStatus::expired) return;
    if (symbols.status == SymbolsStatus::resource_limited) { writer.integer(static_cast<Byte>(symbols.resource_reason)); return; }
    writer.integer(symbols.snapshot_seq); writer.integer(symbols.current_seq);
    write_ranges(writer, symbols.ranges); writer.compact(symbols.cells.size());
    for (const auto &cell : symbols.cells) {
        std::array<Byte, params::CELL_WIRE_BYTES> bytes{};
        (void)serialize_cell(cell, bytes); writer.put(bytes);
    }
    writer.put(symbols.root_vote); writer.integer(symbols.exclusion_version);
    writer.integer(static_cast<Byte>(symbols.exclusions.has_value()));
    if (!symbols.exclusions) return;
    writer.compact(symbols.exclusions->size());
    for (const auto id : *symbols.exclusions) writer.integer(id);
}
void write_message(WireWriter &writer, const Message &message) noexcept {
    std::visit([&](const auto &value) {
        writer.integer(value.version);
        writer.integer(static_cast<Byte>(message.index()));
        writer.put(value.tip_context); write_payload(writer, value);
    }, message);
}
Error read_ranges(WireReader &reader, const Limits &limits, std::vector<Range> &ranges,
                  bool materialize, std::uint64_t &total) {
    const auto count = reader.compact();
    if (reader.error != Error::ok) return reader.error;
    if (count == 0) return Error::malformed_message;
    if (count > limits.max_ranges) return Error::capacity;
    constexpr auto RANGE_BYTES = 2 * sizeof(SymbolIndex);
    if (count > reader.remaining() / RANGE_BYTES) return Error::malformed_message;
    if (materialize) ranges.reserve(static_cast<std::size_t>(count));
    SymbolIndex previous{};
    for (std::uint64_t i = 0; i < count; ++i) {
        const Range range{reader.integer<SymbolIndex>(), reader.integer<SymbolIndex>()};
        const auto error = check_range(range, previous, limits, total);
        if (error != Error::ok) return error;
        previous = range.end;
        if (materialize) ranges.push_back(range);
    }
    return reader.error;
}
Error read_exclusions(WireReader &reader, const Limits &limits, ReconSymbols &symbols, bool materialize) {
    const auto present = reader.flag();
    if (reader.error != Error::ok || !present) return reader.error;
    const auto count = reader.compact();
    if (reader.error != Error::ok) return reader.error;
    if (count > limits.max_exclusions) return Error::capacity;
    if (count > reader.remaining() / sizeof(ShortId)) return Error::malformed_message;
    if (materialize) { symbols.exclusions.emplace(); symbols.exclusions->reserve(static_cast<std::size_t>(count)); }
    ShortId previous{};
    for (std::uint64_t i = 0; i < count; ++i) {
        const auto id = reader.integer<ShortId>();
        if (id <= previous) return Error::invalid_id;
        previous = id;
        if (materialize) symbols.exclusions->push_back(id);
    }
    return reader.error;
}
Error read_payload(WireReader &reader, const Limits &limits, ReconReq &request, bool materialize) {
    request.session_id = reader.integer<SessionId>(); request.request_id = reader.integer<RequestId>();
    request.poll_id = reader.integer<PollId>(); request.open = reader.flag();
    request.reference_size = reader.integer<std::uint64_t>();
    if (reader.flag()) request.known_excl_version = reader.integer<std::uint64_t>();
    if (reader.error != Error::ok) return reader.error;
    if (request.session_id == 0 || request.request_id == 0) return Error::malformed_message;
    std::uint64_t total{};
    return read_ranges(reader, limits, request.ranges, materialize, total);
}
Error read_payload(WireReader &reader, const Limits &, ReconClose &close, bool) noexcept {
    close.session_id = reader.integer<SessionId>();
    if (reader.error != Error::ok) return reader.error;
    return close.session_id ? Error::ok : Error::malformed_message;
}
Error read_cells(WireReader &reader, const Limits &limits, ReconSymbols &symbols,
                 bool materialize, std::uint64_t expected) {
    const auto count = reader.compact();
    if (reader.error != Error::ok) return reader.error;
    if (count > limits.max_cells) return Error::capacity;
    if (count != expected || count > reader.remaining() / params::CELL_WIRE_BYTES) return Error::malformed_message;
    if (materialize) symbols.cells.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        Cell cell{};
        const auto error = parse_cell(reader.take(params::CELL_WIRE_BYTES), cell);
        if (error != Error::ok) return error;
        if (materialize) symbols.cells.push_back(cell);
    }
    return reader.error;
}
Error read_payload(WireReader &reader, const Limits &limits, ReconSymbols &symbols, bool materialize) {
    symbols.session_id = reader.integer<SessionId>(); symbols.request_id = reader.integer<RequestId>();
    symbols.poll_id = reader.integer<PollId>(); symbols.status = static_cast<SymbolsStatus>(reader.integer<Byte>());
    if (reader.error != Error::ok) return reader.error;
    if (symbols.session_id == 0 || symbols.request_id == 0) return Error::malformed_message;
    if (symbols.status == SymbolsStatus::expired) return Error::ok;
    if (symbols.status == SymbolsStatus::resource_limited) {
        symbols.resource_reason = static_cast<ResourceReason>(reader.integer<Byte>());
        return symbols.resource_reason <= ResourceReason::storage_capacity ? reader.error : Error::malformed_message;
    }
    if (symbols.status != SymbolsStatus::normal) return Error::malformed_message;
    symbols.snapshot_seq = reader.integer<Sequence>(); symbols.current_seq = reader.integer<Sequence>();
    std::uint64_t total{};
    const auto range_error = read_ranges(reader, limits, symbols.ranges, materialize, total);
    if (range_error != Error::ok) return range_error;
    const auto cell_error = read_cells(reader, limits, symbols, materialize, total);
    if (cell_error != Error::ok) return cell_error;
    reader.fixed(symbols.root_vote); symbols.exclusion_version = reader.integer<std::uint64_t>();
    if (reader.error != Error::ok) return reader.error;
    return read_exclusions(reader, limits, symbols, materialize);
}
template <typename T> ParseResult read_message(WireReader &reader, const Limits &limits,
                                               const TipContext &context, bool materialize) {
    T value{}; value.tip_context = context;
    const auto error = read_payload(reader, limits, value, materialize);
    if (error != Error::ok) return {error, std::nullopt};
    if (reader.remaining() != 0) return {Error::malformed_message, std::nullopt};
    return {Error::ok, Message{std::move(value)}};
}
ParseResult parse_pass(ByteSpan bytes, const Limits &limits, bool materialize) {
    WireReader reader(bytes);
    const auto version = reader.integer<Byte>(); const auto kind = reader.integer<Byte>();
    TipContext context{}; reader.fixed(context);
    if (reader.error != Error::ok) return {reader.error, std::nullopt};
    if (version != params::PROTOCOL_VERSION) return {Error::unsupported_version, std::nullopt};
    if (kind == static_cast<Byte>(MessageKind::request)) return read_message<ReconReq>(reader, limits, context, materialize);
    if (kind == static_cast<Byte>(MessageKind::symbols)) return read_message<ReconSymbols>(reader, limits, context, materialize);
    if (kind == static_cast<Byte>(MessageKind::close)) return read_message<ReconClose>(reader, limits, context, materialize);
    return {Error::malformed_message, std::nullopt};
}
}
Error serialized_size(const Message &message, const Limits &limits, std::size_t &bytes) noexcept {
    if (message.valueless_by_exception()) return Error::invalid_argument;
    const auto error = std::visit([&](const auto &value) { return validate(value, limits); }, message);
    if (error != Error::ok) return error;
    WireWriter writer({}, byte_limit(limits), true); write_message(writer, message);
    if (writer.error != Error::ok) return writer.error;
    bytes = writer.position;
    return Error::ok;
}
Error serialize(const Message &message, const Limits &limits, MutableByteSpan output, std::size_t &written) noexcept {
    written = 0;
    std::size_t size{}; const auto error = serialized_size(message, limits, size);
    if (error != Error::ok) return error;
    if (output.size() < size) return Error::capacity;
    WireWriter writer(output, size, false); write_message(writer, message);
    written = writer.position;
    return writer.error;
}
Error serialize(const Message &message, const Limits &limits, Bytes &output) {
    std::size_t size{}; const auto error = serialized_size(message, limits, size);
    if (error != Error::ok) return error;
    Bytes encoded(size);
    WireWriter writer(encoded, size, false); write_message(writer, message);
    output = std::move(encoded);
    return Error::ok;
}
ParseResult parse(ByteSpan bytes, const Limits &limits) noexcept {
    if (bytes.size() > byte_limit(limits)) return {Error::capacity, std::nullopt};
    try {
        // Complete canonical validation, including terminal/trailing bytes, before
        // the first owning vector allocation. The same grammar runs both passes.
        const auto checked = parse_pass(bytes, limits, false);
        if (checked.error != Error::ok) return {checked.error, std::nullopt};
        return parse_pass(bytes, limits, true);
    } catch (const std::bad_alloc &) {
        return {Error::capacity, std::nullopt};
    } catch (const std::length_error &) {
        return {Error::capacity, std::nullopt};
    }
}
Error detail::normal_symbols_size(std::uint64_t ranges, std::uint64_t cells,
                                  std::optional<std::uint64_t> exclusions,
                                  const Limits &limits, std::size_t &bytes) noexcept {
    if (ranges == 0 || cells == 0) return Error::invalid_range;
    if (ranges > limits.max_ranges || cells > limits.max_cells ||
        (exclusions && *exclusions > limits.max_exclusions)) return Error::capacity;
    // Empty vectors allocate nothing. The existing writer measures all fixed
    // fields and the one-byte zero counts; add only dynamic field differences.
    WireWriter base({}, std::numeric_limits<std::size_t>::max(), true);
    write_message(base, ReconSymbols{});
    const auto compact_bytes = [](std::uint64_t value) noexcept {
        WireWriter writer({}, std::numeric_limits<std::size_t>::max(), true);
        writer.compact(value);
        return writer.position;
    };
    auto total = static_cast<unsigned __int128>(base.position);
    total += static_cast<unsigned __int128>(ranges) * (sizeof(SymbolIndex) + sizeof(SymbolIndex)) + compact_bytes(ranges) - 1;
    total += static_cast<unsigned __int128>(cells) * params::CELL_WIRE_BYTES + compact_bytes(cells) - 1;
    if (exclusions) total += compact_bytes(*exclusions) + static_cast<unsigned __int128>(*exclusions) * sizeof(ShortId);
    if (total > byte_limit(limits)) return Error::capacity;
    bytes = static_cast<std::size_t>(total);
    return Error::ok;
}
} // namespace snowstorm
