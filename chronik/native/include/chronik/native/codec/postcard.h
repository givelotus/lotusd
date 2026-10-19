// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CODEC_POSTCARD_H
#define CHRONIK_NATIVE_CODEC_POSTCARD_H

#include <chronik/native/error.h>
#include <chronik/native/types.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/**
 * Postcard (serde) wire format, as produced by the Rust `postcard` crate v1
 * for the types the Rust Chronik stores:
 *  - u8 / i8: one raw byte; bool: 0 or 1
 *  - u16..u128, usize: LEB128 varint; i16..i128: zigzag, then varint
 *  - [u8; N]: N raw bytes (a tuple of u8)
 *  - Vec<T> / Bytes / String: varint length, then the items
 *  - Option<T>: tag byte 0 (None) or 1 (Some) then T
 *  - enum: varint variant index (u32), then the variant's fields
 *  - struct / tuple: fields in declaration order, no framing
 *  - BTreeMap<K, V>: varint length, then (K, V) pairs in key order
 */
namespace chronik::native::postcard {

/** postcard::Error, with its Display text as the message. */
class Error : public ChronikError {
public:
    using ChronikError::ChronikError;
};

// postcard::Error Display texts
inline constexpr std::string_view kUnexpectedEnd =
    "Hit the end of buffer, expected more data";
inline constexpr std::string_view kBadVarint =
    "Found a varint that didn't terminate. Is the usize too big for this "
    "platform?";
inline constexpr std::string_view kBadBool = "Found a bool that wasn't 0 or 1";
inline constexpr std::string_view kBadUtf8 = "Tried to parse invalid utf-8";
inline constexpr std::string_view kBadOption =
    "Found an Option discriminant that wasn't 0 or 1";
inline constexpr std::string_view kBadEnum =
    "Found an enum discriminant that was > u32::max_value()";
/** Used for an out-of-range enum variant (serde "unknown variant"). */
inline constexpr std::string_view kSerdeDeCustom =
    "Serde Deserialization Error";

class Writer {
public:
    explicit Writer(Bytes &out) : m_out(out) {}

    void U8(uint8_t v) { m_out.push_back(v); }
    void I8(int8_t v) { m_out.push_back(uint8_t(v)); }
    void Bool(bool v) { m_out.push_back(v ? 1 : 0); }
    void U16(uint16_t v) { Varint(v); }
    void U32(uint32_t v) { Varint(v); }
    void U64(uint64_t v) { Varint(v); }
    void Usize(uint64_t v) { Varint(v); }
    void U128(unsigned __int128 v);
    void I16(int16_t v) { Varint(Zigzag64(v)); }
    void I32(int32_t v) { Varint(Zigzag64(v)); }
    void I64(int64_t v) { Varint(Zigzag64(v)); }
    /** Fixed-size array ([u8; N]): raw bytes, no length. */
    void Raw(ByteView v) { m_out.insert(m_out.end(), v.begin(), v.end()); }
    /** Vec<u8> / Bytes: length then bytes. */
    void ByteVec(ByteView v) {
        Usize(v.size());
        Raw(v);
    }
    void Str(std::string_view s) {
        Usize(s.size());
        m_out.insert(m_out.end(), s.begin(), s.end());
    }
    /** Option tag: false = None, true = Some (caller then writes T). */
    void OptionTag(bool is_some) { U8(is_some ? 1 : 0); }
    void EnumIndex(uint32_t idx) { U32(idx); }
    /** Sequence/map length prefix. */
    void SeqLen(uint64_t len) { Usize(len); }

    void Varint(uint64_t v);
    static uint64_t Zigzag64(int64_t v) {
        return (uint64_t(v) << 1) ^ uint64_t(v >> 63);
    }

    Bytes &Out() { return m_out; }

private:
    Bytes &m_out;
};

class Reader {
public:
    explicit Reader(ByteView data) : m_data(data) {}

    uint8_t U8();
    int8_t I8() { return int8_t(U8()); }
    bool Bool();
    uint16_t U16() { return uint16_t(Varint(3, 0x03)); }
    uint32_t U32() { return uint32_t(Varint(5, 0x0f)); }
    uint64_t U64() { return Varint(10, 0x01); }
    uint64_t Usize() { return U64(); }
    unsigned __int128 U128();
    int16_t I16() { return int16_t(Unzigzag(U16())); }
    int32_t I32() { return int32_t(Unzigzag(U32())); }
    int64_t I64() { return Unzigzag(U64()); }
    /** Fixed-size array: view of the next n bytes. */
    ByteView Raw(size_t n);
    template <size_t N> std::array<uint8_t, N> Array() {
        const ByteView v = Raw(N);
        std::array<uint8_t, N> a;
        std::copy(v.begin(), v.end(), a.begin());
        return a;
    }
    Bytes ByteVec();
    std::string Str();
    bool OptionTag();
    uint32_t EnumIndex() { return U32(); }
    uint64_t SeqLen() { return Usize(); }

    bool AtEnd() const { return m_pos == m_data.size(); }
    size_t Pos() const { return m_pos; }
    ByteView Remaining() const { return m_data.subspan(m_pos); }

private:
    /**
     * Varint with at most max_bytes bytes, whose last byte (if max_bytes are
     * used) must be <= max_last, as postcard's try_take_varint_* do.
     */
    uint64_t Varint(size_t max_bytes, uint8_t max_last);
    static int64_t Unzigzag(uint64_t v) {
        return int64_t(v >> 1) ^ -int64_t(v & 1);
    }

    ByteView m_data;
    size_t m_pos = 0;
};

/**
 * Wraps a postcard decode the way chronik-db's `db_deserialize` does, turning
 * failures into "Inconsistent DB: ..." errors (ser.rs SerError). `type_name`
 * stands in for Rust's std::any::type_name, e.g. "chronik_db::io::SerTx".
 */
template <typename F>
auto DbDeserialize(ByteView bytes, std::string_view type_name, F &&decode)
    -> decltype(decode(std::declval<Reader &>()));

template <typename F>
auto DbDeserializeVec(ByteView bytes, std::string_view type_name, F &&decode)
    -> std::vector<decltype(decode(std::declval<Reader &>()))>;

[[noreturn]] void ThrowDeserializeError(std::string_view type_name,
                                        std::string_view error,
                                        ByteView bytes);
[[noreturn]] void ThrowDeserializeLeftover(std::string_view type_name,
                                           ByteView processed,
                                           ByteView leftover);

template <typename F>
auto DbDeserialize(ByteView bytes, std::string_view type_name, F &&decode)
    -> decltype(decode(std::declval<Reader &>())) {
    Reader reader(bytes);
    using T = decltype(decode(reader));
    std::optional<T> value;
    try {
        value.emplace(decode(reader));
    } catch (const Error &err) {
        ThrowDeserializeError(type_name, err.what(), bytes);
    }
    if (!reader.AtEnd()) {
        ThrowDeserializeLeftover(type_name, bytes.subspan(0, reader.Pos()),
                                 reader.Remaining());
    }
    return std::move(*value);
}

template <typename F>
auto DbDeserializeVec(ByteView bytes, std::string_view type_name, F &&decode)
    -> std::vector<decltype(decode(std::declval<Reader &>()))> {
    std::vector<decltype(decode(std::declval<Reader &>()))> items;
    Reader reader(bytes);
    while (!reader.AtEnd()) {
        const size_t start = reader.Pos();
        try {
            items.push_back(decode(reader));
        } catch (const Error &err) {
            ThrowDeserializeError(type_name, err.what(), bytes.subspan(start));
        }
    }
    return items;
}

} // namespace chronik::native::postcard

#endif // CHRONIK_NATIVE_CODEC_POSTCARD_H
