// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_SCRIPT_SCRIPT_H
#define CHRONIK_NATIVE_SCRIPT_SCRIPT_H

#include <chronik/native/script/opcode.h>
#include <chronik/native/script/result.h>
#include <chronik/native/types.h>

#include <array>
#include <compare>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * Port of the script module of bitcoinsuite-core (Rust), as used by Chronik:
 * op parsing, script classification (variants) and building.
 */
namespace chronik::native::script {

/** Lowercase hex of bytes, in the given order. */
std::string HexEncode(ByteView data);

/** Port of bitcoinsuite_core::error::DataError. */
struct DataError {
    enum class Kind { InvalidLength, InvalidLengthMulti, InvalidHex };
    Kind kind = Kind::InvalidLength;
    size_t expected{};
    std::vector<size_t> expected_multi;
    size_t actual{};
    /** Display of the hex::FromHexError, for InvalidHex. */
    std::string hex_error;

    static DataError InvalidLength(size_t expected, size_t actual) {
        return {Kind::InvalidLength, expected, {}, actual, {}};
    }
    static DataError InvalidLengthMulti(std::vector<size_t> expected,
                                        size_t actual) {
        return {Kind::InvalidLengthMulti, 0, std::move(expected), actual, {}};
    }
    static DataError InvalidHex(std::string msg) {
        return {Kind::InvalidHex, 0, {}, 0, std::move(msg)};
    }
    bool operator==(const DataError &) const = default;
    /** Exact Rust Display text. */
    std::string ToString() const;
};

/** Rust hex::decode with its error messages. */
Result<Bytes, DataError> HexDecode(std::string_view hex);

/** Rust `Debug` format of a `[usize]` / `Vec<usize>`, e.g. "[0, 32]". */
std::string DebugSizes(const std::vector<size_t> &sizes);

/** Rust `bytes::Bytes` Debug format, e.g. b"SLP\0". */
std::string DebugBytes(ByteView bytes);

/** Op::Code(opcode) or Op::Push(opcode, data). */
struct Op {
    Opcode opcode;
    bool is_push = false;
    Bytes data;

    static Op Code(Opcode opcode) { return Op{opcode, false, {}}; }
    static Op Push(Opcode opcode, Bytes data) {
        return Op{opcode, true, std::move(data)};
    }
    auto operator<=>(const Op &) const = default;
    bool operator==(const Op &) const = default;
    /** Display, as in Rust: opcode names, "0x.." or quoted text. */
    std::string ToString() const;
};

/** Read one op from data, advancing it (Op::read_op). */
Result<Op, DataError> ReadOp(ByteView &data);

/** Iterator over the ops of a script; stops after the first error. */
class ScriptOpIter {
public:
    explicit ScriptOpIter(ByteView bytecode) : remaining_(bytecode) {}
    /** nullopt at the end. */
    std::optional<Result<Op, DataError>> Next();

private:
    ByteView remaining_;
};

using ShaRmd160 = std::array<uint8_t, 20>;

inline constexpr size_t SHA_RMD160_SIZE = 20;
inline constexpr size_t PUBKEY_SIZE = 33;
inline constexpr size_t UNCOMPRESSED_PUBKEY_SIZE = 65;

class ScriptVariant;

/** Owning script (bitcoinsuite_core::script::Script). */
class Script {
public:
    Script() = default;
    explicit Script(Bytes bytecode) : bytecode_(std::move(bytecode)) {}
    Script(ByteView bytecode) : bytecode_(bytecode.begin(), bytecode.end()) {}

    static Script P2pkh(const ShaRmd160 &hash);
    static Script P2sh(const ShaRmd160 &hash);
    /** pubkey: 33 bytes */
    static Script P2pk(ByteView pubkey);
    /** pubkey: 65 bytes */
    static Script P2pkUncompressed(ByteView pubkey);

    const Bytes &bytecode() const { return bytecode_; }
    ByteView view() const { return bytecode_; }
    std::string Hex() const { return HexEncode(bytecode_); }
    bool IsOpReturn() const;
    ScriptOpIter IterOps() const { return ScriptOpIter(bytecode_); }
    ScriptVariant Variant() const;
    /** Display (asm) as in Rust. */
    std::string ToString() const;
    /** BitcoinSer: CompactSize length followed by the bytecode. */
    Bytes Ser() const;
    size_t SerLen() const;
    /** Consumes the serialized script from the front of `data`. */
    static Result<Script, DataError> Deser(ByteView &data);

    auto operator<=>(const Script &) const = default;
    bool operator==(const Script &) const = default;

private:
    Bytes bytecode_;
};

/** Script builder (bitcoinsuite_core::script::ScriptMut). */
class ScriptMut {
public:
    void PutOpcodes(std::initializer_list<Opcode> opcodes);
    void PutBytecode(ByteView bytes);
    void PutPushdata(ByteView pushdata);
    /** Like PutPushdata, but encodes empty pushdata as OP_PUSHDATA1 0x00. */
    void PutSlpPushdata(ByteView pushdata);
    Script Freeze() { return Script(std::move(bytes_)); }

private:
    Bytes bytes_;
};

enum class ScriptType { P2PKH, P2SH, P2PK, Other };

/** Parse "p2pkh", "p2sh", "p2pk", "other". */
Result<ScriptType, std::string> ParseScriptType(std::string_view s);

/** Classified script (bitcoinsuite_core::script::ScriptVariant). */
class ScriptVariant {
public:
    ScriptType type = ScriptType::Other;
    /** P2PKH/P2SH: 20-byte hash; P2PK: 33/65-byte pubkey; Other: script */
    Bytes payload;

    static Result<ScriptVariant, DataError>
    FromTypeAndPayload(ScriptType type, ByteView payload);

    Script ToScript() const;
    /** e.g. "p2pkh(0101...)" */
    std::string ToString() const;
    bool operator==(const ScriptVariant &) const = default;
};

} // namespace chronik::native::script

#endif // CHRONIK_NATIVE_SCRIPT_SCRIPT_H
