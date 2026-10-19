// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_SCRIPT_OPCODE_H
#define CHRONIK_NATIVE_SCRIPT_OPCODE_H

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace chronik::native::script {

/** A script opcode (port of bitcoinsuite_core::script::opcode::Opcode). */
struct Opcode {
    uint8_t n{};
    constexpr uint8_t number() const { return n; }
    auto operator<=>(const Opcode &) const = default;
    /** Name as Rust displays it, or "[unrecognized opcode]". */
    std::string ToString() const;
};

inline constexpr Opcode OP_0{0x00};
inline constexpr Opcode OP_FALSE{0x00};
inline constexpr Opcode OP_PUSHDATA1{0x4c};
inline constexpr Opcode OP_PUSHDATA2{0x4d};
inline constexpr Opcode OP_PUSHDATA4{0x4e};
inline constexpr Opcode OP_1NEGATE{0x4f};
inline constexpr Opcode OP_RESERVED{0x50};
inline constexpr Opcode OP_1{0x51};
inline constexpr Opcode OP_TRUE{0x51};
inline constexpr Opcode OP_2{0x52};
inline constexpr Opcode OP_3{0x53};
inline constexpr Opcode OP_4{0x54};
inline constexpr Opcode OP_5{0x55};
inline constexpr Opcode OP_6{0x56};
inline constexpr Opcode OP_7{0x57};
inline constexpr Opcode OP_8{0x58};
inline constexpr Opcode OP_9{0x59};
inline constexpr Opcode OP_10{0x5a};
inline constexpr Opcode OP_11{0x5b};
inline constexpr Opcode OP_12{0x5c};
inline constexpr Opcode OP_13{0x5d};
inline constexpr Opcode OP_14{0x5e};
inline constexpr Opcode OP_15{0x5f};
inline constexpr Opcode OP_16{0x60};
inline constexpr Opcode OP_NOP{0x61};
inline constexpr Opcode OP_VER{0x62};
inline constexpr Opcode OP_IF{0x63};
inline constexpr Opcode OP_NOTIF{0x64};
inline constexpr Opcode OP_VERIF{0x65};
inline constexpr Opcode OP_VERNOTIF{0x66};
inline constexpr Opcode OP_ELSE{0x67};
inline constexpr Opcode OP_ENDIF{0x68};
inline constexpr Opcode OP_VERIFY{0x69};
inline constexpr Opcode OP_RETURN{0x6a};
inline constexpr Opcode OP_TOALTSTACK{0x6b};
inline constexpr Opcode OP_FROMALTSTACK{0x6c};
inline constexpr Opcode OP_2DROP{0x6d};
inline constexpr Opcode OP_2DUP{0x6e};
inline constexpr Opcode OP_3DUP{0x6f};
inline constexpr Opcode OP_2OVER{0x70};
inline constexpr Opcode OP_2ROT{0x71};
inline constexpr Opcode OP_2SWAP{0x72};
inline constexpr Opcode OP_IFDUP{0x73};
inline constexpr Opcode OP_DEPTH{0x74};
inline constexpr Opcode OP_DROP{0x75};
inline constexpr Opcode OP_DUP{0x76};
inline constexpr Opcode OP_NIP{0x77};
inline constexpr Opcode OP_OVER{0x78};
inline constexpr Opcode OP_PICK{0x79};
inline constexpr Opcode OP_ROLL{0x7a};
inline constexpr Opcode OP_ROT{0x7b};
inline constexpr Opcode OP_SWAP{0x7c};
inline constexpr Opcode OP_TUCK{0x7d};
inline constexpr Opcode OP_CAT{0x7e};
inline constexpr Opcode OP_SPLIT{0x7f};
inline constexpr Opcode OP_NUM2BIN{0x80};
inline constexpr Opcode OP_BIN2NUM{0x81};
inline constexpr Opcode OP_SIZE{0x82};
inline constexpr Opcode OP_INVERT{0x83};
inline constexpr Opcode OP_AND{0x84};
inline constexpr Opcode OP_OR{0x85};
inline constexpr Opcode OP_XOR{0x86};
inline constexpr Opcode OP_EQUAL{0x87};
inline constexpr Opcode OP_EQUALVERIFY{0x88};
inline constexpr Opcode OP_RESERVED1{0x89};
inline constexpr Opcode OP_RESERVED2{0x8a};
inline constexpr Opcode OP_1ADD{0x8b};
inline constexpr Opcode OP_1SUB{0x8c};
inline constexpr Opcode OP_2MUL{0x8d};
inline constexpr Opcode OP_2DIV{0x8e};
inline constexpr Opcode OP_NEGATE{0x8f};
inline constexpr Opcode OP_ABS{0x90};
inline constexpr Opcode OP_NOT{0x91};
inline constexpr Opcode OP_0NOTEQUAL{0x92};
inline constexpr Opcode OP_ADD{0x93};
inline constexpr Opcode OP_SUB{0x94};
inline constexpr Opcode OP_MUL{0x95};
inline constexpr Opcode OP_DIV{0x96};
inline constexpr Opcode OP_MOD{0x97};
inline constexpr Opcode OP_LSHIFT{0x98};
inline constexpr Opcode OP_RSHIFT{0x99};
inline constexpr Opcode OP_BOOLAND{0x9a};
inline constexpr Opcode OP_BOOLOR{0x9b};
inline constexpr Opcode OP_NUMEQUAL{0x9c};
inline constexpr Opcode OP_NUMEQUALVERIFY{0x9d};
inline constexpr Opcode OP_NUMNOTEQUAL{0x9e};
inline constexpr Opcode OP_LESSTHAN{0x9f};
inline constexpr Opcode OP_GREATERTHAN{0xa0};
inline constexpr Opcode OP_LESSTHANOREQUAL{0xa1};
inline constexpr Opcode OP_GREATERTHANOREQUAL{0xa2};
inline constexpr Opcode OP_MIN{0xa3};
inline constexpr Opcode OP_MAX{0xa4};
inline constexpr Opcode OP_WITHIN{0xa5};
inline constexpr Opcode OP_RIPEMD160{0xa6};
inline constexpr Opcode OP_SHA1{0xa7};
inline constexpr Opcode OP_SHA256{0xa8};
inline constexpr Opcode OP_HASH160{0xa9};
inline constexpr Opcode OP_HASH256{0xaa};
inline constexpr Opcode OP_CODESEPARATOR{0xab};
inline constexpr Opcode OP_CHECKSIG{0xac};
inline constexpr Opcode OP_CHECKSIGVERIFY{0xad};
inline constexpr Opcode OP_CHECKMULTISIG{0xae};
inline constexpr Opcode OP_CHECKMULTISIGVERIFY{0xaf};
inline constexpr Opcode OP_NOP1{0xb0};
inline constexpr Opcode OP_CHECKLOCKTIMEVERIFY{0xb1};
inline constexpr Opcode OP_NOP2{0xb1};
inline constexpr Opcode OP_CHECKSEQUENCEVERIFY{0xb2};
inline constexpr Opcode OP_NOP3{0xb2};
inline constexpr Opcode OP_NOP4{0xb3};
inline constexpr Opcode OP_NOP5{0xb4};
inline constexpr Opcode OP_NOP6{0xb5};
inline constexpr Opcode OP_NOP7{0xb6};
inline constexpr Opcode OP_NOP8{0xb7};
inline constexpr Opcode OP_NOP9{0xb8};
inline constexpr Opcode OP_NOP10{0xb9};
inline constexpr Opcode OP_CHECKDATASIG{0xba};
inline constexpr Opcode OP_CHECKDATASIGVERIFY{0xbb};
inline constexpr Opcode OP_REVERSEBYTES{0xbc};
inline constexpr Opcode OP_PREFIX_BEGIN{0xf0};
inline constexpr Opcode OP_PREFIX_END{0xf7};
inline constexpr Opcode OP_INVALIDOPCODE{0xff};

/**
 * Name of an opcode number; for aliases (OP_0/OP_FALSE etc.) the first
 * definition wins, as in Rust's generated match.
 */
std::optional<std::string_view> OpcodeNumberToName(uint8_t opcode);

} // namespace chronik::native::script

#endif // CHRONIK_NATIVE_SCRIPT_OPCODE_H
