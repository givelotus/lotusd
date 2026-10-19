// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-core: script/script.rs, script/variant.rs and
// script/opcode.rs tests.

#include <chronik/native/script/script.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::script;

namespace {

Bytes Hex(std::string_view hex) {
    std::string clean;
    for (char c : hex) {
        if (c != ' ' && c != '\n') {
            clean += c;
        }
    }
    return HexDecode(clean).value();
}

Bytes Repeat(uint8_t b, size_t n) {
    return Bytes(n, b);
}

} // namespace

BOOST_AUTO_TEST_SUITE(script_tests)


// opcode.rs: test_opcode_from_u8
BOOST_AUTO_TEST_CASE(test_opcode_from_u8) {
    BOOST_CHECK_EQUAL(OP_0.number(), 0);
    BOOST_CHECK_EQUAL(OP_1.number(), 0x51);
    BOOST_CHECK_EQUAL(OP_TRUE.number(), 0x51);
}

// opcode.rs: test_display_opcode
BOOST_AUTO_TEST_CASE(test_display_opcode) {
    BOOST_CHECK_EQUAL(OP_0.ToString(), "OP_0");
    BOOST_CHECK_EQUAL(OP_1.ToString(), "OP_1");
    BOOST_CHECK_EQUAL(OP_TRUE.ToString(), "OP_1");
    // Additional: alias display and unknown opcodes
    BOOST_CHECK_EQUAL(OP_NOP2.ToString(), "OP_CHECKLOCKTIMEVERIFY");
    BOOST_CHECK_EQUAL(OP_NOP3.ToString(), "OP_CHECKSEQUENCEVERIFY");
    BOOST_CHECK_EQUAL(Opcode{0xee}.ToString(), "[unrecognized opcode]");
    BOOST_CHECK(OpcodeNumberToName(0xff) == "OP_INVALIDOPCODE");
}

static void VerifySer(const Script &a, const Bytes &b) {
    BOOST_CHECK(a.Ser() == b);
    BOOST_CHECK_EQUAL(a.SerLen(), b.size());
    ByteView view = b;
    auto deser = Script::Deser(view);
    BOOST_REQUIRE(deser.ok());
    BOOST_CHECK(deser.value() == a);
    BOOST_CHECK(view.empty());
}

// script.rs: test_ser_script
BOOST_AUTO_TEST_CASE(test_ser_script) {
    VerifySer(Script(), {0x00});
    VerifySer(Script(Bytes{0x51}), {0x01, 0x51});
    VerifySer(Script(Bytes{0x51, 0x52}), {0x02, 0x51, 0x52});
    {
        Bytes expected{0xfd, 0xfd, 0};
        auto body = Repeat(4, 0xfd);
        expected.insert(expected.end(), body.begin(), body.end());
        VerifySer(Script(Repeat(4, 0xfd)), expected);
    }
    {
        Bytes expected{0xfe, 0, 0, 1, 0};
        auto body = Repeat(5, 0x10000);
        expected.insert(expected.end(), body.begin(), body.end());
        VerifySer(Script(Repeat(5, 0x10000)), expected);
    }
}

// Additional (op.rs has no #[test]): op parsing of all push encodings.
BOOST_AUTO_TEST_CASE(test_read_ops) {
    {
        Bytes data{0x51, 0x02, 0xaa, 0xbb, 0x4c, 0x01, 0xcc};
        ScriptOpIter iter(data);
        auto op = iter.Next();
        BOOST_CHECK(op->value() == Op::Code(OP_1));
        op = iter.Next();
        BOOST_CHECK(op->value() == Op::Push(Opcode{2}, {0xaa, 0xbb}));
        op = iter.Next();
        BOOST_CHECK(op->value() == Op::Push(OP_PUSHDATA1, {0xcc}));
        BOOST_CHECK(!iter.Next());
    }
    {
        Bytes data{0x4d, 0x01, 0x00, 0xdd, 0x4e, 0x01, 0x00, 0x00, 0x00, 0xee};
        ScriptOpIter iter(data);
        BOOST_CHECK(iter.Next()->value() == Op::Push(OP_PUSHDATA2, {0xdd}));
        BOOST_CHECK(iter.Next()->value() == Op::Push(OP_PUSHDATA4, {0xee}));
        BOOST_CHECK(!iter.Next());
    }
    // Errors stop iteration
    for (const auto &[data, expected] :
         std::vector<std::pair<Bytes, size_t>>{
             {{0x02, 0x00}, 2}, {{0x4c}, 1}, {{0x4d, 0x00}, 2}, {{0x4e}, 4}}) {
        ScriptOpIter iter(data);
        auto op = iter.Next();
        BOOST_REQUIRE(op && !op->ok());
        BOOST_CHECK(op->error().kind == DataError::Kind::InvalidLength);
        BOOST_CHECK_EQUAL(op->error().expected, expected);
        BOOST_CHECK(!iter.Next());
    }
    BOOST_CHECK_EQUAL(DataError::InvalidLength(4, 0).ToString(),
                      "Invalid length, expected 4 bytes but got 0 bytes");
}

// script.rs: test_variant
BOOST_AUTO_TEST_CASE(test_variant) {
    const Bytes uncomp_pk = Repeat(4, 65);
    BOOST_CHECK(Script::P2pkUncompressed(uncomp_pk).Variant() ==
                (ScriptVariant{ScriptType::P2PK, uncomp_pk}));

    const Bytes not_uncomp_pk = Repeat(6, 65);
    Bytes script_bytes{0x41};
    auto rep = Repeat(6, 65);
    script_bytes.insert(script_bytes.end(), rep.begin(), rep.end());
    script_bytes.push_back(0xac);
    BOOST_CHECK(Script::P2pkUncompressed(not_uncomp_pk).Variant() ==
                (ScriptVariant{ScriptType::Other, script_bytes}));

    const Bytes comp_pk_0x02 = Repeat(2, 33);
    BOOST_CHECK(Script::P2pk(comp_pk_0x02).Variant() ==
                (ScriptVariant{ScriptType::P2PK, comp_pk_0x02}));

    Bytes comp_pk_0x03 = Repeat(6, 33);
    comp_pk_0x03[0] = 0x03;
    BOOST_CHECK(Script::P2pk(comp_pk_0x03).Variant() ==
                (ScriptVariant{ScriptType::P2PK, comp_pk_0x03}));

    const Bytes not_comp_pk = Repeat(6, 33);
    Bytes not_comp_script{0x21};
    not_comp_script.insert(not_comp_script.end(), not_comp_pk.begin(),
                           not_comp_pk.end());
    not_comp_script.push_back(0xac);
    BOOST_CHECK(Script::P2pk(not_comp_pk).Variant() ==
                (ScriptVariant{ScriptType::Other, not_comp_script}));

    Bytes script_data{0x21};
    script_data.insert(script_data.end(), comp_pk_0x03.begin(),
                       comp_pk_0x03.end());
    script_data.push_back(0xac);
    BOOST_CHECK(Script(script_data).Variant() ==
                (ScriptVariant{ScriptType::P2PK, comp_pk_0x03}));

    BOOST_CHECK(Script(not_comp_script).Variant() ==
                (ScriptVariant{ScriptType::Other, not_comp_script}));

    // P2PKH / P2SH
    ShaRmd160 hash;
    hash.fill(0x11);
    BOOST_CHECK(Script::P2pkh(hash).Variant() ==
                (ScriptVariant{ScriptType::P2PKH, Repeat(0x11, 20)}));
    BOOST_CHECK(Script::P2sh(hash).Variant() ==
                (ScriptVariant{ScriptType::P2SH, Repeat(0x11, 20)}));
    BOOST_CHECK(Script::P2pkh(hash).Variant().ToScript() ==
                Script::P2pkh(hash));
    BOOST_CHECK(Script::P2sh(hash).Variant().ToScript() == Script::P2sh(hash));
}

// script.rs: test_script_display
BOOST_AUTO_TEST_CASE(test_script_display) {
    ShaRmd160 ff;
    ff.fill(0xff);
    BOOST_CHECK_EQUAL(Script::P2pkh(ff).ToString(),
                      "OP_DUP OP_HASH160 "
                      "0xffffffffffffffffffffffffffffffffffffffff "
                      "OP_EQUALVERIFY OP_CHECKSIG");
    BOOST_CHECK_EQUAL(Script(Hex("ee")).ToString(), "[unrecognized opcode]");
    BOOST_CHECK_EQUAL(Script(Hex("0200")).ToString(), "[corrupt PUSHDATA]");
    BOOST_CHECK_EQUAL(Script(Hex("6a4c00")).ToString(), "OP_RETURN \"\"");
    BOOST_CHECK_EQUAL(
        Script(Hex("6a334368616e63656c6c6f72206f6e20746865204272696e6b206"
                   "f66205365636f6e64204261696c6f757420666f722042616e6b73"))
            .ToString(),
        "OP_RETURN \"Chancellor on the Brink of Second Bailout for Banks\"");
    BOOST_CHECK_EQUAL(
        Script(Hex("6a16d791d6b0d6bcd7a8d6b5d790d7a9d6b4d781d799d7aa"))
            .ToString(),
        "OP_RETURN \"\xd7\x91\xd6\xb0\xd6\xbc\xd7\xa8\xd6\xb5\xd7\x90\xd7\xa9"
        "\xd6\xb4\xd7\x81\xd7\x99\xd7\xaa\"");
    BOOST_CHECK_EQUAL(
        Script(Hex("6a04534c500001010453454e44207e7dacd72dcdb14e00a03dd3a"
                   "ff47f019ed51a6f1f4e4f532ae50692f62bc4e5080000000000038"
                   "bd708000000000000091408000000000000092b080000000000000"
                   "67c08000000000000067c080000000000000cf7080000000000000"
                   "19f08000000000000033e08000000000000019f080000000000000"
                   "e6108000000000000002a"))
            .ToString(),
        "OP_RETURN \"SLP\\0\" 0x01 \"SEND\" "
        "0x7e7dacd72dcdb14e00a03dd3aff47f019ed51a6f1f4e4f532ae50692f62bc4e5 "
        "0x0000000000038bd7 0x0000000000000914 0x000000000000092b "
        "0x000000000000067c 0x000000000000067c 0x0000000000000cf7 "
        "0x000000000000019f 0x000000000000033e 0x000000000000019f "
        "0x0000000000000e61 0x000000000000002a");
    BOOST_CHECK_EQUAL(
        Script(Hex("6a2a313233343536373839302d3d21402324255e262a28295f2b6"
                   "07e5b5d5c7b7d7c3b273a222c2e2f3c3e3f"))
            .ToString(),
        "OP_RETURN \"1234567890-=!@#$%^&*()_+`~[]\\{}|;':\",./<>?\"");
    BOOST_CHECK_EQUAL(Script(Hex("6a094769766520f09faab7")).ToString(),
                      "OP_RETURN \"Give \xf0\x9f\xaa\xb7\"");
}

// variant.rs: test_script_type
BOOST_AUTO_TEST_CASE(test_script_type) {
    BOOST_CHECK(ParseScriptType("p2pkh").value() == ScriptType::P2PKH);
    BOOST_CHECK(ParseScriptType("p2sh").value() == ScriptType::P2SH);
    BOOST_CHECK(ParseScriptType("p2pk").value() == ScriptType::P2PK);
    BOOST_CHECK(ParseScriptType("other").value() == ScriptType::Other);
    BOOST_CHECK_EQUAL(ParseScriptType("foobar").error(),
                      "Unknown script type: foobar");
}

// variant.rs: test_script_variant
BOOST_AUTO_TEST_CASE(test_script_variant) {
    BOOST_CHECK(ScriptVariant::FromTypeAndPayload(ScriptType::P2PKH,
                                                  Repeat(2, 33))
                    .error() == DataError::InvalidLength(20, 33));
    BOOST_CHECK(ScriptVariant::FromTypeAndPayload(ScriptType::P2SH,
                                                  Repeat(2, 33))
                    .error() == DataError::InvalidLength(20, 33));
    const auto err_p2pk20 =
        ScriptVariant::FromTypeAndPayload(ScriptType::P2PK, Repeat(2, 20))
            .error();
    BOOST_CHECK(err_p2pk20 == DataError::InvalidLengthMulti({33, 65}, 20));
    BOOST_CHECK_EQUAL(
        err_p2pk20.ToString(),
        "Invalid length, expected one of [33, 65] but got 20 bytes");
    BOOST_CHECK(ScriptVariant::FromTypeAndPayload(ScriptType::P2PK,
                                                  Repeat(4, 64))
                    .error() == DataError::InvalidLengthMulti({33, 65}, 64));
    BOOST_CHECK(ScriptVariant::FromTypeAndPayload(ScriptType::Other,
                                                  Repeat(4, 64))
                    .ok());
}

// variant.rs: test_script_variant_to_string
BOOST_AUTO_TEST_CASE(test_script_variant_to_string) {
    BOOST_CHECK_EQUAL(
        (ScriptVariant{ScriptType::P2PKH, Repeat(1, 20)}).ToString(),
        "p2pkh(0101010101010101010101010101010101010101)");
    BOOST_CHECK_EQUAL(
        (ScriptVariant{ScriptType::P2SH, Repeat(2, 20)}).ToString(),
        "p2sh(0202020202020202020202020202020202020202)");
    BOOST_CHECK_EQUAL(
        (ScriptVariant{ScriptType::P2PK, Repeat(3, 33)}).ToString(),
        "p2pk(030303030303030303030303030303030303030303030303030303030303"
        "030303)");
    BOOST_CHECK_EQUAL(
        (ScriptVariant{ScriptType::P2PK, Repeat(4, 65)}).ToString(),
        "p2pk(040404040404040404040404040404040404040404040404040404040404"
        "040404040404040404040404040404040404040404040404040404040404"
        "0404040404)");
    BOOST_CHECK_EQUAL(
        (ScriptVariant{ScriptType::Other, Hex("deafbeef")}).ToString(),
        "other(deafbeef)");
}

BOOST_AUTO_TEST_CASE(test_hex_and_debug_formats) {
    BOOST_CHECK(HexDecode("0aFf").value() == (Bytes{0x0a, 0xff}));
    BOOST_CHECK_EQUAL(HexDecode("abc").error().ToString(),
                      "Invalid hex: Odd number of digits");
    BOOST_CHECK_EQUAL(HexDecode("0x").error().ToString(),
                      "Invalid hex: Invalid character 'x' at position 1");
    BOOST_CHECK_EQUAL(DebugBytes(Bytes{'S', 'L', 'P', 0}), "b\"SLP\\0\"");
    BOOST_CHECK_EQUAL(DebugBytes(Bytes{'S', 'L', 'P', 0x99, '"', '\\', '\n'}),
                      "b\"SLP\\x99\\\"\\\\\\n\"");
    BOOST_CHECK_EQUAL(DebugSizes({0, 32}), "[0, 32]");
}

// Additional: doc tests of script_mut.rs
BOOST_AUTO_TEST_CASE(test_script_mut_doc) {
    BOOST_CHECK(ScriptMut().Freeze().bytecode().empty());
    {
        ScriptMut script_mut;
        script_mut.PutOpcodes({OP_EQUAL, OP_TRUE});
        BOOST_CHECK_EQUAL(script_mut.Freeze().Hex(), "8751");
    }
    {
        ScriptMut script_mut;
        script_mut.PutBytecode(Bytes{1, 2, 3, 4, 5});
        BOOST_CHECK(script_mut.Freeze() == Script(Bytes{1, 2, 3, 4, 5}));
    }
    auto pushdata = [](const Bytes &data) {
        ScriptMut script_mut;
        script_mut.PutPushdata(data);
        return script_mut.Freeze().bytecode();
    };
    BOOST_CHECK_EQUAL(HexEncode(pushdata({})), "00");
    BOOST_CHECK_EQUAL(HexEncode(pushdata({0x77})), "0177");
    {
        Bytes expected{0x4c, 0x4c};
        auto body = Repeat(0x55, 0x4c);
        expected.insert(expected.end(), body.begin(), body.end());
        BOOST_CHECK(pushdata(Repeat(0x55, 0x4c)) == expected);
    }
    {
        Bytes expected{0x4d, 0x00, 0x01};
        auto body = Repeat(0x33, 0x100);
        expected.insert(expected.end(), body.begin(), body.end());
        BOOST_CHECK(pushdata(Repeat(0x33, 0x100)) == expected);
    }
    {
        Bytes expected{0x4e, 0x00, 0x00, 0x01, 0x00};
        auto body = Repeat(0x22, 0x10000);
        expected.insert(expected.end(), body.begin(), body.end());
        BOOST_CHECK(pushdata(Repeat(0x22, 0x10000)) == expected);
    }
    auto slp_pushdata = [](const Bytes &data) {
        ScriptMut script_mut;
        script_mut.PutSlpPushdata(data);
        return script_mut.Freeze().Hex();
    };
    BOOST_CHECK_EQUAL(slp_pushdata({}), "4c00");
    BOOST_CHECK_EQUAL(slp_pushdata({0x77}), "0177");
}

// Additional: doc tests of script.rs
BOOST_AUTO_TEST_CASE(test_script_doc) {
    ShaRmd160 hash;
    const Bytes hash_bytes = Hex("00112233445566778899aabbccddeeff00112233");
    std::copy(hash_bytes.begin(), hash_bytes.end(), hash.begin());
    BOOST_CHECK_EQUAL(Script::P2pkh(hash).Hex(),
                      "76a91400112233445566778899aabbccddeeff0011223388ac");
    BOOST_CHECK_EQUAL(Script::P2sh(hash).Hex(),
                      "a91400112233445566778899aabbccddeeff0011223387");
    BOOST_CHECK_EQUAL(
        Script::P2pk(Hex("0200112233445566778899aabbccddeeff00112233445566778"
                         "899aabbccddeeff"))
            .Hex(),
        "210200112233445566778899aabbccddeeff00112233445566778899aabbccddee"
        "ffac");
    BOOST_CHECK_EQUAL(
        Script::P2pkUncompressed(
            Hex("0400112233445566778899aabbccddeeff00112233445566778899aabbccd"
                "deeff00112233445566778899aabbccddeeff001122334455667788"
                "99aabbccddeeff"))
            .Hex(),
        "410400112233445566778899aabbccddeeff00112233445566778899aabbccddee"
        "ff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        "ac");
    BOOST_CHECK_EQUAL(Script(Bytes{0x51}).Hex(), "51");
    BOOST_CHECK(Script(Bytes{0x6a}).IsOpReturn());
    BOOST_CHECK(Script(Bytes{0x6a, 0x00}).IsOpReturn());
    BOOST_CHECK(!Script(Bytes{0x6f}).IsOpReturn());

    // Simple script
    {
        const Script script(Hex("0301020387"));
        auto iter = script.IterOps();
        BOOST_CHECK(iter.Next()->value() == Op::Push(Opcode{3}, {1, 2, 3}));
        BOOST_CHECK(iter.Next()->value() == Op::Code(OP_EQUAL));
        BOOST_CHECK(!iter.Next());
    }
    // Complex script; has invalid op at the end
    {
        const Script script(Hex("6a504c021234004d01001260884cffabcd"));
        auto iter = script.IterOps();
        BOOST_CHECK(iter.Next()->value() == Op::Code(OP_RETURN));
        BOOST_CHECK(iter.Next()->value() == Op::Code(OP_RESERVED));
        BOOST_CHECK(iter.Next()->value() ==
                    Op::Push(OP_PUSHDATA1, {0x12, 0x34}));
        BOOST_CHECK(iter.Next()->value() == Op::Code(OP_0));
        BOOST_CHECK(iter.Next()->value() == Op::Push(OP_PUSHDATA2, {0x12}));
        BOOST_CHECK(iter.Next()->value() == Op::Code(OP_16));
        BOOST_CHECK(iter.Next()->value() == Op::Code(OP_EQUALVERIFY));
        BOOST_CHECK(iter.Next()->error() == DataError::InvalidLength(0xff, 2));
        BOOST_CHECK(!iter.Next());
    }

    // variant()
    hash.fill(4);
    BOOST_CHECK(Script::P2pkh(hash).Variant() ==
                (ScriptVariant{ScriptType::P2PKH, Repeat(4, 20)}));
    BOOST_CHECK(Script::P2sh(hash).Variant() ==
                (ScriptVariant{ScriptType::P2SH, Repeat(4, 20)}));
    BOOST_CHECK(Script::P2pk(Repeat(2, 33)).Variant() ==
                (ScriptVariant{ScriptType::P2PK, Repeat(2, 33)}));
    BOOST_CHECK(Script::P2pkUncompressed(Repeat(4, 65)).Variant() ==
                (ScriptVariant{ScriptType::P2PK, Repeat(4, 65)}));
    BOOST_CHECK(Script().Variant() == (ScriptVariant{ScriptType::Other, {}}));
}

// Additional: doc test of pubkey_variant.rs
BOOST_AUTO_TEST_CASE(test_pubkey_variant_doc) {
    BOOST_CHECK(
        ScriptVariant::FromTypeAndPayload(ScriptType::P2PK, Repeat(2, 33))
            .value() == (ScriptVariant{ScriptType::P2PK, Repeat(2, 33)}));
    BOOST_CHECK(
        ScriptVariant::FromTypeAndPayload(ScriptType::P2PK, Repeat(4, 65))
            .value() == (ScriptVariant{ScriptType::P2PK, Repeat(4, 65)}));
    BOOST_CHECK(
        ScriptVariant::FromTypeAndPayload(ScriptType::P2PK, Repeat(4, 66))
            .error() == DataError::InvalidLengthMulti({33, 65}, 66));
}

BOOST_AUTO_TEST_SUITE_END()
