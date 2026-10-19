// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-http protobuf.rs / validation.rs, and an emulation of
// prost 0.11.9 Message::decode error reporting (the DecodeError Display text
// is part of Chronik's wire-visible error messages).

#include <chronik/native/error.h>
#include <chronik/native/http.h>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include <string>
#include <utility>
#include <vector>

namespace chronik::native {

namespace {

using google::protobuf::Descriptor;
using google::protobuf::FieldDescriptor;

enum class WireType : uint8_t {
    Varint = 0,
    SixtyFourBit = 1,
    LengthDelimited = 2,
    StartGroup = 3,
    EndGroup = 4,
    ThirtyTwoBit = 5,
};

const char *WireTypeName(WireType wt) {
    switch (wt) {
        case WireType::Varint:
            return "Varint";
        case WireType::SixtyFourBit:
            return "SixtyFourBit";
        case WireType::LengthDelimited:
            return "LengthDelimited";
        case WireType::StartGroup:
            return "StartGroup";
        case WireType::EndGroup:
            return "EndGroup";
        case WireType::ThirtyTwoBit:
            return "ThirtyTwoBit";
    }
    return "?";
}

struct DecodeErr {
    std::string description;
    std::vector<std::pair<std::string, std::string>> stack;
};

constexpr int RECURSION_LIMIT = 100;

/** Single cursor over the whole buffer, like prost's `&mut impl Buf`. */
struct ProstReader {
    const uint8_t *data;
    size_t size;
    size_t pos = 0;

    size_t Remaining() const { return size - pos; }

    [[noreturn]] static void Fail(std::string desc) {
        throw DecodeErr{std::move(desc), {}};
    }

    uint64_t Varint() {
        // prost decode_varint (fast slice and slow paths agree): up to 10
        // bytes, the 10th must be < 0x02; running out is an error.
        uint64_t value = 0;
        const size_t max = std::min<size_t>(10, Remaining());
        for (size_t count = 0; count < max; ++count) {
            const uint8_t byte = data[pos + count];
            value |= uint64_t(byte & 0x7F) << (count * 7);
            if (byte <= 0x7F) {
                if (count == 9 && byte >= 0x02) {
                    Fail("invalid varint");
                }
                pos += count + 1;
                return value;
            }
        }
        Fail("invalid varint");
    }

    std::pair<uint32_t, WireType> Key() {
        const uint64_t key = Varint();
        if (key > 0xFFFFFFFFull) {
            Fail("invalid key value: " + std::to_string(key));
        }
        const uint64_t wt = key & 0x07;
        if (wt > 5) {
            Fail("invalid wire type value: " + std::to_string(wt));
        }
        const uint32_t tag = uint32_t(key) >> 3;
        if (tag < 1) {
            Fail("invalid tag value: 0");
        }
        return {tag, WireType(wt)};
    }

    void Advance(uint64_t len) {
        if (len > Remaining()) {
            Fail("buffer underflow");
        }
        pos += size_t(len);
    }
};

void CheckWireType(WireType expected, WireType actual) {
    if (expected != actual) {
        ProstReader::Fail(std::string("invalid wire type: ") +
                          WireTypeName(actual) + " (expected " +
                          WireTypeName(expected) + ")");
    }
}

void LimitReached(int recurse) {
    if (recurse == 0) {
        ProstReader::Fail("recursion limit reached");
    }
}

void SkipField(ProstReader &r, WireType wt, uint32_t tag, int recurse) {
    LimitReached(recurse);
    uint64_t len = 0;
    switch (wt) {
        case WireType::Varint:
            r.Varint();
            break;
        case WireType::ThirtyTwoBit:
            len = 4;
            break;
        case WireType::SixtyFourBit:
            len = 8;
            break;
        case WireType::LengthDelimited:
            len = r.Varint();
            break;
        case WireType::StartGroup:
            while (true) {
                auto [inner_tag, inner_wt] = r.Key();
                if (inner_wt == WireType::EndGroup) {
                    if (inner_tag != tag) {
                        ProstReader::Fail("unexpected end group tag");
                    }
                    break;
                }
                SkipField(r, inner_wt, inner_tag, recurse - 1);
            }
            break;
        case WireType::EndGroup:
            ProstReader::Fail("unexpected end group tag");
    }
    r.Advance(len);
}

template <typename F> void MergeLoop(ProstReader &r, F &&merge) {
    const uint64_t len = r.Varint();
    const size_t remaining = r.Remaining();
    if (len > remaining) {
        ProstReader::Fail("buffer underflow");
    }
    const size_t limit = remaining - size_t(len);
    while (r.Remaining() > limit) {
        merge();
    }
    if (r.Remaining() != limit) {
        ProstReader::Fail("delimited length exceeded");
    }
}

bool IsValidUtf8(const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t b = p[i];
        size_t need;
        uint8_t lo = 0x80, hi = 0xBF;
        if (b < 0x80) {
            ++i;
            continue;
        } else if (b >= 0xC2 && b <= 0xDF) {
            need = 1;
        } else if (b >= 0xE0 && b <= 0xEF) {
            need = 2;
            lo = b == 0xE0 ? 0xA0 : 0x80;
            hi = b == 0xED ? 0x9F : 0xBF;
        } else if (b >= 0xF0 && b <= 0xF4) {
            need = 3;
            lo = b == 0xF0 ? 0x90 : 0x80;
            hi = b == 0xF4 ? 0x8F : 0xBF;
        } else {
            return false;
        }
        if (i + need >= n) {
            return false;
        }
        for (size_t j = 1; j <= need; ++j) {
            uint8_t c = p[i + j];
            uint8_t l = j == 1 ? lo : 0x80, h = j == 1 ? hi : 0xBF;
            if (c < l || c > h) {
                return false;
            }
        }
        i += need + 1;
    }
    return true;
}

WireType ExpectedWireType(const FieldDescriptor *field) {
    switch (field->type()) {
        case FieldDescriptor::TYPE_INT32:
        case FieldDescriptor::TYPE_INT64:
        case FieldDescriptor::TYPE_UINT32:
        case FieldDescriptor::TYPE_UINT64:
        case FieldDescriptor::TYPE_SINT32:
        case FieldDescriptor::TYPE_SINT64:
        case FieldDescriptor::TYPE_BOOL:
        case FieldDescriptor::TYPE_ENUM:
            return WireType::Varint;
        case FieldDescriptor::TYPE_FIXED64:
        case FieldDescriptor::TYPE_SFIXED64:
        case FieldDescriptor::TYPE_DOUBLE:
            return WireType::SixtyFourBit;
        case FieldDescriptor::TYPE_FIXED32:
        case FieldDescriptor::TYPE_SFIXED32:
        case FieldDescriptor::TYPE_FLOAT:
            return WireType::ThirtyTwoBit;
        case FieldDescriptor::TYPE_GROUP:
            return WireType::StartGroup;
        default:
            return WireType::LengthDelimited;
    }
}

void MergeOneField(ProstReader &r, const Descriptor *desc, int recurse);
void MergeField(ProstReader &r, const FieldDescriptor *field, WireType wt,
                int recurse);

/** One scalar/string/bytes/message value of `field`, prost merge rules. */
void MergeValue(ProstReader &r, const FieldDescriptor *field, WireType wt,
                int recurse) {
    const WireType expected = ExpectedWireType(field);
    CheckWireType(expected, wt);
    switch (field->type()) {
        case FieldDescriptor::TYPE_MESSAGE: {
            LimitReached(recurse);
            const Descriptor *inner = field->message_type();
            MergeLoop(r, [&] { MergeOneField(r, inner, recurse - 1); });
            return;
        }
        case FieldDescriptor::TYPE_STRING:
        case FieldDescriptor::TYPE_BYTES: {
            const uint64_t len = r.Varint();
            if (len > r.Remaining()) {
                ProstReader::Fail("buffer underflow");
            }
            const uint8_t *start = r.data + r.pos;
            r.pos += size_t(len);
            if (field->type() == FieldDescriptor::TYPE_STRING &&
                !IsValidUtf8(start, size_t(len))) {
                ProstReader::Fail(
                    "invalid string value: data is not UTF-8 encoded");
            }
            return;
        }
        case FieldDescriptor::TYPE_GROUP:
            // Not used by proto3; skip it like an unknown group.
            SkipField(r, wt, uint32_t(field->number()), recurse);
            return;
        default:
            break;
    }
    switch (expected) {
        case WireType::Varint:
            r.Varint();
            return;
        case WireType::ThirtyTwoBit:
            if (r.Remaining() < 4) {
                ProstReader::Fail("buffer underflow");
            }
            r.pos += 4;
            return;
        case WireType::SixtyFourBit:
            if (r.Remaining() < 8) {
                ProstReader::Fail("buffer underflow");
            }
            r.pos += 8;
            return;
        default:
            return;
    }
}

void MergeField(ProstReader &r, const FieldDescriptor *field, WireType wt,
                int recurse) {
    if (field->is_map()) {
        // prost hash_map::merge ignores the wire type of the entry
        LimitReached(recurse);
        const Descriptor *entry = field->message_type();
        MergeLoop(r, [&] {
            auto [tag, entry_wt] = r.Key();
            const FieldDescriptor *kv = entry->FindFieldByNumber(int(tag));
            if ((tag == 1 || tag == 2) && kv) {
                MergeValue(r, kv, entry_wt, recurse - 1);
            } else {
                SkipField(r, entry_wt, tag, recurse - 1);
            }
        });
        return;
    }
    if (field->is_repeated()) {
        const bool packable = field->type() != FieldDescriptor::TYPE_STRING &&
                              field->type() != FieldDescriptor::TYPE_BYTES &&
                              field->type() != FieldDescriptor::TYPE_MESSAGE &&
                              field->type() != FieldDescriptor::TYPE_GROUP;
        if (packable && wt == WireType::LengthDelimited) {
            MergeLoop(r, [&] {
                MergeValue(r, field, ExpectedWireType(field), recurse);
            });
            return;
        }
        CheckWireType(ExpectedWireType(field), wt);
    }
    MergeValue(r, field, wt, recurse);
}

/** Decode one key and merge its field (prost-derive merge_field). */
void MergeOneField(ProstReader &r, const Descriptor *desc, int recurse) {
    auto [tag, wt] = r.Key();
    const FieldDescriptor *field = desc->FindFieldByNumber(int(tag));
    if (!field) {
        SkipField(r, wt, tag, recurse);
        return;
    }
    try {
        MergeField(r, field, wt, recurse);
    } catch (DecodeErr &err) {
        // prost-derive pushes (struct name, field ident); a oneof pushes the
        // oneof's field name.
        const auto *oneof = field->real_containing_oneof();
        err.stack.emplace_back(std::string(desc->name()),
                               oneof ? std::string(oneof->name())
                                     : std::string(field->name()));
        throw;
    }
}

void MergeMessageFields(ProstReader &r, const Descriptor *desc, int recurse) {
    while (r.Remaining() > 0) {
        MergeOneField(r, desc, recurse);
    }
}

/** http::HeaderValue::to_str: visible ASCII or tab only. */
bool HeaderToStr(const std::string &value) {
    for (unsigned char c : value) {
        if (!((c >= 32 && c < 127) || c == '\t')) {
            return false;
        }
    }
    return true;
}

} // namespace

std::optional<std::string>
ProstDecodeError(const google::protobuf::Message &msg, ByteView data) {
    ProstReader reader{data.data(), data.size()};
    try {
        MergeMessageFields(reader, msg.GetDescriptor(), RECURSION_LIMIT);
    } catch (const DecodeErr &err) {
        std::string out = "failed to decode Protobuf message: ";
        for (const auto &[message, field] : err.stack) {
            out += message + "." + field + ": ";
        }
        out += err.description;
        return out;
    }
    return std::nullopt;
}

void DecodeProtobuf(ByteView data, google::protobuf::Message &out) {
    if (auto err = ProstDecodeError(out, data)) {
        throw ChronikError(*err);
    }
    out.Clear();
    if (!out.ParseFromArray(data.data(), int(data.size()))) {
        throw ChronikError("failed to decode Protobuf message: invalid message");
    }
}

void CheckContentType(const HttpRequest &req, std::string_view expected) {
    const std::string *content_type = req.Header("content-type");
    if (!content_type) {
        throw ChronikError("400: No Content-Type set");
    }
    if (!HeaderToStr(*content_type)) {
        throw ChronikError("400: Content-Type bad encoding: failed to convert "
                           "header to a str");
    }
    if (*content_type != expected) {
        throw ChronikError("400: Content-Type must be " +
                           std::string(expected) + ", got " + *content_type);
    }
}

void ParseProtobufRequest(const HttpRequest &req,
                          google::protobuf::Message &out) {
    CheckContentType(req, CONTENT_TYPE_PROTOBUF);
    if (req.body_too_large || req.body.size() > MAX_REQUEST_BODY_SIZE) {
        throw ChronikError("413: Request body exceeds maximum size of " +
                           std::to_string(MAX_REQUEST_BODY_SIZE) + " bytes");
    }
    try {
        DecodeProtobuf(req.body, out);
    } catch (const ChronikError &err) {
        throw ChronikError(std::string("400: Bad protobuf: ") + err.what());
    }
}

} // namespace chronik::native
