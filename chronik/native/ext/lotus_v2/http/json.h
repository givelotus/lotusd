// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_JSON_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_JSON_H

#include <chronik/native/types.h>

#include <cstdint>
#include <functional>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

/**
 * The JSON of the Rust V2 HTTP routes (serde_json 1.0 without
 * preserve_order): a Value whose objects serialize with their keys sorted
 * (serde_json's Map is a BTreeMap), written compactly with serde_json's
 * string escapes, and a strict parser reproducing which documents
 * serde_json::from_slice accepts for the routes' derived request structs.
 */
namespace chronik::native::lotus_v2::http {

/** serde_json::Value restricted to what the routes emit. */
class Json {
public:
    enum class Kind { Null, Bool, UInt, Str, Arr, Obj };

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool b) : m_kind(Kind::Bool), m_bool(b) {}
    /** Integers must go through U() (no silent conversion to bool). */
    template <typename T>
        requires(std::is_integral_v<T> && !std::is_same_v<T, bool>)
    Json(T) = delete;
    /** Unsigned integers (serde serializes all of them as JSON numbers). */
    static Json U(uint64_t v);
    Json(std::string s) : m_kind(Kind::Str), m_str(std::move(s)) {}
    Json(const char *s) : Json(std::string(s)) {}
    Json(std::string_view s) : Json(std::string(s)) {}
    static Json Array(std::vector<Json> items = {});
    /** An object; later duplicate keys replace earlier ones. */
    static Json Object(std::initializer_list<std::pair<std::string, Json>> m);
    /** Optional value: null when absent. */
    template <typename T, typename F>
    static Json Opt(const std::optional<T> &v, F &&f) {
        return v ? Json(f(*v)) : Json();
    }

    Kind GetKind() const { return m_kind; }
    /** Object insert (replacing an existing key), like Map::insert. */
    void Set(std::string key, Json value);
    /** Object merge, like Map::extend. */
    void Extend(const Json &other);
    void Push(Json value);
    const std::vector<Json> &Items() const { return m_items; }

    /** Compact serde_json::to_vec. */
    std::string Dump() const;
    void Write(std::string &out) const;

private:
    Kind m_kind = Kind::Null;
    bool m_bool = false;
    uint64_t m_uint = 0;
    std::string m_str;
    std::vector<Json> m_items;
    std::vector<std::pair<std::string, Json>> m_members;
};

/** serde_json string serialization (quotes and escapes). */
void WriteJsonString(std::string_view s, std::string &out);

/**
 * A parsed JSON document keeping member order and duplicates, for typed
 * decoding with serde derive semantics.
 */
struct JsonNode {
    enum class Kind { Null, Bool, Num, Str, Arr, Obj };
    Kind kind = Kind::Null;
    bool b = false;
    /** Set for numbers serde_json parses as u64 (no sign/fraction/exp). */
    std::optional<uint64_t> u;
    std::string s;
    std::vector<JsonNode> arr;
    std::vector<std::pair<std::string, JsonNode>> obj;
};

/**
 * serde_json::from_slice syntax: one value with optional surrounding
 * whitespace, strict UTF-8 and escapes (no lone surrogates), recursion limit
 * 128. nullopt on any error.
 */
std::optional<JsonNode> ParseJson(ByteView bytes);

/**
 * One field of a derived struct for DecodeStruct: `set` receives the value
 * (nullptr when the field is missing and may be defaulted) and returns false
 * on a type error.
 */
struct JsonField {
    std::string_view name;
    /** #[serde(default)] */
    bool serde_default = false;
    /** Option<T> (missing in a map deserializes to None) */
    bool option = false;
    std::function<bool(const JsonNode *)> set;
};

/**
 * serde derive Deserialize with deny_unknown_fields: a map (unknown and
 * duplicate fields rejected) or a sequence (fields in order; missing
 * trailing fields only with #[serde(default)]; no extra elements).
 */
bool DecodeStruct(const JsonNode &node, const std::vector<JsonField> &fields);

/** Primitive serde deserializers (false on a type/range error). */
bool DecodeString(const JsonNode *node, std::string &out);
bool DecodeBool(const JsonNode *node, bool &out);
bool DecodeUnsigned(const JsonNode *node, uint64_t max, uint64_t &out);
bool DecodeStrings(const JsonNode *node, std::vector<std::string> &out);
bool DecodeOptString(const JsonNode *node, std::optional<std::string> &out);
bool DecodeOptBool(const JsonNode *node, std::optional<bool> &out);

} // namespace chronik::native::lotus_v2::http

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_JSON_H
