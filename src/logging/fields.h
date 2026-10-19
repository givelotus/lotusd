// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_FIELDS_H
#define BITCOIN_LOGGING_FIELDS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

/**
 * The structured log field vocabulary: the only keys a log event can carry.
 *
 * Every field is declared once, here, with its value type, its generic
 * snake_case name (used by text, logfmt, json, json-gcp, and as
 * LOTUS_<NAME> by journald) and its name in the Elastic Common Schema and
 * in the OpenTelemetry semantic conventions where those define one. A
 * field without a standard name is lotus.<name> in ECS and stays an
 * attribute named <name> elsewhere. Call sites name fields through the
 * typed keys in BCLog::LogField (e.g. LogField::PeerId), so a free-form
 * string key does not compile and a new field has to be added here, where
 * reviewers see it. Keys are small integers: a call site stores the id and
 * the value; names are looked up on the logger thread.
 *
 * Core fields (time, level, category, thread, source location, message)
 * are captured by the logger itself and are not in this table.
 *
 * Standard names (ECS 8.11 and OpenTelemetry semantic conventions 1.44;
 * see doc/logging-api.md):
 *  - Addr is a remote peer, not necessarily a network sender. ECS therefore
 *    keeps it custom (lotus.addr) rather than claiming source.address.
 *    It may contain host:port, so OTel keeps it custom too. PeerAddress and
 *    PeerPort map separately to network.peer.address / network.peer.port.
 *  - network.direction: ECS values include "inbound" and "outbound".
 *  - HttpUserAgent is the HTTP header; generic P2P UserAgent stays custom.
 *  - error.message: ECS only; OTel deprecated its generic error.message.
 *  - event.reason: ECS ("reason why this event happened").
 *  - event.duration: ECS, in nanoseconds (encoders convert).
 *  - Path is a full filesystem path (file.path in ECS and OTel).
 *  - Method is a recognized RPC method or _OTHER (OTel rpc.method).
 *    OriginalMethod preserves the raw name (rpc.method_original).
 */
#define BCLOG_FIELDS(X)                                                        \
    /* Id, generic name, type, ECS name, OTel name */                          \
    X(PeerId, peer_id, INT, "", "")                                            \
    X(Addr, addr, STRING, "", "")                                              \
    X(PeerAddress, peer_address, STRING, "", "network.peer.address")           \
    X(PeerPort, peer_port, INT, "", "network.peer.port")                       \
    X(Network, network, STRING, "", "")                                        \
    X(Direction, direction, STRING, "network.direction", "")                   \
    X(Transport, transport, STRING, "", "")                                    \
    X(ConnType, conn_type, STRING, "", "")                                     \
    X(UserAgent, user_agent, STRING, "", "")                                   \
    X(HttpUserAgent, http_user_agent, STRING, "user_agent.original",           \
      "user_agent.original")                                                   \
    X(Version, version, INT, "", "")                                           \
    X(Services, services, STRING, "", "")                                      \
    X(MsgType, msg_type, STRING, "", "")                                       \
    X(BlockHash, block_hash, HASH, "", "")                                     \
    X(Height, height, INT, "", "")                                             \
    X(TxId, txid, HASH, "", "")                                                \
    X(Bytes, bytes, UINT, "", "")                                              \
    X(Count, count, UINT, "", "")                                              \
    X(AmountSats, amount_sats, INT, "", "")                                    \
    X(Method, method, STRING, "", "rpc.method")                                \
    X(OriginalMethod, original_method, STRING, "", "rpc.method_original")      \
    X(Error, error, STRING, "error.message", "")                               \
    X(Reason, reason, STRING, "event.reason", "")                              \
    X(DurationUs, duration_us, DURATION, "event.duration", "")                 \
    X(Path, path, STRING, "file.path", "file.path")                            \
    X(Wallet, wallet, STRING, "", "")                                          \
    X(Name, name, STRING, "", "")                                              \
    X(Value, value, STRING, "", "")

namespace BCLog {

/** How a field's value is stored and rendered */
enum class FieldType : uint8_t {
    //! Signed integer (JSON number)
    INT,
    //! Unsigned integer (JSON number)
    UINT,
    //! Floating point (JSON number)
    FLOAT,
    //! true/false
    BOOL,
    //! Text (JSON string); also values rendered as text (addresses...)
    STRING,
    //! 256-bit hash, rendered as 64 lowercase hex digits (as in RPC)
    HASH,
    //! A duration; the generic unit is microseconds (JSON number)
    DURATION,
};

enum class FieldId : uint16_t {
#define BCLOG_FIELD_ID(id, name, type, ecs, otel) id,
    BCLOG_FIELDS(BCLOG_FIELD_ID)
#undef BCLOG_FIELD_ID
        COUNT
};

struct FieldInfo {
    //! Generic snake_case name
    std::string_view name;
    FieldType type;
    //! ECS name, or "" (then lotus.<name>)
    std::string_view ecs;
    //! OpenTelemetry semantic convention name, or "" (then <name>)
    std::string_view otel;
};

inline constexpr std::array<FieldInfo, size_t(FieldId::COUNT)> FIELDS{{
#define BCLOG_FIELD_INFO(id, name, type, ecs, otel)                            \
    FieldInfo{#name, FieldType::type, ecs, otel},
    BCLOG_FIELDS(BCLOG_FIELD_INFO)
#undef BCLOG_FIELD_INFO
}};

inline constexpr const FieldInfo &GetFieldInfo(FieldId id) {
    return FIELDS[size_t(id)];
}

/** A typed key: the only way to name a field at a call site */
template <FieldType T> struct FieldKey {
    const FieldId id;
    consteval explicit FieldKey(FieldId value) : id{value} {
        if (size_t(value) >= FIELDS.size() || GetFieldInfo(value).type != T) {
            throw "Invalid typed log field key";
        }
    }
};

/** The keys, e.g. LogField::PeerId */
namespace LogField {
#define BCLOG_FIELD_KEY(id, name, type, ecs, otel)                             \
    inline constexpr FieldKey<FieldType::type> id{FieldId::id};
    BCLOG_FIELDS(BCLOG_FIELD_KEY)
#undef BCLOG_FIELD_KEY
} // namespace LogField

} // namespace BCLog

#endif // BITCOIN_LOGGING_FIELDS_H
