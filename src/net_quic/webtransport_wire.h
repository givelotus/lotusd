// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_WEBTRANSPORT_WIRE_H
#define BITCOIN_NET_QUIC_WEBTRANSPORT_WIRE_H

#include <span.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * WebTransport over HTTP/3 wire elements (draft-ietf-webtrans-http3-16 and
 * the earlier drafts browsers still speak), without any library: QUIC
 * variable-length integers, the WebTransport stream headers, capsules on
 * the CONNECT stream, error code mapping and the wt-available-protocols
 * list. Pure functions, unit-tested and fuzzed.
 */
namespace wt {

//! SETTINGS identifiers announcing WebTransport support, per draft range
constexpr uint64_t SETTINGS_ENABLE_WEBTRANSPORT_D02{0x2b603742};  // -00..-06
constexpr uint64_t SETTINGS_WT_MAX_SESSIONS_D07{0xc671706a};      // -07..-12
constexpr uint64_t SETTINGS_WT_MAX_SESSIONS_D13{0x14e9cd29};      // -13..-14
constexpr uint64_t SETTINGS_WT_ENABLED{0x2c7cf000};               // -15..-16
constexpr uint64_t SETTINGS_WT_INITIAL_MAX_STREAMS_UNI{0x2b64};
constexpr uint64_t SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI{0x2b65};
constexpr uint64_t SETTINGS_WT_INITIAL_MAX_DATA{0x2b61};
//! Draft-04 HTTP datagrams (Chrome, Firefox)
constexpr uint64_t SETTINGS_H3_DATAGRAM_DRAFT04{0xffd277};

//! Stream type of a WebTransport unidirectional stream
constexpr uint64_t UNI_STREAM_TYPE{0x54};
//! Signal value starting a WebTransport bidirectional stream
constexpr uint64_t BIDI_SIGNAL{0x41};

//! Capsules (RFC 9297 framing on the CONNECT stream)
constexpr uint64_t CAPSULE_CLOSE_SESSION{0x2843};
constexpr uint64_t CAPSULE_DRAIN_SESSION{0x78ae};
//! Largest WT_CLOSE_SESSION reason (draft §5)
constexpr size_t MAX_CLOSE_REASON{1024};
//! Largest capsule we buffer (others are an error)
constexpr uint64_t MAX_CAPSULE_SIZE{64 * 1024};

//! HTTP/3 error codes (draft §9.5)
constexpr uint64_t WT_BUFFERED_STREAM_REJECTED{0x3994bd84};
constexpr uint64_t WT_SESSION_GONE{0x170d7b68};
//! Our application error: a stream not following the P2P class-stream rules
constexpr uint32_t WT_P2P_BAD_STREAM{1};

//! First and last HTTP/3 code of WebTransport application errors
constexpr uint64_t APP_ERROR_FIRST{0x52e4a40fa8db};
constexpr uint64_t APP_ERROR_LAST{0x52e5ac983162};

/** Bytes of a QUIC variable-length integer for `v` (v < 2^62) */
size_t VarintSize(uint64_t v);
void PutVarint(std::vector<uint8_t> &out, uint64_t v);
/** Decode a varint at the start of `in`: bytes consumed (0: incomplete) */
size_t GetVarint(Span<const uint8_t> in, uint64_t &value);

/** WebTransport application error code -> HTTP/3 error code (§4.4) */
uint64_t WebTransportCodeToHttp(uint32_t code);
/** HTTP/3 error code -> WebTransport application error code, or
 * std::nullopt outside the range or on a reserved (grease) codepoint */
std::optional<uint32_t> HttpCodeToWebTransport(uint64_t http_code);

/** How the first bytes of a stream decide what it is */
struct StreamPrefix {
    enum class Status {
        //! More bytes are needed
        INCOMPLETE,
        //! Not a WebTransport stream: an HTTP/3 stream
        HTTP3,
        //! A WebTransport stream; session_id and header_len are set
        WEBTRANSPORT,
    };
    Status status{Status::INCOMPLETE};
    uint64_t session_id{0};
    //! Bytes of the stream type/signal and session id
    size_t header_len{0};
};

/**
 * Classify a peer stream from its first bytes: a unidirectional stream
 * whose type is 0x54, or a bidirectional stream starting with signal 0x41,
 * is a WebTransport stream followed by its session id. Anything else is
 * left to HTTP/3.
 */
StreamPrefix ParseStreamPrefix(Span<const uint8_t> in, bool unidirectional);

/** The WebTransport header of a bidirectional stream (signal, session) */
std::vector<uint8_t> BidiStreamHeader(uint64_t session_id);
/** The WebTransport header of a unidirectional stream (type, session) */
std::vector<uint8_t> UniStreamHeader(uint64_t session_id);

/** One capsule (type, length, value) */
struct Capsule {
    uint64_t type{0};
    std::vector<uint8_t> value;
};

/** Result of parsing the start of a capsule byte stream */
struct CapsuleParse {
    enum class Status { INCOMPLETE, OK, ERROR };
    Status status{Status::INCOMPLETE};
    Capsule capsule;
    size_t consumed{0};
    std::string error;
};

/** Parse one capsule from the start of `in` */
CapsuleParse ParseCapsule(Span<const uint8_t> in);

void EncodeCapsule(std::vector<uint8_t> &out, uint64_t type,
                   Span<const uint8_t> value);

/** WT_CLOSE_SESSION: 32-bit error code and a UTF-8 reason (≤ 1024 bytes) */
struct CloseSession {
    uint32_t code{0};
    std::string reason;
};
std::optional<CloseSession> DecodeCloseSession(Span<const uint8_t> value);
std::vector<uint8_t> EncodeCloseSession(uint32_t code, std::string_view reason);

/**
 * Parse an RFC 8941 List of Strings (wt-available-protocols): the strings
 * in order, or std::nullopt if malformed. Parameters are ignored.
 */
std::optional<std::vector<std::string>>
ParseProtocolList(std::string_view field);
/** Serialize one RFC 8941 String (wt-protocol) */
std::string SerializeProtocol(std::string_view protocol);

/** The newest draft a peer's SETTINGS identifier announces (for display):
 * returns the identifier's rank (0: not a WebTransport setting) */
int DraftRank(uint64_t settings_id);

} // namespace wt

#endif // BITCOIN_NET_QUIC_WEBTRANSPORT_WIRE_H
