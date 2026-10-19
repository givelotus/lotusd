// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <logging/values.h>
#include <netbase.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#ifdef __linux__
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <vector>

using BCLog::LogStatic;
namespace LogField = BCLog::LogField;
using namespace std::chrono_literals;

namespace {
/** Log to a temporary file in a given format; read back the lines */
struct EventLogSetup : public BasicTestingSetup {
    fs::path prev_path{LogInstance().m_file_path};
    BCLog::LogFormat prev_format{LogInstance().m_log_format};
    bool prev_timestamps{LogInstance().m_log_timestamps};
    bool prev_sourcelocations{LogInstance().m_log_sourcelocations};
    bool prev_threadnames{LogInstance().m_log_threadnames};
    uint32_t prev_mask{LogInstance().GetCategoryMask()};

    EventLogSetup() {
        LogInstance().Flush();
        LogInstance().m_file_path = m_args.GetDataDirBase() / "events.log";
        LogInstance().m_reopen_file = true;
        LogInstance().m_log_timestamps = false;
        LogInstance().m_log_sourcelocations = false;
        LogInstance().m_log_threadnames = false;
        LogInstance().SetRateLimiting(nullptr);
        LogInstance().DisableCategory(BCLog::ALL);
        LogInstance().EnableCategory(BCLog::NET);
    }
    ~EventLogSetup() {
        LogInstance().Flush();
        LogInstance().m_file_path = prev_path;
        LogInstance().m_reopen_file = true;
        LogInstance().m_log_format = prev_format;
        LogInstance().m_log_timestamps = prev_timestamps;
        LogInstance().m_log_sourcelocations = prev_sourcelocations;
        LogInstance().m_log_threadnames = prev_threadnames;
        LogInstance().DisableCategory(BCLog::ALL);
        LogInstance().EnableCategory(BCLog::LogFlags{prev_mask});
        LogInstance().Flush();
    }
    void Format(BCLog::LogFormat format) {
        LogInstance().Flush();
        LogInstance().m_log_format = format;
    }
    std::vector<std::string> Lines() {
        LogInstance().Flush();
        std::vector<std::string> lines;
        std::ifstream ifs{LogInstance().m_file_path};
        for (std::string line; std::getline(ifs, line);) {
            if (!line.empty()) {
                lines.push_back(line);
            }
        }
        std::ofstream{LogInstance().m_file_path, std::ios::trunc};
        LogInstance().m_reopen_file = true;
        return lines;
    }
    UniValue Json() {
        const auto lines{Lines()};
        BOOST_REQUIRE_EQUAL(lines.size(), 1U);
        UniValue v;
        BOOST_REQUIRE(v.read(lines[0]));
        return v;
    }
};

template <typename T>
concept AcceptsFreeKey = requires(BCLog::EventBuilder &builder, T key) {
    builder.Field(key, int64_t{42});
};
static_assert(!AcceptsFreeKey<const char *>);
static_assert(!AcceptsFreeKey<std::string>);

uint256 SomeHash() {
    return uint256S(
        "00000000000000000123456789abcdef0123456789abcdef0123456789abcdef");
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(logging_event_tests, EventLogSetup)

BOOST_AUTO_TEST_CASE(nonfinite_float_fields_produce_valid_json) {
    // Raw consumer fixture: Value supplies a name, not a producer type contract.
    BCLog::JsonEncoder json;
    BCLog::JsonGcpEncoder gcp;
    BCLog::JsonEcsEncoder ecs;
    const BCLog::LogEventSite site{"numeric_encoding", nullptr, BCLog::ALL,
                                   BCLog::Level::Info};
    for (const double value : {1.25, std::numeric_limits<double>::quiet_NaN(),
                               std::numeric_limits<double>::infinity(),
                               -std::numeric_limits<double>::infinity()}) {
        std::array<std::byte, sizeof(BCLog::FieldHeader) + sizeof(value)> data;
        const BCLog::FieldHeader header{BCLog::FieldId::Value,
                                        BCLog::FieldKind::F64, false,
                                        sizeof(value), 0};
        std::memcpy(data.data(), &header, sizeof(header));
        std::memcpy(data.data() + sizeof(header), &value, sizeof(value));
        BCLog::LogLine line{};
        line.level = BCLog::Level::Info;
        line.category = BCLog::ALL;
        line.event = &site;
        line.fields = BCLog::FieldList{data, 1};
        for (const BCLog::LogEncoder *encoder :
             {static_cast<BCLog::LogEncoder *>(&json),
              static_cast<BCLog::LogEncoder *>(&gcp),
              static_cast<BCLog::LogEncoder *>(&ecs)}) {
            std::string encoded;
            encoder->Encode(line, BCLog::LogOptions{.timestamps = false}, encoded);
            UniValue record;
            const bool valid{record.read(encoded)};
            BOOST_CHECK_MESSAGE(valid, encoded);
            if (!valid) continue;
            const auto &field{record[encoder == &ecs ? "lotus.value" : "value"]};
            if (std::isfinite(value)) BOOST_CHECK_EQUAL(field.get_real(), value);
            else BOOST_CHECK(field.isNull());
        }
    }
}

BOOST_AUTO_TEST_CASE(event_text_and_json) {
    const CService addr{LookupNumeric("203.0.113.7", 10605)};
    for (const auto format : {BCLog::LogFormat::TEXT, BCLog::LogFormat::JSON}) {
        Format(format);
        LogEvent(BCLog::NET, "peer_connected",
                 "New peer connected: peer={peer_id}")
            .Field(LogField::PeerId, 17)
            .Field(LogField::Addr, addr)
            .Field(LogField::Transport, LogStatic("wss"))
            .Field(LogField::BlockHash, SomeHash())
            .Field(LogField::Bytes, uint64_t{712345})
            .Field(LogField::DurationUs, 1500us)
            .Field(LogField::UserAgent, std::string{"/Lotus:1.0 \"x\"/"});
        if (format == BCLog::LogFormat::TEXT) {
            const auto lines{Lines()};
            BOOST_REQUIRE_EQUAL(lines.size(), 1U);
            BOOST_CHECK_EQUAL(
                lines[0],
                "[net] New peer connected: peer=17 addr=203.0.113.7:10605 "
                "transport=wss "
                "block_hash="
                "00000000000000000123456789abcdef0123456789abcdef0123456789abcd"
                "ef"
                " bytes=712345 duration_us=1500 "
                "user_agent=\"/Lotus:1.0 \\\"x\\\"/\"");
        } else {
            const UniValue v{Json()};
            BOOST_CHECK_EQUAL(v["message"].get_str(),
                              "New peer connected: peer=17");
            BOOST_CHECK_EQUAL(v["event"].get_str(), "peer_connected");
            BOOST_CHECK_EQUAL(v["category"].get_str(), "net");
            BOOST_CHECK_EQUAL(v["level"].get_str(), "debug");
            // Numbers stay numbers
            BOOST_CHECK(v["peer_id"].isNum());
            BOOST_CHECK_EQUAL(v["peer_id"].getInt<int>(), 17);
            BOOST_CHECK_EQUAL(v["bytes"].getInt<int64_t>(), 712345);
            BOOST_CHECK_EQUAL(v["duration_us"].getInt<int>(), 1500);
            BOOST_CHECK_EQUAL(v["addr"].get_str(), "203.0.113.7:10605");
            BOOST_CHECK_EQUAL(v["transport"].get_str(), "wss");
            BOOST_CHECK_EQUAL(v["block_hash"].get_str(), SomeHash().GetHex());
            BOOST_CHECK_EQUAL(v["user_agent"].get_str(), "/Lotus:1.0 \"x\"/");
        }
    }
}

BOOST_AUTO_TEST_CASE(event_without_template) {
    LogEvent(BCLog::NET, "ping_timeout").Field(LogField::PeerId, 3);
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 1U);
    BOOST_CHECK_EQUAL(lines[0], "[net] ping_timeout peer_id=3");
    LogInfoEvent(BCLog::ALL, "startup_done");
    BOOST_CHECK_EQUAL(Lines().at(0), "startup_done");
}

BOOST_AUTO_TEST_CASE(event_escaping) {
    Format(BCLog::LogFormat::JSON);
    const std::string nasty{"a\"b\\c\nd\x01\xff"};
    LogEvent(BCLog::NET, "weird", "say {error}").Field(LogField::Error, nasty);
    const UniValue v{Json()};
    BOOST_CHECK_EQUAL(v["error"].get_str(), "a\"b\\c\nd\x01\xef\xbf\xbd");
    BOOST_CHECK_EQUAL(v["message"].get_str(), "say a\"b\\c\nd\x01\xef\xbf\xbd");
    Format(BCLog::LogFormat::TEXT);
    LogEvent(BCLog::NET, "weird", "say {error}").Field(LogField::Error, nasty);
    // Text: control characters escaped as everywhere in the text format
    BOOST_CHECK_EQUAL(Lines().at(0), "[net] say a\"b\\c");
}

BOOST_AUTO_TEST_CASE(event_disabled_evaluates_nothing) {
    int evaluated{0};
    const auto value{[&] {
        ++evaluated;
        return 1;
    }};
    LogInstance().DisableCategory(BCLog::NET);
    LogEvent(BCLog::NET, "never").Field(LogField::PeerId, value());
    BOOST_CHECK_EQUAL(evaluated, 0);
    LogInstance().EnableCategory(BCLog::NET);
    LogEvent(BCLog::NET, "now").Field(LogField::PeerId, value());
    BOOST_CHECK_EQUAL(evaluated, 1);
    BOOST_CHECK_EQUAL(Lines().size(), 1U);
}

BOOST_AUTO_TEST_CASE(event_dangling_else) {
    // The macro is an if/else: an outer else still binds to the outer if.
    bool took_else{false};
    if (false)
        LogEvent(BCLog::NET, "no");
    else
        took_else = true;
    BOOST_CHECK(took_else);
}

BOOST_AUTO_TEST_CASE(event_reference_outlives_caller) {
    // A transaction logged by reference stays alive until rendered, after
    // the caller dropped it; then the logger releases it.
    LogInstance().PauseForTesting(true);
    LogInstance().Flush();
    std::weak_ptr<const CTransaction> weak;
    {
        CMutableTransaction mtx;
        mtx.nLockTime = 1234;
        const CTransactionRef tx{MakeTransactionRef(mtx)};
        weak = tx;
        LogEvent(BCLog::NET, "tx_received", "got {txid}")
            .Field(LogField::Name, tx);
    }
    BOOST_CHECK(!weak.expired());
    const auto lines{Lines()};
    LogInstance().PauseForTesting(false);
    BOOST_CHECK(weak.expired());
    BOOST_REQUIRE_EQUAL(lines.size(), 1U);
    BOOST_CHECK(lines[0].find("name=") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(event_copies_strings) {
    // Non-literal strings are copied: changing the source afterwards does
    // not change the logged value.
    std::string s{"before"};
    LogInstance().PauseForTesting(true);
    LogEvent(BCLog::NET, "copied").Field(LogField::Name, s);
    s = "after!";
    const auto lines{Lines()};
    LogInstance().PauseForTesting(false);
    BOOST_CHECK_EQUAL(lines.at(0), "[net] copied name=before");
}

BOOST_AUTO_TEST_CASE(
    last_string_truncation_is_marked_without_a_following_field) {
    Format(BCLog::LogFormat::JSON);
    const std::string large(1000, 'x');
    LogEvent(BCLog::NET, "last_string", "last={name}")
        .Field(LogField::Name, large);
    const auto row{Json()};
    const auto retained{row["name"].get_str()};
    BOOST_REQUIRE(!retained.empty());
    BOOST_CHECK(retained.size() < large.size());
    BOOST_CHECK(large.starts_with(retained));
    BOOST_CHECK_EQUAL(row["message"].get_str(), "last=" + retained);
    BOOST_REQUIRE(row["fields_truncated"].isBool());
    BOOST_CHECK(row["fields_truncated"].get_bool());

    // Empty ordinary fields fit and must not gain a spurious marker.
    LogEvent(BCLog::NET, "last_string_empty", "last={name}")
        .Field(LogField::Name, std::string{});
    const auto empty{Json()};
    BOOST_CHECK_EQUAL(empty["name"].get_str(), "");
    BOOST_CHECK_EQUAL(empty["message"].get_str(), "last=");
    BOOST_CHECK(empty["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(event_truncation) {
    Format(BCLog::LogFormat::JSON);
    const std::string big(1000, 'x');
    LogEvent(BCLog::NET, "big")
        .Field(LogField::Name, big)
        .Field(LogField::PeerId, 1);
    const UniValue v{Json()};
    // The string is cut to the record's room; the next field is left out
    BOOST_CHECK(v["name"].get_str().size() < 500);
    BOOST_CHECK(v["fields_truncated"].get_bool());
    BOOST_CHECK(!v.exists("peer_id"));
}

BOOST_AUTO_TEST_CASE(event_field_registry) {
    // Every field has a unique snake_case name; standard names are dotted.
    std::set<std::string_view> names, ecs_names, otel_names;
    for (const auto &f : BCLog::FIELDS) {
        BOOST_CHECK(names.insert(f.name).second);
        BOOST_CHECK(f.ecs.empty() || ecs_names.insert(f.ecs).second);
        BOOST_CHECK(f.otel.empty() || otel_names.insert(f.otel).second);
        for (const char c : f.name) {
            BOOST_CHECK((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '_');
        }
        BOOST_CHECK(f.ecs.empty() || f.ecs.find('.') != std::string_view::npos);
        BOOST_CHECK(f.otel.empty() ||
                    f.otel.find('.') != std::string_view::npos);
    }
    BOOST_CHECK(BCLog::GetFieldInfo(BCLog::FieldId::Addr).ecs.empty());
    BOOST_CHECK(BCLog::GetFieldInfo(BCLog::FieldId::Addr).otel.empty());
    BOOST_CHECK_EQUAL(BCLog::GetFieldInfo(BCLog::FieldId::PeerAddress).otel,
                      "network.peer.address");
    BOOST_CHECK_EQUAL(BCLog::GetFieldInfo(BCLog::FieldId::PeerPort).otel,
                      "network.peer.port");
    BOOST_CHECK(BCLog::GetFieldInfo(BCLog::FieldId::UserAgent).otel.empty());
    BOOST_CHECK_EQUAL(BCLog::GetFieldInfo(BCLog::FieldId::HttpUserAgent).otel,
                      "user_agent.original");
    BOOST_CHECK(BCLog::GetFieldInfo(BCLog::FieldId::Error).otel.empty());
    BOOST_CHECK_EQUAL(BCLog::GetFieldInfo(BCLog::FieldId::OriginalMethod).otel,
                      "rpc.method_original");
    BOOST_CHECK_EQUAL(BCLog::GetFieldInfo(BCLog::FieldId::Error).ecs,
                      "error.message");
}

BOOST_AUTO_TEST_CASE(logfmt_encoding) {
    BOOST_CHECK(BCLog::ParseLogFormat("logfmt") == BCLog::LogFormat::LOGFMT);
    Format(BCLog::LogFormat::LOGFMT);
    LogEvent(BCLog::NET, "peer_connected", "connected to {addr}")
        .Field(LogField::PeerId, 42)
        .Field(LogField::Addr, std::string{"a\"b\nc"});
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 1U);
    BOOST_CHECK(lines[0].find("peer_id=42") != std::string::npos);
    BOOST_CHECK(lines[0].find("addr=\"a\\\"b\\nc\"") != std::string::npos);
    BOOST_CHECK(lines[0].find("level=\"debug\"") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(json_event_name_escaping) {
    Format(BCLog::LogFormat::JSON);
    LogEvent(BCLog::NET, "quote\"slash\\newline\n", "event message");
    const auto record{Json()};
    BOOST_CHECK_EQUAL(record["event"].get_str(), "quote\"slash\\newline\n");
    BOOST_CHECK_EQUAL(record["message"].get_str(), "event message");
}

BOOST_AUTO_TEST_CASE(structured_source_caller) {
    Format(BCLog::LogFormat::JSON);
    LogInstance().m_log_sourcelocations = true;
    LogEvent(BCLog::NET, "caller_location");
    const auto record{Json()};
    BOOST_CHECK_EQUAL(
        record["source"]["function"].get_str(),
        "logging_event_tests::structured_source_caller::test_method");
}

BOOST_AUTO_TEST_CASE(gcp_json_schema) {
    BOOST_CHECK(BCLog::ParseLogFormat("json-gcp") ==
                BCLog::LogFormat::JSON_GCP);
    Format(BCLog::LogFormat::JSON_GCP);
    LogInstance().m_log_timestamps = true;
    LogInstance().m_log_sourcelocations = true;
    LogWarningEvent(BCLog::NET, "peer_failed", "failed: {error}")
        .Field(LogField::PeerId, 7)
        .Field(LogField::Error, "quote\"newline\n");
    const auto record{Json()};
    BOOST_CHECK_EQUAL(record["severity"].get_str(), "WARNING");
    BOOST_CHECK(record["level"].isNull());
    BOOST_CHECK(record["time"].isStr());
    BOOST_CHECK_EQUAL(record["peer_id"].getInt<int64_t>(), 7);
    BOOST_CHECK_EQUAL(record["error"].get_str(), "quote\"newline\n");
    const auto location{record["logging.googleapis.com/sourceLocation"]};
    BOOST_CHECK(location["file"].isStr());
    BOOST_CHECK(location["line"].isStr());
    BOOST_CHECK_EQUAL(location["function"].get_str().find('('),
                      std::string::npos);
}

BOOST_AUTO_TEST_CASE(ecs_json_schema) {
    BOOST_CHECK(BCLog::ParseLogFormat("json-ecs") ==
                BCLog::LogFormat::JSON_ECS);
    Format(BCLog::LogFormat::JSON_ECS);
    LogInstance().m_log_timestamps = false;
    LogInstance().m_log_sourcelocations = true;
    LogEvent(BCLog::NET, "peer_received", "received {bytes} bytes")
        .Field(LogField::PeerId, 7)
        .Field(LogField::Addr, "peer.example:8333")
        .Field(LogField::Bytes, uint64_t{123})
        .Field(LogField::DurationUs, 1500ns)
        .Field(LogField::Error, "error text");
    const auto record{Json()};
    BOOST_CHECK_EQUAL(record["ecs.version"].get_str(), "8.11.0");
    BOOST_CHECK(record["@timestamp"].isStr());
    BOOST_CHECK_EQUAL(record["log.level"].get_str(), "debug");
    BOOST_CHECK_EQUAL(record["log.logger"].get_str(), "net");
    BOOST_CHECK_EQUAL(record["event.action"].get_str(), "peer_received");
    BOOST_CHECK_EQUAL(record["lotus.peer_id"].getInt<int>(), 7);
    BOOST_CHECK_EQUAL(record["lotus.addr"].get_str(), "peer.example:8333");
    BOOST_CHECK(record["source.address"].isNull());
    BOOST_CHECK_EQUAL(record["lotus.bytes"].getInt<int>(), 123);
    BOOST_CHECK_EQUAL(record["event.duration"].getInt<int>(), 1500);
    BOOST_CHECK_EQUAL(record["error.message"].get_str(), "error text");
    BOOST_CHECK(record["log.origin.file.line"].isNum());
    BOOST_CHECK_EQUAL(record["log.origin.function"].get_str(),
                      "logging_event_tests::ecs_json_schema::test_method");
    BOOST_CHECK(record["level"].isNull());
    BOOST_CHECK(record["peer_id"].isNull());
}

BOOST_AUTO_TEST_CASE(journal_native_encoding) {
#ifdef __linux__
    BOOST_CHECK(BCLog::ParseLogFormat("journald") ==
                BCLog::LogFormat::JOURNALD);
#else
    BOOST_CHECK(!BCLog::ParseLogFormat("journald"));
#endif
    BCLog::JournaldEncoder encoder;
    BCLog::LogLine line{.time = SystemClock::now(),
                        .level = BCLog::Level::Warning,
                        .category = BCLog::NET,
                        .thread = "network",
                        .loc = std::source_location::current(),
                        .message = "first\nsecond\n"};
    std::string encoded;
    encoder.Encode(line, BCLog::LogOptions{.sourcelocations = true}, encoded);
    BOOST_CHECK(encoded.starts_with("PRIORITY=4\nMESSAGE\n"));
    const size_t length_at{encoded.find("MESSAGE\n") + 8};
    BOOST_REQUIRE(encoded.size() > length_at + 8);
    // Native multiline framing: uint64 little-endian, then exact bytes.
    BOOST_CHECK_EQUAL(uint8_t(encoded[length_at]), 12);
    for (size_t i = 1; i < 8; ++i)
        BOOST_CHECK_EQUAL(encoded[length_at + i], 0);
    BOOST_CHECK_EQUAL(encoded.substr(length_at + 8, 13), "first\nsecond\n");
    BOOST_CHECK(encoded.find("LOTUS_CATEGORY=net\n") != std::string::npos);
    BOOST_CHECK(encoded.find("CODE_FUNC=logging_event_tests::journal_native_"
                             "encoding::test_method\n") != std::string::npos);
    line.message = std::string_view{"nul\0byte", 8};
    encoder.Encode(line, {}, encoded);
    BOOST_CHECK(
        encoded.find(std::string{"MESSAGE\n\x08\0\0\0\0\0\0\0nul\0byte\n",
                                 25}) != std::string::npos);
    for (auto [level, priority] : {std::pair{BCLog::Level::Trace, "7"},
                                   std::pair{BCLog::Level::Debug, "7"},
                                   std::pair{BCLog::Level::Info, "6"},
                                   std::pair{BCLog::Level::Error, "3"}}) {
        line.level = level;
        encoder.Encode(line, {}, encoded);
        BOOST_CHECK(
            encoded.starts_with(std::string{"PRIORITY="} + priority + "\n"));
    }
}

#ifdef __linux__
BOOST_AUTO_TEST_CASE(journal_native_transport) {
    struct OwnedFd {
        int fd;
        ~OwnedFd() {
            if (fd >= 0) close(fd);
        }
    };
    OwnedFd receiver{socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    BOOST_REQUIRE(receiver.fd >= 0);
    const timeval timeout{.tv_sec = 1, .tv_usec = 0};
    BOOST_REQUIRE_EQUAL(setsockopt(receiver.fd, SOL_SOCKET, SO_RCVTIMEO,
                                   &timeout, sizeof(timeout)),
                        0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const std::string path{
        fs::PathToString(m_args.GetDataDirBase() / "journal.sock")};
    BOOST_REQUIRE(path.size() < sizeof(addr.sun_path));
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    BOOST_REQUIRE_EQUAL(
        bind(receiver.fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)),
        0);
    BCLog::JournalSink sink;
    BOOST_REQUIRE(!sink.Open(path + ".absent"));
    BOOST_REQUIRE(sink.Open(path));
    BOOST_CHECK(!sink.Send({}));
    const std::string small{"MESSAGE=small\n"};
    BOOST_REQUIRE(sink.Send(small));
    char data[64]{};
    BOOST_REQUIRE_EQUAL(recv(receiver.fd, data, sizeof(data), 0),
                        ssize_t(small.size()));
    BOOST_CHECK_EQUAL(std::string(data, small.size()), small);

    const std::string large{"MESSAGE=" + std::string(2 * 1024 * 1024, 'x') +
                            "\n"};
    BOOST_REQUIRE(sink.Send(large));
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    iovec iov{.iov_base = data, .iov_len = sizeof(data)};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    BOOST_REQUIRE_EQUAL(recvmsg(receiver.fd, &msg, 0), 0);
    BOOST_CHECK_EQUAL(msg.msg_flags & MSG_CTRUNC, 0);
    cmsghdr *header{CMSG_FIRSTHDR(&msg)};
    BOOST_REQUIRE(header);
    BOOST_REQUIRE_EQUAL(header->cmsg_level, SOL_SOCKET);
    BOOST_REQUIRE_EQUAL(header->cmsg_type, SCM_RIGHTS);
    BOOST_REQUIRE_EQUAL(header->cmsg_len, CMSG_LEN(sizeof(int)));
    int fd{-1};
    std::memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    const OwnedFd passed{fd};
    BOOST_REQUIRE(passed.fd >= 0);
    const int seals{F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE};
    BOOST_CHECK_EQUAL(fcntl(passed.fd, F_GET_SEALS), seals);
    std::string actual(large.size(), '\0');
    size_t offset{0};
    while (offset < actual.size()) {
        const ssize_t n{
            read(passed.fd, actual.data() + offset, actual.size() - offset)};
        BOOST_REQUIRE(n > 0);
        offset += n;
    }
    BOOST_CHECK_EQUAL(actual, large);
    // Replacing the journal socket must not permanently break a connected sink.
    close(receiver.fd);
    receiver.fd = -1;
    fs::remove(path);
    const OwnedFd replacement{socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    BOOST_REQUIRE(replacement.fd >= 0);
    BOOST_REQUIRE_EQUAL(setsockopt(replacement.fd, SOL_SOCKET, SO_RCVTIMEO,
                                   &timeout, sizeof(timeout)),
                        0);
    BOOST_REQUIRE_EQUAL(
        bind(replacement.fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)),
        0);
    BOOST_REQUIRE(sink.Send(small));
    BOOST_REQUIRE_EQUAL(recv(replacement.fd, data, sizeof(data), 0),
                        ssize_t(small.size()));
    BOOST_CHECK_EQUAL(std::string(data, small.size()), small);
    sink.Close();
    BOOST_CHECK(!sink.Send(small));
    fs::remove(path);
}
#endif

BOOST_AUTO_TEST_CASE(syslog_rfc5424_encoding) {
    BOOST_CHECK(BCLog::ParseLogFormat("syslog") == BCLog::LogFormat::SYSLOG);
    BCLog::SyslogEncoder encoder;
    BCLog::LogLine line{.time = SystemClock::time_point{} + 123456us,
                        .level = BCLog::Level::Warning,
                        .category = BCLog::NET,
                        .thread = "network",
                        .loc = std::source_location::current(),
                        .message = "quote\"\ninvalid\xff\n"};
    std::string encoded;
    encoder.Encode(line, BCLog::LogOptions{.sourcelocations = true}, encoded);
    const std::string prefix{
        "<28>1 1970-01-01T00:00:00.123456Z - - - - - \xef\xbb\xbf"};
    BOOST_REQUIRE(encoded.starts_with(prefix));
    UniValue payload;
    BOOST_REQUIRE(payload.read(encoded.substr(prefix.size())));
    BOOST_CHECK_EQUAL(payload["message"].get_str(),
                      "quote\"\ninvalid\xef\xbf\xbd");
    BOOST_CHECK_EQUAL(
        payload["source"]["function"].get_str(),
        "logging_event_tests::syslog_rfc5424_encoding::test_method");
    BOOST_CHECK_EQUAL(std::count(encoded.begin(), encoded.end(), '\n'), 1);
    encoder.Encode(line, BCLog::LogOptions{.timestamps = false}, encoded);
    BOOST_CHECK(encoded.starts_with("<28>1 - - - - - - \xef\xbb\xbf"));
    Format(BCLog::LogFormat::SYSLOG);
    LogEvent(BCLog::NET, "peer_received", "received {bytes} bytes")
        .Field(LogField::PeerId, 42)
        .Field(LogField::Bytes, uint64_t{123});
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 1U);
    const auto start{lines[0].find("\xef\xbb\xbf")};
    BOOST_REQUIRE(start != std::string::npos);
    BOOST_REQUIRE(payload.read(lines[0].substr(start + 3)));
    BOOST_CHECK_EQUAL(payload["peer_id"].getInt<int>(), 42);
    BOOST_CHECK_EQUAL(payload["bytes"].getInt<int>(), 123);
}

BOOST_AUTO_TEST_CASE(peer_address_and_port_are_separate) {
    Format(BCLog::LogFormat::JSON);
    const CService endpoint{LookupNumeric("203.0.113.7", 10605)};
    LogEvent(BCLog::NET, "peer_endpoint", "peer endpoint")
        .Field(LogField::PeerId, 42)
        .Field(LogField::Addr, endpoint)
        .Field(LogField::PeerAddress, static_cast<const CNetAddr &>(endpoint))
        .Field(LogField::PeerPort, endpoint.GetPort());
    const auto record{Json()};
    BOOST_CHECK_EQUAL(record["addr"].get_str(), "203.0.113.7:10605");
    BOOST_CHECK_EQUAL(record["peer_address"].get_str(), "203.0.113.7");
    BOOST_CHECK_EQUAL(record["peer_port"].getInt<int>(), 10605);
}

BOOST_AUTO_TEST_CASE(wss_packed_address_keeps_full_payload) {
    CNetAddr address;
    BOOST_REQUIRE(
        address.SetWSSDomain("this-is-a-long-websocket-peer-name.example.org",
                             "/p2p/custom-websocket-path"));
    std::array<std::byte, BCLog::LogValue<CService>::MAX_SIZE> packed;
    const CService service{address, 443};
    const auto size{BCLog::LogValue<CService>::Pack(service, packed)};
    std::string rendered;
    BCLog::LogValue<CService>::Render(std::span{packed}.first(size), rendered);
    BOOST_CHECK_EQUAL(rendered, service.ToStringAddrPort());
    Format(BCLog::LogFormat::JSON);
    LogEvent(BCLog::NET, "peer_wss_address", "WSS {addr}")
        .Field(LogField::PeerId, 42)
        .Field(LogField::Addr, service);
    const auto record{Json()};
    BOOST_CHECK_EQUAL(record["addr"].get_str(), service.ToStringAddrPort());
    BOOST_CHECK(record["fields_truncated"].isNull());
    const std::string label(63, 'a');
    const std::string host{label + "." + label + "." + label + "." +
                           std::string(61, 'b')};
    BOOST_REQUIRE_EQUAL(host.size(), 253U);
    BOOST_REQUIRE(address.SetWSSDomain(host, "/" + std::string(254, 'c')));
    const CService maximum{address, 443};
    const auto maximum_size{BCLog::LogValue<CService>::Pack(maximum, packed)};
    rendered.clear();
    BCLog::LogValue<CService>::Render(std::span{packed}.first(maximum_size),
                                      rendered);
    BOOST_CHECK_EQUAL(rendered, maximum.ToStringAddrPort());
    LogEvent(BCLog::NET, "peer_wss_address", "WSS {addr}")
        .Field(LogField::PeerId, 42)
        .Field(LogField::Addr, maximum);
    const auto oversized{Json()};
    BOOST_CHECK(oversized["addr"].isNull());
    BOOST_CHECK(oversized["fields_truncated"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
