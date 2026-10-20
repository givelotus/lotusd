// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <chain.h>
#include <chainparams.h>
#include <checkqueue.h>
#include <coins.h>
#include <common/args.h>
#include <flatfile.h>
#include <headerssync.h>
#include <index/blockfilterindex.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <logging/values.h>
#include <netbase.h>
#include <node/ui_interface.h>
#include <node/utxo_snapshot.h>
#include <noui.h>
#include <pow/pow.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <timedata.h>
#include <univalue.h>
#include <util/asmap.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#if defined(__linux__) || defined(MAC_OSX)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#ifdef __linux__
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
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

BOOST_AUTO_TEST_CASE(float_message_precision_preserves_raw_fields) {
    Format(BCLog::LogFormat::JSON);
    for (const double value : {0.0, -0.0, 1.23456789, 1e-10,
                               std::numeric_limits<double>::max(),
                               std::numeric_limits<double>::quiet_NaN(),
                               std::numeric_limits<double>::infinity(),
                               -std::numeric_limits<double>::infinity()}) {
        LogInfoEvent(BCLog::ALL, "precision", "{elapsed_ms:.0f}/{elapsed_ms:.1f}/{elapsed_ms:.2f}/{elapsed_ms:.3f}/{elapsed_ms:f}/{elapsed_ms:g}/{elapsed_ms:.18f}/{elapsed_ms:.18g}")
            .Field(LogField::ElapsedMs, value);
        const auto record{Json()};
        BOOST_CHECK_EQUAL(record["message"].get_str(),
                          strprintf("%.0f/%.1f/%.2f/%.3f/%f/%g/%.18f/%.18g", value,
                                    value, value, value, value, value, value, value));
        if (std::isfinite(value)) {
            BOOST_CHECK_EQUAL(record["elapsed_ms"].get_real(), value);
        } else {
            BOOST_CHECK(record["elapsed_ms"].isNull());
        }
    }
    LogInfoEvent(BCLog::ALL, "invalid_precision", "{elapsed_ms:.19f}/{elapsed_ms:08.2f}/{elapsed_ms:.2x}")
        .Field(LogField::ElapsedMs, 1.25);
    BOOST_CHECK_EQUAL(Json()["message"].get_str(),
                      "{elapsed_ms:.19f}/{elapsed_ms:08.2f}/{elapsed_ms:.2x}");
    LogInfoEvent(BCLog::ALL, "invalid_float_type", "{count:.2f}")
        .Field(LogField::Count, 1);
    BOOST_CHECK_EQUAL(Json()["message"].get_str(), "{count:.2f}");
}

BOOST_AUTO_TEST_CASE(filesystem_quoted_message_preserves_raw_snapshot) {
    Format(BCLog::LogFormat::JSON);
    for (std::string path :
         {std::string{}, std::string{"a b"}, std::string{"a&b\"c\\d"},
          std::string{"caf\xc3\xa9/\xe6\x96\x87"}, std::string{"line\nbreak\t"},
          std::string{"a\0b", 3}}) {
        const std::string original{path};
        LogInfoEvent(BCLog::ALL, "filesystem_path_fixture", "path=({path:fsq})")
            .Field(LogField::Path, path);
        // The producer's string may be destroyed or reused before the logger
        // reads the event. Both JSON and quoting must use the copied snapshot.
        path.assign("mutated");
        const auto record{Json()};
        BOOST_CHECK_EQUAL(record["path"].get_str(), original);
        BOOST_CHECK_EQUAL(record["message"].get_str(),
                          strprintf("path=(%s)", fs::quoted(original)));
        BOOST_CHECK(record["fields_truncated"].isNull());
    }
    LogInfoEvent(BCLog::ALL, "filesystem_static_path", "{path:fsq}")
        .Field(LogField::Path, LogStatic("a&b\"c"));
    const auto literal{Json()};
    BOOST_CHECK_EQUAL(literal["path"].get_str(), "a&b\"c");
    BOOST_CHECK_EQUAL(literal["message"].get_str(),
                      strprintf("%s", fs::quoted("a&b\"c")));
    // Unsupported runtime field kinds fail closed instead of inventing a
    // numeric string quotation contract. Production lint rejects this case.
    LogInfoEvent(BCLog::ALL, "filesystem_invalid_type", "{count:fsq}")
        .Field(LogField::Count, 1);
    BOOST_CHECK_EQUAL(Json()["message"].get_str(), "{count:fsq}");
}

BOOST_AUTO_TEST_CASE(mempool_persistence_fields_keep_counts_and_seconds) {
    Format(BCLog::LogFormat::JSON);
    LogInfoEvent(
        BCLog::ALL, "mempool_persistence_fixture",
        "{mempool_import_succeeded_count}/{mempool_import_failed_count}/{mempool_import_expired_count}/{mempool_import_present_count}/{mempool_import_waiting_broadcast_count} {mempool_copy_seconds:g}/{mempool_dump_seconds:g}")
        .Field(LogField::MempoolImportSucceededCount, int64_t{2})
        .Field(LogField::MempoolImportFailedCount, int64_t{3})
        .Field(LogField::MempoolImportExpiredCount, int64_t{5})
        .Field(LogField::MempoolImportPresentCount, int64_t{7})
        .Field(LogField::MempoolImportWaitingBroadcastCount, int64_t{11})
        .Field(LogField::MempoolCopySeconds, 1.25e-9)
        .Field(LogField::MempoolDumpSeconds, 0.0123456789);
    const auto record{Json()};
    BOOST_CHECK_EQUAL(record["message"].get_str(),
                      strprintf("2/3/5/7/11 %g/%g", 1.25e-9, 0.0123456789));
    for (const auto &[key, expected] :
         std::array<std::pair<const char *, int64_t>, 5>{
             {{"mempool_import_succeeded_count", 2},
              {"mempool_import_failed_count", 3},
              {"mempool_import_expired_count", 5},
              {"mempool_import_present_count", 7},
              {"mempool_import_waiting_broadcast_count", 11}}}) {
        BOOST_CHECK(record[key].isNum());
        BOOST_CHECK_EQUAL(record[key].getInt<int64_t>(), expected);
    }
    BOOST_CHECK_EQUAL(record["mempool_copy_seconds"].get_real(), 1.25e-9);
    BOOST_CHECK_EQUAL(record["mempool_dump_seconds"].get_real(), 0.0123456789);
    BOOST_CHECK(record["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(validation_state_snapshot_preserves_canonical_text) {
    const auto verify = [](auto state) {
        using State = decltype(state);
        const std::string expected{state.ToString()};
        std::array<std::byte, 512> bytes;
        const auto size{BCLog::LogValue<State>::Size(state)};
        BOOST_REQUIRE(size <= bytes.size());
        BOOST_CHECK_EQUAL(BCLog::LogValue<State>::Pack(
                              state, std::span{bytes}.first(size)), size);
        state.Error("changed after packing");
        std::string rendered;
        BCLog::LogValue<State>::Render(std::span{bytes}.first(size), rendered);
        BOOST_CHECK_EQUAL(rendered, expected);
    };
    TxValidationState tx;
    verify(tx);
    tx.Invalid(TxValidationResult::TX_CONSENSUS,
               std::string("why\0reason", 10), "debug\nline");
    verify(tx);
    tx.Error("runtime error");
    verify(tx);
    BlockValidationState block;
    verify(block);
    block.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "", "debug only");
    verify(block);
    block.Error("runtime error");
    verify(block);

    BlockValidationState error;
    error.Error("runtime error");
    verify(error);

    Format(BCLog::LogFormat::JSON);
    LogInfoEvent(BCLog::ALL, "validation_state_fixture", "{reason}")
        .Field(LogField::Reason, tx);
    BOOST_CHECK_EQUAL(Json()["reason"].get_str(), tx.ToString());
    tx.Invalid(TxValidationResult::TX_CONSENSUS, std::string(5000, 'x'));
    BOOST_CHECK_EQUAL(BCLog::LogValue<TxValidationState>::Size(tx), 5003);
    LogInfoEvent(BCLog::ALL, "validation_state_large_fixture", "{reason}")
        .Field(LogField::Reason, tx);
    const auto record{Json()};
    BOOST_CHECK(record["fields_truncated"].get_bool());
    BOOST_CHECK(record["reason"].isNull());
    tx.Invalid(TxValidationResult::TX_CONSENSUS, std::string(70000, 'x'));
    BOOST_CHECK_EQUAL(BCLog::LogValue<TxValidationState>::Size(tx),
                      BCLog::LogValue<TxValidationState>::MAX_SIZE);
}

BOOST_AUTO_TEST_CASE(explicit_info_bypass_preserves_progress_delivery) {
    Format(BCLog::LogFormat::TEXT);
    // Hold one window throughout this test; no timer/reset race is involved.
    LogInstance().SetRateLimiting(BCLog::LogRateLimiter::Create(
        [](auto, auto) {}, 1000, 1h));
    for (int i = 0; i < 30; ++i) {
        LogInfoEventNoRateLimit(BCLog::ALL, "progress_unthrottled", "{name}")
            .Field(LogField::Name, std::string(99, 'p'));
    }
    LogInstance().Flush();
    LogInstance().SetRateLimiting(nullptr);
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 30U);
    for (const auto &line : lines) {
        BOOST_CHECK_EQUAL(line, std::string(99, 'p'));
    }
}

BOOST_AUTO_TEST_CASE(integer_hex_keeps_numeric_fields) {
    Format(BCLog::LogFormat::JSON);
    LogInfoEventNoRateLimit(BCLog::ALL, "hex_fixture", "version=0x{version:08x}")
        .Field(LogField::Version, uint32_t{0x80000002});
    const auto record{Json()};
    BOOST_CHECK_EQUAL(record["message"].get_str(), "version=0x80000002");
    BOOST_CHECK(record["version"].isNum());
    BOOST_CHECK_EQUAL(record["version"].getInt<int64_t>(), 2147483650);
    Format(BCLog::LogFormat::TEXT);
    LogInfoEventNoRateLimit(BCLog::ALL, "hex_fixture", "version=0x{version:08x}")
        .Field(LogField::Version, uint32_t{2});
    BOOST_CHECK_EQUAL(Lines().at(0), "version=0x00000002");
    for (const char *invalid : {"{version:017x}", "{version:00x}",
                                "{version:8x}", "{version:08X}"}) {
        const BCLog::LogEventSite site{"hex_invalid", invalid, BCLog::ALL,
                                      BCLog::Level::Info};
        BCLog::EventBuilder{site, nullptr}.Field(LogField::Version, 2);
        BOOST_CHECK(Lines().at(0).starts_with(invalid));
    }
    LogInfoEventNoRateLimit(BCLog::ALL, "hex_signed", "{version:08x}")
        .Field(LogField::Version, -1);
    BOOST_CHECK(Lines().at(0).starts_with("{version:08x}"));
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

BOOST_AUTO_TEST_CASE(text_priority_prefix) {
    BCLog::TextEncoder encoder;
    BCLog::LogLine line{.time = SystemClock::time_point{},
                        .level = BCLog::Level::Warning,
                        .category = BCLog::ALL,
                        .message = "first\nsecond\n"};
    std::string encoded;
    encoder.Encode(line, BCLog::LogOptions{.timestamps = false}, encoded);
    BOOST_CHECK_EQUAL(encoded, "[warning] first\nsecond\n");
    encoder.Encode(
        line, BCLog::LogOptions{.timestamps = false, .text_priority = true},
        encoded);
    BOOST_CHECK_EQUAL(encoded, "<4>[warning] first\n<4>second\n");
    line.level = BCLog::Level::Info;
    encoder.Encode(
        line, BCLog::LogOptions{.timestamps = false, .text_priority = true},
        encoded);
    BOOST_CHECK_EQUAL(encoded, "<6>first\n<6>second\n");
    BCLog::JsonEncoder{}.Encode(line, BCLog::LogOptions{.text_priority = true},
                                encoded);
    UniValue record;
    BOOST_REQUIRE(record.read(encoded));
    BOOST_CHECK_EQUAL(record["message"].get_str(), "first\nsecond");
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

BOOST_AUTO_TEST_CASE(fee_rate_value_is_snapshot_and_preserves_text) {
    Format(BCLog::LogFormat::JSON);
    const std::array<int64_t, 8> amounts{
        std::numeric_limits<int64_t>::min(), -100000001, -1, 0,
        1, 100000000, 100000001, std::numeric_limits<int64_t>::max()};
    for (const int64_t amount : amounts) {
        CFeeRate rate{amount * SATOSHI};
        const auto expected{rate.ToString()};
        std::array<std::byte, BCLog::LogValue<CFeeRate>::MAX_SIZE> packed;
        const auto size{BCLog::LogValue<CFeeRate>::Pack(rate, packed)};
        rate = CFeeRate{};
        std::string rendered;
        BCLog::LogValue<CFeeRate>::Render(std::span{packed}.first(size),
                                        rendered);
        BOOST_CHECK_EQUAL(rendered, expected);
    }
    CFeeRate rate{12345 * SATOSHI};
    const auto expected{rate.ToString()};
    LogInfoEvent(BCLog::ALL, "fee_rate_snapshot", "rate={fee_rate}")
        .Field(LogField::FeeRate, rate);
    rate = CFeeRate{};
    const auto record{Json()};
    BOOST_CHECK_EQUAL(record["fee_rate"].get_str(), expected);
    BOOST_CHECK_EQUAL(record["message"].get_str(), "rate=" + expected);
}

BOOST_AUTO_TEST_CASE(addrman_events_preserve_endpoint_bucket_and_state_counts) {
    Format(BCLog::LogFormat::JSON);
    LogInstance().EnableCategory(BCLog::ADDRMAN);
    const CService endpoint{LookupNumeric("250.1.1.1", 10605)};
    const CNetAddr origin{LookupNumeric("252.2.2.2", 0)};
    {
        AddrMan manager{{},
                        /*deterministic=*/true,
                        /*consistency_check_ratio=*/0};
        CAddress address{endpoint, NODE_NETWORK};
        address.nTime = Now<NodeSeconds>();
        BOOST_REQUIRE(manager.Add({address}, origin));
        BOOST_CHECK_EQUAL(manager.size(), 1U);
        BOOST_CHECK_EQUAL(
            manager.Select(/*newOnly=*/true).first.ToStringAddrPort(),
            endpoint.ToStringAddrPort());
        manager.Good(endpoint);
        BOOST_CHECK_EQUAL(manager.size(), 1U);
        BOOST_CHECK_EQUAL(manager.Select().first.ToStringAddrPort(),
                          endpoint.ToStringAddrPort());
        BOOST_CHECK_EQUAL(manager.GetAddr(0, 0, std::nullopt).size(), 1U);
    }
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 6U);
    bool found_add{false}, found_counts{false}, found_tried{false},
        found_new_select{false}, found_tried_select{false},
        found_getaddr{false};
    for (const auto &line : lines) {
        UniValue record;
        BOOST_REQUIRE(record.read(line));
        BOOST_CHECK_EQUAL(record["level"].get_str(), "debug");
        BOOST_CHECK_EQUAL(record["category"].get_str(), "addrman");
        BOOST_CHECK(record["fields_truncated"].isNull());
        const auto event{record["event"].get_str()};
        if (event == "addrman_addresses_added") {
            found_counts = true;
            BOOST_CHECK_EQUAL(record["addr"].get_str(), origin.ToStringAddr());
            BOOST_CHECK_EQUAL(record["count"].getInt<int>(), 1);
            BOOST_CHECK_EQUAL(record["candidate_count"].getInt<int>(), 1);
            BOOST_CHECK_EQUAL(record["tried_address_count"].getInt<int>(), 0);
            BOOST_CHECK_EQUAL(record["new_address_count"].getInt<int>(), 1);
            BOOST_CHECK_EQUAL(
                record["message"].get_str(),
                "Added 1 addresses (of 1) from 252.2.2.2: 0 tried, 1 new");
        } else if (event == "addrman_getaddr_finished") {
            found_getaddr = true;
            BOOST_CHECK_EQUAL(record["count"].getInt<int>(), 1);
            BOOST_CHECK_EQUAL(record["message"].get_str(),
                              "GetAddr returned 1 random addresses");
        } else {
            BOOST_CHECK_EQUAL(record["addr"].get_str(),
                              endpoint.ToStringAddrPort());
            if (event == "addrman_address_added_new") {
                found_add = true;
                BOOST_CHECK_EQUAL(record["mapped_as"].getInt<int>(), 0);
                const int bucket{record["new_bucket_index"].getInt<int>()};
                const int position{record["new_bucket_position"].getInt<int>()};
                BOOST_CHECK(bucket >= 0 && position >= 0);
                BOOST_CHECK_EQUAL(
                    record["message"].get_str(),
                    strprintf("Added %s mapped to AS0 to new[%i][%i]",
                              endpoint.ToStringAddrPort(), bucket, position));
            } else if (event == "addrman_address_moved_tried") {
                found_tried = true;
                BOOST_CHECK_EQUAL(record["mapped_as"].getInt<int>(), 0);
                const int bucket{record["tried_bucket_index"].getInt<int>()};
                const int position{
                    record["tried_bucket_position"].getInt<int>()};
                BOOST_CHECK(bucket >= 0 && position >= 0);
                BOOST_CHECK_EQUAL(
                    record["message"].get_str(),
                    strprintf("Moved %s mapped to AS0 to tried[%i][%i]",
                              endpoint.ToStringAddrPort(), bucket, position));
            } else if (event == "addrman_address_selected_new") {
                found_new_select = true;
                BOOST_CHECK_EQUAL(record["message"].get_str(),
                                  "Selected 250.1.1.1:10605 from new");
            } else if (event == "addrman_address_selected_tried") {
                found_tried_select = true;
                BOOST_CHECK_EQUAL(record["message"].get_str(),
                                  "Selected 250.1.1.1:10605 from tried");
            } else {
                BOOST_ERROR("Unexpected address-manager event: " + event);
            }
        }
    }
    BOOST_CHECK(found_add && found_counts && found_tried && found_new_select &&
                found_tried_select && found_getaddr);
}

BOOST_AUTO_TEST_CASE(config_argument_fields_keep_redaction_and_section_text) {
    Format(BCLog::LogFormat::JSON);
    struct ConfigArgs : ArgsManager {
        using ArgsManager::ReadConfigStream;
    };
    ConfigArgs args;
    for (const char *option : {"-visible", "-boolean"}) {
        args.AddArg(option, "", ArgsManager::ALLOW_ANY,
                    OptionsCategory::OPTIONS);
    }
    args.AddArg("-secret", "", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE,
                OptionsCategory::OPTIONS);
    const char *argv[]{
        "logging-fixture", "-noboolean=0",
        "-visible=wss://example.invalid/p2p?token=url-canary-a962&x=1",
        "-secret=private-canary-891a"};
    std::string error;
    BOOST_REQUIRE(args.ParseParameters(std::size(argv), argv, error));
    std::istringstream config{"[regtest]\nvisible=configured\n"};
    BOOST_REQUIRE(args.ReadConfigStream(config, "fixture.conf", error));
    args.SelectConfigNetwork("regtest");
    args.LogArgs();
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 5U);
    bool found_double_negative{false}, found_section{false},
        found_secret{false}, found_url{false};
    for (const auto &line : lines) {
        BOOST_CHECK(line.find("url-canary-a962") == std::string::npos);
        BOOST_CHECK(line.find("private-canary-891a") == std::string::npos);
        UniValue record;
        BOOST_REQUIRE(record.read(line));
        BOOST_CHECK_EQUAL(record["level"].get_str(), "info");
        BOOST_CHECK(record["config_option"].isStr());
        BOOST_CHECK(record["value"].isStr());
        const auto event{record["event"].get_str()};
        if (event == "config_double_negative_interpreted") {
            found_double_negative = true;
            BOOST_CHECK_EQUAL(record["config_option"].get_str(), "boolean");
            BOOST_CHECK_EQUAL(record["value"].get_str(), "0");
            BOOST_CHECK_EQUAL(
                record["message"].get_str(),
                "Warning: parsed potentially confusing double-negative -boolean=0");
            continue;
        }
        BOOST_CHECK_EQUAL(event, "config_argument_displayed");
        const auto option{record["config_option"].get_str()};
        const auto value{record["value"].get_str()};
        BOOST_CHECK_EQUAL(record["message"].get_str(),
                          record["log_prefix"].get_str() + " " +
                              record["config_section_prefix"].get_str() +
                              option + "=" + value);
        if (record["log_prefix"].get_str() == "Config file arg:") {
            found_section = true;
            BOOST_CHECK_EQUAL(record["config_section_prefix"].get_str(),
                              "[regtest] ");
            BOOST_CHECK_EQUAL(value, "\"configured\"");
        } else if (option == "secret") {
            found_secret = true;
            BOOST_CHECK_EQUAL(value, "****");
        } else if (option == "visible") {
            found_url = true;
            BOOST_CHECK_EQUAL(value,
                              "\"wss://example.invalid/p2p?token=***&x=1\"");
        }
    }
    BOOST_CHECK(found_double_negative && found_section && found_secret &&
                found_url);
}

BOOST_AUTO_TEST_CASE(
    config_settings_fields_keep_unknown_keys_and_parser_errors) {
    Format(BCLog::LogFormat::JSON);
    ArgsManager args;
    for (const char *option : {"-datadir", "-settings"}) {
        args.AddArg(option, "", ArgsManager::ALLOW_ANY,
                    OptionsCategory::OPTIONS);
    }
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    const auto settings{m_args.GetDataDirBase() /
                        "logging-fixture-settings.json"};
    args.ForceSetArg("-settings", fs::PathToString(settings));
    std::ofstream{settings} << R"({"unknown-logging-fixture":"safe"})";
    BOOST_REQUIRE(args.ReadSettingsFile());
    args.LogArgs();
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 2U);
    UniValue unknown, displayed;
    BOOST_REQUIRE(unknown.read(lines[0]));
    BOOST_REQUIRE(displayed.read(lines[1]));
    BOOST_CHECK_EQUAL(unknown["event"].get_str(),
                      "config_settings_option_unknown");
    BOOST_CHECK_EQUAL(unknown["config_option"].get_str(),
                      "unknown-logging-fixture");
    BOOST_CHECK_EQUAL(
        unknown["message"].get_str(),
        "Ignoring unknown rw_settings value unknown-logging-fixture");
    BOOST_CHECK_EQUAL(displayed["event"].get_str(),
                      "config_settings_argument_displayed");
    BOOST_CHECK_EQUAL(displayed["config_option"].get_str(),
                      "unknown-logging-fixture");
    BOOST_CHECK_EQUAL(displayed["value"].get_str(), "\"safe\"");
    BOOST_CHECK_EQUAL(displayed["message"].get_str(),
                      "Setting file arg: unknown-logging-fixture = \"safe\"");
    std::ofstream{settings} << "{";
    BOOST_CHECK(!args.ReadSettingsFile());
    const auto failure{Json()};
    BOOST_CHECK_EQUAL(failure["event"].get_str(), "config_settings_error");
    BOOST_CHECK(failure["error"].isStr());
    BOOST_CHECK(!failure["error"].get_str().empty());
    BOOST_CHECK_EQUAL(failure["message"].get_str(), failure["error"].get_str());
    BOOST_CHECK_EQUAL(failure["level"].get_str(), "info");
}

BOOST_AUTO_TEST_CASE(character_value_preserves_printf_byte_and_json_escaping) {
    Format(BCLog::LogFormat::JSON);
    for (uint8_t value :
         std::array<uint8_t, 11>{0, 1, 9, 10, 13, 34, 38, 92, 104, 115, 127}) {
        const auto expected{strprintf("%c", value)};
        LogInfoEvent(BCLog::ALL, "character_snapshot", "byte=({value})")
            .Field(LogField::Value, BCLog::LogChar{value});
        value = 0xff;
        const auto record{Json()};
        BOOST_CHECK_EQUAL(record["value"].get_str(), expected);
        BOOST_CHECK_EQUAL(record["message"].get_str(),
                          "byte=(" + expected + ")");
        BOOST_CHECK(record["fields_truncated"].isNull());
    }
}

BOOST_AUTO_TEST_CASE(hex_value_is_snapshot_and_preserves_hexstr_output) {
    Format(BCLog::LogFormat::JSON);
    std::vector<std::vector<uint8_t>> cases{
        {}, {0}, {0xff}, {0, 1, 0x80, 0xff}};
    std::vector<uint8_t> all_bytes;
    for (int i = 0; i < 256; ++i) {
        all_bytes.push_back(uint8_t(i));
    }
    cases.push_back(all_bytes);
    for (auto bytes : cases) {
        const auto expected{HexStr(bytes)};
        LogInfoEvent(BCLog::ALL, "hex_snapshot", "bytes={value}")
            .Field(LogField::Value, BCLog::LogHex{bytes});
        // The record must not retain the view or defer reading this buffer.
        std::fill(bytes.begin(), bytes.end(), 0x55);
        bytes.clear();
        bytes.shrink_to_fit();
        const auto record{Json()};
        BOOST_CHECK_EQUAL(record["value"].get_str(), expected);
        BOOST_CHECK_EQUAL(record["message"].get_str(), "bytes=" + expected);
        BOOST_CHECK(record["fields_truncated"].isNull());
    }
    std::vector<uint8_t> oversized(BCLog::LogValue<BCLog::LogHex>::MAX_SIZE + 1,
                                   0xab);
    LogInfoEvent(BCLog::ALL, "hex_snapshot", "bytes={value}")
        .Field(LogField::Value, BCLog::LogHex{oversized})
        .Field(LogField::Count, oversized.size());
    const auto record{Json()};
    BOOST_CHECK(record["value"].isNull());
    BOOST_CHECK(record["fields_truncated"].get_bool());
    BOOST_CHECK_EQUAL(record["count"].getInt<uint64_t>(), oversized.size());
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

BOOST_AUTO_TEST_CASE(
    block_filter_range_errors_keep_signed_heights_and_messages) {
    Format(BCLog::LogFormat::JSON);
    BlockFilterIndex index(interfaces::MakeChain(m_node, Params()),
                           BlockFilterType::BASIC, 1 << 20, true);
    Lines(); // Exclude database setup diagnostics from the operation
             // assertions.
    CBlockIndex stop;
    stop.nHeight = 4;
    std::vector<BlockFilter> filters;
    BOOST_CHECK(!index.LookupFilterRange(-1, &stop, filters));
    BOOST_CHECK(filters.empty());
    auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(),
                      "block_filter_start_height_negative");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "error");
    BOOST_CHECK(row["index_start_height"].isNum());
    BOOST_CHECK_EQUAL(row["index_start_height"].getInt<int>(), -1);
    BOOST_CHECK_EQUAL(row["source_function"].get_str(), "LookupRange");
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      "LookupRange: start height (-1) is negative");
    BOOST_CHECK(row["fields_truncated"].isNull());

    BOOST_CHECK(!index.LookupFilterRange(5, &stop, filters));
    BOOST_CHECK(filters.empty());
    row = Json();
    BOOST_CHECK_EQUAL(row["event"].get_str(),
                      "block_filter_height_range_reversed");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "error");
    BOOST_CHECK(row["index_start_height"].isNum());
    BOOST_CHECK(row["index_stop_height"].isNum());
    BOOST_CHECK_EQUAL(row["index_start_height"].getInt<int>(), 5);
    BOOST_CHECK_EQUAL(row["index_stop_height"].getInt<int>(), 4);
    BOOST_CHECK_EQUAL(
        row["message"].get_str(),
        "LookupRange: start height (5) is greater than stop height (4)");
    BOOST_CHECK(row["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(ui_notifications_preserve_levels_secure_gate_and_stderr) {
    Format(BCLog::LogFormat::JSON);
    std::ostringstream captured;
    struct RestoreStream {
        std::streambuf *previous;
        ~RestoreStream() { std::cerr.rdbuf(previous); }
    } restore{std::cerr.rdbuf(captured.rdbuf())};
    const std::string body{"ui test % body & \"quoted\""};
    for (const unsigned int style :
         {CClientUIInterface::MSG_INFORMATION, CClientUIInterface::MSG_WARNING,
          CClientUIInterface::MSG_ERROR}) {
        const std::string level{style == CClientUIInterface::MSG_ERROR ? "error"
                                : style == CClientUIInterface::MSG_WARNING
                                    ? "warning"
                                    : "info"};
        const std::string prefix{
            style == CClientUIInterface::MSG_ERROR     ? "Error: "
            : style == CClientUIInterface::MSG_WARNING ? "Warning: "
                                                       : "Information: "};
        captured.str("");
        BOOST_CHECK(
            !noui_ThreadSafeMessageBox(Untranslated(body), "unused", style));
        const auto row{Json()};
        BOOST_CHECK_EQUAL(row["event"].get_str(), "node_ui_message");
        BOOST_CHECK_EQUAL(row["level"].get_str(), level);
        BOOST_CHECK_EQUAL(row["message_text"].get_str(), body);
        BOOST_CHECK_EQUAL(row["log_prefix"].get_str(), prefix);
        BOOST_CHECK_EQUAL(row["message"].get_str(), prefix + body);
        BOOST_CHECK_EQUAL(captured.str(), prefix + body + "\n");
        BOOST_CHECK(row["fields_truncated"].isNull());
    }
    captured.str("");
    const std::string secure_body{"fake-secure-ui-canary"};
    BOOST_CHECK(!noui_ThreadSafeMessageBox(Untranslated(secure_body), "unused",
                                           CClientUIInterface::MSG_ERROR |
                                               CClientUIInterface::SECURE));
    BOOST_CHECK_EQUAL(captured.str(), "Error: " + secure_body + "\n");
    BOOST_CHECK(
        Lines().empty()); // Guard suppresses all field capture/file output.
}

BOOST_AUTO_TEST_CASE(ui_init_message_preserves_opaque_untranslated_prose) {
    Format(BCLog::LogFormat::JSON);
    const std::string body{"Indexing 50%: value=17\nsecond line"};
    noui_InitMessage(body);
    const auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(), "node_ui_init_message");
    BOOST_CHECK_EQUAL(row["message_text"].get_str(), body);
    BOOST_CHECK_EQUAL(row["message"].get_str(), "init message: " + body);
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(
    snapshot_base_hash_paths_preserve_optional_result_and_trailing_data) {
    LOCK(cs_main); // ReadSnapshotBaseBlockhash requires the chainstate lock.
    Format(BCLog::LogFormat::JSON);
    const fs::path directory{m_args.GetDataDirBase() / "snapshot-log-control"};
    const fs::path file_path{directory / node::SNAPSHOT_BLOCKHASH_FILENAME};
    BOOST_REQUIRE(!fs::exists(directory));
    BOOST_CHECK(!node::ReadSnapshotBaseBlockhash(directory));
    auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(),
                      "snapshot_base_hash_directory_missing");
    BOOST_CHECK_EQUAL(row["path"].get_str(), fs::PathToString(directory));
    BOOST_CHECK_EQUAL(
        row["message"].get_str(),
        "[snapshot] cannot read base blockhash: no chainstate dir exists at path " +
            fs::PathToString(directory));
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");

    BOOST_REQUIRE(fs::create_directory(directory));
    BOOST_CHECK(!node::ReadSnapshotBaseBlockhash(directory));
    row = Json();
    BOOST_CHECK_EQUAL(row["event"].get_str(),
                      "snapshot_base_hash_file_missing");
    BOOST_CHECK_EQUAL(row["directory"].get_str(), fs::PathToString(directory));
    BOOST_CHECK_EQUAL(row["path"].get_str(), fs::PathToString(file_path));
    BOOST_CHECK_EQUAL(
        row["message"].get_str(),
        "[snapshot] snapshot chainstate dir is malformed! no base blockhash file exists at path " +
            fs::PathToString(directory) + ". Try deleting " +
            fs::PathToString(file_path) + " and calling loadtxoutset again?");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");

    const BlockHash expected{SomeHash()};
    {
        AutoFile file{fsbridge::fopen(file_path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        file << expected;
        file << uint8_t{
            0x58}; // Valid hash followed by one original warning trigger.
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
    const auto result{node::ReadSnapshotBaseBlockhash(directory)};
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(
        *result ==
        expected); // Warning must not turn successful read into failure.
    row = Json();
    BOOST_CHECK_EQUAL(row["event"].get_str(),
                      "snapshot_base_hash_trailing_data");
    BOOST_CHECK_EQUAL(row["path"].get_str(), fs::PathToString(file_path));
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      "[snapshot] warning: unexpected trailing data in " +
                          fs::PathToString(file_path));
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["fields_truncated"].isNull());
}

#if (defined(MAC_OSX) && defined(F_FULLFSYNC)) || defined(__linux__)
BOOST_AUTO_TEST_CASE(
    file_commit_failure_preserves_error_text_and_false_return) {
    Format(BCLog::LogFormat::JSON);
#if defined(MAC_OSX) && defined(F_FULLFSYNC)
    // /dev/null accepts stdio writes but cannot perform F_FULLFSYNC.
    AutoFile file{fsbridge::fopen(fs::path{"/dev/null"}, "wb")};
    constexpr const char *event{"file_commit_fullfsync_failed"};
    constexpr const char *prefix{"fcntl F_FULLFSYNC failed: "};
#else
    // Buffer one byte so /dev/full reports its actual ENOSPC in fflush.
    std::array<char, 4096> buffer{};
    AutoFile file{fsbridge::fopen(fs::path{"/dev/full"}, "wb")};
    BOOST_REQUIRE(!file.IsNull());
    BOOST_REQUIRE_EQUAL(
        setvbuf(file.Get(), buffer.data(), _IOFBF, buffer.size()), 0);
    constexpr const char *event{"file_commit_stdio_flush_failed"};
    constexpr const char *prefix{"fflush failed: "};
#endif
    BOOST_REQUIRE(!file.IsNull());
    const char value{'x'};
    BOOST_REQUIRE_EQUAL(fwrite(&value, 1, 1, file.Get()), 1U);
    BOOST_CHECK(!FileCommit(file.Get()));
    const auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(), event);
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_REQUIRE(row["error"].isStr());
    BOOST_CHECK(!row["error"].get_str().empty());
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      std::string{prefix} + row["error"].get_str());
    BOOST_CHECK(row["fields_truncated"].isNull());
}
#endif

BOOST_AUTO_TEST_CASE(ignored_config_option_does_not_log_its_value) {
    Format(BCLog::LogFormat::JSON);
    struct ConfigArgs : ArgsManager {
        using ArgsManager::ReadConfigStream;
    } args;
    std::istringstream input{
        "unknown_logging_option=not-a-real-secret-canary-215\n"};
    std::string error;
    BOOST_REQUIRE(args.ReadConfigStream(input, "logging-fixture.conf", error,
                                        /*ignore_invalid_keys=*/true));
    BOOST_CHECK(error.empty());
    const auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(), "config_unknown_option_ignored");
    BOOST_CHECK_EQUAL(row["config_option"].get_str(), "unknown_logging_option");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK_EQUAL(
        row["message"].get_str(),
        "Ignoring unknown configuration value unknown_logging_option");
    BOOST_CHECK(row.write().find("not-a-real-secret-canary-215") ==
                std::string::npos);
    BOOST_CHECK(row["value"].isNull());
    BOOST_CHECK(row["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(
    asmap_missing_and_invalid_files_keep_path_and_signed_length) {
    Format(BCLog::LogFormat::JSON);
    const fs::path missing{m_args.GetDataDirBase() / "missing-asmap"};
    BOOST_CHECK(DecodeAsmap(missing).empty());
    auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(), "asmap_file_open_failed");
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      "Failed to open asmap file from disk");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    const fs::path malformed{m_args.GetDataDirBase() / "asmap&\"invalid.raw"};
    {
        std::ofstream file{malformed, std::ios::binary};
        file.put('\0'); // Too short even for the minimum RETURN ASN encoding.
        BOOST_REQUIRE(file.good());
    }
    BOOST_CHECK(DecodeAsmap(malformed).empty());
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 2U);
    BOOST_REQUIRE(row.read(lines[0]));
    BOOST_CHECK_EQUAL(row["event"].get_str(), "asmap_file_opened");
    BOOST_CHECK(row["asmap_length_bytes"].isNum());
    BOOST_CHECK_EQUAL(row["asmap_length_bytes"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(row["path"].get_str(), fs::PathToString(malformed));
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      strprintf("Opened asmap file %s (%d bytes) from disk",
                                fs::quoted(fs::PathToString(malformed)), 1));
    BOOST_CHECK(row["fields_truncated"].isNull());
    BOOST_REQUIRE(row.read(lines[1]));
    BOOST_CHECK_EQUAL(row["event"].get_str(), "asmap_file_invalid");
    BOOST_CHECK_EQUAL(row["path"].get_str(), fs::PathToString(malformed));
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      strprintf("Sanity check of asmap file %s failed",
                                fs::quoted(fs::PathToString(malformed))));
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(
    flatfile_open_failure_preserves_plain_path_and_null_result) {
    Format(BCLog::LogFormat::JSON);
    const fs::path directory{m_args.GetDataDirBase() / "absent-flat-files"};
    FlatFileSeq sequence{directory, "blk", 1024};
    const FlatFilePos missing{17, 0};
    BOOST_CHECK(sequence.Open(missing, /*read_only=*/true) == nullptr);
    BOOST_CHECK(!fs::exists(directory));
    const auto row{Json()};
    const auto path{fs::PathToString(sequence.FileName(missing))};
    BOOST_CHECK_EQUAL(row["event"].get_str(), "flatfile_open_failed");
    BOOST_CHECK_EQUAL(row["path"].get_str(), path);
    BOOST_CHECK_EQUAL(row["message"].get_str(), "Unable to open file " + path);
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["fields_truncated"].isNull());
}

#if defined(__linux__) || defined(MAC_OSX)
BOOST_AUTO_TEST_CASE(
    flatfile_fifo_seek_failure_keeps_unsigned_offset_and_null_result) {
    Format(BCLog::LogFormat::JSON);
    const fs::path directory{m_args.GetDataDirBase() / "flatfile-fifo"};
    fs::create_directories(directory);
    FlatFileSeq sequence{directory, "blk", 1024};
    const FlatFilePos position{18, 1};
    const fs::path path{sequence.FileName(position)};
    BOOST_REQUIRE_EQUAL(mkfifo(path.c_str(), 0600), 0);
    // Hold both FIFO ends so fopen(read-only) does not wait for a writer.
    // No bytes are exchanged: a FIFO's real fseek returns ESPIPE.
    struct Descriptor {
        int value;
        ~Descriptor() {
            if (value >= 0) close(value);
        }
    } holder{open(path.c_str(), O_RDWR | O_NONBLOCK)};
    BOOST_REQUIRE(holder.value >= 0);
    BOOST_CHECK(sequence.Open(position, /*read_only=*/true) == nullptr);
    const auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(), "flatfile_seek_failed");
    BOOST_CHECK(row["file_offset"].isNum());
    BOOST_CHECK_EQUAL(row["file_offset"].getInt<uint64_t>(), 1U);
    BOOST_CHECK_EQUAL(row["path"].get_str(), fs::PathToString(path));
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      "Unable to seek to position 1 of " +
                          fs::PathToString(path));
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["fields_truncated"].isNull());
}
#endif

BOOST_AUTO_TEST_CASE(
    headers_presync_rejections_keep_peer_height_and_final_state) {
    Format(BCLog::LogFormat::JSON);
    LogInstance().DisableCategory(
        BCLog::NET); // Leave only actual Info failures.
    CBlockIndex base{Params().GenesisBlock()};
    BlockHash base_hash{base.GetBlockHeader().GetHash()};
    base.phashBlock = &base_hash;
    base.nChainWork = GetBlockProof(base);
    auto params{Params().GetConsensus()};
    params.fPowAllowMinDifficultyBlocks = false;
    HeadersSyncState invalid{-7, params, &base, arith_uint256{1} << 255};
    CBlockHeader bad{base.GetBlockHeader()};
    bad.hashPrevBlock = base_hash;
    bad.nBits = 0; // Actual invalid target is rejected before storing a header.
    const auto rejected{invalid.ProcessNextHeaders({bad}, true)};
    BOOST_CHECK(!rejected.success);
    BOOST_CHECK(invalid.GetState() == HeadersSyncState::State::FINAL);
    auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(),
                      "headers_presync_difficulty_invalid");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["peer_id"].isNum());
    BOOST_CHECK_EQUAL(row["peer_id"].getInt<int64_t>(), -7);
    BOOST_CHECK(row["height"].isNum());
    BOOST_CHECK_EQUAL(row["height"].getInt<int64_t>(), base.nHeight + 1);
    BOOST_CHECK_EQUAL(
        row["message"].get_str(),
        strprintf(
            "Initial headers sync aborted with peer=%d: invalid difficulty transition at height=%i (presync phase)",
            -7, base.nHeight + 1));
    BOOST_CHECK(row["fields_truncated"].isNull());

    // A synthetic starting tip at the future-time bound leaves zero allowed
    // commitments. One commitment is attempted within each 610-header period,
    // regardless of randomized offset. HeadersSyncState assumes its caller has
    // already checked PoW; no claim that these synthetic headers are valid.
    base.nTime =
        Ticks<std::chrono::seconds>(GetAdjustedTime().time_since_epoch()) + MAX_FUTURE_BLOCK_TIME;
    base_hash = base.GetBlockHeader().GetHash();
    params.fPowAllowMinDifficultyBlocks = true;
    HeadersSyncState bounded{8, params, &base, arith_uint256{1} << 255};
    std::vector<CBlockHeader> headers;
    BlockHash previous{base_hash};
    for (unsigned i{0}; i < 610; ++i) {
        CBlockHeader header{base.GetBlockHeader()};
        header.hashPrevBlock = previous;
        header.nNonce += i + 1;
        previous = header.GetHash();
        headers.push_back(header);
    }
    const auto exceeded{bounded.ProcessNextHeaders(headers, true)};
    BOOST_CHECK(!exceeded.success);
    BOOST_CHECK(bounded.GetState() == HeadersSyncState::State::FINAL);
    row = Json();
    BOOST_CHECK_EQUAL(row["event"].get_str(),
                      "headers_presync_commitments_exceeded");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["peer_id"].isNum());
    BOOST_CHECK_EQUAL(row["peer_id"].getInt<int64_t>(), 8);
    BOOST_CHECK(row["height"].isNum());
    const auto height{row["height"].getInt<int64_t>()};
    BOOST_CHECK(height >= base.nHeight + 1 && height <= base.nHeight + 610);
    BOOST_CHECK_EQUAL(
        row["message"].get_str(),
        strprintf(
            "Initial headers sync aborted with peer=%d: exceeded max commitments at height=%i (presync phase)",
            8, height));
    BOOST_CHECK(row["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(
    transaction_missing_input_preserves_hash_kind_and_nullopt) {
    Format(BCLog::LogFormat::JSON);
    CMutableTransaction mutable_tx;
    mutable_tx.nVersion = 2; // The shared owner remains applicable to ABC.
    mutable_tx.vin.resize(1);
    mutable_tx.vin[0].prevout = COutPoint{TxId{SomeHash()}, 0};
    const auto tx{MakeTransactionRef(std::move(mutable_tx))};
    CBlockIndex tip{Params().GenesisBlock()};
    const CCoinsView empty;
    BOOST_CHECK(!CalculateLockPointsAtTip(&tip, empty, *tx).has_value());
    const auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(), "transaction_input_missing");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK_EQUAL(row["source_function"].get_str(), "CalculatePrevHeights");
    BOOST_CHECK(row["input_index"].isNum());
    BOOST_CHECK_EQUAL(row["input_index"].getInt<uint64_t>(), 0U);
    BOOST_CHECK_EQUAL(row["tx_hash"].get_str(), tx->GetHash().GetHex());
    BOOST_CHECK(row["txid"].isNull());
    BOOST_CHECK_EQUAL(
        row["message"].get_str(),
        strprintf("ERROR: %s: Missing input %d in transaction '%s'",
                  "CalculatePrevHeights", 0, tx->GetHash().GetHex()));
    BOOST_CHECK(row["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(
    actual_validation_caches_keep_integer_budgets_and_capacity) {
    Format(BCLog::LogFormat::JSON);
    const ValidationCache cache{2 * 1024 * 1024, 2 * 1024 * 1024};
    const auto lines{Lines()};
    BOOST_REQUIRE_EQUAL(lines.size(), 2U);
    for (size_t index{0}; index < lines.size(); ++index) {
        UniValue row;
        BOOST_REQUIRE(row.read(lines[index]));
        const std::string kind{index == 0 ? "signature" : "script execution"};
        BOOST_CHECK_EQUAL(row["event"].get_str(),
                          index == 0 ? "signature_cache_initialized"
                                     : "script_execution_cache_initialized");
        BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
        BOOST_CHECK(row["cache_requested_mib"].isNum());
        BOOST_CHECK_EQUAL(row["cache_requested_mib"].getInt<uint64_t>(), 2U);
        BOOST_CHECK(row["cache_allocated_mib"].isNum());
        const auto allocated{row["cache_allocated_mib"].getInt<uint64_t>()};
        BOOST_CHECK(allocated <= 2U);
        BOOST_CHECK(row["cache_capacity"].isNum());
        const auto capacity{row["cache_capacity"].getInt<uint64_t>()};
        BOOST_CHECK(capacity > 0);
        BOOST_CHECK_EQUAL(
            row["message"].get_str(),
            strprintf(
                "Using %zu MiB out of %zu MiB requested for %s cache, able to store %zu elements",
                size_t(allocated), size_t(2), kind, size_t(capacity)));
        BOOST_CHECK(row["fields_truncated"].isNull());
    }
}

BOOST_AUTO_TEST_CASE(
    actual_checkqueue_constructor_keeps_additional_worker_count) {
    Format(BCLog::LogFormat::JSON);
    CCheckQueue<std::function<std::optional<int>()>> queue{128, 0};
    const auto row{Json()};
    BOOST_CHECK_EQUAL(row["event"].get_str(), "script_verification_workers");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["script_worker_threads"].isNum());
    BOOST_CHECK_EQUAL(row["script_worker_threads"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      "Script verification uses 0 additional threads");
    BOOST_CHECK(row["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_SUITE_END()
