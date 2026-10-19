// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

#include <torcontrol.h>

#include <test/util/setup_common.h>

#include <event2/util.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <optional>
#include <string>
#include <utility>

std::pair<std::string, std::string> SplitTorReplyLine(const std::string &s);
std::map<std::string, std::string> ParseTorReplyMapping(const std::string &s);

BOOST_FIXTURE_TEST_SUITE(torcontrol_tests, BasicTestingSetup)

static void CheckSplitTorReplyLine(std::string input, std::string command,
                                   std::string args) {
    auto ret = SplitTorReplyLine(input);
    BOOST_CHECK_EQUAL(ret.first, command);
    BOOST_CHECK_EQUAL(ret.second, args);
}

BOOST_AUTO_TEST_CASE(util_SplitTorReplyLine) {
    // Data we should receive during normal usage
    CheckSplitTorReplyLine("PROTOCOLINFO PIVERSION", "PROTOCOLINFO",
                           "PIVERSION");
    CheckSplitTorReplyLine("AUTH METHODS=COOKIE,SAFECOOKIE "
                           "COOKIEFILE=\"/home/x/.tor/control_auth_cookie\"",
                           "AUTH",
                           "METHODS=COOKIE,SAFECOOKIE "
                           "COOKIEFILE=\"/home/x/.tor/control_auth_cookie\"");
    CheckSplitTorReplyLine("AUTH METHODS=NULL", "AUTH", "METHODS=NULL");
    CheckSplitTorReplyLine("AUTH METHODS=HASHEDPASSWORD", "AUTH",
                           "METHODS=HASHEDPASSWORD");
    CheckSplitTorReplyLine("VERSION Tor=\"0.2.9.8 (git-a0df013ea241b026)\"",
                           "VERSION", "Tor=\"0.2.9.8 (git-a0df013ea241b026)\"");
    CheckSplitTorReplyLine("AUTHCHALLENGE SERVERHASH=aaaa SERVERNONCE=bbbb",
                           "AUTHCHALLENGE", "SERVERHASH=aaaa SERVERNONCE=bbbb");

    // Other valid inputs
    CheckSplitTorReplyLine("COMMAND", "COMMAND", "");
    CheckSplitTorReplyLine("COMMAND SOME  ARGS", "COMMAND", "SOME  ARGS");

    // These inputs are valid because PROTOCOLINFO accepts an OtherLine that is
    // just an OptArguments, which enables multiple spaces to be present
    // between the command and arguments.
    CheckSplitTorReplyLine("COMMAND  ARGS", "COMMAND", " ARGS");
    CheckSplitTorReplyLine("COMMAND   EVEN+more  ARGS", "COMMAND",
                           "  EVEN+more  ARGS");
}

static void
CheckParseTorReplyMapping(std::string input,
                          std::map<std::string, std::string> expected) {
    auto ret = ParseTorReplyMapping(input);
    BOOST_CHECK_EQUAL(ret.size(), expected.size());
    auto r_it = ret.begin();
    auto e_it = expected.begin();
    while (r_it != ret.end() && e_it != expected.end()) {
        BOOST_CHECK_EQUAL(r_it->first, e_it->first);
        BOOST_CHECK_EQUAL(r_it->second, e_it->second);
        r_it++;
        e_it++;
    }
}

BOOST_AUTO_TEST_CASE(util_ParseTorReplyMapping) {
    // Data we should receive during normal usage
    CheckParseTorReplyMapping(
        "METHODS=COOKIE,SAFECOOKIE "
        "COOKIEFILE=\"/home/x/.tor/control_auth_cookie\"",
        {
            {"METHODS", "COOKIE,SAFECOOKIE"},
            {"COOKIEFILE", "/home/x/.tor/control_auth_cookie"},
        });
    CheckParseTorReplyMapping("METHODS=NULL", {
                                                  {"METHODS", "NULL"},
                                              });
    CheckParseTorReplyMapping("METHODS=HASHEDPASSWORD",
                              {
                                  {"METHODS", "HASHEDPASSWORD"},
                              });
    CheckParseTorReplyMapping("Tor=\"0.2.9.8 (git-a0df013ea241b026)\"",
                              {
                                  {"Tor", "0.2.9.8 (git-a0df013ea241b026)"},
                              });
    CheckParseTorReplyMapping("SERVERHASH=aaaa SERVERNONCE=bbbb",
                              {
                                  {"SERVERHASH", "aaaa"},
                                  {"SERVERNONCE", "bbbb"},
                              });
    CheckParseTorReplyMapping("ServiceID=exampleonion1234",
                              {
                                  {"ServiceID", "exampleonion1234"},
                              });
    CheckParseTorReplyMapping("PrivateKey=RSA1024:BLOB",
                              {
                                  {"PrivateKey", "RSA1024:BLOB"},
                              });
    CheckParseTorReplyMapping("ClientAuth=bob:BLOB",
                              {
                                  {"ClientAuth", "bob:BLOB"},
                              });

    // Other valid inputs
    CheckParseTorReplyMapping("Foo=Bar=Baz Spam=Eggs", {
                                                           {"Foo", "Bar=Baz"},
                                                           {"Spam", "Eggs"},
                                                       });
    CheckParseTorReplyMapping("Foo=\"Bar=Baz\"", {
                                                     {"Foo", "Bar=Baz"},
                                                 });
    CheckParseTorReplyMapping("Foo=\"Bar Baz\"", {
                                                     {"Foo", "Bar Baz"},
                                                 });

    // Escapes
    CheckParseTorReplyMapping("Foo=\"Bar\\ Baz\"", {
                                                       {"Foo", "Bar Baz"},
                                                   });
    CheckParseTorReplyMapping("Foo=\"Bar\\Baz\"", {
                                                      {"Foo", "BarBaz"},
                                                  });
    CheckParseTorReplyMapping("Foo=\"Bar\\@Baz\"", {
                                                       {"Foo", "Bar@Baz"},
                                                   });
    CheckParseTorReplyMapping("Foo=\"Bar\\\"Baz\" Spam=\"\\\"Eggs\\\"\"",
                              {
                                  {"Foo", "Bar\"Baz"},
                                  {"Spam", "\"Eggs\""},
                              });
    CheckParseTorReplyMapping("Foo=\"Bar\\\\Baz\"", {
                                                        {"Foo", "Bar\\Baz"},
                                                    });

    // C escapes
    CheckParseTorReplyMapping(
        "Foo=\"Bar\\nBaz\\t\" Spam=\"\\rEggs\" "
        "Octals=\"\\1a\\11\\17\\18\\81\\377\\378\\400\\2222\" Final=Check",
        {
            {"Foo", "Bar\nBaz\t"},
            {"Spam", "\rEggs"},
            {"Octals", "\1a\11\17\1"
                       "881\377\37"
                       "8\40"
                       "0\222"
                       "2"},
            {"Final", "Check"},
        });
    CheckParseTorReplyMapping("Valid=Mapping Escaped=\"Escape\\\\\"",
                              {
                                  {"Valid", "Mapping"},
                                  {"Escaped", "Escape\\"},
                              });
    CheckParseTorReplyMapping("Valid=Mapping Bare=\"Escape\\\"", {});
    CheckParseTorReplyMapping("OneOctal=\"OneEnd\\1\" TwoOctal=\"TwoEnd\\11\"",
                              {
                                  {"OneOctal", "OneEnd\1"},
                                  {"TwoOctal", "TwoEnd\11"},
                              });

    // Special handling for null case
    // (needed because string comparison reads the null as end-of-string)
    auto ret = ParseTorReplyMapping("Null=\"\\0\"");
    BOOST_CHECK_EQUAL(ret.size(), 1U);
    auto r_it = ret.begin();
    BOOST_CHECK_EQUAL(r_it->first, "Null");
    BOOST_CHECK_EQUAL(r_it->second.size(), 1U);
    BOOST_CHECK_EQUAL(r_it->second[0], '\0');

    // A more complex valid grammar. PROTOCOLINFO accepts a VersionLine that
    // takes a key=value pair followed by an OptArguments, making this valid.
    // Because an OptArguments contains no semantic data, there is no point in
    // parsing it.
    CheckParseTorReplyMapping("SOME=args,here MORE optional=arguments  here",
                              {
                                  {"SOME", "args,here"},
                              });

    // Inputs that are effectively invalid under the target grammar.
    // PROTOCOLINFO accepts an OtherLine that is just an OptArguments, which
    // would make these inputs valid. However,
    // - This parser is never used in that situation, because the
    //   SplitTorReplyLine parser enables OtherLine to be skipped.
    // - Even if these were valid, an OptArguments contains no semantic data,
    //   so there is no point in parsing it.
    CheckParseTorReplyMapping("ARGS", {});
    CheckParseTorReplyMapping("MORE ARGS", {});
    CheckParseTorReplyMapping("MORE  ARGS", {});
    CheckParseTorReplyMapping("EVEN more=ARGS", {});
    CheckParseTorReplyMapping("EVEN+more ARGS", {});
}

BOOST_AUTO_TEST_CASE(util_ParseTorControlAddress) {
    // Expected results: the address and port as CService prints them, or
    // nullopt when the address is rejected.
    const std::vector<std::pair<std::string, std::optional<std::string>>>
        vectors{
            {"127.0.0.1:9051", "127.0.0.1:9051"},
            {"127.0.0.1", "127.0.0.1:0"},
            {"127.0.0.1:65535", "127.0.0.1:65535"},
            {"127.0.0.1:+80", "127.0.0.1:80"},
            {"127.0.0.1: 80", "127.0.0.1:80"},
            {"127.0.0.1:80abc", "127.0.0.1:80"},
            {"[::1]:9051", "[::1]:9051"},
            {"[::1]", "[::1]:0"},
            {"[::1]9051", "[::1]:0"},
            {"::1", "[::1]:0"},
            {"1:2:3:4:5:6:7:8", "[1:2:3:4:5:6:7:8]:0"},
            {"[2001:db8::1]:1", "[2001:db8::1]:1"},
            {"localhost:9051", std::nullopt},
            {"localhost", std::nullopt},
            {"tor.example.com:9051", std::nullopt},
            {"127.0.0.1:0", std::nullopt},
            {"127.0.0.1:65536", std::nullopt},
            {"127.0.0.1:-1", std::nullopt},
            {"127.0.0.1:", std::nullopt},
            {"127.0.0.1:x", std::nullopt},
            {"127.1", std::nullopt},
            {"256.1.1.1", std::nullopt},
            {"1.2.3.4.5", std::nullopt},
            {"", std::nullopt},
            {":9051", std::nullopt},
            {"[::1", std::nullopt},
            {"[::1]:0", std::nullopt},
            {"[127.0.0.1]:80", std::nullopt},
            {"::1:9051:x", std::nullopt},
        };
    for (const auto &[input, expected] : vectors) {
        const std::optional<CService> parsed{ParseTorControlAddress(input)};
        BOOST_CHECK_MESSAGE(parsed.has_value() == expected.has_value(),
                            "input: " << input);
        if (parsed && expected) {
            BOOST_CHECK_EQUAL(parsed->ToStringAddrPort(), *expected);
        }

        // The accepted forms are those of libevent's parser.
        struct sockaddr_storage storage {};
        int len = sizeof(storage);
        const bool libevent_ok =
            evutil_parse_sockaddr_port(input.c_str(),
                                       reinterpret_cast<sockaddr *>(&storage),
                                       &len) == 0;
        BOOST_CHECK_MESSAGE(libevent_ok == expected.has_value(),
                            "libevent input: " << input);
        if (libevent_ok && expected) {
            CService service;
            BOOST_CHECK(service.SetSockAddr(
                reinterpret_cast<const sockaddr *>(&storage), len));
            BOOST_CHECK_EQUAL(service.ToStringAddrPort(), *expected);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
