// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpserver.h>
#include <netaddress.h>
#include <util/strencodings.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

std::string RequestMethodString(HTTPRequest::RequestMethod m);

FUZZ_TARGET(http_request) {
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const std::vector<uint8_t> http_buffer =
        ConsumeRandomLengthByteVector(fuzzed_data_provider, 4096);
    auto http_request{ParseHTTPRequestForTesting(
        std::string{http_buffer.begin(), http_buffer.end()})};
    if (!http_request) {
        return;
    }

    const HTTPRequest::RequestMethod request_method =
        http_request->GetRequestMethod();
    (void)RequestMethodString(request_method);
    (void)http_request->GetURI();
    (void)http_request->GetHeader("Host");
    const std::string header =
        fuzzed_data_provider.ConsumeRandomLengthString(16);
    (void)http_request->GetHeader(header);
    try {
        http_request->WriteHeader(
            header, fuzzed_data_provider.ConsumeRandomLengthString(16));
    } catch (const std::exception &) {
        // Invalid header names are rejected.
    }
    (void)http_request->GetHeader(header);
    (void)http_request->ReadBody();
    const CService service = http_request->GetPeer();
    assert(service.ToStringAddrPort() == "[::]:0");
}
