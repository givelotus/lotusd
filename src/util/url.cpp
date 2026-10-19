// Copyright (c) 2015-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/url.h>

#include <util/strencodings.h>

#include <cstddef>
#include <cstdint>

std::string urlDecode(const std::string &urlEncoded) {
    std::string res;
    res.reserve(urlEncoded.size());
    for (size_t i = 0; i < urlEncoded.size(); ++i) {
        char c = urlEncoded[i];
        if (c == '%' && i + 2 < urlEncoded.size()) {
            const signed char hi = HexDigit(urlEncoded[i + 1]);
            const signed char lo = HexDigit(urlEncoded[i + 2]);
            if (hi >= 0 && lo >= 0) {
                c = static_cast<char>((hi << 4) | lo);
                i += 2;
            }
        }
        if (c == '\0') {
            // The result was a C string: it ends at the first NUL.
            break;
        }
        res.push_back(c);
    }
    return res;
}

std::string urlEncode(const std::string &str) {
    static constexpr char HEX[] = "0123456789ABCDEF";
    std::string res;
    res.reserve(str.size());
    for (const char ch : str) {
        const uint8_t c = static_cast<uint8_t>(ch);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
            c == '~') {
            res.push_back(ch);
        } else {
            res.push_back('%');
            res.push_back(HEX[c >> 4]);
            res.push_back(HEX[c & 0xf]);
        }
    }
    return res;
}
