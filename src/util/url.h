// Copyright (c) 2015-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_URL_H
#define BITCOIN_UTIL_URL_H

#include <string>

/**
 * Percent-decode a URL component. Only "%XX" with two hexadecimal digits (in
 * either case) is decoded; anything else, including '+', is copied unchanged.
 * The result ends at the first decoded NUL character.
 */
std::string urlDecode(const std::string &urlEncoded);

/**
 * Percent-encode a URL component. The unreserved characters A-Z, a-z, 0-9,
 * '-', '.', '_' and '~' are kept; every other byte becomes "%XX" in upper-case
 * hexadecimal.
 */
std::string urlEncode(const std::string &str);

#endif // BITCOIN_UTIL_URL_H
