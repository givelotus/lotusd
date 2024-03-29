// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>

#include <test/scriptflags.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/test/unit_test.hpp>

#include <map>
#include <vector>

static std::map<std::string, uint32_t> mapFlagNames = {
    {"NONE", SCRIPT_VERIFY_NONE},
    {"DISABLE_TAPROOT_SIGHASH_LOTUS", SCRIPT_DISABLE_TAPROOT_SIGHASH_LOTUS},
    {"DISCOURAGE_UPGRADABLE_NOPS", SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
    {"CLEANSTACK", SCRIPT_VERIFY_CLEANSTACK},
    {"MINIMALIF", SCRIPT_VERIFY_MINIMALIF},
    {"SIGHASH_FORKID", SCRIPT_ENABLE_SIGHASH_FORKID},
    {"REPLAY_PROTECTION", SCRIPT_ENABLE_REPLAY_PROTECTION},
    {"INPUT_SIGCHECKS", SCRIPT_VERIFY_INPUT_SIGCHECKS},
};

uint32_t ParseScriptFlags(std::string strFlags) {
    if (strFlags.empty()) {
        return 0;
    }

    uint32_t flags = 0;
    std::vector<std::string> words;
    boost::algorithm::split(words, strFlags, boost::algorithm::is_any_of(","));

    for (std::string &word : words) {
        if (!mapFlagNames.count(word)) {
            BOOST_ERROR("Bad test: unknown verification flag '" << word << "'");
        }
        flags |= mapFlagNames[word];
    }

    return flags;
}

std::string FormatScriptFlags(uint32_t flags) {
    if (flags == 0) {
        return "";
    }

    std::string ret;
    std::map<std::string, uint32_t>::const_iterator it = mapFlagNames.begin();
    while (it != mapFlagNames.end()) {
        if (flags & it->second) {
            ret += it->first + ",";
        }
        it++;
    }

    return ret.substr(0, ret.size() - 1);
}
