// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// chronik-native-lotus-v2-dump: the V2-tier counterpart of
// chronik-native-dump for contrib/chronik-parity. Prints the legacy Chronik
// env of a Lotus V2 node (eCash tables plus the six V2 group tables) as
// sorted "table<TAB>key_hex<TAB>value_hex" lines. Run it on the index of a
// stopped node (<datadir>/<net>/indexes/chronik).
//
// If the V2 service's env exists (<dir>/v2_index), its subdatabases follow
// as "v2_index:<table>" lines (raw MDBX keys and values, as both
// implementations share the layout), then one "v2_index:flat" line per flat
// segment file: file name (hex), size and SHA-256 of its contents.

#include <chronik/native/mdbx_store.h>
#include <chronik/native/schema.h>
#include <core/db/dump.h>

#include <ext/lotus_v2/db/env.h>
#include <ext/lotus_v2/groups/groups.h>

// Portable SHA-256, only needed to open envs with hashed long keys.
#include <test/test_sha256.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

using namespace chronik::native;

namespace {

std::string Hex(const uint8_t *data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 * len);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0xf]);
    }
    return out;
}

/** The v2_index env and its flat segment files, if the env exists. */
void DumpV2Index(const std::filesystem::path &dir, std::ostream &out) {
    if (!std::filesystem::is_regular_file(dir / "mdbx.dat")) {
        return;
    }
    {
        const lotus_v2::V2Env env(dir);
        std::ostringstream tables;
        db::DumpStore(env.Store(), lotus_v2::V2Env::Tables(), tables);
        std::istringstream lines(tables.str());
        for (std::string line; std::getline(lines, line);) {
            out << "v2_index:" << line << "\n";
        }
    }
    std::vector<std::filesystem::path> segments;
    for (const auto &entry : std::filesystem::directory_iterator(dir)) {
        const std::string name = entry.path().filename().string();
        if (entry.is_regular_file() && name.starts_with("v2_tx_") &&
            name.ends_with(".dat")) {
            segments.push_back(entry.path());
        }
    }
    std::sort(segments.begin(), segments.end());
    for (const auto &path : segments) {
        std::ifstream file(path, std::ios::binary);
        const Bytes bytes((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
        uint8_t hash[32];
        test::TestSha256(bytes, hash);
        const std::string name = path.filename().string();
        out << "v2_index:flat\t"
            << Hex(reinterpret_cast<const uint8_t *>(name.data()), name.size())
            << "\t" << bytes.size() << ":" << Hex(hash, 32) << "\n";
    }
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 2 || std::string(argv[1]) == "-h" ||
        std::string(argv[1]) == "--help") {
        std::cerr << "usage: chronik-native-lotus-v2-dump <indexes/chronik "
                     "dir>\n";
        return argc == 2 ? 0 : 2;
    }
    const std::filesystem::path dir = argv[1];
    if (!std::filesystem::is_directory(dir)) {
        std::cerr << "not a directory: " << dir << "\n";
        return 1;
    }
    try {
        schema::Schema schema;
        const lotus_v2::LegacyGroupsExtension ext;
        for (const GroupDef *group : ext.Groups()) {
            for (const TableSpec &spec : GroupTableSpecs(*group)) {
                schema.Add(spec);
            }
        }
        StoreOptions opts;
        opts.sha256 = test::TestSha256;
        auto store =
            OpenMdbxStore(dir, schema.Tables(), opts, ChronikIndexProfile());
        db::DumpStore(*store, schema.Tables(), std::cout);
        store.reset();
        DumpV2Index(dir / "v2_index", std::cout);
    } catch (const std::exception &e) {
        std::cerr << "chronik-native-lotus-v2-dump: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
