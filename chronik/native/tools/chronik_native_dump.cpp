// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// chronik-native-dump: print a Chronik index (Rust- or native-built, schema
// v13 MDBX env) as sorted "table<TAB>key_hex<TAB>value_hex" lines, dup values
// expanded (design §8.3). Used by contrib/chronik-parity. Run it on the index
// of a stopped node (<datadir>/<net>/indexes/chronik).

#include <chronik/native/mdbx_store.h>
#include <chronik/native/schema.h>
#include <core/db/dump.h>

// Portable SHA-256, only needed to open envs with hashed long keys.
#include <test/test_sha256.h>

#include <filesystem>
#include <iostream>
#include <string>

using namespace chronik::native;

int main(int argc, char **argv) {
    if (argc != 2 || std::string(argv[1]) == "-h" ||
        std::string(argv[1]) == "--help") {
        std::cerr << "usage: chronik-native-dump <indexes/chronik dir>\n";
        return argc == 2 ? 0 : 2;
    }
    const std::filesystem::path dir = argv[1];
    if (!std::filesystem::is_directory(dir)) {
        std::cerr << "not a directory: " << dir << "\n";
        return 1;
    }
    try {
        StoreOptions opts;
        opts.sha256 = test::TestSha256;
        auto store =
            OpenMdbxStore(dir, schema::EcashTables(), opts, ChronikIndexProfile());
        db::DumpStore(*store, schema::EcashTables(), std::cout);
    } catch (const std::exception &e) {
        std::cerr << "chronik-native-dump: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
