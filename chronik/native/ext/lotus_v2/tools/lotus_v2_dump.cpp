// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// chronik-native-lotus-v2-dump: the V2-tier counterpart of
// chronik-native-dump for contrib/chronik-parity. Prints the legacy Chronik
// env of a Lotus V2 node (eCash tables plus the six V2 group tables) as
// sorted "table<TAB>key_hex<TAB>value_hex" lines. Run it on the index of a
// stopped node (<datadir>/<net>/indexes/chronik).

#include <chronik/native/mdbx_store.h>
#include <chronik/native/schema.h>
#include <core/db/dump.h>

#include <ext/lotus_v2/groups/groups.h>

// Portable SHA-256, only needed to open envs with hashed long keys.
#include <test/test_sha256.h>

#include <filesystem>
#include <iostream>
#include <string>

using namespace chronik::native;

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
    } catch (const std::exception &e) {
        std::cerr << "chronik-native-lotus-v2-dump: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
