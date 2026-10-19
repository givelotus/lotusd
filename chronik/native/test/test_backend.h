// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TEST_TEST_BACKEND_H
#define CHRONIK_NATIVE_TEST_TEST_BACKEND_H

#include <chronik/native/store.h>
#if CHRONIK_NATIVE_HAVE_LEVELDB
#include <chronik/native/leveldb_store.h>
#endif
#if CHRONIK_NATIVE_HAVE_MDBX
#include <chronik/native/mdbx_store.h>
#endif

#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>

/**
 * Storage backend used by the tests that are not per-backend (indexer,
 * queries, service, ...): MDBX when linked, else LevelDB. Setting
 * CHRONIK_NATIVE_TEST_BACKEND=mdbx|leveldb selects one explicitly, so a build
 * with both backends can run the whole suite against either. The KvStore
 * conformance suite (store_tests) always covers every linked backend.
 */
namespace chronik::native::test {

/** Registers every backend linked into the test binary. */
inline void RegisterTestStores() {
#if CHRONIK_NATIVE_HAVE_MDBX
    RegisterMdbxStore();
#endif
#if CHRONIK_NATIVE_HAVE_LEVELDB
    RegisterLevelDbStore();
#endif
}

inline StoreBackend TestBackend() {
    RegisterTestStores();
    if (const char *env = std::getenv("CHRONIK_NATIVE_TEST_BACKEND")) {
        const auto backend = ParseStoreBackend(env);
        if (!backend || !HasStoreBackend(*backend)) {
            throw std::runtime_error(
                std::string("CHRONIK_NATIVE_TEST_BACKEND=") + env +
                " is not a backend of this build");
        }
        return *backend;
    }
#if CHRONIK_NATIVE_HAVE_MDBX
    return StoreBackend::Mdbx;
#else
    return StoreBackend::LevelDb;
#endif
}

/** <datadir_net>/indexes/<dir of TestBackend()> */
inline std::filesystem::path TestIndexDir(const std::filesystem::path &net) {
    return net / "indexes" / std::string(StoreIndexDirName(TestBackend()));
}

} // namespace chronik::native::test

#endif // CHRONIK_NATIVE_TEST_TEST_BACKEND_H
