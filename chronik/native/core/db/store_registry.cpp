// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/error.h>
#include <chronik/native/store.h>

#include <map>
#include <mutex>

namespace chronik::native {

namespace {
struct Backend {
    StoreOpenFn open;
    StoreDestroyFn destroy;
};

std::mutex &RegistryMutex() {
    static std::mutex mutex;
    return mutex;
}

std::map<StoreBackend, Backend> &Registry() {
    static std::map<StoreBackend, Backend> registry;
    return registry;
}

Backend GetBackend(StoreBackend backend) {
    std::lock_guard<std::mutex> lock(RegistryMutex());
    auto it = Registry().find(backend);
    if (it == Registry().end()) {
        throw ChronikError("Chronik storage backend " +
                           std::string(StoreBackendName(backend)) +
                           " is not available in this build");
    }
    return it->second;
}
} // namespace

std::string_view StoreBackendName(StoreBackend backend) {
    switch (backend) {
        case StoreBackend::Mdbx:
            return "mdbx";
        case StoreBackend::LevelDb:
            return "leveldb";
    }
    return "unknown";
}

std::optional<StoreBackend> ParseStoreBackend(std::string_view name) {
    for (StoreBackend b : {StoreBackend::Mdbx, StoreBackend::LevelDb}) {
        if (StoreBackendName(b) == name) {
            return b;
        }
    }
    return std::nullopt;
}

std::string_view StoreIndexDirName(StoreBackend backend) {
    switch (backend) {
        case StoreBackend::Mdbx:
            return "chronik";
        case StoreBackend::LevelDb:
            return "chronik-leveldb";
    }
    return "chronik";
}

void RegisterStoreBackend(StoreBackend backend, StoreOpenFn open,
                          StoreDestroyFn destroy) {
    std::lock_guard<std::mutex> lock(RegistryMutex());
    Registry()[backend] = Backend{std::move(open), std::move(destroy)};
}

bool HasStoreBackend(StoreBackend backend) {
    std::lock_guard<std::mutex> lock(RegistryMutex());
    return Registry().count(backend) > 0;
}

std::unique_ptr<KvStore> OpenStore(StoreBackend backend,
                                   const std::filesystem::path &dir,
                                   std::span<const TableSpec> tables,
                                   const StoreOptions &opts) {
    return GetBackend(backend).open(dir, tables, opts);
}

void DestroyStore(StoreBackend backend, const std::filesystem::path &dir) {
    GetBackend(backend).destroy(dir);
}

} // namespace chronik::native
