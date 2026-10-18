// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_DEVELOPMENT_COMMAND_H
#define LOTUS_V2_DEVELOPMENT_COMMAND_H
#include "development_chain.h"
namespace lotus::v2 {
struct DevelopmentManifest {
    HeaderChainProfile hp{}; OrdinaryCandidateProfile op{}; MonetaryProfile mp{};
    BlockCostProfile cp{}; MonetaryState initial{}; std::vector<uint8_t> genesis;
    uint64_t future_window{}, block_read_limit{};
};
// Strict, bounded configuration parsing only. Does not open/create a home or
// establish genesis/chain validity; OpenDevelopmentChain performs those checks.
// Runtime callers retain explicit profiles and storage creation options. Output
// changes only on success. No network parameters or defaults are supplied.
bool LoadDevelopmentManifest(const std::string &manifest_path,
    DevelopmentManifest &out, std::string &error);
// Prepare/check the isolated development home marker and return its chainstate
// subdirectory. Reject unrelated files, symlinks and mismatched identities using
// the same rules as the offline command. Does not open or migrate storage.
bool PrepareDevelopmentHomeDirectory(const DevelopmentManifest &manifest,
    const std::string &home, std::string &directory, std::string &error);
// Reuses the offline command's strict manifest and isolated namespace checks.
// Caller supplies the home explicitly and serializes its access. A fresh home
// is initialized; existing homes must match. Outputs change only on success.
bool OpenDevelopmentHome(const std::string &manifest_path, const std::string &directory,
    DevelopmentManifest &out, DiskStateStore &store, std::string &error);

int RunDevelopmentCommand(int argc, char *argv[]);
}
#endif
