// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/sqlite.h>
#include <wallet/walletutil.h>

#include <common/args.h>
#include <logging.h>

#include <exception>
#include <fstream>

fs::path GetWalletDir() {
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetPathArg("-walletdir");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = gArgs.GetDataDirNet();
        // If a wallets directory exists, use that, otherwise default to
        // GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

std::vector<fs::path> ListWalletDir() {
    const fs::path wallet_dir = GetWalletDir();
    const size_t offset = fs::PathToString(wallet_dir).size() + 1;
    std::vector<fs::path> paths;
    std::error_code ec;

    for (auto it = fs::recursive_directory_iterator(wallet_dir, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            LogInfoEvent(BCLog::ALL, "wallet_directory_iteration_failed",
                         "{source_function}: {error} {path}")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Error, ec.message())
                .Field(BCLog::LogField::Path, fs::PathToString(it->path()));
            continue;
        }

        try {
            // Get wallet path relative to walletdir by removing walletdir from
            // the wallet path. This can be replaced by
            // boost::filesystem::lexically_relative once boost is bumped
            // to 1.60.
            const auto path_str = it->path().native().substr(offset);
            const fs::path path{path_str.begin(), path_str.end()};

            if (it->status().type() == fs::file_type::directory) {
                std::error_code dir_ec;
                fs::directory_iterator(it->path(), dir_ec);
                if (dir_ec) {
                    LogInfoEvent(
                        BCLog::ALL, "wallet_directory_scan_failed",
                        "{source_function}: Error scanning {path}: {error}")
                        .Field(BCLog::LogField::SourceFunction, __func__)
                        .Field(BCLog::LogField::Path,
                               fs::PathToString(it->path()))
                        .Field(BCLog::LogField::Error, dir_ec.message());
                    it.disable_recursion_pending();
                } else if (ExistsSQLiteDatabase(it->path())) {
                    paths.emplace_back(path);
                }
            } else if (it.depth() == 0 &&
                       it->path().filename() == WALLET_DATABASE_FILENAME &&
                       ExistsSQLiteDatabase(wallet_dir)) {
                paths.emplace_back();
            }
        } catch (const std::exception &e) {
            LogInfoEvent(BCLog::ALL, "wallet_directory_scan_exception",
                         "{source_function}: Error scanning {path}: {error}")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Path, it->path().string())
                .Field(BCLog::LogField::Error, e.what());
            it.disable_recursion_pending();
        }
    }

    return paths;
}
