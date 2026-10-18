// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/fs.h>
#include <wallet/db.h>

#include <string>

void SplitWalletPath(const fs::path &wallet_path, fs::path &env_directory,
                     std::string &database_filename) {
    // Wallet paths are directories; individual legacy data files are
    // unsupported.
    env_directory = wallet_path;
    database_filename = WALLET_DATABASE_FILENAME;
}
