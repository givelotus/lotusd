// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/error.h>
#include <chronik/native/index/merge.h>

#include <mutex>

namespace chronik::native::index::merge {

namespace {
std::mutex g_mutex;
std::optional<std::string> g_merge_error;
std::function<void(const std::string &)> g_logger;
} // namespace

void CheckForErrors() {
    std::optional<std::string> err;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        err.swap(g_merge_error);
    }
    if (err) {
        throw ChronikError(*err);
    }
}

void HandleErr(const std::string &msg) {
    std::function<void(const std::string &)> logger;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_merge_error = msg;
        logger = g_logger;
    }
    if (logger) {
        logger("MERGE ERROR: " + msg + "\n");
    }
}

void SetErrorLogger(std::function<void(const std::string &)> logger) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_logger = std::move(logger);
}

} // namespace chronik::native::index::merge
