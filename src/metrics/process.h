// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_METRICS_PROCESS_H
#define BITCOIN_METRICS_PROCESS_H

#include <cstdint>
#include <optional>

namespace metrics {

/** Resource figures of this process, as Prometheus' process_* metrics */
struct ProcessStats {
    //! Resident set size
    std::optional<uint64_t> resident_bytes;
    //! Virtual memory size
    std::optional<uint64_t> virtual_bytes;
    //! Open file descriptors
    std::optional<uint64_t> open_fds;
    //! Soft limit on open file descriptors (RLIMIT_NOFILE)
    std::optional<uint64_t> max_fds;
};

/**
 * Read this process's figures from the OS (Linux: /proc/self; macOS:
 * task_info and proc_pidinfo). Figures the platform does not give are
 * absent.
 */
ProcessStats ReadProcessStats();

} // namespace metrics

#endif // BITCOIN_METRICS_PROCESS_H
