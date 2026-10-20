// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <metrics/process.h>

#ifndef WIN32
#include <sys/resource.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <libproc.h>
#include <mach/mach.h>
#elif defined(__linux__)
#include <dirent.h>

#include <fstream>
#endif

#include <memory>

namespace metrics {

ProcessStats ReadProcessStats() {
    ProcessStats stats;
#ifndef WIN32
    struct rlimit limit{};
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 &&
        limit.rlim_cur != RLIM_INFINITY) {
        stats.max_fds = uint64_t(limit.rlim_cur);
    }
#endif
#if defined(__APPLE__)
    mach_task_basic_info_data_t info{};
    mach_msg_type_number_t count{MACH_TASK_BASIC_INFO_COUNT};
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info),
                  &count) == KERN_SUCCESS) {
        stats.resident_bytes = uint64_t(info.resident_size);
        stats.virtual_bytes = uint64_t(info.virtual_size);
    }
    const int bytes{proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, nullptr, 0)};
    if (bytes >= 0) {
        // The size of a buffer for all descriptors: an upper bound that the
        // kernel computes from the descriptor table; list them for the
        // exact count.
        std::unique_ptr<proc_fdinfo[]> fds{
            new proc_fdinfo[size_t(bytes) / PROC_PIDLISTFD_SIZE + 1]};
        const int used{
            proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds.get(), bytes)};
        if (used >= 0) {
            stats.open_fds = uint64_t(used) / PROC_PIDLISTFD_SIZE;
        }
    }
#elif defined(__linux__)
    {
        std::ifstream statm{"/proc/self/statm"};
        uint64_t size_pages{0}, resident_pages{0};
        if (statm >> size_pages >> resident_pages) {
            const long page{sysconf(_SC_PAGESIZE)};
            if (page > 0) {
                stats.virtual_bytes = size_pages * uint64_t(page);
                stats.resident_bytes = resident_pages * uint64_t(page);
            }
        }
    }
    if (DIR * dir{opendir("/proc/self/fd")}) {
        uint64_t n{0};
        while (const dirent *entry{readdir(dir)}) {
            if (entry->d_name[0] != '.') {
                ++n;
            }
        }
        closedir(dir);
        // Not counting the descriptor opendir used
        stats.open_fds = n > 0 ? n - 1 : 0;
    }
#endif
    return stats;
}

} // namespace metrics
