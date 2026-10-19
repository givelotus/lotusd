// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/thread.h>

#include <logging.h>
#include <util/exception.h>
#include <util/threadnames.h>

#include <exception>
#include <string>

void util::TraceThread(std::string_view thread_name,
                       std::function<void()> thread_func) {
    util::ThreadRename(std::string{thread_name});
    try {
        LogInfoEvent(BCLog::ALL, "thread_started", "{name} thread start")
            .Field(BCLog::LogField::Name, thread_name);
        thread_func();
        LogInfoEvent(BCLog::ALL, "thread_exited", "{name} thread exit")
            .Field(BCLog::LogField::Name, thread_name);
    } catch (const std::exception &e) {
        PrintExceptionContinue(&e, thread_name);
        throw;
    } catch (...) {
        PrintExceptionContinue(nullptr, thread_name);
        throw;
    }
}
