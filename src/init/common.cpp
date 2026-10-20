// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <clientversion.h>
#include <common/args.h>
#include <logging.h>
#include <node/miner.h>
#include <node/ui_interface.h>
#include <util/fs_helpers.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>

#include <functional>
#include <vector>

using node::DEFAULT_PRINTPRIORITY;

using util::SplitString;

namespace init {
void AddLoggingArgs(ArgsManager &argsman) {
    argsman.AddArg(
        "-debuglogfile=<file>",
        strprintf("Specify location of debug log file (default: %s). Relative "
                  "paths will be prefixed by a net-specific datadir location. "
                  "Pass -nodebuglogfile to disable writing the log to a file.)",
                  DEFAULT_DEBUGLOGFILE),
        ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg(
        "-debuglogjsonfile=<file>",
        "Also write the log as generic JSON lines (as -logformat=json, with "
        "source locations) to this file, whatever -logformat is. Relative "
        "paths are prefixed by the net-specific datadir. Meant for tests and "
        "tools that match structured fields.",
        ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY,
        OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-debug=<category>",
                   "Output debug and trace logging (default: -nodebug, "
                   "supplying <category> is optional). "
                   "If <category> is not supplied or if <category> = 1, output "
                   "all debug and trace logging. <category> can be: " +
                       LogInstance().LogCategoriesString() +
                       ". This option can be specified multiple times to "
                       "output multiple categories.",
                   ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-debugexclude=<category>",
        strprintf(
            "Exclude debug and trace logging for a category. Can be used in "
            "conjunction with -debug=1 to output debug and trace logging for "
            "all categories except the specified category. This option can be "
            "specified multiple times to exclude multiple categories."),
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-logips",
        strprintf("Include IP addresses in debug output (default: %u)",
                  DEFAULT_LOGIPS),
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-loglevel=<level>|<category>:<level>",
        strprintf(
            "Set the global or per-category severity level for logging "
            "categories enabled with the -debug configuration option or the "
            "logging RPC. Possible values are %s (default=%s); The following "
            "levels are always logged: error, warning, info. If "
            "<category>:<level> is supplied, the setting will override the "
            "global one and may be specified multiple times to set multiple "
            "category-specific levels. <category> can be: %s.",
            LogInstance().LogLevelsString(),
            LogInstance().LogLevelToStr(BCLog::DEFAULT_LOG_LEVEL),
            LogInstance().LogCategoriesString()),
        ArgsManager::DISALLOW_NEGATION | ArgsManager::DISALLOW_ELISION |
            ArgsManager::DEBUG_ONLY,
        OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-logtimestamps",
        strprintf("Prepend debug output with timestamp (default: %u)",
                  DEFAULT_LOGTIMESTAMPS),
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-logthreadnames",
        strprintf("Prepend debug output with name of the originating thread "
                  "(default: %u)",
                  DEFAULT_LOGTHREADNAMES),
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-logsourcelocations",
        strprintf(
            "Prepend debug output with name of the originating source location "
            "(source file, line number and function name) (default: %u)",
            DEFAULT_LOGSOURCELOCATIONS),
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-logtimemicros",
        strprintf("Add microsecond precision to debug timestamps (default: %u)",
                  DEFAULT_LOGTIMEMICROS),
        ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY,
        OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-loglevelalways",
        strprintf("Always prepend a category and level (default: %u)",
                  DEFAULT_LOGLEVELALWAYS),
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-logtextpriority",
        "Prefix each text output line with a systemd <N> severity (default: "
        "0). "
        "For journal capture of stdout; does not affect JSON, logfmt or syslog",
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-logformat=<format>",
        strprintf(
            "Format of log lines: %s (default: %s). journald sends native "
            "entries to "
            "/run/systemd/journal/socket (Linux only); stdout remains text. "
            "json writes one "
            "JSON object per line with the fields time (RFC 3339, "
            "microseconds; omitted with -logtimestamps=0), level, category, "
            "thread, message and, with -logsourcelocations, source (file, "
            "line, function); -logthreadnames, -logtimemicros and "
            "-loglevelalways do not apply to it",
            BCLog::SupportedLogFormats(), DEFAULT_LOGFORMAT),
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-logratelimit",
                   strprintf("Apply rate limiting to unconditional logging to "
                             "mitigate disk-filling attacks (default: %u)",
                             BCLog::DEFAULT_LOGRATELIMIT),
                   ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY,
                   OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-printtoconsole",
                   "Send trace/debug info to console (default: 1 when no "
                   "-daemon. To disable logging to file, set -nodebuglogfile)",
                   ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-printpriority",
                   strprintf("Log transaction priority and fee per kB when "
                             "mining blocks (default: %d)",
                             DEFAULT_PRINTPRIORITY),
                   ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY,
                   OptionsCategory::DEBUG_TEST);
    argsman.AddArg(
        "-shrinkdebugfile",
        "Shrink debug.log file on client startup (default: 1 when no -debug)",
        ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
}

void SetLoggingOptions(const ArgsManager &args) {
    LogInstance().m_print_to_file = !args.IsArgNegated("-debuglogfile");
    LogInstance().m_file_path = AbsPathForConfigVal(
        args, args.GetPathArg("-debuglogfile", DEFAULT_DEBUGLOGFILE));
    if (const fs::path json_path{args.GetPathArg("-debuglogjsonfile")};
        !json_path.empty()) {
        LogInstance().m_json_file_path = AbsPathForConfigVal(args, json_path);
    }

    LogInstance().m_print_to_console =
        args.GetBoolArg("-printtoconsole", !args.GetBoolArg("-daemon", false));
    LogInstance().m_log_timestamps =
        args.GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
    LogInstance().m_log_time_micros =
        args.GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);
    LogInstance().m_log_threadnames =
        args.GetBoolArg("-logthreadnames", DEFAULT_LOGTHREADNAMES);
    LogInstance().m_log_sourcelocations =
        args.GetBoolArg("-logsourcelocations", DEFAULT_LOGSOURCELOCATIONS);
    LogInstance().m_log_text_priority =
        args.GetBoolArg("-logtextpriority", false);
    LogInstance().m_always_print_category_level =
        args.GetBoolArg("-loglevelalways", DEFAULT_LOGLEVELALWAYS);

    // An invalid value is an init error (AppInitParameterInteraction).
    LogInstance().m_log_format =
        BCLog::ParseLogFormat(args.GetArg("-logformat", DEFAULT_LOGFORMAT))
            .value_or(BCLog::LogFormat::TEXT);

    fLogIPs = args.GetBoolArg("-logips", DEFAULT_LOGIPS);
}

void SetLoggingLevel(const ArgsManager &args) {
    if (!args.IsArgSet("-loglevel")) {
        return;
    }
    for (const std::string &level_str : args.GetArgs("-loglevel")) {
        if (level_str.find_first_of(':', 3) == std::string::npos) {
            // user passed a global log level, i.e. -loglevel=<level>
            if (!LogInstance().SetLogLevel(level_str)) {
                InitWarning(strprintf(_("Unsupported global logging level "
                                        "-loglevel=%s. Valid values: %s."),
                                      level_str,
                                      LogInstance().LogLevelsString()));
            }
        } else {
            // user passed a category-specific log level, i.e.
            // -loglevel=<category>:<level>
            const auto &toks = SplitString(level_str, ':');
            if (!(toks.size() == 2 &&
                  LogInstance().SetCategoryLogLevel(toks[0], toks[1]))) {
                InitWarning(strprintf(
                    _("Unsupported category-specific logging level "
                      "-loglevel=%s. Expected -loglevel=<category>:<loglevel>. "
                      "Valid categories: %s. Valid loglevels: %s."),
                    level_str, LogInstance().LogCategoriesString(),
                    LogInstance().LogLevelsString()));
            }
        }
    }
}

void SetLoggingCategories(const ArgsManager &args) {
    if (args.IsArgSet("-debug")) {
        // Special-case: if -debug=0/-nodebug is set, turn off debugging
        // messages
        const std::vector<std::string> categories = args.GetArgs("-debug");

        if (std::none_of(
                categories.begin(), categories.end(),
                [](std::string cat) { return cat == "0" || cat == "none"; })) {
            for (const auto &cat : categories) {
                if (!LogInstance().EnableCategory(cat)) {
                    InitWarning(
                        strprintf(_("Unsupported logging category %s=%s."),
                                  "-debug", cat));
                }
            }
        }
    }

    // Now remove the logging categories which were explicitly excluded
    for (const std::string &cat : args.GetArgs("-debugexclude")) {
        if (!LogInstance().DisableCategory(cat)) {
            InitWarning(strprintf(_("Unsupported logging category %s=%s."),
                                  "-debugexclude", cat));
        }
    }
}

bool StartLogging(const ArgsManager &args) {
    BCLog::Logger &logger = LogInstance();
    if (logger.m_print_to_file &&
        logger.m_log_format != BCLog::LogFormat::JOURNALD) {
        if (args.GetBoolArg("-shrinkdebugfile",
                            logger.DefaultShrinkDebugFile())) {
            // Do this first since it both loads a bunch of debug.log into
            // memory, and because this needs to happen before any other
            // debug.log printing.
            logger.ShrinkDebugFile();
        }
    }

    if (!logger.StartLogging()) {
        return InitError(Untranslated(logger.StartupError()));
    }

    if (!logger.m_log_timestamps) {
        LogInfoEvent(BCLog::ALL, "node_startup_time",
                     "Startup time: {startup_time}")
            .Field(BCLog::LogField::StartupTime,
                   FormatISO8601DateTime(GetTime()));
    }
    LogInfoEvent(BCLog::ALL, "node_default_data_directory",
                 "Default data directory {path}")
        .Field(BCLog::LogField::Path, fs::PathToString(GetDefaultDataDir()));
    LogInfoEvent(BCLog::ALL, "node_active_data_directory",
                 "Using data directory {path}")
        .Field(BCLog::LogField::Path, fs::PathToString(gArgs.GetDataDirNet()));

    // Only log conf file usage message if conf file actually exists.
    fs::path config_file_path = args.GetConfigFilePath();
    if (fs::exists(config_file_path)) {
        LogInfoEvent(BCLog::ALL, "node_config_file_loaded",
                     "Config file: {path}")
            .Field(BCLog::LogField::Path, fs::PathToString(config_file_path));
    } else if (args.IsArgSet("-conf")) {
        // Warn if no conf file exists at path provided by user
        InitWarning(
            strprintf(_("The specified config file %s does not exist\n"),
                      fs::PathToString(config_file_path)));
    } else {
        // Not categorizing as "Warning" because it's the default behavior
        LogInfoEvent(BCLog::ALL, "node_config_file_missing_skipped",
                     "Config file: {path} (not found, skipping)")
            .Field(BCLog::LogField::Path, fs::PathToString(config_file_path));
    }

    // Log the config arguments to debug.log
    args.LogArgs();

    return true;
}

void LogPackageVersion() {
    std::string version_string = FormatFullVersion();
#ifdef DEBUG
    version_string += " (debug build)";
#else
    version_string += " (release build)";
#endif
    LogInfoEvent(BCLog::ALL, "client_version_announced",
                 "{client_name} version {client_version} for the eCash network")
        .Field(BCLog::LogField::ClientName, CLIENT_NAME)
        .Field(BCLog::LogField::ClientVersion, version_string);
}
} // namespace init
