// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Entry points of the native Chronik for the ABC/eCash node, with the
// signatures of chronik/chronik-cpp/chronik.h so init.cpp is unchanged.
//
// Skeleton: the native indexer is not wired yet, so -chronik fails cleanly at
// startup instead of silently running without an index.

#include <common/args.h>
#include <config.h>
#include <node/context.h>
#include <node/ui_interface.h>
#include <util/translation.h>

#include <chronik-cpp/chronik.h>

namespace chronik {

bool Start(const ArgsManager &args, const Config &config,
           const node::NodeContext &node, bool fWipe) {
    return InitError(
        Untranslated("The native Chronik implementation is not available yet "
                     "in this build; rebuild with "
                     "-DCHRONIK_IMPLEMENTATION=rust"));
}

void Interrupt() {}

void Stop() {}

} // namespace chronik
