// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/context.h>
#include <lotus_v2/fee_hysteresis.h>

#include <addrman.h>
#include <avalanche/processor.h>
#include <banman.h>
#include <interfaces/chain.h>
#include <kernel/context.h>
#include <net.h>
#include <net_processing.h>
#include <node/kernel_notifications.h>
#include <node/snapshot.h>
#include <node/transaction.h>
#include <scheduler.h>
#include <txmempool.h>
#include <validation.h>

namespace node {
NodeContext::NodeContext() : snapshot_publisher(GetGlobalSnapshotPublisherPtr()) {}
NodeContext::~NodeContext() {
    rpc_admission.reset();
}
} // namespace node
