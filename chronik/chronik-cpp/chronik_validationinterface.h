// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rust/cxx.h>

#include <cstdint>

#ifndef BITCOIN_CHRONIK_CPP_CHRONIK_VALIDATIONINTERFACE_H
#define BITCOIN_CHRONIK_CPP_CHRONIK_VALIDATIONINTERFACE_H

namespace node {
struct NodeContext;
} // namespace node

namespace chronik_bridge {
class ChronikBridge;
struct Chronik;
} // namespace chronik_bridge

class CBlock;
class CBlockIndex;

namespace chronik_v2 {
struct Binding;
struct NativeBlock;

Binding get_v2_binding(const chronik_bridge::ChronikBridge &bridge);
/** Consensus block-size limit (largest valid block, in wire bytes). */
uint32_t get_v2_max_block_bytes(const chronik_bridge::ChronikBridge &bridge);
NativeBlock bridge_v2_native_block(const CBlock &block,
                                   const CBlockIndex &bindex);
} // namespace chronik_v2

namespace chronik {

void StartChronikValidationInterface(
    const node::NodeContext &node,
    rust::Box<chronik_bridge::Chronik> chronik_box);

/**
 * Stop serving Chronik requests, while keeping the indexer running. Must be
 * called before the node context Chronik's request handlers rely on is torn
 * down.
 */
void InterruptChronikRequestHandlers();

/**
 * Unregister the validation interface and release the Chronik instance. Must
 * only be called when no validation interface callback can be running.
 */
void StopChronikValidationInterface();
} // namespace chronik

#endif // BITCOIN_CHRONIK_CPP_CHRONIK_VALIDATIONINTERFACE_H
