// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_HOSTS_ABC_ABC_V2_H
#define CHRONIK_NATIVE_HOSTS_ABC_ABC_V2_H

#include <chronik/native/extension.h>
#include <chronik/native/host.h>

#include <ext/lotus_v2/service/ffi.h>

#include <filesystem>
#include <memory>
#include <mutex>

class CBlock;
class CBlockIndex;
class CTransaction;
namespace node {
struct NodeContext;
} // namespace node
namespace chronik::native::lotus_v2 {
class V2Service;
} // namespace chronik::native::lotus_v2

/**
 * Lotus V2 node input of the native V2 service (V2 tier only): ports of
 * chronik-cpp/chronik.cpp get_v2_binding and bridge_v2_native_block.
 */
namespace chronik::native::abc {

/** Chain binding of the active chain (chain ID, genesis, header profile). */
lotus_v2::ffi::Binding GetV2Binding();

/**
 * The native block of a connected node block: 134-byte header (parent ID
 * and height patched in), V2 transactions re-encoded with the default
 * profile (coinbase normalized), their explorer facts and native outputs.
 * Throws std::runtime_error like the Rust bridge.
 */
lotus_v2::ffi::NativeBlock ConvertV2NativeBlock(const CBlock &block,
                                                const CBlockIndex &bindex);
/**
 * The native form of one transaction (`coinbase` for a block's first) at
 * block-file position (file_num, data_pos); used at connect and to read an
 * indexed transaction back from the block files.
 */
lotus_v2::ffi::NativeTx ConvertV2NativeTx(const CTransaction &ctx,
                                          bool coinbase, uint32_t n,
                                          uint32_t file_num,
                                          uint32_t data_pos);

/**
 * The native V2 service of a Lotus V2 node (port of the V2 parts of
 * chronik-lib bridge.rs), as an OwnEnv extension driven after the core:
 *  - Open: the v2_index env at <indexes>/chronik/v2_index, fresh when wiped
 *    or without mdbx.dat, reopened fresh if opening fails (an index of
 *    another schema version fails instead, asking for -chronikreindex).
 *    Indexed transactions are read back from the node's block files;
 *  - Resync (after the core's resync): pop checkpoints until one is on the
 *    active chain, replay the active chain from there, stop silently at the
 *    first error, then publish the authority;
 *  - Connect/Disconnect: the block's native form (read from disk, since the
 *    core's Block does not carry the node block), publishing the authority
 *    after each success. Failures are logged and never fail the indexer;
 *  - RegisterRoutes: /v2 and /v2/explorer/v1 (chronik-http v2.rs and
 *    v2_explorer.rs), each request on the then-current service.
 */
class AbcV2ServiceExtension final : public Extension {
public:
    AbcV2ServiceExtension(const node::NodeContext &node, const Host &host);
    ~AbcV2ServiceExtension() override;

    Txn TxnMode() const override { return Txn::OwnEnv; }
    void Open(const std::filesystem::path &indexes_dir, bool wipe) override;
    void Resync() override;
    void Connect(const Block &block, WriteTxn *) override;
    void Disconnect(const Block &block, WriteTxn *) override;
    void Close() override;
    /** /v2 and /v2/explorer/v1 over the current service. */
    void RegisterRoutes(Router &router) override;

    /** The service, once opened (shared with the HTTP layer). */
    std::shared_ptr<lotus_v2::V2Service> Service() const;

private:
    void Log(const std::string &msg) const;
    void SetService(std::shared_ptr<lotus_v2::V2Service> service);

    const node::NodeContext &m_node;
    const Host &m_host;
    /** Written on the indexer thread; read by HTTP handlers. */
    mutable std::mutex m_service_mutex;
    std::shared_ptr<lotus_v2::V2Service> m_service;
};

} // namespace chronik::native::abc

#endif // CHRONIK_NATIVE_HOSTS_ABC_ABC_V2_H
