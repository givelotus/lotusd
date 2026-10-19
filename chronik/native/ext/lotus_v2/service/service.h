// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_SERVICE_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_SERVICE_H

#include <ext/lotus_v2/db/branch.h>
#include <ext/lotus_v2/query/branches.h>
#include <ext/lotus_v2/service/authority.h>
#include <ext/lotus_v2/service/ffi.h>

#include <array>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

/**
 * Bounded native V2 service sharing one serialized DB owner with readers
 * (port of chronik-lib/src/v2.rs V2Service).
 *
 * The typed response byte budget uses canonical field order: arrays are raw
 * bytes, integers fixed-width little-endian, booleans one byte, and vectors a
 * u32 count then elements. All optional slots are always present. A page has
 * a 307-byte envelope and each match has 265 fixed bytes, followed by its
 * output wire and matching-position bytes.
 *
 * Native callers authenticate consensus, canonical IDs and committed ordering.
 * This service checks bindings and model shape, and never advances node state.
 * Readiness is only the equality of separately supplied node/index anchors.
 *
 * Every failure throws V2ServiceError whose message is the Rust error string.
 */
namespace chronik::native::lotus_v2 {

class V2ServiceError : public ChronikError {
public:
    using ChronikError::ChronikError;
};

/** The DB owner: readers hold `mutex` for the whole snapshot use. */
struct SharedV2Db {
    SharedV2Db(const std::filesystem::path &path, const Binding &binding,
               const Bounds &bounds)
        : db(path, binding, bounds) {}
    std::mutex mutex;
    V2Db db;
};

/** Thread-safe confirmed index owner. Copies share storage and caps. */
class V2Service {
public:
    /**
     * Open a dedicated directory: fresh requires its absence, existing
     * requires mdbx.dat. Nothing is deleted. Reads stay unavailable until
     * explicit genesis commits. `sha256` is the host SHA-256 (filter digest).
     */
    static std::unique_ptr<V2Service>
    Open(const std::string &path, const ffi::Binding &binding, bool fresh,
         const ffi::ServiceLimits &limits, query_branches::Sha256Fn sha256);

    /** Invalidate before native chain changes or recovery. */
    uint64_t InvalidateAuthority();
    /** Publish only after the native chain is stable. */
    uint64_t PublishAuthority(const ffi::Anchor &anchor);
    /** Suspend reads for a native work turn. */
    uint64_t SuspendAuthority();
    /** Publish a fully reconciled native stamp. */
    uint64_t PublishAuthorityContext(const ffi::Anchor &anchor,
                                     uint64_t context_generation,
                                     uint64_t chain_revision);

    /** Another handle sharing this service (Rust clone_shared). */
    V2Service CloneShared() const { return *this; }
    /** The DB owner, for the HTTP layer. */
    std::shared_ptr<SharedV2Db> SharedDatabase() const { return m_db; }
    std::shared_ptr<Authority> GetAuthority() const { return m_authority; }
    const std::array<uint8_t, 16> &ServiceEpoch() const {
        return m_service_epoch;
    }
    /** Set when the last transition failed. */
    std::shared_ptr<std::atomic<bool>> IndexError() const {
        return m_index_error;
    }

    /** The current indexed checkpoint, if initialized. */
    std::optional<ffi::Anchor> Checkpoint() const;
    /** Initialize complete caller-authenticated genesis. */
    void InitializeGenesis(const ffi::NativeBlock &block);
    /** Index one authoritative committed block. */
    void ConnectBlock(const ffi::NativeBlock &block);
    /** Undo exactly the expected indexed anchor. */
    void DisconnectBlock(const ffi::Anchor &expected);
    /** Compare separate indexed and authoritative node checkpoints. */
    ffi::Status GetStatus(const ffi::Anchor &node) const;
    /** Confirmed branch records or UTXOs on one stable bounded snapshot. */
    ffi::BranchPage QueryBranches(const ffi::BranchRequest &request) const;

    const ffi::ServiceLimits &Limits() const { return m_limits; }

private:
    V2Service() = default;
    CommittedBlock Block(const ffi::NativeBlock &block) const;
    template <typename F> void Transition(F &&action);

    std::shared_ptr<SharedV2Db> m_db;
    ffi::ServiceLimits m_limits;
    Bounds m_bounds{1};
    Bytes32 m_genesis{};
    std::shared_ptr<Authority> m_authority;
    std::array<uint8_t, 16> m_service_epoch{};
    std::shared_ptr<std::atomic<bool>> m_index_error;
    query_branches::Sha256Fn m_sha256;
};

/** Canonical empty continuation (no cursor). */
ffi::Continuation EmptyContinuation();

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_SERVICE_H
