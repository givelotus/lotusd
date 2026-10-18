// Copyright (c) 2026 The Lotus developers
// Standalone V2 ordinary-transaction review model; not block consensus.
#ifndef LOTUS_V2_ORDINARY_VALIDATION_H
#define LOTUS_V2_ORDINARY_VALIDATION_H

#include "sparse_state.h"
#include "vm.h"

#include <map>
#include <functional>
#include <string>
#include <vector>

namespace lotus::v2 {

// This map makes the candidate independently testable. Production chainstate
// must replace it with an authenticated, persistent view and undo support.
using DevelopmentUtxoView = std::map<Outpoint, Coin, OutpointLess>;

struct OrdinaryCandidateProfile {
    TxProfile transaction;
    VmProfile vm;
    VmCostProfile vm_cost;
    uint64_t candidate_height;
    uint64_t parent_mtp;
    uint64_t coinbase_maturity;
    uint64_t dust_limit;
    VmCostUnits max_total_invocation_cost;
};

struct OrdinaryCandidateEffects {
    Hash txid{};
    Hash txhash{};
    __uint128_t native_fee{};
    __uint128_t token_output_burn_floor{};
    VmCostUnits invocation_cost{};
    uint64_t serialized_bytes{};
    std::vector<Outpoint> consumed;
    std::vector<Coin> created;
};

// Checks only this candidate's P01 framing, C04/C14 arithmetic and mint
// coverage, contextual locks/maturity, selected path execution and explicit
// byte/token fee floors. This is not a full V2 consensus validity result:
// transaction-wide P05 L(tx), parabolic block burn, block ordering and state
// commitments require separate checks. On failure both effects and view stay
// unchanged. Unknown or unsupported VM behavior rejects.
bool CheckOrdinaryCandidate(const Transaction &tx,
                            const OrdinaryCandidateProfile &profile,
                            const ChainId &chain_id,
                            const DevelopmentUtxoView &view,
                            OrdinaryCandidateEffects &effects,
                            std::string &error);

// Read-only backend boundary. Error is operational, never evidence of an
// invalid transaction. The callback must read one stable transaction view and
// return the complete authenticated coin on Found. No full-set scan is needed.
enum class CoinReadResult { Found, Missing, Error };
using CoinLookup = std::function<CoinReadResult(const Outpoint &, Coin &,
                                               std::string &)>;
enum class CandidateCheckResult {
    Accepted,
    Invalid,
    StorageError,
    Inconclusive
};
bool ValidateOrdinaryProfile(const OrdinaryCandidateProfile &, std::string &);

struct OrdinaryValidationCacheStats {
    uint64_t hits{};
    uint64_t misses{};
    size_t entries{};
};
OrdinaryValidationCacheStats GetOrdinaryValidationCacheStats();
void ClearOrdinaryValidationCache();

Hash OrdinaryValidationProfileDigest(const OrdinaryCandidateProfile &profile);
bool CheckOrdinaryLocks(const Transaction &tx, const std::vector<Coin> &spent,
                        const OrdinaryCandidateProfile &profile,
                        std::string &error);
bool TryGetCachedOrdinaryResolved(
    const OrdinaryCandidateProfile &profile, const ChainId &chain_id,
    uint64_t wire_size, const IdentityDigests &identities,
    const Hash &resolved_coins_digest, const Hash *precomputed_profile_digest,
    OrdinaryCandidateEffects &effects, CandidateCheckResult &result,
    std::string &error);
void PutCachedOrdinaryResolved(
    const OrdinaryCandidateProfile &profile, const ChainId &chain_id,
    uint64_t wire_size, const IdentityDigests &identities,
    const Hash &resolved_coins_digest, const Hash *precomputed_profile_digest,
    const OrdinaryCandidateEffects &effects);
CandidateCheckResult VerifyOrdinaryUncached(
    const Transaction &tx, const OrdinaryCandidateProfile &profile,
    const ChainId &chain_id, uint64_t wire_size,
    const IdentityDigests &identities, const std::vector<Coin> &spent,
    const ResolvedCoins &resolved, const Hash &resolved_coins_digest,
    const Hash *precomputed_profile_digest, OrdinaryCandidateEffects &effects,
    std::string &error, BatchSigCollector *batch_sigs = nullptr);

CandidateCheckResult CheckOrdinaryWithLookup(
    const Transaction &tx, const OrdinaryCandidateProfile &profile,
    const ChainId &chain_id, const CoinLookup &lookup,
    OrdinaryCandidateEffects &effects, std::string &error,
    const uint64_t *precomputed_wire_bytes = nullptr,
    const IdentityDigests *precomputed_identities = nullptr);

// Reference atomic application: validate against the original view, then
// stage changes in a copy and swap only after every operation succeeds.
bool ApplyOrdinaryCandidate(const Transaction &tx,
                            const OrdinaryCandidateProfile &profile,
                            const ChainId &chain_id,
                            DevelopmentUtxoView &view,
                            OrdinaryCandidateEffects &effects,
                            std::string &error);

} // namespace lotus::v2
#endif
