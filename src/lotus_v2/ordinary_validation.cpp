#include "ordinary_validation.h"
#include "lock.h"
#include "vendor/blake3/blake3.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <list>
#include <map>
#include <mutex>
#include <set>
#include <unordered_map>

namespace lotus::v2 {
namespace {
using Wide = __uint128_t;
constexpr Wide MAX_WIDE = ~Wide{0};
constexpr size_t MAX_ORDINARY_VALIDATION_CACHE_ENTRIES = 8192;

struct Totals {
    Wide inputs{};
    Wide outputs{};
};

bool Add(Wide &sum, Wide value) {
    if (sum > MAX_WIDE - value) return false;
    sum += value;
    return true;
}

bool Multiply(Wide a, Wide b, Wide &product) {
    if (b && a > MAX_WIDE / b) return false;
    product = a * b;
    return true;
}

bool AtLeastAfter(uint64_t now, uint64_t start, uint64_t delay) {
    return start <= UINT64_MAX - delay && now >= start + delay;
}

bool AddAsset(std::map<Hash32, Totals> &tokens, Wide &native,
              const Output &output, std::string &error, bool input) {
    Wide &sum = output.HasToken()
                    ? (input ? tokens[output.token_id].inputs
                             : tokens[output.token_id].outputs)
                    : native;
    if (!Add(sum, output.value)) {
        error = "asset sum overflow";
        return false;
    }
    return true;
}

struct OrdinaryCacheKey {
    ChainId chain_id{};
    Hash profile_digest{};
    Hash txid{};
    Hash txhash{};
    Hash resolved_coins_digest{};
    uint64_t wire_size{};

    bool operator==(const OrdinaryCacheKey &other) const noexcept {
        return wire_size == other.wire_size && chain_id == other.chain_id &&
               profile_digest == other.profile_digest && txid == other.txid &&
               txhash == other.txhash &&
               resolved_coins_digest == other.resolved_coins_digest;
    }
};

struct OrdinaryCacheKeyHasher {
    size_t operator()(const OrdinaryCacheKey &key) const noexcept {
        size_t h1 = 0, h2 = 0, h3 = 0, h4 = 0;
        std::memcpy(&h1, key.txhash.data(), sizeof(size_t));
        std::memcpy(&h2, key.resolved_coins_digest.data(), sizeof(size_t));
        std::memcpy(&h3, key.profile_digest.data(), sizeof(size_t));
        std::memcpy(&h4, key.chain_id.data(), sizeof(size_t));
        return h1 ^ (h2 * 0x9e3779b97f4a7c15ULL) ^
               (h3 * 0xbf58476d1ce4e5b9ULL) ^ (h4 * 0x94d049bb133111ebULL) ^
               static_cast<size_t>(key.wire_size);
    }
};

struct CachedOrdinaryValidation {
    Wide native_fee{};
    Wide token_output_burn_floor{};
    VmCostUnits invocation_cost{};
};

class ValidatedOrdinaryCache {
public:
    static ValidatedOrdinaryCache &Instance() {
        static ValidatedOrdinaryCache cache;
        return cache;
    }

    bool TryGet(const OrdinaryCacheKey &key,
                CachedOrdinaryValidation &out) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = index_.find(key);
        if (it == index_.end()) return false;
        ++hits_;
        lru_.splice(lru_.begin(), lru_, it->second);
        out = it->second->second;
        return true;
    }

    void RecordMiss() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        ++misses_;
    }

    void Put(const OrdinaryCacheKey &key,
             const CachedOrdinaryValidation &value) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = index_.find(key);
        if (it != index_.end()) {
            it->second->second = value;
            lru_.splice(lru_.begin(), lru_, it->second);
            return;
        }
        if (lru_.size() >= MAX_ORDINARY_VALIDATION_CACHE_ENTRIES) {
            index_.erase(lru_.back().first);
            lru_.pop_back();
        }
        lru_.emplace_front(key, value);
        index_.emplace(lru_.front().first, lru_.begin());
    }

    OrdinaryValidationCacheStats Stats() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return {hits_, misses_, lru_.size()};
    }

    void Clear() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        index_.clear();
        lru_.clear();
        hits_ = 0;
        misses_ = 0;
    }

private:
    using ListType =
        std::list<std::pair<OrdinaryCacheKey, CachedOrdinaryValidation>>;
    mutable std::mutex mutex_;
    ListType lru_;
    std::unordered_map<OrdinaryCacheKey, ListType::iterator,
                       OrdinaryCacheKeyHasher>
        index_;
    uint64_t hits_{};
    uint64_t misses_{};
};

} // namespace

OrdinaryValidationCacheStats GetOrdinaryValidationCacheStats() {
    return ValidatedOrdinaryCache::Instance().Stats();
}

void ClearOrdinaryValidationCache() {
    ValidatedOrdinaryCache::Instance().Clear();
}

Hash OrdinaryValidationProfileDigest(const OrdinaryCandidateProfile &op) {
    std::vector<uint8_t> bytes;
    bytes.reserve(8192);
    auto put = [&](VmCostUnits value, unsigned width = 8) {
        for (unsigned i = 0; i < width; ++i)
            bytes.push_back(uint8_t(value >> (8 * i)));
    };
    const auto &t = op.transaction;
    for (auto value :
         {t.max_inputs, t.max_outputs, t.max_mints, t.max_script_bytes,
          t.max_arguments, t.max_argument_bytes, t.max_branch_proof_depth})
        put(value);
    const auto &v = op.vm;
    for (auto value : {v.max_script_bytes, v.max_arguments, v.max_element_bytes,
                       v.max_stack_items, v.max_altstack_items, v.max_vm_bytes,
                       v.max_ast_depth, v.max_steps})
        put(value);
    put(op.candidate_height);
    put(op.parent_mtp);
    put(op.coinbase_maturity);
    put(op.dust_limit);
    put(op.vm_cost.max_invocation_cost, 16);
    put(op.vm_cost.structural_byte_cost);
    for (const auto &cost : op.vm_cost.opcode) {
        put(cost.base);
        put(cost.per_operand_byte);
        put(cost.per_result_byte);
    }
    for (const auto &cost : op.vm_cost.ext_opcode) {
        put(cost.base);
        put(cost.per_operand_byte);
        put(cost.per_result_byte);
    }
    put(op.vm_cost.field_sizes.size());
    for (const auto &[opcode, sizes] : op.vm_cost.field_sizes) {
        put(opcode, 1);
        put(sizes.size());
        for (auto value : sizes)
            put(value);
    }
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    constexpr char domain[] = "Lotus/v2/ordinary-validation-profile";
    blake3_hasher_update(&hasher, domain, sizeof(domain));
    blake3_hasher_update(&hasher, bytes.data(), bytes.size());
    Hash digest{};
    blake3_hasher_finalize(&hasher, digest.data(), digest.size());
    return digest;
}

bool CheckOrdinaryLocks(const Transaction &tx, const std::vector<Coin> &spent,
                        const OrdinaryCandidateProfile &profile,
                        std::string &error) {
    if (!AbsoluteLockSatisfied(tx.lock, profile.candidate_height,
                               profile.parent_mtp)) {
        error = "absolute lock";
        return false;
    }
    size_t spent_index = 0;
    for (const Input &input : tx.inputs) {
        if (input.flags != 1) continue;
        const Coin &coin = spent[spent_index++];
        if (coin.creation_height > profile.candidate_height ||
            !AtLeastAfter(profile.candidate_height, coin.creation_height,
                          coin.coinbase ? profile.coinbase_maturity : 0)) {
            error = "coinbase maturity or future coin";
            return false;
        }
        if (IsUtxoExpired(coin, profile.candidate_height)) {
            error = "bad-txns-input-expired";
            return false;
        }
        if (input.sequence == UINT32_MAX) continue;
        const uint64_t delay = input.sequence & 0xffff;
        if (input.sequence & 0x400000) {
            if (!AtLeastAfter(profile.parent_mtp, coin.creation_parent_mtp,
                              delay * 512)) {
                error = "relative time lock";
                return false;
            }
        } else if (!AtLeastAfter(profile.candidate_height,
                                 coin.creation_height, delay)) {
            error = "relative height lock";
            return false;
        }
    }
    return true;
}

bool ValidateOrdinaryProfile(const OrdinaryCandidateProfile &profile,
                             std::string &error) {
    const auto &p = profile.transaction;
    if (!p.max_inputs || p.max_inputs > 65535 || p.max_outputs > 65535 ||
        p.max_mints > p.max_inputs || p.max_arguments > 65535 ||
        p.max_argument_bytes > VM_HARD_ELEMENT_BYTES ||
        p.max_branch_proof_depth > 64 || !profile.candidate_height ||
        !profile.coinbase_maturity || !profile.dust_limit ||
        !profile.max_total_invocation_cost) {
        error = "invalid ordinary profile or context";
        return false;
    }
    return ValidateVmCostProfile(profile.vm, profile.vm_cost, error);
}

bool TryGetCachedOrdinaryResolved(
    const OrdinaryCandidateProfile &profile, const ChainId &chain_id,
    uint64_t wire_size, const IdentityDigests &identities,
    const Hash &resolved_coins_digest, const Hash *precomputed_profile_digest,
    OrdinaryCandidateEffects &effects, CandidateCheckResult &result,
    std::string &error) {
    const Hash profile_digest = precomputed_profile_digest != nullptr
                                    ? *precomputed_profile_digest
                                    : OrdinaryValidationProfileDigest(profile);
    const OrdinaryCacheKey key{chain_id,          profile_digest,
                               identities.txid,   identities.txhash,
                               resolved_coins_digest, wire_size};
    CachedOrdinaryValidation cached;
    if (!ValidatedOrdinaryCache::Instance().TryGet(key, cached))
        return false;
    if (cached.invocation_cost > profile.max_total_invocation_cost) {
        error = "invocation cost unavailable or over budget";
        result = CandidateCheckResult::Invalid;
        return true;
    }
    effects.txid = identities.txid;
    effects.txhash = identities.txhash;
    effects.serialized_bytes = wire_size;
    effects.native_fee = cached.native_fee;
    effects.token_output_burn_floor = cached.token_output_burn_floor;
    effects.invocation_cost = cached.invocation_cost;
    result = CandidateCheckResult::Accepted;
    return true;
}

void PutCachedOrdinaryResolved(
    const OrdinaryCandidateProfile &profile, const ChainId &chain_id,
    uint64_t wire_size, const IdentityDigests &identities,
    const Hash &resolved_coins_digest, const Hash *precomputed_profile_digest,
    const OrdinaryCandidateEffects &effects) {
    const Hash profile_digest = precomputed_profile_digest != nullptr
                                    ? *precomputed_profile_digest
                                    : OrdinaryValidationProfileDigest(profile);
    const OrdinaryCacheKey key{chain_id,          profile_digest,
                               identities.txid,   identities.txhash,
                               resolved_coins_digest, wire_size};
    ValidatedOrdinaryCache::Instance().Put(
        key, CachedOrdinaryValidation{effects.native_fee,
                                      effects.token_output_burn_floor,
                                      effects.invocation_cost});
}

CandidateCheckResult VerifyOrdinaryUncached(
    const Transaction &tx, const OrdinaryCandidateProfile &profile,
    const ChainId &chain_id, uint64_t wire_size,
    const IdentityDigests &identities, const std::vector<Coin> &spent,
    const ResolvedCoins &resolved, const Hash &resolved_coins_digest,
    const Hash *precomputed_profile_digest, OrdinaryCandidateEffects &effects,
    std::string &error, BatchSigCollector *batch_sigs) {
    try {
        ValidatedOrdinaryCache::Instance().RecordMiss();
        Wide native_inputs = 0, native_outputs = 0;
        std::map<Hash32, Totals> tokens;
        for (const Coin &coin : spent) {
            if (!AddAsset(tokens, native_inputs, coin.output, error, true))
                return CandidateCheckResult::Invalid;
        }
        size_t token_output_count = 0;
        for (const Output &output : tx.outputs) {
            token_output_count += output.HasToken();
            if (!AddAsset(tokens, native_outputs, output, error, false))
                return CandidateCheckResult::Invalid;
        }
        if (native_inputs < native_outputs) {
            error = "native inflation";
            return CandidateCheckResult::Invalid;
        }
        const Wide native_fee = native_inputs - native_outputs;
        Wide token_floor;
        if (!Multiply(Wide{2} * profile.dust_limit, token_output_count,
                      token_floor)) {
            error = "token floor overflow";
            return CandidateCheckResult::Invalid;
        }
        Wide byte_numerator;
        if (!Multiply(Wide{1000}, wire_size, byte_numerator) ||
            !Add(byte_numerator, 999)) {
            error = "byte fee overflow";
            return CandidateCheckResult::Invalid;
        }
        const Wide byte_floor = byte_numerator / 1000;
        if (native_fee < byte_floor || native_fee < token_floor) {
            error = "native fee below byte or token-output floor";
            return CandidateCheckResult::Invalid;
        }

        std::map<Hash32, PositiveDelta> positive_deltas;
        for (const auto &[token_id, totals] : tokens) {
            if (totals.outputs <= totals.inputs) continue;
            const Wide delta = totals.outputs - totals.inputs;
            PositiveDelta encoded{};
            for (size_t b = 0; b < encoded.size(); ++b)
                encoded[b] = uint8_t(delta >> (8 * b));
            positive_deltas.emplace(token_id, encoded);
        }
        for (const Input &input : tx.inputs) {
            if (input.flags != 3) continue;
            if (positive_deltas.erase(input.prev_txid) != 1) {
                error = "mint without matching positive token delta";
                return CandidateCheckResult::Invalid;
            }
        }
        if (!positive_deltas.empty()) {
            error = "positive token delta lacks mint input";
            return CandidateCheckResult::Invalid;
        }

        PreparedVmTransaction prepared_vm;
        const auto preparation =
            prepared_vm.PrepareChecked(tx, profile.transaction, chain_id,
                                       resolved, profile.vm_cost, error,
                                       &identities);
        if (preparation != SigningPreparationStatus::Ready)
            return preparation == SigningPreparationStatus::InvalidWitness
                       ? CandidateCheckResult::Invalid
                       : CandidateCheckResult::Inconclusive;
        VmCostUnits invocation_cost = 0;
        BatchSigCollector tx_staged_sigs;
        BatchSigCollector *collector_ptr =
            batch_sigs != nullptr ? &tx_staged_sigs : nullptr;
        for (size_t i = 0; i < tx.inputs.size(); ++i) {
            const Input &input = tx.inputs[i];
            std::optional<PositiveDelta> delta;
            if (input.flags == 3) {
                const Totals &totals = tokens.at(input.prev_txid);
                const Wide amount = totals.outputs - totals.inputs;
                PositiveDelta encoded{};
                for (size_t b = 0; b < encoded.size(); ++b)
                    encoded[b] = uint8_t(amount >> (8 * b));
                delta = encoded;
            }
            for (size_t j = 0; j < input.witnesses.size(); ++j) {
                const BranchWitness &witness = input.witnesses[j];
                const auto context =
                    prepared_vm.Invocation(i, j, delta, collector_ptr);
                const VmChargedResult vm = EvaluateVmCharged(
                    witness.script, witness.arguments, profile.vm,
                    prepared_vm.Cost(), uint16_t(tx.inputs.size()),
                    uint16_t(tx.outputs.size()), &context, collector_ptr);
                if (vm.invocation.status != VmStatus::Success &&
                    vm.invocation.status != VmStatus::AutomaticSuccess) {
                    error = "witness VM invalid/unsupported: " +
                            vm.invocation.error;
                    return vm.invocation.status == VmStatus::Invalid
                               ? CandidateCheckResult::Invalid
                               : CandidateCheckResult::Inconclusive;
                }
                if (!vm.charged) {
                    error = "invocation cost unavailable";
                    return CandidateCheckResult::Inconclusive;
                }
                if (!Add(invocation_cost, vm.accounting_cost) ||
                    invocation_cost > profile.max_total_invocation_cost) {
                    error = "invocation cost unavailable or over budget";
                    return CandidateCheckResult::Invalid;
                }
            }
        }
        effects.txid = identities.txid;
        effects.txhash = identities.txhash;
        effects.serialized_bytes = wire_size;
        effects.native_fee = native_fee;
        effects.token_output_burn_floor = token_floor;
        effects.invocation_cost = invocation_cost;
        if (batch_sigs != nullptr) {
            batch_sigs->Merge(std::move(tx_staged_sigs));
        } else {
            PutCachedOrdinaryResolved(profile, chain_id, wire_size, identities,
                                      resolved_coins_digest,
                                      precomputed_profile_digest, effects);
        }
        return CandidateCheckResult::Accepted;
    } catch (const std::exception &exception) {
        error = exception.what();
        return CandidateCheckResult::Inconclusive;
    }
}

CandidateCheckResult CheckOrdinaryWithLookup(const Transaction &tx,
                            const OrdinaryCandidateProfile &profile,
                            const ChainId &chain_id,
                            const CoinLookup &lookup,
                            OrdinaryCandidateEffects &effects,
                            std::string &error,
                            const uint64_t *precomputed_wire_bytes,
                            const IdentityDigests *precomputed_identities) {
    try {
        if (!ValidateOrdinaryProfile(profile, error))
            return CandidateCheckResult::Inconclusive;
        uint64_t wire_size = 0;
        if (precomputed_wire_bytes != nullptr) {
            wire_size = *precomputed_wire_bytes;
        } else {
            std::vector<uint8_t> wire;
            if (!EncodeTransaction(tx, profile.transaction, wire, error))
                return CandidateCheckResult::Invalid;
            wire_size = static_cast<uint64_t>(wire.size());
        }
        std::vector<Coin> spent;
        ResolvedCoins resolved(tx.inputs.size());
        std::set<Outpoint, OutpointLess> seen;
        spent.reserve(tx.inputs.size());
        OrdinaryCandidateEffects staged;
        staged.serialized_bytes = wire_size;
        blake3_hasher coins_hasher;
        blake3_hasher_init(&coins_hasher);
        constexpr char coins_domain[] = "Lotus/v2/ordinary-resolved-coins";
        blake3_hasher_update(&coins_hasher, coins_domain, sizeof(coins_domain));
        for (size_t i = 0; i < tx.inputs.size(); ++i) {
            const Input &input = tx.inputs[i];
            if (input.flags == 2) {
                error = "coinbase is not an ordinary transaction";
                return CandidateCheckResult::Invalid;
            }
            if (input.flags != 1) continue;
            const Outpoint outpoint{input.prev_txid, input.prev_index};
            if (!seen.insert(outpoint).second) {
                error = "repeated spend";
                return CandidateCheckResult::Invalid;
            }
            Coin coin;
            const auto read = lookup(outpoint, coin, error);
            if (read == CoinReadResult::Error)
                return CandidateCheckResult::StorageError;
            if (read == CoinReadResult::Missing) {
                error = "unresolved spend";
                return CandidateCheckResult::Invalid;
            }
            if (coin.outpoint != outpoint) {
                error = "coin lookup returned a different outpoint";
                return CandidateCheckResult::StorageError;
            }
            std::vector<uint8_t> encoded_coin;
            if (!EncodeCoin(coin, encoded_coin)) {
                error = "invalid resolved coin";
                return CandidateCheckResult::StorageError;
            }
            uint8_t len_le[8];
            const uint64_t coin_len = encoded_coin.size();
            for (unsigned b = 0; b < 8; ++b)
                len_le[b] = uint8_t(coin_len >> (8 * b));
            blake3_hasher_update(&coins_hasher, len_le, sizeof(len_le));
            blake3_hasher_update(&coins_hasher, encoded_coin.data(),
                                 encoded_coin.size());
            spent.push_back(coin);
            resolved[i] = coin.output;
            staged.consumed.push_back(outpoint);
        }
        Hash resolved_coins_digest{};
        blake3_hasher_finalize(&coins_hasher, resolved_coins_digest.data(),
                               resolved_coins_digest.size());
        if (!CheckOrdinaryLocks(tx, spent, profile, error))
            return CandidateCheckResult::Invalid;

        IdentityDigests computed_identities;
        const IdentityDigests *identities_ptr = precomputed_identities;
        if (identities_ptr == nullptr) {
            if (!ComputeIdentities(tx, profile.transaction, chain_id,
                                   computed_identities, error))
                return CandidateCheckResult::Invalid;
            identities_ptr = &computed_identities;
        }
        const IdentityDigests &identities = *identities_ptr;

        const Hash profile_digest = OrdinaryValidationProfileDigest(profile);
        CandidateCheckResult cpu_result = CandidateCheckResult::Inconclusive;
        if (!TryGetCachedOrdinaryResolved(
                profile, chain_id, wire_size, identities, resolved_coins_digest,
                &profile_digest, staged, cpu_result, error)) {
            cpu_result = VerifyOrdinaryUncached(
                tx, profile, chain_id, wire_size, identities, spent, resolved,
                resolved_coins_digest, &profile_digest, staged, error);
        }
        if (cpu_result != CandidateCheckResult::Accepted)
            return cpu_result;

        size_t spendable_outputs = 0;
        for (const Output &out : tx.outputs) {
            if (!out.IsBurn()) ++spendable_outputs;
        }
        const uint64_t fee_u64 =
            staged.native_fee > Wide(UINT64_MAX)
                ? UINT64_MAX
                : static_cast<uint64_t>(staged.native_fee);
        const uint64_t fee_per_output =
            ComputeTxFeePerSpendableOutput(fee_u64, spendable_outputs);
        const uint64_t exp_height = ComputeUtxoExpirationHeight(
            profile.candidate_height, false, fee_per_output);

        for (size_t j = 0; j < tx.outputs.size(); ++j) {
            if (tx.outputs[j].IsBurn()) continue;
            const Outpoint outpoint{identities.txid, uint32_t(j)};
            Coin occupied;
            const auto read = lookup(outpoint, occupied, error);
            if (read == CoinReadResult::Error)
                return CandidateCheckResult::StorageError;
            if (read == CoinReadResult::Found) {
                if (occupied.outpoint != outpoint) {
                    error = "coin lookup returned a different outpoint";
                    return CandidateCheckResult::StorageError;
                }
                error = "created outpoint already occupied";
                return CandidateCheckResult::Invalid;
            }
            staged.created.push_back(
                Coin{outpoint, tx.outputs[j], profile.candidate_height,
                     profile.parent_mtp, false, fee_per_output, exp_height});
        }
        effects = std::move(staged);
        error.clear();
        return CandidateCheckResult::Accepted;
    } catch (const std::exception &exception) {
        error = exception.what();
        return CandidateCheckResult::Inconclusive;
    }
}

bool CheckOrdinaryCandidate(const Transaction &tx,
                            const OrdinaryCandidateProfile &profile,
                            const ChainId &chain_id,
                            const DevelopmentUtxoView &view,
                            OrdinaryCandidateEffects &effects,
                            std::string &error) {
    const CoinLookup lookup = [&view](const Outpoint &outpoint, Coin &coin,
                                     std::string &) {
        const auto found = view.find(outpoint);
        if (found == view.end()) return CoinReadResult::Missing;
        coin = found->second;
        return CoinReadResult::Found;
    };
    return CheckOrdinaryWithLookup(tx, profile, chain_id, lookup, effects,
                                   error) == CandidateCheckResult::Accepted;
}

bool ApplyOrdinaryCandidate(const Transaction &tx,
                            const OrdinaryCandidateProfile &profile,
                            const ChainId &chain_id,
                            DevelopmentUtxoView &view,
                            OrdinaryCandidateEffects &effects,
                            std::string &error) {
    OrdinaryCandidateEffects staged;
    if (!CheckOrdinaryCandidate(tx, profile, chain_id, view, staged, error))
        return false;
    DevelopmentUtxoView next = view;
    for (const Outpoint &outpoint : staged.consumed) {
        if (next.erase(outpoint) != 1) {
            error = "staged spend disappeared";
            return false;
        }
    }
    for (const Coin &coin : staged.created) {
        if (!next.emplace(coin.outpoint, coin).second) {
            error = "staged output collision";
            return false;
        }
    }
    view.swap(next);
    effects = std::move(staged);
    error.clear();
    return true;
}

} // namespace lotus::v2
