// Copyright (c) 2026 The Lotus developers
// Candidate P01 identity/signing bytes; no VM or full transaction validity.
#ifndef LOTUS_V2_SIGNING_H
#define LOTUS_V2_SIGNING_H

#include "commitment.h"
#include "transaction.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace lotus::v2 {

struct IdentityDigests {
    Hash txid;
    Hash txhash;
    Hash inputs_root;
    Hash full_inputs_root;
    Hash outputs_root;
    std::vector<Hash> output_leaves;
};

using ResolvedCoins = std::vector<std::optional<Output>>;
using PositiveDelta = std::array<uint8_t, 16>; // u128 little-endian, nonzero

// Immutable snapshot for repeated CHECKSIG/SIGHASH calls on one validated
// transaction. Rebuild it if the transaction or resolved coins change.
enum class SigningPreparationStatus {
    Ready,
    InvalidWitness,
    Unsupported,
    OperationalError
};

class PreparedSigningContext {
public:
    PreparedSigningContext() = default;
    const IdentityDigests &Identities() const { return identities_; }

private:
    struct Invocation {
        uint8_t kind{};
        std::vector<uint8_t> selector; // 41-byte spend or 81-byte mint form.
    };
    IdentityDigests identities_;
    ChainId chain_id_{};
    uint64_t lock_{};
    Hash txid_{};
    Hash coins_root_{};
    Hash outputs_root_{};
    std::vector<Hash> output_leaves_;
    std::vector<std::optional<Hash>> own_input_hashes_;
    std::vector<std::vector<Invocation>> invocations_;
    bool ready_ = false;

    friend SigningPreparationStatus
    PrepareSigningContextChecked(const Transaction &, const TxProfile &,
                                 const ChainId &, const ResolvedCoins &,
                                 PreparedSigningContext &, std::string &,
                                 const IdentityDigests *);
    friend bool PrepareSigningContext(
        const Transaction &, const TxProfile &, const ChainId &,
        const ResolvedCoins &, PreparedSigningContext &, std::string &);
    friend bool SigningMessage(const PreparedSigningContext &, size_t, size_t,
                               uint8_t, const std::optional<PositiveDelta> &,
                               Hash &, std::string &);
    friend bool ValidateSigningInvocation(const PreparedSigningContext &,
                                          size_t, size_t,
                                          const std::optional<PositiveDelta> &,
                                          std::string &);
};

SigningPreparationStatus PrepareSigningContextChecked(
    const Transaction &tx, const TxProfile &profile, const ChainId &chain_id,
    const ResolvedCoins &resolved, PreparedSigningContext &result,
    std::string &error,
    const IdentityDigests *precomputed_identities = nullptr);

bool PrepareSigningContext(const Transaction &tx, const TxProfile &profile,
                           const ChainId &chain_id,
                           const ResolvedCoins &resolved,
                           PreparedSigningContext &result,
                           std::string &error);
// Validates invocation indices and spend/mint delta rules without hashing the
// signing message preimage (used at VM invocation entry before CHECKSIG).
bool ValidateSigningInvocation(const PreparedSigningContext &prepared,
                               size_t input_index, size_t witness_index,
                               const std::optional<PositiveDelta> &positive_delta,
                               std::string &error);
// After preparation this hashes one fixed-width signing preimage. No input,
// output, witness, or coin collection is traversed per invocation.
bool SigningMessage(const PreparedSigningContext &prepared, size_t input_index,
                    size_t witness_index, uint8_t mode,
                    const std::optional<PositiveDelta> &positive_delta,
                    Hash &result, std::string &error);

bool ComputeIdentities(const Transaction &tx, const TxProfile &profile,
                       const ChainId &chain_id, IdentityDigests &result,
                       std::string &error);
// Computes identities for a transaction whose canonical wire framing has
// already been validated against `profile`.
bool ComputeIdentitiesValidated(const Transaction &tx,
                                const TxProfile &profile,
                                const ChainId &chain_id,
                                IdentityDigests &result, std::string &error);
// Fast path when canonical wire framing has been validated and txid/txhash are
// already known: populates txid/txhash and computes output commitments only
// when non-mode-0 sighashes may be requested.
bool ComputeOutputIdentitiesOnly(const Transaction &tx, const Hash &known_txid,
                                 const Hash &known_txhash,
                                 IdentityDigests &result, std::string &error);
bool ComputeCoinsRoot(const Transaction &tx, const ResolvedCoins &resolved,
                      Hash &result, std::string &error);
bool ComputeOwnInputHash(const Transaction &tx, const TxProfile &profile,
                         const ResolvedCoins &resolved, size_t input_index,
                         Hash &result, std::string &error);

// One-off convenience wrapper. Repeated invocations must use the prepared
// overload to avoid rebuilding roots on every signature. Resolved coins and
// positive mint delta come from a separate validated accounting/state layer.
bool SigningMessage(const Transaction &tx, const TxProfile &profile,
                    const ChainId &chain_id, const ResolvedCoins &resolved,
                    size_t input_index, size_t witness_index, uint8_t mode,
                    const std::optional<PositiveDelta> &positive_delta,
                    Hash &result, std::string &error);

enum class SignatureStatus {
    Valid,
    InvalidSignature, // correct wire form and key, BIP340 check failed
    InvalidEncoding,  // wrong 64/65-byte mode form
    InvalidPublicKey, // wrong length or invalid x-only point
};

SignatureStatus VerifyBip340Signature(std::span<const uint8_t> public_key,
                                      std::span<const uint8_t> signature,
                                      const Hash &message, bool mint);

struct BatchSigItem {
    std::array<uint8_t, 32> pubkey{};
    std::array<uint8_t, 64> parsed_pubkey{};
    std::array<uint8_t, 64> sig{};
    Hash msg{};
};

struct LegacyBatchSigItem {
    std::array<uint8_t, 64> parsed_pubkey{};
    std::array<uint8_t, 64> sig{};
    Hash msg{};
    std::array<uint8_t, 32> cache_entry{};
    bool store_in_cache{false};
};

// Collects BIP340 Schnorr and legacy 64-byte Schnorr (pubkey, sig64, msg32)
// tuples during NULLFAIL script execution for deferred multi-scalar
// multiplication batch verification (Strauss / Pippenger via
// secp256k1_schnorrsig_verify_batch and secp256k1_schnorr_verify_batch) and
// bisection fallback to pinpoint the exact failing signature index.
class BatchSigCollector {
public:
    BatchSigCollector() = default;

    // Validates that `pubkey` is a canonical 32-byte x-only secp256k1 key and
    // `sig` has at least 64 bytes (using the 64-byte R||s prefix), then records
    // the tuple for deferred batch verification. Returns false if `pubkey` or
    // `sig` encoding is invalid.
    bool Add(std::span<const uint8_t> pubkey, std::span<const uint8_t> sig,
             const Hash &msg);

    // Validates that `pubkey` is a valid 33/65-byte secp256k1 public key and
    // `sig64` is 64 bytes, then records the tuple for deferred legacy Schnorr
    // batch verification.
    bool AddLegacySchnorr(std::span<const uint8_t> pubkey,
                          std::span<const uint8_t> sig64,
                          const uint8_t *msg32,
                          const uint8_t *cache_entry32 = nullptr,
                          bool store_in_cache = false);

    void Reserve(size_t n) {
        items_.reserve(n);
        legacy_items_.reserve(n);
    }
    void Clear() noexcept {
        items_.clear();
        legacy_items_.clear();
    }
    bool Empty() const noexcept {
        return items_.empty() && legacy_items_.empty();
    }
    size_t Size() const noexcept {
        return items_.size() + legacy_items_.size();
    }
    const std::vector<BatchSigItem> &Items() const noexcept { return items_; }
    const std::vector<LegacyBatchSigItem> &LegacyItems() const noexcept {
        return legacy_items_;
    }

    void Merge(const BatchSigCollector &other);
    void Merge(BatchSigCollector &&other);

    // Verifies all collected signatures in batch using multi-scalar
    // multiplication. When `num_threads == 0`, automatically partitions large
    // batches across hardware worker threads.
    bool VerifyAll(size_t num_threads = 0) const;

    // Returns std::nullopt if all collected signatures are valid, or the
    // 0-based index of the first invalid signature via batch bisection.
    std::optional<size_t> FirstFailingIndex(size_t num_threads = 0) const;

private:
    std::vector<BatchSigItem> items_;
    std::vector<LegacyBatchSigItem> legacy_items_;
};

// Test/wallet helper. Caller supplies fresh nonce auxiliary entropy for real
// signing; deterministic zero auxiliary bytes are used only in fixed vectors.
// Local keypair storage is cleansed on every exit. Caller-owned secret_key and
// aux_randomness remain the caller's responsibility; this API retains no copy.
bool SignBip340Message(const std::array<uint8_t, 32> &secret_key,
                       const Hash &message, uint8_t mode,
                       const std::array<uint8_t, 32> &aux_randomness,
                       std::vector<uint8_t> &result, std::string &error);

void RunParallelSigningWork(
    size_t total_items, size_t min_grain,
    const std::function<void(size_t, size_t)> &fn);

} // namespace lotus::v2
#endif

