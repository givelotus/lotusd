#include "signing.h"
#include "batch_randomizers.h"

#include "tagged_hash.h"
#include "vendor/blake3/blake3.h"

#include "../support/cleanse.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorr.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace lotus::v2 {
namespace {

    void Integer(uint64_t value, size_t width, std::vector<uint8_t> &out) {
        for (size_t i = 0; i < width; ++i)
            out.push_back(uint8_t(value >> (8 * i)));
    }

    void CompactSize(uint64_t value, std::vector<uint8_t> &out) {
        if (value < 253)
            Integer(value, 1, out);
        else if (value <= 65535) {
            out.push_back(253);
            Integer(value, 2, out);
        } else if (value <= 4294967295ULL) {
            out.push_back(254);
            Integer(value, 4, out);
        } else {
            out.push_back(255);
            Integer(value, 8, out);
        }
    }

    bool OutputBytes(const Output &output, std::vector<uint8_t> &out,
                     std::string &error) {
        return EncodeOutput(output, out, error);
    }

    // The wire of a spent coin; a legacy coin has its LegacyCoinWire.
    bool CoinBytes(const Output &coin, std::vector<uint8_t> &out,
                   std::string &error) {
        return EncodeCoinOutput(coin, out, error);
    }

    bool AnyLegacyCoin(const ResolvedCoins &resolved) noexcept {
        for (const auto &coin : resolved) {
            if (coin && coin->legacy_script) return true;
        }
        return false;
    }

    bool ResolvedValid(const Transaction &tx, const ResolvedCoins &resolved,
                       std::string &error) {
        if (resolved.size() != tx.inputs.size()) {
            error = "resolved count";
            return false;
        }
        for (size_t i = 0; i < tx.inputs.size(); ++i) {
            if (tx.inputs[i].flags != 1 && tx.inputs[i].flags != 3) {
                error = "unsupported input kind for signing";
                return false;
            }
            if (tx.inputs[i].flags == 1 &&
                (!resolved[i] || resolved[i]->IsBurn())) {
                error = "spend resolved coin";
                return false;
            }
            if (tx.inputs[i].flags == 3 && resolved[i]) {
                error = "mint resolved coin";
                return false;
            }
        }
        return true;
    }

    bool NonzeroDelta(const PositiveDelta &delta) {
        return std::any_of(delta.begin(), delta.end(),
                           [](uint8_t byte) { return byte != 0; });
    }

    bool OwnInputHashFromCoinWire(const Input &input, const TxProfile &profile,
                                  const std::vector<uint8_t> &coin_wire,
                                  std::vector<uint8_t> &core, Hash &result,
                                  std::string &error) {
        core.clear();
        if (!EncodeInputCore(input, profile, core, error))
            return false;
        CompactSize(coin_wire.size(), core);
        core.insert(core.end(), coin_wire.begin(), coin_wire.end());
        result = TaggedHash(HashDomain::OwnInput, core);
        error.clear();
        return true;
    }

    bool OwnInputHashOf(const Input &input, const TxProfile &profile,
                        const Output &coin, Hash &result, std::string &error) {
        std::vector<uint8_t> core, wire;
        if (!CoinBytes(coin, wire, error))
            return false;
        return OwnInputHashFromCoinWire(input, profile, wire, core, result,
                                        error);
    }

    bool WitnessIsAutomaticSuccess(const BranchWitness &w) noexcept {
        return w.script.size() == 1 && w.script[0] == 0x4e;
    }

    bool WitnessIsPureMode0Checksig(const BranchWitness &w) noexcept {
        if (WitnessIsAutomaticSuccess(w)) return true;
        return w.script.size() == 34 && w.script[0] == 0x20 &&
               (w.script[33] == 0xbb || w.script[33] == 0xbc) &&
               w.arguments.size() == 1 &&
               (w.arguments[0].size() == 64 ||
                (w.arguments[0].size() == 65 && w.arguments[0][64] == 0));
    }

    bool WitnessIsMode0Or1Checksig(const BranchWitness &w) noexcept {
        if (WitnessIsAutomaticSuccess(w)) return true;
        return w.script.size() == 34 && w.script[0] == 0x20 &&
               (w.script[33] == 0xbb || w.script[33] == 0xbc) &&
               w.arguments.size() == 1 &&
               (w.arguments[0].size() == 64 ||
                (w.arguments[0].size() == 65 && w.arguments[0][64] <= 1));
    }

    bool InputIsPureMode0Checksig(const Input &input) noexcept {
        if (input.flags != 1 || input.witnesses.empty()) return false;
        for (const auto &w : input.witnesses) {
            if (!WitnessIsPureMode0Checksig(w)) return false;
        }
        return true;
    }

    bool InputMayUseMode2(const Input &input) noexcept {
        if (input.flags != 1 || input.witnesses.empty()) return false;
        for (const auto &w : input.witnesses) {
            if (!WitnessIsMode0Or1Checksig(w)) return true;
        }
        return false;
    }

    bool TxIsPureMode0Checksig(const Transaction &tx) noexcept {
        if (tx.inputs.empty()) return false;
        for (const auto &in : tx.inputs) {
            if (!InputIsPureMode0Checksig(in)) return false;
        }
        return true;
    }

    bool TxIsAllAutomaticSuccess(const Transaction &tx) noexcept {
        if (tx.inputs.empty()) return false;
        for (const auto &in : tx.inputs) {
            if (in.flags != 1 || in.witnesses.empty()) return false;
            for (const auto &w : in.witnesses) {
                if (!WitnessIsAutomaticSuccess(w)) return false;
            }
        }
        return true;
    }

} // namespace

bool ComputeIdentitiesValidated(const Transaction &tx,
                                const TxProfile &profile,
                                const ChainId &chain_id,
                                IdentityDigests &result, std::string &error) {
    std::vector<Hash> core_leaves, full_leaves;
    core_leaves.reserve(tx.inputs.size());
    full_leaves.reserve(tx.inputs.size());
    std::vector<uint8_t> core, full;
    for (const auto &input : tx.inputs) {
        core.clear();
        full.clear();
        if (!EncodeInputCore(input, profile, core, error) ||
            !EncodeInputFull(input, profile, full, error))
            return false;
        core_leaves.push_back(InputCoreLeaf(core));
        full_leaves.push_back(InputFullLeaf(full));
    }
    IdentityDigests computed;
    computed.inputs_root = IndexedTreeRoot(core_leaves);
    computed.full_inputs_root = IndexedTreeRoot(full_leaves);
    computed.output_leaves.reserve(tx.outputs.size());
    std::vector<uint8_t> wire;
    for (const auto &output : tx.outputs) {
        wire.clear();
        if (!OutputBytes(output, wire, error)) return false;
        computed.output_leaves.push_back(OutputLeaf(wire));
    }
    computed.outputs_root = IndexedTreeRoot(computed.output_leaves);
    TxHeaderCore header{};
    header[0] = 7;
    for (size_t i = 0; i < 8; ++i)
        header[4 + i] = uint8_t(tx.lock >> (8 * i));
    header[12] = uint8_t(tx.inputs.size());
    header[13] = uint8_t(tx.inputs.size() >> 8);
    header[14] = uint8_t(tx.outputs.size());
    header[15] = uint8_t(tx.outputs.size() >> 8);
    computed.txid = TransactionId(chain_id, header, computed.inputs_root,
                                  computed.outputs_root);
    computed.txhash = TransactionHash(
        chain_id, header, computed.full_inputs_root, computed.outputs_root);
    result = std::move(computed);
    error.clear();
    return true;
}

bool ComputeOutputIdentitiesOnly(const Transaction &tx, const Hash &known_txid,
                                 const Hash &known_txhash,
                                 IdentityDigests &result, std::string &error) {
    IdentityDigests computed{};
    computed.txid = known_txid;
    computed.txhash = known_txhash;
    if (!TxIsPureMode0Checksig(tx)) {
        computed.output_leaves.reserve(tx.outputs.size());
        std::vector<uint8_t> wire;
        for (const auto &output : tx.outputs) {
            wire.clear();
            if (!OutputBytes(output, wire, error)) return false;
            computed.output_leaves.push_back(OutputLeaf(wire));
        }
        computed.outputs_root = IndexedTreeRoot(computed.output_leaves);
    }
    result = std::move(computed);
    error.clear();
    return true;
}

bool ComputeIdentities(const Transaction &tx, const TxProfile &profile,
                       const ChainId &chain_id, IdentityDigests &result,
                       std::string &error) {
    std::vector<uint8_t> validated_wire;
    if (!EncodeTransaction(tx, profile, validated_wire, error)) return false;
    return ComputeIdentitiesValidated(tx, profile, chain_id, result, error);
}

bool ComputeCoinsRoot(const Transaction &tx, const ResolvedCoins &resolved,
                      Hash &result, std::string &error) {
    if (!ResolvedValid(tx, resolved, error)) return false;
    std::vector<Hash> leaves;
    leaves.reserve(tx.inputs.size());
    std::vector<uint8_t> wire;
    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        if (tx.inputs[i].flags == 3)
            leaves.push_back(CoinEntryLeaf({}));
        else {
            wire.clear();
            if (!CoinBytes(*resolved[i], wire, error)) return false;
            leaves.push_back(CoinEntryLeaf(wire));
        }
    }
    result = IndexedTreeRoot(leaves);
    error.clear();
    return true;
}

bool ComputeOwnInputHash(const Transaction &tx, const TxProfile &profile,
                         const ResolvedCoins &resolved, size_t input_index,
                         Hash &result, std::string &error) {
    if (!ResolvedValid(tx, resolved, error) ||
        input_index >= tx.inputs.size() || tx.inputs[input_index].flags != 1) {
        error = "own input spend";
        return false;
    }
    return OwnInputHashOf(tx.inputs[input_index], profile,
                          *resolved[input_index], result, error);
}

SigningPreparationStatus PrepareSigningContextChecked(
    const Transaction &tx, const TxProfile &profile, const ChainId &chain_id,
    const ResolvedCoins &resolved, PreparedSigningContext &result,
    std::string &error, const IdentityDigests *precomputed_identities) {
    try {
        IdentityDigests computed_ids;
        const IdentityDigests *ids = precomputed_identities;
        if (ids == nullptr) {
            if (!ComputeIdentities(tx, profile, chain_id, computed_ids, error))
                return SigningPreparationStatus::OperationalError;
            ids = &computed_ids;
        }
        if (!ResolvedValid(tx, resolved, error))
            return SigningPreparationStatus::OperationalError;

        PreparedSigningContext prepared;
        prepared.chain_id_ = chain_id;
        prepared.lock_ = tx.lock;
        prepared.identities_ = *ids;
        prepared.txid_ = ids->txid;
        prepared.outputs_root_ = ids->outputs_root;
        prepared.output_leaves_ = ids->output_leaves;
        prepared.own_input_hashes_.resize(tx.inputs.size());
        prepared.invocations_.resize(tx.inputs.size());

        static const Hash kOpTrueBranchLeaf = []() {
            const std::array<uint8_t, 1> s{0x4e};
            return BranchLeaf(s);
        }();

        if (precomputed_identities != nullptr && TxIsAllAutomaticSuccess(tx) &&
            !AnyLegacyCoin(resolved)) {
            for (size_t i = 0; i < tx.inputs.size(); ++i) {
                const Input &input = tx.inputs[i];
                const Output &coin = *resolved[i];
                if (input.path_index >= coin.paths.size() ||
                    input.witnesses.size() !=
                        coin.paths[input.path_index].size()) {
                    error = "positional witness count/index";
                    return SigningPreparationStatus::InvalidWitness;
                }
                const auto &path = coin.paths[input.path_index];
                auto &invocations = prepared.invocations_[i];
                invocations.resize(path.size());
                for (size_t j = 0; j < path.size(); ++j) {
                    const uint8_t branch_index = path[j];
                    const BranchWitness &witness = input.witnesses[j];
                    if (branch_index >= coin.branches.size() ||
                        (witness.siblings.empty()
                             ? coin.branches[branch_index] != kOpTrueBranchLeaf
                             : BranchProofRoot(kOpTrueBranchLeaf,
                                               witness.siblings) !=
                                   coin.branches[branch_index])) {
                        error = "branch membership";
                        return SigningPreparationStatus::InvalidWitness;
                    }
                    invocations[j].kind = 1;
                }
            }
            prepared.ready_ = true;
            result = std::move(prepared);
            error.clear();
            return SigningPreparationStatus::Ready;
        }

        std::vector<Hash> coin_leaves;
        coin_leaves.reserve(tx.inputs.size());
        std::vector<uint8_t> coin_wire, core;

        for (size_t i = 0; i < tx.inputs.size(); ++i) {
            const Input &input = tx.inputs[i];
            auto &invocations = prepared.invocations_[i];
            if (input.flags == 1) {
                const Output &coin = *resolved[i];
                // A legacy coin is spent through path 0 by one witness with
                // no siblings (the legacy bridge); a V2 coin by one of its
                // paths.
                const size_t path_width =
                    coin.legacy_script
                        ? 1
                        : (input.path_index < coin.paths.size()
                               ? coin.paths[input.path_index].size()
                               : 0);
                if ((coin.legacy_script
                         ? input.path_index != 0
                         : input.path_index >= coin.paths.size()) ||
                    input.witnesses.size() != path_width) {
                    error = "positional witness count/index";
                    return SigningPreparationStatus::InvalidWitness;
                }
                coin_wire.clear();
                if (!CoinBytes(coin, coin_wire, error))
                    return SigningPreparationStatus::OperationalError;
                coin_leaves.push_back(CoinEntryLeaf(coin_wire));
                if (precomputed_identities == nullptr || coin.legacy_script ||
                    !InputIsPureMode0Checksig(input)) {
                    if (!OwnInputHashFromCoinWire(
                            input, profile, coin_wire, core,
                            prepared.own_input_hashes_[i].emplace(), error))
                        return SigningPreparationStatus::OperationalError;
                    if (i < tx.outputs.size() &&
                        ids->output_leaves.empty() &&
                        InputMayUseMode2(input)) {
                        if (prepared.output_leaves_.empty()) {
                            prepared.output_leaves_.resize(tx.outputs.size());
                        }
                        core.clear();
                        if (!OutputBytes(tx.outputs[i], core, error))
                            return SigningPreparationStatus::OperationalError;
                        prepared.output_leaves_[i] = OutputLeaf(core);
                    }
                }
                if (coin.legacy_script) {
                    const BranchWitness &witness = input.witnesses[0];
                    if (!witness.siblings.empty()) {
                        error = "legacy coin witness";
                        return SigningPreparationStatus::InvalidWitness;
                    }
                    const Hash leaf =
                        LegacyBridgeLeaf(*coin.legacy_script, witness.script);
                    PreparedSigningContext::Invocation invocation;
                    invocation.kind = 1;
                    invocation.selector.reserve(41);
                    invocation.selector.push_back(1);
                    Integer(i, 4, invocation.selector);
                    Integer(0, 4, invocation.selector);
                    invocation.selector.insert(invocation.selector.end(),
                                               leaf.begin(), leaf.end());
                    invocations.push_back(std::move(invocation));
                    continue;
                }
                const auto &path = coin.paths[input.path_index];
                invocations.reserve(path.size());
                for (size_t j = 0; j < path.size(); ++j) {
                    const uint8_t branch_index = path[j];
                    const BranchWitness &witness = input.witnesses[j];
                    const Hash leaf = WitnessIsAutomaticSuccess(witness)
                                          ? kOpTrueBranchLeaf
                                          : BranchLeaf(witness.script);
                    if (branch_index >= coin.branches.size() ||
                        BranchProofRoot(leaf, witness.siblings) !=
                            coin.branches[branch_index]) {
                        error = "branch membership";
                        return SigningPreparationStatus::InvalidWitness;
                    }
                    PreparedSigningContext::Invocation invocation;
                    invocation.kind = 1;
                    invocation.selector.reserve(41);
                    invocation.selector.push_back(1);
                    Integer(i, 4, invocation.selector);
                    Integer(branch_index, 4, invocation.selector);
                    invocation.selector.insert(invocation.selector.end(),
                                               leaf.begin(), leaf.end());
                    invocations.push_back(std::move(invocation));
                }
            } else if (input.flags == 3) {
                coin_leaves.push_back(CoinEntryLeaf({}));
                const BranchWitness &witness = input.witnesses[0];
                const Hash leaf = BranchLeaf(witness.script);
                if (BranchProofRoot(leaf, witness.siblings) !=
                    input.prev_txid) {
                    error = "mint root";
                    return SigningPreparationStatus::InvalidWitness;
                }
                PreparedSigningContext::Invocation invocation;
                invocation.kind = 3;
                invocation.selector.reserve(81);
                invocation.selector.push_back(3);
                invocation.selector.insert(invocation.selector.end(),
                                           input.prev_txid.begin(),
                                           input.prev_txid.end());
                invocation.selector.insert(invocation.selector.end(), 16, 0);
                invocation.selector.insert(invocation.selector.end(),
                                           leaf.begin(), leaf.end());
                invocations.push_back(std::move(invocation));
            }
        }
        prepared.coins_root_ = IndexedTreeRoot(coin_leaves);
        prepared.ready_ = true;
        result = std::move(prepared);
        error.clear();
        return SigningPreparationStatus::Ready;
    } catch (const std::exception &exception) {
        error = exception.what();
        return SigningPreparationStatus::OperationalError;
    }
}

bool PrepareSigningContext(const Transaction &tx, const TxProfile &profile,
                           const ChainId &chain, const ResolvedCoins &coins,
                           PreparedSigningContext &result, std::string &error) {
    return PrepareSigningContextChecked(tx, profile, chain, coins, result,
                                        error) ==
           SigningPreparationStatus::Ready;
}

bool ValidateSigningInvocation(const PreparedSigningContext &prepared,
                               size_t input_index, size_t witness_index,
                               const std::optional<PositiveDelta> &positive_delta,
                               std::string &error) {
    if (!prepared.ready_ || input_index >= prepared.invocations_.size() ||
        witness_index >= prepared.invocations_[input_index].size()) {
        error = "signing mode or invocation index";
        return false;
    }
    const auto &invocation =
        prepared.invocations_[input_index][witness_index];
    if (invocation.kind == 1 && positive_delta) {
        error = "spend delta";
        return false;
    }
    if (invocation.kind == 3 &&
        (!positive_delta || !NonzeroDelta(*positive_delta))) {
        error = "mint selector delta/mode";
        return false;
    }
    error.clear();
    return true;
}

bool SigningMessage(const PreparedSigningContext &prepared, size_t input_index,
                    size_t witness_index, uint8_t mode,
                    const std::optional<PositiveDelta> &positive_delta,
                    Hash &result, std::string &error) {
    if (!prepared.ready_ || mode > 2 ||
        input_index >= prepared.invocations_.size() ||
        witness_index >= prepared.invocations_[input_index].size()) {
        error = "signing mode or invocation index";
        return false;
    }
    const auto &invocation =
        prepared.invocations_[input_index][witness_index];
    if (invocation.kind == 1 && positive_delta) {
        error = "spend delta";
        return false;
    }
    if (invocation.kind == 3 &&
        (mode != 0 || !positive_delta || !NonzeroDelta(*positive_delta))) {
        error = "mint selector delta/mode";
        return false;
    }
    if (mode == 2 && input_index >= prepared.output_leaves_.size()) {
        error = "partial mode unavailable";
        return false;
    }
    const size_t expected_len =
        invocation.kind == 3 ? 178 : mode == 0 ? 138 : 150;
    std::array<uint8_t, 178> preimage{};
    uint8_t *dst = preimage.data();
    std::memcpy(dst, prepared.chain_id_.data(), 32);
    dst += 32;
    *dst++ = mode;
    if (mode == 0) {
        std::memcpy(dst, prepared.txid_.data(), 32);
        dst += 32;
        std::memcpy(dst, prepared.coins_root_.data(), 32);
        dst += 32;
    } else {
        if (!prepared.own_input_hashes_[input_index].has_value()) {
            error = "own input hash unavailable";
            return false;
        }
        dst[0] = 7;
        dst[1] = 0;
        dst[2] = 0;
        dst[3] = 0;
        dst += 4;
        for (size_t i = 0; i < 8; ++i) {
            dst[i] = uint8_t(prepared.lock_ >> (8 * i));
        }
        dst += 8;
        const Hash &own = *prepared.own_input_hashes_[input_index];
        std::memcpy(dst, own.data(), 32);
        dst += 32;
        const Hash &output_commitment = mode == 1
            ? prepared.outputs_root_ : prepared.output_leaves_[input_index];
        std::memcpy(dst, output_commitment.data(), 32);
        dst += 32;
    }
    if (invocation.kind == 3) {
        if (invocation.selector.size() != 81) {
            error = "sighash preimage width";
            return false;
        }
        std::memcpy(dst, invocation.selector.data(), 33);
        dst += 33;
        std::memcpy(dst, positive_delta->data(), 16);
        dst += 16;
        std::memcpy(dst, invocation.selector.data() + 49, 32);
        dst += 32;
    } else {
        if (invocation.selector.size() != 41) {
            error = "sighash preimage width";
            return false;
        }
        std::memcpy(dst, invocation.selector.data(), 41);
        dst += 41;
    }
    if (static_cast<size_t>(dst - preimage.data()) != expected_len) {
        error = "sighash preimage width";
        return false;
    }
    result = TaggedHash(HashDomain::Sighash,
                        std::span<const uint8_t>(preimage.data(), expected_len));
    error.clear();
    return true;
}

bool SigningMessage(const Transaction &tx, const TxProfile &profile,
                    const ChainId &chain_id, const ResolvedCoins &resolved,
                    size_t input_index, size_t witness_index, uint8_t mode,
                    const std::optional<PositiveDelta> &positive_delta,
                    Hash &result, std::string &error) {
    PreparedSigningContext prepared;
    if (!PrepareSigningContext(tx, profile, chain_id, resolved, prepared,
                               error))
        return false;
    return SigningMessage(prepared, input_index, witness_index, mode,
                          positive_delta, result, error);
}

SignatureStatus VerifyBip340Signature(std::span<const uint8_t> public_key,
                                      std::span<const uint8_t> signature,
                                      const Hash &message, bool mint) {
    if (!((signature.size() == 64) ||
          (signature.size() == 65 && !mint &&
           (signature[64] == 1 || signature[64] == 2)))) {
        return SignatureStatus::InvalidEncoding;
    }
    if (public_key.size() != 32) return SignatureStatus::InvalidPublicKey;
    secp256k1_xonly_pubkey parsed;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &parsed,
                                      public_key.data())) {
        return SignatureStatus::InvalidPublicKey;
    }
    return secp256k1_schnorrsig_verify(secp256k1_context_static,
                                       signature.data(), message.data(),
                                       message.size(), &parsed)
               ? SignatureStatus::Valid
               : SignatureStatus::InvalidSignature;
}

bool SignBip340Message(const std::array<uint8_t, 32> &secret_key,
                       const Hash &message, uint8_t mode,
                       const std::array<uint8_t, 32> &aux_randomness,
                       std::vector<uint8_t> &result, std::string &error) {
    if (mode > 2) {
        error = "signing mode";
        return false;
    }
    using ContextPtr = std::unique_ptr<secp256k1_context,
                                       decltype(&secp256k1_context_destroy)>;
    ContextPtr ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN),
                   secp256k1_context_destroy);
    if (!ctx) {
        error = "secp256k1 context";
        return false;
    }
    // The keypair embeds the private scalar. Keep cleanup attached to its
    // lifetime, including invalid-key/signing failures and allocation throws.
    struct ScopedKeypair {
        secp256k1_keypair value{};
        ScopedKeypair() = default;
        ScopedKeypair(const ScopedKeypair &) = delete;
        ScopedKeypair &operator=(const ScopedKeypair &) = delete;
        ~ScopedKeypair() { memory_cleanse(&value, sizeof(value)); }
    } pair;
    if (!secp256k1_keypair_create(ctx.get(), &pair.value, secret_key.data())) {
        error = "invalid secret key";
        return false;
    }
    std::vector<uint8_t> sig(64);
    if (!secp256k1_schnorrsig_sign32(ctx.get(), sig.data(), message.data(),
                                     &pair.value, aux_randomness.data())) {
        error = "BIP340 signing failed";
        return false;
    }
    if (mode) sig.push_back(mode);
    result = std::move(sig);
    error.clear();
    return true;
}

namespace {
bool VerifyBatchSlice(std::span<const BatchSigItem> slice) {
    if (slice.empty()) return true;
    if (slice.size() == 1) {
        return secp256k1_schnorrsig_verify(
                   secp256k1_context_static, slice[0].sig.data(),
                   slice[0].msg.data(), slice[0].msg.size(),
                   reinterpret_cast<const secp256k1_xonly_pubkey *>(
                       slice[0].parsed_pubkey.data())) == 1;
    }
    const size_t n = slice.size();
    std::vector<const unsigned char *> sigs(n);
    std::vector<const unsigned char *> msgs(n);
    std::vector<const secp256k1_xonly_pubkey *> pubkeys(n);

    for (size_t i = 0; i < n; ++i) {
        sigs[i] = slice[i].sig.data();
        msgs[i] = slice[i].msg.data();
        pubkeys[i] = reinterpret_cast<const secp256k1_xonly_pubkey *>(
            slice[i].parsed_pubkey.data());
    }
    const auto rand32 = GenerateBatchRandomizers(
        n, "Lotus/v2/schnorr-batch-randomizer");

    return secp256k1_schnorrsig_verify_batch(
               secp256k1_context_static, sigs.data(), msgs.data(),
               pubkeys.data(), rand32.data(), n) == 1;
}

bool VerifyLegacyBatchSlice(std::span<const LegacyBatchSigItem> slice) {
    if (slice.empty()) return true;
    if (slice.size() == 1) {
        return secp256k1_schnorr_verify(
                   secp256k1_context_static, slice[0].sig.data(),
                   slice[0].msg.data(),
                   reinterpret_cast<const secp256k1_pubkey *>(
                       slice[0].parsed_pubkey.data())) == 1;
    }
    const size_t n = slice.size();
    std::vector<const unsigned char *> sigs(n);
    std::vector<const unsigned char *> msgs(n);
    std::vector<const secp256k1_pubkey *> pubkeys(n);

    for (size_t i = 0; i < n; ++i) {
        sigs[i] = slice[i].sig.data();
        msgs[i] = slice[i].msg.data();
        pubkeys[i] = reinterpret_cast<const secp256k1_pubkey *>(
            slice[i].parsed_pubkey.data());
    }
    const auto rand32 = GenerateBatchRandomizers(
        n, "Lotus/v2/legacy-schnorr-batch-randomizer");

    return secp256k1_schnorr_verify_batch(
               secp256k1_context_static, sigs.data(), msgs.data(),
               pubkeys.data(), rand32.data(), n) == 1;
}

std::optional<size_t> BisectBatchSlice(std::span<const BatchSigItem> slice,
                                       size_t base_offset) {
    if (slice.empty()) return std::nullopt;
    if (VerifyBatchSlice(slice)) return std::nullopt;
    if (slice.size() == 1) return base_offset;
    const size_t mid = slice.size() / 2;
    if (auto left = BisectBatchSlice(slice.subspan(0, mid), base_offset)) {
        return left;
    }
    return BisectBatchSlice(slice.subspan(mid), base_offset + mid);
}

std::optional<size_t>
BisectLegacyBatchSlice(std::span<const LegacyBatchSigItem> slice,
                       size_t base_offset) {
    if (slice.empty()) return std::nullopt;
    if (VerifyLegacyBatchSlice(slice)) return std::nullopt;
    if (slice.size() == 1) return base_offset;
    const size_t mid = slice.size() / 2;
    if (auto left =
            BisectLegacyBatchSlice(slice.subspan(0, mid), base_offset)) {
        return left;
    }
    return BisectLegacyBatchSlice(slice.subspan(mid), base_offset + mid);
}

class SigningWorkerPool {
public:
    static SigningWorkerPool &Instance() {
        static SigningWorkerPool pool;
        return pool;
    }

    template <typename Fn>
    void Run(size_t num_workers, Fn &&fn) {
        if (num_workers <= 1) {
            fn(0);
            return;
        }
        std::function<void(size_t)> task_fn(std::forward<Fn>(fn));
        std::unique_lock<std::mutex> dispatch_lock(m_dispatch_mutex);
        EnsureWorkers(num_workers - 1);
        const size_t active = std::min(num_workers - 1, m_threads.size());
        if (active == 0) {
            dispatch_lock.unlock();
            task_fn(0);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_task = &task_fn;
            m_active_workers = active;
            m_remaining.store(active, std::memory_order_release);
            ++m_generation;
        }
        m_cv_start.notify_all();
        task_fn(0);
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv_done.wait(lock, [this]() {
                return m_remaining.load(std::memory_order_acquire) == 0;
            });
            m_task = nullptr;
        }
    }

private:
    SigningWorkerPool() = default;
    ~SigningWorkerPool() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stop = true;
            ++m_generation;
        }
        m_cv_start.notify_all();
        for (auto &t : m_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    void EnsureWorkers(size_t count) {
        while (m_threads.size() < count) {
            const size_t worker_id = m_threads.size() + 1;
            m_threads.emplace_back([this, worker_id]() {
                uint64_t seen_gen = 0;
                while (true) {
                    const std::function<void(size_t)> *fn = nullptr;
                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv_start.wait(lock, [this, &seen_gen]() {
                            return m_stop || m_generation != seen_gen;
                        });
                        if (m_stop) {
                            return;
                        }
                        seen_gen = m_generation;
                        if (worker_id <= m_active_workers) {
                            fn = m_task;
                        }
                    }
                    if (fn != nullptr) {
                        (*fn)(worker_id);
                        if (m_remaining.fetch_sub(
                                1, std::memory_order_acq_rel) == 1) {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            m_cv_done.notify_one();
                        }
                    }
                }
            });
        }
    }

    std::mutex m_dispatch_mutex;
    std::mutex m_mutex;
    std::condition_variable m_cv_start;
    std::condition_variable m_cv_done;
    std::vector<std::thread> m_threads;
    const std::function<void(size_t)> *m_task{nullptr};
    size_t m_active_workers{0};
    std::atomic<size_t> m_remaining{0};
    uint64_t m_generation{0};
    bool m_stop{false};
};

size_t EffectiveBatchThreads(size_t total_items, size_t requested_threads) {
    if (total_items < 32) return 1;
    size_t hw = requested_threads;
    if (hw == 0) {
        hw = std::min<size_t>(
            std::max<size_t>(std::thread::hardware_concurrency(), 1), 16);
    }
    return std::min<size_t>(hw, (total_items + 15) / 16);
}
} // namespace

bool BatchSigCollector::Add(std::span<const uint8_t> pubkey,
                            std::span<const uint8_t> sig, const Hash &msg) {
    if (pubkey.size() != 32 || sig.size() < 64) return false;
    secp256k1_xonly_pubkey parsed;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &parsed,
                                      pubkey.data())) {
        return false;
    }
    BatchSigItem item;
    std::memcpy(item.pubkey.data(), pubkey.data(), 32);
    std::memcpy(item.parsed_pubkey.data(), parsed.data, 64);
    std::memcpy(item.sig.data(), sig.data(), 64);
    item.msg = msg;
    items_.push_back(item);
    return true;
}

bool BatchSigCollector::AddLegacySchnorr(std::span<const uint8_t> pubkey,
                                         std::span<const uint8_t> sig64,
                                         const uint8_t *msg32,
                                         const uint8_t *cache_entry32,
                                         bool store_in_cache) {
    if (sig64.size() != 64 || msg32 == nullptr ||
        (pubkey.size() != 33 && pubkey.size() != 65)) {
        return false;
    }
    secp256k1_pubkey parsed;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed,
                                   pubkey.data(), pubkey.size())) {
        return false;
    }
    LegacyBatchSigItem item;
    std::memcpy(item.parsed_pubkey.data(), parsed.data, 64);
    std::memcpy(item.sig.data(), sig64.data(), 64);
    std::memcpy(item.msg.data(), msg32, 32);
    if (store_in_cache && cache_entry32 != nullptr) {
        std::memcpy(item.cache_entry.data(), cache_entry32, 32);
        item.store_in_cache = true;
    }
    legacy_items_.push_back(item);
    return true;
}

void BatchSigCollector::Merge(const BatchSigCollector &other) {
    if (!other.items_.empty()) {
        items_.insert(items_.end(), other.items_.begin(), other.items_.end());
    }
    if (!other.legacy_items_.empty()) {
        legacy_items_.insert(legacy_items_.end(), other.legacy_items_.begin(),
                             other.legacy_items_.end());
    }
}

void BatchSigCollector::Merge(BatchSigCollector &&other) {
    if (!other.items_.empty()) {
        if (items_.empty()) {
            items_ = std::move(other.items_);
        } else {
            items_.insert(items_.end(), other.items_.begin(),
                          other.items_.end());
            other.items_.clear();
        }
    }
    if (!other.legacy_items_.empty()) {
        if (legacy_items_.empty()) {
            legacy_items_ = std::move(other.legacy_items_);
        } else {
            legacy_items_.insert(legacy_items_.end(),
                                 other.legacy_items_.begin(),
                                 other.legacy_items_.end());
            other.legacy_items_.clear();
        }
    }
}

bool BatchSigCollector::VerifyAll(size_t num_threads) const {
    if (!items_.empty()) {
        const size_t threads = EffectiveBatchThreads(items_.size(), num_threads);
        const std::span<const BatchSigItem> all(items_.data(), items_.size());
        if (threads <= 1) {
            if (!VerifyBatchSlice(all)) return false;
        } else {
            std::atomic<bool> all_valid{true};
            auto run_chunk = [&](size_t t) {
                const size_t begin = (items_.size() * t) / threads;
                const size_t end = (items_.size() * (t + 1)) / threads;
                if (begin >= end || !all_valid.load(std::memory_order_relaxed))
                    return;
                if (!VerifyBatchSlice(all.subspan(begin, end - begin))) {
                    all_valid.store(false, std::memory_order_relaxed);
                }
            };
            SigningWorkerPool::Instance().Run(threads, run_chunk);
            if (!all_valid.load(std::memory_order_relaxed)) return false;
        }
    }

    if (!legacy_items_.empty()) {
        const size_t threads =
            EffectiveBatchThreads(legacy_items_.size(), num_threads);
        const std::span<const LegacyBatchSigItem> all(legacy_items_.data(),
                                                      legacy_items_.size());
        if (threads <= 1) {
            if (!VerifyLegacyBatchSlice(all)) return false;
        } else {
            std::atomic<bool> all_valid{true};
            auto run_chunk = [&](size_t t) {
                const size_t begin = (legacy_items_.size() * t) / threads;
                const size_t end = (legacy_items_.size() * (t + 1)) / threads;
                if (begin >= end || !all_valid.load(std::memory_order_relaxed))
                    return;
                if (!VerifyLegacyBatchSlice(all.subspan(begin, end - begin))) {
                    all_valid.store(false, std::memory_order_relaxed);
                }
            };
            SigningWorkerPool::Instance().Run(threads, run_chunk);
            if (!all_valid.load(std::memory_order_relaxed)) return false;
        }
    }

    return true;
}

std::optional<size_t>
BatchSigCollector::FirstFailingIndex(size_t num_threads) const {
    if (!items_.empty()) {
        const size_t threads = EffectiveBatchThreads(items_.size(), num_threads);
        const std::span<const BatchSigItem> all(items_.data(), items_.size());
        if (threads <= 1) {
            if (auto fail = BisectBatchSlice(all, 0)) {
                return fail;
            }
        } else {
            std::vector<uint8_t> chunk_ok(threads, 1);
            auto check_chunk = [&](size_t t) {
                const size_t begin = (items_.size() * t) / threads;
                const size_t end = (items_.size() * (t + 1)) / threads;
                if (begin < end &&
                    !VerifyBatchSlice(all.subspan(begin, end - begin))) {
                    chunk_ok[t] = 0;
                }
            };
            SigningWorkerPool::Instance().Run(threads, check_chunk);
            for (size_t t = 0; t < threads; ++t) {
                if (chunk_ok[t] == 0) {
                    const size_t begin = (items_.size() * t) / threads;
                    const size_t end = (items_.size() * (t + 1)) / threads;
                    if (auto fail = BisectBatchSlice(
                            all.subspan(begin, end - begin), begin)) {
                        return fail;
                    }
                }
            }
        }
    }

    if (!legacy_items_.empty()) {
        const size_t base = items_.size();
        const size_t threads =
            EffectiveBatchThreads(legacy_items_.size(), num_threads);
        const std::span<const LegacyBatchSigItem> all(legacy_items_.data(),
                                                      legacy_items_.size());
        if (threads <= 1) {
            if (auto fail = BisectLegacyBatchSlice(all, base)) {
                return fail;
            }
        } else {
            std::vector<uint8_t> chunk_ok(threads, 1);
            auto check_chunk = [&](size_t t) {
                const size_t begin = (legacy_items_.size() * t) / threads;
                const size_t end = (legacy_items_.size() * (t + 1)) / threads;
                if (begin < end &&
                    !VerifyLegacyBatchSlice(all.subspan(begin, end - begin))) {
                    chunk_ok[t] = 0;
                }
            };
            SigningWorkerPool::Instance().Run(threads, check_chunk);
            for (size_t t = 0; t < threads; ++t) {
                if (chunk_ok[t] == 0) {
                    const size_t begin = (legacy_items_.size() * t) / threads;
                    const size_t end = (legacy_items_.size() * (t + 1)) / threads;
                    if (auto fail = BisectLegacyBatchSlice(
                            all.subspan(begin, end - begin), base + begin)) {
                        return fail;
                    }
                }
            }
        }
    }

    return std::nullopt;
}

void RunParallelSigningWork(
    size_t total_items, size_t min_grain,
    const std::function<void(size_t, size_t)> &fn) {
    if (total_items == 0) {
        return;
    }
    const size_t grain = std::max<size_t>(min_grain, 1);
    if (total_items < grain * 2) {
        fn(0, total_items);
        return;
    }
    const size_t hw = std::min<size_t>(
        std::max<size_t>(std::thread::hardware_concurrency(), 1), 16);
    const size_t threads =
        std::min<size_t>(hw, (total_items + grain - 1) / grain);
    if (threads <= 1) {
        fn(0, total_items);
        return;
    }
    SigningWorkerPool::Instance().Run(threads, [&](size_t t) {
        const size_t begin = (total_items * t) / threads;
        const size_t end = (total_items * (t + 1)) / threads;
        if (begin < end) {
            fn(begin, end);
        }
    });
}

} // namespace lotus::v2

