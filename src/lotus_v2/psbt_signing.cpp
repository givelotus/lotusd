// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "psbt_signing.h"

#include "address.h"

#include <support/cleanse.h>

#include <algorithm>
#include <limits>

namespace lotus::v2 {
namespace {
    bool Fail(std::string &error, const char *message) {
        error = message;
        return false;
    }

    struct Prepared {
        NativePsbtData data;
        Transaction tx;
        std::vector<Coin> coins;
        ResolvedCoins resolved;
        PreparedSigningContext signing;
        NativePsbtReview review;
    };

    bool SameCoin(const Coin &a, const Coin &b) {
        PsbtBytes left, right;
        return EncodeCoin(a, left) && EncodeCoin(b, right) && left == right;
    }

    bool Authenticate(const NativePsbt &psbt, const NativePsbtContext &context,
                      Prepared &prepared, std::string &error) {
        if (!psbt.Inspect(prepared.data, error)) return false;
        if (prepared.data.chain_id != context.chain_id) {
            return Fail(error,
                        "native PSBT ChainID differs from trusted chain");
        }
        if (!ValidateOrdinaryProfile(context.profile, error)) return false;
        prepared.coins.reserve(prepared.data.inputs.size());
        for (const auto &input : prepared.data.inputs) {
            if (!input.coin)
                return Fail(error, "native PSBT is missing a full coin");
            bool authenticated = false;
            if (context.lookup) {
                Coin trusted;
                const auto status =
                    context.lookup(input.coin->outpoint, trusted, error);
                if (status == CoinReadResult::Error) return false;
                if (status == CoinReadResult::Missing) {
                    return Fail(
                        error,
                        "native PSBT coin is unavailable in trusted state");
                }
                if (!SameCoin(*input.coin, trusted)) {
                    return Fail(error,
                                "native PSBT coin differs from trusted state");
                }
                authenticated = true;
            }
            if (input.proof) {
                if (!context.trusted_utxo_root || !prepared.data.utxo_root ||
                    *context.trusted_utxo_root != *prepared.data.utxo_root ||
                    !VerifyCoinProof(input.coin->outpoint, *input.proof,
                                     *context.trusted_utxo_root)) {
                    return Fail(error,
                                "native PSBT coin proof is not authenticated");
                }
                authenticated = true;
            }
            if (!authenticated)
                return Fail(
                    error,
                    "native PSBT requires independently authenticated coins");
            prepared.coins.push_back(*input.coin);
            prepared.resolved.push_back(input.coin->output);
        }
        prepared.tx = prepared.data.tx_template;
        for (size_t i = 0; i < prepared.tx.inputs.size(); ++i) {
            const auto &metadata = prepared.data.inputs[i];
            for (size_t w = 0; w < prepared.tx.inputs[i].witnesses.size();
                 ++w) {
                auto args = metadata.arguments.find(uint16_t(w));
                if (args == metadata.arguments.end()) {
                    return Fail(
                        error,
                        "native PSBT is missing explicit witness arguments");
                }
                prepared.tx.inputs[i].witnesses[w].arguments = args->second;
            }
        }
        if (!CheckOrdinaryLocks(prepared.tx, prepared.coins, context.profile,
                                error))
            return false;
        if (!PrepareSigningContext(prepared.tx, context.profile.transaction,
                                   context.chain_id, prepared.resolved,
                                   prepared.signing, error))
            return false;
        return true;
    }

    bool Review(Prepared &prepared, const NativePsbtContext &context,
                std::string &error) {
        if (!ComputeVmAssetTotals(prepared.tx, prepared.resolved,
                                  prepared.review.assets, error))
            return false;
        const auto native = prepared.review.assets.find(Hash{});
        const VmAssetTotals zero{};
        const auto &totals =
            native == prepared.review.assets.end() ? zero : native->second;
        if (totals.outputs > totals.inputs)
            return Fail(error, "native PSBT inflates native currency");
        prepared.review.native_fee = totals.inputs - totals.outputs;
        for (const auto &[asset, amounts] : prepared.review.assets) {
            if (asset != Hash{} && amounts.outputs > amounts.inputs) {
                return Fail(error,
                            "native PSBT inflates a token without a mint");
            }
        }

        // Calculate the final wire size from explicit slots, without pretending
        // that dummy signature bytes authorize or validate a spend.
        Transaction projected = prepared.tx;
        for (size_t i = 0; i < prepared.data.inputs.size(); ++i) {
            for (const auto &[slot, request] :
                 prepared.data.inputs[i].requests) {
                if (request.scheme != 0)
                    return Fail(error,
                                "legacy bridge PSBT signing is unsupported");
                if (request.mode != 0 && !context.allow_partial_modes) {
                    return Fail(error, "partial native PSBT signing mode "
                                       "requires explicit authorization");
                }
                if (request.mode == 2 && i >= projected.outputs.size()) {
                    return Fail(
                        error,
                        "native PSBT paired-output mode has no paired output");
                }
                projected.inputs[i]
                    .witnesses[slot.witness]
                    .arguments[slot.argument]
                    .assign(request.mode == 0 ? 64 : 65, 0);
            }
        }
        PsbtBytes wire;
        if (!EncodeTransaction(projected, context.profile.transaction, wire,
                               error))
            return false;
        prepared.review.signed_wire_bytes = wire.size();
        size_t token_outputs = 0;
        for (const auto &output : projected.outputs)
            token_outputs += output.HasToken();
        const __uint128_t token_floor =
            __uint128_t{2} * context.profile.dust_limit * token_outputs;
        if (prepared.review.native_fee < wire.size() ||
            prepared.review.native_fee < token_floor) {
            return Fail(error,
                        "native PSBT fee is below the byte or token floor");
        }
        return true;
    }

    bool SupportedRole(const Prepared &prepared, size_t input_index,
                       PsbtSlot slot, const PsbtSignRequest &request,
                       std::string &error) {
        if (request.scheme != 0 ||
            prepared.coins[input_index].output.legacy_script) {
            return Fail(error, "automated native PSBT signer does not support "
                               "this coin policy");
        }
        const auto &witness =
            prepared.tx.inputs[input_index].witnesses[slot.witness];
        PsbtBytes direct{32};
        direct.insert(direct.end(), request.public_key.begin(),
                      request.public_key.end());
        direct.push_back(0xbb); // Native CHECKSIG.
        if (slot.argument == 0 && witness.arguments.size() == 1 &&
            witness.script == direct)
            return true;
        const std::span<const uint8_t, 32> pubkey(request.public_key.data(),
                                                  32);
        if (slot.argument == 0 && witness.arguments.size() == 2 &&
            witness.arguments[1] == request.public_key &&
            witness.script == KeyHashProgram(NativeKeyHash(pubkey)))
            return true;
        return Fail(
            error, "native PSBT signing request has an unsupported key policy");
    }

    bool VerifyPartial(const Prepared &prepared, size_t input_index,
                       PsbtSlot slot, const PsbtSignRequest &request,
                       const PsbtBytes &signature, std::string &error) {
        if (request.scheme != 0 ||
            prepared.coins[input_index].output.legacy_script) {
            return Fail(error,
                        "legacy bridge PSBT finalization is unsupported");
        }
        Hash message;
        if (!SigningMessage(prepared.signing, input_index, slot.witness,
                            request.mode, std::nullopt, message, error))
            return false;
        if (VerifyBip340Signature(request.public_key, signature, message,
                                  false) != SignatureStatus::Valid)
            return Fail(error, "invalid native PSBT partial signature");
        return true;
    }
} // namespace

bool UpdateNativePsbt(NativePsbt &psbt, const NativePsbtContext &context,
                      std::string &error) {
    NativePsbtData data;
    if (!psbt.Inspect(data, error)) return false;
    if (data.chain_id != context.chain_id || !context.lookup) {
        return Fail(
            error,
            "native PSBT update requires the trusted chain and coin lookup");
    }
    NativePsbt updated = psbt;
    for (size_t i = 0; i < data.tx_template.inputs.size(); ++i) {
        const auto &input = data.tx_template.inputs[i];
        Coin coin;
        const auto result =
            context.lookup({input.prev_txid, input.prev_index}, coin, error);
        if (result == CoinReadResult::Error) return false;
        if (result == CoinReadResult::Missing) continue;
        if (coin.outpoint != Outpoint{input.prev_txid, input.prev_index}) {
            return Fail(error, "trusted lookup returned a different outpoint");
        }
        PsbtBytes bytes;
        if (!EncodeCoin(coin, bytes))
            return Fail(error, "invalid trusted coin");
        auto [it, added] = updated.inputs[i].emplace(NativePsbtKey(1), bytes);
        if (!added && it->second != bytes)
            return Fail(error, "native PSBT coin conflicts with trusted state");
    }
    if (!updated.Inspect(data, error)) return false;
    psbt = std::move(updated);
    error.clear();
    return true;
}

bool ReviewNativePsbt(const NativePsbt &psbt, const NativePsbtContext &context,
                      NativePsbtReview &review, std::string &error) {
    Prepared prepared;
    if (!Authenticate(psbt, context, prepared, error) ||
        !Review(prepared, context, error))
        return false;
    review = std::move(prepared.review);
    error.clear();
    return true;
}

bool SignNativePsbt(NativePsbt &psbt, const NativePsbtContext &context,
                    const NativePsbtKeyLookup &keys,
                    const std::array<uint8_t, 32> &aux_randomness,
                    size_t &signed_slots, std::string &error) {
    signed_slots = 0;
    Prepared prepared;
    if (!Authenticate(psbt, context, prepared, error) ||
        !Review(prepared, context, error))
        return false;
    NativePsbt signed_psbt = psbt;
    size_t added = 0;
    for (size_t i = 0; i < prepared.data.inputs.size(); ++i) {
        const auto &input = prepared.data.inputs[i];
        for (const auto &[slot, request] : input.requests) {
            if (!SupportedRole(prepared, i, slot, request, error)) return false;
            auto present = input.signatures.find(slot);
            if (present != input.signatures.end()) {
                if (!VerifyPartial(prepared, i, slot, request, present->second,
                                   error))
                    return false;
                continue;
            }
            std::array<uint8_t, 32> secret{};
            struct Cleanse {
                std::array<uint8_t, 32> &secret;
                ~Cleanse() { memory_cleanse(secret.data(), secret.size()); }
            } cleanse{secret};
            if (!keys || !keys(request.public_key, secret)) continue;
            Hash message;
            PsbtBytes signature;
            if (!SigningMessage(prepared.signing, i, slot.witness, request.mode,
                                std::nullopt, message, error) ||
                !SignBip340Message(secret, message, request.mode,
                                   aux_randomness, signature, error) ||
                !VerifyPartial(prepared, i, slot, request, signature, error))
                return false;
            signed_psbt.inputs[i][NativePsbtKey(4, EncodePsbtSlot(slot))] =
                std::move(signature);
            ++added;
        }
    }
    NativePsbtData checked;
    if (!signed_psbt.Inspect(checked, error)) return false;
    psbt = std::move(signed_psbt);
    signed_slots = added;
    error.clear();
    return true;
}

bool FinalizeNativePsbt(NativePsbt &psbt, const NativePsbtContext &context,
                        Transaction &extracted, std::string &error) {
    Prepared prepared;
    if (!Authenticate(psbt, context, prepared, error) ||
        !Review(prepared, context, error))
        return false;
    Transaction final_tx = prepared.tx;
    for (size_t i = 0; i < prepared.data.inputs.size(); ++i) {
        const auto &input = prepared.data.inputs[i];
        if (prepared.coins[i].output.legacy_script) {
            return Fail(error,
                        "legacy bridge PSBT finalization is unsupported");
        }
        for (const auto &[slot, request] : input.requests) {
            auto signature = input.signatures.find(slot);
            if (signature == input.signatures.end())
                return Fail(error,
                            "native PSBT is missing a requested signature");
            if (!VerifyPartial(prepared, i, slot, request, signature->second,
                               error))
                return false;
            final_tx.inputs[i]
                .witnesses[slot.witness]
                .arguments[slot.argument] = signature->second;
        }
        for (const auto &[witness, args] : input.final_arguments) {
            if (args != final_tx.inputs[i].witnesses[witness].arguments) {
                return Fail(
                    error,
                    "native PSBT final arguments conflict with declared slots");
            }
        }
    }
    DevelopmentUtxoView view;
    for (const auto &coin : prepared.coins)
        view.emplace(coin.outpoint, coin);
    OrdinaryCandidateEffects effects;
    if (!CheckOrdinaryCandidate(final_tx, context.profile, context.chain_id,
                                view, effects, error))
        return false;
    IdentityDigests original, final_ids;
    if (!ComputeIdentities(prepared.data.tx_template,
                           context.profile.transaction, context.chain_id,
                           original, error) ||
        !ComputeIdentities(final_tx, context.profile.transaction,
                           context.chain_id, final_ids, error) ||
        original.txid != final_ids.txid) {
        return Fail(error,
                    "native PSBT finalization changed transaction identity");
    }
    NativePsbt finalized = psbt;
    for (size_t i = 0; i < final_tx.inputs.size(); ++i) {
        for (size_t w = 0; w < final_tx.inputs[i].witnesses.size(); ++w) {
            finalized
                .inputs[i][NativePsbtKey(5, EncodePsbtWitness(uint16_t(w)))] =
                EncodePsbtArguments(final_tx.inputs[i].witnesses[w].arguments);
        }
    }
    NativePsbtData checked;
    if (!finalized.Inspect(checked, error)) return false;
    psbt = std::move(finalized);
    extracted = std::move(final_tx);
    error.clear();
    return true;
}
} // namespace lotus::v2
