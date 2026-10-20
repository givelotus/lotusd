// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <wallet/rpc/native_psbt.h>

#include <interfaces/chain.h>
#include <key.h>
#include <random.h>
#include <rpc/native_psbt.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <support/cleanse.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <array>

#include <univalue.h>

UniValue WalletProcessNativePsbtRPC(const JSONRPCRequest &request,
                                    const CWallet &wallet) {
    using namespace lotus::v2;
    auto psbt = rpc::DecodeNativePsbtBase64(request.params[0].get_str());
    // Wallet RPC requests carry WalletContext rather than NodeContext.
    // Resolve the wallet's in-process chain before using node validation.
    auto *node = wallet.chain().context();
    if (!node) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "native PSBT requires an in-process node chain");
    }
    JSONRPCRequest node_request = request;
    node_request.context = node;
    auto context = rpc::NativePsbtNodeContext(node_request);
    const bool sign =
        request.params[1].isNull() || request.params[1].get_bool();
    const bool finalize =
        request.params[4].isNull() || request.params[4].get_bool();
    std::string error;
    if (!UpdateNativePsbt(psbt, context, error)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }
    if (!request.params[2].isNull()) {
        const std::string scope = request.params[2].get_str();
        uint8_t mode;
        if (scope == "DEFAULT")
            mode = 0;
        else if (scope == "OWN_INPUT_ALL_OUTPUTS")
            mode = 1;
        else if (scope == "OWN_INPUT_PAIRED_OUTPUT")
            mode = 2;
        else
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "native PSBT sighashtype must be DEFAULT, "
                "OWN_INPUT_ALL_OUTPUTS or OWN_INPUT_PAIRED_OUTPUT");
        NativePsbtData data;
        if (!psbt.Inspect(data, error))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, error);
        for (const auto &input : data.inputs) {
            for (const auto &[slot, signing] : input.requests) {
                (void)slot;
                if (signing.mode != mode) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       "native PSBT request scope differs from "
                                       "explicit authorization");
                }
            }
        }
        context.allow_partial_modes = mode != 0;
    }

    size_t slots = 0;
    if (!sign && request.params[2].isNull()) context.allow_partial_modes = true;
    if (sign) {
        EnsureWalletIsUnlocked(&wallet);
        LOCK(wallet.cs_wallet);
        auto manager = wallet.GetLegacyScriptPubKeyMan();
        if (!manager) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "native PSBT key lookup currently requires a "
                               "legacy key-store wallet");
        }
        NativePsbtKeyLookup keys = [manager](std::span<const uint8_t> xonly,
                                             std::array<uint8_t, 32> &secret) {
            // Try both SEC parities. The x-only policy and BIP340 helper
            // verify the key relation and apply scalar normalization.
            for (uint8_t parity : {2, 3}) {
                std::vector<uint8_t> encoded{parity};
                encoded.insert(encoded.end(), xonly.begin(), xonly.end());
                const CPubKey public_key(encoded);
                CKey key;
                if (manager->GetKey(public_key.GetID(), key)) {
                    std::copy(key.begin(), key.end(), secret.begin());
                    return true;
                }
            }
            return false;
        };
        std::array<uint8_t, 32> aux;
        GetStrongRandBytes(aux);
        if (!SignNativePsbt(psbt, context, keys, aux, slots, error)) {
            throw JSONRPCError(RPC_WALLET_ERROR, error);
        }
    }
    Transaction extracted;
    // Check completeness even when cleanup/final marker insertion is not
    // requested, matching the existing walletprocesspsbt contract.
    auto checked = psbt;
    const bool complete =
        FinalizeNativePsbt(checked, context, extracted, error) &&
        rpc::ValidateNativePsbtNode(node_request, extracted, error);
    if (complete && finalize) psbt = std::move(checked);
    UniValue result(UniValue::VOBJ);
    result.pushKV("psbt", rpc::EncodeNativePsbtBase64(psbt));
    result.pushKV("complete", complete);
    result.pushKV("signed_slots", slots);
    if (!complete) result.pushKV("error", error);
    return result;
}
