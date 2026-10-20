// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <rpc/native_psbt.h>

#include <chain.h>
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <lotus_v2/mempool_overlay.h>
#include <lotus_v2/node_profile.h>
#include <node/context.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <limits>

#include <univalue.h>

namespace rpc {
namespace {
    using namespace lotus::v2;

    [[noreturn]] void DecodeError(const std::string &error) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           "TX decode failed: " + error);
    }

    void CheckNativeBase64Size(const std::string &base64) {
        if (base64.size() > ((MAX_NATIVE_PSBT_BYTES + 2) / 3) * 4) {
            DecodeError("native PSBT exceeds total size limit");
        }
        if (base64.size() % 4 != 0) DecodeError("invalid Base64 length");
        size_t decoded = base64.size() / 4 * 3;
        if (!base64.empty() && base64.back() == '=') --decoded;
        if (base64.size() >= 2 && base64[base64.size() - 2] == '=') --decoded;
        if (decoded > MAX_NATIVE_PSBT_BYTES)
            DecodeError("native PSBT exceeds total size limit");
    }

    // Probe only the global version without allocating decoded transaction or
    // metadata values. Native size limits are enforced before Base64
    // allocation; valid legacy documents retain their existing
    // resource/serialization path.
    class VersionProbe {
        const std::string &text;
        size_t pos{};
        uint32_t accumulator{};
        unsigned bits{};

        bool Byte(uint8_t &result) {
            while (bits < 8) {
                if (pos == text.size()) return false;
                const unsigned char c = text[pos++];
                int digit = c >= 'A' && c <= 'Z'   ? c - 'A'
                            : c >= 'a' && c <= 'z' ? c - 'a' + 26
                            : c >= '0' && c <= '9' ? c - '0' + 52
                            : c == '+'             ? 62
                            : c == '/'             ? 63
                                                   : -1;
                if (digit < 0) return false;
                accumulator = (accumulator << 6) | uint32_t(digit);
                bits += 6;
            }
            bits -= 8;
            result = uint8_t(accumulator >> bits);
            return true;
        }

        bool Integer(size_t width, uint64_t &result) {
            result = 0;
            for (size_t i = 0; i < width; ++i) {
                uint8_t byte;
                if (!Byte(byte)) return false;
                result |= uint64_t(byte) << (8 * i);
            }
            return true;
        }

        bool Compact(uint64_t &result) {
            uint8_t lead;
            if (!Byte(lead)) return false;
            if (lead < 253) {
                result = lead;
                return true;
            }
            const size_t width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
            return Integer(width, result) &&
                   (width == 2   ? result >= 253
                    : width == 4 ? result > 0xffff
                                 : result > 0xffffffff);
        }

        bool Skip(uint64_t count) {
            if (count > text.size()) return false;
            uint8_t byte;
            for (uint64_t i = 0; i < count; ++i)
                if (!Byte(byte)) return false;
            return true;
        }

    public:
        explicit VersionProbe(const std::string &encoded) : text(encoded) {}

        bool Version(uint64_t &version) {
            constexpr std::array<uint8_t, 5> magic{0x70, 0x73, 0x62, 0x74,
                                                   0xff};
            uint8_t byte;
            for (auto expected : magic)
                if (!Byte(byte) || byte != expected) return false;
            bool found = false;
            version = 0;
            while (true) {
                uint64_t key_size, value_size;
                if (!Compact(key_size)) return false;
                if (!key_size) return true;
                if (!Byte(byte) || !Skip(key_size - 1) || !Compact(value_size))
                    return false;
                if (key_size == 1 && byte == 0xfb) {
                    if (found || value_size != 4 || !Integer(4, version))
                        return false;
                    found = true;
                } else if (!Skip(value_size)) {
                    return false;
                }
            }
        }
    };

    UniValue MapJSON(const PsbtMap &map) {
        UniValue result(UniValue::VOBJ);
        for (const auto &[key, value] : map)
            result.pushKV(HexStr(key), HexStr(value));
        return result;
    }

    UniValue MapsJSON(const std::vector<PsbtMap> &maps) {
        UniValue result(UniValue::VARR);
        for (const auto &map : maps)
            result.push_back(MapJSON(map));
        return result;
    }

    UniValue NativeTransactionJSON(const Transaction &tx) {
        UniValue result(UniValue::VOBJ), inputs(UniValue::VARR),
            outputs(UniValue::VARR);
        result.pushKV("version", 7);
        result.pushKV("lock", std::to_string(tx.lock));
        for (const auto &input : tx.inputs) {
            UniValue item(UniValue::VOBJ), witnesses(UniValue::VARR);
            PsbtBytes txid(input.prev_txid.rbegin(), input.prev_txid.rend());
            item.pushKV("txid", HexStr(txid));
            item.pushKV("vout", input.prev_index);
            item.pushKV("sequence", input.sequence);
            item.pushKV("path_index", input.path_index);
            for (const auto &witness : input.witnesses) {
                UniValue branch(UniValue::VOBJ), siblings(UniValue::VARR);
                branch.pushKV("script", HexStr(witness.script));
                for (const auto &hash : witness.siblings)
                    siblings.push_back(HexStr(hash));
                branch.pushKV("siblings", std::move(siblings));
                witnesses.push_back(std::move(branch));
            }
            item.pushKV("witnesses", std::move(witnesses));
            inputs.push_back(std::move(item));
        }
        for (const auto &output : tx.outputs) {
            UniValue item(UniValue::VOBJ), branches(UniValue::VARR),
                paths(UniValue::VARR);
            // Decimal strings preserve all unsigned native atoms for clients
            // whose JSON number implementation uses floating point.
            item.pushKV("value_atoms", std::to_string(output.value));
            item.pushKV("flags", output.flags);
            if (output.HasToken())
                item.pushKV("token_id", HexStr(output.token_id));
            if (output.HasState())
                item.pushKV("state_root", HexStr(output.state_root));
            for (const auto &branch : output.branches)
                branches.push_back(HexStr(branch));
            for (const auto &path : output.paths) {
                UniValue indices(UniValue::VARR);
                for (uint8_t index : path)
                    indices.push_back(index);
                paths.push_back(std::move(indices));
            }
            item.pushKV("branches", std::move(branches));
            item.pushKV("paths", std::move(paths));
            outputs.push_back(std::move(item));
        }
        result.pushKV("vin", std::move(inputs));
        result.pushKV("vout", std::move(outputs));
        return result;
    }
} // namespace

static RPCResult NativePsbtDecodeResult() {
    const RPCResult map_value{RPCResult::Type::STR_HEX, "key",
                              "Exact hexadecimal key/value pair"};
    const RPCResult input_map{
        RPCResult::Type::OBJ_DYN, "", "Native input metadata", {map_value}};
    const RPCResult output_map{
        RPCResult::Type::OBJ_DYN, "", "Native output metadata", {map_value}};
    return RPCResult{
        "For native Lotus PSBTs",
        RPCResult::Type::OBJ,
        "",
        "",
        {{RPCResult::Type::OBJ,
          "tx",
          "Native template; unsigned atom amounts and lock are decimal strings",
          {{RPCResult::Type::ELISION, "",
            "Version, lock, txid, hash, hex, vin and native vout policies"}}},
         {RPCResult::Type::NUM, "psbt_version", "Explicit native PSBT version"},
         {RPCResult::Type::STR_HEX, "chain_id", "Raw ChainID bytes"},
         {RPCResult::Type::OBJ_DYN,
          "global_map",
          "Exact global metadata",
          {map_value}},
         {RPCResult::Type::ARR, "inputs", "", {input_map}},
         {RPCResult::Type::ARR, "outputs", "", {output_map}},
         {RPCResult::Type::STR, "coin_authentication",
          "not_checked; decoding does not authenticate coins"}}};
}

static RPCResult NativePsbtFinalizeResult() {
    return RPCResult{"For native Lotus PSBTs",
                     RPCResult::Type::OBJ,
                     "",
                     "",
                     {{RPCResult::Type::STR, "psbt", true,
                       "Preserved PSBT when not extracted"},
                      {RPCResult::Type::STR_HEX, "hex", true,
                       "Fully validated extracted native wire"},
                      {RPCResult::Type::BOOL, "complete",
                       "All signatures and native validation checks passed"},
                      {RPCResult::Type::STR, "error", true,
                       "Reason validation or completion failed"}}};
}

RPCResults NativePsbtDecodeResults(RPCResult legacy) {
    return RPCResults{std::move(legacy), NativePsbtDecodeResult()};
}

RPCResults NativePsbtFinalizeResults(RPCResult legacy) {
    return RPCResults{std::move(legacy), NativePsbtFinalizeResult()};
}

bool IsNativePsbt(const std::string &base64) {
    uint64_t version = 0;
    if (!VersionProbe(base64).Version(version)) {
        if (version == NATIVE_PSBT_VERSION)
            DecodeError("invalid PSBT global map");
        // Preserve legacy decoder diagnostics for invalid Base64 and v0
        // documents. A recognized native version never falls back.
        return false;
    }
    if (version == 0) return false;
    if (version != NATIVE_PSBT_VERSION) DecodeError("unsupported PSBT version");
    CheckNativeBase64Size(base64);
    return true;
}

NativePsbt DecodeNativePsbtBase64(const std::string &base64) {
    CheckNativeBase64Size(base64);
    auto bytes = DecodeBase64(base64);
    if (!bytes) DecodeError("invalid Base64");
    NativePsbt psbt;
    std::string error;
    if (!DecodeNativePsbt(*bytes, psbt, error)) DecodeError(error);
    return psbt;
}

std::string EncodeNativePsbtBase64(const NativePsbt &psbt) {
    PsbtBytes bytes;
    std::string error;
    if (!psbt.Serialize(bytes, error)) DecodeError(error);
    return EncodeBase64(bytes);
}

NativePsbtContext NativePsbtNodeContext(const JSONRPCRequest &request) {
    auto &chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CBlockIndex *tip = chainman.ActiveChain().Tip();
    if (!tip)
        throw JSONRPCError(RPC_MISC_ERROR,
                           "native PSBT requires an active chain tip");
    bool found = false;
    const auto root = GetV2BlockUtxoRoot(tip->GetBlockHash(), &found);
    if (!found)
        throw JSONRPCError(RPC_MISC_ERROR,
                           "native PSBT authenticated state is unavailable");
    NativePsbtContext context{
        GetActiveV2ChainId(),
        OrdinaryCandidateProfile{
            DefaultTxProfile, NodeV2VmProfile(), NodeV2VmCost(),
            uint64_t(tip->nHeight) + 1, uint64_t(tip->GetMedianTimePast()),
            COINBASE_MATURITY, NodeV2MonetaryProfile().dust_limit,
            std::numeric_limits<VmCostUnits>::max()},
        [root](const Outpoint &outpoint, lotus::v2::Coin &coin, std::string &) {
            auto found_coin = SmtFind(root, outpoint);
            if (!found_coin) return CoinReadResult::Missing;
            coin = *found_coin;
            return CoinReadResult::Found;
        },
        SmtRoot(root), false};
    return context;
}

bool ValidateNativePsbtNode(const JSONRPCRequest &request,
                            const Transaction &tx, std::string &error) {
    auto &chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CTransaction native(CMutableTransaction::FromV2Transaction(tx));
    TxValidationState state;
    Amount fee;
    auto &view = chainman.ActiveChainstate().CoinsTip();
    int sigchecks = 0;
    const PrecomputedTransactionData txdata(native);
    if (!CheckRegularTransaction(native, state) ||
        !Consensus::CheckTxInputs(native, state, view,
                                  chainman.ActiveChain().Height() + 1, fee) ||
        !CheckInputScripts(native, state, view, STANDARD_SCRIPT_VERIFY_FLAGS,
                           false, false, txdata, chainman.m_validation_cache,
                           sigchecks)) {
        error = state.ToString();
        return false;
    }
    return true;
}

UniValue DecodeNativePsbtRPC(const JSONRPCRequest &request) {
    const auto psbt = DecodeNativePsbtBase64(request.params[0].get_str());
    NativePsbtData data;
    std::string error;
    if (!psbt.Inspect(data, error)) DecodeError(error);
    UniValue result(UniValue::VOBJ);
    UniValue tx = NativeTransactionJSON(data.tx_template);
    IdentityDigests identities;
    if (!ComputeIdentities(data.tx_template, DefaultTxProfile, data.chain_id,
                           identities, error))
        DecodeError(error);
    PsbtBytes txid(identities.txid.rbegin(), identities.txid.rend());
    PsbtBytes txhash(identities.txhash.rbegin(), identities.txhash.rend());
    tx.pushKV("txid", HexStr(txid));
    tx.pushKV("hash", HexStr(txhash));
    tx.pushKV("hex", HexStr(psbt.global.at(NativePsbtKey(2))));
    result.pushKV("tx", std::move(tx));
    result.pushKV("psbt_version", NATIVE_PSBT_VERSION);
    result.pushKV("chain_id", HexStr(data.chain_id));
    result.pushKV("global_map", MapJSON(psbt.global));
    result.pushKV("inputs", MapsJSON(psbt.inputs));
    result.pushKV("outputs", MapsJSON(psbt.outputs));
    // Deserialization is transport/schema validity, never authenticated state.
    result.pushKV("coin_authentication", "not_checked");
    return result;
}

UniValue CombineNativePsbtRPC(const JSONRPCRequest &request) {
    const auto &documents = request.params[0].get_array();
    NativePsbt combined = DecodeNativePsbtBase64(documents[0].get_str());
    std::string error;
    for (size_t i = 1; i < documents.size(); ++i) {
        if (!IsNativePsbt(documents[i].get_str())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "cannot combine native and legacy PSBTs");
        }
        const auto psbt = DecodeNativePsbtBase64(documents[i].get_str());
        if (!combined.Merge(psbt, error))
            throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }
    return EncodeNativePsbtBase64(combined);
}

UniValue FinalizeNativePsbtRPC(const JSONRPCRequest &request) {
    auto psbt = DecodeNativePsbtBase64(request.params[0].get_str());
    auto context = NativePsbtNodeContext(request);
    // Extraction verifies existing signatures; it does not authorize new
    // private-key use. The signer enforces explicit partial-mode approval.
    context.allow_partial_modes = true;
    Transaction extracted;
    std::string error;
    const bool complete = FinalizeNativePsbt(psbt, context, extracted, error) &&
                          ValidateNativePsbtNode(request, extracted, error);
    const bool extract =
        request.params[1].isNull() || request.params[1].get_bool();
    UniValue result(UniValue::VOBJ);
    if (complete && extract) {
        PsbtBytes wire;
        if (!EncodeTransaction(extracted, DefaultTxProfile, wire, error))
            DecodeError(error);
        result.pushKV("hex", HexStr(wire));
    } else {
        result.pushKV("psbt", EncodeNativePsbtBase64(psbt));
    }
    result.pushKV("complete", complete);
    if (!complete) result.pushKV("error", error);
    return result;
}

UniValue UpdateNativePsbtRPC(const JSONRPCRequest &request) {
    if (!request.params[1].isNull() && !request.params[1].get_array().empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "native PSBT descriptor import is unsupported");
    }
    auto psbt = DecodeNativePsbtBase64(request.params[0].get_str());
    std::string error;
    if (!UpdateNativePsbt(psbt, NativePsbtNodeContext(request), error)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }
    return EncodeNativePsbtBase64(psbt);
}

std::string ConvertNativePsbtRPC(const CMutableTransaction &tx) {
    NativePsbt psbt;
    std::string error;
    // The creator refuses every nonempty argument vector, including when the
    // legacy permitsigdata override is set. It never guesses signature slots.
    if (!CreateNativePsbt(tx.ToV2Transaction(), GetActiveV2ChainId(), psbt,
                          error)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }
    return EncodeNativePsbtBase64(psbt);
}
} // namespace rpc
