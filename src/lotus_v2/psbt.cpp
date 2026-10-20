// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "psbt.h"

#include <crypto/ripemd160.h>
#include <crypto/sha256.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <algorithm>
#include <array>
#include <bit>

namespace lotus::v2 {
namespace {
    using namespace psbt_detail;
    constexpr std::array<uint8_t, 5> MAGIC{0x70, 0x73, 0x62, 0x74, 0xff};
    constexpr std::array<uint8_t, 8> IDENTIFIER{'l', 'o', 't', 'u',
                                                's', '-', 'v', '2'};

    bool Fail(std::string &error, const char *message) {
        error = message;
        return false;
    }

    bool Scalar(const Bytes &bytes, size_t width, uint64_t &value) {
        Reader reader(bytes);
        return bytes.size() == width && reader.Integer(width, value);
    }

    bool Count(const Map &map, uint8_t key, uint64_t &value) {
        auto found = map.find({key});
        if (found == map.end()) return false;
        Reader reader(found->second);
        return reader.Compact(value) && reader.Empty();
    }

    bool PublicKey(std::span<const uint8_t> bytes, bool xonly = false) {
        if (xonly) {
            secp256k1_xonly_pubkey pubkey;
            return bytes.size() == 32 &&
                   secp256k1_xonly_pubkey_parse(secp256k1_context_static,
                                                &pubkey, bytes.data());
        }
        secp256k1_pubkey pubkey;
        return (bytes.size() == 33 || bytes.size() == 65) &&
               secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey,
                                         bytes.data(), bytes.size());
    }

    // Validate proprietary framing for every identifier, including unknown
    // ones. Standard keys are reported separately. Other namespaces remain
    // opaque.
    struct Key {
        uint64_t type{};
        bool native{};
        uint64_t subtype{};
        Bytes data;
    };
    bool ParseKey(const Bytes &bytes, Key &key, std::string &error) {
        Reader reader(bytes);
        if (!reader.Compact(key.type))
            return Fail(error, "invalid PSBT key type");
        if (key.type != 0xfc) {
            return reader.Blob(reader.Remaining(), key.data);
        }
        Bytes identifier;
        if (!reader.Vector(MAX_NATIVE_PSBT_KEY_BYTES, identifier) ||
            !reader.Compact(key.subtype)) {
            return Fail(error, "invalid PSBT proprietary key");
        }
        key.native = std::ranges::equal(identifier, IDENTIFIER);
        return reader.Blob(reader.Remaining(), key.data);
    }

    bool Bounds(const Map &map, std::string &error) {
        if (map.size() > MAX_NATIVE_PSBT_MAP_ENTRIES) {
            return Fail(error, "too many PSBT map entries");
        }
        for (const auto &[key, value] : map) {
            if (key.empty() || key.size() > MAX_NATIVE_PSBT_KEY_BYTES ||
                value.size() > MAX_NATIVE_PSBT_VALUE_BYTES) {
                return Fail(error, "PSBT field exceeds profile bounds");
            }
        }
        return true;
    }

    size_t CompactWidth(size_t value) {
        return value < 253           ? 1
               : value <= 0xffff     ? 3
               : value <= 0xffffffff ? 5
                                     : 9;
    }

    bool AddMapSize(const Map &map, size_t &total) {
        if (total >= MAX_NATIVE_PSBT_BYTES) return false;
        ++total; // Separator.
        for (const auto &[key, value] : map) {
            for (size_t bytes : {CompactWidth(key.size()), key.size(),
                                 CompactWidth(value.size()), value.size()}) {
                if (bytes > MAX_NATIVE_PSBT_BYTES - total) return false;
                total += bytes;
            }
        }
        return true;
    }

    bool Arguments(const Bytes &bytes, PsbtArguments &result) {
        Reader reader(bytes);
        uint64_t count;
        if (!reader.Compact(count) || count > DefaultTxProfile.max_arguments ||
            count > reader.Remaining())
            return false;
        PsbtArguments parsed;
        parsed.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            Bytes arg;
            if (!reader.Vector(DefaultTxProfile.max_argument_bytes, arg))
                return false;
            parsed.push_back(std::move(arg));
        }
        if (!reader.Empty()) return false;
        result = std::move(parsed);
        return true;
    }

    bool Origin(const Key &key, const Bytes &value) {
        return key.data.size() == 33 && PublicKey(key.data) &&
               value.size() >= 4 && (value.size() - 4) % 4 == 0 &&
               (value.size() - 4) / 4 <= 255;
    }

    bool IsLegacyP2pkh(const Output &coin) {
        if (!coin.legacy_script) return false;
        const auto &script = *coin.legacy_script;
        return script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
               script[2] == 20 && script[23] == 0x88 && script[24] == 0xac;
    }

    bool IsLegacyP2sh(const Output &coin) {
        if (!coin.legacy_script) return false;
        const auto &script = *coin.legacy_script;
        return script.size() == 23 && script[0] == 0xa9 && script[1] == 20 &&
               script[22] == 0x87;
    }

    bool LegacyP2pkhRole(const Input &input, const Output &coin, PsbtSlot slot,
                         const PsbtSignRequest &request,
                         const PsbtArguments &args) {
        if (!IsLegacyP2pkh(coin) || input.path_index != 0 ||
            input.witnesses.size() != 1 || slot.witness != 0 ||
            slot.argument != 0 || !input.witnesses[0].script.empty() ||
            !input.witnesses[0].siblings.empty() || args.size() != 2 ||
            args[1].size() != 33 || !PublicKey(args[1]) ||
            !std::equal(request.public_key.begin(), request.public_key.end(),
                        args[1].begin() + 1))
            return false;
        std::array<uint8_t, 20> hash;
        std::array<uint8_t, 32> sha;
        CSHA256().Write(args[1].data(), args[1].size()).Finalize(sha.data());
        CRIPEMD160().Write(sha.data(), sha.size()).Finalize(hash.data());
        return std::equal(hash.begin(), hash.end(),
                          coin.legacy_script->begin() + 3);
    }

    bool Proof(const Bytes &bytes, CoinProof &result) {
        Reader reader(bytes);
        Bytes bitmap;
        uint64_t count;
        if (!reader.Blob(32, bitmap) || !reader.Compact(count) || count > 256 ||
            reader.Remaining() != count * 32)
            return false;
        size_t bits = 0;
        for (auto byte : bitmap)
            bits += std::popcount(byte);
        if (count != bits) return false;
        CoinProof parsed;
        parsed.presence = ProofPresence::Present;
        std::copy(bitmap.begin(), bitmap.end(), parsed.bitmap.begin());
        for (size_t i = 0; i < count; ++i) {
            Bytes hash;
            if (!reader.Blob(32, hash)) return false;
            Hash sibling;
            std::copy(hash.begin(), hash.end(), sibling.begin());
            parsed.siblings.push_back(sibling);
        }
        result = std::move(parsed);
        return true;
    }

    bool InputMap(const Map &map, const Input &input, NativePsbtInput &parsed,
                  bool has_root, std::string &error) {
        if (!Bounds(map, error)) return false;
        for (const auto &[raw_key, value] : map) {
            Key key;
            if (!ParseKey(raw_key, key, error)) return false;
            if (key.type != 0xfc)
                return Fail(error, "standard native PSBT input key");
            if (!key.native || key.subtype >= 0x80) continue;
            if (key.subtype == 1) {
                Coin coin;
                if (!key.data.empty() || !DecodeCoinBytes(value, coin) ||
                    coin.outpoint.tx_id != input.prev_txid ||
                    coin.outpoint.index != input.prev_index) {
                    return Fail(error, "invalid PSBT coin or outpoint");
                }
                parsed.coin = std::move(coin);
            } else if (key.subtype == 2 || key.subtype == 5) {
                uint64_t witness;
                PsbtArguments args;
                if (!Scalar(key.data, 2, witness) ||
                    witness >= input.witnesses.size() ||
                    !Arguments(value, args))
                    return Fail(error, "invalid PSBT arguments");
                (key.subtype == 2 ? parsed.arguments : parsed.final_arguments)
                    .emplace(uint16_t(witness), std::move(args));
            } else if (key.subtype == 3 || key.subtype == 4) {
                Reader reader(key.data);
                uint64_t witness, argument;
                if (key.data.size() != 4 || !reader.Integer(2, witness) ||
                    !reader.Integer(2, argument) ||
                    witness >= input.witnesses.size()) {
                    return Fail(error, "invalid PSBT signature slot");
                }
                PsbtSlot slot{uint16_t(witness), uint16_t(argument)};
                if (key.subtype == 4) {
                    parsed.signatures.emplace(slot, value);
                } else {
                    if (value.size() < 2 || value[0] > 2 || value[1] > 2 ||
                        !PublicKey(std::span(value).subspan(2),
                                   value[0] == 0)) {
                        return Fail(error, "invalid PSBT signing request");
                    }
                    parsed.requests.emplace(
                        slot,
                        PsbtSignRequest{value[0], value[1],
                                        Bytes(value.begin() + 2, value.end())});
                }
            } else if (key.subtype == 6) {
                CoinProof proof;
                if (!key.data.empty() || !has_root || !Proof(value, proof)) {
                    return Fail(error, "invalid PSBT coin proof");
                }
                parsed.proof = std::move(proof);
            } else if (key.subtype == 7) {
                if (!Origin(key, value))
                    return Fail(error, "invalid PSBT key origin");
            } else {
                return Fail(error, "unknown critical native PSBT input field");
            }
        }
        for (const auto &[slot, request] : parsed.requests) {
            auto args = parsed.arguments.find(slot.witness);
            if (args == parsed.arguments.end() ||
                slot.argument >= args->second.size() ||
                !args->second[slot.argument].empty()) {
                return Fail(error,
                            "PSBT request requires an empty argument slot");
            }
            if (parsed.coin) {
                const auto &coin = parsed.coin->output;
                if ((request.scheme != 0 && !IsLegacyP2sh(coin)) ||
                    (request.scheme == 0 && coin.legacy_script &&
                     !LegacyP2pkhRole(input, coin, slot, request,
                                      args->second))) {
                    return Fail(
                        error,
                        "PSBT request scheme does not match coin policy");
                }
            }
        }
        for (const auto &[slot, signature] : parsed.signatures) {
            if (!parsed.requests.contains(slot)) {
                return Fail(error, "PSBT signature has no signing request");
            }
            if (signature.empty() || signature.size() > 73) {
                return Fail(error, "invalid PSBT signature size");
            }
            const auto &request = parsed.requests.at(slot);
            if (request.scheme == 0) {
                if (signature.size() != (request.mode == 0 ? 64 : 65) ||
                    (request.mode != 0 && signature.back() != request.mode)) {
                    return Fail(error,
                                "invalid native PSBT signature mode encoding");
                }
            } else {
                constexpr std::array<uint8_t, 3> types{0x41, 0xc1, 0xc3};
                if (signature.back() != types[request.mode] ||
                    (request.scheme == 2 && signature.size() != 65)) {
                    return Fail(
                        error, "invalid legacy PSBT bridge signature encoding");
                }
            }
        }
        if (parsed.proof) {
            if (!parsed.coin)
                return Fail(error, "PSBT proof requires its coin");
            parsed.proof->coin = parsed.coin;
        }
        return true;
    }
} // namespace

PsbtBytes NativePsbtKey(uint64_t subtype, std::span<const uint8_t> keydata) {
    Bytes result{0xfc};
    Vector(IDENTIFIER, result);
    Compact(subtype, result);
    result.insert(result.end(), keydata.begin(), keydata.end());
    return result;
}

PsbtBytes EncodePsbtArguments(const PsbtArguments &arguments) {
    Bytes result;
    Compact(arguments.size(), result);
    for (const auto &arg : arguments)
        Vector(arg, result);
    return result;
}

PsbtBytes EncodePsbtWitness(uint16_t witness) {
    Bytes result;
    Integer(witness, 2, result);
    return result;
}

PsbtBytes EncodePsbtSlot(PsbtSlot slot) {
    Bytes result = EncodePsbtWitness(slot.witness);
    Integer(slot.argument, 2, result);
    return result;
}

bool NativePsbt::Inspect(NativePsbtData &result, std::string &error) const {
    size_t encoded_size = MAGIC.size();
    if (!AddMapSize(global, encoded_size))
        return Fail(error, "native PSBT exceeds total size limit");
    for (const auto &map : inputs) {
        if (!AddMapSize(map, encoded_size))
            return Fail(error, "native PSBT exceeds total size limit");
    }
    for (const auto &map : outputs) {
        if (!AddMapSize(map, encoded_size))
            return Fail(error, "native PSBT exceeds total size limit");
    }
    if (!Bounds(global, error)) return false;
    NativePsbtData parsed;
    uint64_t version{}, in_count{}, out_count{};
    auto version_it = global.find({0xfb});
    if (version_it == global.end() || !Scalar(version_it->second, 4, version) ||
        version != NATIVE_PSBT_VERSION || !Count(global, 4, in_count) ||
        !Count(global, 5, out_count) || in_count == 0 ||
        in_count > MAX_TX_INPUTS || out_count > MAX_TX_OUTPUTS ||
        inputs.size() != in_count || outputs.size() != out_count) {
        return Fail(error, "invalid native PSBT version or counts");
    }
    bool chain = false, tx = false;
    for (const auto &[raw_key, value] : global) {
        Key key;
        if (!ParseKey(raw_key, key, error)) return false;
        if (key.type != 0xfc) {
            if ((key.type != 4 && key.type != 5 && key.type != 0xfb) ||
                !key.data.empty())
                return Fail(error, "standard native PSBT global key");
            continue;
        }
        if (!key.native || key.subtype >= 0x80) continue;
        if (!key.data.empty())
            return Fail(error, "unexpected native PSBT global keydata");
        if (key.subtype == 1 || key.subtype == 3) {
            if (value.size() != 32)
                return Fail(error, "invalid PSBT chain/root width");
            Hash hash;
            std::copy(value.begin(), value.end(), hash.begin());
            if (key.subtype == 1) {
                parsed.chain_id = hash;
                chain = true;
            } else {
                parsed.utxo_root = hash;
            }
        } else if (key.subtype == 2) {
            Bytes roundtrip;
            if (!DecodeTransaction(value, DefaultTxProfile, parsed.tx_template,
                                   error) ||
                !EncodeTransaction(parsed.tx_template, DefaultTxProfile,
                                   roundtrip, error) ||
                value != roundtrip)
                return Fail(error, "invalid native PSBT transaction template");
            for (const auto &input : parsed.tx_template.inputs) {
                if (input.flags != 1 || input.witnesses.size() > 16) {
                    return Fail(error,
                                "native PSBT requires ordinary spend inputs");
                }
                for (const auto &witness : input.witnesses) {
                    if (!witness.arguments.empty())
                        return Fail(error, "PSBT template has arguments");
                }
            }
            tx = true;
        } else {
            return Fail(error, "unknown critical native PSBT global field");
        }
    }
    if (!chain || !tx || parsed.tx_template.inputs.size() != in_count ||
        parsed.tx_template.outputs.size() != out_count) {
        return Fail(error,
                    "missing native PSBT chain/template or mismatched counts");
    }
    parsed.inputs.resize(inputs.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
        if (!InputMap(inputs[i], parsed.tx_template.inputs[i], parsed.inputs[i],
                      parsed.utxo_root.has_value(), error))
            return false;
    }
    for (const auto &map : outputs) {
        if (!Bounds(map, error)) return false;
        for (const auto &[raw_key, value] : map) {
            Key key;
            if (!ParseKey(raw_key, key, error)) return false;
            if (key.type != 0xfc)
                return Fail(error, "standard native PSBT output key");
            if (!key.native || key.subtype >= 0x80) continue;
            if (key.subtype != 1)
                return Fail(error, "unknown critical native PSBT output field");
            if (!Origin(key, value))
                return Fail(error, "invalid PSBT output key origin");
        }
    }
    result = std::move(parsed);
    error.clear();
    return true;
}

bool NativePsbt::Serialize(PsbtBytes &result, std::string &error) const {
    NativePsbtData parsed;
    if (!Inspect(parsed, error)) return false;
    Bytes wire(MAGIC.begin(), MAGIC.end());
    WriteMap(global, wire);
    for (const auto &map : inputs)
        WriteMap(map, wire);
    for (const auto &map : outputs)
        WriteMap(map, wire);
    if (wire.size() > MAX_NATIVE_PSBT_BYTES)
        return Fail(error, "native PSBT exceeds total size limit");
    result = std::move(wire);
    return true;
}

bool DecodeNativePsbt(std::span<const uint8_t> wire, NativePsbt &result,
                      std::string &error) {
    if (wire.size() > MAX_NATIVE_PSBT_BYTES || wire.size() < MAGIC.size() ||
        !std::equal(MAGIC.begin(), MAGIC.end(), wire.begin())) {
        return Fail(error, "invalid native PSBT magic or size");
    }
    Reader reader(wire.subspan(MAGIC.size()));
    NativePsbt parsed;
    auto read_map = [&](Map &map) {
        return reader.ReadMap(map, MAX_NATIVE_PSBT_KEY_BYTES,
                              MAX_NATIVE_PSBT_VALUE_BYTES,
                              MAX_NATIVE_PSBT_MAP_ENTRIES, error);
    };
    uint64_t in_count{}, out_count{};
    if (!read_map(parsed.global)) return false;
    if (!Count(parsed.global, 4, in_count) ||
        !Count(parsed.global, 5, out_count) || in_count == 0 ||
        in_count > MAX_TX_INPUTS || out_count > MAX_TX_OUTPUTS ||
        in_count + out_count > reader.Remaining()) {
        return Fail(error, "invalid native PSBT map counts");
    }
    parsed.inputs.resize(in_count);
    parsed.outputs.resize(out_count);
    for (auto &map : parsed.inputs)
        if (!read_map(map)) return false;
    for (auto &map : parsed.outputs)
        if (!read_map(map)) return false;
    if (!reader.Empty()) return Fail(error, "trailing native PSBT bytes");
    NativePsbtData data;
    if (!parsed.Inspect(data, error)) return false;
    result = std::move(parsed);
    return true;
}

bool CreateNativePsbt(const Transaction &tx_template, const ChainId &chain_id,
                      NativePsbt &result, std::string &error) {
    NativePsbt parsed;
    Bytes wire;
    if (!EncodeTransaction(tx_template, DefaultTxProfile, wire, error))
        return false;
    Integer(NATIVE_PSBT_VERSION, 4, parsed.global[{0xfb}]);
    Compact(tx_template.inputs.size(), parsed.global[{4}]);
    Compact(tx_template.outputs.size(), parsed.global[{5}]);
    parsed.global[NativePsbtKey(1)] = Bytes(chain_id.begin(), chain_id.end());
    parsed.global[NativePsbtKey(2)] = std::move(wire);
    parsed.inputs.resize(tx_template.inputs.size());
    parsed.outputs.resize(tx_template.outputs.size());
    NativePsbtData data;
    if (!parsed.Inspect(data, error)) return false;
    result = std::move(parsed);
    return true;
}

bool NativePsbt::Merge(const NativePsbt &other, std::string &error) {
    NativePsbtData left, right;
    if (!Inspect(left, error) || !other.Inspect(right, error)) return false;
    if (left.chain_id != right.chain_id ||
        global.at(NativePsbtKey(2)) != other.global.at(NativePsbtKey(2))) {
        return Fail(error, "different native PSBT chain or template");
    }
    NativePsbt merged = *this;
    if (!MergeMap(merged.global, other.global, error)) return false;
    for (size_t i = 0; i < inputs.size(); ++i) {
        if (!MergeMap(merged.inputs[i], other.inputs[i], error)) return false;
    }
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (!MergeMap(merged.outputs[i], other.outputs[i], error)) return false;
    }
    if (!merged.Inspect(left, error)) return false;
    *this = std::move(merged);
    return true;
}
} // namespace lotus::v2
