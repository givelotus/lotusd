// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token/color.h>

namespace chronik::native::token {

using CK = ColorError::Kind;

std::string ColorParseError::ToString() const {
    switch (v.index()) {
        case 0:
            return "eMPP error: " + std::get<0>(v).ToString();
        case 1:
            return "SLP error: " + std::get<1>(v).ToString();
        default:
            return "ALP error: " + std::get<2>(v).ToString();
    }
}

std::string FailedParsing::ToString() const {
    std::string s = "Parsing failed";
    if (pushdata_idx) {
        s += " at pushdata idx " + std::to_string(*pushdata_idx);
    }
    return s + ": " + error.ToString();
}

ColorError ColorError::TooFewOutputs(size_t expected, size_t actual) {
    ColorError e;
    e.kind = CK::TooFewOutputs;
    e.expected = expected;
    e.actual = actual;
    return e;
}
ColorError ColorError::GenesisMustBeFirst() {
    ColorError e;
    e.kind = CK::GenesisMustBeFirst;
    return e;
}
ColorError ColorError::DescendingTokenType(uint8_t before, uint8_t after) {
    ColorError e;
    e.kind = CK::DescendingTokenType;
    e.before = before;
    e.after = after;
    return e;
}
ColorError ColorError::DuplicateTokenId(size_t prev_section_idx,
                                        TokenId token_id) {
    ColorError e;
    e.kind = CK::DuplicateTokenId;
    e.prev_section_idx = prev_section_idx;
    e.token_id = token_id;
    return e;
}
ColorError ColorError::DuplicateIntentionalBurnTokenId(size_t prev_burn_idx,
                                                       size_t burn_idx,
                                                       TokenId token_id) {
    ColorError e;
    e.kind = CK::DuplicateIntentionalBurnTokenId;
    e.prev_burn_idx = prev_burn_idx;
    e.burn_idx = burn_idx;
    e.token_id = token_id;
    return e;
}
ColorError ColorError::OverlappingAtoms(Token prev_token, size_t output_idx,
                                        Atoms atoms) {
    ColorError e;
    e.kind = CK::OverlappingAtoms;
    e.prev_token = std::move(prev_token);
    e.output_idx = output_idx;
    e.atoms = atoms;
    return e;
}
ColorError ColorError::OverlappingMintBaton(Token prev_token,
                                            size_t output_idx) {
    ColorError e;
    e.kind = CK::OverlappingMintBaton;
    e.prev_token = std::move(prev_token);
    e.output_idx = output_idx;
    return e;
}

std::string ColorError::ToString() const {
    switch (kind) {
        case CK::TooFewOutputs:
            return "Too few outputs, expected " + std::to_string(expected) +
                   " but got " + std::to_string(actual);
        case CK::GenesisMustBeFirst:
            return "GENESIS must be the first pushdata";
        case CK::DescendingTokenType:
            return "Descending token type: " + std::to_string(before) +
                   " > " + std::to_string(after) +
                   ", token types must be in ascending order";
        case CK::DuplicateTokenId:
            return "Duplicate token_id " + token_id.ToString() +
                   ", found in section " + std::to_string(prev_section_idx);
        case CK::DuplicateIntentionalBurnTokenId:
            return "Duplicate intentional burn token_id " +
                   token_id.ToString() + ", found in burn #" +
                   std::to_string(prev_burn_idx) + " and #" +
                   std::to_string(burn_idx);
        case CK::OverlappingAtoms:
            return "Overlapping atoms when trying to color " +
                   std::to_string(atoms) + " at index " +
                   std::to_string(output_idx) +
                   ", output is already colored with " +
                   (prev_token ? prev_token->ToString() : std::string());
        case CK::OverlappingMintBaton:
            return "Overlapping mint baton when trying to color mint baton "
                   "at index " +
                   std::to_string(output_idx) +
                   ", output is already colored with " +
                   (prev_token ? prev_token->ToString() : std::string());
    }
    return {};
}

bool ColoredTxSection::IsMintVaultMint() const {
    if (tx_type != TxType::MINT) {
        return false;
    }
    return meta.token_type == TokenType::Slp(SlpTokenType::MintVault());
}

std::optional<ColoredTx> ColoredTx::ColorTx(const Tx &tx) {
    if (tx.outputs.empty()) {
        return std::nullopt;
    }
    const Bytes &op_return = tx.outputs[0].script;
    if (op_return.empty() || op_return[0] != script::OP_RETURN.n) {
        return std::nullopt;
    }
    ColoredTx colored;
    colored.outputs.resize(tx.outputs.size());

    auto slp_result = slp::Parse(tx.txid, op_return);
    if (slp_result.ok()) {
        if (slp_result.value()) {
            uint8_t max_token_type = 0;
            auto err = colored.ColorSection(0, *slp_result.value(),
                                            max_token_type);
            if (err) {
                throw std::logic_error("Coloring SLP always succeeds");
            }
            return colored;
        }
    } else {
        colored.failed_parsings.push_back(FailedParsing{
            std::nullopt, op_return, ColorParseError{slp_result.error()}});
        return colored;
    }

    auto empp_result = empp::Parse(op_return);
    if (!empp_result.ok()) {
        colored.failed_parsings.push_back(FailedParsing{
            std::nullopt, op_return, ColorParseError{empp_result.error()}});
        return colored;
    }
    if (!empp_result.value()) {
        return std::nullopt;
    }

    if (colored.ColorAllAlpPushdata(std::move(*empp_result.value()),
                                    tx.txid)) {
        return colored;
    }
    return std::nullopt;
}

bool ColoredTx::ColorAllAlpPushdata(std::vector<Bytes> pushdata,
                                    const TxId &txid) {
    uint8_t max_token_type = 0;
    bool has_any_alp = false;
    for (size_t pushdata_idx = 0; pushdata_idx < pushdata.size();
         ++pushdata_idx) {
        Bytes &data = pushdata[pushdata_idx];
        auto parsed = alp::ParseSection(txid, data);
        if (!parsed.ok()) {
            failed_parsings.push_back(FailedParsing{
                pushdata_idx, std::move(data), ColorParseError{parsed.error()}});
            has_any_alp = true;
            continue;
        }
        if (!parsed.value()) {
            continue;
        }
        has_any_alp = true;
        auto err = ColorSection(pushdata_idx, *parsed.value(), max_token_type);
        if (err) {
            failed_colorings.push_back(FailedColoring{
                pushdata_idx, std::move(*parsed.value()), std::move(*err)});
        }
    }
    return has_any_alp;
}

std::optional<ColorError> ColoredTx::ColorSection(size_t pushdata_idx,
                                                  const ParsedData &parsed,
                                                  uint8_t &max_token_type) {
    const TokenMeta &meta = parsed.meta;
    if (max_token_type > meta.token_type.ToU8()) {
        return ColorError::DescendingTokenType(max_token_type,
                                               meta.token_type.ToU8());
    }
    max_token_type = meta.token_type.ToU8();

    const TxType tx_type = parsed.tx_type.tx_type();
    if (tx_type == TxType::MINT || tx_type == TxType::SEND) {
        for (size_t prev_section_idx = 0; prev_section_idx < sections.size();
             ++prev_section_idx) {
            if (sections[prev_section_idx].meta.token_id == meta.token_id) {
                return ColorError::DuplicateTokenId(prev_section_idx,
                                                    meta.token_id);
            }
        }
    }

    const auto &v = parsed.tx_type.v;
    switch (v.index()) {
        case 0:
            return ColorGenesis(pushdata_idx, meta, std::get<0>(v));
        case 1:
            return ColorMint(meta, std::get<1>(v));
        case 2:
            return ColorSend(meta, std::get<2>(v).atoms);
        case 3:
            return ColorBurn(meta, std::get<3>(v).atoms);
        default:
            return ColorUnknown(meta);
    }
}

std::optional<ColorError>
ColoredTx::ColorGenesis(size_t pushdata_idx, const TokenMeta &meta,
                        const ParsedGenesis &genesis) {
    if (pushdata_idx != 0) {
        return ColorError::GenesisMustBeFirst();
    }
    auto has_colored_out_of_range = ColorMintData(meta, genesis.mint_data);
    if (!has_colored_out_of_range) {
        return has_colored_out_of_range.error();
    }
    sections.push_back(ColoredTxSection{meta, TxType::GENESIS, 0,
                                        has_colored_out_of_range.value(),
                                        genesis.info});
    return std::nullopt;
}

std::optional<ColorError> ColoredTx::ColorMint(const TokenMeta &meta,
                                               const ParsedMintData &mint) {
    auto has_colored_out_of_range = ColorMintData(meta, mint);
    if (!has_colored_out_of_range) {
        return has_colored_out_of_range.error();
    }
    sections.push_back(ColoredTxSection{meta, TxType::MINT, 0,
                                        has_colored_out_of_range.value(),
                                        std::nullopt});
    return std::nullopt;
}

Result<bool, ColorError>
ColoredTx::ColorMintData(const TokenMeta &meta,
                         const ParsedMintData &mint_data) {
    const size_t token_idx = sections.size();

    std::optional<size_t> out_of_range_idx;
    for (size_t i = 0; i < mint_data.atoms_vec.size(); ++i) {
        const size_t output_idx = mint_data.AtomsBegin() + i;
        const Atoms atoms = mint_data.atoms_vec[i];
        if (atoms != 0) {
            if (output_idx < outputs.size()) {
                if (outputs[output_idx]) {
                    return Err(ColorError::OverlappingAtoms(
                        GetToken(*outputs[output_idx]), output_idx, atoms));
                }
            } else {
                out_of_range_idx = output_idx;
            }
        }
    }
    for (size_t output_idx = mint_data.BatonsBegin();
         output_idx < mint_data.BatonsEnd(); ++output_idx) {
        if (output_idx < outputs.size()) {
            if (outputs[output_idx]) {
                return Err(ColorError::OverlappingMintBaton(
                    GetToken(*outputs[output_idx]), output_idx));
            }
        } else {
            out_of_range_idx = output_idx;
        }
    }

    if (out_of_range_idx && meta.token_type.IsAlp()) {
        return Err(
            ColorError::TooFewOutputs(*out_of_range_idx + 1, outputs.size()));
    }

    for (size_t i = 0; i < mint_data.atoms_vec.size(); ++i) {
        const size_t output_idx = mint_data.AtomsBegin() + i;
        if (output_idx >= outputs.size()) {
            break;
        }
        const Atoms atoms = mint_data.atoms_vec[i];
        if (atoms > 0) {
            outputs[output_idx] =
                TokenOutput{token_idx, TokenVariant::MakeAtoms(atoms)};
        }
    }
    for (size_t output_idx = mint_data.BatonsBegin();
         output_idx < mint_data.BatonsEnd(); ++output_idx) {
        if (output_idx >= outputs.size()) {
            break;
        }
        outputs[output_idx] = TokenOutput{token_idx, TokenVariant::MintBaton()};
    }
    return out_of_range_idx.has_value();
}

std::optional<ColorError>
ColoredTx::ColorSend(const TokenMeta &meta, const std::vector<Atoms> &atoms) {
    std::optional<size_t> out_of_range_idx;
    for (size_t idx = 0; idx < atoms.size(); ++idx) {
        if (atoms[idx] != 0) {
            const size_t output_idx = idx + 1;
            if (output_idx < outputs.size()) {
                if (outputs[output_idx]) {
                    return ColorError::OverlappingAtoms(
                        GetToken(*outputs[output_idx]), output_idx,
                        atoms[idx]);
                }
            } else {
                out_of_range_idx = output_idx;
            }
        }
    }

    if (out_of_range_idx && meta.token_type.IsAlp()) {
        return ColorError::TooFewOutputs(*out_of_range_idx + 1,
                                         outputs.size());
    }

    uint128 required_input_sum = 0;
    for (size_t idx = 0; idx < atoms.size(); ++idx) {
        if (atoms[idx] == 0) {
            continue;
        }
        required_input_sum += atoms[idx];
        if (idx + 1 < outputs.size()) {
            outputs[idx + 1] = TokenOutput{sections.size(),
                                           TokenVariant::MakeAtoms(atoms[idx])};
        }
    }

    sections.push_back(ColoredTxSection{meta, TxType::SEND, required_input_sum,
                                        out_of_range_idx.has_value(),
                                        std::nullopt});
    return std::nullopt;
}

std::optional<ColorError> ColoredTx::ColorBurn(const TokenMeta &meta,
                                               Atoms atoms) {
    for (size_t prev_burn_idx = 0; prev_burn_idx < intentional_burns.size();
         ++prev_burn_idx) {
        if (intentional_burns[prev_burn_idx].meta.token_id == meta.token_id) {
            return ColorError::DuplicateIntentionalBurnTokenId(
                prev_burn_idx, intentional_burns.size(), meta.token_id);
        }
    }
    intentional_burns.push_back(IntentionalBurn{meta, atoms});
    return std::nullopt;
}

std::optional<ColorError> ColoredTx::ColorUnknown(const TokenMeta &meta) {
    for (size_t i = 1; i < outputs.size(); ++i) {
        if (!outputs[i]) {
            outputs[i] = TokenOutput{
                sections.size(),
                TokenVariant::Unknown(meta.token_type.ToU8())};
        }
    }
    sections.push_back(ColoredTxSection{meta, TxType::UNKNOWN, 0, false,
                                        std::nullopt});
    return std::nullopt;
}

Token ColoredTx::GetToken(const TokenOutput &token_output) const {
    const auto &section = sections[token_output.token_idx];
    return Token{section.meta, token_output.variant};
}

} // namespace chronik::native::token
