// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token/verify.h>

#include <algorithm>
#include <map>
#include <stdexcept>

namespace chronik::native::token {

std::string BurnError::ToString() const {
    switch (kind) {
        case Kind::TooManyTxInputs:
            return "Too many tx inputs, got " + std::to_string(num_inputs) +
                   " but only " + std::to_string(alp_consts::MAX_TX_INPUTS) +
                   " allowed";
        case Kind::MissingNft1Group:
            return "Invalid NFT1 CHILD GENESIS: No GROUP token";
        case Kind::MissingMintBaton:
            return "Missing MINT baton";
        case Kind::MissingMintVault:
            return "Missing MINT vault";
        case Kind::InsufficientInputSum:
            return "Insufficient token input output sum: " +
                   U128ToString(actual) + " < " + U128ToString(required);
    }
    return {};
}

// ---- TokenTx ----

Token TokenTx::GetToken(const TokenOutput &token_output) const {
    return Token{entries[token_output.token_idx].meta, token_output.variant};
}

SpentToken TokenTx::GetSpentToken(const TokenOutput &token_output) const {
    const auto &entry = entries[token_output.token_idx];
    return SpentToken{Token{entry.meta, token_output.variant},
                      entry.group_token_meta};
}

// ---- Burn summary ----

bool TokenTxEntry::HasUnintentionalBurn() const {
    if (burns_mint_batons) {
        return true;
    }
    if (intentional_burn_atoms) {
        return uint128(*intentional_burn_atoms) != actual_burn_atoms;
    }
    return actual_burn_atoms > 0;
}

bool TokenTxEntry::IsNormal() const {
    if (is_invalid || HasUnintentionalBurn()) {
        return false;
    }
    if (!failed_colorings.empty() || burn_error) {
        return false;
    }
    return true;
}

std::string TokenTxEntry::BurnSummary() const {
    if (IsNormal()) {
        if (intentional_burn_atoms) {
            return "OK: Intentional burn of " +
                   std::to_string(*intentional_burn_atoms) + " atoms";
        }
        return "OK: No burn";
    }
    const bool any_actual_burn = burns_mint_batons || actual_burn_atoms != 0;
    if (!any_actual_burn && (burn_error || !failed_colorings.empty())) {
        std::vector<std::string> parts;
        for (const auto &coloring : failed_colorings) {
            parts.push_back("Invalid coloring at pushdata idx " +
                            std::to_string(coloring.pushdata_idx) + ": " +
                            coloring.error.ToString());
        }
        if (burn_error) {
            parts.push_back("Validation error: " + burn_error->ToString());
        }
        std::string joined;
        for (size_t i = 0; i < parts.size(); ++i) {
            if (i > 0) {
                joined += ". ";
            }
            joined += parts[i];
        }
        return joined;
    }
    std::string s = "Unexpected burn: ";
    if (burns_mint_batons) {
        s += "Burns mint baton(s)";
        if (actual_burn_atoms > 0) {
            s += " and " + U128ToString(actual_burn_atoms) + " atoms";
        }
    } else if (actual_burn_atoms > 0) {
        s += "Burns " + U128ToString(actual_burn_atoms) + " atoms";
    }
    if (intentional_burn_atoms) {
        const Atoms intentional = *intentional_burn_atoms;
        if (actual_burn_atoms > 0) {
            s += ", but intended to burn " + std::to_string(intentional);
            const uint128 intentional128 = intentional;
            if (intentional128 > actual_burn_atoms) {
                s += "; burned " +
                     U128ToString(intentional128 - actual_burn_atoms) +
                     " too few";
            } else {
                s += "; burned " +
                     U128ToString(actual_burn_atoms - intentional128) +
                     " too many";
            }
        } else if (burns_mint_batons) {
            s += "; expected " + std::to_string(intentional) +
                 " atoms to be burned instead";
        } else {
            s += "Expected " + std::to_string(intentional) +
                 " atoms to be burned, but none found";
        }
    }
    if (failed_colorings.empty() && !burn_error) {
        return s;
    }
    s += ". Reason(s):";
    for (const auto &coloring : failed_colorings) {
        s += " Invalid coloring at pushdata idx " +
             std::to_string(coloring.pushdata_idx) + ": " +
             coloring.error.ToString() + ".";
    }
    if (burn_error) {
        s += ' ';
        s += burn_error->ToString();
    }
    return s;
}

// ---- Verification ----

namespace {

struct BareBurn {
    uint128 burn_atoms{};
    bool burns_mint_batons = false;
    std::optional<TokenMeta> group_token_meta;
    bool is_invalid = false;
};

TokenTxEntry MakeEntry(const TokenMeta &meta) {
    TokenTxEntry entry;
    entry.meta = meta;
    return entry;
}

} // namespace

TokenTx VerifyContext::Verify(ColoredTx tx) const {
    std::vector<TokenTxEntry> entries;
    for (const auto &section : tx.sections) {
        entries.push_back(VerifySection(tx, section));
    }

    for (const auto &intentional_burn : tx.intentional_burns) {
        const bool found =
            std::any_of(entries.begin(), entries.end(), [&](const auto &e) {
                return e.meta.token_id == intentional_burn.meta.token_id;
            });
        if (!found) {
            TokenTxEntry entry = MakeEntry(intentional_burn.meta);
            entry.tx_type = TxType::BURN;
            entry.intentional_burn_atoms = intentional_burn.atoms;
            entries.push_back(std::move(entry));
        }
    }

    // calc_bare_burns (BTreeMap keyed by TokenMeta, i.e. sorted)
    std::map<TokenMeta, BareBurn> bare_burns;
    for (size_t input_idx = 0; input_idx < spent_tokens.size(); ++input_idx) {
        const auto &input = spent_tokens[input_idx];
        if (!input) {
            continue;
        }
        const bool in_sections =
            std::any_of(tx.sections.begin(), tx.sections.end(),
                        [&](const auto &section) {
                            return section.meta == input->token.meta;
                        });
        if (in_sections) {
            continue;
        }
        auto [it, inserted] = bare_burns.try_emplace(
            input->token.meta,
            BareBurn{0, false, input->group_token_meta, false});
        BareBurn &bare_burn = it->second;

        if (input_idx == 0 && !entries.empty()) {
            const auto &first_entry = entries.front();
            if (first_entry.meta.token_type ==
                    TokenType::Slp(SlpTokenType::Nft1Child()) &&
                first_entry.tx_type == TxType::GENESIS &&
                !first_entry.is_invalid) {
                continue;
            }
        }

        bare_burn.is_invalid = true;
        switch (input->token.variant.kind) {
            case TokenVariant::Kind::Atoms:
                bare_burn.burn_atoms += input->token.variant.atoms_value;
                break;
            case TokenVariant::Kind::MintBaton:
                bare_burn.burns_mint_batons = true;
                break;
            case TokenVariant::Kind::Unknown:
                break;
        }
    }

    for (auto &failed_coloring : tx.failed_colorings) {
        auto it = std::find_if(entries.begin(), entries.end(),
                               [&](const auto &entry) {
                                   return entry.meta ==
                                          failed_coloring.parsed.meta;
                               });
        if (it != entries.end()) {
            it->failed_colorings.push_back(std::move(failed_coloring));
            continue;
        }
        TokenTxEntry entry = MakeEntry(failed_coloring.parsed.meta);
        entry.tx_type = failed_coloring.parsed.tx_type.tx_type();
        if (const auto *genesis = failed_coloring.parsed.tx_type.genesis()) {
            entry.genesis_info = genesis->info;
        }
        entry.is_invalid = true;
        entry.failed_colorings.push_back(std::move(failed_coloring));
        entries.push_back(std::move(entry));
    }

    for (const auto &[burn_meta, bare_burn] : bare_burns) {
        auto it = std::find_if(
            entries.begin(), entries.end(),
            [&](const auto &entry) { return entry.meta == burn_meta; });
        if (it != entries.end()) {
            if (bare_burn.burns_mint_batons) {
                it->is_invalid = true;
            }
            it->actual_burn_atoms = bare_burn.burn_atoms;
            it->burns_mint_batons = bare_burn.burns_mint_batons;
            it->group_token_meta = bare_burn.group_token_meta;
            continue;
        }
        TokenTxEntry entry = MakeEntry(burn_meta);
        entry.group_token_meta = bare_burn.group_token_meta;
        entry.is_invalid = bare_burn.is_invalid;
        entry.actual_burn_atoms = bare_burn.burn_atoms;
        entry.burns_mint_batons = bare_burn.burns_mint_batons;
        entries.push_back(std::move(entry));
    }

    std::vector<std::optional<TokenOutput>> outputs;
    outputs.reserve(tx.outputs.size());
    for (auto &output : tx.outputs) {
        if (!output || entries[output->token_idx].is_invalid) {
            outputs.push_back(std::nullopt);
        } else {
            outputs.push_back(output);
        }
    }
    return TokenTx{std::move(entries), std::move(outputs),
                   std::move(tx.failed_parsings)};
}

TokenTxEntry VerifyContext::VerifySection(const ColoredTx &tx,
                                          const ColoredTxSection &section) const {
    const uint128 input_sum = CalcInputSum(section.meta);

    TokenTxEntry entry = MakeEntry(section.meta);
    entry.tx_type = section.tx_type;
    entry.genesis_info = section.genesis_info;
    entry.group_token_meta = InheritedGroupTokenMeta(section.meta);
    entry.intentional_burn_atoms = IntentionalBurnAtoms(tx, section.meta);
    entry.has_colored_out_of_range = section.has_colored_out_of_range;

    if (section.meta.token_type.IsAlp() &&
        spent_tokens.size() > alp_consts::MAX_TX_INPUTS) {
        entry.is_invalid = true;
        entry.actual_burn_atoms = input_sum;
        entry.burns_mint_batons = HasMintBaton(section.meta);
        entry.burn_error = BurnError::TooManyTxInputs(spent_tokens.size());
        return entry;
    }

    switch (section.tx_type) {
        case TxType::GENESIS:
            if (section.meta.token_type ==
                TokenType::Slp(SlpTokenType::Nft1Child())) {
                if (!spent_tokens.empty() && spent_tokens[0] &&
                    spent_tokens[0]->token.meta.token_type ==
                        TokenType::Slp(SlpTokenType::Nft1Group()) &&
                    spent_tokens[0]->token.variant.atoms() > 0) {
                    entry.group_token_meta = spent_tokens[0]->token.meta;
                } else {
                    entry.is_invalid = true;
                    entry.burn_error = BurnError::MissingNft1Group();
                }
            }
            return entry;
        case TxType::MINT:
            entry.actual_burn_atoms = input_sum;
            if (section.IsMintVaultMint()) {
                if (!HasMintVault()) {
                    entry.is_invalid = true;
                    entry.burn_error = BurnError::MissingMintVault();
                }
                return entry;
            }
            if (!HasMintBaton(section.meta)) {
                entry.is_invalid = true;
                entry.burn_error = BurnError::MissingMintBaton();
            }
            return entry;
        case TxType::SEND:
            if (input_sum < section.required_input_sum) {
                entry.is_invalid = true;
                entry.actual_burn_atoms = input_sum;
                entry.burns_mint_batons = HasMintBaton(section.meta);
                entry.burn_error = BurnError::InsufficientInputSum(
                    section.required_input_sum, input_sum);
                return entry;
            }
            entry.actual_burn_atoms =
                input_sum - CalcOutputSum(tx, section.meta);
            entry.burns_mint_batons = HasMintBaton(section.meta);
            return entry;
        case TxType::UNKNOWN:
            return entry;
        case TxType::BURN:
            break;
    }
    throw std::logic_error(
        "BURNs are only in intentional_burns, not in sections");
}

bool VerifyContext::HasMintBaton(const TokenMeta &meta) const {
    return std::any_of(spent_tokens.begin(), spent_tokens.end(),
                       [&](const auto &spent) {
                           return spent && spent->token.meta == meta &&
                                  spent->token.variant.IsMintBaton();
                       });
}

bool VerifyContext::HasMintVault() const {
    if (override_has_mint_vault) {
        return *override_has_mint_vault;
    }
    if (!spent_scripts) {
        throw std::logic_error(
            "VerifyContext used incorrectly; spent_scripts must be present "
            "for SLP V2 Mint Vault token types");
    }
    if (!genesis_info || !genesis_info->mint_vault_scripthash) {
        return false;
    }
    const script::Script script =
        script::Script::P2sh(*genesis_info->mint_vault_scripthash);
    return std::any_of(spent_scripts->begin(), spent_scripts->end(),
                       [&](const auto &s) { return s == script; });
}

uint128 VerifyContext::CalcInputSum(const TokenMeta &meta) const {
    uint128 sum = 0;
    for (const auto &spent : spent_tokens) {
        if (spent && spent->token.meta == meta) {
            sum += spent->token.variant.atoms();
        }
    }
    return sum;
}

uint128 VerifyContext::CalcOutputSum(const ColoredTx &tx,
                                     const TokenMeta &meta) const {
    uint128 sum = 0;
    for (const auto &output : tx.outputs) {
        if (output && tx.sections[output->token_idx].meta == meta) {
            sum += output->variant.atoms();
        }
    }
    return sum;
}

std::optional<TokenMeta>
VerifyContext::InheritedGroupTokenMeta(const TokenMeta &meta) const {
    for (const auto &spent : spent_tokens) {
        if (spent && spent->token.meta == meta) {
            return spent->group_token_meta;
        }
    }
    return std::nullopt;
}

std::optional<Atoms>
VerifyContext::IntentionalBurnAtoms(const ColoredTx &tx,
                                    const TokenMeta &meta) const {
    for (const auto &burn : tx.intentional_burns) {
        if (burn.meta == meta) {
            return burn.atoms;
        }
    }
    return std::nullopt;
}

} // namespace chronik::native::token
