// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token/structs.h>

#include <algorithm>

namespace chronik::native::token {

std::string U128ToString(uint128 v) {
    if (v == 0) {
        return "0";
    }
    std::string s;
    while (v > 0) {
        s.push_back(char('0' + int(v % 10)));
        v /= 10;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

std::string TokenId::ToString() const {
    const auto be = txid.Reversed();
    return script::HexEncode(be);
}

uint8_t SlpTokenType::ToU8() const {
    switch (kind) {
        case Kind::Fungible:
            return slp_consts::TOKEN_TYPE_V1;
        case Kind::MintVault:
            return slp_consts::TOKEN_TYPE_V2;
        case Kind::Nft1Group:
            return slp_consts::TOKEN_TYPE_V1_NFT1_GROUP;
        case Kind::Nft1Child:
            return slp_consts::TOKEN_TYPE_V1_NFT1_CHILD;
        case Kind::Unknown:
            return unknown;
    }
    return unknown;
}

std::string SlpTokenType::ToString() const {
    switch (kind) {
        case Kind::Fungible:
            return "FUNGIBLE (V1)";
        case Kind::MintVault:
            return "MINT VAULT (V2)";
        case Kind::Nft1Group:
            return "NFT1 GROUP";
        case Kind::Nft1Child:
            return "NFT1 CHILD";
        case Kind::Unknown:
            return "UNKNOWN (" + std::to_string(unknown) + ")";
    }
    return {};
}

uint8_t AlpTokenType::ToU8() const {
    return kind == Kind::Standard ? alp_consts::STANDARD_TOKEN_TYPE : unknown;
}

std::string AlpTokenType::ToString() const {
    if (kind == Kind::Standard) {
        return "STANDARD (V0)";
    }
    return "UNKNOWN (" + std::to_string(unknown) + ")";
}

std::string TokenType::ToString() const {
    if (IsSlp()) {
        return "SLP " + slp.ToString();
    }
    return "ALP " + alp.ToString();
}

std::string Token::ToString() const {
    std::string s;
    switch (variant.kind) {
        case TokenVariant::Kind::Atoms:
            s = std::to_string(variant.atoms_value);
            break;
        case TokenVariant::Kind::MintBaton:
            s = "Mint baton";
            break;
        case TokenVariant::Kind::Unknown:
            return meta.token_type.ToString();
    }
    return s + " of " + meta.token_id.ToString() + " (" +
           meta.token_type.ToString() + ")";
}

TxType ParsedTxType::tx_type() const {
    switch (v.index()) {
        case 0:
            return TxType::GENESIS;
        case 1:
            return TxType::MINT;
        case 2:
            return TxType::SEND;
        case 3:
            return TxType::BURN;
        default:
            return TxType::UNKNOWN;
    }
}

} // namespace chronik::native::token
