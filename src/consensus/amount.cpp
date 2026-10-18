// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>

#include <univalue.h>

#include <tinyformat.h>

using namespace std::string_view_literals;

// RPCs retain atom precision; a wallet's two-decimal display is a separate UI
// choice. Do not change COIN or any serialized/consensus amount to denominate
// XPI.
static constexpr Currency XPI{1000000 * SATOSHI, SATOSHI, 6, "XPI"sv};

const Currency &Currency::get() {
    return XPI;
}

std::string Amount::ToString() const {
    const auto &currency = Currency::get();
    return strprintf("%d.%0*d %s", *this / currency.baseunit, currency.decimals,
                     (*this % currency.baseunit) / currency.subunit,
                     std::string{currency.ticker});
}

Amount::operator UniValue() const {
    const auto &currency = Currency::get();
    int64_t quotient = *this / currency.baseunit;
    int64_t remainder = (*this % currency.baseunit) / currency.subunit;
    if (amount < 0) {
        quotient = -quotient;
        remainder = -remainder;
    }
    return UniValue(UniValue::VNUM,
                    strprintf("%s%d.%0*d", amount < 0 ? "-" : "", quotient,
                              currency.decimals, remainder));
}

std::optional<Amount> Amount::CheckedAdd(const Amount &other) const noexcept {
    auto result = ::CheckedAdd(this->amount, other.amount);
    if (result.has_value()) {
        return Amount(result.value());
    }
    return std::nullopt;
}

void Amount::SaturatingAdd(const Amount &other) noexcept {
    amount = ::SaturatingAdd(this->amount, other.amount);
}
