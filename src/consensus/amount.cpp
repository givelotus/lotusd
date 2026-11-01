// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>

#include <common/args.h>
#include <currencyunit.h>
#include <univalue.h>

#include <tinyformat.h>

#include <charconv>

#include <atomic>

using namespace std::string_view_literals;

static constexpr Currency BCHA{COIN, SATOSHI, 8, "BCHA"sv};
static constexpr Currency XEC{100 * SATOSHI, SATOSHI, 2, "XEC"sv};

static_assert(BCHA.baseunit > 1 * SATOSHI,
              "BCHA base unit must be greater than 1 satoshi");
static_assert(XEC.baseunit > 1 * SATOSHI,
              "XEC base unit must be greater than 1 satoshi");

//! -1 until SetECash() is called, then 0 (BCHA) or 1 (XEC)
static std::atomic<int> g_ecash{-1};

void Currency::SetECash(bool ecash) {
    g_ecash.store(ecash ? 1 : 0, std::memory_order_relaxed);
}

const Currency &Currency::get() {
    const int ecash{g_ecash.load(std::memory_order_relaxed)};
    if (ecash >= 0) {
        return ecash ? XEC : BCHA;
    }
    return gArgs.GetBoolArg("-ecash", DEFAULT_ECASH) ? XEC : BCHA;
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
    // Verbose mempool RPCs format several of these per transaction.
    char buf[64];
    char *p = buf;
    if (amount < 0) {
        *p++ = '-';
        quotient = -quotient;
        remainder = -remainder;
    }
    p = std::to_chars(p, buf + sizeof(buf), quotient).ptr;
    *p++ = '.';
    if (currency.decimals == 0) {
        // Nothing in the fraction, but it has always been printed.
        *p++ = '0';
    }
    for (int i = currency.decimals - 1; i >= 0; --i) {
        p[i] = static_cast<char>('0' + (remainder % 10));
        remainder /= 10;
    }
    p += currency.decimals;
    return UniValue(UniValue::VNUM,
                    std::string(buf, static_cast<size_t>(p - buf)));
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
