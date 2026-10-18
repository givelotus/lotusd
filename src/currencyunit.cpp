// Copyright (c) 2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <currencyunit.h>

#include <common/args.h>

void SetupCurrencyUnitOptions(ArgsManager &argsman) {
    // Recognize the inherited option solely to provide a clear startup error.
    // V2 has one denomination; XEC/BCHA modes belong to the shared eCash tier.
    argsman.AddArg("-ecash", "Unsupported on Lotus V2; amounts use XPI",
                   ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY,
                   OptionsCategory::OPTIONS);
}
