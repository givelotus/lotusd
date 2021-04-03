// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_FLAGS_H
#define BITCOIN_SCRIPT_SCRIPT_FLAGS_H

/** Script verification flags */
enum {
    SCRIPT_VERIFY_NONE = 0,

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be a
    // mandatory flag applied to scripts in a block. NOPs that are not executed,
    // e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),

    // Require that only a single stack element remains after evaluation. This
    // changes the success criterion from "At least one stack element must
    // remain, and when interpreted as a boolean, it must be true" to "Exactly
    // one stack element must remain, and when interpreted as a boolean, it must
    // be true".
    // (BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH.
    // Note: The Segwit Recovery feature is an exception to CLEANSTACK
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    SCRIPT_VERIFY_MINIMALIF = (1U << 13),

    // Do we accept signatures using SIGHASH_FORKID or SIGHASH_BIP341
    //
    SCRIPT_ENABLE_SIGHASH_FORKID = (1U << 16),

    // Do we accept activate replay protection using a different fork id.
    //
    SCRIPT_ENABLE_REPLAY_PROTECTION = (1U << 17),

    // Require the number of sigchecks in an input to satisfy a specific
    // bound, defined by scriptSig length.
    // Note: The Segwit Recovery feature is a (currently moot) exception to
    // VERIFY_INPUT_SIGCHECKS
    SCRIPT_VERIFY_INPUT_SIGCHECKS = (1U << 22),

    // Require BIP341 sighash for key spend path (spending without revealing the
    // script) in Taproot
    SCRIPT_REQUIRE_BIP341_SIGHASH = (1U << 23),
};

#endif // BITCOIN_SCRIPT_SCRIPT_FLAGS_H
