// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_ERROR_H
#define BITCOIN_SCRIPT_SCRIPT_ERROR_H

#include <string>

enum class ScriptError {
    OK = 0,
    UNKNOWN,
    EVAL_FALSE,
    OP_RETURN,

    /* Max sizes */
    SCRIPT_SIZE,
    PUSH_SIZE,
    OP_COUNT,
    STACK_SIZE,
    SIG_COUNT,
    PUBKEY_COUNT,
    INPUT_SIGCHECKS,

    /* Operands checks */
    INVALID_OPERAND_SIZE,
    INVALID_NUMBER_RANGE,
    IMPOSSIBLE_ENCODING,
    INVALID_SPLIT_RANGE,
    INVALID_BIT_COUNT,

    /* Failed verify operations */
    VERIFY,
    EQUALVERIFY,
    CHECKMULTISIGVERIFY,
    CHECKSIGVERIFY,
    CHECKDATASIGVERIFY,
    NUMEQUALVERIFY,

    /* Logical/Format/Canonical errors */
    BAD_OPCODE,
    DISABLED_OPCODE,
    INVALID_STACK_OPERATION,
    INVALID_ALTSTACK_OPERATION,
    UNBALANCED_CONDITIONAL,
    UNBALANCED_LOOP,

    /* Divisor errors */
    DIV_BY_ZERO,
    MOD_BY_ZERO,

    /* Bitfield errors */
    INVALID_BITFIELD_SIZE,
    INVALID_BIT_RANGE,

    /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
    NEGATIVE_LOCKTIME,
    UNSATISFIED_LOCKTIME,

    /* Malleability */
    SIG_HASHTYPE,
    SIG_DER,
    MINIMALDATA,
    SIG_PUSHONLY,
    SIG_HIGH_S,
    PUBKEYTYPE,
    CLEANSTACK,
    MINIMALIF,
    SIG_NULLFAIL,

    /* Schnorr */
    SIG_BADLENGTH,
    SIG_NONSCHNORR,

    /* softfork safeness */
    DISCOURAGE_UPGRADABLE_NOPS,

    /* anti replay */
    ILLEGAL_FORKID,
    MUST_USE_FORKID,

    /* OP_NUM2BIN size limit exceeded */
    INVALID_NUM2BIN_SIZE,

    /* Auxiliary errors (unused by interpreter) */
    SIGCHECKS_LIMIT_EXCEEDED,

    /* OP_SCRIPTTYPE should never be executed in an executed script, it's only a
       marker */
    INVALID_OP_SCRIPTTYPE,
    /* Script type not supported */
    SCRIPTTYPE_INVALID_TYPE,
    /* Script not formatted in accordance with script type */
    SCRIPTTYPE_MALFORMED_SCRIPT,

    /* Key spend path for Taproot must use Lotus sighash */
    TAPROOT_KEY_SPEND_MUST_USE_LOTUS_SIGHASH,
    /* Key spend path for Taproot must Schnorr signatures */
    TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG,
    /* Key spend path for Taproot failed */
    TAPROOT_VERIFY_SIGNATURE_FAILED,
    /* Taproot annex not supported */
    TAPROOT_ANNEX_NOT_SUPPORTED,
    /* Control block not of size 33+32n */
    TAPROOT_WRONG_CONTROL_SIZE,
    /* Control block doesn't verify commitment */
    TAPROOT_VERIFY_COMMITMENT_FAILED,
    /* Taproot leaf version not supported */
    TAPROOT_LEAF_VERSION_NOT_SUPPORTED,

    /* Indicates that an opcode is not supported in the preamble execution */
    PREAMBLE_UNSUPPORTED_OPCODE,

    ERROR_COUNT,
};

#define SCRIPT_ERR_LAST ScriptError::ERROR_COUNT

std::string ScriptErrorString(const ScriptError error);

namespace {

inline bool set_success(ScriptError *ret) {
    if (ret) {
        *ret = ScriptError::OK;
    }
    return true;
}

inline bool set_error(ScriptError *ret, const ScriptError serror) {
    if (ret) {
        *ret = serror;
    }
    return false;
}

} // namespace

#endif // BITCOIN_SCRIPT_SCRIPT_ERROR_H
