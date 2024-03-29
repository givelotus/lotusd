#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Templates for constructing various sorts of invalid transactions.

These templates (or an iterator over all of them) can be reused in different
contexts to test using a number of invalid transaction types.

Hopefully this makes it easier to get coverage of a full variety of tx
validation checks through different interfaces (AcceptBlock, AcceptToMemPool,
etc.) without repeating ourselves.

Invalid tx cases not covered here can be found by running:

    $ diff \
      <(grep -IREho "bad-txns[a-zA-Z-]+" src | sort -u) \
      <(grep -IEho "bad-txns[a-zA-Z-]+" test/functional/data/invalid_txs.py | sort -u)

"""
import abc
from typing import Optional

from test_framework import script as sc
from test_framework.blocktools import create_tx_with_script
from test_framework.messages import (
    MAX_MONEY,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.txtools import pad_tx

basic_p2sh = sc.CScript(
    [sc.OP_HASH160, sc.hash160(sc.CScript([sc.OP_0])), sc.OP_EQUAL])


class BadTxTemplate:
    """Allows simple construction of a certain kind of invalid tx. Base class to be subclassed."""
    __metaclass__ = abc.ABCMeta

    # The expected error code given by lotusd upon submission of the tx.
    reject_reason: Optional[str] = ""

    # Only specified if it differs from mempool acceptance error.
    block_reject_reason = ""

    # Do we expect to be disconnected after submitting this tx?
    expect_disconnect = False

    # Is this tx considered valid when included in a block, but not for acceptance into
    # the mempool (i.e. does it violate policy but not consensus)?
    valid_in_block = False

    def __init__(self, *, spend_tx=None, spend_block=None):
        self.spend_tx = spend_block.vtx[0] if spend_block else spend_tx
        self.spend_avail = sum(o.nValue for o in self.spend_tx.vout)
        self.valid_txin = CTxIn(
            COutPoint(
                self.spend_tx.txid,
                1),
            b"",
            0xffffffff)

    @abc.abstractmethod
    def get_tx(self, *args, **kwargs):
        """Return a CTransaction that is invalid per the subclass."""
        pass

    def get_setup_tx(self):
        return None


class OutputMissing(BadTxTemplate):
    reject_reason = "bad-txns-vout-empty"
    expect_disconnect = True

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(self.valid_txin)
        tx.rehash()
        return tx


class InputMissing(BadTxTemplate):
    reject_reason = "bad-txns-vin-empty"
    expect_disconnect = True

    def get_tx(self):
        tx = CTransaction()
        tx.vout.append(CTxOut(0, sc.CScript([sc.OP_TRUE] * 100)))
        tx.rehash()
        return tx


class SizeTooSmall(BadTxTemplate):
    reject_reason = "bad-txns-undersize"
    expect_disconnect = False
    valid_in_block = True

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(self.valid_txin)
        tx.vout.append(CTxOut(0, sc.CScript([sc.OP_TRUE])))
        tx.rehash()
        return tx


class BadInputOutpointIndex(BadTxTemplate):
    # Won't be rejected - nonexistent outpoint index is treated as an orphan since the coins
    # database can't distinguish between spent outpoints and outpoints which
    # never existed.
    reject_reason = None
    expect_disconnect = False

    def get_tx(self):
        num_indices = len(self.spend_tx.vin)
        bad_idx = num_indices + 100

        tx = CTransaction()
        tx.vin.append(
            CTxIn(
                COutPoint(
                    self.spend_tx.txid,
                    bad_idx),
                b"",
                0xffffffff))
        tx.vout.append(CTxOut(0, basic_p2sh))
        tx.rehash()
        return tx


class DuplicateInput(BadTxTemplate):
    reject_reason = 'bad-txns-inputs-duplicate'
    expect_disconnect = True

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(self.valid_txin)
        tx.vin.append(self.valid_txin)
        tx.vout.append(CTxOut(1, basic_p2sh))
        tx.rehash()
        return tx


class NonexistentInput(BadTxTemplate):
    # Added as an orphan tx.
    reject_reason = None
    expect_disconnect = False

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(
            CTxIn(
                COutPoint(
                    self.spend_tx.txid +
                    1,
                    0),
                b"",
                0xffffffff))
        tx.vin.append(self.valid_txin)
        tx.vout.append(CTxOut(1, basic_p2sh))
        tx.rehash()
        return tx


class SpendTooMuch(BadTxTemplate):
    reject_reason = 'bad-txns-in-belowout'
    expect_disconnect = True

    def get_tx(self):
        return create_tx_with_script(
            self.spend_tx, 1, script_pub_key=basic_p2sh, amount=(self.spend_avail + 1))


class CreateNegative(BadTxTemplate):
    reject_reason = 'bad-txns-vout-negative'
    expect_disconnect = True

    def get_tx(self):
        return create_tx_with_script(self.spend_tx, 1, amount=-1)


class CreateTooLarge(BadTxTemplate):
    reject_reason = 'bad-txns-vout-toolarge'
    expect_disconnect = True

    def get_tx(self):
        return create_tx_with_script(self.spend_tx, 1, amount=MAX_MONEY + 1)


class CreateSumTooLarge(BadTxTemplate):
    reject_reason = 'bad-txns-txouttotal-toolarge'
    expect_disconnect = True

    def get_tx(self):
        tx = create_tx_with_script(self.spend_tx, 1, amount=MAX_MONEY)
        tx.vout = [tx.vout[0]] * 2
        tx.rehash()
        return tx


class InvalidOPIFConstruction(BadTxTemplate):
    reject_reason = "mandatory-script-verify-flag-failed (Invalid OP_IF construction)"
    expect_disconnect = True
    valid_in_block = True

    def get_tx(self, tx):
        return create_tx_with_script(tx, 0, amount=tx.vout[0].nValue - 10000)

    def get_setup_tx(self):
        return create_tx_with_script(
            self.spend_tx, 1, script_pub_key=b'\x64' * 35,
            amount=(self.spend_avail // 2))


def getDisabledOpcodeTemplate(opcode):
    """ Creates disabled opcode tx template class"""

    def get_tx(self, tx):
        return create_tx_with_script(tx, 0, amount=tx.vout[0].nValue - 10000, script_sig=sc.CScript([sc.CScript([opcode])]))

    def get_setup_tx(self):
        return create_tx_with_script(
            self.spend_tx, 1, amount=self.spend_tx.vout[1].nValue - 10000, script_pub_key=sc.CScript([
                sc.OP_HASH160,
                sc.hash160(sc.CScript([opcode])),
                sc.OP_EQUAL,
            ]))
        return tx

    return type('DisabledOpcode_' + str(opcode), (BadTxTemplate,), {
        'reject_reason': "disabled opcode",
        'expect_disconnect': True,
        'get_tx': get_tx,
        'get_setup_tx': get_setup_tx,
        'valid_in_block': True
    })


# Disabled opcode tx templates (CVE-2010-5137)
DisabledOpcodeTemplates = [getDisabledOpcodeTemplate(opcode) for opcode in [
    sc.OP_INVERT,
    sc.OP_2MUL,
    sc.OP_2DIV,
    sc.OP_MUL]]


def iter_all_templates():
    """Iterate through all bad transaction template types."""
    return BadTxTemplate.__subclasses__()
