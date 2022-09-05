// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <consensus/merkle.h>
#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <cassert>

std::string COutPoint::ToString() const {
    return strprintf("COutPoint(%s, %u)", txid.ToString().substr(0, 10), n);
}

std::string CTxIn::ToString() const {
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull()) {
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    } else {
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    }
    if (nSequence != SEQUENCE_FINAL) {
        str += strprintf(", nSequence=%u", nSequence);
    }
    str += ")";
    return str;
}

std::string CTxOut::ToString() const {
    return strprintf("CTxOut(nValue=%d.%06d, scriptPubKey=%s, carryover=%s)",
                     nValue / COIN, (nValue % COIN) / SATOSHI,
                     HexStr(scriptPubKey).substr(0, 30), HexStr(carryover));
}

std::string CTxPreamble::ToString() const {
    return strprintf("CTxPreamble(predicateScript=%s, loopCounts=%s)",
                     HexStr(predicateScript), HexStr(loopCounts));
}

CMutableTransaction::CMutableTransaction()
    : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction &tx)
    : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion),
      nLockTime(tx.nLockTime) {}

static uint256 ComputeCMutableTransactionHash(const CMutableTransaction &tx) {
    return SerializeHash(tx, SER_GETHASH, 0);
}

static uint256 ComputeTxId(int32_t nVersion, const std::vector<CTxIn> &vin,
                           const std::vector<CTxOut> &vout,
                           uint32_t nLockTime) {
    CHashWriter txid(SER_GETHASH, 0);
    size_t height;
    txid << nVersion;
    txid << TxInputsMerkleRoot(vin, height);
    txid << uint8_t(height);
    txid << TxOutputsMerkleRoot(vout, height);
    txid << uint8_t(height);
    txid << nLockTime;
    return txid.GetHash();
}

TxId CMutableTransaction::GetId() const {
    return TxId(ComputeTxId(nVersion, vin, vout, nLockTime));
}

TxHash CMutableTransaction::GetHash() const {
    return TxHash(ComputeCMutableTransactionHash(*this));
}

uint256 CTransaction::ComputeHash() const {
    return SerializeHash(*this, SER_GETHASH, 0);
}

uint256 CTransaction::ComputeId() const {
    return ComputeTxId(nVersion, vin, vout, nLockTime);
}

/**
 * For backward compatibility, the hash is initialized to 0.
 * TODO: remove the need for this default constructor entirely.
 */
CTransaction::CTransaction()
    : vin(), vout(), preambles(), nVersion(CTransaction::CURRENT_VERSION),
      nLockTime(0), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx)
    : vin(tx.vin), vout(tx.vout), preambles(tx.preambles),
      nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash(ComputeHash()),
      id(ComputeId()) {}
CTransaction::CTransaction(CMutableTransaction &&tx)
    : vin(std::move(tx.vin)), vout(std::move(tx.vout)),
      preambles(std::move(tx.preambles)), nVersion(tx.nVersion),
      nLockTime(tx.nLockTime), hash(ComputeHash()), id(ComputeId()) {}

Amount CTransaction::GetValueOut() const {
    Amount nValueOut = Amount::zero();
    for (const auto &tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) ||
            !MoneyRange(nValueOut + tx_out.nValue)) {
            throw std::runtime_error(std::string(__func__) +
                                     ": value out of range");
        }
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const {
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const {
    std::string str;
    str += strprintf("CTransaction(txid=%s, ver=%d, vin.size=%u, vout.size=%u, "
                     "nLockTime=%u)\n",
                     GetId().ToString().substr(0, 10), nVersion, vin.size(),
                     vout.size(), nLockTime);
    for (const auto &nVin : vin) {
        str += "    " + nVin.ToString() + "\n";
    }
    for (const auto &nVout : vout) {
        str += "    " + nVout.ToString() + "\n";
    }
    return str;
}
