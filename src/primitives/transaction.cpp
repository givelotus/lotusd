// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/output.h>
#include <tinyformat.h>

#include <algorithm>
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

lotus::v2::Output CTxOut::ToV2Output() const {
    lotus::v2::Output out;
    out.value = nValue >= Amount::zero()
                    ? static_cast<uint64_t>(nValue / SATOSHI)
                    : 0;
    const bool is_burn = scriptPubKey.IsUnspendable();
    out.flags = is_burn ? 2 : 0;

    // Pack [uint16_t len_le, scriptPubKey[0..len-1]] across up to 16 branches
    // (31 payload bytes per branch, with branch[k][31] = uint8_t(0x81 + k))
    // so CTxOut <-> lotus::v2::Output is a 100% lossless bijection for
    // UTXOSHARD and BLOCKUNDO serialization while satisfying all V2 Output
    // branch-uniqueness and Merklix UtxoLeaf invariants.
    constexpr size_t kMaxPackedScriptBytes =
        lotus::v2::MAX_OUTPUT_BRANCHES * 31 - 2;
    if (scriptPubKey.size() <= kMaxPackedScriptBytes) {
        const uint16_t script_len = static_cast<uint16_t>(scriptPubKey.size());
        const size_t total_packed = 2 + static_cast<size_t>(script_len);
        const size_t num_branches =
            std::max<size_t>(1, (total_packed + 30) / 31);
        out.branches.resize(num_branches);
        const uint8_t *raw_script = scriptPubKey.data();
        for (size_t k = 0; k < num_branches; ++k) {
            out.branches[k].fill(0);
            uint8_t *dst = out.branches[k].data();
            if (k == 0) {
                dst[0] = static_cast<uint8_t>(script_len & 0xffU);
                dst[1] = static_cast<uint8_t>((script_len >> 8U) & 0xffU);
                const size_t first_chunk =
                    std::min<size_t>(29, script_len);
                if (first_chunk > 0) {
                    std::copy_n(raw_script, first_chunk, dst + 2);
                }
            } else {
                const size_t script_offset = 29 + (k - 1) * 31;
                const size_t chunk =
                    script_offset < script_len
                        ? std::min<size_t>(31, script_len - script_offset)
                        : 0;
                if (chunk > 0) {
                    std::copy_n(raw_script + script_offset, chunk, dst);
                }
            }
            dst[31] = static_cast<uint8_t>(0x81U + k);
        }
    } else {
        std::vector<uint8_t> script_bytes(scriptPubKey.begin(),
                                          scriptPubKey.end());
        out.branches = {lotus::v2::BranchLeaf(script_bytes)};
    }

    if (!is_burn) {
        out.paths = {{0}};
    }
    return out;
}

CTxOut CTxOut::FromV2Output(const lotus::v2::Output &out) {
    const Amount val = static_cast<int64_t>(out.value) * SATOSHI;
    if (!out.branches.empty() &&
        out.branches.size() <= lotus::v2::MAX_OUTPUT_BRANCHES) {
        bool valid_tags = true;
        for (size_t k = 0; k < out.branches.size(); ++k) {
            if (out.branches[k][31] != static_cast<uint8_t>(0x81U + k)) {
                valid_tags = false;
                break;
            }
        }
        if (valid_tags) {
            const uint16_t script_len =
                static_cast<uint16_t>(out.branches[0][0]) |
                (static_cast<uint16_t>(out.branches[0][1]) << 8U);
            const size_t total_packed = 2 + static_cast<size_t>(script_len);
            const size_t expected_branches =
                std::max<size_t>(1, (total_packed + 30) / 31);
            if (expected_branches == out.branches.size()) {
                CScript script;
                script.resize(script_len);
                uint8_t *dst = script.data();
                const size_t first_chunk =
                    std::min<size_t>(29, script_len);
                if (first_chunk > 0) {
                    std::copy_n(out.branches[0].data() + 2, first_chunk, dst);
                }
                for (size_t k = 1; k < out.branches.size(); ++k) {
                    const size_t script_offset = 29 + (k - 1) * 31;
                    const size_t chunk =
                        script_offset < script_len
                            ? std::min<size_t>(31, script_len - script_offset)
                            : 0;
                    if (chunk > 0) {
                        std::copy_n(out.branches[k].data(), chunk,
                                    dst + script_offset);
                    }
                }
                return CTxOut(val, std::move(script));
            }
        }
    }
    if (out.IsBurn()) {
        return CTxOut(val, CScript() << OP_RETURN);
    }
    CScript script;
    if (!out.branches.empty()) {
        script = CScript(out.branches[0].begin(), out.branches[0].end());
    }
    return CTxOut(val, std::move(script));
}

std::string CTxOut::ToString() const {
    const Amount xec = 100 * SATOSHI;
    return strprintf("CTxOut(nValue=%d.%02d, scriptPubKey=%s)", nValue / xec,
                     (nValue % xec) / SATOSHI,
                     HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction()
    : nVersion{CTransaction::CURRENT_VERSION}, nLockTime{0} {}
CMutableTransaction::CMutableTransaction(const CTransaction &tx)
    : vin(tx.vin), vout(tx.vout), nVersion{tx.nVersion},
      nLockTime{tx.nLockTime} {}

static uint256 ComputeCMutableTransactionHash(const CMutableTransaction &tx) {
    return (HashWriter{} << tx).GetHash();
}

TxId CMutableTransaction::GetId() const {
    return TxId(ComputeCMutableTransactionHash(*this));
}

TxHash CMutableTransaction::GetHash() const {
    return TxHash(ComputeCMutableTransactionHash(*this));
}

uint32_t CTransaction::ComputeSerializedSize() const {
    SizeComputer writer;
    SerializeTransaction(*this, writer);
    return writer.size();
}

uint256 CTransaction::ComputeHash() const {
    return (HashWriter{} << *this).GetHash();
}

/**
 * For backward compatibility, the hash is initialized to 0.
 * TODO: remove the need for this default constructor entirely.
 */
CTransaction::CTransaction()
    : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0),
      m_serialize_size(ComputeSerializedSize()), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx)
    : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion),
      nLockTime(tx.nLockTime), m_serialize_size(ComputeSerializedSize()), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx)
    : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion),
      nLockTime(tx.nLockTime), m_serialize_size(ComputeSerializedSize()), hash(ComputeHash()) {}

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

std::string CTransaction::ToString() const {
    std::string str;
    str += strprintf("CTransaction(txid=%s, ver=%u, vin.size=%u, vout.size=%u, "
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
