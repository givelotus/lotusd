// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <lotus_v2/tagged_hash.h>
#include <primitives/block.h>
#include <streams.h>
#include <support/allocators/chunked_slab.h>
#include <tinyformat.h>
#include <algorithm>
#include <cassert>
#include <cstring>
#include <iterator>
#include <memory>
#include <new>
#include <thread>
#include <stdexcept>

std::string COutPoint::ToString() const {
    return strprintf("COutPoint(%s, %u)", txid.ToString().substr(0, 10), n);
}

lotus::v2::Input CTxIn::ToV2Input() const {
    lotus::v2::Input in;
    std::memcpy(in.prev_txid.data(), prevout.GetTxId().begin(), 32);
    in.prev_index = prevout.GetN();
    in.sequence = nSequence;
    if (nFlags != 0) {
        in.flags = nFlags;
        in.path_index = nPathIndex;
        in.witnesses = vWitnesses;
        in.has_coinbase_data = fHasCoinbaseData;
        in.coinbase_data = vCoinbaseData;
        if (in.flags == 2) {
            in.sequence = SEQUENCE_FINAL;
            if (!in.has_coinbase_data && !scriptSig.empty()) {
                in.has_coinbase_data = true;
                in.coinbase_data.assign(scriptSig.begin(), scriptSig.end());
            }
        } else if (in.flags == 1) {
            if (in.sequence != SEQUENCE_FINAL && (in.sequence & ~0x40ffffU)) {
                in.sequence = SEQUENCE_FINAL;
            }
            if (in.witnesses.empty()) {
                lotus::v2::BranchWitness w;
                w.script.assign(scriptSig.begin(), scriptSig.end());
                if (w.script.empty()) {
                    w.script = {0x4e};
                }
                in.witnesses.push_back(std::move(w));
            }
        }
        return in;
    }
    if (prevout.IsNull()) {
        in.flags = 2;
        in.prev_index = 0;
        in.sequence = SEQUENCE_FINAL;
        if (!scriptSig.empty()) {
            in.has_coinbase_data = true;
            in.coinbase_data.assign(scriptSig.begin(), scriptSig.end());
        }
    } else {
        in.flags = 1;
        in.path_index = 0;
        if (in.sequence != SEQUENCE_FINAL && (in.sequence & ~0x40ffffU)) {
            in.sequence = SEQUENCE_FINAL;
        }
        lotus::v2::BranchWitness w;
        w.script.assign(scriptSig.begin(), scriptSig.end());
        if (w.script.empty()) {
            w.script = {0x4e};
        }
        in.witnesses.push_back(std::move(w));
    }
    return in;
}

CTxIn CTxIn::FromV2Input(const lotus::v2::Input &in) {
    uint256 prev_hash;
    std::memcpy(prev_hash.begin(), in.prev_txid.data(), 32);
    CTxIn txin;
    txin.prevout = COutPoint(TxId(prev_hash), in.prev_index);
    txin.nSequence = in.sequence;
    txin.nFlags = in.flags;
    txin.nPathIndex = in.path_index;
    txin.vWitnesses = in.witnesses;
    txin.fHasCoinbaseData = in.has_coinbase_data;
    txin.vCoinbaseData = in.coinbase_data;
    if (in.flags == 2 && in.has_coinbase_data) {
        txin.scriptSig.assign(in.coinbase_data.begin(), in.coinbase_data.end());
    } else if (!in.witnesses.empty() && in.witnesses[0].script.size() <= 28) {
        txin.scriptSig.assign(in.witnesses[0].script.begin(),
                              in.witnesses[0].script.end());
    }
    return txin;
}

CTxIn CTxIn::FromV2Input(lotus::v2::Input &&in) {
    uint256 prev_hash;
    std::memcpy(prev_hash.begin(), in.prev_txid.data(), 32);
    CTxIn txin;
    txin.prevout = COutPoint(TxId(prev_hash), in.prev_index);
    txin.nSequence = in.sequence;
    txin.nFlags = in.flags;
    txin.nPathIndex = in.path_index;
    txin.fHasCoinbaseData = in.has_coinbase_data;
    if (in.flags == 2 && in.has_coinbase_data) {
        txin.scriptSig.assign(in.coinbase_data.begin(), in.coinbase_data.end());
    } else if (!in.witnesses.empty() && in.witnesses[0].script.size() <= 28) {
        txin.scriptSig.assign(in.witnesses[0].script.begin(),
                              in.witnesses[0].script.end());
    }
    txin.vWitnesses = std::move(in.witnesses);
    txin.vCoinbaseData = std::move(in.coinbase_data);
    return txin;
}

std::string CTxIn::ToString() const {
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull() || nFlags == 2) {
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
    const uint64_t val =
        static_cast<uint64_t>(std::max<int64_t>(0, nValue / SATOSHI));
    if (!vBranches.empty()) {
        lotus::v2::Output out;
        out.flags = nFlags;
        out.value = val;
        std::memcpy(out.token_id.data(), tokenId.begin(), 32);
        std::memcpy(out.state_root.data(), stateRoot.begin(), 32);
        out.branches = vBranches;
        out.paths = vPaths;
        return out;
    }
    if (scriptPubKey.size() >= 43) {
        if (scriptPubKey.size() == 45 && scriptPubKey[0] == 0x00 &&
            scriptPubKey[9] == 0x01 && scriptPubKey[42] == 0x01 &&
            scriptPubKey[43] == 0x01 && scriptPubKey[44] == 0x00) {
            lotus::v2::Output decoded;
            decoded.flags = 0;
            decoded.value = val;
            decoded.branches.resize(1);
            std::memcpy(decoded.branches[0].data(), scriptPubKey.data() + 10,
                        32);
            decoded.paths = {{0}};
            return decoded;
        }
        std::string err;
        lotus::v2::Output decoded;
        const std::vector<uint8_t> raw(scriptPubKey.begin(),
                                       scriptPubKey.end());
        if (lotus::v2::DecodeOutput(raw, decoded, err)) {
            decoded.value = val;
            return decoded;
        }
        if (raw[0] == 0x6a && raw.size() >= 44) {
            const std::vector<uint8_t> sub(raw.begin() + 1, raw.end());
            if (lotus::v2::DecodeOutput(sub, decoded, err)) {
                decoded.value = val;
                return decoded;
            }
        }
    }
    throw std::invalid_argument(
        "Native output requires an explicit native policy; "
        "implicit legacy script conversion is unsupported");
}

static void PopulateV2ScriptPubKeyWire(const lotus::v2::Output &o,
                                       CScript &scriptPubKey) {
    if (o.flags == 0 && o.branches.size() == 1 && o.paths.size() == 1 &&
        o.paths[0].size() == 1 && o.paths[0][0] == 0) {
        scriptPubKey.resize(45);
        uint8_t *p = scriptPubKey.data();
        p[0] = 0x00;
        for (size_t i = 0; i < 8; ++i) {
            p[1 + i] = static_cast<uint8_t>(o.value >> (8 * i));
        }
        p[9] = 0x01;
        std::memcpy(p + 10, o.branches[0].data(), 32);
        p[42] = 0x01;
        p[43] = 0x01;
        p[44] = 0x00;
        return;
    }
    std::vector<uint8_t> wire;
    wire.reserve(64);
    std::string err;
    if (lotus::v2::EncodeOutput(o, wire, err)) {
        if (o.IsBurn()) {
            scriptPubKey.clear();
            scriptPubKey.reserve(1 + wire.size());
            scriptPubKey.push_back(0x6a);
            scriptPubKey.insert(scriptPubKey.end(), wire.begin(), wire.end());
        } else {
            scriptPubKey.assign(wire.begin(), wire.end());
        }
    }
}

CTxOut CTxOut::FromV2Output(const lotus::v2::Output &o) {
    CTxOut out;
    out.nValue = static_cast<int64_t>(o.value) * SATOSHI;
    out.nFlags = o.flags;
    std::memcpy(out.tokenId.begin(), o.token_id.data(), 32);
    std::memcpy(out.stateRoot.begin(), o.state_root.data(), 32);
    PopulateV2ScriptPubKeyWire(o, out.scriptPubKey);
    out.vBranches = o.branches;
    out.vPaths = o.paths;
    return out;
}

CTxOut CTxOut::FromV2Output(lotus::v2::Output &&o) {
    CTxOut out;
    out.nValue = static_cast<int64_t>(o.value) * SATOSHI;
    out.nFlags = o.flags;
    std::memcpy(out.tokenId.begin(), o.token_id.data(), 32);
    std::memcpy(out.stateRoot.begin(), o.state_root.data(), 32);
    PopulateV2ScriptPubKeyWire(o, out.scriptPubKey);
    out.vBranches = std::move(o.branches);
    out.vPaths = std::move(o.paths);
    return out;
}

void AdaptLegacyOutputToV7(CTxOut &txout) {
    const lotus::v2::Output out = txout.ToV2Output();
    txout.nFlags = out.flags;
    std::memcpy(txout.tokenId.begin(), out.token_id.data(), 32);
    std::memcpy(txout.stateRoot.begin(), out.state_root.data(), 32);
    txout.vBranches = out.branches;
    txout.vPaths = out.paths;
    if (txout.scriptPubKey.empty()) {
        txout.scriptPubKey = CTxOut::FromV2Output(out).scriptPubKey;
    }
}

void AdaptLegacyInputToV7(CTxIn &txin) {
    const CScript orig_script_sig = txin.scriptSig;
    txin = CTxIn::FromV2Input(txin.ToV2Input());
    if (!orig_script_sig.empty()) {
        txin.scriptSig = orig_script_sig;
    }
}

void AdaptLegacyTxToV7(CMutableTransaction &mtx) {
    const bool is_cb =
        (mtx.vin.size() == 1 &&
         (mtx.vin[0].prevout.IsNull() || mtx.vin[0].nFlags == 2));
    if (!mtx.fHasV2Lock) {
        mtx.nV2Lock = (is_cb || mtx.nLockTime == 0)
                          ? 0ULL
                          : ((uint64_t(mtx.nLockTime) << 8) |
                             (mtx.nLockTime < 500000000U ? 1ULL : 2ULL));
        mtx.fHasV2Lock = true;
    } else if (is_cb) {
        mtx.nV2Lock = 0ULL;
    }
    mtx.nLockTime = static_cast<uint32_t>(mtx.nV2Lock >> 8);
    mtx.nVersion = 7;
    for (auto &txin : mtx.vin) {
        AdaptLegacyInputToV7(txin);
    }
    for (auto &txout : mtx.vout) {
        AdaptLegacyOutputToV7(txout);
    }
}

CTransaction AdaptLegacyTxToV7(const CTransaction &tx) {
    CMutableTransaction mtx(tx);
    AdaptLegacyTxToV7(mtx);
    return CTransaction(std::move(mtx));
}

std::string CTxOut::ToString() const {
    const Amount xec = 100 * SATOSHI;
    return strprintf("CTxOut(nValue=%d.%02d, scriptPubKey=%s)", nValue / xec,
                     (nValue % xec) / SATOSHI,
                     HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction()
    : nVersion{CTransaction::CURRENT_VERSION}, nLockTime{0}, fHasV2Lock{false},
      nV2Lock{0} {}
CMutableTransaction::CMutableTransaction(const CTransaction &tx)
    : vin(tx.vin.begin(), tx.vin.end()), vout(tx.vout.begin(), tx.vout.end()), nVersion{tx.nVersion},
      nLockTime{tx.nLockTime}, fHasV2Lock{tx.fHasV2Lock}, nV2Lock{tx.nV2Lock} {}

lotus::v2::Transaction CMutableTransaction::ToV2Transaction() const {
    lotus::v2::Transaction v2tx;
    const bool is_cb =
        (vin.size() == 1 && (vin[0].prevout.IsNull() || vin[0].nFlags == 2));
    v2tx.lock =
        fHasV2Lock
            ? nV2Lock
            : ((is_cb || nLockTime == 0)
                   ? 0ULL
                   : ((uint64_t(nLockTime) << 8) |
                      (nLockTime < 500000000U ? 1ULL : 2ULL)));
    v2tx.inputs.reserve(vin.size());
    for (const auto &in : vin) {
        v2tx.inputs.push_back(in.ToV2Input());
    }
    v2tx.outputs.reserve(vout.size());
    for (const auto &out : vout) {
        v2tx.outputs.push_back(out.ToV2Output());
    }
    return v2tx;
}

CMutableTransaction
CMutableTransaction::FromV2Transaction(const lotus::v2::Transaction &tx) {
    CMutableTransaction mtx;
    mtx.nVersion = 7;
    mtx.fHasV2Lock = true;
    mtx.nV2Lock = tx.lock;
    mtx.nLockTime = static_cast<uint32_t>(tx.lock >> 8);
    mtx.vin.reserve(tx.inputs.size());
    for (const auto &in : tx.inputs) {
        mtx.vin.push_back(CTxIn::FromV2Input(in));
    }
    mtx.vout.reserve(tx.outputs.size());
    for (const auto &out : tx.outputs) {
        mtx.vout.push_back(CTxOut::FromV2Output(out));
    }
    return mtx;
}

lotus::v2::Transaction CTransaction::ToV2Transaction() const {
    lotus::v2::Transaction v2tx;
    v2tx.lock =
        fHasV2Lock
            ? nV2Lock
            : ((IsCoinBase() || nLockTime == 0)
                   ? 0ULL
                   : ((uint64_t(nLockTime) << 8) |
                      (nLockTime < 500000000U ? 1ULL : 2ULL)));
    v2tx.inputs.reserve(vin.size());
    for (const auto &in : vin) {
        v2tx.inputs.push_back(in.ToV2Input());
    }
    v2tx.outputs.reserve(vout.size());
    for (const auto &out : vout) {
        v2tx.outputs.push_back(out.ToV2Output());
    }
    return v2tx;
}

static_assert(lotus::v2::MAX_TX_INPUTS == MAX_V2_TX_INPUTS &&
              lotus::v2::MAX_TX_OUTPUTS == MAX_V2_TX_OUTPUTS);

// Returns true when the identity is the structural V2 TxId/TxHash. Returns
// false, after filling a fallback digest, when the transaction is not a
// well-formed V2 transaction (ComputeTransactionIdentities fails on its
// content). The fallback only names such a transaction (logs, reject caches);
// validation rejects it with bad-txns-v2-identity, so it is never accepted.
//
// The fallback must never equal the identity of a different transaction,
// valid or not, or rejecting the invalid one could poison a reject cache
// entry for the other. It therefore uses its own domain tag (never TxId or
// TxHash), commits to the chain ID, and hashes the complete serialized
// transaction, which is self-delimiting. TxId and TxHash are the same value:
// a transaction that is not a V2 structure has no witness-free core, and
// excluding any field would let two different transactions share a name.
template <typename TxType>
static bool ComputeV2TxIdentities(const TxType &tx,
                                  lotus::v2::Hash32 &txid_out,
                                  lotus::v2::Hash32 &txhash_out,
                                  lotus::v2::Hash32 *outputs_root_out = nullptr) {
    const uint32_t nVersion = tx.nVersion;
    std::string err;
    if (lotus::v2::ComputeTransactionIdentities(
            tx.ToV2Transaction(), lotus::v2::DefaultTxProfile,
            GetActiveV2ChainId(), txid_out, txhash_out, err,
            outputs_root_out)) {
        if (nVersion != 7) {
            txid_out[0] ^= uint8_t(nVersion & 0xffU);
            txhash_out[0] ^= uint8_t(nVersion & 0xffU);
        }
        return true;
    }
    if (outputs_root_out) {
        *outputs_root_out = lotus::v2::Hash32{};
    }
    const lotus::v2::ChainId &chain_id = GetActiveV2ChainId();
    std::vector<uint8_t> preimage(chain_id.begin(), chain_id.end());
    VectorWriter writer{preimage, preimage.size()};
    SerializeTransaction(tx, writer);
    txid_out =
        lotus::v2::TaggedHash(lotus::v2::HashDomain::TxIdFallback, preimage);
    txhash_out = txid_out;
    return false;
}

TxId CMutableTransaction::GetId() const {
    lotus::v2::Hash32 txid{}, txhash{};
    ComputeV2TxIdentities(*this, txid, txhash);
    uint256 out;
    std::memcpy(out.begin(), txid.data(), 32);
    return TxId(out);
}

TxHash CMutableTransaction::GetHash() const {
    lotus::v2::Hash32 txid{}, txhash{};
    ComputeV2TxIdentities(*this, txid, txhash);
    uint256 out;
    std::memcpy(out.begin(), txhash.data(), 32);
    return TxHash(out);
}

uint256 CTransaction::ComputeHash() const {
    lotus::v2::Hash32 txid{}, txhash{};
    ComputeV2TxIdentities(*this, txid, txhash);
    uint256 out;
    std::memcpy(out.begin(), txid.data(), 32);
    return out;
}

uint256 CTransaction::ComputeWitnessHash() const {
    lotus::v2::Hash32 txid{}, txhash{};
    ComputeV2TxIdentities(*this, txid, txhash);
    uint256 out;
    std::memcpy(out.begin(), txhash.data(), 32);
    return out;
}

void CTransaction::InitHashes() {
    if (nVersion == 7 && fHasV2Lock && !vin.empty() && vin.size() <= 16 &&
        !vout.empty() && vout.size() <= 16 && (nV2Lock & 0xffU) <= 2 &&
        ((nV2Lock & 0xffU) != 0 || nV2Lock == 0)) {
        bool fast_ok = true;
        uint32_t total_size = 16;
        std::array<lotus::v2::Hash32, 16> core_leaves{};
        std::array<lotus::v2::Hash32, 16> full_leaves{};
        std::array<lotus::v2::Hash32, 16> out_leaves{};
        for (size_t i = 0; i < vin.size(); ++i) {
            const CTxIn &in = vin[i];
            if (in.nFlags != 1 || in.fHasCoinbaseData ||
                !in.vCoinbaseData.empty() ||
                in.nPathIndex >= lotus::v2::MAX_OUTPUT_PATHS ||
                in.vWitnesses.size() != 1 ||
                (in.nSequence != UINT32_MAX && (in.nSequence & ~0x40ffffU))) {
                fast_ok = false;
                break;
            }
            const auto &w = in.vWitnesses[0];
            if (!w.siblings.empty() || w.script.size() > 160 ||
                w.arguments.size() > 1 ||
                (w.arguments.size() == 1 && w.arguments[0].size() > 80)) {
                fast_ok = false;
                break;
            }
            for (size_t j = 0; j < i; ++j) {
                if (vin[j].prevout == in.prevout) {
                    fast_ok = false;
                    break;
                }
            }
            if (!fast_ok) {
                break;
            }
            std::array<uint8_t, 300> buf{};
            std::memcpy(buf.data(), in.prevout.GetTxId().begin(), 32);
            const uint32_t prev_n = in.prevout.GetN();
            for (size_t b = 0; b < 4; ++b) {
                buf[32 + b] = static_cast<uint8_t>(prev_n >> (8 * b));
                buf[36 + b] = static_cast<uint8_t>(in.nSequence >> (8 * b));
            }
            buf[40] = 1;
            buf[41] = in.nPathIndex;
            buf[42] = 1;
            buf[43] = static_cast<uint8_t>(w.script.size());
            if (!w.script.empty()) {
                std::memcpy(buf.data() + 44, w.script.data(), w.script.size());
            }
            const size_t core_len = 45 + w.script.size();
            buf[core_len - 1] = 0; // siblings.size() == 0
            core_leaves[i] = lotus::v2::InputCoreLeaf(
                std::span<const uint8_t>(buf.data(), core_len));
            size_t full_len = core_len;
            if (w.arguments.empty()) {
                buf[full_len++] = 0;
            } else {
                const auto &arg0 = w.arguments[0];
                buf[full_len++] = 1;
                buf[full_len++] = static_cast<uint8_t>(arg0.size());
                if (!arg0.empty()) {
                    std::memcpy(buf.data() + full_len, arg0.data(),
                                arg0.size());
                    full_len += arg0.size();
                }
            }
            full_leaves[i] = lotus::v2::InputFullLeaf(
                std::span<const uint8_t>(buf.data(), full_len));
            total_size += static_cast<uint32_t>(full_len);
        }
        if (fast_ok) {
            for (size_t j = 0; j < vout.size(); ++j) {
                const CTxOut &out = vout[j];
                if (out.vBranches.empty() || (out.nFlags & 0x02U) != 0 ||
                    out.scriptPubKey.size() != 45 ||
                    out.scriptPubKey[0] != 0x00 ||
                    out.scriptPubKey[9] != 0x01 ||
                    out.scriptPubKey[42] != 0x01 ||
                    out.scriptPubKey[43] != 0x01 ||
                    out.scriptPubKey[44] != 0x00) {
                    fast_ok = false;
                    break;
                }
                out_leaves[j] = lotus::v2::OutputLeaf(std::span<const uint8_t>(
                    out.scriptPubKey.data(), out.scriptPubKey.size()));
                total_size += static_cast<uint32_t>(out.scriptPubKey.size());
            }
        }
        if (fast_ok) {
            const lotus::v2::Hash inputs_root = lotus::v2::IndexedTreeRoot(
                std::span<const lotus::v2::Hash>(core_leaves.data(),
                                                 vin.size()));
            const lotus::v2::Hash full_inputs_root = lotus::v2::IndexedTreeRoot(
                std::span<const lotus::v2::Hash>(full_leaves.data(),
                                                 vin.size()));
            const lotus::v2::Hash outputs_root = lotus::v2::IndexedTreeRoot(
                std::span<const lotus::v2::Hash>(out_leaves.data(),
                                                 vout.size()));
            lotus::v2::TxHeaderCore header{};
            header[0] = 7;
            for (size_t i = 0; i < 8; ++i) {
                header[4 + i] = static_cast<uint8_t>(nV2Lock >> (8 * i));
            }
            header[12] = static_cast<uint8_t>(vin.size());
            header[13] = static_cast<uint8_t>(vin.size() >> 8);
            header[14] = static_cast<uint8_t>(vout.size());
            header[15] = static_cast<uint8_t>(vout.size() >> 8);
            const auto &chain_id = GetActiveV2ChainId();
            const lotus::v2::Hash txid = lotus::v2::TransactionId(
                chain_id, header, inputs_root, outputs_root);
            const lotus::v2::Hash txhash = lotus::v2::TransactionHash(
                chain_id, header, full_inputs_root, outputs_root);
            std::memcpy(hash.begin(), txid.data(), 32);
            std::memcpy(m_witness_hash.begin(), txhash.data(), 32);
            std::memcpy(m_outputs_hash.begin(), outputs_root.data(), 32);
            m_serialize_size = total_size;
            return;
        }
    }
    lotus::v2::Hash32 txid{}, txhash{}, outputs_root{};
    m_structural_v2_identity = ComputeV2TxIdentities(
        *this, txid, txhash, &outputs_root);
    std::memcpy(hash.begin(), txid.data(), 32);
    std::memcpy(m_witness_hash.begin(), txhash.data(), 32);
    std::memcpy(m_outputs_hash.begin(), outputs_root.data(), 32);
    SizeComputer counter;
    SerializeTransaction(*this, counter);
    m_serialize_size = counter.size();
}

/**
 * For backward compatibility, the hash is initialized to 0.
 * TODO: remove the need for this default constructor entirely.
 */
namespace {
/** Appends serialized bytes to a vector. */
class AppendWriter {
    std::vector<uint8_t> &m_out;

public:
    explicit AppendWriter(std::vector<uint8_t> &out) : m_out(out) {}
    void write(Span<const std::byte> src) {
        m_out.insert(m_out.end(), UCharCast(src.data()),
                     UCharCast(src.data()) + src.size());
    }
    template <typename T> AppendWriter &operator<<(const T &obj) {
        ::Serialize(*this, obj);
        return *this;
    }
};

// The serialized marker is authoritative: logical version7 can also use the
// compatibility wrapper, whose output scripts are literal wire fields.
bool IsPureNativeWire(Span<const uint8_t> bytes) {
    return bytes.size() >= 4 && bytes[0] == 7 && bytes[1] == 0 &&
           bytes[2] == 0 && bytes[3] == 0;
}

bool IsOrdinaryNativeOutput(const CTxOut &out) {
    return out.nFlags == 0 && out.vBranches.size() == 1 &&
           out.vPaths.size() == 1 && out.vPaths[0].size() == 1 &&
           out.vPaths[0][0] == 0;
}

// The usual 45-byte output needs neither a temporary native Output (which
// copies extension vectors) nor a temporary script to count its slab tail.
size_t NativeOutputScriptSize(const CTxOut &out) {
    if (IsOrdinaryNativeOutput(out)) return 45;
    CScript canonical;
    PopulateV2ScriptPubKeyWire(out.ToV2Output(), canonical);
    // Invalid output models have no canonical encoding. The population helper
    // leaves their original script intact; preserve its size for validation.
    return canonical.empty() ? out.scriptPubKey.size() : canonical.size();
}

void CanonicalizeNativeOutputScript(CTxOut &out) {
    if (IsOrdinaryNativeOutput(out) && out.scriptPubKey.size() == 45) {
        const auto &script = out.scriptPubKey;
        const uint64_t value = static_cast<uint64_t>(
            std::max<int64_t>(0, out.nValue / SATOSHI));
        bool matches = script[0] == 0 && script[9] == 1 &&
                       script[42] == 1 && script[43] == 1 && script[44] == 0 &&
                       std::equal(out.vBranches[0].begin(),
                                  out.vBranches[0].end(), script.begin() + 10);
        for (size_t i = 0; i < 8; ++i) {
            matches &= script[1 + i] == static_cast<uint8_t>(value >> (8 * i));
        }
        if (matches) return;
    }
    // Only the script representation changes. Keep the source value and
    // extension fields, including invalid fields needed by validation tests.
    PopulateV2ScriptPubKeyWire(out.ToV2Output(), out.scriptPubKey);
}

TransactionWire SerializeWire(const CMutableTransaction &tx,
                              std::vector<uint8_t> &buf) {
    buf.clear();
    AppendWriter writer{buf};
    SerializeTransaction(tx, writer);
    TransactionWire wire;
    wire.bytes = buf;
    wire.n_inputs = tx.vin.size();
    wire.n_outputs = tx.vout.size();
    wire.source = &tx;
    for (const CTxIn &in : tx.vin) {
        if (IsLongScript(in.scriptSig.size())) {
            wire.long_script_bytes += in.scriptSig.size();
        }
    }
    const bool pure_native = IsPureNativeWire(wire.bytes);
    for (const CTxOut &out : tx.vout) {
        const size_t size = pure_native ? NativeOutputScriptSize(out)
                                        : out.scriptPubKey.size();
        if (IsLongScript(size)) wire.long_script_bytes += size;
    }
    return wire;
}

/** Serialization of CTransaction(): version 2, no inputs or outputs. */
constexpr uint8_t NULL_TRANSACTION_WIRE[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/**
 * Transaction storage holds the inputs, then the outputs, then the bytes of
 * the long scripts.
 */
struct StorageOffsets {
    size_t vout;
    size_t scripts;
    size_t total;
};
StorageOffsets Offsets(size_t n_inputs, size_t n_outputs,
                       size_t long_script_bytes) {
    StorageOffsets offsets;
    offsets.vout = (n_inputs * sizeof(CTxIn) + alignof(CTxOut) - 1) &
                   ~(alignof(CTxOut) - 1);
    offsets.scripts = offsets.vout + n_outputs * sizeof(CTxOut);
    offsets.total = offsets.scripts + long_script_bytes;
    return offsets;
}
static_assert(alignof(CTxIn) <= alignof(std::max_align_t) &&
              alignof(CTxOut) <= alignof(std::max_align_t));


/**
 * Slot sizes of the transaction storage slabs: 128-byte steps up to 2 KiB,
 * where nearly all transactions fall, then coarser up to 4 KiB.
 */
constexpr size_t STORAGE_SLOT_SIZES[] = {
    256,  384,  512,  640,  768,  896,  1024, 1152, 1280, 1408,
    1536, 1664, 1792, 1920, 2048, 2560, 3072, 3584, 4096};

template <size_t Bytes> struct alignas(std::max_align_t) StorageSlot {
    std::byte bytes[Bytes];
};
/** About 1 MiB of slots per slab chunk. */
template <size_t Bytes>
using StorageSlotAllocator =
    GlobalConcurrentSlabAllocator<StorageSlot<Bytes>, (size_t{1} << 20) / Bytes>;

template <size_t I = 0> void *AllocateStorage(size_t bytes) {
    if constexpr (I == std::size(STORAGE_SLOT_SIZES)) {
        return ::operator new(bytes,
                              std::align_val_t{alignof(std::max_align_t)});
    } else {
        constexpr size_t slot_size = STORAGE_SLOT_SIZES[I];
        if (bytes <= slot_size) {
            return StorageSlotAllocator<slot_size>{}.allocate(1);
        }
        return AllocateStorage<I + 1>(bytes);
    }
}

template <size_t I = 0> void DeallocateStorage(void *p, size_t bytes) noexcept {
    if constexpr (I == std::size(STORAGE_SLOT_SIZES)) {
        ::operator delete(p, std::align_val_t{alignof(std::max_align_t)});
    } else {
        constexpr size_t slot_size = STORAGE_SLOT_SIZES[I];
        if (bytes <= slot_size) {
            StorageSlotAllocator<slot_size>{}.deallocate(
                static_cast<StorageSlot<slot_size> *>(p), 1);
            return;
        }
        DeallocateStorage<I + 1>(p, bytes);
    }
}
} // namespace

std::vector<uint8_t> &TransactionScratchBuffer() {
    static thread_local std::vector<uint8_t> buf;
    return buf;
}

void *AllocateTransactionStorage(size_t bytes) {
    return AllocateStorage(bytes);
}

void DeallocateTransactionStorage(void *p, size_t bytes) noexcept {
    DeallocateStorage(p, bytes);
}

TransactionWire ScanTransactionWire(Span<const uint8_t> bytes,
                                    CMutableTransaction *retained) {
    SpanReader reader{bytes};
    CMutableTransaction temporary;
    CMutableTransaction &decoded = retained ? *retained : temporary;
    UnserializeTransaction(decoded, reader);
    TransactionWire wire{bytes.first(bytes.size() - reader.size()),
                         static_cast<uint32_t>(decoded.vin.size()),
                         static_cast<uint32_t>(decoded.vout.size())};
    wire.movable_source = retained;
    for (const auto &in : decoded.vin)
        if (IsLongScript(in.scriptSig.size())) wire.long_script_bytes += in.scriptSig.size();
    for (const auto &out : decoded.vout)
        if (IsLongScript(out.scriptPubKey.size())) wire.long_script_bytes += out.scriptPubKey.size();
    return wire;
}

size_t CTransaction::StorageSize(const TransactionWire &wire) {
    return Offsets(wire.n_inputs, wire.n_outputs, wire.long_script_bytes).total;
}

size_t CTransaction::GetStorageSize() const {
    return Offsets(vin.size(), vout.size(), m_long_script_bytes).total;
}

CTransaction::Layout CTransaction::Place(const TransactionWire &wire,
                                         void *storage, bool owned) {
    const StorageOffsets offsets =
        Offsets(wire.n_inputs, wire.n_outputs, wire.long_script_bytes);
    auto *base = static_cast<std::byte *>(storage);
    auto *scripts = reinterpret_cast<uint8_t *>(base + offsets.scripts);
    size_t scripts_used = 0;

    CMutableTransaction parsed;
    CMutableTransaction *movable = wire.movable_source;
    const CMutableTransaction *decoded = movable ? movable : wire.source;
    if (!decoded) {
        SpanReader reader{wire.bytes};
        UnserializeTransaction(parsed, reader);
        if (!reader.empty()) throw std::ios_base::failure("native transaction trailing bytes");
        decoded = &parsed;
        movable = &parsed;
    }
    if (decoded->vin.size() != wire.n_inputs || decoded->vout.size() != wire.n_outputs)
        throw std::ios_base::failure("native transaction storage framing mismatch");
    Layout layout;
    layout.nVersion = decoded->nVersion;
    layout.nLockTime = decoded->nLockTime;
    layout.fHasV2Lock = decoded->fHasV2Lock;
    layout.nV2Lock = decoded->nV2Lock;
    // Copy short scripts inline; copy long scripts into this transaction's
    // slab tail. Native extension vectors retain their own original ownership.
    auto store_script = [&](const CScript &script) {
        Span<const uint8_t> bytes{script.data(), script.size()};
        if (IsLongScript(bytes.size())) {
            if (bytes.size() > wire.long_script_bytes - scripts_used)
                throw std::ios_base::failure("native long script storage mismatch");
            auto *dest = scripts + scripts_used;
            std::copy(bytes.begin(), bytes.end(), dest);
            scripts_used += bytes.size();
            bytes = {dest, bytes.size()};
        }
        return CScript::Borrow(bytes);
    };
    uint32_t constructed_inputs = 0, constructed_outputs = 0;
    try {
    for (uint32_t i = 0; i < wire.n_inputs; ++i) {
        auto *slot = static_cast<void *>(base + i * sizeof(CTxIn));
        CTxIn input = movable ? std::move(movable->vin[i]) : decoded->vin[i];
        input.scriptSig = store_script(input.scriptSig);
        ::new (slot) const CTxIn(std::move(input));
        ++constructed_inputs;
    }
    for (uint32_t i = 0; i < wire.n_outputs; ++i) {
        auto *slot = static_cast<void *>(base + offsets.vout + i * sizeof(CTxOut));
        CTxOut output = movable ? std::move(movable->vout[i]) : decoded->vout[i];
        if (wire.source && IsPureNativeWire(wire.bytes)) {
            CanonicalizeNativeOutputScript(output);
        }
        output.scriptPubKey = store_script(output.scriptPubKey);
        ::new (slot) const CTxOut(std::move(output));
        ++constructed_outputs;
    }
    } catch (...) {
        std::destroy_n(std::launder(reinterpret_cast<const CTxIn *>(base)), constructed_inputs);
        std::destroy_n(std::launder(reinterpret_cast<const CTxOut *>(base + offsets.vout)), constructed_outputs);
        throw;
    }

    layout.vin = {std::launder(reinterpret_cast<const CTxIn *>(base)),
                  wire.n_inputs};
    layout.vout = {
        std::launder(reinterpret_cast<const CTxOut *>(base + offsets.vout)),
        wire.n_outputs};
    assert(scripts_used == wire.long_script_bytes);
    layout.serialize_size = wire.bytes.size();
    layout.long_script_bytes = wire.long_script_bytes;
    layout.owned = owned;
    return layout;
}

CTransaction::Layout CTransaction::OwnedLayout(const TransactionWire &wire) {
    const size_t size = StorageSize(wire);
    void *storage = AllocateTransactionStorage(size);
    try {
        return Place(wire, storage, /*owned=*/true);
    } catch (...) {
        DeallocateTransactionStorage(storage, size);
        throw;
    }
}

CTransaction::CTransaction(const Layout &layout)
    : vin(layout.vin), vout(layout.vout), nVersion(layout.nVersion),
      nLockTime(layout.nLockTime), fHasV2Lock(layout.fHasV2Lock), nV2Lock(layout.nV2Lock),
      hash(), m_witness_hash(), m_outputs_hash(),
      m_long_script_bytes(layout.long_script_bytes),
      m_owns_storage(layout.owned) { InitHashes(); }

/**
 * For backward compatibility, the hash is initialized to 0.
 * TODO: remove the need for this default constructor entirely.
 */
CTransaction::CTransaction()
    : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0),
      fHasV2Lock(false), nV2Lock(0), hash(), m_witness_hash(), m_outputs_hash(),
      m_long_script_bytes(0), m_owns_storage(false) {
    SizeComputer counter;
    SerializeTransaction(*this, counter);
    m_serialize_size = counter.size();
}

CTransaction::CTransaction(const CMutableTransaction &tx)
    : CTransaction(OwnedLayout(SerializeWire(tx, TransactionScratchBuffer()))) {
}

CTransaction::CTransaction(const TransactionWire &wire, void *storage)
    : CTransaction(Place(wire, storage, /*owned=*/false)) {}

CTransaction::~CTransaction() {
    std::destroy(vin.begin(), vin.end());
    std::destroy(vout.begin(), vout.end());
    if (m_owns_storage) {
        // Place() puts the inputs at the start of the storage.
        DeallocateTransactionStorage(const_cast<CTxIn *>(vin.data()),
                                     GetStorageSize());
    }
}

CTransactionRef MakeTransactionRef(const TransactionWire &wire) {
    TransactionStorageRequest request{
        CTransaction::StorageSize(wire)};
    // allocate_shared allocates before constructing, and forwards
    // request.storage by reference, so the constructor receives the storage
    // address that the allocator has just filled in.
    return std::allocate_shared<const CTransaction>(
        TransactionRefAllocator<CTransaction>{request}, wire, request.storage);
}

CTransactionRef MakeTransactionRef() {
    TransactionStorageRequest request{0};
    return std::allocate_shared<const CTransaction>(
        TransactionRefAllocator<CTransaction>{request});
}

CTransactionRef MakeTransactionRef(const CMutableTransaction &tx) {
    return MakeTransactionRef(SerializeWire(tx, TransactionScratchBuffer()));
}

namespace {
/** Writes serialized bytes into a buffer known to be large enough. */
class RawWriter {
    uint8_t *m_pos;

public:
    explicit RawWriter(uint8_t *pos) : m_pos(pos) {}
    void write(Span<const std::byte> src) {
        std::memcpy(m_pos, src.data(), src.size());
        m_pos += src.size();
    }
    template <typename T> RawWriter &operator<<(const T &obj) {
        ::Serialize(*this, obj);
        return *this;
    }
    const uint8_t *pos() const { return m_pos; }
};
} // namespace

Span<const uint8_t> CTransaction::SerializeToScratch() const {
    static thread_local std::vector<uint8_t> buf;
    // m_serialize_size is exact, so the writes below fill buf exactly.
    buf.resize(m_serialize_size);
    RawWriter writer{buf.data()};
    SerializeTransaction(*this, writer);
    assert(writer.pos() == buf.data() + buf.size());
    return buf;
}

const PrecomputedTransactionData &CTransaction::FillPrecomputedData() const {
    // Hashing is deterministic, so racing callers compute identical data; only
    // the thread that claims the slot writes it.
    const PrecomputedTransactionData computed =
        nVersion == 7 && !vin.empty() && (vin[0].nFlags == 1 || vin[0].nFlags == 3)
            ? PrecomputedTransactionData{}
            : PrecomputedTransactionData::Compute(*this);
    uint8_t expected = PRECOMPUTED_EMPTY;
    if (m_precomputed_state.compare_exchange_strong(
            expected, PRECOMPUTED_WRITING, std::memory_order_relaxed)) {
        m_precomputed = computed;
        m_precomputed_state.store(PRECOMPUTED_READY, std::memory_order_release);
        return m_precomputed;
    }
    // Another thread is storing its identical result; that is a 96-byte copy.
    while (m_precomputed_state.load(std::memory_order_acquire) !=
           PRECOMPUTED_READY) {
        std::this_thread::yield();
    }
    return m_precomputed;
}

Amount CTransaction::GetValueOut() const {
    Amount nValueOut = Amount::zero();
    for (const auto &tx_out : vout) {
        if ((tx_out.nFlags & 1) != 0) {
            continue;
        }
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
