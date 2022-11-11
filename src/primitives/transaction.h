// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include <amount.h>
#include <feerate.h>
#include <primitives/txid.h>
#include <script/script.h>
#include <serialize.h>

static const int SERIALIZE_TRANSACTION = 0x00;
static const uint32_t TX_VERSION_MITRA = 0x07;

/**
 * An outpoint - a combination of a transaction hash and an index n into its
 * vout.
 */
class COutPoint {
private:
    TxId txid;
    uint32_t n;

public:
    static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

    COutPoint() : txid(), n(NULL_INDEX) {}
    COutPoint(TxId txidIn, uint32_t nIn) : txid(txidIn), n(nIn) {}

    SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.txid, obj.n); }

    bool IsNull() const { return txid.IsNull() && n == NULL_INDEX; }

    const TxId &GetTxId() const { return txid; }
    uint32_t GetN() const { return n; }

    friend bool operator<(const COutPoint &a, const COutPoint &b) {
        int cmp = a.txid.Compare(b.txid);
        return cmp < 0 || (cmp == 0 && a.n < b.n);
    }

    friend bool operator==(const COutPoint &a, const COutPoint &b) {
        return (a.txid == b.txid && a.n == b.n);
    }

    friend bool operator!=(const COutPoint &a, const COutPoint &b) {
        return !(a == b);
    }

    std::string ToString() const;
};

/**
 * An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut {
public:
    Amount nValue;
    CScript scriptPubKey;
    std::vector<uint8_t> carryover;

    CTxOut() { SetNull(); }

    CTxOut(Amount nValueIn, CScript scriptPubKeyIn,
           std::vector<uint8_t> carryoverIn = {})
        : nValue(nValueIn), scriptPubKey(scriptPubKeyIn),
          carryover(carryoverIn) {}

    SERIALIZE_METHODS(CTxOut, obj) { READWRITE(obj.nValue, obj.scriptPubKey); }

    void SetNull() {
        nValue = -SATOSHI;
        scriptPubKey.clear();
    }

    bool IsNull() const { return nValue == -SATOSHI; }

    friend bool operator==(const CTxOut &a, const CTxOut &b) {
        return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey &&
                a.carryover == b.carryover);
    }

    friend bool operator!=(const CTxOut &a, const CTxOut &b) {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CTxOutMitraFormatter {
    template <typename Stream> void Ser(Stream &s, const CTxOut &txout) {
        s << txout.nValue;
        s << txout.scriptPubKey;
        s << txout.carryover;
    }

    template <typename Stream> void Unser(Stream &s, CTxOut &txout) {
        s >> txout.nValue;
        s >> txout.scriptPubKey;
        s >> txout.carryover;
    }
};

/**
 * An input of a transaction. It contains the location of the previous
 * transaction's output that it claims and a signature that matches the output's
 * public key.
 */
class CTxIn {
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    // Mitra:
    CTxOut output;
    uint256 preambleMerkleRoot;
    std::vector<std::vector<uint8_t>> witnesses;
    std::vector<uint8_t> loopCounts;

    /**
     * Setting nSequence to this value for every input in a transaction disables
     * nLockTime.
     */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /**
     * If this flag set, CTxIn::nSequence is NOT interpreted as a relative
     * lock-time.
     */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31);

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag is set,
     * the relative lock-time has units of 512 seconds, otherwise it specifies
     * blocks with a granularity of 1.
     */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is applied to
     * extract that lock-time from the sequence field.
     */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /**
     * In order to use the same number of bits to encode roughly the same
     * wall-clock duration, and because blocks are naturally limited to occur
     * every 600s on average, the minimum granularity for time-based relative
     * lock-time is fixed at 512 seconds. Converting from CTxIn::nSequence to
     * seconds is performed by multiplying by 512 = 2^9, or equivalently
     * shifting up by 9 bits.
     */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn() { nSequence = SEQUENCE_FINAL; }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn = CScript(),
                   uint32_t nSequenceIn = SEQUENCE_FINAL)
        : prevout(prevoutIn), scriptSig(scriptSigIn), nSequence(nSequenceIn) {}
    CTxIn(TxId prevTxId, uint32_t nOut, CScript scriptSigIn = CScript(),
          uint32_t nSequenceIn = SEQUENCE_FINAL)
        : CTxIn(COutPoint(prevTxId, nOut), scriptSigIn, nSequenceIn) {}

    SERIALIZE_METHODS(CTxIn, obj) {
        READWRITE(obj.prevout, obj.scriptSig, obj.nSequence);
    }

    friend bool operator==(const CTxIn &a, const CTxIn &b) {
        return (a.prevout == b.prevout && a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence && a.output == b.output &&
                a.preambleMerkleRoot == b.preambleMerkleRoot &&
                a.witnesses == b.witnesses && a.loopCounts == b.loopCounts);
    }

    friend bool operator!=(const CTxIn &a, const CTxIn &b) { return !(a == b); }

    std::string ToString() const;
};

class CMutableTransaction;

struct CTxInMitraFormatter {
    template <typename Stream> void Ser(Stream &s, const CTxIn &txin) {
        s << txin.prevout;
        s << txin.nSequence;
        s << Using<CTxOutMitraFormatter>(txin.output);
        if (txin.preambleMerkleRoot.IsNull()) {
            s << uint8_t(0);
        } else {
            s << uint8_t(1);
            s << txin.preambleMerkleRoot;
        }
        s << txin.witnesses;
        s << txin.loopCounts;
    }

    template <typename Stream> void Unser(Stream &s, CTxIn &txin) {
        s >> txin.prevout;
        s >> txin.nSequence;
        s >> Using<CTxOutMitraFormatter>(txin.output);
        uint8_t hasPreamble;
        s >> hasPreamble;
        if (hasPreamble) {
            s >> txin.preambleMerkleRoot;
        } else {
            txin.preambleMerkleRoot = uint256();
        }
        s >> txin.witnesses;
        s >> txin.loopCounts;
    }
};

class CTxPreamble {
public:
    CScript predicateScript;
    std::vector<std::vector<uint8_t>> witnesses;
    std::vector<uint8_t> loopCounts;

    CTxPreamble() : predicateScript(), witnesses(), loopCounts() {}
    CTxPreamble(CScript predicateScriptIn,
                std::vector<std::vector<uint8_t>> witnessesIn,
                std::vector<uint8_t> loopCountsIn)
        : predicateScript(predicateScriptIn), witnesses(witnessesIn),
          loopCounts(loopCountsIn) {}

    SERIALIZE_METHODS(CTxPreamble, obj) {
        READWRITE(obj.predicateScript, obj.witnesses, obj.loopCounts);
    }

    friend bool operator==(const CTxPreamble &a, const CTxPreamble &b) {
        return (a.predicateScript == b.predicateScript &&
                a.witnesses == b.witnesses && a.loopCounts == b.loopCounts);
    }

    friend bool operator!=(const CTxPreamble &a, const CTxPreamble &b) {
        return !(a == b);
    }

    std::string ToString() const;
};

/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 */
template <typename Stream, typename TxType>
inline void UnserializeTransaction(TxType &tx, Stream &s) {
    s >> tx.nVersion;
    tx.preambles.clear();
    tx.vin.clear();
    tx.vout.clear();
    if (tx.nVersion == TX_VERSION_MITRA) {
        s >> tx.preambles;
        s >> Using<VectorFormatter<CTxInMitraFormatter>>(tx.vin);
        s >> Using<VectorFormatter<CTxOutMitraFormatter>>(tx.vout);
    } else {
        s >> tx.vin;
        s >> tx.vout;
    }
    s >> tx.nLockTime;
}

template <typename Stream, typename TxType>
inline void SerializeTransaction(const TxType &tx, Stream &s) {
    s << tx.nVersion;
    if (tx.nVersion == TX_VERSION_MITRA) {
        s << tx.preambles;
        s << Using<VectorFormatter<CTxInMitraFormatter>>(tx.vin);
        s << Using<VectorFormatter<CTxOutMitraFormatter>>(tx.vout);
    } else {
        s << tx.vin;
        s << tx.vout;
    }
    s << tx.nLockTime;
}

/**
 * The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction {
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = 2;

    // Changing the default transaction version requires a two step process:
    // first adapting relay policy by bumping MAX_STANDARD_VERSION, and then
    // later date bumping the default CURRENT_VERSION at which point both
    // CURRENT_VERSION and MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION = 2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const int32_t nVersion;
    const uint32_t nLockTime;
    // Mitra:
    const std::vector<CTxPreamble> preambles;

private:
    /** Memory only. */
    const uint256 preambleMerkleRoot;
    const uint256 hash;
    const uint256 id;

    uint256 ComputeHash() const;
    uint256 ComputeId() const;
    uint256 ComputePreambleMerkleRoot() const;

public:
    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction &tx);
    explicit CTransaction(CMutableTransaction &&tx);

    template <typename Stream> inline void Serialize(Stream &s) const {
        SerializeTransaction(*this, s);
    }

    /**
     * This deserializing constructor is provided instead of an Unserialize
     * method. Unserialize is not possible, since it would require overwriting
     * const fields.
     */
    template <typename Stream>
    CTransaction(deserialize_type, Stream &s)
        : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const { return vin.empty() && vout.empty(); }

    const TxId GetId() const { return TxId(id); }
    const TxHash GetHash() const { return TxHash(hash); }
    const uint256 GetPreambleMerkleRoot() const { return preambleMerkleRoot; }

    // Return sum of txouts.
    Amount GetValueOut() const;

    /**
     * Get the total transaction size in bytes.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;

    bool IsCoinBase() const {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction &a, const CTransaction &b) {
        return a.GetHash() == b.GetHash();
    }

    friend bool operator!=(const CTransaction &a, const CTransaction &b) {
        return !(a == b);
    }

    std::string ToString() const;
};
#if defined(__x86_64__)
static_assert(sizeof(CTransaction) == 120,
              "sizeof CTransaction is expected to be 120 bytes");
#endif

/**
 * A mutable version of CTransaction.
 */
class CMutableTransaction {
public:
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    int32_t nVersion;
    uint32_t nLockTime;
    // Mitra:
    std::vector<CTxPreamble> preambles;

    CMutableTransaction();
    explicit CMutableTransaction(const CTransaction &tx);

    template <typename Stream> inline void Serialize(Stream &s) const {
        SerializeTransaction(*this, s);
    }

    template <typename Stream> inline void Unserialize(Stream &s) {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream &s) {
        Unserialize(s);
    }

    /**
     * Compute the id and hash of this CMutableTransaction. This is computed on
     * the fly, as opposed to GetId() and GetHash() in CTransaction, which uses
     * a cached result.
     */
    TxId GetId() const;
    TxHash GetHash() const;
    uint256 GetPreambleMerkleRoot() const;

    friend bool operator==(const CMutableTransaction &a,
                           const CMutableTransaction &b) {
        return a.GetHash() == b.GetHash();
    }
};
#if defined(__x86_64__)
static_assert(sizeof(CMutableTransaction) == 56,
              "sizeof CMutableTransaction is expected to be 56 bytes");
#endif

using CTransactionRef = std::shared_ptr<const CTransaction>;
static inline CTransactionRef MakeTransactionRef() {
    return std::make_shared<const CTransaction>();
}
template <typename Tx>
static inline CTransactionRef MakeTransactionRef(Tx &&txIn) {
    return std::make_shared<const CTransaction>(std::forward<Tx>(txIn));
}

class CCoinsView;
/** Precompute sighash midstate to avoid quadratic hashing */
struct PrecomputedTransactionData {
    uint256 hashPrevouts, hashSequence, hashOutputs;
    /** Coins spend by the tx */
    std::vector<CTxOut> m_spent_outputs;
    /** Merkle root of the H(input.prevout || input.nSequence) for all inputs */
    uint256 m_inputs_merkle_root;
    /** Merkle root of the coins spend by the tx */
    uint256 m_inputs_spent_outputs_merkle_root;
    /** Height of the merkle tree of the inputs */
    size_t m_inputs_merkle_height;
    /** Merkle root of the tx outputs */
    uint256 m_outputs_merkle_root;
    /** Height of the merkle tree of the outputs */
    size_t m_outputs_merkle_height;
    /** Sum of the amounts in all the inputs */
    Amount m_amount_inputs_sum;
    /** Sum of the amounts in all the outputs */
    Amount m_amount_outputs_sum;

    PrecomputedTransactionData() = default;

    PrecomputedTransactionData(const PrecomputedTransactionData &txdata) =
        default;
    PrecomputedTransactionData &
    operator=(const PrecomputedTransactionData &txdata) = default;

    // added to silence deprecation warning
    PrecomputedTransactionData &
    operator=(const PrecomputedTransactionData &other) = default;

    template <class T>
    explicit PrecomputedTransactionData(const T &tx,
                                        std::vector<CTxOut> &&spent_outputs);

    template <class T>
    static PrecomputedTransactionData
    FromCoinsView(const T &tx, const CCoinsView &coins_view);
};

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
