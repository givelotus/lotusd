// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include <consensus/amount.h>
#include <feerate.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/header.h>
#include <lotus_v2/output.h>
#include <lotus_v2/transaction.h>
#include <primitives/txid.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <support/allocators/chunked_slab.h>
#include <atomic>
#include <concepts>
#include <cstddef>
#include <memory>
#include <vector>

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
 * An input of a transaction. It contains the location of the previous
 * transaction's output that it claims and a signature that matches the output's
 * public key.
 */
class CTxIn {
public:
    // nSequence follows prevout so that it fills prevout's tail padding.
    COutPoint prevout;
    uint32_t nSequence;
    CScript scriptSig;

    // Lotus V2 input fields (flags: 0 = auto-infer, 1 = spend, 2 = coinbase, 3 = mint)
    uint8_t nFlags{0};
    uint8_t nPathIndex{0};
    std::vector<lotus::v2::BranchWitness> vWitnesses{};
    bool fHasCoinbaseData{false};
    std::vector<uint8_t> vCoinbaseData{};

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
        : prevout(prevoutIn), nSequence(nSequenceIn),
          scriptSig(std::move(scriptSigIn)) {}
    CTxIn(TxId prevTxId, uint32_t nOut, CScript scriptSigIn = CScript(),
          uint32_t nSequenceIn = SEQUENCE_FINAL)
        : CTxIn(COutPoint(prevTxId, nOut), scriptSigIn, nSequenceIn) {}

    SERIALIZE_METHODS(CTxIn, obj) {
        READWRITE(obj.prevout, obj.scriptSig, obj.nSequence);
    }

    lotus::v2::Input ToV2Input() const;
    static CTxIn FromV2Input(const lotus::v2::Input &in);
    static CTxIn FromV2Input(lotus::v2::Input &&in);

    friend bool operator==(const CTxIn &a, const CTxIn &b) {
        if (a.nFlags != 0 && a.nFlags == b.nFlags) {
            return (a.prevout == b.prevout && a.nSequence == b.nSequence &&
                    a.nPathIndex == b.nPathIndex &&
                    a.vWitnesses == b.vWitnesses &&
                    a.fHasCoinbaseData == b.fHasCoinbaseData &&
                    a.vCoinbaseData == b.vCoinbaseData);
        }
        return (a.prevout == b.prevout && a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence && a.nFlags == b.nFlags &&
                a.nPathIndex == b.nPathIndex && a.vWitnesses == b.vWitnesses &&
                a.fHasCoinbaseData == b.fHasCoinbaseData &&
                a.vCoinbaseData == b.vCoinbaseData);
    }

    friend bool operator!=(const CTxIn &a, const CTxIn &b) { return !(a == b); }

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

    // Lotus V2 output fields
    uint8_t nFlags{0};
    uint256 tokenId{};
    std::vector<lotus::v2::Hash32> vBranches{};
    std::vector<std::vector<uint8_t>> vPaths{};

    CTxOut() { SetNull(); }

    CTxOut(Amount nValueIn, CScript scriptPubKeyIn)
        : nValue(nValueIn), scriptPubKey(std::move(scriptPubKeyIn)) {}

    SERIALIZE_METHODS(CTxOut, obj) { READWRITE(obj.nValue, obj.scriptPubKey); }

    void SetNull() {
        nValue = -SATOSHI;
        scriptPubKey.clear();
    }

    bool IsNull() const { return nValue == -SATOSHI; }

    friend bool operator==(const CTxOut &a, const CTxOut &b) {
        return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut &a, const CTxOut &b) {
        return !(a == b);
    }

    lotus::v2::Output ToV2Output() const;
    static CTxOut FromV2Output(const lotus::v2::Output &out);

    std::string ToString() const;
};

class CMutableTransaction;

/**
 * Basic transaction serialization format:
 * - uint32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 */
template <typename Stream, typename TxType>
inline void UnserializeTransaction(TxType &tx, Stream &s) {
    s >> tx.nVersion;
    tx.vin.clear();
    tx.vout.clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an
     * empty vector. */
    s >> tx.vin;
    /* We read a non-empty vin. Assume a normal vout follows. */
    s >> tx.vout;
    s >> tx.nLockTime;
}

template <typename Stream, typename TxType>
inline void SerializeTransaction(const TxType &tx, Stream &s) {
    s << tx.nVersion;
    WriteCompactSize(s, tx.vin.size());
    for (const auto &in : tx.vin) s << in;
    WriteCompactSize(s, tx.vout.size());
    for (const auto &out : tx.vout) s << out;
    s << tx.nLockTime;
}

/**
 * The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction;

/** Precompute sighash midstate to avoid quadratic hashing */
struct PrecomputedTransactionData {
    uint256 hashPrevouts, hashSequence, hashOutputs;

    PrecomputedTransactionData()
        : hashPrevouts(), hashSequence(), hashOutputs() {}

    PrecomputedTransactionData(const PrecomputedTransactionData &txdata) =
        default;
    PrecomputedTransactionData &
    operator=(const PrecomputedTransactionData &txdata) = default;

    template <class T> explicit PrecomputedTransactionData(const T &tx);

    /**
     * Copy the midstate cached when the CTransaction was constructed instead
     * of hashing again.
     */
    explicit PrecomputedTransactionData(const CTransaction &tx);

    /** Hash the midstate of tx. */
    template <class T> static PrecomputedTransactionData Compute(const T &tx);
};

/**
 * The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
/**
 * A serialized transaction whose structure has been checked, with its input
 * and output counts. Used to build a CTransaction from these bytes.
 */
struct TransactionWire {
    Span<const uint8_t> bytes;
    uint32_t n_inputs{0};
    uint32_t n_outputs{0};
    size_t long_script_bytes{0};
    // Used only during immediate construction from an in-memory mutable tx.
    const CMutableTransaction *source{nullptr};
    // Consumed synchronously by the builder; never retained by CTransaction.
    CMutableTransaction *movable_source{nullptr};
};

/** Whether a script of this size is stored outside CScript's inline buffer. */
constexpr bool IsLongScript(uint64_t size) {
    return size > CScriptBase::STATIC_SIZE;
}

/** Per-thread scratch buffer for serialized transaction bytes. */
std::vector<uint8_t> &TransactionScratchBuffer();

/**
 * Find the serialized transaction at the start of bytes, checking its
 * structure exactly like ReadTransactionWire, without copying it.
 */
TransactionWire ScanTransactionWire(Span<const uint8_t> bytes,
                                    CMutableTransaction *decoded = nullptr);

/** Streams whose unread bytes are contiguous in memory, such as DataStream. */
template <typename Stream>
concept ContiguousReadStream = requires(Stream &s, size_t n) {
    { UCharCast(s.data()) } -> std::convertible_to<const uint8_t *>;
    { s.size() } -> std::convertible_to<size_t>;
    s.ignore(n);
};

/**
 * Read one serialized transaction from s into buf, checking its structure
 * exactly like CMutableTransaction deserialization does. buf is reused, so
 * the result is only valid until buf is next modified.
 */
template <typename Stream>
TransactionWire ReadTransactionWire(Stream &s, std::vector<uint8_t> &buf,
                                    CMutableTransaction *decoded = nullptr);

/**
 * Read one serialized transaction from s and return build(wire). Bytes of a
 * contiguous stream are used where they are, and only consumed once build
 * has returned; other streams are read into the per-thread scratch buffer.
 */
template <typename Stream, typename Build>
auto ReadTransactionWith(Stream &s, Build &&build);

/**
 * The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 *
 * A CTransaction stores its inputs and outputs in one allocation, followed by
 * the bytes of every script longer than CScript's inline capacity, which
 * those scripts borrow. A CTransactionRef also shares that allocation with
 * its reference count (see MakeTransactionRef).
 */
class CTransaction {
public:
    // Default transaction version.
    static constexpr uint32_t CURRENT_VERSION{7};

    // Consensus: Valid min/max for nVersion, enforced as a consensus rule after
    // Wellington.
    static constexpr uint32_t MIN_VERSION = 1, MAX_VERSION = 7;

    // The fields are const because the cached hash and size describe them; a
    // CTransaction is never modified after construction.
    const Span<const CTxIn> vin;
    const Span<const CTxOut> vout;
    const uint32_t nVersion;
    const uint32_t nLockTime;
    const bool fHasV2Lock{false};
    const uint64_t nV2Lock{0};

    /** Bytes needed to hold the inputs, outputs and long scripts of wire. */
    static size_t StorageSize(const TransactionWire &wire);

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction &tx);

    /**
     * Build from wire inside caller-provided storage of StorageSize(wire)
     * bytes, which must outlive this object. Used by MakeTransactionRef.
     */
    CTransaction(const TransactionWire &wire, void *storage);

    /** Shared through CTransactionRef, never copied or moved. */
    CTransaction(const CTransaction &) = delete;
    CTransaction &operator=(const CTransaction &) = delete;

    ~CTransaction();

    template <typename Stream> inline void Serialize(Stream &s) const {
        if constexpr (std::is_same_v<std::remove_cvref_t<Stream>,
                                     SizeComputer>) {
            s.seek(m_serialize_size);
            return;
        }
        s.write(MakeByteSpan(SerializeToScratch()));
    }

    /**
     * This deserializing constructor is provided instead of an Unserialize
     * method. Unserialize is not possible, since it would require overwriting
     * const fields.
     */
    template <typename Stream>
    CTransaction(deserialize_type, Stream &s)
        : CTransaction(ReadTransactionWith(s, &CTransaction::OwnedLayout)) {}

    bool IsNull() const { return vin.empty() && vout.empty(); }

    TxId GetId() const { return TxId(hash); }
    TxHash GetHash() const { return TxHash(m_witness_hash); }
    const uint256 &GetOutputsHash() const { return m_outputs_hash; }
    lotus::v2::Transaction ToV2Transaction() const;

    /** Bytes used by the inputs, outputs and long scripts. */
    size_t GetStorageSize() const;

    /**
     * Sighash midstate (hashPrevouts, hashSequence, hashOutputs), computed on
     * first call and immutable afterwards, so safe to share across threads.
     */
    const PrecomputedTransactionData &GetPrecomputedData() const {
        if (m_precomputed_state.load(std::memory_order_acquire) ==
            PRECOMPUTED_READY) {
            return m_precomputed;
        }
        return FillPrecomputedData();
    }

    // Return sum of txouts.
    Amount GetValueOut() const;

    /**
     * Get the total transaction size in bytes.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const { return m_serialize_size; }

    bool IsCoinBase() const {
        return (vin.size() == 1 && (vin[0].prevout.IsNull() || vin[0].nFlags == 2));
    }

    friend bool operator==(const CTransaction &a, const CTransaction &b) {
        return a.GetHash() == b.GetHash();
    }

    friend bool operator!=(const CTransaction &a, const CTransaction &b) {
        return !(a == b);
    }

    std::string ToString() const;

private:
    /** Inputs, outputs and long scripts placed in storage. */
    struct Layout {
        Span<const CTxIn> vin;
        Span<const CTxOut> vout;
        uint256 hash;
        uint32_t serialize_size;
        uint32_t long_script_bytes;
        uint32_t nVersion;
        uint32_t nLockTime;
        bool fHasV2Lock;
        uint64_t nV2Lock;
        bool owned;
    };
    static Layout Place(const TransactionWire &wire, void *storage,
                        bool owned);
    static Layout OwnedLayout(const TransactionWire &wire);
    explicit CTransaction(const Layout &layout);

    uint256 hash;
    uint256 m_witness_hash;
    uint256 m_outputs_hash;
    uint32_t m_serialize_size{0};
    const uint32_t m_long_script_bytes;
    const bool m_owns_storage;
    uint256 ComputeHash() const;
    uint256 ComputeWitnessHash() const;
    void InitHashes();

    /**
     * Sighash midstate, filled on first use. The storage lives inline so the
     * fill never allocates; m_precomputed_state publishes it exactly once.
     */
    enum : uint8_t { PRECOMPUTED_EMPTY, PRECOMPUTED_WRITING, PRECOMPUTED_READY };
    mutable std::atomic<uint8_t> m_precomputed_state{PRECOMPUTED_EMPTY};
    mutable PrecomputedTransactionData m_precomputed;

    const PrecomputedTransactionData &FillPrecomputedData() const;

    /**
     * Serialize into a per-thread buffer, valid until the next call on this
     * thread, so a stream receives the transaction in a single write.
     */
    Span<const uint8_t> SerializeToScratch() const;
};

inline PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction &tx)
    : PrecomputedTransactionData(tx.GetPrecomputedData()) {}

/**
 * A mutable version of CTransaction.
 */
class CMutableTransaction {
public:
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nVersion;
    uint32_t nLockTime;
    bool fHasV2Lock{false};
    uint64_t nV2Lock{0};

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

    lotus::v2::Transaction ToV2Transaction() const;
    static CMutableTransaction
    FromV2Transaction(const lotus::v2::Transaction &tx);

    /**
     * Compute the id and hash of this CMutableTransaction. This is computed on
     * the fly, as opposed to GetId() and GetHash() in CTransaction, which uses
     * a cached result.
     */
    TxId GetId() const;
    TxHash GetHash() const;

    friend bool operator==(const CMutableTransaction &a,
                           const CMutableTransaction &b) {
        return a.GetHash() == b.GetHash();
    }
};

using CTransactionRef = std::shared_ptr<const CTransaction>;

/**
 * Transaction storage comes from process-wide thread-safe slabs, one per size
 * class (transactions are created on network/RPC threads and often released
 * on validation threads). Oversized requests use the heap.
 */
void *AllocateTransactionStorage(size_t bytes);
void DeallocateTransactionStorage(void *p, size_t bytes) noexcept;

/**
 * Storage requested from TransactionRefAllocator, which fills in its address
 * when the control block is allocated.
 */
struct TransactionStorageRequest {
    size_t storage_bytes;
    void *storage{nullptr};
};

/**
 * Allocator that places a transaction's storage directly after the shared_ptr
 * control block, in the same allocation.
 */
template <typename T> class TransactionRefAllocator {
public:
    using value_type = T;

    explicit TransactionRefAllocator(TransactionStorageRequest &request) noexcept
        : m_request(&request), m_storage_bytes(request.storage_bytes) {}
    template <typename U>
    TransactionRefAllocator(const TransactionRefAllocator<U> &other) noexcept
        : m_request(other.m_request), m_storage_bytes(other.m_storage_bytes) {}

    T *allocate(size_t n) {
        assert(n == 1);
        auto *p = static_cast<std::byte *>(
            AllocateTransactionStorage(HeadSize() + m_storage_bytes));
        m_request->storage = p + HeadSize();
        return reinterpret_cast<T *>(p);
    }
    void deallocate(T *p, size_t n) noexcept {
        DeallocateTransactionStorage(p, HeadSize() + m_storage_bytes);
    }

    template <typename U> struct rebind {
        using other = TransactionRefAllocator<U>;
    };

    friend bool operator==(const TransactionRefAllocator &a,
                           const TransactionRefAllocator &b) noexcept {
        return a.m_storage_bytes == b.m_storage_bytes;
    }
    friend bool operator!=(const TransactionRefAllocator &a,
                           const TransactionRefAllocator &b) noexcept {
        return !(a == b);
    }

private:
    template <typename U> friend class TransactionRefAllocator;

    static constexpr size_t HeadSize() noexcept {
        return (sizeof(T) + alignof(std::max_align_t) - 1) &
               ~(alignof(std::max_align_t) - 1);
    }

    /** Only used by allocate(), during MakeTransactionRef. */
    TransactionStorageRequest *m_request;
    size_t m_storage_bytes;
};

/** Build a CTransactionRef around wire in a single allocation. */
CTransactionRef MakeTransactionRef(const TransactionWire &wire);
/** A reference to a null transaction (see CTransaction()). */
CTransactionRef MakeTransactionRef();
CTransactionRef MakeTransactionRef(const CMutableTransaction &tx);

/** Keep the authoritative decode alive until placement has moved its fields. */
template <typename Stream, typename Build>
auto ReadTransactionWith(Stream &s, Build &&build) {
    CMutableTransaction decoded;
    if constexpr (ContiguousReadStream<Stream>) {
        const TransactionWire wire = ScanTransactionWire(
            {UCharCast(s.data()), size_t(s.size())}, &decoded);
        auto result = build(wire);
        s.ignore(wire.bytes.size());
        return result;
    } else {
        return build(ReadTransactionWire(s, TransactionScratchBuffer(), &decoded));
    }
}

/**
 * Deserialize transaction references (P2P tx messages, block vtx, disk) into
 * a single allocation as well.
 */
template <> struct SharedPtrDeserializer<CTransaction> {
    template <typename Stream> static CTransactionRef Make(Stream &s) {
        return ReadTransactionWith(s, [](const TransactionWire &wire) {
            return MakeTransactionRef(wire);
        });
    }
};


/** Record exact native bytes while using the authoritative native framing parser. */
template <typename Stream> class TransactionWireRecorder {
    Stream &source;
    std::vector<uint8_t> &bytes;
public:
    TransactionWireRecorder(Stream &s, std::vector<uint8_t> &b) : source(s), bytes(b) {}
    void read(Span<std::byte> out) {
        source.read(out);
        bytes.insert(bytes.end(), UCharCast(out.data()), UCharCast(out.data()) + out.size());
    }
    template <typename T> TransactionWireRecorder &operator>>(T &obj) {
        ::Unserialize(*this, obj);
        return *this;
    }
};
template <typename Stream>
TransactionWire ReadTransactionWire(Stream &s, std::vector<uint8_t> &buf,
                                    CMutableTransaction *retained) {
    buf.clear();
    TransactionWireRecorder<Stream> recorder{s, buf};
    CMutableTransaction temporary;
    CMutableTransaction &decoded = retained ? *retained : temporary;
    UnserializeTransaction(decoded, recorder);
    TransactionWire wire{buf, static_cast<uint32_t>(decoded.vin.size()),
                         static_cast<uint32_t>(decoded.vout.size())};
    wire.movable_source = retained;
    for (const auto &in : decoded.vin)
        if (IsLongScript(in.scriptSig.size())) wire.long_script_bytes += in.scriptSig.size();
    for (const auto &out : decoded.vout)
        if (IsLongScript(out.scriptPubKey.size())) wire.long_script_bytes += out.scriptPubKey.size();
    return wire;
}
void AdaptLegacyOutputToV7(CTxOut &txout);
void AdaptLegacyInputToV7(CTxIn &txin);
void AdaptLegacyTxToV7(CMutableTransaction &mtx);
CTransaction AdaptLegacyTxToV7(const CTransaction &tx);

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
