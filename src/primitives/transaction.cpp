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
    : vin(tx.vin.begin(), tx.vin.end()), vout(tx.vout.begin(), tx.vout.end()),
      nVersion{tx.nVersion},
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

TransactionWire SerializeWire(const CMutableTransaction &tx,
                              std::vector<uint8_t> &buf) {
    buf.clear();
    AppendWriter writer{buf};
    SerializeTransaction(tx, writer);
    TransactionWire wire;
    wire.bytes = buf;
    wire.n_inputs = tx.vin.size();
    wire.n_outputs = tx.vout.size();
    for (const CTxIn &in : tx.vin) {
        if (IsLongScript(in.scriptSig.size())) {
            wire.long_script_bytes += in.scriptSig.size();
        }
    }
    for (const CTxOut &out : tx.vout) {
        if (IsLongScript(out.scriptPubKey.size())) {
            wire.long_script_bytes += out.scriptPubKey.size();
        }
    }
    return wire;
}

/** Serialization of CTransaction(): version 2, no inputs or outputs. */
constexpr uint8_t NULL_TRANSACTION_WIRE[] = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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

uint256 HashSerialization(Span<const uint8_t> wire) {
    HashWriter hasher;
    hasher.write(MakeByteSpan(wire));
    return hasher.GetHash();
}

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

TransactionWire ScanTransactionWire(Span<const uint8_t> bytes) {
    size_t pos = 0;
    auto skip = [&](uint64_t count) {
        if (count > bytes.size() - pos) {
            throw std::ios_base::failure("ScanTransactionWire(): end of data");
        }
        pos += count;
    };
    auto read_compact_size = [&]() {
        SpanReader reader{bytes.subspan(pos)};
        const uint64_t n = ReadCompactSize(reader);
        pos = bytes.size() - reader.size();
        return n;
    };
    TransactionWire wire;
    auto skip_script = [&]() {
        const uint64_t size = read_compact_size();
        if (IsLongScript(size)) {
            wire.long_script_bytes += size;
        }
        skip(size);
    };
    skip(sizeof(uint32_t));
    const uint64_t n_inputs = read_compact_size();
    for (uint64_t i = 0; i < n_inputs; ++i) {
        skip(sizeof(uint256) + sizeof(uint32_t));
        skip_script();
        skip(sizeof(uint32_t));
    }
    const uint64_t n_outputs = read_compact_size();
    for (uint64_t i = 0; i < n_outputs; ++i) {
        skip(sizeof(int64_t));
        skip_script();
    }
    skip(sizeof(uint32_t));
    wire.bytes = bytes.first(pos);
    wire.n_inputs = n_inputs;
    wire.n_outputs = n_outputs;
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

    // The bytes were produced by serialization or checked by
    // ReadTransactionWire, so decoding them cannot fail. Short scripts are
    // copied into their CScript; long ones into storage, which they borrow.
    const Span<const uint8_t> bytes = wire.bytes;
    SpanReader reader{bytes};
    auto read_script = [&]() {
        const uint64_t size = ReadCompactSize(reader);
        const size_t offset = bytes.size() - reader.size();
        reader = SpanReader{bytes.subspan(offset + size)};
        Span<const uint8_t> script = bytes.subspan(offset, size);
        if (IsLongScript(size)) {
            uint8_t *dest = scripts + scripts_used;
            std::copy(script.begin(), script.end(), dest);
            scripts_used += size;
            script = {dest, script.size()};
        }
        return CScript::Borrow(script);
    };

    Layout layout;
    reader >> layout.nVersion;
    ReadCompactSize(reader);
    for (uint32_t i = 0; i < wire.n_inputs; ++i) {
        COutPoint prevout;
        reader >> prevout;
        CScript script = read_script();
        uint32_t sequence;
        reader >> sequence;
        // Created const: borrowed scripts must never be modified in place.
        ::new (static_cast<void *>(base + i * sizeof(CTxIn)))
            const CTxIn(prevout, std::move(script), sequence);
    }
    ReadCompactSize(reader);
    for (uint32_t i = 0; i < wire.n_outputs; ++i) {
        Amount value;
        reader >> value;
        ::new (static_cast<void *>(base + offsets.vout + i * sizeof(CTxOut)))
            const CTxOut(value, read_script());
    }
    reader >> layout.nLockTime;
    assert(reader.empty());
    assert(scripts_used == wire.long_script_bytes);

    layout.vin = {std::launder(reinterpret_cast<const CTxIn *>(base)),
                  wire.n_inputs};
    layout.vout = {
        std::launder(reinterpret_cast<const CTxOut *>(base + offsets.vout)),
        wire.n_outputs};
    // Hash now: the serialization is not kept, and a contiguous stream may
    // release it as soon as this returns.
    layout.hash = HashSerialization(bytes);
    layout.serialize_size = bytes.size();
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
      nLockTime(layout.nLockTime), hash(layout.hash),
      m_serialize_size(layout.serialize_size),
      m_long_script_bytes(layout.long_script_bytes),
      m_owns_storage(layout.owned) {}

/**
 * For backward compatibility, the hash is initialized to 0.
 * TODO: remove the need for this default constructor entirely.
 */
CTransaction::CTransaction()
    : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0),
      hash(), m_serialize_size(sizeof(NULL_TRANSACTION_WIRE)),
      m_long_script_bytes(0), m_owns_storage(false) {}

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
    // Same bytes as SerializeTransaction over std::vector fields.
    writer << nVersion;
    WriteCompactSize(writer, vin.size());
    for (const CTxIn &in : vin) {
        writer << in;
    }
    WriteCompactSize(writer, vout.size());
    for (const CTxOut &out : vout) {
        writer << out;
    }
    writer << nLockTime;
    assert(writer.pos() == buf.data() + buf.size());
    return buf;
}

const PrecomputedTransactionData &CTransaction::FillPrecomputedData() const {
    // Hashing is deterministic, so racing callers compute identical data; only
    // the thread that claims the slot writes it.
    const PrecomputedTransactionData computed =
        PrecomputedTransactionData::Compute(*this);
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
