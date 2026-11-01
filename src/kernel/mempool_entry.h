// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MEMPOOL_ENTRY_H
#define BITCOIN_KERNEL_MEMPOOL_ENTRY_H

#include <consensus/amount.h>
#include <core_memusage.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <rcu.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <set>

struct LockPoints {
    // Will be set to the blockchain height and median time past values that
    // would be necessary to satisfy all relative locktime constraints (BIP68)
    // of this tx given our view of block chain history
    int height{0};
    int64_t time{0};
};

/**
 * 4-state transaction pre-consensus lifecycle:
 *   0. MEMPOOL    — Validated in local mempool; not yet converged in an epoch.
 *   1. FROZEN     — Included in an epoch that reached beta_snow consecutive
 *                   matching Snowstorm rounds.
 *   2. FINALIZED  — Included in an epoch batch finalized by Avalanche (or
 *                   transitively finalized by a later epoch E' >= E).
 *   3. CONFIRMED  — Included in a connected block on the active chain.
 */
enum class TxPreconsensusState : uint8_t {
    MEMPOOL = 0,
    FROZEN = 1,
    SNOWBALLED = FROZEN,
    FINALIZED = 2,
    CONFIRMED = 3,
};

inline const char *
TxPreconsensusStateToString(TxPreconsensusState state) noexcept {
    switch (state) {
    case TxPreconsensusState::MEMPOOL:
        return "mempool";
    case TxPreconsensusState::FROZEN:
        return "frozen";
    case TxPreconsensusState::FINALIZED:
        return "finalized";
    case TxPreconsensusState::CONFIRMED:
        return "confirmed";
    }
    return "mempool";
}

struct CompareIteratorById {
    // SFINAE for T where T is either a std::reference_wrapper<T> (e.g. a
    // CTxMemPoolEntryRef) or an iterator to a pointer type (e.g., a txiter)
    template <typename T>
    bool operator()(const std::reference_wrapper<T> &a,
                    const std::reference_wrapper<T> &b) const {
        return a.get()->GetTx().GetId() < b.get()->GetTx().GetId();
    }
    template <typename T> bool operator()(const T &a, const T &b) const {
        return (*a)->GetTx().GetId() < (*b)->GetTx().GetId();
    }
};
/** Iterate txs in reverse-topological order */
struct CompareIteratorByRevEntryId {
    template <typename T>
    bool operator()(const std::reference_wrapper<T> &a,
                    const std::reference_wrapper<T> &b) const {
        return a.get()->GetEntryId() > b.get()->GetEntryId();
    }

    template <typename T> bool operator()(const T &a, const T &b) const {
        return (*a)->GetEntryId() > (*b)->GetEntryId();
    }
};

class CTxMemPoolEntry;
using CTxMemPoolEntryRef = RCUPtr<CTxMemPoolEntry>;

/** \class CTxMemPoolEntry
 *
 * CTxMemPoolEntry stores data about the corresponding transaction, as well as
 * data about all in-mempool transactions that depend on the transaction
 * ("descendant" transactions).
 */

class CTxMemPoolEntry {
public:
    // two aliases, should the types ever diverge
    typedef std::set<std::reference_wrapper<const CTxMemPoolEntryRef>,
                     CompareIteratorById>
        Parents;
    typedef std::set<std::reference_wrapper<const CTxMemPoolEntryRef>,
                     CompareIteratorById>
        Children;

private:
    //! Unique identifier -- used for topological sorting
    uint64_t entryId = 0;

    const CTransactionRef tx;
    const TxId m_txid;
    mutable Parents m_parents;
    mutable Children m_children;
    //! Cached to avoid expensive parent-transaction lookups
    const Amount nFee;
    //! ... and avoid recomputing tx size
    const size_t nTxSize;
    //! ... and total memory usage
    const size_t nUsageSize;
    //! Local time when entering the mempool
    const int64_t nTime;
    //! Chain height when entering the mempool
    const unsigned int entryHeight;
    //! Total sigChecks
    const int64_t sigChecks;
    //! Used for determining the priority of the transaction for mining in a
    //! block
    std::atomic<Amount> m_modified_fee{Amount::zero()};
    //! Whether this locally submitted transaction awaits initial broadcast
    mutable std::atomic<bool> m_unbroadcast{false};
    //! Lock-free pre-consensus lifecycle state (TxPreconsensusState)
    mutable std::atomic<uint8_t> m_preconsensus_state{
        static_cast<uint8_t>(TxPreconsensusState::MEMPOOL)};
    //! Pre-consensus epoch sequence number (0 if not yet assigned to an epoch)
    mutable std::atomic<uint32_t> m_epoch_seq{0};
    //! Track the height and time at which tx was final
    LockPoints lockPoints;

    IMPLEMENT_RCU_REFCOUNT(uint64_t);

public:
    CTxMemPoolEntry(const CTransactionRef &_tx, const Amount fee, int64_t time,
                    unsigned int entry_height, int64_t sigchecks, LockPoints lp)
        : tx{_tx}, m_txid{tx->GetId()}, nFee{fee}, nTxSize(tx->GetTotalSize()),
          nUsageSize{RecursiveDynamicUsage(tx)}, nTime(time),
          entryHeight{entry_height}, sigChecks(sigchecks), m_modified_fee{nFee},
          lockPoints(lp) {}

    CTxMemPoolEntry(const CTxMemPoolEntry &other) = delete;
    CTxMemPoolEntry(CTxMemPoolEntry &&other)
        : entryId(other.entryId), tx(std::move(other.tx)),
          m_txid(other.m_txid),
          m_parents(std::move(other.m_parents)),
          m_children(std::move(other.m_children)), nFee(other.nFee),
          nTxSize(other.nTxSize), nUsageSize(other.nUsageSize),
          nTime(other.nTime), entryHeight(other.entryHeight),
          sigChecks(other.sigChecks),
          m_modified_fee(other.m_modified_fee.load(std::memory_order_relaxed)),
          m_unbroadcast(other.m_unbroadcast.load(std::memory_order_relaxed)),
          m_preconsensus_state(
              other.m_preconsensus_state.load(std::memory_order_relaxed)),
          m_epoch_seq(other.m_epoch_seq.load(std::memory_order_relaxed)),
          lockPoints(std::move(other.lockPoints)),
          refcount(other.refcount.load()) {};

    uint64_t GetEntryId() const { return entryId; }
    //! This should only be set by addUnchecked() before entry insertion into
    //! mempool
    void SetEntryId(uint64_t eid) { entryId = eid; }

    const TxId &GetTxId() const noexcept { return m_txid; }
    const CTransaction &GetTx() const { return *this->tx; }
    CTransactionRef GetSharedTx() const { return this->tx; }
    Amount GetFee() const { return nFee; }
    size_t GetTxSize() const { return nTxSize; }
    size_t GetTxVirtualSize() const {
        return GetVirtualTransactionSize(nTxSize, sigChecks,
                                         ::nBytesPerSigCheck);
    }

    std::chrono::seconds GetTime() const { return std::chrono::seconds{nTime}; }
    unsigned int GetHeight() const { return entryHeight; }
    int64_t GetSigChecks() const { return sigChecks; }
    Amount GetModifiedFee() const {
        return m_modified_fee.load(std::memory_order_relaxed);
    }
    CFeeRate GetModifiedFeeRate() const {
        return CFeeRate(GetModifiedFee(), GetTxVirtualSize());
    }
    size_t DynamicMemoryUsage() const { return nUsageSize; }
    const LockPoints &GetLockPoints() const { return lockPoints; }

    // Updates the modified fees used for mining priority score
    void UpdateModifiedFee(Amount fee_diff) {
        Amount cur = m_modified_fee.load(std::memory_order_relaxed);
        cur.SaturatingAdd(fee_diff);
        m_modified_fee.store(cur, std::memory_order_relaxed);
    };

    bool IsUnbroadcast() const noexcept {
        return m_unbroadcast.load(std::memory_order_relaxed);
    }

    bool SetUnbroadcast(bool unbroadcast) const noexcept {
        return m_unbroadcast.exchange(unbroadcast, std::memory_order_relaxed) !=
               unbroadcast;
    }

    TxPreconsensusState GetPreconsensusState() const noexcept {
        return static_cast<TxPreconsensusState>(
            m_preconsensus_state.load(std::memory_order_relaxed));
    }

    void SetPreconsensusState(TxPreconsensusState state) const noexcept {
        m_preconsensus_state.store(static_cast<uint8_t>(state),
                                   std::memory_order_relaxed);
    }

    bool AdvancePreconsensusState(TxPreconsensusState next_state) const noexcept {
        const uint8_t target = static_cast<uint8_t>(next_state);
        uint8_t cur = m_preconsensus_state.load(std::memory_order_relaxed);
        while (cur < target) {
            if (m_preconsensus_state.compare_exchange_weak(
                    cur, target, std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }

    uint32_t GetEpochSeq() const noexcept {
        return m_epoch_seq.load(std::memory_order_relaxed);
    }

    void SetEpochSeq(uint32_t epoch_seq) const noexcept {
        m_epoch_seq.store(epoch_seq, std::memory_order_relaxed);
    }

    const Parents &GetMemPoolParentsConst() const { return m_parents; }
    const Children &GetMemPoolChildrenConst() const { return m_children; }
    Parents &GetMemPoolParents() const { return m_parents; }
    Children &GetMemPoolChildren() const { return m_children; }
};

#endif // BITCOIN_KERNEL_MEMPOOL_ENTRY_H
