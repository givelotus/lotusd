// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/txrelay_index.h>

#include <crypto/siphash.h>
#include <logging.h>
#include <logging/values.h>
#include <lotus_v2/set_reconciliation.h>
#include <node/metrics.h>

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace txrelay {

EpochKey MakeEpochKey(const BlockHash &tip, uint64_t height) {
    lotus::v2::Hash prev{};
    std::memcpy(prev.data(), tip.begin(), prev.size());
    const auto [k0, k1] = lotus::v2::DeriveEpochSipHashKey(prev, height);
    return EpochKey{uint256{tip}, k0, k1};
}

uint64_t ComputeShortId(uint64_t k0, uint64_t k1, const TxId &txid,
                        unsigned bits) {
    // Same function as the Merklix handler's ComputeMerklixShortId, so the
    // handler's request matching and summaries agree with the index.
    uint64_t id{SipHashUint256(k0, k1, txid)};
    if (bits < 64) {
        id &= (uint64_t{1} << bits) - 1;
    }
    return id != 0 ? id : 1;
}

uint256 ShortIdRequestKey(const uint256 &epoch_id, uint64_t short_id) {
    uint256 key{epoch_id};
    for (unsigned i = 0; i < 8; ++i) {
        key.begin()[i] = uint8_t(short_id >> (8 * i));
    }
    return key;
}

std::optional<uint64_t> ParseShortIdRequestKey(const uint256 &key,
                                               const uint256 &epoch_id) {
    if (std::memcmp(key.begin() + 8, epoch_id.begin() + 8, 24) != 0) {
        return std::nullopt;
    }
    uint64_t short_id{0};
    for (unsigned i = 0; i < 8; ++i) {
        short_id |= uint64_t(key.begin()[i]) << (8 * i);
    }
    return short_id;
}

TxRelayIndex::TxRelayIndex(unsigned shortid_bits)
    : m_bits{std::clamp(shortid_bits, 1U, 64U)} {}

void TxRelayIndex::InsertUnlocked(Epoch &epoch, const TxId &txid) const {
    const uint64_t short_id{ShortId(epoch.key, txid)};
    if (!epoch.short_id_of.emplace(txid, short_id).second) {
        return;
    }
    auto &txids{epoch.by_short_id[short_id]};
    if (!txids.empty()) {
        // Keep both: either may be requested under this short id.
        ++m_collisions;
        if (auto *m{node::GetNodeMetrics()}) {
            m->txrelay_shortid_collision.Inc();
        }
        LogEvent(BCLog::TXRELAY, "mempool_tx_shortid_collision",
                 "short id {short_id} of {txid} already holds {count} "
                 "transaction(s) in this epoch")
            .Field(BCLog::LogField::TxId, txid)
            .Field(BCLog::LogField::ShortId, short_id)
            .Field(BCLog::LogField::Count, uint64_t(txids.size()));
    }
    txids.push_back(txid);
}

void TxRelayIndex::SetEpoch(const EpochKey &key,
                            const std::function<Snapshot()> &snapshot) {
    LOCK(m_rebuild_mutex);
    {
        LOCK(m_mutex);
        if (m_current && m_current->key == key) {
            return;
        }
        m_epoch_changes.clear();
        m_epoch_overflow = false;
        m_rebuilding = true;
    }
    try {
        // Start tracking before taking the snapshot, covering the gap between
        // releasing the mempool lock and building the new epoch as well.
        const auto txs{snapshot()};
        auto epoch{std::make_unique<Epoch>()};
        epoch->key = key;
        epoch->by_short_id.reserve(txs.size());
        epoch->short_id_of.reserve(txs.size());
        for (const auto &[txid, time] : txs) {
            InsertUnlocked(*epoch, txid);
        }
        LOCK(m_mutex);
        m_rebuilding = false;
        if (m_epoch_overflow) {
            // A bounded failed attempt: keep serving the old epoch. Sustained
            // churn can defer rekeying, but must never publish a stale index.
            m_epoch_changes.clear();
            return;
        }
        for (const auto &[txid, present] : m_epoch_changes) {
            if (present) {
                InsertUnlocked(*epoch, txid);
            } else {
                RemoveFromEpoch(*epoch, txid);
            }
        }
        m_epoch_changes.clear();
        if (!m_current) {
            // Include admissions during the initial snapshot as well as those
            // that already existed before the first index was constructed.
            std::vector<std::pair<Clock, TxId>> window{m_window.begin(),
                                                       m_window.end()};
            window.reserve(window.size() + txs.size());
            for (const auto &[txid, time] : txs) {
                window.emplace_back(time, txid);
            }
            std::stable_sort(
                window.begin(), window.end(),
                [](const auto &a, const auto &b) { return a.first < b.first; });
            m_window.assign(window.begin(), window.end());
        }
        m_previous = std::move(m_current);
        m_current = std::move(epoch);
    } catch (...) {
        LOCK(m_mutex);
        m_rebuilding = false;
        m_epoch_changes.clear();
        throw;
    }
}

void TxRelayIndex::RecordEpochChange(const TxId &txid, bool present) {
    if (!m_rebuilding || m_epoch_overflow) {
        return;
    }
    if (m_epoch_changes.size() == MAX_EPOCH_CHANGES) {
        m_epoch_overflow = true;
        return;
    }
    m_epoch_changes.emplace_back(txid, present);
}

std::optional<EpochKey> TxRelayIndex::Current() const {
    LOCK(m_mutex);
    if (!m_current) {
        return std::nullopt;
    }
    return m_current->key;
}

std::vector<EpochKey> TxRelayIndex::Epochs() const {
    LOCK(m_mutex);
    std::vector<EpochKey> out;
    if (m_current) {
        out.push_back(m_current->key);
    }
    if (m_previous) {
        out.push_back(m_previous->key);
    }
    return out;
}

const TxRelayIndex::Epoch *TxRelayIndex::Get(const uint256 &epoch_id) const {
    if (m_current && m_current->key.epoch_id == epoch_id) {
        return m_current.get();
    }
    if (m_previous && m_previous->key.epoch_id == epoch_id) {
        return m_previous.get();
    }
    return nullptr;
}

std::optional<EpochKey> TxRelayIndex::FindEpoch(const uint256 &epoch_id) const {
    LOCK(m_mutex);
    const Epoch *epoch{Get(epoch_id)};
    if (!epoch) {
        return std::nullopt;
    }
    return epoch->key;
}

void TxRelayIndex::Add(const TxId &txid, Clock time) {
    LOCK(m_mutex);
    RecordEpochChange(txid, true);
    if (m_current) {
        if (m_current->short_id_of.count(txid)) {
            return;
        }
        InsertUnlocked(*m_current, txid);
    }
    m_window.emplace_back(time, txid);
}

void TxRelayIndex::RemoveFromEpoch(Epoch &epoch, const TxId &txid) {
    const auto it{epoch.short_id_of.find(txid)};
    if (it == epoch.short_id_of.end()) {
        return;
    }
    const auto bucket{epoch.by_short_id.find(it->second)};
    if (bucket != epoch.by_short_id.end()) {
        auto &txids{bucket->second};
        txids.erase(std::remove(txids.begin(), txids.end(), txid), txids.end());
        if (txids.empty()) {
            epoch.by_short_id.erase(bucket);
        }
    }
    epoch.short_id_of.erase(it);
}

void TxRelayIndex::Remove(const TxId &txid) {
    LOCK(m_mutex);
    RecordEpochChange(txid, false);
    if (m_current) {
        RemoveFromEpoch(*m_current, txid);
    }
}

TxRelayIndex::Lookup TxRelayIndex::Find(const uint256 &epoch_id,
                                        uint64_t short_id,
                                        std::vector<TxId> *out) const {
    LOCK(m_mutex);
    const Epoch *epoch{Get(epoch_id)};
    if (!epoch) {
        return Lookup::UNKNOWN_EPOCH;
    }
    const auto it{epoch->by_short_id.find(short_id)};
    if (it == epoch->by_short_id.end()) {
        return Lookup::MISSING;
    }
    if (out) {
        out->insert(out->end(), it->second.begin(), it->second.end());
    }
    return Lookup::HAVE;
}

std::vector<TxId> TxRelayIndex::AdmittedSince(Clock since, Clock until) const {
    LOCK(m_mutex);
    std::vector<TxId> out;
    if (!m_current) {
        return out;
    }
    std::unordered_set<TxId, SaltedTxIdHasher> seen;
    for (auto it = m_window.rbegin(); it != m_window.rend(); ++it) {
        if (it->first < since) {
            break;
        }
        if (it->first >= until) {
            continue;
        }
        if (m_current->short_id_of.count(it->second) &&
            seen.insert(it->second).second) {
            out.push_back(it->second);
        }
    }
    return out;
}

void TxRelayIndex::PruneWindow(Clock before) {
    LOCK(m_mutex);
    while (!m_window.empty() && m_window.front().first < before) {
        m_window.pop_front();
    }
}

size_t TxRelayIndex::Size() const {
    LOCK(m_mutex);
    return m_current ? m_current->short_id_of.size() : 0;
}

} // namespace txrelay
