// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/mem/group_utxos.h>

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/hex.h>
#include <chronik/native/index/debug_fmt.h>

namespace chronik::native::mem {

MempoolGroupUtxos::MempoolGroupUtxos(const GroupDef &group)
    : m_group(group) {}

void MempoolGroupUtxos::Insert(const MempoolTx &tx,
                               const IsMempoolTxFn &is_mempool_tx,
                               const GroupAux *aux) {
    const GroupQuery query{false, tx.tx.get()};
    std::vector<MemberItem> items;
    m_group.OutputMembers(query, aux, items);
    for (const MemberItem &item : items) {
        Utxos &utxos = EnsureEntry(m_group.SerMember(item.member));
        const OutPoint outpoint{tx.tx->txid, uint32_t(item.idx)};
        if (!utxos.insert(outpoint).second) {
            // UTXO has been added before already -> error
            throw MempoolGroupUtxosError("Inconsistent mempool: UTXO " +
                                         index::DebugOutPoint(outpoint) +
                                         " already exists in mempool");
        }
    }
    items.clear();
    m_group.InputMembers(query, aux, items);
    for (const MemberItem &item : items) {
        const TxInput &input = tx.tx->inputs.at(item.idx);
        if (!is_mempool_tx(input.prev_out.txid)) {
            continue;
        }
        if (std::optional<std::string> err = RemoveUtxo(
                m_group.SerMember(item.member), &tx.tx->txid,
                input.prev_out)) {
            throw MempoolGroupUtxosError(*err);
        }
    }
}

void MempoolGroupUtxos::Remove(const MempoolTx &tx,
                               const IsMempoolTxFn &is_mempool_tx,
                               const GroupAux *aux) {
    const GroupQuery query{false, tx.tx.get()};
    std::vector<MemberItem> items;
    m_group.InputMembers(query, aux, items);
    for (const MemberItem &item : items) {
        const TxInput &input = tx.tx->inputs.at(item.idx);
        if (!is_mempool_tx(input.prev_out.txid)) {
            // If `tx` previously spent a block tx, don't add the UTXO back
            continue;
        }
        Utxos &utxos = EnsureEntry(m_group.SerMember(item.member));
        // Add the UTXO back
        if (!utxos.insert(input.prev_out).second) {
            // If already there, we undid it twice -> error
            throw MempoolGroupUtxosError(
                "Inconsistent mempool: UTXO " +
                index::DebugOutPoint(input.prev_out) +
                " already unspent in mempool");
        }
    }
    items.clear();
    m_group.OutputMembers(query, aux, items);
    for (const MemberItem &item : items) {
        const OutPoint outpoint{tx.tx->txid, uint32_t(item.idx)};
        // Due to our assumption, all outputs of this tx must be unspent,
        // hence a UTXO entry must exist for the member.
        if (std::optional<std::string> err = RemoveUtxo(
                m_group.SerMember(item.member), nullptr, outpoint)) {
            throw MempoolGroupUtxosError(*err);
        }
    }
}

void MempoolGroupUtxos::RemoveMined(const MempoolTx &tx, const GroupAux *aux) {
    const GroupQuery query{false, tx.tx.get()};
    std::vector<MemberItem> items;
    m_group.OutputMembers(query, aux, items);
    for (const MemberItem &item : items) {
        // Discard the error here, which is expected if an output has
        // previously been spent by another mempool tx.
        RemoveUtxo(m_group.SerMember(item.member), nullptr,
                   OutPoint{tx.tx->txid, uint32_t(item.idx)});
    }
}

const MempoolGroupUtxos::Utxos *
MempoolGroupUtxos::GetUtxos(ByteView member_ser) const {
    const auto it = m_utxos.find(Bytes(member_ser.begin(), member_ser.end()));
    return it == m_utxos.end() ? nullptr : &it->second;
}

void MempoolGroupUtxos::VisitPrefix(
    ByteView member_prefix, ByteView member_start,
    const std::function<bool(const Bytes &, const Utxos &)> &visit) const {
    for (auto it =
             m_utxos.lower_bound(Bytes(member_start.begin(), member_start.end()));
         it != m_utxos.end(); ++it) {
        if (!StartsWith(it->first, member_prefix)) {
            return;
        }
        if (!visit(it->first, it->second)) {
            return;
        }
    }
}

MempoolGroupUtxos::Utxos &MempoolGroupUtxos::EnsureEntry(ByteView member_ser) {
    return m_utxos[Bytes(member_ser.begin(), member_ser.end())];
}

std::optional<std::string>
MempoolGroupUtxos::RemoveUtxo(ByteView member_ser, const TxId *txid,
                              const OutPoint &outpoint) {
    auto make_err = [&] {
        if (txid) {
            return "Inconsistent mempool: UTXO " +
                   index::DebugOutPoint(outpoint) + " spent by " +
                   HashToHex(*txid) + " doesn't exist in mempool";
        }
        return "Inconsistent mempool when removing tx: UTXO " +
               index::DebugOutPoint(outpoint) + " doesn't exist in mempool";
    };
    const auto it = m_utxos.find(Bytes(member_ser.begin(), member_ser.end()));
    if (it == m_utxos.end()) {
        return make_err();
    }
    if (it->second.erase(outpoint) == 0) {
        return make_err();
    }
    if (it->second.empty()) {
        // Clean up if there's no utxos for this member anymore
        m_utxos.erase(it);
    }
    return std::nullopt;
}

} // namespace chronik::native::mem
