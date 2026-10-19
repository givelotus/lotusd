// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer subs.rs and subs_group.rs.

#include <chronik/native/subs.h>

#include <chronik/native/codec/script_compress.h>
#include <chronik/native/token/lokad_id.h>

#include <set>

namespace chronik::native {

namespace {

constexpr uint8_t OP_RETURN = 0x6a;

Bytes ToBytes(ByteView v) { return Bytes(v.begin(), v.end()); }

Bytes ReversedBytes(ByteView v) { return Bytes(v.rbegin(), v.rend()); }

} // namespace

// ---- Group kinds ----

Bytes TxIdSubsGroupKind::SerMember(ByteView member) const {
    // member.hash().to_be_bytes()
    return ReversedBytes(member);
}

void TxIdSubsGroupKind::TxMembers(const Tx &tx, const SubsAux &,
                                  std::vector<SubsMember> &out) const {
    // input_members: none; output_members: the txid itself
    out.push_back({ReversedBytes(tx.txid.b), std::nullopt});
}

Bytes ScriptSubsGroupKind::SerMember(ByteView member) const {
    return CompressScript(member);
}

std::array<uint8_t, 32> ScriptSubsGroupKind::HashMember(ByteView script) const {
    uint8_t digest[32];
    m_sha256(script, digest);
    std::array<uint8_t, 32> be;
    for (size_t i = 0; i < 32; ++i) {
        be[i] = digest[31 - i];
    }
    return be;
}

void ScriptSubsGroupKind::TxMembers(const Tx &tx, const SubsAux &,
                                    std::vector<SubsMember> &out) const {
    // ScriptGroupIter with is_coinbase = false (SubsGroup's GroupQuery):
    // inputs stop at the first input without a coin.
    for (const TxInput &input : tx.inputs) {
        if (!input.coin) {
            break;
        }
        const Bytes &script = input.coin->output.script;
        out.push_back({CompressScript(script), HashMember(script)});
    }
    // Outputs skip OP_RETURN scripts.
    for (const TxOutput &output : tx.outputs) {
        if (!output.script.empty() && output.script[0] == OP_RETURN) {
            continue;
        }
        out.push_back({CompressScript(output.script), HashMember(output.script)});
    }
}

Bytes TokenIdSubsGroupKind::SerMember(ByteView member) const {
    // TokenId::to_be_bytes
    return ReversedBytes(member);
}

void TokenIdSubsGroupKind::TxMembers(const Tx &tx, const SubsAux &aux,
                                     std::vector<SubsMember> &out) const {
    if (!aux.token_id) {
        return;
    }
    auto it = aux.token_id->txs.find(tx.txid);
    if (it == aux.token_id->txs.end()) {
        return;
    }
    // input_members (is_coinbase is false here), then output_members
    for (const auto &token_id : it->second.first) {
        if (token_id) {
            const auto be = token_id->ToBeBytes();
            out.push_back({Bytes(be.begin(), be.end()), std::nullopt});
        }
    }
    for (const auto &token_id : it->second.second) {
        if (token_id) {
            const auto be = token_id->ToBeBytes();
            out.push_back({Bytes(be.begin(), be.end()), std::nullopt});
        }
    }
}

Bytes LokadIdSubsGroupKind::SerMember(ByteView member) const {
    return ToBytes(member);
}

void LokadIdSubsGroupKind::TxMembers(const Tx &tx, const SubsAux &,
                                     std::vector<SubsMember> &out) const {
    for (const token::LokadId &id : token::ParseTxLokadIds(tx)) {
        out.push_back({Bytes(id.begin(), id.end()), std::nullopt});
    }
}

// ---- SubsGroup ----

BroadcastReceiver<TxMsg> SubsGroup::SubscribeToSer(ByteView member_ser) {
    auto it = m_subs.find(member_ser);
    if (it != m_subs.end()) {
        return it->second.Subscribe();
    }
    BroadcastSender<TxMsg> sender(GROUP_CHANNEL_CAPACITY);
    BroadcastReceiver<TxMsg> receiver = sender.Subscribe();
    m_subs.emplace(ToBytes(member_ser), std::move(sender));
    return receiver;
}

void SubsGroup::UnsubscribeFromSer(ByteView member_ser) {
    auto it = m_subs.find(member_ser);
    if (it != m_subs.end() && it->second.ReceiverCount() == 0) {
        m_subs.erase(it);
    }
}

void SubsGroup::HandleTxEvent(const Tx &tx, const SubsAux &aux,
                              TxMsgType msg_type, WakerList *wakers) {
    const TxMsg msg{msg_type, tx.txid};
    m_scratch.clear();
    m_kind->TxMembers(tx, aux, m_scratch);
    std::set<Bytes, SubsKeyLess> already_notified;
    std::set<std::array<uint8_t, 32>> already_notified_hash;
    for (const SubsMember &member : m_scratch) {
        if (!already_notified.count(member.ser)) {
            auto it = m_subs.find(member.ser);
            if (it != m_subs.end()) {
                // Unclean unsubscribe
                if (!it->second.Send(msg, wakers)) {
                    m_subs.erase(it);
                }
            }
            already_notified.insert(member.ser);
        }
        // What is below is only for ScriptGroup
        if (!member.hash) {
            continue;
        }
        if (!already_notified_hash.count(*member.hash)) {
            auto it = m_subs.find(*member.hash);
            if (it != m_subs.end()) {
                // Unclean unsubscribe
                if (!it->second.Send(msg, wakers)) {
                    m_subs.erase(it);
                }
            }
            already_notified_hash.insert(*member.hash);
        }
    }
}

// ---- Subs ----

Subs::Subs(Sha256Fn sha256)
    : Subs(std::make_unique<TxIdSubsGroupKind>(),
           std::make_unique<ScriptSubsGroupKind>(std::move(sha256)),
           std::make_unique<TokenIdSubsGroupKind>(),
           std::make_unique<LokadIdSubsGroupKind>()) {}

Subs::Subs(std::unique_ptr<SubsGroupKind> txid,
           std::unique_ptr<SubsGroupKind> script,
           std::unique_ptr<SubsGroupKind> token_id,
           std::unique_ptr<SubsGroupKind> lokad_id)
    : m_subs_txid(std::move(txid)), m_subs_script(std::move(script)),
      m_subs_token_id(std::move(token_id)),
      m_subs_lokad_id(std::move(lokad_id)) {}

void Subs::TxEventAllGroups(const Tx &tx, TxMsgType msg_type,
                            const SubsAux &aux) {
    BroadcastTxMsg(tx.txid, msg_type);
    m_subs_txid.HandleTxEvent(tx, aux, msg_type, &m_pending_wakers);
    m_subs_script.HandleTxEvent(tx, aux, msg_type, &m_pending_wakers);
    m_subs_token_id.HandleTxEvent(tx, aux, msg_type, &m_pending_wakers);
    m_subs_lokad_id.HandleTxEvent(tx, aux, msg_type, &m_pending_wakers);
}

void Subs::HandleTxEvent(const Tx &tx, TxMsgType msg_type, const SubsAux &aux) {
    TxEventAllGroups(tx, msg_type, aux);
}

bool Subs::AllGroupsEmpty() const {
    return m_subs_txid.IsEmpty() && m_subs_script.IsEmpty() &&
           m_subs_token_id.IsEmpty() && m_subs_lokad_id.IsEmpty();
}

void Subs::HandleBlockTxEvents(const std::vector<TxRef> &txs,
                               TxMsgType msg_type, const SubsAux &aux) {
    if (AllGroupsEmpty()) {
        // Short-circuit if no subscriptions
        return;
    }
    for (const TxRef &tx : txs) {
        TxEventAllGroups(*tx, msg_type, aux);
    }
}

void Subs::HandleBlockTxEvents(const std::vector<Tx> &txs, TxMsgType msg_type,
                               const SubsAux &aux) {
    if (AllGroupsEmpty()) {
        // Short-circuit if no subscriptions
        return;
    }
    for (const Tx &tx : txs) {
        TxEventAllGroups(tx, msg_type, aux);
    }
}

void Subs::BroadcastBlockMsg(const BlockMsg &msg) {
    // receiver_count() > 0 check and send are atomic here, so Rust's
    // "Unexpected send error" log cannot happen.
    m_subs_block.Send(msg, &m_pending_wakers);
}

void Subs::BroadcastTxMsg(const TxId &txid, TxMsgType msg_type) {
    m_subs_txs.Send(TxMsg{msg_type, txid}, &m_pending_wakers);
}

} // namespace chronik::native
