// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-http/src/ws.rs (without plugins).

#include <core/ws/ws_handler.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/proto.h>
#include <chronik/native/script/script.h>
#include <chronik/native/token/structs.h>

#include <array>
#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace chronik::native {

namespace {

using LokadIdKey = std::array<uint8_t, 4>;
using ScriptKey = std::pair<int, Bytes>;

enum class SubKind { Blocks, Txs, TxId, Script, TokenId, LokadId, Plugin };

struct ParsedSub {
    bool is_unsub = false;
    SubKind kind = SubKind::Blocks;
    TxId txid;
    script::ScriptVariant script_variant;
    token::TokenId token_id;
    LokadIdKey lokad_id{};
    std::string plugin_name;
    Bytes plugin_group;
};

/** "Unexpected message type {0}" */
std::string UnexpectedMessageType(const char *type) {
    return std::string("Unexpected message type ") + type;
}
constexpr const char *MISSING_SUB_TYPE =
    "400: Missing sub_type in WsSub message";

std::string ScriptTypeDebug(script::ScriptType type) {
    switch (type) {
        case script::ScriptType::P2PKH:
            return "P2PKH";
        case script::ScriptType::P2SH:
            return "P2SH";
        case script::ScriptType::P2PK:
            return "P2PK";
        case script::ScriptType::Other:
            return "Other";
    }
    return "Other";
}

/** `s.parse::<TxId>()` (Sha256d::from_be_hex), errors with DataError text. */
Hash32 ParseBeHash(std::string_view hex) {
    auto bytes = script::HexDecode(hex);
    if (!bytes) {
        throw ChronikError(bytes.error().ToString());
    }
    if (bytes.value().size() != 32) {
        throw ChronikError(
            script::DataError::InvalidLength(32, bytes.value().size())
                .ToString());
    }
    return Hash32::FromReversed(bytes.value());
}

/** parse.rs parse_script_variant */
script::ScriptVariant ParseScriptVariant(const std::string &script_type,
                                         ByteView payload) {
    auto type = script::ParseScriptType(script_type);
    if (!type) {
        throw ChronikError("400: " + type.error());
    }
    auto variant =
        script::ScriptVariant::FromTypeAndPayload(type.value(), payload);
    if (!variant) {
        throw ChronikError("400: Invalid payload for " +
                           ScriptTypeDebug(type.value()) + ": " +
                           variant.error().ToString());
    }
    return std::move(variant.value());
}

ByteView StrBytes(const std::string &s) {
    return ByteView(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

/** sub_client_msg_action for a binary message */
ParsedSub ParseWsSub(std::span<const uint8_t> data) {
    proto::WsSub sub;
    DecodeProtobuf(data, sub);
    ParsedSub parsed;
    parsed.is_unsub = sub.is_unsub();
    switch (sub.sub_type_case()) {
        case proto::WsSub::SUB_TYPE_NOT_SET:
            throw ChronikError(MISSING_SUB_TYPE);
        case proto::WsSub::kBlocks:
            parsed.kind = SubKind::Blocks;
            break;
        case proto::WsSub::kTxid:
            parsed.kind = SubKind::TxId;
            parsed.txid = ParseBeHash(sub.txid().txid());
            break;
        case proto::WsSub::kScript:
            parsed.kind = SubKind::Script;
            parsed.script_variant = ParseScriptVariant(
                sub.script().script_type(), StrBytes(sub.script().payload()));
            break;
        case proto::WsSub::kTokenId:
            parsed.kind = SubKind::TokenId;
            parsed.token_id = token::TokenId{ParseBeHash(sub.token_id().token_id())};
            break;
        case proto::WsSub::kLokadId:
            parsed.kind = SubKind::LokadId;
            parsed.lokad_id = ParseLokadId(StrBytes(sub.lokad_id().lokad_id()));
            break;
        case proto::WsSub::kPlugin:
            parsed.kind = SubKind::Plugin;
            parsed.plugin_name = sub.plugin().plugin_name();
            parsed.plugin_group.assign(sub.plugin().group().begin(),
                                       sub.plugin().group().end());
            break;
        case proto::WsSub::kTxs:
            parsed.kind = SubKind::Txs;
            break;
    }
    return parsed;
}

std::string HashBytesStr(const Hash32 &h) {
    return std::string(reinterpret_cast<const char *>(h.b.data()), h.b.size());
}

Bytes Encode(const proto::WsMsg &msg) {
    const std::string s = msg.SerializeAsString();
    return Bytes(s.begin(), s.end());
}

/** sub_block_msg_action */
Bytes BlockMsgBytes(const BlockMsg &block_msg) {
    proto::WsMsg msg;
    proto::MsgBlock *block = msg.mutable_block();
    switch (block_msg.msg_type) {
        case BlockMsgType::Connected:
            block->set_msg_type(proto::BLK_CONNECTED);
            break;
        case BlockMsgType::Disconnected:
            block->set_msg_type(proto::BLK_DISCONNECTED);
            break;
        case BlockMsgType::Finalized:
            block->set_msg_type(proto::BLK_FINALIZED);
            break;
        case BlockMsgType::Invalidated:
            block->set_msg_type(proto::BLK_INVALIDATED);
            break;
    }
    block->set_block_hash(HashBytesStr(block_msg.hash));
    block->set_block_height(block_msg.height);
    block->set_block_timestamp(block_msg.timestamp);
    if (block_msg.coinbase_tx) {
        const Tx &tx = *block_msg.coinbase_tx;
        proto::CoinbaseData *data = block->mutable_coinbase_data();
        if (!tx.inputs.empty()) {
            data->set_coinbase_scriptsig(std::string(
                tx.inputs[0].script.begin(), tx.inputs[0].script.end()));
        }
        for (const TxOutput &output : tx.outputs) {
            proto::TxOutput *out = data->add_coinbase_outputs();
            out->set_sats(output.sats);
            out->set_output_script(
                std::string(output.script.begin(), output.script.end()));
        }
    }
    return Encode(msg);
}

/** sub_tx_msg_action */
Bytes TxMsgBytes(const TxMsg &tx_msg) {
    proto::WsMsg msg;
    proto::MsgTx *tx = msg.mutable_tx();
    switch (tx_msg.msg_type.kind) {
        case TxMsgType::Kind::AddedToMempool:
            tx->set_msg_type(proto::TX_ADDED_TO_MEMPOOL);
            break;
        case TxMsgType::Kind::RemovedFromMempool:
            tx->set_msg_type(proto::TX_REMOVED_FROM_MEMPOOL);
            break;
        case TxMsgType::Kind::Confirmed:
            tx->set_msg_type(proto::TX_CONFIRMED);
            break;
        case TxMsgType::Kind::Finalized:
            tx->set_msg_type(proto::TX_FINALIZED);
            tx->mutable_finalization_reason()->set_finalization_type(
                tx_msg.msg_type.reason == TxFinalizationReason::PostConsensus
                    ? proto::TX_FINALIZATION_REASON_POST_CONSENSUS
                    : proto::TX_FINALIZATION_REASON_PRE_CONSENSUS);
            break;
        case TxMsgType::Kind::Invalidated:
            tx->set_msg_type(proto::TX_INVALIDATED);
            break;
    }
    tx->set_txid(HashBytesStr(tx_msg.txid));
    return Encode(msg);
}

class SessionState : public std::enable_shared_from_this<SessionState> {
public:
    SessionState(std::shared_ptr<WsSession> session,
                 std::shared_ptr<SubsHub> hub,
                 std::shared_ptr<SubscriptionLimiter> limiter,
                 WsHandlerSettings settings, SerialExecutor post,
                 HttpLogFn log)
        : m_session(std::move(session)), m_hub(std::move(hub)),
          m_limiter(std::move(limiter)), m_settings(settings),
          m_post(std::move(post)), m_log(std::move(log)),
          m_client_key(SubscriptionClientKey::Ip(m_session->PeerIp())) {
        if (m_settings.observe_connections) {
            try { m_settings.observe_connections(1); } catch (...) {}
        }
    }

    void OnBinary(std::span<const uint8_t> data) {
        bool subscribed = false;
        {
            std::lock_guard lock(m_mutex);
            if (m_closed) {
                return;
            }
            try {
                subscribed = HandleSub(ParseWsSub(data));
            } catch (const std::exception &e) {
                SendError(e.what());
            }
        }
        if (subscribed) {
            // A message may have been sent between Subscribe and SetWaker
            ScheduleDrain();
        }
    }

    void OnText() {
        std::lock_guard lock(m_mutex);
        if (m_closed) {
            return;
        }
        SendError(UnexpectedMessageType("Text"));
    }

    void OnClosed() {
        std::lock_guard lock(m_mutex);
        Cleanup();
    }

    void Drain() {
        std::lock_guard lock(m_mutex);
        if (m_closed) {
            return;
        }
        while (NextAction()) {
        }
    }

    /** Called by wakers (any thread, no locks held). */
    void ScheduleDrain() {
        if (m_drain_scheduled.exchange(true)) {
            return;
        }
        std::weak_ptr<SessionState> weak = weak_from_this();
        m_post([weak] {
            if (auto self = weak.lock()) {
                self->m_drain_scheduled.store(false);
                self->Drain();
            }
        });
    }

    ~SessionState() {
        std::lock_guard lock(m_mutex);
        Cleanup();
    }

private:
    template <typename T> void ArmWaker(BroadcastReceiver<T> &recv) {
        std::weak_ptr<SessionState> weak = weak_from_this();
        recv.SetWaker([weak] {
            if (auto self = weak.lock()) {
                self->ScheduleDrain();
            }
        });
    }

    void LogDebug(const std::string &msg) const {
        if (m_log) {
            m_log(msg, true);
        }
    }

    void Send(Bytes msg) {
        if (m_session) {
            m_session->SendBinary(std::move(msg));
        }
    }

    void NotifyActivity() {
        if (m_session) {
            m_session->NotifyActivity();
        }
    }

    /** Turn Err into Message and reply (not deduplicated). */
    void SendError(std::string_view error_msg) {
        const StatusError status = ReportStatusError(error_msg, m_log);
        proto::WsMsg msg;
        msg.mutable_error()->set_msg(status.msg);
        Send(Encode(msg));
    }

    /** Deduplicate identical consecutive msgs */
    void SendSubMsg(Bytes msg) {
        if (m_last_msg && *m_last_msg == msg) {
            NotifyActivity();
            return;
        }
        m_last_msg = msg;
        Send(std::move(msg));
    }

    /** Handle one queued subscription message; false if none is queued. */
    template <typename T, typename F>
    bool TryRecvOne(BroadcastReceiver<T> &recv, F &&to_bytes) {
        RecvResult<T> r = recv.TryRecv();
        switch (r.status) {
            case RecvStatus::Message:
                SendSubMsg(to_bytes(*r.msg));
                return true;
            case RecvStatus::Lagged:
                // Lagged: WsAction::Nothing
                NotifyActivity();
                return true;
            case RecvStatus::Empty:
            case RecvStatus::Closed:
                return false;
        }
        return false;
    }

    template <typename Map> bool TryRecvMap(Map &map) {
        for (auto &[key, recv] : map) {
            if (TryRecvOne(recv, TxMsgBytes)) {
                return true;
            }
        }
        return false;
    }

    /** One iteration of the biased select over the receivers. */
    bool NextAction() {
        if (m_blocks && TryRecvOne(*m_blocks, BlockMsgBytes)) {
            return true;
        }
        if (m_txs && TryRecvOne(*m_txs, TxMsgBytes)) {
            return true;
        }
        return TryRecvMap(m_txids) || TryRecvMap(m_scripts) ||
               TryRecvMap(m_token_ids) || TryRecvMap(m_lokad_ids);
    }

    void AcquireSub() {
        SubscriptionAcquire acquired = m_limiter->TryAcquire(m_client_key);
        if (!acquired) {
            throw ChronikError(
                WsSubscriptionLimitErrorMessage(*acquired.error));
        }
        m_sub_guards.push_back(std::move(*acquired.guard));
    }

    void ReleaseOneSub() {
        if (!m_sub_guards.empty()) {
            m_sub_guards.pop_back();
        }
    }

    /** Returns whether a new receiver was added. */
    bool HandleSub(const ParsedSub &sub) {
        bool subscribed = false;
        {
            auto subs = m_hub->Write();
            switch (sub.kind) {
                case SubKind::Blocks:
                    if (sub.is_unsub) {
                        LogDebug("WS unsubscribe from blocks\n");
                        if (m_blocks) {
                            m_blocks.reset();
                            ReleaseOneSub();
                        }
                    } else {
                        LogDebug("WS subscribe to blocks\n");
                        // Silently ignore multiple subs to blocks
                        if (!m_blocks) {
                            AcquireSub();
                            m_blocks.emplace(subs->SubToBlockMsgs());
                            ArmWaker(*m_blocks);
                            subscribed = true;
                        }
                    }
                    break;
                case SubKind::Txs:
                    if (sub.is_unsub) {
                        LogDebug("WS unsubscribe from all txs\n");
                        if (m_txs) {
                            m_txs.reset();
                            ReleaseOneSub();
                        }
                    } else {
                        LogDebug("WS subscribe to all txs\n");
                        // Silently ignore multiple subs to all txs
                        if (!m_txs) {
                            AcquireSub();
                            m_txs.emplace(subs->SubToTxMsgs());
                            ArmWaker(*m_txs);
                            subscribed = true;
                        }
                    }
                    break;
                case SubKind::TxId: {
                    const ByteView member(sub.txid.b.data(), 32);
                    if (sub.is_unsub) {
                        LogDebug("WS unsubscribe from txid " +
                                 HashToHex(sub.txid) + "\n");
                        if (m_txids.erase(sub.txid) > 0) {
                            ReleaseOneSub();
                        }
                        subs->SubsTxId().UnsubscribeFromMember(member);
                    } else if (!m_txids.count(sub.txid)) {
                        LogDebug("WS subscribe to txid " +
                                 HashToHex(sub.txid) + "\n");
                        AcquireSub();
                        auto it =
                            m_txids
                                .emplace(sub.txid, subs->SubsTxId()
                                                       .SubscribeToMember(member))
                                .first;
                        ArmWaker(it->second);
                        subscribed = true;
                    }
                    break;
                }
                case SubKind::Script: {
                    const script::Script script =
                        sub.script_variant.ToScript();
                    const ScriptKey key{int(sub.script_variant.type),
                                        sub.script_variant.payload};
                    if (sub.is_unsub) {
                        LogDebug("WS unsubscribe from " +
                                 sub.script_variant.ToString() + "\n");
                        if (m_scripts.erase(key) > 0) {
                            ReleaseOneSub();
                        }
                        subs->SubsScript().UnsubscribeFromMember(
                            script.view());
                    } else if (!m_scripts.count(key)) {
                        const size_t script_len = script.bytecode().size();
                        if (script_len >
                            m_settings.subscription_max_script_size) {
                            throw ChronikError(WsScriptTooLargeMessage(
                                script_len,
                                m_settings.subscription_max_script_size));
                        }
                        LogDebug("WS subscribe to " +
                                 sub.script_variant.ToString() + "\n");
                        AcquireSub();
                        auto it = m_scripts
                                      .emplace(key, subs->SubsScript()
                                                        .SubscribeToMember(
                                                            script.view()))
                                      .first;
                        ArmWaker(it->second);
                        subscribed = true;
                    }
                    break;
                }
                case SubKind::TokenId: {
                    const ByteView member(sub.token_id.txid.b.data(), 32);
                    if (sub.is_unsub) {
                        LogDebug("WS unsubscribe from token ID " +
                                 sub.token_id.ToString() + "\n");
                        if (m_token_ids.erase(sub.token_id) > 0) {
                            ReleaseOneSub();
                        }
                        subs->SubsTokenId().UnsubscribeFromMember(member);
                    } else if (!m_token_ids.count(sub.token_id)) {
                        LogDebug("WS subscribe to token ID " +
                                 sub.token_id.ToString() + "\n");
                        AcquireSub();
                        auto it =
                            m_token_ids
                                .emplace(sub.token_id,
                                         subs->SubsTokenId().SubscribeToMember(
                                             member))
                                .first;
                        ArmWaker(it->second);
                        subscribed = true;
                    }
                    break;
                }
                case SubKind::LokadId: {
                    const ByteView member(sub.lokad_id.data(), 4);
                    if (sub.is_unsub) {
                        LogDebug("WS unsubscribe from LOKAD ID " +
                                 HexEncode(member) + "\n");
                        if (m_lokad_ids.erase(sub.lokad_id) > 0) {
                            ReleaseOneSub();
                        }
                        subs->SubsLokadId().UnsubscribeFromMember(member);
                    } else if (!m_lokad_ids.count(sub.lokad_id)) {
                        LogDebug("WS subscribe to LOKAD ID " +
                                 HexEncode(member) + "\n");
                        AcquireSub();
                        auto it =
                            m_lokad_ids
                                .emplace(sub.lokad_id,
                                         subs->SubsLokadId().SubscribeToMember(
                                             member))
                                .first;
                        ArmWaker(it->second);
                        subscribed = true;
                    }
                    break;
                }
                case SubKind::Plugin:
                    if (!sub.is_unsub &&
                        sub.plugin_group.size() >
                            m_settings.subscription_max_plugin_size) {
                        throw ChronikError(WsPluginGroupTooLargeMessage(
                            sub.plugin_group.size(),
                            m_settings.subscription_max_plugin_size));
                    }
                    // No plugins are loaded in the native implementation
                    throw ChronikError("404: Plugin " +
                                       RustDebugStr(sub.plugin_name) +
                                       " not loaded");
            }
        }
        return subscribed;
    }

    void Cleanup() {
        if (m_closed) {
            return;
        }
        m_closed = true;
        if (m_settings.observe_connections) {
            try { m_settings.observe_connections(-1); } catch (...) {}
        }
        // Dropping guards releases subscription limit slots.
        m_sub_guards.clear();
        const bool has_member_subs = !m_txids.empty() || !m_scripts.empty() ||
                                     !m_token_ids.empty() ||
                                     !m_lokad_ids.empty();
        if (has_member_subs) {
            auto subs = m_hub->Write();
            for (auto it = m_txids.begin(); it != m_txids.end();) {
                const TxId txid = it->first;
                it = m_txids.erase(it);
                subs->SubsTxId().UnsubscribeFromMember(
                    ByteView(txid.b.data(), 32));
            }
            for (auto it = m_scripts.begin(); it != m_scripts.end();) {
                const ScriptKey key = it->first;
                it = m_scripts.erase(it);
                auto variant = script::ScriptVariant::FromTypeAndPayload(
                    script::ScriptType(key.first), key.second);
                if (variant) {
                    subs->SubsScript().UnsubscribeFromMember(
                        variant.value().ToScript().view());
                }
            }
            for (auto it = m_token_ids.begin(); it != m_token_ids.end();) {
                const token::TokenId token_id = it->first;
                it = m_token_ids.erase(it);
                subs->SubsTokenId().UnsubscribeFromMember(
                    ByteView(token_id.txid.b.data(), 32));
            }
            for (auto it = m_lokad_ids.begin(); it != m_lokad_ids.end();) {
                const LokadIdKey lokad_id = it->first;
                it = m_lokad_ids.erase(it);
                subs->SubsLokadId().UnsubscribeFromMember(
                    ByteView(lokad_id.data(), 4));
            }
        }
        m_blocks.reset();
        m_txs.reset();
        m_session.reset();
    }

    std::mutex m_mutex;
    std::shared_ptr<WsSession> m_session;
    std::shared_ptr<SubsHub> m_hub;
    std::shared_ptr<SubscriptionLimiter> m_limiter;
    WsHandlerSettings m_settings;
    SerialExecutor m_post;
    HttpLogFn m_log;
    SubscriptionClientKey m_client_key;
    std::atomic<bool> m_drain_scheduled{false};
    bool m_closed = false;

    std::optional<BroadcastReceiver<BlockMsg>> m_blocks;
    std::optional<BroadcastReceiver<TxMsg>> m_txs;
    std::map<TxId, BroadcastReceiver<TxMsg>> m_txids;
    std::map<ScriptKey, BroadcastReceiver<TxMsg>> m_scripts;
    std::map<token::TokenId, BroadcastReceiver<TxMsg>> m_token_ids;
    std::map<LokadIdKey, BroadcastReceiver<TxMsg>> m_lokad_ids;
    /** Guards for active subscriptions attributed to this connection's IP. */
    std::vector<SubscriptionGuard> m_sub_guards;
    std::optional<Bytes> m_last_msg;
};

class ChronikWsHandler final : public WsHandler {
public:
    explicit ChronikWsHandler(std::shared_ptr<SessionState> state)
        : m_state(std::move(state)) {}
    ~ChronikWsHandler() override {
        // Releases subscriptions even if OnClosed never ran (shutdown)
        m_state->OnClosed();
    }
    void OnBinary(std::span<const uint8_t> msg) override {
        m_state->OnBinary(msg);
    }
    void OnText() override { m_state->OnText(); }
    void OnClosed() override { m_state->OnClosed(); }

private:
    std::shared_ptr<SessionState> m_state;
};

} // namespace

std::unique_ptr<WsHandler>
MakeChronikWsHandler(std::shared_ptr<WsSession> session,
                     std::shared_ptr<SubsHub> hub,
                     std::shared_ptr<SubscriptionLimiter> limiter,
                     WsHandlerSettings settings, SerialExecutor post,
                     HttpLogFn log) {
    auto state = std::make_shared<SessionState>(
        std::move(session), std::move(hub), std::move(limiter), settings,
        std::move(post), std::move(log));
    return std::make_unique<ChronikWsHandler>(std::move(state));
}

} // namespace chronik::native
