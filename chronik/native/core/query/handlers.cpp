// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-http handlers.rs and the query routes of server.rs
// make_router (everything except /blockchain-info, /chronik-info, /ws,
// /pause and /resume, which are registered elsewhere).

#include <chronik/native/routes.h>

#include <core/query/query.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/groups/token_id.h>
#include <chronik/native/http.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/mem/mempool.h>
#include <chronik/native/proto.h>
#include <chronik/native/script/script.h>

#include <algorithm>
#include <limits>
#include <map>
#include <string>
#include <tuple>

namespace chronik::native {

namespace {

using query::GroupMemberArg;
using QueryParamMap = std::map<std::string, std::string>;

// ------------------------------------------------------------ params ----

/**
 * Rust `str::parse::<T>()` for the integer types, returning the
 * `ParseIntError` Display text on failure.
 */
std::optional<std::string> ParseRustIntError(std::string_view s, bool is_signed,
                                             __int128 min, __int128 max,
                                             int64_t &out) {
    if (s.empty()) {
        return "cannot parse integer from empty string";
    }
    size_t i = 0;
    bool neg = false;
    if (s[0] == '+' || (s[0] == '-' && is_signed)) {
        neg = s[0] == '-';
        i = 1;
        if (s.size() == 1) {
            return "invalid digit found in string";
        }
    }
    __int128 value = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return "invalid digit found in string";
        }
        const int digit = s[i] - '0';
        value = value * 10 + (neg ? -digit : digit);
        if (value > max) {
            return "number too large to fit in target type";
        }
        if (value < min) {
            return "number too small to fit in target type";
        }
    }
    out = int64_t(value);
    return std::nullopt;
}

/** handlers.rs get_param: "400: Invalid param {name}: {value}, {msg}" */
std::optional<int64_t> GetIntParam(const QueryParamMap &params,
                                   const std::string &param_name,
                                   bool is_signed, __int128 min, __int128 max) {
    const auto it = params.find(param_name);
    if (it == params.end()) {
        return std::nullopt;
    }
    int64_t value = 0;
    if (auto err = ParseRustIntError(it->second, is_signed, min, max, value)) {
        throw ChronikError("400: Invalid param " + param_name + ": " +
                           it->second + ", " + *err);
    }
    return value;
}

uint32_t GetU32Param(const QueryParamMap &params, const std::string &name,
                     uint32_t default_value) {
    return uint32_t(GetIntParam(params, name, false, 0,
                                std::numeric_limits<uint32_t>::max())
                        .value_or(default_value));
}

int32_t GetI32Param(const QueryParamMap &params, const std::string &name,
                    int32_t default_value) {
    return int32_t(GetIntParam(params, name, true,
                               std::numeric_limits<int32_t>::min(),
                               std::numeric_limits<int32_t>::max())
                       .value_or(default_value));
}

struct PageParams {
    size_t page_num;
    size_t page_size;
};
PageParams GetPageParams(const QueryParamMap &params) {
    const uint32_t page_num = GetU32Param(params, "page", 0);
    const uint32_t page_size =
        GetU32Param(params, "page_size", query::DEFAULT_PAGE_SIZE);
    return {page_num, page_size};
}

/** TxId::from_str wrapped as "400: Not a txid: {txid}" */
TxId ParseTxId(const std::string &txid) {
    if (std::optional<Hash32> hash = query::ParseHashBeHex(txid)) {
        return *hash;
    }
    throw ChronikError("400: Not a txid: " + txid);
}

/** TokenId::from_str with `?` (unprefixed DataError => 500). */
TxId ParseTokenId(const std::string &token_id_hex) {
    auto bytes = script::HexDecode(token_id_hex);
    if (!bytes.ok()) {
        throw ChronikError(bytes.error().ToString());
    }
    if (bytes.value().size() != 32) {
        throw ChronikError(
            script::DataError::InvalidLength(32, bytes.value().size())
                .ToString());
    }
    return Hash32::FromReversed(bytes.value());
}

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

/** parse.rs parse_script_variant_hex(...).to_script() */
Bytes ParseScriptVariantHex(std::string_view script_type,
                            std::string_view payload_hex) {
    const Bytes payload = ParseHex(payload_hex);
    const auto type = script::ParseScriptType(script_type);
    if (!type.ok()) {
        throw ChronikError("400: " + type.error());
    }
    const auto variant =
        script::ScriptVariant::FromTypeAndPayload(type.value(), payload);
    if (!variant.ok()) {
        throw ChronikError("400: Invalid payload for " +
                           ScriptTypeDebug(type.value()) + ": " +
                           variant.error().ToString());
    }
    return variant.value().ToScript().bytecode();
}

/** handlers.rs get_group_member */
GroupMemberArg GetGroupMember(std::string_view script_type,
                              std::string_view payload) {
    GroupMemberArg member;
    if (script_type == "scripthash") {
        std::optional<Bytes> bytes = HexDecode(payload);
        if (!bytes || bytes->size() != 32) {
            throw ChronikError("400: Unable to parse script hash " +
                               RustDebugStr(payload));
        }
        std::copy(bytes->begin(), bytes->end(), member.member_hash.begin());
        return member;
    }
    member.member = ParseScriptVariantHex(script_type, payload);
    return member;
}

/** Verifies the batch is non-empty, within 500, and has no duplicates */
void CheckBatchScriptValidity(
    const google::protobuf::RepeatedPtrField<proto::ScriptRef> &scripts) {
    const size_t n = size_t(scripts.size());
    if (n == 0) {
        throw ChronikError(
            "400: Batch script request must include at least one script");
    }
    if (n > query::MAX_NUM_BATCH_SCRIPTS) {
        throw ChronikError("400: Too many scripts in batch: max is " +
                           std::to_string(query::MAX_NUM_BATCH_SCRIPTS) +
                           ", got " + std::to_string(n));
    }
    std::vector<std::pair<std::string_view, std::string_view>> keys;
    keys.reserve(n);
    for (const proto::ScriptRef &s : scripts) {
        keys.emplace_back(s.script_type(), s.payload());
    }
    std::sort(keys.begin(), keys.end());
    if (std::adjacent_find(keys.begin(), keys.end()) != keys.end()) {
        throw ChronikError("400: Duplicate script entries in batch request");
    }
}

[[noreturn]] void PluginNotLoaded(const std::string &plugin_name) {
    throw ChronikError("404: Plugin " + RustDebugStr(plugin_name) +
                       " not loaded");
}

// ------------------------------------------------------------ context ----

struct Ctx {
    const IndexerImpl &indexer;
    const Host &host;

    query::RenderCtx Render(const IndexerSnapshot &snap) const {
        return query::RenderCtx{snap.Store(), snap.Txn(), host,
                                snap.GetAvalanche(),
                                indexer.IsTokenIndexEnabled()};
    }
    /** Render a planned page after releasing the state lock. */
    proto::TxHistoryPage Finish(IndexerSnapshot &snap,
                                query::TxPagePlan plan) const {
        const query::RenderCtx ctx = Render(snap);
        snap.Unlock();
        return query::RenderTxPage(ctx, std::move(plan));
    }

    query::GroupHistoryQuery ScriptHistory(const IndexerSnapshot &snap) const {
        return query::GroupHistoryQuery{snap, indexer.ScriptGroup(),
                                        &snap.Mempool().ScriptHistory(),
                                        indexer.IsTokenIndexEnabled(),
                                        indexer.IsScripthashIndexEnabled()};
    }
    query::GroupUtxosQuery ScriptUtxos(const IndexerSnapshot &snap) const {
        return query::GroupUtxosQuery{snap, indexer.ScriptGroup(),
                                      &snap.Mempool().ScriptUtxos(),
                                      indexer.IsTokenIndexEnabled(),
                                      indexer.IsScripthashIndexEnabled()};
    }
    static const GroupDef &TokenIdGroup() {
        static const groups::TokenIdGroup group;
        return group;
    }
    query::GroupHistoryQuery TokenIdHistory(const IndexerSnapshot &snap) const {
        return query::GroupHistoryQuery{snap, TokenIdGroup(),
                                        snap.Mempool().TokenIdHistory(),
                                        indexer.IsTokenIndexEnabled(),
                                        indexer.IsScripthashIndexEnabled()};
    }
    query::GroupUtxosQuery TokenIdUtxos(const IndexerSnapshot &snap) const {
        return query::GroupUtxosQuery{snap, TokenIdGroup(),
                                      snap.Mempool().TokenIdUtxos(),
                                      indexer.IsTokenIndexEnabled(),
                                      indexer.IsScripthashIndexEnabled()};
    }
    query::GroupHistoryQuery LokadIdHistory(const IndexerSnapshot &snap) const {
        return query::GroupHistoryQuery{snap, indexer.LokadIdGroup(),
                                        &snap.Mempool().LokadIdHistory(),
                                        indexer.IsTokenIndexEnabled(),
                                        indexer.IsScripthashIndexEnabled()};
    }
};

enum class HistoryKind { Confirmed, History, Unconfirmed };

/** Group history routes: parse member, then page params, then query. */
template <typename MemberFn, typename QueryFn>
HttpResponse GroupHistoryRoute(const Ctx &ctx, const HttpRequest &req,
                               HistoryKind kind, MemberFn &&member_fn,
                               QueryFn &&query_fn) {
    IndexerSnapshot snap = ctx.indexer.Snapshot();
    query::TxPagePlan plan;
    if (kind == HistoryKind::Unconfirmed) {
        const GroupMemberArg member = member_fn();
        plan = query_fn(snap).UnconfirmedTxs(member);
    } else {
        const QueryParamMap params = req.QueryParams();
        const PageParams page = GetPageParams(params);
        const GroupMemberArg member = member_fn();
        plan = kind == HistoryKind::Confirmed
                   ? query_fn(snap).ConfirmedTxs(member, page.page_num,
                                                 page.page_size)
                   : query_fn(snap).RevHistory(member, page.page_num,
                                               page.page_size);
    }
    return HttpResponse::Protobuf(ctx.Finish(snap, std::move(plan)));
}

/**
 * Script history routes: Rust parses the page params BEFORE the script
 * (get_param, then get_group_member).
 */
HttpResponse ScriptHistoryRoute(const Ctx &ctx, const HttpRequest &req,
                                const PathParams &p, HistoryKind kind) {
    return GroupHistoryRoute(
        ctx, req, kind, [&] { return GetGroupMember(p[0], p[1]); },
        [&](const IndexerSnapshot &snap) { return ctx.ScriptHistory(snap); });
}

/** Token ID routes: Rust parses the token ID BEFORE the page params. */
HttpResponse TokenIdHistoryRoute(const Ctx &ctx, const HttpRequest &req,
                                 const PathParams &p, HistoryKind kind) {
    GroupMemberArg member;
    const TxId token_id = ParseTokenId(p[0]);
    member.member = Bytes(token_id.b.begin(), token_id.b.end());
    return GroupHistoryRoute(
        ctx, req, kind, [&] { return member; },
        [&](const IndexerSnapshot &snap) { return ctx.TokenIdHistory(snap); });
}

/** LOKAD ID routes: Rust parses the LOKAD ID BEFORE the page params. */
HttpResponse LokadIdHistoryRoute(const Ctx &ctx, const HttpRequest &req,
                                 const PathParams &p, HistoryKind kind) {
    GroupMemberArg member;
    const std::array<uint8_t, 4> lokad_id = ParseLokadIdHex(p[0]);
    member.member = Bytes(lokad_id.begin(), lokad_id.end());
    return GroupHistoryRoute(
        ctx, req, kind, [&] { return member; },
        [&](const IndexerSnapshot &snap) { return ctx.LokadIdHistory(snap); });
}

/** Plugin history routes: parse group hex, page params, then not loaded. */
HttpResponse PluginHistoryRoute(const HttpRequest &req, const PathParams &p,
                                bool has_page_params) {
    ParseHex(p[1]);
    if (has_page_params) {
        GetPageParams(req.QueryParams());
    }
    PluginNotLoaded(p[0]);
}

proto::ScriptUtxos MakeScriptUtxos(const Bytes &script,
                                   query::UtxoPlan<proto::ScriptUtxo> &&plan) {
    proto::ScriptUtxos result;
    result.set_script(query::BytesStr(script));
    for (proto::ScriptUtxo &utxo : plan.utxos) {
        *result.add_utxos() = std::move(utxo);
    }
    return result;
}

HttpResponse ScriptBatchUtxos(const Ctx &ctx, const HttpRequest &req) {
    const auto request =
        ParseProtobufRequest<proto::ScriptBatchUtxosRequest>(req);
    const auto &scripts = request.params().scripts();
    CheckBatchScriptValidity(scripts);
    IndexerSnapshot snap = ctx.indexer.Snapshot();
    const query::GroupUtxosQuery script_utxos = ctx.ScriptUtxos(snap);
    std::vector<std::pair<Bytes, query::UtxoPlan<proto::ScriptUtxo>>> plans;
    plans.reserve(size_t(scripts.size()));
    for (const proto::ScriptRef &script_req : scripts) {
        const std::string payload_hex =
            HexEncode(ByteView(reinterpret_cast<const uint8_t *>(
                                   script_req.payload().data()),
                               script_req.payload().size()));
        const GroupMemberArg member =
            GetGroupMember(script_req.script_type(), payload_hex);
        const script::Script script = script_utxos.Script(
            member, ctx.indexer.Params().decompress_pubkey);
        plans.emplace_back(script.bytecode(),
                           script_utxos.ValueUtxos(script.view()));
    }
    snap.Unlock();
    proto::ScriptBatchUtxosResponse response;
    for (int i = 0; i < scripts.size(); ++i) {
        auto &[script, plan] = plans[size_t(i)];
        query::FinishUtxos(ctx.host, plan);
        proto::ScriptBatchUtxosRow *row = response.add_rows();
        proto::ScriptRef *ref = row->mutable_script();
        ref->set_script_type(scripts[i].script_type());
        ref->set_payload(scripts[i].payload());
        *row->mutable_utxos() = MakeScriptUtxos(script, std::move(plan));
    }
    return HttpResponse::Protobuf(response);
}

HttpResponse ScriptBatchSummary(const Ctx &ctx, const HttpRequest &req) {
    const auto request =
        ParseProtobufRequest<proto::ScriptBatchSummaryRequest>(req);
    const auto &scripts = request.params().scripts();
    CheckBatchScriptValidity(scripts);
    IndexerSnapshot snap = ctx.indexer.Snapshot();
    const query::GroupHistoryQuery script_history = ctx.ScriptHistory(snap);
    const query::GroupUtxosQuery script_utxos = ctx.ScriptUtxos(snap);
    struct Row {
        query::TxPagePlan history;
        uint32_t num_utxos = 0;
    };
    std::vector<Row> rows;
    // Phase-1 error of row `rows.size()`, after rendering its history (if
    // `partial`) and all previous rows.
    std::exception_ptr deferred;
    std::optional<query::TxPagePlan> partial;
    for (const proto::ScriptRef &script_req : scripts) {
        std::optional<query::TxPagePlan> history;
        try {
            const std::string payload_hex =
                HexEncode(ByteView(reinterpret_cast<const uint8_t *>(
                                       script_req.payload().data()),
                                   script_req.payload().size()));
            const GroupMemberArg member =
                GetGroupMember(script_req.script_type(), payload_hex);
            // As a best effort we use the default page size to load these
            // txs and extract the latest tx from this.
            history =
                script_history.RevHistory(member, 0, query::DEFAULT_PAGE_SIZE);
            if (history->deferred) {
                partial = std::move(history);
                break;
            }
            const script::Script script = script_utxos.Script(
                member, ctx.indexer.Params().decompress_pubkey);
            const uint32_t num_utxos =
                uint32_t(script_utxos.ValueUtxos(script.view()).utxos.size());
            rows.push_back(Row{std::move(*history), num_utxos});
        } catch (...) {
            deferred = std::current_exception();
            partial = std::move(history);
            break;
        }
    }
    const query::RenderCtx render = ctx.Render(snap);
    snap.Unlock();
    proto::ScriptBatchSummaryResponse response;
    for (size_t i = 0; i < rows.size(); ++i) {
        proto::TxHistoryPage page =
            query::RenderTxPage(render, std::move(rows[i].history));
        proto::ScriptBatchSummaryRow *row = response.add_rows();
        proto::ScriptRef *ref = row->mutable_script();
        ref->set_script_type(scripts[int(i)].script_type());
        ref->set_payload(scripts[int(i)].payload());
        row->set_num_txs(page.num_txs());
        row->set_num_utxos(rows[i].num_utxos);
        if (page.txs_size() > 0) {
            *row->mutable_latest_tx() = std::move(*page.mutable_txs(0));
        }
    }
    if (partial) {
        query::RenderTxPage(render, std::move(*partial));
    }
    if (deferred) {
        std::rethrow_exception(deferred);
    }
    return HttpResponse::Protobuf(response);
}

} // namespace

void RegisterQueryRoutes(Router &router, const RouteContext &route_ctx) {
    const Ctx ctx{route_ctx.indexer, route_ctx.host};

    router.Get("/block/:hash_or_height",
               [ctx](const HttpRequest &, const PathParams &p) {
                   IndexerSnapshot snap = ctx.indexer.Snapshot();
                   return HttpResponse::Protobuf(
                       query::BlockByHashOrHeight(snap, p[0]));
               });
    router.Get("/block-header/:hash_or_height",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   const QueryParamMap params = req.QueryParams();
                   const int32_t checkpoint_height =
                       GetI32Param(params, "checkpoint_height", 0);
                   return HttpResponse::Protobuf(query::BlockHeader(
                       ctx.indexer, ctx.host, p[0], checkpoint_height));
               });
    router.Get("/block-txs/:hash_or_height",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   const PageParams page = GetPageParams(req.QueryParams());
                   IndexerSnapshot snap = ctx.indexer.Snapshot();
                   query::TxPagePlan plan = query::PlanBlockTxs(
                       snap, p[0], page.page_num, page.page_size);
                   return HttpResponse::Protobuf(
                       ctx.Finish(snap, std::move(plan)));
               });
    router.Get("/blocks/:start/:end",
               [ctx](const HttpRequest &, const PathParams &p) {
                   const int32_t start_height = PathI32(p, 0);
                   const int32_t end_height = PathI32(p, 1);
                   IndexerSnapshot snap = ctx.indexer.Snapshot();
                   return HttpResponse::Protobuf(
                       query::BlocksByRange(snap, start_height, end_height));
               });
    router.Get("/block-headers/:start/:end",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   const int32_t start_height = PathI32(p, 0);
                   const int32_t end_height = PathI32(p, 1);
                   const QueryParamMap params = req.QueryParams();
                   const int32_t checkpoint_height =
                       GetI32Param(params, "checkpoint_height", 0);
                   return HttpResponse::Protobuf(query::BlockHeadersByRange(
                       ctx.indexer, ctx.host, start_height, end_height,
                       checkpoint_height, true));
               });
    router.Get("/unconfirmed-txs",
               [ctx](const HttpRequest &, const PathParams &) {
                   IndexerSnapshot snap = ctx.indexer.Snapshot();
                   query::TxPagePlan plan = query::PlanUnconfirmedTxs(snap);
                   return HttpResponse::Protobuf(
                       ctx.Finish(snap, std::move(plan)));
               });
    router.Get("/tx/:txid", [ctx](const HttpRequest &, const PathParams &p) {
        IndexerSnapshot snap = ctx.indexer.Snapshot();
        const TxId txid = ParseTxId(p[0]);
        return HttpResponse::Protobuf(query::TxById(snap, ctx.host, txid));
    });
    router.Get("/token/:txid", [ctx](const HttpRequest &, const PathParams &p) {
        IndexerSnapshot snap = ctx.indexer.Snapshot();
        const TxId txid = ParseTxId(p[0]);
        return HttpResponse::Protobuf(query::TokenInfoById(snap, txid));
    });
    router.PostWithOptions(
        "/validate-tx", [ctx](const HttpRequest &req, const PathParams &) {
            const auto raw_tx = ParseProtobufRequest<proto::RawTx>(req);
            const Bytes raw(raw_tx.raw_tx().begin(), raw_tx.raw_tx().end());
            return HttpResponse::Protobuf(
                query::ValidateTx(ctx.indexer, ctx.host, raw));
        });
    router.PostWithOptions(
        "/broadcast-tx", [ctx](const HttpRequest &req, const PathParams &) {
            const auto request =
                ParseProtobufRequest<proto::BroadcastTxRequest>(req);
            const std::vector<Bytes> raw_txs{Bytes(request.raw_tx().begin(),
                                                   request.raw_tx().end())};
            const std::vector<TxId> txids = query::BroadcastTxs(
                ctx.indexer, ctx.host, raw_txs, request.skip_token_checks(),
                request.finalization_timeout_secs());
            proto::BroadcastTxResponse response;
            response.set_txid(query::HashStr(txids.at(0)));
            return HttpResponse::Protobuf(response);
        });
    router.PostWithOptions(
        "/broadcast-txs", [ctx](const HttpRequest &req, const PathParams &) {
            const auto request =
                ParseProtobufRequest<proto::BroadcastTxsRequest>(req);
            std::vector<Bytes> raw_txs;
            for (const std::string &raw_tx : request.raw_txs()) {
                raw_txs.emplace_back(raw_tx.begin(), raw_tx.end());
            }
            const std::vector<TxId> txids = query::BroadcastTxs(
                ctx.indexer, ctx.host, raw_txs, request.skip_token_checks(),
                request.finalization_timeout_secs());
            proto::BroadcastTxsResponse response;
            for (const TxId &txid : txids) {
                response.add_txids(query::HashStr(txid));
            }
            return HttpResponse::Protobuf(response);
        });
    router.Get("/raw-tx/:txid", [ctx](const HttpRequest &, const PathParams &p) {
        IndexerSnapshot snap = ctx.indexer.Snapshot();
        const TxId txid = ParseTxId(p[0]);
        return HttpResponse::Protobuf(query::RawTxById(snap, ctx.host, txid));
    });
    router.PostWithOptions("/script/batch/utxos",
                           [ctx](const HttpRequest &req, const PathParams &) {
                               return ScriptBatchUtxos(ctx, req);
                           });
    router.PostWithOptions("/script/batch/summary",
                           [ctx](const HttpRequest &req, const PathParams &) {
                               return ScriptBatchSummary(ctx, req);
                           });
    router.Get("/script/:type/:payload/confirmed-txs",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return ScriptHistoryRoute(ctx, req, p,
                                             HistoryKind::Confirmed);
               });
    router.Get("/script/:type/:payload/history",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return ScriptHistoryRoute(ctx, req, p, HistoryKind::History);
               });
    router.Get("/script/:type/:payload/unconfirmed-txs",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return ScriptHistoryRoute(ctx, req, p,
                                             HistoryKind::Unconfirmed);
               });
    router.Get("/script/:type/:payload/utxos",
               [ctx](const HttpRequest &, const PathParams &p) {
                   IndexerSnapshot snap = ctx.indexer.Snapshot();
                   const query::GroupUtxosQuery script_utxos =
                       ctx.ScriptUtxos(snap);
                   const GroupMemberArg member = GetGroupMember(p[0], p[1]);
                   const script::Script script = script_utxos.Script(
                       member, ctx.indexer.Params().decompress_pubkey);
                   query::UtxoPlan<proto::ScriptUtxo> plan =
                       script_utxos.ValueUtxos(script.view());
                   snap.Unlock();
                   query::FinishUtxos(ctx.host, plan);
                   return HttpResponse::Protobuf(
                       MakeScriptUtxos(script.bytecode(), std::move(plan)));
               });
    router.Get("/token-id/:token_id/confirmed-txs",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return TokenIdHistoryRoute(ctx, req, p,
                                              HistoryKind::Confirmed);
               });
    router.Get("/token-id/:token_id/history",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return TokenIdHistoryRoute(ctx, req, p,
                                              HistoryKind::History);
               });
    router.Get("/token-id/:token_id/unconfirmed-txs",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return TokenIdHistoryRoute(ctx, req, p,
                                              HistoryKind::Unconfirmed);
               });
    router.Get("/token-id/:token_id/utxos",
               [ctx](const HttpRequest &, const PathParams &p) {
                   const TxId token_id = ParseTokenId(p[0]);
                   IndexerSnapshot snap = ctx.indexer.Snapshot();
                   query::UtxoPlan<proto::Utxo> plan =
                       ctx.TokenIdUtxos(snap).OutputUtxos(
                           ByteView(token_id.b.data(), token_id.b.size()));
                   snap.Unlock();
                   query::FinishUtxos(ctx.host, plan);
                   proto::Utxos utxos;
                   for (proto::Utxo &utxo : plan.utxos) {
                       *utxos.add_utxos() = std::move(utxo);
                   }
                   return HttpResponse::Protobuf(utxos);
               });
    router.Get("/lokad-id/:lokad_id/confirmed-txs",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return LokadIdHistoryRoute(ctx, req, p,
                                              HistoryKind::Confirmed);
               });
    router.Get("/lokad-id/:lokad_id/history",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return LokadIdHistoryRoute(ctx, req, p,
                                              HistoryKind::History);
               });
    router.Get("/lokad-id/:lokad_id/unconfirmed-txs",
               [ctx](const HttpRequest &req, const PathParams &p) {
                   return LokadIdHistoryRoute(ctx, req, p,
                                              HistoryKind::Unconfirmed);
               });
    // Plugins are not ported: every plugin name is "not loaded", answered
    // exactly like Rust with an empty PluginNameMap.
    router.Get("/plugin/:plugin_name/:group_hex/utxos",
               [](const HttpRequest &req, const PathParams &p) -> HttpResponse {
                   PluginHistoryRoute(req, p, false);
               });
    router.Get("/plugin/:plugin_name/:group_hex/confirmed-txs",
               [](const HttpRequest &req, const PathParams &p) -> HttpResponse {
                   PluginHistoryRoute(req, p, true);
               });
    router.Get("/plugin/:plugin_name/:group_hex/history",
               [](const HttpRequest &req, const PathParams &p) -> HttpResponse {
                   PluginHistoryRoute(req, p, true);
               });
    router.Get("/plugin/:plugin_name/:group_hex/unconfirmed-txs",
               [](const HttpRequest &req, const PathParams &p) -> HttpResponse {
                   PluginHistoryRoute(req, p, false);
               });
    router.Get(
        "/plugin/:plugin_name/groups",
        [](const HttpRequest &req, const PathParams &p) -> HttpResponse {
            const QueryParamMap params = req.QueryParams();
            const uint32_t page_size =
                GetU32Param(params, "page_size", query::DEFAULT_PAGE_SIZE);
            Bytes group_prefix;
            if (auto it = params.find("prefix"); it != params.end()) {
                group_prefix = ParseHex(it->second);
            }
            Bytes group_start = group_prefix;
            if (auto it = params.find("start"); it != params.end()) {
                group_start = ParseHex(it->second);
            }
            if (group_start.size() < group_prefix.size() ||
                !std::equal(group_prefix.begin(), group_prefix.end(),
                            group_start.begin())) {
                // If start doesn't start with the prefix, we can
                // short-circuit
                return HttpResponse::Protobuf(proto::PluginGroups{});
            }
            if (page_size < query::PLUGIN_GROUPS_MIN_PAGE_SIZE) {
                throw ChronikError(
                    "400: Requested page size " + std::to_string(page_size) +
                    " is too small, minimum is " +
                    std::to_string(query::PLUGIN_GROUPS_MIN_PAGE_SIZE));
            }
            if (page_size > query::PLUGIN_GROUPS_MAX_PAGE_SIZE) {
                throw ChronikError(
                    "400: Requested page size " + std::to_string(page_size) +
                    " is too big, maximum is " +
                    std::to_string(query::PLUGIN_GROUPS_MAX_PAGE_SIZE));
            }
            PluginNotLoaded(p[0]);
        });
}

} // namespace chronik::native
