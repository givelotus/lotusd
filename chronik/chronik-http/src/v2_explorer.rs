//! Explorer schema 1 over the single schema-3 V2 owner. No runtime callbacks,
//! legacy fallbacks, process-global cursor state or independent storage handle.
use crate::v2::{AuthoritativeState, V2HttpState};
use axum::{
    body::{to_bytes, Body},
    extract::{OriginalUri, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Router,
};
use bitcoinsuite_core::lotus_v2::{
    Hash32, OutPoint, Output, OutputRecord, TxHash, TxId, TxLocation,
};
use chronik_db::{
    v2_branch::{Anchor, ReadSnapshot},
    v2_explorer::{BlockMeta, TxMeta},
};
use chronik_indexer::query::v2_branches::{
    self as branch, BranchFilter, PositionClause, PostingSource, QueryError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Write},
};
const REQUEST_CAP: usize = 32768;
const JSON_CAP: usize = 262144;
const TOKEN_CAP: usize = 2048;
const ITEM_CAP: usize = JSON_CAP - 8192;
const PREFIX: &str = "/v2/explorer/v1";
/// Construct schema-1 routes, preserving the existing V2 router separately.
pub fn router(state: V2HttpState) -> Router {
    let mut r = Router::new();
    for path in [
        "/status",
        "/blocks",
        "/blocks/by-height/:height",
        "/blocks/:block_id",
        "/blocks/:block_id/transactions",
        "/transactions/by-id/:txid",
        "/transactions/by-hash/:txhash",
        "/transactions/by-id/:txid/inputs",
        "/transactions/by-id/:txid/outputs",
        "/transactions/by-id/:txid/witnesses",
        "/transactions/by-id/:txid/wire",
        "/outputs/:txid/:out_idx",
        "/assets",
        "/assets/:token_id",
        "/assets/:token_id/events",
        "/assets/:token_id/outputs",
    ] {
        r = r.route(&format!("{PREFIX}{path}"), get(handle));
    }
    for path in ["/branches/outputs", "/branches/utxos"] {
        r = r.route(&format!("{PREFIX}{path}"), post(handle));
    }
    r.with_state(state)
}
#[derive(Clone, Copy, Debug)]
struct Error(StatusCode, &'static str);
type Result<T> = std::result::Result<T, Error>;
fn invalid() -> Error {
    Error(StatusCode::BAD_REQUEST, "invalid_request")
}
fn limits() -> Error {
    Error(StatusCode::BAD_REQUEST, "invalid_limits")
}
fn unavailable() -> Error {
    Error(StatusCode::SERVICE_UNAVAILABLE, "index_unavailable")
}
fn missing() -> Error {
    Error(StatusCode::NOT_FOUND, "not_in_covered_chain")
}
fn record_limit() -> Error {
    Error(StatusCode::PAYLOAD_TOO_LARGE, "record_limit")
}
struct Capped {
    bytes: Vec<u8>,
    cap: usize,
}
impl Write for Capped {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > self.cap.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("JSON capacity"));
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T, cap: usize) -> Result<Vec<u8>> {
    let mut out = Capped {
        bytes: Vec::new(),
        cap,
    };
    serde_json::to_writer(&mut out, value).map_err(|_| record_limit())?;
    Ok(out.bytes)
}
fn response(status: StatusCode, value: &Value) -> Response {
    let (status,bytes)=match encode(value,JSON_CAP){Ok(b)=>(status,b),Err(_)=>(StatusCode::PAYLOAD_TOO_LARGE,b"{\"api_version\":\"1\",\"error\":{\"code\":\"record_limit\",\"meaning\":\"The complete record exceeds the response limit\"},\"snapshot\":null,\"coverage\":null}".to_vec())};
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Body::from(bytes))
        .unwrap()
}
fn meaning(code: &str) -> &str {
    match code {
        "not_in_covered_chain" => {
            "Absent from covered canonical history at this observation"
        }
        "stale_cursor" => {
            "The continuation belongs to a different observation or query"
        }
        "stale_snapshot" => "The requested observation is no longer current",
        "index_unavailable" => {
            "A coherent complete canonical index is unavailable"
        }
        "record_limit" => "The complete record exceeds the response limit",
        "request_limit" => "The request exceeds the request limit",
        "invalid_range" => "The wire offset exceeds the transaction frame",
        "invalid_cursor" => "Malformed explorer continuation",
        "invalid_limits" => "Noncanonical or excessive request limits",
        _ => "Malformed or unsupported request",
    }
}
fn failure(e: Error, context: Option<&Context>) -> Response {
    response(
        e.0,
        &json!({"api_version":"1","error":{"code":e.1,"meaning":meaning(e.1)},"snapshot":context.map(Context::snapshot),"coverage":context.map(Context::coverage)}),
    )
}
fn hash(s: &str) -> Result<Hash32> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut h = [0; 32];
    hex::decode_to_slice(s, &mut h).map_err(|_| invalid())?;
    Ok(Hash32(h))
}
fn number(s: &str) -> Result<u64> {
    let n = s.parse::<u64>().map_err(|_| limits())?;
    if n.to_string() != s {
        return Err(limits());
    }
    Ok(n)
}
fn ordinal(s: &str) -> Result<u32> {
    u32::try_from(number(s)?).map_err(|_| limits())
}
fn query(raw: Option<&str>) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    if let Some(raw) = raw {
        for pair in raw.split('&') {
            // Contract values are decimal or lowercase hex. Percent escaping is
            // unnecessary; rejecting it also avoids alternate duplicate spellings.
            let (k, v) = pair.split_once('=').ok_or_else(invalid)?;
            if k.is_empty()
                || v.is_empty()
                || k.len() > 32
                || v.len() > TOKEN_CAP
                || pair.contains('%')
                || pair.contains('+')
                || result.insert(k.to_owned(), v.to_owned()).is_some()
            {
                return Err(invalid());
            }
        }
    }
    Ok(result)
}
#[derive(Clone)]
struct Context {
    stamp: AuthoritativeState,
    epoch: [u8; 16],
    binding: chronik_db::v2_branch::Binding,
    anchor: Anchor,
}
impl Context {
    fn snapshot(&self) -> Value {
        json!({"chain_id":hex::encode(self.binding.chain_id),"genesis":hex::encode(self.binding.genesis),"profile_id":hex::encode(self.binding.profile),"tip":hex::encode(self.anchor.block_id),"height":self.anchor.height.to_string(),"service_epoch":hex::encode(self.epoch),"generation":self.stamp.generation.to_string()})
    }
    fn coverage(&self) -> Value {
        json!({"from_height":"0","through_height":self.anchor.height.to_string(),"complete":true,"scope":"canonical_confirmed"})
    }
    fn token(&self) -> String {
        let mut b = vec![1];
        b.extend(self.epoch);
        b.extend(self.stamp.generation.to_be_bytes());
        b.extend(self.binding.chain_id);
        b.extend(self.binding.genesis);
        b.extend(self.binding.profile);
        b.extend(self.anchor.block_id);
        b.extend(self.anchor.height.to_be_bytes());
        hex::encode(b)
    }
    fn check_token(&self, s: &str) -> Result<()> {
        if s.len() != 322
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        if s != self.token() {
            return Err(Error(StatusCode::CONFLICT, "stale_snapshot"));
        }
        Ok(())
    }
    fn envelope(&self, data: Value) -> Value {
        json!({"api_version":"1","snapshot_token":self.token(),"snapshot":self.snapshot(),"coverage":self.coverage(),"data":data})
    }
    fn confirmations(&self, height: u64) -> Result<String> {
        self.anchor
            .height
            .checked_sub(height)
            .and_then(|n| n.checked_add(1))
            .map(|n| n.to_string())
            .ok_or_else(unavailable)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    token: String,
    route: String,
    params: BTreeMap<String, String>,
    filter_digest: String,
    last: String,
}
fn cursor_encode(c: &Cursor) -> Result<String> {
    let bytes = encode(c, TOKEN_CAP / 2)?;
    Ok(hex::encode(bytes))
}
fn cursor_decode(s: &str) -> Result<Cursor> {
    let err = || Error(StatusCode::BAD_REQUEST, "invalid_cursor");
    if s.len() > TOKEN_CAP
        || s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(err());
    }
    let bytes = hex::decode(s).map_err(|_| err())?;
    let c: Cursor = serde_json::from_slice(&bytes).map_err(|_| err())?;
    if c.version != 1
        || c.last.len() > 348
        || c.route.len() > 192
        || c.params.len() > 8
        || c.token.len() != 322
    {
        return Err(err());
    }
    if c.filter_digest != filter_digest(&c.route, &c.params)? {
        return Err(err());
    }
    Ok(c)
}
fn filter_digest(
    route: &str,
    params: &BTreeMap<String, String>,
) -> Result<String> {
    let bytes =
        encode(&("LotusExplorerCursor/1", route, params), TOKEN_CAP / 2)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
struct Request {
    route: String,
    params: BTreeMap<String, String>,
    last: Option<Vec<u8>>,
    page: usize,
    pinned: bool,
}
impl Request {
    fn new(
        route: &str,
        mut params: BTreeMap<String, String>,
        context: &Context,
        allowed: &[&str],
    ) -> Result<Self> {
        if params.keys().any(|k| {
            k != "snapshot_token"
                && k != "cursor"
                && !allowed.contains(&k.as_str())
        }) {
            return Err(invalid());
        }
        let pinned = params.contains_key("snapshot_token");
        if let Some(s) = params.remove("snapshot_token") {
            context.check_token(&s)?;
        }
        if route.starts_with("/assets/")
            && route.ends_with("/outputs")
            && !params.contains_key("cursor")
        {
            params
                .entry("view".into())
                .or_insert_with(|| "history".into());
        }
        let continuation = params
            .remove("cursor")
            .map(|s| cursor_decode(&s))
            .transpose()?;
        let last = if let Some(c) = continuation {
            if c.token != context.token() {
                return Err(Error(StatusCode::CONFLICT, "stale_cursor"));
            }
            if c.route != route {
                return Err(Error(StatusCode::CONFLICT, "stale_cursor"));
            }
            for (k, v) in &params {
                if c.params.get(k) != Some(v) {
                    return Err(Error(StatusCode::CONFLICT, "stale_cursor"));
                }
            }
            params = c.params;
            if params.keys().any(|k| !allowed.contains(&k.as_str())) {
                return Err(Error(StatusCode::BAD_REQUEST, "invalid_cursor"));
            }
            Some(hex::decode(&c.last).map_err(|_| {
                Error(StatusCode::BAD_REQUEST, "invalid_cursor")
            })?)
        } else {
            None
        };
        let page = params
            .get("page_size")
            .map(|s| number(s))
            .transpose()?
            .unwrap_or(25);
        if page == 0 || page > 100 {
            return Err(limits());
        }
        if allowed.contains(&"page_size") {
            params.insert("page_size".into(), page.to_string());
        }
        Ok(Self {
            route: route.to_owned(),
            params,
            last,
            page: page as usize,
            pinned,
        })
    }
    fn continuation(&self, context: &Context, key: &[u8]) -> Result<String> {
        cursor_encode(&Cursor {
            version: 1,
            token: context.token(),
            route: self.route.clone(),
            params: self.params.clone(),
            filter_digest: filter_digest(&self.route, &self.params)?,
            last: hex::encode(key),
        })
    }
    fn integer(&self, name: &str) -> Result<Option<u64>> {
        self.params.get(name).map(|s| number(s)).transpose()
    }
    fn index(&self) -> Result<Option<u32>> {
        self.last
            .as_deref()
            .map(|b| {
                if b.len() != 4 {
                    return Err(Error(
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                    ));
                }
                Ok(u32::from_be_bytes(b.try_into().unwrap()))
            })
            .transpose()
    }
}
struct Page {
    items: Vec<Value>,
    bytes: usize,
    last: Option<Vec<u8>>,
    exhausted: bool,
    examined: usize,
    reads: usize,
}
impl Page {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            bytes: 0,
            last: None,
            exhausted: false,
            examined: 0,
            reads: 0,
        }
    }
    fn read(&mut self) -> Result<()> {
        if self.reads >= 4096 {
            return Err(unavailable());
        }
        self.reads += 1;
        Ok(())
    }
    fn push(&mut self, key: Vec<u8>, value: Value) -> Result<bool> {
        if self.examined >= 1024 {
            return Ok(false);
        }
        self.examined += 1;
        let bytes = encode(&value, ITEM_CAP)?.len();
        if bytes > ITEM_CAP.saturating_sub(self.bytes) {
            if self.items.is_empty() {
                return Err(record_limit());
            }
            return Ok(false);
        }
        self.bytes += bytes;
        self.items.push(value);
        self.last = Some(key);
        Ok(true)
    }
    fn finish(self, r: &Request, c: &Context) -> Result<Value> {
        let next = if self.exhausted {
            None
        } else {
            Some(
                r.continuation(
                    c,
                    self.last
                        .as_deref()
                        .or(r.last.as_deref())
                        .ok_or_else(unavailable)?,
                )?,
            )
        };
        Ok(
            json!({"items":self.items,"next_cursor":next,"exhausted":self.exhausted}),
        )
    }
}
fn location(l: TxLocation) -> Value {
    json!({"block_id":hex::encode(l.block_id.0),"height":l.height.to_string(),"tx_index":l.tx_index.to_string(),"txid":hex::encode(l.txid.0.0),"txhash":hex::encode(l.txhash.0.0)})
}
fn output_fields(out: &Output) -> Value {
    if let Some(script) = &out.legacy_script {
        return json!({"is_legacy":true,"value":out.value.to_string(),"legacy_script":hex::encode(script),"branches":[],"paths":[],"is_burn":out.is_burn(),"has_token":false,"has_state":false});
    }
    json!({"flags":out.flags.to_string(),"value":out.value.to_string(),"has_token":out.has_token(),"token_id":hex::encode(out.token_id.0),"is_burn":out.is_burn(),"has_state":out.has_state(),"state_root":hex::encode(out.state_root.0),"branches":out.branches.iter().map(|h|hex::encode(h.0)).collect::<Vec<_>>(),"paths":out.paths.iter().map(|p|p.iter().map(u8::to_string).collect::<Vec<_>>()).collect::<Vec<_>>()})
}
fn record(r: &OutputRecord) -> Value {
    let mut v = output_fields(&r.output);
    let o = v.as_object_mut().unwrap();
    o.insert("txid".into(), json!(hex::encode(r.outpoint.txid.0 .0)));
    o.insert("out_idx".into(), json!(r.outpoint.out_idx.to_string()));
    o.insert("creation".into(), location(r.creation));
    o.insert("spend".into(),r.spend.map(|s|json!({"transaction":location(s.transaction),"input_index":s.input_index.to_string()})).unwrap_or(Value::Null));
    v
}
fn byte_ref(r: chronik_db::v2_explorer::WireRange) -> Value {
    json!({"offset":r.offset.to_string(),"length":r.length.to_string()})
}
fn tx_summary(t: &TxMeta, c: &Context) -> Result<Value> {
    Ok(
        json!({"txid":hex::encode(t.location.txid.0.0),"txhash":hex::encode(t.location.txhash.0.0),"location":{"block_id":hex::encode(t.location.block_id.0),"height":t.location.height.to_string(),"tx_index":t.location.tx_index.to_string()},"status":"confirmed","confirmations":c.confirmations(t.location.height)?,"input_count":t.input_count.to_string(),"output_count":t.output_count.to_string(),"wire_size":t.wire_size.to_string()}),
    )
}
fn read_le(b: &[u8]) -> u64 {
    b.iter()
        .enumerate()
        .fold(0, |n, (i, b)| n | ((*b as u64) << (8 * i)))
}
fn block_summary(b: &BlockMeta, c: &Context, detail: bool) -> Result<Value> {
    let w = &b.header_wire;
    let mut v = json!({"block_id":hex::encode(b.anchor.block_id),"prev_id":hex::encode(&w[0..32]),"height":b.anchor.height.to_string(),"time":read_le(&w[36..42]).to_string(),"size":read_le(&w[54..62]).to_string(),"tx_count":b.tx_count.to_string(),"status":"confirmed","confirmations":c.confirmations(b.anchor.height)?});
    if detail {
        let o = v.as_object_mut().unwrap();
        o.insert("header_wire".into(), json!(hex::encode(w)));
        o.insert("body_availability".into(), json!("complete"));
        o.insert("finality".into(), json!("unknown"));
        o.insert("header".into(),json!({"prev_id":hex::encode(&w[..32]),"bits":read_le(&w[32..36]).to_string(),"time":read_le(&w[36..42]).to_string(),"nonce":read_le(&w[42..50]).to_string(),"version":read_le(&w[50..54]).to_string(),"size":read_le(&w[54..62]).to_string(),"height":read_le(&w[62..70]).to_string(),"tx_root":hex::encode(&w[70..102]),"state_root":hex::encode(&w[102..134])}));
    }
    Ok(v)
}
fn asset_summary(a: &chronik_db::v2_asset::AssetSummary) -> Value {
    json!({"token_id":hex::encode(a.token_id.0),"first_seen":location(a.first_seen),"event_count":a.event_count.to_string(),"output_count":a.output_count.to_string(),"metadata":{"availability":"unknown","name":null,"symbol":null,"decimals":null,"issuer":null,"mint_cap":null},"supply":{"availability":"unknown"}})
}
fn asset_event(a: &chronik_db::v2_asset::AssetEvent) -> Value {
    json!({"token_id":hex::encode(a.token_id.0),"location":location(a.location),"spent_units":a.spent_units.to_string(),"output_units":a.output_units.to_string(),"explicit_burn_units":a.explicit_burn_units.to_string(),"minted_units":a.minted_units.to_string(),"implicit_burn_units":a.implicit_burn_units.to_string(),"has_mint_input":a.has_mint_input})
}
fn observe(s: &V2HttpState) -> Option<AuthoritativeState> {
    s.node_anchor.as_ref().map(|f| f())
}
async fn handle(
    State(s): State<V2HttpState>,
    OriginalUri(uri): OriginalUri,
    body: Body,
) -> Response {
    if uri.to_string().len() > REQUEST_CAP {
        return failure(
            Error(StatusCode::PAYLOAD_TOO_LARGE, "request_limit"),
            None,
        );
    }
    let params = match query(uri.query()) {
        Ok(p) => p,
        Err(e) => return failure(e, None),
    };
    let path = uri.path().strip_prefix(PREFIX).unwrap_or("");
    if path.contains('%') {
        return failure(invalid(), None);
    }
    let bytes = match to_bytes(body, REQUEST_CAP).await {
        Ok(b) => b,
        Err(_) => {
            return failure(
                Error(StatusCode::PAYLOAD_TOO_LARGE, "request_limit"),
                None,
            )
        }
    };
    if uri.to_string().len().saturating_add(bytes.len()) > REQUEST_CAP {
        return failure(
            Error(StatusCode::PAYLOAD_TOO_LARGE, "request_limit"),
            None,
        );
    }
    if let Err(e) = validate_request(path, &params, &bytes) {
        return failure(e, None);
    }
    let stamp = observe(&s);
    let Ok(db) = s.db.try_lock() else {
        return failure(unavailable(), None);
    };
    if path == "/status" {
        if !params.is_empty() || !bytes.is_empty() {
            return failure(invalid(), None);
        }
        let binding = db.binding();
        let indexed = match db.checkpoint() {
            Ok(a) => a,
            Err(_) => return failure(unavailable(), None),
        };
        if observe(&s) != stamp {
            return failure(unavailable(), None);
        }
        let authority = stamp.and_then(|s| s.anchor);
        let index_error =
            s.index_error.load(std::sync::atomic::Ordering::Acquire);
        let ready = !index_error && indexed.is_some() && indexed == authority;
        let reason = if index_error {
            "index_error"
        } else if authority.is_none() {
            "authority_unknown"
        } else if indexed.is_none() {
            "initializing"
        } else if !ready {
            "catching_up"
        } else {
            "ready"
        };
        let anchor = |a: Anchor| json!({"block_id":hex::encode(a.block_id),"height":a.height.to_string()});
        let coverage=indexed.map(|a|json!({"from_height":"0","through_height":a.height.to_string(),"complete":ready,"scope":"canonical_confirmed"}));
        let value = json!({"api_version":"1","ready":ready,"reason":reason,"indexed_anchor":indexed.map(anchor),"authoritative_anchor":authority.map(anchor),"service_epoch":hex::encode(s.service_epoch),"generation":stamp.map(|s|s.generation.to_string()),"binding":{"chain_id":hex::encode(binding.chain_id),"genesis":hex::encode(binding.genesis),"profile_id":hex::encode(binding.profile)},"coverage":coverage,"capabilities":{"blocks":true,"transactions":true,"transaction_wire":true,"outputs":true,"assets":true,"asset_events":true,"branches":true,"accepted_pool":false,"detached_history":false,"finality":false},"limits":{"request_bytes":REQUEST_CAP.to_string(),"response_bytes":JSON_CAP.to_string(),"page_size":"100","cursor_bytes":TOKEN_CAP.to_string(),"wire_chunk_bytes":"32768","examined_records":"1024","key_reads":"4096"}});
        let result = response(StatusCode::OK, &value);
        return if observe(&s) == stamp {
            result
        } else {
            failure(unavailable(), None)
        };
    }
    if s.index_error.load(std::sync::atomic::Ordering::Acquire)
        || stamp.map_or(true, |s| s.anchor.is_none())
    {
        return failure(unavailable(), None);
    }
    let mut read_budget = chronik_db::v2_asset::AssetReadBudget::new(4096);
    // Snapshot construction reads the checkpoint key. Reserve it before I/O;
    // asset iteration and all secondary joins share the remaining budget.
    if read_budget.charge().is_err() {
        return failure(unavailable(), None);
    }
    let view = match db.snapshot() {
        Ok(v) => v,
        Err(_) => return failure(unavailable(), None),
    };
    let stamp = stamp.unwrap();
    if observe(&s) != Some(stamp) || stamp.anchor != Some(view.anchor) {
        return failure(unavailable(), None);
    }
    let context = Context {
        stamp,
        epoch: s.service_epoch,
        binding: view.binding,
        anchor: view.anchor,
    };
    let result = dispatch(path, params, &bytes, &view, &context, read_budget)
        .and_then(|data| {
            let value = context.envelope(data);
            // The capped encoder runs before the final stamp observation.
            encode(&value, JSON_CAP)?;
            Ok(response(StatusCode::OK, &value))
        })
        .unwrap_or_else(|e| failure(e, Some(&context)));
    if !s.index_error.load(std::sync::atomic::Ordering::Acquire)
        && observe(&s) == Some(stamp)
    {
        result
    } else {
        failure(unavailable(), None)
    }
}
fn db<T, E>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|_| unavailable())
}
fn dispatch(
    path: &str,
    params: BTreeMap<String, String>,
    body: &[u8],
    v: &ReadSnapshot<'_>,
    c: &Context,
    mut asset_budget: chronik_db::v2_asset::AssetReadBudget,
) -> Result<Value> {
    if path.starts_with("/branches/") {
        return branches(path, params, body, v, c);
    }
    if !body.is_empty() {
        return Err(invalid());
    }
    let p = path
        .split('/')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>();
    let allowed: &[&str] = match p.as_slice() {
        ["blocks"] => &["before_height", "page_size"],
        ["blocks", _, "transactions"]
        | ["transactions", "by-id", _, "inputs"]
        | ["transactions", "by-id", _, "outputs"]
        | ["assets"]
        | ["assets", _, "events"] => &["page_size"],
        ["transactions", "by-id", _, "witnesses"] => {
            &["input_index", "page_size"]
        }
        ["transactions", "by-id", _, "wire"] => &["offset", "length"],
        ["assets", _, "outputs"] => &["view", "page_size"],
        _ => &[],
    };
    // Cursor is list-only. Snapshot tokens apply to every data route.
    if params.contains_key("cursor") && !allowed.contains(&"page_size") {
        return Err(invalid());
    }
    let mut r = Request::new(path, params, c, allowed)?;
    if matches!(p.as_slice(), ["assets", _, "outputs"]) {
        r.params
            .entry("view".into())
            .or_insert_with(|| "history".into());
    }
    match p.as_slice() {
        ["blocks"] => {
            let before = r.integer("before_height")?;
            if let Some(key) = &r.last {
                if key.len() != 8 {
                    return Err(Error(
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                    ));
                }
                let last = u64::from_be_bytes(key[..].try_into().unwrap());
                if last > c.anchor.height
                    || before.is_some_and(|bound| last >= bound)
                {
                    return Err(Error(
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                    ));
                }
            }
            let mut height = if let Some(k) = &r.last {
                if k.len() != 8 {
                    return Err(Error(
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                    ));
                }
                u64::from_be_bytes(k[..].try_into().unwrap()).checked_sub(1)
            } else if let Some(before) = before {
                before.checked_sub(1).map(|h| h.min(c.anchor.height))
            } else {
                Some(c.anchor.height)
            };
            let mut page = Page::new();
            while page.items.len() < r.page {
                let Some(h) = height else {
                    page.exhausted = true;
                    break;
                };
                page.read()?;
                let b = db(v.explorer_block_at_height(h))?
                    .ok_or_else(unavailable)?;
                if !page.push(
                    h.to_be_bytes().to_vec(),
                    block_summary(&b, c, false)?,
                )? {
                    break;
                }
                height = h.checked_sub(1);
            }
            if height.is_none() {
                page.exhausted = true;
            }
            page.finish(&r, c)
        }
        ["blocks", "by-height", height] => {
            let height = number(height)?;
            let b =
                db(v.explorer_block_at_height(height))?.ok_or_else(missing)?;
            block_summary(&b, c, true)
        }
        ["blocks", id] => {
            let b = db(v.explorer_block(hash(id)?))?.ok_or_else(missing)?;
            block_summary(&b, c, true)
        }
        ["blocks", id, "transactions"] => {
            let id = hash(id)?;
            let b = db(v.explorer_block(id))?.ok_or_else(missing)?;
            index_page(&r, c, b.tx_count, |index| {
                let (txid, txhash) = db(v.explorer_block_tx(id, index))?
                    .ok_or_else(unavailable)?;
                let t = db(v.explorer_tx(txid))?.ok_or_else(unavailable)?;
                if t.location.txhash != txhash
                    || t.location.block_id != id
                    || t.location.tx_index != index
                {
                    return Err(unavailable());
                }
                tx_summary(&t, c)
            })
        }
        ["transactions", "by-id", id] | ["transactions", "by-hash", id] => {
            let h = hash(id)?;
            let t = if p[1] == "by-id" {
                db(v.explorer_tx(TxId(h)))?
            } else {
                db(v.explorer_tx_by_hash(TxHash(h)))?
            }
            .ok_or_else(missing)?;
            let mut value = tx_summary(&t, c)?;
            value.as_object_mut().unwrap().extend(json!({"lock":t.lock.to_string(),"core_available":true,"witness_available":true,"wire_available":true,"finality":"unknown","accounting":{"availability":"unknown"}}).as_object().unwrap().clone());
            Ok(value)
        }
        ["transactions", "by-id", id, "inputs"] => {
            let id = TxId(hash(id)?);
            let t = db(v.explorer_tx(id))?.ok_or_else(missing)?;
            index_page(&r, c, t.input_count, |index| {
                let i =
                    db(v.explorer_input(id, index))?.ok_or_else(unavailable)?;
                let (kind, path, resolved) = match i.flags {
                    1 | 4 => {
                        let coin = i
                            .resolved_creation
                            .as_ref()
                            .ok_or_else(unavailable)?;
                        let mut out = output_fields(&coin.output);
                        out.as_object_mut().unwrap().extend(json!({"txid":hex::encode(coin.outpoint.txid.0.0),"out_idx":coin.outpoint.out_idx.to_string(),"creation":location(coin.creation)}).as_object().unwrap().clone());
                        (
                            if i.flags == 4 {
                                "legacy_spend"
                            } else {
                                "spend"
                            },
                            if i.flags == 4 {
                                Value::Null
                            } else {
                                json!(i.path_index.to_string())
                            },
                            json!({"availability":"complete","output":out}),
                        )
                    }
                    2 | 5 => (
                        if i.flags == 5 {
                            "legacy_coinbase"
                        } else {
                            "coinbase"
                        },
                        Value::Null,
                        json!({"availability":"not_applicable"}),
                    ),
                    3 => (
                        "mint",
                        Value::Null,
                        json!({"availability":"not_applicable"}),
                    ),
                    _ => return Err(unavailable()),
                };
                Ok(
                    json!({"input_index":index.to_string(),"flags":i.flags.to_string(),"kind":kind,"prev_txid":hex::encode(i.prev_txid),"prev_index":i.prev_index.to_string(),"sequence":i.sequence.to_string(),"path_index":path,"witness_count":i.witness_count.to_string(),"coinbase_data":{"present":i.has_coinbase_data,"wire_ref":if i.has_coinbase_data{byte_ref(i.coinbase_data)}else{Value::Null}},"resolved_coin":resolved}),
                )
            })
        }
        ["transactions", "by-id", id, "outputs"] => {
            let id = TxId(hash(id)?);
            let t = db(v.explorer_tx(id))?.ok_or_else(missing)?;
            index_page(&r, c, t.output_count, |index| {
                Ok(record(
                    &db(v.output(OutPoint {
                        txid: id,
                        out_idx: index,
                    }))?
                    .ok_or_else(unavailable)?,
                ))
            })
        }
        ["transactions", "by-id", id, "witnesses"] => {
            let id = TxId(hash(id)?);
            let t = db(v.explorer_tx(id))?.ok_or_else(missing)?;
            let index = r.integer("input_index")?.ok_or_else(invalid)?;
            let index = u32::try_from(index).map_err(|_| limits())?;
            if index >= t.input_count {
                return Err(missing());
            }
            let input =
                db(v.explorer_input(id, index))?.ok_or_else(unavailable)?;
            index_page(&r, c, input.witness_count, |w| {
                let fact = db(v.explorer_witness(id, index, w))?
                    .ok_or_else(unavailable)?;
                Ok(
                    json!({"witness_index":w.to_string(),"script":byte_ref(fact.script),"siblings":{"count":fact.siblings_count.to_string(),"table_ref":byte_ref(fact.siblings_table),"inline":null},"arguments":{"count":fact.arguments_count.to_string(),"table_ref":byte_ref(fact.arguments_table),"inline":null}}),
                )
            })
        }
        ["transactions", "by-id", id, "wire"] => {
            wire(TxId(hash(id)?), &r, v, c)
        }
        ["outputs", id, index] => Ok(record(
            &db(v.output(OutPoint {
                txid: TxId(hash(id)?),
                out_idx: ordinal(index)?,
            }))?
            .ok_or_else(missing)?,
        )),
        ["assets"] => {
            let mut page = Page::new();
            let mut after = r.last.clone();
            validate_asset_key(after.as_deref(), b"eA", None, 34)?;
            while page.items.len() < r.page && asset_budget.remaining() >= 4 {
                page.read()?;
                let Some((key, a)) = db(v.next_asset_summary_counted(
                    after.as_deref(),
                    &mut asset_budget,
                ))?
                else {
                    page.exhausted = true;
                    break;
                };
                if !page.push(key.clone(), asset_summary(&a))? {
                    break;
                }
                after = Some(key);
            }
            page.finish(&r, c)
        }
        ["assets", id] => Ok(asset_summary(
            &db(v.asset_summary_counted(hash(id)?, &mut asset_budget))?
                .ok_or_else(missing)?,
        )),
        ["assets", id, "events"] => {
            let id = hash(id)?;
            db(v.asset_summary_counted(id, &mut asset_budget))?
                .ok_or_else(missing)?;
            let mut page = Page::new();
            let mut after = r.last.clone();
            validate_asset_key(after.as_deref(), b"eE", Some(id), 46)?;
            while page.items.len() < r.page && asset_budget.remaining() >= 4 {
                page.read()?;
                let Some((key, a)) = db(v.next_asset_event_counted(
                    id,
                    after.as_deref(),
                    &mut asset_budget,
                ))?
                else {
                    page.exhausted = true;
                    break;
                };
                if !page.push(key.clone(), asset_event(&a))? {
                    break;
                }
                after = Some(key);
            }
            page.finish(&r, c)
        }
        ["assets", id, "outputs"] => {
            let id = hash(id)?;
            db(v.asset_summary_counted(id, &mut asset_budget))?
                .ok_or_else(missing)?;
            let view = r
                .params
                .get("view")
                .map(String::as_str)
                .unwrap_or("history");
            if !["history", "unspent"].contains(&view) {
                return Err(invalid());
            }
            let mut page = Page::new();
            let mut after = r.last.clone();
            validate_asset_key(after.as_deref(), b"eP", Some(id), 50)?;
            while page.items.len() < r.page
                && page.examined < 1024
                && asset_budget.remaining() >= 7
            {
                page.read()?;
                let Some((key, op)) = db(v.next_asset_output_counted(
                    id,
                    after.as_deref(),
                    &mut asset_budget,
                ))?
                else {
                    page.exhausted = true;
                    break;
                };
                page.read()?;
                // The counted helper charges the output and each canonical
                // location join immediately before its storage read.
                let out = db(v.output_counted(op, &mut asset_budget))?
                    .ok_or_else(unavailable)?;
                if out.outpoint != op
                    || out.creation.txid != op.txid
                    || !out.output.has_token()
                    || out.output.token_id != id
                    || chronik_db::v2_asset::asset_output_key(
                        id,
                        out.creation,
                        op.out_idx,
                    ) != key
                {
                    return Err(unavailable());
                }
                if view == "unspent"
                    && (out.output.is_burn() || out.spend.is_some())
                {
                    page.examined += 1;
                    page.last = Some(key.clone());
                    after = Some(key);
                    continue;
                }
                if !page.push(key.clone(), record(&out))? {
                    break;
                }
                after = Some(key);
            }
            page.finish(&r, c)
        }
        _ => Err(invalid()),
    }
}
fn index_page(
    r: &Request,
    c: &Context,
    count: u32,
    mut item: impl FnMut(u32) -> Result<Value>,
) -> Result<Value> {
    let mut index = match r.index()? {
        Some(last) => {
            if last >= count {
                return Err(Error(StatusCode::BAD_REQUEST, "invalid_cursor"));
            }
            last.checked_add(1).ok_or_else(unavailable)?
        }
        None => 0,
    };
    let mut page = Page::new();
    while index < count && page.items.len() < r.page {
        page.read()?;
        if !page.push(index.to_be_bytes().to_vec(), item(index)?)? {
            break;
        }
        index += 1;
    }
    if index == count {
        page.exhausted = true;
    }
    page.finish(r, c)
}
fn validate_asset_key(
    key: Option<&[u8]>,
    prefix: &[u8],
    token: Option<Hash32>,
    len: usize,
) -> Result<()> {
    if let Some(key) = key {
        if key.len() != len
            || !key.starts_with(prefix)
            || token.is_some_and(|t| key[2..34] != t.0)
        {
            return Err(Error(StatusCode::BAD_REQUEST, "invalid_cursor"));
        }
    }
    Ok(())
}
fn wire(
    id: TxId,
    r: &Request,
    v: &ReadSnapshot<'_>,
    c: &Context,
) -> Result<Value> {
    let offset = r.integer("offset")?.unwrap_or(0);
    let length = r.integer("length")?.unwrap_or(32768);
    if length == 0 || length > 32768 {
        return Err(limits());
    }
    // A nonzero chunk requires a token so clients cannot assemble frames
    // across changed canonical membership.
    if offset > 0 && !r.pinned {
        return Err(invalid());
    }
    let t = db(v.explorer_tx(id))?.ok_or_else(missing)?;
    if offset > t.wire_size {
        return Err(Error(StatusCode::RANGE_NOT_SATISFIABLE, "invalid_range"));
    }
    let end = offset
        .checked_add(length)
        .ok_or_else(limits)?
        .min(t.wire_size);
    let mut bytes = Vec::with_capacity((end - offset) as usize);
    let mut pos = offset;
    while pos < end {
        let chunk_index =
            u32::try_from(pos / 32768).map_err(|_| unavailable())?;
        let chunk = db(v.explorer_wire_chunk(id, chunk_index))?
            .ok_or_else(unavailable)?;
        let expected =
            (t.wire_size - (chunk_index as u64) * 32768).min(32768) as usize;
        if chunk.len() != expected {
            return Err(unavailable());
        }
        let from = (pos % 32768) as usize;
        let n = ((end - pos) as usize).min(chunk.len() - from);
        if n == 0 {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk[from..from + n]);
        pos += n as u64;
    }
    let _ = c;
    Ok(
        json!({"txid":hex::encode(id.0.0),"txhash":hex::encode(t.location.txhash.0.0),"total_bytes":t.wire_size.to_string(),"offset":offset.to_string(),"bytes_hex":hex::encode(bytes),"next_offset":if end<t.wire_size{json!(end.to_string())}else{Value::Null}}),
    )
}
struct BranchSource<'a, 'b>(&'a ReadSnapshot<'b>);
impl PostingSource for BranchSource<'_, '_> {
    fn snapshot(&self) -> branch::Snapshot {
        branch::Snapshot {
            chain_id: Hash32(self.0.binding.chain_id),
            profile_id: Hash32(self.0.binding.profile),
            tip: Hash32(self.0.anchor.block_id),
            height: self.0.anchor.height,
        }
    }
    fn next_posting(
        &self,
        root: Hash32,
        position: Option<u8>,
        after: Option<OutPoint>,
    ) -> std::result::Result<Option<OutPoint>, QueryError> {
        self.0
            .next_posting(root, position, after)
            .map_err(|_| QueryError::Source("database"))
    }
    fn output(
        &self,
        key: OutPoint,
    ) -> std::result::Result<Option<OutputRecord>, QueryError> {
        self.0
            .output(key)
            .map_err(|_| QueryError::Source("database"))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Clause {
    position: String,
    roots: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchRequest {
    #[serde(default)]
    any_branch: Vec<String>,
    #[serde(default)]
    positions: Vec<Clause>,
    page_size: Option<String>,
    cursor: Option<String>,
    include_burn: Option<bool>,
}
fn branch_error(e: QueryError) -> Error {
    match e {
        QueryError::StaleCursor => Error(StatusCode::CONFLICT, "stale_cursor"),
        QueryError::RecordTooLarge => record_limit(),
        QueryError::InvalidLimits => limits(),
        QueryError::InvalidFilter => invalid(),
        QueryError::Source(_) => unavailable(),
    }
}
fn branches(
    path: &str,
    mut params: BTreeMap<String, String>,
    body: &[u8],
    v: &ReadSnapshot<'_>,
    c: &Context,
) -> Result<Value> {
    if params.keys().any(|k| k != "snapshot_token") {
        return Err(invalid());
    }
    let req: BranchRequest =
        serde_json::from_slice(body).map_err(|_| invalid())?;
    let history = path == "/branches/outputs";
    if !history && req.include_burn.is_some() {
        return Err(invalid());
    }
    let total = req
        .positions
        .iter()
        .try_fold(req.any_branch.len(), |n, p| n.checked_add(p.roots.len()))
        .ok_or_else(limits)?;
    if req.positions.len() > 16 || total > 256 {
        return Err(limits());
    }
    let filter = BranchFilter {
        any_branch: req
            .any_branch
            .iter()
            .map(|s| hash(s))
            .collect::<Result<_>>()?,
        positions: req
            .positions
            .iter()
            .map(|p| {
                Ok(PositionClause {
                    position: u8::try_from(number(&p.position)?)
                        .map_err(|_| limits())?,
                    roots: p
                        .roots
                        .iter()
                        .map(|s| hash(s))
                        .collect::<Result<_>>()?,
                })
            })
            .collect::<Result<_>>()?,
    };
    let kind = if history {
        branch::QueryKind::History {
            include_burn: req.include_burn.unwrap_or(false),
        }
    } else {
        branch::QueryKind::Utxos
    };
    let mut caps = branch::Limits {
        page_size: 25,
        work: 1024,
        posting_reads: 1024,
        result_bytes: 64 * 1024,
        ..Default::default()
    };
    let digest = filter.digest(kind, caps).map_err(branch_error)?;
    params.insert("filter".into(), hex::encode(digest.0));
    if let Some(size) = req.page_size {
        params.insert("page_size".into(), size);
    }
    if let Some(cursor) = req.cursor {
        params.insert("cursor".into(), cursor);
    }
    let r = Request::new(path, params, c, &["filter", "page_size"])?;
    caps.page_size = r.page;
    let source = BranchSource(v);
    let prior = if let Some(last) = &r.last {
        if last.len() != 36 {
            return Err(Error(StatusCode::BAD_REQUEST, "invalid_cursor"));
        }
        Some(branch::Cursor {
            version: 1,
            snapshot: source.snapshot(),
            filter_digest: digest,
            last_key: Some(OutPoint {
                txid: TxId(Hash32(last[..32].try_into().unwrap())),
                out_idx: u32::from_be_bytes(last[32..].try_into().unwrap()),
            }),
        })
    } else {
        None
    };
    let page = branch::query(&source, &filter, kind, caps, prior)
        .map_err(branch_error)?;
    let items=page.matches.iter().map(|m|json!({"record":record(&m.record),"matching_positions":m.matching_positions.iter().map(u8::to_string).collect::<Vec<_>>()})).collect::<Vec<_>>();
    // Engine results have their own logical budget; the JSON budget is checked
    // before the final authority fence and before emitting any body bytes.
    encode(&items, ITEM_CAP)?;
    let continuation = page
        .continuation
        .map(|engine| {
            let last = engine.last_key.ok_or_else(unavailable)?;
            let mut key = last.txid.0 .0.to_vec();
            key.extend(last.out_idx.to_be_bytes());
            r.continuation(c, &key)
        })
        .transpose()?;
    Ok(
        json!({"items":items,"exhausted":continuation.is_none(),"next_cursor":continuation,"posting_reads":page.posting_reads.to_string(),"work":page.work.to_string()}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context {
        Context {
            stamp: AuthoritativeState {
                observation: 2,
                generation: u64::MAX,
                anchor: Some(Anchor {
                    block_id: [4; 32],
                    height: u64::MAX - 1,
                }),
            },
            epoch: [5; 16],
            binding: chronik_db::v2_branch::Binding {
                chain_id: [1; 32],
                genesis: [2; 32],
                profile: [3; 32],
            },
            anchor: Anchor {
                block_id: [4; 32],
                height: u64::MAX - 1,
            },
        }
    }
    #[test]
    fn strict_query_encodings_and_duplicates() {
        for raw in ["a=1&a=2", "%61=1", "a=%30", "a=+1", "a", "=1", "a="] {
            assert!(query(Some(raw)).is_err(), "{raw}");
        }
        for raw in ["00", "+1", "-1", "18446744073709551616", " 1"] {
            assert!(number(raw).is_err(), "{raw}");
        }
        assert_eq!(number(&u64::MAX.to_string()).unwrap(), u64::MAX);
        assert!(hash(&"AA".repeat(32)).is_err());
        assert!(hash(&"ff".repeat(32)).is_ok());
    }
    #[test]
    fn restart_generation_and_filter_bindings() {
        let c = context();
        let r = Request::new("/assets", BTreeMap::new(), &c, &["page_size"])
            .unwrap();
        let token = c.token();
        assert_eq!(token.len(), 322);
        c.check_token(&token).unwrap();
        let cursor = r.continuation(&c, &[8; 34]).unwrap();
        assert!(cursor.len() <= TOKEN_CAP);
        let mut p = BTreeMap::new();
        p.insert("cursor".into(), cursor.clone());
        let mut other = c.clone();
        other.epoch[0] ^= 1;
        assert_eq!(
            Request::new("/assets", p.clone(), &other, &["page_size"])
                .err()
                .unwrap()
                .1,
            "stale_cursor"
        );
        other = c.clone();
        other.stamp.generation -= 1;
        assert_eq!(other.check_token(&token).unwrap_err().1, "stale_snapshot");
        p.insert("page_size".into(), "1".into());
        assert_eq!(
            Request::new("/assets", p, &c, &["page_size"])
                .err()
                .unwrap()
                .1,
            "stale_cursor"
        );
        let mut p = BTreeMap::new();
        p.insert("cursor".into(), cursor);
        let resumed = Request::new("/assets", p, &c, &["page_size"]).unwrap();
        assert_eq!(resumed.page, 25);
        assert_eq!(resumed.last, Some(vec![8; 34]));
    }
    #[test]
    fn capped_encoding_stops_writing_and_no_store() {
        let mut out = Capped {
            bytes: Vec::new(),
            cap: 3,
        };
        assert_eq!(out.write(b"abc").unwrap(), 3);
        assert!(out.write(b"d").is_err());
        assert_eq!(out.bytes, b"abc");
        assert!(encode(&"x".repeat(100), 16).is_err());
        let r = failure(unavailable(), None);
        assert_eq!(r.headers()["cache-control"], "no-store");
    }
    #[test]
    fn typed_key_validation_and_safe_integer_objects() {
        assert!(validate_asset_key(Some(&[0; 34]), b"eA", None, 34).is_err());
        let mut key = b"eP".to_vec();
        key.extend([8; 32]);
        key.extend([0; 16]);
        assert!(validate_asset_key(
            Some(&key),
            b"eP",
            Some(Hash32([9; 32])),
            50
        )
        .is_err());
        let c = context();
        assert_eq!(c.snapshot()["height"], (u64::MAX - 1).to_string());
        assert!(c.confirmations(u64::MAX).is_err());
        let out = Output {
            legacy_script: None,
            flags: 0,
            value: u64::MAX,
            token_id: Hash32([0; 32]),
            state_root: Hash32::default(),
            branches: vec![],
            paths: vec![],
        };
        let value = output_fields(&out);
        assert_eq!(value["value"], u64::MAX.to_string());
        assert_eq!(value["flags"], "0");
        assert_eq!(value["has_token"], false);
        assert_eq!(value["has_state"], false);
        assert_eq!(value["state_root"], hex::encode([0; 32]));
        let stateful = Output {
            flags: 4,
            state_root: Hash32([5; 32]),
            ..out
        };
        let value = output_fields(&stateful);
        assert_eq!(value["has_state"], true);
        assert_eq!(value["state_root"], hex::encode([5; 32]));
    }
}
// Parse and bound the request before any storage observation. Snapshot equality
// is deliberately checked later, only after acquiring a coherent ready view.
fn validate_request(
    path: &str,
    params: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<()> {
    let parts = path
        .split('/')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>();
    let (allowed, key_len): (&[&str], Option<usize>) = match parts.as_slice() {
        ["status"] => (&[], None),
        ["blocks"] => (&["before_height", "page_size"], Some(8)),
        ["blocks", "by-height", h] => {
            number(h)?;
            (&[], None)
        }
        ["blocks", id] => {
            hash(id)?;
            (&[], None)
        }
        ["blocks", id, "transactions"] => {
            hash(id)?;
            (&["page_size"], Some(4))
        }
        ["transactions", "by-id", id] | ["transactions", "by-hash", id] => {
            hash(id)?;
            (&[], None)
        }
        ["transactions", "by-id", id, "inputs"]
        | ["transactions", "by-id", id, "outputs"] => {
            hash(id)?;
            (&["page_size"], Some(4))
        }
        ["transactions", "by-id", id, "witnesses"] => {
            hash(id)?;
            if !params.contains_key("input_index")
                && !params.contains_key("cursor")
            {
                return Err(invalid());
            }
            (&["input_index", "page_size"], Some(4))
        }
        ["transactions", "by-id", id, "wire"] => {
            hash(id)?;
            (&["offset", "length"], None)
        }
        ["outputs", id, index] => {
            hash(id)?;
            ordinal(index)?;
            (&[], None)
        }
        ["assets"] => (&["page_size"], Some(34)),
        ["assets", id] => {
            hash(id)?;
            (&[], None)
        }
        ["assets", id, "events"] => {
            hash(id)?;
            (&["page_size"], Some(46))
        }
        ["assets", id, "outputs"] => {
            hash(id)?;
            (&["view", "page_size"], Some(50))
        }
        ["branches", kind] if *kind == "outputs" || *kind == "utxos" => {
            if params.keys().any(|k| k != "snapshot_token") {
                return Err(invalid());
            }
            let r: BranchRequest =
                serde_json::from_slice(body).map_err(|_| invalid())?;
            if *kind == "utxos" && r.include_burn.is_some() {
                return Err(invalid());
            }
            let count = r
                .positions
                .iter()
                .try_fold(r.any_branch.len(), |n, c| {
                    n.checked_add(c.roots.len())
                })
                .ok_or_else(limits)?;
            if count > 256 || r.positions.len() > 16 {
                return Err(limits());
            }
            for root in &r.any_branch {
                hash(root)?;
            }
            for p in &r.positions {
                if number(&p.position)? >= 16 {
                    return Err(limits());
                }
                for root in &p.roots {
                    hash(root)?;
                }
            }
            if let Some(page) = r.page_size {
                let n = number(&page)?;
                if n == 0 || n > 100 {
                    return Err(limits());
                }
            }
            if let Some(cursor) = r.cursor {
                let c = cursor_decode(&cursor)?;
                if hex::decode(c.last).map_err(|_| invalid())?.len() != 36 {
                    return Err(Error(
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                    ));
                }
            }
            if let Some(token) = params.get("snapshot_token") {
                validate_token(token)?;
            }
            return Ok(());
        }
        _ => return Err(invalid()),
    };
    if !body.is_empty() {
        return Err(invalid());
    }
    for (key, value) in params {
        match key.as_str() {
            "snapshot_token" if path != "/status" => validate_token(value)?,
            "cursor" if key_len.is_some() => {
                let c = cursor_decode(value)?;
                validate_token(&c.token).map_err(|_| {
                    Error(StatusCode::BAD_REQUEST, "invalid_cursor")
                })?;
                let last = hex::decode(&c.last).map_err(|_| {
                    Error(StatusCode::BAD_REQUEST, "invalid_cursor")
                })?;
                if Some(last.len()) != key_len {
                    return Err(Error(
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                    ));
                }
                for (name, val) in &c.params {
                    if !allowed.contains(&name.as_str()) {
                        return Err(Error(
                            StatusCode::BAD_REQUEST,
                            "invalid_cursor",
                        ));
                    }
                    validate_parameter(name, val)?;
                }
                if matches!(
                    parts.as_slice(),
                    ["assets", _, "events"] | ["assets", _, "outputs"]
                ) {
                    let token = hash(parts[1])?;
                    let prefix =
                        if parts[2] == "events" { b"eE" } else { b"eP" };
                    validate_asset_key(
                        Some(&last),
                        prefix,
                        Some(token),
                        key_len.unwrap(),
                    )?;
                }
                if path == "/assets" {
                    validate_asset_key(Some(&last), b"eA", None, 34)?;
                }
            }
            name if allowed.contains(&name) => validate_parameter(name, value)?,
            _ => return Err(invalid()),
        }
    }
    if matches!(parts.as_slice(), ["transactions", "by-id", _, "wire"])
        && params
            .get("offset")
            .map(|s| number(s))
            .transpose()?
            .unwrap_or(0)
            > 0
        && !params.contains_key("snapshot_token")
    {
        return Err(invalid());
    }
    if matches!(parts.as_slice(), ["transactions", "by-id", _, "wire"]) {
        let offset = params
            .get("offset")
            .map(|s| number(s))
            .transpose()?
            .unwrap_or(0);
        let length = params
            .get("length")
            .map(|s| number(s))
            .transpose()?
            .unwrap_or(32768);
        offset.checked_add(length).ok_or_else(limits)?;
    }
    Ok(())
}
fn validate_parameter(name: &str, value: &str) -> Result<()> {
    match name {
        "page_size" => {
            let n = number(value)?;
            if n == 0 || n > 100 {
                return Err(limits());
            }
        }
        "length" => {
            let n = number(value)?;
            if n == 0 || n > 32768 {
                return Err(limits());
            }
        }
        "input_index" => {
            ordinal(value)?;
        }
        "before_height" | "offset" => {
            number(value)?;
        }
        "view" => {
            if value != "history" && value != "unspent" {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}
fn validate_token(s: &str) -> Result<()> {
    if s.len() != 322
        || !s.starts_with("01")
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
#[path = "v2_explorer_http_tests.rs"]
mod http_tests;
