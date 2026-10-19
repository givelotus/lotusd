//! Opt-in confirmed V2 JSON API. All hex uses native wire order, without
//! reversal. Root sets are OR, position clauses are AND on the same output;
//! an any-branch set and position clauses together are AND. Money and heights
//! are decimal strings. This router neither starts a listener nor indexes a pool.
use axum::{
    body::{to_bytes, Body},
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Router,
};
use bitcoinsuite_core::lotus_v2::{
    Hash32, OutPoint, OutputRecord, TxId, TxLocation,
};
use chronik_db::v2_branch::{Anchor, ReadSnapshot, V2Db};
use chronik_indexer::query::v2_branches::{
    self as query, BranchFilter, Cursor, Limits, PositionClause, PostingSource,
    QueryError, QueryKind, Snapshot,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const BODY_CAP: usize = 32 * 1024;
const JSON_CAP: usize = 256 * 1024;
/// Coherent authoritative node observation for fencing confirmed reads.
/// Publishers must advance generation on every transition and recovery boundary,
/// including an anchor ABA, and must never wrap or reuse generations. Unknown or
/// recovering state has no anchor. Publication must be atomic and nonblocking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoritativeState {
    /// Monotonic observation fence, advanced on each suspend/publication. It
    /// participates in request fences but never in snapshot tokens or cursors.
    pub observation: u64,
    /// Durable snapshot generation; unchanged only for a certified idle turn.
    pub generation: u64,
    /// Authoritative committed tip; absent while unknown or recovering.
    pub anchor: Option<Anchor>,
}
/// State shared with the authoritative V2 adapter, independent of legacy Chronik.
#[derive(Clone)]
pub struct V2HttpState {
    /// Operational transition failure; cleared only by successful indexing.
    pub index_error: Arc<std::sync::atomic::AtomicBool>,
    /// Per-service-open entropy; never persisted or reused across restarts.
    pub service_epoch: [u8; 16],
    /// Confirmed database; reads fail with 503 if another owner holds its lock.
    /// Acquired locks span bounded synchronous RocksDB reads and encoding.
    /// Cooperative server shutdown cannot preempt an in-progress storage read.
    pub db: Arc<Mutex<V2Db>>,
    /// Coherent stamped node observation, absent when authority is unavailable.
    /// Must not lock the DB, block on its owner, or reenter this router. The
    /// generation contract on `AuthoritativeState` is required for ABA safety.
    pub node_anchor: Option<Arc<dyn Fn() -> AuthoritativeState + Send + Sync>>,
}
/// Construct a versioned router without opening a port or enabling V2 implicitly.
pub fn router(state: V2HttpState) -> Router {
    let explorer = crate::v2_explorer::router(state.clone());
    Router::new()
        .route("/v2/status", get(status))
        .route("/v2/branches/utxos", post(utxos))
        .route("/v2/branches/outputs", post(outputs))
        .route("/v2/utxos/:txid/:out_idx", get(utxo))
        .with_state(state)
        .merge(explorer)
}
fn response(status: StatusCode, value: Value) -> Response {
    match serde_json::to_vec(&value) {
        Ok(bytes) if bytes.len() <= JSON_CAP => Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header("content-type", "application/json")
            .body(Body::from("{\"error\":\"response_limit\"}"))
            .unwrap(),
    }
}
fn fail(status: StatusCode, message: &str) -> Response {
    response(status, json!({"error":message}))
}
fn internal() -> Response {
    fail(StatusCode::SERVICE_UNAVAILABLE, "index_unavailable")
}
fn hash(s: &str) -> Result<Hash32, ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(s, &mut bytes).map_err(|_| ())?;
    Ok(Hash32(bytes))
}
fn snapshot(s: &ReadSnapshot<'_>) -> Snapshot {
    Snapshot {
        chain_id: Hash32(s.binding.chain_id),
        profile_id: Hash32(s.binding.profile),
        tip: Hash32(s.anchor.block_id),
        height: s.anchor.height,
    }
}
fn snapshot_json(s: Snapshot) -> Value {
    json!({"chain_id":hex::encode(s.chain_id.0), "profile_id":hex::encode(s.profile_id.0), "tip":hex::encode(s.tip.0), "height":s.height.to_string()})
}
fn location(l: TxLocation) -> Value {
    json!({"block_id":hex::encode(l.block_id.0), "height":l.height.to_string(), "tx_index":l.tx_index, "txid":hex::encode(l.txid.0.0), "txhash":hex::encode(l.txhash.0.0)})
}
fn record(r: &OutputRecord) -> Value {
    json!({"txid":hex::encode(r.outpoint.txid.0.0), "out_idx":r.outpoint.out_idx, "flags":r.output.flags, "value":r.output.value.to_string(), "token_id":hex::encode(r.output.token_id.0), "branches":r.output.branches.iter().map(|r|hex::encode(r.0)).collect::<Vec<_>>(), "paths":r.output.paths, "creation":location(r.creation), "spend":r.spend.map(|s|json!({"transaction":location(s.transaction), "input_index":s.input_index}))})
}
struct Source<'a>(ReadSnapshot<'a>);
impl PostingSource for Source<'_> {
    fn snapshot(&self) -> Snapshot {
        snapshot(&self.0)
    }
    fn next_posting(
        &self,
        root: Hash32,
        position: Option<u8>,
        after: Option<OutPoint>,
    ) -> Result<Option<OutPoint>, QueryError> {
        self.0
            .next_posting(root, position, after)
            .map_err(|_| QueryError::Source("database"))
    }
    fn output(
        &self,
        key: OutPoint,
    ) -> Result<Option<OutputRecord>, QueryError> {
        self.0
            .output(key)
            .map_err(|_| QueryError::Source("database"))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Clause {
    position: u8,
    roots: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    any_branch: Vec<String>,
    #[serde(default)]
    positions: Vec<Clause>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "page_default")]
    page_size: usize,
    #[serde(default)]
    include_burn: bool,
}
fn page_default() -> usize {
    100
}
// Fixed 174-byte transport: version, chain, profile, tip, height LE, digest,
// key-presence byte, TxID and output ordinal LE. Absent key has zero padding.
fn encode_cursor(c: Cursor) -> String {
    let mut b = vec![c.version];
    b.extend(c.snapshot.chain_id.0);
    b.extend(c.snapshot.profile_id.0);
    b.extend(c.snapshot.tip.0);
    b.extend(c.snapshot.height.to_le_bytes());
    b.extend(c.filter_digest.0);
    b.push(u8::from(c.last_key.is_some()));
    let op = c.last_key.unwrap_or_default();
    b.extend(op.txid.0 .0);
    b.extend(op.out_idx.to_le_bytes());
    hex::encode(b)
}
fn decode_cursor(s: &str) -> Result<Cursor, ()> {
    if s.len() != 348 {
        return Err(());
    }
    let b = hex::decode(s).map_err(|_| ())?;
    let h = |i| Hash32(b[i..i + 32].try_into().unwrap());
    let last_key = match b[137] {
        0 if b[138..].iter().all(|v| *v == 0) => None,
        1 => Some(OutPoint {
            txid: TxId(h(138)),
            out_idx: u32::from_le_bytes(b[170..174].try_into().unwrap()),
        }),
        _ => return Err(()),
    };
    Ok(Cursor {
        version: b[0],
        snapshot: Snapshot {
            chain_id: h(1),
            profile_id: h(33),
            tip: h(65),
            height: u64::from_le_bytes(b[97..105].try_into().unwrap()),
        },
        filter_digest: h(105),
        last_key,
    })
}
fn observe(s: &V2HttpState) -> Option<AuthoritativeState> {
    s.node_anchor.as_ref().map(|provider| provider())
}
fn ready(stamp: Option<AuthoritativeState>, anchor: Anchor) -> bool {
    stamp.is_some_and(|stamp| stamp.anchor == Some(anchor))
}
// The final observation is the response's linearization point. Encoding is
// completed before this fence; no success survives a transition or recovery.
fn fenced(
    s: &V2HttpState,
    stamp: Option<AuthoritativeState>,
    result: Response,
) -> Response {
    if observe(s) == stamp {
        result
    } else {
        internal()
    }
}
async fn status(State(s): State<V2HttpState>) -> Response {
    let stamp = observe(&s);
    let Ok(db) = s.db.try_lock() else {
        return internal();
    };
    let Ok(view) = db.snapshot() else {
        return internal();
    };
    let current = observe(&s);
    let is_ready = stamp == current && ready(current, view.anchor);
    let result = response(
        StatusCode::OK,
        json!({"version":2,"confirmed_only":true,"pool_indexed":false,"ready":is_ready,"generation":current.map(|s|s.generation.to_string()),"snapshot":snapshot_json(snapshot(&view))}),
    );
    if observe(&s) == current {
        result
    } else {
        internal()
    }
}
async fn utxos(State(s): State<V2HttpState>, body: Body) -> Response {
    branches(s, body, false).await
}
async fn outputs(State(s): State<V2HttpState>, body: Body) -> Response {
    branches(s, body, true).await
}
async fn branches(s: V2HttpState, body: Body, history: bool) -> Response {
    let Ok(bytes) = to_bytes(body, BODY_CAP).await else {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "request_limit");
    };
    let Ok(r) = serde_json::from_slice::<Request>(&bytes) else {
        return fail(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let count = r
        .positions
        .iter()
        .try_fold(r.any_branch.len(), |n, c| n.checked_add(c.roots.len()));
    if r.page_size == 0
        || r.page_size > 100
        || r.positions.len() > 16
        || count.map_or(true, |n| n > 256)
        || (!history && r.include_burn)
    {
        return fail(StatusCode::BAD_REQUEST, "invalid_limits");
    }
    let parsed = (|| {
        Ok::<_, ()>(BranchFilter {
            any_branch: r
                .any_branch
                .iter()
                .map(|s| hash(s))
                .collect::<Result<_, _>>()?,
            positions: r
                .positions
                .iter()
                .map(|c| {
                    Ok(PositionClause {
                        position: c.position,
                        roots: c
                            .roots
                            .iter()
                            .map(|s| hash(s))
                            .collect::<Result<_, _>>()?,
                    })
                })
                .collect::<Result<_, ()>>()?,
        })
    })();
    let Ok(filter) = parsed else {
        return fail(StatusCode::BAD_REQUEST, "invalid_hex");
    };
    let cursor = match r.cursor.as_deref().map(decode_cursor).transpose() {
        Ok(c) => c,
        Err(()) => return fail(StatusCode::BAD_REQUEST, "invalid_cursor"),
    };
    let stamp = observe(&s);
    if stamp.map_or(true, |stamp| stamp.anchor.is_none()) {
        return internal();
    }
    let Ok(db) = s.db.try_lock() else {
        return internal();
    };
    let Ok(view) = db.snapshot() else {
        return internal();
    };
    if observe(&s) != stamp || !ready(stamp, view.anchor) {
        return internal();
    }

    let kind = if history {
        QueryKind::History {
            include_burn: r.include_burn,
        }
    } else {
        QueryKind::Utxos
    };
    let source = Source(view);
    let result = match query::query(
        &source,
        &filter,
        kind,
        Limits {
            page_size: r.page_size,
            ..Limits::default()
        },
        cursor,
    ) {
        Ok(p) => response(
            StatusCode::OK,
            json!({"version":2,"confirmed_only":true,"snapshot":snapshot_json(p.snapshot),"outputs":p.matches.iter().map(|m|json!({"record":record(&m.record),"matching_positions":m.matching_positions})).collect::<Vec<_>>(),"cursor":p.continuation.map(encode_cursor),"generation":stamp.map(|s|s.generation.to_string()),"posting_reads":p.posting_reads,"work":p.work}),
        ),
        Err(QueryError::StaleCursor) => {
            fail(StatusCode::CONFLICT, "stale_cursor")
        }
        Err(QueryError::InvalidFilter | QueryError::InvalidLimits) => {
            fail(StatusCode::BAD_REQUEST, "invalid_filter")
        }
        Err(QueryError::RecordTooLarge) => {
            fail(StatusCode::PAYLOAD_TOO_LARGE, "record_limit")
        }
        Err(QueryError::Source(_)) => internal(),
    };
    fenced(&s, stamp, result)
}
async fn utxo(
    State(s): State<V2HttpState>,
    Path((txid, index)): Path<(String, String)>,
) -> Response {
    let (Ok(txid), Ok(out_idx)) = (hash(&txid), index.parse::<u32>()) else {
        return fail(StatusCode::BAD_REQUEST, "invalid_outpoint");
    };
    if index != out_idx.to_string() {
        return fail(StatusCode::BAD_REQUEST, "invalid_outpoint");
    }
    let stamp = observe(&s);
    if stamp.map_or(true, |stamp| stamp.anchor.is_none()) {
        return internal();
    }
    let Ok(db) = s.db.try_lock() else {
        return internal();
    };
    let Ok(view) = db.snapshot() else {
        return internal();
    };
    if observe(&s) != stamp || !ready(stamp, view.anchor) {
        return internal();
    }

    let result = match view.utxo(OutPoint {
        txid: TxId(txid),
        out_idx,
    }) {
        Ok(Some(r)) => response(
            StatusCode::OK,
            json!({"version":2,"confirmed_only":true,"snapshot":snapshot_json(snapshot(&view)),"record":record(&r),"generation":stamp.map(|s|s.generation.to_string())}),
        ),
        Ok(None) => fail(StatusCode::NOT_FOUND, "utxo_not_found"),
        Err(_) => internal(),
    };
    fenced(&s, stamp, result)
}

impl std::fmt::Debug for V2HttpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2HttpState")
            .field("has_node_anchor", &self.node_anchor.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoinsuite_core::lotus_v2::{Output, TxHash};
    use chronik_db::v2_branch::{
        Binding, CommittedBlock, ConfirmedTx, SpentInput,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    static ID: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        state: V2HttpState,
        path: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "lotus-v2-http-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed)
            ));
            let mut db = V2Db::open(
                &path,
                Binding {
                    chain_id: [1; 32],
                    genesis: [2; 32],
                    profile: [3; 32],
                },
                chronik_db::v2_branch::Bounds::new(32_000_000).unwrap(),
            )
            .unwrap();
            db.initialize_genesis(test_block(
                Anchor {
                    block_id: [2; 32],
                    height: 0,
                },
                Anchor {
                    block_id: [2; 32],
                    height: 0,
                },
                vec![ConfirmedTx {
                    pos: chronik_db::v2_branch::TxPos::default(),
                    location: loc([2; 32], 0, 4),
                    outputs: vec![output(), output()],
                    spends: vec![],
                    explorer: test_facts(vec![]),
                }],
            ))
            .unwrap();
            Self {
                state: V2HttpState {
                    index_error: Arc::new(std::sync::atomic::AtomicBool::new(
                        false,
                    )),
                    service_epoch: [1; 16],
                    db: Arc::new(Mutex::new(db)),
                    node_anchor: Some(Arc::new(|| AuthoritativeState {
                        observation: 2,
                        generation: 1,
                        anchor: Some(Anchor {
                            block_id: [2; 32],
                            height: 0,
                        }),
                    })),
                },
                path,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    fn test_facts(
        spends: Vec<OutPoint>,
    ) -> chronik_db::v2_explorer::ExplorerTxFacts {
        use chronik_db::v2_explorer::*;
        ExplorerTxFacts {
            wire: vec![0],
            lock: 0,
            inputs: spends
                .into_iter()
                .map(|op| InputFact {
                    prev_txid: op.txid.0 .0,
                    prev_index: op.out_idx,
                    sequence: 0,
                    flags: 1,
                    path_index: 0,
                    has_coinbase_data: false,
                    coinbase_data: WireRange::default(),
                    witnesses: vec![WitnessFact {
                        script: WireRange {
                            offset: 0,
                            length: 0,
                        },
                        siblings_table: WireRange {
                            offset: 0,
                            length: 1,
                        },
                        siblings_count: 0,
                        arguments_table: WireRange {
                            offset: 0,
                            length: 1,
                        },
                        arguments_count: 0,
                    }],
                })
                .collect(),
        }
    }
    fn test_block(
        anchor: Anchor,
        parent: Anchor,
        transactions: Vec<ConfirmedTx>,
    ) -> CommittedBlock {
        let mut header_wire = [0; 134];
        if anchor.height > 0 {
            header_wire[..32].copy_from_slice(&parent.block_id);
        }
        header_wire[62..70].copy_from_slice(&anchor.height.to_le_bytes());
        header_wire[54..62].copy_from_slice(&134u64.to_le_bytes());
        CommittedBlock {
            anchor,
            parent,
            transactions,
            explorer: chronik_db::v2_explorer::ExplorerBlockFacts {
                header_wire,
            },
        }
    }
    fn loc(block: [u8; 32], height: u64, id: u8) -> TxLocation {
        TxLocation {
            block_id: Hash32(block),
            height,
            tx_index: 0,
            txid: TxId(Hash32([id; 32])),
            txhash: TxHash(Hash32([id + 1; 32])),
        }
    }
    fn output() -> Output {
        Output {
            flags: 0,
            value: u64::MAX,
            token_id: Hash32([0; 32]),
            state_root: Hash32::default(),
            branches: vec![Hash32([9; 32])],
            paths: vec![vec![0]],
        }
    }
    fn request(page: usize, cursor: Option<&str>) -> Body {
        Body::from(json!({"any_branch":[hex::encode([9;32])],"page_size":page,"cursor":cursor}).to_string())
    }
    async fn value(r: Response) -> Value {
        serde_json::from_slice(
            &to_bytes(r.into_body(), JSON_CAP).await.unwrap(),
        )
        .unwrap()
    }
    #[tokio::test]
    async fn actual_db_output_paging_spends_reorg_and_stale_cursor() {
        let mut f = Fixture::new();
        let p = value(branches(f.state.clone(), request(1, None), true).await)
            .await;
        assert_eq!(p["outputs"].as_array().unwrap().len(), 1);
        assert_eq!(p["outputs"][0]["record"]["value"], u64::MAX.to_string());
        let cursor = p["cursor"].as_str().unwrap();
        let second = value(
            branches(f.state.clone(), request(1, Some(cursor)), true).await,
        )
        .await;
        assert_eq!(second["outputs"][0]["record"]["out_idx"], 1);
        let parent = Anchor {
            block_id: [2; 32],
            height: 0,
        };
        let child = Anchor {
            block_id: [6; 32],
            height: 1,
        };
        let op = OutPoint {
            txid: TxId(Hash32([4; 32])),
            out_idx: 0,
        };
        f.state
            .db
            .lock()
            .unwrap()
            .connect(&test_block(
                child,
                parent,
                vec![ConfirmedTx {
                    pos: chronik_db::v2_branch::TxPos::default(),
                    location: loc([6; 32], 1, 7),
                    outputs: vec![],
                    spends: vec![SpentInput {
                        outpoint: op,
                        input_index: 0,
                    }],
                    explorer: test_facts(vec![op]),
                }],
            ))
            .unwrap();
        f.state.node_anchor = Some(Arc::new(move || AuthoritativeState {
            observation: 2,
            generation: 2,
            anchor: Some(child),
        }));
        assert_eq!(
            branches(f.state.clone(), request(1, Some(cursor)), true)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        let history =
            value(branches(f.state.clone(), request(100, None), true).await)
                .await;
        assert!(history["outputs"][0]["record"]["spend"].is_object());
        let coins =
            value(branches(f.state.clone(), request(100, None), false).await)
                .await;
        assert_eq!(coins["outputs"].as_array().unwrap().len(), 1);
        f.state.db.lock().unwrap().disconnect(child).unwrap();
        f.state.node_anchor = Some(Arc::new(move || AuthoritativeState {
            observation: 2,
            generation: 3,
            anchor: Some(parent),
        }));
        let coins =
            value(branches(f.state.clone(), request(100, None), false).await)
                .await;
        assert_eq!(coins["outputs"].as_array().unwrap().len(), 2);
        let status = value(status(State(f.state.clone())).await).await;
        assert_eq!(status["ready"], true);
        let mut ready_state = f.state.clone();
        ready_state.node_anchor = Some(Arc::new(move || AuthoritativeState {
            observation: 2,
            generation: 1,
            anchor: Some(parent),
        }));
        assert_eq!(
            value(super::status(State(ready_state.clone())).await).await
                ["ready"],
            true
        );
        ready_state.node_anchor = Some(Arc::new(move || AuthoritativeState {
            observation: 2,
            generation: 2,
            anchor: Some(child),
        }));
        assert_eq!(
            value(super::status(State(ready_state)).await).await["ready"],
            false
        );
    }
    #[tokio::test]
    async fn rejects_malformed_unknown_and_caps_before_queries() {
        let f = Fixture::new();
        for s in [
            "{",
            "{\"unknown\":1}",
            "{\"any_branch\":[\"zz\"]}",
            "{\"page_size\":101}",
            "{\"positions\":[{\"position\":256,\"roots\":[]}]}",
            "{\"cursor\":\"00\"}",
        ] {
            assert_eq!(
                branches(f.state.clone(), Body::from(s), true)
                    .await
                    .status(),
                StatusCode::BAD_REQUEST,
                "{s}"
            );
        }
        assert_eq!(
            branches(
                f.state.clone(),
                Body::from(vec![b' '; BODY_CAP + 1]),
                true
            )
            .await
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            response(StatusCode::OK, json!("x".repeat(JSON_CAP))).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let txid = hex::encode([4; 32]);
        assert_eq!(
            utxo(
                State(f.state.clone()),
                Path((txid.clone(), "4294967296".into()))
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            utxo(State(f.state.clone()), Path((txid, "0".into())))
                .await
                .status(),
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn router_uses_versioned_routes_without_network() {
        use tower::ServiceExt;
        let f = Fixture::new();
        let app = router(f.state.clone());
        for uri in ["/v2/status", "/v2/utxos/0404040404040404040404040404040404040404040404040404040404040404/0"] {
            let result = app.clone().oneshot(axum::http::Request::builder().uri(uri).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }
        let result = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v2/branches/outputs")
                    .body(request(100, None))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(value(result).await["outputs"].as_array().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn readiness_fences_unknown_recovery_behind_and_aba() {
        let mut f = Fixture::new();
        let parent = Anchor {
            block_id: [2; 32],
            height: 0,
        };
        let child = Anchor {
            block_id: [6; 32],
            height: 1,
        };
        f.state.node_anchor = None;
        assert_eq!(
            branches(f.state.clone(), request(100, None), true)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        for anchor in [None, Some(child)] {
            f.state.node_anchor = Some(Arc::new(move || AuthoritativeState {
                observation: 2,
                generation: 2,
                anchor,
            }));
            assert_eq!(
                branches(f.state.clone(), request(100, None), false)
                    .await
                    .status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(
                utxo(
                    State(f.state.clone()),
                    Path((hex::encode([4; 32]), "0".into()))
                )
                .await
                .status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        // The third observation occurs after result construction/encoding.
        // Changing generation while retaining the same anchor models an ABA
        // or recovery boundary that bare anchor comparison cannot detect.
        for point_lookup in [false, true] {
            for changed_anchor in [Some(parent), Some(child), None] {
                let calls = Arc::new(AtomicU64::new(0));
                f.state.node_anchor = Some(Arc::new(move || {
                    let changed = calls.fetch_add(1, Ordering::SeqCst) >= 2;
                    AuthoritativeState {
                        observation: 2,
                        generation: if changed { 5 } else { 3 },
                        anchor: if changed {
                            changed_anchor
                        } else {
                            Some(parent)
                        },
                    }
                }));
                let result = if point_lookup {
                    utxo(
                        State(f.state.clone()),
                        Path((hex::encode([4; 32]), "0".into())),
                    )
                    .await
                } else {
                    branches(f.state.clone(), request(100, None), true).await
                };
                assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
            }
        }
        f.state.node_anchor = Some(Arc::new(move || AuthoritativeState {
            observation: 2,
            generation: 6,
            anchor: Some(parent),
        }));
        assert_eq!(
            branches(f.state.clone(), request(100, None), true)
                .await
                .status(),
            StatusCode::OK
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn held_database_returns_503_on_all_routes_without_waiting() {
        use tower::ServiceExt;
        let f = Fixture::new();
        let db = f.state.db.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let owner = std::thread::spawn(move || {
            let _guard = db.lock().unwrap();
            locked_tx.send(()).unwrap();
            // Bounded fallback allows a regression to fail instead of hanging.
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(5));
        });
        locked_rx.recv().unwrap();
        let app = router(f.state.clone());
        for (method,uri,body) in [
            ("GET","/v2/status",Body::empty()),
            ("GET","/v2/utxos/0404040404040404040404040404040404040404040404040404040404040404/0",Body::empty()),
            ("POST","/v2/branches/utxos",request(100,None)),
            ("POST","/v2/branches/outputs",request(100,None)),
        ] {
            let result=app.clone().oneshot(axum::http::Request::builder().method(method).uri(uri).body(body).unwrap()).await.unwrap();
            assert_eq!(result.status(),StatusCode::SERVICE_UNAVAILABLE);
            // The owner has not released the DB: each response was immediate
            // contention rejection, rather than waiting for the fallback.
            assert!(f.state.db.try_lock().is_err());
        }
        release_tx.send(()).unwrap();
        owner.join().unwrap();
    }
    #[test]
    fn cursor_fixed_encoding_and_binding() {
        let c = Cursor {
            version: 1,
            snapshot: Snapshot {
                chain_id: Hash32([1; 32]),
                profile_id: Hash32([2; 32]),
                tip: Hash32([3; 32]),
                height: u64::MAX,
            },
            filter_digest: Hash32([4; 32]),
            last_key: Some(OutPoint {
                txid: TxId(Hash32([5; 32])),
                out_idx: u32::MAX,
            }),
        };
        assert_eq!(decode_cursor(&encode_cursor(c)), Ok(c));
        let mut c = c;
        c.last_key = None;
        assert_eq!(decode_cursor(&encode_cursor(c)), Ok(c));
    }
}
