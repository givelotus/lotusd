//! Actual in-process router coverage; no listener or native service is started.
use super::*;
use chronik_db::{
    v2_branch::{Binding, CommittedBlock, ConfirmedTx, V2Db},
    v2_explorer::{
        ExplorerBlockFacts, ExplorerTxFacts, InputFact, WireRange, WitnessFact,
    },
};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use tower::ServiceExt;
static ID: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    state: V2HttpState,
    path: std::path::PathBuf,
    wire: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_outputs(2)
    }
    fn with_outputs(count: usize) -> Self {
        Self::with_kind(count, false)
    }
    fn with_kind(count: usize, burn: bool) -> Self {
        let path = std::env::temp_dir().join(format!(
            "lotus-explorer-http-{}-{}",
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
        )
        .unwrap();
        let anchor = Anchor {
            block_id: [2; 32],
            height: 0,
        };
        let mut header_wire = [0; 134];
        header_wire[54..62].copy_from_slice(&134u64.to_le_bytes());
        let mut wire = (0..40000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        wire[1] = 0; // Native empty argument table CompactSize count.
        let input = InputFact {
            prev_txid: [9; 32],
            prev_index: 0,
            sequence: u32::MAX,
            flags: 3,
            path_index: 0,
            has_coinbase_data: false,
            coinbase_data: WireRange::default(),
            witnesses: vec![WitnessFact {
                script: WireRange {
                    offset: 2,
                    length: 1,
                },
                siblings_table: WireRange {
                    offset: 0,
                    length: 1,
                },
                siblings_count: 0,
                arguments_table: WireRange {
                    offset: 1,
                    length: 1,
                },
                arguments_count: 0,
            }],
            resolved_creation: None,
        };
        let token = Output {
            flags: if burn { 3 } else { 1 },
            value: u64::MAX,
            token_id: Hash32([9; 32]),
            branches: vec![Hash32([8; 32]), Hash32([7; 32])],
            paths: if burn { vec![] } else { vec![vec![0, 1]] },
        };
        db.initialize_genesis(CommittedBlock {
            anchor,
            parent: anchor,
            explorer: ExplorerBlockFacts { header_wire },
            transactions: vec![ConfirmedTx {
                location: TxLocation {
                    block_id: Hash32([2; 32]),
                    height: 0,
                    tx_index: 0,
                    txid: TxId(Hash32([4; 32])),
                    txhash: TxHash(Hash32([5; 32])),
                },
                outputs: vec![token; count],
                spends: vec![],
                explorer: ExplorerTxFacts {
                    wire: wire.clone(),
                    lock: u64::MAX,
                    inputs: vec![input],
                },
            }],
        })
        .unwrap();
        Self {
            state: V2HttpState {
                db: Arc::new(Mutex::new(db)),
                node_anchor: Some(Arc::new(move || AuthoritativeState {
                    observation: 2,
                    generation: 1,
                    anchor: Some(anchor),
                })),
                service_epoch: [6; 16],
                index_error: Arc::new(AtomicBool::new(false)),
            },
            path,
            wire,
        }
    }
    fn app(&self) -> Router {
        router(self.state.clone())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
async fn call(app: &Router, path: &str, body: Option<Value>) -> Response {
    let mut r = axum::http::Request::builder().uri(format!("{PREFIX}{path}"));
    let bytes = if let Some(body) = body {
        r = r.method("POST");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    app.clone().oneshot(r.body(bytes).unwrap()).await.unwrap()
}
async fn value(r: Response) -> Value {
    serde_json::from_slice(&to_bytes(r.into_body(), JSON_CAP).await.unwrap())
        .unwrap()
}
fn id(n: u8) -> String {
    hex::encode([n; 32])
}
fn routes() -> Vec<String> {
    vec![
        "/status".into(),
        "/blocks".into(),
        "/blocks/by-height/0".into(),
        format!("/blocks/{}", id(2)),
        format!("/blocks/{}/transactions", id(2)),
        format!("/transactions/by-id/{}", id(4)),
        format!("/transactions/by-hash/{}", id(5)),
        format!("/transactions/by-id/{}/inputs", id(4)),
        format!("/transactions/by-id/{}/outputs", id(4)),
        format!("/transactions/by-id/{}/witnesses?input_index=0", id(4)),
        format!("/transactions/by-id/{}/wire", id(4)),
        format!("/outputs/{}/0", id(4)),
        "/assets".into(),
        format!("/assets/{}", id(9)),
        format!("/assets/{}/events", id(9)),
        format!("/assets/{}/outputs?view=history", id(9)),
        format!("/assets/{}/outputs?view=unspent", id(9)),
    ]
}
#[tokio::test]
async fn every_route_serves_schema_and_exact_native_facts() {
    let f = Fixture::new();
    let app = f.app();
    for path in routes() {
        let r = call(&app, &path, None).await;
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        assert_eq!(r.headers()["cache-control"], "no-store");
        let v = value(r).await;
        assert_eq!(v["api_version"], "1");
        if path != "/status" {
            assert_eq!(v["snapshot"]["genesis"], id(2));
            assert_eq!(v["snapshot"]["height"], "0");
            assert_eq!(v["coverage"]["complete"], true);
            assert!(v["snapshot_token"].is_string());
        }
    }
    for kind in ["outputs", "utxos"] {
        let r = call(
            &app,
            &format!("/branches/{kind}"),
            Some(json!({"any_branch":[id(8)],"page_size":"1"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let v = value(r).await;
        assert_eq!(v["data"]["items"][0]["matching_positions"][0], "0");
        assert_eq!(v["data"]["items"][0]["record"]["paths"][0][1], "1");
    }
    let block = value(call(&app, "/blocks/by-height/0", None).await).await;
    assert_eq!(block["data"]["header_wire"].as_str().unwrap().len(), 268);
    assert_eq!(block["data"]["prev_id"], id(0));
    let tx = value(
        call(&app, &format!("/transactions/by-id/{}", id(4)), None).await,
    )
    .await;
    assert_ne!(tx["data"]["txid"], tx["data"]["txhash"]);
    assert_eq!(tx["data"]["lock"], u64::MAX.to_string());
    assert_eq!(tx["data"]["accounting"]["availability"], "unknown");
    let input = value(
        call(&app, &format!("/transactions/by-id/{}/inputs", id(4)), None)
            .await,
    )
    .await;
    assert_eq!(input["data"]["items"][0]["kind"], "mint");
    assert!(input["data"]["items"][0]["path_index"].is_null());
    assert_eq!(input["data"]["items"][0]["sequence"], u32::MAX.to_string());
    let asset =
        value(call(&app, &format!("/assets/{}/events", id(9)), None).await)
            .await;
    assert_eq!(
        asset["data"]["items"][0]["output_units"],
        (u128::from(u64::MAX) * 2).to_string()
    );
}
#[tokio::test]
async fn wire_chunks_reconstruct_only_with_pinned_snapshot() {
    let f = Fixture::new();
    let app = f.app();
    let path = format!("/transactions/by-id/{}/wire", id(4));
    let first = value(call(&app, &path, None).await).await;
    let token = first["snapshot_token"].as_str().unwrap();
    let mut bytes =
        hex::decode(first["data"]["bytes_hex"].as_str().unwrap()).unwrap();
    assert_eq!(bytes.len(), 32768);
    assert_eq!(
        call(&app, &format!("{path}?offset=32768"), None)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let next = value(
        call(
            &app,
            &format!("{path}?offset=32768&snapshot_token={token}"),
            None,
        )
        .await,
    )
    .await;
    bytes.extend(
        hex::decode(next["data"]["bytes_hex"].as_str().unwrap()).unwrap(),
    );
    assert_eq!(bytes, f.wire);
    assert!(next["data"]["next_offset"].is_null());
    let end = value(
        call(
            &app,
            &format!("{path}?offset=40000&snapshot_token={token}"),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(end["data"]["bytes_hex"], "");
    assert!(end["data"]["next_offset"].is_null());
    assert_eq!(
        call(
            &app,
            &format!("{path}?offset=40001&snapshot_token={token}"),
            None
        )
        .await
        .status(),
        StatusCode::RANGE_NOT_SATISFIABLE
    );
}
#[tokio::test]
async fn list_continuations_and_restart_fences() {
    let f = Fixture::new();
    let app = f.app();
    let path = format!("/transactions/by-id/{}/outputs", id(4));
    let first =
        value(call(&app, &format!("{path}?page_size=1"), None).await).await;
    let cursor = first["data"]["next_cursor"].as_str().unwrap();
    let second =
        value(call(&app, &format!("{path}?cursor={cursor}"), None).await).await;
    assert_eq!(second["data"]["items"][0]["out_idx"], "1");
    assert_eq!(second["data"]["exhausted"], true);
    let mut restarted = f.state.clone();
    restarted.service_epoch[0] ^= 1;
    let restarted = router(restarted);
    assert_eq!(
        call(&restarted, &format!("{path}?cursor={cursor}"), None)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let token = first["snapshot_token"].as_str().unwrap();
    let r =
        call(&restarted, &format!("{path}?snapshot_token={token}"), None).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(value(r).await["error"]["code"], "stale_snapshot");
}
#[tokio::test(flavor = "current_thread")]
async fn held_owner_unknown_authority_and_aba_never_return_success_or_404() {
    let mut f = Fixture::new();
    let db = f.state.db.clone();
    let guard = db.lock().unwrap();
    let app = f.app();
    for path in routes() {
        assert_eq!(
            call(&app, &path, None).await.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
    }
    for kind in ["outputs", "utxos"] {
        assert_eq!(
            call(
                &app,
                &format!("/branches/{kind}"),
                Some(json!({"any_branch":[id(8)]}))
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    drop(guard);
    f.state.node_anchor = None;
    assert_eq!(
        call(&f.app(), "/blocks", None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let calls = Arc::new(AtomicU64::new(0));
    f.state.node_anchor = Some(Arc::new(move || AuthoritativeState {
        observation: 2,
        generation: if calls.fetch_add(1, Ordering::SeqCst) >= 2 {
            2
        } else {
            1
        },
        anchor: Some(Anchor {
            block_id: [2; 32],
            height: 0,
        }),
    }));
    let r =
        call(&f.app(), &format!("/transactions/by-id/{}", id(99)), None).await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(value(r).await["snapshot"].is_null());
}
#[tokio::test]
async fn malformed_parameters_rejected_before_a_busy_storage_read() {
    let f = Fixture::new();
    let db = f.state.db.clone();
    let _guard = db.lock().unwrap();
    let app = f.app();
    for path in [
        "/blocks?unknown=1".to_owned(),
        "/blocks?page_size=01".into(),
        "/blocks?page_size=1&page_size=2".into(),
        "/blocks/by-height/01".into(),
        format!("/assets/{}", "AA".repeat(32)),
        format!("/transactions/by-id/{}/wire?length=0", id(4)),
        format!("/transactions/by-id/{}/witnesses", id(4)),
    ] {
        assert_eq!(
            call(&app, &path, None).await.status(),
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
}

#[tokio::test]
async fn empty_work_limited_branch_page_advances_without_claiming_exhaustion() {
    let f = Fixture::with_outputs(600);
    let app = f.app();
    let body = json!({"any_branch":[id(8)],"positions":[{"position":"0","roots":[id(7)]}]});
    let first =
        value(call(&app, "/branches/outputs", Some(body.clone())).await).await;
    assert_eq!(first["data"]["items"].as_array().unwrap().len(), 0);
    assert_eq!(first["data"]["exhausted"], false);
    assert_eq!(first["data"]["work"], "1024");
    let cursor = first["data"]["next_cursor"].as_str().unwrap();
    let mut next = body;
    next.as_object_mut()
        .unwrap()
        .insert("cursor".into(), json!(cursor));
    let next = value(call(&app, "/branches/outputs", Some(next)).await).await;
    assert_eq!(next["data"]["exhausted"], true);
    assert!(next["data"]["next_cursor"].is_null());
}
#[tokio::test]
async fn index_failure_and_absence_are_explicit() {
    let f = Fixture::new();
    let app = f.app();
    let miss =
        value(call(&app, &format!("/assets/{}", id(99)), None).await).await;
    assert_eq!(miss["error"]["code"], "not_in_covered_chain");
    assert!(miss["snapshot"].is_object());
    assert_eq!(miss["coverage"]["complete"], true);
    f.state.index_error.store(true, Ordering::Release);
    let status = value(call(&app, "/status", None).await).await;
    assert_eq!(status["ready"], false);
    assert_eq!(status["reason"], "index_error");
    assert_eq!(
        call(&app, "/blocks", None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn burned_only_asset_unspent_scan_is_bounded_and_continues_empty() {
    let f = Fixture::with_kind(1100, true);
    let app = f.app();
    let path = format!("/assets/{}/outputs?view=unspent", id(9));
    let first = value(call(&app, &path, None).await).await;
    assert_eq!(first["data"]["items"].as_array().unwrap().len(), 0);
    assert_eq!(first["data"]["exhausted"], false);
    let cursor = first["data"]["next_cursor"].as_str().unwrap();
    let next =
        value(call(&app, &format!("{path}&cursor={cursor}"), None).await).await;
    assert_eq!(next["data"]["items"].as_array().unwrap().len(), 0);
    assert_eq!(next["data"]["exhausted"], true);
    let asset =
        value(call(&app, &format!("/assets/{}", id(9)), None).await).await;
    assert_eq!(asset["data"]["output_count"], "1100");
}

#[tokio::test]
async fn observation_only_idle_boundary_rejects_inflight_success_and_absence() {
    for id in [4, 99] {
        let mut f = Fixture::new();
        let calls = Arc::new(AtomicU64::new(0));
        f.state.node_anchor = Some(Arc::new(move || AuthoritativeState {
            generation: 1,
            observation: if calls.fetch_add(1, Ordering::SeqCst) >= 2 {
                4
            } else {
                2
            },
            anchor: Some(Anchor {
                block_id: [2; 32],
                height: 0,
            }),
        }));
        let result = call(
            &f.app(),
            &format!("/transactions/by-id/{}", self::id(id)),
            None,
        )
        .await;
        assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(value(result).await["snapshot"].is_null());
    }
}
