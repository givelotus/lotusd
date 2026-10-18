use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn limits() -> f::ServiceLimits {
    f::ServiceLimits {
        block_bytes: 1024 * 1024,
        transactions: 4096,
        changes: 65536,
        roots: 256,
        clauses: 16,
        page_size: 1,
        posting_reads: 4096,
        work: 8192,
        response_bytes: 4096,
    }
}
fn binding() -> f::Binding {
    f::Binding {
        chain_id: [1; 32],
        genesis: [2; 32],
        profile: [3; 32],
    }
}
fn tip(id: u8, height: u64) -> f::Anchor {
    f::Anchor {
        block_id: [id; 32],
        height,
    }
}
fn block(
    id: u8,
    height: u64,
    parent: u8,
    tx: u8,
    inputs: Vec<f::Input>,
) -> f::NativeBlock {
    let output = Output {
        flags: 0,
        value: u64::MAX,
        token_id: Hash32([0; 32]),
        branches: vec![Hash32([9; 32])],
        paths: vec![vec![0]],
    };
    f::NativeBlock {
        anchor: tip(id, height),
        parent: tip(parent, height.saturating_sub(1)),
        header_wire: header(height, parent),
        transactions: vec![f::NativeTx {
            txid: [tx; 32],
            txhash: [tx + 1; 32],
            index: 0,
            inputs: inputs.clone(),
            full_inputs: full_inputs(&inputs),
            wire: vec![0],
            lock: 0,
            outputs: vec![f::NativeOutput {
                wire: output.encode().unwrap(),
            }],
        }],
    }
}
fn no_cursor() -> f::Continuation {
    continuation(None)
}
fn request(utxos: bool) -> f::BranchRequest {
    f::BranchRequest {
        any_branch: vec![f::Root { bytes: [9; 32] }],
        positions: vec![],
        utxos,
        include_burn: false,
        cursor: no_cursor(),
    }
}
struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "lotus-v2-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn explicit_genesis_complete_spend_disconnect_reopen() {
    let path = Temp::new();
    assert!(open_service(path.path(), binding(), false, limits()).is_err());
    let service = open_service(path.path(), binding(), true, limits()).unwrap();
    assert!(!service.status(tip(2, 0)).unwrap().initialized);
    assert!(service.query_branches(request(true)).is_err());
    assert!(service
        .initialize_genesis(block(99, 0, 99, 10, vec![]))
        .is_err());
    service
        .initialize_genesis(block(2, 0, 2, 10, vec![]))
        .unwrap();
    let page = service.query_branches(request(true)).unwrap();
    assert_eq!(page.matches.len(), 1);
    assert_eq!(
        Output::decode(&page.matches[0].wire).unwrap().value,
        u64::MAX
    );
    assert!(page.encoded_bytes <= 4096);
    let cursor = page.cursor;
    assert!(service.status(tip(2, 0)).unwrap().ready);
    assert!(!service.status(tip(4, 1)).unwrap().ready);
    let input = f::Input {
        txid: [10; 32],
        out_idx: 0,
        input_index: 3,
    };
    service
        .connect_block(block(4, 1, 2, 12, vec![input]))
        .unwrap();
    let mut stale = request(true);
    stale.cursor = cursor;
    assert!(service.query_branches(stale).is_err());
    let history = service.query_branches(request(false)).unwrap();
    assert_eq!(history.encoded_bytes as usize, encoded_page(&history).len());
    assert!(history.matches[0].spent);
    assert_eq!(history.matches[0].input_index, 3);
    assert_eq!(
        service.query_branches(request(true)).unwrap().matches[0].txid,
        [12; 32]
    );
    let shared = service.clone_shared();
    std::thread::spawn(move || {
        assert!(shared.status(tip(4, 1)).unwrap().ready)
    })
    .join()
    .unwrap();
    service.disconnect_block(tip(4, 1)).unwrap();
    assert_eq!(
        service.query_branches(request(true)).unwrap().matches[0].txid,
        [10; 32]
    );
    drop(service);
    let service =
        open_service(path.path(), binding(), false, limits()).unwrap();
    assert!(service.status(tip(2, 0)).unwrap().ready);
    drop(service);
    let mut foreign = binding();
    foreign.profile = [42; 32];
    assert!(open_service(path.path(), foreign, false, limits()).is_err());
    assert!(open_service(path.path(), binding(), true, limits()).is_err());
}
#[test]
fn input_and_response_caps_preserve_checkpoint() {
    let path = Temp::new();
    let mut caps = limits();
    caps.changes = 1;
    let service = open_service(path.path(), binding(), true, caps).unwrap();
    service
        .initialize_genesis(block(2, 0, 2, 10, vec![]))
        .unwrap();
    let mut large = block(4, 1, 2, 12, vec![]);
    large.transactions[0].outputs.push(f::NativeOutput {
        wire: vec![0; MAX_OUTPUT_BYTES + 1],
    });
    assert!(service.connect_block(large).is_err());
    let mut oversized = block(4, 1, 2, 12, vec![]);
    oversized.transactions[0].outputs[0].wire = vec![0; MAX_OUTPUT_BYTES + 1];
    assert!(service.connect_block(oversized).is_err());
    let mut malformed = block(4, 1, 2, 12, vec![]);
    malformed.transactions[0].index = 7;
    assert!(service.connect_block(malformed).is_err());
    assert!(service.status(tip(2, 0)).unwrap().ready);
    let mut invalid = request(true);
    invalid.positions = vec![f::Position {
        position: 16,
        roots: vec![f::Root { bytes: [9; 32] }],
    }];
    assert!(service.query_branches(invalid).is_err());
    let mut many = request(true);
    many.any_branch = (0..257).map(|_| f::Root { bytes: [9; 32] }).collect();
    assert!(service.query_branches(many).is_err());
    drop(service);
    let mut caps = limits();
    caps.response_bytes = 512;
    let service = open_service(path.path(), binding(), false, caps).unwrap();
    assert!(service.query_branches(request(true)).is_err());
}

// Independent canonical transport encoder: exercise each actual field, rather
// than duplicating the service's fixed-overhead accounting constants.
fn encoded_page(page: &f::BranchPage) -> Vec<u8> {
    fn a(out: &mut Vec<u8>, a: &f::Anchor) {
        out.extend(a.block_id);
        out.extend(a.height.to_le_bytes());
    }
    fn loc(out: &mut Vec<u8>, l: &f::Location) {
        a(out, &l.anchor);
        out.extend(l.tx_index.to_le_bytes());
        out.extend(l.txid);
        out.extend(l.txhash);
    }
    fn vec(out: &mut Vec<u8>, b: &[u8]) {
        out.extend((b.len() as u32).to_le_bytes());
        out.extend(b);
    }
    let mut out = Vec::new();
    a(&mut out, &page.anchor);
    out.extend(page.chain_id);
    out.extend(page.profile);
    out.extend((page.matches.len() as u32).to_le_bytes());
    for m in &page.matches {
        out.extend(m.txid);
        out.extend(m.out_idx.to_le_bytes());
        vec(&mut out, &m.wire);
        loc(&mut out, &m.creation);
        out.push(u8::from(m.spent));
        loc(&mut out, &m.spend);
        out.extend(m.input_index.to_le_bytes());
        vec(&mut out, &m.matching_positions);
    }
    let c = &page.cursor;
    out.push(u8::from(c.present));
    out.push(c.version);
    out.extend(c.chain_id);
    out.extend(c.profile);
    a(&mut out, &c.anchor);
    out.extend(c.filter_digest);
    out.push(u8::from(c.has_last));
    out.extend(c.last_txid);
    out.extend(c.last_out_idx.to_le_bytes());
    out.extend(page.posting_reads.to_le_bytes());
    out.extend(page.work.to_le_bytes());
    out.extend(page.encoded_bytes.to_le_bytes());
    out
}
#[test]
fn exact_transport_response_and_block_boundaries() {
    let path = Temp::new();
    let service = open_service(path.path(), binding(), true, limits()).unwrap();
    let genesis = block(2, 0, 2, 10, vec![]);
    assert_eq!(genesis.transactions[0].outputs[0].wire.len(), 45);
    service.initialize_genesis(genesis).unwrap();
    let page = service.query_branches(request(true)).unwrap();
    let encoded = encoded_page(&page);
    assert_eq!(encoded.len(), 618);
    assert_eq!(page.encoded_bytes as usize, encoded.len());
    drop(service);
    for (cap, ok) in [(600, false), (617, false), (618, true), (619, true)] {
        let mut caps = limits();
        caps.response_bytes = cap;
        let service =
            open_service(path.path(), binding(), false, caps).unwrap();
        let result = service.query_branches(request(true));
        assert_eq!(result.is_ok(), ok, "cap {cap}");
        if let Ok(page) = result {
            let bytes = encoded_page(&page);
            assert_eq!(page.encoded_bytes as usize, bytes.len());
            assert!(bytes.len() <= cap as usize);
        }
    }
    let mut caps = limits();
    caps.block_bytes = 217;
    let other = Temp::new();
    let service = open_service(other.path(), binding(), true, caps).unwrap();
    let empty = f::NativeBlock {
        anchor: tip(2, 0),
        parent: tip(2, 0),
        transactions: vec![],
        header_wire: header(0, 2),
    };
    assert!(service.initialize_genesis(empty.clone()).is_err());
    assert!(!service.status(tip(2, 0)).unwrap().initialized);
    drop(service);
    let mut caps = limits();
    caps.block_bytes = 218;
    let service = open_service(other.path(), binding(), false, caps).unwrap();
    service.initialize_genesis(empty).unwrap();
    assert!(service.status(tip(2, 0)).unwrap().ready);
}

fn http(address: &str, method: &str, path: &str, body: &str) -> String {
    use std::io::{Read, Write};
    let mut socket = std::net::TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    write!(socket,"{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len()).unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    response
}
#[test]
fn explicit_loopback_server_lifecycle_authority_and_reorg() {
    let path = Temp::new();
    let service = open_service(path.path(), binding(), true, limits()).unwrap();
    assert!(start_v2_server(&service, "localhost:0").is_err());
    assert!(start_v2_server(&service, "").is_err());
    let server = start_v2_server(&service, "127.0.0.1:0").unwrap();
    let address = server.actual_address();
    assert_ne!(address.parse::<std::net::SocketAddr>().unwrap().port(), 0);
    let body = format!("{{\"any_branch\":[\"{}\"]}}", "09".repeat(32));
    assert!(http(&address, "GET", "/v2/status", "").starts_with("HTTP/1.1 503"));
    service
        .initialize_genesis(block(2, 0, 2, 10, vec![]))
        .unwrap();
    assert!(http(&address, "POST", "/v2/branches/utxos", &body)
        .starts_with("HTTP/1.1 503"));
    let first = service.publish_authority(tip(2, 0)).unwrap();
    assert!(http(&address, "GET", "/v2/status", "").contains("\"ready\":true"));
    let query = http(&address, "POST", "/v2/branches/utxos", &body);
    assert!(query.starts_with("HTTP/1.1 200"));
    assert!(query.contains(&"0a".repeat(32)));
    let unknown = service.invalidate_authority().unwrap();
    assert!(unknown > first);
    assert!(http(&address, "POST", "/v2/branches/utxos", &body)
        .starts_with("HTTP/1.1 503"));
    let ahead = service.publish_authority(tip(4, 1)).unwrap();
    assert!(ahead > unknown);
    assert!(http(&address, "POST", "/v2/branches/utxos", &body)
        .starts_with("HTTP/1.1 503"));
    service.connect_block(block(4, 1, 2, 12, vec![])).unwrap();
    // DB success does not publish authoritative freshness by itself.
    assert!(http(&address, "POST", "/v2/branches/utxos", &body)
        .starts_with("HTTP/1.1 503"));
    let connected = service.publish_authority(tip(4, 1)).unwrap();
    assert!(connected > ahead);
    assert!(http(&address, "POST", "/v2/branches/utxos", &body)
        .starts_with("HTTP/1.1 200"));
    service.invalidate_authority().unwrap();
    service.disconnect_block(tip(4, 1)).unwrap();
    let aba = service.publish_authority(tip(2, 0)).unwrap();
    assert!(aba > connected);
    assert!(http(&address, "POST", "/v2/branches/utxos", &body)
        .starts_with("HTTP/1.1 200"));
    service.connect_block(block(5, 1, 2, 14, vec![])).unwrap();
    service.publish_authority(tip(5, 1)).unwrap();
    assert!(http(&address, "GET", "/v2/status", "").contains("\"ready\":true"));
    server.stop().unwrap();
    server.stop().unwrap();
    assert!(std::net::TcpStream::connect(&address).is_err());
    let server = start_v2_server(&service, "127.0.0.1:0").unwrap();
    let address = server.actual_address();
    drop(server);
    assert!(std::net::TcpStream::connect(&address).is_err());
}

#[test]
fn real_server_busy_database_returns_503_and_stops_with_owner_held() {
    let path = Temp::new();
    let service = open_service(path.path(), binding(), true, limits()).unwrap();
    service
        .initialize_genesis(block(2, 0, 2, 10, vec![]))
        .unwrap();
    service.publish_authority(tip(2, 0)).unwrap();
    let server = start_v2_server(&service, "127.0.0.1:0").unwrap();
    let address = server.actual_address();
    let body = format!("{{\"any_branch\":[\"{}\"]}}", "09".repeat(32));
    let shared = service.shared_database();
    let owner = shared.lock().unwrap();
    let outpoint_path = format!("/v2/utxos/{}/0", "0a".repeat(32));
    for (method, path, body) in [
        ("GET", "/v2/status", ""),
        ("POST", "/v2/branches/utxos", body.as_str()),
        ("POST", "/v2/branches/outputs", body.as_str()),
        ("GET", outpoint_path.as_str(), ""),
    ] {
        assert!(http(&address, method, path, body).starts_with("HTTP/1.1 503"));
    }
    let start = std::time::Instant::now();
    server.stop().unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
    assert!(std::net::TcpStream::connect(&address).is_err());
    // The owner remains held until stop has completed: shutdown must never
    // depend on the database owner's release.
    assert_eq!(owner.checkpoint().unwrap(), Some(anchor(&tip(2, 0))));
    drop(owner);
}

fn header(height: u64, parent: u8) -> [u8; 134] {
    let mut h = [0; 134];
    if height > 0 {
        h[..32].fill(parent);
    }
    h[62..70].copy_from_slice(&height.to_le_bytes());
    h[54..62].copy_from_slice(&134u64.to_le_bytes());
    h
}
fn full_inputs(inputs: &[f::Input]) -> Vec<f::NativeFullInput> {
    let mut full = vec![];
    for i in inputs {
        while full.len() < i.input_index as usize {
            full.push(f::NativeFullInput {
                prev_txid: [0; 32],
                prev_index: 0,
                sequence: u32::MAX,
                flags: 2,
                path_index: 0,
                has_coinbase_data: false,
                coinbase_data: f::WireRange {
                    offset: 0,
                    length: 0,
                },
                witnesses: vec![],
            });
        }
        full.push(f::NativeFullInput {
            prev_txid: i.txid,
            prev_index: i.out_idx,
            sequence: 0,
            flags: 1,
            path_index: 0,
            has_coinbase_data: false,
            coinbase_data: f::WireRange {
                offset: 0,
                length: 0,
            },
            witnesses: vec![f::NativeWitness {
                script: f::WireRange {
                    offset: 0,
                    length: 0,
                },
                siblings_table: f::WireRange {
                    offset: 0,
                    length: 1,
                },
                siblings_count: 0,
                arguments_table: f::WireRange {
                    offset: 0,
                    length: 1,
                },
                arguments_count: 0,
            }],
        });
    }
    full
}

#[test]
fn explorer_idle_context_turns_keep_tokens_and_cursors_but_real_changes_stale()
{
    fn field(response: &str, key: &str) -> String {
        let prefix = format!("\"{key}\":\"");
        response
            .split_once(&prefix)
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap()
            .to_owned()
    }
    let path = Temp::new();
    let service = open_service(path.path(), binding(), true, limits()).unwrap();
    let mut genesis = block(2, 0, 2, 10, vec![]);
    let duplicate = genesis.transactions[0].outputs[0].clone();
    genesis.transactions[0].outputs.push(duplicate);
    service.initialize_genesis(genesis).unwrap();
    let generation =
        service.publish_authority_context(tip(2, 0), 7, 11).unwrap();
    let server = start_v2_server(&service, "127.0.0.1:0").unwrap();
    let address = server.actual_address();
    let body = format!(
        "{{\"any_branch\":[\"{}\"],\"page_size\":\"1\"}}",
        "09".repeat(32)
    );
    let first =
        http(&address, "POST", "/v2/explorer/v1/branches/outputs", &body);
    assert!(first.starts_with("HTTP/1.1 200"));
    let token = field(&first, "snapshot_token");
    let cursor = field(&first, "next_cursor");
    let continuation=format!("{{\"any_branch\":[\"{}\"],\"page_size\":\"1\",\"cursor\":\"{cursor}\"}}","09".repeat(32));
    for _ in 0..30 {
        assert_eq!(service.suspend_authority().unwrap(), generation);
        assert!(http(&address, "GET", "/v2/explorer/v1/blocks", "")
            .starts_with("HTTP/1.1 503"));
        assert_eq!(
            service.publish_authority_context(tip(2, 0), 7, 11).unwrap(),
            generation
        );
    }
    assert!(http(
        &address,
        "POST",
        "/v2/explorer/v1/branches/outputs",
        &continuation
    )
    .starts_with("HTTP/1.1 200"));
    let wire=format!("/v2/explorer/v1/transactions/by-id/{}/wire?offset=1&length=1&snapshot_token={token}","0a".repeat(32));
    assert!(http(&address, "GET", &wire, "").starts_with("HTTP/1.1 200"));
    assert!(
        service.publish_authority_context(tip(2, 0), 8, 11).unwrap()
            > generation
    );
    assert!(http(
        &address,
        "POST",
        "/v2/explorer/v1/branches/outputs",
        &continuation
    )
    .starts_with("HTTP/1.1 409"));
    assert!(http(&address, "GET", &wire, "").starts_with("HTTP/1.1 409"));
    let current = service.publish_authority_context(tip(2, 0), 8, 11).unwrap();
    let invalidated = service.invalidate_authority().unwrap();
    assert!(invalidated > current);
    assert_eq!(
        service.publish_authority_context(tip(2, 0), 8, 11).unwrap(),
        invalidated
    );
    service.connect_block(block(4, 1, 2, 12, vec![])).unwrap();
    service.publish_authority_context(tip(4, 1), 9, 12).unwrap();
    service.disconnect_block(tip(4, 1)).unwrap();
    assert!(
        service
            .publish_authority_context(tip(2, 0), 10, 13)
            .unwrap()
            > invalidated
    );
    assert!(http(&address, "GET", &wire, "").starts_with("HTTP/1.1 409"));
    server.stop().unwrap();
}
