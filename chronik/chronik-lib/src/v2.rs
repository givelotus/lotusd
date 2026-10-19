//! Bounded native V2 service sharing a serialized DB owner with Rust readers.
//!
//! The typed response byte budget uses canonical field order: arrays are raw
//! bytes, integers are fixed-width little-endian, booleans are one byte, and
//! vectors carry a u32 count followed by elements. All optional slots are always
//! present. A page has a 307-byte envelope and each match has 265 fixed bytes,
//! followed by its output wire and matching-position bytes. This is a transport
//! payload cap; CXX allocator metadata is not serialized. HTTP adapters must
//! enforce their own encoding cap if expanding these records to JSON.
//!
//! Native callers authenticate consensus, canonical IDs and committed ordering.
//! This service checks bindings and model shape, and never advances node state.
//! CXX caller vectors already exist when entering Rust. Caps reject them before
//! allocating model copies; native callers must also bound their construction.
//! Readiness is only the equality of separately supplied node/index checkpoints.
use crate::v2_ffi as f;
use bitcoinsuite_core::lotus_v2::{
    Hash32, OutPoint, Output, OutputRecord, TxHash, TxId, TxLocation,
    MAX_OUTPUT_BYTES,
};
use chronik_db::v2_branch::{self as db, ReadSnapshot, V2Db};
use chronik_db::v2_explorer::{
    ExplorerBlockFacts, ExplorerTxFacts, InputFact, WireRange, WitnessFact,
};
use chronik_indexer::query::v2_branches as q;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
};
type Result<T> = std::result::Result<T, String>;
/// Thread-safe confirmed index owner. Clones share storage and immutable caps.
#[derive(Clone, Debug)]
pub struct V2Service {
    db: Arc<Mutex<V2Db>>,
    limits: f::ServiceLimits,
    bounds: db::Bounds,
    genesis: [u8; 32],
    authority: Arc<crate::v2_server::Authority>,
    service_epoch: [u8; 16],
    index_error: Arc<AtomicBool>,
}
/// Open a dedicated directory; fresh requires absence, existing requires mdbx.dat.
/// No deletion occurs. Reads stay unavailable until explicit genesis commits.
pub fn open_service(
    path: &str,
    binding: f::Binding,
    fresh: bool,
    limits: f::ServiceLimits,
) -> Result<Box<V2Service>> {
    if path.is_empty() || path.len() > 4096 {
        return Err("path bound".into());
    }
    // block_bytes is the consensus block-size limit; the index bounds and
    // the largest transaction and change counts follow from it.
    let bounds = db::Bounds::new(limits.block_bytes.into())
        .map_err(|_| "service limits")?;
    if limits.transactions == 0
        || limits.transactions as usize > bounds.transactions()
        || limits.changes == 0
        || limits.changes as usize > bounds.changes()
        || limits.roots == 0
        || limits.roots > 256
        || limits.clauses == 0
        || limits.clauses > 16
        || limits.page_size == 0
        || limits.page_size > 1000
        || limits.posting_reads == 0
        || limits.posting_reads > 65536
        || limits.work == 0
        || limits.work > 131072
        || limits.response_bytes < 512
        || limits.response_bytes > 1024 * 1024
    {
        return Err("service limits".into());
    }
    let mut service_epoch = [0u8; 16];
    getrandom::getrandom(&mut service_epoch)
        .map_err(|_| "explorer entropy unavailable")?;
    let path = Path::new(path);
    if fresh {
        std::fs::create_dir(path).map_err(|e| e.to_string())?;
    } else if !path.join("mdbx.dat").is_file() {
        return Err("existing V2 DB required".into());
    }
    let database = V2Db::open(
        path,
        db::Binding {
            chain_id: binding.chain_id,
            genesis: binding.genesis,
            profile: binding.profile,
        },
        bounds,
    )
    .map_err(|e| e.to_string())?;
    Ok(Box::new(V2Service {
        db: Arc::new(Mutex::new(database)),
        limits,
        bounds,
        genesis: binding.genesis,
        authority: Arc::new(crate::v2_server::Authority::default()),
        service_epoch,
        index_error: Arc::new(AtomicBool::new(false)),
    }))
}
fn anchor(a: &f::Anchor) -> db::Anchor {
    db::Anchor {
        block_id: a.block_id,
        height: a.height,
    }
}
fn ffi_anchor(a: db::Anchor) -> f::Anchor {
    f::Anchor {
        block_id: a.block_id,
        height: a.height,
    }
}
impl V2Service {
    /// Invalidate before native chain changes or recovery, before taking node
    /// locks. Every call advances the durable generation, including ABA.
    pub fn invalidate_authority(&self) -> Result<u64> {
        self.authority.publish(None)
    }
    /// Publish only after the native chain is stable. The indexed checkpoint
    /// remains independent; HTTP returns unavailable when these anchors differ.
    pub fn publish_authority(&self, a: f::Anchor) -> Result<u64> {
        self.authority.publish(Some(anchor(&a)))
    }
    /// Suspend reads for a native work turn without invalidating durable
    /// continuations. Only exact-context reconciliation can safely resume them.
    pub fn suspend_authority(&self) -> Result<u64> {
        self.authority.suspend()
    }
    /// Publish a fully reconciled native stamp. Every native mutation/recovery
    /// must change its context generation or revision, even at an unchanged tip.
    pub fn publish_authority_context(
        &self,
        a: f::Anchor,
        context_generation: u64,
        chain_revision: u64,
    ) -> Result<u64> {
        self.authority.publish_context(
            anchor(&a),
            context_generation,
            chain_revision,
        )
    }
    /// Clone the shared handle for another Rust service, including future HTTP.
    pub fn clone_shared(&self) -> Self {
        self.clone()
    }
    /// Share the exact DB owner with a Rust HTTP adapter. Readers must hold the
    /// mutex through snapshot use; native committed transitions remain the only
    /// authorized mutation source. Node readiness requires a separate provider.
    pub fn shared_database(&self) -> Arc<Mutex<V2Db>> {
        Arc::clone(&self.db)
    }
    /// Build a shared V2 HTTP state handle for embedding in ChronikServer.
    pub fn http_state(&self) -> chronik_http::v2::V2HttpState {
        let authority = Arc::clone(&self.authority);
        chronik_http::v2::V2HttpState {
            db: self.shared_database(),
            service_epoch: self.service_epoch,
            index_error: Arc::clone(&self.index_error),
            node_anchor: Some(Arc::new(move || authority.observe())),
        }
    }
    /// Return the current indexed checkpoint, if initialized.
    pub fn checkpoint(&self) -> Result<Option<f::Anchor>> {
        Ok(self
            .lock()?
            .checkpoint()
            .map_err(|e| e.to_string())?
            .map(ffi_anchor))
    }
    fn lock(&self) -> Result<MutexGuard<'_, V2Db>> {
        self.db.lock().map_err(|_| "V2 DB lock poisoned".into())
    }
    fn block(&self, block: f::NativeBlock) -> Result<db::CommittedBlock> {
        if block.transactions.len() > self.limits.transactions as usize {
            return Err("transaction bound".into());
        }
        // The block's wire bytes are within the consensus size limit; the
        // facts copied for them are within the index bounds it implies.
        let facts_cap = self.bounds.batch_bytes();
        let mut wire = block.header_wire.len();
        let mut bytes = 218usize;
        let mut changes = 0usize;
        if wire > self.bounds.block_bytes() || bytes > facts_cap {
            return Err("block bytes bound".into());
        }
        for tx in &block.transactions {
            wire = wire
                .checked_add(tx.wire.len())
                .ok_or("block overflow")?;
            if wire > self.bounds.block_bytes() {
                return Err("block bytes bound".into());
            }
            let descriptor_bytes = tx
                .full_inputs
                .iter()
                .try_fold(0usize, |n, i| {
                    i.witnesses
                        .len()
                        .checked_mul(80)
                        .and_then(|w| n.checked_add(w + 128))
                })
                .ok_or("descriptor overflow")?;
            bytes = bytes
                .checked_add(tx.wire.len())
                .and_then(|n| n.checked_add(descriptor_bytes))
                .ok_or("full facts overflow")?;
            if bytes > facts_cap {
                return Err("full facts bound".into());
            }

            changes = changes
                .checked_add(tx.inputs.len())
                .and_then(|n| n.checked_add(tx.outputs.len()))
                .ok_or("change overflow")?;
            bytes = bytes
                .checked_add(76)
                .and_then(|n| {
                    tx.inputs
                        .len()
                        .checked_mul(40)
                        .and_then(|k| n.checked_add(k))
                })
                .ok_or("block overflow")?;
            if changes > self.limits.changes as usize || bytes > facts_cap {
                return Err("block input bound".into());
            }
            for output in &tx.outputs {
                if output.wire.len() > MAX_OUTPUT_BYTES {
                    return Err("output bound".into());
                }
                bytes = bytes
                    .checked_add(4 + output.wire.len())
                    .ok_or("block overflow")?;
                if bytes > facts_cap {
                    return Err("block bytes bound".into());
                }
            }
        }
        let transactions = block
            .transactions
            .into_iter()
            .map(|tx| {
                let outputs = tx
                    .outputs
                    .into_iter()
                    .map(|o| Output::decode(&o.wire).map_err(|e| e.to_string()))
                    .collect::<Result<Vec<_>>>()?;
                Ok(db::ConfirmedTx {
                    location: TxLocation {
                        block_id: Hash32(block.anchor.block_id),
                        height: block.anchor.height,
                        tx_index: tx.index,
                        txid: TxId(Hash32(tx.txid)),
                        txhash: TxHash(Hash32(tx.txhash)),
                    },
                    explorer: ExplorerTxFacts {
                        wire: tx.wire,
                        lock: tx.lock,
                        inputs: tx
                            .full_inputs
                            .into_iter()
                            .map(|i| InputFact {
                                prev_txid: i.prev_txid,
                                prev_index: i.prev_index,
                                sequence: i.sequence,
                                flags: i.flags,
                                path_index: i.path_index,
                                has_coinbase_data: i.has_coinbase_data,
                                coinbase_data: range(i.coinbase_data),
                                witnesses: i
                                    .witnesses
                                    .into_iter()
                                    .map(|w| WitnessFact {
                                        script: range(w.script),
                                        siblings_table: range(w.siblings_table),
                                        siblings_count: w.siblings_count,
                                        arguments_table: range(
                                            w.arguments_table,
                                        ),
                                        arguments_count: w.arguments_count,
                                    })
                                    .collect(),
                                resolved_creation: None,
                            })
                            .collect(),
                    },
                    outputs,
                    spends: tx
                        .inputs
                        .into_iter()
                        .map(|i| db::SpentInput {
                            outpoint: OutPoint {
                                txid: TxId(Hash32(i.txid)),
                                out_idx: i.out_idx,
                            },
                            input_index: i.input_index,
                        })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(db::CommittedBlock {
            anchor: anchor(&block.anchor),
            parent: anchor(&block.parent),
            transactions,
            explorer: ExplorerBlockFacts {
                header_wire: block.header_wire,
            },
        })
    }
    /// Initialize complete caller-authenticated genesis, checking even empty blocks.
    pub fn initialize_genesis(&self, block: f::NativeBlock) -> Result<()> {
        self.transition(|| {
            if block.anchor.height != 0
                || block.parent.height != 0
                || block.anchor.block_id != block.parent.block_id
                || block.anchor.block_id != self.genesis
            {
                return Err("genesis binding/shape".into());
            }
            let block = self.block(block)?;
            self.lock()?
                .initialize_genesis(block)
                .map_err(|e| e.to_string())
        })
    }
    /// Index one authoritative committed block without changing node state.
    pub fn connect_block(&self, block: f::NativeBlock) -> Result<()> {
        self.transition(|| {
            let block = self.block(block)?;
            self.lock()?.connect(&block).map_err(|e| e.to_string())
        })
    }
    /// Undo exactly the expected indexed anchor.
    pub fn disconnect_block(&self, expected: f::Anchor) -> Result<()> {
        self.transition(|| {
            self.lock()?
                .disconnect(anchor(&expected))
                .map_err(|e| e.to_string())
        })
    }
    fn transition(&self, action: impl FnOnce() -> Result<()>) -> Result<()> {
        let result = self.invalidate_authority().and_then(|_| action());
        self.index_error.store(result.is_err(), Ordering::Release);
        result
    }
    /// Compare separate indexed and authoritative node checkpoints.
    pub fn status(&self, node: f::Anchor) -> Result<f::Status> {
        let checkpoint =
            self.lock()?.checkpoint().map_err(|e| e.to_string())?;
        Ok(f::Status {
            initialized: checkpoint.is_some(),
            ready: checkpoint == Some(anchor(&node)),
            indexed: ffi_anchor(checkpoint.unwrap_or(db::Anchor {
                block_id: [0; 32],
                height: 0,
            })),
            node,
        })
    }
    /// Query confirmed branch records or UTXOs on one stable bounded snapshot.
    pub fn query_branches(
        &self,
        request: f::BranchRequest,
    ) -> Result<f::BranchPage> {
        if request.positions.len() > self.limits.clauses as usize
            || request.any_branch.len() > self.limits.roots as usize
        {
            return Err("query input bound".into());
        }
        let total = request
            .positions
            .iter()
            .try_fold(request.any_branch.len(), |n, p| {
                n.checked_add(p.roots.len())
            })
            .ok_or("root overflow")?;
        if total > self.limits.roots as usize
            || request.positions.len() > self.limits.clauses as usize
        {
            return Err("query input bound".into());
        }
        let filter = q::BranchFilter {
            any_branch: request
                .any_branch
                .into_iter()
                .map(|r| Hash32(r.bytes))
                .collect(),
            positions: request
                .positions
                .into_iter()
                .map(|p| q::PositionClause {
                    position: p.position,
                    roots: p
                        .roots
                        .into_iter()
                        .map(|r| Hash32(r.bytes))
                        .collect(),
                })
                .collect(),
        };
        let c = request.cursor;
        let cursor = c.present.then(|| q::Cursor {
            version: c.version,
            snapshot: q::Snapshot {
                chain_id: Hash32(c.chain_id),
                profile_id: Hash32(c.profile),
                tip: Hash32(c.anchor.block_id),
                height: c.anchor.height,
            },
            filter_digest: Hash32(c.filter_digest),
            last_key: c.has_last.then_some(OutPoint {
                txid: TxId(Hash32(c.last_txid)),
                out_idx: c.last_out_idx,
            }),
        });
        let database = self.lock()?;
        let source = Source(database.snapshot().map_err(|e| e.to_string())?);
        // Fixed-width transport includes absent spend slots. This conservative
        // budget covers vector framing and all optional cursor/record fields.
        let envelope = 307usize;
        let room = self.limits.response_bytes as usize - envelope;
        let page_cap = (self.limits.page_size as usize).min(room / 300).max(1);
        let limits = q::Limits {
            roots: self.limits.roots as usize,
            clauses: self.limits.clauses as usize,
            page_size: page_cap,
            posting_reads: self.limits.posting_reads as usize,
            work: self.limits.work as usize,
            result_bytes: room.saturating_sub(page_cap * 119),
        };
        let page = q::query(
            &source,
            &filter,
            if request.utxos {
                q::QueryKind::Utxos
            } else {
                q::QueryKind::History {
                    include_burn: request.include_burn,
                }
            },
            limits,
            cursor,
        )
        .map_err(|e| format!("V2 query: {e:?}"))?;
        let matches = page
            .matches
            .into_iter()
            .map(|m| {
                let spend = m.record.spend;
                Ok(f::OutputMatch {
                    txid: m.record.outpoint.txid.0 .0,
                    out_idx: m.record.outpoint.out_idx,
                    wire: m
                        .record
                        .output
                        .encode()
                        .map_err(|e| e.to_string())?,
                    creation: location(m.record.creation),
                    spent: spend.is_some(),
                    spend: spend
                        .map(|s| location(s.transaction))
                        .unwrap_or_else(empty_location),
                    input_index: spend.map_or(0, |s| s.input_index),
                    matching_positions: m.matching_positions,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let encoded_bytes = envelope
            + matches
                .iter()
                .map(|m| 265 + m.wire.len() + m.matching_positions.len())
                .sum::<usize>();
        if encoded_bytes > self.limits.response_bytes as usize {
            return Err("response bytes bound".into());
        }
        Ok(f::BranchPage {
            anchor: f::Anchor {
                block_id: page.snapshot.tip.0,
                height: page.snapshot.height,
            },
            chain_id: page.snapshot.chain_id.0,
            profile: page.snapshot.profile_id.0,
            matches,
            cursor: continuation(page.continuation),
            posting_reads: page.posting_reads as u64,
            work: page.work as u64,
            encoded_bytes: encoded_bytes as u64,
        })
    }
}
struct Source<'a>(ReadSnapshot<'a>);
impl q::PostingSource for Source<'_> {
    fn snapshot(&self) -> q::Snapshot {
        q::Snapshot {
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
    ) -> std::result::Result<Option<OutPoint>, q::QueryError> {
        self.0
            .next_posting(root, position, after)
            .map_err(|_| q::QueryError::Source("DB posting"))
    }
    fn output(
        &self,
        key: OutPoint,
    ) -> std::result::Result<Option<OutputRecord>, q::QueryError> {
        self.0
            .output(key)
            .map_err(|_| q::QueryError::Source("DB record"))
    }
}
fn location(l: TxLocation) -> f::Location {
    f::Location {
        anchor: f::Anchor {
            block_id: l.block_id.0,
            height: l.height,
        },
        tx_index: l.tx_index,
        txid: l.txid.0 .0,
        txhash: l.txhash.0 .0,
    }
}
fn empty_location() -> f::Location {
    f::Location {
        anchor: f::Anchor {
            block_id: [0; 32],
            height: 0,
        },
        tx_index: 0,
        txid: [0; 32],
        txhash: [0; 32],
    }
}
fn continuation(c: Option<q::Cursor>) -> f::Continuation {
    let present = c.is_some();
    let c = c.unwrap_or(q::Cursor {
        version: 1,
        snapshot: q::Snapshot {
            chain_id: Hash32([0; 32]),
            profile_id: Hash32([0; 32]),
            tip: Hash32([0; 32]),
            height: 0,
        },
        filter_digest: Hash32([0; 32]),
        last_key: None,
    });
    f::Continuation {
        present,
        version: c.version,
        chain_id: c.snapshot.chain_id.0,
        profile: c.snapshot.profile_id.0,
        anchor: f::Anchor {
            block_id: c.snapshot.tip.0,
            height: c.snapshot.height,
        },
        filter_digest: c.filter_digest.0,
        has_last: c.last_key.is_some(),
        last_txid: c.last_key.map_or([0; 32], |k| k.txid.0 .0),
        last_out_idx: c.last_key.map_or(0, |k| k.out_idx),
    }
}

#[cfg(test)]
#[path = "v2tests/tests.rs"]
mod tests;

/// Start an explicitly bound native V2 HTTP listener sharing this service.
pub fn start_v2_server(
    service: &V2Service,
    bind: &str,
) -> Result<Box<crate::v2_server::V2Server>> {
    crate::v2_server::start(
        service.shared_database(),
        Arc::clone(&service.authority),
        service.service_epoch,
        Arc::clone(&service.index_error),
        bind,
    )
}

fn range(r: f::WireRange) -> WireRange {
    WireRange {
        offset: r.offset,
        length: r.length,
    }
}
