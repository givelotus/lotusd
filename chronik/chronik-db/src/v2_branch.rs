//! Separate, versioned V2 confirmed branch database. No legacy DB or runtime
//! signals are used. Callers supply only authoritative committed transitions.
//! A synced libmdbx batch commits records, history postings, undo and checkpoint
//! together. Node/index commits remain separate and require adapter replay.

use crate::{
    mdbx::{MdbxEnv, MdbxError, MdbxSnapshot, MdbxWriteBatch},
    v2_asset::SpentCoin,
    v2_explorer::{ExplorerBlockFacts, ExplorerTxFacts},
};
use bitcoinsuite_core::lotus_v2::{
    Hash32, OutPoint, Output, OutputRecord, SpendLocation, TxHash, TxId,
    TxLocation,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex},
};

/// Schema cannot share a legacy Chronik database directory. Version 4 stores
/// node block-file positions instead of transaction and output copies.
pub const SCHEMA_VERSION: u32 = 4;
/// Shortest V2 transaction: the native codec rejects anything shorter (a
/// 16-byte header and at least one input).
pub const MIN_TX_WIRE_BYTES: usize = 58;
/// Shortest V2 transaction header (version, lock, input and output counts).
pub const MIN_TX_HEADER_WIRE_BYTES: usize = 16;
/// Shortest V2 input (a coinbase input without data).
pub const MIN_INPUT_WIRE_BYTES: usize = 42;
/// Shortest V2 spend input (no witnesses).
pub const MIN_SPEND_WIRE_BYTES: usize = 43;
/// Shortest V2 output.
pub const MIN_OUTPUT_WIRE_BYTES: usize = 43;
/// Shortest V2 branch witness.
pub const MIN_WITNESS_WIRE_BYTES: usize = 3;
/// Staging reserved per wire byte of a block. Every per-element reservation
/// of a connect (below and in `v2_explorer`), charged to the shortest wire
/// encoding of its element, stays within it; see the
/// `staging_covers_shortest_encodings` test.
pub const STAGING_PER_WIRE_BYTE: usize = 1024;
/// Staging reserved once per block (framing, checkpoint, header facts).
pub const STAGING_PER_BLOCK: usize = 64 * 1024;
/// Branch staging reserved per transaction.
pub(crate) const RESERVE_TX: usize = 512;
/// Asset staging reserved per output, spend and input.
pub(crate) const RESERVE_ASSET_ELEMENT: usize = 8192;
/// Branch staging reserved per spend: old/new records, undo and keys.
pub(crate) const RESERVE_SPEND: usize = 6 * MAX_RECORD_BYTES + 1024;
/// Branch staging reserved per output, plus `RESERVE_BRANCH` per branch.
pub(crate) const RESERVE_OUTPUT: usize = 6 * MAX_RECORD_BYTES;
/// Posting staging reserved per output branch (two postings).
pub(crate) const RESERVE_BRANCH: usize = 2 * 512;

/// Size bounds of the index, derived from the consensus block-size limit
/// (the largest valid block's wire bytes). A block within that limit always
/// fits them: its transaction count, its created and consumed outputs and
/// the staging reserved for it are all bounded by its wire bytes. The memory
/// of one connect is linear in the block's size, as it is for the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    block_bytes: usize,
}
impl Bounds {
    /// Largest supported block-size limit (hosts pass it in 32 bits).
    pub const MAX_BLOCK_BYTES: u64 = u32::MAX as u64;
    /// Bounds for blocks of at most `max_block_bytes` wire bytes.
    pub fn new(max_block_bytes: u64) -> Result<Self> {
        if max_block_bytes == 0 || max_block_bytes > Self::MAX_BLOCK_BYTES {
            return Err(Error::Invalid("block size limit"));
        }
        Ok(Bounds {
            block_bytes: max_block_bytes as usize,
        })
    }
    /// Consensus block-size limit in wire bytes.
    pub fn block_bytes(&self) -> usize {
        self.block_bytes
    }
    /// Most transactions a block within the limit can hold.
    pub fn transactions(&self) -> usize {
        self.block_bytes / MIN_TX_WIRE_BYTES
    }
    /// Most created plus consumed outputs a block within the limit can hold.
    pub fn changes(&self) -> usize {
        self.block_bytes / MIN_INPUT_WIRE_BYTES
    }
    /// Bound on the staging reserved for one block within the limit, and on
    /// its receipt, undo and write batch.
    pub fn batch_bytes(&self) -> usize {
        self.block_bytes
            .saturating_mul(STAGING_PER_WIRE_BYTE)
            .saturating_add(STAGING_PER_BLOCK)
    }
}

/// Immutable deployment binding; all bytes are native V2 wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Native chain identity.
    pub chain_id: [u8; 32],
    /// Genesis block identity.
    pub genesis: [u8; 32],
    /// Exact consensus/deployment profile digest.
    pub profile: [u8; 32],
}
/// Confirmed checkpoint, including the explicitly indexed height-zero genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Authoritative block identity.
    pub block_id: [u8; 32],
    /// Authoritative block height.
    pub height: u64,
}
/// Position of a confirmed transaction in the node's block files: the
/// `blkNNNNN.dat` file number and the byte offset of its serialization.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct TxPos {
    /// Block file number (`blkNNNNN.dat`).
    pub file_num: u32,
    /// Byte offset of the serialized transaction in that file.
    pub data_pos: u32,
}
/// A transaction from the authoritative committed block, in block order.
#[derive(Clone, Debug)]
pub struct ConfirmedTx {
    /// Confirmed accepted transaction identity and location.
    pub location: TxLocation,
    /// Position of the transaction in the node's block files. The index
    /// stores it instead of the transaction and reads the transaction back
    /// through its `TxSource`.
    pub pos: TxPos,
    /// Complete outputs in native output order.
    pub outputs: Vec<Output>,
    /// Consumed coins with their native input ordinals.
    pub spends: Vec<SpentInput>,
    /// Complete authenticated native transaction facts.
    pub explorer: ExplorerTxFacts,
}
/// A confirmed transaction read back from the node's block files and
/// converted to its native facts, exactly as when its block was connected.
#[derive(Clone, Debug)]
pub struct NodeTx {
    /// Transaction identity.
    pub txid: TxId,
    /// Transaction hash.
    pub txhash: TxHash,
    /// Complete outputs in native output order.
    pub outputs: Vec<Output>,
    /// Consumed coins with their native input ordinals.
    pub spends: Vec<SpentInput>,
    /// Complete native transaction facts, including the wire.
    pub explorer: ExplorerTxFacts,
}
impl From<&ConfirmedTx> for NodeTx {
    fn from(tx: &ConfirmedTx) -> Self {
        NodeTx {
            txid: tx.location.txid,
            txhash: tx.location.txhash,
            outputs: tx.outputs.clone(),
            spends: tx.spends.clone(),
            explorer: tx.explorer.clone(),
        }
    }
}
/// Reads confirmed transactions from the node. The index stores only block
/// file positions; every transaction byte, output and input it serves comes
/// from here, checked against the identities, wire size and checksum it
/// recorded when the block was connected.
pub trait TxSource: Send + Sync {
    /// Load the transaction at `pos`. `txid` is its expected identity and
    /// `coinbase` is true for the first transaction of its block.
    fn load_tx(
        &self,
        pos: TxPos,
        txid: TxId,
        coinbase: bool,
    ) -> std::result::Result<NodeTx, String>;
}
/// In-memory `TxSource` for tests and tools. A `V2Db` opened with it records
/// the transactions of every block it connects, keyed by txid with their
/// position; a read at another position fails.
#[derive(Debug, Default)]
pub struct MemTxSource {
    txs: Mutex<BTreeMap<TxId, (TxPos, NodeTx)>>,
}
impl MemTxSource {
    /// Record the transactions of `block`.
    pub fn record(&self, block: &CommittedBlock) {
        let mut txs = self.txs.lock().unwrap_or_else(|e| e.into_inner());
        for tx in &block.transactions {
            txs.insert(tx.location.txid, (tx.pos, NodeTx::from(tx)));
        }
    }
    /// Change a recorded transaction; returns whether it was recorded.
    pub fn modify(&self, txid: TxId, f: impl FnOnce(&mut NodeTx)) -> bool {
        let mut txs = self.txs.lock().unwrap_or_else(|e| e.into_inner());
        match txs.get_mut(&txid) {
            Some((_, tx)) => {
                f(tx);
                true
            }
            None => false,
        }
    }
}
impl TxSource for MemTxSource {
    fn load_tx(
        &self,
        pos: TxPos,
        txid: TxId,
        _coinbase: bool,
    ) -> std::result::Result<NodeTx, String> {
        let txs = self.txs.lock().unwrap_or_else(|e| e.into_inner());
        match txs.get(&txid) {
            Some((recorded, tx)) if *recorded == pos => Ok(tx.clone()),
            Some(_) => Err("transaction position mismatch".into()),
            None => Err("unknown transaction".into()),
        }
    }
}
/// Confirmed native spend input, preserving its original input ordinal.
#[derive(Clone, Copy, Debug)]
pub struct SpentInput {
    /// Consumed output identity.
    pub outpoint: OutPoint,
    /// Native input ordinal, including gaps for non-spend inputs.
    pub input_index: u32,
}
/// Confirmed-only transition. Input ordinals in `spends` must include their native
/// positions, hence use `SpentInput` for transactions with non-spend inputs.
#[derive(Clone, Debug)]
pub struct CommittedBlock {
    /// Checkpoint matching this transition or read snapshot.
    pub anchor: Anchor,
    /// Required checkpoint before connection.
    pub parent: Anchor,
    /// Transactions in exact confirmed block order.
    pub transactions: Vec<ConfirmedTx>,
    /// Exact authenticated native header.
    pub explorer: ExplorerBlockFacts,
}

/// Stable failure category (including storage engine detail for operational errors).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Storage engine failure.
    #[error("V2 database: {0}")]
    Db(#[from] MdbxError),
    /// Rejected transition, binding or explicit resource limit.
    #[error("invalid V2 index transition: {0}")]
    Invalid(&'static str),
    /// Inconsistent persisted encoding.
    #[error("corrupt V2 index encoding")]
    Corrupt,
    /// The index was written by another schema version.
    #[error(
        "V2 index schema version {found} is incompatible with version \
         {expected}; restart with -chronikreindex to rebuild the V2 index"
    )]
    Schema {
        /// Schema version of the stored index.
        found: u32,
        /// Schema version of this build.
        expected: u32,
    },
    /// The node could not read an indexed transaction from its block files.
    #[error("V2 index node read: {0}")]
    Node(String),
}
/// Result returned by native branch and index operations.
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(v).map_err(|_| Error::Corrupt)
}
pub(crate) fn decode<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T> {
    postcard::from_bytes(b).map_err(|_| Error::Corrupt)
}
fn op_bytes(op: OutPoint) -> [u8; 36] {
    let mut b = [0; 36];
    b[..32].copy_from_slice(&op.txid.0 .0);
    b[32..].copy_from_slice(&op.out_idx.to_be_bytes());
    b
}
fn op_decode(b: &[u8]) -> Result<OutPoint> {
    if b.len() != 36 {
        return Err(Error::Corrupt);
    }
    Ok(OutPoint {
        txid: TxId(Hash32(b[..32].try_into().unwrap())),
        out_idx: u32::from_be_bytes(b[32..].try_into().unwrap()),
    })
}
fn key(prefix: u8, bytes: &[u8]) -> Vec<u8> {
    let mut k = vec![prefix];
    k.extend(bytes);
    k
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Loc {
    block: [u8; 32],
    height: u64,
    index: u32,
    txid: [u8; 32],
    txhash: [u8; 32],
}
impl From<TxLocation> for Loc {
    fn from(l: TxLocation) -> Self {
        Self {
            block: l.block_id.0,
            height: l.height,
            index: l.tx_index,
            txid: l.txid.0 .0,
            txhash: l.txhash.0 .0,
        }
    }
}
impl From<Loc> for TxLocation {
    fn from(l: Loc) -> Self {
        Self {
            block_id: Hash32(l.block),
            height: l.height,
            tx_index: l.index,
            txid: TxId(Hash32(l.txid)),
            txhash: TxHash(Hash32(l.txhash)),
        }
    }
}
/// Coin facts of one output and its spend. The complete output (branches and
/// paths) is read from its creating transaction through the node; creation
/// and spend locations are joined from the transaction location index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Coin {
    flags: u8,
    value: u64,
    token_id: Option<[u8; 32]>,
    spend: Option<([u8; 32], u32)>,
}
impl Coin {
    fn new(output: &Output) -> Self {
        Coin {
            flags: output.flags,
            value: output.value,
            token_id: output.has_token().then_some(output.token_id.0),
            spend: None,
        }
    }
    fn matches(&self, output: &Output) -> bool {
        self.flags == output.flags
            && self.value == output.value
            && self.token_id == output.has_token().then_some(output.token_id.0)
    }
    fn is_burn(&self) -> bool {
        self.flags & 2 != 0
    }
    fn spent_coin(&self, outpoint: OutPoint) -> SpentCoin {
        SpentCoin {
            outpoint,
            flags: self.flags,
            value: self.value,
            token_id: Hash32(self.token_id.unwrap_or_default()),
        }
    }
}
/// Largest encoded `Coin`: flags, value, token and spend reference.
const MAX_COIN_BYTES: usize = 96;
fn decode_coin(bytes: &[u8]) -> Result<Coin> {
    if bytes.len() > MAX_COIN_BYTES {
        return Err(Error::Corrupt);
    }
    let coin: Coin = decode(bytes)?;
    if coin.flags & !7 != 0 || coin.token_id.is_some() != (coin.flags & 1 != 0)
    {
        return Err(Error::Corrupt);
    }
    Ok(coin)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReceiptTx {
    location: Loc,
    file_num: u32,
    data_pos: u32,
    wire_size: u64,
    wire_checksum: u64,
}
#[derive(Serialize, Deserialize)]
struct Undo {
    binding: Binding,
    anchor: Anchor,
    parent: Option<Anchor>,
    entries: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}
/// Load a recorded transaction through the node, checking that it is the
/// transaction the index recorded at that position.
fn load_checked(
    source: &dyn TxSource,
    location: TxLocation,
    pos: TxPos,
    wire_size: u64,
    wire_checksum: u64,
) -> Result<NodeTx> {
    let tx = source
        .load_tx(pos, location.txid, location.tx_index == 0)
        .map_err(Error::Node)?;
    if tx.txid != location.txid
        || tx.txhash != location.txhash
        || tx.explorer.wire.len() as u64 != wire_size
        || seahash::hash(&tx.explorer.wire) != wire_checksum
    {
        return Err(Error::Corrupt);
    }
    Ok(tx)
}

/// Owns a dedicated database. Mutations require exclusive Rust access.
pub struct V2Db {
    pub(crate) db: MdbxEnv,
    binding: Binding,
    bounds: Bounds,
    source: Arc<dyn TxSource>,
    recorder: Option<Arc<MemTxSource>>,
}
impl V2Db {
    /// Open with a fresh in-memory transaction source that records every
    /// connected block (tests and tools; see `open_with_source`).
    pub fn open(
        path: impl AsRef<Path>,
        binding: Binding,
        bounds: Bounds,
    ) -> Result<Self> {
        Self::open_recording(
            path,
            binding,
            bounds,
            Arc::new(MemTxSource::default()),
        )
    }
    /// Open with an in-memory source that records every connected block, so
    /// a reopened database can share the transactions of an earlier one.
    pub fn open_recording(
        path: impl AsRef<Path>,
        binding: Binding,
        bounds: Bounds,
        source: Arc<MemTxSource>,
    ) -> Result<Self> {
        let mut db = Self::open_with_source(
            path,
            binding,
            bounds,
            source.clone() as Arc<dyn TxSource>,
        )?;
        db.recorder = Some(source);
        Ok(db)
    }
    /// Open or create a dedicated V2 directory; reject foreign/legacy schema.
    /// `bounds` come from the consensus block-size limit. Transactions are
    /// read through `source` (the node's block files).
    pub fn open_with_source(
        path: impl AsRef<Path>,
        binding: Binding,
        bounds: Bounds,
        source: Arc<dyn TxSource>,
    ) -> Result<Self> {
        let db = MdbxEnv::open(path)?;
        match db.get(b"v2-binding")? {
            Some(existing) => {
                let (version, stored): (u32, Binding) =
                    postcard::take_from_bytes(&existing)
                        .map(|(v, _)| v)
                        .map_err(|_| Error::Corrupt)?;
                if version != SCHEMA_VERSION {
                    return Err(Error::Schema {
                        found: version,
                        expected: SCHEMA_VERSION,
                    });
                }
                if stored != binding
                    || existing != encode(&(SCHEMA_VERSION, binding))?
                {
                    return Err(Error::Invalid("binding/schema mismatch"));
                }
            }
            None => {
                if !db.is_empty()? {
                    return Err(Error::Invalid("nonempty foreign database"));
                }
                let mut batch = MdbxWriteBatch::default();
                batch.put(b"v2-binding", encode(&(SCHEMA_VERSION, binding))?);
                write(&db, batch, bounds)?;
            }
        }
        Ok(Self {
            db,
            binding,
            bounds,
            source,
            recorder: None,
        })
    }
    /// Immutable deployment binding.
    pub fn binding(&self) -> Binding {
        self.binding
    }
    /// Size bounds from the consensus block-size limit.
    pub fn bounds(&self) -> Bounds {
        self.bounds
    }
    /// Last fully indexed block; a new database has no checkpoint.
    pub fn checkpoint(&self) -> Result<Option<Anchor>> {
        self.db.get(b"tip")?.map(|b| decode(&b)).transpose()
    }
    /// Index the caller-authenticated committed genesis, including every output.
    /// Its identity must equal the immutable deployment genesis binding.
    pub fn initialize_genesis(&mut self, block: CommittedBlock) -> Result<()> {
        if block.parent != block.anchor {
            return Err(Error::Invalid("genesis parent"));
        }
        self.connect_impl(&block, true)
    }
    /// Read a stable MVCC snapshot and its matching checkpoint. New indexes
    /// remain unavailable until committed genesis initialization succeeds.
    pub fn snapshot(&self) -> Result<ReadSnapshot<'_>> {
        let inner = self.db.snapshot()?;
        let anchor = decode(
            &inner
                .get(b"tip")?
                .ok_or(Error::Invalid("uninitialized index"))?,
        )?;
        Ok(ReadSnapshot::new(
            inner,
            anchor,
            self.binding,
            self.bounds,
            self.source.clone(),
        ))
    }
    /// Atomically index one committed child block. Exact tip replay is a no-op;
    /// conflicting reuse, missing coins and double spends fail before writing.
    pub fn connect(&mut self, block: &CommittedBlock) -> Result<()> {
        self.connect_impl(block, false)
    }
    fn connect_impl(
        &mut self,
        block: &CommittedBlock,
        genesis: bool,
    ) -> Result<()> {
        let bounds = self.bounds;
        if block.transactions.len() > bounds.transactions() {
            return Err(Error::Invalid("transaction bound"));
        }
        if (!genesis
            && (block.parent.height.checked_add(1)
                != Some(block.anchor.height)
                || block.anchor.block_id == block.parent.block_id))
            || (genesis
                && (block.anchor.height != 0
                    || block.anchor.block_id != self.binding.genesis))
        {
            return Err(Error::Invalid("block identity"));
        }
        // Conservative staging reservation includes receipt, old/new records,
        // map nodes, posting keys, undo encoding and batch framing. Reject before
        // allocating receipt/maps rather than constructing a huge rejected batch.
        let mut reserved = 1024usize;
        reserve(
            &mut reserved,
            crate::v2_explorer::preflight_explorer_block(block)?,
            bounds,
        )?;
        for tx in &block.transactions {
            reserve(&mut reserved, RESERVE_TX, bounds)?;
            reserve(
                &mut reserved,
                tx.outputs
                    .len()
                    .checked_add(tx.spends.len())
                    .and_then(|n| n.checked_add(tx.explorer.inputs.len()))
                    .and_then(|n| n.checked_mul(RESERVE_ASSET_ELEMENT))
                    .ok_or(Error::Invalid("asset staging capacity"))?,
                bounds,
            )?;
            reserve(
                &mut reserved,
                tx.spends
                    .len()
                    .checked_mul(RESERVE_SPEND)
                    .ok_or(Error::Invalid("staging capacity"))?,
                bounds,
            )?;
            for output in &tx.outputs {
                output.validate().map_err(|_| Error::Invalid("output"))?;
                reserve(
                    &mut reserved,
                    RESERVE_OUTPUT + output.branches.len() * RESERVE_BRANCH,
                    bounds,
                )?;
            }
        }
        let mut changes = 0usize;
        let mut txids = BTreeSet::new();
        let mut receipt = Vec::new();
        for (i, tx) in block.transactions.iter().enumerate() {
            changes = changes
                .checked_add(tx.outputs.len())
                .and_then(|n| n.checked_add(tx.spends.len()))
                .ok_or(Error::Invalid("change bound"))?;
            if changes > bounds.changes() {
                return Err(Error::Invalid("change bound"));
            }
            if tx.location.block_id.0 != block.anchor.block_id
                || tx.location.height != block.anchor.height
                || tx.location.tx_index as usize != i
                || !txids.insert(tx.location.txid)
            {
                return Err(Error::Invalid("transaction identity/order"));
            }
            for output in &tx.outputs {
                output.encode().map_err(|_| Error::Invalid("output"))?;
            }
            receipt.push(ReceiptTx {
                location: tx.location.into(),
                file_num: tx.pos.file_num,
                data_pos: tx.pos.data_pos,
                wire_size: tx.explorer.wire.len() as u64,
                wire_checksum: seahash::hash(&tx.explorer.wire),
            });
        }
        let receipt =
            encode(&(block.anchor, block.parent, &block.explorer, receipt))?;
        if receipt.len() > bounds.batch_bytes() {
            return Err(Error::Invalid("receipt bound"));
        }
        let tip = self.checkpoint()?;
        let block_key = key(b'b', &block.anchor.block_id);
        if tip == Some(block.anchor) {
            return self.check_replay(block, &block_key, &receipt);
        }
        // Resolve the asset facts of every spend: from in-block parents,
        // which are applied before their children (the host may confirm
        // blocks in canonical (txid) order, where a child can precede the
        // parent whose output it spends), or from the coin index.
        let order = processing_order(&block.transactions);
        let mut created: BTreeMap<OutPoint, SpentCoin> = BTreeMap::new();
        let mut spent_coins = vec![Vec::new(); block.transactions.len()];
        for &tx_index in &order {
            let tx = &block.transactions[tx_index];
            for (index, input) in tx.explorer.inputs.iter().enumerate() {
                if input.flags != 1 {
                    continue;
                }
                let op = OutPoint {
                    txid: TxId(Hash32(input.prev_txid)),
                    out_idx: input.prev_index,
                };
                if !tx
                    .spends
                    .iter()
                    .any(|s| s.input_index as usize == index && s.outpoint == op)
                {
                    return Err(Error::Invalid("full spend mismatch"));
                }
                let coin = match created.get(&op) {
                    Some(coin) => *coin,
                    None => decode_coin(
                        &self
                            .db
                            .get(key(b'o', &op_bytes(op)))?
                            .ok_or(Error::Invalid("missing coin"))?,
                    )?
                    .spent_coin(op),
                };
                spent_coins[tx_index].push(coin);
            }
            if tx.spends.iter().any(|s| {
                tx.explorer
                    .inputs
                    .get(s.input_index as usize)
                    .is_none_or(|i| i.flags != 1)
            }) {
                return Err(Error::Invalid("full spend missing"));
            }
            for (i, output) in tx.outputs.iter().enumerate() {
                let op = OutPoint {
                    txid: tx.location.txid,
                    out_idx: i as u32,
                };
                created.insert(op, SpentCoin::from_output(op, output));
            }
        }
        if (if genesis {
            tip.is_some()
        } else {
            tip != Some(block.parent)
        }) || self.db.get(&block_key)?.is_some()
        {
            return Err(Error::Invalid("checkpoint/duplicate block"));
        }
        let explorer_entries = crate::v2_explorer::plan_explorer_block(block)?;
        let mut state: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        let mut undo = BTreeMap::new();
        let mut spent = BTreeSet::new();
        for tx in order.iter().map(|&i| &block.transactions[i]) {
            let tx_key = key(b't', &tx.location.txid.0 .0);
            if self.db.get(&tx_key)?.is_some() {
                return Err(Error::Invalid("duplicate transaction"));
            }
            undo.insert(tx_key.clone(), None);
            state.insert(tx_key, Some(encode(&Loc::from(tx.location))?));
            if tx
                .spends
                .windows(2)
                .any(|w| w[0].input_index >= w[1].input_index)
            {
                return Err(Error::Invalid("input ordinal order"));
            }
            let mut input_ordinals = BTreeSet::new();
            for input in &tx.spends {
                let op = &input.outpoint;
                if !input_ordinals.insert(input.input_index) {
                    return Err(Error::Invalid("duplicate input ordinal"));
                }
                if !spent.insert(*op) {
                    return Err(Error::Invalid("double spend"));
                }
                let k = key(b'o', &op_bytes(*op));
                let previous = match state.get(&k) {
                    Some(v) => v.clone(),
                    None => self.db.get(&k)?,
                }
                .ok_or(Error::Invalid("missing coin"))?;
                let mut coin = decode_coin(&previous)?;
                if coin.spend.is_some() || coin.is_burn() {
                    return Err(Error::Invalid("spent/burn coin"));
                }
                undo.entry(k.clone()).or_insert(self.db.get(&k)?);
                coin.spend = Some((tx.location.txid.0 .0, input.input_index));
                state.insert(k, Some(encode(&coin)?));
            }
            for (i, output) in tx.outputs.iter().enumerate() {
                let op = OutPoint {
                    txid: tx.location.txid,
                    out_idx: u32::try_from(i)
                        .map_err(|_| Error::Invalid("output index"))?,
                };
                let k = key(b'o', &op_bytes(op));
                if state.contains_key(&k) || self.db.get(&k)?.is_some() {
                    return Err(Error::Invalid("duplicate outpoint"));
                }
                undo.insert(k.clone(), None);
                state.insert(k, Some(encode(&Coin::new(output))?));
                for (position, root) in output.branches.iter().enumerate() {
                    for pos in [position as u8, 255] {
                        let mut k = posting_prefix(*root, Some(pos));
                        k.extend(op_bytes(op));
                        undo.insert(k.clone(), None);
                        state.insert(k, Some(vec![]));
                    }
                }
            }
        }
        for (k, v) in explorer_entries {
            if state.contains_key(&k) || self.db.get(&k)?.is_some() {
                return Err(Error::Invalid("duplicate explorer key"));
            }
            undo.insert(k.clone(), None);
            state.insert(k, Some(v));
        }
        for (k, v) in asset_entries(block, &order, &spent_coins, |k| {
            self.db.get(k).map_err(Into::into)
        })? {
            let old = self.db.get(&k)?;
            if !k.starts_with(b"eA") && old.is_some() {
                return Err(Error::Invalid("duplicate asset entry"));
            }
            undo.entry(k.clone()).or_insert(old);
            state.insert(k, Some(v));
        }
        let undo = encode(&Undo {
            binding: self.binding,
            anchor: block.anchor,
            parent: if genesis { None } else { Some(block.parent) },
            entries: undo.into_iter().collect(),
        })?;
        let size = receipt.len()
            + undo.len()
            + state
                .iter()
                .map(|(k, v)| k.len() + v.as_ref().map_or(0, Vec::len))
                .sum::<usize>();
        if size > bounds.batch_bytes() {
            return Err(Error::Invalid("batch bound"));
        }
        let mut batch = MdbxWriteBatch::default();
        for (k, v) in state {
            if let Some(v) = v {
                batch.put(k, v);
            }
        }
        batch.put(block_key, receipt);
        batch.put(key(b'u', &block.anchor.block_id), undo);
        batch.put(b"tip", encode(&block.anchor)?);
        batch.delete(b"disconnected");
        write(&self.db, batch, bounds)?;
        if let Some(recorder) = &self.recorder {
            recorder.record(block);
        }
        Ok(())
    }
    /// Exact replay of the indexed tip: its receipt (transaction identities,
    /// positions and wire checksums), explorer entries, created coins and
    /// spend references must all equal what was indexed.
    fn check_replay(
        &self,
        block: &CommittedBlock,
        block_key: &[u8],
        receipt: &[u8],
    ) -> Result<()> {
        let stored = self.db.get(block_key)?.ok_or(Error::Corrupt)?;
        if stored.len() > self.bounds.batch_bytes() {
            return Err(Error::Corrupt);
        }
        let conflict = Error::Invalid("conflicting replay");
        if stored != receipt {
            return Err(conflict);
        }
        for (k, v) in crate::v2_explorer::plan_explorer_block(block)? {
            if self.db.get(&k)?.as_ref() != Some(&v) {
                return Err(conflict);
            }
        }
        for tx in &block.transactions {
            for (i, output) in tx.outputs.iter().enumerate() {
                let op = OutPoint {
                    txid: tx.location.txid,
                    out_idx: i as u32,
                };
                match self.db.get(key(b'o', &op_bytes(op)))? {
                    Some(bytes) if decode_coin(&bytes)?.matches(output) => {}
                    _ => return Err(conflict),
                }
            }
            for spend in &tx.spends {
                match self.db.get(key(b'o', &op_bytes(spend.outpoint)))? {
                    Some(bytes)
                        if decode_coin(&bytes)?.spend
                            == Some((
                                tx.location.txid.0 .0,
                                spend.input_index,
                            )) => {}
                    _ => return Err(conflict),
                }
            }
        }
        Ok(())
    }
    /// Atomically undo the current block, including outputs spent in that block.
    /// Repeating the immediately completed disconnect is idempotent.
    pub fn disconnect(&mut self, anchor: Anchor) -> Result<()> {
        if anchor.height == 0 {
            return Err(Error::Invalid("genesis disconnect"));
        }
        let tip = self.snapshot()?.anchor;
        if tip != anchor {
            if self.db.get(b"disconnected")?.as_deref()
                == Some(encode(&anchor)?.as_slice())
            {
                return Ok(());
            }
            return Err(Error::Invalid("disconnect checkpoint"));
        }
        let bytes = self
            .db
            .get(key(b'u', &anchor.block_id))?
            .ok_or(Error::Invalid("missing undo"))?;
        if bytes.len() > self.bounds.batch_bytes() {
            return Err(Error::Corrupt);
        }
        let undo: Undo = decode(&bytes)?;
        validate_undo(
            &self.db,
            &*self.source,
            self.binding,
            self.bounds,
            anchor,
            &undo,
        )?;
        let parent = undo.parent.ok_or(Error::Corrupt)?;
        let mut batch = MdbxWriteBatch::default();
        for (k, v) in undo.entries {
            match v {
                Some(v) => batch.put(k, v),
                None => batch.delete(k),
            }
        }
        batch.delete(key(b'b', &anchor.block_id));
        batch.delete(key(b'u', &anchor.block_id));
        batch.put(b"tip", encode(&parent)?);
        batch.put(b"disconnected", encode(&anchor)?);
        write(&self.db, batch, self.bounds)
    }
}
// An output frame is <=812 bytes; each location is 96 hash bytes plus
// at most 15 varint bytes. Staging reservations per spend and output keep the
// bound of the former full output record (two locations and the output).
const MAX_RECORD_BYTES: usize = 1200;
fn reserve(total: &mut usize, bytes: usize, bounds: Bounds) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or(Error::Invalid("staging capacity"))?;
    if *total > bounds.batch_bytes() {
        return Err(Error::Invalid("staging capacity"));
    }
    Ok(())
}
/// Check that an undo log inverts exactly the indexed block. The block is
/// rebuilt from the node through `source` (its receipt keeps only positions),
/// and every key the block wrote must hold the value it wrote, with the
/// undo's prior value being the one connect replaced.
fn validate_undo(
    db: &MdbxEnv,
    source: &dyn TxSource,
    binding: Binding,
    bounds: Bounds,
    anchor: Anchor,
    undo: &Undo,
) -> Result<()> {
    let parent = undo.parent.ok_or(Error::Corrupt)?;
    if undo.binding != binding
        || undo.anchor != anchor
        || parent.height.checked_add(1) != Some(anchor.height)
        || (parent.height == 0 && parent.block_id != binding.genesis)
        || undo.entries.len() > bounds.batch_bytes() / 40
    {
        return Err(Error::Corrupt);
    }
    let receipt = db.get(key(b'b', &anchor.block_id))?.ok_or(Error::Corrupt)?;
    if receipt.len() > bounds.batch_bytes() {
        return Err(Error::Corrupt);
    }
    let (recorded_anchor, recorded_parent, explorer, transactions): (
        Anchor,
        Anchor,
        ExplorerBlockFacts,
        Vec<ReceiptTx>,
    ) = decode(&receipt)?;
    if recorded_anchor != anchor
        || recorded_parent != parent
        || transactions.len() > bounds.transactions()
    {
        return Err(Error::Corrupt);
    }
    let mut reservation = 1024;
    let mut restored = Vec::with_capacity(transactions.len());
    for (index, tx) in transactions.iter().enumerate() {
        if tx.location.block != anchor.block_id
            || tx.location.height != anchor.height
            || tx.location.index as usize != index
            || tx.wire_size == 0
            || tx.wire_size > bounds.block_bytes() as u64
        {
            return Err(Error::Corrupt);
        }
        let location: TxLocation = tx.location.clone().into();
        let pos = TxPos {
            file_num: tx.file_num,
            data_pos: tx.data_pos,
        };
        let node = load_checked(
            source,
            location,
            pos,
            tx.wire_size,
            tx.wire_checksum,
        )?;
        reserve(
            &mut reservation,
            RESERVE_TX
                + node
                    .spends
                    .len()
                    .checked_mul(RESERVE_SPEND)
                    .ok_or(Error::Corrupt)?,
            bounds,
        )
        .map_err(|_| Error::Corrupt)?;
        for output in &node.outputs {
            reserve(
                &mut reservation,
                RESERVE_OUTPUT + output.branches.len() * RESERVE_BRANCH,
                bounds,
            )
            .map_err(|_| Error::Corrupt)?;
        }
        restored.push(ConfirmedTx {
            location,
            pos,
            outputs: node.outputs,
            spends: node.spends,
            explorer: node.explorer,
        });
    }
    let block = CommittedBlock {
        anchor,
        parent,
        explorer,
        transactions: restored,
    };
    reserve(
        &mut reservation,
        crate::v2_explorer::preflight_explorer_block(&block)?,
        bounds,
    )
    .map_err(|_| Error::Corrupt)?;
    let undo_map: BTreeMap<Vec<u8>, Option<Vec<u8>>> =
        undo.entries.iter().cloned().collect();
    if undo_map.len() != undo.entries.len() {
        return Err(Error::Corrupt);
    }
    let in_block: BTreeSet<TxId> =
        block.transactions.iter().map(|tx| tx.location.txid).collect();
    let order = processing_order(&block.transactions);
    // Value of every key the block wrote, and the prior value its undo must
    // restore.
    let mut current: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut previous: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
    let mut spent_coins = vec![Vec::new(); block.transactions.len()];
    for &tx_index in &order {
        let tx = &block.transactions[tx_index];
        let k = key(b't', &tx.location.txid.0 .0);
        current.insert(k.clone(), encode(&Loc::from(tx.location))?);
        previous.insert(k, None);
        for spend in &tx.spends {
            let op = spend.outpoint;
            let k = key(b'o', &op_bytes(op));
            let before = match current.get(&k) {
                Some(bytes) => decode_coin(bytes)?,
                None => {
                    // A coin created before this block: its undo value is
                    // the unspent coin, created at or below the parent.
                    let bytes = undo_map
                        .get(&k)
                        .cloned()
                        .flatten()
                        .ok_or(Error::Corrupt)?;
                    let creation: Loc = decode(
                        &db.get(key(b't', &op.txid.0 .0))?
                            .ok_or(Error::Corrupt)?,
                    )?;
                    if in_block.contains(&op.txid)
                        || creation.txid != op.txid.0 .0
                        || creation.height > parent.height
                    {
                        return Err(Error::Corrupt);
                    }
                    let coin = decode_coin(&bytes)?;
                    previous.insert(k.clone(), Some(bytes));
                    coin
                }
            };
            if before.spend.is_some() || before.is_burn() {
                return Err(Error::Corrupt);
            }
            spent_coins[tx_index].push(before.spent_coin(op));
            let mut after = before;
            after.spend = Some((tx.location.txid.0 .0, spend.input_index));
            current.insert(k, encode(&after)?);
        }
        for (i, output) in tx.outputs.iter().enumerate() {
            let op = OutPoint {
                txid: tx.location.txid,
                out_idx: u32::try_from(i).map_err(|_| Error::Corrupt)?,
            };
            let k = key(b'o', &op_bytes(op));
            if current.insert(k.clone(), encode(&Coin::new(output))?).is_some()
            {
                return Err(Error::Corrupt);
            }
            previous.insert(k, None);
            for (position, root) in output.branches.iter().enumerate() {
                for position in [position as u8, 255] {
                    let mut k = posting_prefix(*root, Some(position));
                    k.extend(op_bytes(op));
                    current.insert(k.clone(), vec![]);
                    previous.insert(k, None);
                }
            }
        }
    }
    for (k, v) in crate::v2_explorer::plan_explorer_block(&block)? {
        if current.insert(k.clone(), v).is_some() {
            return Err(Error::Corrupt);
        }
        previous.insert(k, None);
    }
    for (k, v) in asset_entries(&block, &order, &spent_coins, |k| {
        Ok(undo_map.get(k).cloned().flatten())
    })? {
        let prior = undo_map.get(&k).ok_or(Error::Corrupt)?;
        if current.insert(k.clone(), v).is_some()
            || (!k.starts_with(b"eA") && prior.is_some())
        {
            return Err(Error::Corrupt);
        }
        previous.insert(k, prior.clone());
    }
    if previous != undo_map {
        return Err(Error::Corrupt);
    }
    for (k, v) in &current {
        if db.get(k)?.as_ref() != Some(v) {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}
/// Order in which a block's transactions are resolved and applied: every
/// in-block parent before the children spending its outputs, and otherwise
/// block order (so a topologically ordered block keeps its own order). A
/// dependency cycle cannot be confirmed; its members follow in block order
/// and are rejected as spending a missing coin.
fn processing_order(transactions: &[ConfirmedTx]) -> Vec<usize> {
    use std::{cmp::Reverse, collections::BinaryHeap};
    let index: BTreeMap<TxId, usize> = transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| (tx.location.txid, i))
        .collect();
    let mut pending = vec![0usize; transactions.len()];
    let mut children = vec![Vec::new(); transactions.len()];
    for (child, tx) in transactions.iter().enumerate() {
        for spend in &tx.spends {
            match index.get(&spend.outpoint.txid) {
                Some(&parent) if parent != child => {
                    pending[child] += 1;
                    children[parent].push(child);
                }
                _ => {}
            }
        }
    }
    let mut ready: BinaryHeap<Reverse<usize>> = (0..transactions.len())
        .filter(|&i| pending[i] == 0)
        .map(Reverse)
        .collect();
    let mut order = Vec::with_capacity(transactions.len());
    while let Some(Reverse(i)) = ready.pop() {
        order.push(i);
        for &child in &children[i] {
            pending[child] -= 1;
            if pending[child] == 0 {
                ready.push(Reverse(child));
            }
        }
    }
    if order.len() < transactions.len() {
        let mut placed = vec![false; transactions.len()];
        for &i in &order {
            placed[i] = true;
        }
        order.extend((0..transactions.len()).filter(|&i| !placed[i]));
    }
    order
}
/// Asset entries of a block; `spent_coins[i]` holds the resolved spends of
/// transaction `i` in input order.
fn asset_entries(
    block: &CommittedBlock,
    order: &[usize],
    spent_coins: &[Vec<SpentCoin>],
    mut old_value: impl FnMut(&[u8]) -> Result<Option<Vec<u8>>>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    use crate::v2_asset::{self as a, AssetTxView};
    let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for &tx_index in order {
        let tx = &block.transactions[tx_index];
        let resolved_spends = &spent_coins[tx_index];
        let mint_token_ids: Vec<_> = tx
            .explorer
            .inputs
            .iter()
            .filter(|i| i.flags == 3)
            .map(|i| Hash32(i.prev_txid))
            .collect();
        let view = || AssetTxView {
            location: tx.location,
            outputs: &tx.outputs,
            resolved_spends,
            mint_token_ids: &mint_token_ids,
        };
        let events = a::derive_asset_events(view())?;
        let mut summaries = BTreeMap::new();
        for event in events {
            let k = a::asset_summary_key(event.token_id);
            let bytes = match entries.get(&k) {
                Some(v) => Some(v.clone()),
                None => old_value(&k)?,
            };
            summaries.insert(
                event.token_id,
                bytes.as_deref().map(a::decode_asset_summary).transpose()?,
            );
        }
        for (k, v) in a::plan_asset_tx(view(), &summaries)? {
            entries.insert(k, v);
        }
    }
    Ok(entries)
}
fn write(db: &MdbxEnv, batch: MdbxWriteBatch, bounds: Bounds) -> Result<()> {
    if batch.size_in_bytes() > bounds.batch_bytes() {
        return Err(Error::Invalid("serialized batch bound"));
    }
    db.write(batch)?;
    Ok(())
}
fn posting_prefix(root: Hash32, position: Option<u8>) -> Vec<u8> {
    let mut k = key(b'p', &root.0);
    k.push(position.unwrap_or(255));
    k
}

/// Bounded read facade: each call returns at most one record/posting; consumers
/// enforce request budgets. MVCC read snapshots avoid copying the UTXO set.
pub struct ReadSnapshot<'a> {
    pub(crate) inner: MdbxSnapshot<'a>,
    /// Checkpoint matching this transition or read snapshot.
    pub anchor: Anchor,
    /// Immutable schema deployment binding.
    pub binding: Binding,
    /// Size bounds from the consensus block-size limit.
    pub bounds: Bounds,
    source: Arc<dyn TxSource>,
    /// Last transaction read through the node, with the metadata it was
    /// checked against (consecutive outputs usually share a transaction).
    last_tx: Mutex<Option<(crate::v2_explorer::TxMeta, Arc<NodeTx>)>>,
}
impl<'a> ReadSnapshot<'a> {
    pub(crate) fn new(
        inner: MdbxSnapshot<'a>,
        anchor: Anchor,
        binding: Binding,
        bounds: Bounds,
        source: Arc<dyn TxSource>,
    ) -> Self {
        ReadSnapshot {
            inner,
            anchor,
            binding,
            bounds,
            source,
            last_tx: Mutex::new(None),
        }
    }
    /// The transaction described by `meta`, read through the node and checked
    /// against its identities, counts, lock, wire size and checksum.
    pub(crate) fn node_tx(
        &self,
        meta: &crate::v2_explorer::TxMeta,
    ) -> Result<Arc<NodeTx>> {
        if let Ok(guard) = self.last_tx.lock() {
            if let Some((cached, tx)) = guard.as_ref() {
                if cached == meta {
                    return Ok(tx.clone());
                }
            }
        }
        let tx = load_checked(
            &*self.source,
            meta.location,
            TxPos {
                file_num: meta.file_num,
                data_pos: meta.data_pos,
            },
            meta.wire_size,
            meta.wire_checksum,
        )?;
        if tx.outputs.len() != meta.output_count as usize
            || tx.explorer.inputs.len() != meta.input_count as usize
            || tx.explorer.lock != meta.lock
        {
            return Err(Error::Corrupt);
        }
        let tx = Arc::new(tx);
        if let Ok(mut guard) = self.last_tx.lock() {
            *guard = Some((meta.clone(), tx.clone()));
        }
        Ok(tx)
    }
    /// Complete output `op`, read from its creating transaction at `creation`.
    fn creation_output(
        &self,
        op: OutPoint,
        creation: TxLocation,
    ) -> Result<Output> {
        let bytes = self
            .inner
            .get(crate::v2_explorer::tx_key(op.txid))?
            .ok_or(Error::Corrupt)?;
        let meta: crate::v2_explorer::TxMeta =
            crate::v2_explorer::decode_record(&bytes)?;
        if meta.location != creation || op.out_idx >= meta.output_count {
            return Err(Error::Corrupt);
        }
        let tx = self.node_tx(&meta)?;
        let output = tx
            .outputs
            .get(op.out_idx as usize)
            .ok_or(Error::Corrupt)?
            .clone();
        output.validate().map_err(|_| Error::Corrupt)?;
        Ok(output)
    }
    /// Canonical transaction location owned by the original location index.
    pub fn transaction(&self, txid: TxId) -> Result<Option<TxLocation>> {
        self.transaction_counted(
            txid,
            &mut crate::v2_asset::AssetReadBudget::new(usize::MAX),
        )
    }
    /// Canonical location joined to height, charging each actual key read.
    pub fn transaction_counted(
        &self,
        txid: TxId,
        budget: &mut crate::v2_asset::AssetReadBudget,
    ) -> Result<Option<TxLocation>> {
        budget.charge()?;
        let Some(bytes) = self.inner.get(key(b't', &txid.0 .0))? else {
            return Ok(None);
        };
        if bytes.len() > 128 {
            return Err(Error::Corrupt);
        }
        let location: TxLocation = decode::<Loc>(&bytes)?.into();
        if location.txid != txid || location.height > self.anchor.height {
            return Err(Error::Corrupt);
        }
        budget.charge()?;
        if self
            .inner
            .get(crate::v2_explorer::height_key(location.height))?
            .as_deref()
            != Some(location.block_id.0.as_slice())
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(location))
    }
    /// Full output with creation/spend history. Burns remain queryable.
    pub fn output(&self, op: OutPoint) -> Result<Option<OutputRecord>> {
        self.output_counted(
            op,
            &mut crate::v2_asset::AssetReadBudget::new(usize::MAX),
        )
    }
    /// Full historical output, charging each actual storage get before I/O.
    pub fn output_counted(
        &self,
        op: OutPoint,
        budget: &mut crate::v2_asset::AssetReadBudget,
    ) -> Result<Option<OutputRecord>> {
        budget.charge()?;
        let Some(bytes) = self.inner.get(key(b'o', &op_bytes(op)))? else {
            return Ok(None);
        };
        let coin = decode_coin(&bytes)?;
        let creation = self
            .transaction_counted(op.txid, budget)?
            .ok_or(Error::Corrupt)?;
        let spend = match coin.spend {
            Some((txid, input_index)) => Some(SpendLocation {
                transaction: self
                    .transaction_counted(TxId(Hash32(txid)), budget)?
                    .ok_or(Error::Corrupt)?,
                input_index,
            }),
            None => None,
        };
        let output = self.creation_output(op, creation)?;
        if !coin.matches(&output) {
            return Err(Error::Corrupt);
        }
        Ok(Some(OutputRecord {
            outpoint: op,
            output,
            creation,
            spend,
        }))
    }
    /// Return an unspent spendable output. Burn commitments are always excluded.
    pub fn utxo(&self, op: OutPoint) -> Result<Option<OutputRecord>> {
        Ok(self.output(op)?.filter(|record| {
            record.spend.is_none() && !record.output.is_burn()
        }))
    }
    /// Strictly ordered next outpoint for root and optional public position.
    pub fn next_posting(
        &self,
        root: Hash32,
        position: Option<u8>,
        after: Option<OutPoint>,
    ) -> Result<Option<OutPoint>> {
        if position.is_some_and(|p| p >= 16) {
            return Err(Error::Invalid("position"));
        }
        let Some(bytes) = self.inner.next_posting_dupfixed(
            root.0,
            position.unwrap_or(255),
            after.map(op_bytes),
        )?
        else {
            return Ok(None);
        };
        op_decode(&bytes).map(Some)
    }
    /// All strictly ordered outpoints for root and optional public position after `after`,
    /// fetched in bulk via `MDBX_GET_MULTIPLE` / `MDBX_NEXT_MULTIPLE`.
    pub fn postings_after(
        &self,
        root: Hash32,
        position: Option<u8>,
        after: Option<OutPoint>,
    ) -> Result<Vec<OutPoint>> {
        if position.is_some_and(|p| p >= 16) {
            return Err(Error::Invalid("position"));
        }
        let raw = self.inner.postings_dupfixed_after(
            root.0,
            position.unwrap_or(255),
            after.map(op_bytes),
        )?;
        raw.into_iter().map(|b| op_decode(&b)).collect()
    }
}

#[cfg(test)]
fn fixture_header(anchor: Anchor, parent: Anchor) -> ExplorerBlockFacts {
    let mut header_wire = [0; 134];
    if anchor.height > 0 {
        header_wire[..32].copy_from_slice(&parent.block_id);
    }
    header_wire[62..70].copy_from_slice(&anchor.height.to_le_bytes());
    header_wire[54..62].copy_from_slice(&134u64.to_le_bytes());
    ExplorerBlockFacts { header_wire }
}
#[cfg(test)]
fn fixture_witness() -> crate::v2_explorer::WitnessFact {
    use crate::v2_explorer::{WireRange, WitnessFact};
    WitnessFact {
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
    }
}
#[cfg(test)]
fn fixture_facts(spends: &[SpentInput], outputs: &[Output]) -> ExplorerTxFacts {
    use crate::v2_explorer::{InputFact, WireRange};
    let mut inputs = vec![];
    for spend in spends {
        while inputs.len() < spend.input_index as usize {
            inputs.push(InputFact {
                prev_txid: [0; 32],
                prev_index: 0,
                sequence: u32::MAX,
                flags: 2,
                path_index: 0,
                has_coinbase_data: false,
                coinbase_data: WireRange::default(),
                witnesses: vec![],
            });
        }
        inputs.push(InputFact {
            prev_txid: spend.outpoint.txid.0 .0,
            prev_index: spend.outpoint.out_idx,
            sequence: 0,
            flags: 1,
            path_index: 0,
            has_coinbase_data: false,
            coinbase_data: WireRange::default(),
            witnesses: vec![fixture_witness()],
        });
    }
    if spends.is_empty() {
        for output in outputs.iter().filter(|o| o.has_token()) {
            if inputs.iter().any(|i| i.prev_txid == output.token_id.0) {
                continue;
            }
            inputs.push(InputFact {
                prev_txid: output.token_id.0,
                prev_index: 0,
                sequence: u32::MAX,
                flags: 3,
                path_index: 0,
                has_coinbase_data: false,
                coinbase_data: WireRange::default(),
                witnesses: vec![fixture_witness()],
            });
        }
    }
    ExplorerTxFacts {
        wire: vec![0],
        lock: 0,
        inputs,
    }
}
#[cfg(test)]
fn fixture_genesis(transactions: Vec<ConfirmedTx>) -> CommittedBlock {
    let anchor = Anchor {
        block_id: [2; 32],
        height: 0,
    };
    CommittedBlock {
        anchor,
        parent: anchor,
        explorer: fixture_header(anchor, anchor),
        transactions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            chain_id: [1; 32],
            genesis: [2; 32],
            profile: [3; 32],
        }
    }
    /// The consensus default block-size limit.
    fn bounds() -> Bounds {
        Bounds::new(32_000_000).unwrap()
    }
    fn output(root: u8, burn: bool) -> Output {
        Output {
            flags: if burn { 2 } else { 0 },
            value: 100,
            token_id: Hash32::default(),
            state_root: Hash32::default(),
            branches: vec![Hash32([root; 32])],
            paths: if burn { vec![] } else { vec![vec![0]] },
        }
    }
    fn block(
        parent: Anchor,
        id: u8,
        txid: u8,
        outputs: Vec<Output>,
        spends: Vec<OutPoint>,
    ) -> CommittedBlock {
        let anchor = Anchor {
            block_id: [id; 32],
            height: parent.height + 1,
        };
        let spends: Vec<_> = spends
            .into_iter()
            .enumerate()
            .map(|(i, outpoint)| SpentInput {
                outpoint,
                input_index: i as u32,
            })
            .collect();
        let explorer = fixture_facts(&spends, &outputs);
        CommittedBlock {
            anchor,
            parent,
            explorer: fixture_header(anchor, parent),
            transactions: vec![ConfirmedTx {
                pos: crate::v2_branch::TxPos::default(),
                location: TxLocation {
                    block_id: Hash32(anchor.block_id),
                    height: anchor.height,
                    tx_index: 0,
                    txid: TxId(Hash32([txid; 32])),
                    txhash: TxHash(Hash32([txid + 1; 32])),
                },
                outputs,
                spends,
                explorer,
            }],
        }
    }
    fn op(txid: u8, index: u32) -> OutPoint {
        OutPoint {
            txid: TxId(Hash32([txid; 32])),
            out_idx: index,
        }
    }
    #[test]
    fn schema4_complete_facts_atomic_replay_and_tamper() {
        use crate::{v2_asset as a, v2_explorer as e};
        let dir = tempdir::TempDir::new("v2-schema4").unwrap();
        let mem = Arc::new(MemTxSource::default());
        let mut db =
            V2Db::open_recording(dir.path(), binding(), bounds(), mem.clone())
                .unwrap();
        db.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let genesis = db.checkpoint().unwrap().unwrap();
        let mut token = output(5, false);
        token.flags = 1;
        token.token_id = Hash32([77; 32]);
        let baseline = db.db.dump_all().unwrap();
        let mut first = block(genesis, 10, 20, vec![token.clone()], vec![]);
        first.transactions[0].explorer.wire = vec![0; 65537];
        db.connect(&first).unwrap();
        let second = block(first.anchor, 11, 22, vec![], vec![op(20, 0)]);
        db.connect(&second).unwrap();
        db.connect(&second).unwrap(); // frozen inputs must survive exact replay
        let view = db.snapshot().unwrap();
        assert_eq!(
            view.explorer_block_at_height(2).unwrap().unwrap().anchor,
            second.anchor
        );
        assert_eq!(
            view.explorer_tx_by_hash(TxHash(Hash32([23; 32])))
                .unwrap()
                .unwrap()
                .location
                .txid,
            TxId(Hash32([22; 32]))
        );
        let input = view
            .explorer_input(TxId(Hash32([22; 32])), 0)
            .unwrap()
            .unwrap();
        assert_eq!(input.resolved_creation.unwrap().output, token);
        assert_eq!(
            view.asset_summary(Hash32([77; 32]))
                .unwrap()
                .unwrap()
                .event_count,
            2
        );
        drop(view);
        let input_key = e::input_key(TxId(Hash32([22; 32])), 0);
        let saved = db.db.get(&input_key).unwrap().unwrap();
        let mut corrupted: e::StoredInputMeta = e::decode_record(&saved).unwrap();
        corrupted.flags = 255;
        db.db
            .put(&input_key, e::encode_record(&corrupted).unwrap())
            .unwrap();
        assert!(db
            .snapshot()
            .unwrap()
            .explorer_input(TxId(Hash32([22; 32])), 0)
            .is_err());
        db.db.put(&input_key, &saved).unwrap();
        corrupted = e::decode_record(&saved).unwrap();
        corrupted.coinbase_data = e::WireRange {
            offset: u64::MAX,
            length: 1,
        };
        db.db
            .put(&input_key, e::encode_record(&corrupted).unwrap())
            .unwrap();
        assert!(db
            .snapshot()
            .unwrap()
            .explorer_input(TxId(Hash32([22; 32])), 0)
            .is_err());
        db.db.put(&input_key, saved).unwrap();
        let witness_key = e::witness_key(TxId(Hash32([20; 32])), 0, 0);
        let saved = db.db.get(&witness_key).unwrap().unwrap();
        let mut corrupted: e::WitnessFact = e::decode_record(&saved).unwrap();
        corrupted.script = e::WireRange {
            offset: 65537,
            length: 1,
        };
        db.db
            .put(&witness_key, e::encode_record(&corrupted).unwrap())
            .unwrap();
        assert!(db
            .snapshot()
            .unwrap()
            .explorer_witness(TxId(Hash32([20; 32])), 0, 0)
            .is_err());
        db.db.put(&witness_key, saved).unwrap();
        let block_key = e::block_key(Hash32(second.anchor.block_id));
        let saved = db.db.get(&block_key).unwrap().unwrap();
        let mut corrupted: e::BlockMeta = e::decode_record(&saved).unwrap();
        corrupted.header_wire[0] ^= 1;
        db.db
            .put(&block_key, e::encode_record(&corrupted).unwrap())
            .unwrap();
        assert!(db
            .snapshot()
            .unwrap()
            .explorer_block(Hash32(second.anchor.block_id))
            .is_err());
        db.db.put(&block_key, saved).unwrap();
        let record_key = key(b'o', &op_bytes(op(20, 0)));
        let saved = db.db.get(&record_key).unwrap().unwrap();
        let mut corrupted: Coin = decode(&saved).unwrap();
        corrupted.spend.as_mut().unwrap().0[0] ^= 1;
        db.db.put(&record_key, encode(&corrupted).unwrap()).unwrap();
        assert!(db.snapshot().unwrap().output(op(20, 0)).is_err());
        corrupted = decode(&saved).unwrap();
        corrupted.value += 1;
        db.db.put(&record_key, encode(&corrupted).unwrap()).unwrap();
        assert!(db.snapshot().unwrap().output(op(20, 0)).is_err());
        db.db.put(&record_key, saved).unwrap();
        let summary_key = a::asset_summary_key(Hash32([77; 32]));
        let saved = db.db.get(&summary_key).unwrap().unwrap();
        let mut corrupted = a::decode_asset_summary(&saved).unwrap();
        corrupted.first_seen.txhash = TxHash(Hash32([88; 32]));
        db.db
            .put(&summary_key, a::encode_asset_summary(&corrupted).unwrap())
            .unwrap();
        assert!(db
            .snapshot()
            .unwrap()
            .asset_summary(Hash32([77; 32]))
            .is_err());
        db.db.put(&summary_key, saved).unwrap();
        let event_key = a::asset_event_key(
            Hash32([77; 32]),
            second.transactions[0].location,
        );
        let saved = db.db.get(&event_key).unwrap().unwrap();
        let mut corrupted: a::AssetEvent = e::decode_record(&saved).unwrap();
        corrupted.location.block_id = Hash32([88; 32]);
        db.db
            .put(&event_key, e::encode_record(&corrupted).unwrap())
            .unwrap();
        let previous = a::asset_event_key(
            Hash32([77; 32]),
            first.transactions[0].location,
        );
        assert!(db
            .snapshot()
            .unwrap()
            .next_asset_event(Hash32([77; 32]), Some(&previous))
            .is_err());
        db.db.put(&event_key, saved).unwrap();
        let mut conflicting = second.clone();
        conflicting.transactions[0].explorer.wire.push(1);
        assert!(db.connect(&conflicting).is_err());
        // The node's bytes no longer match the recorded wire checksum: reads
        // and the undo check fail closed.
        assert!(mem.modify(TxId(Hash32([22; 32])), |tx| tx.explorer.wire[0] ^= 1));
        assert!(db
            .snapshot()
            .unwrap()
            .explorer_wire_slice(TxId(Hash32([22; 32])), 0, 1)
            .is_err());
        assert!(db.disconnect(second.anchor).is_err());
        assert_eq!(db.checkpoint().unwrap(), Some(second.anchor));
        assert!(mem.modify(TxId(Hash32([22; 32])), |tx| tx.explorer.wire[0] ^= 1));
        db.disconnect(second.anchor).unwrap();
        assert!(db
            .snapshot()
            .unwrap()
            .explorer_tx(TxId(Hash32([22; 32])))
            .unwrap()
            .is_none());
        assert!(db
            .db
            .get(a::asset_event_key(
                Hash32([77; 32]),
                second.transactions[0].location
            ))
            .unwrap()
            .is_none());
        assert_eq!(
            db.snapshot()
                .unwrap()
                .asset_summary(Hash32([77; 32]))
                .unwrap()
                .unwrap()
                .event_count,
            1
        );
        db.connect(&second).unwrap();
        db.disconnect(second.anchor).unwrap();
        db.disconnect(first.anchor).unwrap();
        assert!(db
            .snapshot()
            .unwrap()
            .asset_summary(Hash32([77; 32]))
            .unwrap()
            .is_none());
        let after: Vec<_> = db
            .db
            .dump_all()
            .unwrap()
            .into_iter()
            .filter(|(k, _)| k.as_slice() != b"disconnected")
            .collect();
        assert_eq!(after, baseline); // every e-family, receipt and undo restored exactly

        drop(db);
        // An index of an older schema is refused with a reindex instruction,
        // never read with this build's layouts.
        for old in [2u32, 3] {
            let raw = MdbxEnv::open(dir.path()).unwrap();
            raw.put(b"v2-binding", encode(&(old, binding())).unwrap())
                .unwrap();
            drop(raw);
            let err = V2Db::open(dir.path(), binding(), bounds())
                .err()
                .unwrap();
            assert!(matches!(
                err,
                Error::Schema { found, expected: SCHEMA_VERSION } if found == old
            ));
            assert!(err.to_string().contains("-chronikreindex"));
        }
    }
    #[test]
    fn restart_inverse_burns_and_replay() {
        let dir = tempdir::TempDir::new("v2-index").unwrap();
        // The node's block files outlive a restart: share one source.
        let mem = Arc::new(MemTxSource::default());
        let mut db =
            V2Db::open_recording(dir.path(), binding(), bounds(), mem.clone())
                .unwrap();
        db.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let genesis = db.snapshot().unwrap().anchor;
        let first = block(
            genesis,
            10,
            20,
            vec![output(5, false), output(6, true)],
            vec![],
        );
        db.connect(&first).unwrap();
        db.connect(&first).unwrap();
        let before = db.snapshot().unwrap();
        let original = before.output(op(20, 0)).unwrap().unwrap();
        assert!(before.utxo(op(20, 0)).unwrap().is_some());
        assert!(before.utxo(op(20, 1)).unwrap().is_none());
        assert_eq!(
            before.next_posting(Hash32([6; 32]), None, None).unwrap(),
            Some(op(20, 1))
        );
        let second = block(
            first.anchor,
            11,
            22,
            vec![output(7, false)],
            vec![op(20, 0)],
        );
        drop(before);
        db.connect(&second).unwrap();
        let anchored = db.snapshot().unwrap();
        let spent = anchored.output(op(20, 0)).unwrap().unwrap();
        assert!(anchored.utxo(op(20, 0)).unwrap().is_none());
        assert_eq!(
            spent.spend.unwrap().transaction.txid,
            TxId(Hash32([22; 32]))
        );
        assert_eq!(
            anchored
                .next_posting(Hash32([5; 32]), Some(0), None)
                .unwrap(),
            Some(op(20, 0))
        );
        // Existing read snapshots remain coherent across disconnect.
        drop(anchored);
        drop(db);
        let mut db =
            V2Db::open_recording(dir.path(), binding(), bounds(), mem.clone())
                .unwrap();
        assert_eq!(db.snapshot().unwrap().anchor, second.anchor);
        db.connect(&second).unwrap();
        db.disconnect(second.anchor).unwrap();
        db.disconnect(second.anchor).unwrap();
        assert_eq!(
            db.snapshot().unwrap().output(op(20, 0)).unwrap(),
            Some(original)
        );
        assert!(db.snapshot().unwrap().output(op(22, 0)).unwrap().is_none());
        db.connect(&second).unwrap();
        db.disconnect(second.anchor).unwrap();
        db.disconnect(first.anchor).unwrap();
        assert_eq!(db.snapshot().unwrap().anchor, genesis);
        assert!(db
            .snapshot()
            .unwrap()
            .next_posting(Hash32([6; 32]), None, None)
            .unwrap()
            .is_none());
        drop(db);
        assert!(matches!(
            V2Db::open(
                dir.path(),
                Binding {
                    profile: [4; 32],
                    ..binding()
                },
                bounds(),
            ),
            Err(Error::Invalid("binding/schema mismatch"))
        ));
    }
    #[test]
    fn explicit_genesis_history_and_coins() {
        let dir = tempdir::TempDir::new("v2-genesis").unwrap();
        let mut db = V2Db::open(dir.path(), binding(), bounds()).unwrap();
        assert_eq!(db.checkpoint().unwrap(), None);
        assert!(db.snapshot().is_err());
        let genesis = Anchor {
            block_id: binding().genesis,
            height: 0,
        };
        let mut tx = block(
            genesis,
            10,
            20,
            vec![output(5, false), output(6, true)],
            vec![],
        )
        .transactions
        .remove(0);
        let wrong = tx.clone();
        assert!(db.initialize_genesis(fixture_genesis(vec![wrong])).is_err());
        assert_eq!(db.checkpoint().unwrap(), None);
        tx.location.block_id = Hash32(binding().genesis);
        tx.location.height = 0;
        db.initialize_genesis(fixture_genesis(vec![tx.clone()]))
            .unwrap();
        db.initialize_genesis(fixture_genesis(vec![tx])).unwrap();
        assert_eq!(
            db.snapshot()
                .unwrap()
                .next_posting(Hash32([6; 32]), None, None)
                .unwrap(),
            Some(op(20, 1))
        );
        assert!(db.snapshot().unwrap().utxo(op(20, 1)).unwrap().is_none());
        let child = block(genesis, 11, 22, vec![], vec![op(20, 0)]);
        db.connect(&child).unwrap();
        db.disconnect(child.anchor).unwrap();
        assert!(db.snapshot().unwrap().utxo(op(20, 0)).unwrap().is_some());
        assert!(db.disconnect(genesis).is_err());
        drop(db);
        assert_eq!(
            V2Db::open(dir.path(), binding(), bounds())
                .unwrap()
                .checkpoint()
                .unwrap(),
            Some(genesis)
        );
    }
    #[test]
    fn early_capacity_and_corrupt_storage_fail_closed() {
        let dir = tempdir::TempDir::new("v2-capacity").unwrap();
        let mut db = V2Db::open(dir.path(), binding(), bounds()).unwrap();
        db.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let genesis = db.checkpoint().unwrap().unwrap();
        let wide = Output {
            branches: (0..16).map(|i| Hash32([i; 32])).collect(),
            paths: vec![vec![0]],
            ..output(5, false)
        };
        // 2000 sixteen-branch outputs need more than a 32 KB block.
        let small_dir = tempdir::TempDir::new("v2-capacity-small").unwrap();
        let mut small = V2Db::open(
            small_dir.path(),
            binding(),
            Bounds::new(32_768).unwrap(),
        )
        .unwrap();
        small.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let oversized = block(genesis, 10, 20, vec![wide; 2000], vec![]);
        assert!(matches!(
            small.connect(&oversized),
            Err(Error::Invalid("staging capacity"))
        ));
        assert_eq!(small.checkpoint().unwrap(), Some(genesis));
        db.connect(&oversized).unwrap();
        db.disconnect(oversized.anchor).unwrap();
        assert_eq!(db.checkpoint().unwrap(), Some(genesis));
        let first = block(genesis, 10, 20, vec![output(5, false)], vec![]);
        db.connect(&first).unwrap();
        let record_key = key(b'o', &op_bytes(op(20, 0)));
        let original = db.db.get(&record_key).unwrap().unwrap();
        db.db
            .put(&record_key, vec![0; MAX_RECORD_BYTES + 1])
            .unwrap();
        assert!(matches!(
            db.snapshot().unwrap().output(op(20, 0)),
            Err(Error::Corrupt)
        ));
        db.db.put(record_key, original).unwrap();
        let undo_key = key(b'u', &first.anchor.block_id);
        let original_undo = db.db.get(&undo_key).unwrap().unwrap();
        let mut undo: Undo = decode(&original_undo).unwrap();
        undo.entries
            .push((b"tip".to_vec(), Some(encode(&genesis).unwrap())));
        db.db.put(&undo_key, encode(&undo).unwrap()).unwrap();
        assert!(matches!(db.disconnect(first.anchor), Err(Error::Corrupt)));
        assert_eq!(db.checkpoint().unwrap(), Some(first.anchor));
        let mut undo: Undo = decode(&original_undo).unwrap();
        undo.binding.profile = [99; 32];
        db.db.put(&undo_key, encode(&undo).unwrap()).unwrap();
        assert!(matches!(db.disconnect(first.anchor), Err(Error::Corrupt)));
        db.db.put(&undo_key, original_undo).unwrap();
        db.disconnect(first.anchor).unwrap();
    }
    #[test]
    fn complete_token_policy_and_sixteen_positions() {
        let dir = tempdir::TempDir::new("v2-policy").unwrap();
        let mut db = V2Db::open(dir.path(), binding(), bounds()).unwrap();
        db.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let genesis = db.snapshot().unwrap().anchor;
        let policy = Output {
            flags: 1,
            value: u64::MAX,
            token_id: Hash32([77; 32]),
            state_root: Hash32::default(),
            branches: (0..16).map(|i| Hash32([i; 32])).collect(),
            paths: vec![(0..16).collect()],
        };
        let first = block(genesis, 10, 20, vec![policy.clone()], vec![]);
        db.connect(&first).unwrap();
        for position in 0..16 {
            assert_eq!(
                db.snapshot()
                    .unwrap()
                    .next_posting(Hash32([position; 32]), Some(position), None)
                    .unwrap(),
                Some(op(20, 0))
            );
        }
        let second = block(first.anchor, 11, 22, vec![], vec![op(20, 0)]);
        db.connect(&second).unwrap();
        db.disconnect(second.anchor).unwrap();
        let restored =
            db.snapshot().unwrap().output(op(20, 0)).unwrap().unwrap();
        assert_eq!(restored.output, policy);
        assert!(restored.spend.is_none());
    }
    #[test]
    fn invalid_transitions_leave_checkpoint_unchanged() {
        let dir = tempdir::TempDir::new("v2-invalid").unwrap();
        let mut db = V2Db::open(dir.path(), binding(), bounds()).unwrap();
        db.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let genesis = db.snapshot().unwrap().anchor;
        let first = block(
            genesis,
            10,
            20,
            vec![output(5, false), output(6, true)],
            vec![],
        );
        db.connect(&first).unwrap();
        for inputs in
            [vec![op(20, 0), op(20, 0)], vec![op(20, 1)], vec![op(99, 0)]]
        {
            assert!(db
                .connect(&block(first.anchor, 11, 22, vec![], inputs))
                .is_err());
            assert_eq!(db.snapshot().unwrap().anchor, first.anchor);
            assert!(db
                .snapshot()
                .unwrap()
                .output(op(20, 0))
                .unwrap()
                .unwrap()
                .spend
                .is_none());
        }
        let mut malformed = block(first.anchor, 11, 22, vec![], vec![]);
        malformed.transactions[0].location.block_id = Hash32([99; 32]);
        assert!(db.connect(&malformed).is_err());
        let mut replay = first.clone();
        replay.transactions[0].outputs[0].value = 101;
        assert!(db.connect(&replay).is_err());
        let duplicate = block(first.anchor, 11, 20, vec![], vec![]);
        assert!(db.connect(&duplicate).is_err());
        // More transactions than a block within the size limit can hold.
        let small_dir = tempdir::TempDir::new("v2-small").unwrap();
        let small_bounds = Bounds::new(4 * MIN_TX_WIRE_BYTES as u64).unwrap();
        let mut small =
            V2Db::open(small_dir.path(), binding(), small_bounds).unwrap();
        small.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let mut overflow = block(genesis, 11, 22, vec![], vec![]);
        overflow.transactions = vec![
            overflow.transactions[0].clone();
            small_bounds.transactions() + 1
        ];
        assert!(matches!(
            small.connect(&overflow),
            Err(Error::Invalid("transaction bound"))
        ));
        assert!(db
            .snapshot()
            .unwrap()
            .next_posting(Hash32([5; 32]), Some(16), None)
            .is_err());
    }
    #[test]
    fn intra_block_spend_and_snapshot_isolation() {
        let dir = tempdir::TempDir::new("v2-intra").unwrap();
        let mut db = V2Db::open(dir.path(), binding(), bounds()).unwrap();
        db.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let genesis = db.snapshot().unwrap().anchor;
        let mut first = block(genesis, 10, 20, vec![output(5, false)], vec![]);
        let mut child = first.transactions[0].clone();
        child.location.tx_index = 1;
        child.location.txid = TxId(Hash32([22; 32]));
        child.location.txhash = TxHash(Hash32([23; 32]));
        child.spends = vec![SpentInput {
            outpoint: op(20, 0),
            input_index: 3,
        }];
        child.explorer = fixture_facts(&child.spends, &child.outputs);
        first.transactions.push(child);
        db.connect(&first).unwrap();
        assert_eq!(
            db.snapshot()
                .unwrap()
                .output(op(20, 0))
                .unwrap()
                .unwrap()
                .spend
                .unwrap()
                .input_index,
            3
        );
        let snapshot = db.snapshot().unwrap();
        assert_eq!(
            snapshot
                .next_posting(Hash32([5; 32]), None, Some(op(20, 0)))
                .unwrap(),
            Some(op(22, 0))
        );
        assert!(snapshot
            .next_posting(Hash32([5; 32]), None, Some(op(22, 0)))
            .unwrap()
            .is_none());
        drop(snapshot);
        db.disconnect(first.anchor).unwrap();
        assert!(db.snapshot().unwrap().output(op(20, 0)).unwrap().is_none());
        assert!(db.snapshot().unwrap().output(op(22, 0)).unwrap().is_none());
    }
    /// The staging reserved for any element, charged to its shortest wire
    /// encoding, stays within STAGING_PER_WIRE_BYTE: a block within the
    /// consensus size limit always fits `Bounds::batch_bytes`.
    #[test]
    fn staging_covers_shortest_encodings() {
        use crate::v2_explorer as e;
        // Charged to every wire byte: explorer entries and started chunks.
        let per_byte = e::RESERVE_PER_WIRE_BYTE
            + e::RESERVE_CHUNK.div_ceil(e::WIRE_CHUNK_BYTES);
        let budget = STAGING_PER_WIRE_BYTE - per_byte;
        let tx = RESERVE_TX + e::RESERVE_TX + e::RESERVE_CHUNK;
        assert!(tx <= budget * MIN_TX_HEADER_WIRE_BYTES);
        // A spend is an input, a spend and an asset element twice.
        let spend =
            2 * RESERVE_ASSET_ELEMENT + RESERVE_SPEND + e::RESERVE_INPUT;
        assert!(spend <= budget * MIN_SPEND_WIRE_BYTES);
        let input = RESERVE_ASSET_ELEMENT + e::RESERVE_INPUT;
        assert!(input <= budget * MIN_INPUT_WIRE_BYTES);
        assert!(e::RESERVE_WITNESS <= budget * MIN_WITNESS_WIRE_BYTES);
        // The shortest output has one branch; each further one is 32 bytes.
        let output = RESERVE_ASSET_ELEMENT + RESERVE_OUTPUT + RESERVE_BRANCH;
        assert!(output <= budget * MIN_OUTPUT_WIRE_BYTES);
        assert!(RESERVE_BRANCH <= budget * 32);
        assert!(1024 + e::RESERVE_BLOCK <= STAGING_PER_BLOCK);
        let bounds = Bounds::new(32_000_000).unwrap();
        assert_eq!(bounds.transactions(), 32_000_000 / MIN_TX_WIRE_BYTES);
        assert_eq!(bounds.changes(), 32_000_000 / MIN_INPUT_WIRE_BYTES);
        assert!(Bounds::new(0).is_err());
        assert!(Bounds::new(Bounds::MAX_BLOCK_BYTES + 1).is_err());
    }
    /// A block over the former fixed bounds (4096 transactions, 32 MiB of
    /// staging) but within the consensus size limit is indexed and undone.
    #[test]
    fn block_over_former_fixed_bounds_is_indexed() {
        const TXS: u32 = 4100;
        let dir = tempdir::TempDir::new("v2-large").unwrap();
        let mut db = V2Db::open(dir.path(), binding(), bounds()).unwrap();
        db.initialize_genesis(fixture_genesis(vec![])).unwrap();
        let genesis = db.checkpoint().unwrap().unwrap();
        let fan = block(
            genesis,
            10,
            20,
            vec![output(5, false); TXS as usize],
            vec![],
        );
        db.connect(&fan).unwrap();
        let anchor = Anchor {
            block_id: [11; 32],
            height: 2,
        };
        // Each spends one fan output to one output: the shortest
        // encodings, as in a real block of this many transactions.
        let wire_len = MIN_TX_HEADER_WIRE_BYTES
            + MIN_SPEND_WIRE_BYTES
            + MIN_WITNESS_WIRE_BYTES
            + MIN_OUTPUT_WIRE_BYTES;
        let txid = |i: u32| {
            let mut id = [0x60; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            TxId(Hash32(id))
        };
        let transactions: Vec<_> = (0..TXS)
            .map(|i| {
                let spends = vec![SpentInput {
                    outpoint: op(20, i),
                    input_index: 0,
                }];
                let outputs = vec![output(6, false)];
                let mut explorer = fixture_facts(&spends, &outputs);
                explorer.wire = vec![0; wire_len];
                ConfirmedTx {
                    pos: crate::v2_branch::TxPos::default(),
                    location: TxLocation {
                        block_id: Hash32(anchor.block_id),
                        height: anchor.height,
                        tx_index: i,
                        txid: txid(i),
                        txhash: TxHash(Hash32({
                            let mut h = [0x61; 32];
                            h[..4].copy_from_slice(&i.to_be_bytes());
                            h
                        })),
                    },
                    outputs,
                    spends,
                    explorer,
                }
            })
            .collect();
        let large = CommittedBlock {
            anchor,
            parent: fan.anchor,
            explorer: fixture_header(anchor, fan.anchor),
            transactions,
        };
        // Over the former bounds by count and by reserved staging.
        assert!(large.transactions.len() > 4096);
        assert!(
            crate::v2_explorer::preflight_explorer_block(&large).unwrap()
                > 32 * 1024 * 1024
        );
        assert!(TXS as usize * wire_len <= bounds().block_bytes());
        db.connect(&large).unwrap();
        assert_eq!(db.checkpoint().unwrap(), Some(anchor));
        let snapshot = db.snapshot().unwrap();
        for i in [0, TXS / 2, TXS - 1] {
            let spent = snapshot.output(op(20, i)).unwrap().unwrap();
            assert_eq!(spent.spend.unwrap().transaction.txid, txid(i));
            let created = OutPoint {
                txid: txid(i),
                out_idx: 0,
            };
            assert!(snapshot.utxo(created).unwrap().is_some());
        }
        drop(snapshot);
        db.disconnect(anchor).unwrap();
        assert_eq!(db.checkpoint().unwrap(), Some(fan.anchor));
        assert!(db
            .snapshot()
            .unwrap()
            .output(op(20, TXS - 1))
            .unwrap()
            .unwrap()
            .spend
            .is_none());
    }
    /// Hosts may confirm blocks in canonical (txid) order, where a child
    /// precedes the in-block parent whose output it spends.
    #[test]
    fn canonical_order_block_spends_later_parents() {
        fn tx(
            anchor: Anchor,
            index: u32,
            txid: u8,
            outputs: Vec<Output>,
            spends: Vec<OutPoint>,
        ) -> ConfirmedTx {
            let spends: Vec<_> = spends
                .into_iter()
                .enumerate()
                .map(|(i, outpoint)| SpentInput {
                    outpoint,
                    input_index: i as u32,
                })
                .collect();
            ConfirmedTx {
                pos: crate::v2_branch::TxPos::default(),
                location: TxLocation {
                    block_id: Hash32(anchor.block_id),
                    height: anchor.height,
                    tx_index: index,
                    txid: TxId(Hash32([txid; 32])),
                    txhash: TxHash(Hash32([txid ^ 0xff; 32])),
                },
                explorer: fixture_facts(&spends, &outputs),
                outputs,
                spends,
            }
        }
        let mut token = output(5, false);
        token.flags = 1;
        token.token_id = Hash32([77; 32]);
        // 0x20 -> 0x30 -> 0x40 -> 0x21, carrying a token; 0x31 mints a
        // second token that 0x22 spends. Canonical order is 0x21, 0x22,
        // 0x30, 0x31, 0x40; the topological order is 0x30, 0x31, 0x22,
        // 0x40, 0x21.
        let connect = |canonical: bool| {
            let dir = tempdir::TempDir::new("v2-ctor").unwrap();
            let mut db = V2Db::open(dir.path(), binding(), bounds()).unwrap();
            db.initialize_genesis(fixture_genesis(vec![])).unwrap();
            let genesis = db.checkpoint().unwrap().unwrap();
            let first = block(genesis, 10, 0x20, vec![token.clone()], vec![]);
            db.connect(&first).unwrap();
            let anchor = Anchor {
                block_id: [11; 32],
                height: 2,
            };
            let mut minted = token.clone();
            minted.token_id = Hash32([78; 32]);
            let mut ids = vec![
                (0x30, token.clone(), Some(op(0x20, 0))),
                (0x31, minted.clone(), None),
                (0x22, minted.clone(), Some(op(0x31, 0))),
                (0x40, token.clone(), Some(op(0x30, 0))),
                (0x21, token.clone(), Some(op(0x40, 0))),
            ];
            if canonical {
                ids.sort_by_key(|(txid, _, _)| *txid);
            }
            let transactions = ids
                .into_iter()
                .enumerate()
                .map(|(i, (txid, out, spend))| {
                    tx(
                        anchor,
                        i as u32,
                        txid,
                        vec![out],
                        spend.into_iter().collect(),
                    )
                })
                .collect();
            let second = CommittedBlock {
                anchor,
                parent: first.anchor,
                explorer: fixture_header(anchor, first.anchor),
                transactions,
            };
            db.connect(&second).unwrap();
            db.connect(&second).unwrap(); // exact replay is a no-op
            (dir, db, second)
        };
        let (_topo_dir, topo, _) = connect(false);
        let (_dir, mut db, second) = connect(true);
        assert_eq!(
            second.transactions[0].location.txid,
            TxId(Hash32([0x21; 32]))
        );
        let view = db.snapshot().unwrap();
        for (parent, child) in
            [(0x20, 0x30), (0x30, 0x40), (0x40, 0x21), (0x31, 0x22)]
        {
            let spend = view.output(op(parent, 0)).unwrap().unwrap().spend;
            assert_eq!(
                spend.unwrap().transaction.txid,
                TxId(Hash32([child; 32]))
            );
        }
        assert!(view.output(op(0x21, 0)).unwrap().unwrap().spend.is_none());
        let input = view
            .explorer_input(TxId(Hash32([0x21; 32])), 0)
            .unwrap()
            .unwrap();
        assert_eq!(input.resolved_creation.unwrap().outpoint, op(0x40, 0));
        let topo_view = topo.snapshot().unwrap();
        for token_id in [77, 78] {
            let summary =
                view.asset_summary(Hash32([token_id; 32])).unwrap().unwrap();
            let expected = topo_view
                .asset_summary(Hash32([token_id; 32]))
                .unwrap()
                .unwrap();
            assert_eq!(summary.event_count, expected.event_count);
            assert_eq!(summary.output_count, expected.output_count);
        }
        // The mint stays the first seen location, after its spender.
        let minted = view.asset_summary(Hash32([78; 32])).unwrap().unwrap();
        assert_eq!(minted.first_seen.txid, TxId(Hash32([0x31; 32])));
        assert_eq!(minted.first_seen.tx_index, 3);
        let input = view
            .explorer_input(TxId(Hash32([0x22; 32])), 0)
            .unwrap()
            .unwrap();
        assert_eq!(input.resolved_creation.unwrap().outpoint, op(0x31, 0));
        drop(view);
        db.disconnect(second.anchor).unwrap();
        let view = db.snapshot().unwrap();
        assert!(view.output(op(0x20, 0)).unwrap().unwrap().spend.is_none());
        for txid in [0x21, 0x22, 0x30, 0x31, 0x40] {
            assert!(view.output(op(txid, 0)).unwrap().is_none());
        }
        drop(view);
        db.connect(&second).unwrap();

        // A dependency cycle cannot be resolved.
        let anchor = Anchor {
            block_id: [12; 32],
            height: 3,
        };
        let cycle = CommittedBlock {
            anchor,
            parent: second.anchor,
            explorer: fixture_header(anchor, second.anchor),
            transactions: vec![
                tx(anchor, 0, 0x50, vec![output(6, false)], vec![op(0x51, 0)]),
                tx(anchor, 1, 0x51, vec![output(6, false)], vec![op(0x50, 0)]),
            ],
        };
        assert_eq!(
            db.connect(&cycle).unwrap_err().to_string(),
            "invalid V2 index transition: missing coin"
        );
        assert_eq!(db.checkpoint().unwrap(), Some(second.anchor));
    }
}

#[cfg(test)]
mod crash_tests {
    use super::*;
    #[test]
    fn durable_checkpoint_without_clean_shutdown() {
        const ENV: &str = "LOTUS_V2_DB_CRASH_TEST_PATH";
        let binding = Binding {
            chain_id: [1; 32],
            genesis: [2; 32],
            profile: [3; 32],
        };
        let parent = Anchor {
            block_id: binding.genesis,
            height: 0,
        };
        let block = CommittedBlock {
            anchor: Anchor {
                block_id: [8; 32],
                height: 1,
            },
            parent,
            explorer: fixture_header(
                Anchor {
                    block_id: [8; 32],
                    height: 1,
                },
                parent,
            ),
            transactions: vec![],
        };
        if let Some(path) = std::env::var_os(ENV) {
            let mut db =
                V2Db::open(path, binding, Bounds::new(32_000_000).unwrap())
                    .unwrap();
            db.initialize_genesis(fixture_genesis(vec![])).unwrap();
            db.connect(&block).unwrap();
            // Bypass Rust destructors: durability must come from the synced WAL.
            std::process::exit(77);
        }
        let dir = tempdir::TempDir::new("v2-durable").unwrap();
        let status = std::process::Command::new(
            std::env::current_exe().unwrap(),
        )
        .args([
            "--exact",
            "v2_branch::crash_tests::durable_checkpoint_without_clean_shutdown",
        ])
        .env(ENV, dir.path())
        .status()
        .unwrap();
        assert_eq!(status.code(), Some(77));
        let mut db =
            V2Db::open(dir.path(), binding, Bounds::new(32_000_000).unwrap())
                .unwrap();
        assert_eq!(db.snapshot().unwrap().anchor, block.anchor);
        db.connect(&block).unwrap();
        db.disconnect(block.anchor).unwrap();
        assert_eq!(db.snapshot().unwrap().anchor, parent);
    }
}

impl std::fmt::Debug for V2Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2Db")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ReadSnapshot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadSnapshot")
            .field("anchor", &self.anchor)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}
