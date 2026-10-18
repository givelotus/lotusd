//! Bounded explorer queries over the owner's one immutable read snapshot.
//! Authority, restart-safe cursor binding and capped JSON encoding belong to HTTP.
use bitcoinsuite_core::lotus_v2::{
    Hash32, OutPoint, OutputRecord, TxHash, TxId,
};
use chronik_db::{
    v2_branch::{Error, ReadSnapshot},
    v2_explorer::{
        BlockMeta, InputMeta, TxMeta, WitnessFact, WIRE_CHUNK_BYTES,
    },
};

type Result<T> = std::result::Result<T, Error>;
/// New-schema page/work limits.
pub const MAX_PAGE_SIZE: usize = 100;
/// Maximum records examined in one page (point-indexed pages examine <= 100).
pub const MAX_EXAMINED: usize = 1024;
/// Maximum key reads reserved before querying.
pub const MAX_KEY_READS: usize = 4096;
/// Logical result cap, leaving room for decimal/hex JSON expansion.
pub const MAX_PAGE_BYTES: usize = 96 * 1024;

// Physical read ceilings with shared canonical joins: transaction = eT + t/eH
// + eB/eH/parent-eH + eO = 7; historical output = o + creation t/eH
// + optional spender t/eH = 5; input = transaction7 + eI1 + witness
// endpoints2 + output5 + creation transaction7 = 22; witness = input22
// + eW1 + transaction7 + up to four wire-chunk reads = 34. Reserve every
// initial parent lookup too. Even a 100-item witness page reserves only 3429.
/// Read-only seam for pinned production snapshots and independent fixture tests.
pub trait ExplorerSource {
    /// Read validated metadata for a native block identity.
    fn block(&self, id: Hash32) -> Result<Option<BlockMeta>>;
    /// Read block metadata joined to its canonical height.
    fn block_at_height(&self, height: u64) -> Result<Option<BlockMeta>>;
    /// Read validated metadata for a structural transaction ID.
    fn transaction(&self, id: TxId) -> Result<Option<TxMeta>>;
    /// Resolve a wire transaction hash to validated metadata.
    fn transaction_by_hash(&self, hash: TxHash) -> Result<Option<TxMeta>>;
    /// Read both transaction identities at a block ordinal.
    fn block_transaction(
        &self,
        block: Hash32,
        index: u32,
    ) -> Result<Option<(TxId, TxHash)>>;
    /// Read an input descriptor joined to its resolved creation.
    fn input(&self, id: TxId, index: u32) -> Result<Option<InputMeta>>;
    /// Read a bounded witness descriptor at an input ordinal.
    fn witness(
        &self,
        id: TxId,
        input: u32,
        index: u32,
    ) -> Result<Option<WitnessFact>>;
    /// Read an indexed output with its creation and optional spend.
    fn output(&self, op: OutPoint) -> Result<Option<OutputRecord>>;
    /// Read one bounded wire chunk from the recorded transaction.
    fn wire(&self, id: TxId, chunk: u32) -> Result<Option<Vec<u8>>>;
}
impl ExplorerSource for ReadSnapshot<'_> {
    fn block(&self, id: Hash32) -> Result<Option<BlockMeta>> {
        self.explorer_block(id)
    }
    fn block_at_height(&self, h: u64) -> Result<Option<BlockMeta>> {
        self.explorer_block_at_height(h)
    }
    fn transaction(&self, id: TxId) -> Result<Option<TxMeta>> {
        self.explorer_tx(id)
    }
    fn transaction_by_hash(&self, h: TxHash) -> Result<Option<TxMeta>> {
        self.explorer_tx_by_hash(h)
    }
    fn block_transaction(
        &self,
        b: Hash32,
        i: u32,
    ) -> Result<Option<(TxId, TxHash)>> {
        self.explorer_block_tx(b, i)
    }
    fn input(&self, id: TxId, i: u32) -> Result<Option<InputMeta>> {
        self.explorer_input(id, i)
    }
    fn witness(&self, id: TxId, i: u32, w: u32) -> Result<Option<WitnessFact>> {
        self.explorer_witness(id, i, w)
    }
    fn output(&self, op: OutPoint) -> Result<Option<OutputRecord>> {
        ReadSnapshot::output(self, op)
    }
    fn wire(&self, id: TxId, c: u32) -> Result<Option<Vec<u8>>> {
        self.explorer_wire_chunk(id, c)
    }
}
/// Typed continuation is exclusive. HTTP binds it to route/filter/snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    /// Complete records in the requested canonical order.
    pub items: Vec<T>,
    /// Exclusive ordinal continuation, or None at exhaustion.
    pub next_index: Option<u64>,
    /// Whether this snapshot has no further records for the query.
    pub exhausted: bool,
    /// Number of index records examined to produce this page.
    pub examined: usize,
    /// Physical key-read reservation, including all canonical and frozen-coin joins.
    /// Optional/missing records can consume fewer reads than this ceiling.
    pub key_reads: usize,
}
/// Exact byte chunk, at most 32768 bytes without reading the full frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireChunk {
    /// Structural transaction identity for these exact wire bytes.
    pub txid: TxId,
    /// Hash of the exact serialized transaction.
    pub txhash: TxHash,
    /// Length of the full serialized transaction in bytes.
    pub total_bytes: u64,
    /// Zero-based byte offset of this chunk in the transaction.
    pub offset: u64,
    /// Exact bounded wire bytes returned for this chunk.
    pub bytes: Vec<u8>,
    /// Next byte offset, or None at the end of the transaction.
    pub next_offset: Option<u64>,
}
/// Integer encoding for every new JSON integer, including u64::MAX.
pub fn unsigned_decimal(value: impl Into<u128>) -> String {
    value.into().to_string()
}
/// Confirmations only after canonical membership has been proven by the source.
pub fn confirmations(tip_height: u64, creation_height: u64) -> Result<u64> {
    tip_height
        .checked_sub(creation_height)
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::Invalid("confirmation arithmetic"))
}
fn page_size(size: usize) -> Result<()> {
    if size == 0 || size > MAX_PAGE_SIZE {
        return Err(Error::Invalid("explorer page limits"));
    }
    Ok(())
}
fn required<T>(item: Option<T>) -> Result<T> {
    item.ok_or(Error::Corrupt)
}
fn ordinal_page<T>(
    count: u32,
    after: Option<u64>,
    size: usize,
    initial_reads: usize,
    reads_per_item: usize,
    mut load: impl FnMut(u32) -> Result<(T, usize)>,
) -> Result<Page<T>> {
    page_size(size)?;
    if after.is_some_and(|i| i >= u64::from(count)) {
        return Err(Error::Invalid("explorer continuation ordinal"));
    }
    let start = match after {
        Some(i) => i + 1,
        None => 0,
    };
    let mut items = Vec::with_capacity(size.min(count as usize));
    let mut index = start;
    let mut bytes = 0usize;
    let mut examined = 0usize;
    while index < u64::from(count) && items.len() < size {
        // Reserve reads and examination before the storage call.
        if examined + 1 > MAX_EXAMINED
            || initial_reads + (examined + 1) * reads_per_item > MAX_KEY_READS
        {
            break;
        }
        examined += 1;
        let (item, record_bytes) = load(index as u32)?;
        if record_bytes > MAX_PAGE_BYTES {
            return Err(Error::Invalid("explorer record limit"));
        }
        if bytes
            .checked_add(record_bytes)
            .map_or(true, |n| n > MAX_PAGE_BYTES)
        {
            if items.is_empty() {
                return Err(Error::Invalid("explorer record limit"));
            }
            break;
        }
        bytes += record_bytes;
        items.push(item);
        index += 1;
    }
    let exhausted = index == u64::from(count);
    Ok(Page {
        items,
        next_index: if exhausted {
            None
        } else {
            Some(index.checked_sub(1).ok_or(Error::Corrupt)?)
        },
        exhausted,
        examined,
        key_reads: initial_reads + examined * reads_per_item,
    })
}
/// Descending canonical blocks; before is exclusive (a cursor is another before).
pub fn blocks_page(
    source: &impl ExplorerSource,
    tip: u64,
    before: Option<u64>,
    size: usize,
) -> Result<Page<BlockMeta>> {
    page_size(size)?;
    let mut next = match before {
        Some(0) => None,
        Some(h) => Some((h - 1).min(tip)),
        None => Some(tip),
    };
    let mut items = Vec::with_capacity(size);
    while let Some(height) = next {
        if items.len() == size {
            break;
        }
        let block = required(source.block_at_height(height)?)?;
        if block.anchor.height != height {
            return Err(Error::Corrupt);
        }
        items.push(block);
        next = height.checked_sub(1);
    }
    let exhausted = next.is_none();
    let examined = items.len();
    Ok(Page {
        next_index: if exhausted {
            None
        } else {
            items.last().map(|b| b.anchor.height)
        },
        items,
        exhausted,
        examined,
        key_reads: examined * 4,
    })
}
/// Native block transaction order, with both typed identities.
pub fn block_transactions_page(
    source: &impl ExplorerSource,
    block: Hash32,
    after: Option<u64>,
    size: usize,
) -> Result<Option<Page<TxMeta>>> {
    page_size(size)?;
    let Some(meta) = source.block(block)? else {
        return Ok(None);
    };
    ordinal_page(meta.tx_count, after, size, 3, 8, |index| {
        let (id, hash) = required(source.block_transaction(block, index)?)?;
        let tx = required(source.transaction(id)?)?;
        if tx.location.txhash != hash
            || tx.location.block_id != block
            || tx.location.tx_index != index
            || tx.location.height != meta.anchor.height
        {
            return Err(Error::Corrupt);
        }
        Ok((tx, 256))
    })
    .map(Some)
}
/// Complete native input order, including non-spend ordinals.
pub fn inputs_page(
    source: &impl ExplorerSource,
    id: TxId,
    after: Option<u64>,
    size: usize,
) -> Result<Option<Page<InputMeta>>> {
    page_size(size)?;
    let Some(tx) = source.transaction(id)? else {
        return Ok(None);
    };
    ordinal_page(tx.input_count, after, size, 7, 22, |index| {
        let input = required(source.input(id, index)?)?;
        chronik_db::v2_explorer::validate_input_meta(&input, tx.wire_size)?;
        let bytes = 256
            + input.resolved_creation.as_ref().map_or(0, |coin| {
                812 + 128
                    + coin.output.paths.iter().map(Vec::len).sum::<usize>()
            });
        Ok((input, bytes))
    })
    .map(Some)
}
/// Every output, including burns and currently spent historical outputs.
pub fn outputs_page(
    source: &impl ExplorerSource,
    id: TxId,
    after: Option<u64>,
    size: usize,
) -> Result<Option<Page<OutputRecord>>> {
    page_size(size)?;
    let Some(tx) = source.transaction(id)? else {
        return Ok(None);
    };
    ordinal_page(tx.output_count, after, size, 7, 5, |index| {
        let output = required(source.output(OutPoint {
            txid: id,
            out_idx: index,
        })?)?;
        if output.creation != tx.location
            || output.outpoint
                != (OutPoint {
                    txid: id,
                    out_idx: index,
                })
        {
            return Err(Error::Corrupt);
        }
        Ok((output, 1200))
    })
    .map(Some)
}
/// Witness descriptors have no unbounded inline arguments/proof arrays.
pub fn witnesses_page(
    source: &impl ExplorerSource,
    id: TxId,
    input_index: u32,
    after: Option<u64>,
    size: usize,
) -> Result<Option<Page<WitnessFact>>> {
    page_size(size)?;
    let Some(tx) = source.transaction(id)? else {
        return Ok(None);
    };
    if input_index >= tx.input_count {
        return Ok(None);
    }
    let input = required(source.input(id, input_index)?)?;
    ordinal_page(input.witness_count, after, size, 29, 34, |index| {
        let witness = required(source.witness(id, input_index, index)?)?;
        chronik_db::v2_explorer::validate_witness_fact(&witness, tx.wire_size)?;
        Ok((witness, 128))
    })
    .map(Some)
}
/// Exact native frame bytes. Snapshot-token continuation checks belong to HTTP.
pub fn wire_chunk(
    source: &impl ExplorerSource,
    id: TxId,
    offset: u64,
    length: usize,
) -> Result<Option<WireChunk>> {
    if length == 0 || length > WIRE_CHUNK_BYTES {
        return Err(Error::Invalid("explorer wire limits"));
    }
    let Some(tx) = source.transaction(id)? else {
        return Ok(None);
    };
    if offset > tx.wire_size {
        return Err(Error::Invalid("explorer wire range"));
    }
    let remaining = tx.wire_size - offset;
    let wanted = remaining.min(length as u64) as usize;
    let mut bytes = Vec::with_capacity(wanted);
    let end = offset
        .checked_add(wanted as u64)
        .ok_or(Error::Invalid("explorer wire range"))?;
    let mut position = offset;
    while position < end {
        let index = u32::try_from(position / WIRE_CHUNK_BYTES as u64)
            .map_err(|_| Error::Corrupt)?;
        let chunk = required(source.wire(id, index)?)?;
        let chunk_start = u64::from(index) * WIRE_CHUNK_BYTES as u64;
        let expected =
            (tx.wire_size - chunk_start).min(WIRE_CHUNK_BYTES as u64) as usize;
        if chunk.len() != expected {
            return Err(Error::Corrupt);
        }
        let local = (position - chunk_start) as usize;
        let take = (expected - local).min((end - position) as usize);
        if take == 0 {
            return Err(Error::Corrupt);
        }
        bytes.extend_from_slice(&chunk[local..local + take]);
        position += take as u64;
    }
    Ok(Some(WireChunk {
        txid: id,
        txhash: tx.location.txhash,
        total_bytes: tx.wire_size,
        offset,
        bytes,
        next_offset: if end == tx.wire_size { None } else { Some(end) },
    }))
}

#[cfg(test)]
#[path = "v2_explorer_query_tests.rs"]
mod explorer_query_tests;
