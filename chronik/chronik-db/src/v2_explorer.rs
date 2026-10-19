//! Complete native explorer facts backed by `libmdbx` named subdatabases and
//! append-only flat segment files (`(file_num, data_pos, wire_size)` pointers).
//! Only the V2 DB owner commits these entries, together with its receipt,
//! checkpoint and undo.
use crate::v2_branch::{Anchor, CommittedBlock, Error, ReadSnapshot};
use bitcoinsuite_core::lotus_v2::{
    Hash32, OutPoint, Output, TxHash, TxId, TxLocation,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

type Result<T> = std::result::Result<T, Error>;
/// Maximum wire slice size per HTTP wire request (32 KiB).
pub const WIRE_CHUNK_BYTES: usize = 32768;
/// Native header length.
pub const HEADER_BYTES: usize = 134;
/// Maximum serialized individual metadata record.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
/// Explorer staging reserved once per block.
pub(crate) const RESERVE_BLOCK: usize = 4096;
/// Explorer staging reserved per wire byte (entries and flat-file staging).
pub(crate) const RESERVE_PER_WIRE_BYTE: usize = 6;
/// Explorer staging reserved per transaction.
pub(crate) const RESERVE_TX: usize = 4096;
/// Explorer staging reserved per input.
pub(crate) const RESERVE_INPUT: usize = 8192;
/// Explorer staging reserved per branch witness.
pub(crate) const RESERVE_WITNESS: usize = 2048;
/// Explorer staging reserved per started wire chunk.
pub(crate) const RESERVE_CHUNK: usize = 1024;

/// Serde adapters preserve native digest order and typed identities.
pub mod native_serde {
    use super::*;
    macro_rules! digest_adapter {
        ($name:ident,$ty:ty,$to:expr,$from:expr) => {
            /// Serde adapter preserving native digest byte order.
            pub mod $name {
                use super::*;
                /// Serialize the indexed value using its native field representation.
                pub fn serialize<S: serde::Serializer>(
                    v: &$ty,
                    s: S,
                ) -> std::result::Result<S::Ok, S::Error> {
                    ($to)(v).serialize(s)
                }
                /// Deserialize and validate the indexed field representation.
                pub fn deserialize<'de, D: serde::Deserializer<'de>>(
                    d: D,
                ) -> std::result::Result<$ty, D::Error> {
                    Ok(($from)(<[u8; 32]>::deserialize(d)?))
                }
            }
        };
    }
    digest_adapter!(hash, Hash32, |v: &Hash32| v.0, Hash32);
    digest_adapter!(txid, TxId, |v: &TxId| v.0 .0, |b| TxId(Hash32(b)));
    digest_adapter!(txhash, TxHash, |v: &TxHash| v.0 .0, |b| TxHash(Hash32(b)));
    /// Serde adapter for confirmed transaction positions and identities.
    pub mod location {
        use super::*;
        /// Serialize the indexed value using its native field representation.
        pub fn serialize<S: serde::Serializer>(
            v: &TxLocation,
            s: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            (
                v.block_id.0,
                v.height,
                v.tx_index,
                v.txid.0 .0,
                v.txhash.0 .0,
            )
                .serialize(s)
        }
        /// Deserialize and validate the indexed field representation.
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> std::result::Result<TxLocation, D::Error> {
            let (block_id, height, tx_index, txid, txhash) =
                Deserialize::deserialize(d)?;
            Ok(TxLocation {
                block_id: Hash32(block_id),
                height,
                tx_index,
                txid: TxId(Hash32(txid)),
                txhash: TxHash(Hash32(txhash)),
            })
        }
    }
    /// Serde adapter for structural transaction IDs and output indexes.
    pub mod outpoint {
        use super::*;
        /// Serialize the indexed value using its native field representation.
        pub fn serialize<S: serde::Serializer>(
            v: &OutPoint,
            s: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            (v.txid.0 .0, v.out_idx).serialize(s)
        }
        /// Deserialize and validate the indexed field representation.
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> std::result::Result<OutPoint, D::Error> {
            let (txid, out_idx) = Deserialize::deserialize(d)?;
            Ok(OutPoint {
                txid: TxId(Hash32(txid)),
                out_idx,
            })
        }
    }
    /// Serde adapter for the encoded indexed output.
    pub mod output {
        use super::*;
        /// Serialize the indexed value using its native field representation.
        pub fn serialize<S: serde::Serializer>(
            v: &Output,
            s: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            v.encode().map_err(serde::ser::Error::custom)?.serialize(s)
        }
        /// Deserialize and validate the indexed field representation.
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> std::result::Result<Output, D::Error> {
            Output::decode(&Vec::<u8>::deserialize(d)?)
                .map_err(serde::de::Error::custom)
        }
    }
    /// Serde adapter for an exact 134-byte native block header.
    pub mod header {
        use super::*;
        /// Serialize the indexed value using its native field representation.
        pub fn serialize<S: serde::Serializer>(
            v: &[u8; 134],
            s: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            s.serialize_bytes(v)
        }
        /// Deserialize and validate the indexed field representation.
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> std::result::Result<[u8; 134], D::Error> {
            Vec::<u8>::deserialize(d)?
                .try_into()
                .map_err(|_| serde::de::Error::custom("header length"))
        }
    }
}
/// Payload or native framed-table byte interval in the exact transaction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WireRange {
    /// Zero-based byte offset in the retained transaction frame.
    pub offset: u64,
    /// Number of bytes covered by this range.
    pub length: u64,
}
impl WireRange {
    /// Reject overflow and offsets outside the retained frame.
    pub fn validate(self, wire_size: u64) -> Result<()> {
        if self
            .offset
            .checked_add(self.length)
            .filter(|end| *end <= wire_size)
            .is_none()
        {
            return Err(Error::Invalid("explorer wire range"));
        }
        Ok(())
    }
}
/// One native public witness, represented without large inline vectors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessFact {
    /// Byte range containing the public witness script.
    pub script: WireRange,
    /// Byte range containing the framed sibling hashes.
    pub siblings_table: WireRange,
    /// Number of sibling hashes in the framed table.
    pub siblings_count: u32,
    /// Byte range containing the framed argument items.
    pub arguments_table: WireRange,
    /// Number of arguments in the framed table.
    pub arguments_count: u32,
}
/// Immutable creation fact resolved by the single DB owner before the spend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedCreation {
    #[serde(with = "native_serde::outpoint")]
    /// Identity and output index of the resolved creation.
    pub outpoint: OutPoint,
    #[serde(with = "native_serde::output")]
    /// Indexed output of the resolved creation.
    pub output: Output,
    #[serde(with = "native_serde::location")]
    /// Confirmed transaction position that created the output.
    pub creation: TxLocation,
}
/// Complete native input facts; selectors retain their raw meaning by flags.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InputFact {
    /// Raw transaction identity of the previous outpoint.
    pub prev_txid: [u8; 32],
    /// Output index in the previous transaction.
    pub prev_index: u32,
    /// Raw input sequence number.
    pub sequence: u32,
    /// Input grammar and selector flags retained from the transaction.
    pub flags: u8,
    /// Selected public witness path index.
    pub path_index: u8,
    /// Whether this input carries a coinbase data range.
    pub has_coinbase_data: bool,
    /// Byte range of coinbase data, when present.
    pub coinbase_data: WireRange,
    /// Witness descriptors in transaction order.
    pub witnesses: Vec<WitnessFact>,
    pub resolved_creation: Option<ResolvedCreation>,
}
/// Required native transaction frame, never reconstructed from output records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExplorerTxFacts {
    /// Exact transaction bytes supplied by the node.
    pub wire: Vec<u8>,
    /// Raw transaction lock field.
    pub lock: u64,
    /// Input descriptors in transaction order.
    pub inputs: Vec<InputFact>,
}
/// Exact authenticated native header (genesis retains its zero predecessor).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExplorerBlockFacts {
    #[serde(with = "native_serde::header")]
    /// Exact 134-byte native block header.
    pub header_wire: [u8; 134],
}
/// Fixed transaction metadata with a compact `(file_num, data_pos, wire_size)`
/// pointer into the append-only flat segment file (`v2_tx_NNNNN.dat`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxMeta {
    #[serde(with = "native_serde::location")]
    /// Confirmed block position and typed transaction identities.
    pub location: TxLocation,
    /// Raw transaction lock field.
    pub lock: u64,
    /// Number of inputs in the exact transaction.
    pub input_count: u32,
    /// Number of outputs in the exact transaction.
    pub output_count: u32,
    /// Block data file number containing the transaction.
    pub file_num: u32,
    pub data_pos: u64,
    pub wire_size: u64,
    /// Seahash checksum of the exact serialized transaction.
    pub wire_checksum: u64,
}
/// Fixed block metadata joined to canonical height.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockMeta {
    /// Canonical block identity and height.
    pub anchor: Anchor,
    #[serde(with = "native_serde::header")]
    /// Exact 134-byte native block header.
    pub header_wire: [u8; 134],
    /// Number of transactions in this block.
    pub tx_count: u32,
}
/// Input descriptor with a count instead of an unbounded witness vector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InputMeta {
    /// Raw transaction identity of the previous outpoint.
    pub prev_txid: [u8; 32],
    /// Output index in the previous transaction.
    pub prev_index: u32,
    /// Raw input sequence number.
    pub sequence: u32,
    /// Input grammar and selector flags retained from the transaction.
    pub flags: u8,
    /// Selected public witness path index.
    pub path_index: u8,
    /// Whether this input carries a coinbase data range.
    pub has_coinbase_data: bool,
    /// Byte range of coinbase data, when present.
    pub coinbase_data: WireRange,
    /// Number of separately stored witness descriptors.
    pub witness_count: u32,
    /// Creating output and position for a resolved spending input.
    pub resolved_creation: Option<ResolvedCreation>,
}
impl InputFact {
    /// Bounded persisted descriptor.
    pub fn metadata(&self) -> Result<InputMeta> {
        Ok(InputMeta {
            prev_txid: self.prev_txid,
            prev_index: self.prev_index,
            sequence: self.sequence,
            flags: self.flags,
            path_index: self.path_index,
            has_coinbase_data: self.has_coinbase_data,
            coinbase_data: self.coinbase_data,
            witness_count: u32::try_from(self.witnesses.len())
                .map_err(|_| Error::Invalid("witness count"))?,
            resolved_creation: self.resolved_creation.clone(),
        })
    }
}
/// Bounded record encoder used by the owner and receipt reconstruction.
pub fn encode_record<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = postcard::to_allocvec(value).map_err(|_| Error::Corrupt)?;
    if value.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid("explorer record bound"));
    }
    Ok(value)
}
/// Stored record decoder rejects excessive records before deserialization.
pub fn decode_record<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Corrupt);
    }
    postcard::from_bytes(bytes).map_err(|_| Error::Corrupt)
}
fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    k.extend(suffix);
    k
}
/// Database key for the canonical block identity at a height.
pub fn height_key(height: u64) -> Vec<u8> {
    key(b"eH", &height.to_be_bytes())
}
/// Database key for metadata identified by native block identity.
pub fn block_key(id: Hash32) -> Vec<u8> {
    key(b"eB", &id.0)
}
/// Database key for a transaction ordinal within a native block.
pub fn block_tx_key(id: Hash32, index: u32) -> Vec<u8> {
    let mut k = key(b"eO", &id.0);
    k.extend(index.to_be_bytes());
    k
}
/// Database key for metadata identified by structural transaction ID.
pub fn tx_key(id: TxId) -> Vec<u8> {
    key(b"eT", &id.0 .0)
}
/// Database key mapping a wire transaction hash to its structural ID.
pub fn txhash_key(id: TxHash) -> Vec<u8> {
    key(b"eX", &id.0 .0)
}
/// Database key for an input ordinal within a transaction.
pub fn input_key(id: TxId, index: u32) -> Vec<u8> {
    let mut k = key(b"eI", &id.0 .0);
    k.extend(index.to_be_bytes());
    k
}
/// Database key for a witness ordinal within one transaction input.
pub fn witness_key(id: TxId, input: u32, index: u32) -> Vec<u8> {
    let mut k = key(b"eW", &id.0 .0);
    k.extend(input.to_be_bytes());
    k.extend(index.to_be_bytes());
    k
}
fn add_size(total: &mut usize, amount: usize) -> Result<()> {
    *total = total
        .checked_add(amount)
        .ok_or(Error::Invalid("explorer batch bound"))?;
    Ok(())
}
/// Conservative reservation before any planner allocation. Accounts for entries,
/// flat-file write staging, vector objects and fixed per-record overhead. The
/// block's owner checks it against the index bounds (`v2_branch::Bounds`).
pub fn preflight_explorer_block(block: &CommittedBlock) -> Result<usize> {
    let mut size = RESERVE_BLOCK;
    for tx in &block.transactions {
        add_size(
            &mut size,
            tx.explorer
                .wire
                .len()
                .checked_mul(RESERVE_PER_WIRE_BYTE)
                .ok_or(Error::Invalid("wire bound"))?,
        )?;
        add_size(&mut size, RESERVE_TX)?;
        for input in &tx.explorer.inputs {
            add_size(&mut size, RESERVE_INPUT)?;
            add_size(
                &mut size,
                input
                    .witnesses
                    .len()
                    .checked_mul(RESERVE_WITNESS)
                    .ok_or(Error::Invalid("witness bound"))?,
            )?;
        }
        add_size(
            &mut size,
            (tx.explorer.wire.len() / WIRE_CHUNK_BYTES + 1) * RESERVE_CHUNK,
        )?;
    }
    Ok(size)
}
/// Validate a bounded stored input before exposing any field. This checks the
/// native descriptor shape, not script execution or transaction consensus.
pub fn validate_input_meta(input: &InputMeta, wire_size: u64) -> Result<()> {
    input
        .coinbase_data
        .validate(wire_size)
        .map_err(|_| Error::Corrupt)?;
    if !input.has_coinbase_data && input.coinbase_data != WireRange::default() {
        return Err(Error::Corrupt);
    }
    let valid = match input.flags {
        1 => {
            !input.has_coinbase_data
                && input.path_index < 16
                && (1..=16).contains(&input.witness_count)
                && (input.sequence == u32::MAX
                    || input.sequence & !0x40ffff == 0)
                && input.resolved_creation.as_ref().is_some_and(|coin| {
                    coin.outpoint.txid.0 .0 == input.prev_txid
                        && coin.outpoint.out_idx == input.prev_index
                        && coin.creation.txid == coin.outpoint.txid
                        && !coin.output.is_burn()
                        && coin.output.validate().is_ok()
                })
        }
        2 => {
            input.path_index == 0
                && input.sequence == u32::MAX
                && input.witness_count == 0
                && input.resolved_creation.is_none()
                && (!input.has_coinbase_data
                    || (1..=8192).contains(&input.coinbase_data.length))
        }
        3 => {
            input.path_index == 0
                && input.sequence == u32::MAX
                && input.witness_count == 1
                && input.prev_index == 0
                && input.prev_txid != [0; 32]
                && !input.has_coinbase_data
                && input.resolved_creation.is_none()
        }
        _ => false,
    };
    if !valid {
        return Err(Error::Corrupt);
    }
    Ok(())
}
/// Check witness ranges without allocating scripts, arguments or proofs.
pub fn validate_witness_fact(
    witness: &WitnessFact,
    wire_size: u64,
) -> Result<()> {
    for range in [
        witness.script,
        witness.siblings_table,
        witness.arguments_table,
    ] {
        range.validate(wire_size).map_err(|_| Error::Corrupt)?;
    }
    if witness.siblings_count > 64
        || witness.arguments_count > 65535
        || witness.siblings_table.length == 0
        || witness.arguments_table.length == 0
        || u64::from(witness.arguments_count)
            > witness.arguments_table.length - 1
    {
        return Err(Error::Corrupt);
    }
    Ok(())
}
fn validate_input(input: &InputFact, size: u64) -> Result<()> {
    if !matches!(input.flags, 1..=3) {
        return Err(Error::Invalid("input flags"));
    }
    input.coinbase_data.validate(size)?;
    if !input.has_coinbase_data && input.coinbase_data != WireRange::default() {
        return Err(Error::Invalid("absent coinbase range"));
    }
    match (input.flags, &input.resolved_creation) {
        (1, Some(coin))
            if coin.outpoint.txid.0 .0 == input.prev_txid
                && coin.outpoint.out_idx == input.prev_index
                && coin.creation.txid == coin.outpoint.txid
                && !coin.output.is_burn() => {}
        (2 | 3, None) => {}
        _ => return Err(Error::Invalid("frozen spend creation")),
    }
    for witness in &input.witnesses {
        witness.script.validate(size)?;
        witness.siblings_table.validate(size)?;
        witness.arguments_table.validate(size)?;
        if witness.siblings_table.length == 0
            || witness.arguments_table.length == 0
        {
            return Err(Error::Invalid("missing witness table framing"));
        }
    }
    Ok(())
}
/// Deterministic exact entries and flat-file `(file_num, data_pos, wire)` writes
/// starting from `(start_file_num, start_data_pos)`.
pub fn plan_explorer_block_at(
    block: &CommittedBlock,
    start_file_num: u32,
    start_data_pos: u64,
) -> Result<(
    Vec<(Vec<u8>, Vec<u8>)>,
    Vec<(u32, u64, Vec<u8>)>,
    (u32, u64),
)> {
    preflight_explorer_block(block)?;
    let h = &block.explorer.header_wire;
    if u64::from_le_bytes(h[62..70].try_into().unwrap()) != block.anchor.height
    {
        return Err(Error::Invalid("explorer header height"));
    }
    if (block.anchor.height == 0 && h[..32] != [0; 32])
        || (block.anchor.height != 0 && h[..32] != block.parent.block_id)
    {
        return Err(Error::Invalid("explorer header parent"));
    }
    let mut entries = vec![
        (
            height_key(block.anchor.height),
            block.anchor.block_id.to_vec(),
        ),
        (
            block_key(Hash32(block.anchor.block_id)),
            encode_record(&BlockMeta {
                anchor: block.anchor,
                header_wire: *h,
                tx_count: u32::try_from(block.transactions.len())
                    .map_err(|_| Error::Invalid("transaction count"))?,
            })?,
        ),
    ];
    let mut flat_writes = Vec::with_capacity(block.transactions.len());
    let mut cur_file_num = start_file_num;
    let mut cur_data_pos = start_data_pos;
    for (index, tx) in block.transactions.iter().enumerate() {
        let loc = tx.location;
        if loc.block_id.0 != block.anchor.block_id
            || loc.height != block.anchor.height
            || loc.tx_index as usize != index
        {
            return Err(Error::Invalid("explorer transaction location"));
        }
        let facts = &tx.explorer;
        if facts.wire.is_empty() {
            return Err(Error::Invalid("empty transaction frame"));
        }
        let wire_size = facts.wire.len() as u64;
        if cur_data_pos > 0
            && cur_data_pos.saturating_add(wire_size)
                > crate::mdbx::MAX_FLAT_SEGMENT_BYTES
        {
            cur_file_num = cur_file_num
                .checked_add(1)
                .ok_or(Error::Invalid("flat file segment overflow"))?;
            cur_data_pos = 0;
        }
        let file_num = cur_file_num;
        let data_pos = cur_data_pos;
        let wire_checksum = seahash::hash(&facts.wire);
        cur_data_pos = cur_data_pos
            .checked_add(wire_size)
            .ok_or(Error::Invalid("flat file offset overflow"))?;
        flat_writes.push((file_num, data_pos, facts.wire.clone()));

        let meta = TxMeta {
            location: loc,
            lock: facts.lock,
            input_count: u32::try_from(facts.inputs.len())
                .map_err(|_| Error::Invalid("input count"))?,
            output_count: u32::try_from(tx.outputs.len())
                .map_err(|_| Error::Invalid("output count"))?,
            file_num,
            data_pos,
            wire_size,
            wire_checksum,
        };
        entries.push((tx_key(loc.txid), encode_record(&meta)?));
        entries.push((txhash_key(loc.txhash), loc.txid.0 .0.to_vec()));
        let mut ids = loc.txid.0 .0.to_vec();
        ids.extend(loc.txhash.0 .0);
        entries.push((block_tx_key(loc.block_id, loc.tx_index), ids));
        let expected_spends = facts
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.flags == 1)
            .map(|(index, input)| {
                (
                    index as u32,
                    OutPoint {
                        txid: TxId(Hash32(input.prev_txid)),
                        out_idx: input.prev_index,
                    },
                )
            })
            .collect::<Vec<_>>();
        if expected_spends.len() != tx.spends.len()
            || !expected_spends.iter().zip(&tx.spends).all(
                |((index, outpoint), spend)| {
                    *index == spend.input_index && *outpoint == spend.outpoint
                },
            )
        {
            return Err(Error::Invalid("explorer spend subset"));
        }
        for (i, input) in facts.inputs.iter().enumerate() {
            validate_input(input, meta.wire_size)?;
            entries.push((
                input_key(loc.txid, i as u32),
                encode_record(&input.metadata()?)?,
            ));
            for (w, witness) in input.witnesses.iter().enumerate() {
                entries.push((
                    witness_key(loc.txid, i as u32, w as u32),
                    encode_record(witness)?,
                ));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    if entries.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Error::Invalid("duplicate explorer identity"));
    }
    Ok((entries, flat_writes, (cur_file_num, cur_data_pos)))
}
/// Deterministic exact entries starting at flat-file position `(0, 0)`.
pub fn plan_explorer_block(
    block: &CommittedBlock,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    plan_explorer_block_at(block, 0, 0).map(|(entries, _, _)| entries)
}
impl ReadSnapshot<'_> {
    /// Canonical block with validated height/header joins.
    pub fn explorer_block(&self, id: Hash32) -> Result<Option<BlockMeta>> {
        let Some(bytes) = self.inner.get(block_key(id))? else {
            return Ok(None);
        };
        let meta: BlockMeta = decode_record(&bytes)?;
        if meta.anchor.block_id != id.0
            || meta.anchor.height > self.anchor.height
            || self.inner.get(height_key(meta.anchor.height))?.as_deref()
                != Some(&id.0)
        {
            return Err(Error::Corrupt);
        }
        if u64::from_le_bytes(meta.header_wire[62..70].try_into().unwrap())
            != meta.anchor.height
        {
            return Err(Error::Corrupt);
        }
        if meta.anchor.height == 0 {
            if meta.header_wire[..32] != [0; 32] {
                return Err(Error::Corrupt);
            }
        } else if self
            .inner
            .get(height_key(meta.anchor.height - 1))?
            .as_deref()
            != Some(&meta.header_wire[..32])
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(meta))
    }
    /// Read block metadata joined to the canonical height index.
    pub fn explorer_block_at_height(
        &self,
        height: u64,
    ) -> Result<Option<BlockMeta>> {
        let Some(bytes) = self.inner.get(height_key(height))? else {
            return Ok(None);
        };
        let id =
            Hash32(bytes.as_slice().try_into().map_err(|_| Error::Corrupt)?);
        let meta = self.explorer_block(id)?.ok_or(Error::Corrupt)?;
        if meta.anchor.height != height {
            return Err(Error::Corrupt);
        }
        Ok(Some(meta))
    }
    /// Transaction metadata joined to the existing location authority and order.
    pub fn explorer_tx(&self, id: TxId) -> Result<Option<TxMeta>> {
        let Some(bytes) = self.inner.get(tx_key(id))? else {
            return Ok(None);
        };
        let meta: TxMeta = decode_record(&bytes)?;
        let loc = meta.location;
        if meta.input_count > 65535
            || meta.output_count > 65535
            || meta.wire_size == 0
            || meta.wire_size > self.bounds.block_bytes() as u64
        {
            return Err(Error::Corrupt);
        }
        if loc.txid != id || self.transaction(id)? != Some(loc) {
            return Err(Error::Corrupt);
        }
        let block = self.explorer_block(loc.block_id)?.ok_or(Error::Corrupt)?;
        if block.anchor.height != loc.height
            || loc.tx_index >= block.tx_count
            || self.explorer_block_tx(loc.block_id, loc.tx_index)?
                != Some((id, loc.txhash))
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(meta))
    }
    /// Resolve a wire transaction hash to its validated metadata.
    pub fn explorer_tx_by_hash(&self, hash: TxHash) -> Result<Option<TxMeta>> {
        let Some(bytes) = self.inner.get(txhash_key(hash))? else {
            return Ok(None);
        };
        let id = TxId(Hash32(
            bytes.as_slice().try_into().map_err(|_| Error::Corrupt)?,
        ));
        let meta = self.explorer_tx(id)?.ok_or(Error::Corrupt)?;
        if meta.location.txhash != hash {
            return Err(Error::Corrupt);
        }
        Ok(Some(meta))
    }
    /// Read both transaction identities at a block transaction ordinal.
    pub fn explorer_block_tx(
        &self,
        block: Hash32,
        index: u32,
    ) -> Result<Option<(TxId, TxHash)>> {
        self.inner
            .get(block_tx_key(block, index))?
            .map(|bytes| {
                if bytes.len() != 64 {
                    return Err(Error::Corrupt);
                }
                Ok((
                    TxId(Hash32(bytes[..32].try_into().unwrap())),
                    TxHash(Hash32(bytes[32..].try_into().unwrap())),
                ))
            })
            .transpose()
    }
    /// Read an input descriptor and validate its resolved creation.
    pub fn explorer_input(
        &self,
        id: TxId,
        index: u32,
    ) -> Result<Option<InputMeta>> {
        let Some(tx) = self.explorer_tx(id)? else {
            return Ok(None);
        };
        let Some(bytes) = self.inner.get(input_key(id, index))? else {
            return if index < tx.input_count {
                Err(Error::Corrupt)
            } else {
                Ok(None)
            };
        };
        if index >= tx.input_count {
            return Err(Error::Corrupt);
        }
        let input: InputMeta = decode_record(&bytes)?;
        validate_input_meta(&input, tx.wire_size)?;
        // A descriptor count must reach an existing final ordinal and stop at
        // the next key. Missing interior ordinals fail when that page is read.
        if input.witness_count > 0 {
            let last = self
                .inner
                .get(witness_key(id, index, input.witness_count - 1))?
                .ok_or(Error::Corrupt)?;
            let last: WitnessFact = decode_record(&last)?;
            validate_witness_fact(&last, tx.wire_size)?;
        }
        if self
            .inner
            .get(witness_key(id, index, input.witness_count))?
            .is_some()
        {
            return Err(Error::Corrupt);
        }
        if let Some(coin) = &input.resolved_creation {
            let historical =
                self.output(coin.outpoint)?.ok_or(Error::Corrupt)?;
            if historical.output != coin.output
                || historical.creation != coin.creation
                || historical.spend.as_ref().map_or(true, |spend| {
                    spend.transaction != tx.location
                        || spend.input_index != index
                })
                || self
                    .explorer_tx(coin.creation.txid)?
                    .as_ref()
                    .map_or(true, |creation_tx| {
                        creation_tx.location != coin.creation
                            || coin.outpoint.out_idx >= creation_tx.output_count
                    })
                // Created earlier, or elsewhere in the same block (which may
                // be in canonical, not topological, order).
                || coin.creation.height > tx.location.height
                || (coin.creation.height == tx.location.height
                    && coin.creation.tx_index == tx.location.tx_index)
            {
                return Err(Error::Corrupt);
            }
        }
        Ok(Some(input))
    }
    /// Read a bounded witness descriptor for one transaction input.
    pub fn explorer_witness(
        &self,
        id: TxId,
        input_index: u32,
        index: u32,
    ) -> Result<Option<WitnessFact>> {
        let Some(input) = self.explorer_input(id, input_index)? else {
            return Ok(None);
        };
        let Some(bytes) =
            self.inner.get(witness_key(id, input_index, index))?
        else {
            return if index < input.witness_count {
                Err(Error::Corrupt)
            } else {
                Ok(None)
            };
        };
        if index >= input.witness_count {
            return Err(Error::Corrupt);
        }
        let tx = self.explorer_tx(id)?.ok_or(Error::Corrupt)?;
        let witness: WitnessFact = decode_record(&bytes)?;
        validate_witness_fact(&witness, tx.wire_size)?;
        let (siblings, count_bytes) =
            self.explorer_table_count(id, tx.wire_size, witness.siblings_table)?;
        let (arguments, _) = self.explorer_table_count(
            id,
            tx.wire_size,
            witness.arguments_table,
        )?;
        if siblings != u64::from(witness.siblings_count)
            || arguments != u64::from(witness.arguments_count)
            || siblings
                .checked_mul(32)
                .and_then(|n| n.checked_add(count_bytes))
                != Some(witness.siblings_table.length)
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(witness))
    }
    // Read only the <=9 count bytes from the flat segment file at
    // `(tx.file_num, tx.data_pos + range.offset)`.
    fn explorer_table_count(
        &self,
        id: TxId,
        wire_size: u64,
        range: WireRange,
    ) -> Result<(u64, u64)> {
        range.validate(wire_size).map_err(|_| Error::Corrupt)?;
        if range.length == 0 {
            return Err(Error::Corrupt);
        }
        let needed = range.length.min(9) as usize;
        let slice = self
            .explorer_wire_slice(id, range.offset, needed as u64)?
            .ok_or(Error::Corrupt)?;
        if slice.len() != needed {
            return Err(Error::Corrupt);
        }
        let mut bytes = [0u8; 9];
        bytes[..needed].copy_from_slice(&slice);
        let (value, width) = match bytes[0] {
            0..=252 => (u64::from(bytes[0]), 1),
            253 if needed >= 3 => (
                u64::from(u16::from_le_bytes(bytes[1..3].try_into().unwrap())),
                3,
            ),
            254 if needed >= 5 => (
                u64::from(u32::from_le_bytes(bytes[1..5].try_into().unwrap())),
                5,
            ),
            255 if needed >= 9 => {
                (u64::from_le_bytes(bytes[1..9].try_into().unwrap()), 9)
            }
            _ => return Err(Error::Corrupt),
        };
        if (width == 3 && value < 253)
            || (width == 5 && value <= u16::MAX as u64)
            || (width == 9 && value <= u32::MAX as u64)
        {
            return Err(Error::Corrupt);
        }
        Ok((value, width))
    }
    /// Read a slice `[offset .. min(offset + length, wire_size)]` of raw
    /// transaction wire bytes directly from the append-only flat segment file
    /// referenced by `TxMeta`'s `(file_num, data_pos, wire_size)` pointer.
    pub fn explorer_wire_slice(
        &self,
        id: TxId,
        offset: u64,
        length: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(tx) = self.explorer_tx(id)? else {
            return Ok(None);
        };
        if offset > tx.wire_size {
            return Err(Error::Corrupt);
        }
        let full = self
            .inner
            .read_flat(tx.file_num, tx.data_pos, tx.wire_size as usize)
            .map_err(|_| Error::Corrupt)?;
        if seahash::hash(&full) != tx.wire_checksum {
            return Err(Error::Corrupt);
        }
        let end = offset.saturating_add(length).min(tx.wire_size) as usize;
        Ok(Some(full[offset as usize..end].to_vec()))
    }
    /// Read a 32 KiB chunk of raw transaction wire bytes via the flat-file
    /// `(file_num, data_pos, wire_size)` pointer stored in `TxMeta`.
    pub fn explorer_wire_chunk(
        &self,
        id: TxId,
        index: u32,
    ) -> Result<Option<Vec<u8>>> {
        let Some(tx) = self.explorer_tx(id)? else {
            return Ok(None);
        };
        let start = u64::from(index)
            .checked_mul(WIRE_CHUNK_BYTES as u64)
            .ok_or(Error::Corrupt)?;
        if start >= tx.wire_size {
            return Ok(None);
        }
        let bytes = self.explorer_wire_slice(id, start, WIRE_CHUNK_BYTES as u64)?;
        if bytes
            .as_ref()
            .is_some_and(|b| b.is_empty() || b.len() > WIRE_CHUNK_BYTES)
        {
            return Err(Error::Corrupt);
        }
        Ok(bytes)
    }
    /// Exclusive bounded seek. The key shape is constrained by the caller's
    /// exact family prefix and expected width; no foreign key can continue it.
    pub fn explorer_next_raw(
        &self,
        prefix: &[u8],
        key_len: usize,
        after: Option<&[u8]>,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let allowed = matches!(
            (prefix.get(..2), prefix.len(), key_len),
            (Some(b"eH"), 2, 10)
                | (Some(b"eO"), 34, 38)
                | (Some(b"eI"), 34, 38)
                | (Some(b"eW"), 38, 42)
        );
        if !allowed
            || after.is_some_and(|k| k.len() != key_len || !k.starts_with(prefix))
        {
            return Err(Error::Invalid("explorer continuation key"));
        }
        let Some((k, v)) =
            self.inner
                .seek_next_regular(prefix, after, || Ok::<(), Error>(()))?
        else {
            return Ok(None);
        };
        if k.len() != key_len || v.len() > MAX_RECORD_BYTES {
            return Err(Error::Corrupt);
        }
        Ok(Some((k, v)))
    }
}

#[cfg(test)]
#[path = "v2_explorer_model_tests.rs"]
mod tests;
