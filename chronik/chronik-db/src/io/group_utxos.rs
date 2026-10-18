// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Module for [`GroupUtxoWriter`] and [`GroupUtxoReader`].

use std::{marker::PhantomData, time::Instant};

use abc_rust_error::Result;
use crate::db::{compaction_filter::Decision, WriteBatch};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    data::DbOutpoint,
    db::{Db, CF},
    group::{Group, GroupQuery, UtxoData},
    index_tx::IndexTx,
    io::{group_utxos::GroupUtxoError::*, merge::catch_merge_errors},
    ser::{db_deserialize, db_deserialize_vec, db_serialize_vec},
};

const INSERT: u8 = b'I';
const DELETE: u8 = b'D';

/// Shorthand for `UtxoEntry<G::UtxoData>`
pub type DbGroupUtxo<G> = UtxoEntry<<G as Group>::UtxoData>;

/// Configuration for group utxos reader/writers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GroupUtxoConf {
    /// Column family to store the group utxos entries.
    pub cf_name: &'static str,
}

struct GroupUtxoColumn<'a> {
    db: &'a Db,
    cf: &'a CF,
}

/// Entry in the UTXO DB for a group.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UtxoEntry<D> {
    /// Outpoint of the UTXO.
    pub outpoint: DbOutpoint,

    /// Data attached to the UTXO attached to the UTXO for easy access, e.g.
    /// the UTXO value and/or script.
    pub data: D,
}

/// Write UTXOs of a group to the DB.
#[derive(Debug)]
pub struct GroupUtxoWriter<'a, G: Group> {
    col: GroupUtxoColumn<'a>,
    group: G,
}

/// Read UTXOs of a group from the DB.
#[derive(Debug)]
pub struct GroupUtxoReader<'a, G: Group> {
    col: GroupUtxoColumn<'a>,
    phantom: PhantomData<G>,
}

/// In-memory data for indexing UTXOs of a group.
#[derive(Debug, Default)]
pub struct GroupUtxoMemData {
    /// Stats about cache hits, num requests etc.
    pub stats: GroupUtxoStats,
}

/// Stats about cache hits, num requests etc.
#[derive(Clone, Debug, Default)]
pub struct GroupUtxoStats {
    /// Total number of txs updated.
    pub n_total: usize,
    /// Time [s] for insert/delete.
    pub t_total: f64,
}

/// Error indicating something went wrong with the tx index.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GroupUtxoError {
    /// UTXO already in the DB
    #[error(
        "Duplicate UTXO: {0:?} has been added twice to the member's UTXOs"
    )]
    DuplicateUtxo(DbOutpoint),

    /// UTXO already in the DB
    #[error("UTXO doesn't exist: {0:?} is not in the member's UTXOs")]
    UtxoDoesntExist(DbOutpoint),

    /// Used merge_cf incorrectly, prefix must either be I or D.
    #[error(
        "Bad usage of merge: Unknown prefix {prefix:02x}, \
         expected I or D: {encoded}",
        prefix = .0,
        encoded = hex::encode(.1),
    )]
    UnknownOperandPrefix(u8, Vec<u8>),
}

fn partial_merge_utxos(
    _key: &[u8],
    _existing_value: Option<&[u8]>,
    _operands: &crate::db::MergeOperands,
) -> Option<Vec<u8>> {
    // We don't use partial merge
    None
}

fn init_merge_utxos<D: for<'a> Deserialize<'a>>(
    _key: &[u8],
    existing_value: Option<&[u8]>,
    operands: &crate::db::MergeOperands,
) -> Result<Vec<UtxoEntry<D>>> {
    let mut entries = match existing_value {
        Some(entries_ser) => db_deserialize_vec::<UtxoEntry<D>>(entries_ser)?,
        None => vec![],
    };
    if operands.into_iter().all(|operand| operand[0] == INSERT) {
        // If we only have inserts, we can pre-allocate the exact memory we need
        entries.reserve_exact(operands.len());
    }
    Ok(entries)
}

fn apply_merge_utxos<D: for<'a> Deserialize<'a>>(
    _key: &[u8],
    entries: &mut Vec<UtxoEntry<D>>,
    operand: &[u8],
) -> Result<()> {
    match operand[0] {
        INSERT => {
            let new_entry = db_deserialize::<UtxoEntry<D>>(&operand[1..])?;
            match entries.binary_search_by_key(&&new_entry.outpoint, |entry| {
                &entry.outpoint
            }) {
                Ok(_) => return Err(DuplicateUtxo(new_entry.outpoint).into()),
                Err(insert_idx) => entries.insert(insert_idx, new_entry),
            }
        }
        DELETE => {
            let delete_outpoint = db_deserialize::<DbOutpoint>(&operand[1..])?;
            match entries.binary_search_by_key(&&delete_outpoint, |entry| {
                &entry.outpoint
            }) {
                Ok(delete_idx) => entries.remove(delete_idx),
                Err(_) => return Err(UtxoDoesntExist(delete_outpoint).into()),
            };
        }
        _ => {
            return Err(
                UnknownOperandPrefix(operand[0], operand.to_vec()).into()
            );
        }
    }
    Ok(())
}

fn ser_merge_utxos<D: Serialize>(
    _key: &[u8],
    entries: Vec<UtxoEntry<D>>,
) -> Result<Vec<u8>> {
    db_serialize_vec::<UtxoEntry<D>>(entries)
}

// We must use a compaction filter that removes empty entries
fn compaction_filter_utxos(_level: u32, _key: &[u8], value: &[u8]) -> Decision {
    if value.is_empty() {
        Decision::Remove
    } else {
        Decision::Keep
    }
}

const OUTPOINT_PREFIX_LEN: usize = 12;

fn encode_outpoint_prefix(outpoint: &DbOutpoint) -> [u8; OUTPOINT_PREFIX_LEN] {
    let mut buf = [0u8; OUTPOINT_PREFIX_LEN];
    buf[..8].copy_from_slice(&outpoint.tx_num.to_be_bytes());
    buf[8..12].copy_from_slice(&outpoint.out_idx.to_be_bytes());
    buf
}

fn encode_utxo_dup<D: UtxoData>(entry: &UtxoEntry<D>) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(D::FIXED_DUP_SIZE.unwrap_or(OUTPOINT_PREFIX_LEN + 16));
    buf.extend_from_slice(&encode_outpoint_prefix(&entry.outpoint));
    entry.data.ser_dup_data(&mut buf);
    buf
}

fn decode_utxo_dup<D: UtxoData>(bytes: &[u8]) -> Result<UtxoEntry<D>> {
    if bytes.len() < OUTPOINT_PREFIX_LEN {
        return Err(crate::ser::SerError::DeserializeError {
            type_name: std::any::type_name::<UtxoEntry<D>>(),
            error: postcard::Error::DeserializeUnexpectedEnd,
            bytes: bytes.to_vec(),
        }
        .into());
    }
    let tx_num = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let out_idx = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    let data =
        D::deser_dup_data(&bytes[OUTPOINT_PREFIX_LEN..]).ok_or_else(|| {
            crate::ser::SerError::DeserializeError {
                type_name: std::any::type_name::<D>(),
                error: postcard::Error::DeserializeUnexpectedEnd,
                bytes: bytes.to_vec(),
            }
        })?;
    Ok(UtxoEntry {
        outpoint: DbOutpoint { tx_num, out_idx },
        data,
    })
}

impl<'a> GroupUtxoColumn<'a> {
    fn new(db: &'a Db, conf: &GroupUtxoConf) -> Result<Self> {
        let cf = db.cf(conf.cf_name)?;
        Ok(GroupUtxoColumn { db, cf })
    }
}

impl<'a, G: Group> GroupUtxoWriter<'a, G> {
    /// Create a new [`GroupUtxoWriter`].
    pub fn new(db: &'a Db, group: G) -> Result<Self> {
        let conf = G::utxo_conf();
        let col = GroupUtxoColumn::new(db, &conf)?;
        Ok(GroupUtxoWriter { col, group })
    }

    /// Insert the txs of a block from the UTXOs in the DB for the group.
    ///
    /// Add all the UTXOs created by the outputs of the txs to the DB, remove
    /// all the UTXOs spend by the inputs of the txs.
    pub fn insert<'tx>(
        &self,
        batch: &mut WriteBatch,
        txs: &'tx [IndexTx<'tx>],
        aux: &G::Aux,
        mem_data: &mut GroupUtxoMemData,
    ) -> Result<()> {
        let stats = &mut mem_data.stats;
        stats.n_total += txs.len();
        let t_start = Instant::now();
        for index_tx in txs {
            let query = GroupQuery {
                is_coinbase: index_tx.is_coinbase,
                tx: index_tx.tx,
            };
            for item in self.group.output_members(query, aux) {
                let new_entry = Self::output_utxo(index_tx, item.idx);
                self.insert_utxo_entry(batch, &item.member, new_entry)?;
            }
        }
        for index_tx in txs {
            if index_tx.is_coinbase {
                continue;
            }
            let query = GroupQuery {
                is_coinbase: index_tx.is_coinbase,
                tx: index_tx.tx,
            };
            for item in self.group.input_members(query, aux) {
                let delete_entry = Self::input_utxo(index_tx, item.idx);
                let has_coin = index_tx.tx.inputs[item.idx].coin.is_some();
                self.delete_utxo_entry(
                    batch,
                    &item.member,
                    &delete_entry,
                    has_coin,
                )?;
            }
        }
        stats.t_total += t_start.elapsed().as_secs_f64();
        Ok(())
    }

    /// Remove the txs of a block from the UTXOs in the DB for the group.
    ///
    /// Add all the UTXOs spent by the inputs of the txs and remove all the
    /// UTXOs created by the outputs of the txs.
    pub fn delete<'tx>(
        &self,
        batch: &mut WriteBatch,
        txs: &'tx [IndexTx<'tx>],
        aux: &G::Aux,
        mem_data: &mut GroupUtxoMemData,
    ) -> Result<()> {
        let stats = &mut mem_data.stats;
        stats.n_total += txs.len();
        let t_start = Instant::now();
        for index_tx in txs {
            if index_tx.is_coinbase {
                continue;
            }
            let query = GroupQuery {
                is_coinbase: index_tx.is_coinbase,
                tx: index_tx.tx,
            };
            for item in self.group.input_members(query, aux) {
                let new_entry = Self::input_utxo(index_tx, item.idx);
                self.insert_utxo_entry(batch, &item.member, new_entry)?;
            }
        }
        for index_tx in txs {
            let query = GroupQuery {
                is_coinbase: index_tx.is_coinbase,
                tx: index_tx.tx,
            };
            for item in self.group.output_members(query, aux) {
                let delete_entry = Self::output_utxo(index_tx, item.idx);
                self.delete_utxo_entry(
                    batch,
                    &item.member,
                    &delete_entry,
                    true,
                )?;
            }
        }
        stats.t_total += t_start.elapsed().as_secs_f64();
        Ok(())
    }

    /// Clear all UTXO data from the DB
    pub fn wipe(&self, batch: &mut WriteBatch) {
        batch.delete_range_cf(self.col.cf, [].as_ref(), &[0xff; 16]);
    }

    pub(crate) fn add_cfs(columns: &mut Vec<crate::db::ColumnFamilyDescriptor>) {
        let cf_name = G::utxo_conf().cf_name;
        let mut options = crate::db::Options::default();
        options.set_dupsort(G::UtxoData::FIXED_DUP_SIZE);
        let merge_op_name = format!("{}::merge_op_utxos", cf_name);
        options.set_merge_operator(
            merge_op_name.as_str(),
            catch_merge_errors(
                init_merge_utxos::<G::UtxoData>,
                apply_merge_utxos::<G::UtxoData>,
                ser_merge_utxos::<G::UtxoData>,
            ),
            partial_merge_utxos,
        );
        let compaction_filter_name =
            format!("{}::compaction_filter_utxos", cf_name);
        options.set_compaction_filter(
            &compaction_filter_name,
            compaction_filter_utxos,
        );
        columns.push(crate::db::ColumnFamilyDescriptor::new(cf_name, options));
    }

    fn output_utxo(
        index_tx: &IndexTx<'_>,
        idx: usize,
    ) -> UtxoEntry<G::UtxoData> {
        UtxoEntry {
            outpoint: DbOutpoint {
                tx_num: index_tx.tx_num,
                out_idx: idx as u32,
            },
            data: G::UtxoData::from_output(&index_tx.tx.outputs[idx]),
        }
    }

    fn input_utxo(
        index_tx: &IndexTx<'_>,
        idx: usize,
    ) -> UtxoEntry<G::UtxoData> {
        UtxoEntry {
            outpoint: DbOutpoint {
                tx_num: index_tx.input_nums[idx],
                out_idx: index_tx.tx.inputs[idx].prev_out.out_idx,
            },
            data: index_tx.tx.inputs[idx]
                .coin
                .as_ref()
                .map(|coin| G::UtxoData::from_output(&coin.output))
                .unwrap_or_default(),
        }
    }

    fn insert_utxo_entry(
        &self,
        batch: &mut WriteBatch,
        member: &G::Member<'_>,
        new_entry: UtxoEntry<G::UtxoData>,
    ) -> Result<()> {
        batch.put_dup_cf(
            self.col.cf,
            self.group.ser_member(member),
            encode_utxo_dup(&new_entry),
        );
        Ok(())
    }

    fn delete_utxo_entry(
        &self,
        batch: &mut WriteBatch,
        member: &G::Member<'_>,
        delete_entry: &UtxoEntry<G::UtxoData>,
        has_coin: bool,
    ) -> Result<()> {
        if has_coin && G::UtxoData::FIXED_DUP_SIZE.is_some() {
            batch.delete_dup_prefix_cf(
                self.col.cf,
                self.group.ser_member(member),
                encode_utxo_dup(delete_entry),
            );
        } else {
            batch.delete_dup_prefix_cf(
                self.col.cf,
                self.group.ser_member(member),
                encode_outpoint_prefix(&delete_entry.outpoint),
            );
        }
        Ok(())
    }
}

type GroupUtxoIterItem<G> = Result<(Box<[u8]>, Vec<DbGroupUtxo<G>>)>;

impl<'a, G: Group> GroupUtxoReader<'a, G> {
    /// Create a new [`GroupUtxoReader`].
    pub fn new(db: &'a Db) -> Result<Self> {
        let conf = G::utxo_conf();
        let col = GroupUtxoColumn::new(db, &conf)?;
        Ok(GroupUtxoReader {
            col,
            phantom: PhantomData,
        })
    }

    /// Query the UTXOs for the given member.
    pub fn utxos(
        &self,
        member: &[u8],
    ) -> Result<Option<Vec<UtxoEntry<G::UtxoData>>>> {
        let mut entries = Vec::new();
        self.col
            .db
            .get_dups_visit(self.col.cf, member, |raw| {
                entries.push(decode_utxo_dup::<G::UtxoData>(raw)?);
                Ok(())
            })?;
        if entries.is_empty() {
            return Ok(None);
        }
        Ok(Some(entries))
    }

    /// Iterate over all group members with a given prefix, starting from some
    /// given prefix
    pub fn prefix_iterator(
        &self,
        member_prefix: &'a [u8],
        member_start: &'a [u8],
    ) -> impl Iterator<Item = GroupUtxoIterItem<G>> + 'a {
        self.col
            .db
            .dup_prefix_iterator(self.col.cf, member_prefix, member_start)
            .filter_map(|entry| {
                let (key, raw_dups) = match entry {
                    Ok(entry) => entry,
                    Err(err) => return Some(Err(err)),
                };
                if raw_dups.is_empty() {
                    return None;
                }
                let mut utxos = Vec::with_capacity(raw_dups.len());
                for raw in raw_dups {
                    match decode_utxo_dup::<G::UtxoData>(&raw) {
                        Ok(utxo) => utxos.push(utxo),
                        Err(err) => return Some(Err(err)),
                    }
                }
                Some(Ok((key, utxos)))
            })
    }
}

impl std::fmt::Debug for GroupUtxoColumn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupUtxoColumn {{ .. }}")
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use abc_rust_error::Result;
    use bitcoinsuite_core::tx::Tx;
    use crate::db::WriteBatch;

    use crate::{
        data::DbOutpoint,
        db::Db,
        index_tx::prepare_indexed_txs,
        io::{
            BlockTxs, GroupUtxoMemData, GroupUtxoReader, GroupUtxoWriter,
            TxEntry, TxWriter, TxsMemData, UtxoEntry,
        },
        test::{make_inputs_tx, ser_value, ValueGroup},
    };

    use super::{decode_utxo_dup, encode_utxo_dup};
    use crate::group::{UtxoDataOutput, UtxoDataValue};

    #[test]
    fn test_utxo_dup_layout() -> Result<()> {
        // tx_num BE8 || out_idx BE4 || sats LE8 [|| raw script], as eCash
        // writes it; the native Chronik reads and writes the same bytes.
        let entry = UtxoEntry::<UtxoDataOutput> {
            outpoint: DbOutpoint {
                tx_num: 77,
                out_idx: 2,
            },
            data: (546, vec![0x76, 0xa9].into()),
        };
        let ser = encode_utxo_dup(&entry);
        assert_eq!(
            hex::encode(&ser),
            "000000000000004d00000002220200000000000076a9",
        );
        assert_eq!(decode_utxo_dup::<UtxoDataOutput>(&ser)?, entry);
        let empty = UtxoEntry::<UtxoDataOutput> {
            data: (0, vec![].into()),
            ..entry.clone()
        };
        let ser = encode_utxo_dup(&empty);
        assert_eq!(ser.len(), 20);
        assert_eq!(decode_utxo_dup::<UtxoDataOutput>(&ser)?, empty);
        let value = UtxoEntry::<UtxoDataValue> {
            outpoint: entry.outpoint,
            data: 546,
        };
        assert_eq!(
            hex::encode(encode_utxo_dup(&value)),
            "000000000000004d000000022202000000000000",
        );

        // Short payloads are reported over the whole entry.
        assert_eq!(
            decode_utxo_dup::<UtxoDataOutput>(&[0; 19])
                .unwrap_err()
                .to_string(),
            "Inconsistent DB: Cannot deserialize byte sequence as (i64, \
             bytes::bytes::Bytes): Hit the end of buffer, expected more \
             data. Byte sequence: 00000000000000000000000000000000000000",
        );
        assert_eq!(
            decode_utxo_dup::<UtxoDataValue>(&[0; 13])
                .unwrap_err()
                .to_string(),
            "Inconsistent DB: Cannot deserialize byte sequence as i64: Hit \
             the end of buffer, expected more data. Byte sequence: \
             00000000000000000000000000",
        );
        Ok(())
    }

    #[test]
    fn test_value_group_utxos() -> Result<()> {
        abc_rust_error::install();
        let tempdir = tempdir::TempDir::new("chronik-db--group_history")?;
        let mut cfs = Vec::new();
        GroupUtxoWriter::<ValueGroup>::add_cfs(&mut cfs);
        TxWriter::add_cfs(&mut cfs);
        let db = Db::open_with_cfs(tempdir.path(), cfs)?;
        let tx_writer = TxWriter::new(&db)?;
        let mem_data = RefCell::new(GroupUtxoMemData::default());
        let txs_mem_data = RefCell::new(TxsMemData::default());
        let group_writer = GroupUtxoWriter::new(&db, ValueGroup)?;
        let group_reader = GroupUtxoReader::<ValueGroup>::new(&db)?;

        let block_height = RefCell::new(-1);
        let txs_batch = |txs: &[Tx]| BlockTxs {
            txs: txs
                .iter()
                .map(|tx| TxEntry {
                    txid: tx.txid(),
                    ..Default::default()
                })
                .collect(),
            block_height: *block_height.borrow(),
        };
        let connect_block = |txs: &[Tx]| -> Result<()> {
            let mut batch = WriteBatch::default();
            *block_height.borrow_mut() += 1;
            let first_tx_num = tx_writer.insert(
                &mut batch,
                &txs_batch(txs),
                &mut txs_mem_data.borrow_mut(),
            )?;
            let index_txs = prepare_indexed_txs(&db, first_tx_num, txs)?;
            group_writer.insert(
                &mut batch,
                &index_txs,
                &(),
                &mut mem_data.borrow_mut(),
            )?;
            db.write_batch(batch)?;
            Ok(())
        };
        let disconnect_block = |txs: &[Tx]| -> Result<()> {
            let mut batch = WriteBatch::default();
            let first_tx_num = tx_writer.delete(
                &mut batch,
                &txs_batch(txs),
                &mut txs_mem_data.borrow_mut(),
            )?;
            let index_txs = prepare_indexed_txs(&db, first_tx_num, txs)?;
            group_writer.delete(
                &mut batch,
                &index_txs,
                &(),
                &mut mem_data.borrow_mut(),
            )?;
            db.write_batch(batch)?;
            *block_height.borrow_mut() -= 1;
            Ok(())
        };
        let utxo = |tx_num, out_idx, value| UtxoEntry {
            outpoint: DbOutpoint { tx_num, out_idx },
            data: value,
        };
        let read_utxos = |val: i64| group_reader.utxos(&ser_value(val));

        let block0 =
            vec![make_inputs_tx(0x01, [(0x00, u32::MAX, 0xffff)], [100, 200])];
        connect_block(&block0)?;
        assert_eq!(read_utxos(100)?, Some(vec![utxo(0, 0, 100)]));
        assert_eq!(read_utxos(200)?, Some(vec![utxo(0, 1, 200)]));

        let block1 = vec![
            make_inputs_tx(0x02, [(0x00, u32::MAX, 0xffff)], [200]),
            make_inputs_tx(0x03, [(0x01, 0, 100)], [10, 20, 10]),
            make_inputs_tx(
                0x04,
                [(0x03, 0, 10), (0x01, 1, 200), (0x03, 1, 20)],
                [200],
            ),
        ];
        connect_block(&block1)?;
        assert_eq!(read_utxos(10)?, Some(vec![utxo(2, 2, 10)]));
        assert_eq!(read_utxos(20)?, None);
        assert_eq!(read_utxos(100)?, None);
        assert_eq!(
            read_utxos(200)?,
            Some(vec![utxo(1, 0, 200), utxo(3, 0, 200)]),
        );

        disconnect_block(&block1)?;
        assert_eq!(read_utxos(10)?, None);
        assert_eq!(read_utxos(20)?, None);
        assert_eq!(read_utxos(100)?, Some(vec![utxo(0, 0, 100)]));
        assert_eq!(read_utxos(200)?, Some(vec![utxo(0, 1, 200)]));

        // Reorg block
        let block1 = vec![
            make_inputs_tx(0x02, [(0x00, u32::MAX, 0xffff)], [200]),
            make_inputs_tx(0x10, [(0x01, 0, 100)], [100, 200, 100]),
            make_inputs_tx(
                0x11,
                [(0x10, 0, 100), (0x10, 1, 200), (0x01, 1, 200)],
                [200],
            ),
            make_inputs_tx(0x12, [(0x11, 0, 200)], [200]),
        ];

        connect_block(&block1)?;
        assert_eq!(read_utxos(100)?, Some(vec![utxo(2, 2, 100)]));
        assert_eq!(
            read_utxos(200)?,
            Some(vec![utxo(1, 0, 200), utxo(4, 0, 200)]),
        );

        disconnect_block(&block1)?;
        assert_eq!(read_utxos(100)?, Some(vec![utxo(0, 0, 100)]));
        assert_eq!(read_utxos(200)?, Some(vec![utxo(0, 1, 200)]));

        disconnect_block(&block0)?;
        assert_eq!(read_utxos(100)?, None);
        assert_eq!(read_utxos(200)?, None);

        // Multi-page MDBX_DUPFIXED test (1200 x 20B = 24,000B > 16 KiB page size):
        // verifies MDBX_SEEK_AND_GET_MULTIPLE + MDBX_NEXT_MULTIPLE in utxos(),
        // MDBX_GET_MULTIPLE + MDBX_NEXT_MULTIPLE in prefix_iterator(), and
        // direct exact-match mdbx_del(txn, dbi, &k, &v) on disconnect.
        let big_block = vec![make_inputs_tx(
            0x99,
            [(0x00, u32::MAX, 0xffff)],
            [500i64; 1200],
        )];
        connect_block(&big_block)?;
        let expected_big: Vec<_> =
            (0..1200u32).map(|idx| utxo(0, idx, 500)).collect();
        assert_eq!(read_utxos(500)?, Some(expected_big.clone()));
        let prefix_items: Vec<_> = group_reader
            .prefix_iterator(&[], &[])
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(
            prefix_items,
            vec![(Box::from(ser_value(500)), expected_big)]
        );
        disconnect_block(&big_block)?;
        assert_eq!(read_utxos(500)?, None);

        Ok(())
    }
}
