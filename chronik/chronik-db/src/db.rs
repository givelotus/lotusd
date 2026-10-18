// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Module containing [`Db`] and errors, which encapsulates a database backed
//! by `libmdbx`.
//! Read and write operations should exclusively be done with dedicated writers
//! and readers, such as [`crate::io::BlockWriter`].

#![allow(unsafe_code)]

use std::{
    borrow::Cow,
    collections::{btree_map::Entry, BTreeMap, HashMap},
    ffi::{c_char, c_int, c_uint, c_void, CStr, CString},
    path::Path,
    ptr, slice,
    sync::{Arc, Mutex},
};

use abc_rust_error::Result;
use bitcoinsuite_core::hash::{Hashed, Sha256};
use thiserror::Error;

use crate::{
    groups::{
        LokadIdHistoryWriter, ScriptHistoryWriter, ScriptUtxoWriter,
        TokenIdHistoryWriter, TokenIdUtxoWriter,
    },
    io::{
        token::TokenWriter, BlockStatsWriter, BlockWriter, MetadataWriter,
        SpentByWriter, TxWriter,
    },
    plugins::PluginsWriter,
};

// All column family names used by Chronik should be defined here
/// Column family name for the block data.
pub const CF_BLK: &str = "blk";
/// Column family for the first tx_num of the block. Used to get a list of the
/// txs of the block.
pub const CF_BLK_BY_FIRST_TX: &str = "blk_by_first_tx";
/// Column family for stats about blocks.
pub const CF_BLK_STATS: &str = "blk_stats";
/// Column family for the block height of the first tx_num of that block. Used
/// to get the block height of a tx.
pub const CF_FIRST_TX_BY_BLK: &str = "first_tx_by_blk";
/// Column family to store tx history by LOKAD ID.
pub const CF_LOKAD_ID_HISTORY: &str = "lokad_id_history";
/// Column family to store number of txs by LOKAD ID.
pub const CF_LOKAD_ID_HISTORY_NUM_TXS: &str = "lokad_id_history_num_txs";
/// Column family to lookup a block by its hash.
pub const CF_LOOKUP_BLK_BY_HASH: &str = "lookup_blk_by_hash";
/// Column family to lookup a tx by its hash.
pub const CF_LOOKUP_TX_BY_HASH: &str = "lookup_tx_by_hash";
/// Column family name for db metadata.
pub const CF_META: &str = "meta";
/// Column family to store plugin group UTXOs.
pub const CF_PLUGIN_GROUP_UTXOS: &str = "plugin_utxos";
/// Column family to store tx history by plugin groups.
pub const CF_PLUGIN_HISTORY: &str = "plugin_history";
/// Column family to store number of txs by plugin groups.
pub const CF_PLUGIN_HISTORY_NUM_TXS: &str = "plugin_history_num_txs";
/// Column family to store plugin metadata.
pub const CF_PLUGIN_META: &str = "plugin_meta";
/// Column family to store plugin outputs.
pub const CF_PLUGIN_OUTPUTS: &str = "plugin_outputs";
/// Column family for the scripthash:script index
pub const CF_SCRIPTHASH: &str = "scripthash";
/// Column family to store tx history by script.
pub const CF_SCRIPT_HISTORY: &str = "script_history";
/// Column family to store number of txs by script.
pub const CF_SCRIPT_HISTORY_NUM_TXS: &str = "script_history_num_txs";
/// Column family for utxos by script.
pub const CF_SCRIPT_UTXO: &str = "script_utxo";
/// Column family to store tx history by token ID.
pub const CF_TOKEN_ID_HISTORY: &str = "token_id_history";
/// Column family to store number of txs by token ID.
pub const CF_TOKEN_ID_HISTORY_NUM_TXS: &str = "token_id_history_num_txs";
/// Column family for utxos by token ID.
pub const CF_TOKEN_ID_UTXO: &str = "token_id_utxo";
/// Column family to store which outputs have been spent by which tx inputs.
pub const CF_SPENT_BY: &str = "spent_by";
/// Column family for genesis info by token_tx_num
pub const CF_TOKEN_GENESIS_INFO: &str = "token_genesis_info";
/// Column family for TokenMeta by token_tx_num
pub const CF_TOKEN_META: &str = "token_meta";
/// Column family for token tx data by tx
pub const CF_TOKEN_TX: &str = "token_tx";
/// Column family for the tx data.
pub const CF_TX: &str = "tx";

#[allow(non_camel_case_types, dead_code, unreachable_pub)]
mod ffi {
    use super::*;

    pub enum MDBX_env {}
    pub enum MDBX_txn {}
    pub enum MDBX_cursor {}
    pub type MDBX_dbi = u32;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MDBX_val {
        pub iov_base: *mut c_void,
        pub iov_len: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct MDBX_stat {
        pub ms_psize: u32,
        pub ms_depth: u32,
        pub ms_branch_pages: u64,
        pub ms_leaf_pages: u64,
        pub ms_overflow_pages: u64,
        pub ms_entries: u64,
        pub ms_mod_txnid: u64,
    }

    pub const MDBX_SUCCESS: c_int = 0;
    pub const MDBX_RESULT_TRUE: c_int = -1;
    pub const MDBX_NOTFOUND: c_int = -30798;
    pub const MDBX_ENODATA: c_int = 96; // macOS ENODATA

    // Environment flags
    pub const MDBX_SAFE_NOSYNC: c_uint = 0x10000;
    pub const MDBX_RDONLY: c_uint = 0x20000;
    pub const MDBX_NOMETASYNC: c_uint = 0x40000;
    pub const MDBX_WRITEMAP: c_uint = 0x80000;
    pub const MDBX_UTTERLY_NOSYNC: c_uint = MDBX_SAFE_NOSYNC | 0x100000;
    pub const MDBX_NOSTICKYTHREADS: c_uint = 0x200000;
    pub const MDBX_NOMEMINIT: c_uint = 0x1000000;
    pub const MDBX_LIFORECLAIM: c_uint = 0x4000000;
    pub const MDBX_OPT_SYNC_BYTES: c_uint = 2;
    pub const MDBX_OPT_SYNC_PERIOD: c_uint = 3;

    // Transaction flags
    pub const MDBX_TXN_READWRITE: c_uint = 0;
    pub const MDBX_TXN_RDONLY: c_uint = MDBX_RDONLY;

    // DBI flags
    pub const MDBX_DUPSORT: c_uint = 0x04;
    pub const MDBX_DUPFIXED: c_uint = 0x10;
    pub const MDBX_CREATE: c_uint = 0x40000;

    // Put flags
    pub const MDBX_UPSERT: c_uint = 0;
    pub const MDBX_CURRENT: c_uint = 0x40;

    // Cursor operations
    pub const MDBX_FIRST: c_uint = 0;
    pub const MDBX_FIRST_DUP: c_uint = 1;
    pub const MDBX_GET_BOTH_RANGE: c_uint = 3;
    pub const MDBX_GET_CURRENT: c_uint = 4;
    pub const MDBX_GET_MULTIPLE: c_uint = 5;
    pub const MDBX_LAST: c_uint = 6;
    pub const MDBX_NEXT: c_uint = 8;
    pub const MDBX_NEXT_DUP: c_uint = 9;
    pub const MDBX_NEXT_MULTIPLE: c_uint = 10;
    pub const MDBX_NEXT_NODUP: c_uint = 11;
    pub const MDBX_PREV: c_uint = 12;
    pub const MDBX_SET_KEY: c_uint = 16;
    pub const MDBX_SET_RANGE: c_uint = 17;
    pub const MDBX_TO_KEY_LESSER_OR_EQUAL: c_uint = 22;
    pub const MDBX_SEEK_AND_GET_MULTIPLE: c_uint = 36;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MDBX_batch_kv_op {
        pub key_ptr: *const c_void,
        pub key_len: usize,
        pub val_ptr: *const c_void,
        pub val_len: usize,
        pub is_delete: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct MDBX_batch_dup_op {
        pub key_ptr: *const c_void,
        pub key_len: usize,
        pub val_ptr: *const c_void,
        pub val_len: usize,
        pub op_kind: u32,
    }

    extern "C" {
        pub fn mdbx_strerror(errnum: c_int) -> *const c_char;
        pub fn mdbx_env_create(penv: *mut *mut MDBX_env) -> c_int;
        pub fn mdbx_env_set_maxreaders(
            env: *mut MDBX_env,
            readers: c_uint,
        ) -> c_int;
        pub fn mdbx_env_set_maxdbs(
            env: *mut MDBX_env,
            dbs: MDBX_dbi,
        ) -> c_int;
        pub fn mdbx_env_set_geometry(
            env: *mut MDBX_env,
            size_lower: isize,
            size_now: isize,
            size_upper: isize,
            growth_step: isize,
            shrink_threshold: isize,
            pagesize: isize,
        ) -> c_int;
        pub fn mdbx_env_open(
            env: *mut MDBX_env,
            pathname: *const c_char,
            flags: c_uint,
            mode: c_uint,
        ) -> c_int;
        pub fn mdbx_env_close_ex(
            env: *mut MDBX_env,
            dont_sync: bool,
        ) -> c_int;
        pub fn mdbx_env_sync_ex(
            env: *mut MDBX_env,
            force: bool,
            nonblock: bool,
        ) -> c_int;
        pub fn mdbx_env_set_option(
            env: *mut MDBX_env,
            option: c_uint,
            value: u64,
        ) -> c_int;
        pub fn mdbx_env_get_option(
            env: *const MDBX_env,
            option: c_uint,
            value: *mut u64,
        ) -> c_int;
        pub fn mdbx_env_get_flags(
            env: *const MDBX_env,
            flags: *mut c_uint,
        ) -> c_int;

        pub fn mdbx_txn_begin_ex(
            env: *mut MDBX_env,
            parent: *mut MDBX_txn,
            flags: c_uint,
            txn: *mut *mut MDBX_txn,
            context: *mut c_void,
        ) -> c_int;
        pub fn mdbx_txn_commit_ex(
            txn: *mut MDBX_txn,
            latency: *mut c_void,
        ) -> c_int;
        pub fn mdbx_txn_abort(txn: *mut MDBX_txn) -> c_int;
        pub fn mdbx_txn_reset(txn: *mut MDBX_txn) -> c_int;
        pub fn mdbx_txn_renew(txn: *mut MDBX_txn) -> c_int;

        pub fn mdbx_dbi_open(
            txn: *mut MDBX_txn,
            name: *const c_char,
            flags: c_uint,
            dbi: *mut MDBX_dbi,
        ) -> c_int;
        pub fn mdbx_dbi_stat(
            txn: *const MDBX_txn,
            dbi: MDBX_dbi,
            stat: *mut MDBX_stat,
            bytes: usize,
        ) -> c_int;

        pub fn mdbx_get(
            txn: *const MDBX_txn,
            dbi: MDBX_dbi,
            key: *const MDBX_val,
            data: *mut MDBX_val,
        ) -> c_int;
        pub fn mdbx_put(
            txn: *mut MDBX_txn,
            dbi: MDBX_dbi,
            key: *const MDBX_val,
            data: *mut MDBX_val,
            flags: c_uint,
        ) -> c_int;
        pub fn mdbx_del(
            txn: *mut MDBX_txn,
            dbi: MDBX_dbi,
            key: *const MDBX_val,
            data: *const MDBX_val,
        ) -> c_int;
        pub fn mdbx_drop(
            txn: *mut MDBX_txn,
            dbi: MDBX_dbi,
            del: bool,
        ) -> c_int;

        pub fn mdbx_cursor_create(context: *mut c_void) -> *mut MDBX_cursor;
        pub fn mdbx_cursor_bind(
            txn: *mut MDBX_txn,
            cursor: *mut MDBX_cursor,
            dbi: MDBX_dbi,
        ) -> c_int;
        pub fn mdbx_cursor_unbind(cursor: *mut MDBX_cursor) -> c_int;
        pub fn mdbx_cursor_open(
            txn: *const MDBX_txn,
            dbi: MDBX_dbi,
            cursor: *mut *mut MDBX_cursor,
        ) -> c_int;
        pub fn mdbx_cursor_close(cursor: *mut MDBX_cursor);
        pub fn mdbx_cursor_get(
            cursor: *mut MDBX_cursor,
            key: *mut MDBX_val,
            data: *mut MDBX_val,
            op: c_uint,
        ) -> c_int;
        pub fn mdbx_cursor_put(
            cursor: *mut MDBX_cursor,
            key: *const MDBX_val,
            data: *mut MDBX_val,
            flags: c_uint,
        ) -> c_int;
        pub fn mdbx_cursor_del(
            cursor: *mut MDBX_cursor,
            flags: c_uint,
        ) -> c_int;
        pub fn mdbx_cursor_count(
            cursor: *const MDBX_cursor,
            count: *mut usize,
        ) -> c_int;

        pub fn mdbx_batch_kv_apply(
            txn: *mut MDBX_txn,
            dbi: MDBX_dbi,
            ops: *const MDBX_batch_kv_op,
            n_ops: usize,
        ) -> c_int;
        pub fn mdbx_batch_dup_apply(
            txn: *mut MDBX_txn,
            dbi: MDBX_dbi,
            ops: *const MDBX_batch_dup_op,
            n_ops: usize,
        ) -> c_int;
        pub fn mdbx_batch_multi_get(
            txn: *mut MDBX_txn,
            dbi: MDBX_dbi,
            keys: *const MDBX_val,
            vals_out: *mut MDBX_val,
            rcs_out: *mut c_int,
            n_keys: usize,
        ) -> c_int;
        pub fn mdbx_dupfixed_get_pages(
            cursor: *mut MDBX_cursor,
            key: *const MDBX_val,
            elem_size: usize,
            pages_out: *mut MDBX_val,
            max_pages: usize,
            n_pages_out: *mut usize,
        ) -> c_int;
        pub fn mdbx_dupfixed_get_current_pages(
            cursor: *mut MDBX_cursor,
            elem_size: usize,
            pages_out: *mut MDBX_val,
            max_pages: usize,
            n_pages_out: *mut usize,
        ) -> c_int;
    }
}

const MAX_INLINE_KEY_LEN: usize = 7500;
const HASHED_KEY_PREFIX: &[u8] = b"MDBX_SHA256_KEY:";

fn normalize_key(key: &[u8]) -> Cow<'_, [u8]> {
    if key.len() <= MAX_INLINE_KEY_LEN {
        Cow::Borrowed(key)
    } else {
        let digest = Sha256::digest(key);
        let mut out =
            Vec::with_capacity(HASHED_KEY_PREFIX.len() + digest.as_ref().len());
        out.extend_from_slice(HASHED_KEY_PREFIX);
        out.extend_from_slice(digest.as_ref());
        Cow::Owned(out)
    }
}

fn mdbx_err(rc: c_int, context: &str) -> DbError {
    let msg = unsafe {
        let ptr = ffi::mdbx_strerror(rc);
        if ptr.is_null() {
            "unknown mdbx error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    DbError::RocksDb(Error {
        message: format!("{context}: [{rc}] {msg}"),
    })
}

/// Compaction filter decision compatibility module.
pub mod compaction_filter {
    /// Whether to keep or remove a key-value entry after merge/compaction.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Decision {
        /// Keep the entry in the database.
        Keep,
        /// Remove the entry from the database.
        Remove,
    }
}

/// Sequence of merge operands passed to a column family merge operator.
#[derive(Clone, Debug, Default)]
pub struct MergeOperands {
    operands: Vec<Vec<u8>>,
}

impl MergeOperands {
    /// Iterator over the merge operand byte slices.
    pub fn iter(&self) -> MergeOperandsIter<'_> {
        MergeOperandsIter {
            inner: self.operands.iter(),
        }
    }

    /// Number of merge operands.
    pub fn len(&self) -> usize {
        self.operands.len()
    }

    /// Whether there are no merge operands.
    pub fn is_empty(&self) -> bool {
        self.operands.is_empty()
    }
}

/// Iterator over [`MergeOperands`].
#[derive(Debug)]
pub struct MergeOperandsIter<'a> {
    inner: std::slice::Iter<'a, Vec<u8>>,
}

impl<'a> Iterator for MergeOperandsIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Vec::as_slice)
    }
}

impl<'a> IntoIterator for &'a MergeOperands {
    type IntoIter = MergeOperandsIter<'a>;
    type Item = &'a [u8];

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

type FullMergeFn = Arc<
    dyn Fn(&[u8], Option<&[u8]>, &MergeOperands) -> Option<Vec<u8>>
        + Send
        + Sync,
>;
type CompactionFilterFn =
    Box<dyn Fn(u32, &[u8], &[u8]) -> compaction_filter::Decision + Send + Sync>;

/// Column family configuration options.
#[derive(Default)]
pub struct Options {
    full_merge: Option<FullMergeFn>,
    compaction_filter: Option<CompactionFilterFn>,
    dupsort: bool,
    dupfixed: bool,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("has_merge", &self.full_merge.is_some())
            .field("has_compaction_filter", &self.compaction_filter.is_some())
            .field("dupsort", &self.dupsort)
            .field("dupfixed", &self.dupfixed)
            .finish()
    }
}

impl Options {
    /// Configure this column family to use native `MDBX_DUPSORT` (and optionally
    /// `MDBX_DUPFIXED` when duplicate values have a constant byte size).
    pub fn set_dupsort(&mut self, dupfixed: bool) {
        self.dupsort = true;
        self.dupfixed = dupfixed;
    }

    /// Register a merge operator for this column family.
    pub fn set_merge_operator<F, P>(
        &mut self,
        _name: &str,
        full_merge_fn: F,
        _partial_merge_fn: P,
    ) where
        F: Fn(&[u8], Option<&[u8]>, &MergeOperands) -> Option<Vec<u8>>
            + Send
            + Sync
            + 'static,
        P: Fn(&[u8], Option<&[u8]>, &MergeOperands) -> Option<Vec<u8>>
            + Send
            + Sync
            + 'static,
    {
        self.full_merge = Some(Arc::new(full_merge_fn));
    }

    /// Register a compaction filter for this column family.
    pub fn set_compaction_filter<F>(&mut self, _name: &str, filter_fn: F)
    where
        F: Fn(u32, &[u8], &[u8]) -> compaction_filter::Decision
            + Send
            + Sync
            + 'static,
    {
        self.compaction_filter = Some(Box::new(filter_fn));
    }
}

/// Descriptor for opening/creating a named subdatabase (`MDBX_dbi`) in `libmdbx`.
#[derive(Debug)]
pub struct ColumnFamilyDescriptor {
    name: String,
    options: Options,
}

impl ColumnFamilyDescriptor {
    /// Create a new [`ColumnFamilyDescriptor`].
    pub fn new(name: impl Into<String>, options: Options) -> Self {
        ColumnFamilyDescriptor {
            name: name.into(),
            options,
        }
    }

    /// Name of the column family.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Handle to a named subdatabase (`MDBX_dbi`) and its associated merge/filter
/// callbacks.
#[derive(Debug)]
pub struct ColumnFamily {
    name: String,
    dbi: ffi::MDBX_dbi,
    options: Options,
}

pub(crate) type CF = ColumnFamily;

/// Direction for cursor iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Iterate in ascending key order.
    Forward,
    /// Iterate in descending key order.
    Reverse,
}

/// Starting mode for cursor iteration.
#[derive(Clone, Copy, Debug)]
pub enum IteratorMode<'a> {
    /// Start at the first key in the subdatabase.
    Start,
    /// Start at the last key in the subdatabase and iterate backwards.
    End,
    /// Start at `start` in the given `Direction`.
    From(&'a [u8], Direction),
}

#[derive(Clone, Debug)]
enum KeyOp {
    Put(Vec<u8>),
    Delete,
    Merge {
        base: Option<Option<Vec<u8>>>,
        operands: Vec<Vec<u8>>,
    },
}

#[derive(Clone, Debug)]
enum DupOp {
    Put12([u8; 12]),
    Put(Vec<u8>),
    Delete { fixed_dup_size: Option<usize> },
}

#[derive(Clone, Debug, Default)]
struct CfBatch {
    delete_ranges: Vec<(Vec<u8>, Vec<u8>)>,
    key_ops: BTreeMap<Vec<u8>, KeyOp>,
    dup_ops: BTreeMap<Vec<u8>, BTreeMap<[u8; 12], DupOp>>,
}

/// Atomic batch of writes (`put`, `delete`, `merge`, `delete_range`) across
/// column families.
#[derive(Clone, Debug, Default)]
pub struct WriteBatch {
    cf_batches: BTreeMap<ffi::MDBX_dbi, CfBatch>,
}

impl WriteBatch {
    /// Insert or overwrite `key -> value` in `cf`.
    pub fn put_cf(
        &mut self,
        cf: &CF,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) {
        let norm_key = normalize_key(key.as_ref()).into_owned();
        let cf_batch = self.cf_batches.entry(cf.dbi).or_default();
        cf_batch
            .key_ops
            .insert(norm_key, KeyOp::Put(value.as_ref().to_vec()));
    }

    /// Delete `key` from `cf`.
    pub fn delete_cf(&mut self, cf: &CF, key: impl AsRef<[u8]>) {
        let norm_key = normalize_key(key.as_ref()).into_owned();
        let cf_batch = self.cf_batches.entry(cf.dbi).or_default();
        cf_batch.key_ops.insert(norm_key, KeyOp::Delete);
    }

    /// Insert a 12-byte fixed-size duplicate value (`(tx_num, out_idx)`) under
    /// `key` in a `MDBX_DUPSORT | MDBX_DUPFIXED` column family without heap
    /// allocation.
    pub fn put_dup12_cf(
        &mut self,
        cf: &CF,
        key: impl AsRef<[u8]>,
        dup_val_12: [u8; 12],
    ) {
        let norm_key = normalize_key(key.as_ref()).into_owned();
        let cf_batch = self.cf_batches.entry(cf.dbi).or_default();
        cf_batch
            .dup_ops
            .entry(norm_key)
            .or_default()
            .insert(dup_val_12, DupOp::Put12(dup_val_12));
    }

    /// Insert a sorted duplicate value (`dup_val`, whose first 12 bytes are the
    /// big-endian `(tx_num, out_idx)` outpoint prefix) under `key` in a
    /// `MDBX_DUPSORT` column family.
    pub fn put_dup_cf(
        &mut self,
        cf: &CF,
        key: impl AsRef<[u8]>,
        dup_val: Vec<u8>,
    ) {
        let norm_key = normalize_key(key.as_ref()).into_owned();
        let prefix: [u8; 12] = dup_val[..12]
            .try_into()
            .expect("dup_val must be >= 12 bytes");
        let cf_batch = self.cf_batches.entry(cf.dbi).or_default();
        cf_batch
            .dup_ops
            .entry(norm_key)
            .or_default()
            .insert(prefix, DupOp::Put(dup_val));
    }

    /// Delete the duplicate value starting with `prefix_12` under `key` in a
    /// `MDBX_DUPSORT` column family.
    pub fn delete_dup_prefix_cf(
        &mut self,
        cf: &CF,
        key: impl AsRef<[u8]>,
        prefix_12: [u8; 12],
        fixed_dup_size: Option<usize>,
    ) {
        let norm_key = normalize_key(key.as_ref()).into_owned();
        let cf_batch = self.cf_batches.entry(cf.dbi).or_default();
        let key_map = cf_batch.dup_ops.entry(norm_key).or_default();
        match key_map.entry(prefix_12) {
            Entry::Occupied(e) => {
                if matches!(e.get(), DupOp::Put12(_) | DupOp::Put(_)) {
                    // Created and spent within the same WriteBatch: cancel the
                    // pending Put without touching the B+Tree.
                    e.remove();
                }
            }
            Entry::Vacant(e) => {
                e.insert(DupOp::Delete { fixed_dup_size });
            }
        }
    }

    /// Queue a merge operand on `key` in `cf`.
    pub fn merge_cf(
        &mut self,
        cf: &CF,
        key: impl AsRef<[u8]>,
        operand: impl AsRef<[u8]>,
    ) {
        let norm_key = normalize_key(key.as_ref()).into_owned();
        let op_bytes = operand.as_ref().to_vec();
        let cf_batch = self.cf_batches.entry(cf.dbi).or_default();
        match cf_batch.key_ops.entry(norm_key) {
            Entry::Vacant(e) => {
                e.insert(KeyOp::Merge {
                    base: None,
                    operands: vec![op_bytes],
                });
            }
            Entry::Occupied(mut e) => match e.get_mut() {
                KeyOp::Put(prev_val) => {
                    let base_val = std::mem::take(prev_val);
                    *e.into_mut() = KeyOp::Merge {
                        base: Some(Some(base_val)),
                        operands: vec![op_bytes],
                    };
                }
                KeyOp::Delete => {
                    *e.into_mut() = KeyOp::Merge {
                        base: Some(None),
                        operands: vec![op_bytes],
                    };
                }
                KeyOp::Merge { operands, .. } => {
                    operands.push(op_bytes);
                }
            },
        }
    }

    /// Delete all keys in `[from, to)` from `cf`.
    pub fn delete_range_cf<K: AsRef<[u8]>>(
        &mut self,
        cf: &CF,
        from: K,
        to: K,
    ) {
        let from_ref = from.as_ref();
        let to_ref = to.as_ref();
        let cf_batch = self.cf_batches.entry(cf.dbi).or_default();
        cf_batch
            .key_ops
            .retain(|k, _| k.as_slice() < from_ref || k.as_slice() >= to_ref);
        cf_batch
            .dup_ops
            .retain(|k, _| k.as_slice() < from_ref || k.as_slice() >= to_ref);
        cf_batch
            .delete_ranges
            .push((from_ref.to_vec(), to_ref.to_vec()));
    }
}

/// Compatibility helper for `DB::destroy`.
#[derive(Debug)]
pub struct DB;

impl DB {
    /// Destroy the database files at `path`.
    pub fn destroy(_options: &Options, path: impl AsRef<Path>) -> Result<()> {
        Db::destroy(path)
    }
}

/// Underlying storage error message wrapper.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct Error {
    message: String,
}

#[derive(Default)]
struct ReadPool {
    txns: Vec<*mut ffi::MDBX_txn>,
    cursors: Vec<*mut ffi::MDBX_cursor>,
}

/// Indexer database backed by `libmdbx`.
pub struct Db {
    env: *mut ffi::MDBX_env,
    cfs: HashMap<String, ColumnFamily>,
    cf_by_dbi: HashMap<ffi::MDBX_dbi, String>,
    cf_names: Vec<String>,
    read_pool: Mutex<ReadPool>,
}

unsafe impl Send for Db {}
unsafe impl Sync for Db {}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("cf_names", &self.cf_names)
            .finish()
    }
}

/// Errors indicating something went wrong with the database itself.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DbError {
    /// Legacy index data must not be replaced by an empty MDBX database.
    #[error("Existing RocksDB index at {0}; automatic MDBX migration is unsupported. Existing files were left untouched. Stop the node, move the entire reported Chronik index directory to a backup outside the datadir, and restart with -chronik=1 -chronikreindex=1 to rebuild from block files. Do not remove chainstate or blocks; retain unpruned block files or resync the chain if historical blocks are unavailable.")]
    LegacyRocksDb(String),

    /// Column family requested but not defined during `Db::open`.
    #[error("Column family {0} doesn't exist")]
    NoSuchColumnFamily(String),

    /// Error with the underlying storage engine.
    #[error("libmdbx error: {0}")]
    RocksDb(Error),
}

use self::DbError::*;

type DbIterItem = Result<(Box<[u8]>, Box<[u8]>)>;

struct DbIter<'a> {
    db: &'a Db,
    txn: *mut ffi::MDBX_txn,
    cursor: *mut ffi::MDBX_cursor,
    next_op: c_uint,
    first_item: Option<DbIterItem>,
    done: bool,
}

impl<'a> DbIter<'a> {
    fn new(db: &'a Db, dbi: ffi::MDBX_dbi, mode: IteratorMode<'_>) -> Self {
        unsafe {
            let txn = match db.acquire_read_txn() {
                Ok(t) => t,
                Err(err) => {
                    return DbIter {
                        db,
                        txn: ptr::null_mut(),
                        cursor: ptr::null_mut(),
                        next_op: ffi::MDBX_NEXT,
                        first_item: Some(Err(err.into())),
                        done: true,
                    };
                }
            };

            let cursor = match db.acquire_read_cursor(txn, dbi) {
                Ok(c) => c,
                Err(err) => {
                    db.release_read_txn(txn);
                    return DbIter {
                        db,
                        txn: ptr::null_mut(),
                        cursor: ptr::null_mut(),
                        next_op: ffi::MDBX_NEXT,
                        first_item: Some(Err(err.into())),
                        done: true,
                    };
                }
            };

            let mut k = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            let mut v = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };

            let (rc, next_op) = match mode {
                IteratorMode::Start => (
                    ffi::mdbx_cursor_get(
                        cursor,
                        &mut k,
                        &mut v,
                        ffi::MDBX_FIRST,
                    ),
                    ffi::MDBX_NEXT,
                ),
                IteratorMode::End => (
                    ffi::mdbx_cursor_get(
                        cursor,
                        &mut k,
                        &mut v,
                        ffi::MDBX_LAST,
                    ),
                    ffi::MDBX_PREV,
                ),
                IteratorMode::From(start, Direction::Forward) => {
                    if start.is_empty() {
                        (
                            ffi::mdbx_cursor_get(
                                cursor,
                                &mut k,
                                &mut v,
                                ffi::MDBX_FIRST,
                            ),
                            ffi::MDBX_NEXT,
                        )
                    } else {
                        let norm = normalize_key(start);
                        k.iov_base = norm.as_ptr() as *mut c_void;
                        k.iov_len = norm.len();
                        (
                            ffi::mdbx_cursor_get(
                                cursor,
                                &mut k,
                                &mut v,
                                ffi::MDBX_SET_RANGE,
                            ),
                            ffi::MDBX_NEXT,
                        )
                    }
                }
                IteratorMode::From(start, Direction::Reverse) => {
                    let norm = normalize_key(start);
                    k.iov_base = norm.as_ptr() as *mut c_void;
                    k.iov_len = norm.len();
                    (
                        ffi::mdbx_cursor_get(
                            cursor,
                            &mut k,
                            &mut v,
                            ffi::MDBX_TO_KEY_LESSER_OR_EQUAL,
                        ),
                        ffi::MDBX_PREV,
                    )
                }
            };

            if rc == ffi::MDBX_SUCCESS || rc == ffi::MDBX_RESULT_TRUE {
                let item = Self::extract_kv(k, v);
                DbIter {
                    db,
                    txn,
                    cursor,
                    next_op,
                    first_item: Some(Ok(item)),
                    done: false,
                }
            } else {
                db.release_read_cursor(cursor);
                db.release_read_txn(txn);
                let first_item =
                    if rc != ffi::MDBX_NOTFOUND && rc != ffi::MDBX_ENODATA {
                        Some(Err(mdbx_err(rc, "mdbx_cursor_get").into()))
                    } else {
                        None
                    };
                DbIter {
                    db,
                    txn: ptr::null_mut(),
                    cursor: ptr::null_mut(),
                    next_op,
                    first_item,
                    done: true,
                }
            }
        }
    }

    #[inline]
    unsafe fn extract_kv(
        k: ffi::MDBX_val,
        v: ffi::MDBX_val,
    ) -> (Box<[u8]>, Box<[u8]>) {
        let k_slice = if k.iov_len == 0 {
            &[]
        } else {
            slice::from_raw_parts(k.iov_base as *const u8, k.iov_len)
        };
        let v_slice = if v.iov_len == 0 {
            &[]
        } else {
            slice::from_raw_parts(v.iov_base as *const u8, v.iov_len)
        };
        (Box::from(k_slice), Box::from(v_slice))
    }

    unsafe fn close_handles(&mut self) {
        if !self.cursor.is_null() {
            self.db.release_read_cursor(self.cursor);
            self.cursor = ptr::null_mut();
        }
        if !self.txn.is_null() {
            self.db.release_read_txn(self.txn);
            self.txn = ptr::null_mut();
        }
    }
}

impl Iterator for DbIter<'_> {
    type Item = DbIterItem;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first) = self.first_item.take() {
            return Some(first);
        }
        if self.done {
            return None;
        }
        unsafe {
            let mut k = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            let mut v = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            let rc =
                ffi::mdbx_cursor_get(self.cursor, &mut k, &mut v, self.next_op);
            if rc == ffi::MDBX_SUCCESS || rc == ffi::MDBX_RESULT_TRUE {
                Some(Ok(Self::extract_kv(k, v)))
            } else {
                self.done = true;
                self.close_handles();
                if rc != ffi::MDBX_NOTFOUND && rc != ffi::MDBX_ENODATA {
                    Some(Err(mdbx_err(rc, "mdbx_cursor_get").into()))
                } else {
                    None
                }
            }
        }
    }
}

impl Drop for DbIter<'_> {
    fn drop(&mut self) {
        unsafe {
            self.close_handles();
        }
    }
}

struct DupPrefixIter<'a, T, F> {
    db: &'a Db,
    txn: *mut ffi::MDBX_txn,
    cursor: *mut ffi::MDBX_cursor,
    prefix: &'a [u8],
    fixed_dup_size: Option<usize>,
    decode_fn: F,
    first_step: bool,
    init_err: Option<DbError>,
    done: bool,
    _marker: std::marker::PhantomData<T>,
}

impl<'a, T, F> DupPrefixIter<'a, T, F> {
    fn new(
        db: &'a Db,
        dbi: ffi::MDBX_dbi,
        prefix: &'a [u8],
        start: &[u8],
        fixed_dup_size: Option<usize>,
        decode_fn: F,
    ) -> Self {
        unsafe {
            let txn = match db.acquire_read_txn() {
                Ok(t) => t,
                Err(err) => {
                    return DupPrefixIter {
                        db,
                        txn: ptr::null_mut(),
                        cursor: ptr::null_mut(),
                        prefix,
                        fixed_dup_size,
                        decode_fn,
                        first_step: false,
                        init_err: Some(err),
                        done: true,
                        _marker: std::marker::PhantomData,
                    };
                }
            };

            let cursor = match db.acquire_read_cursor(txn, dbi) {
                Ok(c) => c,
                Err(err) => {
                    db.release_read_txn(txn);
                    return DupPrefixIter {
                        db,
                        txn: ptr::null_mut(),
                        cursor: ptr::null_mut(),
                        prefix,
                        fixed_dup_size,
                        decode_fn,
                        first_step: false,
                        init_err: Some(err),
                        done: true,
                        _marker: std::marker::PhantomData,
                    };
                }
            };

            let mut k = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            let mut v = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };

            let rc = if start.is_empty() {
                ffi::mdbx_cursor_get(cursor, &mut k, &mut v, ffi::MDBX_FIRST)
            } else {
                let norm = normalize_key(start);
                k.iov_base = norm.as_ptr() as *mut c_void;
                k.iov_len = norm.len();
                ffi::mdbx_cursor_get(
                    cursor,
                    &mut k,
                    &mut v,
                    ffi::MDBX_SET_RANGE,
                )
            };

            if rc == ffi::MDBX_SUCCESS || rc == ffi::MDBX_RESULT_TRUE {
                DupPrefixIter {
                    db,
                    txn,
                    cursor,
                    prefix,
                    fixed_dup_size,
                    decode_fn,
                    first_step: true,
                    init_err: None,
                    done: false,
                    _marker: std::marker::PhantomData,
                }
            } else {
                db.release_read_cursor(cursor);
                db.release_read_txn(txn);
                let init_err =
                    if rc != ffi::MDBX_NOTFOUND && rc != ffi::MDBX_ENODATA {
                        Some(mdbx_err(rc, "mdbx_cursor_get(dup_prefix_init)"))
                    } else {
                        None
                    };
                DupPrefixIter {
                    db,
                    txn: ptr::null_mut(),
                    cursor: ptr::null_mut(),
                    prefix,
                    fixed_dup_size,
                    decode_fn,
                    first_step: false,
                    init_err,
                    done: true,
                    _marker: std::marker::PhantomData,
                }
            }
        }
    }

    unsafe fn close_handles(&mut self) {
        if !self.cursor.is_null() {
            self.db.release_read_cursor(self.cursor);
            self.cursor = ptr::null_mut();
        }
        if !self.txn.is_null() {
            self.db.release_read_txn(self.txn);
            self.txn = ptr::null_mut();
        }
    }
}

impl<T, F> Iterator for DupPrefixIter<'_, T, F>
where
    F: FnMut(&[u8]) -> Result<T>,
{
    type Item = Result<(Box<[u8]>, Vec<T>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(err) = self.init_err.take() {
            return Some(Err(err.into()));
        }
        if self.done {
            return None;
        }
        unsafe {
            let mut k = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            let mut v = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            let op = if self.first_step {
                self.first_step = false;
                ffi::MDBX_GET_CURRENT
            } else {
                ffi::MDBX_NEXT_NODUP
            };
            let mut rc = ffi::mdbx_cursor_get(self.cursor, &mut k, &mut v, op);
            if rc != ffi::MDBX_SUCCESS && rc != ffi::MDBX_RESULT_TRUE {
                self.done = true;
                self.close_handles();
                if rc != ffi::MDBX_NOTFOUND && rc != ffi::MDBX_ENODATA {
                    return Some(Err(
                        mdbx_err(rc, "mdbx_cursor_get(NEXT_NODUP)").into(),
                    ));
                }
                return None;
            }

            let k_slice = if k.iov_len == 0 {
                &[]
            } else {
                slice::from_raw_parts(k.iov_base as *const u8, k.iov_len)
            };
            if !k_slice.starts_with(self.prefix) {
                self.done = true;
                self.close_handles();
                return None;
            }
            let key_box = Box::from(k_slice);

            if let Some(elem_size) = self.fixed_dup_size {
                let mut pages = [ffi::MDBX_val {
                    iov_base: ptr::null_mut(),
                    iov_len: 0,
                }; 32];
                let mut n_pages: usize = 0;
                rc = ffi::mdbx_dupfixed_get_current_pages(
                    self.cursor,
                    elem_size,
                    pages.as_mut_ptr(),
                    pages.len(),
                    &mut n_pages,
                );
                if rc != ffi::MDBX_SUCCESS && rc != ffi::MDBX_RESULT_TRUE {
                    self.done = true;
                    self.close_handles();
                    return Some(Err(mdbx_err(
                        rc,
                        "mdbx_dupfixed_get_current_pages",
                    )
                    .into()));
                }
                let total_elems: usize = pages[..n_pages]
                    .iter()
                    .map(|p| p.iov_len / elem_size)
                    .sum();
                let mut items = Vec::with_capacity(total_elems);
                for page in &pages[..n_pages] {
                    let page_slice = slice::from_raw_parts(
                        page.iov_base as *const u8,
                        page.iov_len,
                    );
                    for chunk in page_slice.chunks_exact(elem_size) {
                        match (self.decode_fn)(chunk) {
                            Ok(item) => items.push(item),
                            Err(err) => {
                                self.done = true;
                                self.close_handles();
                                return Some(Err(err));
                            }
                        }
                    }
                }
                while rc == ffi::MDBX_RESULT_TRUE {
                    rc = ffi::mdbx_cursor_get(
                        self.cursor,
                        &mut k,
                        &mut v,
                        ffi::MDBX_NEXT_MULTIPLE,
                    );
                    if rc == ffi::MDBX_NOTFOUND || rc == ffi::MDBX_ENODATA {
                        break;
                    }
                    if rc != ffi::MDBX_SUCCESS && rc != ffi::MDBX_RESULT_TRUE {
                        self.done = true;
                        self.close_handles();
                        return Some(Err(mdbx_err(
                            rc,
                            "mdbx_cursor_get(NEXT_MULTIPLE)",
                        )
                        .into()));
                    }
                    let page_slice = slice::from_raw_parts(
                        v.iov_base as *const u8,
                        v.iov_len,
                    );
                    for chunk in page_slice.chunks_exact(elem_size) {
                        match (self.decode_fn)(chunk) {
                            Ok(item) => items.push(item),
                            Err(err) => {
                                self.done = true;
                                self.close_handles();
                                return Some(Err(err));
                            }
                        }
                    }
                    rc = ffi::MDBX_RESULT_TRUE;
                }
                return Some(Ok((key_box, items)));
            }

            let mut count: usize = 0;
            let _ = ffi::mdbx_cursor_count(self.cursor, &mut count);
            let mut items = Vec::with_capacity(count.max(1));

            while rc == ffi::MDBX_SUCCESS || rc == ffi::MDBX_RESULT_TRUE {
                let v_slice = if v.iov_len == 0 {
                    &[]
                } else {
                    slice::from_raw_parts(v.iov_base as *const u8, v.iov_len)
                };
                match (self.decode_fn)(v_slice) {
                    Ok(item) => items.push(item),
                    Err(err) => {
                        self.done = true;
                        self.close_handles();
                        return Some(Err(err));
                    }
                }
                rc = ffi::mdbx_cursor_get(
                    self.cursor,
                    &mut k,
                    &mut v,
                    ffi::MDBX_NEXT_DUP,
                );
            }
            if rc != ffi::MDBX_NOTFOUND && rc != ffi::MDBX_ENODATA {
                self.done = true;
                self.close_handles();
                return Some(Err(
                    mdbx_err(rc, "mdbx_cursor_get(NEXT_DUP)").into(),
                ));
            }
            Some(Ok((key_box, items)))
        }
    }
}

impl<T, F> Drop for DupPrefixIter<'_, T, F> {
    fn drop(&mut self) {
        unsafe {
            self.close_handles();
        }
    }
}

impl Db {
    unsafe fn acquire_read_txn(
        &self,
    ) -> std::result::Result<*mut ffi::MDBX_txn, DbError> {
        if let Ok(mut pool) = self.read_pool.lock() {
            if let Some(txn) = pool.txns.pop() {
                drop(pool);
                let rc = ffi::mdbx_txn_renew(txn);
                if rc == ffi::MDBX_SUCCESS {
                    return Ok(txn);
                }
                ffi::mdbx_txn_abort(txn);
                return Err(mdbx_err(rc, "mdbx_txn_renew"));
            }
        }
        let mut txn: *mut ffi::MDBX_txn = ptr::null_mut();
        let rc = ffi::mdbx_txn_begin_ex(
            self.env,
            ptr::null_mut(),
            ffi::MDBX_TXN_RDONLY,
            &mut txn,
            ptr::null_mut(),
        );
        if rc != ffi::MDBX_SUCCESS {
            return Err(mdbx_err(rc, "mdbx_txn_begin_ex(read)"));
        }
        Ok(txn)
    }

    unsafe fn release_read_txn(&self, txn: *mut ffi::MDBX_txn) {
        if txn.is_null() {
            return;
        }
        if ffi::mdbx_txn_reset(txn) != ffi::MDBX_SUCCESS {
            ffi::mdbx_txn_abort(txn);
            return;
        }
        if let Ok(mut pool) = self.read_pool.lock() {
            if pool.txns.len() < 64 {
                pool.txns.push(txn);
                return;
            }
        }
        ffi::mdbx_txn_abort(txn);
    }

    unsafe fn acquire_read_cursor(
        &self,
        txn: *mut ffi::MDBX_txn,
        dbi: ffi::MDBX_dbi,
    ) -> std::result::Result<*mut ffi::MDBX_cursor, DbError> {
        let mut cursor = ptr::null_mut();
        if let Ok(mut pool) = self.read_pool.lock() {
            if let Some(c) = pool.cursors.pop() {
                cursor = c;
            }
        }
        if cursor.is_null() {
            cursor = ffi::mdbx_cursor_create(ptr::null_mut());
            if cursor.is_null() {
                return Err(mdbx_err(-12, "mdbx_cursor_create"));
            }
        }
        let rc = ffi::mdbx_cursor_bind(txn, cursor, dbi);
        if rc != ffi::MDBX_SUCCESS {
            ffi::mdbx_cursor_close(cursor);
            return Err(mdbx_err(rc, "mdbx_cursor_bind"));
        }
        Ok(cursor)
    }

    unsafe fn release_read_cursor(&self, cursor: *mut ffi::MDBX_cursor) {
        if cursor.is_null() {
            return;
        }
        if ffi::mdbx_cursor_unbind(cursor) != ffi::MDBX_SUCCESS {
            ffi::mdbx_cursor_close(cursor);
            return;
        }
        if let Ok(mut pool) = self.read_pool.lock() {
            if pool.cursors.len() < 64 {
                pool.cursors.push(cursor);
                return;
            }
        }
        ffi::mdbx_cursor_close(cursor);
    }

    /// Opens the database under the specified path.
    /// Creates the database file and necessary column families if necessary.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut cfs = Vec::new();
        BlockWriter::add_cfs(&mut cfs);
        BlockStatsWriter::add_cfs(&mut cfs);
        MetadataWriter::add_cfs(&mut cfs);
        TxWriter::add_cfs(&mut cfs);
        ScriptHistoryWriter::add_cfs(&mut cfs);
        ScriptUtxoWriter::add_cfs(&mut cfs);
        SpentByWriter::add_cfs(&mut cfs);
        TokenWriter::add_cfs(&mut cfs);
        TokenIdHistoryWriter::add_cfs(&mut cfs);
        TokenIdUtxoWriter::add_cfs(&mut cfs);
        LokadIdHistoryWriter::add_cfs(&mut cfs);
        PluginsWriter::add_cfs(&mut cfs);
        Self::open_with_cfs(path, cfs)
    }

    pub(crate) fn open_with_cfs(
        path: impl AsRef<Path>,
        cfs: Vec<ColumnFamilyDescriptor>,
    ) -> Result<Self> {
        let path_ref = path.as_ref();
        // The historical migration stub moved files without importing any
        // keys. Refuse legacy or partially backed-up indexes before creating
        // MDBX files; migration/reindexing must be an explicit separate step.
        if path_ref.try_exists()? {
            for entry in std::fs::read_dir(path_ref)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if matches!(
                    name.as_ref(),
                    "CURRENT" | "IDENTITY" | "rocksdb.bak"
                ) || name.starts_with("MANIFEST-")
                    || name.starts_with("OPTIONS-")
                    || name.ends_with(".sst")
                {
                    return Err(
                        LegacyRocksDb(path_ref.display().to_string()).into()
                    );
                }
            }
        }
        std::fs::create_dir_all(path_ref).map_err(|err| {
            RocksDb(Error {
                message: format!(
                    "Failed to create DB directory {}: {err}",
                    path_ref.display()
                ),
            })
        })?;

        let path_cstr = CString::new(path_ref.to_string_lossy().as_bytes())
            .map_err(|err| {
                RocksDb(Error {
                    message: format!("Invalid DB path: {err}"),
                })
            })?;

        unsafe {
            let mut env: *mut ffi::MDBX_env = ptr::null_mut();
            let mut rc = ffi::mdbx_env_create(&mut env);
            if rc != ffi::MDBX_SUCCESS {
                return Err(mdbx_err(rc, "mdbx_env_create").into());
            }

            rc = ffi::mdbx_env_set_maxreaders(env, 256);
            if rc != ffi::MDBX_SUCCESS {
                ffi::mdbx_env_close_ex(env, true);
                return Err(mdbx_err(rc, "mdbx_env_set_maxreaders").into());
            }

            let max_dbs = (cfs.len() as u32 + 16).max(64);
            rc = ffi::mdbx_env_set_maxdbs(env, max_dbs);
            if rc != ffi::MDBX_SUCCESS {
                ffi::mdbx_env_close_ex(env, true);
                return Err(mdbx_err(rc, "mdbx_env_set_maxdbs").into());
            }

            let size_lower: isize = 1 << 20; // 1 MiB
            let size_now: isize = 16 << 20; // 16 MiB
            let size_upper: isize = 256 << 30; // 256 GiB
            let growth_step: isize = 64 << 20; // 64 MiB
            let shrink_threshold: isize = 128 << 20; // 128 MiB
            let pagesize: isize = 16384; // 16 KiB pages (supports keys up to ~8,150B)

            rc = ffi::mdbx_env_set_geometry(
                env,
                size_lower,
                size_now,
                size_upper,
                growth_step,
                shrink_threshold,
                pagesize,
            );
            if rc != ffi::MDBX_SUCCESS {
                ffi::mdbx_env_close_ex(env, true);
                return Err(mdbx_err(rc, "mdbx_env_set_geometry").into());
            }

            let env_flags = ffi::MDBX_SAFE_NOSYNC
                | ffi::MDBX_NOMETASYNC
                | ffi::MDBX_LIFORECLAIM
                | ffi::MDBX_NOSTICKYTHREADS
                | ffi::MDBX_NOMEMINIT;

            rc = ffi::mdbx_env_open(env, path_cstr.as_ptr(), env_flags, 0o600);
            if rc != ffi::MDBX_SUCCESS {
                ffi::mdbx_env_close_ex(env, true);
                return Err(mdbx_err(rc, "mdbx_env_open").into());
            }

            // Bound deferred durability at transaction commits; the period is
            // not a background timer. SAFE_NOSYNC retains the last steady
            // checkpoint until a new one is safely synchronized.
            for (option, value) in [
                (ffi::MDBX_OPT_SYNC_BYTES, 16 << 20),
                (ffi::MDBX_OPT_SYNC_PERIOD, 1 << 16),
            ] {
                rc = ffi::mdbx_env_set_option(env, option, value);
                if rc != ffi::MDBX_SUCCESS {
                    ffi::mdbx_env_close_ex(env, true);
                    return Err(mdbx_err(rc, "mdbx_env_set_option(sync)").into());
                }
            }

            let mut txn: *mut ffi::MDBX_txn = ptr::null_mut();
            rc = ffi::mdbx_txn_begin_ex(
                env,
                ptr::null_mut(),
                ffi::MDBX_TXN_READWRITE,
                &mut txn,
                ptr::null_mut(),
            );
            if rc != ffi::MDBX_SUCCESS {
                ffi::mdbx_env_close_ex(env, true);
                return Err(mdbx_err(rc, "mdbx_txn_begin_ex(open_cfs)").into());
            }

            let mut cf_map = HashMap::with_capacity(cfs.len());
            let mut cf_by_dbi = HashMap::with_capacity(cfs.len());
            let mut cf_names = Vec::with_capacity(cfs.len());

            for desc in cfs {
                let name_cstr = CString::new(desc.name.as_bytes()).unwrap();
                let mut dbi: ffi::MDBX_dbi = 0;
                let mut dbi_flags = ffi::MDBX_CREATE;
                if desc.options.dupsort {
                    dbi_flags |= ffi::MDBX_DUPSORT;
                    if desc.options.dupfixed {
                        dbi_flags |= ffi::MDBX_DUPFIXED;
                    }
                }
                rc = ffi::mdbx_dbi_open(
                    txn,
                    name_cstr.as_ptr(),
                    dbi_flags,
                    &mut dbi,
                );
                if rc != ffi::MDBX_SUCCESS {
                    ffi::mdbx_txn_abort(txn);
                    ffi::mdbx_env_close_ex(env, true);
                    return Err(mdbx_err(rc, "mdbx_dbi_open").into());
                }
                cf_names.push(desc.name.clone());
                cf_by_dbi.insert(dbi, desc.name.clone());
                cf_map.insert(
                    desc.name.clone(),
                    ColumnFamily {
                        name: desc.name,
                        dbi,
                        options: desc.options,
                    },
                );
            }

            rc = ffi::mdbx_txn_commit_ex(txn, ptr::null_mut());
            if rc != ffi::MDBX_SUCCESS {
                ffi::mdbx_env_close_ex(env, true);
                return Err(mdbx_err(rc, "mdbx_txn_commit_ex(open_cfs)").into());
            }

            let db = Db {
                env,
                cfs: cf_map,
                cf_by_dbi,
                cf_names,
                read_pool: Mutex::new(ReadPool::default()),
            };
            // Publish the column-family metadata durably before returning.
            db.close()?;
            Ok(db)
        }
    }

    /// Destroy the DB, i.e. delete all its associated files.
    pub fn destroy(path: impl AsRef<Path>) -> Result<()> {
        let path_ref = path.as_ref();
        if !path_ref.exists() {
            return Ok(());
        }
        let _ = std::fs::remove_dir_all(path_ref.join("rocksdb.bak"));
        for name in [
            "mdbx.dat", "mdbx.lck", "LOCK", "CURRENT", "IDENTITY", "LOG",
            "LOG.old",
        ] {
            let _ = std::fs::remove_file(path_ref.join(name));
        }
        if let Ok(entries) = std::fs::read_dir(path_ref) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                    if fname.starts_with("MANIFEST-")
                        || fname.starts_with("OPTIONS-")
                        || fname.starts_with("LOG.old.")
                        || fname.ends_with(".sst")
                        || fname.ends_with(".log")
                    {
                        let _ = std::fs::remove_file(p);
                    }
                }
            }
        }
        let _ = std::fs::remove_dir(path_ref);
        Ok(())
    }

    /// Return a column family handle with the given name.
    pub fn cf(&self, name: &str) -> Result<&CF> {
        Ok(self
            .cfs
            .get(name)
            .ok_or_else(|| NoSuchColumnFamily(name.to_string()))?)
    }

    pub(crate) fn get(
        &self,
        cf: &CF,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        let norm_key = normalize_key(key.as_ref());
        let k = ffi::MDBX_val {
            iov_base: norm_key.as_ptr() as *mut c_void,
            iov_len: norm_key.len(),
        };
        let mut v = ffi::MDBX_val {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        };

        unsafe {
            let txn = self.acquire_read_txn()?;
            let rc = ffi::mdbx_get(txn, cf.dbi, &k, &mut v);
            if rc == ffi::MDBX_SUCCESS {
                let slice = if v.iov_len == 0 {
                    &[]
                } else {
                    slice::from_raw_parts(v.iov_base as *const u8, v.iov_len)
                };
                let out = slice.to_vec();
                self.release_read_txn(txn);
                return Ok(Some(out));
            }
            self.release_read_txn(txn);
            if rc == ffi::MDBX_NOTFOUND {
                return Ok(None);
            }
            Err(mdbx_err(rc, "mdbx_get").into())
        }
    }

    pub(crate) fn get_dups_visit<T, F>(
        &self,
        cf: &CF,
        key: impl AsRef<[u8]>,
        fixed_dup_size: Option<usize>,
        mut decode_fn: F,
    ) -> Result<Option<Vec<T>>>
    where
        F: FnMut(&[u8]) -> Result<T>,
    {
        let norm_key = normalize_key(key.as_ref());
        unsafe {
            let txn = self.acquire_read_txn()?;
            let cursor = match self.acquire_read_cursor(txn, cf.dbi) {
                Ok(c) => c,
                Err(err) => {
                    self.release_read_txn(txn);
                    return Err(err.into());
                }
            };
            let mut k = ffi::MDBX_val {
                iov_base: norm_key.as_ptr() as *mut c_void,
                iov_len: norm_key.len(),
            };
            let mut v = ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };

            if let Some(elem_size) = fixed_dup_size {
                let mut pages = [ffi::MDBX_val {
                    iov_base: ptr::null_mut(),
                    iov_len: 0,
                }; 32];
                let mut n_pages: usize = 0;
                let mut rc = ffi::mdbx_dupfixed_get_pages(
                    cursor,
                    &k,
                    elem_size,
                    pages.as_mut_ptr(),
                    pages.len(),
                    &mut n_pages,
                );
                if rc == ffi::MDBX_NOTFOUND || rc == ffi::MDBX_ENODATA {
                    self.release_read_cursor(cursor);
                    self.release_read_txn(txn);
                    return Ok(None);
                }
                if rc != ffi::MDBX_SUCCESS && rc != ffi::MDBX_RESULT_TRUE {
                    self.release_read_cursor(cursor);
                    self.release_read_txn(txn);
                    return Err(
                        mdbx_err(rc, "mdbx_dupfixed_get_pages").into(),
                    );
                }
                let total_elems: usize = pages[..n_pages]
                    .iter()
                    .map(|p| p.iov_len / elem_size)
                    .sum();
                let mut items = Vec::with_capacity(total_elems);
                for page in &pages[..n_pages] {
                    let page_slice = slice::from_raw_parts(
                        page.iov_base as *const u8,
                        page.iov_len,
                    );
                    for chunk in page_slice.chunks_exact(elem_size) {
                        match decode_fn(chunk) {
                            Ok(item) => items.push(item),
                            Err(err) => {
                                self.release_read_cursor(cursor);
                                self.release_read_txn(txn);
                                return Err(err);
                            }
                        }
                    }
                }
                while rc == ffi::MDBX_RESULT_TRUE {
                    rc = ffi::mdbx_cursor_get(
                        cursor,
                        &mut k,
                        &mut v,
                        ffi::MDBX_NEXT_MULTIPLE,
                    );
                    if rc == ffi::MDBX_NOTFOUND || rc == ffi::MDBX_ENODATA {
                        break;
                    }
                    if rc != ffi::MDBX_SUCCESS && rc != ffi::MDBX_RESULT_TRUE {
                        self.release_read_cursor(cursor);
                        self.release_read_txn(txn);
                        return Err(mdbx_err(
                            rc,
                            "mdbx_cursor_get(NEXT_MULTIPLE)",
                        )
                        .into());
                    }
                    let page_slice = slice::from_raw_parts(
                        v.iov_base as *const u8,
                        v.iov_len,
                    );
                    for chunk in page_slice.chunks_exact(elem_size) {
                        match decode_fn(chunk) {
                            Ok(item) => items.push(item),
                            Err(err) => {
                                self.release_read_cursor(cursor);
                                self.release_read_txn(txn);
                                return Err(err);
                            }
                        }
                    }
                    rc = ffi::MDBX_RESULT_TRUE;
                }
                self.release_read_cursor(cursor);
                self.release_read_txn(txn);
                return if items.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(items))
                };
            }

            let mut rc = ffi::mdbx_cursor_get(
                cursor,
                &mut k,
                &mut v,
                ffi::MDBX_SET_KEY,
            );
            if rc == ffi::MDBX_NOTFOUND || rc == ffi::MDBX_ENODATA {
                self.release_read_cursor(cursor);
                self.release_read_txn(txn);
                return Ok(None);
            }
            if rc != ffi::MDBX_SUCCESS && rc != ffi::MDBX_RESULT_TRUE {
                self.release_read_cursor(cursor);
                self.release_read_txn(txn);
                return Err(mdbx_err(rc, "mdbx_cursor_get(SET_KEY)").into());
            }
            let mut count: usize = 0;
            let _ = ffi::mdbx_cursor_count(cursor, &mut count);
            let mut items = Vec::with_capacity(count.max(1));
            while rc == ffi::MDBX_SUCCESS || rc == ffi::MDBX_RESULT_TRUE {
                let v_slice = if v.iov_len == 0 {
                    &[]
                } else {
                    slice::from_raw_parts(v.iov_base as *const u8, v.iov_len)
                };
                match decode_fn(v_slice) {
                    Ok(item) => items.push(item),
                    Err(err) => {
                        self.release_read_cursor(cursor);
                        self.release_read_txn(txn);
                        return Err(err);
                    }
                }
                rc = ffi::mdbx_cursor_get(
                    cursor,
                    &mut k,
                    &mut v,
                    ffi::MDBX_NEXT_DUP,
                );
            }
            self.release_read_cursor(cursor);
            self.release_read_txn(txn);
            if rc != ffi::MDBX_NOTFOUND && rc != ffi::MDBX_ENODATA {
                return Err(mdbx_err(rc, "mdbx_cursor_get(NEXT_DUP)").into());
            }
            if items.is_empty() {
                Ok(None)
            } else {
                Ok(Some(items))
            }
        }
    }

    pub(crate) fn dup_prefix_iterator<'a, T: 'a, F>(
        &'a self,
        cf: &CF,
        prefix: &'a [u8],
        start: &[u8],
        fixed_dup_size: Option<usize>,
        decode_fn: F,
    ) -> impl Iterator<Item = Result<(Box<[u8]>, Vec<T>)>> + 'a
    where
        F: FnMut(&[u8]) -> Result<T> + 'a,
    {
        DupPrefixIter::new(
            self,
            cf.dbi,
            prefix,
            start,
            fixed_dup_size,
            decode_fn,
        )
    }

    pub(crate) fn multi_get(
        &self,
        cf: &CF,
        keys: impl IntoIterator<Item = impl AsRef<[u8]>>,
        _sorted_inputs: bool,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let norm_keys: Vec<Cow<'_, [u8]>> = keys
            .into_iter()
            .map(|k| normalize_key(k.as_ref()).into_owned().into())
            .collect();
        let n = norm_keys.len();
        if n == 0 {
            return Ok(Vec::new());
        }

        let raw_keys: Vec<ffi::MDBX_val> = norm_keys
            .iter()
            .map(|k| ffi::MDBX_val {
                iov_base: k.as_ptr() as *mut c_void,
                iov_len: k.len(),
            })
            .collect();
        let mut raw_vals = vec![
            ffi::MDBX_val {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            n
        ];
        let mut rcs = vec![0 as c_int; n];

        unsafe {
            let txn = self.acquire_read_txn()?;
            let rc = ffi::mdbx_batch_multi_get(
                txn,
                cf.dbi,
                raw_keys.as_ptr(),
                raw_vals.as_mut_ptr(),
                rcs.as_mut_ptr(),
                n,
            );
            if rc != ffi::MDBX_SUCCESS {
                self.release_read_txn(txn);
                return Err(mdbx_err(rc, "mdbx_batch_multi_get").into());
            }
            let mut results = Vec::with_capacity(n);
            for (item_rc, v) in rcs.into_iter().zip(raw_vals.into_iter()) {
                if item_rc == ffi::MDBX_SUCCESS {
                    let slice = if v.iov_len == 0 {
                        &[]
                    } else {
                        slice::from_raw_parts(
                            v.iov_base as *const u8,
                            v.iov_len,
                        )
                    };
                    results.push(Some(slice.to_vec()));
                } else {
                    results.push(None);
                }
            }
            self.release_read_txn(txn);
            Ok(results)
        }
    }

    pub(crate) fn iterator_end(
        &self,
        cf: &CF,
    ) -> impl Iterator<Item = DbIterItem> + '_ {
        DbIter::new(self, cf.dbi, IteratorMode::End)
    }

    pub(crate) fn iterator<'a>(
        &'a self,
        cf: &CF,
        start: &[u8],
        direction: Direction,
    ) -> impl Iterator<Item = DbIterItem> + 'a {
        DbIter::new(self, cf.dbi, IteratorMode::From(start, direction))
    }

    pub(crate) fn full_iterator(
        &self,
        cf: &CF,
    ) -> impl Iterator<Item = DbIterItem> + '_ {
        DbIter::new(self, cf.dbi, IteratorMode::Start)
    }

    pub(crate) fn estimate_num_keys(&self, cf: &CF) -> Result<Option<u64>> {
        unsafe {
            let txn = self.acquire_read_txn()?;
            let mut stat = ffi::MDBX_stat::default();
            let rc = ffi::mdbx_dbi_stat(
                txn,
                cf.dbi,
                &mut stat,
                std::mem::size_of::<ffi::MDBX_stat>(),
            );
            self.release_read_txn(txn);
            if rc != ffi::MDBX_SUCCESS {
                return Err(mdbx_err(rc, "mdbx_dbi_stat").into());
            }
            Ok(Some(stat.ms_entries))
        }
    }

    /// Writes the batch atomically. Commits may defer disk synchronization up to
    /// the configured byte/commit-checked period thresholds. Call `close()` for
    /// an explicit durable checkpoint. Chronik can replay this derived index
    /// against the node's authoritative block history after restart.
    pub fn write_batch(&self, write_batch: WriteBatch) -> Result<()> {
        if write_batch.cf_batches.is_empty() {
            return Ok(());
        }

        unsafe {
            let mut txn: *mut ffi::MDBX_txn = ptr::null_mut();
            let mut rc = ffi::mdbx_txn_begin_ex(
                self.env,
                ptr::null_mut(),
                ffi::MDBX_TXN_READWRITE,
                &mut txn,
                ptr::null_mut(),
            );
            if rc != ffi::MDBX_SUCCESS {
                return Err(
                    mdbx_err(rc, "mdbx_txn_begin_ex(write_batch)").into()
                );
            }

            let mut kv_batch_ops: Vec<ffi::MDBX_batch_kv_op> = Vec::new();
            let mut dup_batch_ops: Vec<ffi::MDBX_batch_dup_op> = Vec::new();

            for (dbi, cf_batch) in write_batch.cf_batches {
                let cf_opt = self
                    .cf_by_dbi
                    .get(&dbi)
                    .and_then(|name| self.cfs.get(name));

                // 1. Apply any delete_range_cf operations first
                for (from, to) in cf_batch.delete_ranges {
                    if from.is_empty() && to.iter().all(|&b| b == 0xff) {
                        rc = ffi::mdbx_drop(txn, dbi, false);
                        if rc != ffi::MDBX_SUCCESS {
                            ffi::mdbx_txn_abort(txn);
                            return Err(mdbx_err(
                                rc,
                                "mdbx_drop(delete_range)",
                            )
                            .into());
                        }
                        continue;
                    }
                    let mut cursor: *mut ffi::MDBX_cursor = ptr::null_mut();
                    rc = ffi::mdbx_cursor_open(txn, dbi, &mut cursor);
                    if rc != ffi::MDBX_SUCCESS {
                        ffi::mdbx_txn_abort(txn);
                        return Err(mdbx_err(
                            rc,
                            "mdbx_cursor_open(delete_range)",
                        )
                        .into());
                    }
                    let mut k = ffi::MDBX_val {
                        iov_base: from.as_ptr() as *mut c_void,
                        iov_len: from.len(),
                    };
                    let mut v = ffi::MDBX_val {
                        iov_base: ptr::null_mut(),
                        iov_len: 0,
                    };
                    rc = if from.is_empty() {
                        ffi::mdbx_cursor_get(
                            cursor,
                            &mut k,
                            &mut v,
                            ffi::MDBX_FIRST,
                        )
                    } else {
                        ffi::mdbx_cursor_get(
                            cursor,
                            &mut k,
                            &mut v,
                            ffi::MDBX_SET_RANGE,
                        )
                    };
                    while rc == ffi::MDBX_SUCCESS || rc == ffi::MDBX_RESULT_TRUE
                    {
                        let k_slice = if k.iov_len == 0 {
                            &[]
                        } else {
                            slice::from_raw_parts(
                                k.iov_base as *const u8,
                                k.iov_len,
                            )
                        };
                        if k_slice >= to.as_slice() {
                            break;
                        }
                        rc = ffi::mdbx_cursor_del(cursor, 0);
                        if rc != ffi::MDBX_SUCCESS {
                            ffi::mdbx_cursor_close(cursor);
                            ffi::mdbx_txn_abort(txn);
                            return Err(mdbx_err(
                                rc,
                                "mdbx_cursor_del(delete_range)",
                            )
                            .into());
                        }
                        rc = ffi::mdbx_cursor_get(
                            cursor,
                            &mut k,
                            &mut v,
                            ffi::MDBX_GET_CURRENT,
                        );
                        if rc == ffi::MDBX_ENODATA || rc == ffi::MDBX_NOTFOUND {
                            rc = ffi::mdbx_cursor_get(
                                cursor,
                                &mut k,
                                &mut v,
                                ffi::MDBX_NEXT,
                            );
                        }
                    }
                    ffi::mdbx_cursor_close(cursor);
                    if rc != ffi::MDBX_SUCCESS
                        && rc != ffi::MDBX_RESULT_TRUE
                        && rc != ffi::MDBX_NOTFOUND
                        && rc != ffi::MDBX_ENODATA
                    {
                        ffi::mdbx_txn_abort(txn);
                        return Err(mdbx_err(
                            rc,
                            "mdbx_cursor_get(delete_range)",
                        )
                        .into());
                    }
                }

                // 2. Apply key operations in sorted key order via batched C FFI
                if !cf_batch.key_ops.is_empty() {
                    kv_batch_ops.clear();
                    kv_batch_ops.reserve(cf_batch.key_ops.len());
                    for (key, op) in &cf_batch.key_ops {
                        match op {
                            KeyOp::Put(val) => {
                                kv_batch_ops.push(ffi::MDBX_batch_kv_op {
                                    key_ptr: key.as_ptr() as *const c_void,
                                    key_len: key.len(),
                                    val_ptr: val.as_ptr() as *const c_void,
                                    val_len: val.len(),
                                    is_delete: 0,
                                });
                            }
                            KeyOp::Delete => {
                                kv_batch_ops.push(ffi::MDBX_batch_kv_op {
                                    key_ptr: key.as_ptr() as *const c_void,
                                    key_len: key.len(),
                                    val_ptr: ptr::null(),
                                    val_len: 0,
                                    is_delete: 1,
                                });
                            }
                            KeyOp::Merge { .. } => {}
                        }
                    }
                    if !kv_batch_ops.is_empty() {
                        rc = ffi::mdbx_batch_kv_apply(
                            txn,
                            dbi,
                            kv_batch_ops.as_ptr(),
                            kv_batch_ops.len(),
                        );
                        if rc != ffi::MDBX_SUCCESS {
                            ffi::mdbx_txn_abort(txn);
                            return Err(
                                mdbx_err(rc, "mdbx_batch_kv_apply").into()
                            );
                        }
                    }

                    for (key, op) in cf_batch.key_ops {
                        if let KeyOp::Merge { base, operands } = op {
                            let k = ffi::MDBX_val {
                                iov_base: key.as_ptr() as *mut c_void,
                                iov_len: key.len(),
                            };
                            let Some(cf) = cf_opt else {
                                ffi::mdbx_txn_abort(txn);
                                return Err(RocksDb(Error {
                                    message: format!(
                                        "Unknown dbi {dbi} in merge"
                                    ),
                                })
                                .into());
                            };
                            let Some(ref full_merge_fn) =
                                cf.options.full_merge
                            else {
                                ffi::mdbx_txn_abort(txn);
                                return Err(RocksDb(Error {
                                    message: format!(
                                        "No merge operator configured for CF {}",
                                        cf.name
                                    ),
                                })
                                .into());
                            };

                            let db_existing: Option<&[u8]> = match base {
                                None => {
                                    let mut v = ffi::MDBX_val {
                                        iov_base: ptr::null_mut(),
                                        iov_len: 0,
                                    };
                                    rc = ffi::mdbx_get(txn, dbi, &k, &mut v);
                                    if rc == ffi::MDBX_SUCCESS {
                                        let s = if v.iov_len == 0 {
                                            &[]
                                        } else {
                                            slice::from_raw_parts(
                                                v.iov_base as *const u8,
                                                v.iov_len,
                                            )
                                        };
                                        Some(s)
                                    } else if rc == ffi::MDBX_NOTFOUND {
                                        None
                                    } else {
                                        ffi::mdbx_txn_abort(txn);
                                        return Err(mdbx_err(
                                            rc,
                                            "mdbx_get(merge)",
                                        )
                                        .into());
                                    }
                                }
                                Some(None) => None,
                                Some(Some(ref base_vec)) => {
                                    Some(base_vec.as_slice())
                                }
                            };

                            let merge_operands = MergeOperands { operands };
                            let merged = full_merge_fn(
                                &key,
                                db_existing,
                                &merge_operands,
                            );

                            match merged {
                                Some(merged_val) => {
                                    let should_remove = cf
                                        .options
                                        .compaction_filter
                                        .as_ref()
                                        .map(|filter_fn| {
                                            filter_fn(0, &key, &merged_val)
                                                == compaction_filter::Decision::Remove
                                        })
                                        .unwrap_or(false);

                                    if should_remove {
                                        rc = ffi::mdbx_del(
                                            txn,
                                            dbi,
                                            &k,
                                            ptr::null(),
                                        );
                                        if rc != ffi::MDBX_SUCCESS
                                            && rc != ffi::MDBX_NOTFOUND
                                        {
                                            ffi::mdbx_txn_abort(txn);
                                            return Err(mdbx_err(
                                                rc,
                                                "mdbx_del(merge_remove)",
                                            )
                                            .into());
                                        }
                                    } else {
                                        let mut v = ffi::MDBX_val {
                                            iov_base: merged_val.as_ptr()
                                                as *mut c_void,
                                            iov_len: merged_val.len(),
                                        };
                                        rc = ffi::mdbx_put(
                                            txn,
                                            dbi,
                                            &k,
                                            &mut v,
                                            ffi::MDBX_UPSERT,
                                        );
                                        if rc != ffi::MDBX_SUCCESS {
                                            ffi::mdbx_txn_abort(txn);
                                            return Err(mdbx_err(
                                                rc,
                                                "mdbx_put(merge)",
                                            )
                                            .into());
                                        }
                                    }
                                }
                                None => {
                                    rc = ffi::mdbx_del(
                                        txn,
                                        dbi,
                                        &k,
                                        ptr::null(),
                                    );
                                    if rc != ffi::MDBX_SUCCESS
                                        && rc != ffi::MDBX_NOTFOUND
                                    {
                                        ffi::mdbx_txn_abort(txn);
                                        return Err(mdbx_err(
                                            rc,
                                            "mdbx_del(merge_none)",
                                        )
                                        .into());
                                    }
                                }
                            }
                        }
                    }
                }

                // 3. Apply native MDBX_DUPSORT / MDBX_DUPFIXED operations in a single C batch call
                if !cf_batch.dup_ops.is_empty() {
                    dup_batch_ops.clear();
                    for (key, prefix_map) in &cf_batch.dup_ops {
                        let key_ptr = key.as_ptr() as *const c_void;
                        let key_len = key.len();
                        for (prefix_12, dup_op) in prefix_map {
                            match dup_op {
                                DupOp::Put12(arr) => {
                                    dup_batch_ops.push(ffi::MDBX_batch_dup_op {
                                        key_ptr,
                                        key_len,
                                        val_ptr: arr.as_ptr() as *const c_void,
                                        val_len: 12,
                                        op_kind: 0,
                                    });
                                }
                                DupOp::Put(val) => {
                                    dup_batch_ops.push(ffi::MDBX_batch_dup_op {
                                        key_ptr,
                                        key_len,
                                        val_ptr: val.as_ptr() as *const c_void,
                                        val_len: val.len(),
                                        op_kind: 0,
                                    });
                                }
                                DupOp::Delete { fixed_dup_size } => {
                                    let (val_len, op_kind) =
                                        if *fixed_dup_size == Some(12) {
                                            (12, 1)
                                        } else {
                                            (fixed_dup_size.unwrap_or(12), 2)
                                        };
                                    dup_batch_ops.push(ffi::MDBX_batch_dup_op {
                                        key_ptr,
                                        key_len,
                                        val_ptr: prefix_12.as_ptr()
                                            as *const c_void,
                                        val_len,
                                        op_kind,
                                    });
                                }
                            }
                        }
                    }
                    rc = ffi::mdbx_batch_dup_apply(
                        txn,
                        dbi,
                        dup_batch_ops.as_ptr(),
                        dup_batch_ops.len(),
                    );
                    if rc != ffi::MDBX_SUCCESS {
                        ffi::mdbx_txn_abort(txn);
                        return Err(
                            mdbx_err(rc, "mdbx_batch_dup_apply").into()
                        );
                    }
                }
            }

            rc = ffi::mdbx_txn_commit_ex(txn, ptr::null_mut());
            if rc != ffi::MDBX_SUCCESS {
                return Err(
                    mdbx_err(rc, "mdbx_txn_commit_ex(write_batch)").into()
                );
            }
            Ok(())
        }
    }

    /// Compatibility alias: MDBX uses copy-on-write, with the same atomicity and
    /// deferred durability policy as `write_batch`, rather than a separate WAL.
    pub fn write_batch_without_wal(
        &self,
        write_batch: WriteBatch,
    ) -> Result<()> {
        self.write_batch(write_batch)
    }

    /// Whether any of the column families in the DB have any data.
    pub fn is_db_empty(&self) -> Result<bool> {
        for cf_name in &self.cf_names {
            let cf = self.cf(cf_name)?;
            if self.estimate_num_keys(cf)?.unwrap_or(0) > 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Durably synchronize all committed batches, e.g. before shutdown. The
    /// environment remains open; errors are propagated to the caller.
    pub fn close(&self) -> Result<()> {
        if !self.env.is_null() {
            unsafe {
                let rc = ffi::mdbx_env_sync_ex(self.env, true, false);
                if rc != ffi::MDBX_SUCCESS && rc != ffi::MDBX_RESULT_TRUE {
                    return Err(mdbx_err(rc, "mdbx_env_sync_ex").into());
                }
            }
        }
        Ok(())
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe {
            if let Ok(mut pool) = self.read_pool.lock() {
                for cursor in pool.cursors.drain(..) {
                    if !cursor.is_null() {
                        ffi::mdbx_cursor_close(cursor);
                    }
                }
                for txn in pool.txns.drain(..) {
                    if !txn.is_null() {
                        ffi::mdbx_txn_abort(txn);
                    }
                }
            }
            if !self.env.is_null() {
                if let Err(err) = self.close() {
                    // Drop cannot return an error or depend on Chronik's
                    // logger still being mounted during shutdown.
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr(),
                        format_args!("Chronik MDBX shutdown sync failed: {err}\n"),
                    );
                }
                ffi::mdbx_env_close_ex(self.env, false);
                self.env = ptr::null_mut();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdbx_durability_policy() -> Result<()> {
        let tempdir = tempdir::TempDir::new("chronik-db--durability")?;
        let db = Db::open(tempdir.path())?;
        let mut flags = 0;
        let mut bytes = 0;
        let mut period = 0;
        unsafe {
            assert_eq!(ffi::mdbx_env_get_flags(db.env, &mut flags), 0);
            assert_eq!(ffi::mdbx_env_get_option(db.env, ffi::MDBX_OPT_SYNC_BYTES, &mut bytes), 0);
            assert_eq!(ffi::mdbx_env_get_option(db.env, ffi::MDBX_OPT_SYNC_PERIOD, &mut period), 0);
        }
        println!("MDBX flags={flags:#x} sync_bytes={bytes} sync_period={period}");
        assert_eq!(flags & ffi::MDBX_WRITEMAP, 0);
        assert_ne!(flags & ffi::MDBX_SAFE_NOSYNC, 0);
        assert_ne!(flags & ffi::MDBX_NOMETASYNC, 0);
        assert_ne!(flags & ffi::MDBX_UTTERLY_NOSYNC, ffi::MDBX_UTTERLY_NOSYNC);
        assert_eq!(bytes, 16 << 20);
        assert_eq!(period, 1 << 16);
        let cf = db.cf(CF_META)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf, b"durability", b"acknowledged");
        db.write_batch(batch)?;
        db.close()?;
        // A second forced sync reports that the explicit flush has already
        // made this environment steady; no pending writes remain.
        assert_eq!(unsafe { ffi::mdbx_env_sync_ex(db.env, true, false) }, ffi::MDBX_RESULT_TRUE);
        drop(db);
        let db = Db::open(tempdir.path())?;
        assert_eq!(db.get(db.cf(CF_META)?, b"durability")?, Some(b"acknowledged".to_vec()));
        Ok(())
    }

    #[cfg(unix)]
    fn crash_batch(db: &Db, number: u64) -> Result<()> {
        let cf = db.cf(CF_META)?;
        let mut batch = WriteBatch::default();
        for slot in 0_u32..64 {
            let key = [b"row".as_slice(), &number.to_be_bytes(), &slot.to_be_bytes()].concat();
            let value = vec![(number as u8).wrapping_add(slot as u8); 4096];
            batch.put_cf(cf, key, value);
        }
        // The checkpoint and every indexed row must commit atomically.
        batch.put_cf(cf, b"checkpoint", number.to_be_bytes());
        db.write_batch(batch)
    }

    #[cfg(unix)]
    fn assert_crash_contents(db: &Db, checkpoint: u64) -> Result<()> {
        let cf = db.cf(CF_META)?;
        let actual: BTreeMap<Vec<u8>, Vec<u8>> = db.full_iterator(cf)
            .map(|row| row.map(|(key, value)| (key.into_vec(), value.into_vec())))
            .collect::<Result<_>>()?;
        let mut expected = BTreeMap::new();
        expected.insert(b"checkpoint".to_vec(), checkpoint.to_be_bytes().to_vec());
        for number in 1..=checkpoint {
            for slot in 0_u32..64 {
                let key = [b"row".as_slice(), &number.to_be_bytes(), &slot.to_be_bytes()].concat();
                expected.insert(key, vec![(number as u8).wrapping_add(slot as u8); 4096]);
            }
        }
        assert_eq!(actual, expected, "no partial or uncheckpointed batch rows");
        Ok(())
    }

    // Subprocess entrypoint: the controller below selects this test explicitly.
    #[cfg(unix)]
    #[test]
    fn mdbx_crash_child() -> Result<()> {
        use std::io::Write;
        let Ok(home) = std::env::var("LOTUS_CHRONIK_CRASH_HOME") else {
            return Ok(());
        };
        let home = Path::new(&home);
        let db = Db::open(home.join("db"))?;
        crash_batch(&db, 1)?;
        db.close()?;
        let mut ready = std::fs::File::create(home.join("ready"))?;
        ready.write_all(b"checkpoint 1 flushed; next grouped writes entering")?;
        ready.sync_all()?;
        for number in 2..=200 {
            crash_batch(&db, number)?;
        }
        panic!("controller did not interrupt the write workload");
    }

    #[cfg(unix)]
    #[test]
    fn test_mdbx_process_crash_replay_parity() -> Result<()> {
        use std::{os::unix::process::ExitStatusExt, process::{Command, Stdio}, time::{Duration, Instant}};
        for cycle in 0..5 {
            let home = tempdir::TempDir::new("chronik-db--process-crash")?;
            let log = std::fs::File::create(home.path().join("child.log"))?;
            let mut child = Command::new(std::env::current_exe()?)
                .args(["--exact", "db::tests::mdbx_crash_child", "--nocapture"])
                .env("LOTUS_CHRONIK_CRASH_HOME", home.path())
                .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log))
                .spawn()?;
            let start = Instant::now();
            while !home.path().join("ready").exists() {
                assert!(child.try_wait()?.is_none(), "crash child exited: {}", std::fs::read_to_string(home.path().join("child.log"))?);
                assert!(start.elapsed() < Duration::from_secs(30), "crash child stalled");
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(1));
            child.kill()?;
            assert_eq!(child.wait()?.signal(), Some(9));
            let db = Db::open(home.path().join("db"))?;
            let bytes = db.get(db.cf(CF_META)?, b"checkpoint")?.expect("flushed checkpoint survives");
            let checkpoint = u64::from_be_bytes(bytes.try_into().unwrap());
            assert!((1..=200).contains(&checkpoint));
            assert_crash_contents(&db, checkpoint)?;
            // Replay missed work against a deterministic logical index oracle,
            // then explicitly checkpoint and reopen the same database.
            for number in checkpoint + 1..=checkpoint + 3 {
                crash_batch(&db, number)?;
            }
            db.close()?;
            drop(db);
            let reopened = Db::open(home.path().join("db"))?;
            assert_crash_contents(&reopened, checkpoint + 3)?;
            println!("Chronik process crash cycle {cycle}: checkpoint {checkpoint}, atomic rows and replay/reopen parity passed");
        }
        Ok(())
    }

    #[test]
    fn test_legacy_rocksdb_open_preserves_files() -> Result<()> {
        let tempdir = tempdir::TempDir::new("chronik-db--preserve-legacy")?;
        let db_path = tempdir.path().join("chronik");
        std::fs::create_dir_all(&db_path)?;
        let fixtures = [
            ("CURRENT", b"MANIFEST-000001\n".as_slice()),
            ("IDENTITY", b"legacy-rocksdb-id".as_slice()),
            ("MANIFEST-000001", b"manifest".as_slice()),
            ("000002.sst", b"retained data bytes".as_slice()),
        ];
        for (name, bytes) in fixtures {
            std::fs::write(db_path.join(name), bytes)?;
        }

        // These are deliberately not valid RocksDB files. Opening them must
        // fail without silently replacing the index with an empty MDBX store.
        let error = Db::open(&db_path).err().expect("legacy index must be refused").to_string();
        assert!(error.contains("move the entire reported Chronik index directory"));
        assert!(error.contains("-chronikreindex=1"));
        assert!(!db_path.join("mdbx.dat").exists());
        assert!(!db_path.join("rocksdb.bak").exists());
        for (name, bytes) in fixtures {
            assert_eq!(std::fs::read(db_path.join(name))?, bytes);
        }
        Ok(())
    }

    #[test]
    fn test_legacy_backup_open_preserves_files() -> Result<()> {
        let tempdir = tempdir::TempDir::new("chronik-db--preserve-backup")?;
        let db_path = tempdir.path().join("chronik");
        let backup = db_path.join("rocksdb.bak");
        std::fs::create_dir_all(&backup)?;
        std::fs::write(backup.join("CURRENT"), b"legacy index")?;
        std::fs::write(db_path.join("mdbx.dat"), b"existing MDBX bytes")?;

        let result = Db::open(&db_path);
        assert!(result.is_err());
        assert_eq!(std::fs::read(backup.join("CURRENT"))?, b"legacy index");
        assert_eq!(
            std::fs::read(db_path.join("mdbx.dat"))?,
            b"existing MDBX bytes"
        );
        Ok(())
    }
}
