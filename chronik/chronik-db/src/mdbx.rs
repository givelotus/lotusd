// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Safe Rust wrapper around bundled `libmdbx` with named `MDBX_dbi` subdatabases
//! (`MDBX_DUPSORT | MDBX_DUPFIXED` for 1-to-many OutPoint postings) and
//! append-only flat segment files (`v2_tx_NNNNN.dat`) for raw transaction and
//! witness wire bytes referenced by `(file_num, offset, length)` pointers.

use std::{
    collections::BTreeMap,
    ffi::{c_char, c_int, c_void, CStr, CString},
    fs::{self, File, OpenOptions},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    ptr, slice,
    sync::{Arc, Mutex},
};

#[repr(C)]
struct MDBX_env {
    _private: [u8; 0],
}

#[repr(C)]
struct MDBX_txn {
    _private: [u8; 0],
}

#[repr(C)]
struct MDBX_cursor {
    _private: [u8; 0],
}

/// Handle for a named `libmdbx` subdatabase (`MDBX_dbi`).
pub type MdbxDbi = u32;

/// Owned key and value bytes copied from one MDBX record.
pub type MdbxKeyValue = (Vec<u8>, Vec<u8>);

#[repr(C)]
#[derive(Clone, Copy)]
struct MDBX_val {
    iov_base: *mut c_void,
    iov_len: usize,
}

impl MDBX_val {
    fn from_slice(bytes: &[u8]) -> Self {
        Self {
            iov_base: bytes.as_ptr() as *mut c_void,
            iov_len: bytes.len(),
        }
    }

    fn empty() -> Self {
        Self {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        }
    }

    unsafe fn as_slice<'a>(&self) -> &'a [u8] {
        if self.iov_len == 0 || self.iov_base.is_null() {
            &[]
        } else {
            slice::from_raw_parts(self.iov_base as *const u8, self.iov_len)
        }
    }
}

#[cfg(target_os = "macos")]
type MdbxMode = u16;
#[cfg(not(target_os = "macos"))]
type MdbxMode = u32;

const MDBX_SUCCESS: c_int = 0;
const MDBX_RESULT_TRUE: c_int = -1;
const MDBX_NOTFOUND: c_int = -30798;
#[cfg(target_os = "macos")]
const MDBX_ENODATA: c_int = 96;
#[cfg(not(target_os = "macos"))]
const MDBX_ENODATA: c_int = 61;

const MDBX_NOSTICKYTHREADS: u32 = 0x0020_0000;
const MDBX_LIFORECLAIM: u32 = 0x0400_0000;

const MDBX_TXN_READWRITE: u32 = 0;
const MDBX_TXN_RDONLY: u32 = 0x0002_0000;

const MDBX_DB_DEFAULTS: u32 = 0;
const MDBX_DUPSORT: u32 = 0x04;
const MDBX_DUPFIXED: u32 = 0x10;
const MDBX_CREATE: u32 = 0x0004_0000;

const MDBX_UPSERT: u32 = 0;

const MDBX_OPT_MAX_DB: c_int = 0;
const MDBX_OPT_MAX_READERS: c_int = 1;

const MDBX_LOG_DONTCHANGE: c_int = -1;
const MDBX_DBG_LEGACY_MULTIOPEN: c_int = 16;

#[repr(C)]
#[allow(dead_code, non_camel_case_types)]
#[derive(Clone, Copy)]
enum MDBX_cursor_op {
    MDBX_FIRST = 0,
    MDBX_FIRST_DUP = 1,
    MDBX_GET_BOTH = 2,
    MDBX_GET_BOTH_RANGE = 3,
    MDBX_GET_CURRENT = 4,
    MDBX_GET_MULTIPLE = 5,
    MDBX_LAST = 6,
    MDBX_LAST_DUP = 7,
    MDBX_NEXT = 8,
    MDBX_NEXT_DUP = 9,
    MDBX_NEXT_MULTIPLE = 10,
    MDBX_NEXT_NODUP = 11,
    MDBX_PREV = 12,
    MDBX_PREV_DUP = 13,
    MDBX_PREV_NODUP = 14,
    MDBX_SET = 15,
    MDBX_SET_KEY = 16,
    MDBX_SET_RANGE = 17,
    MDBX_SEEK_AND_GET_MULTIPLE = 36,
}

#[allow(clashing_extern_declarations)]
extern "C" {
    fn mdbx_setup_debug(
        log_level: c_int,
        debug_flags: c_int,
        logger: *const c_void,
    ) -> c_int;
    fn mdbx_env_create(penv: *mut *mut MDBX_env) -> c_int;
    fn mdbx_env_set_option(
        env: *mut MDBX_env,
        option: c_int,
        value: u64,
    ) -> c_int;
    fn mdbx_env_set_geometry(
        env: *mut MDBX_env,
        size_lower: isize,
        size_now: isize,
        size_upper: isize,
        growth_step: isize,
        shrink_threshold: isize,
        pagesize: isize,
    ) -> c_int;
    fn mdbx_env_open(
        env: *mut MDBX_env,
        pathname: *const c_char,
        flags: u32,
        mode: MdbxMode,
    ) -> c_int;
    fn mdbx_env_close_ex(env: *mut MDBX_env, dont_sync: bool) -> c_int;
    fn mdbx_txn_begin_ex(
        env: *mut MDBX_env,
        parent: *mut MDBX_txn,
        flags: u32,
        txn: *mut *mut MDBX_txn,
        context: *mut c_void,
    ) -> c_int;
    fn mdbx_txn_commit_ex(txn: *mut MDBX_txn, latency: *mut c_void) -> c_int;
    fn mdbx_txn_abort(txn: *mut MDBX_txn) -> c_int;
    fn mdbx_dbi_open(
        txn: *mut MDBX_txn,
        name: *const c_char,
        flags: u32,
        dbi: *mut MdbxDbi,
    ) -> c_int;
    fn mdbx_get(
        txn: *const MDBX_txn,
        dbi: MdbxDbi,
        key: *const MDBX_val,
        data: *mut MDBX_val,
    ) -> c_int;
    fn mdbx_put(
        txn: *mut MDBX_txn,
        dbi: MdbxDbi,
        key: *const MDBX_val,
        data: *mut MDBX_val,
        flags: u32,
    ) -> c_int;
    fn mdbx_del(
        txn: *mut MDBX_txn,
        dbi: MdbxDbi,
        key: *const MDBX_val,
        data: *const MDBX_val,
    ) -> c_int;
    fn mdbx_cursor_open(
        txn: *mut MDBX_txn,
        dbi: MdbxDbi,
        cursor: *mut *mut MDBX_cursor,
    ) -> c_int;
    fn mdbx_cursor_close(cursor: *mut MDBX_cursor);
    fn mdbx_cursor_get(
        cursor: *mut MDBX_cursor,
        key: *mut MDBX_val,
        data: *mut MDBX_val,
        op: MDBX_cursor_op,
    ) -> c_int;
    fn mdbx_strerror_r(
        errnum: c_int,
        buf: *mut c_char,
        buflen: usize,
    ) -> *const c_char;
}

/// Error returned by `libmdbx` or flat segment file operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("mdbx storage error: {0}")]
pub struct MdbxError(pub String);

fn mdbx_err(rc: c_int) -> MdbxError {
    let mut buf = [0 as c_char; 256];
    let msg = unsafe {
        let ptr = mdbx_strerror_r(rc, buf.as_mut_ptr(), buf.len());
        if ptr.is_null() {
            format!("libmdbx error code {rc}")
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    MdbxError(format!("{msg} ({rc})"))
}

fn check_rc(rc: c_int) -> Result<(), MdbxError> {
    if rc == MDBX_SUCCESS || rc == MDBX_RESULT_TRUE {
        Ok(())
    } else {
        Err(mdbx_err(rc))
    }
}

/// Maximum byte size per flat transaction wire segment file (`v2_tx_NNNNN.dat`)
/// before rotating to `file_num + 1` (2 GiB).
pub const MAX_FLAT_SEGMENT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Named `MDBX_dbi` subdatabases opened within the `libmdbx` environment.
///
/// Replaces single-column-family prefix multiplexing with isolated B+tree
/// subdatabases and `MDBX_DUPSORT | MDBX_DUPFIXED` multimaps for 1-to-many
/// `OutPoint` postings.
#[derive(Clone, Copy, Debug)]
pub struct MdbxTables {
    /// Singleton metadata (`"v2-binding"`, `"tip"`, `"disconnected"`, `"flat_pos"`).
    pub meta: MdbxDbi,
    /// Block receipts (`block_id (32B) -> ReceiptBlock`).
    pub block_receipts: MdbxDbi,
    /// Per-block undo logs (`block_id (32B) -> Undo`).
    pub undo: MdbxDbi,
    /// Canonical transaction locations (`txid (32B) -> Loc`).
    pub tx_locations: MdbxDbi,
    /// Output records and spend state (`OutPoint (36B) -> Record`).
    pub outputs: MdbxDbi,
    /// Branch/root postings (`root(32B)||pos(1B) (33B) -> OutPoint (36B)`),
    /// opened with `MDBX_DUPSORT | MDBX_DUPFIXED`.
    pub postings: MdbxDbi,
    /// Explorer height-to-block index (`height_be (8B) -> block_id (32B)`).
    pub explorer_height: MdbxDbi,
    /// Explorer block header metadata (`block_id (32B) -> BlockMeta`).
    pub explorer_block: MdbxDbi,
    /// Explorer block transaction ordinal index (`block_id(32B)||tx_idx_be(4B) -> txid (32B)`).
    pub explorer_block_tx: MdbxDbi,
    /// Explorer transaction metadata + flat-file `(file_num, data_pos, wire_size)` pointer.
    pub explorer_tx: MdbxDbi,
    /// Explorer txhash-to-txid lookup (`txhash (32B) -> txid (32B)`).
    pub explorer_txhash: MdbxDbi,
    /// Explorer input metadata (`txid(32B)||input_idx_be(4B) -> InputMeta`).
    pub explorer_input: MdbxDbi,
    /// Explorer witness metadata (`txid(32B)||input_idx_be(4B)||wit_idx_be(4B) -> WitnessFact`).
    pub explorer_witness: MdbxDbi,
    /// Asset summary records (`token_id (32B) -> AssetSummary`).
    pub asset_summary: MdbxDbi,
    /// Asset event history (`token_id(32B)||height_be(8B)||tx_idx_be(4B) (44B) -> AssetEvent`).
    pub asset_event: MdbxDbi,
    /// Asset output postings (`token_id(32B)||height_be(8B)||tx_idx_be(4B)||out_idx_be(4B) (48B) -> OutPoint (36B)`).
    pub asset_output: MdbxDbi,
}

#[derive(Clone, Copy)]
enum KeyRoute<'a> {
    Regular {
        dbi: MdbxDbi,
        subkey: &'a [u8],
    },
    DupFixed {
        dbi: MdbxDbi,
        subkey: &'a [u8],
        dupval: &'a [u8],
    },
}

fn route_key<'a>(
    tables: &MdbxTables,
    key: &'a [u8],
) -> Result<KeyRoute<'a>, MdbxError> {
    if key == b"v2-binding"
        || key == b"tip"
        || key == b"disconnected"
        || key == b"flat_pos"
    {
        return Ok(KeyRoute::Regular {
            dbi: tables.meta,
            subkey: key,
        });
    }
    match key {
        [b'b', rest @ ..] if rest.len() == 32 => Ok(KeyRoute::Regular {
            dbi: tables.block_receipts,
            subkey: rest,
        }),
        [b'u', rest @ ..] if rest.len() == 32 => Ok(KeyRoute::Regular {
            dbi: tables.undo,
            subkey: rest,
        }),
        [b't', rest @ ..] if rest.len() == 32 => Ok(KeyRoute::Regular {
            dbi: tables.tx_locations,
            subkey: rest,
        }),
        [b'o', rest @ ..] if rest.len() == 36 => Ok(KeyRoute::Regular {
            dbi: tables.outputs,
            subkey: rest,
        }),
        [b'p', rest @ ..] if rest.len() == 69 => Ok(KeyRoute::DupFixed {
            dbi: tables.postings,
            subkey: &rest[..33],
            dupval: &rest[33..],
        }),
        [b'e', b'H', rest @ ..] if rest.len() == 8 => Ok(KeyRoute::Regular {
            dbi: tables.explorer_height,
            subkey: rest,
        }),
        [b'e', b'B', rest @ ..] if rest.len() == 32 => Ok(KeyRoute::Regular {
            dbi: tables.explorer_block,
            subkey: rest,
        }),
        [b'e', b'O', rest @ ..] if rest.len() == 36 => Ok(KeyRoute::Regular {
            dbi: tables.explorer_block_tx,
            subkey: rest,
        }),
        [b'e', b'T', rest @ ..] if rest.len() == 32 => Ok(KeyRoute::Regular {
            dbi: tables.explorer_tx,
            subkey: rest,
        }),
        [b'e', b'X', rest @ ..] if rest.len() == 32 => Ok(KeyRoute::Regular {
            dbi: tables.explorer_txhash,
            subkey: rest,
        }),
        [b'e', b'I', rest @ ..] if rest.len() == 36 => Ok(KeyRoute::Regular {
            dbi: tables.explorer_input,
            subkey: rest,
        }),
        [b'e', b'W', rest @ ..] if rest.len() == 40 => Ok(KeyRoute::Regular {
            dbi: tables.explorer_witness,
            subkey: rest,
        }),
        [b'e', b'A', rest @ ..] if rest.len() == 32 => Ok(KeyRoute::Regular {
            dbi: tables.asset_summary,
            subkey: rest,
        }),
        [b'e', b'E', rest @ ..] if rest.len() == 44 => Ok(KeyRoute::Regular {
            dbi: tables.asset_event,
            subkey: rest,
        }),
        [b'e', b'P', rest @ ..] if rest.len() == 48 => Ok(KeyRoute::Regular {
            dbi: tables.asset_output,
            subkey: rest,
        }),
        _ => Err(MdbxError(format!(
            "unrecognized logical key of length {}",
            key.len()
        ))),
    }
}

/// Append-only flat segment file store (`v2_tx_NNNNN.dat`) for raw transaction
/// and witness wire frames.
#[derive(Debug)]
pub struct FlatFileStore {
    dir: PathBuf,
    files: Mutex<BTreeMap<u32, Arc<File>>>,
}

impl FlatFileStore {
    fn open(dir: &Path) -> Result<Self, MdbxError> {
        Ok(Self {
            dir: dir.to_path_buf(),
            files: Mutex::new(BTreeMap::new()),
        })
    }

    fn segment_path(&self, file_num: u32) -> PathBuf {
        self.dir.join(format!("v2_tx_{file_num:05}.dat"))
    }

    fn get_or_open(
        &self,
        file_num: u32,
        create: bool,
    ) -> Result<Arc<File>, MdbxError> {
        let mut guard = self
            .files
            .lock()
            .map_err(|_| MdbxError("flat file lock poisoned".into()))?;
        if let Some(f) = guard.get(&file_num) {
            return Ok(Arc::clone(f));
        }
        let path = self.segment_path(file_num);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .open(&path)
            .map_err(|e| MdbxError(format!("open {}: {e}", path.display())))?;
        let arc = Arc::new(file);
        guard.insert(file_num, Arc::clone(&arc));
        Ok(arc)
    }

    /// Write `bytes` at `(file_num, offset)` using positional `pwrite`.
    pub fn write_at(
        &self,
        file_num: u32,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), MdbxError> {
        if bytes.is_empty() {
            let _ = self.get_or_open(file_num, true)?;
            return Ok(());
        }
        let file = self.get_or_open(file_num, true)?;
        file.write_all_at(bytes, offset).map_err(|e| {
            MdbxError(format!("pwrite flat file {file_num}@{offset}: {e}"))
        })
    }

    /// Flush data for segment `file_num` to stable storage.
    pub fn sync_file(&self, file_num: u32) -> Result<(), MdbxError> {
        let file = self.get_or_open(file_num, true)?;
        file.sync_data()
            .map_err(|e| MdbxError(format!("fdatasync flat file {file_num}: {e}")))
    }

    /// Read `len` bytes from `(file_num, offset)` using positional `pread`.
    pub fn read_at(
        &self,
        file_num: u32,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, MdbxError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let file = self.get_or_open(file_num, false)?;
        let mut buf = vec![0u8; len];
        file.read_exact_at(&mut buf, offset).map_err(|e| {
            MdbxError(format!(
                "pread flat file {file_num}@{offset}+{len}: {e}"
            ))
        })?;
        Ok(buf)
    }

    /// Truncate flat segment storage back to `(file_num, write_pos)` after a
    /// block disconnect commits.
    pub fn truncate_to(
        &self,
        file_num: u32,
        write_pos: u64,
    ) -> Result<(), MdbxError> {
        if let Ok(file) = self.get_or_open(file_num, false) {
            file.set_len(write_pos).map_err(|e| {
                MdbxError(format!(
                    "truncate flat file {file_num} to {write_pos}: {e}"
                ))
            })?;
            file.sync_data().map_err(|e| {
                MdbxError(format!("sync truncated flat file {file_num}: {e}"))
            })?;
        }
        let mut guard = self
            .files
            .lock()
            .map_err(|_| MdbxError("flat file lock poisoned".into()))?;
        let higher: Vec<u32> =
            guard.keys().copied().filter(|&k| k > file_num).collect();
        for k in higher {
            guard.remove(&k);
            let _ = fs::remove_file(self.segment_path(k));
        }
        Ok(())
    }
}

/// Staged write batch for atomic commit across `libmdbx` subdatabases.
#[derive(Default, Debug)]
pub struct MdbxWriteBatch {
    ops: Vec<BatchOp>,
    approx_bytes: usize,
}

#[derive(Debug)]
enum BatchOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

impl MdbxWriteBatch {
    /// Stage a key/value insertion or update.
    pub fn put(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        let k = key.into();
        let v = value.into();
        self.approx_bytes = self.approx_bytes.saturating_add(k.len() + v.len());
        self.ops.push(BatchOp::Put(k, v));
    }

    /// Stage a key deletion.
    pub fn delete(&mut self, key: impl Into<Vec<u8>>) {
        let k = key.into();
        self.approx_bytes = self.approx_bytes.saturating_add(k.len());
        self.ops.push(BatchOp::Delete(k));
    }

    /// Total staged key + value payload bytes.
    pub fn size_in_bytes(&self) -> usize {
        self.approx_bytes
    }
}

/// `libmdbx` database environment paired with append-only flat segment files.
pub struct MdbxEnv {
    env: *mut MDBX_env,
    tables: MdbxTables,
    flat: Arc<FlatFileStore>,
}

// Safety: `MDBX_env` is thread-safe and opened with `MDBX_NOSTICKYTHREADS`.
unsafe impl Send for MdbxEnv {}
unsafe impl Sync for MdbxEnv {}

impl std::fmt::Debug for MdbxEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdbxEnv")
            .field("tables", &self.tables)
            .finish_non_exhaustive()
    }
}

fn open_dbi(
    txn: *mut MDBX_txn,
    name: &str,
    extra_flags: u32,
) -> Result<MdbxDbi, MdbxError> {
    let cname = CString::new(name)
        .map_err(|_| MdbxError("invalid subdatabase name".into()))?;
    let mut dbi: MdbxDbi = 0;
    let rc = unsafe {
        mdbx_dbi_open(txn, cname.as_ptr(), MDBX_CREATE | extra_flags, &mut dbi)
    };
    check_rc(rc)?;
    Ok(dbi)
}

fn txn_get(
    txn: *mut MDBX_txn,
    tables: &MdbxTables,
    key: &[u8],
) -> Result<Option<Vec<u8>>, MdbxError> {
    match route_key(tables, key)? {
        KeyRoute::Regular { dbi, subkey } => {
            let k_val = MDBX_val::from_slice(subkey);
            let mut v_val = MDBX_val::empty();
            let rc = unsafe { mdbx_get(txn, dbi, &k_val, &mut v_val) };
            if rc == MDBX_NOTFOUND {
                return Ok(None);
            }
            check_rc(rc)?;
            Ok(Some(unsafe { v_val.as_slice() }.to_vec()))
        }
        KeyRoute::DupFixed {
            dbi,
            subkey,
            dupval,
        } => {
            let mut cursor: *mut MDBX_cursor = ptr::null_mut();
            let rc = unsafe { mdbx_cursor_open(txn, dbi, &mut cursor) };
            check_rc(rc)?;
            let mut k_val = MDBX_val::from_slice(subkey);
            let mut v_val = MDBX_val::from_slice(dupval);
            let get_rc = unsafe {
                mdbx_cursor_get(
                    cursor,
                    &mut k_val,
                    &mut v_val,
                    MDBX_cursor_op::MDBX_GET_BOTH,
                )
            };
            unsafe { mdbx_cursor_close(cursor) };
            if get_rc == MDBX_NOTFOUND {
                return Ok(None);
            }
            check_rc(get_rc)?;
            Ok(Some(Vec::new()))
        }
    }
}

fn txn_put(
    txn: *mut MDBX_txn,
    tables: &MdbxTables,
    key: &[u8],
    value: &[u8],
) -> Result<(), MdbxError> {
    match route_key(tables, key)? {
        KeyRoute::Regular { dbi, subkey } => {
            let k_val = MDBX_val::from_slice(subkey);
            let mut v_val = MDBX_val::from_slice(value);
            let rc =
                unsafe { mdbx_put(txn, dbi, &k_val, &mut v_val, MDBX_UPSERT) };
            check_rc(rc)
        }
        KeyRoute::DupFixed {
            dbi,
            subkey,
            dupval,
        } => {
            if !value.is_empty() {
                return Err(MdbxError(
                    "dupfixed posting entry must have empty payload".into(),
                ));
            }
            let k_val = MDBX_val::from_slice(subkey);
            let mut v_val = MDBX_val::from_slice(dupval);
            let rc =
                unsafe { mdbx_put(txn, dbi, &k_val, &mut v_val, MDBX_UPSERT) };
            check_rc(rc)
        }
    }
}

fn txn_del(
    txn: *mut MDBX_txn,
    tables: &MdbxTables,
    key: &[u8],
) -> Result<(), MdbxError> {
    match route_key(tables, key)? {
        KeyRoute::Regular { dbi, subkey } => {
            let k_val = MDBX_val::from_slice(subkey);
            let rc = unsafe { mdbx_del(txn, dbi, &k_val, ptr::null()) };
            if rc == MDBX_NOTFOUND {
                return Ok(());
            }
            check_rc(rc)
        }
        KeyRoute::DupFixed {
            dbi,
            subkey,
            dupval,
        } => {
            let k_val = MDBX_val::from_slice(subkey);
            let v_val = MDBX_val::from_slice(dupval);
            let rc = unsafe { mdbx_del(txn, dbi, &k_val, &v_val) };
            if rc == MDBX_NOTFOUND {
                return Ok(());
            }
            check_rc(rc)
        }
    }
}

impl MdbxEnv {
    /// Open or create a `libmdbx` environment and all 16 named subdatabases at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MdbxError> {
        let dir = path.as_ref();
        fs::create_dir_all(dir).map_err(|e| {
            MdbxError(format!("create_dir_all {}: {e}", dir.display()))
        })?;
        let cpath = CString::new(
            dir.to_str()
                .ok_or_else(|| MdbxError("non-utf8 db path".into()))?,
        )
        .map_err(|_| MdbxError("nul byte in db path".into()))?;

        unsafe {
            let logger_dontchange = (-1isize) as *const c_void;
            mdbx_setup_debug(
                MDBX_LOG_DONTCHANGE,
                MDBX_DBG_LEGACY_MULTIOPEN,
                logger_dontchange,
            );
        }

        let mut env: *mut MDBX_env = ptr::null_mut();
        check_rc(unsafe { mdbx_env_create(&mut env) })?;

        let init = (|| -> Result<MdbxTables, MdbxError> {
            check_rc(unsafe { mdbx_env_set_option(env, MDBX_OPT_MAX_DB, 32) })?;
            check_rc(unsafe {
                mdbx_env_set_option(env, MDBX_OPT_MAX_READERS, 256)
            })?;
            check_rc(unsafe {
                mdbx_env_set_geometry(
                    env,
                    -1,
                    -1,
                    16isize << 30, // 16 GiB upper bound
                    16isize << 20, // 16 MiB growth step
                    64isize << 20, // 64 MiB shrink threshold
                    4096, // 4 KiB page size (all V2 subdatabase keys <= 68B)
                )
            })?;
            check_rc(unsafe {
                mdbx_env_open(
                    env,
                    cpath.as_ptr(),
                    MDBX_NOSTICKYTHREADS | MDBX_LIFORECLAIM,
                    0o644 as MdbxMode,
                )
            })?;

            let mut txn: *mut MDBX_txn = ptr::null_mut();
            check_rc(unsafe {
                mdbx_txn_begin_ex(
                    env,
                    ptr::null_mut(),
                    MDBX_TXN_READWRITE,
                    &mut txn,
                    ptr::null_mut(),
                )
            })?;

            let open_res = (|| -> Result<MdbxTables, MdbxError> {
                let dup_flags = MDBX_DUPSORT | MDBX_DUPFIXED;
                Ok(MdbxTables {
                    meta: open_dbi(txn, "meta", MDBX_DB_DEFAULTS)?,
                    block_receipts: open_dbi(
                        txn,
                        "block_receipts",
                        MDBX_DB_DEFAULTS,
                    )?,
                    undo: open_dbi(txn, "undo", MDBX_DB_DEFAULTS)?,
                    tx_locations: open_dbi(
                        txn,
                        "tx_locations",
                        MDBX_DB_DEFAULTS,
                    )?,
                    outputs: open_dbi(txn, "outputs", MDBX_DB_DEFAULTS)?,
                    postings: open_dbi(txn, "postings", dup_flags)?,
                    explorer_height: open_dbi(
                        txn,
                        "explorer_height",
                        MDBX_DB_DEFAULTS,
                    )?,
                    explorer_block: open_dbi(
                        txn,
                        "explorer_block",
                        MDBX_DB_DEFAULTS,
                    )?,
                    explorer_block_tx: open_dbi(
                        txn,
                        "explorer_block_tx",
                        MDBX_DB_DEFAULTS,
                    )?,
                    explorer_tx: open_dbi(
                        txn,
                        "explorer_tx",
                        MDBX_DB_DEFAULTS,
                    )?,
                    explorer_txhash: open_dbi(
                        txn,
                        "explorer_txhash",
                        MDBX_DB_DEFAULTS,
                    )?,
                    explorer_input: open_dbi(
                        txn,
                        "explorer_input",
                        MDBX_DB_DEFAULTS,
                    )?,
                    explorer_witness: open_dbi(
                        txn,
                        "explorer_witness",
                        MDBX_DB_DEFAULTS,
                    )?,
                    asset_summary: open_dbi(
                        txn,
                        "asset_summary",
                        MDBX_DB_DEFAULTS,
                    )?,
                    asset_event: open_dbi(
                        txn,
                        "asset_event",
                        MDBX_DB_DEFAULTS,
                    )?,
                    asset_output: open_dbi(
                        txn,
                        "asset_output",
                        MDBX_DB_DEFAULTS,
                    )?,
                })
            })();

            match open_res {
                Ok(tables) => {
                    check_rc(unsafe {
                        mdbx_txn_commit_ex(txn, ptr::null_mut())
                    })?;
                    Ok(tables)
                }
                Err(e) => {
                    unsafe {
                        mdbx_txn_abort(txn);
                    }
                    Err(e)
                }
            }
        })();

        match init {
            Ok(tables) => {
                let flat = Arc::new(FlatFileStore::open(dir)?);
                Ok(Self { env, tables, flat })
            }
            Err(e) => {
                unsafe {
                    mdbx_env_close_ex(env, true);
                }
                Err(e)
            }
        }
    }

    /// Reference to the flat segment file store.
    pub fn flat(&self) -> &FlatFileStore {
        &self.flat
    }

    /// Point lookup across the named subdatabases using a logical key.
    pub fn get(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<Vec<u8>>, MdbxError> {
        let snap = self.snapshot()?;
        snap.get(key)
    }

    /// Single-key durable write in an ACID `libmdbx` write transaction.
    pub fn put(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), MdbxError> {
        let mut txn: *mut MDBX_txn = ptr::null_mut();
        check_rc(unsafe {
            mdbx_txn_begin_ex(
                self.env,
                ptr::null_mut(),
                MDBX_TXN_READWRITE,
                &mut txn,
                ptr::null_mut(),
            )
        })?;
        match txn_put(txn, &self.tables, key.as_ref(), value.as_ref()) {
            Ok(()) => {
                check_rc(unsafe { mdbx_txn_commit_ex(txn, ptr::null_mut()) })
            }
            Err(e) => {
                unsafe {
                    mdbx_txn_abort(txn);
                }
                Err(e)
            }
        }
    }

    /// Commit a `MdbxWriteBatch` atomically in a single durable `libmdbx` write transaction.
    pub fn write(&self, batch: MdbxWriteBatch) -> Result<(), MdbxError> {
        let mut txn: *mut MDBX_txn = ptr::null_mut();
        check_rc(unsafe {
            mdbx_txn_begin_ex(
                self.env,
                ptr::null_mut(),
                MDBX_TXN_READWRITE,
                &mut txn,
                ptr::null_mut(),
            )
        })?;
        for op in batch.ops {
            let res = match op {
                BatchOp::Put(k, v) => txn_put(txn, &self.tables, &k, &v),
                BatchOp::Delete(k) => txn_del(txn, &self.tables, &k),
            };
            if let Err(e) = res {
                unsafe {
                    mdbx_txn_abort(txn);
                }
                return Err(e);
            }
        }
        check_rc(unsafe { mdbx_txn_commit_ex(txn, ptr::null_mut()) })
    }

    /// Open a consistent MVCC read-only snapshot transaction (`MDBX_TXN_RDONLY`).
    pub fn snapshot(&self) -> Result<MdbxSnapshot<'_>, MdbxError> {
        let mut txn: *mut MDBX_txn = ptr::null_mut();
        check_rc(unsafe {
            mdbx_txn_begin_ex(
                self.env,
                ptr::null_mut(),
                MDBX_TXN_RDONLY,
                &mut txn,
                ptr::null_mut(),
            )
        })?;
        Ok(MdbxSnapshot {
            txn,
            tables: self.tables,
            flat: Arc::clone(&self.flat),
            posting_cache: Mutex::new(None),
            _marker: std::marker::PhantomData,
        })
    }

    /// Dump all logical `(key, value)` pairs across all named subdatabases in
    /// canonical key order (used by state-restoration unit tests).
    pub fn dump_all(&self) -> Result<Vec<MdbxKeyValue>, MdbxError> {
        let snap = self.snapshot()?;
        snap.dump_all()
    }

    /// Return true if all named subdatabases are empty.
    pub fn is_empty(&self) -> Result<bool, MdbxError> {
        Ok(self.dump_all()?.is_empty())
    }
}

impl Drop for MdbxEnv {
    fn drop(&mut self) {
        if !self.env.is_null() {
            unsafe {
                mdbx_env_close_ex(self.env, false);
            }
            self.env = ptr::null_mut();
        }
    }
}

#[derive(Clone, Debug)]
struct DupFixedPageCache {
    key33: [u8; 33],
    items: Vec<[u8; 36]>,
    next_idx: usize,
}

/// Consistent MVCC read-only transaction snapshot over `libmdbx` + flat files.
pub struct MdbxSnapshot<'a> {
    txn: *mut MDBX_txn,
    tables: MdbxTables,
    flat: Arc<FlatFileStore>,
    posting_cache: Mutex<Option<DupFixedPageCache>>,
    _marker: std::marker::PhantomData<&'a MdbxEnv>,
}

// Safety: `MDBX_NOSTICKYTHREADS` unbinds read-only transactions from TLS.
unsafe impl Send for MdbxSnapshot<'_> {}
unsafe impl Sync for MdbxSnapshot<'_> {}

impl MdbxSnapshot<'_> {
    /// Point lookup in the appropriate named `MDBX_dbi` subdatabase.
    pub fn get(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<Vec<u8>>, MdbxError> {
        txn_get(self.txn, &self.tables, key.as_ref())
    }

    /// Read a slice of raw transaction wire bytes from `(file_num, offset, len)`
    /// in the append-only flat segment store.
    pub fn read_flat(
        &self,
        file_num: u32,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, MdbxError> {
        self.flat.read_at(file_num, offset, len)
    }

    /// Strictly ordered next 36-byte `OutPoint` in `tables.postings`
    /// (`MDBX_DUPSORT | MDBX_DUPFIXED`) for `(root, position)` after `after`.
    ///
    /// Uses `MDBX_GET_MULTIPLE` and `MDBX_NEXT_MULTIPLE` to read an entire leaf
    /// page of packed 36-byte entries in a single FFI call and caches the page
    /// inside this snapshot for sequential iteration.
    pub fn next_posting_dupfixed(
        &self,
        root: [u8; 32],
        position: u8,
        after: Option<[u8; 36]>,
    ) -> Result<Option<[u8; 36]>, MdbxError> {
        let mut key33 = [0u8; 33];
        key33[..32].copy_from_slice(&root);
        key33[32] = position;

        if let Some(after_bytes) = after {
            if let Ok(mut guard) = self.posting_cache.lock() {
                if let Some(cache) = guard.as_mut() {
                    if cache.key33 == key33 {
                        if cache.next_idx > 0
                            && cache.next_idx < cache.items.len()
                            && cache.items[cache.next_idx - 1] == after_bytes
                        {
                            let out = cache.items[cache.next_idx];
                            cache.next_idx += 1;
                            return Ok(Some(out));
                        }
                        if cache.items.first() <= Some(&after_bytes)
                            && cache.items.last() > Some(&after_bytes)
                        {
                            let idx = cache
                                .items
                                .partition_point(|x| *x <= after_bytes);
                            cache.next_idx = idx + 1;
                            return Ok(Some(cache.items[idx]));
                        }
                    }
                }
            }
        }

        let items =
            self.read_dupfixed36_pages(self.tables.postings, &key33, after, 1)?;
        let Some(&first) = items.first() else {
            return Ok(None);
        };
        if let Ok(mut guard) = self.posting_cache.lock() {
            *guard = Some(DupFixedPageCache {
                key33,
                items,
                next_idx: 1,
            });
        }
        Ok(Some(first))
    }

    /// Read all 36-byte `OutPoint` entries in `tables.postings` for
    /// `(root, position)` strictly after `after`, using `MDBX_GET_MULTIPLE`
    /// and `MDBX_NEXT_MULTIPLE`.
    pub fn postings_dupfixed_after(
        &self,
        root: [u8; 32],
        position: u8,
        after: Option<[u8; 36]>,
    ) -> Result<Vec<[u8; 36]>, MdbxError> {
        let mut key33 = [0u8; 33];
        key33[..32].copy_from_slice(&root);
        key33[32] = position;
        self.read_dupfixed36_pages(
            self.tables.postings,
            &key33,
            after,
            usize::MAX,
        )
    }

    fn read_dupfixed36_pages(
        &self,
        dbi: MdbxDbi,
        subkey: &[u8],
        after: Option<[u8; 36]>,
        max_pages: usize,
    ) -> Result<Vec<[u8; 36]>, MdbxError> {
        let mut cursor: *mut MDBX_cursor = ptr::null_mut();
        check_rc(unsafe { mdbx_cursor_open(self.txn, dbi, &mut cursor) })?;
        let res = (|| -> Result<Vec<[u8; 36]>, MdbxError> {
            let mut k_val = MDBX_val::from_slice(subkey);
            let mut v_val = MDBX_val::empty();
            let mut out = Vec::new();
            let mut pages_fetched = 0usize;

            match after {
                None => {
                    let mult_rc = unsafe {
                        mdbx_cursor_get(
                            cursor,
                            &mut k_val,
                            &mut v_val,
                            MDBX_cursor_op::MDBX_SEEK_AND_GET_MULTIPLE,
                        )
                    };
                    if mult_rc == MDBX_NOTFOUND || mult_rc == MDBX_ENODATA {
                        return Ok(out);
                    }
                    check_rc(mult_rc)?;
                    let page_slice = unsafe { v_val.as_slice() };
                    if page_slice.len() % 36 != 0 {
                        return Err(MdbxError(
                            "corrupt dupfixed36 value length".into(),
                        ));
                    }
                    out.reserve(page_slice.len() / 36);
                    for chunk in page_slice.chunks_exact(36) {
                        out.push(chunk.try_into().unwrap());
                    }
                    pages_fetched += 1;
                }
                Some(after_bytes) => {
                    v_val = MDBX_val::from_slice(&after_bytes);
                    let rc = unsafe {
                        mdbx_cursor_get(
                            cursor,
                            &mut k_val,
                            &mut v_val,
                            MDBX_cursor_op::MDBX_GET_BOTH_RANGE,
                        )
                    };
                    if rc == MDBX_NOTFOUND || rc == MDBX_ENODATA {
                        return Ok(out);
                    }
                    check_rc(rc)?;
                    let first_slice = unsafe { v_val.as_slice() };
                    if first_slice.len() != 36 {
                        return Err(MdbxError(
                            "corrupt dupfixed36 value length".into(),
                        ));
                    }
                    let first_ptr = v_val.iov_base as *const u8;
                    let skip_first = first_slice == after_bytes;

                    let mult_rc = unsafe {
                        mdbx_cursor_get(
                            cursor,
                            ptr::null_mut(),
                            &mut v_val,
                            MDBX_cursor_op::MDBX_GET_MULTIPLE,
                        )
                    };
                    if mult_rc == MDBX_NOTFOUND || mult_rc == MDBX_ENODATA {
                        return Ok(out);
                    }
                    check_rc(mult_rc)?;
                    if v_val.iov_len % 36 != 0 {
                        return Err(MdbxError(
                            "corrupt dupfixed36 value length".into(),
                        ));
                    }
                    let page_base = v_val.iov_base as *const u8;
                    let page_end = unsafe { page_base.add(v_val.iov_len) };
                    let start_ptr = if skip_first {
                        unsafe { first_ptr.add(36) }
                    } else {
                        first_ptr
                    };
                    if start_ptr < page_end {
                        let rem_len = page_end as usize - start_ptr as usize;
                        if rem_len % 36 != 0 {
                            return Err(MdbxError(
                                "corrupt dupfixed36 offset alignment".into(),
                            ));
                        }
                        let rem_slice = unsafe {
                            slice::from_raw_parts(start_ptr, rem_len)
                        };
                        out.reserve(rem_len / 36);
                        for chunk in rem_slice.chunks_exact(36) {
                            out.push(chunk.try_into().unwrap());
                        }
                        pages_fetched += 1;
                    }
                }
            }

            while out.is_empty() || pages_fetched < max_pages {
                let next_rc = unsafe {
                    mdbx_cursor_get(
                        cursor,
                        ptr::null_mut(),
                        &mut v_val,
                        MDBX_cursor_op::MDBX_NEXT_MULTIPLE,
                    )
                };
                if next_rc == MDBX_NOTFOUND || next_rc == MDBX_ENODATA {
                    break;
                }
                check_rc(next_rc)?;
                let page_slice = unsafe { v_val.as_slice() };
                if page_slice.len() % 36 != 0 {
                    return Err(MdbxError(
                        "corrupt dupfixed36 value length".into(),
                    ));
                }
                out.reserve(page_slice.len() / 36);
                for chunk in page_slice.chunks_exact(36) {
                    out.push(chunk.try_into().unwrap());
                }
                pages_fetched += 1;
            }
            Ok(out)
        })();
        unsafe { mdbx_cursor_close(cursor) };
        res
    }

    /// Exclusive forward seek within one of the named regular subdatabases
    /// (`eH`, `eO`, `eI`, `eW`, `eA`, `eE`, `eP`), charging `charge` before each
    /// cursor operation (`MDBX_FIRST`/`MDBX_SET_RANGE` and optional `MDBX_NEXT`).
    pub fn seek_next_regular<E: From<MdbxError>>(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        mut charge: impl FnMut() -> Result<(), E>,
    ) -> Result<Option<MdbxKeyValue>, E> {
        let dbi = match prefix.get(..2) {
            Some(b"eH") => self.tables.explorer_height,
            Some(b"eO") => self.tables.explorer_block_tx,
            Some(b"eI") => self.tables.explorer_input,
            Some(b"eW") => self.tables.explorer_witness,
            Some(b"eA") => self.tables.asset_summary,
            Some(b"eE") => self.tables.asset_event,
            Some(b"eP") => self.tables.asset_output,
            _ => {
                return Err(E::from(MdbxError(
                    "invalid regular seek family prefix".into(),
                )))
            }
        };
        let family_prefix = &prefix[..2];
        let sub_prefix = &prefix[2..];
        let after_subkey = after.map(|k| &k[2..]);

        let mut cursor: *mut MDBX_cursor = ptr::null_mut();
        check_rc(unsafe { mdbx_cursor_open(self.txn, dbi, &mut cursor) })?;
        let res = (|| -> Result<Option<MdbxKeyValue>, E> {
            charge()?;
            let mut k_val = MDBX_val::empty();
            let mut v_val = MDBX_val::empty();
            let start = after_subkey.unwrap_or(sub_prefix);
            let rc = if start.is_empty() {
                unsafe {
                    mdbx_cursor_get(
                        cursor,
                        &mut k_val,
                        &mut v_val,
                        MDBX_cursor_op::MDBX_FIRST,
                    )
                }
            } else {
                k_val = MDBX_val::from_slice(start);
                unsafe {
                    mdbx_cursor_get(
                        cursor,
                        &mut k_val,
                        &mut v_val,
                        MDBX_cursor_op::MDBX_SET_RANGE,
                    )
                }
            };
            if rc == MDBX_NOTFOUND {
                return Ok(None);
            }
            check_rc(rc)?;
            if after_subkey.is_some()
                && unsafe { k_val.as_slice() } == after_subkey.unwrap()
            {
                charge()?;
                let next_rc = unsafe {
                    mdbx_cursor_get(
                        cursor,
                        &mut k_val,
                        &mut v_val,
                        MDBX_cursor_op::MDBX_NEXT,
                    )
                };
                if next_rc == MDBX_NOTFOUND {
                    return Ok(None);
                }
                check_rc(next_rc)?;
            }
            let k_slice = unsafe { k_val.as_slice() };
            if !k_slice.starts_with(sub_prefix) {
                return Ok(None);
            }
            let mut full_key =
                Vec::with_capacity(family_prefix.len() + k_slice.len());
            full_key.extend_from_slice(family_prefix);
            full_key.extend_from_slice(k_slice);
            let v_slice = unsafe { v_val.as_slice() };
            Ok(Some((full_key, v_slice.to_vec())))
        })();
        unsafe { mdbx_cursor_close(cursor) };
        res
    }

    /// Dump all logical `(key, value)` entries across all named subdatabases.
    pub fn dump_all(&self) -> Result<Vec<MdbxKeyValue>, MdbxError> {
        let mut out = Vec::new();
        let regular_tables: &[(MdbxDbi, &[u8])] = &[
            (self.tables.meta, b""),
            (self.tables.block_receipts, b"b"),
            (self.tables.undo, b"u"),
            (self.tables.tx_locations, b"t"),
            (self.tables.outputs, b"o"),
            (self.tables.explorer_height, b"eH"),
            (self.tables.explorer_block, b"eB"),
            (self.tables.explorer_block_tx, b"eO"),
            (self.tables.explorer_tx, b"eT"),
            (self.tables.explorer_txhash, b"eX"),
            (self.tables.explorer_input, b"eI"),
            (self.tables.explorer_witness, b"eW"),
            (self.tables.asset_summary, b"eA"),
            (self.tables.asset_event, b"eE"),
            (self.tables.asset_output, b"eP"),
        ];
        for &(dbi, prefix) in regular_tables {
            let mut cursor: *mut MDBX_cursor = ptr::null_mut();
            check_rc(unsafe { mdbx_cursor_open(self.txn, dbi, &mut cursor) })?;
            let mut k_val = MDBX_val::empty();
            let mut v_val = MDBX_val::empty();
            let mut rc = unsafe {
                mdbx_cursor_get(
                    cursor,
                    &mut k_val,
                    &mut v_val,
                    MDBX_cursor_op::MDBX_FIRST,
                )
            };
            while rc == MDBX_SUCCESS || rc == MDBX_RESULT_TRUE {
                let mut full_key =
                    Vec::with_capacity(prefix.len() + k_val.iov_len);
                full_key.extend_from_slice(prefix);
                full_key.extend_from_slice(unsafe { k_val.as_slice() });
                let val = unsafe { v_val.as_slice() }.to_vec();
                out.push((full_key, val));
                rc = unsafe {
                    mdbx_cursor_get(
                        cursor,
                        &mut k_val,
                        &mut v_val,
                        MDBX_cursor_op::MDBX_NEXT,
                    )
                };
            }
            unsafe { mdbx_cursor_close(cursor) };
            if rc != MDBX_NOTFOUND {
                check_rc(rc)?;
            }
        }
        let dup_tables: &[(MdbxDbi, &[u8])] = &[(self.tables.postings, b"p")];
        for &(dbi, prefix) in dup_tables {
            let mut cursor: *mut MDBX_cursor = ptr::null_mut();
            check_rc(unsafe { mdbx_cursor_open(self.txn, dbi, &mut cursor) })?;
            let mut k_val = MDBX_val::empty();
            let mut v_val = MDBX_val::empty();
            let mut rc = unsafe {
                mdbx_cursor_get(
                    cursor,
                    &mut k_val,
                    &mut v_val,
                    MDBX_cursor_op::MDBX_FIRST,
                )
            };
            while rc == MDBX_SUCCESS || rc == MDBX_RESULT_TRUE {
                let k_vec = unsafe { k_val.as_slice() }.to_vec();
                let mut mult_rc = unsafe {
                    mdbx_cursor_get(
                        cursor,
                        ptr::null_mut(),
                        &mut v_val,
                        MDBX_cursor_op::MDBX_GET_MULTIPLE,
                    )
                };
                while mult_rc == MDBX_SUCCESS || mult_rc == MDBX_RESULT_TRUE {
                    let page_slice = unsafe { v_val.as_slice() };
                    for v_slice in page_slice.chunks_exact(36) {
                        let mut full_key = Vec::with_capacity(
                            prefix.len() + k_vec.len() + v_slice.len(),
                        );
                        full_key.extend_from_slice(prefix);
                        full_key.extend_from_slice(&k_vec);
                        full_key.extend_from_slice(v_slice);
                        out.push((full_key, Vec::new()));
                    }
                    mult_rc = unsafe {
                        mdbx_cursor_get(
                            cursor,
                            ptr::null_mut(),
                            &mut v_val,
                            MDBX_cursor_op::MDBX_NEXT_MULTIPLE,
                        )
                    };
                }
                if mult_rc != MDBX_NOTFOUND && mult_rc != MDBX_ENODATA {
                    unsafe { mdbx_cursor_close(cursor) };
                    check_rc(mult_rc)?;
                }
                rc = unsafe {
                    mdbx_cursor_get(
                        cursor,
                        &mut k_val,
                        &mut v_val,
                        MDBX_cursor_op::MDBX_NEXT_NODUP,
                    )
                };
            }
            unsafe { mdbx_cursor_close(cursor) };
            if rc != MDBX_NOTFOUND {
                check_rc(rc)?;
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

impl std::fmt::Debug for MdbxSnapshot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdbxSnapshot")
            .field("tables", &self.tables)
            .finish_non_exhaustive()
    }
}

impl Drop for MdbxSnapshot<'_> {
    fn drop(&mut self) {
        if !self.txn.is_null() {
            unsafe {
                mdbx_txn_abort(self.txn);
            }
            self.txn = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_subdatabases_dupfixed_postings_and_flat_files() {
        let dir = tempdir::TempDir::new("mdbx-v2-unit").unwrap();
        let env = MdbxEnv::open(dir.path()).unwrap();
        assert!(env.is_empty().unwrap());
        assert!(dir.path().join("mdbx.dat").is_file());

        // Insert into postings with MDBX_DUPSORT | MDBX_DUPFIXED
        let root = [7u8; 32];
        let pos = 3u8;
        let op1 = [1u8; 36];
        let op2 = [2u8; 36];
        let op3 = [3u8; 36];
        let make_key = |op: [u8; 36]| {
            let mut k = vec![b'p'];
            k.extend_from_slice(&root);
            k.push(pos);
            k.extend_from_slice(&op);
            k
        };
        let mut batch = MdbxWriteBatch::default();
        batch.put(make_key(op2), vec![]);
        batch.put(make_key(op1), vec![]);
        batch.put(make_key(op3), vec![]);
        batch.put(b"tip", b"anchor-bytes");
        env.write(batch).unwrap();

        let snap = env.snapshot().unwrap();
        assert_eq!(
            snap.get(b"tip").unwrap().as_deref(),
            Some(&b"anchor-bytes"[..])
        );
        assert_eq!(
            snap.next_posting_dupfixed(root, pos, None).unwrap(),
            Some(op1)
        );
        assert_eq!(
            snap.next_posting_dupfixed(root, pos, Some(op1)).unwrap(),
            Some(op2)
        );
        let mut between = op2;
        between[35] = 99;
        assert_eq!(
            snap.next_posting_dupfixed(root, pos, Some(between))
                .unwrap(),
            Some(op3)
        );
        assert_eq!(
            snap.next_posting_dupfixed(root, pos, Some(op3)).unwrap(),
            None
        );

        // Delete middle duplicate value without affecting op1 and op3
        let mut del_batch = MdbxWriteBatch::default();
        del_batch.delete(make_key(op2));
        env.write(del_batch).unwrap();

        let snap2 = env.snapshot().unwrap();
        assert_eq!(
            snap2.next_posting_dupfixed(root, pos, Some(op1)).unwrap(),
            Some(op3)
        );
        // Old MVCC snapshot still sees op2
        assert_eq!(
            snap.next_posting_dupfixed(root, pos, Some(op1)).unwrap(),
            Some(op2)
        );
        drop(snap);
        drop(snap2);

        // Test multi-page MDBX_GET_MULTIPLE / MDBX_NEXT_MULTIPLE (300 x 36B > 4096B page size)
        let root_multi = [9u8; 32];
        let mut multi_batch = MdbxWriteBatch::default();
        let mut expected_ops = Vec::with_capacity(300);
        for i in 0..300u32 {
            let mut op = [0u8; 36];
            op[..4].copy_from_slice(&i.to_be_bytes());
            expected_ops.push(op);
            let mut k = vec![b'p'];
            k.extend_from_slice(&root_multi);
            k.push(pos);
            k.extend_from_slice(&op);
            multi_batch.put(k, vec![]);
        }
        env.write(multi_batch).unwrap();

        let snap3 = env.snapshot().unwrap();
        let bulk = snap3
            .postings_dupfixed_after(root_multi, pos, None)
            .unwrap();
        assert_eq!(bulk, expected_ops);
        let bulk_after_150 = snap3
            .postings_dupfixed_after(root_multi, pos, Some(expected_ops[150]))
            .unwrap();
        assert_eq!(bulk_after_150, &expected_ops[151..]);

        let mut iter_ops = Vec::with_capacity(300);
        let mut cursor_op = None;
        while let Some(next_op) = snap3
            .next_posting_dupfixed(root_multi, pos, cursor_op)
            .unwrap()
        {
            iter_ops.push(next_op);
            cursor_op = Some(next_op);
        }
        assert_eq!(iter_ops, expected_ops);
        drop(snap3);

        // Flat file append, pread, and truncate
        env.flat().write_at(0, 0, b"hello ").unwrap();
        env.flat().write_at(0, 6, b"world!").unwrap();
        env.flat().sync_file(0).unwrap();
        assert_eq!(env.flat().read_at(0, 0, 12).unwrap(), b"hello world!");
        assert_eq!(env.flat().read_at(0, 6, 5).unwrap(), b"world");
        env.flat().truncate_to(0, 5).unwrap();
        assert_eq!(env.flat().read_at(0, 0, 5).unwrap(), b"hello");
        assert!(env.flat().read_at(0, 0, 6).is_err());
    }
}
