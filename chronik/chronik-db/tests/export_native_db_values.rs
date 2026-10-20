// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Test-only exporter of golden DB value bytes for the native C++ Chronik
//! (chronik/native). It writes `chronik/native/test/fixtures/db_values.json`,
//! a flat JSON object `{"case name": "hex bytes", ...}` with the exact bytes
//! the Rust chronik-db stores as values (and a few value-like keys) in its
//! tables: blocks, block stats, txs, reverse-lookup indexes, spent-by, group
//! history pages and merge operands, UTXO duplicate values, metadata and the
//! token tables (`DbTokenTx`, `TokenMeta`, `GenesisInfo`). The native test
//! chronik/native/test/golden_db_values_tests.cpp decodes every case with the
//! native codecs, re-encodes it and requires byte equality.
//!
//! The fixtures describe the eCash-tier storage layout, which the Lotus V2
//! tier keeps (including `UtxoDataOutput`'s `sats LE8 || script` duplicate
//! entries), so the exporter gives the same bytes on either tier:
//!
//!   CHRONIK_NATIVE_FIXTURES_DIR=<repo>/chronik/native/test/fixtures \
//!   cargo test --locked -p chronik-db --test export_native_db_values
//!
//! Without `CHRONIK_NATIVE_FIXTURES_DIR` it writes next to this crate
//! (`../native/test/fixtures`). On macOS the build needs `LIBCLANG_PATH` and
//! `DYLD_FALLBACK_LIBRARY_PATH` (e.g. /Library/Developer/CommandLineTools/
//! usr/lib) and `PYO3_PYTHON` (a Python <= 3.13).
//!
//! `SerBlock`, `SerTx` and the BE key helpers are private to chronik-db; they
//! are mirrored here with the same field order and types (postcard encodes a
//! struct as its fields in order, so the bytes are identical). All other value
//! types are the real public crate types.

use std::{collections::BTreeMap, fmt::Write as _, path::PathBuf};

use bitcoinsuite_core::{hash::ShaRmd160, tx::TxId};
use bitcoinsuite_slp::{
    structs::{GenesisInfo, TokenMeta},
    token_id::TokenId,
    token_type::{AlpTokenType, SlpTokenType, TokenType},
};
use chronik_db::{
    data::DbOutpoint,
    group::{UtxoData, UtxoDataOutput, UtxoDataValue},
    io::{
        token::{DbToken, DbTokenTx},
        BlockStats, SpentByEntry,
    },
};
use serde::Serialize;

/// Mirror of chronik-db `io::blocks::SerBlock` (private).
#[derive(Serialize)]
struct SerBlock {
    hash: [u8; 32],
    n_bits: u32,
    timestamp: i64,
    file_num: u32,
    data_pos: u32,
}

/// Mirror of chronik-db `io::txs::SerTx` (private).
#[derive(Serialize)]
struct SerTx {
    txid: [u8; 32],
    data_pos: u32,
    undo_pos: u32,
    time_first_seen: i64,
    is_legacy: bool,
}

struct Fixtures(BTreeMap<String, String>);

impl Fixtures {
    fn pc<T: Serialize + ?Sized>(&mut self, name: &str, value: &T) {
        let bytes = postcard::to_allocvec(value).expect("postcard");
        self.raw(name, &bytes);
    }

    /// `db_serialize_vec`: concatenated postcard items, no length prefix.
    fn pc_vec<T: Serialize>(&mut self, name: &str, items: &[T]) {
        let mut bytes = Vec::new();
        for item in items {
            bytes.extend(postcard::to_allocvec(item).expect("postcard"));
        }
        self.raw(name, &bytes);
    }

    fn raw(&mut self, name: &str, bytes: &[u8]) {
        let prev = self.0.insert(name.to_string(), hex::encode(bytes));
        assert!(prev.is_none(), "duplicate fixture {name}");
    }

    fn to_json(&self) -> String {
        let mut s = String::from("{\n");
        let n = self.0.len();
        for (i, (k, v)) in self.0.iter().enumerate() {
            let comma = if i + 1 < n { "," } else { "" };
            writeln!(s, "  \"{k}\": \"{v}\"{comma}").unwrap();
        }
        s.push_str("}\n");
        s
    }
}

fn seq(n: usize, mul: u8, add: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(mul).wrapping_add(add))
        .collect()
}

fn arr32(mul: u8, add: u8) -> [u8; 32] {
    seq(32, mul, add).try_into().unwrap()
}

fn token_id(mul: u8, add: u8) -> TokenId {
    TokenId::new(TxId::new(arr32(mul, add)))
}

/// Mirror of the private `encode_utxo_dup` of io/group_utxos.rs.
fn utxo_dup<D: UtxoData>(tx_num: u64, out_idx: u32, data: &D) -> Vec<u8> {
    let outpoint = DbOutpoint { tx_num, out_idx };
    let mut buf = Vec::new();
    buf.extend_from_slice(&outpoint.tx_num.to_be_bytes());
    buf.extend_from_slice(&outpoint.out_idx.to_be_bytes());
    data.ser_dup_data(&mut buf);
    buf
}

#[test]
fn export_native_db_values() {
    let mut f = Fixtures(BTreeMap::new());

    // ---- blk: BlockHeight BE4 -> SerBlock ----
    f.pc(
        "SerBlock/genesis",
        &SerBlock {
            hash: arr32(1, 0),
            n_bits: 0x207f_ffff,
            timestamp: 1_296_688_602,
            file_num: 0,
            data_pos: 8,
        },
    );
    f.pc(
        "SerBlock/max",
        &SerBlock {
            hash: [0xff; 32],
            n_bits: u32::MAX,
            timestamp: i64::MAX,
            file_num: u32::MAX,
            data_pos: u32::MAX,
        },
    );
    f.pc(
        "SerBlock/neg_ts",
        &SerBlock {
            hash: arr32(3, 7),
            n_bits: 0x1d00_ffff,
            timestamp: i64::MIN,
            file_num: 127,
            data_pos: 128,
        },
    );

    // ---- blk_by_first_tx: TxNum BE8 -> BlockHeight BE4;
    //      first_tx_by_blk: BlockHeight BE4 -> TxNum BE8 ----
    for h in [0i32, 1, 1_000_000, i32::MAX] {
        f.raw(&format!("BlockHeightBe/{h}"), &h.to_be_bytes());
    }
    for n in [0u64, 1, 1 << 40, u64::MAX] {
        f.raw(&format!("TxNumBe/{n}"), &n.to_be_bytes());
    }

    // ---- blk_stats: BlockHeight BE4 -> BlockStats ----
    f.pc("BlockStats/zero", &BlockStats::default());
    f.pc(
        "BlockStats/typical",
        &BlockStats {
            block_size: 285,
            num_txs: 1,
            num_inputs: 1,
            num_outputs: 2,
            sum_input_sats: 0,
            sum_coinbase_output_sats: 5_000_000_000,
            sum_normal_output_sats: 0,
            sum_burned_sats: 0,
        },
    );
    f.pc(
        "BlockStats/extremes",
        &BlockStats {
            block_size: u64::MAX,
            num_txs: 128,
            num_inputs: 1 << 35,
            num_outputs: 0x3fff,
            sum_input_sats: i64::MAX,
            sum_coinbase_output_sats: i64::MIN,
            sum_normal_output_sats: -1,
            sum_burned_sats: 64,
        },
    );

    // ---- tx: TxNum BE8 -> SerTx ----
    f.pc(
        "SerTx/coinbase",
        &SerTx {
            txid: arr32(2, 9),
            data_pos: 81,
            undo_pos: 0,
            time_first_seen: 0,
            is_legacy: false,
        },
    );
    f.pc(
        "SerTx/normal",
        &SerTx {
            txid: arr32(5, 7),
            data_pos: 0x00ff_ff00,
            undo_pos: 0x1234,
            time_first_seen: 1_699_999_999,
            is_legacy: false,
        },
    );
    f.pc(
        "SerTx/max",
        &SerTx {
            txid: [0xee; 32],
            data_pos: u32::MAX,
            undo_pos: u32::MAX,
            time_first_seen: -1,
            is_legacy: false,
        },
    );

    // ---- lookup_tx_by_hash / lookup_blk_by_hash:
    //      CheapHash -> postcard Vec<SerialNum>; merge operand: SerialNum ----
    f.pc("LookupTxNums/one", &vec![5u64]);
    f.pc("LookupTxNums/many", &vec![0u64, 127, 128, 1 << 40, u64::MAX]);
    f.pc("LookupTxNums/empty", &Vec::<u64>::new());
    f.pc("LookupTxNumOperand/300", &300u64);
    f.pc("LookupHeights/one", &vec![0i32]);
    f.pc("LookupHeights/many", &vec![1i32, 63, 64, 1_000_000, i32::MAX]);
    f.pc("LookupHeightOperand/700000", &700_000i32);

    // ---- spent_by: TxNum BE8 -> concatenated postcard SpentByEntry ----
    f.pc_vec(
        "SpentByEntries/one",
        &[SpentByEntry { out_idx: 0, tx_num: 0, input_idx: 0 }],
    );
    f.pc_vec(
        "SpentByEntries/three",
        &[
            SpentByEntry { out_idx: 0, tx_num: 1, input_idx: 0 },
            SpentByEntry { out_idx: 1, tx_num: 300, input_idx: 2 },
            SpentByEntry { out_idx: 200, tx_num: u64::MAX, input_idx: 70000 },
        ],
    );
    f.pc_vec(
        "SpentByEntries/max",
        &[SpentByEntry {
            out_idx: u32::MAX,
            tx_num: u64::MAX,
            input_idx: u32::MAX,
        }],
    );

    // ---- *_history: member || PageNum BE4 -> concatenated postcard TxNum;
    //      *_history_num_txs: member -> NumTxs BE4 ----
    f.pc_vec("HistoryPage/one", &[0u64]);
    f.pc_vec("HistoryPage/many", &[1u64, 127, 128, 16383, 16384, 1 << 40, u64::MAX]);
    let full_page: Vec<u64> = (0..1000u64).map(|i| i * 997).collect();
    f.pc_vec("HistoryPage/full_1000", &full_page);
    let mut concat = vec![b'C'];
    for n in [42u64, 128] {
        concat.extend(postcard::to_allocvec(&n).unwrap());
    }
    f.raw("HistoryOperand/concat", &concat);
    let mut trim = vec![b'T'];
    trim.extend_from_slice(&9u32.to_be_bytes());
    f.raw("HistoryOperand/trim", &trim);
    for n in [0u32, 1, 1000, u32::MAX] {
        f.raw(&format!("NumTxsBe/{n}"), &n.to_be_bytes());
    }
    let member = [0x01u8, 0x02, 0x03];
    for page in [0u32, 1, 0x0102_0304] {
        let key = [member.as_ref(), &page.to_be_bytes()].concat();
        f.raw(&format!("HistoryPageKey/{page}"), &key);
    }

    // ---- script_utxo (UtxoDataValue) / token_id_utxo (UtxoDataOutput) dups:
    //      tx_num BE8 || out_idx BE4 || UtxoData payload ----
    let value_cases: [(&str, u64, u32, UtxoDataValue); 4] = [
        ("zero", 0, 0, 0),
        ("typical", 12345, 1, 5_000_000_000),
        ("negative", 1 << 40, 0xffff, -1),
        ("max", u64::MAX, u32::MAX, i64::MAX),
    ];
    for (name, tx_num, out_idx, sats) in value_cases {
        f.raw(&format!("UtxoDupValue/{name}"), &utxo_dup(tx_num, out_idx, &sats));
    }
    let mut p2pkh = vec![0x76, 0xa9, 20];
    p2pkh.extend(seq(20, 3, 1));
    p2pkh.extend([0x88, 0xac]);
    let output_cases: [(&str, u64, u32, UtxoDataOutput); 4] = [
        ("empty_script", 0, 0, (546, vec![].into())),
        ("p2pkh", 77, 2, (546, p2pkh.into())),
        ("op_return", 1 << 33, 0, (0, vec![0x6a, 4, b'S', b'L', b'P', 0].into())),
        ("long_script", u64::MAX, u32::MAX, (i64::MIN, seq(300, 7, 1).into())),
    ];
    for (name, tx_num, out_idx, data) in output_cases {
        f.raw(&format!("UtxoDupOutput/{name}"), &utxo_dup(tx_num, out_idx, &data));
    }

    // ---- meta ----
    for v in [0u64, 13, 300] {
        f.pc(&format!("MetaSchemaVersion/{v}"), &v);
    }
    f.pc("MetaBool/false", &false);
    f.pc("MetaBool/true", &true);

    // ---- token_meta: TxNum BE8 (GENESIS) -> TokenMeta ----
    let token_types = [
        ("slp_fungible", TokenType::Slp(SlpTokenType::Fungible)),
        ("slp_mint_vault", TokenType::Slp(SlpTokenType::MintVault)),
        ("slp_nft1_group", TokenType::Slp(SlpTokenType::Nft1Group)),
        ("slp_nft1_child", TokenType::Slp(SlpTokenType::Nft1Child)),
        ("slp_unknown_0", TokenType::Slp(SlpTokenType::Unknown(0))),
        ("slp_unknown_7", TokenType::Slp(SlpTokenType::Unknown(7))),
        ("slp_unknown_255", TokenType::Slp(SlpTokenType::Unknown(255))),
        ("alp_standard", TokenType::Alp(AlpTokenType::Standard)),
        ("alp_unknown_1", TokenType::Alp(AlpTokenType::Unknown(1))),
        ("alp_unknown_255", TokenType::Alp(AlpTokenType::Unknown(255))),
    ];
    for (i, (name, token_type)) in token_types.into_iter().enumerate() {
        f.pc(
            &format!("TokenMeta/{name}"),
            &TokenMeta {
                token_id: token_id(7, i as u8),
                token_type,
            },
        );
    }

    // ---- token_genesis_info: TxNum BE8 (GENESIS) -> GenesisInfo ----
    f.pc("GenesisInfo/slp_empty", &GenesisInfo::empty_slp());
    f.pc("GenesisInfo/alp_empty", &GenesisInfo::empty_alp());
    f.pc(
        "GenesisInfo/slp_fungible",
        &GenesisInfo {
            token_ticker: b"SLPT".to_vec().into(),
            token_name: b"SLP Test Token".to_vec().into(),
            mint_vault_scripthash: None,
            url: b"https://example.com/slp".to_vec().into(),
            hash: Some(arr32(4, 4)),
            data: None,
            auth_pubkey: None,
            decimals: 4,
        },
    );
    f.pc(
        "GenesisInfo/slp_no_hash",
        &GenesisInfo {
            token_ticker: b"N".to_vec().into(),
            token_name: vec![].into(),
            mint_vault_scripthash: None,
            url: vec![].into(),
            hash: None,
            data: None,
            auth_pubkey: None,
            decimals: 9,
        },
    );
    f.pc(
        "GenesisInfo/slp_mint_vault",
        &GenesisInfo {
            token_ticker: b"MV".to_vec().into(),
            token_name: b"Mint vault".to_vec().into(),
            mint_vault_scripthash: Some(ShaRmd160(
                seq(20, 2, 1).try_into().unwrap(),
            )),
            url: b"x".to_vec().into(),
            hash: Some([0u8; 32]),
            data: None,
            auth_pubkey: None,
            decimals: 0,
        },
    );
    f.pc(
        "GenesisInfo/alp_full",
        &GenesisInfo {
            token_ticker: b"ALP".to_vec().into(),
            token_name: b"ALP Token".to_vec().into(),
            mint_vault_scripthash: None,
            url: b"https://example.com/alp".to_vec().into(),
            hash: None,
            data: Some(seq(200, 5, 3).into()),
            auth_pubkey: Some(seq(33, 1, 2).into()),
            decimals: 8,
        },
    );
    f.pc(
        "GenesisInfo/alp_empty_data_pubkey",
        &GenesisInfo {
            token_ticker: b"A".to_vec().into(),
            token_name: b"B".to_vec().into(),
            mint_vault_scripthash: None,
            url: vec![].into(),
            hash: None,
            data: Some(vec![].into()),
            auth_pubkey: Some(seq(33, 3, 2).into()),
            decimals: 255,
        },
    );
    f.pc(
        "GenesisInfo/long_fields",
        &GenesisInfo {
            token_ticker: seq(130, 1, 0).into(),
            token_name: seq(300, 3, 1).into(),
            mint_vault_scripthash: Some(ShaRmd160([0xff; 20])),
            url: seq(17000, 1, 1).into(),
            hash: Some([0xff; 32]),
            data: Some(seq(128, 9, 9).into()),
            auth_pubkey: Some(vec![].into()),
            decimals: 1,
        },
    );

    // ---- token_tx: TxNum BE8 -> DbTokenTx ----
    f.pc("DbTokenTx/default", &DbTokenTx::default());
    f.pc(
        "DbTokenTx/slp_send",
        &DbTokenTx {
            token_tx_nums: vec![5],
            group_token_indices: BTreeMap::new(),
            inputs: vec![DbToken::Atoms(0, 1000), DbToken::NoToken],
            outputs: vec![
                DbToken::NoToken,
                DbToken::Atoms(0, 600),
                DbToken::Atoms(0, 400),
            ],
            flags: 0,
        },
    );
    f.pc(
        "DbTokenTx/mint_vault_flag",
        &DbTokenTx {
            token_tx_nums: vec![1 << 33],
            group_token_indices: BTreeMap::new(),
            inputs: vec![DbToken::NoToken],
            outputs: vec![DbToken::NoToken, DbToken::Atoms(0, u64::MAX)],
            flags: 1,
        },
    );
    f.pc(
        "DbTokenTx/flags_ff",
        &DbTokenTx {
            token_tx_nums: vec![],
            group_token_indices: BTreeMap::new(),
            inputs: vec![],
            outputs: vec![],
            flags: 0xff,
        },
    );
    let mut group_token_indices = BTreeMap::new();
    group_token_indices.insert(0, 1);
    group_token_indices.insert(2, 1);
    f.pc(
        "DbTokenTx/nft1_child_group",
        &DbTokenTx {
            token_tx_nums: vec![700, 300, 701],
            group_token_indices,
            inputs: vec![DbToken::Atoms(1, 1), DbToken::Atoms(0, 1)],
            outputs: vec![
                DbToken::NoToken,
                DbToken::Atoms(0, 1),
                DbToken::Atoms(2, 1),
            ],
            flags: 0,
        },
    );
    let mut group_token_indices = BTreeMap::new();
    group_token_indices.insert(1, 0);
    group_token_indices.insert(u32::MAX, 128);
    f.pc(
        "DbTokenTx/all_variants",
        &DbTokenTx {
            token_tx_nums: vec![5, 1 << 33, u64::MAX],
            group_token_indices,
            inputs: vec![
                DbToken::NoToken,
                DbToken::Atoms(0, 1000),
                DbToken::MintBaton(1),
                DbToken::UnknownSlp(0x88),
                DbToken::UnknownAlp(0xff),
            ],
            outputs: vec![
                DbToken::NoToken,
                DbToken::Atoms(1, 0xffff_ffff_ffff),
                DbToken::MintBaton(u32::MAX),
                DbToken::UnknownSlp(0),
                DbToken::UnknownAlp(3),
                DbToken::Atoms(u32::MAX, u64::MAX),
            ],
            flags: 1,
        },
    );
    let many: Vec<DbToken> = (0..200u32)
        .map(|i| match i % 5 {
            0 => DbToken::NoToken,
            1 => DbToken::Atoms(i % 3, u64::from(i) << 20),
            2 => DbToken::MintBaton(i % 3),
            3 => DbToken::UnknownSlp(i as u8),
            _ => DbToken::UnknownAlp(i as u8),
        })
        .collect();
    f.pc(
        "DbTokenTx/many_200",
        &DbTokenTx {
            token_tx_nums: (0..130u64).map(|i| i * 1_000_003).collect(),
            group_token_indices: (0..130u32).map(|i| (i, 129 - i)).collect(),
            inputs: many.clone(),
            outputs: many,
            flags: 0,
        },
    );

    let dir = std::env::var_os("CHRONIK_NATIVE_FIXTURES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../native/test/fixtures")
        });
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("db_values.json"), f.to_json()).unwrap();
}
