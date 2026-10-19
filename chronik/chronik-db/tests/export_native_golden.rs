// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Test-only exporter of golden byte vectors for the native C++ Chronik
//! (chronik/native). It writes `chronik/native/test/fixtures/codec.json`, a
//! flat JSON object `{"case name": "hex bytes", ...}` holding the postcard
//! encodings, seahash values and script compressions the Rust Chronik writes
//! to its database. The native unit tests re-encode every case and require
//! byte equality.
//!
//! Run: `cargo test -p chronik-db --test export_native_golden`
//!
//! `SerBlock` and `SerTx` are private to chronik-db; they are mirrored here
//! with the same field order and types (serde/postcard encode a struct as its
//! fields in order, so the bytes are identical). All other value types are the
//! real public crate types.

use std::{collections::BTreeMap, fmt::Write as _, path::PathBuf};

use bitcoinsuite_core::{
    hash::ShaRmd160,
    script::{compress_script_variant, Script},
    tx::TxId,
};
use bitcoinsuite_slp::{
    structs::{GenesisInfo, TokenMeta},
    token_id::TokenId,
    token_type::{AlpTokenType, SlpTokenType, TokenType},
};
use chronik_db::io::{
    token::{DbToken, DbTokenTx},
    BlockStats, SpentByEntry,
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
}

struct Fixtures(BTreeMap<String, String>);

impl Fixtures {
    fn pc<T: Serialize>(&mut self, name: &str, value: &T) {
        let bytes = postcard::to_allocvec(value).expect("postcard");
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

#[test]
fn export_native_golden() {
    let mut f = Fixtures(BTreeMap::new());

    // ---- primitives ----
    for v in [0u16, 1, 0x7f, 0x80, 0x3fff, 0x4000, u16::MAX] {
        f.pc(&format!("u16/{v}"), &v);
    }
    for v in [0u32, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fffff, 0x200000,
              0x0fffffff, 0x10000000, u32::MAX] {
        f.pc(&format!("u32/{v}"), &v);
    }
    for v in [0u64, 1, 0x7f, 0x80, u32::MAX as u64, 1 << 35, 1 << 56,
              (1 << 63) - 1, 1 << 63, u64::MAX] {
        f.pc(&format!("u64/{v}"), &v);
    }
    for v in [0i32, 1, -1, 63, -64, 64, -65, i32::MAX, i32::MIN] {
        f.pc(&format!("i32/{v}"), &v);
    }
    for v in [0i64, 1, -1, 63, -64, 64, -65, i32::MAX as i64,
              i32::MIN as i64, i64::MAX, i64::MIN] {
        f.pc(&format!("i64/{v}"), &v);
    }
    for v in [0i16, -1, i16::MAX, i16::MIN] {
        f.pc(&format!("i16/{v}"), &v);
    }
    for v in [0u128, 1, u64::MAX as u128, u128::MAX] {
        f.pc(&format!("u128/{v}"), &v);
    }
    f.pc("u8/0", &0u8);
    f.pc("u8/255", &255u8);
    f.pc("bool/false", &false);
    f.pc("bool/true", &true);
    f.pc("option_u32/none", &None::<u32>);
    f.pc("option_u32/some_300", &Some(300u32));
    f.pc("option_bytes/some", &Some(bytes::Bytes::from(vec![1u8, 2, 3])));
    f.pc("string/empty", &String::new());
    f.pc("string/native", &"native/v0.34.1".to_string());
    f.pc("string/unicode", &"ünï ✓".to_string());
    f.pc("vec_u8/empty", &Vec::<u8>::new());
    f.pc("vec_u8/200", &seq(200, 7, 3));
    f.pc("vec_i32/heights", &vec![0i32, 1, 1000, 1_000_000, i32::MAX]);
    f.pc("vec_u64/tx_nums", &vec![0u64, 127, 128, 1 << 40, u64::MAX]);
    let mut map = BTreeMap::new();
    map.insert(5u32, 1u32);
    map.insert(0u32, 300u32);
    map.insert(1000u32, 0u32);
    f.pc("btreemap_u32_u32", &map);

    // ---- seahash ----
    for n in [0usize, 1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 63, 64,
              65, 100, 1000] {
        let data = seq(n, 13, 5);
        f.raw(&format!("seahash/{n}"), &seahash::hash(&data).to_be_bytes());
    }
    f.raw("seahash/txid", &seahash::hash(&arr32(3, 1)).to_be_bytes());

    // ---- script compression (compress_script_variant(&script.variant())) --
    let mut scripts: Vec<(&str, Vec<u8>)> = vec![];
    let mut p2pkh = vec![0x76, 0xa9, 20];
    p2pkh.extend(seq(20, 3, 1));
    p2pkh.extend([0x88, 0xac]);
    scripts.push(("p2pkh", p2pkh));
    let mut p2sh = vec![0xa9, 20];
    p2sh.extend(seq(20, 5, 2));
    p2sh.push(0x87);
    scripts.push(("p2sh", p2sh));
    let mut p2pk02 = vec![33, 0x02];
    p2pk02.extend(seq(32, 9, 4));
    p2pk02.push(0xac);
    scripts.push(("p2pk_compressed_02", p2pk02));
    let mut p2pk03 = vec![33, 0x03];
    p2pk03.extend(seq(32, 9, 4));
    p2pk03.push(0xac);
    scripts.push(("p2pk_compressed_03", p2pk03));
    let mut p2pk_even = vec![65, 0x04];
    p2pk_even.extend(seq(63, 11, 6));
    p2pk_even.push(0x10);
    p2pk_even.push(0xac);
    scripts.push(("p2pk_uncompressed_even", p2pk_even));
    let mut p2pk_odd = vec![65, 0x04];
    p2pk_odd.extend(seq(63, 11, 6));
    p2pk_odd.push(0x11);
    p2pk_odd.push(0xac);
    scripts.push(("p2pk_uncompressed_odd", p2pk_odd));
    let mut bad_pk = vec![33, 0x04];
    bad_pk.extend(seq(32, 9, 4));
    bad_pk.push(0xac);
    scripts.push(("other_bad_pubkey_prefix", bad_pk));
    scripts.push(("other_empty", vec![]));
    scripts.push(("other_op_return", vec![0x6a, 4, b'S', b'L', b'P', 0]));
    scripts.push(("other_121", vec![4; 121]));
    scripts.push(("other_122", vec![4; 122]));
    scripts.push(("other_10000", seq(10000, 1, 0)));
    let mut p2pkh_long = vec![0x76, 0xa9, 20];
    p2pkh_long.extend(seq(20, 3, 1));
    p2pkh_long.extend([0x88, 0xac, 0x00]);
    scripts.push(("other_p2pkh_trailing", p2pkh_long));
    for (name, script) in scripts {
        f.raw(&format!("script/{name}"), &script);
        let compressed = compress_script_variant(
            &Script::new(script.clone().into()).variant(),
        );
        f.raw(&format!("compress/{name}"), &compressed);
    }

    // ---- DB value structs ----
    f.pc(
        "SerBlock/a",
        &SerBlock {
            hash: arr32(1, 0),
            n_bits: 0x1d00ffff,
            timestamp: 1_700_000_000,
            file_num: 3,
            data_pos: 0x0102_0304,
        },
    );
    f.pc(
        "SerBlock/neg_ts",
        &SerBlock {
            hash: [0xff; 32],
            n_bits: u32::MAX,
            timestamp: -1,
            file_num: 0,
            data_pos: 8,
        },
    );
    f.pc(
        "BlockStats/a",
        &BlockStats {
            block_size: 1_000_000,
            num_txs: 2,
            num_inputs: 3,
            num_outputs: 4,
            sum_input_sats: 5_000_000_000,
            sum_coinbase_output_sats: 625_000_000,
            sum_normal_output_sats: -7,
            sum_burned_sats: 0,
        },
    );
    f.pc(
        "SerTx/coinbase",
        &SerTx {
            txid: arr32(2, 9),
            data_pos: 81,
            undo_pos: 0,
            time_first_seen: 0,
        },
    );
    f.pc(
        "SerTx/normal",
        &SerTx {
            txid: arr32(5, 7),
            data_pos: 0x00ff_ff00,
            undo_pos: 0x1234,
            time_first_seen: 1_699_999_999,
        },
    );
    // spent_by: pc* of entries (no length prefix)
    let entries = [
        SpentByEntry { out_idx: 0, tx_num: 1, input_idx: 0 },
        SpentByEntry { out_idx: 1, tx_num: 300, input_idx: 2 },
        SpentByEntry { out_idx: 200, tx_num: u64::MAX, input_idx: 70000 },
    ];
    let mut spent_by = Vec::new();
    for entry in &entries {
        spent_by.extend(postcard::to_allocvec(entry).unwrap());
    }
    f.raw("SpentByEntries/three", &spent_by);
    // spent_by key: postcard varint tx_num
    f.pc("SpentByKey/0", &0u64);
    f.pc("SpentByKey/1000000", &1_000_000u64);

    let token_types = [
        ("slp_fungible", TokenType::Slp(SlpTokenType::Fungible)),
        ("slp_mint_vault", TokenType::Slp(SlpTokenType::MintVault)),
        ("slp_nft1_group", TokenType::Slp(SlpTokenType::Nft1Group)),
        ("slp_nft1_child", TokenType::Slp(SlpTokenType::Nft1Child)),
        ("slp_unknown_7", TokenType::Slp(SlpTokenType::Unknown(7))),
        ("alp_standard", TokenType::Alp(AlpTokenType::Standard)),
        ("alp_unknown_255", TokenType::Alp(AlpTokenType::Unknown(255))),
    ];
    for (name, token_type) in token_types {
        f.pc(
            &format!("TokenMeta/{name}"),
            &TokenMeta {
                token_id: TokenId::new(TxId::new(arr32(7, 3))),
                token_type,
            },
        );
    }

    f.pc("GenesisInfo/default", &GenesisInfo::default());
    f.pc(
        "GenesisInfo/full",
        &GenesisInfo {
            token_ticker: b"TKN".to_vec().into(),
            token_name: b"Token name".to_vec().into(),
            mint_vault_scripthash: Some(ShaRmd160(seq(20, 2, 1).try_into().unwrap())),
            url: b"https://example.com".to_vec().into(),
            hash: Some(arr32(4, 4)),
            data: Some(vec![0u8; 0].into()),
            auth_pubkey: Some(seq(33, 1, 2).into()),
            decimals: 9,
        },
    );

    let mut group_token_indices = BTreeMap::new();
    group_token_indices.insert(1, 0);
    f.pc("DbTokenTx/default", &DbTokenTx::default());
    f.pc(
        "DbTokenTx/full",
        &DbTokenTx {
            token_tx_nums: vec![5, 1 << 33],
            group_token_indices,
            inputs: vec![
                DbToken::NoToken,
                DbToken::Atoms(0, 1000),
                DbToken::MintBaton(1),
            ],
            outputs: vec![
                DbToken::NoToken,
                DbToken::Atoms(1, 0xffff_ffff_ffff),
                DbToken::UnknownSlp(0x88),
                DbToken::UnknownAlp(3),
            ],
            flags: 1,
        },
    );

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../native/test/fixtures/codec.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, f.to_json()).unwrap();
}
