use super::*;
use crate::v2_branch::{Bounds, ConfirmedTx, SpentInput};
fn fixture() -> CommittedBlock {
    let anchor = Anchor {
        block_id: [3; 32],
        height: 1,
    };
    let parent = Anchor {
        block_id: [2; 32],
        height: 0,
    };
    let mut header_wire = [0; 134];
    header_wire[..32].copy_from_slice(&parent.block_id);
    header_wire[62..70].copy_from_slice(&1u64.to_le_bytes());
    let location = TxLocation {
        block_id: Hash32(anchor.block_id),
        height: 1,
        tx_index: 0,
        txid: TxId(Hash32([4; 32])),
        txhash: TxHash(Hash32([5; 32])),
    };
    CommittedBlock {
        anchor,
        parent,
        explorer: ExplorerBlockFacts { header_wire },
        transactions: vec![ConfirmedTx {
            location,
            pos: crate::v2_branch::TxPos {
                file_num: 3,
                data_pos: 128,
            },
            outputs: vec![],
            spends: Vec::<SpentInput>::new(),
            explorer: ExplorerTxFacts {
                wire: vec![42; WIRE_CHUNK_BYTES + 3],
                lock: u64::MAX,
                inputs: vec![InputFact {
                    prev_txid: [2; 32],
                    prev_index: 1,
                    sequence: u32::MAX,
                    flags: 2,
                    path_index: 255,
                    has_coinbase_data: true,
                    coinbase_data: WireRange {
                        offset: WIRE_CHUNK_BYTES as u64,
                        length: 3,
                    },
                    witnesses: vec![WitnessFact {
                        script: WireRange {
                            offset: 20,
                            length: 0,
                        },
                        siblings_table: WireRange {
                            offset: 21,
                            length: 1,
                        },
                        siblings_count: 0,
                        arguments_table: WireRange {
                            offset: 22,
                            length: 1,
                        },
                        arguments_count: 0,
                    }],
                }],
            },
        }],
    }
}
#[test]
fn complete_native_facts_and_chunk_entries_roundtrip() {
    let block = fixture();
    let facts = &block.transactions[0].explorer;
    let bytes = postcard::to_allocvec(facts).unwrap();
    assert_eq!(
        postcard::from_bytes::<ExplorerTxFacts>(&bytes).unwrap(),
        *facts
    );
    assert_eq!(
        postcard::from_bytes::<ExplorerBlockFacts>(
            &postcard::to_allocvec(&block.explorer).unwrap()
        )
        .unwrap(),
        block.explorer
    );
    let entries = plan_explorer_block(&block).unwrap();
    let id = block.transactions[0].location.txid;
    let find = |key: Vec<u8>| {
        entries.iter().find(|(k, _)| *k == key).unwrap().1.clone()
    };
    let tx_meta: TxMeta = decode_record(&find(tx_key(id))).unwrap();
    assert_eq!(tx_meta.file_num, 3);
    assert_eq!(tx_meta.data_pos, 128);
    assert_eq!(tx_meta.wire_size, facts.wire.len() as u64);
    assert_eq!(tx_meta.wire_checksum, seahash::hash(&facts.wire));
    assert!(!entries.iter().any(|(k, _)| k.starts_with(b"eR")));
    assert_ne!(id.0 .0, block.transactions[0].location.txhash.0 .0);
    assert_eq!(
        find(txhash_key(block.transactions[0].location.txhash)),
        id.0 .0
    );
    let input: StoredInputMeta =
        decode_record(&find(input_key(id, 0))).unwrap();
    assert_eq!(input.sequence, u32::MAX);
    assert_eq!(input.witness_count, 1);
    assert_eq!(input.coinbase_data.offset, WIRE_CHUNK_BYTES as u64);
    assert!(preflight_explorer_block(&block).unwrap() > facts.wire.len() * 3);
}
#[test]
fn ranges_and_incomplete_spends_fail_before_entries() {
    let mut block = fixture();
    block.transactions[0].explorer.inputs[0].coinbase_data = WireRange {
        offset: u64::MAX,
        length: 2,
    };
    assert!(plan_explorer_block(&block).is_err());
    let mut block = fixture();
    block.transactions[0].explorer.inputs[0].flags = 1;
    assert!(preflight_explorer_block(&block).is_ok());
    assert!(plan_explorer_block(&block).is_err());
    let mut block = fixture();
    block.explorer.header_wire[62] = 2;
    assert!(plan_explorer_block(&block).is_err());
}
#[test]
fn spend_input_metadata_does_not_copy_the_spent_output() {
    let mut block = fixture();
    let input = &mut block.transactions[0].explorer.inputs[0];
    input.flags = 1;
    let output = Output {
        flags: 0,
        value: u64::MAX,
        token_id: Hash32([0; 32]),
        branches: vec![Hash32([7; 32])],
        paths: vec![vec![0]],
    };
    let coin = ResolvedCreation {
        outpoint: OutPoint {
            txid: TxId(Hash32(input.prev_txid)),
            out_idx: input.prev_index,
        },
        output,
        creation: TxLocation {
            block_id: Hash32([2; 32]),
            height: 0,
            tx_index: 2,
            txid: TxId(Hash32(input.prev_txid)),
            txhash: TxHash(Hash32([8; 32])),
        },
    };
    block.transactions[0].spends.push(SpentInput {
        outpoint: coin.outpoint,
        input_index: 0,
    });
    let id = block.transactions[0].location.txid;
    let entries = plan_explorer_block(&block).unwrap();
    let stored = &entries.iter().find(|(k, _)| *k == input_key(id, 0)).unwrap().1;
    let input: StoredInputMeta = decode_record(stored).unwrap();
    assert_eq!(input.flags, 1);
    assert!(stored.len() < 64);
    let encoded = encode_record(&coin).unwrap();
    assert_eq!(decode_record::<ResolvedCreation>(&encoded).unwrap(), coin);
    assert_eq!(coin.output.value, u64::MAX);
}
#[test]
fn reservation_and_metadata_bounds_reject_oversize() {
    let bounds = Bounds::new(4096).unwrap();
    let mut block = fixture();
    block.transactions[0]
        .explorer
        .wire
        .resize(bounds.batch_bytes() / RESERVE_PER_WIRE_BYTE + 1, 0);
    assert!(preflight_explorer_block(&block).unwrap() > bounds.batch_bytes());
    assert!(decode_record::<TxMeta>(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
}

#[test]
fn valid_postcard_corrupt_input_fields_are_rejected_at_read_validation() {
    let input = InputMeta {
        prev_txid: [2; 32],
        prev_index: 1,
        sequence: u32::MAX,
        flags: 2,
        path_index: 0,
        has_coinbase_data: true,
        coinbase_data: WireRange {
            offset: 20,
            length: 3,
        },
        witness_count: 0,
        resolved_creation: None,
    };
    validate_input_meta(&input, 100).unwrap();
    let mut bad = input.clone();
    bad.flags = 255;
    let bad: InputMeta = decode_record(&encode_record(&bad).unwrap()).unwrap();
    assert!(matches!(
        validate_input_meta(&bad, 100),
        Err(Error::Corrupt)
    ));
    let mut bad = input.clone();
    bad.coinbase_data = WireRange {
        offset: u64::MAX,
        length: 1,
    };
    let bad: InputMeta = decode_record(&encode_record(&bad).unwrap()).unwrap();
    assert!(matches!(
        validate_input_meta(&bad, 100),
        Err(Error::Corrupt)
    ));
    let mut bad = input.clone();
    bad.witness_count = 1;
    assert!(matches!(
        validate_input_meta(&bad, 100),
        Err(Error::Corrupt)
    ));
    let mut bad = input;
    bad.flags = 1;
    bad.has_coinbase_data = false;
    bad.coinbase_data = WireRange::default();
    bad.witness_count = 1;
    assert!(matches!(
        validate_input_meta(&bad, 100),
        Err(Error::Corrupt)
    ));
}
#[test]
fn valid_postcard_corrupt_witness_tables_are_rejected_at_read_validation() {
    let witness = WitnessFact {
        script: WireRange {
            offset: 5,
            length: 3,
        },
        siblings_table: WireRange {
            offset: 9,
            length: 1,
        },
        siblings_count: 0,
        arguments_table: WireRange {
            offset: 10,
            length: 1,
        },
        arguments_count: 0,
    };
    validate_witness_fact(&witness, 20).unwrap();
    let mut bad = witness.clone();
    bad.arguments_table = WireRange {
        offset: u64::MAX,
        length: 1,
    };
    let bad: WitnessFact = decode_record(&encode_record(&bad).unwrap()).unwrap();
    assert!(matches!(
        validate_witness_fact(&bad, 20),
        Err(Error::Corrupt)
    ));
    let mut bad = witness.clone();
    bad.siblings_table.length = 0;
    assert!(matches!(
        validate_witness_fact(&bad, 20),
        Err(Error::Corrupt)
    ));
    let mut bad = witness;
    bad.arguments_count = 1;
    assert!(matches!(
        validate_witness_fact(&bad, 20),
        Err(Error::Corrupt)
    ));
}
