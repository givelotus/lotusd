use super::*;
use bitcoinsuite_core::lotus_v2::TxLocation;
use chronik_db::v2_branch::Anchor;
use std::{cell::Cell, collections::BTreeMap};
struct Fixture {
    tx: Option<TxMeta>,
    wire: Vec<u8>,
    reads: Cell<usize>,
    blocks: BTreeMap<u64, BlockMeta>,
}
impl Fixture {
    fn new() -> Self {
        let location = TxLocation {
            block_id: Hash32([1; 32]),
            height: 2,
            tx_index: 0,
            txid: TxId(Hash32([2; 32])),
            txhash: TxHash(Hash32([3; 32])),
        };
        let wire = (0..WIRE_CHUNK_BYTES * 2 + 7)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        let tx = TxMeta {
            location,
            lock: u64::MAX,
            input_count: 0,
            output_count: 0,
            file_num: 0,
            data_pos: 0,
            wire_size: wire.len() as u64,
            wire_checksum: 0,
        };
        let blocks = (0..3)
            .map(|height| {
                (
                    height,
                    BlockMeta {
                        anchor: Anchor {
                            block_id: if height == 2 {
                                [1; 32]
                            } else {
                                [height as u8 + 5; 32]
                            },
                            height,
                        },
                        header_wire: [0; 134],
                        tx_count: if height == 2 { 1 } else { 0 },
                    },
                )
            })
            .collect();
        Self {
            tx: Some(tx),
            wire,
            reads: Cell::new(0),
            blocks,
        }
    }
}
impl ExplorerSource for Fixture {
    fn block(&self, id: Hash32) -> Result<Option<BlockMeta>> {
        Ok(self
            .blocks
            .values()
            .find(|b| b.anchor.block_id == id.0)
            .cloned())
    }
    fn block_at_height(&self, h: u64) -> Result<Option<BlockMeta>> {
        Ok(self.blocks.get(&h).cloned())
    }
    fn transaction(&self, id: TxId) -> Result<Option<TxMeta>> {
        Ok(self.tx.clone().filter(|tx| tx.location.txid == id))
    }
    fn transaction_by_hash(&self, h: TxHash) -> Result<Option<TxMeta>> {
        Ok(self.tx.clone().filter(|tx| tx.location.txhash == h))
    }
    fn block_transaction(&self, b: Hash32, i: u32) -> Result<Option<(TxId, TxHash)>> {
        Ok(self
            .tx
            .as_ref()
            .filter(|tx| tx.location.block_id == b && tx.location.tx_index == i)
            .map(|tx| (tx.location.txid, tx.location.txhash)))
    }
    fn input(&self, _: TxId, _: u32) -> Result<Option<InputMeta>> {
        Ok(None)
    }
    fn witness(&self, _: TxId, _: u32, _: u32) -> Result<Option<WitnessFact>> {
        Ok(None)
    }
    fn output(&self, _: OutPoint) -> Result<Option<OutputRecord>> {
        Ok(None)
    }
    fn wire(&self, _: TxId, chunk: u32) -> Result<Option<Vec<u8>>> {
        self.reads.set(self.reads.get() + 1);
        Ok(self
            .wire
            .chunks(WIRE_CHUNK_BYTES)
            .nth(chunk as usize)
            .map(|c| c.to_vec()))
    }
}
#[test]
fn exact_chunks_reconstruct_frame_with_at_most_two_reads() {
    let f = Fixture::new();
    let id = f.tx.as_ref().unwrap().location.txid;
    let mut full = vec![];
    let mut offset = 0;
    loop {
        let before = f.reads.get();
        let chunk = wire_chunk(&f, id, offset, 32768).unwrap().unwrap();
        assert!(f.reads.get() - before <= 2);
        full.extend(chunk.bytes);
        match chunk.next_offset {
            Some(n) => {
                assert!(n > offset);
                offset = n
            }
            None => break,
        }
    }
    assert_eq!(full, f.wire);
    let cross = wire_chunk(&f, id, 32767, 32768).unwrap().unwrap();
    assert_eq!(cross.bytes, f.wire[32767..65535]);
    let end = wire_chunk(&f, id, f.wire.len() as u64, 1).unwrap().unwrap();
    assert!(end.bytes.is_empty());
    assert_eq!(end.next_offset, None);
    assert!(wire_chunk(&f, id, f.wire.len() as u64 + 1, 1).is_err());
    assert!(wire_chunk(&f, id, 0, 0).is_err());
    assert!(wire_chunk(&f, id, 0, 32769).is_err());
}
#[test]
fn typed_identity_and_decimal_integers_are_exact() {
    let f = Fixture::new();
    let tx = f.tx.as_ref().unwrap();
    assert_eq!(
        f.transaction_by_hash(tx.location.txhash).unwrap(),
        Some(tx.clone())
    );
    assert!(f.transaction(TxId(tx.location.txhash.0)).unwrap().is_none());
    assert_eq!(unsigned_decimal(u64::MAX), "18446744073709551615");
    assert_eq!(
        unsigned_decimal(u128::MAX),
        "340282366920938463463374607431768211455"
    );
    assert_eq!(confirmations(2, 2).unwrap(), 1);
    assert!(confirmations(1, 2).is_err());
    assert!(confirmations(u64::MAX, 0).is_err());
}
#[test]
fn pages_advance_and_reorg_removes_canonical_objects() {
    let mut f = Fixture::new();
    let tx = f.tx.clone().unwrap();
    let first = blocks_page(&f, 2, None, 1).unwrap();
    assert_eq!(first.items[0].anchor.height, 2);
    assert_eq!(first.next_index, Some(2));
    let second = blocks_page(&f, 2, first.next_index, 2).unwrap();
    assert_eq!(
        second
            .items
            .iter()
            .map(|b| b.anchor.height)
            .collect::<Vec<_>>(),
        vec![1, 0]
    );
    assert!(second.exhausted);
    let txs = block_transactions_page(&f, tx.location.block_id, None, 1)
        .unwrap()
        .unwrap();
    assert_eq!(txs.items, vec![tx.clone()]);
    assert!(txs.exhausted);
    assert!(blocks_page(&f, 2, None, 101).is_err());
    f.tx = None;
    f.blocks.remove(&2);
    assert!(wire_chunk(&f, tx.location.txid, 0, 32).unwrap().is_none());
    assert!(block_transactions_page(&f, tx.location.block_id, None, 1)
        .unwrap()
        .is_none());
    assert!(blocks_page(&f, 2, None, 1).is_err());
}
#[test]
fn oversize_indivisible_record_errors_without_stuck_cursor() {
    assert!(ordinal_page(1, None, 1, 0, 1, |_| Ok(((), MAX_PAGE_BYTES + 1))).is_err());
    let page = ordinal_page(3, None, 3, 0, 1, |i| Ok((i, MAX_PAGE_BYTES / 2))).unwrap();
    assert_eq!(page.items, vec![0, 1]);
    assert_eq!(page.examined, 3);
    assert_eq!(page.key_reads, 3);
    assert_eq!(page.next_index, Some(1));
    assert!(!page.exhausted);
    assert!(ordinal_page::<()>(2, Some(2), 1, 0, 1, |_| Ok(((), 1))).is_err());
}
