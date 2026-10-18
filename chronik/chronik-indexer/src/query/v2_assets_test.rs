use super::*;
use bitcoinsuite_core::lotus_v2::{Output, TxHash, TxId, TxLocation};
use chronik_db::v2_asset::asset_summary_key;
use std::{cell::Cell, collections::BTreeMap};
#[derive(Default)]
struct Memory {
    summaries: BTreeMap<Vec<u8>, AssetSummary>,
    postings: BTreeMap<Vec<u8>, OutPoint>,
    outputs: BTreeMap<OutPoint, OutputRecord>,
    calls: Cell<usize>,
}
fn next<T: Clone>(map: &BTreeMap<Vec<u8>, T>, after: Option<&[u8]>) -> Option<(Vec<u8>, T)> {
    map.iter()
        .find(|(k, _)| after.is_none_or(|a| k.as_slice() > a))
        .map(|(k, v)| (k.clone(), v.clone()))
}
impl Memory {
    fn charge(&self, budget: &mut AssetReadBudget) -> Result<(), Error> {
        budget.charge().map_err(|_| Error::Source)?;
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}
impl Source for Memory {
    fn summary(
        &self,
        a: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, AssetSummary)>, Error> {
        self.charge(budget)?;
        if a.is_some_and(|a| self.summaries.contains_key(a)) {
            self.charge(budget)?;
        }
        let item = next(&self.summaries, a);
        if item.is_some() {
            self.charge(budget)?;
            self.charge(budget)?;
        }
        Ok(item)
    }
    fn event(
        &self,
        _: Hash32,
        _: Option<&[u8]>,
        _: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, AssetEvent)>, Error> {
        unreachable!()
    }
    fn posting(
        &self,
        t: Hash32,
        a: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, OutPoint)>, Error> {
        self.charge(budget)?;
        if a.is_some_and(|a| self.postings.contains_key(a)) {
            self.charge(budget)?;
        }
        Ok(next(&self.postings, a).filter(|(k, _)| k[2..34] == t.0))
    }
    fn output(
        &self,
        op: OutPoint,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<OutputRecord>, Error> {
        self.charge(budget)?;
        let record = self.outputs.get(&op).cloned();
        if let Some(record) = &record {
            self.charge(budget)?;
            self.charge(budget)?;
            if record.creation != location(record.creation.tx_index) {
                return Err(Error::Source);
            }
            if record.spend.is_some() {
                self.charge(budget)?;
                self.charge(budget)?;
            }
        }
        Ok(record)
    }
}
fn location(i: u32) -> TxLocation {
    TxLocation {
        block_id: Hash32([9; 32]),
        height: 7,
        tx_index: i,
        txid: TxId(Hash32([i as u8 + 10; 32])),
        txhash: TxHash(Hash32([i as u8 + 20; 32])),
    }
}
#[test]
fn registry_pages_equal_full_ordered_scan() {
    let mut m = Memory::default();
    for t in (1..30).rev() {
        let token = Hash32([t; 32]);
        m.summaries.insert(
            asset_summary_key(token),
            AssetSummary {
                token_id: token,
                first_seen: location(0),
                event_count: 1,
                output_count: 0,
            },
        );
    }
    let mut after = None;
    let mut all = Vec::new();
    loop {
        let p = assets(
            &m,
            after.as_deref(),
            Limits {
                page_size: 3,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(p.reads <= 12);
        assert!(p.examined <= 3);
        all.extend(p.items.iter().map(|s| s.token_id));
        if p.exhausted {
            break;
        }
        assert_ne!(after, p.next_key);
        after = p.next_key;
    }
    assert_eq!(
        all,
        m.summaries.values().map(|s| s.token_id).collect::<Vec<_>>()
    );
}
#[test]
fn empty_unspent_page_advances_and_history_keeps_zero_burns() {
    let mut m = Memory::default();
    let token = Hash32([1; 32]);
    for i in 0..5 {
        let creation = location(i);
        let op = OutPoint {
            txid: creation.txid,
            out_idx: 0,
        };
        m.postings.insert(asset_output_key(token, creation, 0), op);
        m.outputs.insert(
            op,
            OutputRecord {
                outpoint: op,
                creation,
                spend: None,
                output: Output {
                    flags: if i < 4 { 3 } else { 1 },
                    value: 0,
                    token_id: token,
                    branches: vec![Hash32([8; 32])],
                    paths: if i < 4 { vec![] } else { vec![vec![0]] },
                },
            },
        );
    }
    let limits = Limits {
        examined: 2,
        reads: 12,
        ..Limits::default()
    };
    let p = outputs(&m, token, true, None, limits).unwrap();
    assert!(p.items.is_empty());
    assert!(!p.exhausted);
    assert_eq!(p.reads, 9);
    assert_eq!(m.calls.get(), 9);
    let q = outputs(&m, token, true, p.next_key.as_deref(), limits).unwrap();
    assert!(q.items.is_empty());
    assert!(q.next_key > p.next_key);
    let r = outputs(&m, token, true, q.next_key.as_deref(), limits).unwrap();
    assert_eq!(r.items.len(), 1);
    assert!(r.exhausted);
    assert_eq!(r.reads, 7);
    let full = outputs(&m, token, false, None, Limits::default()).unwrap();
    assert_eq!(full.items.len(), 5);
}
#[test]
fn malformed_cursor_join_or_indivisible_record_fails() {
    let m = Memory::default();
    let token = Hash32([1; 32]);
    assert_eq!(
        assets(&m, Some(b"eE"), Limits::default()).unwrap_err(),
        Error::InvalidCursor
    );
    assert_eq!(
        assets(
            &m,
            None,
            Limits {
                result_bytes: 1,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        Error::RecordLimit
    );
    assert_eq!(m.calls.get(), 0);
    let mut m = Memory::default();
    let loc = location(0);
    let op = OutPoint {
        txid: loc.txid,
        out_idx: 0,
    };
    m.postings.insert(asset_output_key(token, loc, 0), op);
    assert_eq!(
        outputs(&m, token, false, None, Limits::default()).unwrap_err(),
        Error::Source
    );
}

#[test]
fn output_creation_identity_and_join_read_budget_are_enforced() {
    let mut m = Memory::default();
    let token = Hash32([1; 32]);
    let loc = location(0);
    let op = OutPoint {
        txid: loc.txid,
        out_idx: 0,
    };
    m.postings.insert(asset_output_key(token, loc, 0), op);
    let mut forged = loc;
    forged.txhash = TxHash(Hash32([99; 32]));
    m.outputs.insert(
        op,
        OutputRecord {
            outpoint: op,
            creation: forged,
            spend: None,
            output: Output {
                flags: 1,
                value: 0,
                token_id: token,
                branches: vec![Hash32([8; 32])],
                paths: vec![vec![0]],
            },
        },
    );
    assert_eq!(
        outputs(&m, token, false, None, Limits::default()).unwrap_err(),
        Error::Source
    );
    assert_eq!(m.calls.get(), 4); // posting + output + canonical transaction/height creation
    m.outputs.get_mut(&op).unwrap().creation = loc;
    m.calls.set(0);
    let p = outputs(
        &m,
        token,
        false,
        None,
        Limits {
            reads: 7,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(p.reads, 4);
    assert_eq!(m.calls.get(), 4);
    assert_eq!(p.items.len(), 1);
    assert!(!p.exhausted);
    // The next indivisible candidate would require up to seven reads; no
    // speculative call runs with only three remaining. The cursor advances.
    assert!(p.next_key.is_some());
}
