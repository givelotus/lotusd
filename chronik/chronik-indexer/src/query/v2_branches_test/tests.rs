use super::*;
use bitcoinsuite_core::lotus_v2::{TxHash, TxId, TxLocation};
use std::collections::BTreeMap;
struct Source(BTreeMap<OutPoint, OutputRecord>);
fn anchor() -> Snapshot {
    Snapshot {
        chain_id: Hash32([1; 32]),
        profile_id: Hash32([2; 32]),
        tip: Hash32([3; 32]),
        height: 10,
    }
}
impl PostingSource for Source {
    fn snapshot(&self) -> Snapshot {
        anchor()
    }
    fn next_posting(
        &self,
        root: Hash32,
        pos: Option<u8>,
        after: Option<OutPoint>,
    ) -> Result<Option<OutPoint>, QueryError> {
        // Test-only scan oracle; production adapters must seek postings.
        Ok(self
            .0
            .iter()
            .filter(|(k, r)| {
                after.is_none_or(|a| **k > a)
                    && pos.map_or_else(
                        || r.output.branches.contains(&root),
                        |p| r.output.branches.get(p as usize) == Some(&root),
                    )
            })
            .map(|(k, _)| *k)
            .next())
    }
    fn output(
        &self,
        key: OutPoint,
    ) -> Result<Option<OutputRecord>, QueryError> {
        Ok(self.0.get(&key).cloned())
    }
}
fn root(n: u8) -> Hash32 {
    Hash32([n; 32])
}
fn source() -> Source {
    Source(
        (0..40)
            .map(|i| {
                let key = OutPoint {
                    txid: TxId(root(i)),
                    out_idx: 0,
                };
                let output = Output {
                    flags: if i % 7 == 0 { 2 } else { 0 },
                    value: i as u64,
                    token_id: Hash32::default(),
                    state_root: Hash32::default(),
                    branches: vec![root(i % 3), root(8 + i % 2)],
                    paths: if i % 7 == 0 { vec![] } else { vec![vec![0, 1]] },
                };
                (
                    key,
                    OutputRecord {
                        outpoint: key,
                        output,
                        creation: TxLocation {
                            block_id: root(3),
                            height: 10,
                            tx_index: i as u32,
                            txid: key.txid,
                            txhash: TxHash(root(i)),
                        },
                        spend: None,
                    },
                )
            })
            .collect(),
    )
}
#[test]
fn pagination_matches_same_output_oracle() {
    let s = source();
    for kind in [
        QueryKind::Utxos,
        QueryKind::History { include_burn: true },
        QueryKind::History {
            include_burn: false,
        },
    ] {
        for f in [
            BranchFilter {
                any_branch: vec![root(0), root(1), root(0)],
                positions: vec![],
            },
            BranchFilter {
                any_branch: vec![],
                positions: vec![
                    PositionClause {
                        position: 1,
                        roots: vec![root(9)],
                    },
                    PositionClause {
                        position: 0,
                        roots: vec![root(0), root(2)],
                    },
                ],
            },
            BranchFilter {
                any_branch: vec![root(0)],
                positions: vec![PositionClause {
                    position: 1,
                    roots: vec![root(9)],
                }],
            },
        ] {
            let expected: Vec<_> =
                s.0.values()
                    .filter(|r| {
                        f.matches(&r.output)
                            && (matches!(
                                kind,
                                QueryKind::History { include_burn: true }
                            ) || !r.output.is_burn())
                    })
                    .map(|r| r.outpoint)
                    .collect();
            let limits = Limits {
                page_size: 2,
                posting_reads: 6,
                work: 9,
                ..Limits::default()
            };
            let mut cursor = None;
            let mut actual = vec![];
            for _ in 0..100 {
                let p = query(&s, &f, kind, limits, cursor).unwrap();
                assert!(
                    p.posting_reads <= limits.posting_reads
                        && p.work <= limits.work
                );
                actual.extend(p.matches.into_iter().map(|m| m.record.outpoint));
                cursor = p.continuation;
                if cursor.is_none() {
                    break;
                }
            }
            assert!(cursor.is_none());
            assert_eq!(actual, expected);
        }
    }
}
#[test]
fn bounds_canonical_digest_and_stale_cursor() {
    let s = source();
    let limits = Limits::default();
    let f = BranchFilter {
        any_branch: vec![root(1), root(0), root(1)],
        positions: vec![],
    };
    let mut canonical = f.clone();
    canonical.any_branch = vec![root(0), root(1)];
    assert_eq!(
        f.digest(QueryKind::Utxos, limits),
        canonical.digest(QueryKind::Utxos, limits)
    );
    for bad in [
        BranchFilter {
            any_branch: vec![],
            positions: vec![],
        },
        BranchFilter {
            any_branch: vec![],
            positions: vec![PositionClause {
                position: 16,
                roots: vec![root(0)],
            }],
        },
        BranchFilter {
            any_branch: vec![],
            positions: vec![PositionClause {
                position: 0,
                roots: vec![],
            }],
        },
        BranchFilter {
            any_branch: vec![],
            positions: vec![
                PositionClause {
                    position: 0,
                    roots: vec![root(0)]
                };
                2
            ],
        },
    ] {
        assert_eq!(bad.canonicalize(limits), Err(QueryError::InvalidFilter));
    }
    assert_eq!(
        f.canonicalize(Limits { roots: 2, ..limits }),
        Err(QueryError::InvalidFilter)
    );
    let page = query(
        &s,
        &f,
        QueryKind::Utxos,
        Limits {
            page_size: 1,
            ..limits
        },
        None,
    )
    .unwrap();
    let mut c = page.continuation.unwrap();
    c.snapshot.tip = root(55);
    assert!(matches!(
        query(&s, &f, QueryKind::Utxos, limits, Some(c)),
        Err(QueryError::StaleCursor)
    ));
    assert!(matches!(
        query(
            &s,
            &f,
            QueryKind::Utxos,
            Limits {
                result_bytes: 1,
                ..limits
            },
            None
        ),
        Err(QueryError::RecordTooLarge)
    ));
}
#[test]
fn byte_continuation_and_all_positions() {
    let mut s = source();
    let record = s.0.values_mut().next().unwrap();
    record.output.flags = 0;
    record.output.branches = (0..16).map(root).collect();
    record.output.paths = vec![(0..16).collect()];
    let f = BranchFilter {
        any_branch: vec![],
        positions: (0..16)
            .map(|position| PositionClause {
                position,
                roots: vec![root(position)],
            })
            .collect(),
    };
    assert_eq!(
        query(&s, &f, QueryKind::Utxos, Limits::default(), None)
            .unwrap()
            .matches
            .len(),
        1
    );
    let f = BranchFilter {
        any_branch: vec![root(0), root(1), root(2)],
        positions: vec![],
    };
    let limits = Limits {
        result_bytes: 1000,
        ..Limits::default()
    };
    let mut cursor = None;
    let mut keys = vec![];
    loop {
        let p = query(&s, &f, QueryKind::Utxos, limits, cursor).unwrap();
        keys.extend(p.matches.iter().map(|m| m.record.outpoint));
        cursor = p.continuation;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        keys.len(),
        s.0.values().filter(|r| !r.output.is_burn()).count()
    );
}

#[test]
fn spent_token_history_and_missing_positions() {
    use bitcoinsuite_core::lotus_v2::SpendLocation;
    let mut s = source();
    let record = s.0.values_mut().nth(1).unwrap();
    let key = record.outpoint;
    record.output.flags = 1;
    record.output.token_id = root(80);
    record.output.value = u64::MAX;
    record.spend = Some(SpendLocation {
        transaction: record.creation,
        input_index: 7,
    });
    let f = BranchFilter {
        any_branch: vec![root(1)],
        positions: vec![],
    };
    let h = query(
        &s,
        &f,
        QueryKind::History { include_burn: true },
        Limits::default(),
        None,
    )
    .unwrap();
    let found = h.matches.iter().find(|m| m.record.outpoint == key).unwrap();
    assert_eq!(found.record.output.value, u64::MAX);
    assert_eq!(found.record.spend.unwrap().input_index, 7);
    let u = query(&s, &f, QueryKind::Utxos, Limits::default(), None).unwrap();
    assert!(!u.matches.iter().any(|m| m.record.outpoint == key));
    let missing = BranchFilter {
        any_branch: vec![root(1)],
        positions: vec![PositionClause {
            position: 15,
            roots: vec![root(9)],
        }],
    };
    assert!(query(
        &s,
        &missing,
        QueryKind::History { include_burn: true },
        Limits::default(),
        None
    )
    .unwrap()
    .matches
    .is_empty());
}

#[test]
fn all_snapshot_components_bind_cursor() {
    let s = source();
    let f = BranchFilter {
        any_branch: vec![root(1)],
        positions: vec![],
    };
    let limits = Limits {
        page_size: 1,
        ..Limits::default()
    };
    let cursor = query(&s, &f, QueryKind::Utxos, limits, None)
        .unwrap()
        .continuation
        .unwrap();
    for component in 0..4 {
        let mut changed = cursor;
        match component {
            0 => changed.snapshot.chain_id = root(90),
            1 => changed.snapshot.profile_id = root(90),
            2 => changed.snapshot.tip = root(90),
            _ => changed.snapshot.height += 1,
        }
        assert!(matches!(
            query(&s, &f, QueryKind::Utxos, limits, Some(changed)),
            Err(QueryError::StaleCursor)
        ));
    }
}

#[test]
fn matching_outputs_in_same_transaction_remain_distinct() {
    let mut s = source();
    let mut record = s.0.values().nth(1).unwrap().clone();
    let first = record.outpoint;
    record.outpoint.out_idx = 1;
    let second = record.outpoint;
    s.0.insert(second, record);
    let f = BranchFilter {
        any_branch: vec![root(1), root(9)],
        positions: vec![],
    };
    let limits = Limits {
        page_size: 1,
        ..Limits::default()
    };
    let mut cursor = None;
    let mut found = vec![];
    loop {
        let p = query(
            &s,
            &f,
            QueryKind::History { include_burn: true },
            limits,
            cursor,
        )
        .unwrap();
        found.extend(p.matches.into_iter().map(|m| m.record.outpoint));
        cursor = p.continuation;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(found.iter().filter(|&&key| key == first).count(), 1);
    assert_eq!(found.iter().filter(|&&key| key == second).count(), 1);
    assert!(found.windows(2).all(|w| w[0] < w[1]));
}
