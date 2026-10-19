use super::*;
use bitcoinsuite_core::lotus_v2::{TxHash, TxId};
fn location(index: u32) -> TxLocation {
    TxLocation {
        block_id: Hash32([9; 32]),
        height: 7,
        tx_index: index,
        txid: TxId(Hash32([index as u8 + 10; 32])),
        txhash: TxHash(Hash32([index as u8 + 20; 32])),
    }
}
fn output(token: u8, value: u64, burn: bool) -> Output {
    Output {
        flags: if burn { 3 } else { 1 },
        value,
        token_id: Hash32([token; 32]),
        branches: vec![Hash32([8; 32])],
        paths: if burn { vec![] } else { vec![vec![0]] },
    }
}
fn coin(token: u8, value: u64, index: u32) -> ResolvedCreation {
    ResolvedCreation {
        outpoint: OutPoint {
            txid: location(0).txid,
            out_idx: index,
        },
        output: output(token, value, false),
        creation: location(0),
    }
}
fn view<'a>(
    outputs: &'a [Output],
    spends: &'a [ResolvedCreation],
    mints: &'a [Hash32],
) -> AssetTxView<'a> {
    AssetTxView {
        location: location(1),
        outputs,
        resolved_spends: spends,
        mint_token_ids: mints,
    }
}
#[test]
fn full_union_input_only_implicit_burn_and_exact_positions() {
    let outputs = [output(2, 0, true), output(3, 12, false), output(3, 8, true)];
    let spends = [coin(1, 55, 0), coin(3, 13, 1)];
    let mints = [Hash32([3; 32])];
    let events = derive_asset_events(view(&outputs, &spends, &mints)).unwrap();
    assert_eq!(
        events.iter().map(|e| e.token_id.0[0]).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        (
            events[0].spent_units,
            events[0].implicit_burn_units,
            events[0].output_units
        ),
        (55, 55, 0)
    );
    assert_eq!(
        (events[2].minted_units, events[2].explicit_burn_units),
        (7, 8)
    );
    assert!(events.iter().all(|e| e.location == location(1)));
    let old = events.iter().map(|e| (e.token_id, None)).collect();
    let plan = plan_asset_tx(view(&outputs, &spends, &mints), &old).unwrap();
    assert_eq!(plan.len(), 9);
    let key = asset_output_key(Hash32([3; 32]), location(1), 2);
    let bytes = &plan.iter().find(|(k, _)| *k == key).unwrap().1;
    assert_eq!(&bytes[..32], &location(1).txid.0 .0);
    assert_eq!(&bytes[32..], &2u32.to_be_bytes());
}
#[test]
fn multimint_and_quantities_exceeding_u64_are_exact() {
    let outputs = [
        output(2, u64::MAX, false),
        output(2, u64::MAX, true),
        output(1, 1, false),
    ];
    let mints = [Hash32([2; 32]), Hash32([1; 32])];
    let events = derive_asset_events(view(&outputs, &[], &mints)).unwrap();
    assert_eq!(events[1].minted_units, 2 * u128::from(u64::MAX));
    assert_eq!(events[1].explicit_burn_units, u128::from(u64::MAX));
    assert_eq!(events[0].minted_units, 1);
}
#[test]
fn mint_bijection_rejects_duplicate_missing_extra_and_zero_selectors() {
    let outputs = [output(1, 1, false)];
    for mints in [
        vec![],
        vec![Hash32([1; 32]); 2],
        vec![Hash32([1; 32]), Hash32([2; 32])],
        vec![Hash32::default()],
    ] {
        assert!(derive_asset_events(view(&outputs, &[], &mints)).is_err());
    }
    assert!(derive_asset_events(view(&[output(1, 0, true)], &[], &[Hash32([1; 32])])).is_err());
}
#[test]
fn explicit_and_implicit_burns_remain_distinct() {
    let events = derive_asset_events(view(&[output(1, 4, true)], &[coin(1, 10, 0)], &[])).unwrap();
    assert_eq!(
        (
            events[0].spent_units,
            events[0].output_units,
            events[0].explicit_burn_units,
            events[0].implicit_burn_units
        ),
        (10, 4, 4, 6)
    );
    let zero = derive_asset_events(view(&[output(2, 0, true)], &[], &[])).unwrap();
    assert_eq!(zero.len(), 1);
    assert_eq!(zero[0].output_units, 0);
}
#[test]
fn malformed_duplicate_spends_and_burn_inputs_are_rejected() {
    let mut c = coin(1, 0, 0);
    assert!(derive_asset_events(view(&[], &[c.clone(), c.clone()], &[])).is_err());
    c.output = output(1, 0, true);
    assert!(derive_asset_events(view(&[], &[c], &[])).is_err());
    let mut malformed = output(1, 0, false);
    malformed.flags |= 4;
    assert!(derive_asset_events(view(&[malformed], &[], &[])).is_err());
}
#[test]
fn summary_checked_counts_first_seen_and_reconnect_plan_parity() {
    let outputs = [output(1, 0, true), output(1, 0, false)];
    let tx = view(&outputs, &[], &[]);
    let token = Hash32([1; 32]);
    let old = BTreeMap::from([(token, None)]);
    let initial = plan_asset_tx(tx, &old).unwrap();
    // Disconnect restores the exact old values, then reconnect recomputes the
    // identical plan. This is model parity; the parent owns durable undo tests.
    assert_eq!(initial, plan_asset_tx(tx, &old).unwrap());
    let summary: AssetSummary = decode(&initial[0].1).unwrap();
    assert_eq!((summary.event_count, summary.output_count), (1, 2));
    let later = AssetTxView {
        location: location(2),
        ..tx
    };
    let updated = plan_asset_tx(later, &BTreeMap::from([(token, Some(summary.clone()))])).unwrap();
    let next: AssetSummary = decode(&updated[0].1).unwrap();
    assert_eq!(next.first_seen, summary.first_seen);
    assert_eq!((next.event_count, next.output_count), (2, 4));
    let mut bad = summary.clone();
    bad.event_count = u64::MAX;
    assert!(plan_asset_tx(later, &BTreeMap::from([(token, Some(bad))])).is_err());
    let mut bad = summary;
    bad.output_count = u64::MAX;
    assert!(plan_asset_tx(later, &BTreeMap::from([(token, Some(bad))])).is_err());
}
#[test]
fn amount_addition_detects_u128_overflow() {
    let mut units = u128::MAX;
    assert!(add(&mut units, 1).is_err());
    assert_eq!(units, u128::MAX);
}

// Dedicated temporary storage fixtures exercise the real persisted reader
// boundary; they do not open any application index or production directory.
#[derive(Serialize)]
struct CanonicalLocation(#[serde(with = "native_serde::location")] TxLocation);
fn put_location(db: &crate::mdbx::MdbxEnv, loc: TxLocation) {
    db.put(
        [b"eH".as_slice(), &loc.height.to_be_bytes()].concat(),
        loc.block_id.0,
    )
    .unwrap();
    db.put(
        [b"t".as_slice(), &loc.txid.0 .0].concat(),
        postcard::to_allocvec(&CanonicalLocation(loc)).unwrap(),
    )
    .unwrap();
}
fn read_snapshot(db: &crate::mdbx::MdbxEnv) -> ReadSnapshot<'_> {
    ReadSnapshot {
        inner: db.snapshot().unwrap(),
        anchor: crate::v2_branch::Anchor {
            block_id: [9; 32],
            height: 7,
        },
        binding: crate::v2_branch::Binding {
            chain_id: [1; 32],
            genesis: [2; 32],
            profile: [3; 32],
        },
        bounds: crate::v2_branch::Bounds::new(32_000_000).unwrap(),
    }
}
#[test]
fn persisted_summary_and_event_reject_forged_same_position_identity() {
    let dir = tempdir::TempDir::new("v2-asset-canonical-join").unwrap();
    let db = crate::mdbx::MdbxEnv::open(dir.path()).unwrap();
    let canonical = location(1);
    put_location(&db, canonical);
    let token = Hash32([1; 32]);
    for field in 0..3 {
        let mut forged = canonical;
        match field {
            0 => forged.block_id = Hash32([99; 32]),
            1 => forged.txid = TxId(Hash32([99; 32])),
            _ => forged.txhash = TxHash(Hash32([99; 32])),
        };
        let summary = AssetSummary {
            token_id: token,
            first_seen: forged,
            event_count: 1,
            output_count: 1,
        };
        db.put(asset_summary_key(token), encode(&summary).unwrap())
            .unwrap();
        let event = AssetEvent {
            token_id: token,
            location: forged,
            spent_units: 1,
            output_units: 1,
            explicit_burn_units: 0,
            minted_units: 0,
            implicit_burn_units: 0,
            has_mint_input: false,
        };
        db.put(asset_event_key(token, forged), encode(&event).unwrap())
            .unwrap();
        let snapshot = read_snapshot(&db);
        assert!(matches!(snapshot.asset_summary(token), Err(Error::Corrupt)));
        assert!(matches!(
            snapshot.next_asset_summary(None),
            Err(Error::Corrupt)
        ));
        assert!(matches!(
            snapshot.next_asset_event(token, None),
            Err(Error::Corrupt)
        ));
    }
}
#[test]
fn persisted_iterator_budget_counts_initial_join_and_exclusive_reread() {
    let dir = tempdir::TempDir::new("v2-asset-read-budget").unwrap();
    let db = crate::mdbx::MdbxEnv::open(dir.path()).unwrap();
    let loc = location(1);
    put_location(&db, loc);
    for byte in 1..=2 {
        let token = Hash32([byte; 32]);
        db.put(
            asset_summary_key(token),
            encode(&AssetSummary {
                token_id: token,
                first_seen: loc,
                event_count: 1,
                output_count: 0,
            })
            .unwrap(),
        )
        .unwrap();
    }
    let snapshot = read_snapshot(&db);
    let mut budget = AssetReadBudget::new(9);
    let (first, _) = snapshot
        .next_asset_summary_counted(None, &mut budget)
        .unwrap()
        .unwrap();
    assert_eq!(budget.reads(), 3); // first iterator item + canonical transaction/height gets
    let (second, _) = snapshot
        .next_asset_summary_counted(Some(&first), &mut budget)
        .unwrap()
        .unwrap();
    assert_eq!(budget.reads(), 7); // exclusive reread + next item + canonical transaction/height gets
    assert!(snapshot
        .next_asset_summary_counted(Some(&second), &mut budget)
        .unwrap()
        .is_none());
    assert_eq!(budget.reads(), 9); // exclusive reread + exhausted next
    assert_eq!(budget.remaining(), 0);
    let mut short = AssetReadBudget::new(1);
    assert!(snapshot
        .asset_summary_counted(Hash32([1; 32]), &mut short)
        .is_err());
    assert_eq!(short.reads(), 1); // canonical read refused before storage
}
