use super::*;
fn anchor(height: u64) -> Anchor {
    Anchor {
        block_id: [(height % 256) as u8; 32],
        height,
    }
}
#[test]
fn idle_turns_preserve_durable_generation_and_fence_observations() {
    let authority = Authority::default();
    assert_eq!(
        authority.observe(),
        AuthoritativeState {
            observation: 0,
            generation: 0,
            anchor: None
        }
    );
    let generation = authority.publish_context(anchor(1), 7, 11).unwrap();
    let first = authority.observe();
    for _ in 0..100 {
        assert_eq!(authority.suspend().unwrap(), generation);
        let suspended = authority.observe();
        assert!(suspended.anchor.is_none());
        assert!(suspended.observation > first.observation);
        assert_eq!(
            authority.publish_context(anchor(1), 7, 11).unwrap(),
            generation
        );
        assert_eq!(authority.observe().anchor, Some(anchor(1)));
    }
    assert_ne!(authority.observe().observation, first.observation);
    assert_eq!(authority.observe().generation, first.generation);
}
#[test]
fn context_aba_and_durable_invalidation_never_resurrect_generations() {
    let authority = Authority::default();
    let mut previous = authority.publish_context(anchor(1), 7, 11).unwrap();
    for (a, c, r) in [
        (anchor(1), 8, 11),
        (anchor(1), 7, 11),
        (anchor(1), 7, 12),
        (anchor(2), 7, 12),
        (anchor(1), 7, 11),
    ] {
        authority.suspend().unwrap();
        let next = authority.publish_context(a, c, r).unwrap();
        assert!(next > previous);
        previous = next;
    }
    let invalidated = authority.publish(None).unwrap();
    assert!(invalidated > previous);
    assert_eq!(
        authority.publish_context(anchor(1), 7, 11).unwrap(),
        invalidated
    );
    let generic = authority.publish(Some(anchor(1))).unwrap();
    assert!(generic > invalidated);
    assert!(authority.publish_context(anchor(1), 7, 11).unwrap() > generic);
}
#[test]
fn coherent_nonblocking_stamps_and_terminal_overflow() {
    let authority = Arc::new(Authority::default());
    let writer = Arc::clone(&authority);
    let thread = std::thread::spawn(move || {
        for n in 1..10000u64 {
            writer.suspend().unwrap();
            writer.publish_context(anchor(n), n, n).unwrap();
        }
    });
    for _ in 0..20000 {
        let state = authority.observe();
        if let Some(a) = state.anchor {
            assert_eq!(state.observation % 2, 0);
            assert_eq!(state.generation, a.height);
            assert_eq!(a.block_id, [(a.height % 256) as u8; 32]);
        }
    }
    thread.join().unwrap();
    let guard = authority.writer.lock().unwrap();
    assert!(authority.observe().anchor.is_some());
    drop(guard);
    authority.sequence.store(u64::MAX - 1, Ordering::SeqCst);
    assert!(authority.publish_context(anchor(1), 7, 11).is_err());
    assert_eq!(
        authority.observe(),
        AuthoritativeState {
            observation: u64::MAX,
            generation: u64::MAX,
            anchor: None
        }
    );
    assert!(authority.publish(None).is_err());
    assert!(authority.suspend().is_err());
    assert!(authority.observe().anchor.is_none());
}
#[test]
fn durable_exhaustion_and_poison_are_terminal_unknown() {
    let authority = Authority::default();
    authority.publish_context(anchor(1), 7, 11).unwrap();
    authority.generation.store(u64::MAX - 1, Ordering::SeqCst);
    assert!(authority.publish(None).is_err());
    assert!(authority.publish_context(anchor(1), 7, 11).is_err());
    assert!(authority.suspend().is_err());
    assert!(authority.observe().anchor.is_none());
    let authority = Arc::new(Authority::default());
    let writer = Arc::clone(&authority);
    assert!(std::thread::spawn(move || {
        let _guard = writer.writer.lock().unwrap();
        panic!("poison authority writer");
    })
    .join()
    .is_err());
    assert!(authority.suspend().is_err());
    assert!(authority.publish_context(anchor(1), 7, 11).is_err());
    assert!(authority.observe().anchor.is_none());
}
