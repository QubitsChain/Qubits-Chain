use qubits_crypto::{SchemeId, SecretKey};
use qubits_state::{
    CommittedBlock, MemoryState, Overlay, PutBlock, StateReader, Store, TxLocation, Verdict,
    WriteSet,
};
use qubits_types::{Address, ChainParams, Genesis, Hash};

fn genesis() -> Genesis {
    Genesis {
        chain_id: "qubits-test".into(),
        timestamp_ms: 1_000,
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 10,
        },
        validators: vec![qubits_types::Validator::self_paid(
            SecretKey::from_seed(SchemeId::MlDsa65, &[5; 32])
                .unwrap()
                .public_key()
                .clone(),
        )],
        accounts: vec![],
    }
}

fn writes(entries: &[(&str, Option<&str>)]) -> WriteSet {
    entries
        .iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), v.map(|v| v.as_bytes().to_vec())))
        .collect()
}

fn open() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    (dir, store)
}

fn init(store: &Store) -> Hash {
    let prepared = store
        .prepare(0, &writes(&[("a", Some("1")), ("b", Some("2"))]))
        .unwrap();
    let root = prepared.root();
    store.commit_genesis(&genesis(), prepared).unwrap();
    root
}

fn commit(store: &Store, height: u64, w: &WriteSet, bytes: &[u8], tx_ids: &[Hash]) -> Hash {
    let prepared = store.prepare(height, w).unwrap();
    let root = prepared.root();
    let block = CommittedBlock {
        height,
        state_root: root,
        bytes,
        tx_ids,
        addresses: &[],
        receipts: &[],
        meta: &[],
    };
    store.commit_block(&block, prepared).unwrap();
    root
}

#[test]
fn empty_database_has_no_state() {
    let (_dir, store) = open();
    assert_eq!(store.latest_height().unwrap(), None);
    assert_eq!(store.genesis().unwrap(), None);
    assert_eq!(store.get(b"a").unwrap(), None);
}

#[test]
fn genesis_is_written_once() {
    let (_dir, store) = open();
    let root = init(&store);
    assert_eq!(store.latest_height().unwrap(), Some(0));
    assert_eq!(store.genesis().unwrap(), Some(genesis()));
    assert_eq!(store.state_root(0).unwrap(), root);
    assert_eq!(store.get(b"a").unwrap(), Some(b"1".to_vec()));
    assert!(store.prepare(0, &writes(&[("x", Some("1"))])).is_err());
}

#[test]
fn blocks_update_state_and_keep_history() {
    let (_dir, store) = open();
    let root0 = init(&store);
    let tx_ids = [Hash([1; 32]), Hash([2; 32])];
    let root1 = commit(
        &store,
        1,
        &writes(&[("a", Some("10")), ("b", None), ("c", Some("3"))]),
        b"block one",
        &tx_ids,
    );
    assert_ne!(root0, root1);

    assert_eq!(store.latest_height().unwrap(), Some(1));
    assert_eq!(store.get(b"a").unwrap(), Some(b"10".to_vec()));
    assert_eq!(store.get(b"b").unwrap(), None, "deleted");
    assert_eq!(store.get(b"c").unwrap(), Some(b"3".to_vec()));

    assert_eq!(store.get_at(0, b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(store.get_at(0, b"b").unwrap(), Some(b"2".to_vec()));
    assert_eq!(store.get_at(0, b"c").unwrap(), None);
    assert_eq!(store.state_root(0).unwrap(), root0);
    assert_eq!(store.state_root(1).unwrap(), root1);

    assert_eq!(store.block(1).unwrap(), Some(b"block one".to_vec()));
    assert_eq!(store.block(2).unwrap(), None);
    let loc = store.tx_location(&tx_ids[1]).unwrap().unwrap();
    assert_eq!((loc.height, loc.index), (1, 1));
}

#[test]
fn block_without_state_changes() {
    let (_dir, store) = open();
    let root0 = init(&store);
    assert_eq!(commit(&store, 1, &WriteSet::new(), b"empty", &[]), root0);
    assert_eq!(store.state_root(1).unwrap(), root0);
    assert_eq!(store.get(b"a").unwrap(), Some(b"1".to_vec()));
}

#[test]
fn mismatched_commits_are_refused() {
    let (_dir, store) = open();
    init(&store);
    let w = writes(&[("a", Some("10"))]);
    assert!(store.prepare(2, &w).is_err(), "skipping a version");

    let prepared = store.prepare(1, &w).unwrap();
    let wrong_root = CommittedBlock {
        height: 1,
        state_root: Hash([9; 32]),
        bytes: b"x",
        tx_ids: &[],
        addresses: &[],
        receipts: &[],
        meta: &[],
    };
    assert!(store.commit_block(&wrong_root, prepared).is_err());

    let prepared = store.prepare(1, &w).unwrap();
    let wrong_height = CommittedBlock {
        height: 2,
        state_root: prepared.root(),
        bytes: b"x",
        tx_ids: &[],
        addresses: &[],
        receipts: &[],
        meta: &[],
    };
    assert!(store.commit_block(&wrong_height, prepared).is_err());

    assert_eq!(store.latest_height().unwrap(), Some(0));
    assert_eq!(store.get(b"a").unwrap(), Some(b"1".to_vec()));
}

#[test]
fn speculative_roots_match_sequential_commits() {
    let (_d1, speculative) = open();
    let (_d2, sequential) = open();
    init(&speculative);
    init(&sequential);
    let w1 = writes(&[("a", Some("10")), ("z", Some("new"))]);
    let w2 = writes(&[("a", None), ("b", Some("20"))]);
    let w3 = WriteSet::new();

    let r1 = speculative.speculative_root(&[&w1]).unwrap();
    let r2 = speculative.speculative_root(&[&w1, &w2]).unwrap();
    let r3 = speculative.speculative_root(&[&w1, &w2, &w3]).unwrap();
    assert_eq!(
        speculative.speculative_root(&[]).unwrap(),
        speculative.state_root(0).unwrap()
    );
    assert_eq!(
        speculative.latest_height().unwrap(),
        Some(0),
        "nothing written"
    );

    assert_eq!(commit(&sequential, 1, &w1, b"1", &[]), r1);
    assert_eq!(commit(&sequential, 2, &w2, b"2", &[]), r2);
    assert_eq!(commit(&sequential, 3, &w3, b"3", &[]), r3);

    commit(&speculative, 1, &w1, b"1", &[]);
    assert_eq!(speculative.speculative_root(&[&w2, &w3]).unwrap(), r3);
}

#[test]
fn overlay_reads_newest_layer_first() {
    let (_dir, store) = open();
    init(&store);
    let w1 = writes(&[("a", Some("10")), ("c", Some("3"))]);
    let w2 = writes(&[("a", None), ("b", Some("20"))]);
    let overlay = Overlay::new(&store, vec![&w1, &w2]);
    assert_eq!(
        overlay.get(b"a").unwrap(),
        None,
        "deleted in the newest layer"
    );
    assert_eq!(overlay.get(b"b").unwrap(), Some(b"20".to_vec()));
    assert_eq!(overlay.get(b"c").unwrap(), Some(b"3".to_vec()));
    assert_eq!(overlay.get(b"zzz").unwrap(), None);
    assert_eq!(store.get(b"a").unwrap(), Some(b"1".to_vec()));
}

#[test]
fn metadata_is_written_with_blocks_and_alone() {
    let (_dir, store) = open();
    init(&store);
    store.put_meta(b"safety", b"v1").unwrap();
    assert_eq!(store.get_meta(b"safety").unwrap(), Some(b"v1".to_vec()));
    let prepared = store.prepare(1, &WriteSet::new()).unwrap();
    let meta = [(&b"consensus"[..], b"tip".to_vec())];
    let block = CommittedBlock {
        height: 1,
        state_root: prepared.root(),
        bytes: b"b",
        tx_ids: &[],
        addresses: &[],
        receipts: &[],
        meta: &meta,
    };
    store.commit_block(&block, prepared).unwrap();
    assert_eq!(store.get_meta(b"consensus").unwrap(), Some(b"tip".to_vec()));
    assert_eq!(store.get_meta(b"missing").unwrap(), None);
    store.put_meta(b"latest_height", &[0xff; 8]).unwrap();
    assert_eq!(store.latest_height().unwrap(), Some(1));
}

#[test]
fn proofs_verify_against_the_state_root() {
    let (_dir, store) = open();
    init(&store);
    let root1 = commit(&store, 1, &writes(&[("a", Some("10"))]), b"1", &[]);
    let root0 = store.state_root(0).unwrap();

    let (value, proof) = store.get_with_proof(1, b"a").unwrap();
    assert_eq!(value.as_deref(), Some(&b"10"[..]));
    Store::verify_proof(root1, b"a", Some(b"10"), &proof).unwrap();
    assert!(
        Store::verify_proof(root1, b"a", Some(b"11"), &proof).is_err(),
        "wrong value"
    );
    assert!(
        Store::verify_proof(root0, b"a", Some(b"10"), &proof).is_err(),
        "wrong root"
    );

    let (absent, proof) = store.get_with_proof(1, b"zzz").unwrap();
    assert_eq!(absent, None);
    Store::verify_proof(root1, b"zzz", None, &proof).unwrap();

    let (old, proof) = store.get_with_proof(0, b"a").unwrap();
    assert_eq!(old.as_deref(), Some(&b"1"[..]));
    Store::verify_proof(root0, b"a", Some(b"1"), &proof).unwrap();
}

#[test]
fn roots_are_deterministic_and_content_sensitive() {
    let (_d1, s1) = open();
    let (_d2, s2) = open();
    let (_d3, s3) = open();
    let w = writes(&[("a", Some("1")), ("b", Some("2"))]);
    let r1 = s1.prepare(0, &w).unwrap().root();
    let r2 = s2.prepare(0, &w).unwrap().root();
    let r3 = s3
        .prepare(0, &writes(&[("a", Some("1")), ("b", Some("3"))]))
        .unwrap()
        .root();
    assert_eq!(r1, r2);
    assert_ne!(r1, r3);
}

#[test]
fn state_survives_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let root = {
        let store = Store::open(dir.path()).unwrap();
        init(&store)
    };
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.latest_height().unwrap(), Some(0));
    assert_eq!(store.state_root(0).unwrap(), root);
    assert_eq!(store.get(b"b").unwrap(), Some(b"2".to_vec()));
    assert_eq!(store.genesis().unwrap(), Some(genesis()));
}

#[test]
fn memory_state_applies_writes() {
    let mut state = MemoryState::new();
    state.apply(&writes(&[("a", Some("1")), ("b", Some("2"))]));
    state.apply(&writes(&[("a", None), ("b", Some("3"))]));
    assert_eq!(state.get(b"a").unwrap(), None);
    assert_eq!(state.get(b"b").unwrap(), Some(b"3".to_vec()));
    assert_eq!(state.len(), 1);
}

#[test]
fn pruning_keeps_recent_state_exact_and_refuses_old_versions() {
    let (_d1, pruned) = open();
    let (_d2, archive) = open();
    init(&pruned);
    init(&archive);
    let step = |i: u64| {
        let value = format!("v{i}");
        let key = format!("k{i}");
        writes(&[
            ("a", Some(value.as_str())),
            (key.as_str(), Some("x")),
            (
                "b",
                if i.is_multiple_of(2) {
                    None
                } else {
                    Some("odd")
                },
            ),
        ])
    };
    for i in 1..=30 {
        let w = step(i);
        assert_eq!(
            commit(&pruned, i, &w, b"b", &[]),
            commit(&archive, i, &w, b"b", &[])
        );
    }
    let before = pruned.tree_size().unwrap();
    let deleted = pruned.prune(25).unwrap();
    let after = pruned.tree_size().unwrap();
    assert!(deleted > 0);
    assert!(
        after.0 < before.0 && after.1 < before.1,
        "{before:?} -> {after:?}"
    );
    assert_eq!(pruned.pruned_before().unwrap(), 25);

    for v in 25..=30 {
        assert_eq!(
            pruned.state_root(v).unwrap(),
            archive.state_root(v).unwrap()
        );
        for key in [&b"a"[..], b"b", b"k3", b"k27", b"missing"] {
            assert_eq!(
                pruned.get_at(v, key).unwrap(),
                archive.get_at(v, key).unwrap()
            );
            let (value, proof) = pruned.get_with_proof(v, key).unwrap();
            Store::verify_proof(pruned.state_root(v).unwrap(), key, value.as_deref(), &proof)
                .unwrap();
        }
    }
    assert!(pruned.state_root(24).unwrap_err().0.contains("pruned"));
    assert!(pruned.get_at(10, b"a").is_err());
    assert!(pruned.get_with_proof(0, b"a").is_err());

    for i in 31..=35 {
        let w = step(i);
        assert_eq!(
            commit(&pruned, i, &w, b"b", &[]),
            commit(&archive, i, &w, b"b", &[])
        );
    }
    assert_eq!(pruned.get(b"a").unwrap(), Some(b"v35".to_vec()));
    assert_eq!(pruned.prune(20).unwrap(), 0, "never un-prunes or re-prunes");
    assert!(pruned.prune(35).unwrap() > 0);
    assert_eq!(
        pruned.state_root(35).unwrap(),
        archive.state_root(35).unwrap()
    );
}

#[test]
fn prune_marker_survives_reopening() {
    let dir = tempfile::tempdir().unwrap();
    {
        let store = Store::open(dir.path()).unwrap();
        init(&store);
        for i in 1..=5 {
            commit(
                &store,
                i,
                &writes(&[("a", Some(&*format!("{i}")))]),
                b"b",
                &[],
            );
        }
        store.prune(4).unwrap();
    }
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.pruned_before().unwrap(), 4);
    assert!(store.get_at(3, b"a").is_err());
    assert_eq!(store.get(b"a").unwrap(), Some(b"5".to_vec()));
}

fn snapshot_chain(store: &Store, heights: u64) {
    for h in 1..=heights {
        let mut w = WriteSet::new();
        for i in 0..200u32 {
            if (i + h as u32).is_multiple_of(3) {
                let value = (i * 1000 + h as u32).to_string().into_bytes();
                w.insert(format!("k{i}").into_bytes(), Some(value));
            }
        }
        if h == 4 {
            w.insert(b"k8".to_vec(), None);
        }
        commit(store, h, &w, format!("block{h}").as_bytes(), &[]);
    }
}

fn chunks_of(store: &Store, version: u64, max_bytes: usize) -> Vec<qubits_state::StateChunk> {
    let mut chunks = Vec::new();
    let mut from = Some([0u8; 32]);
    while let Some(start) = from {
        let chunk = store.state_chunk(version, Some(start), max_bytes).unwrap();
        from = chunk.next();
        chunks.push(chunk);
    }
    chunks
}

#[test]
fn a_snapshot_rebuilds_one_version_from_chunks() {
    let (_dir, store) = open();
    init(&store);
    snapshot_chain(&store, 6);
    let version = 5;
    let root = store.state_root(version).unwrap();
    let chunks = chunks_of(&store, version, 300);
    assert!(chunks.len() > 10, "{} chunks", chunks.len());
    assert!(chunks.last().unwrap().done);
    assert!(chunks[..chunks.len() - 1].iter().all(|c| !c.done));
    let leaves: usize = chunks.iter().map(|c| c.leaves.len()).sum();
    // k8 was deleted at height 4 and not written again before 5
    assert_eq!(
        leaves,
        200 - 1 + 2,
        "200 keys, k8 gone, a and b from genesis"
    );

    let (_dir2, fresh) = open();
    init(&fresh);
    let mut restore = fresh.begin_restore(version, root).unwrap();
    for chunk in chunks.clone() {
        restore.add_chunk(chunk).unwrap();
    }
    let block = CommittedBlock {
        height: version,
        state_root: root,
        bytes: b"block5",
        tx_ids: &[Hash([3; 32])],
        addresses: &[],
        receipts: &[],
        meta: &[(b"tip", vec![1])],
    };
    fresh.finish_restore(restore, &block).unwrap();

    assert_eq!(fresh.latest_height().unwrap(), Some(version));
    assert_eq!(fresh.state_root(version).unwrap(), root);
    assert_eq!(fresh.pruned_before().unwrap(), version);
    assert_eq!(fresh.blocks_from().unwrap(), version);
    assert_eq!(store.blocks_from().unwrap(), 1);
    assert!(fresh.state_root(3).is_err(), "nothing below the snapshot");
    assert_eq!(
        fresh.block(version).unwrap().as_deref(),
        Some(b"block5".as_slice())
    );
    assert!(fresh.block(4).unwrap().is_none());
    assert_eq!(fresh.get_meta(b"tip").unwrap(), Some(vec![1]));
    assert_eq!(
        fresh.tx_location(&Hash([3; 32])).unwrap().map(|l| l.height),
        Some(version)
    );
    for i in 0..200 {
        let key = format!("k{i}").into_bytes();
        let want = store.get_at(version, &key).unwrap();
        let (got, proof) = fresh.get_with_proof(version, &key).unwrap();
        assert_eq!(got, want, "k{i}");
        Store::verify_proof(root, &key, got.as_deref(), &proof).unwrap();
    }
    assert_eq!(fresh.get_at(version, b"k8").unwrap(), None);
    assert_eq!(fresh.get_at(version, b"a").unwrap(), Some(b"1".to_vec()));

    let mut w6 = WriteSet::new();
    for i in 0..200u32 {
        if (i + 6).is_multiple_of(3) {
            w6.insert(
                format!("k{i}").into_bytes(),
                Some((i * 1000 + 6).to_string().into_bytes()),
            );
        }
    }
    let root6 = commit(&fresh, 6, &w6, b"block6", &[]);
    assert_eq!(root6, store.state_root(6).unwrap());
    assert_eq!(
        fresh.get_at(6, b"k0").unwrap(),
        store.get_at(6, b"k0").unwrap()
    );
    assert_eq!(
        fresh.get_at(5, b"k0").unwrap(),
        store.get_at(5, b"k0").unwrap()
    );
    fresh.prune(6).unwrap();
    assert_eq!(fresh.state_root(6).unwrap(), root6);
}

#[test]
fn chunks_from_a_lying_source_are_refused() {
    let (_dir, store) = open();
    init(&store);
    snapshot_chain(&store, 2);
    let version = 2;
    let root = store.state_root(version).unwrap();
    let chunks = chunks_of(&store, version, 500);
    assert!(chunks.len() >= 3);

    let attempt = |root: Hash, edit: &dyn Fn(&mut Vec<qubits_state::StateChunk>)| {
        let (dir, fresh) = open();
        init(&fresh);
        let mut mine = chunks.clone();
        edit(&mut mine);
        let mut restore = fresh.begin_restore(version, root).unwrap();
        let mut result = Ok(());
        for chunk in mine {
            result = restore.add_chunk(chunk);
            if result.is_err() {
                break;
            }
        }
        let result = result.and_then(|()| {
            fresh.finish_restore(
                restore,
                &CommittedBlock {
                    height: version,
                    state_root: root,
                    bytes: b"b",
                    tx_ids: &[],
                    addresses: &[],
                    receipts: &[],
                    meta: &[],
                },
            )
        });
        (dir, fresh, result)
    };

    let (_d, fresh, ok) = attempt(root, &|_| {});
    ok.unwrap();
    assert_eq!(fresh.latest_height().unwrap(), Some(version));

    let (_d, fresh, bad) = attempt(root, &|c| c[0].leaves[0].1.push(b'x'));
    assert!(bad.is_err(), "tampered value");
    assert_eq!(fresh.latest_height().unwrap(), Some(0), "nothing counts");

    let (_d, _, bad) = attempt(root, &|c| {
        c[0].leaves.remove(1);
    });
    assert!(bad.is_err(), "a leaf left out");

    let (_d, _, bad) = attempt(root, &|c| {
        c.swap(0, 1);
    });
    assert!(bad.is_err(), "chunks out of order");

    let (_d, _, bad) = attempt(root, &|c| {
        c.pop();
    });
    assert!(bad.is_err(), "the last chunk missing");

    let (_d, _, bad) = attempt(Hash([9; 32]), &|_| {});
    assert!(bad.is_err(), "another root");

    let (_d, fresh, bad) = attempt(root, &|c| c[1].leaves[0].1.push(b'x'));
    assert!(bad.is_err());
    let mut again = fresh.begin_restore(version, root).unwrap();
    for chunk in chunks.clone() {
        again.add_chunk(chunk).unwrap();
    }
    fresh
        .finish_restore(
            again,
            &CommittedBlock {
                height: version,
                state_root: root,
                bytes: b"b",
                tx_ids: &[],
                addresses: &[],
                receipts: &[],
                meta: &[],
            },
        )
        .unwrap();
    assert_eq!(fresh.state_root(version).unwrap(), root);

    assert!(
        store.begin_restore(version, root).is_err(),
        "only a fresh chain restores"
    );
    assert!(fresh.state_chunk(version, Some([0; 32]), 10).is_ok());
    assert!(
        fresh.state_chunk(1, Some([0; 32]), 10).is_err(),
        "pruned below the snapshot"
    );
    assert!(store.state_chunk(9, Some([0; 32]), 10).is_err());
}

fn restore_all(
    fresh: &Store,
    version: u64,
    root: Hash,
    chunks: Vec<qubits_state::StateChunk>,
) -> Result<(), qubits_state::Error> {
    let mut restore = fresh.begin_restore(version, root)?;
    for chunk in chunks {
        restore.add_chunk(chunk)?;
    }
    let block = CommittedBlock {
        height: version,
        state_root: root,
        bytes: b"b",
        tx_ids: &[],
        addresses: &[],
        receipts: &[],
        meta: &[],
    };
    fresh.finish_restore(restore, &block)
}

#[test]
fn the_last_chunk_ends_on_the_last_live_leaf() {
    let (_dir, store) = open();
    init(&store);
    let live: WriteSet = (0..10)
        .map(|i| (format!("live{i}").into_bytes(), Some(b"v".to_vec())))
        .collect();
    commit(&store, 1, &live, b"block1", &[]);
    let later: WriteSet = (0..200)
        .map(|i| (format!("later{i}").into_bytes(), Some(b"v".to_vec())))
        .collect();
    commit(&store, 2, &later, b"block2", &[]);

    let chunks = chunks_of(&store, 1, 1);
    assert!(
        chunks
            .iter()
            .all(|c| !c.leaves.is_empty() && c.proof.is_some())
    );
    assert_eq!(chunks.iter().map(|c| c.leaves.len()).sum::<usize>(), 12);

    let (_dir2, fresh) = open();
    init(&fresh);
    let root = store.state_root(1).unwrap();
    restore_all(&fresh, 1, root, chunks).unwrap();
    assert_eq!(fresh.state_root(1).unwrap(), root);
}

#[test]
fn a_retry_reads_nothing_from_a_failed_restore() {
    let (_dir, store) = open();
    init(&store);
    let first = writes(&[("gone", Some("old")), ("kept", Some("1"))]);
    commit(&store, 1, &first, b"block1", &[]);
    commit(&store, 2, &writes(&[("gone", None)]), b"block2", &[]);

    let (_dir2, fresh) = open();
    init(&fresh);
    let mut failed = fresh
        .begin_restore(1, store.state_root(1).unwrap())
        .unwrap();
    for chunk in chunks_of(&store, 1, 1) {
        failed.add_chunk(chunk).unwrap();
    }
    drop(failed);

    let root = store.state_root(2).unwrap();
    restore_all(&fresh, 2, root, chunks_of(&store, 2, 1)).unwrap();
    let (got, proof) = fresh.get_with_proof(2, b"gone").unwrap();
    assert_eq!(got, None);
    Store::verify_proof(root, b"gone", None, &proof).unwrap();
    assert_eq!(fresh.get_at(2, b"gone").unwrap(), None);
    assert_eq!(fresh.get_at(2, b"kept").unwrap(), Some(b"1".to_vec()));
    assert_eq!(fresh.get_at(2, b"a").unwrap(), Some(b"1".to_vec()));
}

#[test]
fn old_blocks_are_dropped_with_their_index_and_proofs() {
    let (_dir, store) = open();
    init(&store);
    for h in 1..=10u64 {
        let w = writes(&[("k", Some("v"))]);
        let prepared = store.prepare(h, &w).unwrap();
        let bytes = format!("block{h}");
        let block = CommittedBlock {
            height: h,
            state_root: prepared.root(),
            bytes: bytes.as_bytes(),
            tx_ids: &[Hash([h as u8; 32])],
            addresses: &[],
            receipts: &[],
            meta: &[(b"proof", vec![h as u8])],
        };
        store.commit_block(&block, prepared).unwrap();
    }
    assert_eq!(store.blocks_from().unwrap(), 1);

    // keep 4, stop at 7: 1..3 and 5..6 go
    let deleted = store
        .prune_history(100, 100, |h, bytes| {
            assert_eq!(bytes, format!("block{h}").as_bytes());
            Ok(match h {
                4 => Verdict::Keep,
                7.. => Verdict::Stop,
                _ => Verdict::Delete {
                    tx_ids: vec![Hash([h as u8; 32])],
                    addresses: vec![],
                    meta: vec![b"proof".to_vec()],
                },
            })
        })
        .unwrap();
    assert_eq!(deleted, 5);
    assert_eq!(store.blocks_from().unwrap(), 7);
    for h in [1, 2, 3, 5, 6] {
        assert!(store.block(h).unwrap().is_none(), "{h}");
        assert!(store.tx_location(&Hash([h as u8; 32])).unwrap().is_none());
    }
    for h in [4, 7, 8, 9, 10] {
        assert!(store.block(h).unwrap().is_some(), "{h}");
        assert_eq!(
            store
                .tx_location(&Hash([h as u8; 32]))
                .unwrap()
                .map(|l| l.height),
            Some(h)
        );
    }
    assert_eq!(
        store.get_meta(b"proof").unwrap(),
        None,
        "the meta keys named went too"
    );
    assert_eq!(store.latest_height().unwrap(), Some(10));
    assert_eq!(store.get_at(10, b"k").unwrap(), Some(b"v".to_vec()));

    // a bounded pass looks at `limit` heights only
    let deleted = store
        .prune_history(100, 1, |_, _| {
            Ok(Verdict::Delete {
                tx_ids: vec![],
                addresses: vec![],
                meta: vec![],
            })
        })
        .unwrap();
    assert_eq!((deleted, store.blocks_from().unwrap()), (1, 8));
    // never above `below`
    let deleted = store
        .prune_history(8, 100, |_, _| {
            Ok(Verdict::Delete {
                tx_ids: vec![],
                addresses: vec![],
                meta: vec![],
            })
        })
        .unwrap();
    assert_eq!((deleted, store.blocks_from().unwrap()), (0, 8));
}

fn at(height: u64, index: u32) -> TxLocation {
    TxLocation { height, index }
}

fn listed(store: &Store, who: Address) -> Vec<(u64, u32)> {
    store
        .address_transactions(&who, None, 100)
        .unwrap()
        .into_iter()
        .map(|l| (l.height, l.index))
        .collect()
}

/// Blocks 1..=4 of two transactions: the first names alice and bob, the second alice alone.
fn commit_named(store: &Store, alice: Address, bob: Address) {
    for h in 1..=4u64 {
        let prepared = store.prepare(h, &writes(&[("k", Some("v"))])).unwrap();
        let bytes = format!("block{h}");
        let block = CommittedBlock {
            height: h,
            state_root: prepared.root(),
            bytes: bytes.as_bytes(),
            tx_ids: &[Hash([h as u8; 32]), Hash([h as u8 + 100; 32])],
            addresses: &[vec![alice, bob], vec![alice]],
            receipts: &[],
            meta: &[],
        };
        store.commit_block(&block, prepared).unwrap();
    }
}

#[test]
fn transactions_are_listed_by_address_newest_first() {
    let (_dir, store) = open();
    init(&store);
    let (alice, bob, carol) = (Address([1; 32]), Address([2; 32]), Address([3; 32]));
    commit_named(&store, alice, bob);

    assert_eq!(listed(&store, bob), [(4, 0), (3, 0), (2, 0), (1, 0)]);
    assert_eq!(
        listed(&store, alice),
        [
            (4, 1),
            (4, 0),
            (3, 1),
            (3, 0),
            (2, 1),
            (2, 0),
            (1, 1),
            (1, 0)
        ]
    );
    assert!(listed(&store, carol).is_empty());

    // pages go on from just below the last one given
    let page = store.address_transactions(&alice, None, 3).unwrap();
    assert_eq!(page, [at(4, 1), at(4, 0), at(3, 1)]);
    let page = store
        .address_transactions(&alice, Some(at(3, 1)), 3)
        .unwrap();
    assert_eq!(page, [at(3, 0), at(2, 1), at(2, 0)]);
    // a cursor that is not an entry works too
    let page = store
        .address_transactions(&bob, Some(at(3, 7)), 10)
        .unwrap();
    assert_eq!(page, [at(3, 0), at(2, 0), at(1, 0)]);
    assert!(
        store
            .address_transactions(&bob, Some(at(1, 0)), 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_address_index_follows_dropped_and_returned_blocks() {
    let (_dir, store) = open();
    init(&store);
    let (alice, bob) = (Address([1; 32]), Address([2; 32]));
    commit_named(&store, alice, bob);

    store
        .prune_history(3, 100, |h, _| {
            Ok(Verdict::Delete {
                tx_ids: vec![Hash([h as u8; 32]), Hash([h as u8 + 100; 32])],
                addresses: vec![vec![alice, bob], vec![alice]],
                meta: vec![],
            })
        })
        .unwrap();
    assert_eq!(store.blocks_from().unwrap(), 3);
    assert_eq!(listed(&store, bob), [(4, 0), (3, 0)]);
    assert_eq!(listed(&store, alice), [(4, 1), (4, 0), (3, 1), (3, 0)]);

    // put back from an era file, without receipts: listed as the node was told
    let put = |h: u64| PutBlock {
        bytes: format!("block{h}").into_bytes(),
        tx_ids: vec![Hash([h as u8; 32])],
        addresses: vec![vec![bob]],
        meta: vec![],
    };
    store.put_blocks(1, &[put(1), put(2)]).unwrap();
    assert_eq!(listed(&store, bob), [(4, 0), (3, 0), (2, 0), (1, 0)]);
}

#[test]
fn the_address_index_is_rebuilt_from_the_blocks_held() {
    let (_dir, store) = open();
    init(&store);
    let (alice, bob, carol) = (Address([1; 32]), Address([2; 32]), Address([3; 32]));
    assert_eq!(store.address_index_version().unwrap(), None);
    commit_named(&store, alice, bob);

    // a new rule: everything is carol's now
    let mut seen = Vec::new();
    let blocks = store
        .rebuild_address_index(7, |h, bytes| {
            assert_eq!(bytes, format!("block{h}").as_bytes());
            seen.push(h);
            Ok(vec![vec![carol]])
        })
        .unwrap();
    assert_eq!((blocks, seen), (4, vec![1, 2, 3, 4]));
    assert_eq!(store.address_index_version().unwrap(), Some(7));
    assert!(listed(&store, alice).is_empty(), "the old entries went");
    assert!(listed(&store, bob).is_empty());
    assert_eq!(listed(&store, carol), [(4, 0), (3, 0), (2, 0), (1, 0)]);

    // a rebuild that fails leaves no version, so the next open tries again
    assert!(
        store
            .rebuild_address_index(8, |_, _| Err("bad block".into()))
            .is_err()
    );
    assert_eq!(store.address_index_version().unwrap(), None);
}

#[test]
fn a_database_from_a_later_version_still_opens() {
    let dir = tempfile::tempdir().unwrap();
    {
        let store = Store::open(dir.path()).unwrap();
        init(&store);
    }
    {
        let mut options = rocksdb::Options::default();
        options.create_missing_column_families(true);
        let mut names = rocksdb::DB::list_cf(&options, dir.path()).unwrap();
        names.push("added_later".into());
        let db = rocksdb::DB::open_cf(&options, dir.path(), &names).unwrap();
        db.put_cf(db.cf_handle("added_later").unwrap(), b"k", b"v")
            .unwrap();
    }
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.latest_height().unwrap(), Some(0));
    assert_eq!(store.get(b"a").unwrap(), Some(b"1".to_vec()));
}
