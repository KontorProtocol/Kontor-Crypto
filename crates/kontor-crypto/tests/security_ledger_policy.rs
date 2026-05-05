//! Tests for historical root retention policy behavior.

use ff::PrimeField;
use kontor_crypto::api::{self, Challenge, FieldElement, FileMetadata, PorSystem};
use kontor_crypto::{config, FileLedger, HistoricalRootPolicy, KontorPoRError};
use rand::{Rng, SeedableRng};

fn deterministic_nonce(seed: u64) -> [u8; 16] {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    rng.gen()
}

fn synthetic_metadata(file_id: &str, root: FieldElement, depth: usize) -> FileMetadata {
    FileMetadata {
        root,
        object_id: format!("object_{}", file_id),
        file_id: file_id.to_string(),
        nonce: vec![],
        padded_len: 1 << depth,
        original_size: 100,
        filename: format!("{}.dat", file_id),
    }
}

#[test]
fn test_default_historical_root_policy_is_bounded() {
    let ledger = FileLedger::new();
    assert_eq!(
        ledger.historical_root_policy(),
        HistoricalRootPolicy::MaxRoots(config::DEFAULT_MAX_HISTORICAL_ROOTS)
    );
}

#[test]
fn test_max_roots_policy_prunes_oldest_entries() {
    let mut ledger = FileLedger::new();
    ledger.set_historical_root_policy(HistoricalRootPolicy::MaxRoots(3));

    let mut observed_roots = Vec::new();
    for i in 0..6u64 {
        let metadata = synthetic_metadata(&format!("file_{}", i), FieldElement::from(i + 1), 3);
        ledger.add_file(&metadata).unwrap();
        let root: [u8; 32] = ledger.root().to_repr().into();
        observed_roots.push(root);
    }

    assert_eq!(ledger.historical_roots.len(), 3);
    assert_eq!(ledger.historical_roots, observed_roots[3..6].to_vec());
}

#[test]
fn test_unlimited_policy_keeps_all_entries() {
    let mut ledger = FileLedger::new();
    ledger.set_historical_root_policy(HistoricalRootPolicy::Unlimited);

    for i in 0..25u64 {
        let metadata = synthetic_metadata(&format!("file_{}", i), FieldElement::from(i + 10), 3);
        ledger.add_file(&metadata).unwrap();
    }

    assert_eq!(ledger.historical_roots.len(), 25);
}

#[test]
fn test_pruned_root_invalidates_old_multifile_proof() {
    let data1 = vec![1u8; 100];
    let data2 = vec![2u8; 100];
    let data3 = vec![3u8; 100];

    let (prepared1, meta1) = api::prepare_file(&data1, "a.dat", &deterministic_nonce(1)).unwrap();
    let (prepared2, meta2) = api::prepare_file(&data2, "b.dat", &deterministic_nonce(2)).unwrap();
    let (_prepared3, meta3) = api::prepare_file(&data3, "c.dat", &deterministic_nonce(3)).unwrap();

    let mut ledger = FileLedger::new();
    ledger.set_historical_root_policy(HistoricalRootPolicy::MaxRoots(1));

    ledger.add_file(&meta1).unwrap();
    ledger.add_file(&meta2).unwrap();

    let challenges = vec![
        Challenge::new_test(meta1.clone(), 2000, 1, FieldElement::from(11u64)),
        Challenge::new_test(meta2.clone(), 2000, 1, FieldElement::from(22u64)),
    ];

    let system_before = PorSystem::new(&ledger);
    let proof = system_before
        .prove(vec![&prepared1, &prepared2], &challenges)
        .unwrap();
    assert!(system_before.verify(&proof, &challenges).unwrap());

    ledger.add_file(&meta3).unwrap();

    let system_after = PorSystem::new(&ledger);
    let result = system_after.verify(&proof, &challenges);

    assert!(
        matches!(result, Err(KontorPoRError::InvalidLedgerRoot { .. })),
        "Expected old proof to be invalidated after root pruning, got: {:?}",
        result
    );
}

#[test]
fn test_save_load_preserves_historical_root_policy() {
    let mut ledger = FileLedger::new();
    ledger.set_historical_root_policy(HistoricalRootPolicy::MaxRoots(7));
    ledger
        .add_file(&synthetic_metadata(
            "persisted",
            FieldElement::from(42u64),
            3,
        ))
        .unwrap();

    let temp_path = std::env::temp_dir().join("kontor_policy_persist_test.bin");
    ledger.save(&temp_path).unwrap();
    let loaded = FileLedger::load(&temp_path).unwrap();
    std::fs::remove_file(temp_path).ok();

    assert_eq!(
        loaded.historical_root_policy(),
        HistoricalRootPolicy::MaxRoots(7)
    );
}
