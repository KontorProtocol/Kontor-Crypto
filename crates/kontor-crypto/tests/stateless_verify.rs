//! Stateless verification equivalence.
//!
//! `verify_stateless` must accept/reject exactly what the ledger-based `verify`
//! does, sourcing its single fact — the valid-root set — from plain data instead
//! of a live `FileLedger`. And `aggregate_root` must reproduce `FileLedger::root`
//! byte-for-byte so a contract can compute the current ledger root itself.
//!
//! The stateless path intentionally skips the per-file metadata cross-check (the
//! contract is the registry and checks file existence itself), so the binding for
//! a multi-file proof is valid-root membership + the SNARK.

mod common;
use common::fixtures::{setup_test_scenario, TestConfig};

use ff::PrimeField;
use kontor_crypto::api::{verify_stateless, FieldElement, PorSystem};
use kontor_crypto::ledger::FileLedger;
use kontor_crypto::{aggregate_root, aggregate_root_from_files, KontorPoRError};
use std::collections::HashSet;

/// Derive the stateless verifier's input from a populated ledger — the set of
/// valid aggregated roots a contract would hold in its own storage.
fn valid_roots(ledger: &FileLedger) -> HashSet<[u8; 32]> {
    let mut roots: HashSet<[u8; 32]> = ledger.historical_roots.iter().copied().collect();
    roots.insert(ledger.root().to_repr().into());
    roots
}

#[test]
fn stateless_matches_ledger_multi_file() {
    let setup = setup_test_scenario(&TestConfig::multi_file(2)).unwrap();
    let ledger = setup.ledger_ref().unwrap();
    let system = PorSystem::new(ledger);
    let files: Vec<&_> = setup.file_refs().values().copied().collect();
    let proof = system.prove(files, &setup.challenges).unwrap();

    // Ground truth: ledger-based verify accepts.
    assert!(system.verify(&proof, &setup.challenges).unwrap());

    let roots = valid_roots(ledger);

    // Equivalence: stateless verify accepts the same proof.
    assert!(
        verify_stateless(&setup.challenges, &proof, &roots).unwrap(),
        "stateless verify must accept what ledger verify accepts"
    );

    // aggregate_root reproduces the ledger root exactly (rc and (root,depth) forms).
    let expected: [u8; 32] = ledger.root().to_repr().into();
    let rcs: Vec<FieldElement> = ledger.files.values().map(|e| e.rc).collect();
    assert_eq!(aggregate_root(&rcs).unwrap(), expected);
    let files_rd: Vec<(FieldElement, usize)> =
        ledger.files.values().map(|e| (e.root, e.depth)).collect();
    assert_eq!(aggregate_root_from_files(&files_rd).unwrap(), expected);

    // Negative: a valid-root set missing the proof's root → reject (multi-file).
    let no_roots = HashSet::new();
    assert!(matches!(
        verify_stateless(&setup.challenges, &proof, &no_roots),
        Err(KontorPoRError::InvalidLedgerRoot { .. })
    ));
}

#[test]
fn stateless_matches_ledger_single_file() {
    let setup = setup_test_scenario(&TestConfig::default()).unwrap();
    let ledger = setup.ledger_ref().unwrap();
    let system = PorSystem::new(ledger);
    let files: Vec<&_> = setup.file_refs().values().copied().collect();
    let proof = system.prove(files, &setup.challenges).unwrap();

    assert!(system.verify(&proof, &setup.challenges).unwrap());

    let roots = valid_roots(ledger);
    assert!(verify_stateless(&setup.challenges, &proof, &roots).unwrap());

    // Single-file proofs skip the ledger-root check (the circuit uses the file's
    // own root), so an empty valid-root set still verifies.
    let no_roots = HashSet::new();
    assert!(verify_stateless(&setup.challenges, &proof, &no_roots).unwrap());
}
