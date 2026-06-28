//! Stateless verification equivalence.
//!
//! `verify_stateless` must accept/reject exactly what the ledger-based `verify`
//! does, sourcing its facts — the valid-root set and the `file_id -> (slot, rc)`
//! registry — from plain data instead of a live `FileLedger`. And `aggregate_root`
//! must reproduce `FileLedger::root` byte-for-byte (including sparse, append-only
//! slots) so a contract can compute the current ledger root itself.

mod common;
use common::fixtures::{setup_test_scenario, TestConfig};

use ff::PrimeField;
use kontor_crypto::api::{verify_stateless, FieldElement, PorSystem, StatelessLedger};
use kontor_crypto::ledger::FileLedger;
use kontor_crypto::{aggregate_root, aggregate_root_from_files, KontorPoRError};
use std::collections::{BTreeMap, HashSet};

/// The set of valid aggregated roots a contract would hold in its own storage.
fn valid_roots(ledger: &FileLedger) -> HashSet<[u8; 32]> {
    let mut roots: HashSet<[u8; 32]> = ledger.historical_roots.iter().copied().collect();
    roots.insert(ledger.root().to_repr().into());
    roots
}

/// The `file_id -> (stable slot, rc)` registry snapshot a contract would hold.
fn registry(ledger: &FileLedger) -> BTreeMap<String, (usize, FieldElement)> {
    ledger
        .files
        .iter()
        .map(|(id, e)| (id.clone(), (e.ledger_index, e.entry.rc)))
        .collect()
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
    let files_reg = registry(ledger);

    // Equivalence: stateless verify accepts the same proof.
    let view = StatelessLedger {
        valid_roots: &roots,
        files: &files_reg,
    };
    assert!(
        verify_stateless(&setup.challenges, &proof, &view).unwrap(),
        "stateless verify must accept what ledger verify accepts"
    );

    // aggregate_root reproduces the ledger root exactly, from (rc, slot) and from
    // (root, depth, slot) forms.
    let expected: [u8; 32] = ledger.root().to_repr().into();
    let rc_slots: Vec<(FieldElement, usize)> = ledger
        .files
        .values()
        .map(|e| (e.entry.rc, e.ledger_index))
        .collect();
    assert_eq!(aggregate_root(&rc_slots).unwrap(), expected);
    let file_slots: Vec<(FieldElement, usize, usize)> = ledger
        .files
        .values()
        .map(|e| (e.entry.root, e.entry.depth, e.ledger_index))
        .collect();
    assert_eq!(aggregate_root_from_files(&file_slots).unwrap(), expected);

    // Negative: a valid-root set missing the proof's root → reject (multi-file).
    let no_roots = HashSet::new();
    let empty_view = StatelessLedger {
        valid_roots: &no_roots,
        files: &files_reg,
    };
    assert!(matches!(
        verify_stateless(&setup.challenges, &proof, &empty_view),
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
    let files_reg = registry(ledger);
    let view = StatelessLedger {
        valid_roots: &roots,
        files: &files_reg,
    };
    assert!(verify_stateless(&setup.challenges, &proof, &view).unwrap());

    // Single-file proofs skip the ledger-root check (the circuit uses the file's
    // own root), so an empty valid-root set still verifies.
    let no_roots = HashSet::new();
    let empty_view = StatelessLedger {
        valid_roots: &no_roots,
        files: &files_reg,
    };
    assert!(verify_stateless(&setup.challenges, &proof, &empty_view).unwrap());
}

/// `aggregate_root` must honour sparse, append-only slots: a gap (a removed file's
/// slot) is a zero leaf, exactly as `FileLedger::rebuild_tree` lays it out. Placing
/// the same rcs at non-contiguous slots must change the root, and the order the
/// pairs are supplied in must not matter.
#[test]
fn aggregate_root_honours_sparse_slots() {
    let a = FieldElement::from(11u64);
    let b = FieldElement::from(22u64);

    let dense = aggregate_root(&[(a, 0), (b, 1)]).unwrap();
    let sparse = aggregate_root(&[(a, 0), (b, 2)]).unwrap();
    assert_ne!(
        dense, sparse,
        "a gap at slot 1 must change the aggregated root"
    );

    // Order-independence: pairs may arrive in any order.
    let reordered = aggregate_root(&[(b, 2), (a, 0)]).unwrap();
    assert_eq!(sparse, reordered);

    // Duplicate slots are rejected.
    assert!(matches!(
        aggregate_root(&[(a, 0), (b, 0)]),
        Err(KontorPoRError::InvalidInput(_))
    ));
}
